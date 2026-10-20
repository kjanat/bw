import { test, expect } from 'bun:test';
import { randomBytes } from 'node:crypto';
import { unzipSync, zipSync } from 'fflate';
import { VaultwardenClient, type JsonObject } from '#client';
import { VaultService } from '#vault-service';
import { encrypt, decrypt, deriveKdfKey, deriveMasterKey } from '#crypto';
import { transformItem, encryptItem } from '#item-codec';
import { parseCsv, writeCsv, decryptExportDocument, ImportFailure, importVault } from '#transfer';

const key = Buffer.alloc(64, 6);
const itemKey = Buffer.alloc(64, 7);
const item = {
	id: 'old-item',
	type: 1,
	name: 'Example, "quoted"',
	notes: 'line1\nline2',
	folderId: 'old-folder',
	favorite: true,
	login: {
		username: 'person',
		password: 'private',
		totp: null,
		uris: [{ uri: 'https://example.com/a,b' }, { uri: 'https://second.example.com' }],
	},
	fields: [{ name: 'custom', value: 'private-field', type: 0 }],
	archivedDate: null,
	revisionDate: '2026-01-01T00:00:00Z',
};
function fixture(handler?: (path: string, init: RequestInit) => Response) {
	const snapshot = {
		profile: { id: 'account' },
		folders: [{ id: 'old-folder', name: encrypt(Buffer.from('Folder, name'), key) }],
		collections: [],
		ciphers: [{ ...encryptItem(item, itemKey), key: encrypt(itemKey, key) }],
	};
	const transport =
		((url: unknown, init: RequestInit) =>
			handler ? handler(String(url), init) : Response.json({})) as unknown as typeof fetch;
	return new VaultService(new VaultwardenClient('https://example.com', { fetch: transport }), 'access', snapshot, key);
}
test('CSV parser and writer round-trip commas, quoted newlines, escaped quotes, and CRLF', () => {
	const rows = [['name', 'notes', 'password'], ['A, B', 'first\nsecond', '"quoted"'], ['empty', '', '']];
	expect(parseCsv(writeCsv(rows))).toEqual(rows);
	expect(() => parseCsv('name\n"unfinished')).toThrow('Unterminated');
	expect(() => parseCsv('"closed"junk')).toThrow('quoting');
});
test('export KDF salts retain case while account email salts normalize', async () => {
	const kdf = { type: 0, iterations: 1000 } as const;
	expect(
		(await deriveKdfKey('password', 'UPPER+Salt==', kdf)).equals(await deriveKdfKey('password', 'upper+salt==', kdf)),
	).toBe(false);
	expect(await deriveMasterKey('password', ' Person@Example.com ', kdf)).toEqual(
		await deriveMasterKey('password', 'person@example.com', kdf),
	);
});
test('plain and account-encrypted JSON exports round-trip without exposing per-item keys', async () => {
	const vault = fixture();
	try {
		const plain = JSON.parse((await vault.exportVault('json')).toString());
		expect(plain.encrypted).toBe(false);
		expect(plain.items[0].login.password).toBe('private');
		expect(plain.items[0].key).toBeUndefined();
		expect(plain.folders[0].name).toBe('Folder, name');
		const encrypted = JSON.parse((await vault.exportVault('encrypted_json')).toString());
		expect(JSON.stringify(encrypted)).not.toContain('private');
		expect(encrypted.items[0].key).toMatch(/^2\./);
		const clear = await decryptExportDocument(encrypted, key);
		expect((clear.items as JsonObject[])[0]!.name).toBe(item.name);
		await expect(decryptExportDocument(encrypted, randomBytes(64))).rejects.toThrow('authentication');
	} finally {
		vault.dispose();
	}
});
for (const kdf of [{ type: 0, iterations: 10000 }, { type: 1, iterations: 2, memory: 16, parallelism: 1 }] as const) {
	test(`password export uses KDF ${kdf.type} and rejects a wrong password`, async () => {
		const vault = fixture();
		try {
			const encrypted = JSON.parse(
				(await vault.exportVault('encrypted_json', { password: 'file-password', kdf })).toString(),
			);
			expect(encrypted.passwordProtected).toBe(true);
			expect(encrypted.kdfType).toBe(kdf.type);
			expect(JSON.stringify(encrypted)).not.toContain('private-field');
			const clear = await decryptExportDocument(encrypted, key, 'file-password');
			expect((clear.items as JsonObject[])[0]!.name).toBe(item.name);
			await expect(decryptExportDocument(encrypted, key, 'wrong')).rejects.toThrow('authentication');
		} finally {
			vault.dispose();
		}
	});
}
test('bulk JSON import remaps folder relations and encrypts every item with a new key', async () => {
	let requests = 0;
	const vault = fixture((path, init) => {
		requests++;
		expect(path).toEndWith('/api/ciphers/import');
		const body = JSON.parse(String(init.body));
		expect(body.folderRelationships).toEqual([{ key: 0, value: 0 }]);
		expect(body.folders[0].id).toBeUndefined();
		expect(decrypt(body.folders[0].name, key).toString()).toBe('Folder');
		const cipher = body.ciphers[0];
		expect(cipher.id).toBeUndefined();
		expect(cipher.encryptedFor).toBe('account');
		const perItem = decrypt(cipher.key, key);
		try {
			expect(perItem.equals(key)).toBe(false);
			expect(transformItem(cipher, perItem, 'decrypt').name).toBe(item.name);
		} finally {
			perItem.fill(0);
		}
		return new Response(null, { status: 204 });
	});
	try {
		expect(
			await vault.importVault(
				'bitwardenjson',
				JSON.stringify({ encrypted: false, folders: [{ id: 'old-folder', name: 'Folder' }], items: [item] }),
			),
		).toEqual({ items: 1, folders: 1, collections: 0, attachments: 0 });
		expect(requests).toBe(1);
	} finally {
		vault.dispose();
	}
});
test('organization import includes full collection membership arrays required by Vaultwarden 1.36', async () => {
	let calls = 0;
	const vault = fixture((path, init) => {
		calls++;
		expect(path).toContain('/api/ciphers/import-organization?organizationId=organization');
		const body = JSON.parse(String(init.body));
		expect(body.collections[0]).toMatchObject({ externalId: null, groups: [], users: [] });
		expect(body.collections[0].id).toBeUndefined();
		expect(decrypt(body.collections[0].name, key).toString()).toBe('Collection');
		expect(body.collectionRelationships).toEqual([{ key: 0, value: 0 }]);
		return new Response(null, { status: 204 });
	});
	try {
		expect(
			await importVault(
				vault,
				{ user: key, organization: () => key },
				'bitwardenjson',
				JSON.stringify({
					collections: [{ id: 'source', name: 'Collection' }],
					items: [{ ...item, collectionIds: ['source'] }],
				}),
				{ organizationId: 'organization' },
			),
		).toEqual({ items: 1, folders: 0, collections: 1, attachments: 0 });
		expect(calls).toBe(1);
	} finally {
		vault.dispose();
	}
});
test('malformed input is rejected before sending an import, and uncertain server errors are distinguished', async () => {
	let calls = 0;
	const vault = fixture(() => {
		calls++;
		return Response.json({}, { status: 500 });
	});
	await expect(vault.importVault('bitwardenjson', '{ invalid')).rejects.toThrow('Invalid vault export');
	expect(calls).toBe(0);
	await expect(vault.importVault('bitwardenjson', JSON.stringify({ items: [{ type: 99, name: 'Unsupported' }] })))
		.rejects.toThrow('Unsupported');
	expect(calls).toBe(0);
	try {
		await vault.importVault('bitwardenjson', JSON.stringify({ items: [item] }));
		throw new Error('expected failure');
	} catch (error) {
		expect(error).toBeInstanceOf(ImportFailure);
		expect((error as ImportFailure).serverMayHaveChanged).toBe(true);
	}
	vault.dispose();
});
test('ZIP exports contain data.json and a versioned attachment manifest', async () => {
	const vault = fixture();
	try {
		const archive = unzipSync(await vault.exportVault('zip'));
		expect(JSON.parse(Buffer.from(archive['data.json']!).toString()).items[0].name).toBe(item.name);
		expect(JSON.parse(Buffer.from(archive['vw-manifest.json']!).toString())).toEqual({ version: 1, attachments: [] });
	} finally {
		vault.dispose();
	}
});

test('ambiguous official ZIP attachment names fail before any server mutation', async () => {
	let calls = 0;
	const vault = fixture(() => {
		calls++;
		return Response.json({});
	});
	const archive = zipSync({
		'data.json': Buffer.from(JSON.stringify({ items: [item, { ...item, id: 'other' }] })),
		'attachments/Example, _quoted_/file.bin': Buffer.from('payload'),
	});
	try {
		await expect(vault.importVault('bitwardenzip', archive)).rejects.toThrow('ambiguous');
		expect(calls).toBe(0);
	} finally {
		vault.dispose();
	}
});
