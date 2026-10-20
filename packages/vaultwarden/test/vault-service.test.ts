import { expect, test } from 'bun:test';
import { generateKeyPairSync, publicEncrypt, createPublicKey, constants } from 'node:crypto';
import type { JsonObject } from '#client';
import { VaultwardenClient } from '#client';
import { encrypt, decrypt, encryptAttachment } from '#crypto';
import { VaultService } from '#vault-service';
import { transformItem, encryptItem } from '#item-codec';
import { totp } from '#totp';

const userKey = Buffer.alloc(64, 1);
const itemKey = Buffer.alloc(64, 2);
const plaintext = {
	type: 1,
	name: 'Example',
	notes: 'notes',
	login: { username: 'person', password: 'secret', uris: [{ uri: 'https://example.com' }] },
	fields: [{ name: 'custom', value: 'private', type: 0 }],
	passwordHistory: [{ password: 'previous', lastUsedDate: 'date' }],
};
function wire(overrides: JsonObject = {}) {
	return {
		...encryptItem(plaintext, itemKey),
		id: 'item',
		key: encrypt(itemKey, userKey),
		revisionDate: '2026-01-01T00:00:00Z',
		...overrides,
	};
}
function service(
	handler: (path: string, init: RequestInit) => Response,
	snapshot: JsonObject = { profile: { id: 'user' }, ciphers: [wire()], folders: [] },
) {
	const fetcher = ((url: unknown, init: RequestInit) => handler(String(url), init)) as unknown as typeof fetch;
	return new VaultService(
		new VaultwardenClient('https://example.com', { fetch: fetcher }),
		'access',
		snapshot,
		userKey,
	);
}
test('item codec encrypts all known fields, including history and custom fields, symmetrically', () => {
	const encrypted = transformItem(plaintext, itemKey, 'encrypt');
	expect(JSON.stringify(encrypted)).not.toContain('previous');
	expect(transformItem(encrypted, itemKey, 'decrypt')).toEqual(plaintext);
});
test('edits retain existing item key and send the client revision guard', async () => {
	const vault = service((path, init) => {
		expect(path).toEndWith('/api/ciphers/item');
		expect(init.method).toBe('PUT');
		const data = JSON.parse(String(init.body));
		expect(data.lastKnownRevisionDate).toBe('2026-01-01T00:00:00Z');
		expect(data.encryptedFor).toBe('user');
		expect(transformItem(data, itemKey, 'decrypt').name).toBe('Changed');
		return Response.json({ ...data, id: 'item', revisionDate: '2026-01-01T00:00:01Z' });
	});
	const item = vault.getItem('item');
	item.name = 'Changed';
	expect((await vault.editItem('item', item)).name).toBe('Changed');
});
test('lists distinguish trash and archive and combine object filters with OR', () => {
	const vault = service(() => Response.json({}), {
		profile: { id: 'user' },
		folders: [],
		ciphers: [
			wire(),
			wire({ id: 'trash', deletedDate: 'date' }),
			wire({ id: 'archive', archivedDate: 'date' }),
			wire({ id: 'folder', folderId: 'folder' }),
		],
	});
	expect(vault.listItems().map(i => i.id)).toEqual(['item', 'folder']);
	expect(vault.listItems({ trash: true }).map(i => i.id)).toEqual(['trash']);
	expect(vault.listItems({ archived: true }).map(i => i.id)).toEqual(['archive']);
	expect(vault.listItems({ folderId: 'folder', organizationId: 'notnull' }).map(i => i.id)).toEqual(['folder']);
});
test('decrypts organization items and collections using account RSA private key', () => {
	const rsa = generateKeyPairSync('rsa', {
		modulusLength: 2048,
		publicKeyEncoding: { type: 'spki', format: 'der' },
		privateKeyEncoding: { type: 'pkcs8', format: 'der' },
	});
	const orgKey = Buffer.alloc(64, 3);
	const wrapped = `3.${
		publicEncrypt({
			key: createPublicKey({ key: rsa.publicKey, format: 'der', type: 'spki' }),
			oaepHash: 'sha256',
			padding: constants.RSA_PKCS1_OAEP_PADDING,
		}, orgKey).toString('base64')
	}`;
	const snapshot = {
		profile: {
			id: 'user',
			privateKey: encrypt(rsa.privateKey, userKey),
			organizations: [{ id: 'org', name: 'Organization', key: wrapped }],
		},
		folders: [],
		collections: [{ id: 'collection', organizationId: 'org', name: encrypt(Buffer.from('Collection'), orgKey) }],
		ciphers: [wire({ organizationId: 'org', key: encrypt(itemKey, orgKey) })],
	};
	const vault = service(() => Response.json({}), snapshot);
	try {
		expect(vault.listItems()[0]?.name).toBe('Example');
		expect(vault.listCollections()[0]?.name).toBe('Collection');
		expect(vault.findCollection('LECT').name).toBe('Collection');
		expect(vault.listOrganizations()[0]?.key).toBeUndefined();
	} finally {
		vault.dispose();
		rsa.privateKey.fill(0);
		orgKey.fill(0);
	}
});
test('TOTP matches RFC 6238 known answers and supports parameterized URIs', () => {
	const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
	expect(totp(`otpauth://totp/test?secret=${secret}&digits=8`, 59000)).toBe('94287082');
	expect(totp(`otpauth://totp/test?secret=${secret}&digits=8`, 1111111109000)).toBe('07081804');
	expect(() => totp('otpauth://hotp/test?secret=ABC')).toThrow('TOTP');
});

function organizationSnapshot(ciphers: JsonObject[] = []) {
	const rsa = generateKeyPairSync('rsa', {
		modulusLength: 2048,
		publicKeyEncoding: { type: 'spki', format: 'der' },
		privateKeyEncoding: { type: 'pkcs8', format: 'der' },
	});
	const orgKey = Buffer.alloc(64, 9);
	const wrapped = `3.${
		publicEncrypt({
			key: createPublicKey({ key: rsa.publicKey, format: 'der', type: 'spki' }),
			padding: constants.RSA_PKCS1_OAEP_PADDING,
			oaepHash: 'sha256',
		}, orgKey).toString('base64')
	}`;
	return {
		orgKey,
		snapshot: {
			profile: {
				id: 'user',
				privateKey: encrypt(rsa.privateKey, userKey),
				organizations: [{ id: 'org', key: wrapped }],
			},
			ciphers,
			collections: [{ id: 'collection', organizationId: 'org', name: encrypt(Buffer.from('Collection'), orgKey) }],
		},
	};
}
for (const legacy of [false, true]) {
	test(`move ${legacy ? 'legacy' : 'per-item-key'} item never shares the account key`, async () => {
		const input = legacy
			? { ...transformItem(plaintext, userKey, 'encrypt'), id: 'item', key: null, revisionDate: '2026-01-01T00:00:00Z' }
			: wire();
		const { snapshot, orgKey } = organizationSnapshot([input]);
		const vault = service((path, init) => {
			expect(path).toEndWith('/api/ciphers/item/share');
			const body = JSON.parse(String(init.body));
			const key = decrypt(body.cipher.key, orgKey);
			try {
				expect(key.equals(userKey)).toBe(false);
				if (!legacy) expect(key).toEqual(itemKey);
				expect(transformItem(body.cipher, key, 'decrypt').login).toMatchObject(plaintext.login);
			} finally {
				key.fill(0);
			}
			return Response.json({ ...body.cipher, id: 'item' });
		}, snapshot);
		try {
			expect((await vault.moveItem('item', 'org', ['collection'])).name).toBe('Example');
		} finally {
			vault.dispose();
			orgKey.fill(0);
		}
	});
}
test('collection rename preserves existing membership assignments', async () => {
	const { snapshot, orgKey } = organizationSnapshot();
	const users = [{ id: 'member', readOnly: true, hidePasswords: true, manage: false }];
	const vault = service((_path, init) => {
		if (init.method === 'GET') {
			return Response.json({ id: 'collection', name: encrypt(Buffer.from('Old'), orgKey), users, groups: [] });
		}
		const body = JSON.parse(String(init.body));
		expect(body.users).toEqual(users);
		expect(body.groups).toEqual([]);
		expect(decrypt(body.name, orgKey).toString()).toBe('New');
		return Response.json({ ...body, id: 'collection' });
	}, snapshot);
	try {
		expect((await vault.editCollection('org', 'collection', { name: 'New' })).name).toBe('New');
	} finally {
		vault.dispose();
	}
});
test('move rejects a collection from another organization before any network mutation', async () => {
	const { snapshot } = organizationSnapshot([wire()]);
	let calls = 0;
	const vault = service(() => {
		calls++;
		return Response.json({});
	}, snapshot);
	await expect(vault.moveItem('item', 'org', ['other-collection'])).rejects.toThrow('another organization');
	expect(calls).toBe(0);
	vault.dispose();
});

test('failed binary upload removes incomplete attachment metadata', async () => {
	const methods: string[] = [];
	const vault = service((path, init) => {
		methods.push(init.method!);
		if (path.endsWith('/attachment/v2')) {
			return Response.json({ attachmentId: 'attachment', fileUploadType: 0, cipherResponse: wire() });
		}
		if (init.method === 'POST') {
			expect(init.body).toBeInstanceOf(FormData);
			return Response.json({}, { status: 500 });
		}
		return new Response(null, { status: 204 });
	});
	await expect(vault.createAttachment('item', 'private.bin', Buffer.from([0, 255]))).rejects.toThrow(
		'incomplete metadata was removed',
	);
	expect(methods).toEqual(['POST', 'POST', 'DELETE']);
	vault.dispose();
});

test('attachment queries search item names and filenames, preferring one exact filename before downloading', async () => {
	const key = Buffer.alloc(64, 7), contents = Buffer.from([0, 255, 10, 1]);
	const attachments = [
		{ id: 'abc123', fileName: encrypt(Buffer.from('Report.bin'), itemKey), key: encrypt(key, itemKey) },
		{ id: 'def456', fileName: encrypt(Buffer.from('Report.bin.backup'), itemKey), key: encrypt(key, itemKey) },
	];
	const paths: string[] = [];
	const vault = service((path, init) => {
		paths.push(path);
		if (path.startsWith('https://files.example/')) {
			expect(new Headers(init.headers).has('Authorization')).toBe(false);
			expect(init.credentials).toBe('omit');
			return new Response(new Uint8Array(encryptAttachment(contents, key)));
		}
		expect(path).toMatch(/\/api\/ciphers\/item\/attachment\/(abc123|def456)$/);
		return Response.json({ url: 'https://files.example/signed-attachment' });
	}, { profile: {}, ciphers: [wire({ attachments })] });
	try {
		for (const query of ['REPORT.BIN', 'ABC123']) {
			const result = await vault.getAttachment('Example', query);
			try {
				expect(result.fileName).toBe('Report.bin');
				expect(result.contents).toEqual(contents);
			} finally {
				result.contents.fill(0);
			}
		}
		expect(paths).toHaveLength(4);
		for (const query of ['REPORT', '.bin', 'missing', '']) {
			await expect(vault.getAttachment('item', query)).rejects.toThrow();
		}
		expect(paths).toHaveLength(4);
		const partial = await vault.getAttachment('item', 'BACKUP');
		expect(partial.fileName).toBe('Report.bin.backup');
		expect(paths[4]).toEndWith('/attachment/def456');
		partial.contents.fill(0);
		attachments.push({
			id: 'duplicate',
			fileName: encrypt(Buffer.from('REPORT.BIN'), itemKey),
			key: encrypt(key, itemKey),
		});
		await expect(vault.getAttachment('item', 'report.bin')).rejects.toThrow('Multiple');
		expect(paths).toHaveLength(6);
	} finally {
		vault.dispose();
		key.fill(0);
	}
});

test('attachment metadata falls back only on 404, retaining cached keys and credential-free downloads', async () => {
	const key = Buffer.alloc(64, 8), contents = Buffer.from('synthetic attachment');
	for (const status of [404, 401, 403, 429, 500]) {
		let downloads = 0;
		const attachment = {
			id: 'attachment',
			fileName: encrypt(Buffer.from('old.bin'), itemKey),
			key: encrypt(key, itemKey),
			url: 'https://files.example/cached',
		};
		const vault = service((path, init) => {
			if (path.startsWith('https://files.example/')) {
				downloads++;
				expect(new Headers(init.headers).has('Authorization')).toBe(false);
				return new Response(new Uint8Array(encryptAttachment(contents, key)));
			}
			return Response.json({}, { status });
		}, { profile: {}, ciphers: [wire({ attachments: [attachment] })] });
		try {
			if (status === 404) {
				const result = await vault.getAttachment('item', 'old.bin');
				expect(result.contents).toEqual(contents);
				result.contents.fill(0);
			} else await expect(vault.getAttachment('item', 'old.bin')).rejects.toThrow(`HTTP ${status}`);
			expect(downloads).toBe(status === 404 ? 1 : 0);
		} finally {
			vault.dispose();
		}
	}
	key.fill(0);
});
