import { test, expect } from 'bun:test';
import { randomBytes } from 'node:crypto';
import { unzipSync } from 'fflate';
import { VaultwardenClient, type JsonObject } from '#client';
import { VaultService } from '#vault-service';
import { encrypt, decrypt, deriveKdfKey, deriveMasterKey } from '#crypto';
import { transformItem, encryptItem } from '#item-codec';
import {
	parseCsv,
	writeCsv,
	decryptExportDocument,
	ImportFailure,
	importVault,
	officialZipAttachments,
} from '#transfer';

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
test('JSON export retains bank account, driver license, and passport sections', async () => {
	const items = [
		{ id: 'bank', type: 6, name: 'Bank', bankAccount: { accountNumber: 'bank-number' } },
		{ id: 'license', type: 7, name: 'License', driversLicense: { licenseNumber: 'license-number' } },
		{ id: 'passport', type: 8, name: 'Passport', passport: { passportNumber: 'passport-number' } },
	];
	const snapshot = {
		profile: { id: 'account' },
		folders: [],
		collections: [],
		ciphers: items.map(value => ({ ...encryptItem(value, itemKey), key: encrypt(itemKey, key) })),
	};
	const vault = new VaultService(
		new VaultwardenClient(
			'https://example.com',
			{ fetch: (async () => Response.json({})) as unknown as typeof fetch },
		),
		'access',
		snapshot,
		key,
	);
	try {
		const exported = JSON.parse((await vault.exportVault('json')).toString());
		expect(exported.items.map((value: JsonObject) => value.id)).toEqual(['bank', 'license', 'passport']);
		expect(exported.items[0].bankAccount.accountNumber).toBe('bank-number');
		expect(exported.items[1].driversLicense.licenseNumber).toBe('license-number');
		expect(exported.items[2].passport.passportNumber).toBe('passport-number');
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
test('JSON import accepts and encrypts bank account, driver license, and passport items', async () => {
	const items = [
		{ type: 6, name: 'Bank', bankAccount: { accountNumber: 'bank-number' } },
		{ type: 7, name: 'License', driversLicense: { licenseNumber: 'license-number' } },
		{ type: 8, name: 'Passport', passport: { passportNumber: 'passport-number' } },
	];
	const vault = fixture((_path, init) => {
		const body = JSON.parse(String(init.body));
		expect(body.ciphers).toHaveLength(3);
		for (const [index, cipher] of body.ciphers.entries()) {
			const perItem = decrypt(cipher.key, key);
			try {
				const decoded = transformItem(cipher, perItem, 'decrypt');
				expect(decoded).toMatchObject(items[index]!);
			} finally {
				perItem.fill(0);
			}
		}
		return new Response(null, { status: 204 });
	});
	try {
		expect(await vault.importVault('bitwardenjson', JSON.stringify({ items }))).toEqual({
			items: 3,
			folders: 0,
			collections: 0,
			attachments: 0,
		});
	} finally {
		vault.dispose();
	}
});
test('empty imports stop before the API while folder-only imports remain valid', async () => {
	let requests = 0;
	const vault = fixture((_path, init) => {
		requests++;
		const body = JSON.parse(String(init.body));
		expect(body.ciphers).toEqual([]);
		expect(body.folders).toHaveLength(1);
		return new Response(null, { status: 204 });
	});
	try {
		await expect(vault.importVault('bitwardenjson', JSON.stringify({ items: [], folders: [] })))
			.rejects.toThrow('Nothing to import.');
		expect(requests).toBe(0);
		expect(await vault.importVault('bitwardenjson', JSON.stringify({ items: [], folders: [{ name: 'Folder only' }] })))
			.toEqual({ items: 0, folders: 1, collections: 0, attachments: 0 });
		expect(requests).toBe(1);
	} finally {
		vault.dispose();
	}
});
test('placeholder-only malformed imports are rejected without false positives for named logins and notes', async () => {
	let requests = 0;
	const vault = fixture(() => {
		requests++;
		return new Response(null, { status: 204 });
	});
	try {
		const badLogin = { type: 1, name: '--', login: { username: null, password: '  ', uris: [] } };
		await expect(vault.importVault('bitwardenjson', JSON.stringify({ items: [badLogin] })))
			.rejects.toThrow('Invalid vault export or import format.');
		expect(requests).toBe(0);
		const validItems = [
			{
				type: 1,
				name: 'Website login',
				login: { username: null, password: null, uris: [{ uri: 'https://example.test' }] },
			},
			{ type: 2, name: 'Secure note', secureNote: { type: 0 }, notes: 'notes without a login password' },
			{ type: 1, name: '', login: { username: null, password: null, uris: [] } },
			{ type: 1, name: '--', login: null },
		];
		await vault.importVault('bitwardenjson', JSON.stringify({ items: validItems }));
		expect(requests).toBe(1);
	} finally {
		vault.dispose();
	}
});
test('Bitwarden JSON imports keep only the five newest password history records', async () => {
	let imported: JsonObject | undefined;
	const vault = fixture((_path, init) => {
		const body = JSON.parse(String(init.body));
		const cipher = body.ciphers[0];
		const perItem = decrypt(cipher.key, key);
		try {
			imported = transformItem(cipher, perItem, 'decrypt');
		} finally {
			perItem.fill(0);
		}
		return new Response(null, { status: 204 });
	});
	const passwordHistory = Array.from({ length: 7 }, (_, index) => ({
		password: `old-${index}`,
		lastUsedDate: `2026-01-0${index + 1}T00:00:00.000Z`,
	}));
	try {
		await vault.importVault(
			'bitwardenjson',
			JSON.stringify({ items: [{ ...item, passwordHistory }] }),
		);
		expect(imported!.passwordHistory).toEqual(passwordHistory.slice(0, 5));
	} finally {
		vault.dispose();
	}
});
test('unified Keeper import selects JSON and CSV exports and sends both through Vaultwarden bulk import', async () => {
	const names: string[] = [];
	const vault = fixture((_path, init) => {
		const body = JSON.parse(String(init.body));
		for (const cipher of body.ciphers as JsonObject[]) {
			const itemKey = decrypt(String(cipher.key), key);
			try {
				names.push(String(transformItem(cipher, itemKey, 'decrypt').name));
			} finally {
				itemKey.fill(0);
			}
		}
		return new Response(null, { status: 204 });
	});
	try {
		const jsonResult = await vault.importVault(
			'keeper',
			JSON.stringify({
				records: [{ title: 'Keeper JSON generic', login: 'alice', password: 'json-secret' }],
			}),
			{ fileName: 'keeper-export.json' },
		);
		const csvResult = await vault.importVault(
			'keeper',
			'Personal,Keeper CSV generic,bob,csv-secret,https://keeper.example.test,Imported by test',
			{ fileName: 'keeper-export.CSV' },
		);
		expect(jsonResult.items).toBe(1);
		expect(csvResult.items).toBe(1);
		expect(names).toEqual(['Keeper JSON generic', 'Keeper CSV generic']);
		await expect(vault.importVault(
			'keeper',
			JSON.stringify({ records: [{ title: 'Content says JSON' }] }),
			{ fileName: 'keeper-export.csv' },
		)).rejects.toThrow('Invalid CSV quoting.');
		await expect(vault.importVault(
			'keeper',
			'Personal,Keeper CSV generic,bob,csv-secret,https://keeper.example.test,Imported by test',
			{ fileName: 'keeper-export.json' },
		)).rejects.toThrow('Invalid Keeper JSON.');
		await expect(vault.importVault(
			'keeper',
			JSON.stringify({ records: [{ title: 'Unsupported extension' }] }),
			{ fileName: 'keeper-export.txt' },
		)).rejects.toThrow('Cannot determine Keeper file type. Use a .csv or .json file.');
	} finally {
		vault.dispose();
	}
});
test('Password Boss JSON and Password Dragon XML dispatch through encrypted Vaultwarden imports', async () => {
	const imported: JsonObject[] = [], folders: string[] = [];
	const vault = fixture((_path, init) => {
		const body = JSON.parse(String(init.body)) as JsonObject;
		for (const folder of body.folders as JsonObject[]) folders.push(decrypt(String(folder.name), key).toString());
		for (const cipher of body.ciphers as JsonObject[]) {
			const cipherKey = decrypt(String(cipher.key), key);
			try {
				imported.push(transformItem(cipher, cipherKey, 'decrypt'));
			} finally {
				cipherKey.fill(0);
			}
		}
		return new Response(null, { status: 204 });
	});
	try {
		const passwordBoss = await vault.importVault(
			'passwordbossjson',
			JSON.stringify([{
				itemType: 'Login',
				itemTypeName: 'Login',
				name: 'Password Boss import',
				folder: 'Password Boss folder',
				username: 'boss-user',
				password: 'boss-secret',
				url: 'https://boss.example.test',
				notes: 'boss note',
				customFields: [{ name: 'Recovery', value: 'boss-recovery' }],
			}]),
		);
		const passwordDragon = await vault.importVault(
			'passworddragonxml',
			`<PasswordManager><record><Category>Password Dragon folder</Category><Account-Name>Password Dragon import</Account-Name>
<User-Id>dragon-user</User-Id><Password>dragon-secret</Password><URL>dragon.example.test</URL>
<Notes>dragon note</Notes><Attribute-1>dragon-recovery</Attribute-1></record></PasswordManager>`,
		);
		expect(passwordBoss).toMatchObject({ items: 1, folders: 1 });
		expect(passwordDragon).toMatchObject({ items: 1, folders: 1 });
		expect(imported.map(value => ({
			name: value.name,
			notes: value.notes,
			username: (value.login as JsonObject).username,
			password: (value.login as JsonObject).password,
			uris: ((value.login as JsonObject).uris as JsonObject[]).map(uri => ({ uri: uri.uri, match: uri.match })),
			fields: value.fields,
		}))).toEqual([
			{
				name: 'Password Boss import',
				notes: 'boss note',
				username: 'boss-user',
				password: 'boss-secret',
				uris: [{ uri: 'https://boss.example.test', match: null }],
				fields: [{ name: 'Recovery', value: 'boss-recovery', type: 0 }],
			},
			{
				name: 'Password Dragon import',
				notes: 'dragon note',
				username: 'dragon-user',
				password: 'dragon-secret',
				uris: [{ uri: 'http://dragon.example.test', match: null }],
				fields: [{ name: 'Attribute-1', value: 'dragon-recovery', type: 0 }],
			},
		]);
		expect(folders).toEqual(['Password Boss folder', 'Password Dragon folder']);
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
test('ZIP exports use the Bitwarden data and attachment layout without a custom manifest', async () => {
	const vault = fixture();
	try {
		const archive = unzipSync(await vault.exportVault('zip'));
		expect(JSON.parse(Buffer.from(archive['data.json']!).toString()).items[0].name).toBe(item.name);
		expect(archive['attachments/']).toBeDefined();
		expect(archive['vw-manifest.json']).toBeUndefined();
	} finally {
		vault.dispose();
	}
});

test('ZIP attachment paths use decrypted item names and Bitwarden duplicate suffixes', async () => {
	const vault = fixture();
	const first = {
		...encryptItem(item, itemKey),
		id: 'first',
		key: encrypt(itemKey, key),
		attachments: [{ id: 'one' }, { id: 'two' }],
	};
	const second = { ...first, id: 'second', attachments: [{ id: 'three' }] };
	vault.snapshot.ciphers = [first, second];
	vault.getAttachment = async (_itemId, attachmentId) => ({
		fileName: 'photo.png',
		contents: Buffer.from(attachmentId),
	});
	try {
		const archive = unzipSync(await vault.exportVault('zip'));
		expect(Object.keys(archive).filter(path => path.startsWith('attachments/'))).toEqual([
			'attachments/',
			'attachments/Example, _quoted_/photo.png',
			'attachments/Example, _quoted_/photo_1.png',
			'attachments/Example, _quoted__1/photo.png',
		]);
	} finally {
		vault.dispose();
	}
});

test('ZIP export skips unavailable attachments and reports the skipped item and attachment IDs', async () => {
	const vault = fixture();
	vault.snapshot.ciphers = [{
		...encryptItem(item, itemKey),
		id: 'item-with-attachments',
		key: encrypt(itemKey, key),
		attachments: [{ id: 'unavailable' }, { id: 'available' }],
	}];
	vault.getAttachment = async (_itemId, attachmentId) => {
		if (attachmentId === 'unavailable') throw new Error('synthetic download failure');
		return { fileName: 'kept.bin', contents: Buffer.from('kept') };
	};
	const skipped: Array<[string, string]> = [];
	try {
		const archive = unzipSync(
			await vault.exportVault('zip', {
				onAttachmentSkipped: (itemId, attachmentId) => skipped.push([itemId, attachmentId]),
			}),
		);
		expect(skipped).toEqual([['item-with-attachments', 'unavailable']]);
		expect(Buffer.from(archive['attachments/Example, _quoted_/kept.bin']!).toString()).toBe('kept');
	} finally {
		vault.dispose();
	}
});

test('organization ZIP export is rejected before making a server request', async () => {
	let calls = 0;
	const vault = fixture(() => {
		calls++;
		return Response.json({});
	});
	await expect(vault.exportVault('zip', { organizationId: 'organization' })).rejects.toThrow(
		'Zip export not supported for organization.',
	);
	expect(calls).toBe(0);
	vault.dispose();
});

test('official ZIP attachment paths map duplicate item names using the _1 suffix', () => {
	const attachments = officialZipAttachments([
		{ ...item, id: 'first' },
		{ ...item, id: 'second' },
	], {
		'attachments/Example, _quoted_/first.bin': Buffer.from('first'),
		'attachments/Example, _quoted__1/second.bin': Buffer.from('second'),
	});
	expect(attachments).toEqual([
		{ itemId: 'first', fileName: 'first.bin', path: 'attachments/Example, _quoted_/first.bin' },
		{ itemId: 'second', fileName: 'second.bin', path: 'attachments/Example, _quoted__1/second.bin' },
	]);
});
