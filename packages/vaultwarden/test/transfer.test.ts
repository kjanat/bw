import { test, expect } from 'bun:test';
import { randomBytes } from 'node:crypto';
import { unzipSync } from 'fflate';
import { VaultwardenClient, type JsonObject } from '#client';
import { VaultService } from '#vault-service';
import { encrypt, decrypt, encryptAttachment, decryptAttachment, deriveKdfKey, deriveMasterKey } from '#crypto';
import { transformItem, encryptItem } from '#item-codec';
import { withImportSync } from '#test/import-server';
import {
	parseCsv,
	writeCsv,
	decryptExportDocument,
	exportVault,
	ImportFailure,
	IncompleteExportError,
	importFormats,
	importVault,
	officialZipAttachments,
} from '#transfer';

const key = Buffer.alloc(64, 6);
const itemKey = Buffer.alloc(64, 7);
test('import formats cover the pinned bw list plus the native ZIP extension', async () => {
	const reference = await Bun.file(
		new URL('../../../docs/reference/bw-import-formats-2026.10.0.json', import.meta.url),
	).json() as { formats: string[] };
	expect([...importFormats].filter(format => format !== 'bitwardenzip').sort().join('\n')).toBe(
		[...reference.formats].sort().join('\n'),
	);
	expect(importFormats).toContain('bitwardenzip');
});
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
const policyOrganization = (id: string, overrides: JsonObject = {}): JsonObject => ({
	id,
	status: 2,
	type: 2,
	enabled: true,
	usePolicies: true,
	isProviderUser: false,
	...overrides,
});
function fixture(handler?: (path: string, init: RequestInit) => Response | Promise<Response>) {
	const snapshot = {
		profile: { id: 'account' },
		folders: [{ id: 'old-folder', name: encrypt(Buffer.from('Folder, name'), key) }],
		collections: [],
		ciphers: [{ ...encryptItem(item, itemKey), key: encrypt(itemKey, key) }],
	};
	const transport = withImportSync((url, init) => handler ? handler(String(url), init) : Response.json({}));
	return new VaultService(new VaultwardenClient('https://example.com', { fetch: transport }), 'access', snapshot, key);
}
test('CSV parser and writer round-trip commas, quoted newlines, escaped quotes, and CRLF', () => {
	const rows = [['name', 'notes', 'password'], ['A, B', 'first\nsecond', '"quoted"'], ['empty', '', '']];
	expect(parseCsv(writeCsv(rows))).toEqual(rows);
	expect(() => parseCsv('name\n"unfinished')).toThrow('Unterminated');
	expect(() => parseCsv('"closed"junk')).toThrow('quoting');
});
test('export KDF salts are case-sensitive while account email salts normalize', async () => {
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
test('exports redact passkey private keys when viewPassword is false', async () => {
	const passkeyItem = {
		...encryptItem({
			...item,
			login: { fido2Credentials: [{ credentialId: 'credential', keyValue: 'synthetic-private-key' }] },
		}, itemKey),
		key: encrypt(itemKey, key),
		viewPassword: false,
	};
	const vault = fixture();
	vault.snapshot.ciphers = [passkeyItem];
	try {
		const plain = JSON.parse((await vault.exportVault('json')).toString());
		expect(plain.items[0].login.fido2Credentials[0].keyValue).toBeNull();
		const encrypted = JSON.parse((await vault.exportVault('encrypted_json')).toString());
		const clear = await decryptExportDocument(encrypted, key);
		expect(((clear.items as JsonObject[])[0]!.login as JsonObject).fido2Credentials)
			.toEqual([{ credentialId: 'credential', keyValue: null }]);
		const csv = (await vault.exportVault('csv')).toString();
		expect(csv).not.toContain('synthetic-private-key');
	} finally {
		vault.dispose();
	}
});
test('Bitwarden CSV export serializes URI arrays with bw flat comma joining', async () => {
	const vault = fixture();
	try {
		const rows = parseCsv((await vault.exportVault('csv')).toString());
		expect(rows[1]![8]).toBe('https://example.com/a,b,https://second.example.com');
	} finally {
		vault.dispose();
	}
});
test('Bitwarden CSV export resolves folder IDs regardless of letter case', async () => {
	const vault = fixture();
	try {
		(vault.snapshot.folders as JsonObject[])[0]!.id = 'OLD-FOLDER';
		const rows = parseCsv((await vault.exportVault('csv')).toString());
		expect(rows[1]![0]).toBe('Folder, name');
	} finally {
		vault.dispose();
	}
});
test('production CSV export limits output to login and secure-note items while JSON includes newer Vaultwarden types', async () => {
	const vault = fixture();
	const entries = [
		{ type: 1, name: 'login', login: {} },
		{ type: 2, name: 'note', secureNote: { type: 0 } },
		{ type: 6, name: 'bank', bankAccount: { accountNumber: 'bank-number' } },
		{ type: 7, name: 'license', driversLicense: { licenseNumber: 'license-number' } },
		{ type: 8, name: 'passport', passport: { passportNumber: 'passport-number' } },
	];
	vault.snapshot.ciphers = entries.map(value => ({
		...encryptItem(value, itemKey),
		id: value.name,
		key: encrypt(itemKey, key),
	}));
	try {
		const csv = parseCsv((await vault.exportVault('csv')).toString());
		expect(csv.slice(1).map(row => row[3])).toEqual(['login', 'note']);
		const json = JSON.parse((await vault.exportVault('json')).toString());
		expect(json.items.map((value: JsonObject) => value.name)).toEqual(entries.map(value => value.name));
	} finally {
		vault.dispose();
	}
});
test('personal exports are blocked by an active organization policy, except for owners', async () => {
	let requests = 0;
	const vault = fixture(() => {
		requests++;
		return Response.json({ ciphers: [] });
	});
	vault.snapshot.profile = {
		id: 'account',
		organizations: [policyOrganization('organization', { role: 2 })],
	};
	vault.snapshot.policies = [{ organizationId: 'ORGANIZATION', type: 10, enabled: true }];
	try {
		await expect(vault.exportVault('json')).rejects.toThrow(
			'One or more organization policies prevents you from exporting your personal vault.',
		);
		expect(requests).toBe(0);
		(vault.snapshot.profile as JsonObject).organizations = [
			policyOrganization('organization', { type: 0, role: 0 }),
		];
		const ownerExport = JSON.parse((await vault.exportVault('json')).toString());
		expect(ownerExport.encrypted).toBe(false);
	} finally {
		vault.dispose();
	}
});
test('personal export policy from accepted organization sync data blocks the request in the library', async () => {
	let requests = 0;
	const vault = fixture(() => {
		requests++;
		return Response.json({ ciphers: [] });
	});
	vault.snapshot.profile = {
		id: 'account',
		organizations: [policyOrganization('organization', { status: 1, role: 2 })],
	};
	vault.snapshot.policiesNew = [{ organizationId: 'organization', type: 10, enabled: true }];
	try {
		await expect(vault.exportVault('json')).rejects.toThrow(
			'One or more organization policies prevents you from exporting your personal vault.',
		);
		expect(requests).toBe(0);
	} finally {
		vault.dispose();
	}
});
test('personal export policy exemptions match the SDK for administrators and provider users', async () => {
	for (
		const organization of [
			policyOrganization('organization', { type: 1, role: 1 }),
			policyOrganization('organization', { isProviderUser: true }),
		]
	) {
		const vault = fixture(() => Response.json({ ciphers: [] }));
		vault.snapshot.profile = { id: 'account', organizations: [organization] };
		vault.snapshot.policies = [{ organizationId: 'organization', type: 10, enabled: true }];
		try {
			const exported = JSON.parse((await vault.exportVault('json')).toString());
			expect(exported.encrypted).toBe(false);
		} finally {
			vault.dispose();
		}
	}
});
test('personal export policy without a synced organization context is enforced by default', async () => {
	let requests = 0;
	const vault = fixture(() => {
		requests++;
		return Response.json({ ciphers: [] });
	});
	vault.snapshot.policiesNew = [{ organizationId: 'not-synced', type: 10, enabled: true }];
	try {
		await expect(vault.exportVault('json')).rejects.toThrow(
			'One or more organization policies prevents you from exporting your personal vault.',
		);
		expect(requests).toBe(0);
	} finally {
		vault.dispose();
	}
});
test('personal exports are allowed when the organization disables policy enforcement', async () => {
	let requests = 0;
	const vault = fixture(() => {
		requests++;
		return Response.json({ ciphers: [] });
	});
	vault.snapshot.profile = {
		id: 'account',
		organizations: [policyOrganization('organization', { role: 2, usePolicies: false })],
	};
	vault.snapshot.policies = [{ organizationId: 'organization', type: 10, enabled: true }];
	try {
		const exported = JSON.parse((await vault.exportVault('json')).toString());
		expect(exported.encrypted).toBe(false);
		expect(requests).toBe(0);
	} finally {
		vault.dispose();
	}
});
test('exports omit cipher types restricted by organization policy', async () => {
	const vault = fixture();
	vault.snapshot.profile = {
		id: 'account',
		organizations: [policyOrganization('organization', { role: 2 })],
	};
	vault.snapshot.policies = [{ organizationId: 'organization', type: 15, enabled: true, data: [1] }];
	vault.snapshot.ciphers = [
		...vault.snapshot.ciphers as JsonObject[],
		{ ...encryptItem({ id: 'allowed-card', type: 3, name: 'Allowed card' }, itemKey), key: encrypt(itemKey, key) },
	];
	try {
		const exported = JSON.parse((await vault.exportVault('json')).toString());
		expect(exported.items.map((value: JsonObject) => value.id)).toEqual(['allowed-card']);
	} finally {
		vault.dispose();
	}
});

test('ZIP uses one policy-filtered item set for JSON and attachment contents', async () => {
	const vault = fixture();
	vault.snapshot.profile = { id: 'account', organizations: [policyOrganization('organization')] };
	vault.snapshot.policiesNew = [{ organizationId: 'organization', type: 15, enabled: true, data: [1] }];
	vault.snapshot.ciphers = [
		{
			...encryptItem({ ...item, id: 'restricted' }, itemKey),
			key: encrypt(itemKey, key),
			attachments: [{ id: 'must-not-export' }],
		},
		{
			...encryptItem({ type: 3, name: 'Allowed', id: 'allowed', card: { number: '4111111111111111' } }, itemKey),
			key: encrypt(itemKey, key),
			attachments: [{ id: 'allowed-file' }],
		},
	];
	const downloaded: string[] = [];
	vault.getAttachment = async () => {
		throw new Error('Backup must use exact IDs.');
	};
	vault.getAttachmentById = async (itemId, id) => {
		downloaded.push(itemId + '/' + id);
		return { fileName: 'safe.txt', contents: Buffer.from('allowed-body') };
	};
	try {
		const archive = unzipSync(await vault.exportVault('zip'));
		expect(JSON.parse(Buffer.from(archive['data.json']!).toString()).items.map((item: JsonObject) => item.id)).toEqual([
			'allowed',
		]);
		expect(downloaded).toEqual(['allowed/allowed-file']);
		expect(Object.keys(archive).filter(path => path.startsWith('attachments/') && !path.endsWith('/'))).toEqual([
			'attachments/Allowed/safe.txt',
		]);
	} finally {
		vault.dispose();
	}
});
test('organization exports match uppercase organization IDs against synced cipher and collection IDs', async () => {
	const organizationId = '11111111-1111-1111-1111-111111111111';
	const organizationKey = Buffer.alloc(64, 8);
	const orgItem = {
		...encryptItem({ id: 'organization-item', type: 1, name: 'Organization item' }, itemKey),
		id: 'organization-item',
		organizationId,
		collectionIds: ['organization-collection'],
		key: encrypt(itemKey, organizationKey),
	};
	const vault = fixture((path) => {
		expect(path).toContain(`/api/organizations/${organizationId.toUpperCase()}/export`);
		return Response.json({
			ciphers: [orgItem],
			collections: [{
				id: 'organization-collection',
				organizationId,
				name: encrypt(Buffer.from('Organization collection'), organizationKey),
			}],
		});
	});
	try {
		const document = JSON.parse((await exportVault(
			vault,
			{ user: key, organization: () => organizationKey },
			'json',
			{ organizationId: organizationId.toUpperCase() },
		)).toString());
		expect(document.items.map((value: JsonObject) => value.id)).toEqual(['organization-item']);
		expect(document.collections.map((value: JsonObject) => value.id)).toEqual(['organization-collection']);
	} finally {
		vault.dispose();
		organizationKey.fill(0);
	}
});
test('JSON export includes bank account, driver license, and passport sections', async () => {
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
	const folderId = '11111111-1111-1111-1111-111111111111';
	const vault = fixture((path, init) => {
		requests++;
		expect(path).toEndWith('/api/ciphers/import');
		const body = JSON.parse(String(init.body));
		expect(body.folderRelationships).toEqual([{ key: 0, value: 0 }]);
		expect(body.folders[0].id).toBe(folderId);
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
				JSON.stringify({
					encrypted: false,
					folders: [{ id: folderId, name: 'Folder' }],
					items: [{ ...item, folderId }],
				}),
			),
		).toEqual({ items: 1, folders: 1, collections: 0, attachments: 0 });
		expect(requests).toBe(1);
	} finally {
		vault.dispose();
	}
});
test('bulk JSON import drops invalid source group IDs before sending the request', async () => {
	let imported: JsonObject | undefined;
	const vault = fixture((_path, init) => {
		imported = JSON.parse(String(init.body));
		return new Response(null, { status: 204 });
	});
	try {
		await vault.importVault(
			'bitwardenjson',
			JSON.stringify({ encrypted: false, folders: [{ id: 'external-folder-id', name: 'Folder' }], items: [] }),
		);
		expect((imported!.folders as JsonObject[])[0]!.id).toBeUndefined();
	} finally {
		vault.dispose();
	}
});
test('Bitwarden JSON import replaces whitespace-only cipher names with the default', async () => {
	let imported: JsonObject | undefined;
	const vault = fixture((_path, init) => {
		imported = JSON.parse(String(init.body));
		return new Response(null, { status: 204 });
	});
	try {
		await vault.importVault(
			'bitwardenjson',
			JSON.stringify({ encrypted: false, items: [{ type: 1, name: '   ', login: { password: 'secret' } }] }),
		);
		const cipher = (imported!.ciphers as JsonObject[])[0]!;
		const importedKey = decrypt(String(cipher.key), key);
		try {
			expect(transformItem(cipher, importedKey, 'decrypt').name).toBe('--');
		} finally {
			importedKey.fill(0);
		}
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
	const vault = fixture((path, init) => {
		if (path.endsWith('/api/config')) return Response.json({ server: { name: 'Vaultwarden' } });
		if (path.endsWith('/api/version')) return Response.json('1.37.4');
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
test('JSON import rejects newer cipher types on Vaultwarden 1.36 before posting an import', async () => {
	const requests: string[] = [];
	const vault = fixture((path, init) => {
		requests.push(`${init.method ?? 'GET'} ${new URL(path).pathname}`);
		if (path.endsWith('/api/config')) return Response.json({ server: { name: 'Vaultwarden' } });
		if (path.endsWith('/api/version')) return Response.json('1.36.0');
		throw new Error(`Unexpected request: ${path}`);
	});
	try {
		await expect(
			vault.importVault(
				'bitwardenjson',
				JSON.stringify({ items: [{ type: 6, name: 'Bank', bankAccount: { accountNumber: 'bank-number' } }] }),
			),
		).rejects.toThrow('bank account requires Vaultwarden 1.37.4 or newer; this server reports 1.36.0');
		expect(requests).toEqual(['GET /api/config', 'GET /api/version']);
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
			{ type: 1, name: '--', login: {} },
		];
		await vault.importVault('bitwardenjson', JSON.stringify({ items: validItems }));
		expect(requests).toBe(1);
	} finally {
		vault.dispose();
	}
});
test('Bitwarden JSON imports include only the five newest password history records', async () => {
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
test('organization import resolves collection IDs case-insensitively and includes Vaultwarden 1.36 membership arrays', async () => {
	let calls = 0;
	const collectionId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
	const vault = fixture((path, init) => {
		if (path.endsWith('/api/config')) return Response.json({ server: { name: 'Vaultwarden' } });
		if (path.endsWith('/api/version')) return Response.json('1.36.0');
		calls++;
		expect(path).toContain('/api/ciphers/import-organization?organizationId=organization');
		const body = JSON.parse(String(init.body));
		expect(body.collections[0]).toMatchObject({ externalId: null, groups: [], users: [] });
		expect(body.collections[0].id).toBe(collectionId);
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
					collections: [{ id: collectionId.toUpperCase(), name: 'Collection' }],
					items: [{ ...item, collectionIds: [collectionId] }],
				}),
				{ organizationId: 'organization' },
			),
		).toEqual({ items: 1, folders: 0, collections: 1, attachments: 0 });
		expect(calls).toBe(1);
	} finally {
		vault.dispose();
	}
});
test('Vaultwarden organization import rejects collectionless items when membership is not full access', async () => {
	const requests: string[] = [];
	const vault = new VaultService(
		new VaultwardenClient('https://example.com', {
			fetch: withImportSync(async (url: unknown) => {
				requests.push(String(url));
				if (String(url).endsWith('/api/config')) return Response.json({ server: { name: 'Vaultwarden' } });
				if (String(url).endsWith('/api/version')) return Response.json('1.37.4');
				throw new Error(`Unexpected request: ${url}`);
			}),
		}),
		'access',
		{
			profile: {
				id: 'account',
				organizations: [{ id: 'organization', status: 2, type: 2, permissions: { editAnyCollection: false } }],
			},
			ciphers: [],
			folders: [],
			collections: [],
		},
		key,
	);
	try {
		await expect(importVault(
			vault,
			{ user: key, organization: () => key },
			'bitwardenjson',
			JSON.stringify({ items: [{ type: 1, name: 'Unassigned', login: { password: 'secret' } }] }),
			{ organizationId: 'organization' },
		)).rejects.toMatchObject({ status: 400 });
		expect(requests).toEqual(['https://example.com/api/config', 'https://example.com/api/version']);
	} finally {
		vault.dispose();
	}
});
test('Vaultwarden 1.36 allows collectionless organization imports for regular members', async () => {
	const requests: string[] = [];
	const vault = new VaultService(
		new VaultwardenClient('https://example.com', {
			fetch: withImportSync(async (url: unknown) => {
				requests.push(String(url));
				if (String(url).endsWith('/api/config')) return Response.json({ server: { name: 'Vaultwarden' } });
				if (String(url).endsWith('/api/version')) return Response.json('1.36.0');
				if (String(url).includes('/api/ciphers/import-organization')) return new Response(null, { status: 204 });
				throw new Error(`Unexpected request: ${url}`);
			}),
		}),
		'access',
		{
			profile: {
				id: 'account',
				organizations: [{ id: 'organization', status: 2, type: 2, permissions: { editAnyCollection: false } }],
			},
			ciphers: [],
			folders: [],
			collections: [],
		},
		key,
	);
	try {
		expect(
			await importVault(
				vault,
				{ user: key, organization: () => key },
				'bitwardenjson',
				JSON.stringify({ items: [{ type: 1, name: 'Unassigned', login: { password: 'secret' } }] }),
				{ organizationId: 'organization' },
			),
		).toEqual({ items: 1, folders: 0, collections: 0, attachments: 0 });
		expect(requests).toEqual([
			'https://example.com/api/config',
			'https://example.com/api/version',
			'https://example.com/api/ciphers/import-organization?organizationId=organization',
		]);
	} finally {
		vault.dispose();
	}
});
test('Vaultwarden full-access managers can import collectionless organization items', async () => {
	const requests: string[] = [];
	const vault = new VaultService(
		new VaultwardenClient('https://example.com', {
			fetch: withImportSync(async (url: unknown) => {
				requests.push(String(url));
				if (String(url).endsWith('/api/config')) return Response.json({ server: { name: 'Vaultwarden' } });
				if (String(url).endsWith('/api/version')) return Response.json('1.37.4');
				if (String(url).includes('/api/ciphers/import-organization')) return new Response(null, { status: 204 });
				throw new Error(`Unexpected request: ${url}`);
			}),
		}),
		'access',
		{
			profile: {
				id: 'account',
				organizations: [{ id: 'organization', status: 2, type: 4, permissions: { editAnyCollection: true } }],
			},
			ciphers: [],
			folders: [],
			collections: [],
		},
		key,
	);
	try {
		expect(
			await importVault(
				vault,
				{ user: key, organization: () => key },
				'bitwardenjson',
				JSON.stringify({ items: [{ type: 1, name: 'Unassigned', login: { password: 'secret' } }] }),
				{ organizationId: 'organization' },
			),
		).toEqual({ items: 1, folders: 0, collections: 0, attachments: 0 });
		expect(requests).toEqual([
			'https://example.com/api/config',
			'https://example.com/api/version',
			'https://example.com/api/ciphers/import-organization?organizationId=organization',
		]);
	} finally {
		vault.dispose();
	}
});
test('Vaultwarden 1.37.4 organization imports preflight existing and new collection permissions', async () => {
	const existingId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
	for (
		const [type, accessAll, readOnly, expectedAllowed] of [
			[2, false, true, false],
			[2, false, false, true],
			[3, false, false, true],
			[3, true, false, true],
		] as const
	) {
		const requests: string[] = [];
		const vault = new VaultService(
			new VaultwardenClient('https://example.com', {
				fetch: withImportSync(async (url: unknown) => {
					const path = String(url);
					requests.push(path);
					if (path.endsWith('/api/config')) return Response.json({ server: { name: 'Vaultwarden' } });
					if (path.endsWith('/api/version')) return Response.json('1.37.4');
					if (path.includes('/api/ciphers/import-organization')) return new Response(null, { status: 204 });
					throw new Error(`Unexpected request: ${path}`);
				}),
			}),
			'access',
			{
				profile: { id: 'account', organizations: [{ id: 'organization', status: 2, type, accessAll }] },
				ciphers: [],
				folders: [],
				collections: [{ id: existingId, organizationId: 'organization', readOnly }],
			},
			key,
		);
		try {
			const input = JSON.stringify({
				collections: [{ id: existingId, name: 'Existing' }],
				items: [{ ...item, collectionIds: [existingId] }],
			});
			if (expectedAllowed) {
				await importVault(vault, { user: key, organization: () => key }, 'bitwardenjson', input, {
					organizationId: 'organization',
				});
				expect(requests.some(path => path.includes('/api/ciphers/import-organization'))).toBe(true);
			} else {
				await expect(importVault(vault, { user: key, organization: () => key }, 'bitwardenjson', input, {
					organizationId: 'organization',
				})).rejects.toMatchObject({ status: 400 });
				expect(requests.some(path => path.includes('/api/ciphers/import-organization'))).toBe(false);
			}
		} finally {
			vault.dispose();
		}
	}
	{
		const requests: string[] = [];
		const vault = new VaultService(
			new VaultwardenClient('https://example.com', {
				fetch: withImportSync(async (url: unknown) => {
					const path = String(url);
					requests.push(path);
					if (path.endsWith('/api/config')) return Response.json({ server: { name: 'Vaultwarden' } });
					if (path.endsWith('/api/version')) return Response.json('1.37.4');
					throw new Error(`Unexpected request: ${path}`);
				}),
			}),
			'access',
			{
				profile: { id: 'account', organizations: [{ id: 'organization', status: 2, type: 3, accessAll: false }] },
				ciphers: [],
				folders: [],
				collections: [],
			},
			key,
		);
		try {
			await expect(importVault(
				vault,
				{ user: key, organization: () => key },
				'bitwardenjson',
				JSON.stringify({ collections: [{ name: 'New' }], items: [{ ...item, collectionIds: ['new'] }] }),
				{ organizationId: 'organization' },
			)).rejects.toMatchObject({ status: 400 });
			expect(requests.some(path => path.includes('/api/ciphers/import-organization'))).toBe(false);
		} finally {
			vault.dispose();
		}
	}
	const unknownRoleRequests: string[] = [];
	const unknownRoleVault = new VaultService(
		new VaultwardenClient('https://example.com', {
			fetch: withImportSync(async (url: unknown) => {
				const path = String(url);
				unknownRoleRequests.push(path);
				if (path.endsWith('/api/config')) return Response.json({ server: { name: 'Vaultwarden' } });
				if (path.endsWith('/api/version')) return Response.json('1.37.4');
				throw new Error(`Unexpected request: ${path}`);
			}),
		}),
		'access',
		{
			profile: { id: 'account', organizations: [{ id: 'organization', status: 2, type: 99, accessAll: false }] },
			ciphers: [],
			folders: [],
			collections: [],
		},
		key,
	);
	try {
		await expect(importVault(
			unknownRoleVault,
			{ user: key, organization: () => key },
			'bitwardenjson',
			JSON.stringify({ collections: [{ name: 'New' }], items: [{ ...item, collectionIds: ['new'] }] }),
			{ organizationId: 'organization' },
		)).rejects.toMatchObject({ status: 400 });
		expect(unknownRoleRequests.some(path => path.includes('/api/ciphers/import-organization'))).toBe(false);
	} finally {
		unknownRoleVault.dispose();
	}
});
test('Bitwarden CSV imports ignore organization favorites and import personal favorites', async () => {
	for (const [organizationId, favorite] of [[undefined, true], ['organization', false]] as const) {
		let imported: JsonObject | undefined;
		const vault = fixture((path, init) => {
			if (path.endsWith('/api/config')) return Response.json({ server: { name: 'Bitwarden' } });
			expect(path).toContain(
				organizationId ? '/ciphers/import-organization?organizationId=organization' : '/ciphers/import',
			);
			imported = JSON.parse(String(init.body));
			return new Response(null, { status: 204 });
		});
		try {
			await importVault(
				vault,
				{ user: key, organization: () => key },
				'bitwardencsv',
				'name,favorite,login_username,login_password\nFavorite item,1,user,secret\n',
				organizationId ? { organizationId } : undefined,
			);
			const cipher = (imported!.ciphers as JsonObject[])[0]!;
			expect(cipher.favorite).toBe(favorite);
			const importedKey = decrypt(String(cipher.key), key);
			try {
				const item = transformItem(cipher, importedKey, 'decrypt');
				expect((item.login as JsonObject).uris).toBeNull();
			} finally {
				importedKey.fill(0);
			}
		} finally {
			vault.dispose();
		}
	}
});
test('Bitwarden CSV handles blank rows and tolerates short or extra fields like bw', async () => {
	let imported: JsonObject | undefined;
	const vault = fixture((_path, init) => {
		imported = JSON.parse(String(init.body));
		return new Response(null, { status: 204 });
	});
	try {
		const csv = 'name,login_password\nFirst,secret\n\nMiddle,secret\nExtra,secret,ignored\nShort';
		await importVault(vault, { user: key, organization: () => key }, 'bitwardencsv', csv);
		const ciphers = imported!.ciphers as JsonObject[];
		expect(ciphers).toHaveLength(5);
		const decoded = ciphers.map(cipher => {
			const cipherKey = decrypt(String(cipher.key), key);
			try {
				return transformItem(cipher, cipherKey, 'decrypt');
			} finally {
				cipherKey.fill(0);
			}
		});
		expect(decoded.map(cipher => cipher.name)).toEqual(['First', '--', 'Middle', 'Extra', 'Short']);
		expect(decoded[1]!.login).toMatchObject({ username: null, password: null });
		expect((decoded[3]!.login as JsonObject).password).toBe('secret');
		expect((decoded[4]!.login as JsonObject).password).toBeNull();
	} finally {
		vault.dispose();
	}
});
test('Bitwarden CSV import includes significant whitespace at the end of the source', async () => {
	let imported: JsonObject | undefined;
	const vault = fixture((_path, init) => {
		imported = JSON.parse(String(init.body));
		return new Response(null, { status: 204 });
	});
	try {
		await importVault(
			vault,
			{ user: key, organization: () => key },
			'bitwardencsv',
			'name,login_password\nItem,secret ',
		);
		const cipher = (imported!.ciphers as JsonObject[])[0]!;
		const cipherKey = decrypt(String(cipher.key), key);
		try {
			expect((transformItem(cipher, cipherKey, 'decrypt').login as JsonObject).password).toBe('secret ');
		} finally {
			cipherKey.fill(0);
		}
	} finally {
		vault.dispose();
	}
});
test('Bitwarden CSV renames duplicate headers like Papa Parse in bw', async () => {
	let imported: JsonObject | undefined;
	const vault = fixture((_path, init) => {
		imported = JSON.parse(String(init.body));
		return new Response(null, { status: 204 });
	});
	try {
		await importVault(
			vault,
			{ user: key, organization: () => key },
			'bitwardencsv',
			'name,login_password,login_password\nItem,primary,ignored\n',
		);
		const cipher = (imported!.ciphers as JsonObject[])[0]!;
		const cipherKey = decrypt(String(cipher.key), key);
		try {
			expect((transformItem(cipher, cipherKey, 'decrypt').login as JsonObject).password).toBe('primary');
		} finally {
			cipherKey.fill(0);
		}
	} finally {
		vault.dispose();
	}
});
test('Bitwarden CSV auto-detects delimiters for files and URI lists like Papa Parse in bw', async () => {
	let imported: JsonObject | undefined;
	const vault = fixture((_path, init) => {
		imported = JSON.parse(String(init.body));
		return new Response(null, { status: 204 });
	});
	try {
		await importVault(
			vault,
			{ user: key, organization: () => key },
			'bitwardencsv',
			'name;login_uri;login_password\nItem;first.example|second.example;secret\n',
		);
		const cipher = (imported!.ciphers as JsonObject[])[0]!;
		const cipherKey = decrypt(String(cipher.key), key);
		try {
			const decoded = transformItem(cipher, cipherKey, 'decrypt');
			expect((decoded.login as JsonObject).uris).toMatchObject([
				{ uri: 'http://first.example' },
				{ uri: 'http://second.example' },
			]);
		} finally {
			cipherKey.fill(0);
		}
	} finally {
		vault.dispose();
	}
});
test('Bitwarden organization CSV imports ignore personal folder values without collections', async () => {
	let imported: JsonObject | undefined;
	const vault = fixture((path, init) => {
		if (path.endsWith('/api/config')) return Response.json({ server: { name: 'Bitwarden' } });
		imported = JSON.parse(String(init.body));
		return new Response(null, { status: 204 });
	});
	try {
		expect(
			await importVault(
				vault,
				{ user: key, organization: () => key },
				'bitwardencsv',
				'name,folder,collections\nItem,PersonalFolder,\n',
				{ organizationId: 'organization' },
			),
		).toEqual({ items: 1, folders: 0, collections: 0, attachments: 0 });
		expect(imported!.collections).toEqual([]);
		expect((imported!.ciphers as JsonObject[])[0]!.collectionIds).toBeUndefined();
	} finally {
		vault.dispose();
	}
});
test('Bitwarden CSV normalizes folder paths and creates parent folder or collection groups', async () => {
	let personalBody: JsonObject | undefined;
	const personal = fixture((_path, init) => {
		personalBody = JSON.parse(String(init.body));
		return new Response(null, { status: 204 });
	});
	try {
		await importVault(
			personal,
			{ user: key, organization: () => key },
			'bitwardencsv',
			writeCsv([
				['name', 'folder', 'login_password'],
				['Nested item', '\\\\Work\\Finance', 'secret'],
				['Unfiled item', '  ', 'secret'],
			]),
		);
		const folders = personalBody!.folders as JsonObject[];
		expect(folders.map(folder => decrypt(String(folder.name), key).toString())).toEqual([
			'Work/Finance',
			'Work',
		]);
		expect(personalBody!.folderRelationships).toEqual([{ key: 0, value: 0 }]);
	} finally {
		personal.dispose();
	}

	let organizationBody: JsonObject | undefined;
	const organization = fixture((path, init) => {
		if (path.endsWith('/api/config')) return Response.json({ server: { name: 'Bitwarden' } });
		organizationBody = JSON.parse(String(init.body));
		return new Response(null, { status: 204 });
	});
	try {
		await importVault(
			organization,
			{ user: key, organization: () => key },
			'bitwardencsv',
			writeCsv([
				['name', 'collections', 'login_password'],
				['Shared item', '/Org\\Team, ,Other/Child', 'secret'],
			]),
			{ organizationId: 'organization' },
		);
		const collections = organizationBody!.collections as JsonObject[];
		expect(collections.map(collection => decrypt(String(collection.name), key).toString())).toEqual([
			'Org/Team',
			'Org',
			'Other/Child',
			'Other',
		]);
		expect(organizationBody!.collectionRelationships).toEqual([{ key: 0, value: 0 }, { key: 0, value: 2 }]);
	} finally {
		organization.dispose();
	}
});
test('Bitwarden CSV archived dates ignore whitespace and serialize like importer Date values', async () => {
	let imported: JsonObject | undefined;
	const vault = fixture((_path, init) => {
		imported = JSON.parse(String(init.body));
		return new Response(null, { status: 204 });
	});
	try {
		await importVault(
			vault,
			{ user: key, organization: () => key },
			'bitwardencsv',
			writeCsv([
				['name', 'archivedDate'],
				['Whitespace date', '  '],
				['Invalid date', 'not-a-date'],
				['Valid date', '2024-05-01T12:30:00.000Z'],
			]),
		);
		expect((imported!.ciphers as JsonObject[]).map(cipher => cipher.archivedDate)).toEqual([
			null,
			null,
			'2024-05-01T12:30:00.000Z',
		]);
	} finally {
		vault.dispose();
	}
});
test('Bitwarden CSV import defaults blank names instead of using title or URL columns', async () => {
	let imported: JsonObject | undefined;
	const vault = fixture((_path, init) => {
		imported = JSON.parse(String(init.body));
		return new Response(null, { status: 204 });
	});
	try {
		await importVault(
			vault,
			{ user: key, organization: () => key },
			'bitwardencsv',
			'name,title,url,login_password\n ,Title fallback,https://url-fallback.example,secret\n',
		);
		const cipher = (imported!.ciphers as JsonObject[])[0]!;
		const importedKey = decrypt(String(cipher.key), key);
		try {
			expect(decrypt(String(cipher.name), importedKey).toString()).toBe('--');
		} finally {
			importedKey.fill(0);
		}
	} finally {
		vault.dispose();
	}
});
test('Bitwarden CSV imports login data without a name column using the default name', async () => {
	let imported: JsonObject | undefined;
	const vault = fixture((_path, init) => {
		imported = JSON.parse(String(init.body));
		return new Response(null, { status: 204 });
	});
	try {
		await importVault(vault, { user: key, organization: () => key }, 'bitwardencsv', 'login_password\nsecret\n');
		const cipher = (imported!.ciphers as JsonObject[])[0]!;
		const cipherKey = decrypt(String(cipher.key), key);
		try {
			const decoded = transformItem(cipher, cipherKey, 'decrypt');
			expect(decoded.name).toBe('--');
			expect((decoded.login as JsonObject).password).toBe('secret');
		} finally {
			cipherKey.fill(0);
		}
	} finally {
		vault.dispose();
	}
});
test('Bitwarden CSV import follows native field defaults and URI coercions', async () => {
	let imported: JsonObject | undefined;
	const vault = fixture((_path, init) => {
		imported = JSON.parse(String(init.body));
		return new Response(null, { status: 204 });
	});
	try {
		await importVault(
			vault,
			{ user: key, organization: () => key },
			'bitwardencsv',
			'name,notes,note,extra,favorite,reprompt,fields,login_uri,uri,url,login_username,username,login_password,password,login_totp,totp\n'
				+ 'Item,,alias-note,alias-extra, ,1.5,"User: first\rRecovery: second",,example.com,ignored.example,,fallback-user,,secret,,fallback-totp\n',
		);
		const cipher = (imported!.ciphers as JsonObject[])[0]!;
		const importedKey = decrypt(String(cipher.key), key);
		try {
			const item = transformItem(cipher, importedKey, 'decrypt');
			expect(item).toMatchObject({
				name: 'Item',
				notes: null,
				favorite: false,
				reprompt: 1,
				fields: [
					{ name: 'User', value: 'first', type: 0 },
					{ name: 'Recovery', value: 'second', type: 0 },
				],
				login: {
					username: 'fallback-user',
					password: 'secret',
					totp: 'fallback-totp',
					uris: [{ uri: 'http://example.com' }],
				},
			});
		} finally {
			importedKey.fill(0);
		}
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
	vault.getAttachmentById = async (_itemId, attachmentId) => ({
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

test('ZIP export rejects duplicate item names when only one item has attachments', async () => {
	const vault = fixture();
	vault.snapshot.ciphers = [
		{ ...encryptItem(item, itemKey), id: 'without-attachment', key: encrypt(itemKey, key), attachments: [] },
		{ ...encryptItem(item, itemKey), id: 'with-attachment', key: encrypt(itemKey, key), attachments: [{ id: 'file' }] },
	];
	let downloads = 0;
	vault.getAttachmentById = async () => {
		downloads++;
		return { fileName: 'photo.png', contents: Buffer.from('file') };
	};
	try {
		await expect(vault.exportVault('zip')).rejects.toThrow('ambiguous');
		expect(downloads).toBe(0);
	} finally {
		vault.dispose();
	}
});

test('ZIP export rejects missing attachments by default and supports explicit partial backups with notices', async () => {
	const vault = fixture();
	vault.snapshot.ciphers = [{
		...encryptItem(item, itemKey),
		id: 'item-with-attachments',
		key: encrypt(itemKey, key),
		attachments: [{ id: 'unavailable' }, { id: 'available' }],
	}];
	vault.getAttachmentById = async (_itemId, attachmentId) => {
		if (attachmentId === 'unavailable') throw new Error('synthetic download failure');
		return { fileName: 'attachment.bin', contents: Buffer.from('attachment-bytes') };
	};
	const skipped: Array<[string, string]> = [];
	try {
		await expect(vault.exportVault('zip', { allowPartial: true })).rejects.toThrow('attachment-skip callback');
		await expect(vault.exportVault('json', { allowPartial: true })).rejects.toThrow('only available for ZIP');
		try {
			await vault.exportVault('zip', { onAttachmentSkipped: (itemId, id) => skipped.push([itemId, id]) });
			throw new Error('Incomplete backup was accepted.');
		} catch (error) {
			expect(error).toBeInstanceOf(IncompleteExportError);
			expect((error as IncompleteExportError).skippedAttachments).toEqual([{
				itemId: 'item-with-attachments',
				attachmentId: 'unavailable',
			}]);
		}
		expect(skipped).toEqual([['item-with-attachments', 'unavailable']]);
		skipped.length = 0;
		const archive = unzipSync(
			await vault.exportVault('zip', {
				allowPartial: true,
				onAttachmentSkipped: (itemId, attachmentId) => skipped.push([itemId, attachmentId]),
			}),
		);
		expect(skipped).toEqual([['item-with-attachments', 'unavailable']]);
		expect(Buffer.from(archive['attachments/Example, _quoted_/attachment.bin']!).toString()).toBe('attachment-bytes');
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

test('official ZIP import accepts items with omitted or null attachment metadata', () => {
	for (
		const itemWithoutAttachments of [
			{ ...item, id: 'without-attachment', attachments: undefined },
			{ ...item, id: 'without-attachment', attachments: null },
		]
	) {
		const attachments = officialZipAttachments([
			itemWithoutAttachments,
		], {
			'attachments/Example, _quoted_/only-file.bin': Buffer.from('synthetic file'),
		});
		expect(attachments).toEqual([{
			itemId: 'without-attachment',
			fileName: 'only-file.bin',
			path: 'attachments/Example, _quoted_/only-file.bin',
		}]);
	}
});

test('official ZIP import refuses duplicate-name attachment paths when an attachment folder is missing', () => {
	expect(() =>
		officialZipAttachments([
			{ ...item, id: 'first' },
			{ ...item, id: 'second' },
		], {
			'attachments/Example, _quoted_/only-file.bin': Buffer.from('synthetic file'),
		})
	).toThrow('ZIP attachment item names are ambiguous or missing.');
});

for (const names of [['A/B', 'A\\B'], ['A', 'A', 'A_1'], ['A', 'A_1', 'A']]) {
	test(`ZIP export rejects ambiguous item folders before downloading: ${names.join(', ')}`, async () => {
		const vault = fixture();
		vault.snapshot.ciphers = names.map((name, index) => ({
			...encryptItem({ ...item, name }, itemKey),
			id: `item-${index}`,
			key: encrypt(itemKey, key),
			attachments: [{ id: 'file' }],
		}));
		let downloads = 0;
		vault.getAttachmentById = async () => {
			downloads++;
			return { fileName: 'file.txt', contents: Buffer.from('synthetic') };
		};
		try {
			await expect(vault.exportVault('zip')).rejects.toThrow('ambiguous');
			expect(downloads).toBe(0);
		} finally {
			vault.dispose();
		}
	});
}

test('ZIP export/import includes every attachment when generated and original filenames collide', async () => {
	const attachmentKey = Buffer.alloc(64, 19);
	const bodies = new Map([
		['first', { name: 'file.txt', contents: 'first' }],
		['second', { name: 'file.txt', contents: 'second' }],
		['third', { name: 'file_1.txt', contents: 'third' }],
		['fourth', { name: 'first', contents: 'fourth' }],
		['fifth', { name: 'backup-first.bin', contents: 'fifth' }],
	]);
	const downloads: string[] = [];
	const source = fixture((url) => {
		const path = new URL(url).pathname;
		const id = path.split('/').at(-1)!;
		const file = bodies.get(id)!;
		downloads.push(id);
		if (path.startsWith('/api/ciphers/')) return Response.json({ url: `https://example.com/files/${id}` });
		return new Response(new Uint8Array(encryptAttachment(Buffer.from(file.contents), attachmentKey)));
	});
	source.snapshot.profile = { id: 'account', premium: true };
	source.snapshot.ciphers = [{
		...encryptItem(item, itemKey),
		id: 'source-item',
		key: encrypt(itemKey, key),
		attachments: [...bodies].map(([id, file]) => ({
			id,
			fileName: encrypt(Buffer.from(file.name), itemKey),
			key: encrypt(attachmentKey, itemKey),
		})),
	}];
	let created: JsonObject[] = [], restoredFolders: JsonObject[] = [];
	const restored: { name: string; contents: string }[] = [];
	const pending = new Map<string, { name: string; key: Buffer }>();
	const target = new VaultService(
		new VaultwardenClient('https://example.com', {
			fetch: (async (url: unknown, init: RequestInit) => {
				const path = new URL(String(url)).pathname;
				if (path === '/api/ciphers/import') {
					const body = JSON.parse(String(init.body));
					created = body.ciphers.map((cipher: JsonObject, index: number) => ({ ...cipher, id: `new-${index}` }));
					for (const relation of body.folderRelationships) created[relation.key]!.folderId = `folder-${relation.value}`;
					restoredFolders = body.folders.map((folder: JsonObject, index: number) => ({
						...folder,
						id: `folder-${index}`,
					}));
					return new Response(null, { status: 204 });
				}
				if (path === '/api/sync') {
					return Response.json({
						profile: { id: 'account', premium: true },
						ciphers: created,
						folders: restoredFolders,
					});
				}
				if (path.endsWith('/attachment/v2')) {
					const body = JSON.parse(String(init.body));
					const id = `attachment-${pending.size}`;
					const importedKey = decrypt(String(created[0]!.key), key);
					try {
						pending.set(id, {
							name: decrypt(body.fileName, importedKey).toString(),
							key: decrypt(body.key, importedKey),
						});
					} finally {
						importedKey.fill(0);
					}
					return Response.json({ attachmentId: id, fileUploadType: 0, cipherResponse: created[0] });
				}
				const upload = /\/attachment\/(attachment-\d+)$/.exec(path);
				if (upload && init.method === 'POST') {
					const metadata = pending.get(upload[1]!)!;
					const file = (init.body as FormData).get('data') as Blob;
					restored.push({
						name: metadata.name,
						contents: decryptAttachment(new Uint8Array(await file.arrayBuffer()), metadata.key).toString(),
					});
					metadata.key.fill(0);
					return new Response(null, { status: 204 });
				}
				throw new Error(`Unexpected ZIP round-trip request: ${init.method} ${path}`);
			}) as typeof fetch,
		}),
		'access',
		{ profile: { id: 'account' }, ciphers: [], folders: [] },
		key,
	);
	try {
		const zip = await source.exportVault('zip');
		const archive = unzipSync(zip);
		const files = Object.keys(archive).filter(path => path.startsWith('attachments/') && !path.endsWith('/'));
		expect(files).toHaveLength(5);
		expect(files.map(path => Buffer.from(archive[path]!).toString()).sort()).toEqual([
			'fifth',
			'first',
			'fourth',
			'second',
			'third',
		]);
		expect(downloads).toEqual([...bodies.keys()].flatMap(id => [id, id]));
		expect(await target.importVault('bitwardenzip', zip)).toMatchObject({ items: 1, attachments: 5 });
		expect(restored.map(value => value.contents).sort()).toEqual(['fifth', 'first', 'fourth', 'second', 'third']);
		expect(new Set(restored.map(value => value.name)).size).toBe(5);
	} finally {
		source.dispose();
		target.dispose();
		for (const metadata of pending.values()) metadata.key.fill(0);
	}
});
