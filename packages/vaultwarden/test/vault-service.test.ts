import type { JsonObject } from '#client';
import { VaultwardenClient } from '#client';
import { decrypt, decryptAttachment, encrypt, encryptAttachment, encryptSharedKey } from '#crypto';
import { encryptItem, transformItem } from '#item-codec';
import { vaultItemResponse } from '#local-api-models';
import { template } from '#templates';
import { totp } from '#totp';
import { findNamedObject, MultipleResultsError } from '#search';
import { VaultService } from '#vault-service';
import { expect, test } from 'bun:test';
import { constants, createPublicKey, generateKeyPairSync, publicEncrypt } from 'node:crypto';

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
	handler: (path: string, init: RequestInit) => Response | Promise<Response>,
	snapshot: JsonObject = { profile: { id: 'user' }, ciphers: [wire()], folders: [] },
) {
	const fetcher = (async (url: unknown, init: RequestInit) => handler(String(url), init)) as unknown as typeof fetch;
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
test('ambiguous item search exposes candidate IDs in the reference error', () => {
	const vault = service(() => Response.json({}), {
		profile: { id: 'user' },
		folders: [],
		ciphers: [wire({ id: 'first-match' }), wire({ id: 'second-match' })],
	});
	try {
		expect(() => vault.findItem('Example')).toThrow(
			'More than one result was found. Try getting a specific object by `id` instead. '
				+ 'The following objects were found:\nfirst-match\nsecond-match',
		);
	} finally {
		vault.dispose();
	}
});
test('ambiguous named-object search exposes candidate IDs', () => {
	const values = [{ id: 'folder-one', name: 'Shared folder one' }, { id: 'folder-two', name: 'Shared folder two' }];
	try {
		findNamedObject(values, 'Shared');
		throw new Error('Expected ambiguous lookup to fail.');
	} catch (error) {
		expect(error).toBeInstanceOf(MultipleResultsError);
		expect((error as MultipleResultsError).ids).toEqual(['folder-one', 'folder-two']);
	}
});
test('TOTP entitlement uses personal premium or the organization cipher grant', () => {
	const vault = service(() => Response.json({}), {
		profile: { id: 'user', premium: false, premiumPersonally: false, premiumFromOrganization: false },
		ciphers: [
			{ id: 'personal' },
			{ id: 'org-enabled', organizationId: 'org', organizationUseTotp: true },
			{ id: 'org-disabled', organizationId: 'org', organizationUseTotp: false },
		],
	});
	try {
		expect(vault.canAccessTotp('personal')).toBe(false);
		expect(vault.canAccessTotp('org-enabled')).toBe(true);
		expect(vault.canAccessTotp('org-disabled')).toBe(false);
	} finally {
		vault.dispose();
	}
	const premium = service(() => Response.json({}), {
		profile: { id: 'user', premiumPersonally: true },
		ciphers: [{ id: 'personal' }],
	});
	try {
		expect(premium.canAccessTotp('personal')).toBe(true);
	} finally {
		premium.dispose();
	}
});
test('newer bank account, driver license, and passport fields encrypt and decrypt', () => {
	for (
		const [type, section, secret, field] of [
			[6, 'bankAccount', 'bank-number', 'accountNumber'],
			[7, 'driversLicense', 'license-number', 'licenseNumber'],
			[8, 'passport', 'passport-number', 'passportNumber'],
		] as const
	) {
		const value = {
			type,
			name: section,
			[section]: { [field]: secret },
		};
		const encrypted = transformItem(value, itemKey, 'encrypt');
		expect(JSON.stringify(encrypted)).not.toContain(secret);
		expect(transformItem(encrypted, itemKey, 'decrypt')).toEqual(value);
	}
	for (const [type, section] of [[6, 'bankAccount'], [7, 'driversLicense'], [8, 'passport']] as const) {
		const model = { type, id: 'item', name: 'Example', key: 'decrypted-key', [section]: { reference: 'field' } };
		const response = vaultItemResponse(model);
		expect(response[section]).toEqual(model[section]);
		expect(response.key).toBeUndefined();
	}
	expect((template('item.bankAccount') as JsonObject).accountNumber).toBe('000123456789');
	expect((template('item.driversLicense') as JsonObject).licenseNumber).toBe('D12345678');
	expect((template('item.passport') as JsonObject).passportNumber).toBe('A12345678');
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
	}, { profile: { id: 'user', premiumPersonally: true }, ciphers: [wire()] });
	const item = vault.getItem('item');
	item.name = 'Changed';
	expect((await vault.editItem('item', item)).name).toBe('Changed');
});
test('archived-item edit prompt depends on archive entitlement', () => {
	const archived = wire({ id: 'archived', archivedDate: '2026-01-01T00:00:00Z' });
	const unentitled = service(() => Response.json({}), {
		profile: { id: 'user' },
		ciphers: [archived, wire({ id: 'active' })],
		folders: [],
	});
	const personallyEntitled = service(() => Response.json({}), {
		profile: { id: 'user', premiumPersonally: true },
		ciphers: [archived],
		folders: [],
	});
	const organizationEntitled = service(() => Response.json({}), {
		profile: { id: 'user', premiumFromOrganization: true },
		ciphers: [archived],
		folders: [],
	});
	expect(unentitled.shouldUnarchiveBeforeEdit('archived')).toBe(true);
	expect(personallyEntitled.shouldUnarchiveBeforeEdit('archived')).toBe(false);
	expect(organizationEntitled.shouldUnarchiveBeforeEdit('archived')).toBe(false);
	expect(unentitled.shouldUnarchiveBeforeEdit('active')).toBe(false);
});
test('editing a deleted item is rejected before making a server request', async () => {
	let requests = 0;
	const vault = service(() => {
		requests++;
		return Response.json({});
	}, { profile: { id: 'user' }, ciphers: [wire({ deletedDate: '2026-01-01T00:00:00Z' })], folders: [] });
	await expect(vault.editItem('item', vault.getItem('item'))).rejects.toThrow(
		'You may not edit a deleted item. Use the restore command first.',
	);
	expect(requests).toBe(0);
});
test('confirmed personal-ownership policies block personal edits for non-admin members', async () => {
	let requests = 0;
	const organizationId = 'org';
	const vault = service(() => {
		requests++;
		return Response.json({});
	}, {
		profile: { id: 'user', organizations: [{ id: organizationId, status: 2, type: 2 }] },
		policies: [{ organizationId, type: 5, enabled: true }],
		ciphers: [wire()],
		folders: [],
	});
	await expect(vault.editItem('item', vault.getItem('item'))).rejects.toThrow(
		'An organization policy restricts editing this cipher. Please use the share command first before modifying it.',
	);
	expect(requests).toBe(0);
});
test('personal-ownership policy precheck ignores admins and non-confirmed memberships', async () => {
	for (
		const membership of [
			{ id: 'org', status: 2, type: 0 },
			{ id: 'org', status: 2, type: 1 },
			{ id: 'org', status: 1, type: 2 },
		]
	) {
		let requests = 0;
		const vault = service((_path, init) => {
			requests++;
			const data = JSON.parse(String(init.body));
			return Response.json({ ...data, id: 'item', revisionDate: '2026-01-01T00:00:01Z' });
		}, {
			profile: { id: 'user', organizations: [membership] },
			policies: [{ organizationId: 'org', type: 5, enabled: true }],
			ciphers: [wire()],
			folders: [],
		});
		await vault.editItem('item', vault.getItem('item'));
		expect(requests).toBe(1);
	}
});
test('sync edit, delete, and restore permissions stop forbidden mutations locally', async () => {
	let requests = 0;
	const vault = service(() => {
		requests++;
		return Response.json({});
	}, {
		profile: { id: 'user' },
		ciphers: [
			wire({ id: 'read-only', edit: false }),
			wire({ id: 'no-delete', permissions: { delete: false } }),
			wire({ id: 'no-restore', deletedDate: '2026-01-01T00:00:00Z', permissions: { restore: false } }),
		],
		folders: [],
	});
	await expect(vault.editItem('read-only', vault.getItem('read-only'))).rejects.toMatchObject({
		message: 'You do not have permission to edit this item',
	});
	await expect(vault.deleteItem('no-delete')).rejects.toThrow('You do not have permission to delete this item.');
	await expect(vault.restoreItem('no-restore')).rejects.toThrow('You do not have permission to restore this item');
	expect(requests).toBe(0);
});
test('restore refuses an active item before the server request', async () => {
	let requests = 0;
	const vault = service(() => {
		requests++;
		return Response.json({});
	}, { profile: { id: 'user' }, ciphers: [wire({ id: 'active' })] });
	await expect(vault.restoreItem('active')).rejects.toThrow('Cipher is not in trash.');
	expect(requests).toBe(0);
});
test('restore uses unarchive only for archived items, and trash restore takes precedence', async () => {
	const paths: string[] = [];
	const vault = service((path, init) => {
		paths.push(`${init.method} ${path}`);
		return Response.json({});
	}, {
		profile: { id: 'user' },
		ciphers: [
			wire({ id: 'archived', archivedDate: '2026-01-01T00:00:00Z' }),
			wire({ id: 'archived-and-trashed', archivedDate: '2026-01-01T00:00:00Z', deletedDate: '2026-01-02T00:00:00Z' }),
		],
	});
	await vault.restoreItem('archived');
	await vault.restoreItem('archived-and-trashed');
	expect(paths).toEqual([
		'PUT https://example.com/api/ciphers/archived/unarchive',
		'PUT https://example.com/api/ciphers/archived-and-trashed/restore',
	]);
});
test('editing a hidden-password item preserves secrets redacted from the CLI response', async () => {
	const privateItem = {
		type: 1,
		name: 'Private',
		login: { username: 'person', password: 'hidden-password', totp: 'hidden-totp' },
		fields: [
			{ name: 'hidden-field', value: 'hidden-custom-value', type: 1 },
			{ name: 'hidden-field', value: 'second-hidden-custom-value', type: 1 },
		],
		passwordHistory: [{ password: 'hidden-history', lastUsedDate: '2026-01-01T00:00:00Z' }],
	};
	const existing = {
		...encryptItem(privateItem, itemKey),
		id: 'item',
		key: encrypt(itemKey, userKey),
		viewPassword: false,
		revisionDate: '2026-01-01T00:00:00Z',
	};
	let submitted: JsonObject | undefined;
	const vault = service((_path, init) => {
		submitted = transformItem(JSON.parse(String(init.body)), itemKey, 'decrypt');
		return Response.json({ ...JSON.parse(String(init.body)), id: 'item', viewPassword: false });
	}, { profile: { id: 'user' }, ciphers: [existing], folders: [] });
	const response = vaultItemResponse(vault.getItem('item'));
	expect(JSON.stringify(response)).not.toContain('hidden-password');
	expect(JSON.stringify(response)).not.toContain('hidden-totp');
	expect(JSON.stringify(response)).not.toContain('hidden-custom-value');
	expect(JSON.stringify(response)).not.toContain('second-hidden-custom-value');
	response.name = 'Renamed';
	await vault.editItem('item', response as Parameters<VaultService['editItem']>[1]);
	expect((submitted?.login as JsonObject).password).toBe('hidden-password');
	expect((submitted?.login as JsonObject).totp).toBe('hidden-totp');
	expect(((submitted?.fields as JsonObject[])[0] ?? {}).value).toBe('hidden-custom-value');
	expect(((submitted?.fields as JsonObject[])[1] ?? {}).value).toBe('second-hidden-custom-value');
	expect(submitted?.name).toBe('Renamed');
});
test('item collection edits enforce organization ownership and view permission before mutation', async () => {
	let requests = 0;
	const vault = service(() => {
		requests++;
		return Response.json({});
	}, {
		profile: { id: 'user' },
		collections: [],
		ciphers: [wire({ id: 'personal' }), wire({ id: 'restricted', organizationId: 'org', viewPassword: false })],
	});
	await expect(vault.editItemCollections('personal', [])).rejects.toThrow(
		'Item does not belong to an organization. Consider moving it first.',
	);
	await expect(vault.editItemCollections('restricted', [])).rejects.toMatchObject({
		message: 'You do not have permission to edit this item',
	});
	expect(requests).toBe(0);
});
test('item collection edits return the updated decrypted cipher like bw', async () => {
	const { publicKey, privateKey } = generateKeyPairSync('rsa', {
		modulusLength: 2048,
		publicKeyEncoding: { type: 'spki', format: 'der' },
		privateKeyEncoding: { type: 'pkcs8', format: 'der' },
	});
	const organizationKey = Buffer.alloc(64, 5), cipherKey = Buffer.alloc(64, 6);
	const organizationId = 'organization', collectionId = 'collection';
	const cipher = {
		...encryptItem({ ...plaintext, name: 'Organization item' }, cipherKey),
		id: 'organization-item',
		key: encrypt(cipherKey, organizationKey),
		organizationId,
		collectionIds: [collectionId],
		revisionDate: '2026-01-01T00:00:00Z',
	};
	let requestBody: JsonObject | undefined;
	const vault = service((path, init) => {
		expect(path).toBe('https://example.com/api/ciphers/organization-item/collections');
		expect(init.method).toBe('PUT');
		requestBody = JSON.parse(String(init.body));
		return Response.json(cipher);
	}, {
		profile: {
			id: 'user',
			privateKey: encrypt(privateKey, userKey),
			organizations: [{ id: organizationId, key: encryptSharedKey(organizationKey, publicKey.toString('base64')) }],
		},
		collections: [{ id: collectionId, organizationId }],
		ciphers: [
			{ ...cipher, viewPassword: true },
		],
	});
	try {
		const updated = await vault.editItemCollections('organization-item', [collectionId]);
		expect(requestBody).toEqual({ collectionIds: [collectionId] });
		expect(updated).toMatchObject({
			id: 'organization-item',
			name: 'Organization item',
			organizationId,
			collectionIds: [collectionId],
		});
	} finally {
		vault.dispose();
		organizationKey.fill(0);
		cipherKey.fill(0);
	}
});
test('archive refuses an archived item and a trashed item before mutation', async () => {
	let requests = 0;
	const vault = service(() => {
		requests++;
		return Response.json({});
	}, {
		profile: { id: 'user', premiumPersonally: true },
		ciphers: [
			wire({ id: 'archived', archivedDate: '2026-01-01T00:00:00Z' }),
			wire({ id: 'trashed', deletedDate: '2026-01-01T00:00:00Z' }),
		],
		folders: [],
	});
	await expect(vault.archiveItem('archived')).rejects.toThrow('Item is already archived.');
	await expect(vault.archiveItem('trashed')).rejects.toThrow(
		'Item is in the trash, the item must be restored before archiving.',
	);
	expect(requests).toBe(0);
});
test('archive requires premium before applying item-state checks or calling the server', async () => {
	let requests = 0;
	const vault = service(() => {
		requests++;
		return Response.json({});
	}, {
		profile: { id: 'user', premiumPersonally: false, premiumFromOrganization: false },
		ciphers: [wire({ id: 'already-archived', archivedDate: '2026-01-01T00:00:00Z' })],
	});
	await expect(vault.archiveItem('already-archived')).rejects.toThrow(
		'Premium status is required to use this feature.',
	);
	expect(requests).toBe(0);
});
test('premium archive sends the archive request', async () => {
	let request: { path: string; method: string | undefined } | undefined;
	const vault = service((path, init) => {
		request = { path, method: init.method };
		return Response.json({});
	}, {
		profile: { id: 'user', premiumPersonally: true },
		ciphers: [wire()],
	});
	await vault.archiveItem('item');
	expect(request).toEqual({ path: 'https://example.com/api/ciphers/item/archive', method: 'PUT' });
});
test('lists distinguish trash and archive and combine object filters with OR', () => {
	const vault = service(() => Response.json({}), {
		profile: { id: 'user', premium: true },
		folders: [],
		ciphers: [
			wire(),
			wire({ id: 'trash', deletedDate: 'date' }),
			wire({ id: 'archive', archivedDate: 'date' }),
			wire({ id: 'trash-archive', deletedDate: 'date', archivedDate: 'date' }),
			wire({ id: 'folder', folderId: 'folder' }),
		],
	});
	expect(vault.listItems().map(i => i.id)).toEqual(['item', 'folder']);
	expect(vault.listItems({ trash: true }).map(i => i.id)).toEqual(['trash']);
	expect(vault.listItems({ trash: true, archived: true }).map(i => i.id)).toEqual(['trash-archive']);
	expect(vault.listItems({ archived: true }).map(i => i.id)).toEqual(['archive']);
	expect(vault.listItems({ folderId: 'folder', organizationId: 'notnull' }).map(i => i.id)).toEqual(['folder']);
});
test('archived listing follows the synced premium capability', () => {
	const vault = service(() => Response.json({}), {
		profile: { id: 'user', premium: false, organizations: [{ id: 'org' }] },
		folders: [],
		ciphers: [wire(), wire({ id: 'archive', archivedDate: 'date' })],
	});
	expect(vault.listItems({ archived: true }).map(item => item.id)).toEqual(['item']);
	const organizationPremiumVault = service(() => Response.json({}), {
		profile: { id: 'user', premium: false, premiumFromOrganization: true },
		folders: [],
		ciphers: [wire(), wire({ id: 'archive', archivedDate: 'date' })],
	});
	expect(organizationPremiumVault.listItems({ archived: true }).map(item => item.id)).toEqual(['archive']);
});
test('restricted-item policies hide disallowed items from list and report the policy denial on get', async () => {
	const organizationA = '11111111-1111-1111-1111-111111111111';
	const organizationB = '22222222-2222-2222-2222-222222222222';
	const rsa = generateKeyPairSync('rsa', {
		modulusLength: 2048,
		publicKeyEncoding: { type: 'spki', format: 'der' },
		privateKeyEncoding: { type: 'pkcs8', format: 'der' },
	});
	const organizationKey = Buffer.alloc(64, 8);
	const wrappedKey = `3.${
		publicEncrypt({
			key: createPublicKey({ key: rsa.publicKey, format: 'der', type: 'spki' }),
			oaepHash: 'sha256',
			padding: constants.RSA_PKCS1_OAEP_PADDING,
		}, organizationKey).toString('base64')
	}`;
	const organizationCipher = (id: string, type: number, organizationId: string) =>
		wire({ id, type, organizationId, key: encrypt(itemKey, organizationKey) });
	let requests = 0;
	const vault = service(() => {
		requests++;
		return Response.json({});
	}, {
		profile: {
			id: 'user',
			privateKey: encrypt(rsa.privateKey, userKey),
			organizations: [{ id: organizationA, key: wrappedKey }, { id: organizationB, key: wrappedKey }],
		},
		folders: [],
		policies: [{ organizationId: organizationA, type: 15, enabled: true, data: [3] }],
		ciphers: [
			wire({ id: 'personal-card', type: 3 }),
			organizationCipher('org-a-card', 3, organizationA),
			organizationCipher('org-b-card', 3, organizationB),
			organizationCipher('org-a-login', 1, organizationA),
		],
	});
	try {
		expect(vault.listItems().map(item => item.id)).toEqual(['org-b-card', 'org-a-login']);
		expect(() => vault.findItem('personal-card')).toThrow(
			'Access to this item type is restricted by organizational policy.',
		);
		expect(() => vault.findItem('org-a-card')).toThrow(
			'Access to this item type is restricted by organizational policy.',
		);
		expect(() => vault.findItem('org-a-card', () => false)).toThrow(
			'Access to this item type is restricted by organizational policy.',
		);
		expect(vault.findItem('org-b-card').id).toBe('org-b-card');
		await expect(vault.editItem('org-a-card', vault.getItem('org-a-card'))).rejects.toThrow(
			'Editing this item type is restricted by organizational policy.',
		);
		await expect(vault.deleteItem('org-a-card')).rejects.toThrow(
			'Deleting this item type is restricted by organizational policy.',
		);
		await expect(vault.createItem({ type: 3, name: 'Restricted card' })).rejects.toThrow(
			'Creating this item type is restricted by organizational policy.',
		);
		expect(requests).toBe(0);
	} finally {
		vault.dispose();
		rsa.privateKey.fill(0);
		organizationKey.fill(0);
	}
});
test('password health includes archived and policy-hidden logins exactly once', async () => {
	const vault = service(() => Response.json({}), {
		profile: { id: 'user', premium: false },
		folders: [],
		policies: [{ organizationId: 'org', type: 15, enabled: true, data: [1] }],
		ciphers: [
			wire({ id: 'active' }),
			wire({ id: 'archived', archivedDate: '2026-01-01T00:00:00Z' }),
		],
	});
	try {
		expect(vault.listItems().map(item => item.id)).toEqual([]);
		const rows = await vault.passwordHealth({ checkExposed: false });
		expect(rows.map(row => row.id)).toEqual(['active', 'archived']);
		expect(rows.map(row => row.reuseCount)).toEqual([2, 2]);
	} finally {
		vault.dispose();
	}
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
				organizations: [{ id: 'org', organizationUserId: 'membership', key: wrapped }],
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
test('move supports an organization item without collection assignments', async () => {
	const { snapshot, orgKey } = organizationSnapshot([wire()]);
	const vault = service((path, init) => {
		expect(path).toEndWith('/api/ciphers/item/share');
		const body = JSON.parse(String(init.body));
		expect(body.collectionIds).toEqual([]);
		const key = decrypt(body.cipher.key, orgKey);
		try {
			expect(transformItem(body.cipher, key, 'decrypt').login).toMatchObject(plaintext.login);
		} finally {
			key.fill(0);
		}
		return Response.json({ ...body.cipher, id: 'item', organizationId: 'org', collectionIds: [] });
	}, snapshot);
	try {
		expect((await vault.moveItem('item', 'org', [])).organizationId).toBe('org');
	} finally {
		vault.dispose();
		orgKey.fill(0);
	}
});
test('moving a legacy item migrates its attachment bytes and keys before sharing', async () => {
	const fileContents = Buffer.from('legacy attachment contents'),
		legacyFile = encryptAttachment(fileContents, userKey),
		oldAttachment = {
			id: 'old-attachment',
			fileName: encrypt(Buffer.from('legacy.txt'), userKey),
			url: 'https://example.com/download/old-attachment',
			size: legacyFile.length,
		},
		legacyCipher = {
			...transformItem(plaintext, userKey, 'encrypt'),
			id: 'item',
			key: null,
			revisionDate: '2026-01-01T00:00:00Z',
			attachments: [oldAttachment],
		},
		{ snapshot, orgKey } = organizationSnapshot([legacyCipher]);
	let attachments: JsonObject[] = [oldAttachment], uploadedFile: Buffer | undefined;
	const vault = service(async (path, init) => {
		if (path.endsWith('/download/old-attachment')) return new Response(new Uint8Array(legacyFile));
		if (path.endsWith('/attachment/old-attachment') && init.method === 'GET') {
			return Response.json({ ...oldAttachment });
		}
		if (path.endsWith('/attachment/v2')) {
			const body = JSON.parse(String(init.body));
			const attachmentKey = decrypt(body.key, userKey);
			try {
				expect(decrypt(body.fileName, userKey).toString()).toBe('legacy.txt');
				expect(attachmentKey.equals(userKey)).toBe(false);
				const metadata = {
					id: 'new-attachment',
					fileName: body.fileName,
					key: body.key,
					url: 'https://example.com/download/new-attachment',
				};
				attachments = [...attachments, metadata];
				return Response.json({
					attachmentId: 'new-attachment',
					fileUploadType: 0,
					cipherResponse: { ...legacyCipher, attachments },
				});
			} finally {
				attachmentKey.fill(0);
			}
		}
		if (path.endsWith('/attachment/new-attachment')) {
			const form = init.body as FormData;
			const blob = form.get('data') as Blob;
			const ciphertext = Buffer.from(await blob.arrayBuffer()),
				key = decrypt(
					((attachments.find(value => value.id === 'new-attachment') ?? {}) as JsonObject).key as string,
					userKey,
				);
			try {
				expect(decryptAttachment(ciphertext, key)).toEqual(fileContents);
				uploadedFile = ciphertext;
			} finally {
				key.fill(0);
			}
			return Response.json({});
		}
		if (path.endsWith('/attachment/old-attachment') && init.method === 'DELETE') {
			attachments = attachments.filter(value => value.id !== 'old-attachment');
			return Response.json({});
		}
		if (path.includes('/sync?')) {
			return Response.json({
				profile: snapshot.profile,
				ciphers: [{ ...legacyCipher, attachments }],
				collections: snapshot.collections,
			});
		}
		if (path.endsWith('/share')) {
			const body = JSON.parse(String(init.body)), newKey = decrypt(body.cipher.key, orgKey);
			try {
				const migrated = body.cipher.attachments2['new-attachment'];
				expect(body.cipher.attachments2['old-attachment']).toBeUndefined();
				expect(decrypt(migrated.fileName, newKey).toString()).toBe('legacy.txt');
				const attachmentKey = decrypt(migrated.key, newKey);
				try {
					expect(decryptAttachment(uploadedFile!, attachmentKey)).toEqual(fileContents);
				} finally {
					attachmentKey.fill(0);
				}
				return Response.json({ ...body.cipher, id: 'item' });
			} finally {
				newKey.fill(0);
			}
		}
		throw new Error(`Unexpected request: ${path}`);
	}, snapshot);
	try {
		expect((await vault.moveItem('item', 'org', ['collection'])).name).toBe('Example');
	} finally {
		vault.dispose();
		fileContents.fill(0);
		legacyFile.fill(0);
		uploadedFile?.fill(0);
		orgKey.fill(0);
	}
});
test('collection rename preserves memberships when the request omits them', async () => {
	const { snapshot, orgKey } = organizationSnapshot();
	const vault = service((path, init) => {
		if (path.endsWith('/api/organizations/org/collections/collection/details')) {
			expect(init.method).toBe('GET');
			return Response.json({
				id: 'collection',
				name: encrypt(Buffer.from('Old'), orgKey),
				groups: [{ id: 'group' }],
				users: [{ id: 'member', readOnly: true, hidePasswords: true, manage: false }],
			});
		}
		expect(path).toEndWith('/api/organizations/org/collections/collection');
		expect(init.method).toBe('PUT');
		const body = JSON.parse(String(init.body));
		expect(body.users).toEqual([{ id: 'member', readOnly: true, hidePasswords: true, manage: false }]);
		expect(body.groups).toEqual([{ id: 'group' }]);
		expect(body.externalId).toBeUndefined();
		expect(decrypt(body.name, orgKey).toString()).toBe('New');
		return Response.json({
			id: 'collection',
			name: body.name,
			users: body.users,
			groups: body.groups,
		});
	}, snapshot);
	try {
		expect((await vault.editCollection('org', 'collection', { name: 'New' })).name).toBe('New');
	} finally {
		vault.dispose();
	}
});
test('new organization collections grant the current member manage access by default', async () => {
	const { snapshot, orgKey } = organizationSnapshot();
	const vault = service((path, init) => {
		expect(path).toEndWith('/api/organizations/org/collections');
		expect(init.method).toBe('POST');
		const body = JSON.parse(String(init.body));
		expect(body.groups).toEqual([]);
		expect(body.users).toEqual([{ id: 'membership', readOnly: false, hidePasswords: false, manage: true }]);
		return Response.json({ id: 'created-collection', name: encrypt(Buffer.from('Created'), orgKey) });
	}, snapshot);
	try {
		expect((await vault.createCollection('org', { name: 'Created' })).name).toBe('Created');
	} finally {
		vault.dispose();
		orgKey.fill(0);
	}
});
test('move rejects an inaccessible collection before any network mutation', async () => {
	const { snapshot } = organizationSnapshot([wire()]);
	let calls = 0;
	const vault = service(() => {
		calls++;
		return Response.json({});
	}, snapshot);
	await expect(vault.moveItem('item', 'org', ['other-collection'])).rejects.toThrow(
		'You do not have permission to add items to this collection.',
	);
	expect(calls).toBe(0);
	vault.dispose();
});

test('move applies the bw collection-edit rule from cached organization and collection access', async () => {
	for (
		const organization of [
			{ type: 1, allowAdminAccessToAllCollectionItems: true },
			{ type: 4, permissions: { editAnyCollection: true } },
		]
	) {
		const { snapshot, orgKey } = organizationSnapshot([wire()]);
		Object.assign(snapshot.profile.organizations[0]!, organization);
		Object.assign(snapshot.collections[0]!, { readOnly: true, manage: false });
		const vault = service((path, init) => {
			expect(path).toEndWith('/api/ciphers/item/share');
			const body = JSON.parse(String(init.body));
			return Response.json({ ...body.cipher, id: 'item', organizationId: 'org' });
		}, snapshot);
		try {
			expect((await vault.moveItem('item', 'org', ['collection'])).organizationId).toBe('org');
		} finally {
			vault.dispose();
			orgKey.fill(0);
		}
	}
});

test('move lowercases cipher and organization IDs like bw before lookup and mutation', async () => {
	const { snapshot, orgKey } = organizationSnapshot([wire()]);
	const vault = service((path, init) => {
		expect(path).toEndWith('/api/ciphers/item/share');
		const body = JSON.parse(String(init.body));
		expect(body.cipher.organizationId).toBe('org');
		return Response.json({ ...body.cipher, id: 'item', organizationId: 'org' });
	}, snapshot);
	try {
		expect((await vault.moveItem('ITEM', 'ORG', ['collection'])).organizationId).toBe('org');
	} finally {
		vault.dispose();
		orgKey.fill(0);
	}
});

test('move rejects read-only collections for a regular organization member before mutation', async () => {
	const { snapshot, orgKey } = organizationSnapshot([wire()]);
	Object.assign(snapshot.profile.organizations[0]!, { type: 2 });
	Object.assign(snapshot.collections[0]!, { readOnly: true, manage: false });
	let calls = 0;
	const vault = service(() => {
		calls++;
		return Response.json({});
	}, snapshot);
	await expect(vault.moveItem('item', 'org', ['collection'])).rejects.toThrow(
		'You do not have permission to add items to this collection.',
	);
	expect(calls).toBe(0);
	vault.dispose();
	orgKey.fill(0);
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
	}, { profile: { premiumPersonally: true }, ciphers: [wire()] });
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
	}, { profile: { premiumPersonally: true }, ciphers: [wire({ attachments })] });
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
		for (const query of ['REPORT', '.bin']) {
			await expect(vault.getAttachment('item', query)).rejects.toThrow('More than one result was found.');
		}
		await expect(vault.getAttachment('item', 'missing')).rejects.toThrow(
			'Attachment `missing` was not found.',
		);
		await expect(vault.getAttachment('item', '')).rejects.toThrow('Attachment not found.');
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
		await expect(vault.getAttachment('item', 'report.bin')).rejects.toThrow(
			'More than one result was found. Try getting a specific object by `id` instead. '
				+ 'The following objects were found:\nabc123\ndef456\nduplicate',
		);
		expect(paths).toHaveLength(6);
	} finally {
		vault.dispose();
		key.fill(0);
	}
});

test('attachment reads distinguish items without attachments from unknown attachment names', async () => {
	const vault = service(() => {
		throw new Error('Attachment download should not be requested.');
	}, { profile: { id: 'user' }, ciphers: [wire({ attachments: [] })] });
	try {
		await expect(vault.getAttachment('item', 'missing')).rejects.toThrow('No attachments available for this item.');
	} finally {
		vault.dispose();
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
		}, { profile: { premiumPersonally: true }, ciphers: [wire({ attachments: [attachment] })] });
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
test('attachment download requires premium for personal items before network access', async () => {
	let requests = 0;
	const attachment = {
		id: 'attachment',
		fileName: encrypt(Buffer.from('private.bin'), itemKey),
		key: encrypt(Buffer.alloc(64, 8), itemKey),
	};
	const vault = service(() => {
		requests++;
		return Response.json({});
	}, {
		profile: { premiumPersonally: false, premiumFromOrganization: false },
		ciphers: [wire({ attachments: [attachment] })],
	});
	try {
		expect(vault.canAccessAttachment('item')).toBe(false);
		await expect(vault.getAttachment('item', 'private.bin')).rejects.toThrow(
			'Premium status is required to use this feature.',
		);
		await expect(vault.createAttachment('item', 'private.bin', Buffer.from('synthetic'))).rejects.toThrow(
			'Premium status is required to use this feature.',
		);
		await expect(vault.deleteAttachment('item', 'attachment')).rejects.toThrow(
			'Premium status is required to use this feature.',
		);
		expect(requests).toBe(0);
	} finally {
		vault.dispose();
	}
	const organization = service(() => Response.json({}), {
		profile: { premiumPersonally: false, organizations: [{ id: 'org' }] },
		ciphers: [{ id: 'organization-item', organizationId: 'org' }],
	});
	try {
		expect(organization.canAccessAttachment('organization-item')).toBe(true);
	} finally {
		organization.dispose();
	}
});
test('attachment deletion validates membership before sending the server request', async () => {
	let requests = 0;
	const vault = service((path, init) => {
		requests++;
		expect(path).toEndWith('/api/ciphers/item/attachment/AbC123');
		expect(init.method).toBe('DELETE');
		return Response.json({});
	}, { profile: { premiumPersonally: true }, ciphers: [wire({ attachments: [{ id: 'AbC123' }] })] });
	await expect(vault.deleteAttachment('item', 'missing')).rejects.toThrow('Attachment `missing` was not found.');
	expect(requests).toBe(0);
	await vault.deleteAttachment('item', 'abc123');
	expect(requests).toBe(1);
	const empty = service(() => {
		requests++;
		return Response.json({});
	}, { profile: {}, ciphers: [wire({ attachments: [] })] });
	await expect(empty.deleteAttachment('item', 'missing')).rejects.toThrow('No attachments available for this item.');
	expect(requests).toBe(1);
});
