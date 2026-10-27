import type { JsonObject } from '#client';
import { VaultwardenClient } from '#client';
import { decrypt, decryptAttachment, decryptSharedKey, encrypt, encryptAttachment, encryptSharedKey } from '#crypto';
import { encryptItem, transformItem } from '#item-codec';
import {
	localApiObject,
	organizationCollectionResponse,
	sendObjectResponse,
	vaultItemResponse,
} from '#local-api-models';
import { template } from '#templates';
import { totp } from '#totp';
import { findNamedObject, MultipleResultsError } from '#search';
import { assertAttachmentSize, VaultService } from '#vault-service';
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
const policyOrganization = (id: string, overrides: JsonObject = {}): JsonObject => ({
	id,
	status: 2,
	type: 2,
	enabled: true,
	usePolicies: true,
	isProviderUser: false,
	...overrides,
});
function wire(overrides: JsonObject = {}) {
	return {
		...encryptItem(plaintext, itemKey),
		id: 'item',
		key: encrypt(itemKey, userKey),
		edit: true,
		viewPassword: true,
		permissions: { delete: true, restore: true },
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
test('ambiguous item search exposes candidate IDs in the reference error', async () => {
	const vault = service(() => Response.json({}), {
		profile: { id: 'user' },
		folders: [],
		ciphers: [wire({ id: 'first-match' }), wire({ id: 'second-match' })],
	});
	try {
		await expect(vault.findItem('Example')).rejects.toThrow(
			'More than one result was found. Try getting a specific object by `id` instead. '
				+ 'The following objects were found:\nfirst-match\nsecond-match',
		);
	} finally {
		vault.dispose();
	}
});
test('item lookup applies bw term matching to notes and URI hostnames', async () => {
	const itemId = '00000000-0000-0000-0000-000000000004';
	const cipher = encryptItem({
		id: itemId,
		type: 1,
		name: 'Alpha record',
		notes: 'marker in notes',
		login: { username: 'Beta user', password: 'secret', uris: [{ uri: 'https://example.test/private-path' }] },
	}, itemKey);
	const vault = service(() => Response.json({}), {
		profile: { id: 'user' },
		folders: [],
		ciphers: [{ ...cipher, id: itemId, key: encrypt(itemKey, userKey), edit: true, viewPassword: true }],
	});
	try {
		expect((await vault.findItem('Alpha marker')).id).toBe(itemId);
		expect((await vault.findItem('Beta example.test')).id).toBe(itemId);
		await expect(vault.findItem('private-path')).rejects.toMatchObject({ name: 'VaultObjectNotFoundError' });
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
test('URI matching uses policies from accepted organization sync data in the library', async () => {
	const item = {
		...encryptItem({
			...plaintext,
			login: { ...plaintext.login, uris: [{ uri: 'https://example.com' }] },
		}, itemKey),
		id: 'item',
		key: encrypt(itemKey, userKey),
	};
	const vault = service(() => Response.json({}), {
		profile: { id: 'user', organizations: [policyOrganization('org')] },
		policiesNew: [{ organizationId: 'org', type: 16, enabled: true, data: JSON.stringify({ uriMatchDetection: 1 }) }],
		ciphers: [item],
		folders: [],
	});
	try {
		expect(await vault.listItemsForUrl('https://sub.example.com', {}, { defaultMatch: 0 })).toEqual([]);
	} finally {
		vault.dispose();
	}
});
test('URI match policies exempt owners before choosing the effective match strategy', async () => {
	const item = {
		...encryptItem({
			...plaintext,
			login: { ...plaintext.login, uris: [{ uri: 'https://example.com' }] },
		}, itemKey),
		id: 'item',
		key: encrypt(itemKey, userKey),
	};
	const vault = service(() => Response.json({}), {
		profile: { id: 'user', organizations: [policyOrganization('org', { type: 0 })] },
		policies: [{ organizationId: 'org', type: 16, enabled: true, data: { uriMatchDetection: 1 } }],
		ciphers: [item],
		folders: [],
	});
	try {
		expect(await vault.listItemsForUrl('https://sub.example.com', {}, { defaultMatch: 0 })).toHaveLength(1);
	} finally {
		vault.dispose();
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
		const model = {
			type,
			id: 'item',
			name: 'Example',
			key: 'decrypted-key',
			[section]: { reference: 'field', internalField: 'must be omitted' },
		};
		const response = vaultItemResponse(model);
		expect(response[section]).toEqual({});
		expect(response.key).toBeUndefined();
	}
	expect((template('item.bankAccount') as JsonObject).accountNumber).toBe('000123456789');
	expect((template('item.driversLicense') as JsonObject).licenseNumber).toBe('D12345678');
	expect((template('item.passport') as JsonObject).passportNumber).toBe('A12345678');
});
test('item responses whitelist nested export fields and report field response types', () => {
	const response = vaultItemResponse({
		id: 'item',
		type: 3,
		organizationId: null,
		folderId: null,
		collectionIds: null,
		revisionDate: '2026-01-02T03:04:05Z',
		creationDate: '2026-01-02T03:04:05Z',
		deletedDate: null,
		archivedDate: null,
		card: {
			cardholderName: 'Alice Example',
			number: '4111111111111111',
			internalField: 'must be omitted',
		},
		fields: [{ name: 'Custom', value: 'value', type: 1, linkedId: null, internalField: 'must be omitted' }],
		passwordHistory: [{ lastUsedDate: null, password: null, internalField: 'must be omitted' }],
		attachments: [{
			id: 'attachment',
			fileName: null,
			size: '4',
			sizeName: null,
			url: 'https://example.test/file',
			internalField: true,
		}],
	});
	expect(JSON.parse(JSON.stringify(response))).toEqual({
		object: 'item',
		id: 'item',
		type: 3,
		reprompt: 0,
		name: '',
		favorite: false,
		collectionIds: [],
		fields: [{ name: 'Custom', value: 'value', type: 1, linkedId: null }],
		passwordHistory: [{ lastUsedDate: null, password: null }],
		revisionDate: '2026-01-02T03:04:05.000Z',
		creationDate: '2026-01-02T03:04:05.000Z',
		card: { cardholderName: 'Alice Example', number: '4111111111111111' },
		attachments: [{
			id: 'attachment',
			fileName: null,
			size: '4',
			sizeName: null,
			url: 'https://example.test/file',
		}],
	});
});
test('item responses project FIDO2 credentials into the pinned export response shape', () => {
	const response = vaultItemResponse({
		id: 'item',
		type: 1,
		name: 'Passkey',
		login: {
			fido2Credentials: [{
				credentialId: 'credential',
				keyType: 'public-key',
				keyAlgorithm: 'ECDSA',
				keyCurve: 'P-256',
				keyValue: 'public-key-data',
				rpId: 'example.test',
				userHandle: 'handle',
				userName: 'alice',
				counter: 7,
				rpName: 'Example',
				userDisplayName: 'Alice',
				discoverable: true,
				creationDate: '2026-01-02T03:04:05.000Z',
				internalField: 'must be omitted',
			}],
		},
	});
	expect((response.login as JsonObject).fido2Credentials).toEqual([{
		credentialId: 'credential',
		keyType: 'public-key',
		keyAlgorithm: 'ECDSA',
		keyCurve: 'P-256',
		keyValue: 'public-key-data',
		rpId: 'example.test',
		userHandle: 'handle',
		userName: 'alice',
		counter: '7',
		rpName: 'Example',
		userDisplayName: 'Alice',
		discoverable: 'true',
		creationDate: '2026-01-02T03:04:05.000Z',
	}]);
});
test('item responses redact FIDO2 private keys when the caller cannot view passwords', () => {
	const response = vaultItemResponse({
		id: 'item',
		type: 1,
		viewPassword: false,
		login: { fido2Credentials: [{ credentialId: 'credential', keyValue: 'private-key-material' }] },
	});
	expect(((response.login as JsonObject).fido2Credentials as JsonObject[])[0]!.keyValue).toBeNull();
});
test('library response models project collections and Sends instead of leaking sync properties', () => {
	expect(localApiObject('collection', {
		id: 'collection',
		organizationId: null,
		name: 'Personal',
		externalId: null,
		key: 'encrypted-key',
		internalField: 'must be omitted',
	})).toEqual({
		object: 'collection',
		id: 'collection',
		organizationId: null,
		name: 'Personal',
		externalId: null,
	});
	expect(organizationCollectionResponse({
		id: 'org-collection',
		organizationId: 'organization',
		name: 'Engineering',
		externalId: null,
		groups: [{ id: 'group', readOnly: true, manage: false, internalField: 'discard' }],
		users: [{ id: 'member', readOnly: false, hidePasswords: true, manage: true, internalField: 'discard' }],
		internalField: 'must be omitted',
	})).toEqual({
		object: 'org-collection',
		id: 'org-collection',
		organizationId: 'organization',
		name: 'Engineering',
		externalId: null,
		groups: [{ id: 'group', readOnly: true, hidePasswords: false, manage: false }],
		users: [{ id: 'member', readOnly: false, hidePasswords: true, manage: true }],
	});
	expect(organizationCollectionResponse({
		id: 'org-collection',
		organizationId: 'organization',
		name: 'Engineering',
		externalId: null,
	})).toMatchObject({ groups: null, users: null });
	const send = {
		object: 'send',
		id: 'send-id',
		name: 'Text Send',
		key: 'send-key',
		type: 0,
		accessCount: 2,
		emails: null,
		text: { text: 'payload', hidden: true, internalField: 'discard' },
		internalField: 'must be omitted',
	};
	expect(localApiObject('send', send)).toEqual({
		object: 'send',
		id: 'send-id',
		name: 'Text Send',
		key: 'send-key',
		type: 0,
		accessCount: 2,
		emails: [],
		text: { text: 'payload', hidden: true },
	});
	expect(
		sendObjectResponse(
			{ object: 'send-access', id: 'send-id', name: 'Text Send', type: 0, text: send.text },
			'send-access',
		),
	)
		.toEqual({
			object: 'send-access',
			id: 'send-id',
			name: 'Text Send',
			type: 0,
			text: { text: 'payload', hidden: true },
		});
});
test('organization lists exclude unconfirmed memberships while lookup includes provider organizations', () => {
	const vault = service(() => Response.json({}), {
		profile: {
			organizations: [
				{ id: 'invited', name: 'Invited', status: 0 },
				{ id: 'accepted', name: 'Accepted', status: 1 },
				{ id: 'confirmed', name: 'Confirmed', status: 2, key: 'wrapped-key' },
			],
			organizationsNew: [
				{ id: 'invited', name: 'Invited', status: 0 },
				{ id: 'accepted', name: 'Accepted', status: 1 },
				{ id: 'confirmed', name: 'Confirmed', status: 2, key: 'wrapped-key' },
			],
			providerOrganizations: [{ id: 'provider', name: 'Managed by provider', key: 'provider-wrapped-key' }],
		},
	});
	try {
		expect(vault.listOrganizations()).toEqual([
			{ id: 'confirmed', name: 'Confirmed', status: 2 },
		]);
		expect(vault.findOrganization('Managed by provider')).toMatchObject({
			id: 'provider',
			name: 'Managed by provider',
			status: 2,
		});
	} finally {
		vault.dispose();
	}
});
test('edits reuse the existing item key and send the client revision guard', async () => {
	const vault = service((path, init) => {
		expect(path).toEndWith('/api/ciphers/item');
		expect(init.method).toBe('PUT');
		const data = JSON.parse(String(init.body));
		expect(data.lastKnownRevisionDate).toBe('2026-01-01T00:00:00Z');
		expect(data.encryptedFor).toBe('user');
		expect(transformItem(data, itemKey, 'decrypt').name).toBe('Changed');
		return Response.json({ ...data, id: 'item', revisionDate: '2026-01-01T00:00:01Z' });
	}, { profile: { id: 'user', premiumPersonally: true }, ciphers: [wire()] });
	const item = await vault.getItem('item');
	item.name = 'Changed';
	expect((await vault.editItem('item', item)).name).toBe('Changed');
});
test('item creation enforces the connected Vaultwarden version before posting', async () => {
	const requests: string[] = [];
	const vault = service((path, init) => {
		const url = new URL(path);
		requests.push(`${init.method ?? 'GET'} ${url.pathname}`);
		if (url.pathname === '/api/config') return Response.json({ server: { name: 'Vaultwarden' } });
		if (url.pathname === '/api/version') return Response.json('1.36.0');
		throw new Error(`Unexpected request: ${url.pathname}`);
	});
	try {
		await expect(vault.createItem({
			type: 6,
			name: 'Bank account',
			bankAccount: { accountNumber: 'synthetic-number' },
		} as never)).rejects.toThrow('bank account requires Vaultwarden 1.37.4 or newer');
		expect(requests).toEqual(['GET /api/config', 'GET /api/version']);
	} finally {
		vault.dispose();
	}
});
test('Vaultwarden 1.36.0 allows a regular member to create an organization item without a collection', async () => {
	const { snapshot, orgKey } = organizationSnapshot();
	Object.assign(snapshot.profile.organizations[0]!, { status: 2, type: 2 });
	const requests: string[] = [];
	const vault = service((path, init) => {
		requests.push(path);
		if (path.endsWith('/api/config')) return Response.json({ server: { name: 'Vaultwarden' } });
		if (path.endsWith('/api/version')) return Response.json('1.36.0');
		if (path.endsWith('/api/ciphers/create')) {
			const body = JSON.parse(String(init.body));
			expect(body.collectionIds).toEqual([]);
			return Response.json({ ...body.cipher, id: 'created', organizationId: 'org', collectionIds: [] });
		}
		throw new Error(`Unexpected request: ${path}`);
	}, snapshot);
	try {
		const created = await vault.createItem({
			type: 1,
			name: 'Unassigned organization item',
			organizationId: 'org',
			collectionIds: [],
		} as never);
		expect(created.organizationId).toBe('org');
		expect(requests).toEqual([
			'https://example.com/api/config',
			'https://example.com/api/version',
			'https://example.com/api/ciphers/create',
		]);
	} finally {
		vault.dispose();
		orgKey.fill(0);
	}
});
test('Vaultwarden 1.37.4 rejects collectionless organization item creation for regular members before posting', async () => {
	const { snapshot, orgKey } = organizationSnapshot();
	Object.assign(snapshot.profile.organizations[0]!, { status: 2, type: 2 });
	const requests: string[] = [];
	const vault = service(path => {
		requests.push(path);
		if (path.endsWith('/api/config')) return Response.json({ server: { name: 'Vaultwarden' } });
		if (path.endsWith('/api/version')) return Response.json('1.37.4');
		throw new Error(`Unexpected request: ${path}`);
	}, snapshot);
	try {
		await expect(vault.createItem({
			type: 1,
			name: 'Unassigned organization item',
			organizationId: 'org',
			collectionIds: [],
		} as never)).rejects.toThrow('Vaultwarden request failed (HTTP 400).');
		expect(requests).toEqual(['https://example.com/api/config', 'https://example.com/api/version']);
	} finally {
		vault.dispose();
		orgKey.fill(0);
	}
});
test('Vaultwarden full-access members can create an organization item without a collection', async () => {
	const { snapshot, orgKey } = organizationSnapshot();
	Object.assign(snapshot.profile.organizations[0]!, {
		status: 2,
		type: 4,
		permissions: { editAnyCollection: true },
	});
	const requests: string[] = [];
	const vault = service((path, init) => {
		requests.push(path);
		if (path.endsWith('/api/config')) return Response.json({ server: { name: 'Vaultwarden' } });
		if (path.endsWith('/api/version')) return Response.json('1.37.4');
		if (path.endsWith('/api/ciphers/create')) {
			const body = JSON.parse(String(init.body));
			expect(body.collectionIds).toEqual([]);
			return Response.json({ ...body.cipher, id: 'created', organizationId: 'org', collectionIds: [] });
		}
		throw new Error(`Unexpected request: ${path}`);
	}, snapshot);
	try {
		const created = await vault.createItem({
			type: 1,
			name: 'Unassigned organization item',
			organizationId: 'org',
			collectionIds: [],
		} as never);
		expect(created.organizationId).toBe('org');
		expect(requests).toEqual([
			'https://example.com/api/config',
			'https://example.com/api/version',
			'https://example.com/api/ciphers/create',
		]);
	} finally {
		vault.dispose();
		orgKey.fill(0);
	}
});
test('organization item creation rejects inaccessible collections before posting', async () => {
	const { snapshot, orgKey } = organizationSnapshot();
	Object.assign(snapshot.profile.organizations[0]!, { type: 2 });
	Object.assign(snapshot.collections[0]!, { readOnly: true });
	let requests = 0;
	const vault = service(() => {
		requests++;
		return Response.json({});
	}, snapshot);
	try {
		await expect(vault.createItem({
			type: 1,
			name: 'Inaccessible organization item',
			organizationId: 'org',
			collectionIds: ['collection'],
		} as never)).rejects.toThrow('You do not have permission to add items to this collection.');
		expect(requests).toBe(0);
	} finally {
		vault.dispose();
		orgKey.fill(0);
	}
});
test('moving a newer cipher enforces the connected Vaultwarden version before sharing', async () => {
	const requests: string[] = [];
	const vault = service((path, init) => {
		const url = new URL(path);
		requests.push(`${init.method ?? 'GET'} ${url.pathname}`);
		if (url.pathname === '/api/config') return Response.json({ server: { name: 'Vaultwarden' } });
		if (url.pathname === '/api/version') return Response.json('1.36.0');
		throw new Error(`Unexpected request: ${url.pathname}`);
	}, { profile: { id: 'user' }, ciphers: [wire({ type: 6 })], folders: [] });
	try {
		await expect(vault.moveItem('item', 'org', [])).rejects.toThrow(
			'bank account requires Vaultwarden 1.37.4 or newer',
		);
		expect(requests).toEqual(['GET /api/config', 'GET /api/version']);
	} finally {
		vault.dispose();
	}
});
test('archived-item edit prompt adapts the hosted entitlement check to Vaultwarden', async () => {
	const archived = wire({ id: 'archived', archivedDate: '2026-01-01T00:00:00Z' });
	const bitwardenRequests: string[] = [];
	const unentitled = service(path => {
		bitwardenRequests.push(path);
		return Response.json({ server: { name: 'Bitwarden' } });
	}, {
		profile: { id: 'user' },
		ciphers: [archived, wire({ id: 'active' })],
		folders: [],
	});
	const vaultwardenRequests: string[] = [];
	const vaultwarden = service(path => {
		vaultwardenRequests.push(path);
		return Response.json({ server: { name: 'Vaultwarden' } });
	}, {
		profile: { id: 'user', premium: false, premiumPersonally: false },
		ciphers: [archived],
		folders: [],
	});
	const personallyEntitled = service(path => {
		throw new Error(`Unexpected request: ${path}`);
	}, {
		profile: { id: 'user', premiumPersonally: true },
		ciphers: [archived],
		folders: [],
	});
	const organizationEntitled = service(path => {
		throw new Error(`Unexpected request: ${path}`);
	}, {
		profile: { id: 'user', premiumFromOrganization: true },
		ciphers: [archived],
		folders: [],
	});
	expect(await unentitled.shouldUnarchiveBeforeEdit('archived')).toBe(true);
	expect(await vaultwarden.shouldUnarchiveBeforeEdit('archived')).toBe(false);
	expect(await personallyEntitled.shouldUnarchiveBeforeEdit('archived')).toBe(false);
	expect(await organizationEntitled.shouldUnarchiveBeforeEdit('archived')).toBe(false);
	expect(await unentitled.shouldUnarchiveBeforeEdit('active')).toBe(false);
	expect(bitwardenRequests).toEqual(['https://example.com/api/config']);
	expect(vaultwardenRequests).toEqual(['https://example.com/api/config']);
});
test('editing a deleted item is rejected before making a server request', async () => {
	let requests = 0;
	const vault = service(() => {
		requests++;
		return Response.json({});
	}, { profile: { id: 'user' }, ciphers: [wire({ deletedDate: '2026-01-01T00:00:00Z' })], folders: [] });
	await expect(vault.editItem('item', await vault.getItem('item'))).rejects.toThrow(
		'You may not edit a deleted item. Use the restore command first.',
	);
	expect(requests).toBe(0);
});
test('editing a personal item cannot assign an organization outside move', async () => {
	let requests = 0;
	const vault = service(() => {
		requests++;
		return Response.json({});
	});
	try {
		await expect(vault.editItem('item', {
			...(await vault.getItem('item')),
			organizationId: '11111111-1111-1111-1111-111111111111',
		})).rejects.toThrow('Use move to change item ownership.');
		expect(requests).toBe(0);
	} finally {
		vault.dispose();
	}
});
test('member confirmation validates member and organization GUIDs before requests', async () => {
	let requests = 0;
	const vault = service(() => {
		requests++;
		return Response.json({});
	});
	try {
		await expect(vault.confirmMember('11111111-1111-1111-1111-111111111111', 'not-a-guid')).rejects.toThrow(
			'`not-a-guid` is not a GUID.',
		);
		await expect(vault.confirmMember('not-a-guid', '11111111-1111-1111-1111-111111111111')).rejects.toThrow(
			'`not-a-guid` is not a GUID.',
		);
		expect(requests).toBe(0);
	} finally {
		vault.dispose();
	}
});
test('member confirmation reports the pinned status-specific errors before requesting keys', async () => {
	const organizationId = '11111111-1111-1111-1111-111111111111';
	const memberId = '22222222-2222-2222-2222-222222222222';
	for (
		const [status, message] of [
			[0, 'User must accept the invitation before they can be confirmed.'],
			[2, 'User is already confirmed.'],
			[3, 'User is revoked and cannot be confirmed.'],
			[4, 'User is not in a valid state to be confirmed.'],
		] as const
	) {
		const requests: string[] = [];
		const vault = service(path => {
			requests.push(path);
			return Response.json({ status });
		});
		try {
			await expect(vault.confirmMember(organizationId, memberId)).rejects.toThrow(message);
			expect(requests).toEqual([
				`https://example.com/api/organizations/${organizationId}/users/${memberId}`,
			]);
		} finally {
			vault.dispose();
		}
	}
});
test('member confirmation uses the accepted user account key, not a key in the membership projection', async () => {
	const organizationId = '11111111-1111-1111-1111-111111111111';
	const memberId = '22222222-2222-2222-2222-222222222222';
	const userId = '33333333-3333-3333-3333-333333333333';
	const { snapshot, orgKey } = organizationSnapshot();
	(snapshot.profile.organizations as JsonObject[])[0]!.id = organizationId;
	const memberKeys = generateKeyPairSync('rsa', {
		modulusLength: 2048,
		publicKeyEncoding: { type: 'spki', format: 'der' },
		privateKeyEncoding: { type: 'pkcs8', format: 'der' },
	});
	const projectionKeys = generateKeyPairSync('rsa', {
		modulusLength: 2048,
		publicKeyEncoding: { type: 'spki', format: 'der' },
		privateKeyEncoding: { type: 'pkcs8', format: 'der' },
	});
	let confirmBody: JsonObject | undefined;
	const vault = service((path, init) => {
		if (path.endsWith(`/users/${memberId}`)) {
			return Response.json({ status: 1, userId, publicKey: projectionKeys.publicKey.toString('base64') });
		}
		if (path.endsWith(`/users/${userId}/public-key`)) {
			return Response.json({ publicKey: memberKeys.publicKey.toString('base64') });
		}
		if (path.endsWith(`/users/${memberId}/confirm`)) {
			confirmBody = JSON.parse(String(init.body)) as JsonObject;
			return Response.json({});
		}
		throw new Error(`Unexpected request: ${path}`);
	}, snapshot);
	try {
		await vault.confirmMember(organizationId, memberId);
		expect(await decryptSharedKey(String(confirmBody?.key), memberKeys.privateKey)).toEqual(orgKey);
		await expect(decryptSharedKey(String(confirmBody?.key), projectionKeys.privateKey)).rejects.toThrow();
		expect(decrypt(String(confirmBody?.defaultUserCollectionName), orgKey).toString('utf8')).toBe('My Items');
	} finally {
		vault.dispose();
		orgKey.fill(0);
		memberKeys.privateKey.fill(0);
		projectionKeys.privateKey.fill(0);
	}
});
test('confirmed personal-ownership policies block personal edits for non-admin members', async () => {
	let requests = 0;
	const organizationId = 'org';
	const vault = service(() => {
		requests++;
		return Response.json({});
	}, {
		profile: { id: 'user', organizations: [policyOrganization(organizationId)] },
		policies: [{ organizationId, type: 5, enabled: true }],
		ciphers: [wire()],
		folders: [],
	});
	await expect(vault.editItem('item', await vault.getItem('item'))).rejects.toThrow(
		'An organization policy restricts editing this cipher. Please use the share command first before modifying it.',
	);
	expect(requests).toBe(0);
});
test('personal-ownership policy from accepted organization sync data blocks edits in the library', async () => {
	let requests = 0;
	const vault = service(() => {
		requests++;
		return Response.json({});
	}, {
		profile: { id: 'user', organizations: [policyOrganization('org')] },
		policiesNew: [{ organizationId: 'org', type: 5, enabled: true }],
		ciphers: [wire()],
		folders: [],
	});
	await expect(vault.editItem('item', await vault.getItem('item'))).rejects.toThrow(
		'An organization policy restricts editing this cipher. Please use the share command first before modifying it.',
	);
	expect(requests).toBe(0);
});
test('personal-ownership policy precheck ignores owners, admins, invited memberships, and disabled policies', async () => {
	for (
		const membership of [
			policyOrganization('org', { type: 0 }),
			policyOrganization('org', { type: 1 }),
			policyOrganization('org', { status: 0 }),
			policyOrganization('org', { status: 3 }),
			policyOrganization('org', { status: 4 }),
			policyOrganization('org', { enabled: false }),
			policyOrganization('org', { usePolicies: false }),
			policyOrganization('org', { isProviderUser: true }),
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
		await vault.editItem('item', await vault.getItem('item'));
		expect(requests).toBe(1);
	}
});
test('personal-ownership policies apply to accepted organization members', async () => {
	const vault = service(() => Response.json({}), {
		profile: { id: 'user', organizations: [policyOrganization('org', { status: 1 })] },
		policies: [{ organizationId: 'org', type: 5, enabled: true }],
		ciphers: [wire()],
		folders: [],
	});
	await expect(vault.editItem('item', await vault.getItem('item'))).rejects.toThrow(
		'An organization policy restricts editing this cipher. Please use the share command first before modifying it.',
	);
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
			wire({ id: 'missing-edit', edit: undefined }),
			wire({ id: 'no-delete', permissions: { delete: false } }),
			wire({ id: 'no-restore', deletedDate: '2026-01-01T00:00:00Z', permissions: { restore: false } }),
		],
		folders: [],
	});
	await expect(vault.editItem('read-only', await vault.getItem('read-only'))).rejects.toMatchObject({
		message: 'You do not have permission to edit this item',
	});
	await expect(vault.editItem('missing-edit', await vault.getItem('missing-edit'))).rejects.toMatchObject({
		message: 'You do not have permission to edit this item',
	});
	await expect(vault.deleteItem('no-delete')).rejects.toThrow('You do not have permission to delete this item.');
	await expect(vault.restoreItem('no-restore')).rejects.toThrow('You do not have permission to restore this item');
	expect(requests).toBe(0);
});
test('delete and restore use their own permissions instead of the edit flag', async () => {
	const requests: string[] = [];
	const vault = service(path => {
		requests.push(path);
		return Response.json({});
	}, {
		profile: { id: 'user' },
		ciphers: [
			wire({ id: 'delete-only', edit: false, permissions: { delete: true } }),
			wire({ id: 'restore-only', edit: false, deletedDate: '2026-01-01T00:00:00Z', permissions: { restore: true } }),
			wire({ id: 'missing-delete', edit: true, permissions: {} }),
			wire({ id: 'missing-restore', edit: true, deletedDate: '2026-01-01T00:00:00Z', permissions: {} }),
		],
		folders: [],
	});
	try {
		await vault.deleteItem('delete-only');
		await vault.restoreItem('restore-only');
		await expect(vault.deleteItem('missing-delete')).rejects.toThrow('You do not have permission to delete this item.');
		await expect(vault.restoreItem('missing-restore')).rejects.toThrow(
			'You do not have permission to restore this item',
		);
		expect(requests).toEqual([
			'https://example.com/api/ciphers/delete-only/delete',
			'https://example.com/api/ciphers/restore-only/restore',
		]);
	} finally {
		vault.dispose();
	}
});
test('Vaultwarden collection managers can edit, delete, and restore despite read-only sync flags', async () => {
	for (const serverName of ['Vaultwarden', 'Bitwarden']) {
		for (const operation of ['edit', 'delete', 'restore'] as const) {
			const { snapshot, orgKey } = organizationSnapshot();
			Object.assign(snapshot.profile.organizations[0]!, { type: 3 });
			Object.assign(snapshot.collections[0]!, { readOnly: true, hidePasswords: true, manage: true });
			const cipherKey = Buffer.alloc(64, 18);
			const cipher = {
				...encryptItem(plaintext, cipherKey),
				id: 'managed-item',
				key: encrypt(cipherKey, orgKey),
				organizationId: 'org',
				collectionIds: ['collection'],
				revisionDate: '2026-01-01T00:00:00Z',
				edit: false,
				viewPassword: false,
				permissions: { delete: false, restore: false },
				...(operation === 'restore' ? { deletedDate: '2026-01-01T00:00:00Z' } : {}),
			};
			snapshot.ciphers.push(cipher);
			const requests: string[] = [];
			const vault = service(path => {
				if (path.endsWith('/api/config')) return Response.json({ server: { name: serverName } });
				requests.push(path);
				return Response.json(cipher);
			}, snapshot);
			try {
				const action = () =>
					operation === 'edit'
						? vault.editItem('managed-item', { type: 1, name: 'Renamed' })
						: operation === 'delete'
						? vault.deleteItem('managed-item')
						: vault.restoreItem('managed-item');
				if (serverName === 'Vaultwarden') {
					await action();
					expect(requests).toHaveLength(1);
					expect(requests[0]).toContain('/api/ciphers/managed-item');
				} else {
					await expect(action()).rejects.toThrow();
					expect(requests).toEqual([]);
				}
			} finally {
				vault.dispose();
				orgKey.fill(0);
				cipherKey.fill(0);
			}
		}
	}
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
			wire({
				id: 'archived-and-trashed',
				archivedDate: '2026-01-01T00:00:00Z',
				deletedDate: '2026-01-02T00:00:00Z',
				permissions: { restore: true },
			}),
		],
	});
	await vault.restoreItem('archived');
	await vault.restoreItem('archived-and-trashed');
	expect(paths).toEqual([
		'PUT https://example.com/api/ciphers/archived/unarchive',
		'PUT https://example.com/api/ciphers/archived-and-trashed/restore',
	]);
});
test('restore lowercases a cipher ID before the API request', async () => {
	const paths: string[] = [];
	const vault = service(path => {
		paths.push(path);
		return Response.json({});
	}, {
		profile: { id: 'user' },
		ciphers: [wire({ deletedDate: '2026-01-02T00:00:00Z', permissions: { restore: true } })],
		folders: [],
	});
	try {
		await vault.restoreItem('ITEM');
		expect(paths).toEqual(['https://example.com/api/ciphers/item/restore']);
	} finally {
		vault.dispose();
	}
});
test('folder edits and deletes accept uppercase IDs and send lowercase request paths', async () => {
	const encryptedName = encrypt(Buffer.from('Folder'), userKey);
	const paths: string[] = [];
	const vault = service(path => {
		paths.push(path);
		return Response.json({ id: 'folder', name: encryptedName });
	}, {
		profile: { id: 'user' },
		ciphers: [],
		folders: [{ id: 'folder', name: encryptedName }],
	});
	try {
		await vault.editFolder('FOLDER', { name: 'Renamed' });
		await vault.deleteFolder('FOLDER');
		expect(paths).toEqual([
			'https://example.com/api/folders/folder',
			'https://example.com/api/folders/folder',
		]);
	} finally {
		vault.dispose();
	}
});
test('editing a hidden-password item leaves CLI-redacted secrets unchanged', async () => {
	const privateItem = {
		type: 1,
		name: 'Private',
		login: {
			username: 'person',
			password: 'hidden-password',
			totp: 'hidden-totp',
			fido2Credentials: [{ credentialId: 'credential-id', keyValue: 'hidden-passkey-key' }],
		},
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
		edit: true,
		permissions: { delete: true, restore: true },
		viewPassword: false,
		revisionDate: '2026-01-01T00:00:00Z',
	};
	let submitted: JsonObject | undefined;
	const vault = service((_path, init) => {
		submitted = transformItem(JSON.parse(String(init.body)), itemKey, 'decrypt');
		return Response.json({ ...JSON.parse(String(init.body)), id: 'item', viewPassword: false });
	}, { profile: { id: 'user' }, ciphers: [existing], folders: [] });
	const response = vaultItemResponse(await vault.getItem('item'));
	expect(JSON.stringify(response)).not.toContain('hidden-password');
	expect(JSON.stringify(response)).not.toContain('hidden-totp');
	expect(JSON.stringify(response)).not.toContain('hidden-passkey-key');
	expect(JSON.stringify(response)).not.toContain('hidden-custom-value');
	expect(JSON.stringify(response)).not.toContain('second-hidden-custom-value');
	response.name = 'Renamed';
	await vault.editItem('item', response as Parameters<VaultService['editItem']>[1]);
	expect((submitted?.login as JsonObject).password).toBe('hidden-password');
	expect((submitted?.login as JsonObject).totp).toBe('hidden-totp');
	expect(((submitted?.login as JsonObject).fido2Credentials as JsonObject[])[0]?.keyValue)
		.toBe('hidden-passkey-key');
	expect(((submitted?.fields as JsonObject[])[0] ?? {}).value).toBe('hidden-custom-value');
	expect(((submitted?.fields as JsonObject[])[1] ?? {}).value).toBe('second-hidden-custom-value');
	expect(submitted?.name).toBe('Renamed');
});
test('editing a hidden-password non-login item does not require a login section', async () => {
	const existing = {
		...encryptItem({ type: 3, name: 'Private card', card: { number: 'hidden-card-number' } }, itemKey),
		id: 'card',
		key: encrypt(itemKey, userKey),
		edit: true,
		viewPassword: false,
		revisionDate: '2026-01-01T00:00:00Z',
	};
	let submitted: JsonObject | undefined;
	const vault = service((_path, init) => {
		submitted = transformItem(JSON.parse(String(init.body)), itemKey, 'decrypt');
		return Response.json({ ...JSON.parse(String(init.body)), id: 'card', viewPassword: false });
	}, { profile: { id: 'user' }, ciphers: [existing], folders: [] });
	try {
		const response = vaultItemResponse(await vault.getItem('card'));
		response.name = 'Renamed card';
		await vault.editItem('card', response as Parameters<VaultService['editItem']>[1]);
		expect(submitted?.name).toBe('Renamed card');
		expect(submitted?.card).toMatchObject({ number: 'hidden-card-number' });
	} finally {
		vault.dispose();
	}
});
test('item collection edits reject personal items before mutation', async () => {
	let requests = 0;
	const vault = service(() => {
		requests++;
		return Response.json({});
	}, {
		profile: { id: 'user' },
		collections: [],
		ciphers: [wire({ id: 'personal' })],
	});
	await expect(vault.editItemCollections('personal', [])).rejects.toThrow(
		'Item does not belong to an organization. Consider moving it first.',
	);
	expect(requests).toBe(0);
});
test('bw refuses collection edits when password access is hidden', async () => {
	const { snapshot, orgKey } = organizationSnapshot();
	const cipherKey = Buffer.alloc(64, 14);
	const cipher = {
		...encryptItem({ ...plaintext, name: 'Hidden organization item' }, cipherKey),
		id: 'hidden-item',
		key: encrypt(cipherKey, orgKey),
		organizationId: 'org',
		collectionIds: ['collection'],
		viewPassword: false,
	};
	snapshot.ciphers.push(cipher);
	const requests: string[] = [];
	const vault = service(path => {
		requests.push(path);
		if (path.endsWith('/api/config')) return Response.json({ server: { name: 'Bitwarden' } });
		return Response.json(cipher);
	}, snapshot);
	try {
		await expect(vault.editItemCollections('hidden-item', ['collection'])).rejects.toThrow(
			'You do not have permission to edit this item',
		);
		expect(requests).toEqual(['https://example.com/api/config']);
	} finally {
		vault.dispose();
		orgKey.fill(0);
		cipherKey.fill(0);
	}
});
test('Vaultwarden allows collection managers to edit assignments when password access is hidden', async () => {
	const { snapshot, orgKey } = organizationSnapshot();
	const cipherKey = Buffer.alloc(64, 18);
	const cipher = {
		...encryptItem({ ...plaintext, name: 'Managed hidden organization item' }, cipherKey),
		id: 'managed-hidden-item',
		key: encrypt(cipherKey, orgKey),
		organizationId: 'org',
		collectionIds: ['collection'],
		viewPassword: false,
	};
	snapshot.ciphers.push(cipher);
	snapshot.collections.push({ id: 'writable', organizationId: 'org', readOnly: false, manage: false });
	Object.assign(snapshot.collections[0]!, { readOnly: true, hidePasswords: true, manage: true });
	const requests: string[] = [];
	const vault = service((path, init) => {
		requests.push(`${init.method ?? 'GET'} ${path}`);
		if (path.endsWith('/api/config')) return Response.json({ server: { name: 'Vaultwarden' } });
		if (path.endsWith('/api/ciphers/managed-hidden-item/collections')) {
			expect(JSON.parse(String(init.body))).toEqual({ collectionIds: ['collection', 'writable'] });
			return Response.json({ ...cipher, collectionIds: ['collection', 'writable'] });
		}
		throw new Error(`Unexpected request: ${path}`);
	}, snapshot);
	try {
		expect((await vault.editItemCollections('managed-hidden-item', ['collection', 'writable'])).collectionIds)
			.toEqual(['collection', 'writable']);
		expect(requests).toEqual([
			'GET https://example.com/api/config',
			'PUT https://example.com/api/ciphers/managed-hidden-item/collections',
		]);
	} finally {
		vault.dispose();
		orgKey.fill(0);
		cipherKey.fill(0);
	}
});
test('item collection edits reject read-only target collections before mutation', async () => {
	const { snapshot, orgKey } = organizationSnapshot();
	const cipherKey = Buffer.alloc(64, 15);
	snapshot.ciphers.push({
		...encryptItem({ ...plaintext, name: 'Hidden organization item' }, cipherKey),
		id: 'hidden-item',
		key: encrypt(cipherKey, orgKey),
		organizationId: 'org',
		collectionIds: [],
		edit: true,
		viewPassword: true,
	});
	snapshot.collections[0]!.readOnly = true;
	snapshot.collections[0]!.manage = true;
	let requests = 0;
	const vault = service(() => {
		requests++;
		return Response.json({});
	}, snapshot);
	try {
		await expect(vault.editItemCollections('hidden-item', ['collection'])).rejects.toThrow(
			'You do not have permission to edit this collection.',
		);
		delete snapshot.collections[0]!.readOnly;
		await expect(vault.editItemCollections('hidden-item', ['collection'])).rejects.toThrow(
			'You do not have permission to edit this collection.',
		);
		expect(requests).toBe(0);
	} finally {
		vault.dispose();
		orgKey.fill(0);
		cipherKey.fill(0);
	}
});
test('Vaultwarden refuses collection reassignment from a read-only source collection', async () => {
	const { snapshot, orgKey } = organizationSnapshot();
	const cipherKey = Buffer.alloc(64, 27);
	snapshot.ciphers.push({
		...encryptItem({ ...plaintext, name: 'Read-only source collection item' }, cipherKey),
		id: 'read-only-source-item',
		key: encrypt(cipherKey, orgKey),
		organizationId: 'org',
		collectionIds: ['collection'],
		edit: false,
		viewPassword: true,
	});
	Object.assign(snapshot.collections[0]!, { readOnly: true, hidePasswords: false, manage: false });
	snapshot.collections.push({ id: 'writable', organizationId: 'org', readOnly: false, manage: false });
	const requests: string[] = [];
	const vault = service(path => {
		requests.push(path);
		if (path.endsWith('/api/config')) return Response.json({ server: { name: 'Vaultwarden' } });
		throw new Error(`Unexpected request: ${path}`);
	}, snapshot);
	try {
		await expect(vault.editItemCollections('read-only-source-item', ['collection', 'writable'])).rejects.toThrow(
			'You do not have permission to edit this item',
		);
		expect(requests).toEqual(['https://example.com/api/config']);
	} finally {
		vault.dispose();
		orgKey.fill(0);
		cipherKey.fill(0);
	}
});
test('item collection edits reject removing an assignment from a non-writable collection before mutation', async () => {
	const { snapshot, orgKey } = organizationSnapshot();
	const cipherKey = Buffer.alloc(64, 17);
	snapshot.ciphers.push({
		...encryptItem({ ...plaintext, name: 'Read-only organization item' }, cipherKey),
		id: 'read-only-item',
		key: encrypt(cipherKey, orgKey),
		organizationId: 'org',
		collectionIds: ['collection'],
		edit: true,
		viewPassword: true,
	});
	Object.assign(snapshot.collections[0]!, { readOnly: true, manage: false });
	let requests = 0;
	const vault = service(() => {
		requests++;
		return Response.json({});
	}, snapshot);
	try {
		await expect(vault.editItemCollections('read-only-item', [])).rejects.toThrow(
			'You do not have permission to edit this collection.',
		);
		expect(requests).toBe(0);
	} finally {
		vault.dispose();
		orgKey.fill(0);
		cipherKey.fill(0);
	}
});
test('collection reassignment validates changed memberships and gives Vaultwarden owners/admins server access', async () => {
	for (const serverName of ['Vaultwarden', 'Bitwarden']) {
		const { snapshot, orgKey } = organizationSnapshot();
		Object.assign(snapshot.profile.organizations[0]!, { type: 1, allowAdminAccessToAllCollectionItems: false });
		Object.assign(snapshot.collections[0]!, { readOnly: true, manage: false });
		const cipherKey = Buffer.alloc(64, 16);
		const cipher = {
			...encryptItem({ ...plaintext, name: 'Organization item' }, cipherKey),
			id: 'organization-item',
			key: encrypt(cipherKey, orgKey),
			organizationId: 'org',
			collectionIds: [],
			edit: true,
			viewPassword: true,
		};
		snapshot.ciphers.push(cipher);
		const requests: string[] = [];
		const vault = service(path => {
			requests.push(path);
			if (path.endsWith('/api/config')) return Response.json({ server: { name: serverName } });
			if (serverName === 'Vaultwarden') {
				expect(path).toEndWith('/api/ciphers/organization-item/collections');
				return Response.json({ ...cipher, collectionIds: ['collection'] });
			}
			throw new Error('Bitwarden must not receive a collection update for a read-only collection.');
		}, snapshot);
		try {
			if (serverName === 'Vaultwarden') {
				expect((await vault.editItemCollections('organization-item', ['collection'])).organizationId).toBe('org');
				expect(requests).toEqual([
					'https://example.com/api/config',
					'https://example.com/api/ciphers/organization-item/collections',
				]);
			} else {
				await expect(vault.editItemCollections('organization-item', ['collection'])).rejects.toThrow(
					'You do not have permission to edit this collection.',
				);
				expect(requests).toEqual(['https://example.com/api/config']);
			}
		} finally {
			vault.dispose();
			orgKey.fill(0);
			cipherKey.fill(0);
		}
	}
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
			organizations: [{
				id: organizationId,
				key: await encryptSharedKey(organizationKey, publicKey.toString('base64')),
			}],
		},
		collections: [{ id: collectionId, organizationId, readOnly: false, manage: false }],
		ciphers: [
			{ ...cipher, edit: true, viewPassword: true },
		],
	});
	try {
		const updated = await vault.editItemCollections('ORGANIZATION-ITEM', [collectionId.toUpperCase()]);
		expect(requestBody).toEqual({ collectionIds: [collectionId.toUpperCase()] });
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
	const requests: string[] = [];
	const vault = service(path => {
		requests.push(path);
		if (path.endsWith('/api/config')) return Response.json({ server: { name: 'Bitwarden' } });
		return Response.json({});
	}, {
		profile: { id: 'user', premiumPersonally: false, premiumFromOrganization: false },
		ciphers: [wire({ id: 'already-archived', archivedDate: '2026-01-01T00:00:00Z' })],
	});
	await expect(vault.archiveItem('already-archived')).rejects.toThrow(
		'Premium status is required to use this feature.',
	);
	expect(requests).toEqual(['https://example.com/api/config']);
});
test('Vaultwarden archive uses server access instead of the Bitwarden premium gate', async () => {
	const requests: string[] = [];
	const vault = service((path, init) => {
		requests.push(`${init.method ?? 'GET'} ${path}`);
		if (path.endsWith('/api/config')) return Response.json({ server: { name: 'Vaultwarden' } });
		return Response.json({});
	}, {
		profile: { id: 'user', premiumPersonally: false, premiumFromOrganization: false },
		ciphers: [wire()],
	});
	try {
		await vault.archiveItem('item');
		expect(requests).toEqual([
			'GET https://example.com/api/config',
			'PUT https://example.com/api/ciphers/item/archive',
		]);
	} finally {
		vault.dispose();
	}
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
test('lists distinguish trash and archive and combine object filters with OR', async () => {
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
	expect((await vault.listItems()).map(i => i.id)).toEqual(['item', 'folder']);
	expect((await vault.listItems({ trash: true })).map(i => i.id)).toEqual(['trash']);
	expect((await vault.listItems({ trash: true, archived: true })).map(i => i.id)).toEqual(['trash-archive']);
	expect((await vault.listItems({ archived: true })).map(i => i.id)).toEqual(['archive']);
	expect((await vault.listItems({ folderId: 'folder', organizationId: 'notnull' })).map(i => i.id)).toEqual(['folder']);
});
test('basic list search matches bank, driver-license, and passport subtitles after decryption', async () => {
	const ciphers = [
		wire({
			...encryptItem({ type: 6, name: 'Bank record', bankAccount: { bankName: 'Fixture Bank' } }, itemKey),
			id: 'bank',
		}),
		wire({
			...encryptItem(
				{ type: 7, name: 'License record', driversLicense: { firstName: 'Fixture', issuingState: 'NH' } },
				itemKey,
			),
			id: 'license',
		}),
		wire({
			...encryptItem(
				{ type: 8, name: 'Passport record', passport: { givenName: 'Fixture', issuingCountry: 'NL' } },
				itemKey,
			),
			id: 'passport',
		}),
	];
	const vault = service(() => Response.json({}), { profile: { id: 'user' }, folders: [], ciphers });
	try {
		for (const [query, id] of [['Fixture Bank', 'bank'], ['Fixture NH', 'license'], ['Fixture NL', 'passport']]) {
			expect((await vault.listItems({ search: query })).map(item => item.id)).toEqual([id]);
		}
	} finally {
		vault.dispose();
	}
});
test('item list ID filters compare case-sensitively like the reference CLI', async () => {
	const folderId = 'abcdef11-1111-1111-1111-111111111111';
	const { orgKey, snapshot } = organizationSnapshot();
	Object.assign(snapshot, { folders: [{ id: folderId, name: encrypt(Buffer.from('Folder'), userKey) }] });
	snapshot.ciphers = [
		wire({
			id: 'matching',
			folderId,
			organizationId: 'org',
			collectionIds: ['collection'],
			key: encrypt(itemKey, orgKey),
		}),
	];
	const vault = service(() => Response.json({}), snapshot);
	try {
		expect((await vault.listItems({ folderId })).map(item => item.id)).toEqual(['matching']);
		expect((await vault.listItems({ organizationId: 'org' })).map(item => item.id)).toEqual(['matching']);
		expect((await vault.listItems({ collectionId: 'collection' })).map(item => item.id)).toEqual(['matching']);
		expect(await vault.listItems({ folderId: folderId.toUpperCase() })).toEqual([]);
		expect(await vault.listItems({ organizationId: 'ORG' })).toEqual([]);
		expect(await vault.listItems({ collectionId: 'COLLECTION' })).toEqual([]);
	} finally {
		vault.dispose();
		orgKey.fill(0);
	}
});
test('archived listing follows the synced premium capability', async () => {
	const vault = service(() => Response.json({}), {
		profile: { id: 'user', premium: false, organizations: [{ id: 'org' }] },
		folders: [],
		ciphers: [wire(), wire({ id: 'archive', archivedDate: 'date' })],
	});
	expect((await vault.listItems({ archived: true })).map(item => item.id)).toEqual(['item']);
	const organizationPremiumVault = service(() => Response.json({}), {
		profile: { id: 'user', premium: false, premiumFromOrganization: true },
		folders: [],
		ciphers: [wire(), wire({ id: 'archive', archivedDate: 'date' })],
	});
	expect((await organizationPremiumVault.listItems({ archived: true })).map(item => item.id)).toEqual(['archive']);
});
test('Vaultwarden archive and list agree when all synced premium fields are false', async () => {
	const snapshot = {
		profile: { id: 'user', premium: false, premiumPersonally: false, premiumFromOrganization: false },
		folders: [],
		ciphers: [wire(), wire({ id: 'archive', archivedDate: '2026-01-01T00:00:00Z' })],
	};
	const vault = service((path, init) => {
		if (path.endsWith('/api/config')) return Response.json({ server: { name: 'Vaultwarden' } });
		expect(init.method).toBe('PUT');
		return new Response(null, { status: 204 });
	}, snapshot);
	try {
		await vault.archiveItem('item');
		(snapshot.ciphers[0]! as JsonObject).archivedDate = '2026-01-02T00:00:00Z';
		expect((await vault.listItems({ archived: true })).map(item => item.id)).toEqual(['item', 'archive']);
		expect(await vault.listItems()).toEqual([]);
	} finally {
		vault.dispose();
	}
});
test('restricted-item policies hide disallowed items and deny item and attachment reads before requests', async () => {
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
		wire({ id, type, organizationId, key: encrypt(itemKey, organizationKey), permissions: { delete: true } });
	let requests = 0;
	const vault = service(() => {
		requests++;
		return Response.json({});
	}, {
		profile: {
			id: 'user',
			privateKey: encrypt(rsa.privateKey, userKey),
			organizations: [
				{ ...policyOrganization(organizationA), key: wrappedKey },
				{ ...policyOrganization(organizationB), key: wrappedKey },
			],
		},
		folders: [],
		policies: [{ organizationId: organizationA.toUpperCase(), type: 15, enabled: true, data: [3] }],
		ciphers: [
			wire({
				id: 'personal-card',
				type: 3,
				attachments: [{ id: 'restricted-file', fileName: encrypt(Buffer.from('policy.txt'), itemKey) }],
			}),
			organizationCipher('org-a-card', 3, organizationA),
			organizationCipher('org-b-card', 3, organizationB),
			organizationCipher('org-a-login', 1, organizationA),
		],
	});
	try {
		expect((await vault.listItems()).map(item => item.id)).toEqual(['org-b-card', 'org-a-login']);
		await expect(vault.findItem('personal-card')).rejects.toThrow(
			'Access to this item type is restricted by organizational policy.',
		);
		await expect(vault.getItem('personal-card')).rejects.toThrow(
			'Access to this item type is restricted by organizational policy.',
		);
		await expect(vault.getAttachment('personal-card', 'restricted-file')).rejects.toThrow(
			'Access to this item type is restricted by organizational policy.',
		);
		await expect(vault.getAttachmentById('personal-card', 'restricted-file')).rejects.toThrow(
			'Access to this item type is restricted by organizational policy.',
		);
		await expect(vault.findItem('org-a-card')).rejects.toThrow(
			'Access to this item type is restricted by organizational policy.',
		);
		await expect(vault.findItem('org-a-card', () => false)).rejects.toThrow(
			'Access to this item type is restricted by organizational policy.',
		);
		expect((await vault.findItem('org-b-card')).id).toBe('org-b-card');
		await expect(vault.editItem('org-a-card', { type: 3, name: 'Restricted card' })).rejects.toThrow(
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
test('restricted-item policies exempt organization owners like the reference policy resolver', () => {
	const organizationId = '11111111-1111-1111-1111-111111111111';
	const vault = service(() => Response.json({}), {
		profile: { id: 'user', organizations: [policyOrganization(organizationId, { type: 0 })] },
		policies: [{ organizationId, type: 15, enabled: true, data: [3] }],
		ciphers: [wire({ id: 'personal-card', type: 3 })],
		folders: [],
	});
	try {
		expect(vault.isRestrictedItem({ type: 3, organizationId })).toBe(false);
	} finally {
		vault.dispose();
	}
});
test('restricted-item policies do not apply when the organization disables policy enforcement', () => {
	const organizationId = '11111111-1111-1111-1111-111111111111';
	const vault = service(() => Response.json({}), {
		profile: {
			id: 'user',
			organizations: [policyOrganization(organizationId, { usePolicies: false })],
		},
		policies: [{ organizationId, type: 15, enabled: true, data: [3] }],
		ciphers: [wire({ id: 'personal-card', type: 3 })],
		folders: [],
	});
	try {
		expect(vault.isRestrictedItem({ type: 3 })).toBe(false);
	} finally {
		vault.dispose();
	}
});
test('restricted-item policies without a synced organization context are enforced by default', () => {
	const vault = service(() => Response.json({}), {
		profile: { id: 'user' },
		policies: [{ organizationId: 'missing-org', type: 15, enabled: true, data: [3] }],
		ciphers: [wire({ id: 'personal-card', type: 3 })],
		folders: [],
	});
	try {
		expect(vault.isRestrictedItem({ type: 3 })).toBe(true);
	} finally {
		vault.dispose();
	}
});
test('restricted-item policies exempt organization administrators and provider users', () => {
	const organizationId = '11111111-1111-1111-1111-111111111111';
	for (
		const membership of [
			policyOrganization(organizationId, { type: 1 }),
			policyOrganization(organizationId, { isProviderUser: true }),
		]
	) {
		const vault = service(() => Response.json({}), {
			profile: { id: 'user', organizations: [membership] },
			policies: [{ organizationId, type: 15, enabled: true, data: [3] }],
			ciphers: [wire({ id: 'personal-card', type: 3 })],
			folders: [],
		});
		try {
			expect(vault.isRestrictedItem({ type: 3 })).toBe(false);
		} finally {
			vault.dispose();
		}
	}
});
test('password health includes visible archived logins and excludes policy-hidden logins', async () => {
	const visibleVault = service(() => Response.json({}), {
		profile: { id: 'user', premium: false },
		folders: [],
		ciphers: [wire({ id: 'active' }), wire({ id: 'archived', archivedDate: '2026-01-01T00:00:00Z' })],
	});
	try {
		expect((await visibleVault.listItems()).map(item => item.id)).toEqual(['active']);
		const rows = await visibleVault.passwordHealth({ checkExposed: false });
		expect(rows.map(row => row.id)).toEqual(['active', 'archived']);
		expect(rows.map(row => row.reuseCount)).toEqual([2, 2]);
	} finally {
		visibleVault.dispose();
	}
	const restrictedVault = service(() => Response.json({}), {
		profile: { id: 'user', premium: false, organizations: [policyOrganization('org')] },
		folders: [],
		policies: [{ organizationId: 'org', type: 15, enabled: true, data: [1] }],
		ciphers: [
			wire({ id: 'policy-hidden-active' }),
			wire({
				id: 'policy-hidden-archived',
				archivedDate: '2026-01-01T00:00:00Z',
			}),
		],
	});
	try {
		expect(await restrictedVault.listItems()).toEqual([]);
		expect(await restrictedVault.passwordHealth({ checkExposed: false })).toEqual([]);
	} finally {
		restrictedVault.dispose();
	}
});
test('decrypts organization items and collections using account RSA private key', async () => {
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
		expect((await vault.listItems())[0]?.name).toBe('Example');
		expect((await vault.listCollections())[0]?.name).toBe('Collection');
		expect((await vault.findCollection('LECT')).name).toBe('Collection');
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
			collections: [{
				id: 'collection',
				organizationId: 'org',
				name: encrypt(Buffer.from('Collection'), orgKey),
				readOnly: false,
				manage: false,
			}],
		} as JsonObject & {
			profile: JsonObject & { organizations: JsonObject[] };
			ciphers: JsonObject[];
			collections: JsonObject[];
		},
	};
}
test('disposing during concurrent organization-key reads invalidates pending work and allows a fresh read', async () => {
	const { snapshot, orgKey } = organizationSnapshot();
	snapshot.ciphers.push({ ...encryptItem(plaintext, orgKey), id: 'shared', organizationId: 'org' });
	const vault = service(() => {
		throw new Error('Key reads must remain offline.');
	}, snapshot);
	try {
		const pending = Promise.allSettled([vault.getItem('shared'), vault.getItem('shared')]);
		vault.dispose();
		const fresh = vault.getItem('shared');
		const results = await pending;
		for (const result of results) {
			expect(result.status).toBe('rejected');
			if (result.status === 'rejected') expect(result.reason.message).toBe('Organization key request was invalidated.');
		}
		expect((await fresh).name).toBe(plaintext.name);
		expect((await vault.listCollections())[0]!.name).toBe('Collection');
		vault.dispose();
		snapshot.profile.organizations[0]!.key = '3.invalid';
		await expect(vault.getItem('shared')).rejects.toThrow('Organization key authentication failed.');
	} finally {
		vault.dispose();
		orgKey.fill(0);
	}
});
test('organization collection listing follows cached visibility and case-insensitive organization IDs', async () => {
	for (
		const [canViewAllCollections, expectedPath] of [
			[true, '/api/organizations/org/collections'],
			[false, '/api/collections'],
		] as const
	) {
		const { snapshot, orgKey } = organizationSnapshot();
		snapshot.profile.organizations[0]!.canViewAllCollections = canViewAllCollections;
		const paths: string[] = [];
		const vault = service(path => {
			paths.push(new URL(path).pathname);
			return Response.json({
				data: [
					{ id: 'visible', organizationId: 'org', name: encrypt(Buffer.from('Visible'), orgKey) },
					{ id: 'same-id-different-case', organizationId: 'ORG', name: encrypt(Buffer.from('Same ID'), orgKey) },
					{ id: 'other', organizationId: 'other', name: encrypt(Buffer.from('Other'), orgKey) },
				],
			});
		}, snapshot);
		try {
			const collections = await vault.listOrganizationCollections(canViewAllCollections ? 'ORG' : 'org');
			expect(paths).toEqual([expectedPath]);
			expect(collections.map(collection => [collection.id, collection.name])).toEqual([
				['visible', 'Visible'],
				['same-id-different-case', 'Same ID'],
			]);
		} finally {
			vault.dispose();
			orgKey.fill(0);
		}
	}
	let requests = 0;
	const missing = service(() => {
		requests++;
		return Response.json({ data: [] });
	}, { profile: { organizations: [] }, collections: [], ciphers: [] });
	try {
		await expect(missing.listOrganizationCollections('org')).rejects.toThrow('Organization not found.');
		await expect(missing.listOrganizationMembers('org')).rejects.toThrow('Organization not found.');
		await expect(missing.getOrganizationCollection('org', 'collection')).rejects.toThrow('Organization not found.');
		expect(requests).toBe(0);
	} finally {
		missing.dispose();
	}
	const { snapshot, orgKey } = organizationSnapshot();
	requests = 0;
	const differentCase = service(path => {
		requests++;
		if (path.includes('/details')) {
			return Response.json({
				id: 'collection',
				organizationId: 'org',
				name: encrypt(Buffer.from('Collection'), orgKey),
			});
		}
		return Response.json({ data: [] });
	}, snapshot);
	try {
		await differentCase.listOrganizationCollections('ORG');
		await differentCase.listOrganizationMembers('ORG');
		await differentCase.getOrganizationCollection('ORG', 'collection');
		expect(requests).toBe(3);
	} finally {
		differentCase.dispose();
		orgKey.fill(0);
	}
});
test('organization member listing matches the pinned response projection', async () => {
	const { snapshot, orgKey } = organizationSnapshot();
	const vault = service(() =>
		Response.json({
			data: [{
				id: 'member',
				email: 'member@example.test',
				name: 'Member',
				status: 2,
				type: 0,
				twoFactorEnabled: true,
				internalField: 'must not escape',
			}],
		}), snapshot);
	try {
		expect(await vault.listOrganizationMembers('org')).toEqual([{
			object: 'org-member',
			id: 'member',
			email: 'member@example.test',
			name: 'Member',
			status: 2,
			type: 0,
			twoFactorEnabled: true,
		}]);
	} finally {
		vault.dispose();
		orgKey.fill(0);
	}
});
test('item edits merge omitted organization ownership, sections, fields, and collections like bw', async () => {
	const { orgKey, snapshot } = organizationSnapshot();
	snapshot.ciphers.push({
		...encryptItem(plaintext, itemKey),
		id: 'item',
		organizationId: 'org',
		collectionIds: ['collection'],
		key: encrypt(itemKey, orgKey),
		edit: true,
		permissions: { delete: true, restore: true },
		revisionDate: '2026-01-01T00:00:00Z',
	});
	const vault = service((path, init) => {
		expect(path).toEndWith('/api/ciphers/item');
		const data = JSON.parse(String(init.body));
		expect(data.organizationId).toBe('org');
		expect(data.collectionIds).toEqual(['collection']);
		expect(data.lastKnownRevisionDate).toBe('2026-01-01T00:00:00Z');
		const key = decrypt(data.key, orgKey);
		try {
			expect(transformItem(data, key, 'decrypt')).toMatchObject({
				name: 'Edited',
				login: plaintext.login,
				fields: plaintext.fields,
			});
		} finally {
			key.fill(0);
		}
		return Response.json({ ...data, id: 'item', organizationId: 'org', collectionIds: ['collection'] });
	}, snapshot);
	try {
		const result = await vault.editItem('item', { type: 1, name: 'Edited' });
		expect(result.organizationId).toBe('org');
		expect(result.login).toMatchObject(plaintext.login);
	} finally {
		vault.dispose();
		orgKey.fill(0);
	}
});
test('item edits leave omitted relationships unchanged but honor explicit relationship and field clears', async () => {
	let requestBody: JsonObject | undefined;
	const vault = service((_path, init) => {
		requestBody = JSON.parse(String(init.body)) as JsonObject;
		return Response.json({ ...requestBody, id: 'item' });
	}, {
		profile: { id: 'user' },
		ciphers: [wire({ folderId: 'folder', collectionIds: ['collection-a', 'collection-b'] })],
		folders: [],
	});
	try {
		await vault.editItem('item', { type: 1, collectionIds: [], folderId: null, notes: null, favorite: false });
		expect(requestBody).toMatchObject({
			collectionIds: [],
			folderId: null,
			notes: null,
			favorite: false,
		});
		const key = decrypt(String(requestBody!.key), userKey);
		try {
			expect(transformItem(requestBody!, key, 'decrypt')).toMatchObject({
				name: plaintext.name,
				login: plaintext.login,
				fields: plaintext.fields,
				passwordHistory: plaintext.passwordHistory,
			});
		} finally {
			key.fill(0);
		}
	} finally {
		vault.dispose();
	}
});
test('item edits honor an explicit key and rewrap attachment metadata without changing file keys', async () => {
	const nextItemKey = Buffer.alloc(64, 4);
	const attachmentKey = Buffer.alloc(64, 5);
	const snapshot = {
		profile: { id: 'user' },
		folders: [],
		ciphers: [wire({
			attachments: [{
				id: 'attachment',
				fileName: encrypt(Buffer.from('report.txt'), itemKey),
				key: encrypt(attachmentKey, itemKey),
				url: 'https://example.com/attachment',
				size: '12',
			}, {
				id: 'legacy-attachment',
				fileName: encrypt(Buffer.from('legacy.txt'), itemKey),
				url: 'https://example.com/legacy-attachment',
				size: '8',
			}],
		})],
	};
	const vault = service((_path, init) => {
		const body = JSON.parse(String(init.body));
		const wrappedItemKey = decrypt(body.key, userKey);
		try {
			expect(wrappedItemKey).toEqual(nextItemKey);
			expect(transformItem(body, wrappedItemKey, 'decrypt')).toMatchObject({ name: 'Rekeyed' });
			expect(body.attachments).toBeUndefined();
			expect(Object.keys(body.attachments2)).toEqual(['attachment', 'legacy-attachment']);
			expect(decrypt(body.attachments2.attachment.fileName, wrappedItemKey).toString()).toBe('report.txt');
			expect(decrypt(body.attachments2['legacy-attachment'].fileName, wrappedItemKey).toString()).toBe('legacy.txt');
			const rewrappedAttachmentKey = decrypt(body.attachments2.attachment.key, wrappedItemKey);
			try {
				expect(rewrappedAttachmentKey).toEqual(attachmentKey);
			} finally {
				rewrappedAttachmentKey.fill(0);
			}
			const legacyAttachmentKey = decrypt(body.attachments2['legacy-attachment'].key, wrappedItemKey);
			try {
				expect(legacyAttachmentKey).toEqual(itemKey);
			} finally {
				legacyAttachmentKey.fill(0);
			}
			return Response.json({
				...body,
				id: 'item',
				attachments: Object.entries(body.attachments2).map(([id, attachment]) => ({ id, ...attachment as object })),
			});
		} finally {
			wrappedItemKey.fill(0);
		}
	}, snapshot);
	try {
		await vault.editItem('item', { type: 1, name: 'Rekeyed', key: nextItemKey.toString('base64') });
	} finally {
		vault.dispose();
		nextItemKey.fill(0);
		attachmentKey.fill(0);
	}
});
test('editing a legacy item encrypts data with the account key unless a new item key is supplied', async () => {
	const snapshot = {
		profile: { id: 'user' },
		folders: [],
		ciphers: [{
			...transformItem(plaintext, userKey, 'encrypt'),
			id: 'legacy',
			key: null,
			edit: true,
			permissions: { delete: true, restore: true },
			revisionDate: '2026-01-01T00:00:00Z',
		}],
	};
	const vault = service((_path, init) => {
		const body = JSON.parse(String(init.body));
		expect(body.key).toBeNull();
		expect(transformItem(body, userKey, 'decrypt')).toMatchObject({ name: 'Legacy edit' });
		return Response.json({ ...body, id: 'legacy' });
	}, snapshot);
	try {
		await vault.editItem('legacy', { type: 1, name: 'Legacy edit' });
	} finally {
		vault.dispose();
	}
});
test('item edits reject malformed explicit item keys before a server write', async () => {
	let requests = 0;
	const vault = service(() => {
		requests++;
		return Response.json({});
	});
	try {
		await expect(vault.editItem('item', { type: 1, name: 'Bad key', key: Buffer.alloc(16).toString('base64') }))
			.rejects.toThrow('Invalid item key; expected a base64-encoded 512-bit key.');
		expect(requests).toBe(0);
	} finally {
		vault.dispose();
	}
});
test('item edit policy checks the requested type after merging, like bw', async () => {
	const { orgKey, snapshot } = organizationSnapshot();
	Object.assign(snapshot.profile.organizations[0]!, policyOrganization('org'));
	snapshot.policies = [{ organizationId: 'org', type: 15, enabled: true, data: [3] }];
	snapshot.ciphers.push({
		...wire({ organizationId: 'org', key: encrypt(itemKey, orgKey) }),
	});
	let requests = 0;
	const vault = service(() => {
		requests++;
		return Response.json({});
	}, snapshot);
	try {
		await expect(vault.editItem('item', {
			type: 3,
			name: 'Restricted type',
			card: { cardholderName: 'Fixture' },
		})).rejects.toThrow('Editing this item type is restricted by organizational policy.');
		expect(requests).toBe(0);
	} finally {
		vault.dispose();
		orgKey.fill(0);
	}
});
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
test('collectionless moves apply the connected server version and membership permissions', async () => {
	for (
		const [serverName, version, status, type, accessAll, allowed] of [
			['Vaultwarden', '1.36.0', 2, 2, false, true],
			['Vaultwarden', '1.37.4', 2, 2, false, false],
			['Vaultwarden', '1.37.4', 2, 1, false, true],
			['Vaultwarden', '1.37.4', 2, 4, true, true],
			['Vaultwarden', '1.37.4', 1, 2, false, false],
			['Bitwarden', undefined, 2, 2, false, false],
		] as const
	) {
		const { snapshot, orgKey } = organizationSnapshot([wire()]);
		Object.assign(snapshot.profile.organizations[0]!, { status, type, accessAll });
		const requests: string[] = [];
		const vault = service((path, init) => {
			requests.push(path);
			if (path.endsWith('/api/config')) return Response.json({ server: { name: serverName } });
			if (version && path.endsWith('/api/version')) return Response.json(version);
			if (allowed && path.endsWith('/api/ciphers/item/share')) {
				const body = JSON.parse(String(init.body));
				expect(body.collectionIds).toEqual([]);
				return Response.json({ ...body.cipher, id: 'item', organizationId: 'org', collectionIds: [] });
			}
			throw new Error(`Unexpected request: ${path}`);
		}, snapshot);
		try {
			if (allowed) {
				expect((await vault.moveItem('item', 'org', [])).organizationId).toBe('org');
				expect(requests).toContain('https://example.com/api/ciphers/item/share');
			} else {
				await expect(vault.moveItem('item', 'org', [])).rejects.toThrow(
					serverName === 'Bitwarden'
						? 'You must provide at least one collection id for this item.'
						: 'Vaultwarden request failed (HTTP 400).',
				);
				expect(requests).not.toContain('https://example.com/api/ciphers/item/share');
			}
		} finally {
			vault.dispose();
			orgKey.fill(0);
		}
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
test('collection rename omits access assignments so the server leaves them unchanged', async () => {
	const { snapshot, orgKey } = organizationSnapshot();
	const vault = service((path, init) => {
		if (path.endsWith('/api/config')) return Response.json({ server: { name: 'Bitwarden' } });
		expect(path).toEndWith('/api/organizations/org/collections/collection');
		expect(init.method).toBe('PUT');
		const body = JSON.parse(String(init.body));
		expect(body.users).toBeNull();
		expect(body.groups).toBeNull();
		expect(body.externalId).toBeUndefined();
		expect(decrypt(body.name, orgKey).toString()).toBe('New');
		return Response.json({
			id: 'collection',
			name: body.name,
			users: [{ id: 'member', readOnly: true, hidePasswords: true, manage: false }],
			groups: [{ id: 'group' }],
		});
	}, snapshot);
	try {
		expect((await vault.editCollection('ORG', 'COLLECTION', { name: 'New', organizationId: 'org' })).name).toBe(
			'New',
		);
	} finally {
		vault.dispose();
	}
});
test('Vaultwarden collection rename sends fresh assignments because its update endpoint replaces them', async () => {
	const { snapshot, orgKey } = organizationSnapshot();
	const vault = service((path, init) => {
		if (path.endsWith('/api/config')) return Response.json({ server: { name: 'Vaultwarden' } });
		if (path.endsWith('/api/organizations/org/collections/collection/details')) {
			expect(init.method).toBe('GET');
			return Response.json({
				id: 'collection',
				name: encrypt(Buffer.from('Old'), orgKey),
				groups: [{ id: 'group', readOnly: true, hidePasswords: false, manage: true }],
				users: [{ id: 'member', readOnly: false, hidePasswords: true, manage: true }],
			});
		}
		expect(path).toEndWith('/api/organizations/org/collections/collection');
		expect(init.method).toBe('PUT');
		const body = JSON.parse(String(init.body));
		expect(body.groups).toEqual([{ id: 'group', readOnly: true, hidePasswords: false, manage: true }]);
		expect(body.users).toEqual([{ id: 'member', readOnly: false, hidePasswords: true, manage: true }]);
		return Response.json({ id: 'collection', name: body.name, groups: body.groups, users: body.users });
	}, snapshot);
	try {
		expect((await vault.editCollection('org', 'collection', { name: 'Renamed' })).name).toBe('Renamed');
	} finally {
		vault.dispose();
		orgKey.fill(0);
	}
});
test('Vaultwarden collection rename refuses to replace access when details omit assignments', async () => {
	const { snapshot, orgKey } = organizationSnapshot();
	const requests: string[] = [];
	const vault = service(path => {
		requests.push(new URL(path).pathname);
		if (path.endsWith('/api/config')) return Response.json({ server: { name: 'Vaultwarden' } });
		if (path.endsWith('/api/organizations/org/collections/collection/details')) {
			return Response.json({ id: 'collection', name: encrypt(Buffer.from('Old'), orgKey) });
		}
		return Response.json({}, { status: 500 });
	}, snapshot);
	try {
		await expect(vault.editCollection('org', 'collection', { name: 'Renamed' })).rejects.toThrow(
			'Vaultwarden collection access details are incomplete; refusing to replace assignments.',
		);
		expect(requests).toEqual([
			'/api/config',
			'/api/organizations/org/collections/collection/details',
		]);
	} finally {
		vault.dispose();
		orgKey.fill(0);
	}
});
test('new organization collections grant the current member manage access by default', async () => {
	const { snapshot, orgKey } = organizationSnapshot();
	const vault = service((path, init) => {
		if (path.endsWith('/api/config')) return Response.json({ server: { name: 'Bitwarden' } });
		expect(path).toEndWith('/api/organizations/org/collections');
		expect(init.method).toBe('POST');
		const body = JSON.parse(String(init.body));
		expect(body.groups).toBeNull();
		expect(body.users).toEqual([{ id: 'membership', readOnly: false, hidePasswords: false, manage: true }]);
		return Response.json({ id: 'created-collection', name: encrypt(Buffer.from('Created'), orgKey) });
	}, snapshot);
	try {
		expect((await vault.createCollection('ORG', { name: 'Created' })).name).toBe('Created');
	} finally {
		vault.dispose();
		orgKey.fill(0);
	}
});
test('Vaultwarden collection creation sends empty group assignments when omitted', async () => {
	const { snapshot, orgKey } = organizationSnapshot();
	const vault = service((path, init) => {
		if (path.endsWith('/api/config')) return Response.json({ server: { name: 'Vaultwarden' } });
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

test('custom roles with editAnyCollection can assign items to read-only collections', async () => {
	const { snapshot, orgKey } = organizationSnapshot();
	Object.assign(snapshot.profile.organizations[0]!, {
		status: 2,
		type: 4,
		permissions: { editAnyCollection: true },
	});
	Object.assign(snapshot.collections[0]!, { readOnly: true, manage: false });
	const cipher = {
		...encryptItem(plaintext, itemKey),
		id: 'custom-role-item',
		key: encrypt(itemKey, orgKey),
		organizationId: 'org',
		collectionIds: [],
		edit: true,
		viewPassword: true,
	};
	snapshot.ciphers.push(cipher);
	const requests: string[] = [];
	const vault = service((path, init) => {
		requests.push(`${init.method ?? 'GET'} ${path}`);
		expect(path).toEndWith('/api/ciphers/custom-role-item/collections');
		expect(init.method).toBe('PUT');
		expect(JSON.parse(String(init.body))).toEqual({ collectionIds: ['collection'] });
		return Response.json({ ...cipher, collectionIds: ['collection'] });
	}, snapshot);
	try {
		expect((await vault.editItemCollections('custom-role-item', ['collection'])).collectionIds)
			.toEqual(['collection']);
		expect(requests).toEqual([
			'PUT https://example.com/api/ciphers/custom-role-item/collections',
		]);
	} finally {
		vault.dispose();
		orgKey.fill(0);
	}
});

test('move follows Vaultwarden owner and admin collection writability without changing Bitwarden checks', async () => {
	for (const serverName of ['Vaultwarden', 'Bitwarden']) {
		const { snapshot, orgKey } = organizationSnapshot([wire()]);
		Object.assign(snapshot.profile.organizations[0]!, {
			type: 1,
			allowAdminAccessToAllCollectionItems: false,
		});
		Object.assign(snapshot.collections[0]!, { readOnly: true, manage: false });
		const requests: string[] = [];
		const vault = service((path, init) => {
			requests.push(path);
			if (path.endsWith('/api/config')) return Response.json({ server: { name: serverName } });
			if (serverName === 'Vaultwarden') {
				expect(path).toEndWith('/api/ciphers/item/share');
				const body = JSON.parse(String(init.body));
				return Response.json({ ...body.cipher, id: 'item', organizationId: 'org' });
			}
			throw new Error('Bitwarden must not receive a share request for a read-only collection.');
		}, snapshot);
		try {
			if (serverName === 'Vaultwarden') {
				expect((await vault.moveItem('item', 'org', ['collection'])).organizationId).toBe('org');
				expect(requests).toEqual([
					'https://example.com/api/config',
					'https://example.com/api/ciphers/item/share',
				]);
			} else {
				await expect(vault.moveItem('item', 'org', ['collection'])).rejects.toThrow(
					'You do not have permission to add items to this collection.',
				);
				expect(requests).toEqual(['https://example.com/api/config']);
			}
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
		expect((await vault.moveItem('ITEM', 'ORG', ['COLLECTION'])).organizationId).toBe('org');
	} finally {
		vault.dispose();
		orgKey.fill(0);
	}
});

test('edit, delete, and archive lowercase cipher IDs like bw before lookup and mutation', async () => {
	for (const operation of ['edit', 'delete', 'archive'] as const) {
		const paths: string[] = [];
		const snapshot = {
			profile: { id: 'user', premium: true },
			ciphers: [wire({ permissions: { delete: true } })],
			folders: [],
		};
		const vault = service((path) => {
			paths.push(path);
			return Response.json(wire());
		}, snapshot);
		try {
			if (operation === 'edit') await vault.editItem('ITEM', plaintext as never);
			else if (operation === 'delete') await vault.deleteItem('ITEM');
			else await vault.archiveItem('ITEM');
			expect(paths).toEqual([
				`https://example.com/api/ciphers/item${
					operation === 'delete' ? '/delete' : operation === 'archive' ? '/archive' : ''
				}`,
			]);
		} finally {
			vault.dispose();
		}
	}
});

test('move rejects read-only collections for a regular organization member before mutation', async () => {
	for (const manage of [false, true]) {
		const { snapshot, orgKey } = organizationSnapshot([wire()]);
		Object.assign(snapshot.profile.organizations[0]!, { type: 2 });
		Object.assign(snapshot.collections[0]!, { readOnly: true, manage });
		let calls = 0;
		const vault = service(() => {
			calls++;
			return Response.json({});
		}, snapshot);
		try {
			await expect(vault.moveItem('item', 'org', ['collection'])).rejects.toThrow(
				'You do not have permission to add items to this collection.',
			);
			expect(calls).toBe(0);
		} finally {
			vault.dispose();
			orgKey.fill(0);
		}
	}
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

test('attachment size limits follow Bitwarden plaintext and Vaultwarden encrypted payload caps', () => {
	const bitwardenMaximum = 500 * 1024 * 1024;
	const vaultwardenMaximum = Math.floor((550_502_400 - 49) / 16) * 16 - 1;
	expect(() => assertAttachmentSize(bitwardenMaximum, false)).not.toThrow();
	expect(() => assertAttachmentSize(bitwardenMaximum + 1, false)).toThrow('500 MiB');
	expect(() => assertAttachmentSize(vaultwardenMaximum, true)).not.toThrow();
	expect(() => assertAttachmentSize(vaultwardenMaximum + 1, true)).toThrow('Vaultwarden size');
	for (const size of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
		expect(() => assertAttachmentSize(size, false)).toThrow('Invalid attachment size.');
	}
});

test('oversized Bitwarden attachments are rejected before attachment metadata is created', async () => {
	const requests: string[] = [];
	const vault = service(path => {
		requests.push(path);
		if (path.endsWith('/api/config')) return Response.json({ server: { name: 'Bitwarden' } });
		throw new Error(`Unexpected request: ${path}`);
	});
	try {
		const oversized = { length: 500 * 1024 * 1024 + 1 } as Uint8Array;
		await expect(vault.createAttachment('item', 'large.bin', oversized)).rejects.toThrow('500 MiB');
		expect(requests).toEqual(['https://example.com/api/config']);
	} finally {
		vault.dispose();
	}
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
			'Attachment "missing" was not found.',
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

test('exact attachment IDs beat colliding filenames and ID-only downloads reject searches', async () => {
	const key = Buffer.alloc(64, 9);
	const attachments = [
		{ id: 'first', fileName: encrypt(Buffer.from('file.bin'), itemKey), key: encrypt(key, itemKey) },
		{ id: 'second', fileName: encrypt(Buffer.from('first'), itemKey), key: encrypt(key, itemKey) },
	];
	const requests: string[] = [];
	const vault = service(path => {
		requests.push(path);
		if (path.endsWith('/attachment/first')) return Response.json({ url: 'https://example.com/files/first' });
		if (path.endsWith('/files/first')) {
			return new Response(new Uint8Array(encryptAttachment(Buffer.from('first-body'), key)));
		}
		throw new Error('Unexpected attachment request.');
	}, { profile: { id: 'user', premium: true }, ciphers: [wire({ attachments })] });
	try {
		await expect(vault.getAttachmentById('Example', 'first')).rejects.toThrow('Item not found');
		await expect(vault.getAttachmentById('item', 'file.bin')).rejects.toThrow('Attachment ID was not found');
		expect(requests).toHaveLength(0);
		const queryResult = await vault.getAttachment('item', 'first');
		try {
			expect(queryResult.contents.toString()).toBe('first-body');
			expect(queryResult.fileName).toBe('file.bin');
		} finally {
			queryResult.contents.fill(0);
		}
		expect(requests).toHaveLength(2);
		const result = await vault.getAttachmentById('ITEM', 'FIRST');
		try {
			expect(result.contents.toString()).toBe('first-body');
		} finally {
			result.contents.fill(0);
		}
		expect(requests).toHaveLength(4);
	} finally {
		vault.dispose();
		key.fill(0);
	}
});

test('attachment metadata falls back only on 404 and uses cached keys without credentials', async () => {
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
test('attachment download requires premium for personal items before attachment requests', async () => {
	let configRequests = 0, attachmentRequests = 0;
	const attachment = {
		id: 'attachment',
		fileName: encrypt(Buffer.from('private.bin'), itemKey),
		key: encrypt(Buffer.alloc(64, 8), itemKey),
	};
	const vault = service(path => {
		if (path.endsWith('/api/config')) {
			configRequests++;
			return Response.json({ server: { name: 'Bitwarden' } });
		}
		attachmentRequests++;
		return Response.json({});
	}, {
		profile: { premiumPersonally: false, premiumFromOrganization: false },
		ciphers: [wire({ attachments: [attachment] })],
	});
	try {
		expect(await vault.canAccessAttachment('item')).toBe(false);
		await expect(vault.getAttachment('item', 'private.bin')).rejects.toThrow(
			'Premium status is required to use this feature.',
		);
		await expect(vault.createAttachment('item', 'private.bin', Buffer.from('synthetic'))).rejects.toThrow(
			'Premium status is required to use this feature.',
		);
		await expect(vault.deleteAttachment('item', 'attachment')).rejects.toThrow(
			'Premium status is required to use this feature.',
		);
		expect(configRequests).toBe(1);
		expect(attachmentRequests).toBe(0);
	} finally {
		vault.dispose();
	}
	const organization = service(() => Response.json({}), {
		profile: { premiumPersonally: false, organizations: [{ id: 'org' }] },
		ciphers: [{ id: 'organization-item', organizationId: 'org' }],
	});
	try {
		expect(await organization.canAccessAttachment('organization-item')).toBe(true);
	} finally {
		organization.dispose();
	}
});
test('Vaultwarden attachment operations use server access instead of the Bitwarden premium gate', async () => {
	const attachmentKey = Buffer.alloc(64, 12);
	const contents = Buffer.from('unpaid Vaultwarden attachment');
	const paths: string[] = [];
	const existingAttachment = {
		id: 'existing',
		fileName: encrypt(Buffer.from('existing.bin'), itemKey),
		key: encrypt(attachmentKey, itemKey),
	};
	const vault = service((path, init) => {
		paths.push(`${init.method ?? 'GET'} ${path}`);
		if (path.endsWith('/api/config')) return Response.json({ server: { name: 'Vaultwarden' } });
		if (path.endsWith('/attachment/v2')) {
			return Response.json({
				attachmentId: 'uploaded',
				fileUploadType: 0,
				cipherResponse: wire(),
			});
		}
		if (path.endsWith('/attachment/uploaded') && init.method === 'POST') return new Response(null, { status: 204 });
		if (path.endsWith('/attachment/existing') && init.method === 'GET') {
			return Response.json({ url: 'https://example.com/signed-file' });
		}
		if (path.endsWith('/signed-file')) {
			expect(new Headers(init.headers).has('Authorization')).toBe(false);
			return new Response(new Uint8Array(encryptAttachment(contents, attachmentKey)));
		}
		if (path.endsWith('/attachment/existing') && init.method === 'DELETE') return Response.json({});
		throw new Error(`Unexpected attachment request: ${init.method} ${path}`);
	}, {
		profile: { id: 'user', premiumPersonally: false, premiumFromOrganization: false },
		ciphers: [wire({ attachments: [existingAttachment] })],
	});
	try {
		expect(await vault.canAccessAttachment('item')).toBe(true);
		await vault.createAttachment('item', 'uploaded.bin', Buffer.from('upload'));
		const downloaded = await vault.getAttachment('item', 'existing.bin');
		expect(downloaded.contents).toEqual(contents);
		downloaded.contents.fill(0);
		await vault.deleteAttachment('item', 'existing');
		expect(paths.map(value => value.split(' ')[0])).toEqual([
			'GET',
			'POST',
			'POST',
			'GET',
			'GET',
			'DELETE',
		]);
	} finally {
		vault.dispose();
		attachmentKey.fill(0);
	}
});
test('Bitwarden attachments upload encrypted contents to Azure without account credentials', async () => {
	let uploaded = false, renewed = false;
	const vault = service((path, init) => {
		if (path.endsWith('/attachment/v2')) {
			const data = JSON.parse(String(init.body));
			return Response.json({
				attachmentId: 'azure-attachment',
				fileUploadType: 1,
				url: 'https://storage.example/blob?sv=2023-11-03&se=2000-01-01T00%3A00%3A00Z&sig=expired',
				cipherResponse: wire({
					attachments: [{ id: 'azure-attachment', fileName: data.fileName, key: data.key, size: data.fileSize }],
				}),
			});
		}
		if (path.endsWith('/ciphers/item/attachment/azure-attachment/renew')) {
			expect(init.method).toBe('GET');
			renewed = true;
			return Response.json({ url: 'https://storage.example/blob?sv=2023-11-03&sig=renewed' });
		}
		expect(path).toBe('https://storage.example/blob?sv=2023-11-03&sig=renewed');
		expect(init.method).toBe('PUT');
		expect(new Headers(init.headers).get('Authorization')).toBeNull();
		expect(Buffer.from(init.body as Buffer).includes(Buffer.from('synthetic attachment'))).toBe(false);
		uploaded = true;
		return new Response(null, { status: 201 });
	}, {
		profile: { id: 'user', premiumPersonally: true },
		ciphers: [wire()],
	});
	try {
		const result = await vault.createAttachment('item', 'synthetic.bin', Buffer.from('synthetic attachment'));
		expect(result.id).toBe('item');
		expect(uploaded).toBe(true);
		expect(renewed).toBe(true);
	} finally {
		vault.dispose();
	}
});
test('failed Azure attachment upload removes metadata without exposing the signed URL', async () => {
	const methods: string[] = [];
	const signedUrl = 'https://storage.example/blob?sv=2023-11-03&se=2099-01-01T00%3A00%3A00Z&sig=synthetic-secret';
	const vault = service((path, init) => {
		methods.push(init.method!);
		if (path.endsWith('/attachment/v2')) {
			const data = JSON.parse(String(init.body));
			return Response.json({
				attachmentId: 'azure-attachment',
				fileUploadType: 1,
				url: signedUrl,
				cipherResponse: wire({
					attachments: [{ id: 'azure-attachment', fileName: data.fileName, key: data.key, size: data.fileSize }],
				}),
			});
		}
		if (path === signedUrl) {
			expect(new Headers(init.headers).get('Authorization')).toBeNull();
			return new Response(null, { status: 500 });
		}
		expect(path).toBe('https://example.com/api/ciphers/item/attachment/azure-attachment');
		expect(init.method).toBe('DELETE');
		return Response.json({});
	}, { profile: { id: 'user', premiumPersonally: true }, ciphers: [wire()] });
	try {
		await expect(vault.createAttachment('item', 'synthetic.bin', Buffer.from('synthetic attachment')))
			.rejects.toThrow('Attachment upload failed; incomplete metadata was removed.');
		expect(methods).toEqual(['POST', 'PUT', 'DELETE']);
	} finally {
		vault.dispose();
	}
});
test('attachment deletion validates membership before sending the server request', async () => {
	let requests = 0;
	const vault = service((path, init) => {
		requests++;
		expect(path).toEndWith('/api/ciphers/item/attachment/abc123');
		expect(init.method).toBe('DELETE');
		return Response.json({});
	}, { profile: { premiumPersonally: true }, ciphers: [wire({ attachments: [{ id: 'AbC123' }] })] });
	await expect(vault.deleteAttachment('item', 'missing')).rejects.toThrow('Attachment `missing` was not found.');
	expect(requests).toBe(0);
	await vault.deleteAttachment('ITEM', 'ABC123');
	expect(requests).toBe(1);
	const empty = service(() => {
		requests++;
		return Response.json({});
	}, { profile: {}, ciphers: [wire({ attachments: [] })] });
	await expect(empty.deleteAttachment('item', 'missing')).rejects.toThrow('No attachments available for this item.');
	expect(requests).toBe(1);
});
