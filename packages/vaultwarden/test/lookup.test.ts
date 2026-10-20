import { test, expect } from 'bun:test';
import { fingerprintWords } from '#fingerprint';
import { findNamedObject, searchItems } from '#search';
import { matchesUri, matchUriRegex } from '#uri-match';
import { VaultwardenClient } from '#client';
import { VaultService } from '#vault-service';
import { encrypt } from '#crypto';
import { decryptOwnedItem } from '#vault';
import { transformItem, encryptItem, validUriChecksum } from '#item-codec';
import type { VaultItem } from '#models';

test('named objects use case-insensitive substrings and UUID-only ID reads, without exact-name precedence', () => {
	const id = 'abcdef01-0000-0000-0000-000000000001';
	const missing = 'abcdef01-0000-0000-0000-000000000099';
	const values = [
		{ id, name: 'Café Work' },
		{ id: 'abcdef02-0000-0000-0000-000000000002', name: 'Café Work Archive' },
		{ id: 'abcdef03-0000-0000-0000-000000000003', name: missing },
		{ id: 'abcdef04-0000-0000-0000-000000000004', name: null },
	];
	expect(findNamedObject(values, 'ARCHIVE')).toBe(values[1]!);
	expect(findNamedObject(values, ' work ')).toBe(values[1]!);
	expect(findNamedObject(values, id.toUpperCase())).toBe(values[0]!);
	for (const query of ['Café Work', 'work', '']) expect(() => findNamedObject(values, query)).toThrow();
	for (const query of [missing, 'cafe', 'work café', '  work ', '   ']) {
		expect(() => findNamedObject(values, query)).toThrow('not found');
	}
	expect(values[0]!.name).toBe('Café Work');
});

test('folder and organization searches operate on decrypted views and omit organization key material', () => {
	const key = Buffer.alloc(64, 9), id = 'abcdef01-0000-0000-0000-000000000001';
	const vault = new VaultService(new VaultwardenClient('https://example.com'), 'synthetic', {
		profile: { organizations: [{ id, name: 'Engineering Company', key: 'synthetic-org-key' }] },
		folders: [{ id, name: encrypt(Buffer.from('Engineering Work'), key) }],
	}, key);
	try {
		expect(vault.findFolder('WORK').name).toBe('Engineering Work');
		expect(vault.findFolder(id.toUpperCase()).id).toBe(id);
		expect(vault.findOrganization('company')).toEqual({ id, name: 'Engineering Company' });
		expect(vault.findOrganization(id.toUpperCase()).id).toBe(id);
	} finally {
		vault.dispose();
		key.fill(0);
	}
});

test('fingerprint matches an independent Python SHA256/HMAC/big-integer vector', () => {
	expect(fingerprintWords('test@example.com', new Uint8Array(256))).toEqual([
		'visitor',
		'precision',
		'relight',
		'irritate',
		'request',
	]);
	expect(fingerprintWords('different', new Uint8Array(256))).not.toEqual(
		fingerprintWords('test@example.com', new Uint8Array(256)),
	);
	expect(() => fingerprintWords('identity', new Uint8Array())).toThrow('public key');
});
const items: VaultItem[] = [
	{
		id: '12345678-0000-0000-0000-000000000001',
		type: 1,
		name: 'Café Work',
		notes: 'Archived project',
		login: {
			username: 'alice@company.com',
			password: 'do-not-search-this',
			uris: [{ uri: 'https://accounts.example.com/private/path?secret=excluded' }],
		},
	},
	{
		id: '87654321-0000-0000-0000-000000000002',
		type: 3,
		name: 'Payment',
		card: { brand: 'Visa', number: '4111111111119876', code: '123' },
	},
	{
		id: 'cccccccc-0000-0000-0000-000000000003',
		type: 4,
		name: 'Profile',
		identity: { firstName: 'John', lastName: 'Doe', ssn: 'excluded-ssn' },
	},
];
test('basic item search ANDs normalized terms across display fields, URI hostnames and ID prefixes', () => {
	for (const query of ['CAFE alice', 'project work', 'company example', '12345678', 'cafe accounts']) {
		expect(searchItems(items, query).map(item => item.id)).toEqual([items[0]!.id]);
	}
	expect(searchItems(items, 'visa 9876')[0]?.id).toBe(items[1]!.id);
	expect(searchItems(items, 'doe john')[0]?.id).toBe(items[2]!.id);
	for (const query of ['do-not-search-this', 'private/path', 'excluded-ssn', '11111111', '1234567']) {
		expect(searchItems(items, query)).toEqual([]);
	}
	expect(searchItems(items, 'work missing')).toEqual([]);
});
test('URI matching honors all six strategies, domain boundaries, private suffixes, ports, IDNs and the google script exclusion', async () => {
	expect(await matchesUri({ uri: 'https://login.example.co.uk', match: 0 }, 'https://www.example.co.uk/other')).toBe(
		true,
	);
	expect(await matchesUri({ uri: 'https://alice.github.io', match: 0 }, 'https://bob.github.io')).toBe(false);
	expect(await matchesUri({ uri: 'https://example.com', match: 0 }, 'https://example.com.evil.test')).toBe(false);
	expect(await matchesUri({ uri: 'https://测试.com', match: 0 }, 'https://xn--0zwm56d.com')).toBe(true);
	expect(await matchesUri({ uri: 'https://google.com', match: 0 }, 'https://script.google.com')).toBe(false);
	expect(await matchesUri({ uri: 'https://example.com:8443/a', match: 1 }, 'http://example.com:8443/b')).toBe(true);
	expect(await matchesUri({ uri: 'https://example.com:8443', match: 1 }, 'https://example.com')).toBe(false);
	expect(await matchesUri({ uri: 'https://example.com/a', match: 2 }, 'https://example.com/abc')).toBe(true);
	expect(await matchesUri({ uri: 'https://example.com/a', match: 3 }, 'https://example.com/a/')).toBe(false);
	expect(await matchesUri({ uri: 'https://example.com/a', match: 3 }, 'https://example.com/a')).toBe(true);
	expect(await matchesUri({ uri: '^https://[a-z]+\\.example\\.com/', match: 4 }, 'HTTPS://login.example.com/x')).toBe(
		true,
	);
	expect(await matchesUri({ uri: '[', match: 4 }, 'https://example.com')).toBe(false);
	expect(await matchesUri({ uri: 'https://example.com', match: 5 }, 'https://example.com')).toBe(false);
	expect(await matchesUri({ uri: 'http://localhost/a' }, 'http://localhost/b')).toBe(true);
	expect(await matchesUri({ uri: 'https://127.0.0.1/a' }, 'http://127.0.0.1/b')).toBe(true);
	expect(
		await matchesUri({ uri: 'https://alias.test' }, 'https://primary.test', {
			equivalentDomains: [['alias.test', 'primary.test']],
		}),
	).toBe(true);
});
test('pathological URI regexes fail within a bounded worker execution window', async () => {
	await expect(matchUriRegex('(a+)+$', 'a'.repeat(10000) + '!')).rejects.toThrow('execution limit');
	expect(await matchUriRegex('example', 'https://example.com')).toBe(true);
});
test('vault lookups filter before resolving ambiguity and distinguish ID reads from active-only name searches', async () => {
	const key = Buffer.alloc(64, 4);
	const clear: VaultItem[] = [
		{ ...items[0]!, collectionIds: [] },
		{ id: '22345678-0000-0000-0000-000000000002', name: 'Café Work', type: 2, secureNote: { type: 0 } },
		{
			id: '32345678-0000-0000-0000-000000000003',
			name: 'Archived only',
			type: 1,
			archivedDate: '2026-01-01',
			login: { password: 'archived' },
		},
		{
			id: '42345678-0000-0000-0000-000000000004',
			name: 'Deleted',
			type: 1,
			deletedDate: '2026-01-01',
			login: { password: 'deleted' },
		},
	];
	const snapshot = {
		profile: { id: 'account' },
		ciphers: clear.map(item => transformItem(item, key, 'encrypt')),
		domains: { equivalentDomains: [['example.com', 'alias.test']] },
	};
	const vault = new VaultService(new VaultwardenClient('https://example.com'), 'token', snapshot, key);
	try {
		expect(() => vault.findItem('cafe work')).toThrow('Multiple');
		expect(vault.findItem('cafe work', item => item.type === 1).id).toBe(items[0]!.id);
		expect(() => vault.findItem('Archived only')).toThrow('not found');
		expect(vault.findItem(clear[2]!.id!).name).toBe('Archived only');
		expect(vault.findItem(clear[3]!.id!).name).toBe('Deleted');
		expect((await vault.listItemsForUrl('https://alias.test')).map(item => item.id)).toEqual([items[0]!.id]);
		expect(vault.listItems({ collectionId: 'null' })).toHaveLength(2);
		expect(vault.listItems({ collectionId: 'notnull' })).toHaveLength(0);
	} finally {
		vault.dispose();
		key.fill(0);
	}
});

test('a missing UUID never falls back to matching another item by name or notes', () => {
	const key = Buffer.alloc(64, 5), missing = 'aaaaaaaa-0000-0000-0000-000000000099';
	const item: VaultItem = {
		id: 'bbbbbbbb-0000-0000-0000-000000000001',
		type: 1,
		name: missing,
		login: { password: 'unrelated' },
	};
	const vault = new VaultService(new VaultwardenClient('https://example.com'), 'token', {
		profile: {},
		ciphers: [transformItem(item, key, 'encrypt')],
	}, key);
	try {
		expect(() => vault.findItem(missing)).toThrow('not found');
		expect(() => vault.findItem(' ')).toThrow('not found');
	} finally {
		vault.dispose();
		key.fill(0);
	}
});

test('writes generate URI checksums, edits replace stale hashes, and keyed reads exclude invalid URIs', () => {
	const owner = Buffer.alloc(64, 6), perItem = Buffer.alloc(64, 7);
	const view = {
		type: 1,
		name: 'URI integrity',
		login: { uris: [{ uri: 'https://example.com', uriChecksum: 'stale' }] },
	};
	const wire = { ...encryptItem(view, perItem), key: encrypt(perItem, owner) };
	const decrypted = decryptOwnedItem(wire, owner);
	const uri = (decrypted.login as { uris: { uri: string; uriChecksum: string }[] }).uris[0]!;
	expect(validUriChecksum(uri)).toBe(true);
	expect(uri.uriChecksum).not.toBe('stale');
	expect(view.login.uris[0]!.uriChecksum).toBe('stale');
	for (const checksum of [undefined, 'stale', uri.uriChecksum]) {
		const badView = {
			type: 1,
			name: 'Bad URI',
			login: { uris: [{ uri: 'https://different.example', uriChecksum: checksum }] },
		};
		const keyed = { ...transformItem(badView, perItem, 'encrypt'), key: encrypt(perItem, owner) };
		expect((decryptOwnedItem(keyed, owner).login as { uris: unknown[] }).uris).toEqual([]);
	}
	const legacy = transformItem(
		{ type: 1, name: 'Legacy', login: { uris: [{ uri: 'https://example.com' }] } },
		owner,
		'encrypt',
	);
	expect((decryptOwnedItem(legacy, owner).login as { uris: unknown[] }).uris).toHaveLength(1);
	owner.fill(0);
	perItem.fill(0);
});
