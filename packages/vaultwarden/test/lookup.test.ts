import { test, expect } from 'bun:test';
import { fingerprintWords } from '#fingerprint';
import { findNamedObject, searchItems, searchItemsAdvanced } from '#search';
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

test('fingerprint accepts the case-insensitive me alias used by bw', async () => {
	const vault = new VaultService(new VaultwardenClient('https://example.com'), 'synthetic', {
		profile: {
			id: 'abcdef01-0000-0000-0000-000000000001',
			publicKey: Buffer.alloc(256).toString('base64'),
		},
	}, Buffer.alloc(64, 7));
	try {
		expect(await vault.fingerprint('Me')).toBe(await vault.fingerprint('me'));
	} finally {
		vault.dispose();
	}
});

test('fingerprint me requires the local key while explicit user IDs use the API', async () => {
	const id = 'abcdef01-0000-0000-0000-000000000001';
	let requests = 0;
	const localFetch = Object.assign(async () => {
		requests++;
		return Response.json({ publicKey: Buffer.alloc(256).toString('base64') });
	}, { preconnect: () => {} });
	const localOnlyVault = new VaultService(
		new VaultwardenClient('https://example.com', {
			fetch: localFetch,
		}),
		'synthetic',
		{ profile: { id } },
		Buffer.alloc(64, 7),
	);
	try {
		await expect(localOnlyVault.fingerprint('me')).rejects.toThrow('No public key available for the active user.');
		expect(requests).toBe(0);
	} finally {
		localOnlyVault.dispose();
	}

	const publicKey = Buffer.alloc(256).toString('base64');
	const remoteFetch = Object.assign(async () => Response.json({ publicKey }), { preconnect: () => {} });
	const remoteVault = new VaultService(
		new VaultwardenClient('https://example.com', {
			fetch: remoteFetch,
		}),
		'synthetic',
		{ profile: { id: 'active-user' } },
		Buffer.alloc(64, 7),
	);
	try {
		expect(await remoteVault.fingerprint(id)).toBe(fingerprintWords(id, Buffer.from(publicKey, 'base64')).join('-'));
	} finally {
		remoteVault.dispose();
	}

	const missingFetch = Object.assign(async () => new Response('missing', { status: 404 }), { preconnect: () => {} });
	const missingVault = new VaultService(
		new VaultwardenClient('https://example.com', {
			fetch: missingFetch,
		}),
		'synthetic',
		{ profile: { id: 'active-user' } },
		Buffer.alloc(64, 7),
	);
	try {
		await expect(missingVault.fingerprint(id)).rejects.toThrow('not found');
	} finally {
		missingVault.dispose();
	}
});
const items: VaultItem[] = [
	{
		id: '12345678-0000-0000-0000-000000000001',
		type: 1,
		name: 'Café Work',
		notes: 'Archived project',
		fields: [
			{ name: 'Recovery', value: 'backup phrase', type: 0 },
			{ name: 'Private', value: 'excluded-hidden-field', type: 1 },
		],
		attachments: [{ fileName: 'medical-report.pdf' }],
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
	{
		id: 'dddddddd-0000-0000-0000-000000000004',
		type: 6,
		name: 'Main account',
		bankAccount: { bankName: 'Harbor Bank', accountType: 'checking', accountNumber: 'excluded-account' },
	},
	{
		id: 'eeeeeeee-0000-0000-0000-000000000005',
		type: 7,
		name: 'License',
		driversLicense: {
			firstName: 'Alex',
			lastName: 'Rivera',
			issuingState: 'Oregon',
			licenseNumber: 'excluded-license',
		},
	},
	{
		id: 'ffffffff-0000-0000-0000-000000000006',
		type: 8,
		name: 'Passport',
		passport: { givenName: 'Sam', surname: 'Taylor', issuingCountry: 'Canada', passportNumber: 'excluded-passport' },
	},
	{
		id: 'aaaaaaaa-0000-0000-0000-000000000007',
		type: 7,
		name: 'State-only license',
		driversLicense: { firstName: '', lastName: '', issuingState: 'Oregon' },
	},
	{
		id: 'bbbbbbbb-0000-0000-0000-000000000008',
		type: 8,
		name: 'Country-only passport',
		passport: { givenName: '', surname: '', issuingCountry: 'Canada' },
	},
];
test('basic item search ANDs normalized terms across display fields, URI hostnames and ID prefixes', () => {
	for (const query of ['CAFE alice', 'project work', 'company example', '12345678', 'cafe accounts']) {
		expect(searchItems(items, query).map(item => item.id)).toEqual([items[0]!.id]);
	}
	expect(searchItems(items, 'visa 9876')[0]?.id).toBe(items[1]!.id);
	expect(searchItems(items, 'doe john')[0]?.id).toBe(items[2]!.id);
	expect(searchItems(items, 'harbor bank')[0]?.id).toBe(items[3]!.id);
	expect(searchItems(items, 'alex oregon')[0]?.id).toBe(items[4]!.id);
	expect(searchItems(items, 'taylor canada')[0]?.id).toBe(items[5]!.id);
	expect(searchItems([items[6]!], ', oregon')).toEqual([]);
	expect(searchItems([items[7]!], ', canada')).toEqual([]);
	for (const query of ['do-not-search-this', 'private/path', 'excluded-ssn', '11111111', '1234567']) {
		expect(searchItems(items, query)).toEqual([]);
	}
	for (const query of ['checking', 'excluded-account', 'excluded-license', 'excluded-passport']) {
		expect(searchItems(items, query)).toEqual([]);
	}
	expect(searchItems(items, 'work missing')).toEqual([]);
	expect(searchItems(items, '>name:cafe')).toEqual([]);
});
test('basic CLI item search filters single-character and CJK queries without advanced syntax dispatch', () => {
	expect(searchItems([items[6]!], 'x')).toEqual([]);
	const han = { ...items[0]!, id: 'han-id', name: '密碼' };
	expect(searchItems([han, items[1]!], '密').map(item => item.id)).toEqual(['han-id']);
	expect(searchItems(items, '>')).toEqual([]);
});
test('basic item search ignores malformed and empty URI rows like the reference CLI', () => {
	const malformed = {
		...items[0]!,
		login: {
			...items[0]!.login,
			uris: [null, 'bad row', {}, { uri: '   ' }, { uri: 'https://accounts.example.com/login' }],
		},
	} as unknown as VaultItem;
	expect(searchItems([malformed], 'accounts')).toEqual([malformed]);
	expect(searchItems([malformed], 'not-a-host')).toEqual([]);
	const unnamed = { ...items[0]!, name: null } as unknown as VaultItem;
	expect(searchItems([unnamed], 'accounts')).toEqual([unnamed]);
});
test('explicit library Lunr search supports fields without indexing secret custom-field values', () => {
	for (
		const [query, expected] of [
			['>shortid:12345678', items[0]!],
			['>name:cafe', items[0]!],
			['>subtitle:9876', items[1]!],
			['>notes:archived', items[0]!],
			['>login.username:alice@company.com', items[0]!],
			['>login.uris:accounts.example.com', items[0]!],
			['>fields_joined:backup', items[0]!],
			['>attachments_joined:medical', items[0]!],
		] as const
	) {
		expect(searchItemsAdvanced(items, query.slice(1)).map(item => item.id), query).toEqual([expected.id]);
	}
	expect(
		searchItemsAdvanced(
			[{ ...items[0]!, organizationId: 'organization-advanced-search' }],
			'organizationid:organization-advanced-search',
		),
	).toHaveLength(1);
	expect(searchItemsAdvanced(items, 'login.uris:excluded')).toEqual([]);
	expect(searchItemsAdvanced(items, 'login.uris:https')).toEqual([]);
	expect(
		searchItemsAdvanced(
			[{ ...items[1]!, login: { uris: [{ uri: 'https://accounts.example.com' }] } }],
			'login.uris:accounts.example.com',
		),
	).toEqual([]);
	expect(searchItemsAdvanced(items, 'fields:excluded-hidden-field')).toEqual([]);
	expect(searchItemsAdvanced(items, 'name:(')).toEqual([]);
	const malformedUri = {
		...items[0]!,
		login: { ...items[0]!.login, uris: [null, 'bad row', { uri: 'https://accounts.example.com' }] },
	} as unknown as VaultItem;
	expect(searchItemsAdvanced([malformedUri], 'login.uris:accounts.example.com')).toEqual([malformedUri]);
	const malformedMetadata = {
		...items[0]!,
		fields: [null, { name: 'Recovery', value: 'searchable', type: 0 }],
		attachments: [null, { fileName: 'valid.pdf' }],
	} as unknown as VaultItem;
	expect(searchItemsAdvanced([malformedMetadata], 'fields:searchable')).toEqual([malformedMetadata]);
	expect(searchItemsAdvanced([malformedMetadata], 'attachments_joined:valid')).toEqual([malformedMetadata]);
	expect(searchItemsAdvanced([{ ...items[0]!, attachments: [{ fileName: '.env' }] }], 'attachments_joined:env'))
		.toEqual([]);
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
		await expect(vault.findItem('cafe work')).rejects.toThrow('More than one result was found.');
		expect((await vault.findItem('cafe work', item => item.type === 1)).id).toBe(items[0]!.id);
		expect(await vault.listItems({ search: '>name:cafe' })).toEqual([]);
		await expect(vault.findItem('>name:cafe')).rejects.toThrow('not found');
		await expect(vault.findItem('Archived only')).rejects.toThrow('not found');
		expect((await vault.findItem(clear[2]!.id!)).name).toBe('Archived only');
		expect((await vault.findItem(clear[3]!.id!)).name).toBe('Deleted');
		expect((await vault.listItemsForUrl('https://alias.test')).map(item => item.id)).toEqual([items[0]!.id]);
		expect(await vault.listItems({ collectionId: 'null' })).toHaveLength(2);
		expect(await vault.listItems({ collectionId: 'notnull' })).toHaveLength(0);
	} finally {
		vault.dispose();
		key.fill(0);
	}
});

test('a missing UUID never falls back to matching another item by name or notes', async () => {
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
		await expect(vault.findItem(missing)).rejects.toThrow('not found');
		await expect(vault.findItem(' ')).rejects.toThrow('not found');
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
