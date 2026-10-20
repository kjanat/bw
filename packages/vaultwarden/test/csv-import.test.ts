import { expect, test } from 'bun:test';
import { parseExternalCsv } from '#csv-import';
import { writeCsv } from '#csv';
import { VaultwardenClient, object, type JsonObject } from '#client';
import { VaultService } from '#vault-service';
import { decryptOwnedItem } from '#vault';
import { decrypt } from '#crypto';

const items = (document: JsonObject) => (document.items as JsonObject[]);
function nordPassCsv(records: Record<string, string>[]): string {
	const headers = [...new Set(['type', ...records.flatMap(record => Object.keys(record))])];
	return writeCsv([headers, ...records.map(record => headers.map(header => record[header] ?? ''))]);
}
test('NordPass maps all four item types, JSON fields/URLs, expiration, and personal/organization grouping', () => {
	const source = nordPassCsv([
		{
			type: 'password',
			name: 'Login',
			username: ' alice ',
			password: '  secret  ',
			url: 'example.com/a,b',
			additional_urls: JSON.stringify(['https://second.example', '']),
			folder: '\\Work\\Web',
			note: 'notes',
			custom_fields: JSON.stringify([{ label: 'Hidden', type: 'hidden', value: ' literal ' }, {
				label: 'Long',
				type: 'text',
				value: 'x'.repeat(201),
			}, { label: 'Blank', type: 'text', value: '  ' }]),
		},
		{
			type: 'credit_card',
			name: 'Card',
			cardholdername: 'Alice',
			cardnumber: '4111111111111111',
			cvc: '123',
			expirydate: ' 06 / 30 ',
			folder: 'Work/Web',
		},
		{
			type: 'identity',
			name: 'Identity',
			full_name: 'Alice Middle Last Name',
			country: 'nl',
			phone_number: '123',
			address1: 'Street',
			address2: 'Unit',
			city: 'City',
			state: 'State',
			zipcode: '1234',
			email: 'alice@example.com',
		},
		{ type: 'note', name: 'Note', note: 'line1\nline2' },
		{ type: 'unsupported', name: 'Ignored', folder: 'Ignored folder', custom_fields: 'invalid JSON' },
	]);
	const personal = parseExternalCsv('nordpasscsv', source), parsed = items(personal);
	expect(personal.folders).toMatchObject([{ name: 'Work/Web' }]);
	expect(parsed).toHaveLength(4);
	expect(parsed[0]).toMatchObject({
		name: 'Login',
		fields: [{ name: 'Hidden', value: ' literal ', type: 1 }],
		login: {
			username: ' alice ',
			password: '  secret  ',
			uris: [{ uri: 'http://example.com/a,b' }, { uri: 'https://second.example' }],
		},
	});
	expect(parsed[0]!.notes).toBe(`notesLong: ${'x'.repeat(201)}\n`);
	expect(parsed[1]).toMatchObject({
		type: 3,
		card: {
			cardholderName: 'Alice',
			brand: 'Visa',
			number: '4111111111111111',
			code: '123',
			expMonth: '6',
			expYear: '2030',
		},
	});
	expect(parsed[2]).toMatchObject({
		type: 4,
		identity: {
			firstName: 'Alice',
			middleName: 'Middle',
			lastName: 'Last Name',
			country: 'NL',
			phone: '123',
			postalCode: '1234',
		},
	});
	expect(parsed[3]).toMatchObject({ type: 2, secureNote: { type: 0 }, notes: 'line1\nline2' });
	const organization = parseExternalCsv('nordpasscsv', source, true);
	expect(organization.collections).toMatchObject([{ name: 'Work/Web' }]);
	const collection = (organization.collections as JsonObject[])[0]!;
	expect(items(organization).slice(0, 2).map(item => item.collectionIds)).toEqual([[collection.id], [collection.id]]);
	expect(items(organization).every(item => item.folderId === null)).toBe(true);
});
test('NordPass invalid JSON and typed array entries fail without including secrets in diagnostics', () => {
	for (
		const [column, value] of [
			['additional_urls', 'SYNTHETIC_SECRET_INVALID_JSON'],
			['additional_urls', '{}'],
			['additional_urls', '[123]'],
			['custom_fields', 'SYNTHETIC_SECRET_INVALID_JSON'],
			['custom_fields', '{}'],
			['custom_fields', '[null]'],
			['custom_fields', '[{"label":"Secret","value":123}]'],
		]
	) {
		try {
			parseExternalCsv('nordpasscsv', nordPassCsv([{ type: 'password', [column!]: value! }]));
			throw new Error('Expected invalid NordPass input to fail.');
		} catch (error) {
			expect(String(error)).toContain('Invalid NordPass');
			expect(String(error)).not.toContain('SYNTHETIC_SECRET');
		}
	}
	expect(items(parseExternalCsv('nordpasscsv', 'type,note\nnote,hello'))[0]).toMatchObject({
		name: '--',
		notes: 'hello',
	});
});
test('browser CSV preserves literal URI commas and secret whitespace and normalizes Android apps', () => {
	const chrome = items(parseExternalCsv(
		'chromecsv',
		writeCsv([
			['name', 'url', 'username', 'password', 'note'],
			['Browser', 'https://example.com/path,a', 'alice', '  secret  ', 'line1\nline2'],
			['', 'android://hash@com.example.app/', '', '', ''],
		]),
	));
	expect(chrome[0]).toMatchObject({
		name: 'Browser',
		notes: 'line1\nline2',
		login: { password: '  secret  ', uris: [{ uri: 'https://example.com/path,a' }] },
	});
	expect(chrome[1]).toMatchObject({
		name: 'com.example.app',
		login: { uris: [{ uri: 'androidapp://com.example.app' }] },
	});
	const firefox = items(parseExternalCsv(
		'firefoxcsv',
		writeCsv([
			['url', 'username', 'password'],
			['https://www.example.com/login', 'bob', 'secret'],
			['chrome://FirefoxAccounts', 'internal', 'internal'],
		]),
	));
	expect(firefox).toHaveLength(1);
	expect(firefox[0]!.name).toBe('example.com');
	expect(items(parseExternalCsv('firefoxcsv', 'hostname,username,password\nexample.org,alice,secret'))[0])
		.toMatchObject({ name: 'example.org', login: { uris: [{ uri: 'http://example.org' }] } });
});
test('Chromium aliases preserve notes and Android normalization while Arc derives names from URLs', () => {
	const source = writeCsv([
		['name', 'url', 'username', 'password', 'note'],
		['Display name', 'https://www.example.com/a,b', ' alice ', '  secret  ', 'line1\nline2'],
		['', 'android://hash@com.example.app/', 'app', 'secret', 'app notes'],
	]);
	const expected = parseExternalCsv('chromecsv', source);
	for (const format of ['edgecsv', 'operacsv', 'vivaldicsv', 'bravecsv'] as const) {
		expect(parseExternalCsv(format, source)).toEqual(expected);
	}
	expect(items(parseExternalCsv('arccsv', source))[0]).toMatchObject({
		name: 'example.com',
		notes: 'line1\nline2',
		login: { username: ' alice ', password: '  secret  ', uris: [{ uri: 'https://www.example.com/a,b' }] },
	});
});
test('Avira maps website, optional hostname names, and alternate usernames without discarding either identity', () => {
	const parsed = items(parseExternalCsv(
		'aviracsv',
		writeCsv([
			['name', 'website', 'username', 'secondary_username', 'password'],
			['Named', 'example.com/a,b', ' alice ', 'alternate@example.com', '  secret  '],
			['', 'https://www.other.example/path', ' ', ' alternate ', 'secret'],
			['', '', '', '', 'secret'],
		]),
	));
	expect(parsed[0]).toMatchObject({
		name: 'Named',
		notes: 'alternate@example.com',
		login: { username: ' alice ', password: '  secret  ', uris: [{ uri: 'http://example.com/a,b' }] },
	});
	expect(parsed[1]).toMatchObject({ name: 'other.example', notes: null, login: { username: ' alternate ' } });
	expect(parsed[2]).toMatchObject({ name: '--', notes: null, login: { username: null, uris: [] } });
});
test('Passbolt uses the LastPass mapping including structured records and grouping', () => {
	const source = writeCsv([['url', 'name', 'username', 'password', 'extra', 'grouping', 'fav'], [
		'https://example.com',
		'Passbolt',
		'alice',
		' secret ',
		'notes',
		'Work\\Web',
		'1',
	], ['http://sn', 'Note', '', '', 'multiline\nnotes', 'Work\\Web', '0']]);
	const parsed = parseExternalCsv('passboltcsv', source);
	expect(parsed.folders).toMatchObject([{ name: 'Work/Web' }]);
	expect(items(parsed)[0]).toMatchObject({ favorite: true, notes: 'notes', login: { password: ' secret ' } });
	expect(items(parsed)[1]).toMatchObject({ type: 2, notes: 'multiline\nnotes' });
});
test('Safari OTP/notes and KeePassX groups are translated into native import documents', () => {
	expect(
		items(parseExternalCsv(
			'safaricsv',
			writeCsv([
				['Title', 'Url', 'Username', 'Password', 'Notes', 'OTPAuth'],
				['Safari', 'https://example.com', 'alice', 'secret', 'notes', 'otpauth://totp/x?secret=ABC'],
			]),
		))[0],
	).toMatchObject({ name: 'Safari', notes: 'notes', login: { totp: 'otpauth://totp/x?secret=ABC' } });
	const document = parseExternalCsv(
		'keepassxcsv',
		writeCsv([
			['Group', 'Title', 'Username', 'Password', 'URL', 'Notes', 'TOTP'],
			['Root/Work\\Web', 'Entry', 'alice', 'secret', 'example.com/a,b', 'notes', 'ABC'],
			['Root/Ignored', '  ', 'ignored', 'ignored', 'ignored', '', ''],
		]),
		true,
	);
	expect(document.collections).toMatchObject([{ name: 'Work/Web' }]);
	expect(items(document)).toHaveLength(1);
	expect(items(document)[0]).toMatchObject({
		folderId: null,
		collectionIds: [(document.collections as JsonObject[])[0]!.id],
		login: { totp: 'ABC', uris: [{ uri: 'http://example.com/a,b' }] },
	});
});
test('LastPass site, secure note, structured card and identity preserve groups and unrecognized fields', () => {
	const document = parseExternalCsv(
		'lastpasscsv',
		writeCsv([
			['url', 'username', 'password', 'extra', 'name', 'grouping', 'fav', 'totp'],
			['https://example.com/a,b', 'alice', 'secret', 'notes', 'Site', 'Work\\Web', '1', 'ABC'],
			[
				'http://sn',
				'',
				'',
				'NoteType:Credit Card\nNumber:4111111111111111\nName on Card:Alice\nSecurity Code:123\nExpiration Date:June,2030\nIssuer:Example\nNotes:note\ncontinuation:kept',
				'Card',
				'Work\\Web',
				'0',
				'',
			],
			[
				'http://sn',
				'',
				'',
				'NoteType:Address\nFirst Name:Alice\nLast Name:Example\nAddress 1:Street\nUnknown:retained',
				'Identity',
				'(none)',
				'0',
				'',
			],
			[
				'http://sn',
				'',
				'',
				'NoteType:Bank Account\nAccount Number:123\nNotes:entire record',
				'Legacy note',
				'',
				'0',
				'',
			],
		]),
	);
	expect(document.folders).toMatchObject([{ name: 'Work/Web' }]);
	const parsed = items(document);
	expect(parsed[0]).toMatchObject({
		favorite: true,
		login: { totp: 'ABC', uris: [{ uri: 'https://example.com/a,b' }] },
	});
	expect(parsed[1]).toMatchObject({
		type: 3,
		card: { number: '4111111111111111', cardholderName: 'Alice', code: '123', expMonth: '6', expYear: '2030' },
		fields: [{ name: 'Issuer', value: 'Example' }],
		notes: 'note\ncontinuation:kept',
	});
	expect(parsed[2]).toMatchObject({
		type: 4,
		identity: { firstName: 'Alice', lastName: 'Example' },
		fields: [{ name: 'Unknown', value: 'retained' }],
		folderId: null,
	});
	expect(parsed[3]).toMatchObject({ type: 2, notes: 'NoteType:Bank Account\nAccount Number:123\nNotes:entire record' });
});
test('LastPass form-fill identities can retain an accompanying card', () => {
	const document = parseExternalCsv(
		'lastpasscsv',
		writeCsv([
			['profilename', 'profilelanguage', 'firstname', 'lastname', 'ccname', 'ccnum', 'cccsc', 'ccexp'],
			['Profile', 'en', 'Alice', 'Example', 'Alice Example', '4111111111111111', '123', '2030-06'],
		]),
	);
	expect(items(document)).toHaveLength(2);
	expect(items(document)[0]).toMatchObject({ type: 3, card: { brand: 'Visa', expMonth: '6', expYear: '2030' } });
	expect(items(document)[1]).toMatchObject({ type: 4, identity: { firstName: 'Alice', lastName: 'Example' } });
});
test('external imports reject malformed headers and rows before sending data', async () => {
	let calls = 0;
	const client = new VaultwardenClient('https://example.com', {
		fetch: (async () => {
			calls++;
			return Response.json({});
		}) as unknown as typeof fetch,
	});
	const vault = new VaultService(client, 'access', { profile: { id: 'fixture' }, ciphers: [] }, Buffer.alloc(64, 7));
	for (const source of ['name\ninvalid', 'url,username,password,password\nx,a,b,c', 'url,username,password\nx,a']) {
		await expect(vault.importVault('chromecsv', source)).rejects.toThrow();
	}
	await expect(vault.importVault(
		'nordpasscsv',
		nordPassCsv([
			{ type: 'password', name: 'Valid first row', password: 'synthetic secret' },
			{ type: 'password', name: 'Invalid later row', additional_urls: 'invalid JSON' },
		]),
	)).rejects.toThrow('Invalid NordPass');
	expect(calls).toBe(0);
	vault.dispose();
});
test('external CSV imports use fresh encrypted item keys and remap grouping relationships', async () => {
	const key = Buffer.alloc(64, 7);
	let calls = 0;
	const client = new VaultwardenClient('https://example.com', {
		fetch: (async (_url: unknown, init?: RequestInit) => {
			calls++;
			const body = JSON.parse(String(init!.body));
			expect(body.folderRelationships).toEqual([{ key: 0, value: 0 }]);
			expect(decrypt(body.folders[0].name, key).toString()).toBe('Work');
			const cipher = object(body.ciphers[0]);
			const itemKey = decrypt(String(cipher.key), key);
			try {
				expect(itemKey.equals(key)).toBe(false);
			} finally {
				itemKey.fill(0);
			}
			expect(decryptOwnedItem(cipher, key)).toMatchObject({
				name: 'Imported',
				login: { password: 'synthetic-password', uris: [{ uri: 'https://example.com/a,b' }] },
			});
			expect(String(init!.body).includes('synthetic-password')).toBe(false);
			return new Response(null, { status: 204 });
		}) as typeof fetch,
	});
	const vault = new VaultService(client, 'access', { profile: { id: 'fixture' }, ciphers: [] }, key);
	expect(
		await vault.importVault(
			'keepassxcsv',
			'Group,Title,Username,Password,URL\nRoot/Work,Imported,alice,synthetic-password,"https://example.com/a,b"',
		),
	).toEqual({ items: 1, folders: 1, collections: 0, attachments: 0 });
	expect(calls).toBe(1);
	vault.dispose();
});
