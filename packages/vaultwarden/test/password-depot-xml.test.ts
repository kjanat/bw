import { expect, test } from 'bun:test';
import { parsePasswordDepot17Xml } from '#password-depot-xml';
import type { JsonObject } from '#client';

const items = (value: JsonObject) => value.items as JsonObject[];
const document = (records: string, options: { version?: string; encrypted?: string; favorites?: string } = {}) =>
	`<passwordfile><header>${options.version ?? '<version>17.0</version>'}${
		options.encrypted ? `<encrypted>${options.encrypted}</encrypted>` : ''
	}</header>${
		options.favorites ? `<favorites>${options.favorites}</favorites>` : ''
	}<passwords>${records}</passwords></passwordfile>`;

test('Password Depot 17 XML maps login, card, identity, favorites, and nested folders', () => {
	const xml = document(
		`<group fingerprint="folder" name="Personal"><group fingerprint="child" name="Accounts">
	<item><type>0</type><description>Depot login</description><comment>login note</comment><fingerprint>favorite-id</fingerprint>
	<username>alice</username><password> depot-secret </password><url>depot.example.test</url><customfields>
	<field><name>Recovery</name><value>backup-code</value><type>1</type></field></customfields></item>
	<item><type>1</type><description>Depot card</description><customfields>
	<field name="IDS_CardHolder" value="Alice Example"/><field name="IDS_CardNumber" value="4111111111111111"/>
	<field name="IDS_CardExpires" value="05/2026"/><field name="IDS_CardCode" value="123"/>
	<field name="Bank" value="Example Bank" visible="0"/></customfields></item>
	<item><type>3</type><description>Depot identity</description><customfields>
	<field><name>IDS_IdentityName</name><value>Alice Q Example</value></field>
	<field><name>IDS_IdentityEmail</name><value>alice@example.test</value></field></customfields></item>
	</group></group>`,
		{ favorites: Buffer.from('favorite-id\n').toString('base64') },
	);
	const result = parsePasswordDepot17Xml(xml);
	expect(items(result)).toHaveLength(3);
	expect(items(result)[0]).toMatchObject({
		name: 'Depot login',
		favorite: true,
		notes: 'login note',
		folderId: (result.folders as JsonObject[]).find(folder => folder.name === 'Personal/Accounts')!.id,
		login: { username: 'alice', password: ' depot-secret ', uris: [{ uri: 'http://depot.example.test', match: null }] },
		fields: [
			{ name: 'fingerprint', value: 'favorite-id', type: 0 },
			{ name: 'Recovery', value: 'backup-code', type: 1 },
		],
	});
	expect(items(result)[1]).toMatchObject({
		type: 3,
		card: {
			cardholderName: 'Alice Example',
			number: '4111111111111111',
			brand: 'Visa',
			expMonth: '5',
			expYear: '2026',
			code: '123',
		},
		fields: [{ name: 'Bank', value: 'Example Bank', type: 1 }],
	});
	expect(items(result)[2]).toMatchObject({
		type: 4,
		identity: { firstName: 'Alice', middleName: 'Q', lastName: 'Example', email: 'alice@example.test' },
	});
	expect((result.folders as JsonObject[]).map(folder => folder.name)).toEqual(['Personal', 'Personal/Accounts']);
	const organization = parsePasswordDepot17Xml(xml, true);
	expect(organization.folders).toBeUndefined();
	expect(organization.collections).toEqual([
		{ id: expect.any(String), name: 'Personal' },
		{ id: expect.any(String), name: 'Personal/Accounts' },
	]);
	expect(items(organization)[0]!.collectionIds).toEqual([(organization.collections as JsonObject[])[1]!.id]);
});

test('Password Depot 17 XML maps secure-note categories and macOS custom field attributes', () => {
	const result = parsePasswordDepot17Xml(document(`<group>
	<item><type>4</type><description>Information</description><comment>old note</comment><customfields>
	<field name="IDS_InformationText" value="new note"/><field name="Account" value="line one&#10;line two" type="2"/>
	</customfields></item>
	<item><type>2</type><description>License</description><customfields>
	<field name="IDS_LicenseKey" value="license-key" type="1"/></customfields></item>
	</group>`));
	expect(items(result)).toHaveLength(2);
	expect(items(result)[0]).toMatchObject({
		type: 2,
		secureNote: { type: 0 },
		notes: 'new noteAccount: line one\nline two\n',
		fields: [],
	});
	expect(items(result)[1]).toMatchObject({
		type: 2,
		secureNote: { type: 0 },
		fields: [{ name: 'IDS_LicenseKey', value: 'license-key', type: 1 }],
	});
});

test('Password Depot 17 XML validates versions, encryption, structure, and external entities', () => {
	expect(() => parsePasswordDepot17Xml('<root/>')).toThrow('Missing passwordfile root node.');
	expect(() => parsePasswordDepot17Xml('<passwordfile><header/><passwords/></passwordfile>')).toThrow(
		'Missing Password Depot version.',
	);
	expect(() => parsePasswordDepot17Xml(document('', { version: '<version>16.0</version>' }))).toThrow(
		'Unsupported Password Depot version.',
	);
	expect(() => parsePasswordDepot17Xml(document('', { encrypted: 'True' }))).toThrow(
		'Encrypted Password Depot files are unsupported.',
	);
	expect(() => parsePasswordDepot17Xml('<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><passwordfile/>'))
		.toThrow('XML entity declarations are not supported.');
	expect(() => parsePasswordDepot17Xml('<!DOCTYPE x SYSTEM "file:///etc/passwd"><passwordfile/>')).toThrow(
		'External XML document types are not supported.',
	);
});
