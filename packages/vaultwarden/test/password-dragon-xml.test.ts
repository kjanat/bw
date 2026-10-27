import { expect, test } from 'bun:test';
import { parsePasswordDragonXml } from '#password-dragon-xml';
import type { JsonObject } from '#client';

const items = (value: JsonObject) => value.items as JsonObject[];
const document = `<?xml version="1.0"?>
<PasswordManager><record>
<Category>Work/Bank</Category><Account-Name>Bank login</Account-Name>
<User-Id> alice </User-Id><Password>  secret  </Password><URL>bank.example.test</URL>
<Notes>login note</Notes><Attribute-1>recovery code</Attribute-1>
<Attribute-2>multiline\nprivate note</Attribute-2>
</record><record><Category>Unfiled</Category><Account-Name>Unfiled login</Account-Name>
<User-Id>bob</User-Id><Password>password</Password></record>
<record><Category>Unfiled</Category><Account-Name>   </Account-Name></record></PasswordManager>`;

test('Password Dragon XML maps login data, attributes, and category paths', () => {
	const result = parsePasswordDragonXml(document);
	expect(items(result)).toHaveLength(3);
	expect(items(result)[0]).toMatchObject({
		name: 'Bank login',
		folderId: (result.folders as JsonObject[])[0]!.id,
		notes: 'login noteAttribute-2: multiline\nprivate note\n',
		login: {
			username: ' alice ',
			password: '  secret  ',
			uris: [{ uri: 'http://bank.example.test', match: null }],
		},
		fields: [{ name: 'Attribute-1', value: 'recovery code', type: 0 }],
	});
	expect((items(result)[1]!.login as JsonObject).uris).toBeNull();
	expect(items(result)[1]).not.toHaveProperty('folderId');
	expect(items(result)[2]).toMatchObject({ name: '--' });
	expect(result.folders).toEqual([
		{ id: expect.any(String), name: 'Work/Bank' },
		{ id: expect.any(String), name: 'Work' },
	]);
	const organization = parsePasswordDragonXml(document, true);
	expect(items(organization)[0]!.collectionIds).toEqual([
		(organization.collections as JsonObject[])[0]!.id,
	]);
});

test('Password Dragon XML rejects malformed and entity-bearing documents', () => {
	expect(() => parsePasswordDragonXml('<bad')).toThrow('Invalid Password Dragon XML.');
	expect(parsePasswordDragonXml('<Root/>')).toEqual({ encrypted: false, items: [], folders: [] });
	expect(() => parsePasswordDragonXml('<!DOCTYPE x [<!ENTITY secret "private">]><PasswordManager/>'))
		.toThrow('XML entity declarations are not supported.');
});

test('Password Dragon XML imports direct records from every PasswordManager node', () => {
	const result = items(parsePasswordDragonXml(
		'<root><PasswordManager><record><Account-Name>First</Account-Name>'
			+ '<PasswordManager><record><Account-Name>Nested</Account-Name></record></PasswordManager></record>'
			+ '<record><Account-Name>Third</Account-Name></record></PasswordManager>'
			+ '<PasswordManager><record><Account-Name>Second manager</Account-Name></record></PasswordManager></root>',
	));
	expect(result.map(item => item.name)).toEqual(['First', 'Nested', 'Third', 'Second manager']);
});

test('Password Dragon XML reads duplicate attributes and maps missing or blank URLs to null', () => {
	const result = items(parsePasswordDragonXml(
		'<PasswordManager><record><Account-Name>Duplicate fields</Account-Name>'
			+ '<Attribute-1>first</Attribute-1><Attribute-2>second</Attribute-2>'
			+ '<Attribute-1>third</Attribute-1></record>'
			+ '<record><Account-Name>Blank URL</Account-Name><URL>  </URL></record></PasswordManager>',
	));
	expect(result[0]!.fields).toEqual([
		{ name: 'Attribute-1', value: 'first', type: 0 },
		{ name: 'Attribute-2', value: 'second', type: 0 },
		{ name: 'Attribute-1', value: 'third', type: 0 },
	]);
	expect((result[0]!.login as JsonObject).uris).toBeNull();
	expect((result[1]!.login as JsonObject).uris).toBeNull();
});
