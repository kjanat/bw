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
<User-Id>bob</User-Id><Password>password</Password></record></PasswordManager>`;

test('Password Dragon XML maps login data, attributes, and category paths', () => {
	const result = parsePasswordDragonXml(document);
	expect(items(result)).toHaveLength(2);
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
	expect(items(result)[1]).not.toHaveProperty('folderId');
	expect(result.folders).toEqual([
		{ id: expect.any(String), name: 'Work/Bank' },
		{ id: expect.any(String), name: 'Work' },
	]);
	const organization = parsePasswordDragonXml(document, true);
	expect(items(organization)[0]!.collectionIds).toEqual([
		(organization.collections as JsonObject[])[0]!.id,
	]);
});

test('Password Dragon XML rejects malformed, missing-root, and entity-bearing documents', () => {
	expect(() => parsePasswordDragonXml('<bad')).toThrow('Invalid Password Dragon XML.');
	expect(() => parsePasswordDragonXml('<Root/>')).toThrow('Missing PasswordManager root node.');
	expect(() => parsePasswordDragonXml('<!DOCTYPE x [<!ENTITY secret "private">]><PasswordManager/>'))
		.toThrow('XML entity declarations are not supported.');
});
