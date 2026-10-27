import { expect, test } from 'bun:test';
import { parseDelineaXml } from '#delinea-xml';
import type { JsonObject } from '#client';

const items = (value: JsonObject) => value.items as JsonObject[];
const document = `<?xml version="1.0"?>
<Export><ImportFile><Folders><Folder><FolderPath>Work/Bank</FolderPath></Folder></Folders><Secrets>
<Secret><SecretName>Bank login</SecretName><FolderPath>Work/Bank</FolderPath><SecretItems>
<SecretItem><Slug>username</Slug><Value> alice </Value></SecretItem>
<SecretItem><Slug>password</Slug><Value>  secret  </Value></SecretItem>
<SecretItem><Slug>url</Slug><Value>https://bank.example.test</Value></SecretItem>
<SecretItem><Slug>notes</Slug><Value>login note</Value></SecretItem>
<SecretItem><Slug>custom</Slug><Value>private</Value></SecretItem>
</SecretItems></Secret>
<Secret><SecretName>Secure note</SecretName><SecretItems>
<SecretItem><Slug>password</Slug><Value>note-password</Value></SecretItem>
<SecretItem><Slug>notes</Slug><Value>note body</Value></SecretItem>
</SecretItems></Secret>
</Secrets></ImportFile></Export>`;

test('Delinea XML maps logins, secure notes, fields, and predeclared folder paths', () => {
	const result = parseDelineaXml(document);
	expect(items(result)).toHaveLength(2);
	expect(items(result)[0]).toMatchObject({
		name: 'Bank login',
		folderId: (result.folders as JsonObject[])[0]!.id,
		notes: 'login note',
		login: {
			username: ' alice ',
			password: '  secret  ',
			uris: [{ uri: 'https://bank.example.test', match: null }],
		},
		fields: [{ name: 'custom', value: 'private', type: 0 }],
	});
	expect(items(result)[1]).toMatchObject({
		type: 2,
		secureNote: { type: 0 },
		notes: 'note body',
		fields: [{ name: 'password', value: 'note-password', type: 1 }],
	});
	expect(result.folders).toEqual([
		{ id: expect.any(String), name: 'Work/Bank' },
		{ id: expect.any(String), name: 'Work' },
	]);
	const organization = parseDelineaXml(document, true);
	expect(organization.folders).toBeUndefined();
	expect(items(organization)[0]!.collectionIds).toEqual([(organization.collections as JsonObject[])[0]!.id]);
});

test('Delinea XML rejects malformed, missing-root, and entity-bearing documents', () => {
	expect(() => parseDelineaXml('<bad')).toThrow('Invalid Delinea XML.');
	expect(() => parseDelineaXml('<Root/>')).toThrow('Missing ImportFile node.');
	expect(() => parseDelineaXml('<!DOCTYPE x [<!ENTITY secret "private">]><Export><ImportFile/></Export>'))
		.toThrow('XML entity declarations are not supported.');
});
