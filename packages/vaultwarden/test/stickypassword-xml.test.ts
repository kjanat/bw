import { expect, test } from 'bun:test';
import { parseStickyPasswordXml } from '#stickypassword-xml';
import type { JsonObject } from '#client';

const items = (document: JsonObject) => document.items as JsonObject[];
const source = `<?xml version="1.0"?><root><Database>
<Logins><Login ID="login-1" Name="alice" Password="  secret  "/><Login Name="missing-id" Password="ignore"/></Logins>
<Accounts><Account Name="Bank login" Link="bank.example.test" ParentID="group-child" Comments="first/nsecond">
<LoginLinks><Login SourceLoginID="login-1"/></LoginLinks></Account>
<Account Name="Unlinked account"><LoginLinks><Login SourceLoginID="other-id"/></LoginLinks></Account></Accounts>
<Groups><Group ID="group-child" Name="Bank" ParentID="group-parent"/><Group ID="group-parent" Name="Work"/></Groups>
</Database></root>`;

test('Sticky Password XML resolves linked accounts and group ancestry', () => {
	const document = parseStickyPasswordXml(source);
	expect(items(document)).toHaveLength(1);
	expect(items(document)[0]).toMatchObject({
		name: 'Bank login',
		folderId: (document.folders as JsonObject[])[0]!.id,
		notes: 'first\nsecond',
		login: {
			username: 'alice',
			password: '  secret  ',
			uris: [{ uri: 'http://bank.example.test', match: null }],
		},
	});
	expect(document.folders).toEqual([
		{ id: expect.any(String), name: 'Work/Bank' },
		{ id: expect.any(String), name: 'Work' },
	]);
	const organization = parseStickyPasswordXml(source, true);
	expect(organization.folders).toBeUndefined();
	expect(items(organization)[0]!.collectionIds).toEqual([(organization.collections as JsonObject[])[0]!.id]);
});

test('Sticky Password XML rejects malformed, missing-root, and entity-bearing documents', () => {
	expect(() => parseStickyPasswordXml('<root><Database')).toThrow('Invalid Sticky Password XML.');
	expect(() => parseStickyPasswordXml('<root/>')).toThrow('Missing Database node.');
	expect(() => parseStickyPasswordXml('<!DOCTYPE x [<!ENTITY secret "private">]><root><Database/></root>'))
		.toThrow('XML entity declarations are not supported.');
});
