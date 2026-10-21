import { expect, test } from 'bun:test';
import { parsePasswordSafeXml } from '#passwordsafe-xml';
import type { JsonObject } from '#client';

const items = (document: JsonObject) => document.items as JsonObject[];
const source = `<?xml version="1.0"?><passwordsafe delimiter="~"><entry>
<group>Work.Bank</group><title>Bank login</title><username>alice</username><email>alice@example.test</email>
<password>  secret  </password><url>bank.example.test</url><notes>first~second</notes>
</entry><entry><title>Email fallback</title><username>  </username><email>bob@example.test</email><password>mail-secret</password></entry>
<entry><title>Empty user note</title><username>carol</username><email>  </email><notes></notes></entry></passwordsafe>`;

test('Password Safe XML maps fields, dotted folders, note delimiters, and email fallback', () => {
	const document = parsePasswordSafeXml(source);
	expect(items(document)).toHaveLength(3);
	expect(items(document)[0]).toMatchObject({
		name: 'Bank login',
		folderId: (document.folders as JsonObject[])[0]!.id,
		notes: 'first\nsecond\nEmail: alice@example.test',
		login: {
			username: 'alice',
			password: '  secret  ',
			uris: [{ uri: 'http://bank.example.test', match: null }],
		},
	});
	expect(items(document)[1]).toMatchObject({
		name: 'Email fallback',
		login: { username: 'bob@example.test', password: 'mail-secret' },
		notes: null,
	});
	expect(items(document)[2]).toMatchObject({
		name: 'Empty user note',
		login: { username: 'carol', password: null, uris: [] },
		notes: null,
	});
	expect(document.folders).toEqual([
		{ id: expect.any(String), name: 'Work/Bank' },
		{ id: expect.any(String), name: 'Work' },
	]);
	const organization = parsePasswordSafeXml(source, true);
	expect(organization.folders).toBeUndefined();
	expect(items(organization)[0]!.collectionIds).toEqual([(organization.collections as JsonObject[])[0]!.id]);
});

test('Password Safe XML rejects malformed, missing-root, and entity-bearing documents', () => {
	expect(() => parsePasswordSafeXml('<passwordsafe')).toThrow('Invalid Password Safe XML.');
	expect(() => parsePasswordSafeXml('<root/>')).toThrow('Missing passwordsafe node.');
	expect(() => parsePasswordSafeXml('<!DOCTYPE x [<!ENTITY secret "private">]><passwordsafe/>'))
		.toThrow('XML entity declarations are not supported.');
});

test('Password Safe XML matches bw delimiter coercion when the attribute is absent or empty', () => {
	const absent = items(parsePasswordSafeXml(
		'<passwordsafe><entry><title>Missing delimiter</title><notes>remember null token</notes></entry></passwordsafe>',
	));
	expect(absent[0]?.notes).toBe('remember \n token');

	const empty = items(parsePasswordSafeXml(
		'<passwordsafe delimiter=""><entry><title>Empty delimiter</title><notes>abc</notes></entry></passwordsafe>',
	));
	expect(empty[0]?.notes).toBe('a\nb\nc');
});
