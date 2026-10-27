import { expect, test } from 'bun:test';
import { parseKasperskyTxt } from '#text-import';
import type { JsonObject } from '#client';

const items = (document: JsonObject) => document.items as JsonObject[];

test('Kaspersky TXT maps website, application, and note sections with multiline values', () => {
	const source = [
		'Websites',
		'',
		'',
		'---',
		'Website name: Example site',
		'Login name: Work',
		'Website URL: https://example.test/login',
		'Login: alice',
		'Password:   secret  ',
		'Comment: first line',
		'second line',
		'Applications',
		'',
		'',
		'---',
		'Application: Desktop app',
		'Login: workstation\\alice',
		'Password: app-secret',
		'Notes',
		'',
		'',
		'---',
		'Name: Secure note',
		'Text: note first line',
		'note second line',
	].join('\r\n');
	const result = parseKasperskyTxt(source);
	expect(result.folders).toEqual([]);
	expect(items(result)).toHaveLength(3);
	expect(items(result)[0]).toMatchObject({ name: 'Secure note', notes: 'note first line\nnote second line', type: 1 });
	expect(items(result)[1]).toMatchObject({
		name: 'Example site: Work',
		notes: 'first line\nsecond line\n',
		login: {
			username: 'alice',
			password: '  secret  ',
			uris: [{ uri: 'https://example.test/login', match: null }],
		},
	});
	expect(items(result)[2]).toMatchObject({
		name: 'Desktop app',
		login: { username: 'workstation\\alice', password: 'app-secret', uris: [] },
	});
});

test('Kaspersky TXT safely returns an empty document for unrecognized text', () => {
	expect(parseKasperskyTxt('unrecognized export data')).toEqual({ encrypted: false, items: [], folders: [] });
});
