import { expect, test } from 'bun:test';
import { parseClipperzHtml } from '#clipperz-html';
import type { JsonObject } from '#client';

const items = (document: JsonObject) => document.items as JsonObject[];
const wrap = (value: unknown) => {
	const json = JSON.stringify(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;');
	return `<!doctype html><html><body><textarea>${json}</textarea></body></html>`;
};

test('Clipperz HTML reads textarea JSON and maps action/label fields and secure notes', () => {
	const document = parseClipperzHtml(wrap([
		{
			label: 'Bank login \uE009 Username',
			data: { notes: 'first\\nsecond' },
			currentVersion: {
				fields: {
					username: { actionType: 'USERNAME', value: 'alice' },
					password: { label: 'Password', value: '  secret  ' },
					url: { actionType: 'url', value: 'bank.example.test' },
					recovery: { label: 'Recovery code', value: 'private' },
				},
			},
		},
		{
			label: 'Secure note',
			data: { notes: 'note\\ncontent' },
			currentVersion: { fields: { url: { label: 'Other', value: 'metadata' } } },
		},
	]));
	expect(items(document)).toHaveLength(2);
	expect(items(document)[0]).toMatchObject({
		name: 'Bank login',
		notes: 'first\nsecond',
		login: {
			username: 'alice',
			password: '  secret  ',
			uris: [{ uri: 'http://bank.example.test', match: null }],
		},
		fields: [{ name: 'Recovery code', value: 'private', type: 0 }],
	});
	expect(items(document)[1]).toMatchObject({
		type: 2,
		name: 'Secure note',
		notes: 'note\ncontent',
		secureNote: { type: 0 },
		fields: [{ name: 'Other', value: 'metadata', type: 0 }],
	});
});

test('Clipperz HTML rejects missing textarea, malformed JSON, and invalid entries', () => {
	expect(() => parseClipperzHtml('<html><p>No data</p></html>')).toThrow('Missing Clipperz textarea.');
	expect(() => parseClipperzHtml('<textarea>{bad}</textarea>')).toThrow('Invalid Clipperz JSON.');
	expect(() => parseClipperzHtml(wrap([null]))).toThrow('Invalid Clipperz entry.');
});
