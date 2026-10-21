import { expect, test } from 'bun:test';
import { parseExternalJson } from '#json-import';
import type { JsonObject } from '#client';

const items = (value: JsonObject) => value.items as JsonObject[];
const input = {
	items: [{
		type: 'website_password',
		website_password_title: 'Bank login',
		website_password_notes: 'Login notes',
		website_password_username: 'alice',
		website_password_password: '  secret  ',
		website_password_url: 'bank.example.test',
		website_password_auto_submit: true,
		website_password_url_filter: 'bank.*',
		create_date: '2024-01-01',
	}],
	folders: [
		{ name: 'Empty', items: [], folders: [] },
		{
			name: 'Work',
			items: [{
				type: 'application_password',
				application_password_title: 'SSH account',
				application_password_username: 'deploy',
				application_password_password: 'ssh-secret',
				application_password_notes: 'shell access',
				callback_url: 'https://callback.example.test',
			}],
			folders: [{
				name: 'Nested',
				items: [
					{ type: 'note', note_title: 'Recovery', note_notes: 'recovery codes', custom: 'retained' },
					{
						type: 'environment_variables',
						environment_variables_title: 'Deploy environment',
						environment_variables_notes: 'runtime values',
						environment_variables_variables: [{ key: 'REGION', value: 'eu-west' }],
					},
				],
				folders: [],
			}],
		},
	],
};

test('Psono JSON maps item types, custom values, nested folders, and organization collections', () => {
	const result = parseExternalJson('psonojson', JSON.stringify(input));
	expect(items(result)).toHaveLength(4);
	const folderId = (name: string) => (result.folders as JsonObject[]).find(folder => folder.name === name)!.id;
	expect(items(result)[0]).toMatchObject({
		type: 2,
		name: 'Recovery',
		folderId: folderId('Work/Nested'),
		secureNote: { type: 0 },
		notes: 'recovery codes',
		fields: [{ name: 'custom', value: 'retained', type: 0 }],
	});
	expect(items(result)[2]).toMatchObject({
		name: 'SSH account',
		folderId: folderId('Work'),
		login: { username: 'deploy', password: 'ssh-secret' },
		fields: [{ name: 'callback_url', value: 'https://callback.example.test', type: 0 }],
	});
	expect(items(result)[1]).toMatchObject({
		type: 2,
		name: 'Deploy environment',
		secureNote: { type: 0 },
		notes: 'runtime values',
		fields: [{ name: 'REGION', value: 'eu-west', type: 0 }],
	});
	expect(result.folders).toEqual([
		{ id: expect.any(String), name: 'Work/Nested' },
		{ id: expect.any(String), name: 'Work' },
	]);
	expect(items(result)[3]).toMatchObject({
		name: 'Bank login',
		notes: 'Login notes',
		login: {
			username: 'alice',
			password: '  secret  ',
			uris: [{ uri: 'http://bank.example.test', match: null }],
		},
		fields: [
			{ name: 'website_password_auto_submit', value: 'true', type: 2 },
			{ name: 'website_password_url_filter', value: 'bank.*', type: 0 },
			{ name: 'create_date', value: '2024-01-01', type: 0 },
		],
	});
	const organization = parseExternalJson('psonojson', JSON.stringify(input), true);
	expect(organization.folders).toBeUndefined();
	expect(items(organization)[2]!.collectionIds).toEqual([
		(organization.collections as JsonObject[]).find(folder => folder.name === 'Work')!.id,
	]);
});

test('Psono JSON handles TOTP and bookmarks, skips GPG metadata, and rejects malformed trees', () => {
	const result = parseExternalJson(
		'psonojson',
		JSON.stringify({
			items: [
				{ type: 'totp', totp_title: 'Authenticator', totp_code: 'JBSWY3DPEHPK3PXP', totp_period: 30, totp_digits: 6 },
				{
					type: 'bookmark',
					bookmark_title: 'Docs',
					bookmark_url: 'https://docs.example.test',
					bookmark_notes: 'Reference',
				},
				{ type: 'mail_gpg_own_key', mail_gpg_own_key_title: 'Private key', mail_gpg_own_key_private: 'secret-key' },
			],
		}),
	);
	expect(items(result)[0]).toMatchObject({ name: 'Authenticator', login: { totp: 'JBSWY3DPEHPK3PXP' } });
	expect(items(result)[1]).toMatchObject({
		name: 'Docs',
		login: { uris: [{ uri: 'https://docs.example.test', match: null }] },
	});
	expect(items(result)[2]).toMatchObject({ name: '--', login: { username: null, password: null }, fields: [] });
	expect(() => parseExternalJson('psonojson', '{not json')).toThrow('Invalid Psono JSON.');
	expect(() => parseExternalJson('psonojson', JSON.stringify({ folders: [{ name: 2 }] })))
		.toThrow('Invalid Psono folder name.');
});
