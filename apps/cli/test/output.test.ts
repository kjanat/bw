import { expect, test } from 'bun:test';
import type { RuntimeAdapter } from '@kjanat/dreamcli/runtime';
import {
	getObjectResponse,
	listObjectResponse,
	outputSuccess,
	responseData,
	responseMessage,
	withOutputPolicy,
} from '#output';
import { quickSendResult, sendResponseData } from '#send-commands';

test('get organization-collection response matches the bw response projection', () => {
	const collection = {
		id: 'collection-id',
		organizationId: 'organization-id',
		name: 'Engineering',
		externalId: null,
		groups: [{ id: 'group-id', readOnly: true, manage: false, internalField: 'discard' }],
		users: [{ id: 'user-id', readOnly: false, hidePasswords: true, manage: true, internalField: 'discard' }],
		internalField: 'discard',
	};
	const expected = {
		object: 'org-collection',
		id: 'collection-id',
		organizationId: 'organization-id',
		name: 'Engineering',
		externalId: null,
		groups: [{ id: 'group-id', readOnly: true, hidePasswords: false, manage: false }],
		users: [{ id: 'user-id', readOnly: false, hidePasswords: true, manage: true }],
	};
	expect(responseData('get', { object: 'org-collection' }, collection)).toEqual(expected);
	expect(responseData('create', { object: 'org-collection' }, collection)).toEqual(expected);
	expect(responseData('edit', { object: 'org-collection' }, collection)).toEqual(expected);
});

test('create and edit folder response match the bw folder response model', () => {
	const folder = { id: 'folder-id', name: 'Personal', revisionDate: '2026-01-01', internalField: 'discard' };
	const expected = { object: 'folder', id: 'folder-id', name: 'Personal' };
	expect(responseData('create', { object: 'folder' }, folder)).toEqual(expected);
	expect(responseData('edit', { object: 'folder' }, folder)).toEqual(expected);
	expect(getObjectResponse('folder', folder)).toEqual(expected);
	expect(listObjectResponse('folders', folder)).toEqual(expected);
});

test('config getter and saved-file responses match bw message semantics', () => {
	expect(responseMessage('config', { url: '' }, {}, 'https://vault.example.test')).toEqual({
		object: 'string',
		data: 'https://vault.example.test',
	});
	for (
		const [command, args] of [['export', {}], ['receive', {}], ['get', { object: 'attachment' }]] as const
	) {
		expect(responseMessage(command, args, {}, '/tmp/vault-export.json')).toEqual({
			object: 'message',
			title: 'Saved /tmp/vault-export.json',
			message: null,
			raw: '/tmp/vault-export.json',
			noColor: false,
		});
	}
});

test('quick Send returns the access URL unless fullObject is requested', () => {
	expect(responseMessage('send', {}, {}, 'https://vault.example/#/send/id/key')).toEqual({
		object: 'string',
		data: 'https://vault.example/#/send/id/key',
	});
	const fullObject = { object: 'send', id: 'send-id', accessUrl: 'https://vault.example/#/send/id/key' };
	const projected = sendResponseData(fullObject);
	expect(quickSendResult(fullObject, false)).toBe('https://vault.example/#/send/id/key');
	expect(quickSendResult(fullObject, true)).toEqual(projected);
	expect(responseData('send', {}, quickSendResult(fullObject, true))).toEqual(projected);
});

test('owned Send output projects only SendResponse fields', () => {
	expect(sendResponseData({
		id: 'send-id',
		accessId: 'access-id',
		accessUrl: 'https://send.example/#access/key',
		name: 'Fixture',
		notes: null,
		key: 'fixture-key',
		type: 0,
		text: { text: 'secret text', hidden: true, internalField: 'discard' },
		maxAccessCount: null,
		accessCount: 1,
		revisionDate: '2026-01-01T00:00:00.000Z',
		deletionDate: '2026-01-08T00:00:00.000Z',
		expirationDate: null,
		passwordSet: true,
		emails: null,
		disabled: false,
		hideEmail: false,
		authType: 0,
		password: 'must not escape',
		internalField: 'discard',
	})).toEqual({
		object: 'send',
		id: 'send-id',
		accessId: 'access-id',
		accessUrl: 'https://send.example/#access/key',
		name: 'Fixture',
		notes: null,
		key: 'fixture-key',
		type: 0,
		maxAccessCount: null,
		accessCount: 1,
		revisionDate: '2026-01-01T00:00:00.000Z',
		deletionDate: '2026-01-08T00:00:00.000Z',
		expirationDate: null,
		passwordSet: true,
		disabled: false,
		hideEmail: false,
		authType: 0,
		emails: [],
		text: { text: 'secret text', hidden: true },
	});
});

test('received Send object omits owner-only access fields', () => {
	expect(sendResponseData({
		id: 'send-id',
		accessId: 'owner-access-id',
		key: 'owner-key',
		passwordSet: true,
		name: 'Fixture',
		type: 0,
		text: { text: 'received text', hidden: false, internalField: 'discard' },
		internalField: 'discard',
	}, 'send-access')).toEqual({
		object: 'send-access',
		id: 'send-id',
		name: 'Fixture',
		type: 0,
		text: { text: 'received text', hidden: false },
	});
});

test('no-data success stays silent normally and emits only the response envelope in response mode', async () => {
	const normalOutput: string[] = [];
	const normalAdapter = {
		stdout: (value: string | Uint8Array) => normalOutput.push(String(value)),
		stderr: () => {},
	} as unknown as RuntimeAdapter;
	await withOutputPolicy(normalAdapter, async () => outputSuccess());
	expect(normalOutput).toEqual([]);

	const responseOutput: string[] = [];
	const responseAdapter = {
		stdout: (value: string | Uint8Array) => responseOutput.push(String(value)),
		stderr: () => {},
	} as unknown as RuntimeAdapter;
	await withOutputPolicy(responseAdapter, async () => outputSuccess(), true);
	expect(responseOutput).toEqual(['{"success":true}\n']);
});
