import { expect, test } from 'bun:test';
import { createLocalApiHandler, type LocalApiBackend } from '#local-api';
import { VaultwardenClient, type JsonObject } from '#client';
import { VaultService } from '#vault-service';
import { encryptItem } from '#item-codec';
import { generateSecret } from '#generator';

const id = '00000000-0000-0000-0000-000000000001';
function fixture() {
	const key = Buffer.alloc(64, 7);
	const snapshot: JsonObject = {
		profile: { id, organizations: [] },
		folders: [],
		collections: [],
		sends: [],
		ciphers: [
			encryptItem(
				{ id, type: 1, name: 'Café fixture', login: { username: 'alice', password: '  secret  ', uris: [] } },
				key,
			),
		],
	};
	let locked = false, calls = 0;
	const backend: LocalApiBackend = {
		status: async () => ({ status: locked ? 'locked' : 'unlocked' }),
		sync: async () => {
			calls++;
		},
		lock: async () => {
			locked = true;
		},
		unlock: async password => {
			if (password !== 'fixture-password') throw new Error('Invalid password.');
			locked = false;
			return 'synthetic-session';
		},
		generate: async options => generateSecret(options),
		run: async (_mutate, operation) => {
			calls++;
			if (locked) throw new Error('Vault is locked.');
			const client = new VaultwardenClient('https://example.com');
			const vault = new VaultService(client, 'synthetic-access', snapshot, key);
			try {
				return await operation(vault);
			} finally {
				vault.dispose();
			}
		},
	};
	const handler = createLocalApiHandler(backend, { hostname: '127.0.0.1', port: 8087 });
	const request = (path: string, init: RequestInit = {}) => {
		const headers = new Headers(init.headers);
		if (!headers.has('Host')) headers.set('Host', '127.0.0.1:8087');
		return handler(new Request(`http://localhost:8087${path}`, { ...init, headers }));
	};
	return { backend, request, handler, calls: () => calls, snapshot, key };
}
test('local API rejects Origin and rebinding Host headers before invoking the backend', async () => {
	const f = fixture();
	const forbidden: Record<string, string>[] = [{ Origin: 'https://attacker.example' }, { Origin: '' }, {
		Host: 'attacker.example:8087',
	}];
	for (const headers of forbidden) {
		expect((await f.request('/status', { headers })).status).toBe(403);
	}
	expect((await f.handler(new Request('http://localhost:8087/status'))).status).toBe(403);
	expect(f.calls()).toBe(0);
	for (const host of ['localhost:8087', '127.0.0.1:8087', '[::1]:8087', 'LOCALHOST:8087']) {
		expect((await f.request('/status', { headers: { Host: host } })).status).toBe(200);
	}
	const all = createLocalApiHandler(f.backend, { hostname: 'all' });
	expect((await all(new Request('http://10.0.0.2:8087/status', { headers: { Host: '10.0.0.2:8087' } }))).status).toBe(
		200,
	);
	expect((await all(new Request('http://10.0.0.2:8087/status', { headers: { Origin: 'null' } }))).status).toBe(403);
});
test('local API wraps lists and strings and preserves secret whitespace', async () => {
	const { request } = fixture();
	const response = await request('/list/object/items?search=cafe%20alice');
	expect(await response.json()).toMatchObject({
		success: true,
		data: { object: 'list', data: [{ id, name: 'Café fixture' }] },
	});
	expect(await (await request(`/object/password/${id}`)).json()).toEqual({
		success: true,
		data: { object: 'string', data: '  secret  ' },
	});
	expect((await request('/unknown')).status).toBe(404);
	expect((await request('/object/item/%ZZ')).status).toBe(400);
	expect((await request('/list/object/items?trash=garbage')).status).toBe(400);
	const generated = await (await request('/generate?length=32&number=true')).json();
	expect(generated.data.data).toHaveLength(32);
	expect((await request('/generate?length=invalid')).status).toBe(400);
});
test('local API takes unlock passwords only from JSON and serializes lock/unlock/read ordering', async () => {
	const { request } = fixture();
	await request('/lock', { method: 'POST' });
	expect((await request('/list/object/items')).status).toBe(400);
	expect(
		(await request('/unlock?passwordEnv=HOME&passwordFile=/etc/passwd', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: '{}',
		})).status,
	).toBe(400);
	const unlock = request('/unlock', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ password: 'fixture-password' }),
	});
	const list = request('/list/object/items');
	expect(await (await unlock).json()).toMatchObject({ success: true, data: { raw: 'synthetic-session' } });
	expect((await list).status).toBe(200);
	expect(await (await request('/status')).json()).toMatchObject({
		data: { object: 'template', template: { status: 'unlocked' } },
	});
});
test('malformed and oversized JSON fail without invoking mutations and do not poison the request queue', async () => {
	const f = fixture();
	for (const body of ['{"password":"synthetic-secret",', 'x'.repeat(1024 * 1024 + 1)]) {
		const result = await f.request('/object/item', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body,
		});
		expect(result.status).toBe(400);
		expect((await result.text()).includes('synthetic-secret')).toBe(false);
	}
	expect(f.calls()).toBe(0);
	expect((await f.request('/sync', { method: 'POST' })).status).toBe(200);
});
test('attachment downloads retain their bytes after the vault buffer is wiped', async () => {
	const f = fixture(), contents = Buffer.alloc(131072, 171);
	class DownloadVault extends VaultService {
		override async getAttachment() {
			return { fileName: 'fixture\r\n.bin', contents };
		}
	}
	f.backend.run = async (_mutate, action) =>
		action(new DownloadVault(new VaultwardenClient('https://example.com'), 'synthetic', f.snapshot, f.key));
	const response = await f.request(`/object/attachment/file-id?itemid=${id}`);
	expect(response.status).toBe(200);
	expect(response.headers.get('Content-Disposition')).toContain('%0D%0A');
	expect(Buffer.from(await response.arrayBuffer()).equals(Buffer.alloc(131072, 171))).toBe(true);
	expect(contents.every(value => value === 0)).toBe(true);
});
test('local API uses native template envelopes, object discriminators, HEAD and OPTIONS semantics', async () => {
	const { request } = fixture();
	expect(await (await request('/status')).json()).toEqual({
		success: true,
		data: { object: 'template', template: { status: 'unlocked' } },
	});
	expect(await (await request('/object/template/item')).json()).toMatchObject({
		data: { object: 'template', template: { type: 1 } },
	});
	expect(await (await request(`/object/item/${id}`)).json()).toMatchObject({ data: { object: 'item', id } });
	const head = await request('/status', { method: 'HEAD' });
	expect(head.status).toBe(200);
	expect(await head.text()).toBe('');
	const options = await request(`/object/item/${id}`, { method: 'OPTIONS' });
	expect(options.status).toBe(204);
	expect(options.headers.get('Allow')).toBe('GET, HEAD, PUT, DELETE');
	const unsupported = await request('/status', { method: 'DELETE' });
	expect(unsupported.status).toBe(405);
	expect(unsupported.headers.get('Allow')).toBe('GET, HEAD');
});
test('local API rejects file Send creation without accessing a host file', async () => {
	const { request } = fixture();
	const result = await request('/object/send', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({
			type: 1,
			name: 'file',
			deletionDate: new Date(Date.now() + 86400000).toISOString(),
			file: { fileName: '/etc/passwd' },
		}),
	});
	expect(result.status).toBe(400);
	expect(await result.json()).toEqual({
		success: false,
		message: 'Creating a file-based Send is unsupported through the `serve` command at this time.',
	});
});
test('local API projects item responses, normalizes dates and honors hidden-password metadata', async () => {
	const f = fixture();
	f.snapshot.ciphers = [encryptItem({
		id,
		type: 1,
		name: 'restricted',
		viewPassword: false,
		edit: true,
		permissions: { delete: true },
		creationDate: '2026-10-20T12:00:00.123456Z',
		login: { username: 'alice', password: 'synthetic-password', totp: 'synthetic-totp', uri: null, uris: [] },
		fields: [{ name: 'hidden', type: 1, value: 'synthetic-hidden' }],
		passwordHistory: [{ password: 'synthetic-old', lastUsedDate: '2026-10-19T12:00:00Z' }],
		attachments: [{ id: 'a', fileName: 'file', key: 'synthetic-wrapped-key', size: '12' }],
	}, f.key)];
	const result = await (await f.request(`/object/item/${id}`)).json();
	expect(result.data.object).toBe('item');
	expect(result.data.creationDate).toBe('2026-10-20T12:00:00.123Z');
	expect(result.data.login).toMatchObject({
		password: null,
		totp: null,
		fido2Credentials: [],
		passwordRevisionDate: null,
	});
	expect(result.data.fields[0].value).toBeNull();
	for (const field of ['key', 'edit', 'permissions', 'viewPassword', 'passwordHistory']) {
		expect(result.data).not.toHaveProperty(field);
	}
	expect(result.data.attachments[0]).not.toHaveProperty('key');
	expect(result.data.login).not.toHaveProperty('uri');
	expect((await f.request(`/object/password/${id}`)).status).toBe(400);
});
