import { test, expect } from 'bun:test';
import { VaultwardenClient, ApiError, type JsonObject } from '#client';
import { encrypt, decrypt, encryptAttachment } from '#crypto';
import {
	deriveSendKey,
	hashSendPassword,
	SendService,
	receiveSend,
	SendPasswordRequired,
	SendMutationFailure,
} from '#sends';

const accountKey = Buffer.alloc(64, 3);
const seed = Buffer.from(Array.from({ length: 16 }, (_, i) => i));
const key = deriveSendKey(seed);
const accessId = Buffer.alloc(16, 9).toString('base64url');
const link = `https://vault.example/prefix/#/send/${accessId}/${seed.toString('base64url')}`;
function encryptedSend(): JsonObject {
	return {
		id: 'send-id',
		accessId,
		type: 0,
		key: encrypt(seed, accountKey),
		name: encrypt(Buffer.from('Secret send'), key),
		notes: encrypt(Buffer.from('Private notes'), key),
		text: { text: encrypt(Buffer.from('Payload'), key), hidden: true },
		deletionDate: new Date(Date.now() + 86400000).toISOString(),
		disabled: false,
		password: 'server-only-hash',
	};
}
test('Send HKDF and password proof match independent Python stdlib vectors', () => {
	expect(key.toString('hex')).toBe(
		'063a955a1c01b4e1aacb7cd359c919b2cb61041c0c05c94c0eb76fb9a9e144b3fbeca074de1437a1a2330ad2833138abf3be2561a3a30ae1f33e15e1a2f7ca04',
	);
	expect(Buffer.from(hashSendPassword('synthetic-password', seed), 'base64').toString('hex')).toBe(
		'0f80ecb32361e1f1e6f3bee07f74bd853216c8c4c3eeacc5149ecaa709d2c512',
	);
	expect(() => deriveSendKey(Buffer.alloc(32))).toThrow('seed');
});
test('owner reads decrypt with the wrapped Send seed, expose access URL, and omit server password hash', () => {
	const service = new SendService(new VaultwardenClient('https://vault.example/prefix'), 'owner-token', {
		sends: [encryptedSend()],
	}, accountKey);
	const result = service.get('secret');
	expect(result.text).toEqual({ text: 'Payload', hidden: true });
	expect(result.notes).toBe('Private notes');
	expect(result.accessUrl).toBe(link);
	expect(result.passwordSet).toBe(true);
	expect(result.password).toBeUndefined();
});
test('editing retains the seed, omits unchanged password proofs, and never transmits plaintext', async () => {
	let requests = 0;
	const client = new VaultwardenClient('https://vault.example', {
		fetch: (async (url: unknown, init?: RequestInit) => {
			requests++;
			expect(String(url)).toEndWith('/api/sends/send-id');
			const data = JSON.parse(String(init!.body));
			expect(data.password).toBeUndefined();
			const unwrapped = decrypt(data.key, accountKey);
			expect(unwrapped).toEqual(seed);
			expect(decrypt(data.name, deriveSendKey(unwrapped)).toString()).toBe('Renamed');
			expect(String(init!.body)).not.toContain('Payload');
			return Response.json({ ...encryptedSend(), ...data });
		}) as unknown as typeof fetch,
	});
	const service = new SendService(client, 'owner-token', { sends: [encryptedSend()] }, accountKey);
	expect((await service.edit('send-id', { name: 'Renamed' })).name).toBe('Renamed');
	await expect(service.edit('send-id', { type: 1 })).rejects.toThrow('type');
	expect(requests).toBe(1);
});
test('recipient access isolates Send credentials and keeps fragment keys off the wire', async () => {
	const calls: { url: string; init: RequestInit }[] = [];
	const raw = encryptedSend();
	delete raw.key;
	delete raw.notes;
	delete raw.password;
	const transport = (async (url: unknown, init: RequestInit) => {
		calls.push({ url: String(url), init });
		if (String(url).endsWith('/identity/connect/token')) return Response.json({ access_token: 'send-only-token' });
		return Response.json(raw);
	}) as unknown as typeof fetch;
	const result = await receiveSend(link, { password: 'synthetic-password', fetch: transport });
	expect(result.send.text).toMatchObject({ text: 'Payload' });
	expect(result.send.key).toBeUndefined();
	const body = new URLSearchParams(String(calls[0]!.init.body));
	expect(body.get('grant_type')).toBe('send_access');
	expect(body.get('password_hash_b64')).toBe(hashSendPassword('synthetic-password', seed));
	expect(calls[1]!.init.headers).toMatchObject({ Authorization: 'Bearer send-only-token' });
	for (const call of calls) {
		expect(call.url).not.toContain('#');
		expect(String(call.init.body)).not.toContain(seed.toString('base64url'));
		expect(String(call.init.body)).not.toContain('synthetic-password');
	}
});
test('recipient file decrypts authenticated binary data and omits credentials on signed download', async () => {
	const bytes = Buffer.from([0, 255, 128, 1, 0, 10]);
	const raw = { ...encryptedSend(), type: 1, file: { id: 'file-id', fileName: encrypt(Buffer.from('file.bin'), key) } };
	const transport = (async (url: unknown, init: RequestInit) => {
		const path = String(url);
		if (path.endsWith('/identity/connect/token')) return Response.json({ access_token: 'send-only-token' });
		if (path.endsWith('/api/sends/access')) return Response.json(raw);
		if (path.endsWith('/access/file/file-id')) return Response.json({ url: 'https://files.example/signed' });
		expect(path).toBe('https://files.example/signed');
		expect(init.headers).toBeUndefined();
		expect(init.redirect).toBe('error');
		return new Response(new Uint8Array(encryptAttachment(bytes, key)));
	}) as unknown as typeof fetch;
	const result = await receiveSend(link, { fetch: transport });
	expect(result.contents).toEqual(bytes);
	expect(result.fileName).toBe('file.bin');
});
test('invalid fragment URLs fail without requests, and password errors do not expose server text', async () => {
	let count = 0;
	const transport = (async () => {
		count++;
		return Response.json({ send_access_error_type: 'password_hash_b64_required', secret: 'never echo' }, {
			status: 400,
		});
	}) as unknown as typeof fetch;
	await expect(receiveSend('http://remote.example/#/send/id/key', { fetch: transport })).rejects.toThrow('HTTPS');
	await expect(receiveSend(link.replace(seed.toString('base64url'), 'bad'), { fetch: transport })).rejects.toThrow(
		'fragment',
	);
	expect(count).toBe(0);
	await expect(receiveSend(link, { fetch: transport })).rejects.toBeInstanceOf(SendPasswordRequired);
	expect(count).toBe(1);
	const client = new VaultwardenClient('https://vault.example', {
		fetch: (async () =>
			Response.json({ send_access_error_type: 'server-controlled-secret' }, {
				status: 400,
			})) as unknown as typeof fetch,
	});
	try {
		await client.sendAccessToken(accessId);
	} catch (error) {
		expect(error).toBeInstanceOf(ApiError);
		expect(String(error)).not.toContain('server-controlled-secret');
	}
});
for (const file of [false, true]) {
	test(`legacy anonymous Send ${file ? 'file' : 'text'} fallback sends proofs without account tokens or fragment keys`, async () => {
		const calls: { path: string; init: RequestInit }[] = [];
		const contents = Buffer.from([0, 255, 128, 10]);
		const raw = file
			? { ...encryptedSend(), type: 1, file: { id: 'file-id', fileName: encrypt(Buffer.from('legacy.bin'), key) } }
			: encryptedSend();
		const transport = (async (url: unknown, init: RequestInit) => {
			const path = String(url);
			calls.push({ path, init });
			if (path.endsWith('/identity/connect/token')) {
				return Response.json({ message: 'Invalid type', object: 'error' }, { status: 400 });
			}
			if (path === 'https://files.example/legacy') {
				expect(init.headers).toBeUndefined();
				expect(init.redirect).toBe('error');
				return new Response(new Uint8Array(encryptAttachment(contents, key)));
			}
			expect(init.headers).not.toHaveProperty('Authorization');
			expect(JSON.parse(String(init.body))).toEqual({ password: hashSendPassword('synthetic-password', seed) });
			if (path.endsWith(`/api/sends/access/${accessId}`)) return Response.json(raw);
			expect(path).toEndWith('/api/sends/send-id/access/file/file-id');
			return Response.json({ url: 'https://files.example/legacy' });
		}) as unknown as typeof fetch;
		const received = await receiveSend(link, { password: 'synthetic-password', fetch: transport });
		if (file) {
			expect(received.contents).toEqual(contents);
			expect(received.fileName).toBe('legacy.bin');
		} else expect(received.send.text).toMatchObject({ text: 'Payload' });
		expect(calls).toHaveLength(file ? 4 : 2);
		for (const call of calls) {
			expect(call.path).not.toContain('#');
			expect(String(call.init.body)).not.toContain('synthetic-password');
			expect(String(call.init.body)).not.toContain(seed.toString('base64url'));
		}
	});
}
test('legacy password challenges remain distinct and unrelated token failures never trigger fallback', async () => {
	for (
		const [status, message, incorrect] of [[401, 'Password not provided', false], [
			400,
			'Invalid password',
			true,
		]] as const
	) {
		let count = 0;
		const transport = (async () => {
			count++;
			return count === 1
				? Response.json({ message: 'Invalid type' }, { status: 400 })
				: Response.json({ message }, { status });
		}) as unknown as typeof fetch;
		try {
			await receiveSend(link, { fetch: transport });
			throw new Error('Expected challenge.');
		} catch (error) {
			expect(error).toBeInstanceOf(SendPasswordRequired);
			expect((error as SendPasswordRequired).incorrect).toBe(incorrect);
		}
		expect(count).toBe(2);
	}
	for (const status of [400, 401, 429, 500]) {
		let count = 0;
		const transport = (async () => {
			count++;
			return Response.json({ message: 'unrelated synthetic secret' }, { status });
		}) as unknown as typeof fetch;
		await expect(receiveSend(link, { fetch: transport })).rejects.toThrow(`HTTP ${status}`);
		expect(count).toBe(1);
	}
});
test('failed Send file upload rolls back metadata, and failed rollback is distinguished', async () => {
	for (const failDelete of [false, true]) {
		const paths: string[] = [];
		let encryptedName: string;
		const client = new VaultwardenClient('https://vault.example', {
			fetch: (async (url: unknown, init?: RequestInit) => {
				const path = String(url);
				paths.push(path);
				if (path.endsWith('/file/v2')) {
					const data = JSON.parse(String(init!.body));
					encryptedName = data.file.fileName;
					return Response.json({
						fileUploadType: 0,
						sendResponse: { ...data, id: 'new-id', accessId, file: { ...data.file, id: 'file-id' } },
					});
				}
				if (init!.body instanceof FormData) expect((init!.body.get('data') as File).name).toBe(encryptedName);
				if (init!.method === 'DELETE' && !failDelete) return new Response(null, { status: 204 });
				return Response.json({}, { status: 500 });
			}) as unknown as typeof fetch,
		});
		const service = new SendService(client, 'owner-token', { sends: [] }, accountKey);
		const operation = service.create(
			{ type: 1, name: 'File', file: { fileName: 'payload.bin' } },
			Buffer.from('payload'),
		);
		if (failDelete) await expect(operation).rejects.toBeInstanceOf(SendMutationFailure);
		else await expect(operation).rejects.toThrow('incomplete Send removed');
		expect(paths.at(-1)).toEndWith('/api/sends/new-id');
	}
});
