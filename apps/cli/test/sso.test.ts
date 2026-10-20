import { test, expect } from 'bun:test';
import { createServer } from 'node:http';
import { VaultwardenClient } from '@kjanat/vaultwarden';
import { authorizeSso, normalizeSsoArguments } from '#sso-login';

const client = () =>
	new VaultwardenClient('https://vault.example', {
		fetch: (async () => Response.json({ token: 'synthetic' })) as unknown as typeof fetch,
	});
test('bw optional --sso identifier syntax is normalized without changing passwords or post-separator arguments', () => {
	expect(normalizeSsoArguments(['login', '--sso'])).toEqual(['login', '--sso']);
	expect(normalizeSsoArguments(['login', '--sso', 'organization', '--raw'])).toEqual([
		'login',
		'--sso',
		'--identifier',
		'organization',
		'--raw',
	]);
	expect(normalizeSsoArguments(['login', '--sso=organization'])).toEqual([
		'login',
		'--sso',
		'--identifier',
		'organization',
	]);
	expect(normalizeSsoArguments(['login', '--', '--sso', 'password'])).toEqual(['login', '--', '--sso', 'password']);
	expect(normalizeSsoArguments(['get', 'password', '--sso'])).toEqual(['get', 'password', '--sso']);
	expect(normalizeSsoArguments(['--pretty', '--quiet=false', 'login', '--sso', 'organization'])).toEqual([
		'--pretty',
		'--quiet=false',
		'login',
		'--sso',
		'--identifier',
		'organization',
	]);
});
test('SSO listener rejects unrelated/hostile requests, accepts a matching callback and closes its port', async () => {
	let redirect = '';
	const credentials = await authorizeSso(client(), {
		onAuthorization: async address => {
			const auth = new URL(address);
			redirect = auth.searchParams.get('redirect_uri')!;
			const callback = new URL(redirect);
			callback.search = new URLSearchParams({
				code: 'synthetic',
				state: auth.searchParams.get('state')!,
				iss: 'https://vault.example',
			}).toString();
			const wrong = new URL(callback);
			wrong.searchParams.set('state', 'wrong');
			expect((await fetch(wrong)).status).toBe(400);
			expect((await fetch(callback, { headers: { Origin: 'https://attacker.example' } })).status).toBe(400);
			expect((await fetch(callback, { headers: { Host: 'attacker.example' } })).status).toBe(400);
			expect((await fetch(callback)).status).toBe(200);
		},
	});
	expect(credentials.code).toBe('synthetic');
	await expect(fetch(redirect)).rejects.toThrow();
});
test('SSO listener skips occupied ports and reports a validated OAuth denial without exposing provider text', async () => {
	const occupied = createServer();
	await new Promise<void>(resolve => occupied.listen(8065, '127.0.0.1', resolve));
	try {
		await expect(authorizeSso(client(), {
			onAuthorization: async address => {
				const auth = new URL(address), redirect = auth.searchParams.get('redirect_uri')!;
				expect(redirect).not.toBe('http://localhost:8065');
				const callback = new URL(redirect);
				callback.search = new URLSearchParams({
					state: auth.searchParams.get('state')!,
					error: 'synthetic-secret-provider-text',
				}).toString();
				expect((await fetch(callback)).status).toBe(400);
			},
		})).rejects.toThrow('declined');
	} finally {
		await new Promise<void>(resolve => occupied.close(() => resolve()));
	}
});
test('SSO timeout aborts prevalidation, never opens a browser and frees the callback listener', async () => {
	let opened = false;
	const pending = new VaultwardenClient('https://vault.example', {
		fetch: (async (_url: unknown, init: RequestInit) => {
			await new Promise((_resolve, reject) =>
				init.signal!.addEventListener('abort', () => reject(new Error('Aborted')), { once: true })
			);
			return Response.json({});
		}) as unknown as typeof fetch,
	});
	await expect(authorizeSso(pending, {
		timeoutMs: 20,
		onAuthorization: () => {
			opened = true;
		},
	})).rejects.toThrow('timed out');
	expect(opened).toBe(false);
	const probe = createServer();
	await new Promise<void>(resolve => probe.listen(8065, '127.0.0.1', resolve));
	await new Promise<void>(resolve => probe.close(() => resolve()));
});
