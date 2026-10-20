import { test, expect } from 'bun:test';
import { createHash } from 'node:crypto';
import { VaultwardenClient, ApiError } from '#client';
import { createSsoAuthorization, ssoCredentialsFromCallback, loginWithSso, SsoAuthorizationDeclinedError } from '#sso';
import { refreshAccount, unlockAccount } from '#account';
import { deriveMasterKey, stretchKey, encrypt } from '#crypto';

const key = Buffer.alloc(64, 21), email = 'sso@example.com', password = 'synthetic-master-password';
const kdf = { type: 0, iterations: 10000 } as const;
const master = await deriveMasterKey(password, email, kdf),
	stretched = stretchKey(master),
	wrapped = encrypt(key, stretched);
master.fill(0);
stretched.fill(0);
const credentials = { code: 'synthetic-sso-code', codeVerifier: 'v'.repeat(64), redirectUri: 'http://localhost:8065' };
test('SSO authorization uses random state, S256 PKCE and the configured identity endpoint', async () => {
	const client = new VaultwardenClient('https://vault.example/prefix', {
		services: { identity: 'https://identity.example/auth' },
		fetch: (async (url: unknown) => {
			expect(String(url)).toBe('https://identity.example/auth/sso/prevalidate');
			return Response.json({ token: 'synthetic-prevalidation-token' });
		}) as unknown as typeof fetch,
	});
	const first = await createSsoAuthorization(client, credentials.redirectUri, 'organization'),
		second = await createSsoAuthorization(client, credentials.redirectUri);
	expect(first.state).not.toBe(second.state);
	expect(first.codeVerifier).not.toBe(second.codeVerifier);
	const url = new URL(first.url);
	expect(url.pathname).toBe('/auth/connect/authorize');
	expect(url.searchParams.get('code_challenge')).toBe(
		createHash('sha256').update(first.codeVerifier).digest('base64url'),
	);
	expect(url.searchParams.get('code_challenge_method')).toBe('S256');
	expect(url.searchParams.get('domain_hint')).toBe('organization');
	expect(first.url).not.toContain(first.codeVerifier);
	const callback = new URL(credentials.redirectUri);
	callback.search = new URLSearchParams({ state: first.state, code: 'synthetic-code', iss: first.issuer }).toString();
	expect(ssoCredentialsFromCallback(first, callback.href)).toEqual({
		code: 'synthetic-code',
		codeVerifier: first.codeVerifier,
		redirectUri: credentials.redirectUri,
	});
});
test('callback state, issuer, destination, duplicate parameters and OAuth errors are checked before exchange', async () => {
	const client = new VaultwardenClient('https://vault.example', {
		fetch: (async () => Response.json({ token: 'synthetic' })) as unknown as typeof fetch,
	});
	const authorization = await createSsoAuthorization(client, credentials.redirectUri);
	const valid = `${credentials.redirectUri}/?state=${authorization.state}&code=synthetic`;
	for (
		const callback of [
			valid.replace(authorization.state, 'wrong'),
			valid.replace('localhost', 'attacker.example'),
			`${valid}&state=${authorization.state}`,
			`${valid}&code=duplicate`,
			`${valid}&iss=https://wrong.example`,
			valid.replace('/?', '/other?'),
			`${valid}#fragment`,
		]
	) {
		expect(() => ssoCredentialsFromCallback(authorization, callback)).toThrow();
	}
	expect(() => ssoCredentialsFromCallback(authorization, `${valid}&error=access_denied`)).toThrow(
		SsoAuthorizationDeclinedError,
	);
	await expect(createSsoAuthorization(client, 'http://localhost:9000')).rejects.toThrow('8065');
});
test('disabled SSO has an actionable error while rate limits retain their status without retries', async () => {
	for (const status of [400, 429]) {
		let requests = 0;
		const client = new VaultwardenClient('https://vault.example', {
			fetch: (async () => {
				requests++;
				return Response.json({ error: 'synthetic-private-provider-detail' }, { status });
			}) as unknown as typeof fetch,
		});
		const error = await createSsoAuthorization(client, credentials.redirectUri).catch((error: unknown) => error);
		expect(error).toBeInstanceOf(Error);
		expect(String(error)).not.toContain('synthetic-private-provider-detail');
		if (status === 400) {
			expect((error as Error).message).toContain('not enabled');
			expect((error as Error).cause).toBeInstanceOf(ApiError);
		} else {
			expect(error).toBeInstanceOf(ApiError);
			expect((error as ApiError).status).toBe(429);
		}
		expect(requests).toBe(1);
	}
});
test('SSO login resolves email/KDF from authenticated data, retains no grant parameters and refreshes without a password grant', async () => {
	const grants: URLSearchParams[] = [];
	const client = new VaultwardenClient('https://vault.example', {
		deviceId: 'fixture-device',
		fetch: (async (url: unknown, init: RequestInit) => {
			if (String(url).endsWith('/profile')) return Response.json({ id: 'user', email: 'SSO@Example.COM' });
			const body = new URLSearchParams(String(init.body));
			grants.push(body);
			if (body.get('grant_type') === 'refresh_token') {
				return Response.json({ access_token: 'renewed', refresh_token: 'renewed-refresh', expires_in: 3600 });
			}
			expect(body.get('grant_type')).toBe('authorization_code');
			expect(body.get('scope')).toBe('api offline_access');
			expect(body.get('code_verifier')).toBe(credentials.codeVerifier);
			expect(body.get('redirect_uri')).toBe(credentials.redirectUri);
			expect(body.has('password')).toBe(false);
			return Response.json({
				access_token: 'access',
				refresh_token: 'refresh',
				expires_in: 3600,
				key: wrapped,
				kdf: 0,
				kdfIterations: 10000,
			});
		}) as unknown as typeof fetch,
	});
	const account = await loginWithSso(client, credentials);
	expect(account.auth).toBe('sso');
	expect(account.email).toBe(email);
	expect(account.kdf).toEqual(kdf);
	expect(JSON.stringify(account)).not.toContain(credentials.code);
	expect(JSON.stringify(account)).not.toContain(credentials.codeVerifier);
	const unlocked = await unlockAccount(account, password);
	try {
		expect(unlocked).toEqual(key);
	} finally {
		unlocked.fill(0);
	}
	expect((await refreshAccount(client, account)).accessToken).toBe('renewed');
	expect(grants.map(g => g.get('grant_type'))).toEqual(['authorization_code', 'refresh_token']);
});
test('SSO email 2FA retries the same code once and requests delivery using the pending device only', async () => {
	let grants = 0, callbacks = 0, emailRequests = 0;
	const client = new VaultwardenClient('https://vault.example', {
		deviceId: 'fixture-device',
		fetch: (async (url: unknown, init: RequestInit) => {
			if (String(url).endsWith('/profile')) return Response.json({ id: 'user', email });
			if (String(url).endsWith('/send-email-login')) {
				emailRequests++;
				expect(JSON.parse(String(init.body))).toEqual({ deviceIdentifier: 'fixture-device' });
				return Response.json({});
			}
			grants++;
			const body = new URLSearchParams(String(init.body));
			expect(body.get('code')).toBe(credentials.code);
			expect(body.get('code_verifier')).toBe(credentials.codeVerifier);
			if (grants === 1) return Response.json({ twoFactorProviders: [1] }, { status: 400 });
			expect(body.get('twoFactorProvider')).toBe('1');
			expect(body.get('twoFactorToken')).toBe('123456');
			return Response.json({
				access_token: 'access',
				refresh_token: 'refresh',
				expires_in: 3600,
				userDecryptionOptions: {
					masterPasswordUnlock: { masterKeyWrappedUserKey: wrapped, kdf: { kdfType: 0, iterations: 10000 } },
				},
			});
		}) as unknown as typeof fetch,
	});
	const account = await loginWithSso(client, credentials, undefined, {
		onTwoFactor: async challenge => {
			callbacks++;
			await challenge.requestEmail();
			return { provider: 1, token: '123456' };
		},
	});
	expect(account.kdf).toEqual(kdf);
	expect(callbacks).toBe(1);
	expect(grants).toBe(2);
	expect(emailRequests).toBe(1);
});
test('SSO errors and missing vault setup never fall back to password login or repeat grants', async () => {
	for (const scenario of ['cancel', 'retry-failed', 'uninitialized']) {
		let grants = 0;
		const client = new VaultwardenClient('https://vault.example', {
			fetch: (async (url: unknown) => {
				if (String(url).endsWith('/profile')) return Response.json({ id: 'user', email });
				grants++;
				return scenario === 'uninitialized'
					? Response.json({ access_token: 'access', refresh_token: 'refresh', expires_in: 3600 })
					: Response.json({ twoFactorProviders: [0] }, { status: 400 });
			}) as unknown as typeof fetch,
		});
		const operation = loginWithSso(client, credentials, undefined, {
			onTwoFactor: async () => {
				if (scenario === 'cancel') throw new Error('Cancelled');
				return { provider: 0, token: 'wrong' };
			},
		});
		if (scenario === 'uninitialized') await expect(operation).rejects.toThrow('web vault');
		else if (scenario === 'cancel') await expect(operation).rejects.toThrow('Cancelled');
		else await expect(operation).rejects.toBeInstanceOf(ApiError);
		expect(grants).toBe(scenario === 'retry-failed' ? 2 : 1);
	}
});
