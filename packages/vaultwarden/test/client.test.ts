import { expect, test } from 'bun:test';
import { ApiError, VaultwardenClient, serverUrl } from '#client';

function transport(
	handler: (url: string, init: RequestInit) => Response | Promise<Response>,
): typeof fetch {
	return ((url: string | URL | Request, init: RequestInit) => handler(String(url), init)) as typeof fetch;
}
const json = (data: unknown, status = 200) => Response.json(data, { status });
test('account revisions accept integer timestamps and deletion signals, preserving service routing and auth', async () => {
	for (const revision of [0, 1780000000000, -1, '1780000000000', null, {}, 1.5, 8640000000000001]) {
		const api = new VaultwardenClient('https://vault.example', {
			services: { api: 'https://api.example/prefix' },
			fetch: transport((url, init) => {
				expect(url).toBe('https://api.example/prefix/accounts/revision-date');
				expect(new Headers(init.headers).get('Authorization')).toBe('Bearer synthetic-token');
				return json(revision);
			}),
		});
		if (typeof revision === 'number' && Number.isSafeInteger(revision) && Math.abs(revision) <= 8640000000000000) {
			expect(await api.accountRevisionDate('synthetic-token')).toBe(revision);
		} else await expect(api.accountRevisionDate('synthetic-token')).rejects.toThrow('Invalid account revision');
	}
});
test('cipher-type writes use and cache the Vaultwarden release version', async () => {
	for (const [version, supported] of [['1.36.0', false], ['1.37.4', true]] as const) {
		let requests = 0;
		const api = new VaultwardenClient('https://vault.example/base', {
			services: { api: 'https://api.example/prefix' },
			fetch: transport(url => {
				requests++;
				if (url.endsWith('/config')) return json({ server: { name: 'Vaultwarden' } });
				expect(url).toBe('https://api.example/prefix/version');
				return json(version);
			}),
		});
		if (supported) await api.assertCipherTypeSupported(6);
		else {await expect(api.assertCipherTypeSupported(6)).rejects.toThrow(
				'bank account requires Vaultwarden 1.37.4 or newer; this server reports 1.36.0',
			);}
		if (supported) await api.assertCipherTypeSupported(8);
		expect(requests).toBe(2);
	}
});
test('cipher-type compatibility checks do not apply Vaultwarden release limits to Bitwarden', async () => {
	const requests: string[] = [];
	const api = new VaultwardenClient('https://vault.example', {
		fetch: transport(url => {
			requests.push(url);
			return json({ server: { name: 'Bitwarden' } });
		}),
	});
	await api.assertCipherTypeSupported(6);
	await api.assertCipherTypeSupported(8);
	expect(requests).toEqual(['https://vault.example/api/config']);
});
test('requires TLS except loopback and preserves path prefixes', () => {
	expect(serverUrl('https://example.com/vault/')).toBe(
		'https://example.com/vault',
	);
	expect(serverUrl('vault.example/path/')).toBe('https://vault.example/path');
	expect(serverUrl('bitwarden.com')).toBe('https://bitwarden.com');
	expect(serverUrl('http://127.0.0.1:1234')).toBe('http://127.0.0.1:1234');
	for (
		const value of [
			'http://example.com',
			'https://user:pass@example.com',
			'https://example.com/?token=x',
		]
	) {
		expect(() => serverUrl(value)).toThrow();
	}
});
test('prelogin falls back only on missing endpoints', async () => {
	const paths: string[] = [];
	const api = new VaultwardenClient('https://example.com/vault', {
		fetch: transport((url, init) => {
			paths.push(url);
			expect(init.redirect).toBe('error');
			expect(JSON.parse(String(init.body)).email).toBe('test@example.com');
			return paths.length === 1
				? json({}, 404)
				: json({ Kdf: 0, KdfIterations: 600000 });
		}),
	});
	expect(await api.prelogin(' Test@Example.com ')).toEqual({
		type: 0,
		iterations: 600000,
	});
	expect(paths).toEqual([
		'https://example.com/vault/identity/accounts/prelogin',
		'https://example.com/vault/api/accounts/prelogin',
	]);
});
test('prelogin never retries rate limiting or auth failures', async () => {
	let calls = 0;
	const api = new VaultwardenClient('https://example.com', {
		fetch: transport(() => {
			calls++;
			return json({ error: 'sensitive response' }, 429);
		}),
	});
	await expect(api.prelogin('test@example.com')).rejects.toThrow('HTTP 429');
	expect(calls).toBe(1);
});
test('split identity and API endpoints preserve service prefixes through prelogin fallback and API calls', async () => {
	const paths: string[] = [];
	const api = new VaultwardenClient('https://vault.example.com/base', {
		services: { api: 'https://api.example.com/custom/api/', identity: 'https://auth.example.com/custom/identity/' },
		fetch: transport((url, init) => {
			paths.push(url);
			if (url.includes('/custom/identity/')) return json({}, 404);
			if (url.endsWith('/accounts/prelogin')) return json({ kdf: 0, kdfIterations: 600000 });
			expect(new Headers(init.headers).get('Authorization')).toBe('Bearer synthetic-token');
			return json({ data: [] });
		}),
	});
	expect(await api.prelogin('fixture@example.com')).toEqual({ type: 0, iterations: 600000 });
	await api.api('synthetic-token', 'GET', '/folders', undefined, { search: 'a b' });
	expect(paths).toEqual([
		'https://auth.example.com/custom/identity/accounts/prelogin',
		'https://api.example.com/custom/api/accounts/prelogin',
		'https://api.example.com/custom/api/folders?search=a+b',
	]);
	expect(() =>
		new VaultwardenClient('https://vault.example.com', {
			services: { identity: 'http://auth.example.com' },
		})
	).toThrow();
});
test('supports nested KDF settings and modern wrapped user key responses', async () => {
	const api = new VaultwardenClient('https://example.com', {
		deviceId: 'test-device',
		fetch: transport((url, init) => {
			if (url.endsWith('prelogin')) {
				return json({
					kdfSettings: {
						kdfType: 1,
						iterations: 3,
						memory: 64,
						parallelism: 4,
					},
				});
			}
			const body = init.body as URLSearchParams;
			expect(body.get('deviceType')).toBe('8');
			expect(body.get('twoFactorProvider')).toBe('0');
			return json({
				access_token: 'access',
				refresh_token: 'refresh',
				expires_in: 3600,
				UserDecryptionOptions: {
					MasterPasswordUnlock: { MasterKeyWrappedUserKey: 'wrapped' },
				},
			});
		}),
	});
	expect(await api.prelogin('test@example.com')).toEqual({
		type: 1,
		iterations: 3,
		memory: 64,
		parallelism: 4,
	});
	expect(
		(
			await api.login('test@example.com', 'hash', {
				provider: 0,
				token: '123456',
			})
		).encryptedUserKey,
	).toBe('wrapped');
});
test('2FA errors expose provider IDs without echoing server error bodies', async () => {
	const api = new VaultwardenClient('https://example.com', {
		fetch: transport(() =>
			json(
				{
					TwoFactorProviders: [0, 1, 2, 7],
					TwoFactorProviders2: {
						'2': { AuthUrl: 'https://api-test.duosecurity.com/oauth/v1/authorize?request=token' },
						'7': { challenge: 'cG93ZXJmdWw', rpId: 'example.com', allowCredentials: [] },
					},
					error_description: 'sensitive response',
				},
				400,
			)
		),
	});
	try {
		await api.login('test@example.com', 'hash');
		throw new Error('expected failure');
	} catch (error) {
		expect(error).toBeInstanceOf(ApiError);
		expect((error as ApiError).twoFactorProviders).toEqual([0, 1, 2, 7]);
		expect((error as ApiError).twoFactorProviderData[2]).toEqual({
			AuthUrl: 'https://api-test.duosecurity.com/oauth/v1/authorize?request=token',
		});
		expect((error as ApiError).twoFactorProviderData[7]).toEqual({
			challenge: 'cG93ZXJmdWw',
			rpId: 'example.com',
			allowCredentials: [],
		});
		expect(String(error)).not.toContain('sensitive');
	}
});

test('signed attachment download never forwards account credentials or follows redirects', async () => {
	const api = new VaultwardenClient('https://vault.example.com', {
		fetch: transport((url, init) => {
			expect(url).toBe('https://storage.example.com/object?token=synthetic');
			expect(init.headers).toBeUndefined();
			expect(init.credentials).toBe('omit');
			expect(init.redirect).toBe('error');
			return new Response(new Uint8Array([0, 1, 255]));
		}),
	});
	expect(await api.downloadAttachment('https://storage.example.com/object?token=synthetic')).toEqual(
		Buffer.from([0, 1, 255]),
	);
	await expect(api.downloadAttachment('http://storage.example.com/object')).rejects.toThrow('Invalid attachment URL');
	await expect(api.downloadAttachment('https://user:password@storage.example.com/object')).rejects.toThrow(
		'Invalid attachment URL',
	);
});
