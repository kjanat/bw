import { expect, test } from 'bun:test';
import { ApiError, VaultwardenClient, serverUrl } from '#client';

function transport(
	handler: (url: string, init: RequestInit) => Response | Promise<Response>,
): typeof fetch {
	return ((url: string | URL | Request, init: RequestInit) => handler(String(url), init)) as typeof fetch;
}
const json = (data: unknown, status = 200) => Response.json(data, { status });
test('requires TLS except loopback and preserves path prefixes', () => {
	expect(serverUrl('https://example.com/vault/')).toBe(
		'https://example.com/vault',
	);
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
				{ TwoFactorProviders: [0, 1], error_description: 'sensitive response' },
				400,
			)
		),
	});
	try {
		await api.login('test@example.com', 'hash');
		throw new Error('expected failure');
	} catch (error) {
		expect(error).toBeInstanceOf(ApiError);
		expect((error as ApiError).twoFactorProviders).toEqual([0, 1]);
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
