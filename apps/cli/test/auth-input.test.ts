import { test, expect } from 'bun:test';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
	masterPassword,
	apiCredentials,
	loginEmail,
	answerLoginChallenge,
	duoCallbackToken,
	supportedLoginProviders,
} from '#auth-input';

test('master-password sources follow bw precedence and read only a file first line', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-auth-input-'));
	const envName = 'VW_TEST_MASTER_SOURCE';
	const previous = process.env[envName];
	process.env[envName] = 'environment-value';
	try {
		const file = join(dir, 'password.txt');
		await writeFile(file, 'file-value\r\nignored-line\n', { mode: 0o600 });
		expect(await masterPassword({ positional: 'positional-value', file, envName, noInteraction: true })).toBe(
			'positional-value',
		);
		expect(
			await masterPassword({
				positional: 'environment-value',
				positionalSource: 'env',
				file,
				envName,
				noInteraction: true,
			}),
		).toBe('file-value');
		expect(await masterPassword({ positional: 'environment-value', positionalSource: 'env', noInteraction: true }))
			.toBe(
				'environment-value',
			);
		expect(await masterPassword({ file, envName, noInteraction: true })).toBe('file-value');
		await writeFile(file, 'classic-mac-password\rignored-line\r', { mode: 0o600 });
		expect(await masterPassword({ file, envName, noInteraction: true })).toBe('classic-mac-password');
		expect(await masterPassword({ envName, noInteraction: true })).toBe('environment-value');
		await writeFile(file, '\nignored', { mode: 0o600 });
		await expect(masterPassword({ file, envName, noInteraction: true })).rejects.toThrow('required');
	} finally {
		if (previous === undefined) delete process.env[envName];
		else process.env[envName] = previous;
		await rm(dir, { recursive: true, force: true });
	}
});
test('noninteractive login inputs fail without prompting or echoing a credential', async () => {
	await expect(masterPassword({ envName: 'VW_TEST_MISSING_MASTER_SOURCE', noInteraction: true })).rejects.toThrow(
		'required',
	);
	await expect(loginEmail(undefined, true)).rejects.toThrow('email');
	await expect(apiCredentials('VW_TEST_MISSING_CLIENT_ID', 'VW_TEST_MISSING_CLIENT_SECRET', true)).rejects.toThrow(
		'credentials',
	);
	expect(await apiCredentials(undefined, undefined, true, 'synthetic-client-id', 'synthetic-client-secret')).toEqual({
		clientId: 'synthetic-client-id',
		clientSecret: 'synthetic-client-secret',
	});
});
test('named API credential variables override defaults, while explicit CLI values win', async () => {
	const idName = 'VW_TEST_NAMED_CLIENT_ID';
	const secretName = 'VW_TEST_NAMED_CLIENT_SECRET';
	const previousId = process.env[idName], previousSecret = process.env[secretName];
	try {
		process.env[idName] = 'named-client-id';
		process.env[secretName] = 'named-client-secret';
		expect(
			await apiCredentials(
				idName,
				secretName,
				true,
				'default-client-id',
				'default-client-secret',
				'env',
				'env',
			),
		).toEqual({ clientId: 'named-client-id', clientSecret: 'named-client-secret' });
		expect(
			await apiCredentials(
				idName,
				secretName,
				true,
				'cli-client-id',
				'cli-client-secret',
				'cli',
				'cli',
			),
		).toEqual({ clientId: 'cli-client-id', clientSecret: 'cli-client-secret' });
		delete process.env[idName];
		delete process.env[secretName];
		await expect(apiCredentials(
			idName,
			secretName,
			true,
			'default-client-id',
			'default-client-secret',
			'env',
			'env',
		)).rejects.toThrow('credentials');
	} finally {
		if (previousId === undefined) delete process.env[idName];
		else process.env[idName] = previousId;
		if (previousSecret === undefined) delete process.env[secretName];
		else process.env[secretName] = previousSecret;
	}
});
test('noninteractive challenges never send email or prompt for a code', async () => {
	let requests = 0;
	await expect(answerLoginChallenge(
		{
			providers: [1],
			requestEmail: async () => {
				requests++;
			},
		},
		1,
		true,
	))
		.rejects.toThrow('Supply --method and --code');
	expect(requests).toBe(0);
});
test('recovery-code challenges are offered as a supported login provider', () => {
	expect(supportedLoginProviders({
		providers: [0, 8],
		requestEmail: async () => {},
	})).toEqual([0, 8]);
});
test('Duo callback extraction binds the browser redirect to Vaultwarden’s signed request redirect', () => {
	const redirectUri = 'https://vault.example/duo-redirect-connector.html?client=cli';
	const request = `header.${
		Buffer.from(JSON.stringify({ redirect_uri: redirectUri })).toString('base64url')
	}.signature`;
	const authorizationUrl = `https://api-example.duosecurity.com/oauth/v1/authorize?request=${
		encodeURIComponent(request)
	}`;
	expect(duoCallbackToken(`${redirectUri}&code=auth-code&state=login-state`, authorizationUrl)).toBe(
		'auth-code|login-state',
	);
	expect(() => duoCallbackToken('https://attacker.example/callback?code=x&state=y', authorizationUrl)).toThrow(
		'does not match',
	);
	expect(() => duoCallbackToken(`${redirectUri}&code=x`, authorizationUrl)).toThrow('missing');
});
