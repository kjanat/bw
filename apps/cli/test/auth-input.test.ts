import { test, expect } from 'bun:test';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { masterPassword, apiCredentials, loginEmail, answerLoginChallenge } from '#auth-input';

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
		expect(await masterPassword({ file, envName, noInteraction: true })).toBe('file-value');
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
