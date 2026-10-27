import { expect, test } from 'bun:test';
import { runCommand } from '@kjanat/dreamcli/testkit';
import { runCapturedProcess } from '#test/process';
import { password, resolvedExportFormat, toolCommands } from '#tool-commands';
import { reportProgressMessage } from '#report-commands';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { withStore } from '#store';
import type { VaultRuntime } from '#vault-commands';

test('compiled CLI generation enforces policiesNew with legacy policy controls', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-generator-policy-'));
	try {
		for (const field of ['policies', 'policiesNew']) {
			await withStore(dir, async (state, save) => {
				state.account = {
					email: 'synthetic@example.test',
					kdf: { type: 0, iterations: 1000 },
					encryptedUserKey: 'synthetic',
					accessToken: 'synthetic',
					refreshToken: 'synthetic',
					expiresAt: Date.now() + 3600000,
				};
				state.vault = {
					profile: { id: 'user', organizations: [{ id: 'org', status: 2, type: 2, enabled: true, usePolicies: true }] },
					[field]: [{ organizationId: 'org', type: 2, enabled: true, data: { minLength: 32 } }],
				};
				await save();
			});
			const child = await runCapturedProcess([
				'node',
				new URL('../dist/main.js', import.meta.url).pathname,
				'generate',
				'--length',
				'5',
			], { env: { PATH: process.env.PATH!, VW_APPDATA_DIR: dir } });
			expect(child.stderr).toBe('');
			expect(child.code).toBe(0);
			expect(child.stdout.trim()).toHaveLength(32);
		}
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test('JSON export with a password selects encrypted JSON like bw', () => {
	expect(resolvedExportFormat('json', true)).toBe('encrypted_json');
	expect(resolvedExportFormat('json', false)).toBe('json');
	expect(resolvedExportFormat('encrypted_json', false)).toBe('encrypted_json');
	expect(resolvedExportFormat('csv', true)).toBe('csv');
});

test('password sources follow bw priority: explicit value, file, named environment, default environment', async () => {
	const directory = await mkdtemp(join(tmpdir(), 'vw-password-source-'));
	const file = join(directory, 'password.txt');
	const envName = 'VW_TEST_NAMED_PASSWORD';
	const previous = process.env[envName];
	process.env[envName] = 'named secret';
	try {
		await writeFile(file, 'file secret\nsecond line\n', { mode: 0o600 });
		expect(await password('explicit secret', envName, file, 'default secret')).toBe('explicit secret');
		expect(await password(undefined, envName, file, 'default secret')).toBe('file secret');
		expect(await password(undefined, envName, undefined, 'default secret')).toBe('named secret');
		expect(await password(undefined, undefined, undefined, 'default secret')).toBe('default secret');
		await writeFile(file, '\nignored line', { mode: 0o600 });
		expect(await password(undefined, envName, file, 'default secret')).toBeUndefined();
		process.env[envName] = '';
		await expect(password(undefined, envName, undefined, 'default secret')).rejects.toThrow('unset');
		expect(await password(undefined, envName, undefined, undefined, false)).toBeUndefined();
	} finally {
		if (previous === undefined) delete process.env[envName];
		else process.env[envName] = previous;
		await rm(directory, { recursive: true, force: true });
	}
});

test('unprotected imports ignore unused password sources', async () => {
	const directory = await mkdtemp(join(tmpdir(), 'vw-unprotected-import-'));
	const input = join(directory, 'vault.json');
	const protectedInput = join(directory, 'protected.json');
	const passwordFile = join(directory, 'missing-password.txt');
	const envName = 'VW_TEST_UNUSED_IMPORT_PASSWORD';
	const previous = process.env[envName];
	delete process.env[envName];
	await writeFile(input, JSON.stringify({ encrypted: false }));
	await writeFile(protectedInput, JSON.stringify({ passwordProtected: true }));
	let capturedPassword: string | undefined;
	const runtime = {
		run: async (_session: string | undefined, _mutate: boolean, operation: (vault: never) => unknown) =>
			await operation({
				importVault: async (_format: string, _source: Uint8Array, options: { password?: string }) => {
					capturedPassword = options.password;
					return { imported: true };
				},
			} as never),
	} as unknown as VaultRuntime;
	try {
		const { importCommand } = toolCommands(runtime, directory);
		const result = await runCommand(importCommand, [
			'bitwardenjson',
			input,
			'--passwordenv',
			envName,
			'--passwordfile',
			passwordFile,
		], { env: { NOINTERACTION: 'true' } });
		expect(result.exitCode).toBe(0);
		expect(capturedPassword).toBeUndefined();
		const protectedResult = await runCommand(importCommand, [
			'bitwardenjson',
			protectedInput,
			'--passwordenv',
			envName,
			'--nointeraction',
		], { env: { NOINTERACTION: 'true' } });
		expect(protectedResult.exitCode).toBe(1);
		expect(protectedResult.error?.message).toContain('Import file password required.');
		expect(protectedResult.error?.message).not.toContain('environment variable is unset');
	} finally {
		if (previous === undefined) delete process.env[envName];
		else process.env[envName] = previous;
		await rm(directory, { recursive: true, force: true });
	}
});

test('password-health progress text reports the exact riskable login count like bw', () => {
	expect(reportProgressMessage(3, true)).toBe('Checking 3 logins against Have I Been Pwned...');
	expect(reportProgressMessage(0, false)).toBe('Analyzing 0 logins...');
});
