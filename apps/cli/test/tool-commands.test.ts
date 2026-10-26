import { expect, test } from 'bun:test';
import { resolvedExportFormat } from '#tool-commands';
import { reportProgressMessage } from '#report-commands';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { withStore } from '#store';

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
			const child = Bun.spawn([
				'node',
				new URL('../dist/main.js', import.meta.url).pathname,
				'generate',
				'--length',
				'5',
			], {
				env: { PATH: process.env.PATH, VW_APPDATA_DIR: dir },
				stdout: 'pipe',
				stderr: 'pipe',
				timeout: 5000,
				killSignal: 'SIGKILL',
			});
			const [code, stdout, stderr] = await Promise.all([
				child.exited,
				new Response(child.stdout).text(),
				new Response(child.stderr).text(),
			]);
			expect(stderr).toBe('');
			expect(code).toBe(0);
			expect(stdout.trim()).toHaveLength(32);
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

test('password-health progress text reports the exact riskable login count like bw', () => {
	expect(reportProgressMessage(3, true)).toBe('Checking 3 logins against Have I Been Pwned...');
	expect(reportProgressMessage(0, false)).toBe('Analyzing 0 logins...');
});
