import { expect, test } from 'bun:test';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const expected = 'missing-user-key-id-endpoint';

test.each([
	{ name: 'known failures', outcomes: [expected, expected], expected, code: 0 },
	{ name: 'unexpected success', outcomes: ['authenticated', 'authenticated'], expected, code: 1 },
	{ name: 'mixed failures', outcomes: [expected, 'failed'], expected, code: 1 },
	{ name: 'unrelated failures', outcomes: ['failed', 'failed'], expected, code: 1 },
	{ name: 'compatible login', outcomes: ['authenticated', 'authenticated'], expected: '', code: 0 },
	{ name: 'unrecorded incompatibility', outcomes: [expected, expected], expected: '', code: 1 },
	{ name: 'setup failure', outcomes: [], expected, code: 1, setupError: true },
])('reference authentication reporting: $name', async scenario => {
	const directory = await mkdtemp(join(tmpdir(), 'vw-reference-tests-'));
	const helper = fileURLToPath(new URL('./reference-authentication.ts', import.meta.url));
	const suite = fileURLToPath(new URL('./reference-authentication-live.test.ts', import.meta.url));
	try {
		const preload = join(directory, 'probe.ts');
		await writeFile(
			preload,
			`import { mock } from 'bun:test';
mock.module(${JSON.stringify(helper)}, () => ({
  checkReferenceAuthentication: async () => {
    ${scenario.setupError ? "throw new Error('Fixture setup failed');" : `return ${JSON.stringify(scenario.outcomes)};`}
  }
}));
`,
		);
		const child = Bun.spawn(['bun', 'test', '--preload', preload, suite], {
			env: {
				PATH: process.env.PATH,
				VW_TEST_SERVER: 'http://127.0.0.1:1',
				VW_TEST_BW: 'mocked-reference',
				VW_TEST_REFERENCE_DIRECTORY: directory,
				VW_TEST_REFERENCE_FAILURE: scenario.expected,
			},
			stdout: 'pipe',
			stderr: 'pipe',
		});
		const [code, , stderr] = await Promise.all([
			child.exited,
			new Response(child.stdout).text(),
			new Response(child.stderr).text(),
		]);
		expect(stderr).toContain(scenario.setupError ? 'Fixture setup failed' : 'reference PBKDF2:');
		expect({ outcomes: scenario.outcomes, code, diagnostics: code === scenario.code ? '' : stderr })
			.toEqual({ outcomes: scenario.outcomes, code: scenario.code, diagnostics: '' });
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
}, 10000);
