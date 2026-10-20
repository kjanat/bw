import { expect, test } from 'bun:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const executable = new URL('../dist/main.js', import.meta.url).pathname;
async function run(dir: string, args: string[]) {
	const child = Bun.spawn(['node', executable, ...args], {
		env: { PATH: process.env.PATH, VW_APPDATA_DIR: dir },
		stdout: 'pipe',
		stderr: 'pipe',
	});
	return {
		code: await child.exited,
		stdout: await new Response(child.stdout).text(),
		stderr: await new Response(child.stderr).text(),
	};
}
test('built Node CLI exposes DreamCLI help and validates commands', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-cli-'));
	try {
		const help = await run(dir, ['--help']);
		expect(help.code).toBe(0);
		expect(help.stdout).toContain('Vaultwarden-first');
		const config = await run(dir, [
			'config',
			'server',
			'https://example.com/vault/',
		]);
		expect(config.code).toBe(0);
		expect(config.stdout.trim()).toBe('https://example.com/vault');
		const status = await run(dir, ['status']);
		expect(JSON.parse(status.stdout).status).toBe('unauthenticated');
		expect((await run(dir, ['list', 'items'])).code).toBe(1);
		expect(
			(await run(dir, ['config', 'server', 'http://example.com'])).code,
		).toBe(1);
		expect((await run(dir, ['unknown'])).code).not.toBe(0);
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test('generation and import format discovery work before login in the built Node CLI', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-tools-'));
	try {
		const generated = await run(dir, ['generate', '--length', '32', '-u', '-l', '-n', '-s', '--minNumber', '4']);
		expect(generated.code).toBe(0);
		expect(generated.stdout.trim()).toHaveLength(32);
		expect(generated.stdout.trim().match(/[0-9]/g)!.length).toBeGreaterThanOrEqual(4);
		const phrase = await run(dir, ['generate', '-p', '--words', '5', '--separator', '/']);
		expect(phrase.code).toBe(0);
		expect(phrase.stdout.trim().split('/')).toHaveLength(5);
		const formats = await run(dir, ['import', '--formats']);
		expect(formats.code).toBe(0);
		expect(JSON.parse(formats.stdout)).toContain('bitwardenjson');
		expect(JSON.parse(formats.stdout)).toContain('bitwardenzip');
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});
