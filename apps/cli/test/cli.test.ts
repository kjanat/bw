import { expect, test } from 'bun:test';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:http';
import { sealSession, withStore } from '#store';
import { encryptItem } from '@kjanat/vaultwarden';

const executable = new URL('../dist/main.js', import.meta.url).pathname;
async function run(dir: string, args: string[], environment: Record<string, string> = {}) {
	const child = Bun.spawn(['node', executable, ...args], {
		env: { PATH: process.env.PATH, VW_APPDATA_DIR: dir, ...environment },
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

test('quiet suppresses JSON, text, and command errors while preserving operations, help, and exit codes', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-quiet-'));
	try {
		for (
			const args of [['--quiet', 'status'], ['generate', '--quiet'], ['get', 'template', 'item', '--quiet'], [
				'send',
				'template',
				'text',
				'--quiet',
			]]
		) {
			expect(await run(dir, args)).toEqual({ code: 0, stdout: '', stderr: '' });
		}
		expect(await run(dir, ['config', 'server', 'https://example.com/vault', '--quiet'])).toEqual({
			code: 0,
			stdout: '',
			stderr: '',
		});
		expect((await run(dir, ['config', 'server'])).stdout.trim()).toBe('https://example.com/vault');
		expect(await run(dir, ['list', 'items', '--quiet'])).toEqual({ code: 1, stdout: '', stderr: '' });
		expect((await run(dir, ['list', 'items', '--quiet=false'])).stderr).toContain('Vault is locked');
		const parseError = await run(dir, ['generate', '--unknown-fixture-flag', '--quiet']);
		expect(parseError.code).not.toBe(0);
		expect(parseError.stderr).toContain('unknown-fixture-flag');
		expect(await run(dir, ['status'], { VW_QUIET: 'true' })).toEqual({ code: 0, stdout: '', stderr: '' });
		expect((await run(dir, ['status', '--quiet=false'], { VW_QUIET: 'true' })).stdout).toContain('unauthenticated');
		expect((await run(dir, ['--quiet', '--help'])).stdout).toContain('Vaultwarden-first');
		expect((await run(dir, ['--quiet', '--version'])).stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
		expect((await run(dir, ['encode', '--', '--quiet'])).stdout.trim()).toBe(Buffer.from('--quiet').toString('base64'));
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});
test('quiet suppresses exact secret bytes and raw exports without changing the encrypted cache', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-quiet-secrets-'));
	const key = Buffer.alloc(64, 17), id = 'abcdef01-0000-0000-0000-000000000001';
	try {
		let session = '';
		await withStore(dir, async (state, save) => {
			state.server = 'https://example.com';
			state.account = {
				email: 'synthetic@example.com',
				kdf: { type: 0, iterations: 10000 },
				encryptedUserKey: 'synthetic-wrapped-key',
				accessToken: 'synthetic-token',
				refreshToken: 'synthetic-refresh',
				expiresAt: Date.now() + 3600000,
			};
			state.vault = {
				profile: { id: 'synthetic-user' },
				folders: [],
				collections: [],
				ciphers: [{
					...encryptItem({ type: 1, name: 'Private', login: { password: '  {"private":true}  ' } }, key),
					id,
				}],
			};
			session = sealSession(state, key);
			await save();
		});
		const before = await withStore(dir, async state => JSON.stringify(state));
		expect((await run(dir, ['get', 'password', id, '--session', session])).stdout).toBe('  {"private":true}  ');
		expect((await run(dir, ['--pretty', 'get', 'password', id, '--session', session])).stdout).toBe(
			'  {"private":true}  ',
		);
		expect((await run(dir, ['export', '--format', 'json', '--raw', '--session', session, '--pretty'])).stdout).toBe(
			(await run(dir, ['export', '--format', 'json', '--raw', '--session', session])).stdout,
		);
		for (const args of [['get', 'password', id], ['export', '--format', 'json', '--raw']]) {
			expect(await run(dir, [...args, '--session', session, '--quiet'])).toEqual({ code: 0, stdout: '', stderr: '' });
		}
		expect(await withStore(dir, async state => JSON.stringify(state))).toBe(before);
	} finally {
		key.fill(0);
		await rm(dir, { recursive: true, force: true });
	}
});

test('pretty formats structured JSON across global and nested commands without changing raw values', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-pretty-'));
	try {
		const compact = await run(dir, ['get', 'template', 'item']);
		expect(compact.code).toBe(0);
		const value = JSON.parse(compact.stdout), expected = JSON.stringify(value, null, 2) + '\n';
		expect(compact.stdout).toBe(JSON.stringify(value) + '\n');
		for (const args of [['--pretty', 'get', 'template', 'item'], ['get', 'template', 'item', '--pretty']]) {
			expect(await run(dir, args)).toEqual({ code: 0, stdout: expected, stderr: '' });
		}
		expect((await run(dir, ['get', 'template', 'item'], { VW_PRETTY: 'true' })).stdout).toBe(expected);
		expect((await run(dir, ['get', 'template', 'item', '--pretty=false'], { VW_PRETTY: 'true' })).stdout).toBe(
			compact.stdout,
		);
		const nested = await run(dir, ['--pretty', 'send', 'template', 'text']);
		expect(nested.code).toBe(0);
		expect(nested.stdout).toBe(JSON.stringify(JSON.parse(nested.stdout), null, 2) + '\n');
		expect((await run(dir, ['get', 'template', 'item', '--json', '--pretty'])).stdout).toBe(expected);
		expect(await run(dir, ['--pretty', 'status', '--quiet'])).toEqual({ code: 0, stdout: '', stderr: '' });
		expect((await run(dir, ['encode', '--', '--pretty'])).stdout.trim()).toBe(
			Buffer.from('--pretty').toString('base64'),
		);
		expect((await run(dir, ['--help'])).stdout).toContain('--pretty');
		expect((await run(dir, ['get', '--help'])).stdout).toContain('--pretty');
		expect((await run(dir, [])).stdout).toContain('Vaultwarden-first');
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test('sync reads its last date offline, checks revisions, and forces full downloads without an unlock token', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-sync-'));
	const paths: string[] = [];
	let revision = 0, unauthorized = false, downloads = 0, downloadStarted = 0;
	const server = createServer((request, response) => {
		paths.push(request.url!);
		response.setHeader('Content-Type', 'application/json');
		if (request.url === '/identity/connect/token') {
			response.end(
				JSON.stringify({ access_token: 'renewed-synthetic-token', refresh_token: 'renewed', expires_in: 3600 }),
			);
		} else if (unauthorized) {
			unauthorized = false;
			response.writeHead(401).end('{}');
		} else if (request.url === '/api/accounts/revision-date') response.end(JSON.stringify(revision));
		else if (request.url === '/api/sync?excludeDomains=false') {
			downloads++;
			downloadStarted = Date.now();
			setTimeout(() => response.end(JSON.stringify({ profile: { id: 'synthetic-user' }, ciphers: [] })), 20);
		} else response.writeHead(404).end('{}');
	});
	await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
	const address = server.address();
	if (!address || typeof address === 'string') throw new Error('Missing fixture address.');
	try {
		expect((await run(dir, ['sync', '--last'])).code).toBe(1);
		await withStore(dir, async (state, save) => {
			state.server = `http://127.0.0.1:${address.port}`;
			state.account = {
				email: 'synthetic@example.com',
				kdf: { type: 0, iterations: 10000 },
				encryptedUserKey: 'synthetic-wrapped-key',
				accessToken: 'synthetic-token',
				refreshToken: 'synthetic-refresh',
				expiresAt: Date.now() + 3600000,
			};
			await save();
		});
		expect((await run(dir, ['sync', '--last'])).stdout).toBe('\n');
		expect(paths).toEqual([]);
		expect((await run(dir, ['sync'])).stdout.trim()).toBe('Syncing complete.');
		expect(downloads).toBe(1);
		const firstDate = (await run(dir, ['sync', '--last'])).stdout.trim();
		expect(Number.isFinite(Date.parse(firstDate))).toBe(true);
		expect(Date.parse(firstDate)).toBeLessThanOrEqual(downloadStarted);
		paths.length = 0;
		expect((await run(dir, ['sync'])).code).toBe(0);
		expect(paths).toEqual(['/api/accounts/revision-date']);
		expect(downloads).toBe(1);
		paths.length = 0;
		expect((await run(dir, ['sync', '-f'])).code).toBe(0);
		expect(paths).toEqual(['/api/sync?excludeDomains=false']);
		expect(downloads).toBe(2);
		paths.length = 0;
		const saved = await withStore(dir, async state => JSON.stringify(state));
		expect((await run(dir, ['sync', '--last', '--force'])).code).toBe(0);
		expect(paths).toEqual([]);
		expect(await withStore(dir, async state => JSON.stringify(state))).toBe(saved);
		revision = Date.now() + 60000;
		unauthorized = true;
		expect((await run(dir, ['sync'])).code).toBe(0);
		expect(paths).toEqual([
			'/api/accounts/revision-date',
			'/identity/connect/token',
			'/api/accounts/revision-date',
			'/api/sync?excludeDomains=false',
		]);
		expect(downloads).toBe(3);
		const beforeFailure = (await run(dir, ['sync', '--last'])).stdout;
		revision = NaN; // JSON null is an invalid revision, not permission to skip the download.
		expect((await run(dir, ['sync'])).code).toBe(1);
		expect((await run(dir, ['sync', '--last'])).stdout).toBe(beforeFailure);
		expect(downloads).toBe(3);
		revision = -1;
		expect((await run(dir, ['sync'])).code).toBe(1);
		expect((await run(dir, ['status'])).stdout).toContain('unauthenticated');
	} finally {
		await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
		await rm(dir, { recursive: true, force: true });
	}
});

test('organization device approval exposes the reference subcommands and fails explicitly without touching credentials', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-device-approval-'));
	try {
		const help = await run(dir, ['device-approval', '--help']);
		expect(help.code).toBe(0);
		for (const name of ['list', 'approve', 'deny', 'approve-all', 'deny-all']) {
			expect(help.stdout).toContain(name);
			const args = [
				'device-approval',
				name,
				...(['approve', 'deny'].includes(name) ? ['11111111-1111-1111-1111-111111111111'] : []),
				'--organizationid',
				'22222222-2222-2222-2222-222222222222',
				'--session',
				'synthetic-session',
			];
			const result = await run(dir, args);
			expect(result.code).toBe(1);
			expect(result.stderr).toContain('organization SSO trusted-device approval API');
			expect(result.stderr).toContain('Personal auth requests are a different protocol');
			expect(result.stderr).not.toContain('synthetic-session');
			expect(result.stderr).not.toContain('Log in first');
		}
		expect((await run(dir, ['device-approval', 'list'])).code).not.toBe(0);
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});
test('configured service overrides route CLI authentication and are cleared by a new base URL', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-config-'));
	const paths: string[] = [];
	const server = createServer((request, response) => {
		paths.push(request.url!);
		response.writeHead(401, { 'Content-Type': 'application/json' });
		response.end('{}');
	});
	await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
	const address = server.address();
	if (!address || typeof address === 'string') throw new Error('Missing fixture address.');
	const base = `http://127.0.0.1:${address.port}`;
	try {
		const config = await run(dir, [
			'config',
			'server',
			base,
			'--api',
			`${base}/custom-api`,
			'--identity',
			`${base}/custom-auth`,
			'--web-vault',
			`${base}/web`,
		]);
		expect(config.code).toBe(0);
		const login = () => run(dir, ['login', 'fixture@example.com', 'synthetic-password', '--nointeraction']);
		expect((await login()).code).toBe(1);
		expect(paths).toEqual(['/custom-auth/accounts/prelogin']);
		expect((await run(dir, ['config', 'server', base])).code).toBe(0);
		expect((await login()).code).toBe(1);
		expect(paths.at(-1)).toBe('/identity/accounts/prelogin');
		expect((await run(dir, ['config', 'server', base, '--identity', 'https://user:secret@example.com'])).code).toBe(1);
	} finally {
		server.closeAllConnections();
		await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
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
		expect(JSON.parse(formats.stdout)).toContain('nordpasscsv');
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test('Send templates are available before login, and malformed recipient links do not request an account session', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-send-cli-'));
	try {
		const text = await run(dir, ['send', 'template', 'text']);
		expect(text.code).toBe(0);
		expect(JSON.parse(text.stdout).type).toBe(0);
		const file = await run(dir, ['send', 'template', 'file']);
		expect(file.code).toBe(0);
		expect(JSON.parse(file.stdout).type).toBe(1);
		const invalid = await run(dir, ['receive', 'https://vault.example/#/send/bad/key']);
		expect(invalid.code).toBe(1);
		expect(invalid.stderr).toContain('fragment');
		expect(invalid.stderr).not.toContain('session');
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test('authentication checks ignore unused password files and do not prompt', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-auth-check-'));
	try {
		const login = await run(dir, [
			'login',
			'--check',
			'--nointeraction',
			'--passwordfile',
			join(dir, 'missing-secret.txt'),
		]);
		expect(login.code).toBe(1);
		expect(login.stderr).toContain('Not logged in.');
		const unlock = await run(dir, [
			'unlock',
			'--check',
			'--nointeraction',
			'--passwordfile',
			join(dir, 'missing-secret.txt'),
		]);
		expect(unlock.code).toBe(1);
		expect(unlock.stderr).toContain('Log in first.');
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test('schema-derived completions parse in all four shells and fish completes real command prefixes', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-completion-'));
	try {
		for (const shell of ['zsh', 'bash', 'fish', 'powershell']) {
			const generated = await run(dir, ['completion', '--shell', shell]);
			expect(generated.code).toBe(0);
			expect(generated.stdout).toContain('login');
			expect(generated.stdout).toContain('send');
			expect(generated.stdout).toContain('passwordfile');
			const path = join(dir, shell === 'powershell' ? 'completion.ps1' : `completion.${shell}`);
			await writeFile(path, generated.stdout);
			let args = [shell, '-n', path];
			if (shell === 'powershell') {
				const parser = join(dir, 'check.ps1');
				await writeFile(
					parser,
					'param([string]$Path)\n$tokens=$null; $errors=$null\n[System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors) | Out-Null\nif ($errors.Count) { $errors | Out-String | Write-Error; exit 1 }',
				);
				args = ['pwsh', '-NoProfile', '-NonInteractive', '-File', parser, '-Path', path];
			}
			const child = Bun.spawn(args, { stdout: 'pipe', stderr: 'pipe' });
			const [code, stderr] = await Promise.all([child.exited, new Response(child.stderr).text()]);
			if (code) throw new Error(`${shell} completion syntax failed: ${stderr}`);
			if (shell === 'fish') {
				const complete = Bun.spawn(['fish', '--no-config', '-c', 'source $argv[1]; complete -C "vw lo"', path], {
					stdout: 'pipe',
					stderr: 'pipe',
				});
				const output = await new Response(complete.stdout).text();
				expect(await complete.exited).toBe(0);
				expect(output).toContain('login');
				expect(output).toContain('logout');
			}
		}
		expect((await run(dir, ['completion'])).code).toBe(1);
		expect((await run(dir, ['completion', '--shell', 'unknown'])).code).not.toBe(0);
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});
