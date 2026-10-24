import { randomUUID } from 'node:crypto';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join } from 'node:path';
import { spawn, type ChildProcess } from 'node:child_process';
import { createServer } from 'node:net';

const {
	servers: compatibilityTargets,
	referenceCliVersion,
	referenceUnsupportedServers,
	mailpitImage,
} = await Bun
	.file(
		new URL('./fixtures/compatibility-targets.json', import.meta.url),
	).json() as {
		servers: Record<string, string>;
		referenceCliVersion: string;
		referenceUnsupportedServers: string[];
		mailpitImage: string;
	};

const version = process.env.VW_TEST_VERSION ?? '1.37.4';
if (process.platform === 'win32') throw new Error('The managed compatibility runner requires POSIX process groups.');
if (!Object.hasOwn(compatibilityTargets, version)) throw new Error('Unknown VW_TEST_VERSION. Use 1.36.0 or 1.37.4.');
const image = compatibilityTargets[version]!;
if (!/^vaultwarden\/server@sha256:[a-f0-9]{64}$/.test(image)) {
	throw new Error('Compatibility image must use a pinned digest.');
}
const reference = process.env.VW_TEST_BW;
const protocolOnly = process.env.VW_TEST_PROTOCOL_ONLY === '1';
const smtpEnabled = process.env.VW_TEST_SMTP === '1';
const ssoEnabled = process.env.VW_TEST_SSO === '1';
if (ssoEnabled && (smtpEnabled || process.platform !== 'linux')) {
	throw new Error('The SSO fixture requires Linux and runs separately from SMTP mode.');
}
if (process.env.VW_TEST_PROTOCOL_ONLY && !protocolOnly) {
	throw new Error('VW_TEST_PROTOCOL_ONLY must be 1 when enabled.');
}
const compareReference = !protocolOnly && !smtpEnabled && !ssoEnabled && !referenceUnsupportedServers.includes(version);
if (process.env.VW_TEST_SMTP && !smtpEnabled) throw new Error('VW_TEST_SMTP must be 1 when enabled.');
if (!/^axllent\/mailpit@sha256:[a-f0-9]{64}$/.test(mailpitImage)) throw new Error('Mailpit must use a pinned digest.');
if (compareReference && (!reference || !isAbsolute(reference) || !(await stat(reference)).isFile())) {
	throw new Error('VW_TEST_BW must name an absolute path to the independent bw 2026.10.0 executable.');
}
if (!Bun.which('envctl')) throw new Error('Compatibility runner requires envctl for Docker output redaction.');
for (const command of ['docker', 'node', 'ssh-keygen']) {
	if (!Bun.which(command)) throw new Error(`Compatibility runner requires ${command}.`);
}
const directory = await mkdtemp(join(tmpdir(), 'vw-compat-run-'));
const name = `vw-compat-${randomUUID()}`;
const mailName = `${name}-mail`, network = `${name}-network`;
let mailApi: string | undefined;
let oidc: ReturnType<typeof Bun.spawn> | undefined;
let oidcUrl: string | undefined, ssoServer: string | undefined;
const oidcControl = randomUUID();
let interrupted = false;
let running: ChildProcess | undefined;
const stopTests = () => {
	if (running?.pid) {
		try {
			process.kill(-running.pid, 'SIGTERM');
		} catch { /* The owned process group has already exited. */ }
	}
};
const interrupt = () => {
	interrupted = true;
	stopTests();
};
process.on('SIGINT', interrupt);
process.on('SIGTERM', interrupt);

/** Docker output reaches the caller only after envctl; neither raw stream is displayed or saved. */
async function docker(args: string[]): Promise<{ code: number; output: string }> {
	const child = Bun.spawn(['docker', ...args], { stdout: 'pipe', stderr: 'pipe' });
	const safe = Bun.spawn(['envctl', 'redact'], { stdin: 'pipe', stdout: 'pipe', stderr: 'pipe' });
	const stdout = new Response(safe.stdout).text(), stderr = new Response(safe.stderr).text();
	await Promise.all([
		child.stdout.pipeTo(
			new WritableStream({
				write(chunk) {
					safe.stdin.write(chunk);
				},
			}),
		),
		child.stderr.pipeTo(
			new WritableStream({
				write(chunk) {
					safe.stdin.write(chunk);
				},
			}),
		),
	]);
	safe.stdin.end();
	const [code, redacted, redactorCode, redactorError] = await Promise.all([child.exited, stdout, safe.exited, stderr]);
	if (redactorCode !== 0) {
		throw new Error(`envctl redaction failed (exit ${redactorCode}); Docker output was withheld. ${redactorError}`);
	}
	return { code, output: redacted };
}
let exitCode: number | undefined;
try {
	if (compareReference) {
		const referenceVersion = Bun.spawn([reference!, '--version'], {
			env: { PATH: process.env.PATH, BITWARDENCLI_APPDATA_DIR: directory },
			stdout: 'pipe',
			stderr: 'pipe',
		});
		const [code, stdout] = await Promise.all([
			referenceVersion.exited,
			new Response(referenceVersion.stdout).text(),
			new Response(referenceVersion.stderr).text(),
		]);
		if (code !== 0 || stdout.trim() !== referenceCliVersion) {
			throw new Error(`Reference executable must be bw ${referenceCliVersion}.`);
		}
	}
	const node = Bun.spawn(['node', '--version'], { env: { PATH: process.env.PATH }, stdout: 'pipe', stderr: 'pipe' });
	const [nodeCode, nodeVersion] = await Promise.all([
		node.exited,
		new Response(node.stdout).text(),
		new Response(node.stderr).text(),
	]);
	if (nodeCode !== 0 || !/^v\d+\.\d+\.\d+$/.test(nodeVersion.trim())) {
		throw new Error('Could not identify Node executable.');
	}
	console.log(`Vaultwarden ${version}: ${image}`);
	console.log(`Node ${nodeVersion.trim()}; Bun ${Bun.version}`);
	console.log(
		ssoEnabled
			? 'SSO suite: synthetic OIDC provider and compiled CLI login.'
			: smtpEnabled
			? 'SMTP suite: library and compiled CLI login; no reference CLI required.'
			: compareReference
			? `Reference: ${reference} (${referenceCliVersion})`
			: protocolOnly
			? 'Protocol-only suite: compiled CLI against Vaultwarden; independent bw comparison disabled.'
			: `Reference comparison unavailable: bw ${referenceCliVersion} cannot parse Vaultwarden ${version}'s prelogin response. Running our protocol checks.`,
	);
	if (smtpEnabled) {
		const created = await docker(['network', 'create', network]);
		if (created.code !== 0) throw new Error(`Could not create isolated SMTP network: ${created.output}`);
		const mail = await docker([
			'run',
			'-d',
			'--name',
			mailName,
			'--network',
			network,
			'--network-alias',
			'mail',
			'-p',
			'127.0.0.1::8025',
			mailpitImage,
		]);
		if (mail.code !== 0) throw new Error(`Could not start SMTP receiver: ${mail.output}`);
		const port = await docker(['port', mailName, '8025/tcp']);
		if (port.code !== 0 || !/^127\.0\.0\.1:\d+$/.test(port.output.trim())) {
			throw new Error('Could not discover Mailpit loopback port.');
		}
		mailApi = `http://${port.output.trim()}`;
		console.log(`SMTP receiver: ${mailName}; capture-only, with no relay configured.`);
	}
	if (ssoEnabled) {
		oidc = Bun.spawn(['bun', new URL('./fixtures/oidc-provider.ts', import.meta.url).pathname], {
			env: { PATH: process.env.PATH, VW_OIDC_CONTROL: oidcControl },
			stdout: 'pipe',
			stderr: 'inherit',
		});
		const reader = (oidc.stdout as ReadableStream<Uint8Array>).getReader();
		const first = await reader.read();
		oidcUrl = new TextDecoder().decode(first.value).trim();
		reader.releaseLock();
		if (!/^http:\/\/127\.0\.0\.1:\d+$/.test(oidcUrl)) throw new Error('OIDC fixture did not start.');
		const reservation = createServer();
		await new Promise<void>(resolve => reservation.listen(0, '127.0.0.1', resolve));
		const address = reservation.address();
		if (!address || typeof address === 'string') throw new Error('Could not reserve SSO server port.');
		ssoServer = `http://127.0.0.1:${address.port}`;
		await new Promise<void>(resolve => reservation.close(() => resolve()));
	}
	const started = await docker([
		'run',
		'-d',
		'--name',
		name,
		...(ssoEnabled
			? [
				'--network',
				'host',
				'-e',
				'ROCKET_ADDRESS=127.0.0.1',
				'-e',
				`ROCKET_PORT=${new URL(ssoServer!).port}`,
				'-e',
				`DOMAIN=${ssoServer}`,
				'-e',
				'SSO_ENABLED=true',
				'-e',
				'SSO_ONLY=true',
				'-e',
				'SSO_CLIENT_ID=fixture-client',
				'-e',
				'SSO_CLIENT_SECRET=synthetic-oidc-secret',
				'-e',
				`SSO_AUTHORITY=${oidcUrl}`,
			]
			: ['-p', '127.0.0.1::80']),
		'-e',
		'I_REALLY_WANT_VOLATILE_STORAGE=true',
		'-e',
		'SIGNUPS_ALLOWED=true',
		'-e',
		'SIGNUPS_VERIFY=false',
		'-e',
		'LOGIN_RATELIMIT_MAX_BURST=10000',
		'-e',
		'UNAUTHENTICATED_RATELIMIT_MAX_BURST=10000',
		...(smtpEnabled
			? [
				'--network',
				network,
				'-e',
				'SMTP_HOST=mail',
				'-e',
				'SMTP_PORT=1025',
				'-e',
				'SMTP_SECURITY=off',
				'-e',
				'SMTP_FROM=no-reply@example.com',
			]
			: []),
		image,
	]);
	if (started.code !== 0) throw new Error(`Could not start fixture server: ${started.output}`);
	console.log(`Fixture container: ${name}`);
	let server = ssoServer;
	if (!server) {
		const port = await docker(['port', name, '80/tcp']);
		const address = port.output.trim();
		if (port.code !== 0 || !/^127\.0\.0\.1:\d+$/.test(address)) {
			throw new Error('Could not discover disposable loopback port.');
		}
		server = `http://${address}`;
	}
	const deadline = Date.now() + 60000;
	let ready = false;
	while (Date.now() < deadline && !interrupted) {
		try {
			const response = await fetch(`${server}/alive`, { signal: AbortSignal.timeout(1000) });
			if (response.ok) {
				ready = true;
				break;
			}
		} catch { /* The known container is still starting. */ }
		await Bun.sleep(200);
	}
	if (!ready) throw new Error('Disposable Vaultwarden did not become healthy.');
	if (interrupted) throw new Error('Compatibility run interrupted.');
	const cwd = new URL('..', import.meta.url).pathname;
	const env = {
		PATH: process.env.PATH,
		VW_TEST_SERVER: server,
		VW_TEST_BW: compareReference ? reference : undefined,
		VW_TEST_IMPORT_FORMAT: process.env.VW_TEST_IMPORT_FORMAT,
		VW_TEST_IMPORT_SHARD: undefined as string | undefined,
		VW_TEST_SKIP_IMPORTS: undefined as string | undefined,
		VW_TEST_FOCUSED_IMPORT: process.env.VW_TEST_FOCUSED_IMPORT,
		VW_TEST_MAILPIT: mailApi,
		VW_TEST_OIDC: oidcUrl,
		VW_OIDC_CONTROL: ssoEnabled ? oidcControl : undefined,
	};
	const testArgs = (files: string[], overrides: { shard?: string; skipImports?: boolean } = {}) => {
		const args = ['bun', 'test', ...files];
		if (process.env.VW_TEST_CASE) args.push('--test-name-pattern', process.env.VW_TEST_CASE);
		env.VW_TEST_IMPORT_SHARD = overrides.shard ?? process.env.VW_TEST_IMPORT_SHARD;
		env.VW_TEST_SKIP_IMPORTS = overrides.skipImports ? '1' : process.env.VW_TEST_SKIP_IMPORTS;
		return args;
	};
	const shardImportMatrix = compareReference && !process.env.VW_TEST_FOCUSED_IMPORT && !ssoEnabled && !smtpEnabled
		&& !process.env.VW_TEST_CASE && !process.env.VW_TEST_IMPORT_FORMAT && !process.env.VW_TEST_IMPORT_SHARD
		&& !process.env.VW_TEST_SKIP_IMPORTS;
	const runs: { files: string[]; shard?: string; skipImports?: boolean }[] = process.env.VW_TEST_IMPORT_SHARD
		? [{ files: ['test/challenge-live.test.ts'], shard: process.env.VW_TEST_IMPORT_SHARD }]
		: process.env.VW_TEST_SKIP_IMPORTS
		? [{ files: ['test/challenge-live.test.ts'], skipImports: true }]
		: shardImportMatrix
		? [
			{ files: ['test/live.test.ts'] },
			...Array.from({ length: 8 }, (_, index) => ({ files: ['test/challenge-live.test.ts'], shard: `${index}/8` })),
			{ files: ['test/challenge-live.test.ts'], skipImports: true },
		]
		: [{
			files: process.env.VW_TEST_FOCUSED_IMPORT === '1'
				? ['test/import-live.test.ts']
				: ssoEnabled
				? ['test/sso-live.test.ts']
				: smtpEnabled
				? ['test/email-live.test.ts']
				: ['test/live.test.ts', 'test/challenge-live.test.ts'],
		}];
	for (const run of runs) {
		if (runs.length > 1) {
			console.log(
				run.shard ? `Compatibility import shard ${run.shard}` : run.skipImports
					? 'Compatibility REST and authentication checks'
					: 'Compatibility KDF and vault checks',
			);
		}
		const args = testArgs(run.files, { shard: run.shard, skipImports: run.skipImports });
		running = spawn(args[0]!, args.slice(1), { detached: true, cwd, env, stdio: 'inherit' });
		exitCode = await new Promise<number>((resolve, reject) => {
			running!.once('error', reject);
			running!.once('exit', code => resolve(code ?? 130));
		});
		running = undefined;
		if (exitCode !== 0) {
			if (!interrupted) {
				const logs = await docker(['logs', '--tail', '80', name]);
				console.error(logs.output);
			}
			break;
		}
	}
} finally {
	stopTests();
	if (oidc) {
		oidc.kill('SIGTERM');
		await oidc.exited;
	}
	const removed = await docker(['rm', '-f', name]);
	if (removed.code !== 0 && !removed.output.includes('No such container')) {
		exitCode = 1;
		console.error(`Fixture cleanup failed: ${removed.output}`);
	} else console.log(`Removed fixture container: ${name}`);
	if (smtpEnabled) {
		for (const args of [['rm', '-f', mailName], ['network', 'rm', network]]) {
			const result = await docker(args);
			if (result.code !== 0 && !/No such (container|network)/.test(result.output)) {
				exitCode = 1;
				console.error(`SMTP fixture cleanup failed: ${result.output}`);
			}
		}
	}
	await rm(directory, { recursive: true, force: true });
	process.off('SIGINT', interrupt);
	process.off('SIGTERM', interrupt);
}
process.exitCode = interrupted ? 130 : exitCode ?? 1;
