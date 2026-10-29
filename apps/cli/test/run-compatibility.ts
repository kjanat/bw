#!/usr/bin/env bun
import { randomUUID } from 'node:crypto';
import { appendFile, mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join } from 'node:path';
import { spawn, type ChildProcess } from 'node:child_process';
import { createServer } from 'node:net';
import { assertStableVersion, resolveCompatibilityTarget, type CompatibilityTargets } from '#test/compatibility-plan';
import { checkReferenceAuthentication } from '#test/reference-authentication';
import { runDirect } from '../../../tools/runtime.mjs';

export interface CompatibilityOptions {
	version?: string;
	image?: string;
	reference?: string;
	referenceVersion?: string;
	protocolOnly?: boolean;
	smtp?: boolean;
	sso?: boolean;
	testCase?: string;
	importFormat?: string;
	importShard?: string;
	skipImports?: boolean;
	listFiltersOnly?: boolean;
	policyRedactionOnly?: boolean;
	focusedImport?: boolean;
}

export async function runCompatibility(options: CompatibilityOptions = {}) {
	const {
		servers: compatibilityTargets,
		referenceIncompatibilities,
		mailpitImage,
	} = await Bun
		.file(
			new URL('./fixtures/compatibility-targets.json', import.meta.url),
		).json() as CompatibilityTargets & { mailpitImage: string };

	const version = options.version ?? '1.37.4';
	if (process.platform === 'win32') throw new Error('The managed compatibility runner requires POSIX process groups.');
	const { image } = resolveCompatibilityTarget({ servers: compatibilityTargets }, version, options.image);
	const reference = options.reference;
	let expectedReferenceVersion = options.referenceVersion;
	if (expectedReferenceVersion !== undefined) assertStableVersion(expectedReferenceVersion);
	const protocolOnly = options.protocolOnly ?? false;
	const smtpEnabled = options.smtp ?? false;
	const ssoEnabled = options.sso ?? false;
	if (ssoEnabled && process.platform !== 'linux') {
		throw new Error('The SSO fixture requires Linux.');
	}
	const compareReference = !protocolOnly && !smtpEnabled && !ssoEnabled;
	if (!/^axllent\/mailpit@sha256:[a-f0-9]{64}$/.test(mailpitImage)) {
		throw new Error('Mailpit must use a pinned digest.');
	}
	if (compareReference && (!reference || !isAbsolute(reference) || !(await stat(reference)).isFile())) {
		throw new Error(
			'--reference must name an absolute path to the independent bw executable; use --protocol-only to run without it.',
		);
	}
	if (!Bun.which('envctl')) throw new Error('Compatibility runner requires envctl for Docker output redaction.');
	for (const command of ['docker', 'node', 'ssh-keygen']) {
		if (!Bun.which(command)) throw new Error(`Compatibility runner requires ${command}.`);
	}
	const directory = await mkdtemp(join(tmpdir(), 'vw-compat-run-'));
	const name = `vw-compat-${randomUUID()}`;
	const mailName = `${name}-mail`, network = `${name}-network`;
	let mailApi: string | undefined;
	let mailSmtpPort: number | undefined;
	let oidc: ReturnType<typeof Bun.spawn> | undefined;
	let oidcUrl: string | undefined, ssoServer: string | undefined;
	const oidcControl = randomUUID();
	let interrupted = false;
	const cancellation = new AbortController();
	const running = new Set<ChildProcess>();
	const stopTests = () => {
		for (const child of running) {
			if (child.pid) {
				try {
					process.kill(-child.pid, 'SIGTERM');
				} catch { /* The owned process group has already exited. */ }
			}
		}
	};
	const interrupt = () => {
		interrupted = true;
		cancellation.abort();
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
		const [code, redacted, redactorCode, redactorError] = await Promise.all([
			child.exited,
			stdout,
			safe.exited,
			stderr,
		]);
		if (redactorCode !== 0) {
			throw new Error(`envctl redaction failed (exit ${redactorCode}); Docker output was withheld. ${redactorError}`);
		}
		return { code, output: redacted };
	}
	let exitCode: number | undefined;
	const knownIncompatible = Symbol('known reference incompatibility');
	try {
		if (compareReference) {
			const referenceVersion = Bun.spawn([reference!, '--version'], {
				env: { PATH: process.env.PATH, BITWARDENCLI_APPDATA_DIR: directory },
				stdout: 'pipe',
				stderr: 'pipe',
				timeout: 30000,
			});
			const [code, stdout] = await Promise.all([
				referenceVersion.exited,
				new Response(referenceVersion.stdout).text(),
				new Response(referenceVersion.stderr).text(),
			]);
			if (code !== 0) throw new Error('Could not read the reference CLI version.');
			const actual = stdout.trim();
			assertStableVersion(actual);
			if (expectedReferenceVersion !== undefined && actual !== expectedReferenceVersion) {
				throw new Error(`Reference executable must be bw ${expectedReferenceVersion}; got ${actual}.`);
			}
			expectedReferenceVersion = actual;
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
				? 'SSO suite: synthetic OIDC provider and CLI login.'
				: smtpEnabled
				? 'SMTP suite: library and CLI login; no reference CLI required.'
				: compareReference
				? `Reference: ${reference} (${expectedReferenceVersion})`
				: 'Protocol-only suite: CLI against Vaultwarden; independent bw comparison disabled.',
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
				'-p',
				'127.0.0.1::1025',
				mailpitImage,
			]);
			if (mail.code !== 0) throw new Error(`Could not start SMTP receiver: ${mail.output}`);
			const port = await docker(['port', mailName, '8025/tcp']);
			if (port.code !== 0 || !/^127\.0\.0\.1:\d+$/.test(port.output.trim())) {
				throw new Error('Could not discover Mailpit loopback port.');
			}
			mailApi = `http://${port.output.trim()}`;
			if (ssoEnabled) {
				const smtp = await docker(['port', mailName, '1025/tcp']);
				const address = smtp.output.trim();
				const match = /^127\.0\.0\.1:(\d+)$/.exec(address);
				if (smtp.code !== 0 || !match) throw new Error('Could not discover Mailpit SMTP loopback port.');
				mailSmtpPort = Number(match[1]);
			}
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
					...(!ssoEnabled ? ['--network', network] : []),
					'-e',
					`SMTP_HOST=${ssoEnabled ? '127.0.0.1' : 'mail'}`,
					'-e',
					`SMTP_PORT=${ssoEnabled ? mailSmtpPort : 1025}`,
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
		const actualVersion = await fetch(`${server}/api/version`, { signal: AbortSignal.timeout(5000) });
		if (!actualVersion.ok || await actualVersion.json() !== version) {
			throw new Error(`Disposable image does not report the planned Vaultwarden version ${version}.`);
		}
		if (compareReference) {
			const expected = referenceIncompatibilities.find(entry =>
				entry.server === version
				&& entry.referenceCliVersion === expectedReferenceVersion
			);
			const result = await checkReferenceAuthentication({
				server,
				reference: reference!,
				directory,
				expected,
				signal: cancellation.signal,
			});
			const summary = `Vaultwarden ${version} / bw ${expectedReferenceVersion}: ${
				result === 'compatible'
					? 'PBKDF2 and Argon2id login passed; running comparisons.'
					: `Known incompatibility reproduced for both KDFs (${
						expected!.error
					}); reference comparisons unavailable. Server protocol checks run separately.`
			}`;
			console.log(summary);
			if (process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY, `${summary}\n`);
			if (result === 'known-incompatible') throw knownIncompatible;
		}
		const cwd = new URL('..', import.meta.url).pathname;
		const env = {
			PATH: process.env.PATH,
			VOLTA_HOME: process.env.VOLTA_HOME,
			VW_TEST_SERVER: server,
			VW_TEST_VERSION: version,
			VW_TEST_BW: compareReference ? reference : undefined,
			VW_TEST_BW_VERSION: compareReference ? expectedReferenceVersion : undefined,
			VW_TEST_IMPORT_FORMAT: options.importFormat,
			VW_TEST_IMPORT_SHARD: undefined as string | undefined,
			VW_TEST_SKIP_IMPORTS: undefined as string | undefined,
			VW_TEST_LIST_FILTERS_ONLY: options.listFiltersOnly ? '1' : undefined,
			VW_TEST_POLICY_REDACTION_ONLY: options.policyRedactionOnly ? '1' : undefined,
			VW_TEST_FOCUSED_IMPORT: options.focusedImport ? '1' : undefined,
			VW_TEST_MAILPIT: mailApi,
			VW_TEST_OIDC: oidcUrl,
			VW_OIDC_CONTROL: ssoEnabled ? oidcControl : undefined,
		};
		const testArgs = (files: string[]) => {
			const args = ['bun', 'test', ...files];
			if (options.testCase) args.push('--test-name-pattern', options.testCase);
			return args;
		};
		const shardImportMatrix = compareReference && !options.focusedImport && !ssoEnabled
			&& !smtpEnabled
			&& !options.testCase && !options.importFormat && !options.importShard
			&& !options.skipImports;
		const runs: { files: string[]; shard?: string; skipImports?: boolean }[] = options.importShard
			? [{ files: ['test/challenge-live.test.ts'], shard: options.importShard }]
			: options.skipImports
			? [{ files: ['test/challenge-live.test.ts'], skipImports: true }]
			: shardImportMatrix
			? [
				{ files: ['test/live.test.ts', 'test/backup-integrity-live.test.ts'] },
				...Array.from({ length: 8 }, (_, index) => ({ files: ['test/challenge-live.test.ts'], shard: `${index}/8` })),
				{ files: ['test/challenge-live.test.ts'], skipImports: true },
			]
			: [{
				files: options.focusedImport
					? ['test/import-live.test.ts']
					: ssoEnabled
					? ['test/sso-live.test.ts']
					: smtpEnabled
					? ['test/email-live.test.ts']
					: ['test/live.test.ts', 'test/challenge-live.test.ts', 'test/backup-integrity-live.test.ts'],
			}];
		const runOne = async (run: { files: string[]; shard?: string; skipImports?: boolean }): Promise<number> => {
			if (runs.length > 1) {
				console.log(
					run.shard ? `Compatibility import shard ${run.shard}` : run.skipImports
						? 'Compatibility REST and authentication checks'
						: 'Compatibility KDF and vault checks',
				);
			}
			const args = testArgs(run.files);
			const childEnv = {
				...env,
				VW_TEST_IMPORT_SHARD: run.shard ?? options.importShard,
				VW_TEST_SKIP_IMPORTS: run.skipImports || options.skipImports ? '1' : undefined,
			};
			const child = spawn(args[0]!, args.slice(1), { detached: true, cwd, env: childEnv, stdio: 'inherit' });
			running.add(child);
			return await new Promise<number>(resolve => {
				child.once('error', error => {
					console.error(`Could not start compatibility test process: ${error.message}`);
					resolve(1);
				});
				child.once('exit', code => resolve(code ?? 130));
			}).finally(() => {
				running.delete(child);
			});
		};
		const reportFailure = async () => {
			if (!interrupted) {
				const logs = await docker(['logs', '--tail', '80', name]);
				console.error(logs.output);
			}
		};
		if (shardImportMatrix) {
			exitCode = await runOne(runs[0]!);
			if (exitCode === 0 && !interrupted) {
				let nextShard = 1;
				let failed = false;
				const workers = Array.from({ length: Math.min(4, runs.length - 2) }, async () => {
					while (!failed && !interrupted && nextShard < runs.length - 1) {
						const run = runs[nextShard++]!;
						const code = await runOne(run);
						if (code !== 0 && !failed) {
							failed = true;
							exitCode = code;
							stopTests();
						}
					}
				});
				await Promise.all(workers);
				if (!failed && !interrupted) exitCode = await runOne(runs.at(-1)!);
			}
			if (exitCode !== 0) await reportFailure();
		} else {
			for (const run of runs) {
				exitCode = await runOne(run);
				if (exitCode !== 0) {
					await reportFailure();
					break;
				}
			}
		}
	} catch (error) {
		if (error !== knownIncompatible) throw error;
		exitCode = 0;
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
	return interrupted ? 130 : exitCode ?? 1;
}

if (import.meta.main) await runDirect(['compat', 'run'], import.meta.url, { runCompatibility });
