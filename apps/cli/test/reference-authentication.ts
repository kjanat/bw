import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { deriveMasterKey, encrypt, masterPasswordHash, stretchKey, type Kdf } from '@kjanat/vaultwarden';
import { registrationVerificationToken } from '#test/fixtures/registration';
import { writeTestCertificate } from '#test/fixtures/tls';
import type { ReferenceIncompatibility } from '#test/compatibility-plan';

export type AuthenticationOutcome = 'authenticated' | 'invalid-prelogin-kdf' | 'failed';

export function classifyAuthentication(
	outcomes: readonly AuthenticationOutcome[],
	expected?: ReferenceIncompatibility,
): 'compatible' | 'known-incompatible' {
	if (outcomes.length !== 2) throw new Error('Both KDF authentication results are required.');
	if (outcomes.every(result => result === 'authenticated')) {
		if (expected) throw new Error('Reference login now works; remove the stale incompatibility entry.');
		return 'compatible';
	}
	if (expected && outcomes.every(result => result === expected.error)) return 'known-incompatible';
	throw new Error(`Unexpected reference authentication failure: PBKDF2=${outcomes[0]}, Argon2id=${outcomes[1]}.`);
}

/** Check both KDFs against a real disposable server before any comparison can be omitted. */
export async function checkReferenceAuthentication(options: {
	server: string;
	reference: string;
	directory: string;
	expected?: ReferenceIncompatibility;
	signal: AbortSignal;
}) {
	const { server, reference, directory, signal } = options;
	const address = new URL(server);
	if (address.protocol !== 'http:' || address.hostname !== '127.0.0.1') {
		throw new Error('Reference authentication requires a disposable HTTP loopback server.');
	}
	const ca = join(directory, 'reference-ca.pem'), keyPath = join(directory, 'reference-key.pem');
	await writeTestCertificate(ca, keyPath);
	const proxy = Bun.serve({
		hostname: '127.0.0.1',
		port: 0,
		tls: { cert: Bun.file(ca), key: Bun.file(keyPath) },
		async fetch(request) {
			const target = new URL(request.url);
			return fetch(`${server}${target.pathname}${target.search}`, {
				method: request.method,
				headers: { ...Object.fromEntries(request.headers), 'X-Forwarded-Proto': 'https' },
				body: ['GET', 'HEAD'].includes(request.method) ? undefined : await request.arrayBuffer(),
				redirect: 'manual',
				signal,
			});
		},
	});
	const outcomes: AuthenticationOutcome[] = [];
	try {
		for (
			const kdf of [
				{ type: 0, iterations: 600000 },
				{ type: 1, iterations: 3, memory: 64, parallelism: 2 },
			] as Kdf[]
		) {
			signal.throwIfAborted();
			const email = `reference-probe-${randomUUID()}@example.com`;
			const password = `Synthetic-probe-${randomUUID()}!`;
			const userKey = randomBytes(64);
			const master = await deriveMasterKey(password, email, kdf);
			const hash = await masterPasswordHash(master, password), stretched = stretchKey(master);
			const key = encrypt(userKey, stretched);
			master.fill(0);
			stretched.fill(0);
			const rsa = generateKeyPairSync('rsa', {
				modulusLength: 2048,
				publicKeyEncoding: { type: 'spki', format: 'der' },
				privateKeyEncoding: { type: 'pkcs8', format: 'der' },
			});
			const post = (path: string, data: unknown) =>
				fetch(`${server}${path}`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify(data),
					signal: AbortSignal.any([signal, AbortSignal.timeout(10000)]),
				});
			const verify = await post('/identity/accounts/register/send-verification-email', {
				email,
				name: 'Reference probe',
			});
			if (!verify.ok && verify.status !== 404) {
				throw new Error(`Reference fixture verification failed: HTTP ${verify.status}.`);
			}
			const registration = {
				email,
				name: 'Reference probe',
				masterPasswordHash: hash,
				key,
				keys: { publicKey: rsa.publicKey.toString('base64'), encryptedPrivateKey: encrypt(rsa.privateKey, userKey) },
				kdf: kdf.type,
				kdfIterations: kdf.iterations,
				kdfMemory: kdf.type === 1 ? kdf.memory : null,
				kdfParallelism: kdf.type === 1 ? kdf.parallelism : null,
				emailVerificationToken: verify.ok ? await registrationVerificationToken(verify) : undefined,
			};
			rsa.privateKey.fill(0);
			userKey.fill(0);
			const registered = await post(
				verify.ok ? '/identity/accounts/register/finish' : '/identity/accounts/register',
				registration,
			);
			if (!registered.ok) throw new Error(`Reference fixture registration failed: HTTP ${registered.status}.`);
			// Verify the synthetic account independently, so a fixture error cannot count as a known CLI failure.
			const token = await fetch(`${server}/identity/connect/token`, {
				method: 'POST',
				signal: AbortSignal.any([signal, AbortSignal.timeout(10000)]),
				body: new URLSearchParams({
					grant_type: 'password',
					client_id: 'cli',
					scope: 'api offline_access',
					username: email,
					password: hash,
					deviceIdentifier: randomUUID(),
					deviceName: 'Reference probe',
					deviceType: '8',
				}),
			});
			if (!token.ok) throw new Error(`Reference fixture authentication failed: HTTP ${token.status}.`);
			await token.body?.cancel();
			const profile = join(directory, `reference-probe-${kdf.type}`);
			await mkdir(profile);
			async function run(args: string[], session?: string) {
				signal.throwIfAborted();
				const child = Bun.spawn([reference, ...args], {
					env: {
						PATH: process.env.PATH,
						BITWARDENCLI_APPDATA_DIR: profile,
						BW_PASSWORD: password,
						NODE_EXTRA_CA_CERTS: ca,
						...(session ? { BW_SESSION: session } : {}),
					},
					stdin: 'ignore',
					stdout: 'pipe',
					stderr: 'pipe',
					timeout: 90000,
				});
				const abort = () => {
					child.kill('SIGKILL');
				};
				signal.addEventListener('abort', abort, { once: true });
				try {
					const [code, stdout, stderr] = await Promise.all([
						child.exited,
						new Response(child.stdout).text(),
						new Response(child.stderr).text(),
					]);
					signal.throwIfAborted();
					return { code, stdout, stderr };
				} finally {
					signal.removeEventListener('abort', abort);
				}
			}
			if ((await run(['config', 'server', `https://127.0.0.1:${proxy.port}`])).code !== 0) {
				throw new Error('Could not configure the reference CLI server.');
			}
			const login = await run(['login', email, '--passwordenv', 'BW_PASSWORD', '--raw', '--nointeraction']);
			if (login.code !== 0) {
				outcomes.push(
					login.code === 1 && login.stderr.includes('KDF config response does not contain a valid KDF type')
						? 'invalid-prelogin-kdf'
						: 'failed',
				);
			} else {
				const status = await run(['status'], login.stdout.trim());
				const unlocked = status.code === 0 && JSON.parse(status.stdout).status === 'unlocked';
				outcomes.push(unlocked ? 'authenticated' : 'failed');
			}
		}
		return classifyAuthentication(outcomes, options.expected);
	} finally {
		await proxy.stop(true);
	}
}
