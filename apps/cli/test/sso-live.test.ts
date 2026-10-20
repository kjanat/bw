import { test, expect } from 'bun:test';
import { randomUUID, randomBytes, generateKeyPairSync } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
	ApiError,
	VaultwardenClient,
	VaultService,
	deriveMasterKey,
	masterPasswordHash,
	stretchKey,
	encrypt,
	createSsoAuthorization,
	ssoCredentialsFromCallback,
	loginWithSso,
	unlockAccount,
	refreshAccount,
	object,
	text,
	field,
	totp,
} from '@kjanat/vaultwarden';

const server = process.env.VW_TEST_SERVER, provider = process.env.VW_TEST_OIDC, control = process.env.VW_OIDC_CONTROL;
const live = server && provider && control ? test : test.skip;
for (const kdf of [{ type: 0, iterations: 600000 }, { type: 1, iterations: 3, memory: 64, parallelism: 2 }] as const) {
	live(`real Vaultwarden: SSO OIDC (${kdf.type === 0 ? 'PBKDF2' : 'Argon2id'})`, async () => {
		for (const address of [server!, provider!]) {
			const url = new URL(address);
			if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1') {
				throw new Error('SSO fixtures require disposable loopback services.');
			}
		}
		const email = `sso-${randomUUID()}@example.com`,
			password = 'Synthetic-SSO-master-password-123!',
			key = randomBytes(64);
		const master = await deriveMasterKey(password, email, kdf),
			hash = await masterPasswordHash(master, password),
			stretched = stretchKey(master),
			wrapped = encrypt(key, stretched);
		master.fill(0);
		stretched.fill(0);
		const directory = await mkdtemp(join(tmpdir(), 'vw-live-sso-'));
		async function browser(address: string): Promise<string> {
			const start = await fetch(address, { redirect: 'manual' });
			if (![302, 307].includes(start.status)) {
				throw new Error('SSO authorization did not redirect to the fixture provider.');
			}
			const cookies = start.headers.getSetCookie().map(v => v.split(';')[0]).join('; ');
			const location = start.headers.get('location')!;
			if (new URL(location).origin !== provider) throw new Error('Unexpected SSO provider redirect.');
			const signedIn = await fetch(location, { redirect: 'manual' });
			expect(signedIn.status).toBe(302);
			const callback = signedIn.headers.get('location')!;
			if (new URL(callback).origin !== server) throw new Error('Unexpected provider callback.');
			const completed = await fetch(callback, { headers: { Cookie: cookies }, redirect: 'manual' });
			if (![302, 307].includes(completed.status)) throw new Error('Vaultwarden rejected the provider callback.');
			return completed.headers.get('location')!;
		}
		async function run(args: string[]) {
			const child = Bun.spawn(['node', new URL('../dist/main.js', import.meta.url).pathname, ...args], {
				env: { PATH: process.env.PATH, VW_APPDATA_DIR: directory, VW_PASSWORD: password },
				stdin: 'ignore',
				stdout: 'pipe',
				stderr: 'pipe',
			});
			const [code, stdout, stderr] = await Promise.all([
				child.exited,
				new Response(child.stdout).text(),
				new Response(child.stderr).text(),
			]);
			return { code, stdout, stderr };
		}
		try {
			expect(
				(await fetch(`${provider}/__test/identity`, {
					method: 'PUT',
					headers: { Authorization: `Bearer ${control}`, 'Content-Type': 'application/json' },
					body: JSON.stringify({ email, sub: randomUUID() }),
				})).status,
			).toBe(200);
			const verification = await fetch(`${server}/identity/accounts/register/send-verification-email`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ email, name: 'SSO fixture' }),
			});
			expect(verification.status).toBe(200);
			const raw = await verification.text();
			let token: unknown;
			try {
				token = JSON.parse(raw);
			} catch {
				token = raw;
			}
			const pair = generateKeyPairSync('rsa', {
				modulusLength: 2048,
				publicKeyEncoding: { type: 'spki', format: 'der' },
				privateKeyEncoding: { type: 'pkcs8', format: 'der' },
			});
			try {
				const registered = await fetch(`${server}/identity/accounts/register/finish`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({
						email,
						name: 'SSO fixture',
						masterPasswordHash: hash,
						key: wrapped,
						keys: { publicKey: pair.publicKey.toString('base64'), encryptedPrivateKey: encrypt(pair.privateKey, key) },
						kdf: kdf.type,
						kdfIterations: kdf.iterations,
						...(kdf.type === 1 ? { kdfMemory: kdf.memory, kdfParallelism: kdf.parallelism } : {}),
						emailVerificationToken: token,
					}),
				});
				expect(registered.status).toBe(200);
			} finally {
				pair.privateKey.fill(0);
			}
			const client = new VaultwardenClient(server!);
			const authorization = await createSsoAuthorization(client, 'http://localhost:8065');
			const credentials = ssoCredentialsFromCallback(authorization, await browser(authorization.url));
			const account = await loginWithSso(client, credentials);
			expect(account.auth).toBe('sso');
			expect(account.email).toBe(email);
			expect(account.kdf).toEqual(kdf);
			const unwrapped = await unlockAccount(account, password);
			try {
				expect(unwrapped.equals(key)).toBe(true);
			} finally {
				unwrapped.fill(0);
			}
			const renewed = await refreshAccount(client, account);
			expect(renewed.auth).toBe('sso');
			const snapshot = await client.sync(renewed.accessToken),
				vault = new VaultService(client, renewed.accessToken, snapshot, key);
			let itemId: string;
			try {
				itemId = text(
					(await vault.createItem({
						type: 1,
						name: 'SSO compatibility',
						login: { username: 'synthetic', password: '  SSO-owned secret  ' },
					})).id,
				);
			} finally {
				vault.dispose();
			}
			expect((await run(['config', 'server', server!])).code).toBe(0);
			const child = Bun.spawn([
				'node',
				new URL('../dist/main.js', import.meta.url).pathname,
				'--pretty',
				'login',
				'--sso',
				'fixture-organization',
				'--nointeraction',
				'--raw',
			], {
				env: { PATH: process.env.PATH, VW_APPDATA_DIR: directory, VW_PASSWORD: password },
				stdin: 'ignore',
				stdout: 'pipe',
				stderr: 'pipe',
			});
			const ready = Promise.withResolvers<string>();
			let diagnostic = '';
			const stderr = (async () => {
				for await (const chunk of child.stderr) {
					diagnostic += new TextDecoder().decode(chunk);
					const found = diagnostic.match(/(http:\/\/127\.0\.0\.1:\d+\/identity\/connect\/authorize\?[^\r\n]+)\r?\n/);
					if (found) ready.resolve(found[1]!);
				}
			})();
			void child.exited.then(() => ready.reject(new Error('SSO CLI exited before authorization.')));
			const stdout = new Response(child.stdout).text(),
				deadline = setTimeout(() => ready.reject(new Error('SSO CLI authorization did not start.')), 15000);
			let session: string;
			try {
				const callback = await browser(await ready.promise);
				expect((await fetch(callback)).status).toBe(200);
				const code = await child.exited;
				await stderr;
				if (code !== 0) throw new Error('Compiled SSO login failed.');
				session = (await stdout).trim();
				expect(session).not.toBe('');
				expect(diagnostic).not.toContain(password);
			} finally {
				clearTimeout(deadline);
				child.kill('SIGTERM');
				await child.exited;
				await stderr;
				await stdout;
			}
			expect((await run(['get', 'password', itemId!, '--session', session!])).stdout).toBe('  SSO-owned secret  ');
			expect((await run(['sync', '--force'])).code).toBe(0);
			expect((await run(['sync'])).code).toBe(0);
			const lastSync = await run(['sync', '--last']);
			expect(lastSync.code).toBe(0);
			expect(lastSync.stdout.trim()).toBe(JSON.parse((await run(['status'])).stdout).lastSync);
			expect(JSON.parse((await run(['status', '--session', session!])).stdout).status).toBe('unlocked');
			expect((await run(['logout'])).code).toBe(0);
			const bad = await createSsoAuthorization(client, 'http://localhost:8065');
			const badCredentials = ssoCredentialsFromCallback(bad, await browser(bad.url));
			await expect(loginWithSso(client, { ...badCredentials, codeVerifier: 'x'.repeat(64) })).rejects.toBeInstanceOf(
				ApiError,
			);
			const setup = await client.api(renewed.accessToken, 'POST', '/two-factor/get-authenticator', {
				masterPasswordHash: hash,
			});
			const secret = text(field(object(setup.authenticator ?? setup), 'key'));
			await client.api(renewed.accessToken, 'PUT', '/two-factor/authenticator', {
				key: secret,
				token: totp(secret, Date.now() - 30000),
				userVerificationToken: setup.userVerificationToken,
				masterPasswordHash: hash,
			});
			const challenged = await createSsoAuthorization(client, 'http://localhost:8065');
			let callbacks = 0;
			const twoFactor = await loginWithSso(
				client,
				ssoCredentialsFromCallback(challenged, await browser(challenged.url)),
				undefined,
				{
					onTwoFactor: async challenge => {
						callbacks++;
						expect(challenge.providers).toContain(0);
						return { provider: 0, token: totp(secret) };
					},
				},
			);
			expect(callbacks).toBe(1);
			expect(twoFactor.email).toBe(email);
		} finally {
			key.fill(0);
			await rm(directory, { recursive: true, force: true });
		}
	}, 180000);
}
