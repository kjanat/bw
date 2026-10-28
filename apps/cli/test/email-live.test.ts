import { fileURLToPath } from 'node:url';
import { expect, test } from 'bun:test';
import { randomBytes, randomUUID, generateKeyPairSync } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
	VaultwardenClient,
	ApiError,
	deriveMasterKey,
	masterPasswordHash,
	stretchKey,
	encrypt,
	loginWithPassword,
	unlockAccount,
	object,
	type JsonObject,
} from '@kjanat/vaultwarden';

const server = process.env.VW_TEST_SERVER, mailbox = process.env.VW_TEST_MAILPIT;
const live = server && mailbox ? test : test.skip;
for (const kdf of [{ type: 0, iterations: 600000 }, { type: 1, iterations: 3, memory: 64, parallelism: 2 }] as const) {
	live(`real Vaultwarden: email two-factor (${kdf.type === 0 ? 'PBKDF2' : 'Argon2id'})`, async () => {
		for (const address of [server!, mailbox!]) {
			const url = new URL(address);
			if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1') {
				throw new Error('Email tests require disposable loopback services.');
			}
		}
		const id = randomUUID(), email = `email-${id}@example.com`, recipient = `secondfactor-${id}@example.com`;
		const password = 'Synthetic-email-fixture-password-123!', key = randomBytes(64);
		const master = await deriveMasterKey(password, email, kdf),
			hash = await masterPasswordHash(master, password),
			stretched = stretchKey(master);
		const wrapped = encrypt(key, stretched);
		master.fill(0);
		stretched.fill(0);
		const directory = await mkdtemp(join(tmpdir(), 'vw-live-email-'));
		const post = (path: string, body: unknown) =>
			fetch(`${server}${path}`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(body),
			});
		async function messages(): Promise<JsonObject[]> {
			const response = await fetch(`${mailbox}/api/v1/messages`);
			if (!response.ok) throw new Error('SMTP receiver API is unavailable.');
			const data = object(await response.json());
			if (!Array.isArray(data.messages)) throw new Error('SMTP receiver returned an invalid message list.');
			return data.messages.map(object).filter(message =>
				Array.isArray(message.To)
				&& message.To.some(to => object(to).Address === recipient)
			);
		}
		const seen = async () => new Set((await messages()).map(message => message.ID));
		async function delivered(before: Set<unknown>): Promise<string> {
			const deadline = Date.now() + 10000;
			while (Date.now() < deadline) {
				const fresh = (await messages()).find(message => !before.has(message.ID));
				if (fresh) {
					const response = await fetch(`${mailbox}/api/v1/message/${encodeURIComponent(String(fresh.ID))}`);
					if (!response.ok) throw new Error('Could not read captured verification mail.');
					const message = object(await response.json());
					const codes = new Set(String(message.Text ?? '').match(/(?<!\d)\d{6}(?!\d)/g) ?? []);
					if (codes.size !== 1) throw new Error('Captured mail has no unique six-digit code.');
					return [...codes][0]!;
				}
				await Bun.sleep(50);
			}
			throw new Error('Verification email was not delivered to the disposable SMTP receiver.');
		}
		async function run(args: string[]) {
			const child = Bun.spawn(['node', fileURLToPath(import.meta.resolve('#main')), ...args], {
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
			const verification = await post('/identity/accounts/register/send-verification-email', {
				email,
				name: 'Email fixture',
			});
			expect(verification.status).toBe(200);
			const verificationBody = (await verification.text()).trim();
			let verificationToken: unknown = verificationBody;
			if (!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(verificationBody)) {
				try {
					verificationToken = JSON.parse(verificationBody);
				} catch {
					throw new Error('Invalid registration verification response.');
				}
			}
			const pair = generateKeyPairSync('rsa', {
				modulusLength: 2048,
				publicKeyEncoding: { type: 'spki', format: 'der' },
				privateKeyEncoding: { type: 'pkcs8', format: 'der' },
			});
			try {
				const registered = await post('/identity/accounts/register/finish', {
					email,
					name: 'Email fixture',
					masterPasswordHash: hash,
					key: wrapped,
					keys: { publicKey: pair.publicKey.toString('base64'), encryptedPrivateKey: encrypt(pair.privateKey, key) },
					kdf: kdf.type,
					kdfIterations: kdf.iterations,
					...(kdf.type === 1 ? { kdfMemory: kdf.memory, kdfParallelism: kdf.parallelism } : {}),
					emailVerificationToken: verificationToken,
				});
				expect(registered.status).toBe(200);
			} finally {
				pair.privateKey.fill(0);
			}
			const client = new VaultwardenClient(server!), initial = await loginWithPassword(client, email, password);
			const setup = await client.api(initial.accessToken, 'POST', '/two-factor/get-email', {
				masterPasswordHash: hash,
			});
			const beforeEnroll = await seen();
			await client.api(initial.accessToken, 'POST', '/two-factor/send-email', {
				email: recipient,
				masterPasswordHash: hash,
				userVerificationToken: setup.userVerificationToken,
			});
			const enrollmentCode = await delivered(beforeEnroll);
			await client.api(initial.accessToken, 'PUT', '/two-factor/email', {
				email: recipient,
				token: enrollmentCode,
				masterPasswordHash: hash,
				userVerificationToken: setup.userVerificationToken,
			});
			await expect(loginWithPassword(client, email, password)).rejects.toBeInstanceOf(ApiError);
			let callbacks = 0, acceptedCode = '';
			const account = await loginWithPassword(client, email, password, undefined, {
				onTwoFactor: async challenge => {
					callbacks++;
					expect(challenge.providers).toContain(1);
					const beforeRequest = await seen();
					await challenge.requestEmail();
					acceptedCode = await delivered(beforeRequest);
					return { provider: 1, token: acceptedCode };
				},
			});
			expect(callbacks).toBe(1);
			const unwrapped = await unlockAccount(account, password);
			try {
				expect(unwrapped.equals(key)).toBe(true);
			} finally {
				unwrapped.fill(0);
			}
			await expect(loginWithPassword(client, email, password, { provider: 1, token: acceptedCode })).rejects
				.toBeInstanceOf(ApiError);
			const beforeWrong = await seen();
			await client.sendEmailLogin(email, hash);
			const pendingCode = await delivered(beforeWrong),
				wrongCode = `${pendingCode[0] === '0' ? '1' : '0'}${pendingCode.slice(1)}`;
			await expect(loginWithPassword(client, email, password, { provider: 1, token: wrongCode })).rejects
				.toBeInstanceOf(ApiError);
			const configured = await run(['config', 'server', server!]);
			expect(configured.code).toBe(0);
			const beforeMissing = await seen();
			const missing = await run(['login', email, '--method', '1', '--nointeraction']);
			expect(missing.code).toBe(1);
			expect(missing.stderr).toContain('Supply --code for noninteractive');
			expect((await seen()).size).toBe(beforeMissing.size);
			const beforeCli = await seen();
			await client.sendEmailLogin(email, hash);
			const cliCode = await delivered(beforeCli);
			const login = await run(['login', email, '--method', '1', '--code', cliCode, '--nointeraction', '--raw']);
			if (login.code !== 0) throw new Error('CLI login with delivered email code failed.');
			expect(login.stdout.trim()).not.toBe('');
			expect(login.stderr).not.toContain(cliCode);
			expect(login.stderr).not.toContain(password);
			expect((await run(['status', '--session', login.stdout.trim()])).code).toBe(0);
			expect((await run(['logout'])).code).toBe(0);
		} finally {
			key.fill(0);
			await rm(directory, { recursive: true, force: true });
		}
	}, 120000);
}
