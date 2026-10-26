import { expect, test } from 'bun:test';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import {
	createAccountKeyMaterial,
	encrypt,
	encryptSharedKey,
	VaultService,
	VaultwardenClient,
	type JsonObject,
} from '@kjanat/vaultwarden';
import { sealSession, withStore } from '#store';

const server = process.env.VW_TEST_SERVER;
const live = server ? test : test.skip;

live('real Vaultwarden: backup integrity through compiled CLI export and import', async () => {
	const url = new URL(server!);
	if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1') {
		throw new Error('A disposable loopback server is required.');
	}
	const email = `backup-${randomUUID()}@example.test`, password = 'Synthetic-Backup-Password-2026!';
	const kdf = { type: 0, iterations: 600000 } as const;
	const material = await createAccountKeyMaterial(password, email, kdf);
	const directory = await mkdtemp(join(tmpdir(), 'vw-backup-integrity-'));
	let vault: VaultService | undefined;
	const organizationKey = randomBytes(64);
	try {
		const verification = await fetch(`${server}/identity/accounts/register/send-verification-email`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ email, name: 'Backup fixture' }),
		});
		let verificationToken: unknown;
		if (verification.ok) {
			const body = await verification.text();
			try {
				verificationToken = JSON.parse(body);
			} catch {
				verificationToken = body;
			}
		}
		const registered = await fetch(`${server}/identity/accounts/register${verification.ok ? '/finish' : ''}`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				email,
				name: 'Backup fixture',
				masterPasswordHash: material.masterPasswordHash,
				key: material.encryptedUserKey,
				kdf: 0,
				kdfIterations: kdf.iterations,
				emailVerificationToken: verificationToken,
				keys: { publicKey: material.publicKey, encryptedPrivateKey: material.encryptedPrivateKey },
			}),
		});
		expect(registered.status).toBe(200);
		const client = new VaultwardenClient(server!);
		const auth = await client.login(email, material.masterPasswordHash);
		const organization = await client.api(auth.accessToken, 'POST', '/organizations', {
			name: 'Backup organization',
			billingEmail: email,
			planType: 0,
			collectionName: encrypt(Buffer.from('Collection'), organizationKey),
			key: await encryptSharedKey(organizationKey, material.publicKey),
		});
		const refresh = async () => {
			vault?.dispose();
			vault = new VaultService(client, auth.accessToken, await client.sync(auth.accessToken), material.userKey);
			return vault;
		};
		await refresh();
		const initial = await vault!.importVault(
			'bitwardenjson',
			JSON.stringify({
				collections: [],
				items: [
					{ type: 1, name: 'Organization one', login: { password: 'synthetic-one' } },
					{ type: 1, name: 'Organization two', login: { password: 'synthetic-two' } },
				],
			}),
			{ organizationId: String(organization.id) },
		);
		expect(initial.items).toBe(2);
		await refresh();
		expect(await vault!.listItems({ organizationId: String(organization.id) })).toHaveLength(2);
		const item = await vault!.createItem({
			type: 1,
			name: 'Attachment collision backup',
			login: { password: 'synthetic' },
		});
		await refresh();
		await vault!.createAttachment(String(item.id), 'file.txt', Buffer.from('FIRST-BODY'));
		await refresh();
		const original = await vault!.getItem(String(item.id));
		const firstAttachment = (original.attachments as JsonObject[])[0]!;
		for (
			const [name, contents] of [[String(firstAttachment.id), 'SECOND-BODY'], ['file.txt', 'THIRD-BODY'], [
				'file_1.txt',
				'FOURTH-BODY',
			]]
		) {
			await vault!.createAttachment(String(item.id), name!, Buffer.from(contents!));
			await refresh();
		}
		let session = '';
		await withStore(directory, async (state, save) => {
			state.server = server;
			state.account = { ...auth, email, kdf };
			state.vault = vault!.snapshot;
			session = sealSession(state, material.userKey);
			await save();
		});
		const run = async (args: string[]) => {
			const child = Bun.spawn(['node', new URL('../dist/main.js', import.meta.url).pathname, ...args], {
				env: { PATH: process.env.PATH, VW_APPDATA_DIR: directory, VW_SESSION: session },
				stdout: 'pipe',
				stderr: 'pipe',
				timeout: 10000,
				killSignal: 'SIGKILL',
			});
			const [code, stdout, stderr] = await Promise.all([
				child.exited,
				new Response(child.stdout).text(),
				new Response(child.stderr).text(),
			]);
			return { code, stdout, stderr };
		};
		const malformed = join(directory, 'malformed.json');
		await writeFile(
			malformed,
			JSON.stringify({
				collections: [],
				items: [
					{ type: 1, name: 'Must not be partially imported', login: {} },
					{ type: 1, name: 'Missing login section' },
				],
			}),
			{ mode: 0o600 },
		);
		const rejected = await run(['import', 'bitwardenjson', malformed, '--organizationid', String(organization.id)]);
		expect(rejected.code).toBe(1);
		expect(rejected.stderr).toContain('missing its login data');
		await refresh();
		expect(await vault!.listItems({ organizationId: String(organization.id) })).toHaveLength(2);
		const archive = join(directory, 'backup.zip');
		const exported = await run(['export', '--format', 'zip', '--output', archive]);
		expect(exported.code).toBe(0);
		expect(exported.stderr).toBe('');
		const imported = await run(['import', 'bitwardenzip', archive]);
		expect(imported.code).toBe(0);
		expect(imported.stderr).toBe('');
		expect(JSON.parse(imported.stdout)).toMatchObject({ items: 1, attachments: 4 });
		await refresh();
		const restored = (await vault!.listItems()).filter(value => value.id !== item.id && !value.organizationId);
		expect(restored).toHaveLength(1);
		const files = restored[0]!.attachments as JsonObject[];
		expect(files).toHaveLength(4);
		const contents: string[] = [];
		for (const file of files) {
			const downloaded = await vault!.getAttachment(String(restored[0]!.id), String(file.id));
			try {
				contents.push(downloaded.contents.toString());
			} finally {
				downloaded.contents.fill(0);
			}
		}
		expect(contents.sort()).toEqual(['FIRST-BODY', 'FOURTH-BODY', 'SECOND-BODY', 'THIRD-BODY']);

		// Fault injection after client validation reproduces Vaultwarden's HTTP-200
		// partial import and checks the compiled CLI's uncertain-mutation handling.
		const proxy = Bun.serve({
			hostname: '127.0.0.1',
			port: 0,
			async fetch(request) {
				const target = new URL(request.url);
				let body = request.method === 'GET' || request.method === 'HEAD' ? undefined : await request.text();
				if (target.pathname === '/api/ciphers/import-organization' && request.method === 'POST') {
					const data = JSON.parse(body!);
					data.ciphers[1].login = null;
					body = JSON.stringify(data);
				}
				return fetch(`${server}${target.pathname}${target.search}`, {
					method: request.method,
					headers: request.headers,
					body,
				});
			},
		});
		try {
			await withStore(directory, async (state, save) => {
				state.server = `http://127.0.0.1:${proxy.port}`;
				state.vault = vault!.snapshot;
				state.lastSync = new Date().toISOString();
				await save();
			});
			const valid = join(directory, 'partial.json');
			await writeFile(
				valid,
				JSON.stringify({
					collections: [],
					items: [
						{ type: 1, name: 'Accepted partial record', login: {} },
						{ type: 1, name: 'Dropped partial record', login: {} },
					],
				}),
				{ mode: 0o600 },
			);
			const partial = await run(['import', 'bitwardenjson', valid, '--organizationid', String(organization.id)]);
			expect(partial.code).toBe(1);
			expect(partial.stderr).toContain('Import verification failed');
			await withStore(directory, async state => {
				expect(state.vault).toBeUndefined();
				expect(state.lastSync).toBeUndefined();
			});
			await refresh();
			expect(await vault!.listItems({ organizationId: String(organization.id) })).toHaveLength(3);
		} finally {
			proxy.stop(true);
		}
	} finally {
		vault?.dispose();
		material.userKey.fill(0);
		organizationKey.fill(0);
		await rm(directory, { recursive: true, force: true });
	}
}, 30000);
