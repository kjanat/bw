import { expect, test } from 'bun:test';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { generateKeyPairSync, randomBytes, randomUUID, createPublicKey, publicEncrypt, constants } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { withStore } from '#store';
import {
	deriveMasterKey,
	masterPasswordHash,
	stretchKey,
	encrypt,
	decryptSharedKey,
	type Kdf,
} from '@kjanat/vaultwarden';

// Explicit opt-in. Only disposable loopback instances may be mutated by this test.
const server = process.env.VW_TEST_SERVER;
const live = server ? test : test.skip;
for (
	const kdf of [
		{ type: 0, iterations: 600000 },
		{ type: 1, iterations: 3, memory: 64, parallelism: 2 },
	] as Kdf[]
) {
	live(
		`real Vaultwarden: ${kdf.type === 0 ? 'PBKDF2' : 'Argon2id'} login, sync, item keys, sessions, lock, logout`,
		async () => {
			const url = new URL(server!);
			if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1') {
				throw new Error(
					'Live tests require a disposable HTTP loopback server.',
				);
			}
			const email = `fixture-${randomUUID()}@example.com`;
			const password = 'Synthetic-fixture-password-123!';
			const userKey = randomBytes(64);
			const itemKey = randomBytes(64);
			const master = await deriveMasterKey(password, email, kdf);
			const stretched = stretchKey(master);
			const hash = await masterPasswordHash(master, password);
			const wrapped = encrypt(userKey, stretched);
			const rsa = generateKeyPairSync('rsa', {
				modulusLength: 2048,
				publicKeyEncoding: { type: 'spki', format: 'der' },
				privateKeyEncoding: { type: 'pkcs8', format: 'der' },
			});
			master.fill(0);
			stretched.fill(0);
			async function post(path: string, data: unknown, token?: string) {
				return fetch(`${server}${path}`, {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						Accept: 'application/json',
						...(token ? { Authorization: `Bearer ${token}` } : {}),
					},
					body: JSON.stringify(data),
				});
			}
			const verify = await post(
				'/identity/accounts/register/send-verification-email',
				{
					email,
					name: 'Compatibility fixture',
				},
			);
			const verificationToken = verify.ok ? await verify.json() : undefined;
			const registration = {
				keys: {
					publicKey: rsa.publicKey.toString('base64'),
					encryptedPrivateKey: encrypt(rsa.privateKey, userKey),
				},
				email,
				name: 'Compatibility fixture',
				masterPasswordHash: hash,
				key: wrapped,
				kdf: kdf.type,
				kdfIterations: kdf.iterations,
				kdfMemory: kdf.type === 1 ? kdf.memory : null,
				kdfParallelism: kdf.type === 1 ? kdf.parallelism : null,
				emailVerificationToken: verificationToken,
			};
			const registered = await post(
				verify.ok
					? '/identity/accounts/register/finish'
					: '/identity/accounts/register',
				registration,
			);
			expect(registered.status).toBe(200);
			const tokenResponse = await fetch(`${server}/identity/connect/token`, {
				method: 'POST',
				body: new URLSearchParams({
					grant_type: 'password',
					client_id: 'cli',
					scope: 'api offline_access',
					username: email,
					password: hash,
					deviceIdentifier: randomUUID(),
					deviceName: 'Fixture',
					deviceType: '8',
				}),
			});
			expect(tokenResponse.status).toBe(200);
			const auth = (await tokenResponse.json()) as { access_token: string };
			const enc = (s: string) => encrypt(Buffer.from(s), itemKey);
			const orgKey = randomBytes(64);
			const organizationResponse = await post('/api/organizations', {
				name: 'Compatibility organization',
				billingEmail: email,
				planType: 0,
				collectionName: encrypt(Buffer.from('Organization collection'), orgKey),
				key: `3.${
					publicEncrypt({
						key: createPublicKey({ key: rsa.publicKey, format: 'der', type: 'spki' }),
						padding: constants.RSA_PKCS1_OAEP_PADDING,
						oaepHash: 'sha256',
					}, orgKey).toString('base64')
				}`,
			}, auth.access_token);
			expect(organizationResponse.status).toBe(200);
			const organization = await organizationResponse.json() as { id: string };
			const profileResponse = await fetch(`${server}/api/accounts/profile`, {
				headers: { Authorization: `Bearer ${auth.access_token}` },
			});
			const profile = (await profileResponse.json()) as { id: string };
			const created = await post(
				'/api/ciphers',
				{
					encryptedFor: profile.id,
					type: 1,
					organizationId: null,
					folderId: null,
					name: enc('Compatibility fixture'),
					notes: enc('fixture notes'),
					key: encrypt(itemKey, userKey),
					favorite: false,
					reprompt: 0,
					login: {
						username: enc('fixture-user'),
						password: enc('fixture-secret'),
						uris: [{ uri: enc('https://example.com'), match: null }],
					},
					fields: [],
				},
				auth.access_token,
			);
			expect(created.status).toBe(200);
			const item = (await created.json()) as { id: string };
			const dir = await mkdtemp(join(tmpdir(), 'vw-live-'));
			const ca = join(dir, 'ca.pem');
			const keyPath = join(dir, 'key.pem');
			const certificate = Bun.spawnSync(
				[
					'openssl',
					'req',
					'-x509',
					'-newkey',
					'rsa:2048',
					'-nodes',
					'-days',
					'1',
					'-subj',
					'/CN=localhost',
					'-addext',
					'subjectAltName=IP:127.0.0.1,DNS:localhost',
					'-keyout',
					keyPath,
					'-out',
					ca,
				],
				{ stdout: 'pipe', stderr: 'pipe' },
			);
			if (certificate.exitCode !== 0) {
				throw new Error('Could not generate test TLS certificate.');
			}
			const proxy = Bun.serve({
				hostname: '127.0.0.1',
				port: 0,
				tls: { cert: Bun.file(ca), key: Bun.file(keyPath) },
				async fetch(request) {
					const target = new URL(request.url);
					const response = await fetch(
						`${server}${target.pathname}${target.search}`,
						{
							method: request.method,
							headers: { ...Object.fromEntries(request.headers), 'X-Forwarded-Proto': 'https' },
							body: ['GET', 'HEAD'].includes(request.method)
								? undefined
								: await request.arrayBuffer(),
							redirect: 'manual',
						},
					);
					return new Response(response.body, {
						status: response.status,
						headers: response.headers,
					});
				},
			});
			const tlsServer = `https://127.0.0.1:${proxy.port}`;
			async function run(args: string[], session?: string, secret = password, input?: string) {
				const child = Bun.spawn(
					[
						'node',
						new URL('../dist/main.js', import.meta.url).pathname,
						...args,
					],
					{
						env: {
							PATH: process.env.PATH,
							VW_APPDATA_DIR: dir,
							NODE_EXTRA_CA_CERTS: ca,
							VW_PASSWORD: secret,
							...(session ? { VW_SESSION: session } : {}),
						},
						stdin: 'pipe',
						stdout: 'pipe',
						stderr: 'pipe',
					},
				);
				if (input) child.stdin.write(input);
				child.stdin.end();
				const [code, stdout, stderr] = await Promise.all([
					child.exited,
					new Response(child.stdout).text(),
					new Response(child.stderr).text(),
				]);
				return { code, stdout, stderr };
			}
			try {
				expect((await run(['config', 'server', tlsServer])).code).toBe(0);
				expect((await run(['login', email])).code).toBe(0);
				expect((await run(['sync'])).code).toBe(0);
				await withStore(dir, async (state, save) => {
					state.account!.expiresAt = 0;
					await save();
				});
				expect((await run(['sync'])).code).toBe(0);
				await withStore(dir, async (state, save) => {
					state.account!.accessToken = 'expired-fixture-token';
					await save();
				});
				expect((await run(['sync'])).code).toBe(0);
				expect(
					(await run(['unlock', '--raw'], undefined, 'incorrect-password'))
						.code,
				).toBe(1);
				const unlocked = await run(['unlock', '--raw']);
				expect(unlocked.code).toBe(0);
				const session = unlocked.stdout.trim();
				expect(session).toMatch(/^[A-Za-z0-9+/]{43}=$/);
				expect(JSON.parse((await run(['status'], session)).stdout).status).toBe(
					'unlocked',
				);
				const list = await run(['list', 'items'], session);
				expect(list.code).toBe(0);
				expect(JSON.parse(list.stdout)[0].name).toBe('Compatibility fixture');
				expect((await run(['get', 'password', item.id], session)).stdout).toBe(
					'fixture-secret\n',
				);
				const encode = (data: unknown) => Buffer.from(JSON.stringify(data)).toString('base64');
				const checked = async (args: string[], input?: string) => {
					const result = await run(args, session, password, input);
					if (result.code !== 0) throw new Error(`CLI operation failed: ${result.stderr}`);
					return result.stdout;
				};
				expect((await checked(['encode'], JSON.stringify({ name: 'Encoded' }))).trim()).toBe(
					encode({ name: 'Encoded' }),
				);
				const folder = JSON.parse(await checked(['create', 'folder'], encode({ name: 'Private folder' })));
				expect(folder.name).toBe('Private folder');
				expect(JSON.parse(await checked(['list', 'organizations']))[0].name).toBe('Compatibility organization');
				const collections = JSON.parse(await checked(['list', 'collections']));
				expect(collections[0].name).toBe('Organization collection');
				const sharedItem = JSON.parse(
					await checked([
						'create',
						'item',
						encode({
							type: 1,
							name: 'Shared by vw',
							organizationId: organization.id,
							collectionIds: [collections[0].id],
							login: { username: 'organization-user', password: 'organization-secret' },
						}),
					]),
				);
				expect((await checked(['get', 'password', sharedItem.id])).trim()).toBe('organization-secret');
				const collection = JSON.parse(
					await checked([
						'create',
						'org-collection',
						encode({ name: 'Managed collection' }),
						'--organizationid',
						organization.id,
					]),
				);
				expect(collection.name).toBe('Managed collection');
				expect(
					JSON.parse(await checked(['get', 'org-collection', collection.id, '--organizationid', organization.id])).name,
				).toBe('Managed collection');
				expect(
					JSON.parse(await checked(['list', 'org-collections', '--organizationid', organization.id])).some((
						c: { id: string },
					) => c.id === collection.id),
				).toBe(true);
				const movable = JSON.parse(
					await checked([
						'create',
						'item',
						encode({ type: 1, name: 'Move fixture', login: { password: 'moved-secret' } }),
					]),
				);
				const attachmentBytes = Buffer.alloc(131072, Buffer.from([0, 1, 2, 255, 128, 10, 13, 0, 42]));
				const uploadPath = join(dir, 'fixture.bin');
				await writeFile(uploadPath, attachmentBytes, { mode: 0o600 });
				const upload = JSON.parse(
					await checked(['create', 'attachment', '--file', uploadPath, '--itemid', movable.id]),
				);
				const attachmentId = upload.attachments[0].id;
				expect(upload.attachments[0].fileName).toBe('fixture.bin');
				const downloadPath = join(dir, 'download.bin');
				await checked(['get', 'attachment', attachmentId, '--itemid', movable.id, '--output', downloadPath]);
				const beforeMove = await readFile(downloadPath);
				expect(beforeMove).toEqual(attachmentBytes);
				expect((await stat(downloadPath)).mode & 0o777).toBe(0o600);
				const moved = JSON.parse(await checked(['move', movable.id, organization.id, encode([collection.id])]));
				expect(moved.organizationId).toBe(organization.id);
				expect(moved.login.password).toBe('moved-secret');
				const movedDownload = join(dir, 'moved.bin');
				await checked(['get', 'attachment', 'fixture.bin', '--itemid', movable.id, '--output', movedDownload]);
				expect(await readFile(movedDownload)).toEqual(attachmentBytes);
				const binaryChild = Bun.spawn([
					'node',
					new URL('../dist/main.js', import.meta.url).pathname,
					'get',
					'attachment',
					attachmentId,
					'--itemid',
					movable.id,
					'--raw',
				], {
					env: { PATH: process.env.PATH, VW_APPDATA_DIR: dir, VW_SESSION: session, NODE_EXTRA_CA_CERTS: ca },
					stdout: 'pipe',
					stderr: 'pipe',
				});
				const [binaryCode, binaryOutput] = await Promise.all([
					binaryChild.exited,
					new Response(binaryChild.stdout).arrayBuffer(),
					new Response(binaryChild.stderr).text(),
				]);
				expect(binaryCode).toBe(0);
				expect(Buffer.from(binaryOutput).equals(attachmentBytes)).toBe(true);
				await checked(['edit', 'item-collections', movable.id, encode([collections[0].id])]);
				expect(JSON.parse(await checked(['get', 'item', movable.id])).collectionIds).toEqual([collections[0].id]);
				const renamedCollection = JSON.parse(
					await checked([
						'edit',
						'org-collection',
						collection.id,
						encode({ name: 'Renamed collection' }),
						'--organizationid',
						organization.id,
					]),
				);
				expect(renamedCollection.name).toBe('Renamed collection');
				await checked(['delete', 'org-collection', collection.id, '--organizationid', organization.id]);
				const members = JSON.parse(await checked(['list', 'org-members', '--organizationid', organization.id]));
				expect(members.some((m: { email: string }) => m.email === email)).toBe(true);
				// Register a second real account, invite it, and verify confirmation wraps the org key for that account.
				const memberEmail = `member-${randomUUID()}@example.com`;
				const memberKey = randomBytes(64);
				const memberMaster = await deriveMasterKey(password, memberEmail, { type: 0, iterations: 600000 });
				const memberStretch = stretchKey(memberMaster);
				const memberHash = await masterPasswordHash(memberMaster, password);
				const memberRsa = generateKeyPairSync('rsa', {
					modulusLength: 2048,
					publicKeyEncoding: { type: 'spki', format: 'der' },
					privateKeyEncoding: { type: 'pkcs8', format: 'der' },
				});
				try {
					const verifyMember = await post('/identity/accounts/register/send-verification-email', {
						email: memberEmail,
						name: 'Member fixture',
					});
					expect(verifyMember.status).toBe(200);
					const memberRegistered = await post('/identity/accounts/register/finish', {
						email: memberEmail,
						masterPasswordHash: memberHash,
						key: encrypt(memberKey, memberStretch),
						kdf: 0,
						kdfIterations: 600000,
						emailVerificationToken: await verifyMember.json(),
						keys: {
							publicKey: memberRsa.publicKey.toString('base64'),
							encryptedPrivateKey: encrypt(memberRsa.privateKey, memberKey),
						},
					});
					expect(memberRegistered.status).toBe(200);
					const invited = await post(`/api/organizations/${organization.id}/users/invite`, {
						emails: [memberEmail],
						type: 2,
						groups: [],
						collections: [{ id: collections[0].id, readOnly: false, hidePasswords: false, manage: false }],
					}, auth.access_token);
					expect(invited.status).toBe(200);
					const pending = JSON.parse(await checked(['list', 'org-members', '--organizationid', organization.id])).find((
						m: { email: string },
					) => m.email === memberEmail);
					expect(pending.status).toBe(1);
					await checked(['confirm', 'org-member', pending.id, '--organizationid', organization.id]);
					const confirmed = JSON.parse(await checked(['list', 'org-members', '--organizationid', organization.id]))
						.find((m: { email: string }) => m.email === memberEmail);
					expect(confirmed.status).toBe(2);
					const memberLogin = await fetch(`${server}/identity/connect/token`, {
						method: 'POST',
						body: new URLSearchParams({
							grant_type: 'password',
							client_id: 'cli',
							scope: 'api offline_access',
							username: memberEmail,
							password: memberHash,
							deviceIdentifier: randomUUID(),
							deviceName: 'Member fixture',
							deviceType: '8',
						}),
					});
					expect(memberLogin.status).toBe(200);
					const memberAuth = await memberLogin.json() as { access_token: string };
					const memberSync = await fetch(`${server}/api/sync`, {
						headers: { Authorization: `Bearer ${memberAuth.access_token}`, 'Bitwarden-Client-Version': '2026.10.0' },
					});
					expect(memberSync.status).toBe(200);
					const memberVault = await memberSync.json() as { profile: { organizations: { id: string; key: string }[] } };
					const wrapped = memberVault.profile.organizations.find(o => o.id === organization.id)!;
					const shared = decryptSharedKey(wrapped.key, memberRsa.privateKey);
					try {
						expect(shared).toEqual(orgKey);
					} finally {
						shared.fill(0);
					}
				} finally {
					memberKey.fill(0);
					memberMaster.fill(0);
					memberStretch.fill(0);
					memberRsa.privateKey.fill(0);
				}

				expect(JSON.parse(await checked(['list', 'folders']))[0].name).toBe('Private folder');
				const createdItem = JSON.parse(
					await checked([
						'create',
						'item',
						encode({
							type: 1,
							name: 'Created by vw',
							notes: 'new notes',
							folderId: folder.id,
							login: {
								username: 'new-user',
								password: 'new-secret',
								totp: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
								uris: [{ uri: 'https://created.example.com' }],
							},
							fields: [{ type: 0, name: 'private-field', value: 'private-value' }],
						}),
					]),
				);
				expect(createdItem.name).toBe('Created by vw');
				expect(JSON.parse(await checked(['list', 'items', '--folderid', folder.id])).length).toBe(1);
				const editedItem = JSON.parse(
					await checked([
						'edit',
						'item',
						createdItem.id,
						encode({
							...createdItem,
							name: 'Edited by vw',
							login: { ...createdItem.login, password: 'edited-secret' },
						}),
					]),
				);
				expect(editedItem.login.password).toBe('edited-secret');
				const stale = await run([
					'edit',
					'item',
					createdItem.id,
					encode({ ...editedItem, name: 'Stale overwrite', revisionDate: '2000-01-01T00:00:00Z' }),
				], session);
				expect(stale.code).toBe(1);
				expect(JSON.parse(await checked(['get', 'item', createdItem.id])).name).toBe('Edited by vw');
				expect((await checked(['get', 'totp', createdItem.id])).trim()).toMatch(/^\d{6}$/);
				for (
					const [type, section, fields] of [
						[2, 'secureNote', { type: 0 }],
						[3, 'card', { number: '4111111111111111', code: '123', cardholderName: 'Fixture' }],
						[4, 'identity', { firstName: 'Fixture', ssn: 'synthetic-id' }],
						[5, 'sshKey', {
							privateKey: 'synthetic-private-key',
							publicKey: 'synthetic-public-key',
							keyFingerprint: 'synthetic-fingerprint',
						}],
					] as const
				) {
					const value = JSON.parse(
						await checked([
							'create',
							'item',
							encode({ type, name: `Type ${type}`, notes: 'typed notes', [section]: fields }),
						]),
					);
					expect(value[section]).toMatchObject(fields);
					expect(JSON.parse(await checked(['get', 'item', value.id]))[section]).toMatchObject(fields);
					await checked(['delete', 'item', value.id, '--permanent']);
				}
				const organizationImport = join(dir, 'organization-import.json');
				await writeFile(
					organizationImport,
					JSON.stringify({
						encrypted: false,
						collections: [{ id: 'source-collection', name: 'Imported collection' }],
						items: [{
							id: 'source-note',
							type: 2,
							name: 'Imported organization note',
							notes: 'organization import secret',
							secureNote: { type: 0 },
							collectionIds: ['source-collection'],
						}],
					}),
					{ mode: 0o600 },
				);
				const importedOrg = JSON.parse(
					await checked(['import', 'bitwardenjson', organizationImport, '--organizationid', organization.id]),
				);
				expect(importedOrg).toMatchObject({ items: 1, collections: 1 });
				const organizationExport = JSON.parse(
					await checked(['export', '--format', 'json', '--organizationid', organization.id, '--raw']),
				);
				const importedNote = organizationExport.items.find((value: { name: string }) =>
					value.name === 'Imported organization note'
				);
				expect(importedNote.notes).toBe('organization import secret');
				const importedCollection = organizationExport.collections.find((value: { name: string }) =>
					value.name === 'Imported collection'
				);
				expect(importedNote.collectionIds).toContain(importedCollection.id);
				await checked(['delete', 'item', importedNote.id, '--permanent']);
				await checked(['delete', 'org-collection', importedCollection.id, '--organizationid', organization.id]);
				if (process.env.VW_TEST_BW) {
					const officialDir = join(dir, 'official');
					async function official(args: string[], token?: string) {
						const child = Bun.spawn([process.env.VW_TEST_BW!, ...args], {
							env: {
								PATH: process.env.PATH,
								HOME: dir,
								BITWARDENCLI_APPDATA_DIR: officialDir,
								BW_NOINTERACTION: 'true',
								BW_PASSWORD: password,
								NODE_EXTRA_CA_CERTS: ca,
								...(token ? { BW_SESSION: token } : {}),
							},
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
					expect((await official(['config', 'server', tlsServer])).code).toBe(
						0,
					);
					const login = await official([
						'login',
						email,
						'--passwordenv',
						'BW_PASSWORD',
						'--raw',
					]);
					if (login.code !== 0) {
						throw new Error(`Official bw login failed: ${login.stderr}`);
					}
					const result = await official(
						['get', 'password', item.id],
						login.stdout.trim(),
					);
					expect(result.code).toBe(0);
					expect(result.stdout.trim()).toBe('fixture-secret');
					const written = await official(['get', 'item', createdItem.id], login.stdout.trim());
					expect(written.code).toBe(0);
					expect(JSON.parse(written.stdout).login.password).toBe('edited-secret');
					expect(JSON.parse(written.stdout).fields[0].value).toBe('private-value');
					const sharedRead = await official(['get', 'password', sharedItem.id], login.stdout.trim());
					expect(sharedRead.code).toBe(0);
					expect(sharedRead.stdout.trim()).toBe('organization-secret');
					const officialFolder = await official(['get', 'folder', folder.id], login.stdout.trim());
					expect(officialFolder.code).toBe(0);
					expect(JSON.parse(officialFolder.stdout).name).toBe('Private folder');
					const officialAttachment = join(dir, 'official.bin');
					const officialDownload = await official([
						'get',
						'attachment',
						attachmentId,
						'--itemid',
						movable.id,
						'--output',
						officialAttachment,
					], login.stdout.trim());
					expect(officialDownload.code).toBe(0);
					expect(await readFile(officialAttachment)).toEqual(attachmentBytes);
					const officialMoved = await official(['get', 'password', movable.id], login.stdout.trim());
					expect(officialMoved.code).toBe(0);
					expect(officialMoved.stdout.trim()).toBe('moved-secret');
					// Exercise both directions with independent bw serialization and KDF handling.
					const filePassword = join(dir, 'transfer-password.txt');
					await writeFile(filePassword, 'Synthetic-export-password-456!\n', { mode: 0o600 });
					const originalItems = new Set(JSON.parse(await checked(['list', 'items'])).map((v: { id: string }) => v.id));
					const originalFolders = new Set(
						JSON.parse(await checked(['list', 'folders'])).map((v: { id: string }) => v.id),
					);
					async function verifyImported(withAttachment = false) {
						await checked(['sync']);
						const added = JSON.parse(await checked(['list', 'items'])).filter((v: { id: string }) =>
							!originalItems.has(v.id)
						);
						expect(added.length).toBe(2);
						expect(added.find((v: { name: string }) => v.name === 'Edited by vw').login.password).toBe('edited-secret');
						expect(added.find((v: { name: string }) => v.name === 'Compatibility fixture').login.password).toBe(
							'fixture-secret',
						);
						if (withAttachment) {
							const copy = added.find((v: { name: string }) => v.name === 'Compatibility fixture');
							expect(copy.attachments.length).toBe(1);
							const destination = join(dir, `restored-${randomUUID()}.bin`);
							await checked([
								'get',
								'attachment',
								copy.attachments[0].id,
								'--itemid',
								copy.id,
								'--output',
								destination,
							]);
							expect(await readFile(destination)).toEqual(attachmentBytes);
						}
						for (const value of added) await checked(['delete', 'item', value.id, '--permanent']);
						const folders = JSON.parse(await checked(['list', 'folders']));
						for (const value of folders) {
							if (!originalFolders.has(value.id)) await checked(['delete', 'folder', value.id]);
						}
					}
					for (const format of ['json', 'csv', 'encrypted_json', 'password'] as const) {
						const transferFormat = format === 'password' ? 'encrypted_json' : format;
						const importFormat = format === 'csv' ? 'bitwardencsv' : 'bitwardenjson';
						const ours = join(dir, `vw-${format}.export`);
						await checked([
							'export',
							'--format',
							transferFormat,
							'--output',
							ours,
							...(format === 'password' ? ['--passwordfile', filePassword] : []),
						]);
						const imported = await official([
							'import',
							importFormat,
							ours,
							...(format === 'password' ? ['--passwordfile', filePassword] : []),
						], login.stdout.trim());
						if (imported.code) throw new Error(`Official import ${format} failed: ${imported.stderr}`);
						await verifyImported();
						// Refresh bw after deleting the imported copies, then export its authoritative cache.
						expect((await official(['sync'], login.stdout.trim())).code).toBe(0);
						const theirs = join(dir, `bw-${format}.export`);
						const exported = await official([
							'export',
							'--format',
							transferFormat,
							'--output',
							theirs,
							...(format === 'password' ? ['--password', 'Synthetic-export-password-456!'] : []),
						], login.stdout.trim());
						if (exported.code) throw new Error(`Official export ${format} failed: ${exported.stderr}`);
						const result = JSON.parse(
							await checked([
								'import',
								importFormat,
								theirs,
								...(format === 'password' ? ['--passwordfile', filePassword] : []),
							]),
						);
						expect(result.items).toBe(2);
						await verifyImported();
					}
					const attached = JSON.parse(
						await checked(['create', 'attachment', '--file', uploadPath, '--itemid', item.id]),
					);
					for (const source of ['vw', 'bw']) {
						const path = join(dir, `${source}-backup.zip`);
						if (source === 'vw') await checked(['export', '--format', 'zip', '--output', path]);
						else {
							expect((await official(['sync'], login.stdout.trim())).code).toBe(0);
							const result = await official(['export', '--format', 'zip', '--output', path], login.stdout.trim());
							if (result.code) throw new Error(`Official ZIP export failed: ${result.stderr}`);
						}
						const restored = JSON.parse(await checked(['import', 'bitwardenzip', path]));
						expect(restored.attachments).toBe(1);
						await verifyImported(true);
					}
					await checked(['delete', 'attachment', attached.attachments[0].id, '--itemid', item.id]);
				}
				expect(
					(
						await run(['list', 'items', '--search', 'no match'], session)
					).stdout.trim(),
				).toBe('[]');
				await checked(['archive', 'item', createdItem.id]);
				expect(JSON.parse(await checked(['list', 'items', '--archived']))[0].id).toBe(createdItem.id);
				await checked(['restore', 'item', createdItem.id]);
				await checked(['delete', 'item', createdItem.id]);
				expect(JSON.parse(await checked(['list', 'items', '--trash']))[0].id).toBe(createdItem.id);
				await checked(['restore', 'item', createdItem.id]);
				expect((await checked(['get', 'password', createdItem.id])).trim()).toBe('edited-secret');
				await checked(['delete', 'item', createdItem.id, '--permanent']);
				expect((await run(['get', 'item', createdItem.id], session)).code).toBe(1);
				const renamed = JSON.parse(await checked(['edit', 'folder', folder.id, encode({ name: 'Renamed folder' })]));
				expect(renamed.name).toBe('Renamed folder');
				await checked(['delete', 'folder', folder.id]);
				expect(JSON.parse(await checked(['list', 'folders']))).toEqual([]);
				await checked(['delete', 'attachment', attachmentId, '--itemid', movable.id]);
				expect((await run(['get', 'attachment', attachmentId, '--itemid', movable.id, '--raw'], session)).code).toBe(1);
				const persisted = await readFile(join(dir, 'state.json'), 'utf8');
				for (
					const secret of [
						password,
						'fixture-secret',
						'fixture notes',
						userKey.toString('base64'),
						session,
					]
				) {
					expect(persisted).not.toContain(secret);
				}
				expect((await stat(join(dir, 'state.json'))).mode & 0o777).toBe(0o600);
				proxy.stop(true);
				expect((await run(['get', 'password', item.id], session)).stdout).toBe(
					'fixture-secret\n',
				);
				expect((await run(['lock'])).code).toBe(0);
				expect((await run(['get', 'password', item.id], session)).code).toBe(1);
				expect((await run(['logout'])).code).toBe(0);
				expect(JSON.parse((await run(['status'])).stdout).status).toBe(
					'unauthenticated',
				);
			} finally {
				proxy.stop(true);
				orgKey.fill(0);
				userKey.fill(0);
				itemKey.fill(0);
				await rm(dir, { recursive: true, force: true });
			}
		},
		240000,
	);
}
