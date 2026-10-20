import { expect, test } from 'bun:test';
import { randomBytes, randomUUID, generateKeyPairSync } from 'node:crypto';
import { mkdtemp, rm, writeFile, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createServer } from 'node:net';
import {
	ApiError,
	VaultwardenClient,
	deriveMasterKey,
	masterPasswordHash,
	stretchKey,
	encrypt,
	loginWithPassword,
	unlockAccount,
	totp,
	field,
	object,
	text,
	writeCsv,
} from '@kjanat/vaultwarden';

const server = process.env.VW_TEST_SERVER;
const live = server ? test : test.skip;
live('real Vaultwarden: authentication, external imports, and REST compatibility', async () => {
	const location = new URL(server!);
	if (location.protocol !== 'http:' || location.hostname !== '127.0.0.1') {
		throw new Error('Live tests require a disposable HTTP loopback server.');
	}
	const email = `challenge-${randomUUID()}@example.com`, password = 'Synthetic-fixture-password-123!';
	const kdf = { type: 0, iterations: 600000 } as const;
	const master = await deriveMasterKey(password, email, kdf);
	const hash = await masterPasswordHash(master, password), userKey = randomBytes(64), stretched = stretchKey(master);
	const wrapped = encrypt(userKey, stretched);
	master.fill(0);
	stretched.fill(0);
	const post = (path: string, body: unknown) =>
		fetch(`${server}${path}`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
			body: JSON.stringify(body),
		});
	const verify = await post('/identity/accounts/register/send-verification-email', { email, name: 'TOTP fixture' });
	expect(verify.status).toBe(200);
	const registered = await post('/identity/accounts/register/finish', {
		email,
		name: 'TOTP fixture',
		masterPasswordHash: hash,
		key: wrapped,
		keys: (() => {
			const pair = generateKeyPairSync('rsa', {
				modulusLength: 2048,
				publicKeyEncoding: { type: 'spki', format: 'der' },
				privateKeyEncoding: { type: 'pkcs8', format: 'der' },
			});
			try {
				return { publicKey: pair.publicKey.toString('base64'), encryptedPrivateKey: encrypt(pair.privateKey, userKey) };
			} finally {
				pair.privateKey.fill(0);
			}
		})(),
		kdf: kdf.type,
		kdfIterations: kdf.iterations,
		emailVerificationToken: await verify.json(),
	});
	expect(registered.status).toBe(200);
	const client = new VaultwardenClient(server!);
	const initial = await loginWithPassword(client, email, password);
	const setup = await client.api(initial.accessToken, 'POST', '/two-factor/get-authenticator', {
		masterPasswordHash: hash,
	});
	const secret = text(field(object(setup.authenticator ?? setup), 'key'));
	await client.api(initial.accessToken, 'PUT', '/two-factor/authenticator', {
		key: secret,
		token: totp(secret, Date.now() - 30000),
		userVerificationToken: setup.userVerificationToken,
		masterPasswordHash: hash,
	});
	await expect(loginWithPassword(client, email, password)).rejects.toBeInstanceOf(ApiError);
	let challenges = 0;
	const account = await loginWithPassword(client, email, password, undefined, {
		onTwoFactor: async challenge => {
			challenges++;
			expect(challenge.providers).toContain(0);
			await expect(challenge.requestEmail()).rejects.toThrow('unavailable');
			return { provider: 0, token: totp(secret) };
		},
	});
	expect(challenges).toBe(1);
	const unlocked = await unlockAccount(account, password);
	try {
		expect(unlocked.equals(userKey)).toBe(true);
	} finally {
		unlocked.fill(0);
	}
	const dir = await mkdtemp(join(tmpdir(), 'vw-live-challenge-'));
	const executable = new URL('../dist/main.js', import.meta.url).pathname;
	async function run(args: string[], importPassword?: string) {
		const child = Bun.spawn(['node', executable, ...args], {
			env: { PATH: process.env.PATH, VW_APPDATA_DIR: dir, VW_PASSWORD: password, VW_IMPORT_PASSWORD: importPassword },
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
			(await run(['config', 'server', server!, '--api', `${server}/api`, '--identity', `${server}/identity`])).code,
		).toBe(0);
		const missing = await run(['login', email, '--nointeraction']);
		expect(missing.code).toBe(1);
		expect(missing.stderr).toContain('Two-factor authentication is required');
		const login = await run([
			'login',
			email,
			'--method',
			'0',
			'--code',
			totp(secret, Date.now() + 30000),
			'--nointeraction',
			'--raw',
		]);
		expect(login.code).toBe(0);
		expect(login.stdout.trim()).not.toBe('');
		expect(login.stderr.includes(password)).toBe(false);
		const serving = Bun.spawn([
			'node',
			executable,
			'serve',
			'--hostname',
			'127.0.0.1',
			'--port',
			'0',
			'--session',
			login.stdout.trim(),
		], {
			env: { PATH: process.env.PATH, VW_APPDATA_DIR: dir },
			stdout: 'pipe',
			stderr: 'pipe',
		});
		const ready = Promise.withResolvers<string>();
		let diagnostic = '';
		const stderr = (async () => {
			for await (const part of serving.stderr) {
				diagnostic += new TextDecoder().decode(part);
				const address = diagnostic.match(/Listening on (http:\/\/127\.0\.0\.1:\d+)/);
				if (address) ready.resolve(address[1]!);
			}
		})();
		void serving.exited.then(() => ready.reject(new Error('Local API exited before listening.')));
		const stdout = new Response(serving.stdout).text();
		const deadline = setTimeout(() => ready.reject(new Error('Local API did not start.')), 5000);
		try {
			const base = await ready.promise;
			clearTimeout(deadline);
			const call = (path: string, method = 'GET', body?: unknown) =>
				fetch(`${base}${path}`, {
					method,
					headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
					body: body === undefined ? undefined : JSON.stringify(body),
				});
			expect(await (await call('/status')).json()).toMatchObject({
				success: true,
				data: { object: 'template', template: { status: 'unlocked' } },
			});
			expect((await fetch(`${base}/status`, { headers: { Origin: '' } })).status).toBe(403);
			expect((await fetch(`${base}/status`, { headers: { Host: 'attacker.example' } })).status).toBe(403);
			const folder = await (await call('/object/folder', 'POST', { name: 'REST folder' })).json();
			expect(folder.success).toBe(true);
			const folderId = folder.data.id;
			expect((await (await call(`/object/folder/${folderId}`, 'PUT', { name: 'REST renamed' })).json()).success).toBe(
				true,
			);
			const created = await (await call('/object/item', 'POST', {
				type: 1,
				name: 'REST login',
				folderId,
				login: { username: 'rest-user', password: '  rest-secret  ', uris: [] },
			})).json();
			expect(created.success).toBe(true);
			const itemId = created.data.id;
			expect(await (await call(`/object/password/${itemId}`)).json()).toMatchObject({
				data: { object: 'string', data: '  rest-secret  ' },
			});
			expect(await (await call('/list/object/items?search=REST')).json()).toMatchObject({
				data: { object: 'list', data: [{ id: itemId }] },
			});
			const bytes = new Uint8Array(262144).fill(171), form = new FormData();
			form.set('file', new Blob([bytes]), 'REST binary.bin');
			const uploaded = await (await fetch(`${base}/attachment?itemid=${itemId}`, { method: 'POST', body: form }))
				.json();
			expect(uploaded.success).toBe(true);
			const attachmentId = uploaded.data.attachments[0].id;
			const attachment = await call(`/object/attachment/${attachmentId}?itemid=${itemId}`);
			expect(attachment.headers.get('Content-Type')).toBe('application/octet-stream');
			expect(Buffer.from(await attachment.arrayBuffer()).equals(bytes)).toBe(true);
			expect((await (await call(`/object/attachment/${attachmentId}?itemid=${itemId}`, 'DELETE')).json()).success)
				.toBe(true);
			const send = await (await call('/object/send', 'POST', {
				type: 0,
				name: 'REST Send',
				deletionDate: new Date(Date.now() + 86400000).toISOString(),
				text: { text: 'REST payload' },
			}))
				.json();
			expect(send.success).toBe(true);
			expect(await (await call('/send/list')).json()).toMatchObject({ data: { data: [{ id: send.data.id }] } });
			expect((await (await call(`/object/send/${send.data.id}`, 'DELETE')).json()).success).toBe(true);
			expect((await (await call(`/archive/item/${itemId}`, 'POST')).json()).success).toBe(true);
			expect(await (await call('/list/object/items?archived=true')).json()).toMatchObject({
				data: { data: [{ id: itemId }] },
			});
			expect((await (await call(`/restore/item/${itemId}`, 'POST')).json()).success).toBe(true);
			await call('/lock', 'POST');
			expect((await call('/list/object/items')).status).toBe(400);
			expect((await call('/sync', 'POST')).status).toBe(200);
			expect((await call('/unlock?passwordEnv=HOME', 'POST', {})).status).toBe(400);
			const restUnlock = await call('/unlock', 'POST', { password });
			expect(restUnlock.status).toBe(200);
			const restSession = (await restUnlock.json()).data.raw as string;
			if (process.env.VW_TEST_BW) {
				// Use an independent profile. Remove 2FA only on this disposable account,
				// so the reference login does not need to replay our already consumed OTP.
				await client.api(initial.accessToken, 'DELETE', '/two-factor/authenticator', {
					masterPasswordHash: hash,
					key: secret,
					type: 0,
				});
				const ca = join(dir, 'reference-ca.pem'), keyPath = join(dir, 'reference-key.pem');
				const certificate = Bun.spawnSync([
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
				], { stdout: 'pipe', stderr: 'pipe' });
				if (certificate.exitCode !== 0) throw new Error('Could not generate test TLS certificate.');
				const proxy = Bun.serve({
					hostname: '127.0.0.1',
					port: 0,
					tls: { cert: Bun.file(ca), key: Bun.file(keyPath) },
					async fetch(request) {
						const target = new URL(request.url);
						const response = await fetch(`${server}${target.pathname}${target.search}`, {
							method: request.method,
							headers: { ...Object.fromEntries(request.headers), 'X-Forwarded-Proto': 'https' },
							body: ['GET', 'HEAD'].includes(request.method) ? undefined : await request.arrayBuffer(),
							redirect: 'manual',
						});
						return new Response(response.body, { status: response.status, headers: response.headers });
					},
				});
				try {
					const referenceDirectory = join(dir, 'reference');
					const official = async (args: string[], session?: string, importPassword?: string) => {
						const child = Bun.spawn([process.env.VW_TEST_BW!, ...args], {
							env: {
								PATH: process.env.PATH,
								BITWARDENCLI_APPDATA_DIR: referenceDirectory,
								BW_PASSWORD: password,
								NODE_EXTRA_CA_CERTS: ca,
								BW_SESSION: session,
								BW_IMPORT_PASSWORD: importPassword,
							},
							stdout: 'pipe',
							stderr: 'pipe',
							stdin: 'ignore',
						});
						const [code, stdout, stderr] = await Promise.all([
							child.exited,
							new Response(child.stdout).text(),
							new Response(child.stderr).text(),
						]);
						if (code) throw new Error(`Reference CLI failed: ${stderr}`);
						return stdout;
					};
					await official(['config', 'server', `https://127.0.0.1:${proxy.port}`]);
					const referenceSession =
						(await official(['login', email, '--passwordenv', 'BW_PASSWORD', '--raw', '--nointeraction'])).trim();
					const prefix = `csv${randomUUID().replaceAll('-', '').slice(0, 8)}`;
					const csvCases: { format: string; rows: string[][] }[] = [
						{
							format: 'chromecsv',
							rows: [['name', 'url', 'username', 'password', 'note'], [
								`${prefix} Chrome`,
								'https://example.com/a,b',
								'alice',
								'  csv-secret  ',
								'line1\nline2',
							], ['', `android://hash@com.${prefix}.app/`, 'app-user', 'app-secret', '']],
						},
						{
							format: 'firefoxcsv',
							rows: [['url', 'username', 'password'], [
								`https://www.${prefix}.example.com/login`,
								'alice',
								'csv-secret',
							], ['chrome://FirefoxAccounts', 'internal', 'ignored']],
						},
						{
							format: 'safaricsv',
							rows: [['Title', 'Url', 'Username', 'Password', 'Notes', 'OTPAuth'], [
								`${prefix} Safari`,
								'https://example.com',
								'alice',
								'csv-secret',
								'Safari notes',
								'otpauth://totp/example?secret=JBSWY3DPEHPK3PXP',
							]],
						},
						{
							format: 'keepassxcsv',
							rows: [['Group', 'Title', 'Username', 'Password', 'URL', 'Notes', 'TOTP'], [
								`Root/${prefix} Folder`,
								`${prefix} KeePass`,
								'alice',
								'csv-secret',
								'https://example.com/a,b',
								'KeePass notes',
								'JBSWY3DPEHPK3PXP',
							]],
						},
						{
							format: 'lastpasscsv',
							rows: [['url', 'username', 'password', 'extra', 'name', 'grouping', 'fav', 'totp'], [
								'https://example.com/a,b',
								'alice',
								'csv-secret',
								'Site notes',
								`${prefix} LastPass`,
								`${prefix} Folder`,
								'1',
								'JBSWY3DPEHPK3PXP',
							], [
								'http://sn',
								'',
								'',
								'NoteType:Credit Card\nNumber:4111111111111111\nName on Card:Alice\nSecurity Code:123\nExpiration Date:June,2030\nIssuer:Example\nNotes:card note\ncontinued:kept',
								`${prefix} Card`,
								`${prefix} Folder`,
								'0',
								'',
							], [
								'http://sn',
								'',
								'',
								'NoteType:Address\nFirst Name:Alice\nLast Name:Example\nUnknown:retained',
								`${prefix} Identity`,
								'(none)',
								'0',
								'',
							], ['http://sn', '', '', 'NoteType:Generic\nNotes:entire text', `${prefix} Note`, '(none)', '0', '']],
						},
						{
							format: 'lastpasscsv',
							rows: [['profilename', 'profilelanguage', 'ccname', 'ccnum', 'cccsc', 'ccexp'], [
								`${prefix} FormFill`,
								'en',
								'Alice',
								'4111111111111111',
								'123',
								'2030-06',
							]],
						},
					];
					for (const format of ['edgecsv', 'operacsv', 'vivaldicsv', 'bravecsv']) {
						csvCases.push({ format, rows: csvCases.find(value => value.format === 'chromecsv')!.rows });
					}
					csvCases.push({ format: 'passboltcsv', rows: csvCases.find(value => value.format === 'lastpasscsv')!.rows });
					csvCases.push({
						format: 'arccsv',
						rows: [['name', 'url', 'username', 'password', 'note'], [
							'Ignored title',
							`https://www.${prefix}.arc.example/a,b`,
							' alice ',
							'  arc-secret  ',
							'line1\nline2',
						]],
					});
					csvCases.push({
						format: 'aviracsv',
						rows: [['name', 'website', 'username', 'secondary_username', 'password'], [
							`${prefix} Avira`,
							'example.com/a,b',
							' alice ',
							'alternate@example.com',
							'  avira-secret  ',
						], ['', `https://www.${prefix}.avira.example/path`, ' ', ' alternate ', 'secret']],
					});
					const nordPassRecords: Record<string, string>[] = [
						{
							type: 'password',
							name: `${prefix} NordPass login`,
							username: ' alice ',
							password: '  nordpass-secret  ',
							url: 'example.com/a,b',
							additional_urls: JSON.stringify(['https://second.example', '']),
							folder: `\\${prefix} NordPass\\Web`,
							note: 'original notes',
							custom_fields: JSON.stringify([{ label: 'Hidden', type: 'hidden', value: ' literal ' }, {
								label: 'Long',
								type: 'text',
								value: 'x'.repeat(201),
							}, { label: 'Multiline', type: 'text', value: 'line1\r\nline2' }]),
						},
						{
							type: 'credit_card',
							name: `${prefix} NordPass card`,
							cardnumber: '4111111111111111',
							cardholdername: 'Alice',
							cvc: '123',
							expirydate: '06/30',
							folder: `${prefix} NordPass/Web`,
						},
						{
							type: 'identity',
							name: `${prefix} NordPass identity`,
							full_name: 'Alice Middle Last Name',
							address1: 'Street',
							address2: 'Unit',
							city: 'City',
							state: 'State',
							zipcode: '1234',
							country: 'nl',
							email: 'alice@example.com',
							phone_number: '123',
						},
						{ type: 'note', name: `${prefix} NordPass note`, note: 'first\nsecond' },
						{ type: 'unsupported', name: `${prefix} NordPass ignored`, folder: 'Ignored' },
					];
					const nordPassHeaders = [...new Set(nordPassRecords.flatMap(value => Object.keys(value)))];
					csvCases.push({
						format: 'nordpasscsv',
						rows: [nordPassHeaders, ...nordPassRecords.map(value => nordPassHeaders.map(key => value[key] ?? ''))],
					});
					const clean = (value: unknown): unknown =>
						Array.isArray(value) ? value.map(clean) : value && typeof value === 'object'
							? Object.fromEntries(
								Object.entries(value).filter(([, value]) => value != null).map(([key, value]) => [key, clean(value)]),
							)
							: value;
					const project = (items: Record<string, unknown>[], folders: Record<string, unknown>[]) =>
						items.map(item => {
							const login = item.login as Record<string, unknown> | undefined;
							return clean({
								name: item.name,
								type: item.type,
								notes: item.notes,
								favorite: item.favorite,
								reprompt: item.reprompt,
								passwordHistory: item.passwordHistory ?? [],
								archived: !!item.archivedDate,
								sshKey: item.sshKey
									? {
										publicKey: (item.sshKey as Record<string, unknown>).publicKey,
										keyFingerprint: (item.sshKey as Record<string, unknown>).keyFingerprint,
									}
									: undefined,
								fields: [...((item.fields ?? []) as Record<string, unknown>[])].sort((a, b) =>
									String(a.name).localeCompare(String(b.name))
								),
								folder: folders.find(folder => folder.id === item.folderId)?.name,
								login: login
									? {
										username: login.username,
										password: login.password,
										totp: login.totp,
										uris: (login.uris as Record<string, unknown>[] | undefined)?.map(uri => ({
											uri: uri.uri,
											match: uri.match,
										})) ?? [],
									}
									: undefined,
								secureNote: item.secureNote,
								card: item.card,
								identity: item.identity,
							});
						}).sort((a, b) =>
							String((a as Record<string, unknown>).name).localeCompare(String((b as Record<string, unknown>).name))
						);
					const importCases: {
						format: string;
						contents: string | Uint8Array;
						extension: string;
						search?: string;
						password?: string;
						keyFile?: string;
						compareNative?: boolean;
						archived?: boolean;
					}[] = csvCases.map(value => ({
						format: value.format,
						contents: writeCsv(value.rows),
						extension: 'csv',
					}));
					importCases.push({
						format: 'keepass2xml',
						extension: 'xml',
						contents: `<?xml version="1.0" encoding="utf-8"?>
<KeePassFile><Meta><Binaries><Binary ID="0">aWdub3JlZA==</Binary></Binaries></Meta><Root><Group><Name>Ignored root</Name>
<Entry><String><Key>Title</Key><Value>${prefix} XML root</Value></String><String><Key>Password</Key><Value>  xml-secret  </Value></String>
<History><Entry><String><Key>Title</Key><Value>${prefix} XML history must not import</Value></String></Entry></History></Entry>
<Group><Name>${prefix} XML folder</Name><Entry><String><Key>Title</Key><Value><![CDATA[${prefix} Café <login>]]></Value></String>
<String><Key>UserName</Key><Value>alice</Value></String><String><Key>URL</Key><Value>example.com/a,b</Value></String>
<String><Key>otp</Key><Value>key=JBSWY3DPEHPK3PXP</Value></String><String><Key>Notes</Key><Value>first&#10;second</Value></String>
<String><Key>Private</Key><Value ProtectInMemory="True">${'hidden\n' + 'x'.repeat(220)}</Value></String>
<String><Key>Multiline</Key><Value>line1&#10;line2</Value></String><String><Key>Literal</Key><Value>one&amp;two</Value></String></Entry>
<Group><Name>Nested</Name><Entry><String><Key>Title</Key><Value>${prefix} XML nested</Value></String></Entry></Group>
</Group><Group><Name/><Entry><String><Key>Title</Key><Value>${prefix} XML empty folder</Value></String></Entry></Group>
</Group></Root></KeePassFile>`,
					});
					for (const kind of ['aes3', 'aes4', 'argon2d', 'argon2id']) {
						const file = new URL(`./fixtures/kdbx/${kind}.kdbx`, import.meta.url);
						const key = kind === 'aes4' ? 'keyfile-v2.bin' : kind === 'argon2d' ? 'keyfile-raw.bin' : undefined;
						importCases.push({
							format: 'keepasskdbx',
							extension: 'kdbx',
							contents: await readFile(file),
							search: 'KDBX compatibility',
							password: kind === 'argon2d' ? undefined : 'synthetic-database-password',
							keyFile: key ? new URL(`./fixtures/kdbx/${key}`, import.meta.url).pathname : undefined,
							compareNative: kind !== 'argon2d',
						});
					}
					importCases.push({
						format: '1password1pux',
						extension: '1pux',
						search: '1PUX compatibility',
						archived: true,
						contents: await readFile(new URL('./fixtures/onepassword/synthetic.1pux', import.meta.url)),
					});
					const selected = process.env.VW_TEST_IMPORT_FORMAT?.split(',');
					for (
						const [format, file, search] of [
							['1password1pif', 'legacy.1pif', '1PIF compatibility'],
							['1passwordmaccsv', 'mac.csv', 'Legacy CSV compatibility'],
							['1passwordwincsv', 'windows.csv', 'Legacy CSV compatibility'],
						]
					) {
						importCases.push({
							format: format!,
							extension: file!.split('.').at(-1)!,
							search,
							contents: await readFile(new URL(`./fixtures/onepassword/${file}`, import.meta.url)),
						});
					}
					if (selected?.some(format => !importCases.some(value => value.format === format))) {
						throw new Error('Unknown test import format.');
					}
					for (const [index, importCase] of importCases.entries()) {
						if (selected && !selected.includes(importCase.format)) continue;
						const search = importCase.search ?? prefix;
						const input = join(dir, `external-${index}.${importCase.extension}`);
						await writeFile(input, importCase.contents, { mode: 0o600 });
						const credentials = importCase.keyFile ? ['--keyfile', importCase.keyFile] : [];
						const imported = await run(
							['import', importCase.format, input, '--session', restSession, ...credentials],
							importCase.password,
						);
						if (imported.code) throw new Error(`External import failed (${importCase.format}): ${imported.stderr}`);
						const own = (await (await call(`/list/object/items?search=${encodeURIComponent(search)}`)).json()).data
							.data as Record<
								string,
								unknown
							>[];
						if (importCase.archived) {
							own.push(
								...(await (await call(`/list/object/items?archived=true&search=${encodeURIComponent(search)}`)).json())
									.data.data,
							);
							expect(own).toHaveLength(11);
							expect(JSON.parse(imported.stdout).errors).toEqual([{ id: 'bad-ssh', reason: 'sshKeyParseFailed' }]);
						}
						const ownFolders = (await (await call('/list/object/folders')).json()).data.data as Record<
							string,
							unknown
						>[];
						const expected = project(own, ownFolders);
						if (importCase.format === 'keepasskdbx') expect(own).toHaveLength(2);
						for (const item of own) {
							expect((await run(['delete', 'item', String(item.id), '--permanent', '--session', restSession])).code)
								.toBe(0);
						}
						const ownFolderIds = new Set(own.map(item => item.folderId).filter(Boolean));
						for (
							const folder of ownFolders.filter(folder =>
								String(folder.name).includes(search) || ownFolderIds.has(folder.id)
							)
						) {
							expect((await run(['delete', 'folder', String(folder.id), '--session', restSession])).code).toBe(0);
						}
						// The reference CLI requires a nonempty password before calling its SDK.
						if (importCase.compareNative === false) continue;
						const passwordArgs = importCase.password ? ['--passwordenv', 'BW_IMPORT_PASSWORD', '--nointeraction'] : [];
						await official(
							['import', importCase.format, input, ...credentials, ...passwordArgs],
							referenceSession,
							importCase.password,
						);
						const native = JSON.parse(await official(['list', 'items', '--search', search], referenceSession));
						if (importCase.archived) {
							native.push(
								...JSON.parse(await official(['list', 'items', '--archived', '--search', search], referenceSession)),
							);
						}
						const nativeFolders = JSON.parse(await official(['list', 'folders'], referenceSession));
						expect(project(native, nativeFolders)).toEqual(expected);
						const nativeFolderIds = new Set(
							native.map((item: Record<string, unknown>) => item.folderId).filter(Boolean),
						);
						for (const item of native) await official(['delete', 'item', item.id, '--permanent'], referenceSession);
						for (
							const folder of nativeFolders.filter((folder: Record<string, unknown>) =>
								String(folder.name).includes(search) || nativeFolderIds.has(folder.id)
							)
						) await official(['delete', 'folder', folder.id], referenceSession);
					}
					const reservation = createServer();
					await new Promise<void>(resolve => reservation.listen(0, '127.0.0.1', resolve));
					const address = reservation.address();
					if (!address || typeof address === 'string') throw new Error('Missing reference listener address.');
					const referencePort = address.port;
					await new Promise<void>(resolve => reservation.close(() => resolve()));
					const reference = Bun.spawn([
						process.env.VW_TEST_BW!,
						'serve',
						'--hostname',
						'127.0.0.1',
						'--port',
						String(referencePort),
					], {
						env: {
							PATH: process.env.PATH,
							BITWARDENCLI_APPDATA_DIR: referenceDirectory,
							BW_SESSION: referenceSession,
							NODE_EXTRA_CA_CERTS: ca,
						},
						stdout: 'pipe',
						stderr: 'pipe',
						stdin: 'ignore',
					});
					const referenceOut = new Response(reference.stdout).text(),
						referenceError = new Response(reference.stderr).text();
					const referenceBase = `http://127.0.0.1:${referencePort}`;
					try {
						const deadline = Date.now() + 15000;
						let ready = false;
						while (Date.now() < deadline) {
							try {
								if ((await fetch(`${referenceBase}/status`)).ok) {
									ready = true;
									break;
								}
							} catch { /* Wait for the known child to bind. */ }
							await Bun.sleep(50);
						}
						expect(ready).toBe(true);
						const nativeStatus = await (await fetch(`${referenceBase}/status`)).json();
						const ownStatus = await (await call('/status')).json();
						expect(ownStatus.data.object).toBe(nativeStatus.data.object);
						expect(ownStatus.data.template.status).toBe(nativeStatus.data.template.status);
						const nativeItem = await (await fetch(`${referenceBase}/object/item/${itemId}`)).json();
						const ownItem = await (await call(`/object/item/${itemId}`)).json();
						expect(ownItem.data.object).toBe(nativeItem.data.object);
						expect(ownItem.data.id).toBe(nativeItem.data.id);
						expect(ownItem.data.login.password).toBe(nativeItem.data.login.password);
						expect(ownItem.data).toEqual(nativeItem.data);
						expect(
							await (await call(`/object/item/${itemId}`, 'PUT', { ...ownItem.data, name: 'REST revision round-trip' }))
								.json(),
						).toMatchObject({ success: true, data: { name: 'REST revision round-trip' } });
						expect(await (await call(`/object/password/${itemId}`)).json()).toEqual(
							await (await fetch(`${referenceBase}/object/password/${itemId}`)).json(),
						);
						const fileSend = {
							type: 1,
							name: 'Unsupported through REST',
							deletionDate: new Date(Date.now() + 86400000).toISOString(),
							file: { fileName: '/etc/passwd' },
						};
						const nativeRejected = await fetch(`${referenceBase}/object/send`, {
							method: 'POST',
							headers: { 'Content-Type': 'application/json' },
							body: JSON.stringify(fileSend),
						});
						const ownRejected = await call('/object/send', 'POST', fileSend);
						expect(ownRejected.status).toBe(nativeRejected.status);
						expect(await ownRejected.json()).toEqual(await nativeRejected.json());
					} finally {
						reference.kill('SIGTERM');
						await reference.exited;
						await referenceOut;
						await referenceError;
					}
				} finally {
					proxy.stop(true);
				}
			}
			expect((await call(`/object/item/${itemId}?permanent=true`, 'DELETE')).status).toBe(200);
			expect((await call(`/object/folder/${folderId}`, 'DELETE')).status).toBe(200);
		} finally {
			clearTimeout(deadline);
			serving.kill('SIGTERM');
			await serving.exited;
			await stderr;
			await stdout;
		}
		expect((await run(['config', 'server', server!])).code).toBe(1);
		expect((await run(['logout'])).code).toBe(0);
	} finally {
		userKey.fill(0);
		await rm(dir, { recursive: true, force: true });
	}
}, 600000);
