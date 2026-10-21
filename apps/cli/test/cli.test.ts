import { expect, test } from 'bun:test';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:http';
import { sealSession, withStore } from '#store';
import { deriveMasterKey, deriveSendKey, encrypt, encryptItem, stretchKey } from '@kjanat/vaultwarden';

const executable = new URL('../dist/main.js', import.meta.url).pathname;
async function run(
	dir: string,
	args: string[],
	environment: Record<string, string> = {},
	stdinData?: string,
) {
	const child = Bun.spawn(['node', executable, ...args], {
		env: { PATH: process.env.PATH, VW_APPDATA_DIR: dir, ...environment },
		stdin: stdinData === undefined ? 'ignore' : 'pipe',
		stdout: 'pipe',
		stderr: 'pipe',
	});
	if (stdinData !== undefined) {
		if (!child.stdin) throw new Error('Expected a writable CLI stdin.');
		child.stdin.write(stdinData);
		child.stdin.end();
	}
	return {
		code: await child.exited,
		stdout: await new Response(child.stdout).text(),
		stderr: await new Response(child.stderr).text(),
	};
}
test('built Node CLI exposes DreamCLI help and validates commands', { timeout: 15000 }, async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-cli-'));
	try {
		const help = await run(dir, ['--help']);
		expect(help.code).toBe(0);
		expect(help.stdout).toContain('Vaultwarden-first');
		const commandHelp = await run(dir, ['help', 'config']);
		expect(commandHelp.code).toBe(0);
		expect(commandHelp.stdout).toContain('Usage: vw config');
		const loginHelp = await run(dir, ['login', '--help']);
		expect(loginHelp.code).toBe(0);
		expect(loginHelp.stdout).toContain('Two-factor provider: 0=TOTP, 1=email, 2=Duo,');
		expect(loginHelp.stdout).toContain('3=YubiKey, 7=WebAuthn');
		const globalRaw = await run(dir, ['--raw', 'generate', '--length', '5']);
		expect(globalRaw.code).toBe(0);
		expect(globalRaw.stdout.trim()).toHaveLength(5);
		const noInteraction = await run(dir, ['generate', '--nointeraction', '--length', '5']);
		expect(noInteraction.code).toBe(0);
		expect(noInteraction.stdout.trim()).toHaveLength(5);
		const directCommandNoInteraction = await run(dir, ['sdk-version', '--nointeraction']);
		expect(directCommandNoInteraction.code).toBe(0);
		const protectedImport = join(dir, 'protected.json');
		await writeFile(protectedImport, JSON.stringify({ passwordProtected: true }));
		await withStore(dir, async (state, save) => {
			state.account = {
				email: 'synthetic@example.test',
				kdf: { type: 0, iterations: 10000 },
				encryptedUserKey: 'synthetic-wrapped-key',
				accessToken: 'synthetic-token',
				refreshToken: 'synthetic-refresh',
				expiresAt: Date.now() + 3600000,
			};
			await save();
		});
		for (
			const [args, environment] of [
				[['import', 'bitwardenjson', protectedImport, '--nointeraction'], {}],
				[['import', 'bitwardenjson', protectedImport], { BW_NOINTERACTION: 'true' }],
			] as const
		) {
			const result = await run(dir, [...args], environment);
			expect(result.code).toBe(1);
			expect(result.stderr).toContain(
				'Import file password is required. Provide --passwordfile or --passwordenv, or run interactively.',
			);
		}
		const keepassWithoutPassword = await run(dir, [
			'import',
			'keepasskdbx',
			protectedImport,
			'--nointeraction',
		]);
		expect(keepassWithoutPassword.code).toBe(1);
		expect(keepassWithoutPassword.stderr).toContain('Master password is required.');
		const unknownGet = await run(dir, ['get', 'unsupported-object', 'synthetic-id']);
		expect(unknownGet.code).toBe(1);
		expect(unknownGet.stderr).toContain('Unknown object.');
		const unknownList = await run(dir, ['list', 'unsupported-object']);
		expect(unknownList.code).toBe(1);
		expect(unknownList.stderr).toContain('Unknown object.');
		const unknownEdit = await run(dir, [
			'edit',
			'unsupported-object',
			'synthetic-id',
			Buffer.from('{}').toString('base64'),
		]);
		expect(unknownEdit.code).toBe(1);
		expect(unknownEdit.stderr).toContain('Unknown object.');
		const unknownRestore = await run(dir, ['restore', 'unsupported-object', 'synthetic-id']);
		expect(unknownRestore.code).toBe(1);
		expect(unknownRestore.stderr).toContain('Unknown object.');
		await withStore(dir, async (state, save) => {
			delete state.account;
			await save();
		});
		const uppercaseObject = await run(dir, ['--raw', 'get', 'TEMPLATE', 'ITEM']);
		expect(uppercaseObject.code).toBe(1);
		expect(uppercaseObject.stderr).toContain('You are not logged in.');
		const moveHelp = await run(dir, ['move', '--help']);
		expect(moveHelp.code).toBe(0);
		expect(moveHelp.stdout).toContain('[encodedJson]');
		const exportHelp = await run(dir, ['export', '--help']);
		expect(exportHelp.code).toBe(0);
		expect(exportHelp.stdout).toContain('[password]');
		const editHelp = await run(dir, ['edit', '--help']);
		expect(editHelp.code).toBe(0);
		expect(editHelp.stdout).toContain('[encodedJson]');
		const editWithoutJson = await run(dir, ['edit', 'item', 'item-id']);
		expect(editWithoutJson.code).toBe(1);
		expect(editWithoutJson.stderr).toContain('You are not logged in.');
		const createWithoutJson = await run(dir, ['create', 'folder']);
		expect(createWithoutJson.code).toBe(1);
		expect(createWithoutJson.stderr).toContain('You are not logged in.');
		const positionalExportPassword = await run(dir, ['export', 'synthetic-export-secret', '--format', 'json']);
		expect(positionalExportPassword.code).toBe(1);
		expect(positionalExportPassword.stderr).toContain('You are not logged in.');
		expect(positionalExportPassword.stderr).not.toContain('synthetic-export-secret');
		const createAttachmentWithoutItem = await run(dir, ['create', 'attachment']);
		expect(createAttachmentWithoutItem.code).toBe(1);
		expect(createAttachmentWithoutItem.stderr).toContain('You are not logged in.');
		const createAttachmentWithoutFile = await run(dir, ['create', 'attachment', '--itemid', 'item-id']);
		expect(createAttachmentWithoutFile.code).toBe(1);
		expect(createAttachmentWithoutFile.stderr).toContain('You are not logged in.');
		const createAttachmentMissingFile = await run(dir, [
			'create',
			'attachment',
			'--itemid',
			'item-id',
			'--file',
			join(dir, 'missing-attachment-file'),
		]);
		expect(createAttachmentMissingFile.code).toBe(1);
		expect(createAttachmentMissingFile.stderr).toContain('You are not logged in.');
		const invalidEditJson = await run(dir, ['edit', 'item', 'item-id', 'not-base64']);
		expect(invalidEditJson.code).toBe(1);
		expect(invalidEditJson.stderr).toContain('You are not logged in.');
		for (const args of [['send', 'create'], ['send', 'edit']]) {
			const result = await run(dir, args);
			expect(result.code).toBe(1);
			expect(result.stderr).toContain('You are not logged in.');
		}
		const invalidSendJson = await run(dir, ['send', 'create', 'not-base64']);
		expect(invalidSendJson.code).toBe(1);
		expect(invalidSendJson.stderr).toContain('You are not logged in.');
		const emptyShare = await run(dir, ['share', 'item-id', 'organization-id']);
		expect(emptyShare.code).toBe(1);
		expect(emptyShare.stderr).toContain('You are not logged in.');
		const organizationId = '11111111-1111-1111-1111-111111111111';
		const organizationCollection = Buffer.from(JSON.stringify({ organizationId, name: 'Synthetic collection' }))
			.toString('base64');
		const createWithBodyOrganization = await run(dir, ['create', 'org-collection', organizationCollection]);
		expect(createWithBodyOrganization.code).toBe(1);
		expect(createWithBodyOrganization.stderr).toContain('You are not logged in.');
		expect(createWithBodyOrganization.stderr).not.toContain('organization id is required');
		const createWithoutOrganization = await run(
			dir,
			['create', 'org-collection', Buffer.from(JSON.stringify({ name: 'No organization' })).toString('base64')],
		);
		expect(createWithoutOrganization.code).toBe(1);
		expect(createWithoutOrganization.stderr).toContain('You are not logged in.');
		const editWithBodyOrganization = await run(dir, [
			'edit',
			'org-collection',
			'22222222-2222-2222-2222-222222222222',
			organizationCollection,
		]);
		expect(editWithBodyOrganization.code).toBe(1);
		expect(editWithBodyOrganization.stderr).toContain('You are not logged in.');
		const invalidDeleteId = await run(dir, [
			'delete',
			'org-collection',
			'not-a-guid',
			'--organizationid',
			organizationId,
		]);
		expect(invalidDeleteId.code).toBe(1);
		expect(invalidDeleteId.stderr).toContain('You are not logged in.');
		const missingAttachmentItem = await run(dir, ['delete', 'attachment', 'attachment-id']);
		expect(missingAttachmentItem.code).toBe(1);
		expect(missingAttachmentItem.stderr).toContain('You are not logged in.');
		const missingDeleteOrganization = await run(dir, [
			'delete',
			'org-collection',
			'22222222-2222-2222-2222-222222222222',
		]);
		expect(missingDeleteOrganization.code).toBe(1);
		expect(missingDeleteOrganization.stderr).toContain('You are not logged in.');
		const invalidDeleteOrganization = await run(dir, [
			'delete',
			'org-collection',
			'22222222-2222-2222-2222-222222222222',
			'--organizationid',
			'not-a-guid',
		]);
		expect(invalidDeleteOrganization.code).toBe(1);
		expect(invalidDeleteOrganization.stderr).toContain('You are not logged in.');
		const missingListOrganization = await run(dir, ['list', 'org-members']);
		expect(missingListOrganization.code).toBe(1);
		expect(missingListOrganization.stderr).toContain('You are not logged in.');
		const invalidListOrganization = await run(dir, ['list', 'org-collections', '--organizationid', 'not-a-guid']);
		expect(invalidListOrganization.code).toBe(1);
		expect(invalidListOrganization.stderr).toContain('You are not logged in.');
		const missingGetOrganization = await run(dir, [
			'get',
			'org-collection',
			'22222222-2222-2222-2222-222222222222',
		]);
		expect(missingGetOrganization.code).toBe(1);
		expect(missingGetOrganization.stderr).toContain('You are not logged in.');
		const conflictingOrganization = await run(dir, [
			'edit',
			'org-collection',
			'22222222-2222-2222-2222-222222222222',
			organizationCollection,
			'--organizationid',
			'33333333-3333-3333-3333-333333333333',
		]);
		expect(conflictingOrganization.code).toBe(1);
		expect(conflictingOrganization.stderr).toContain('You are not logged in.');
		const reportHelp = await run(dir, ['report', '--help']);
		expect(reportHelp.code).toBe(0);
		expect(reportHelp.stdout).toContain('--no-check-exposed');
		expect(reportHelp.stdout).not.toContain('[no-]check-exposed');
		const config = await run(dir, [
			'config',
			'server',
			'https://example.com/vault/',
		]);
		expect(config.code).toBe(0);
		expect(config.stdout.trim()).toBe('Saved setting `config`.');
		expect((await run(dir, ['config', 'server'])).stdout.trim()).toBe('https://example.com/vault');
		const shorthand = await run(dir, ['config', 'server', 'bitwarden.com']);
		expect(shorthand.code).toBe(0);
		expect(shorthand.stdout.trim()).toBe('Saved setting `config`.');
		expect((await run(dir, ['config', 'server'])).stdout.trim()).toBe('https://bitwarden.com');
		const status = await run(dir, ['status']);
		expect(JSON.parse(status.stdout).status).toBe('unauthenticated');
		expect((await run(dir, ['list', 'items'])).code).toBe(1);
		expect((await run(dir, ['list', 'items', '--cleanexit'])).code).toBe(0);
		expect((await run(dir, ['--cleanexit', 'list', 'items'])).code).toBe(0);
		expect((await run(dir, ['list', 'items', '--cleanexit=false'])).code).toBe(1);
		expect((await run(dir, ['list', 'items'], { BW_CLEANEXIT: 'true' })).code).toBe(0);
		expect(
			(await run(dir, ['config', 'server', 'http://example.com'])).code,
		).toBe(1);
		expect((await run(dir, ['unknown'])).code).not.toBe(0);
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test('get templates require login but do not require an unlocked vault', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-template-login-'));
	try {
		const loggedOut = await run(dir, ['get', 'template', 'item']);
		expect(loggedOut.code).toBe(1);
		expect(loggedOut.stderr).toContain('You are not logged in.');
		await withStore(dir, async (state, save) => {
			state.account = {
				email: 'synthetic@example.test',
				kdf: { type: 0, iterations: 10000 },
				encryptedUserKey: 'synthetic-wrapped-key',
				accessToken: 'synthetic-token',
				refreshToken: 'synthetic-refresh',
				expiresAt: Date.now() + 3600000,
			};
			await save();
		});
		const item = await run(dir, ['--raw', 'get', 'TEMPLATE', 'ITEM']);
		expect(item.code).toBe(0);
		expect(JSON.parse(item.stdout)).toMatchObject({ type: 1, name: 'Item name' });
		const collection = await run(dir, ['get', 'template', 'collection']);
		expect(JSON.parse(collection.stdout)).toEqual({
			organizationId: '00000000-0000-0000-0000-000000000000',
			name: 'Collection name',
			externalId: null,
		});
		const secureNote = await run(dir, ['get', 'template', 'item.secureNote']);
		expect(JSON.parse(secureNote.stdout)).toEqual({ type: 0 });
		const collections = await run(dir, ['get', 'template', 'item-collections']);
		expect(JSON.parse(collections.stdout)).toEqual(['collection-id1', 'collection-id2']);
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test('global nointeraction prevents the password prompt for a protected Send', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-send-nointeraction-'));
	let requests = 0;
	const server = createServer((_request, response) => {
		requests++;
		response.writeHead(400, { 'Content-Type': 'application/json' });
		response.end(JSON.stringify({ send_access_error_type: 'password_hash_b64_required' }));
	});
	await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
	const address = server.address();
	if (!address || typeof address === 'string') throw new Error('Missing fixture address.');
	try {
		const url = `http://127.0.0.1:${address.port}/#/send/${Buffer.alloc(16, 9).toString('base64url')}/${
			Buffer.alloc(16, 1).toString('base64url')
		}`;
		const result = await run(dir, ['--nointeraction', 'receive', url]);
		expect(result.code).toBe(1);
		expect(result.stderr).toContain('Password required');
		expect(result.stderr).not.toContain('Send password:');
		expect(requests).toBe(1);
	} finally {
		await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
		await rm(dir, { recursive: true, force: true });
	}
});

test('quiet suppresses JSON, text, and command errors while preserving operations, help, and exit codes', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-quiet-'));
	try {
		for (
			const args of [['--quiet', 'status'], ['generate', '--quiet'], [
				'send',
				'template',
				'text',
				'--quiet',
			]]
		) {
			expect(await run(dir, args)).toEqual({ code: 0, stdout: '', stderr: '' });
		}
		expect(await run(dir, ['get', 'template', 'item', '--quiet'])).toEqual({
			code: 1,
			stdout: '',
			stderr: '',
		});
		expect(await run(dir, ['config', 'server', 'https://example.com/vault', '--quiet'])).toEqual({
			code: 0,
			stdout: '',
			stderr: '',
		});
		expect((await run(dir, ['config', 'server'])).stdout.trim()).toBe('https://example.com/vault');
		expect(await run(dir, ['list', 'items', '--quiet'])).toEqual({ code: 1, stdout: '', stderr: '' });
		expect((await run(dir, ['list', 'items', '--quiet=false'])).stderr).toContain('You are not logged in.');
		const parseError = await run(dir, ['generate', '--unknown-fixture-flag', '--quiet']);
		expect(parseError.code).not.toBe(0);
		expect(parseError.stderr).toContain('unknown-fixture-flag');
		expect(await run(dir, ['status'], { VW_QUIET: 'true' })).toEqual({ code: 0, stdout: '', stderr: '' });
		expect(await run(dir, ['status'], { BW_QUIET: 'true' })).toEqual({ code: 0, stdout: '', stderr: '' });
		expect((await run(dir, ['status', '--quiet=false'], { VW_QUIET: 'true' })).stdout).toContain('unauthenticated');
		expect((await run(dir, ['--quiet', '--help'])).stdout).toContain('Vaultwarden-first');
		expect((await run(dir, ['--quiet', '--version'])).stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
		expect((await run(dir, ['encode', '--', '--quiet'])).stdout.trim()).toBe(Buffer.from('--quiet').toString('base64'));
		const encoded = await run(dir, ['encode'], {}, '  piped text\n');
		expect(encoded.stdout.trim()).toBe(Buffer.from('  piped text\n').toString('base64'));
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});
test('get misses use bw not-found text; quiet suppresses secrets without changing the cache', async () => {
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
				profile: { id: 'abcdef02-0000-0000-0000-000000000002' },
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
		const missing = await run(dir, [
			'get',
			'item',
			'abcdef01-ffff-ffff-ffff-ffffffffffff',
			'--session',
			session,
		]);
		expect(missing.code).toBe(1);
		expect(missing.stderr).toContain('Not found.');
		const emptyId = await run(dir, ['get', 'item', '', '--session', session]);
		expect(emptyId.code).toBe(1);
		expect(emptyId.stderr).toContain('Not found.');
		const attachmentWithoutItem = await run(dir, ['get', 'attachment', 'file.bin']);
		expect(attachmentWithoutItem.code).toBe(1);
		expect(attachmentWithoutItem.stderr).toContain('--itemid <itemid> required.');
		const fingerprintWithoutKey = await run(dir, ['get', 'fingerprint', 'me', '--session', session]);
		expect(fingerprintWithoutKey.code).toBe(1);
		expect(fingerprintWithoutKey.stderr).toContain('No public key available for the active user.');
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

test('CLI responses redact secrets when Vaultwarden denies password visibility', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-hidden-passwords-'));
	const key = Buffer.alloc(64, 23), id = 'abcdef02-0000-0000-0000-000000000002';
	const secrets = [
		'hidden-password-sentinel',
		'hidden-totp-sentinel',
		'hidden-field-sentinel',
		'hidden-history-sentinel',
	];
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
				profile: { id: 'synthetic-user', premium: false, premiumPersonally: false, premiumFromOrganization: false },
				policies: [{ organizationId: 'synthetic-org', type: 15, enabled: true, data: [3] }],
				folders: [],
				collections: [],
				ciphers: [{
					...encryptItem({
						type: 1,
						name: 'Restricted item',
						login: { password: secrets[0], totp: secrets[1] },
						fields: [{ name: 'hidden', value: secrets[2], type: 1 }],
						passwordHistory: [{ password: secrets[3], lastUsedDate: '2026-01-01T00:00:00Z' }],
					}, key),
					id,
					viewPassword: false,
				}, {
					...encryptItem({ type: 3, name: 'Restricted card', card: { number: 'restricted-card-sentinel' } }, key),
					id: 'restricted-card',
				}, {
					...encryptItem({
						type: 1,
						name: 'Visible item',
						login: { username: 'visible-user', password: 'visible-password' },
					}, key),
					id: 'visible-item',
				}, {
					...encryptItem({
						type: 1,
						name: 'TOTP item',
						login: { totp: 'JBSWY3DPEHPK3PXP' },
					}, key),
					id: 'totp-item',
				}],
			};
			session = sealSession(state, key);
			await save();
		});
		for (const args of [['list', 'items'], ['get', 'item', id]]) {
			const result = await run(dir, [...args, '--session', session]);
			expect(result.code).toBe(0);
			for (const secret of secrets) expect(result.stdout).not.toContain(secret);
			expect(result.stdout).not.toContain('"key"');
		}
		for (const object of ['password', 'totp', 'exposed']) {
			const result = await run(dir, ['get', object, id, '--session', session]);
			expect(result.code).toBe(1);
			for (const secret of secrets) expect(`${result.stdout}${result.stderr}`).not.toContain(secret);
		}
		const listed = await run(dir, ['list', 'items', '--session', session]);
		expect(listed.code).toBe(0);
		expect(listed.stdout).not.toContain('restricted-card-sentinel');
		const restricted = await run(dir, ['get', 'item', 'restricted-card', '--session', session]);
		expect(restricted.code).toBe(1);
		expect(restricted.stderr).toContain('Access to this item type is restricted by organizational policy.');
		const noPremiumTotp = await run(dir, ['get', 'totp', 'totp-item', '--session', session]);
		expect(noPremiumTotp.code).toBe(1);
		expect(noPremiumTotp.stderr).toContain('Premium status is required to use this feature.');
		const secretResponse = await run(dir, [
			'--response',
			'--pretty',
			'get',
			'password',
			'visible-item',
			'--session',
			session,
		]);
		expect(secretResponse.code).toBe(0);
		expect(JSON.parse(secretResponse.stdout)).toEqual({
			success: true,
			data: { object: 'string', data: 'visible-password' },
		});
	} finally {
		key.fill(0);
		await rm(dir, { recursive: true, force: true });
	}
});

test('list applies organization and search filters only where bw supports them', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-list-filters-'));
	const key = Buffer.alloc(64, 41);
	const organizationId = '11111111-1111-1111-1111-111111111111';
	const paths: string[] = [];
	const server = createServer((request, response) => {
		paths.push(request.url!);
		response.setHeader('Content-Type', 'application/json');
		response.end(JSON.stringify({
			data: [{
				object: 'unexpected-upstream-tag',
				id: 'member-id',
				email: 'member@example.test',
				name: 'Synthetic member',
				status: 2,
				type: 0,
				twoFactorEnabled: true,
				internalField: 'must not escape response projection',
			}],
		}));
	});
	await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
	const address = server.address();
	if (!address || typeof address === 'string') throw new Error('Missing fixture address.');
	try {
		let session = '';
		await withStore(dir, async (state, save) => {
			state.server = `http://127.0.0.1:${address.port}`;
			state.account = {
				email: 'synthetic@example.test',
				kdf: { type: 0, iterations: 10000 },
				encryptedUserKey: 'synthetic-wrapped-key',
				accessToken: 'synthetic-token',
				refreshToken: 'synthetic-refresh',
				expiresAt: Date.now() + 3600000,
			};
			state.vault = {
				profile: {
					id: 'synthetic-user',
					organizations: [
						{
							id: organizationId,
							name: 'First organization',
							email: 'billing@example.test',
							key: 'private-key',
						},
						{ id: '22222222-2222-2222-2222-222222222222', name: 'Second organization', key: 'private-key' },
					],
				},
				folders: [{
					id: 'folder-id',
					name: encrypt(Buffer.from('Private folder'), key),
					revisionDate: '2026-01-01T00:00:00.000Z',
					internalField: 'must not escape response projection',
				}],
				collections: [{
					id: 'collection-id',
					name: encrypt(Buffer.from('Private collection'), key),
					organizationId: null,
					externalId: null,
					manage: true,
					internalField: 'must not escape response projection',
				}],
				ciphers: [],
			};
			session = sealSession(state, key);
			await save();
		});
		const folders = await run(dir, ['list', 'folders', '--organizationid', 'missing', '--session', session]);
		expect(folders.code).toBe(0);
		expect(JSON.parse(folders.stdout).map((folder: { name: string }) => folder.name)).toEqual(['Private folder']);
		const whitespaceSearchFolders = await run(dir, ['list', 'folders', '--search', '   ', '--session', session]);
		expect(whitespaceSearchFolders.code).toBe(0);
		expect(JSON.parse(whitespaceSearchFolders.stdout).map((folder: { name: string }) => folder.name)).toEqual([
			'Private folder',
		]);
		const folderResponse = await run(dir, ['--response', 'list', 'folders', '--session', session]);
		expect(JSON.parse(folderResponse.stdout)).toEqual({
			success: true,
			data: { object: 'list', data: [{ object: 'folder', id: 'folder-id', name: 'Private folder' }] },
		});
		const collectionResponse = await run(dir, ['--response', 'list', 'collections', '--session', session]);
		expect(JSON.parse(collectionResponse.stdout)).toEqual({
			success: true,
			data: {
				object: 'list',
				data: [{
					object: 'collection',
					id: 'collection-id',
					organizationId: null,
					name: 'Private collection',
					externalId: null,
				}],
			},
		});
		for (
			const [object, id, expected] of [
				['folder', 'Private folder', { object: 'folder', id: 'folder-id', name: 'Private folder' }],
				[
					'collection',
					'Private collection',
					{
						object: 'collection',
						id: 'collection-id',
						organizationId: null,
						name: 'Private collection',
						externalId: null,
					},
				],
				[
					'organization',
					'first organization',
					{ object: 'organization', id: organizationId, name: 'First organization' },
				],
			] as const
		) {
			const result = await run(dir, ['--response', 'get', object, id, '--session', session]);
			expect(result.code).toBe(0);
			expect(JSON.parse(result.stdout)).toEqual({ success: true, data: expected });
		}
		const organizations = await run(dir, [
			'list',
			'organizations',
			'--organizationid',
			organizationId,
			'--session',
			session,
		]);
		expect(organizations.code).toBe(0);
		expect(JSON.parse(organizations.stdout)).toHaveLength(2);
		const organizationResponse = await run(dir, [
			'--response',
			'list',
			'organizations',
			'--session',
			session,
		]);
		expect(JSON.parse(organizationResponse.stdout)).toEqual({
			success: true,
			data: {
				object: 'list',
				data: [
					{ object: 'organization', id: organizationId, name: 'First organization' },
					{ object: 'organization', id: '22222222-2222-2222-2222-222222222222', name: 'Second organization' },
				],
			},
		});
		const organizationEmailSearch = await run(dir, [
			'list',
			'organizations',
			'--search',
			'billing@example.test',
			'--session',
			session,
		]);
		expect(JSON.parse(organizationEmailSearch.stdout)).toEqual([]);
		const organizationNameSearch = await run(dir, [
			'list',
			'organizations',
			'--search',
			'first organization',
			'--session',
			session,
		]);
		expect(JSON.parse(organizationNameSearch.stdout)).toHaveLength(1);
		const members = await run(dir, [
			'list',
			'org-members',
			'--organizationid',
			organizationId,
			'--search',
			'no-match',
			'--session',
			session,
		]);
		expect(members.code).toBe(0);
		expect(JSON.parse(members.stdout)).toEqual([{
			object: 'unexpected-upstream-tag',
			id: 'member-id',
			email: 'member@example.test',
			name: 'Synthetic member',
			status: 2,
			type: 0,
			twoFactorEnabled: true,
			internalField: 'must not escape response projection',
		}]);
		const memberResponse = await run(dir, [
			'--response',
			'list',
			'org-members',
			'--organizationid',
			organizationId,
			'--session',
			session,
		]);
		expect(memberResponse.code).toBe(0);
		expect(JSON.parse(memberResponse.stdout)).toEqual({
			success: true,
			data: {
				object: 'list',
				data: [{
					object: 'org-member',
					id: 'member-id',
					email: 'member@example.test',
					name: 'Synthetic member',
					status: 2,
					type: 0,
					twoFactorEnabled: true,
				}],
			},
		});
		expect(paths).toEqual([
			`/api/organizations/${organizationId}/users`,
			`/api/organizations/${organizationId}/users`,
		]);
		for (const [id, org] of [['not-a-guid', organizationId], ['00000000-0000-0000-0000-000000000001', 'not-a-guid']]) {
			const invalidCollection = await run(dir, [
				'get',
				'org-collection',
				id!,
				'--organizationid',
				org!,
				'--session',
				session,
			]);
			expect(invalidCollection.code).toBe(1);
			expect(invalidCollection.stderr).toContain('is not a GUID.');
		}
		expect(paths).toEqual([
			`/api/organizations/${organizationId}/users`,
			`/api/organizations/${organizationId}/users`,
		]);
	} finally {
		key.fill(0);
		server.closeAllConnections();
		await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
		await rm(dir, { recursive: true, force: true });
	}
});

test('ambiguous item lookup reports the matching IDs like bw', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-ambiguous-get-'));
	const key = Buffer.alloc(64, 52);
	let session = '';
	const ids = ['11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222'];
	try {
		await withStore(dir, async (state, save) => {
			state.server = 'https://example.test';
			state.account = {
				email: 'synthetic@example.test',
				kdf: { type: 0, iterations: 10000 },
				encryptedUserKey: 'synthetic-wrapped-key',
				accessToken: 'synthetic-access-token',
				refreshToken: 'synthetic-refresh-token',
				expiresAt: Date.now() + 3600000,
			};
			state.vault = {
				profile: { id: 'synthetic-user', organizations: [] },
				folders: ids.map((id, index) => ({ id, name: encrypt(Buffer.from(`Shared folder ${index}`), key) })),
				ciphers: ids.map((id, index) => ({
					...encryptItem({ type: 1, name: `Shared login ${index}`, login: { username: `user-${index}` } }, key),
					id,
					...(index === 0
						? {
							attachments: [
								{ id: 'attachment-one', fileName: encrypt(Buffer.from('Shared attachment one.bin'), key) },
								{ id: 'attachment-two', fileName: encrypt(Buffer.from('Shared attachment two.bin'), key) },
							],
						}
						: {}),
				})),
			};
			session = sealSession(state, key);
			await save();
		});
		const plain = await run(dir, ['get', 'item', 'Shared', '--session', session]);
		expect(plain.code).toBe(1);
		expect(plain.stderr).toContain('More than one result was found. Try getting a specific object by `id` instead.');
		for (const id of ids) expect(plain.stderr).toContain(id);
		const response = await run(dir, ['--response', 'get', 'item', 'Shared', '--session', session]);
		expect(response.code).toBe(1);
		expect(JSON.parse(response.stdout)).toEqual({
			success: false,
			message:
				`More than one result was found. Try getting a specific object by \`id\` instead. The following objects were found:\n${
					ids.join('\n')
				}`,
			data: ids,
		});
		const folders = await run(dir, ['--response', 'get', 'folder', 'Shared', '--session', session]);
		expect(folders.code).toBe(1);
		expect(JSON.parse(folders.stdout)).toEqual({
			success: false,
			message:
				`More than one result was found. Try getting a specific object by \`id\` instead. The following objects were found:\n${
					ids.join('\n')
				}`,
			data: ids,
		});
		const attachments = await run(dir, [
			'--response',
			'get',
			'attachment',
			'Shared attachment',
			'--itemid',
			ids[0]!,
			'--session',
			session,
		]);
		expect(attachments.code).toBe(1);
		expect(JSON.parse(attachments.stdout)).toEqual({
			success: false,
			message: 'More than one result was found. Try getting a specific object by `id` instead. '
				+ 'The following objects were found:\nattachment-one\nattachment-two',
			data: ['attachment-one', 'attachment-two'],
		});
	} finally {
		key.fill(0);
		await rm(dir, { recursive: true, force: true });
	}
});

test('pretty formats structured JSON across global and nested commands without changing raw values', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-pretty-'));
	try {
		await withStore(dir, async (state, save) => {
			state.account = {
				email: 'synthetic@example.test',
				kdf: { type: 0, iterations: 10000 },
				encryptedUserKey: 'synthetic-wrapped-key',
				accessToken: 'synthetic-token',
				refreshToken: 'synthetic-refresh',
				expiresAt: Date.now() + 3600000,
			};
			await save();
		});
		const compact = await run(dir, ['get', 'template', 'item']);
		expect(compact.code).toBe(0);
		const value = JSON.parse(compact.stdout), expected = JSON.stringify(value, null, 2) + '\n';
		expect(compact.stdout).toBe(JSON.stringify(value) + '\n');
		for (const args of [['--pretty', 'get', 'template', 'item'], ['get', 'template', 'item', '--pretty']]) {
			expect(await run(dir, args)).toEqual({ code: 0, stdout: expected, stderr: '' });
		}
		expect((await run(dir, ['get', 'template', 'item'], { VW_PRETTY: 'true' })).stdout).toBe(expected);
		expect((await run(dir, ['get', 'template', 'item'], { BW_PRETTY: 'true' })).stdout).toBe(expected);
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

test('bw-named session environment unlocks status when no vw-named value is set', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-bw-env-'));
	const key = Buffer.alloc(64, 29);
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
			session = sealSession(state, key);
			await save();
		});
		expect(JSON.parse((await run(dir, ['status'], { BW_SESSION: session })).stdout).status).toBe('unlocked');
		expect(JSON.parse((await run(dir, ['--session', session, 'status'])).stdout).status).toBe('unlocked');
		expect(JSON.parse((await run(dir, [`--session=${session}`, 'status'])).stdout).status).toBe('unlocked');
		expect((await run(dir, ['generate', '--length', '5', '--session', session])).stdout.trim()).toHaveLength(5);
		expect(JSON.parse((await run(dir, ['status'], { BW_SESSION: session, VW_SESSION: 'invalid' })).stdout).status)
			.toBe('locked');
		expect(JSON.parse((await run(dir, ['--response', 'login', '--check'])).stdout)).toEqual({
			success: true,
			data: { object: 'message', title: 'You are logged in!', message: null, noColor: false },
		});
		expect(JSON.parse((await run(dir, ['--response', 'unlock', '--check'], { BW_SESSION: session })).stdout))
			.toEqual({
				success: true,
				data: { object: 'message', title: 'Vault is unlocked!', message: null, noColor: false },
			});
	} finally {
		key.fill(0);
		await rm(dir, { recursive: true, force: true });
	}
});

test('response mode matches bw envelopes for status, generated strings, and command errors', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-response-'));
	try {
		const status = await run(dir, ['--response', 'status']);
		expect(status.code).toBe(0);
		expect(JSON.parse(status.stdout)).toEqual({
			success: true,
			data: {
				object: 'template',
				template: { serverUrl: null, lastSync: null, status: 'unauthenticated' },
			},
		});
		const generated = await run(dir, ['generate', '--response', '--length', '8']);
		expect(generated.code).toBe(0);
		expect(JSON.parse(generated.stdout)).toMatchObject({ success: true, data: { object: 'string' } });
		expect(JSON.parse(generated.stdout).data.data).toMatch(/^.{8}$/);
		const encoded = await run(dir, ['encode', 'response fixture', '--response']);
		expect(JSON.parse(encoded.stdout)).toEqual({
			success: true,
			data: { object: 'string', data: Buffer.from('response fixture').toString('base64') },
		});
		const configured = await run(dir, ['config', 'server', 'https://vault.example.test', '--response']);
		expect(JSON.parse(configured.stdout)).toEqual({
			success: true,
			data: { object: 'message', title: 'Saved setting `config`.', message: null, noColor: false },
		});
		const configRead = await run(dir, ['--response', 'config', 'server', '']);
		expect(JSON.parse(configRead.stdout)).toEqual({
			success: true,
			data: { object: 'string', data: 'https://vault.example.test' },
		});
		const whitespaceConfigRead = await run(dir, ['--response', 'config', 'server', '   ']);
		expect(JSON.parse(whitespaceConfigRead.stdout)).toEqual(JSON.parse(configRead.stdout));
		await withStore(dir, async (state, save) => {
			state.account = {
				email: 'synthetic@example.test',
				kdf: { type: 0, iterations: 10000 },
				encryptedUserKey: 'synthetic-wrapped-key',
				accessToken: 'synthetic-token',
				refreshToken: 'synthetic-refresh',
				expiresAt: Date.now() + 3600000,
			};
			await save();
		});
		const itemTemplate = await run(dir, ['--response', 'get', 'template', 'item']);
		expect(JSON.parse(itemTemplate.stdout)).toMatchObject({ success: true, data: { object: 'template' } });
		await withStore(dir, async (state, save) => {
			delete state.account;
			await save();
		});
		const sendTemplate = await run(dir, ['send', 'template', 'text', '--response']);
		expect(JSON.parse(sendTemplate.stdout)).toMatchObject({
			success: true,
			data: { object: 'template', template: { object: 'send' } },
		});
		const sdkVersion = await run(dir, ['sdk-version']);
		expect((await run(dir, ['--response', 'sdk-version'])).stdout).toBe(sdkVersion.stdout);
		expect((await run(dir, ['--response'])).stdout).toContain('Vaultwarden-first');
		const failure = await run(dir, ['--response', 'list', 'items']);
		expect(failure.code).toBe(1);
		expect(JSON.parse(failure.stdout)).toEqual({ success: false, message: 'You are not logged in.' });
		expect(failure.stderr).toBe('');
		const fromEnvironment = await run(dir, ['status'], { BW_RESPONSE: 'true' });
		expect(JSON.parse(fromEnvironment.stdout)).toMatchObject({ success: true, data: { object: 'template' } });
		expect(JSON.parse((await run(dir, ['status'], { BW_RESPONSE: 'true', VW_RESPONSE: 'false' })).stdout))
			.toMatchObject({ serverUrl: 'https://vault.example.test', status: 'unauthenticated' });
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test('lock and logout success messages match pinned bw responses', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-auth-messages-'));
	try {
		await withStore(dir, async (state, save) => {
			state.account = {
				email: 'synthetic@example.test',
				kdf: { type: 0, iterations: 10000 },
				encryptedUserKey: 'synthetic-wrapped-key',
				accessToken: 'synthetic-access-token',
				refreshToken: 'synthetic-refresh-token',
				expiresAt: Date.now() + 3600000,
			};
			await save();
		});
		expect(JSON.parse((await run(dir, ['--response', 'lock'])).stdout)).toEqual({
			success: true,
			data: { object: 'message', title: 'Your vault is locked.', message: null, noColor: false },
		});
		expect(JSON.parse((await run(dir, ['--response', 'logout'])).stdout)).toEqual({
			success: true,
			data: { object: 'message', title: 'You have logged out.', message: null, noColor: false },
		});
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test('status reports the authenticated user ID from the token without requiring a synced vault', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-status-user-'));
	const userId = '11111111-2222-4333-8444-555555555555';
	try {
		await withStore(dir, async (state, save) => {
			state.server = 'https://vault.example.test';
			state.account = {
				email: 'synthetic@example.test',
				kdf: { type: 0, iterations: 10000 },
				encryptedUserKey: 'synthetic-wrapped-key',
				accessToken: `header.${Buffer.from(JSON.stringify({ sub: userId })).toString('base64url')}.signature`,
				refreshToken: 'synthetic-refresh-token',
				expiresAt: Date.now() + 3600000,
			};
			await save();
		});
		const normal = await run(dir, ['status']);
		expect(normal.code).toBe(0);
		expect(JSON.parse(normal.stdout)).toMatchObject({ userId, userEmail: 'synthetic@example.test' });
		const response = await run(dir, ['--response', 'status']);
		expect(JSON.parse(response.stdout)).toMatchObject({
			success: true,
			data: { object: 'template', template: { userId, userEmail: 'synthetic@example.test' } },
		});
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test('unlock prints session guidance by default and exposes the token only through raw output', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-session-output-'));
	const email = 'synthetic@example.test', password = 'synthetic-session-password';
	const kdf = { type: 0 as const, iterations: 10000 }, userKey = Buffer.alloc(64, 31);
	const master = await deriveMasterKey(password, email, kdf), stretched = stretchKey(master);
	try {
		const encryptedUserKey = encrypt(userKey, stretched);
		await withStore(dir, async (state, save) => {
			state.account = {
				email,
				kdf,
				encryptedUserKey,
				accessToken: 'synthetic-access-token',
				refreshToken: 'synthetic-refresh-token',
				expiresAt: Date.now() + 3600000,
			};
			await save();
		});
		const normal = await run(dir, ['unlock', password]);
		expect(normal.code).toBe(0);
		expect(normal.stdout).toContain('Your vault is now unlocked!');
		expect(normal.stdout).toContain('BW_SESSION');
		expect(normal.stdout).toContain('$ bw list items --session ');
		const raw = await run(dir, ['unlock', password, '--raw']);
		expect(raw.code).toBe(0);
		expect(raw.stdout.trim()).toMatch(/^[A-Za-z0-9+/]+=*$/);
		const rawFromBitwardenEnv = await run(dir, ['unlock', password], { BW_RAW: 'true' });
		expect(rawFromBitwardenEnv.code).toBe(0);
		expect(rawFromBitwardenEnv.stdout.trim()).toMatch(/^[A-Za-z0-9+/]+=*$/);
		const response = await run(dir, ['--response', 'unlock', password]);
		expect(JSON.parse(response.stdout)).toMatchObject({
			success: true,
			data: {
				object: 'message',
				title: 'Your vault is now unlocked!',
				message: expect.stringContaining('BW_SESSION'),
				raw: expect.any(String),
			},
		});
	} finally {
		master.fill(0);
		stretched.fill(0);
		userKey.fill(0);
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
		expect(JSON.parse((await run(dir, ['--response', 'sync', '--last'])).stdout)).toEqual({
			success: true,
			data: { object: 'string', data: firstDate },
		});
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

test('API-key login syncs before returning the unlock guidance', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-api-login-'));
	const calls: string[] = [];
	const userId = '11111111-1111-1111-1111-111111111111';
	const server = createServer(async (request, response) => {
		calls.push(request.url!);
		response.setHeader('Content-Type', 'application/json');
		if (request.url === '/identity/connect/token') {
			const body = await new Promise<string>(resolve => {
				let value = '';
				request.setEncoding('utf8').on('data', chunk => value += chunk).on('end', () => resolve(value));
			});
			expect(new URLSearchParams(body).get('grant_type')).toBe('client_credentials');
			response.end(JSON.stringify({
				access_token: 'synthetic-api-access-token',
				expires_in: 3600,
				key: 'synthetic-wrapped-user-key',
				kdf: 0,
				kdfIterations: 10000,
			}));
		} else if (request.url === '/api/accounts/profile') {
			response.end(JSON.stringify({ id: userId, email: 'synthetic@example.com' }));
		} else if (request.url === '/api/sync?excludeDomains=false') {
			response.end(JSON.stringify({ profile: { id: userId }, ciphers: [] }));
		} else response.writeHead(404).end('{}');
	});
	await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
	const address = server.address();
	if (!address || typeof address === 'string') throw new Error('Missing API-login fixture address.');
	const environment = {
		VW_CLIENTID: `user.${userId}`,
		VW_CLIENTSECRET: 'synthetic-api-client-secret',
	};
	try {
		expect((await run(dir, ['config', 'server', `http://127.0.0.1:${address.port}`])).code).toBe(0);
		const login = await run(dir, ['login', '--apikey', '--nointeraction'], environment);
		expect(login.code).toBe(0);
		expect(login.stdout).toContain('You are logged in!');
		expect(login.stdout).toContain('$ vw unlock');
		expect(calls).toEqual([
			'/identity/connect/token',
			'/api/accounts/profile',
			'/api/sync?excludeDomains=false',
		]);
		await withStore(dir, async state => {
			expect(state.account?.auth).toBe('api-key');
			expect(state.vault).toEqual({ profile: { id: userId }, ciphers: [] });
			expect(state.lastSync).toBeDefined();
		});
		const logout = await run(dir, ['logout']);
		expect(logout.code).toBe(0);
		calls.length = 0;
		const responseLogin = await run(dir, ['--response', 'login', '--apikey', '--nointeraction'], environment);
		expect(responseLogin.code).toBe(0);
		expect(JSON.parse(responseLogin.stdout)).toEqual({
			success: true,
			data: {
				object: 'message',
				title: 'You are logged in!',
				message: '\nTo unlock your vault, use the `unlock` command. ex:\n$ vw unlock',
				noColor: false,
			},
		});
		expect(calls).toEqual([
			'/identity/connect/token',
			'/api/accounts/profile',
			'/api/sync?excludeDomains=false',
		]);
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
		for (const name of ['list', 'approve', 'approve-all', 'deny', 'deny-all']) {
			expect(help.stdout).toContain(name);
		}
		const approvalHelp = await run(dir, ['device-approval', 'help']);
		expect(approvalHelp.code).toBe(0);
		expect(approvalHelp.stdout).toContain('help');
		const listHelp = await run(dir, ['device-approval', 'help', 'list']);
		expect(listHelp.code).toBe(0);
		expect(listHelp.stdout).toContain('Usage: vw device-approval list');
		expect(listHelp.stdout).toContain('--organizationid');
		const unknownHelp = await run(dir, ['device-approval', 'help', 'unknown']);
		expect(unknownHelp.code).toBe(0);
		expect(unknownHelp.stdout).toContain('device-approval <command>');
		for (const name of ['list', 'approve', 'deny', 'approve-all', 'deny-all']) {
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
			'--icons',
			`${base}/icons`,
			'--notifications',
			`${base}/notifications`,
			'--events',
			`${base}/events`,
			'--key-connector',
			`${base}/key-connector`,
		]);
		expect(config.code).toBe(0);
		expect(config.stdout.trim()).toBe('Saved setting `config`.');
		await withStore(dir, async state => {
			expect(state.server).toBe(base);
			expect(state.services).toEqual({
				webVault: `${base}/web`,
				api: `${base}/custom-api`,
				identity: `${base}/custom-auth`,
				icons: `${base}/icons`,
				notifications: `${base}/notifications`,
				events: `${base}/events`,
				keyConnector: `${base}/key-connector`,
			});
		});
		const login = () => run(dir, ['login', 'fixture@example.com', 'synthetic-password', '--nointeraction']);
		expect((await login()).code).toBe(1);
		expect(paths).toEqual(['/custom-auth/accounts/prelogin']);
		const reset = await run(dir, ['config', 'server', base]);
		expect(reset.code).toBe(0);
		expect(reset.stdout.trim()).toBe('Saved setting `config`.');
		await withStore(dir, async state => expect(state.services).toEqual({}));
		expect((await login()).code).toBe(1);
		expect(paths.at(-1)).toBe('/identity/accounts/prelogin');
		expect((await run(dir, ['config', 'server', base, '--identity', 'https://user:secret@example.com'])).code).toBe(1);
	} finally {
		server.closeAllConnections();
		await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
		await rm(dir, { recursive: true, force: true });
	}
});

test('generation and import format discovery follow bw login and output semantics in the built Node CLI', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-tools-'));
	try {
		const generated = await run(dir, ['generate', '--length', '32', '-u', '-l', '-n', '-s', '--minNumber', '4']);
		expect(generated.code).toBe(0);
		expect(generated.stdout.trim()).toHaveLength(32);
		expect(generated.stdout.trim().match(/[0-9]/g)!.length).toBeGreaterThanOrEqual(4);
		const clamped = await run(dir, ['generate', '--length', '-1']);
		expect(clamped.code).toBe(0);
		expect(clamped.stdout.trim()).toHaveLength(5);
		const fractional = await run(dir, ['generate', '--length', '5.9', '-n', '--minNumber', '2.9']);
		expect(fractional.code).toBe(0);
		expect(fractional.stdout.trim()).toHaveLength(5);
		expect(fractional.stdout.trim().match(/\d/g)!.length).toBeGreaterThanOrEqual(2);
		const malformed = await run(dir, ['generate', '--length', 'invalid']);
		expect(malformed.code).toBe(0);
		expect(malformed.stdout.trim()).toHaveLength(14);
		const long = await run(dir, ['generate', '--length', '4097']);
		expect(long.code).toBe(0);
		expect(long.stdout.trim()).toHaveLength(4097);
		const manyNumbers = await run(dir, ['generate', '--minNumber', '4097']);
		expect(manyNumbers.code).toBe(0);
		expect(manyNumbers.stdout.trim().match(/[0-9]/g)!.length).toBeGreaterThanOrEqual(4097);
		const manySpecials = await run(dir, ['generate', '-s', '--minSpecial', '4097']);
		expect(manySpecials.code).toBe(0);
		expect(manySpecials.stdout.trim().match(/[!@#$%^&*]/g)!).toHaveLength(4097);
		const phrase = await run(dir, ['generate', '-p', '--words', '5', '--separator', '/']);
		expect(phrase.code).toBe(0);
		expect(phrase.stdout.trim().split('/')).toHaveLength(5);
		const manyWords = await run(dir, ['generate', '-p', '--words', '129', '--separator', '/']);
		expect(manyWords.code).toBe(0);
		expect(manyWords.stdout.trim().split('/')).toHaveLength(129);
		const unauthenticatedFormats = await run(dir, ['import', '--formats']);
		expect(unauthenticatedFormats.code).toBe(1);
		expect(unauthenticatedFormats.stderr).toContain('You are not logged in.');
		await withStore(dir, async (state, save) => {
			state.account = {
				email: 'synthetic@example.test',
				kdf: { type: 0, iterations: 10000 },
				encryptedUserKey: 'synthetic-wrapped-key',
				accessToken: 'synthetic-access-token',
				refreshToken: 'synthetic-refresh-token',
				expiresAt: Date.now() + 3600000,
			};
			await save();
		});
		const formats = await run(dir, ['import', '--formats']);
		expect(formats.code).toBe(0);
		expect(formats.stdout).toStartWith('Supported input formats:\n');
		const supportedFormats = formats.stdout.slice('Supported input formats:\n'.length).trimEnd();
		const formatsResponse = await run(dir, ['--response', 'import', '--formats']);
		expect(JSON.parse(formatsResponse.stdout)).toEqual({
			success: true,
			data: {
				object: 'message',
				title: 'Supported input formats:',
				message: supportedFormats,
				raw: supportedFormats,
				noColor: false,
			},
		});
		const rawFormats = await run(dir, ['--raw', 'import', '--formats']);
		expect(rawFormats.stdout).toBe(`${supportedFormats}\n`);
		const unsupportedKeeperFile = join(dir, 'keeper-export.txt');
		await writeFile(unsupportedKeeperFile, '{"records":[]}');
		const unsupportedKeeper = await run(dir, ['import', 'keeper', unsupportedKeeperFile]);
		expect(unsupportedKeeper.code).toBe(1);
		expect(unsupportedKeeper.stderr).toContain(
			'Cannot determine Keeper file type. Use a .csv or .json file.',
		);
		expect(formats.stdout.split(/\r?\n/)).toContain('bitwardenjson');
		expect(formats.stdout.split(/\r?\n/)).toContain('bitwardenzip');
		expect(formats.stdout.split(/\r?\n/)).toContain('nordpasscsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('passkeepcsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('passwordwallettxt');
		expect(formats.stdout.split(/\r?\n/)).toContain('passpackcsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('ascendocsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('blackberrycsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('blurcsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('codebookcsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('avastcsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('buttercupcsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('padlockcsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('yoticsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('saferpasscsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('securesafecsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('meldiumcsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('splashidcsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('truekeycsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('remembearcsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('upmcsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('logmeoncecsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('mykicsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('msecurecsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('passwordagentcsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('dashlanecsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('delineacsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('kasperskytxt');
		expect(formats.stdout.split(/\r?\n/)).toContain('zohovaultcsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('roboformcsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('keepercsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('keeperjson');
		expect(formats.stdout.split(/\r?\n/)).toContain('dashlanejson');
		expect(formats.stdout.split(/\r?\n/)).toContain('passwordxpcsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('delineaxml');
		expect(formats.stdout.split(/\r?\n/)).toContain('netwrixpasswordsecure');
		expect(formats.stdout.split(/\r?\n/)).toContain('passwordbossjson');
		expect(formats.stdout.split(/\r?\n/)).toContain('psonojson');
		expect(formats.stdout.split(/\r?\n/)).toContain('pwsafexml');
		expect(formats.stdout.split(/\r?\n/)).toContain('stickypasswordxml');
		expect(formats.stdout.split(/\r?\n/)).toContain('clipperzhtml');
		expect(formats.stdout.split(/\r?\n/)).toContain('fsecurefsk');
		expect(formats.stdout.split(/\r?\n/)).toContain('keeper');
		expect(formats.stdout.split(/\r?\n/)).toContain('protonpass');
		expect(formats.stdout.split(/\r?\n/)).toContain('passworddepot17xml');
		expect(formats.stdout.split(/\r?\n/)).toContain('passworddragonxml');
		expect(formats.stdout.split(/\r?\n/)).toContain('safeincloudxml');
		expect(formats.stdout.split(/\r?\n/)).toContain('avastjson');
		expect(formats.stdout.split(/\r?\n/)).toContain('enpassjson');
		expect(formats.stdout.split(/\r?\n/)).toContain('enpasscsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('gnomejson');
		expect(formats.stdout.split(/\r?\n/)).toContain('passmanjson');
		expect(formats.stdout.split(/\r?\n/)).toContain('passkyjson');
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test('Send templates are available before login, and malformed recipient links do not request an account session', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-send-cli-'));
	try {
		const root = await run(dir, []);
		expect(root.code).toBe(0);
		expect(root.stdout).toContain('Vaultwarden-first');
		const unauthenticatedResponse = await run(dir, ['--response', 'list', 'items']);
		expect(unauthenticatedResponse.code).toBe(1);
		expect(JSON.parse(unauthenticatedResponse.stdout)).toEqual({
			success: false,
			message: 'You are not logged in.',
		});
		const text = await run(dir, ['send', 'template', 'text']);
		expect(text.code).toBe(0);
		expect(JSON.parse(text.stdout).type).toBe(0);
		const file = await run(dir, ['send', 'template', 'file']);
		expect(file.code).toBe(0);
		expect(JSON.parse(file.stdout).type).toBe(1);
		const editWithoutId = await run(dir, [
			'send',
			'edit',
			Buffer.from(JSON.stringify({ type: 0, name: 'Missing ID', text: { text: 'value' } })).toString('base64'),
		]);
		expect(editWithoutId.code).toBe(1);
		expect(editWithoutId.stderr).toContain('You are not logged in.');
		const invalid = await run(dir, ['receive', 'https://vault.example/#/send/bad/key']);
		expect(invalid.code).toBe(1);
		expect(invalid.stderr).toContain('fragment');
		expect(invalid.stderr).not.toContain('session');
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test('owned Send CLI results use bw response discriminators', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-send-response-'));
	const userKey = Buffer.alloc(64, 47), seed = Buffer.alloc(16, 48), sendKey = deriveSendKey(seed);
	const id = 'synthetic-send-id';
	try {
		const rawSend = {
			id,
			accessId: Buffer.alloc(16, 49).toString('base64url'),
			type: 0,
			key: encrypt(seed, userKey),
			name: encrypt(Buffer.from('Cached synthetic Send'), sendKey),
			notes: null,
			text: { text: encrypt(Buffer.from('Synthetic payload'), sendKey), hidden: false },
			deletionDate: new Date(Date.now() + 86400000).toISOString(),
			expirationDate: null,
			maxAccessCount: null,
			disabled: false,
			hideEmail: false,
		};
		const rawFileSend = {
			...rawSend,
			id: 'synthetic-file-send-id',
			accessId: Buffer.alloc(16, 51).toString('base64url'),
			type: 1,
			name: encrypt(Buffer.from('Unique synthetic file Send'), sendKey),
			file: { id: 'synthetic-file-id', fileName: encrypt(Buffer.from('synthetic.txt'), sendKey), size: 10 },
		};
		delete (rawFileSend as { text?: unknown }).text;
		let session = '';
		await withStore(dir, async (state, save) => {
			state.server = 'https://example.test';
			state.account = {
				email: 'synthetic@example.test',
				kdf: { type: 0, iterations: 10000 },
				encryptedUserKey: 'synthetic-wrapped-key',
				accessToken: 'synthetic-access-token',
				refreshToken: 'synthetic-refresh-token',
				expiresAt: Date.now() + 3600000,
			};
			state.vault = {
				profile: { id: 'synthetic-user', organizations: [] },
				ciphers: [],
				sends: [rawSend, rawFileSend],
			};
			session = sealSession(state, userKey);
			await save();
		});
		const normal = await run(dir, ['send', 'get', id, '--session', session]);
		expect(normal.code).toBe(0);
		expect(JSON.parse(normal.stdout)).toMatchObject({
			object: 'send',
			id,
			name: 'Cached synthetic Send',
			text: { text: 'Synthetic payload', hidden: false },
		});
		const response = JSON.parse(
			(await run(dir, ['--response', 'send', 'get', id, '--session', session])).stdout,
		);
		expect(response).toMatchObject({
			success: true,
			data: { object: 'send', id, name: 'Cached synthetic Send' },
		});
		const textFromFile = await run(dir, ['send', 'get', 'synthetic-file-send-id', '--text', '--session', session]);
		expect(textFromFile.code).toBe(1);
		expect(textFromFile.stderr).toContain('Not found.');
		const listed = JSON.parse((await run(dir, ['--response', 'send', 'list', '--session', session])).stdout);
		expect(listed).toMatchObject({
			success: true,
			data: {
				object: 'list',
				data: [
					{ object: 'send', id, name: 'Cached synthetic Send' },
					{ object: 'send', id: 'synthetic-file-send-id', name: 'Unique synthetic file Send' },
				],
			},
		});
		const duplicateSend = {
			...rawSend,
			id: 'synthetic-send-id-2',
			accessId: Buffer.alloc(16, 50).toString('base64url'),
		};
		await withStore(dir, async (state, save) => {
			state.vault!.sends = [rawSend, rawFileSend, duplicateSend];
			await save();
		});
		const ambiguous = await run(dir, ['--response', 'send', 'get', 'Cached', '--session', session]);
		expect(ambiguous.code).toBe(1);
		expect(JSON.parse(ambiguous.stdout)).toEqual({
			success: false,
			message: 'More than one result was found. Try getting a specific object by `id` instead. '
				+ 'The following objects were found:\nsynthetic-send-id\nsynthetic-send-id-2',
			data: ['synthetic-send-id', 'synthetic-send-id-2'],
		});
	} finally {
		userKey.fill(0);
		seed.fill(0);
		sendKey.fill(0);
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
		expect(login.stderr).toContain('You are not logged in.');
		const unlock = await run(dir, [
			'unlock',
			'--check',
			'--nointeraction',
			'--passwordfile',
			join(dir, 'missing-secret.txt'),
		]);
		expect(unlock.code).toBe(1);
		expect(unlock.stderr).toContain('You are not logged in.');
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
