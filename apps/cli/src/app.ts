import { generateCompletion, SHELLS } from '@kjanat/dreamcli/completion';
import { masterPassword, loginEmail, apiCredentials, answerLoginChallenge } from '#auth-input';
import { reportCommand } from '#report-commands';
import { deviceApprovalCommand } from '#device-approval-command';
import { CLI_PACKAGE, versionCommands } from '#version-commands';
import { authorizeSso } from '#sso-login';
import { outputPolicyPlugin, outputCommand as command } from '#output';
import { serveCommand } from '#serve-command';
import { sendCommands, receiveCommand } from '#send-commands';
import { arg, cli, flag } from '@kjanat/dreamcli';
import {
	VaultwardenClient,
	PasswordExposureClient,
	ApiError,
	ImportFailure,
	SendMutationFailure,
	loginWithPassword,
	loginWithSso,
	loginWithApiKey,
	refreshAccount,
	unlockAccount,
	serverUrl,
	VaultService,
	totp,
	object,
} from '@kjanat/vaultwarden';
import { writeAttachment, writeStdout } from '#files';
import { toolCommands } from '#tool-commands';
import { vaultCommands, template } from '#vault-commands';
import { dataDirectory, openSession, sealSession, withStore, type State } from '#store';

const sessionFlag = () => flag.string().sensitive().env('VW_SESSION').describe('Unlock session (or VW_SESSION)');
const passwordEnvFlag = () =>
	flag.string().describe('Environment variable containing the master password (default VW_PASSWORD)');
function client(state: State): VaultwardenClient {
	if (!state.server) {
		throw new Error(
			'Configure a server first: vw config server https://vault.example.com',
		);
	}
	return new VaultwardenClient(state.server, { deviceId: state.deviceId, services: state.services });
}
async function renewAccount(state: State, save: () => Promise<void>): Promise<void> {
	const account = state.account;
	if (!account) throw new Error('Log in first.');
	const renewed = await refreshAccount(client(state), account);
	const changed = account.encryptedUserKey !== renewed.encryptedUserKey
		|| JSON.stringify(account.kdf) !== JSON.stringify(renewed.kdf);
	state.account = renewed;
	if (changed) {
		delete state.session;
		delete state.vault;
		delete state.lastSync;
	}
	await save();
	if (changed) throw new Error('Account key settings changed. Run vw sync, then unlock again.');
}
async function sync(state: State, save: () => Promise<void>, force = true): Promise<void> {
	const account = state.account;
	if (!account) throw new Error('Log in first.');
	const api = client(state);
	const refresh = async () => {
		await renewAccount(state, save);
	};
	if (account.expiresAt <= Date.now() + 30_000) await refresh();
	// Use the start time so a server change during download is picked up next time.
	const started = new Date().toISOString();
	const download = async () => {
		const previous = state.lastSync ? Date.parse(state.lastSync) : NaN;
		if (!force && state.vault && Number.isFinite(previous) && previous > 0) {
			const revision = await api.accountRevisionDate(state.account!.accessToken);
			if (revision < 0) {
				delete state.account;
				delete state.vault;
				delete state.session;
				delete state.lastSync;
				await save();
				throw new Error('Account was deleted. Log in again.');
			}
			if (revision <= previous) return;
		}
		state.vault = await api.sync(state.account!.accessToken);
	};
	try {
		await download();
	} catch (error) {
		if (!(error instanceof ApiError) || error.status !== 401) throw error;
		await refresh();
		await download();
	}
	state.lastSync = started;
	await save();
}
export function createApp(directory = dataDirectory()) {
	const config = command('config')
		.description('Read or set the Vaultwarden server')
		.arg('key', arg.enum(['server']))
		.arg('url', arg.string().optional())
		.flag('web-vault', flag.string()).flag('api', flag.string()).flag('identity', flag.string())
		.flag('icons', flag.string()).flag('notifications', flag.string()).flag('events', flag.string())
		.flag('key-connector', flag.string())
		.action(async ({ args, flags, out }) =>
			withStore(directory, async (state, save) => {
				const overrides = {
					webVault: flags['web-vault'],
					api: flags.api,
					identity: flags.identity,
					icons: flags.icons,
					notifications: flags.notifications,
					events: flags.events,
					keyConnector: flags['key-connector'],
				};
				if (args.url || Object.values(overrides).some(value => value !== undefined)) {
					if (state.account) {
						throw new Error('Log out before changing servers.');
					}
					const base = args.url ?? state.server ?? overrides.webVault ?? overrides.api ?? overrides.identity;
					if (!base) throw new Error('Supply a server URL or configure an API or identity endpoint.');
					const url = serverUrl(base);
					const services = Object.fromEntries(
						Object.entries(overrides)
							.filter((entry): entry is [string, string] => entry[1] !== undefined)
							.map(([name, value]) => [name, serverUrl(value)]),
					);
					state.server = url;
					state.services = services;
					await save();
				}
				out.log(state.server ?? '');
			})
		);
	const login = command('login').description('Log in with a master password, SSO, or a personal API key')
		.arg('email', arg.string().env('VW_EMAIL').optional()).arg('password', arg.string().sensitive().optional())
		.flag('passwordenv', passwordEnvFlag()).flag('passwordfile', flag.path())
		.flag('apikey', flag.boolean()).flag('clientidenv', flag.string()).flag('clientsecretenv', flag.string())
		.flag('sso', flag.boolean().describe('Authenticate through Vaultwarden SSO')).flag(
			'identifier',
			flag.string().describe('Optional SSO organization identifier'),
		)
		.flag('check', flag.boolean()).flag('raw', flag.boolean()).flag('nointeraction', flag.boolean())
		.flag('method', flag.number({ int: true, min: 0 }).describe('Two-factor provider: 0=TOTP, 1=email, 3=YubiKey'))
		.flag('code', flag.string().sensitive().env('VW_2FA_TOKEN'))
		.action(async ({ args, flags, out }) =>
			withStore(directory, async (state, save) => {
				if (flags.check) {
					if (!state.account) throw new Error('Not logged in.');
					out.log('Logged in.');
					return;
				}
				if (state.account) throw new Error('Already logged in. Log out before logging in again.');
				if (flags.sso && flags.apikey) throw new Error('Choose either SSO or API-key login.');
				if (flags.identifier && !flags.sso) throw new Error('--identifier requires --sso.');
				if (flags.apikey) {
					if (args.password !== undefined || flags.method !== undefined || flags.code !== undefined) {
						throw new Error('API-key login does not accept a master password or two-factor options.');
					}
					state.account = await loginWithApiKey(
						client(state),
						await apiCredentials(flags.clientidenv, flags.clientsecretenv, flags.nointeraction),
					);
					delete state.session;
					delete state.vault;
					delete state.lastSync;
					await save();
					out.log('Logged in with an API key. Run vw sync, then vw unlock --raw.');
					return;
				}
				if (flags.code !== undefined && flags.method === undefined) {
					throw new Error('Supply --method with --code for two-factor login.');
				}
				if (flags.method !== undefined && flags.code === undefined && (flags.nointeraction || !process.stdin.isTTY)) {
					throw new Error('Supply --code for noninteractive two-factor login.');
				}
				const passwordSource = {
					positional: args.password,
					envName: flags.passwordenv,
					file: flags.passwordfile,
					noInteraction: flags.nointeraction,
				};
				let secret: string;
				if (flags.sso) {
					const credentials = await authorizeSso(client(state), {
						organizationIdentifier: flags.identifier,
						openBrowser: !flags.nointeraction,
					});
					const account = await loginWithSso(
						client(state),
						credentials,
						flags.method === undefined || flags.code === undefined
							? undefined
							: { provider: flags.method, token: flags.code },
						flags.code === undefined
							? { onTwoFactor: challenge => answerLoginChallenge(challenge, flags.method, flags.nointeraction) }
							: {},
					);
					if (args.email?.includes('@') && args.email.trim().toLowerCase() !== account.email) {
						throw new Error('SSO account identity does not match the requested email.');
					}
					secret = await masterPassword(passwordSource);
					const probe = await unlockAccount(account, secret);
					probe.fill(0);
					state.account = account;
				} else {
					const email = await loginEmail(args.email, flags.nointeraction);
					secret = await masterPassword(passwordSource);
					state.account = await loginWithPassword(
						client(state),
						email,
						secret,
						flags.method === undefined || flags.code === undefined
							? undefined
							: { provider: flags.method, token: flags.code },
						flags.code === undefined
							? { onTwoFactor: challenge => answerLoginChallenge(challenge, flags.method, flags.nointeraction) }
							: {},
					);
				}
				delete state.session;
				delete state.vault;
				delete state.lastSync;
				await save();
				try {
					await sync(state, save);
				} catch {
					throw new Error('Logged in, but initial sync failed. Run vw sync, then unlock.');
				}
				const key = await unlockAccount(state.account, secret);
				try {
					const token = sealSession(state, key);
					await save();
					if (!flags.raw) out.status('Logged in and unlocked. Set VW_SESSION to this token for subsequent commands.');
					out.log(token);
				} finally {
					key.fill(0);
				}
			})
		);
	const unlock = command('unlock').description('Unlock the cached user key and issue a session')
		.arg('password', arg.string().sensitive().optional()).flag('passwordenv', passwordEnvFlag())
		.flag('passwordfile', flag.path()).flag('check', flag.boolean())
		.flag('session', sessionFlag()).flag('nointeraction', flag.boolean()).flag('raw', flag.boolean())
		.action(async ({ args, flags, out }) =>
			withStore(directory, async (state, save) => {
				if (!state.account) throw new Error('Log in first.');
				if (flags.check) {
					const key = openSession(state, flags.session);
					key.fill(0);
					out.log('Unlocked.');
					return;
				}
				const key = await unlockAccount(
					state.account,
					await masterPassword({
						positional: args.password,
						envName: flags.passwordenv,
						file: flags.passwordfile,
						noInteraction: flags.nointeraction,
					}),
				);
				try {
					const token = sealSession(state, key);
					await save();
					if (!flags.raw) out.status('Unlocked. Set VW_SESSION to this token for subsequent commands.');
					out.log(token);
				} finally {
					key.fill(0);
				}
			})
		);
	const syncCommand = command('sync')
		.description('Download the encrypted vault (also works while locked)')
		.flag('force', flag.boolean().alias('f').describe('Download even when the server revision is unchanged'))
		.flag('last', flag.boolean().describe('Show the last successful sync date without contacting the server'))
		.action(async ({ flags, out }) =>
			withStore(directory, async (state, save) => {
				if (!state.account) throw new Error('Log in first.');
				if (flags.last) {
					out.log(state.lastSync ?? '');
					return;
				}
				await sync(state, save, flags.force);
				out.log('Syncing complete.');
			})
		);
	const status = command('status')
		.description('Show local login, session, and sync status')
		.flag('session', sessionFlag())
		.action(async ({ flags, out }) =>
			withStore(directory, async (state) => {
				let unlocked = false;
				if (flags.session && state.session && state.account) {
					try {
						const key = openSession(state, flags.session);
						key.fill(0);
						unlocked = true;
					} catch {
						/* Report locked for invalid credentials. */
					}
				}
				out.json({
					serverUrl: state.server ?? null,
					status: state.account
						? unlocked
							? 'unlocked'
							: 'locked'
						: 'unauthenticated',
					userEmail: state.account?.email ?? null,
					lastSync: state.lastSync ?? null,
				});
			})
		);
	const runVault = async <T>(
		session: string | undefined,
		mutate: boolean,
		action: (vault: VaultService) => T | Promise<T>,
		online = false,
	): Promise<T> =>
		withStore(directory, async (state, save) => {
			const key = openSession(state, session);
			let vault: VaultService | undefined;
			try {
				if (!state.vault || !state.account) throw new Error('No cached vault. Run vw sync first.');
				if ((mutate || online) && state.account.expiresAt <= Date.now() + 30000) {
					await renewAccount(state, save);
				}
				vault = new VaultService(client(state), state.account.accessToken, state.vault, key);
				let result: T;
				try {
					result = await action(vault);
				} catch (error) {
					if (error instanceof ImportFailure || error instanceof SendMutationFailure) {
						delete state.vault;
						delete state.lastSync;
						await save();
					}
					throw error;
				}
				if (mutate) {
					// Never retry a completed mutation if refreshing the local cache fails.
					try {
						await sync(state, save);
					} catch {
						delete state.vault;
						delete state.lastSync;
						await save();
						throw new Error('The server change succeeded, but cache refresh failed. Run vw sync before continuing.');
					}
				}
				return result;
			} finally {
				vault?.dispose();
				key.fill(0);
			}
		});
	const operations = vaultCommands({ run: runVault });
	const tools = toolCommands({ run: runVault }, directory);
	const list = command('list').description('List items, folders, collections, or organizations')
		.arg('object', arg.enum(['items', 'folders', 'collections', 'organizations', 'org-collections', 'org-members']))
		.flag('session', sessionFlag()).flag('search', flag.string()).flag('url', flag.string())
		.flag('folderid', flag.string()).flag('organizationid', flag.string()).flag('collectionid', flag.string())
		.flag('trash', flag.boolean()).flag('archived', flag.boolean())
		.action(async ({ args, flags, out }) => {
			out.json(
				await runVault(flags.session, false, async vault => {
					if (args.object === 'items') {
						const filter = {
							search: flags.search,
							folderId: flags.folderid,
							organizationId: flags.organizationid,
							collectionId: flags.collectionid,
							trash: flags.trash,
							archived: flags.archived,
						};
						return flags.url?.trim() ? vault.listItemsForUrl(flags.url, filter) : vault.listItems(filter);
					}
					if ((args.object === 'org-collections' || args.object === 'org-members') && !flags.organizationid) {
						throw new Error('--organizationid is required.');
					}
					const values = args.object === 'folders'
						? vault.listFolders()
						: args.object === 'collections'
						? vault.listCollections()
						: args.object === 'org-collections'
						? await vault.listOrganizationCollections(flags.organizationid!)
						: args.object === 'org-members'
						? await vault.listOrganizationMembers(flags.organizationid!)
						: vault.listOrganizations();
					return values.filter(value =>
						(!flags.search
							|| [value.name, value.email].some(v =>
								typeof v === 'string' && v.toLowerCase().includes(flags.search!.toLowerCase())
							))
						&& (!flags.organizationid || args.object === 'org-members'
							|| (value.organizationId ?? (args.object === 'organizations' ? value.id : undefined))
								=== flags.organizationid)
					);
				}, args.object === 'org-collections' || args.object === 'org-members'),
			);
		});
	const get = command('get').description('Read vault objects, secret fields, or object templates')
		.arg(
			'object',
			arg.enum([
				'item',
				'attachment',
				'password',
				'exposed',
				'fingerprint',
				'send',
				'username',
				'uri',
				'notes',
				'totp',
				'folder',
				'collection',
				'org-collection',
				'organization',
				'template',
			]),
		)
		.arg('id', arg.string().nonEmpty()).flag('session', sessionFlag()).flag('organizationid', flag.string()).flag(
			'itemid',
			flag.string(),
		).flag('output', flag.path()).flag('raw', flag.boolean()).flag('hibp-url', flag.string())
		.action(async ({ args, flags, out }) => {
			if (args.object === 'attachment') {
				if (!flags.itemid) throw new Error('--itemid is required.');
				const attachment = await runVault(
					flags.session,
					false,
					vault => vault.getAttachment(flags.itemid!, args.id),
					true,
				);
				try {
					if (flags.raw && !flags.output) await writeStdout(attachment.contents);
					else out.log(await writeAttachment(flags.output, attachment.fileName, attachment.contents));
				} finally {
					attachment.contents.fill(0);
				}
				return;
			}

			if (args.object === 'template') {
				out.json(template(args.id));
				return;
			}
			const result = await runVault(flags.session, false, async vault => {
				if (args.object === 'send') return vault.sends.get(args.id);
				if (args.object === 'fingerprint') return vault.fingerprint(args.id);
				if (args.object === 'org-collection') {
					if (!flags.organizationid) throw new Error('--organizationid is required.');
					return vault.getOrganizationCollection(flags.organizationid, args.id);
				}
				if (args.object === 'folder') return vault.findFolder(args.id);
				if (args.object === 'collection') return vault.findCollection(args.id);
				if (args.object === 'organization') return vault.findOrganization(args.id);
				const hasText = (value: unknown) => typeof value === 'string' && value.trim().length > 0;
				const item = vault.findItem(args.id, item => {
					if (args.object === 'item') return true;
					if (args.object === 'notes') return hasText(item.notes);
					if (item.type !== 1 || !item.login) return false;
					if (args.object === 'uri') {
						return Array.isArray(item.login.uris) && item.login.uris.length > 0
							&& object(item.login.uris[0]).uri !== '';
					}
					return hasText(item.login[args.object === 'exposed' ? 'password' : args.object]);
				});
				if (args.object === 'item') return item;
				const login = object(item.login ?? {});
				const value = args.object === 'notes'
					? item.notes
					: args.object === 'uri'
					? (Array.isArray(login.uris) ? object(login.uris[0] ?? {}).uri : undefined)
					: login[args.object === 'exposed' ? 'password' : args.object];
				if (typeof value !== 'string') throw new Error('Requested field is absent.');
				if (args.object === 'exposed') {
					return String(await new PasswordExposureClient({ baseUrl: flags['hibp-url'] }).count(value));
				}
				return args.object === 'totp' ? totp(value) : value;
			}, args.object === 'org-collection' || (args.object === 'fingerprint' && args.id !== 'me'));
			if (typeof result === 'string') await writeStdout(result);
			else out.json(result);
		});
	const lock = command('lock')
		.description('Invalidate the current unlock session')
		.action(async ({ out }) =>
			withStore(directory, async (state, save) => {
				delete state.session;
				await save();
				out.log('Vault locked.');
			})
		);
	const logout = command('logout')
		.description('Remove local credentials, cached vault, and session')
		.action(async ({ out }) =>
			withStore(directory, async (state, save) => {
				delete state.account;
				delete state.session;
				delete state.vault;
				delete state.lastSync;
				await save();
				out.log('Logged out.');
			})
		);
	let completionSchema: ReturnType<typeof cli>['schema'];
	let helpApp: ReturnType<typeof cli>;
	const completion = command('completion').description('Generate shell completions from the command definitions')
		.flag('shell', flag.enum(SHELLS)).action(({ flags, out }) => {
			if (!flags.shell) throw new Error('--shell is required.');
			out.log(generateCompletion(completionSchema, flags.shell));
		});
	const versions = versionCommands();
	const app = cli('vw')
		.plugin(outputPolicyPlugin())
		.default(
			command('root').action(async ({ out }) => {
				const help = await helpApp.execute(['--help']);
				out.log(help.stdout.join(''));
			}),
		)
		.version(CLI_PACKAGE.version)
		.description('A Vaultwarden-first client')
		.command(completion)
		.command(deviceApprovalCommand())
		.command(versions.sdkVersion)
		.command(versions.update)
		.command(serveCommand({ run: runVault }, directory, sync))
		.command(reportCommand({ run: runVault }))
		.command(sendCommands({ run: runVault }))
		.command(receiveCommand())
		.command(tools.generate)
		.command(tools.exportCommand)
		.command(tools.importCommand)
		.command(operations.create)
		.command(operations.edit)
		.command(operations.remove)
		.command(operations.restore)
		.command(operations.archive)
		.command(operations.encode)
		.command(operations.move)
		.command(operations.share)
		.command(operations.confirm)
		.command(config)
		.command(login)
		.command(unlock)
		.command(syncCommand)
		.command(status)
		.command(list)
		.command(get)
		.command(lock)
		.command(logout);
	helpApp = app;
	completionSchema = app.schema;
	return app;
}
