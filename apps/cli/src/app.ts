import { masterPassword, loginEmail, apiCredentials, answerLoginChallenge } from '#auth-input';
import { reportCommand } from '#report-commands';
import { deviceApprovalCommand } from '#device-approval-command';
import { CLI_PACKAGE, versionCommands } from '#version-commands';
import { authorizeSso } from '#sso-login';
import {
	getObjectResponse,
	listObjectResponse,
	outputIsResponse,
	outputPolicyPlugin,
	outputResponseError,
	outputCommand as command,
} from '#output';
import { serveCommand } from '#serve-command';
import { sendCommands, receiveCommand } from '#send-commands';
import { arg, cli, flag, plugin } from '@kjanat/dreamcli';
import {
	VaultwardenClient,
	PasswordExposureClient,
	ApiError,
	ImportFailure,
	SendMutationFailure,
	loginWithPassword,
	loginWithSso,
	setupSsoAccount,
	loginWithApiKey,
	refreshAccount,
	unlockAccount,
	serverUrl,
	VaultService,
	MultipleResultsError,
	VaultObjectNotFoundError,
	vaultItemResponse,
	totp,
	object,
	accountUserId,
	templateForServer,
	type JsonObject,
} from '@kjanat/vaultwarden';
import { writeAttachment, writeStdout } from '#files';
import { toolCommands } from '#tool-commands';
import { vaultCommands } from '#vault-commands';
import { dataDirectory, openSession, sealSession, withStore, type State } from '#store';

const sessionFlag = () => flag.string().sensitive().env('SESSION').describe('Unlock session (or VW_SESSION)');
const passwordEnvFlag = () =>
	flag.string().describe(
		'Read the master password from the variable named here. Without this option, login reads VW_PASSWORD.',
	);
const isGuid = (value: string) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
function client(state: State): VaultwardenClient {
	if (!state.server) {
		throw new Error(
			'Configure a server first: vw config server https://vault.example.com',
		);
	}
	return new VaultwardenClient(state.server, { deviceId: state.deviceId, services: state.services });
}
function accountAccessPlugin(directory: string) {
	const publicCommands = new Set([
		'completions',
		'config',
		'encode',
		'generate',
		'help',
		'login',
		'receive',
		'root',
		'sdk-version',
		'serve',
		'status',
		'update',
	]);
	return plugin({
		beforeAction: async ({ args, meta, command }) => {
			if (publicCommands.has(meta.command)) return;
			if (
				['approve', 'approve-all', 'deny', 'deny-all'].includes(meta.command)
				|| (
					meta.command === 'list'
					&& command.flags.organizationid
					&& command.flags.session
					&& !command.args.some(value => value.name === 'object')
				)
			) return;
			if (
				meta.command === 'template'
				&& ['send', 'text', 'file', 'send.text', 'send.file'].includes(String(args.object))
			) return;
			await withStore(directory, async state => {
				if (!state.account) throw new Error('You are not logged in.');
			});
		},
	}, 'account-access');
}
function sessionMessage(title: string, token: string): JsonObject {
	return {
		object: 'message',
		title,
		message:
			`\nTo unlock your vault, set your session key to the \`BW_SESSION\` environment variable. ex:\n$ export BW_SESSION="${token}"\n> $env:BW_SESSION="${token}"\n\nYou can also pass the session key to any command with the \`--session\` option. ex:\n$ bw list items --session ${token}`,
		raw: token,
		noColor: false,
	};
}
function outputSession(
	out: { json(value: unknown): void; log(value: string): void },
	title: string,
	token: string,
	raw: boolean,
) {
	const message = sessionMessage(title, token);
	if (outputIsResponse()) out.json(message);
	else if (raw) out.log(token);
	else out.log(`${title}${message.message}`);
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
				const serverArgument = typeof args.url === 'string' && args.url.trim() ? args.url : undefined;
				if (serverArgument || Object.values(overrides).some(value => value !== undefined)) {
					if (state.account) {
						throw new Error('Log out before changing servers.');
					}
					const base = serverArgument ?? state.server ?? overrides.webVault ?? overrides.api ?? overrides.identity;
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
					out.log('Saved setting `config`.');
					return;
				}
				out.log(state.server ?? '');
			})
		);
	const login = command('login').description('Log in with a master password, SSO, or a personal API key')
		.arg('email', arg.string().env('EMAIL').optional()).arg(
			'password',
			arg.string().sensitive().env('PASSWORD').optional(),
		)
		.flag('passwordenv', passwordEnvFlag()).flag('passwordfile', flag.path())
		.flag('apikey', flag.boolean())
		.flag('clientid', flag.string().sensitive().env('CLIENTID'))
		.flag('clientsecret', flag.string().sensitive().env('CLIENTSECRET'))
		.flag(
			'clientidenv',
			flag.string().describe(
				'Read the API client ID from this variable. Without this option, login reads VW_CLIENTID.',
			),
		)
		.flag(
			'clientsecretenv',
			flag.string().describe(
				'Read the API client secret from this variable. Without this option, login reads VW_CLIENTSECRET.',
			),
		)
		.flag('sso', flag.boolean().describe('Authenticate through Vaultwarden SSO')).flag(
			'identifier',
			flag.string().describe('Optional SSO organization identifier'),
		)
		.flag('check', flag.boolean())
		.flag(
			'method',
			flag.number({ int: true, min: 0 }).describe(
				'Two-factor provider: 0=TOTP, 1=email, 2=Duo, 3=YubiKey, 7=WebAuthn, 8=recovery code',
			),
		)
		.flag('code', flag.string().sensitive().env('2FA_TOKEN'))
		.action(async ({ args, flags, out, sources }) =>
			withStore(directory, async (state, save) => {
				if (flags.check) {
					if (!state.account) throw new Error('You are not logged in.');
					out.log('You are logged in!');
					return;
				}
				if (state.account) throw new Error('Already logged in. Log out before logging in again.');
				if (flags.sso && flags.apikey) throw new Error('Choose either SSO or API-key login.');
				if (flags.identifier && !flags.sso) throw new Error('--identifier requires --sso.');
				if (flags.apikey) {
					if (
						sources.args.password?.stage !== 'env' && args.password !== undefined
						|| flags.method !== undefined || flags.code !== undefined
					) {
						throw new Error('API-key login does not accept a master password or two-factor options.');
					}
					state.account = await loginWithApiKey(
						client(state),
						await apiCredentials(
							flags.clientidenv,
							flags.clientsecretenv,
							flags.nointeraction,
							flags.clientid,
							flags.clientsecret,
							sources.flags.clientid?.stage,
							sources.flags.clientsecret?.stage,
						),
					);
					delete state.session;
					delete state.vault;
					delete state.lastSync;
					await save();
					try {
						await sync(state, save);
					} catch {
						throw new Error('Logged in, but initial sync failed. Run vw sync, then unlock.');
					}
					const title = 'You are logged in!';
					const message = '\nTo unlock your vault, use the `unlock` command. ex:\n$ vw unlock';
					if (outputIsResponse()) {
						out.json({ object: 'message', title, message, noColor: false });
					} else {
						out.log(`${title}${message}`);
					}
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
					positionalSource: sources.args.password?.stage,
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
					let account = await loginWithSso(
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
					if (!account.encryptedUserKey) account = await setupSsoAccount(client(state), account, secret);
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
					outputSession(out, 'You are logged in!', token, flags.raw);
				} finally {
					key.fill(0);
				}
			})
		);
	const unlock = command('unlock').description('Unlock the cached user key and issue a session')
		.arg('password', arg.string().sensitive().env('PASSWORD').optional()).flag(
			'passwordenv',
			passwordEnvFlag(),
		)
		.flag('passwordfile', flag.path()).flag('check', flag.boolean())
		.flag('session', sessionFlag())
		.action(async ({ args, flags, out, sources }) =>
			withStore(directory, async (state, save) => {
				if (!state.account) throw new Error('Log in first.');
				if (flags.check) {
					const key = openSession(state, flags.session);
					key.fill(0);
					out.log('Vault is unlocked!');
					return;
				}
				const key = await unlockAccount(
					state.account,
					await masterPassword({
						positional: args.password,
						positionalSource: sources.args.password?.stage,
						envName: flags.passwordenv,
						file: flags.passwordfile,
						noInteraction: flags.nointeraction,
					}),
				);
				try {
					const token = sealSession(state, key);
					await save();
					outputSession(out, 'Your vault is now unlocked!', token, flags.raw);
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
					if (state.lastSync != null) out.log(state.lastSync);
					else if (outputIsResponse()) out.log('');
					return;
				}
				try {
					await sync(state, save, flags.force);
				} catch (error) {
					const message = error instanceof Error ? error.message : String(error);
					throw new Error(`Syncing failed: ${message}`, { cause: error });
				}
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
					userId: state.account ? accountUserId(state.account) : undefined,
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
			if (!state.account) throw new Error('You are not logged in.');
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
		.arg('object', arg.string())
		.flag('session', sessionFlag()).flag('search', flag.string()).flag('url', flag.string())
		.flag('folderid', flag.string()).flag('organizationid', flag.string()).flag('collectionid', flag.string())
		.flag('trash', flag.boolean()).flag('archived', flag.boolean())
		.action(async ({ args, flags, out }) => {
			const objectType = args.object.toLowerCase();
			if (
				!['items', 'folders', 'collections', 'organizations', 'org-collections', 'org-members'].includes(objectType)
			) {
				throw new Error('Unknown object.');
			}
			out.json(
				await runVault(flags.session, false, async vault => {
					if (objectType === 'org-collections' || objectType === 'org-members') {
						if (!flags.organizationid) throw new Error('`organizationid` option is required.');
						if (!isGuid(flags.organizationid)) {
							throw new Error(`\`${flags.organizationid}\` is not a GUID.`);
						}
					}
					if (objectType === 'items') {
						const filter = {
							search: flags.search,
							folderId: flags.folderid,
							organizationId: flags.organizationid,
							collectionId: flags.collectionid,
							trash: flags.trash,
							archived: flags.archived,
						};
						const items = flags.url?.trim()
							? await vault.listItemsForUrl(flags.url, filter)
							: await vault.listItems(filter);
						return items.map(item => vaultItemResponse(item));
					}
					const values = objectType === 'folders'
						? vault.listFolders()
						: objectType === 'collections'
						? await vault.listCollections()
						: objectType === 'org-collections'
						? await vault.listOrganizationCollections(flags.organizationid!)
						: objectType === 'org-members'
						? await vault.listOrganizationMembers(flags.organizationid!)
						: vault.listOrganizations();
					return values.filter(value =>
						(objectType === 'org-members' || !flags.search?.trim()
							|| (typeof value.name === 'string' && value.name.toLowerCase().includes(flags.search!.toLowerCase())))
						&& (!flags.organizationid || objectType !== 'collections'
							|| value.organizationId === flags.organizationid)
					).map(value => listObjectResponse(objectType, value));
				}, objectType === 'org-collections' || objectType === 'org-members'),
			);
		});
	const get = command('get').description('Read vault objects, secret fields, or object templates')
		.arg('object', arg.string())
		.arg('id', arg.string()).flag('session', sessionFlag()).flag('organizationid', flag.string()).flag(
			'itemid',
			flag.string(),
		).flag('output', flag.path()).flag('hibp-url', flag.string())
		.action(async ({ args, flags, out }) => {
			const objectType = args.object.toLowerCase();
			const id = args.id.toLowerCase();
			if (
				![
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
				].includes(objectType)
			) throw new Error('Unknown object.');
			if (objectType === 'attachment') {
				let attachment: { fileName: string; contents: Buffer };
				try {
					attachment = await runVault(
						flags.session,
						false,
						vault => {
							if (!flags.itemid) throw new Error('--itemid <itemid> required.');
							return vault.getAttachment(flags.itemid, id);
						},
						true,
					);
				} catch (error) {
					if (error instanceof MultipleResultsError && outputResponseError(error.message, error.ids)) throw error;
					throw error;
				}
				try {
					if (flags.raw && !flags.output) await writeStdout(attachment.contents);
					else out.log(await writeAttachment(flags.output, attachment.fileName, attachment.contents));
				} finally {
					attachment.contents.fill(0);
				}
				return;
			}

			if (objectType === 'template') {
				const result = await withStore(directory, async state => templateForServer(id, () => client(state)));
				out.json(result);
				return;
			}
			let result: unknown;
			try {
				result = await runVault(flags.session, false, async vault => {
					if (objectType === 'org-collection') {
						if (!flags.organizationid) throw new Error('`organizationid` option is required.');
						if (!isGuid(id)) throw new Error(`\`${id}\` is not a GUID.`);
						if (!isGuid(flags.organizationid)) {
							throw new Error(`\`${flags.organizationid}\` is not a GUID.`);
						}
					}
					if (objectType === 'send') return vault.sends.get(id);
					if (objectType === 'fingerprint') return vault.fingerprint(id);
					if (objectType === 'org-collection') return vault.getOrganizationCollection(flags.organizationid!, id);
					if (objectType === 'folder') return vault.findFolder(id);
					if (objectType === 'collection') return vault.findCollection(id);
					if (objectType === 'organization') return vault.findOrganization(id);
					const hasText = (value: unknown) => typeof value === 'string' && value.trim().length > 0;
					const item = await vault.findItem(id, item => {
						if (objectType === 'item') return true;
						if (objectType === 'notes') return hasText(item.notes);
						if (item.type !== 1 || !item.login) return false;
						if (objectType === 'uri') {
							const firstUri = Array.isArray(item.login.uris) && item.login.uris.length > 0
								? object(item.login.uris[0]).uri
								: undefined;
							return typeof firstUri === 'string' && firstUri !== '';
						}
						return hasText(item.login[objectType === 'exposed' ? 'password' : objectType]);
					});
					if (objectType === 'item') return vaultItemResponse(item);
					const login = object(item.login ?? {});
					if (item.viewPassword === false && ['password', 'totp', 'exposed'].includes(objectType)) {
						throw new Error(
							objectType === 'totp'
								? 'No TOTP available for this login.'
								: 'No password available for this login.',
						);
					}
					const value = objectType === 'notes'
						? item.notes
						: objectType === 'uri'
						? (Array.isArray(login.uris) ? object(login.uris[0] ?? {}).uri : undefined)
						: login[objectType === 'exposed' ? 'password' : objectType];
					if (typeof value !== 'string') throw new Error('Requested field is absent.');
					if (objectType === 'exposed') {
						return String(await new PasswordExposureClient({ baseUrl: flags['hibp-url'] }).count(value));
					}
					if (objectType === 'totp') {
						const code = totp(value);
						if (!vault.canAccessTotp(String(item.id))) {
							throw new Error('Premium status is required to use this feature.');
						}
						return code;
					}
					return value;
				}, objectType === 'org-collection' || (objectType === 'fingerprint' && id !== 'me'));
			} catch (error) {
				if (error instanceof MultipleResultsError && outputResponseError(error.message, error.ids)) throw error;
				if (error instanceof VaultObjectNotFoundError) throw new Error('Not found.');
				throw error;
			}
			if (typeof result === 'string') await writeStdout(result);
			else out.json(getObjectResponse(objectType, result));
		});
	const lock = command('lock')
		.description('Invalidate the current unlock session')
		.action(async ({ out }) =>
			withStore(directory, async (state, save) => {
				delete state.session;
				await save();
				out.log('Your vault is locked.');
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
				out.log('You have logged out.');
			})
		);
	let helpApp: ReturnType<typeof cli>;
	const versions = versionCommands();
	const app = cli('vw')
		.envPrefix('VW_')
		.plugin(outputPolicyPlugin())
		.plugin(accountAccessPlugin(directory))
		.default(
			command('root').action(async ({ out }) => {
				const help = await helpApp.execute(['--help']);
				out.log(help.stdout.join(''));
			}),
		)
		.version(CLI_PACKAGE.version)
		.description('A Vaultwarden-first client')
		.command(deviceApprovalCommand(async commandName => {
			const target = ['list', 'approve', 'approve-all', 'deny', 'deny-all'].includes(commandName ?? '')
				? commandName
				: undefined;
			const args = ['device-approval', ...(target ? [target] : []), '--help'];
			const help = await helpApp.execute(args);
			const output = help.stdout.join('');
			return target
				? output.replace(/^Usage: vw [^\n]+/, `Usage: vw device-approval ${target} [flags]`)
				: output;
		}, { run: runVault }))
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
		.command(logout)
		.completions();
	helpApp = app;
	return app;
}
