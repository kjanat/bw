import { arg, cli, command, flag } from '@kjanat/dreamcli';
import passwordPrompt from '@inquirer/password';
import {
	VaultwardenClient,
	ApiError,
	ImportFailure,
	loginWithPassword,
	unlockAccount,
	serverUrl,
	VaultService,
	totp,
	object,
	type JsonObject,
} from '@kjanat/vaultwarden';
import { writeAttachment } from '#files';
import { toolCommands } from '#tool-commands';
import { vaultCommands, template } from '#vault-commands';
import { dataDirectory, openSession, sealSession, withStore, type State } from '#store';

const sessionFlag = () => flag.string().env('VW_SESSION').describe('Unlock session (or VW_SESSION)');
const passwordEnvFlag = () =>
	flag
		.string()
		.default('VW_PASSWORD')
		.describe('Environment variable containing the master password');
async function password(envName: string): Promise<string> {
	const value = process.env[envName];
	if (value !== undefined) {
		if (!value) throw new Error('Master password is empty.');
		return value;
	}
	if (!process.stdin.isTTY) {
		throw new Error(
			'Set the master password environment variable or use an interactive terminal.',
		);
	}
	const result = await passwordPrompt({
		message: 'Master password:',
		mask: '*',
	});
	if (!result) throw new Error('Master password is required.');
	return result;
}
function client(state: State): VaultwardenClient {
	if (!state.server) {
		throw new Error(
			'Configure a server first: vw config server https://vault.example.com',
		);
	}
	return new VaultwardenClient(state.server, { deviceId: state.deviceId });
}
async function sync(state: State, save: () => Promise<void>): Promise<void> {
	const account = state.account;
	if (!account) throw new Error('Log in first.');
	const api = client(state);
	const refresh = async () => {
		Object.assign(account, await api.refresh(account.refreshToken));
		await save();
	};
	if (account.expiresAt <= Date.now() + 30_000) await refresh();
	try {
		state.vault = await api.sync(account.accessToken);
	} catch (error) {
		if (!(error instanceof ApiError) || error.status !== 401) throw error;
		await refresh();
		state.vault = await api.sync(account.accessToken);
	}
	state.lastSync = new Date().toISOString();
	await save();
}
function select(items: JsonObject[], query: string): JsonObject {
	const byId = items.find((item) => item.id === query);
	if (byId) return byId;
	const matches = items.filter((item) => item.name === query);
	if (matches.length !== 1) {
		throw new Error(
			matches.length
				? 'Multiple matching items. Use an item ID.'
				: 'Item not found.',
		);
	}
	return matches[0]!;
}
export function createApp(directory = dataDirectory()) {
	const config = command('config')
		.description('Read or set the Vaultwarden server')
		.arg('key', arg.enum(['server']))
		.arg('url', arg.string().optional())
		.action(async ({ args, out }) =>
			withStore(directory, async (state, save) => {
				if (args.url) {
					const url = serverUrl(args.url);
					if (state.account && url !== state.server) {
						throw new Error('Log out before changing servers.');
					}
					state.server = url;
					await save();
				}
				out.log(state.server ?? '');
			})
		);
	const login = command('login')
		.description('Log in to Vaultwarden; the vault remains locked')
		.arg('email', arg.string().nonEmpty())
		.flag('passwordenv', passwordEnvFlag())
		.flag(
			'method',
			flag
				.number({ int: true, min: 0 })
				.describe('Two-factor provider: 0=TOTP, 1=email, 3=YubiKey'),
		)
		.flag(
			'code',
			flag.string().env('VW_2FA_TOKEN').describe('Two-factor token'),
		)
		.action(async ({ args, flags, out }) =>
			withStore(directory, async (state, save) => {
				if (state.account) {
					throw new Error(
						'Already logged in. Log out before logging in again.',
					);
				}
				if ((flags.method === undefined) !== (flags.code === undefined)) {
					throw new Error(
						'Supply both --method and --code for two-factor login.',
					);
				}
				state.account = await loginWithPassword(
					client(state),
					args.email,
					await password(flags.passwordenv),
					flags.method === undefined
						? undefined
						: { provider: flags.method, token: flags.code! },
				);
				delete state.session;
				delete state.vault;
				delete state.lastSync;
				await save();
				out.log('Logged in. Run vw sync, then vw unlock --raw.');
			})
		);
	const unlock = command('unlock')
		.description('Unlock the cached user key and issue a session')
		.flag('passwordenv', passwordEnvFlag())
		.flag('raw', flag.boolean().describe('Print only the session token'))
		.action(async ({ flags, out }) =>
			withStore(directory, async (state, save) => {
				if (!state.account) throw new Error('Log in first.');
				const key = await unlockAccount(
					state.account,
					await password(flags.passwordenv),
				);
				try {
					const token = sealSession(state, key);
					await save();
					if (flags.raw) out.log(token);
					else {
						out.status(
							'Unlocked. Set VW_SESSION to this token for subsequent commands.',
						);
						out.log(token);
					}
				} finally {
					key.fill(0);
				}
			})
		);
	const syncCommand = command('sync')
		.description('Download the encrypted vault (also works while locked)')
		.action(async ({ out }) =>
			withStore(directory, async (state, save) => {
				await sync(state, save);
				out.log('Sync complete.');
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
					Object.assign(state.account, await client(state).refresh(state.account.refreshToken));
					await save();
				}
				vault = new VaultService(client(state), state.account.accessToken, state.vault, key);
				let result: T;
				try {
					result = await action(vault);
				} catch (error) {
					if (error instanceof ImportFailure) {
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
		.flag('session', sessionFlag()).flag('search', flag.string())
		.flag('folderid', flag.string()).flag('organizationid', flag.string()).flag('collectionid', flag.string())
		.flag('trash', flag.boolean()).flag('archived', flag.boolean())
		.action(async ({ args, flags, out }) => {
			out.json(
				await runVault(flags.session, false, async vault => {
					if (args.object === 'items') {
						return vault.listItems({
							search: flags.search,
							folderId: flags.folderid,
							organizationId: flags.organizationid,
							collectionId: flags.collectionid,
							trash: flags.trash,
							archived: flags.archived,
						});
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
		).flag('output', flag.path()).flag('raw', flag.boolean())
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
					if (flags.raw && !flags.output) process.stdout.write(attachment.contents);
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
				if (args.object === 'org-collection') {
					if (!flags.organizationid) throw new Error('--organizationid is required.');
					return vault.getOrganizationCollection(flags.organizationid, args.id);
				}
				if (args.object === 'folder') return select(vault.listFolders(), args.id);
				if (args.object === 'collection') return select(vault.listCollections(), args.id);
				if (args.object === 'organization') return select(vault.listOrganizations(), args.id);
				const item = select([
					...vault.listItems(),
					...vault.listItems({ trash: true }),
					...vault.listItems({ archived: true }),
				], args.id);
				if (args.object === 'item') return item;
				const login = object(item.login ?? {});
				const value = args.object === 'notes'
					? item.notes
					: args.object === 'uri'
					? (Array.isArray(login.uris) ? object(login.uris[0] ?? {}).uri : undefined)
					: login[args.object];
				if (typeof value !== 'string') throw new Error('Requested field is absent.');
				return args.object === 'totp' ? totp(value) : value;
			}, args.object === 'org-collection');
			if (typeof result === 'string') out.log(result);
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
	return cli('vw')
		.version('0.1.0')
		.description('A Vaultwarden-first client')
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
}
