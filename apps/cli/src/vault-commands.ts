import { getObjectResponse, outputCommand as command, outputSuccess } from '#output';
import { readFile } from 'node:fs/promises';
import { basename, resolve } from 'node:path';
import { arg, flag } from '@kjanat/dreamcli';
import { prompt } from '@kjanat/dreamcli/prompt';
import { cliPromptSession } from '#prompts';
import {
	decodeJson,
	decodeStringArray,
	template,
	vaultItemResponse,
	type JsonObject,
	type VaultService,
	type VaultItem,
	type VaultFolder,
	type EditVaultItem,
} from '@kjanat/vaultwarden';

export interface VaultRuntime {
	run<T>(
		session: string | undefined,
		mutate: boolean,
		operation: (vault: VaultService) => Promise<T> | T,
		online?: boolean,
	): Promise<T>;
}
export async function prepareArchivedItemEdit(
	vault: Pick<VaultService, 'shouldUnarchiveBeforeEdit'>,
	id: string,
	data: JsonObject,
	options: {
		noInteraction: boolean;
		isTTY: boolean;
		ask: () => Promise<string>;
		write: (message: string) => void;
	},
): Promise<void> {
	if (!(await vault.shouldUnarchiveBeforeEdit(id))) return;
	if (options.noInteraction || !options.isTTY) {
		options.write(
			'Archive is only available with a Premium subscription, which has ended. Your edit was saved and the item was moved back to your vault.',
		);
	} else if (await options.ask() !== 'confirmed') throw new Error('Edit cancelled.');
	data.archivedDate = null;
}
const session = () => flag.string().sensitive().env('SESSION').describe('Unlock session (or VW_SESSION)');
const input = () => arg.string().stdin({ trim: true }).describe('Base64-encoded JSON, or pipe from vw encode');
const org = () => flag.string().describe('Organization ID');
function organization(value?: string): string {
	if (!value) throw new Error('--organizationid is required for this operation.');
	return value;
}
function decodeRequestJson(value: string): JsonObject {
	try {
		return decodeJson(value);
	} catch {
		throw new Error('Error parsing the encoded request data.');
	}
}
const isGuid = (value: string) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
export function collectionOrganizationId(option: string | undefined, data: JsonObject): string {
	const optionProvided = typeof option === 'string' && !!option.trim();
	const organizationId = optionProvided ? option : data.organizationId;
	if (typeof organizationId !== 'string' || !organizationId.trim()) {
		throw new Error(
			'An organization id is required, either via the `--organizationid` option '
				+ '(or `organizationId` query parameter when using `bw serve`), '
				+ "or the request's `organizationId` property.",
		);
	}
	if (!isGuid(organizationId)) throw new Error(`\`${organizationId}\` is not a GUID.`);
	if (
		optionProvided && typeof data.organizationId === 'string' && data.organizationId.trim()
		&& option.toLowerCase() !== data.organizationId.toLowerCase()
	) {
		throw new Error(
			'The `--organizationid` option (or `organizationId` query parameter) does not match '
				+ "the request's `organizationId` property.",
		);
	}
	const normalized = organizationId.toLowerCase();
	data.organizationId = normalized;
	return normalized;
}
export function vaultCommands(runtime: VaultRuntime) {
	const create = command('create').description('Create an encrypted item, folder, or organization collection')
		.arg('object', arg.enum(['item', 'folder', 'org-collection', 'attachment'])).arg('encodedJson', input().optional())
		.flag(
			'session',
			session(),
		).flag('organizationid', org()).flag('file', flag.path()).flag('itemid', flag.string())
		.action(async ({ args, flags, out }) => {
			if (args.object === 'attachment') {
				const result = await runtime.run(flags.session, true, async vault => {
					if (!flags.itemid) throw new Error('`itemid` option is required.');
					if (!flags.file) throw new Error('`file` option is required.');
					const filePath = resolve(flags.file);
					let contents: Buffer;
					try {
						contents = await readFile(filePath);
					} catch (error) {
						if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') {
							throw new Error(`File not found: ${filePath}`);
						}
						throw error;
					}
					try {
						return await vault.createAttachment(flags.itemid.toLowerCase(), basename(filePath), contents);
					} finally {
						contents.fill(0);
					}
				});
				out.json(vaultItemResponse(result));
				return;
			}
			const result = await runtime.run(flags.session, true, vault => {
				if (!args.encodedJson) throw new Error('`requestJson` was not provided.');
				const data = decodeRequestJson(args.encodedJson);
				const organizationId = args.object === 'org-collection'
					? collectionOrganizationId(flags.organizationid, data)
					: undefined;
				return args.object === 'item'
					? vault.createItem(data as VaultItem)
					: args.object === 'folder'
					? vault.createFolder(data as VaultFolder)
					: vault.createCollection(organizationId!, data);
			});
			out.json(args.object === 'item' ? vaultItemResponse(result) : getObjectResponse(args.object, result));
		});
	const edit = command('edit').description('Edit an item, folder, collection, or item collection assignments')
		.arg('object', arg.string()).arg('id', arg.string()).arg(
			'encodedJson',
			input().optional(),
		).flag('session', session()).flag('organizationid', org())
		.action(async ({ args, flags, out }) => {
			const encodedJson = args.encodedJson;
			if (!['item', 'item-collections', 'folder', 'org-collection'].includes(args.object)) {
				throw new Error('Unknown object.');
			}
			if (args.object === 'item-collections') {
				const result = await runtime.run(
					flags.session,
					true,
					vault => {
						if (!encodedJson) throw new Error('`requestJson` was not provided.');
						return vault.editItemCollections(args.id, decodeStringArray(encodedJson));
					},
				);
				out.json(vaultItemResponse(result));
				return;
			}
			const result = await runtime.run(flags.session, true, async vault => {
				if (!encodedJson) throw new Error('`requestJson` was not provided.');
				const data = decodeRequestJson(encodedJson);
				if (args.object === 'org-collection' && !isGuid(args.id)) {
					throw new Error(`\`${args.id}\` is not a GUID.`);
				}
				const organizationId = args.object === 'org-collection'
					? collectionOrganizationId(flags.organizationid, data)
					: undefined;
				if (args.object === 'item') {
					await prepareArchivedItemEdit(vault, args.id, data, {
						noInteraction: flags.nointeraction,
						isTTY: Boolean(process.stdin.isTTY),
						ask: () =>
							cliPromptSession().ask(prompt.select({
								message:
									"When you edit and save details for an archived item without a Premium subscription, it'll be moved from your archive back to your vault.",
								choices: [
									{ label: 'Move now', value: 'confirmed' },
									{ label: 'Cancel', value: 'cancel' },
								],
							})),
						write: message => out.log(message),
					});
				}
				return args.object === 'item'
					? vault.editItem(args.id, data as EditVaultItem)
					: args.object === 'folder'
					? vault.editFolder(args.id, data as VaultFolder)
					: vault.editCollection(organizationId!, args.id, data);
			});
			out.json(args.object === 'item' ? vaultItemResponse(result) : getObjectResponse(args.object, result));
		});
	const remove = command('delete').description('Trash an item or delete a folder or collection')
		.arg('object', arg.enum(['item', 'folder', 'org-collection', 'attachment'])).arg('id', arg.string()).flag(
			'session',
			session(),
		)
		.flag('organizationid', org()).flag('itemid', flag.string())
		.flag('permanent', flag.boolean().alias('p').describe('Permanently delete the item'))
		.action(async ({ args, flags }) => {
			if (args.object === 'attachment') {
				await runtime.run(flags.session, true, vault => {
					if (!flags.itemid) throw new Error('`itemid` option is required.');
					return vault.deleteAttachment(flags.itemid.toLowerCase(), args.id);
				});
				outputSuccess();
				return;
			}
			await runtime.run(
				flags.session,
				true,
				vault => {
					if (args.object === 'org-collection') {
						if (!flags.organizationid) throw new Error('`organizationid` options is required.');
						if (!isGuid(args.id)) throw new Error(`\`${args.id}\` is not a GUID.`);
						if (!isGuid(flags.organizationid)) {
							throw new Error(`\`${flags.organizationid}\` is not a GUID.`);
						}
					}
					return args.object === 'item'
						? vault.deleteItem(args.id, flags.permanent)
						: args.object === 'folder'
						? vault.deleteFolder(args.id)
						: vault.deleteCollection(organization(flags.organizationid), args.id);
				},
			);
			outputSuccess();
		});
	const restore = command('restore').description('Restore an item from trash or archive')
		.arg('object', arg.string()).arg('id', arg.string()).flag('session', session())
		.action(async ({ args, flags }) => {
			if (args.object !== 'item') throw new Error('Unknown object.');
			await runtime.run(flags.session, true, vault => vault.restoreItem(args.id));
			outputSuccess();
		});
	const archive = command('archive').description('Archive an item')
		.arg('object', arg.enum(['item'])).arg('id', arg.string()).flag('session', session())
		.action(async ({ args, flags }) => {
			await runtime.run(flags.session, true, vault => vault.archiveItem(args.id));
			outputSuccess();
		});
	const moveCommand = (name: string) =>
		command(name).description(
			name === 'share' ? 'Deprecated alias for move' : 'Move a personal item to an organization',
		)
			.arg('id', arg.string()).arg('organizationId', arg.string()).arg('encodedJson', input().optional())
			.flag('session', session()).action(async ({ args, flags, out }) => {
				const moved = await runtime.run(flags.session, true, vault => {
					const collectionIds = args.encodedJson?.trim() ? decodeStringArray(args.encodedJson) : [];
					return vault.moveItem(args.id, args.organizationId, collectionIds);
				});
				out.json(vaultItemResponse(moved));
			});
	const move = moveCommand('move');
	const share = moveCommand('share');
	const confirm = command('confirm').description('Confirm an accepted organization member')
		.arg('object', arg.enum(['org-member'])).arg('id', arg.string()).flag('organizationid', org()).flag(
			'session',
			session(),
		)
		.action(async ({ args, flags }) => {
			await runtime.run(flags.session, true, vault => vault.confirmMember(organization(flags.organizationid), args.id));
			outputSuccess();
		});
	const encode = command('encode').description('Base64 encode UTF-8 stdin')
		.arg('input', arg.string().stdin().optional()).action(({ args, out }) => {
			out.log(Buffer.from(args.input ?? '', 'utf8').toString('base64'));
		});
	return { create, edit, remove, restore, archive, move, share, confirm, encode };
}
export { template };
