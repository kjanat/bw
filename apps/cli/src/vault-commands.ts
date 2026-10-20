import { outputCommand as command } from '#output';
import { readFile } from 'node:fs/promises';
import { basename } from 'node:path';
import { arg, flag } from '@kjanat/dreamcli';
import {
	decodeJson,
	decodeStringArray,
	template,
	type VaultService,
	type VaultItem,
	type VaultFolder,
} from '@kjanat/vaultwarden';

export interface VaultRuntime {
	run<T>(
		session: string | undefined,
		mutate: boolean,
		operation: (vault: VaultService) => Promise<T> | T,
		online?: boolean,
	): Promise<T>;
}
const session = () => flag.string().env('VW_SESSION').describe('Unlock session (or VW_SESSION)');
const input = () => arg.string().stdin({ trim: true }).describe('Base64-encoded JSON, or pipe from vw encode');
const org = () => flag.string().describe('Organization ID');
function organization(value?: string): string {
	if (!value) throw new Error('--organizationid is required for this operation.');
	return value;
}
export function vaultCommands(runtime: VaultRuntime) {
	const create = command('create').description('Create an encrypted item, folder, or organization collection')
		.arg('object', arg.enum(['item', 'folder', 'org-collection', 'attachment'])).arg('encodedJson', input().optional())
		.flag(
			'session',
			session(),
		).flag('organizationid', org()).flag('file', flag.path({ mustExist: true })).flag('itemid', flag.string())
		.action(async ({ args, flags, out }) => {
			if (args.object === 'attachment') {
				if (!flags.file || !flags.itemid) throw new Error('--file and --itemid are required.');
				const contents = await readFile(flags.file);
				try {
					out.json(
						await runtime.run(
							flags.session,
							true,
							vault => vault.createAttachment(flags.itemid!, basename(flags.file!), contents),
						),
					);
				} finally {
					contents.fill(0);
				}
				return;
			}
			if (!args.encodedJson) throw new Error('Encoded JSON is required.');
			const data = decodeJson(args.encodedJson);
			out.json(
				await runtime.run(flags.session, true, vault =>
					args.object === 'item'
						? vault.createItem(data as VaultItem)
						: args.object === 'folder'
						? vault.createFolder(data as VaultFolder)
						: vault.createCollection(organization(flags.organizationid), data)),
			);
		});
	const edit = command('edit').description('Edit an item, folder, collection, or item collection assignments')
		.arg('object', arg.enum(['item', 'folder', 'org-collection', 'item-collections'])).arg('id', arg.string()).arg(
			'encodedJson',
			input(),
		).flag('session', session()).flag('organizationid', org())
		.action(async ({ args, flags, out }) => {
			if (args.object === 'item-collections') {
				await runtime.run(
					flags.session,
					true,
					vault => vault.editItemCollections(args.id, decodeStringArray(args.encodedJson)),
				);
				out.log('Updated item collections.');
				return;
			}
			const data = decodeJson(args.encodedJson);
			out.json(
				await runtime.run(flags.session, true, vault =>
					args.object === 'item'
						? vault.editItem(args.id, data as VaultItem)
						: args.object === 'folder'
						? vault.editFolder(args.id, data as VaultFolder)
						: vault.editCollection(organization(flags.organizationid), args.id, data)),
			);
		});
	const remove = command('delete').description('Trash an item or delete a folder or collection')
		.arg('object', arg.enum(['item', 'folder', 'org-collection', 'attachment'])).arg('id', arg.string()).flag(
			'session',
			session(),
		)
		.flag('organizationid', org()).flag('itemid', flag.string())
		.flag('permanent', flag.boolean().alias('p').describe('Permanently delete the item'))
		.action(async ({ args, flags, out }) => {
			if (args.object === 'attachment') {
				if (!flags.itemid) throw new Error('--itemid is required.');
				await runtime.run(flags.session, true, vault => vault.deleteAttachment(flags.itemid!, args.id));
				out.log('Deleted.');
				return;
			}
			await runtime.run(
				flags.session,
				true,
				vault =>
					args.object === 'item'
						? vault.deleteItem(args.id, flags.permanent)
						: args.object === 'folder'
						? vault.deleteFolder(args.id)
						: vault.deleteCollection(organization(flags.organizationid), args.id),
			);
			out.log('Deleted.');
		});
	const restore = command('restore').description('Restore an item from trash or archive')
		.arg('object', arg.enum(['item'])).arg('id', arg.string()).flag('session', session())
		.action(async ({ args, flags, out }) => {
			await runtime.run(flags.session, true, vault => vault.restoreItem(args.id));
			out.log('Restored.');
		});
	const archive = command('archive').description('Archive an item')
		.arg('object', arg.enum(['item'])).arg('id', arg.string()).flag('session', session())
		.action(async ({ args, flags, out }) => {
			await runtime.run(flags.session, true, vault => vault.archiveItem(args.id));
			out.log('Archived.');
		});
	const moveCommand = (name: string) =>
		command(name).description(
			name === 'share' ? 'Deprecated alias for move' : 'Move a personal item to an organization',
		)
			.arg('id', arg.string()).arg('organizationId', arg.string()).arg('encodedJson', input())
			.flag('session', session()).action(async ({ args, flags, out }) => {
				out.json(
					await runtime.run(flags.session, true, vault =>
						vault.moveItem(args.id, args.organizationId, decodeStringArray(args.encodedJson))),
				);
			});
	const move = moveCommand('move');
	const share = moveCommand('share');
	const confirm = command('confirm').description('Confirm an accepted organization member')
		.arg('object', arg.enum(['org-member'])).arg('id', arg.string()).flag('organizationid', org()).flag(
			'session',
			session(),
		)
		.action(async ({ args, flags, out }) => {
			await runtime.run(flags.session, true, vault => vault.confirmMember(organization(flags.organizationid), args.id));
			out.log('Confirmed.');
		});
	const encode = command('encode').description('Base64 encode UTF-8 stdin')
		.arg('input', arg.string().stdin()).action(({ args, out }) => {
			out.log(Buffer.from(args.input, 'utf8').toString('base64'));
		});
	return { create, edit, remove, restore, archive, move, share, confirm, encode };
}
export { template };
