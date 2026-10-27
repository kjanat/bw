import { outputCommand as command, outputResponseError, outputSuccess } from '#output';
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { basename } from 'node:path';
import { arg, flag } from '@kjanat/dreamcli';
import { secretPrompt } from '#prompts';
import {
	decodeJson,
	object,
	sendObjectResponse,
	sendTemplate,
	receiveSend,
	SendPasswordRequired,
	MultipleResultsError,
	type SendInput,
	type JsonObject,
} from '@kjanat/vaultwarden';
import type { VaultRuntime } from '#vault-commands';
import { writeAttachment, writeStdout } from '#files';

const session = () => flag.string().sensitive().env('SESSION');
const input = () => arg.string().sensitive().stdin({ trim: true }).optional();
function decodeSendJson(value: string): JsonObject {
	try {
		return decodeJson(value);
	} catch {
		throw new Error('Error parsing the encoded request data.');
	}
}
export async function sendPassword(
	value: string | undefined,
	source: string | undefined,
	environmentName: string | undefined,
	passwordFile?: string,
	requireNamedEnvironment = false,
): Promise<string | undefined> {
	const explicitValue = source === 'env' ? undefined : value;
	const defaultValue = source === 'env' ? value : undefined;
	if (explicitValue) return explicitValue;
	if (passwordFile !== undefined) {
		return (await readFile(passwordFile, 'utf8')).split(/\r\n|\r|\n/, 1)[0] || undefined;
	}
	if (environmentName !== undefined) {
		const environmentValue = process.env[environmentName];
		if (!environmentValue) {
			if (requireNamedEnvironment) {
				throw new Error('The selected Send password environment variable is unset.');
			}
			return undefined;
		}
		return environmentValue;
	}
	return defaultValue || undefined;
}
export function sendResponseData(send: JsonObject, objectType = 'send'): JsonObject {
	return sendObjectResponse(send, objectType);
}
export function quickSendResult(send: JsonObject, fullObject: boolean): JsonObject | string {
	return fullObject ? sendResponseData(send) : String(send.accessUrl ?? '');
}
async function raw(contents: Uint8Array): Promise<void> {
	await writeStdout(contents);
}
export function receiveCommand() {
	return command('receive').description('Read a Send without logging in; decrypt its fragment key locally')
		.arg('url', arg.string().sensitive()).flag('password', flag.string().sensitive().env('SEND_PASSWORD'))
		.flag(
			'passwordenv',
			flag.string().describe(
				'Read the Send password from this variable. Without this option, receive reads VW_SEND_PASSWORD.',
			),
		)
		.flag('passwordfile', flag.path({ mustExist: true })).flag('obj', flag.boolean())
		.flag('output', flag.path())
		.action(async ({ args, flags, out, sources }) => {
			let password = await sendPassword(
				flags.password,
				sources.flags.password?.stage,
				flags.passwordenv,
				flags.passwordfile,
				true,
			);
			let result;
			try {
				result = await receiveSend(args.url, { password, download: !flags.obj });
			} catch (error) {
				if (!(error instanceof SendPasswordRequired) || password !== undefined) throw error;
				if (flags.nointeraction) throw new Error('Password required');
				if (!process.stdin.isTTY) throw error;
				password = await secretPrompt('Send password:');
				result = await receiveSend(args.url, { password, download: !flags.obj });
			}
			if (flags.obj) out.json(sendResponseData(result.send, 'send-access'));
			else if (result.contents) {
				try {
					if (flags.raw && !flags.output) await raw(result.contents);
					else out.log(await writeAttachment(flags.output, result.fileName!, result.contents));
				} finally {
					result.contents.fill(0);
				}
			} else await raw(Buffer.from(String(object(result.send.text).text)));
		});
}
export function sendCommands(runtime: VaultRuntime) {
	async function create(data: JsonObject, session: string | undefined, filePath?: string): Promise<JsonObject> {
		const type = data.type ?? (filePath ? 1 : 0);
		if (type !== 0 && type !== 1) throw new Error('This server accepts text and file Sends only.');
		const file = data.file == null ? {} : object(data.file);
		const path = typeof file.fileName === 'string' ? file.fileName : filePath;
		if (type === 1) {
			await runtime.run(session, false, vault => vault.sends.assertCanCreate(1));
		}
		const contents = type === 1 && path ? await readFile(path) : undefined;
		try {
			const request = {
				...data,
				type,
				name: typeof data.name === 'string' ? data.name : type === 1 && path ? basename(path) : randomUUID(),
				...(type === 1 && path ? { file: { fileName: basename(path) } } : {}),
			} as SendInput;
			return await runtime.run(session, true, vault => vault.sends.create(request, contents));
		} finally {
			contents?.fill(0);
		}
	}
	const createCommand = command('create').description('Create a Send from encoded JSON, or file/text options')
		.arg('encodedJson', input()).flag('session', session()).flag('file', flag.path({ mustExist: true }))
		.flag('text', flag.string().sensitive()).flag('hidden', flag.boolean())
		.action(async ({ args, flags, out }) => {
			if (!args.encodedJson) throw new Error('`requestJson` was not provided.');
			const data = decodeSendJson(args.encodedJson);
			if (data.text == null && flags.text !== undefined) data.text = { text: flags.text, hidden: flags.hidden };
			if (data.type == null) data.type = flags.file ? 1 : 0;
			out.json(sendResponseData(await create(data, flags.session, flags.file)));
		});
	const list = command('list').description('List decrypted Sends from the cache').flag('session', session())
		.action(async ({ flags, out }) =>
			out.json(
				(await runtime.run(flags.session, false, vault => vault.sends.list())).map(send => sendResponseData(send)),
			)
		);
	const get = command('get').description('Read an owned Send by ID or unique search term').arg('id', arg.string())
		.flag('session', session()).flag('text', flag.boolean())
		.action(async ({ args, flags, out }) => {
			let send: JsonObject;
			try {
				send = await runtime.run(flags.session, false, vault => vault.sends.get(args.id, flags.text ? 0 : undefined));
			} catch (error) {
				if (error instanceof MultipleResultsError && outputResponseError(error.message, error.ids)) throw error;
				throw error;
			}
			if (flags.text) {
				await raw(Buffer.from(String(object(send.text).text)));
			} else out.json(sendResponseData(send));
		});
	const edit = command('edit').description('Edit Send metadata or text; file contents are immutable')
		.arg('encodedJson', input()).flag('itemid', flag.string()).flag('session', session())
		.action(async ({ args, flags, out }) => {
			if (!args.encodedJson) throw new Error('`requestJson` was not provided.');
			const patch = decodeSendJson(args.encodedJson);
			const id = flags.itemid ?? (typeof patch.id === 'string' ? patch.id : undefined);
			if (!id) throw new Error('`itemid` was not provided.');
			out.json(sendResponseData(
				await runtime.run(flags.session, true, vault => vault.sends.edit(id, patch)),
			));
		});
	const remove = command('delete').description('Permanently delete a Send').arg('id', arg.string()).flag(
		'session',
		session(),
	)
		.action(async ({ args, flags }) => {
			await runtime.run(flags.session, true, vault => vault.sends.delete(args.id));
			outputSuccess();
		});
	const removePassword = command('remove-password').description('Remove password protection from a Send')
		.arg('id', arg.string()).flag('session', session())
		.action(async ({ args, flags, out }) =>
			out.json(sendResponseData(await runtime.run(flags.session, true, vault => vault.sends.removePassword(args.id))))
		);
	const template = command('template').description('Print an editable Send JSON template').arg(
		'object',
		arg.enum(['send', 'text', 'file', 'send.text', 'send.file']),
	)
		.action(({ args, out }) => out.json(sendTemplate(args.object.endsWith('file') ? 1 : 0)));
	return command('send').description('Create or manage encrypted text and file Sends')
		.arg('data', arg.string().sensitive().stdin({ trim: false }).optional()).flag('session', session())
		.flag('file', flag.boolean().alias('f')).flag(
			'deleteInDays',
			flag.number({ min: 0, max: 31 }).alias('d').default(7),
		)
		.flag('password', flag.string().sensitive().env('SEND_PASSWORD')).flag(
			'passwordenv',
			flag.string().describe(
				'Read the Send password from this variable. Without this option, send reads VW_SEND_PASSWORD.',
			),
		)
		.flag('emails', flag.string())
		.flag('maxAccessCount', flag.number({ int: true, min: 0, max: 2147483647 }).alias('a'))
		.flag('hidden', flag.boolean()).flag('name', flag.string().alias('n'))
		.flag('notes', flag.string().sensitive())
		.flag('fullObject', flag.boolean())
		.command(createCommand).command(list).command(get).command(edit).command(remove).command(removePassword).command(
			template,
		).command(receiveCommand())
		.action(async ({ args, flags, out, sources }) => {
			if (args.data === undefined) throw new Error('Send data is required.');
			const password = await sendPassword(
				flags.password,
				sources.flags.password?.stage,
				flags.passwordenv,
				undefined,
				true,
			);
			const result = await create(
				{
					type: flags.file ? 1 : 0,
					name: flags.name ?? (flags.file ? basename(args.data) : randomUUID()),
					notes: flags.notes,
					deletionDate: new Date(Date.now() + flags.deleteInDays * 86400000).toISOString(),
					password,
					emails: flags.emails === undefined
						? undefined
						: flags.emails.split(',').map(email => email.trim()).filter(Boolean),
					maxAccessCount: flags.maxAccessCount,
					...(flags.file ? {} : { text: { text: args.data, hidden: flags.hidden } }),
				},
				flags.session,
				flags.file ? args.data : undefined,
			);
			const output = quickSendResult(result, flags.fullObject);
			if (typeof output === 'string') out.log(output);
			else out.json(output);
		});
}
