import { outputCommand as command, outputIsResponse } from '#output';
import { readFile } from 'node:fs/promises';
import { arg, flag } from '@kjanat/dreamcli';
import { secretPrompt } from '#prompts';
import {
	generateSecret,
	importFormats,
	object,
	parseGeneratorNumber,
	resolveImportFormat,
	type ImportFormat,
} from '@kjanat/vaultwarden';
import { withStore } from '#store';
import { writeAttachment, writeStdout } from '#files';
import type { VaultRuntime } from '#vault-commands';

async function password(
	value: string | undefined,
	env: string | undefined,
	file: string | undefined,
	fallback: string,
): Promise<string | undefined> {
	if ([value !== undefined, env !== undefined, file !== undefined].filter(Boolean).length > 1) {
		throw new Error('Choose one password source.');
	}
	if (value !== undefined) return value;
	if (file) return (await readFile(file, 'utf8')).split(/\r\n|\r|\n/, 1)[0] ?? '';
	const secret = process.env[env ?? fallback];
	if (env && secret === undefined) throw new Error('The selected password environment variable is unset.');
	return secret;
}
export function resolvedExportFormat(
	format: 'csv' | 'json' | 'encrypted_json' | 'zip',
	hasPassword: boolean,
): 'csv' | 'json' | 'encrypted_json' | 'zip' {
	return format === 'json' && hasPassword ? 'encrypted_json' : format;
}
export function toolCommands(runtime: VaultRuntime, directory: string) {
	const generate = command('generate').description('Generate a password or EFF-wordlist passphrase locally')
		.flag('uppercase', flag.boolean().alias('u')).flag('lowercase', flag.boolean().alias('l'))
		.flag('number', flag.boolean().alias('n')).flag('special', flag.boolean().alias('s'))
		.flag('passphrase', flag.boolean().alias('p'))
		.flag('length', flag.string())
		.flag('words', flag.string())
		.flag('minNumber', flag.string())
		.flag('minSpecial', flag.string())
		.flag('separator', flag.string().default('-')).flag('capitalize', flag.boolean().alias('c'))
		.flag('includeNumber', flag.boolean()).flag('ambiguous', flag.boolean().describe('Avoid ambiguous characters'))
		.action(async ({ flags, out }) => {
			const policies = await withStore(
				directory,
				async state => state.account && Array.isArray(state.vault?.policies) ? state.vault!.policies.map(object) : [],
			);
			const { length, words, minNumber, minSpecial, ...options } = flags;
			out.log(
				generateSecret({
					...options,
					length: parseGeneratorNumber(length, 14),
					words: parseGeneratorNumber(words, 6),
					minNumber: parseGeneratorNumber(minNumber, 1),
					minSpecial: parseGeneratorNumber(minSpecial, 0),
					avoidAmbiguous: flags.ambiguous,
				}, policies),
			);
		});
	const exportCommand = command('export').description('Export a personal or organization vault')
		.arg('password', arg.string().sensitive().optional())
		.flag('format', flag.enum(['csv', 'json', 'encrypted_json', 'zip']).default('csv'))
		.flag('organizationid', flag.string()).flag('session', flag.string().env('VW_SESSION'))
		.flag('output', flag.path())
		.flag('password', flag.string()).flag('passwordenv', flag.string()).flag(
			'passwordfile',
			flag.path({ mustExist: true }),
		)
		.action(async ({ args, flags, out }) => {
			if (args.password !== undefined && flags.password !== undefined) {
				throw new Error('Choose one password source.');
			}
			const format = resolvedExportFormat(
				flags.format,
				args.password !== undefined || flags.password !== undefined || !!flags.passwordenv || !!flags.passwordfile,
			);
			const secret = format === 'encrypted_json'
				? await password(args.password ?? flags.password, flags.passwordenv, flags.passwordfile, 'VW_EXPORT_PASSWORD')
				: undefined;
			const result = await runtime.run(
				flags.session,
				false,
				vault =>
					vault.exportVault(format, {
						organizationId: flags.organizationid,
						password: secret,
						onAttachmentSkipped: (itemId, attachmentId) =>
							out.status(`Skipped attachment ${attachmentId} from item ${itemId} during ZIP export.`),
					}),
				format === 'zip' || !!flags.organizationid,
			);
			try {
				if (flags.raw && !flags.output) {
					await writeStdout(result);
				} else {
					const extension = format === 'encrypted_json' ? 'json' : format;
					const name = `vaultwarden_export_${new Date().toISOString().replace(/[:.]/g, '-')}.${extension}`;
					out.log(await writeAttachment(flags.output, name, result));
				}
			} finally {
				result.fill(0);
			}
		});
	const importCommand = command('import').description('Import vault JSON, CSV, XML, KDBX, or a ZIP backup')
		.arg('format', arg.enum(importFormats).optional()).arg('input', arg.path({ mustExist: true }).optional())
		.flag('formats', flag.boolean()).flag('organizationid', flag.string()).flag(
			'session',
			flag.string().env('VW_SESSION'),
		)
		.flag('passwordenv', flag.string()).flag('passwordfile', flag.path({ mustExist: true }))
		.flag('keyfile', flag.path())
		.action(async ({ args, flags, out }) => {
			if (flags.formats) {
				await withStore(directory, async state => {
					if (!state.account) throw new Error('You are not logged in.');
				});
				const formats = [...importFormats].sort().join('\n');
				if (outputIsResponse()) {
					out.json({
						object: 'message',
						title: 'Supported input formats:',
						message: formats,
						raw: formats,
						noColor: false,
					});
				} else out.log(flags.raw ? formats : `Supported input formats:\n${formats}`);
				return;
			}
			if (!args.format || !args.input) {
				throw new Error('An import format and file are required. Use vw import --formats.');
			}
			const format = resolveImportFormat(args.format as ImportFormat, args.input);
			const source = await readFile(args.input);
			let keyFile: Buffer | undefined;
			try {
				if (flags.keyfile) {
					if (format !== 'keepasskdbx') throw new Error('--keyfile requires the keepasskdbx format.');
					keyFile = await readFile(flags.keyfile);
				}
				let secret = await password(undefined, flags.passwordenv, flags.passwordfile, 'VW_IMPORT_PASSWORD');
				if (
					secret === undefined && format === 'keepasskdbx' && !keyFile && !flags.nointeraction
					&& process.stdin.isTTY
				) {
					secret = await secretPrompt('KeePass database password:');
				}
				if (secret === undefined && format === 'keepasskdbx' && !keyFile && flags.nointeraction) {
					throw new Error(
						'Master password is required. Try again in interactive mode or provide a password file or environment variable.',
					);
				}
				if (secret === undefined && format === 'bitwardenjson') {
					let protectedFile = false;
					try {
						protectedFile = JSON.parse(source.toString('utf8')).passwordProtected === true;
					} catch { /* The library reports malformed files without echoing their contents. */ }
					if (protectedFile && flags.nointeraction) {
						throw new Error(
							'Import file password is required. Provide --passwordfile or --passwordenv, or run interactively.',
						);
					}
					if (protectedFile && process.stdin.isTTY) {
						secret = await secretPrompt('Import file password:');
					}
				}
				out.json(
					await runtime.run(flags.session, true, vault =>
						vault.importVault(format, source, {
							organizationId: flags.organizationid,
							password: secret,
							keyFile,
							fileName: args.input,
						})),
				);
			} finally {
				source.fill(0);
				keyFile?.fill(0);
			}
		});
	return { generate, exportCommand, importCommand };
}
