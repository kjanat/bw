import { outputCommand as command, outputIsResponse } from '#output';
import { readFile } from 'node:fs/promises';
import { arg, flag } from '@kjanat/dreamcli';
import { secretPrompt } from '#prompts';
import {
	generateVaultSecret,
	importFormats,
	parseGeneratorNumber,
	resolveImportFormat,
	type ImportFormat,
} from '@kjanat/vaultwarden';
import { withStore } from '#store';
import { writeAttachment, writeStdout } from '#files';
import type { VaultRuntime } from '#vault-commands';

export async function password(
	value: string | undefined,
	env: string | undefined,
	file: string | undefined,
	fallbackValue: string | undefined,
	requireEnvironment = true,
): Promise<string | undefined> {
	if (value) return value;
	if (file) return (await readFile(file, 'utf8')).split(/\r\n|\r|\n/, 1)[0] || undefined;
	if (!env) return fallbackValue || undefined;
	const secret = process.env[env];
	if (!secret) {
		if (requireEnvironment) throw new Error(`Environment variable ${env} is unset.`);
		return undefined;
	}
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
			const snapshot = await withStore(
				directory,
				async state => state.account ? state.vault : undefined,
			);
			const { length, words, minNumber, minSpecial, ...options } = flags;
			out.log(
				generateVaultSecret({
					...options,
					length: parseGeneratorNumber(length, 14),
					words: parseGeneratorNumber(words, 6),
					minNumber: parseGeneratorNumber(minNumber, 1),
					minSpecial: parseGeneratorNumber(minSpecial, 0),
					avoidAmbiguous: flags.ambiguous,
				}, snapshot),
			);
		});
	const exportCommand = command('export').description('Export a personal or organization vault')
		.arg('password', arg.string().sensitive().optional())
		.flag('format', flag.enum(['csv', 'json', 'encrypted_json', 'zip']).default('csv'))
		.flag(
			'allow-partial',
			flag.boolean().describe('Allow a ZIP with missing attachments and report every skipped file'),
		)
		.flag('organizationid', flag.string()).flag('session', flag.string().sensitive().env('SESSION'))
		.flag('output', flag.path())
		.flag('password', flag.string().sensitive().env('EXPORT_PASSWORD')).flag(
			'passwordenv',
			flag.string().describe(
				'Read the export password from this variable. Without this option, export reads VW_EXPORT_PASSWORD.',
			),
		).flag(
			'passwordfile',
			flag.path({ mustExist: true }),
		)
		.action(async ({ args, flags, out, sources }) => {
			if (flags['allow-partial'] && flags.format !== 'zip') throw new Error('--allow-partial requires --format zip.');
			const explicitPassword = sources.flags.password?.stage === 'env' ? undefined : flags.password;
			const environmentPassword = sources.flags.password?.stage === 'env' ? flags.password : undefined;
			if (args.password !== undefined && explicitPassword !== undefined) {
				throw new Error('Choose one password source.');
			}
			const format = resolvedExportFormat(
				flags.format,
				args.password !== undefined || flags.password !== undefined || !!flags.passwordenv || !!flags.passwordfile,
			);
			const secret = format === 'encrypted_json'
				? await password(
					args.password ?? explicitPassword,
					flags.passwordenv,
					flags.passwordfile,
					flags.passwordenv ? undefined : environmentPassword,
				)
				: undefined;
			const result = await runtime.run(
				flags.session,
				false,
				vault =>
					vault.exportVault(format, {
						organizationId: flags.organizationid,
						password: secret,
						allowPartial: flags['allow-partial'],
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
		.arg('format', arg.string().optional()).arg('input', arg.path().optional())
		.flag('formats', flag.boolean()).flag('organizationid', flag.string()).flag(
			'session',
			flag.string().sensitive().env('SESSION'),
		)
		.flag('password', flag.string().sensitive().env('IMPORT_PASSWORD'))
		.flag(
			'passwordenv',
			flag.string().describe(
				'Read the import-file password from this variable. Without this option, import reads VW_IMPORT_PASSWORD.',
			),
		).flag('passwordfile', flag.path())
		.flag('keyfile', flag.path())
		.action(async ({ args, flags, out, sources }) => {
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
			const result = await runtime.run(flags.session, true, async vault => {
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
					const protectedBitwardenJson = (() => {
						if (format !== 'bitwardenjson') return false;
						try {
							return JSON.parse(source.toString('utf8')).passwordProtected === true;
						} catch {
							return false;
						}
					})();
					const requiresPassword = format === 'keepasskdbx' || protectedBitwardenJson;
					const explicitPassword = sources.flags.password?.stage === 'env' ? undefined : flags.password;
					const environmentPassword = sources.flags.password?.stage === 'env' ? flags.password : undefined;
					let secret = requiresPassword
						? await password(
							explicitPassword,
							flags.passwordenv,
							flags.passwordfile,
							flags.passwordenv ? undefined : environmentPassword,
							false,
						)
						: undefined;
					if (
						secret === undefined && format === 'keepasskdbx' && !keyFile && !flags.nointeraction
						&& process.stdin.isTTY
					) {
						secret = await secretPrompt('KeePass database password:');
					}
					if (secret === undefined && format === 'keepasskdbx' && !keyFile && flags.nointeraction) {
						throw new Error(
							'KeePass database password required. Use --password, --passwordfile, --passwordenv, or run in a terminal.',
						);
					}
					if (secret === undefined && protectedBitwardenJson) {
						if (flags.nointeraction) {
							throw new Error(
								'Import file password required. Use --password, --passwordfile, --passwordenv, or run in a terminal.',
							);
						}
						if (process.stdin.isTTY) {
							secret = await secretPrompt('Import file password:');
						}
					}
					return await vault.importVault(format, source, {
						organizationId: flags.organizationid,
						password: secret,
						keyFile,
						fileName: args.input,
					});
				} finally {
					source.fill(0);
					keyFile?.fill(0);
				}
			});
			out.json(result);
		});
	return { generate, exportCommand, importCommand };
}
