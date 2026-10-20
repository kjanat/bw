import { readFile } from 'node:fs/promises';
import { arg, command, flag } from '@kjanat/dreamcli';
import passwordPrompt from '@inquirer/password';
import { generateSecret, importFormats, object, type ImportFormat } from '@kjanat/vaultwarden';
import { withStore } from '#store';
import { writeAttachment } from '#files';
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
	if (file) return (await readFile(file, 'utf8')).split(/\r?\n/, 1)[0] ?? '';
	const secret = process.env[env ?? fallback];
	if (env && secret === undefined) throw new Error('The selected password environment variable is unset.');
	return secret;
}
export function toolCommands(runtime: VaultRuntime, directory: string) {
	const generate = command('generate').description('Generate a password or EFF-wordlist passphrase locally')
		.flag('uppercase', flag.boolean().alias('u')).flag('lowercase', flag.boolean().alias('l'))
		.flag('number', flag.boolean().alias('n')).flag('special', flag.boolean().alias('s'))
		.flag('passphrase', flag.boolean().alias('p'))
		.flag('length', flag.number({ int: true, min: 0, max: 4096 }).default(14))
		.flag('words', flag.number({ int: true, min: 0, max: 128 }).default(6))
		.flag('minNumber', flag.number({ int: true, min: 0, max: 4096 }))
		.flag('minSpecial', flag.number({ int: true, min: 0, max: 4096 }))
		.flag('separator', flag.string().default('-')).flag('capitalize', flag.boolean().alias('c'))
		.flag('includeNumber', flag.boolean()).flag('ambiguous', flag.boolean().describe('Avoid ambiguous characters'))
		.action(async ({ flags, out }) => {
			const policies = await withStore(
				directory,
				async state => state.account && Array.isArray(state.vault?.policies) ? state.vault!.policies.map(object) : [],
			);
			out.log(generateSecret({ ...flags, avoidAmbiguous: flags.ambiguous }, policies));
		});
	const exportCommand = command('export').description('Export a personal or organization vault')
		.flag('format', flag.enum(['csv', 'json', 'encrypted_json', 'zip']).default('csv'))
		.flag('organizationid', flag.string()).flag('session', flag.string().env('VW_SESSION'))
		.flag('output', flag.path()).flag('raw', flag.boolean())
		.flag('password', flag.string()).flag('passwordenv', flag.string()).flag(
			'passwordfile',
			flag.path({ mustExist: true }),
		)
		.action(async ({ flags, out }) => {
			if (
				flags.format !== 'encrypted_json' && (flags.password !== undefined || flags.passwordenv || flags.passwordfile)
			) throw new Error('Export passwords require --format encrypted_json.');
			const secret = flags.format === 'encrypted_json'
				? await password(flags.password, flags.passwordenv, flags.passwordfile, 'VW_EXPORT_PASSWORD')
				: undefined;
			const result = await runtime.run(
				flags.session,
				false,
				vault => vault.exportVault(flags.format, { organizationId: flags.organizationid, password: secret }),
				flags.format === 'zip' || !!flags.organizationid,
			);
			try {
				if (flags.raw && !flags.output) {
					await new Promise<void>((resolve, reject) =>
						process.stdout.write(result, error => error ? reject(error) : resolve())
					);
				} else {
					const extension = flags.format === 'encrypted_json' ? 'json' : flags.format;
					const name = `vaultwarden_export_${new Date().toISOString().replace(/[:.]/g, '-')}.${extension}`;
					out.log(await writeAttachment(flags.output, name, result));
				}
			} finally {
				result.fill(0);
			}
		});
	const importCommand = command('import').description('Import vault JSON, CSV, or a ZIP backup')
		.arg('format', arg.enum(importFormats).optional()).arg('input', arg.path({ mustExist: true }).optional())
		.flag('formats', flag.boolean()).flag('organizationid', flag.string()).flag(
			'session',
			flag.string().env('VW_SESSION'),
		)
		.flag('passwordenv', flag.string()).flag('passwordfile', flag.path({ mustExist: true }))
		.action(async ({ args, flags, out }) => {
			if (flags.formats) {
				out.json(importFormats);
				return;
			}
			if (!args.format || !args.input) {
				throw new Error('An import format and file are required. Use vw import --formats.');
			}
			const source = await readFile(args.input);
			try {
				let secret = await password(undefined, flags.passwordenv, flags.passwordfile, 'VW_IMPORT_PASSWORD');
				if (secret === undefined && args.format === 'bitwardenjson') {
					let protectedFile = false;
					try {
						protectedFile = JSON.parse(source.toString('utf8')).passwordProtected === true;
					} catch { /* The library reports malformed files without echoing their contents. */ }
					if (protectedFile && process.stdin.isTTY) {
						secret = await passwordPrompt({ message: 'Import file password:', mask: '*' });
					}
				}
				out.json(
					await runtime.run(flags.session, true, vault =>
						vault.importVault(args.format as ImportFormat, source, {
							organizationId: flags.organizationid,
							password: secret,
						})),
				);
			} finally {
				source.fill(0);
			}
		});
	return { generate, exportCommand, importCommand };
}
