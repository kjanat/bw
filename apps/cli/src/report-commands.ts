import { outputCommand as command } from '#output';
import { arg, flag } from '@kjanat/dreamcli';
import { PasswordExposureClient } from '@kjanat/vaultwarden';
import type { VaultRuntime } from '#vault-commands';

export function reportProgressMessage(count: number, checkExposed: boolean): string {
	return checkExposed
		? `Checking ${count} logins against Have I Been Pwned...`
		: `Analyzing ${count} logins...`;
}

export function reportCommand(runtime: VaultRuntime) {
	return command('report').description('Report login password strength, reuse, and exposure')
		.arg('object', arg.enum(['password-health']))
		.flag('session', flag.string().sensitive().env('SESSION'))
		.flag(
			'no-check-exposed',
			flag.boolean().describe(
				'Do not check passwords against Have I Been Pwned; this prevents those network requests.',
			),
		)
		.flag('hibp-url', flag.string().describe('HIBP-compatible range API base URL'))
		.action(async ({ flags, out }) => {
			const checkExposed = !flags['no-check-exposed'];
			out.json(
				await runtime.run(flags.session, false, vault =>
					vault.passwordHealth({
						checkExposed,
						exposure: checkExposed ? new PasswordExposureClient({ baseUrl: flags['hibp-url'] }) : undefined,
						onStart: count => out.status(reportProgressMessage(count, checkExposed)),
					})),
			);
		});
}
