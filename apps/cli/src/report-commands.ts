import { outputCommand as command } from '#output';
import { arg, flag } from '@kjanat/dreamcli';
import { PasswordExposureClient } from '@kjanat/vaultwarden';
import type { VaultRuntime } from '#vault-commands';

export function reportCommand(runtime: VaultRuntime) {
	return command('report').description('Report login password strength, reuse, and exposure')
		.arg('object', arg.enum(['password-health']))
		.flag('session', flag.string().env('VW_SESSION'))
		.flag('check-exposed', flag.boolean().default(true).negatable())
		.flag('hibp-url', flag.string().describe('HIBP-compatible range API base URL'))
		.action(async ({ flags, out }) => {
			const checkExposed = flags['check-exposed'];
			out.status(checkExposed ? 'Checking login passwords against Have I Been Pwned…' : 'Analyzing login passwords…');
			out.json(
				await runtime.run(flags.session, false, vault =>
					vault.passwordHealth({
						checkExposed,
						exposure: checkExposed ? new PasswordExposureClient({ baseUrl: flags['hibp-url'] }) : undefined,
					})),
			);
		});
}
