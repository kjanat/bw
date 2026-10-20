import { AsyncLocalStorage } from 'node:async_hooks';
import { command, flag, plugin } from '@kjanat/dreamcli';
import type { RuntimeAdapter } from '@kjanat/dreamcli/runtime';

const policies = new AsyncLocalStorage<{ quiet: boolean; writeJson: (value: unknown) => void }>();

export function outputCommand(name: string) {
	return command(name).flag(
		'pretty',
		flag.boolean().env('VW_PRETTY').describe('Format JSON with two-space indentation'),
	);
}

/** The policy follows one command execution, including raw writes outside DreamCLI. */
export function outputIsQuiet(): boolean {
	return policies.getStore()?.quiet ?? false;
}
export function outputPolicyPlugin() {
	return plugin({
		beforeAction: ({ out, flags, command }) => {
			const policy = policies.getStore();
			if (policy) {
				policy.quiet = command.name !== 'root' && out.verbosity === 'quiet';
				if (flags.pretty) out.json = policy.writeJson;
			}
		},
	});
}
/** Suppress command results, not command execution. Help/version bypass the command hook. */
export function withOutputPolicy<T>(
	adapter: RuntimeAdapter,
	action: (adapter: RuntimeAdapter) => Promise<T>,
): Promise<T> {
	const policy = {
		quiet: false,
		writeJson: (value: unknown) => {
			if (!policy.quiet) adapter.stdout(JSON.stringify(value, null, 2) + '\n');
		},
	};
	return policies.run(policy, () =>
		action({
			...adapter,
			stdout: value => {
				if (!policy.quiet) adapter.stdout(value);
			},
			stderr: value => {
				if (!policy.quiet) adapter.stderr(value);
			},
		}));
}
