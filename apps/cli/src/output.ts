import { AsyncLocalStorage } from 'node:async_hooks';
import { command, flag, plugin } from '@kjanat/dreamcli';
import type { RuntimeAdapter } from '@kjanat/dreamcli/runtime';

interface OutputPolicy {
	quiet: boolean;
	response: boolean;
	commandName?: string;
	args?: Record<string, unknown>;
	writeJson: (value: unknown, pretty?: boolean) => void;
}
const policies = new AsyncLocalStorage<OutputPolicy>();

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
		beforeParse: ({ out }) => {
			const policy = policies.getStore();
			if (policy?.response) {
				out.error = message => policy.writeJson({ success: false, message: responseError(message) }, false);
			}
		},
		beforeAction: ({ out, flags, command, args }) => {
			const policy = policies.getStore();
			if (policy) {
				policy.quiet = command.name !== 'root' && out.verbosity === 'quiet';
				policy.commandName = command.name;
				policy.args = args;
				if (policy.response && command.name !== 'root') {
					const writeResponse = (data: unknown) => policy.writeJson({ success: true, data }, !!flags.pretty);
					out.error = message => policy.writeJson({ success: false, message: responseError(message) }, !!flags.pretty);
					if (command.name !== 'sdk-version') {
						out.log = value => writeResponse(responseMessage(command.name, args, flags, value));
					}
					out.json = value => writeResponse(responseData(command.name, args, value));
				} else if (flags.pretty) out.json = policy.writeJson;
			}
		},
	});
}

function responseError(message: unknown): string {
	return String(message).replace(/^Unexpected error: /, '');
}

function responseMessage(
	commandName: string,
	args: Record<string, unknown>,
	flags: Record<string, unknown>,
	value: unknown,
): unknown {
	if (commandName === 'config') {
		const setting = args.url !== undefined
			|| ['web-vault', 'api', 'identity', 'icons', 'notifications', 'events', 'key-connector'].some(key =>
				flags[key] !== undefined
			);
		if (setting) return { object: 'message', title: 'Saved setting `config`.', message: null, noColor: false };
	}
	if (commandName === 'generate' || typeof value === 'string') {
		return { object: 'string', data: String(value) };
	}
	return { object: 'message', title: String(value), message: null, noColor: false };
}

function responseData(commandName: string, args: Record<string, unknown>, value: unknown): unknown {
	if (commandName === 'status') {
		const status = value && typeof value === 'object' ? value as Record<string, unknown> : {};
		const template: Record<string, unknown> = {
			serverUrl: status.serverUrl ?? null,
			lastSync: status.lastSync ?? null,
			status: status.status,
		};
		if (typeof status.userEmail === 'string') template.userEmail = status.userEmail;
		return { object: 'template', template };
	}
	if (commandName === 'get' && args.object === 'template') return { object: 'template', template: value };
	if (commandName === 'template') {
		const template = value && typeof value === 'object' && !('object' in value)
			? { object: 'send', ...value }
			: value;
		return { object: 'template', template };
	}
	if (commandName === 'get' && typeof value === 'string') return { object: 'string', data: value };
	if (Array.isArray(value)) {
		const itemObject = commandName === 'list'
			? ({
				items: 'cipher',
				folders: 'folder',
				collections: 'collection',
				organizations: 'organization',
				'org-collections': 'collection',
				'org-members': 'organizationUser',
			} as Record<string, string>)[String(args.object)]
			: undefined;
		return {
			object: 'list',
			data: itemObject
				? value.map(item =>
					item && typeof item === 'object' && !Array.isArray(item) && !('object' in item)
						? { object: itemObject, ...item }
						: item
				)
				: value,
		};
	}
	if (value === null || typeof value !== 'object') return { object: 'string', data: value };
	if ('object' in value) return value;
	return { object: 'json', data: value };
}
/** Suppress command results, not command execution. Help/version bypass the command hook. */
export function withOutputPolicy<T>(
	adapter: RuntimeAdapter,
	action: (adapter: RuntimeAdapter) => Promise<T>,
	response = false,
): Promise<T> {
	const policy = {
		quiet: false,
		response,
		writeJson: (value: unknown, pretty = true) => {
			if (!policy.quiet) adapter.stdout(JSON.stringify(value, null, pretty ? 2 : undefined) + '\n');
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
