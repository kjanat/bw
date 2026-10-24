import { AsyncLocalStorage } from 'node:async_hooks';
import { command, flag, plugin } from '@kjanat/dreamcli';
import type { RuntimeAdapter } from '@kjanat/dreamcli/runtime';
import { organizationCollectionResponse } from '@kjanat/vaultwarden';

interface OutputPolicy {
	quiet: boolean;
	response: boolean;
	pretty: boolean;
	commandName?: string;
	args?: Record<string, unknown>;
	responseErrorWritten?: boolean;
	writeJson: (value: unknown, pretty?: boolean) => void;
}
const policies = new AsyncLocalStorage<OutputPolicy>();

export function outputCommand(name: string) {
	return command(name)
		.flag('pretty', flag.boolean().env('VW_PRETTY').describe('Format JSON with two-space indentation'))
		.flag('raw', flag.boolean().env('VW_RAW').describe('Return raw message output'))
		.flag('nointeraction', flag.boolean().env('VW_NOINTERACTION').describe('Do not prompt for interactive input'));
}

/** The policy follows one command execution, including raw writes outside DreamCLI. */
export function outputIsQuiet(): boolean {
	return policies.getStore()?.quiet ?? false;
}
export function outputIsResponse(): boolean {
	return policies.getStore()?.response ?? false;
}
export function outputPolicyPlugin() {
	return plugin({
		beforeParse: ({ out }) => {
			const policy = policies.getStore();
			if (policy?.response) {
				out.error = message => {
					if (!policy.responseErrorWritten) {
						policy.writeJson({ success: false, message: responseError(message) }, false);
					}
				};
			}
		},
		beforeAction: ({ out, flags, command, args }) => {
			const policy = policies.getStore();
			if (policy) {
				policy.quiet = command.name !== 'root' && out.verbosity === 'quiet';
				policy.pretty = !!flags.pretty;
				policy.commandName = command.name;
				policy.args = args;
				if (policy.response && command.name !== 'root') {
					const writeResponse = (data: unknown) => policy.writeJson({ success: true, data }, !!flags.pretty);
					out.error = message => {
						if (!policy.responseErrorWritten) {
							policy.writeJson({ success: false, message: responseError(message) }, !!flags.pretty);
						}
					};
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

export function responseMessage(
	commandName: string,
	args: Record<string, unknown>,
	flags: Record<string, unknown>,
	value: unknown,
): unknown {
	const hasServerArgument = typeof args.url === 'string' && args.url.trim() !== '';
	const configSetting = hasServerArgument
		|| ['web-vault', 'api', 'identity', 'icons', 'notifications', 'events', 'key-connector'].some(key =>
			flags[key] !== undefined
		);
	if (commandName === 'config') {
		if (configSetting) return { object: 'message', title: 'Saved setting `config`.', message: null, noColor: false };
	}
	if (
		commandName === 'generate'
		|| commandName === 'encode'
		|| (commandName === 'send' && !flags.fullObject)
		|| (commandName === 'config' && !configSetting)
	) {
		return { object: 'string', data: String(value) };
	}
	if (commandName === 'sync' && flags.last) {
		return { object: 'string', data: value === '' ? null : String(value) };
	}
	if (
		commandName === 'export'
		|| commandName === 'receive'
		|| (commandName === 'get' && args.object === 'attachment')
	) {
		const path = String(value);
		return { object: 'message', title: `Saved ${path}`, message: null, raw: path, noColor: false };
	}
	return { object: 'message', title: String(value), message: null, noColor: false };
}

/** Route raw string results through the same response envelope as `out.log`. */
export function writeResponseString(value: string): boolean {
	const policy = policies.getStore();
	if (!policy?.response) return false;
	policy.writeJson({ success: true, data: { object: 'string', data: value } }, policy.pretty);
	return true;
}

/** Emit the reference's successful no-data envelope; ordinary CLI mode stays silent. */
export function outputSuccess(): void {
	const policy = policies.getStore();
	if (policy?.response) policy.writeJson({ success: true }, policy.pretty);
}

/** Emit a reference-compatible failure that carries useful machine-readable details. */
export function outputResponseError(message: string, data?: unknown): boolean {
	const policy = policies.getStore();
	if (!policy?.response) return false;
	policy.writeJson({ success: false, message, ...(data === undefined ? {} : { data }) }, policy.pretty);
	policy.responseErrorWritten = true;
	return true;
}

/** Serialize list entries through the same response models in normal and response modes. */
export function listObjectResponse(objectType: string, value: unknown): unknown {
	const itemObject = ({
		items: 'cipher',
		folders: 'folder',
		collections: 'collection',
		organizations: 'organization',
		'org-collections': 'collection',
		'org-members': 'org-member',
	} as Record<string, string>)[objectType];
	if (!itemObject || !value || typeof value !== 'object' || Array.isArray(value)) return value;
	const source = value as Record<string, unknown>;
	if (itemObject === 'folder') return { object: itemObject, id: source.id, name: source.name };
	if (itemObject === 'collection') {
		return {
			object: itemObject,
			id: source.id,
			organizationId: source.organizationId,
			name: source.name,
			externalId: source.externalId,
		};
	}
	if (itemObject === 'organization') {
		return {
			object: itemObject,
			id: source.id,
			name: source.name,
			status: source.status,
			type: source.type,
			enabled: source.enabled,
		};
	}
	if (itemObject === 'org-member') {
		return {
			object: itemObject,
			id: source.id,
			email: source.email,
			name: source.name,
			status: source.status,
			type: source.type,
			twoFactorEnabled: source.twoFactorEnabled,
		};
	}
	return 'object' in source ? source : { object: itemObject, ...source };
}

/** Serialize standalone object reads through the reference command response models. */
export function getObjectResponse(objectType: string, value: unknown): unknown {
	if (!value || typeof value !== 'object' || Array.isArray(value)) return value;
	const source = value as Record<string, unknown>;
	if (objectType === 'folder') return { object: 'folder', id: source.id, name: source.name };
	if (objectType === 'collection') {
		return {
			object: 'collection',
			id: source.id,
			organizationId: source.organizationId,
			name: source.name,
			externalId: source.externalId,
		};
	}
	if (objectType === 'organization') {
		return {
			object: 'organization',
			id: source.id,
			name: source.name,
			status: source.status,
			type: source.type,
			enabled: source.enabled,
		};
	}
	if (objectType === 'org-collection') return organizationCollectionResponse(source);
	return value;
}

export function responseData(commandName: string, args: Record<string, unknown>, value: unknown): unknown {
	if (commandName === 'status') {
		const status = value && typeof value === 'object' ? value as Record<string, unknown> : {};
		const template: Record<string, unknown> = {
			serverUrl: status.serverUrl ?? null,
			lastSync: status.lastSync ?? null,
			status: status.status,
		};
		if (typeof status.userEmail === 'string') template.userEmail = status.userEmail;
		if (typeof status.userId === 'string') template.userId = status.userId;
		return { object: 'template', template };
	}
	if (commandName === 'get' && args.object === 'template') return { object: 'template', template: value };
	if (commandName === 'get') return getObjectResponse(String(args.object).toLowerCase(), value);
	if (commandName === 'template') {
		const template = value && typeof value === 'object' && !('object' in value)
			? { object: 'send', ...value }
			: value;
		return { object: 'template', template };
	}
	if (
		(commandName === 'create' || commandName === 'edit')
		&& value && typeof value === 'object' && !Array.isArray(value)
	) {
		return getObjectResponse(String(args.object).toLowerCase(), value);
	}
	if (commandName === 'get' && typeof value === 'string') return { object: 'string', data: value };
	if (Array.isArray(value)) {
		const itemObject = commandName === 'list' ? String(args.object).toLowerCase() : undefined;
		return {
			object: 'list',
			data: itemObject
				? value.map(item => listObjectResponse(itemObject, item))
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
		pretty: false,
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
