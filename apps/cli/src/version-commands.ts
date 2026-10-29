import { outputCommand as command } from '#output';
import CLI_PACKAGE from '#pkg' with { type: 'json' };
import { SDK_VERSION } from '@kjanat/vaultwarden';

export { CLI_PACKAGE };

export interface PackageVersion {
	name: string;
	version: string;
	private?: boolean;
}
interface Semver {
	numbers: bigint[];
	pre: string[];
}
function parseVersion(value: string): Semver {
	if (value.length > 256) throw new Error('Invalid package version metadata.');
	const match =
		/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/
			.exec(value);
	if (!match) throw new Error('Invalid package version metadata.');
	const pre = match[4]?.split('.') ?? [];
	if (pre.some(part => /^\d+$/.test(part) && part.length > 1 && part[0] === '0')) {
		throw new Error('Invalid package version metadata.');
	}
	return { numbers: match.slice(1, 4).map(value => BigInt(value!)), pre };
}
function compareVersions(left: string, right: string): number {
	const a = parseVersion(left), b = parseVersion(right);
	for (let i = 0; i < 3; i++) if (a.numbers[i] !== b.numbers[i]) return a.numbers[i]! > b.numbers[i]! ? 1 : -1;
	if (!a.pre.length || !b.pre.length) return a.pre.length === b.pre.length ? 0 : !a.pre.length ? 1 : -1;
	for (let i = 0; i < Math.max(a.pre.length, b.pre.length); i++) {
		const l = a.pre[i], r = b.pre[i];
		if (l === r) continue;
		if (l === undefined || r === undefined) return l === undefined ? -1 : 1;
		const ln = /^\d+$/.test(l), rn = /^\d+$/.test(r);
		if (ln && rn) return BigInt(l) > BigInt(r) ? 1 : -1;
		if (ln !== rn) return ln ? -1 : 1;
		return l > r ? 1 : -1;
	}
	return 0;
}
export interface UpdateResult {
	status: 'private' | 'unpublished' | 'current' | 'available' | 'ahead';
	name: string;
	current: string;
	latest?: string;
}
/** Check this independent npm package only. The request never receives vault state or account credentials. */
export async function checkForUpdates(
	metadata: PackageVersion = CLI_PACKAGE,
	transport: typeof fetch = fetch,
): Promise<UpdateResult> {
	const result = { name: metadata.name, current: metadata.version };
	parseVersion(metadata.version);
	if (metadata.private) return { ...result, status: 'private' };
	let response: Response;
	try {
		response = await transport(`https://registry.npmjs.org/${encodeURIComponent(metadata.name)}/latest`, {
			redirect: 'error',
			signal: AbortSignal.timeout(10000),
			headers: { Accept: 'application/json' },
		});
	} catch {
		throw new Error('Could not check the independent package update channel.');
	}
	if (response.status === 404) return { ...result, status: 'unpublished' };
	if (!response.ok) throw new Error(`Package update check failed (HTTP ${response.status}).`);
	let version: unknown;
	try {
		version = (await response.json() as { version?: unknown }).version;
	} catch {
		throw new Error('Invalid update channel response.');
	}
	if (typeof version !== 'string') throw new Error('Invalid update channel response.');
	const ordering = compareVersions(version, metadata.version);
	return { ...result, latest: version, status: ordering > 0 ? 'available' : ordering < 0 ? 'ahead' : 'current' };
}
export function versionCommands() {
	const sdkVersion = command('sdk-version').description('Print the independent TypeScript SDK version')
		.action(({ out }) => out.log(SDK_VERSION));
	const update = command('update').description('Check updates for this independent CLI package')
		.action(async ({ out }) => {
			const result = await checkForUpdates();
			if (result.status === 'private') {
				out.log(
					`${result.name} ${result.current} is a private development build; no public update channel is configured.`,
				);
			} else if (result.status === 'unpublished') {
				out.log(`No published release exists for ${result.name}. Current version: ${result.current}.`);
			} else if (result.status === 'available') {
				out.log(`Update available for ${result.name}: ${result.current} → ${result.latest}.`);
			} else if (result.status === 'ahead') {
				out.log(`${result.name} ${result.current} is newer than the published version ${result.latest}.`);
			} else out.log(`${result.name} ${result.current} is up to date.`);
		});
	return { sdkVersion, update };
}
