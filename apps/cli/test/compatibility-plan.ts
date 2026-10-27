export interface CompatibilityTargets {
	nodeVersions: string[];
	servers: Record<string, string>;
	referenceCliVersion: string;
	referenceUnsupportedServers: string[];
	mailpitImage: string;
}
const pinnedImage = /^vaultwarden\/server@sha256:[a-f0-9]{64}$/;
const stableVersion = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

function assertStableVersion(version: string): void {
	if (!stableVersion.test(version) || !Bun.semver.satisfies(version, '>=0.0.0')) {
		throw new Error(`Invalid stable Vaultwarden version: ${version}`);
	}
}

export function latestStableVersion(tags: readonly string[]): string {
	const versions = [...new Set(tags.filter(tag => stableVersion.test(tag) && Bun.semver.satisfies(tag, '>=0.0.0')))]
		.sort(Bun.semver.order);
	const latest = versions.at(-1);
	if (!latest) throw new Error('No stable Vaultwarden version tags found in the registry.');
	return latest;
}

/** Local baselines stay pinned; newly discovered releases require an explicit immutable image. */
export function resolveCompatibilityTarget(
	targets: Pick<CompatibilityTargets, 'servers'>,
	version: string,
	imageOverride?: string,
): { version: string; image: string } {
	assertStableVersion(version);
	const image = imageOverride ?? (Object.hasOwn(targets.servers, version) ? targets.servers[version] : undefined);
	if (!image) {
		throw new Error('Unknown VW_TEST_VERSION. Supply VW_TEST_IMAGE as an immutable vaultwarden/server digest.');
	}
	if (!pinnedImage.test(image)) throw new Error('Compatibility image must use a pinned vaultwarden/server digest.');
	return { version, image };
}

/** Baselines plus the latest stable release, once per server/Node pair. */
export async function planCompatibility(
	targets: CompatibilityTargets,
	tags: readonly string[],
	resolveImage: (version: string) => Promise<string>,
) {
	const latest = latestStableVersion(tags);
	const servers = new Map(
		Object.entries(targets.servers).map(([version]) => {
			const target = resolveCompatibilityTarget(targets, version);
			return [target.version, target.image];
		}),
	);
	if (servers.size === 0) throw new Error('At least one pinned compatibility baseline is required.');
	const newest = [...servers.keys()].sort(Bun.semver.order).at(-1)!;
	if (Bun.semver.order(latest, newest) > 0) {
		const target = resolveCompatibilityTarget(targets, latest, await resolveImage(latest));
		servers.set(target.version, target.image);
	}
	const nodes = [...new Set(targets.nodeVersions)];
	if (!nodes.length || nodes.some(node => !/^[1-9]\d*$/.test(node))) {
		throw new Error('Node matrix versions must be positive major versions.');
	}
	if (!/^\d+\.\d+\.\d+$/.test(targets.referenceCliVersion)) throw new Error('Invalid reference CLI version.');
	const include = [...servers].sort(([a], [b]) => Bun.semver.order(a, b)).flatMap(([server, image]) =>
		nodes.map(node => ({
			server,
			node,
			image,
			reference: !targets.referenceUnsupportedServers.includes(server),
			referenceCliVersion: targets.referenceCliVersion,
		}))
	);
	if (include.length > 256) throw new Error("Compatibility matrix exceeds GitHub Actions' 256-job limit.");
	return { include };
}

/** Resolve the multi-platform manifest once, before the matrix fans out. */
export async function resolveReleaseImage(
	version: string,
	runCrane: (args: string[]) => Promise<string>,
): Promise<string> {
	assertStableVersion(version);
	const digest = (await runCrane(['digest', `vaultwarden/server:${version}`])).trim();
	if (!/^sha256:[a-f0-9]{64}$/.test(digest)) throw new Error('crane returned no valid immutable image digest.');
	return `vaultwarden/server@${digest}`;
}
