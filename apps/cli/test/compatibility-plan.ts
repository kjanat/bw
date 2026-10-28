export interface CompatibilityTargets {
	nodeVersion: string;
	servers: Record<string, string>;
	referenceCliVersion: string;
	referenceCliVersions: Record<string, string | null>;
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

/** Test each server once on the primary Node runtime, with its pinned reference CLI. */
export async function planCompatibility(
	targets: CompatibilityTargets,
	tags: readonly string[],
	resolveImage: (version: string) => Promise<string>,
) {
	const servers = new Map(
		Object.entries(targets.servers).map(([version]) => {
			const target = resolveCompatibilityTarget(targets, version);
			return [target.version, target.image];
		}),
	);
	if (servers.size === 0) throw new Error('At least one pinned compatibility baseline is required.');
	if (!/^[1-9]\d*$/.test(targets.nodeVersion)) {
		throw new Error('The primary Node version must be a positive major version.');
	}
	if (!stableVersion.test(targets.referenceCliVersion)) throw new Error('Invalid reference CLI version.');
	for (const [server, reference] of Object.entries(targets.referenceCliVersions)) {
		assertStableVersion(server);
		if (reference !== null && !stableVersion.test(reference)) throw new Error('Invalid reference CLI version.');
	}
	const latest = latestStableVersion(tags);
	const newest = [...servers.keys()].sort(Bun.semver.order).at(-1)!;
	if (Bun.semver.order(latest, newest) > 0) {
		const target = resolveCompatibilityTarget(targets, latest, await resolveImage(latest));
		servers.set(target.version, target.image);
	}
	const include = [...servers].sort(([a], [b]) => Bun.semver.order(a, b)).map(([server, image]) => {
		const referenceCliVersion = Object.hasOwn(targets.referenceCliVersions, server)
			? targets.referenceCliVersions[server]!
			: targets.referenceCliVersion;
		return {
			server,
			node: targets.nodeVersion,
			image,
			reference: referenceCliVersion !== null,
			referenceCliVersion,
		};
	});
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
