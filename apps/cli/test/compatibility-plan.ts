export type CompatibilityMode = 'full' | 'pr';
export interface ReferenceIncompatibility {
	server: string;
	referenceCliVersion: string;
	error: 'invalid-prelogin-kdf';
}
export interface CompatibilityTargets {
	nodeVersion: string;
	minimumServerVersion: string;
	minimumReferenceCliVersion: string;
	servers: Record<string, string>;
	referenceIncompatibilities: ReferenceIncompatibility[];
}
const pinnedImage = /^vaultwarden\/server@sha256:[a-f0-9]{64}$/;
const stableVersion = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

export function assertStableVersion(version: string): void {
	if (!stableVersion.test(version) || !Bun.semver.satisfies(version, '>=0.0.0')) {
		throw new Error(`Invalid stable version: ${version}`);
	}
}

export function supportedVersions(versions: readonly string[], minimum: string): string[] {
	assertStableVersion(minimum);
	return [
		...new Set(versions.filter(version =>
			stableVersion.test(version)
			&& Bun.semver.satisfies(version, `>=${minimum}`)
		)),
	].sort(Bun.semver.order);
}

/** Local baselines stay pinned; other releases require an explicit immutable image. */
export function resolveCompatibilityTarget(
	targets: Pick<CompatibilityTargets, 'servers'>,
	version: string,
	imageOverride?: string,
): { version: string; image: string } {
	assertStableVersion(version);
	const image = imageOverride ?? (Object.hasOwn(targets.servers, version) ? targets.servers[version] : undefined);
	if (!image) throw new Error('Unknown server version. Supply --image with an immutable vaultwarden/server digest.');
	if (!pinnedImage.test(image)) throw new Error('Compatibility image must use a pinned vaultwarden/server digest.');
	return { version, image };
}

export async function discoverReferenceVersions(
	fetchRegistry: (input: string, init: RequestInit) => Promise<Response> = fetch,
): Promise<string[]> {
	const response = await fetchRegistry('https://registry.npmjs.org/@bitwarden%2fcli', {
		headers: { Accept: 'application/vnd.npm.install-v1+json' },
		signal: AbortSignal.timeout(30000),
	});
	if (!response.ok) throw new Error(`Bitwarden CLI discovery failed: npm HTTP ${response.status}.`);
	const metadata = await response.json() as { name?: unknown; versions?: unknown };
	if (
		metadata.name !== '@bitwarden/cli' || !metadata.versions || typeof metadata.versions !== 'object'
		|| Array.isArray(metadata.versions)
	) throw new Error('Invalid Bitwarden CLI registry metadata.');
	return Object.keys(metadata.versions);
}

/** PRs cover both newest edges; full runs cover every supported server/CLI pair. */
export async function planCompatibility(
	targets: CompatibilityTargets,
	serverTags: readonly string[],
	referenceVersions: readonly string[],
	resolveImage: (version: string) => Promise<string>,
	mode: CompatibilityMode = 'full',
) {
	if (mode !== 'full' && mode !== 'pr') throw new Error('Compatibility mode must be full or pr.');
	if (!/^[1-9]\d*$/.test(targets.nodeVersion)) {
		throw new Error('The primary Node version must be a positive major version.');
	}
	const servers = supportedVersions(serverTags, targets.minimumServerVersion);
	const references = supportedVersions(referenceVersions, targets.minimumReferenceCliVersion);
	if (!servers.includes(targets.minimumServerVersion)) {
		throw new Error('Registry is missing the minimum supported server.');
	}
	if (!references.includes(targets.minimumReferenceCliVersion)) {
		throw new Error('Registry is missing the minimum supported CLI.');
	}
	for (const version of Object.keys(targets.servers)) {
		resolveCompatibilityTarget(targets, version);
		if (!servers.includes(version)) throw new Error(`Registry is missing configured server ${version}.`);
	}
	const exceptions = new Set<string>();
	for (const entry of targets.referenceIncompatibilities) {
		const key = `${entry.server}/${entry.referenceCliVersion}`;
		if (
			!servers.includes(entry.server) || !references.includes(entry.referenceCliVersion)
			|| entry.error !== 'invalid-prelogin-kdf' || exceptions.has(key)
		) {
			throw new Error(`Invalid or duplicate reference incompatibility: ${key}.`);
		}
		exceptions.add(key);
	}
	const newestServer = servers.at(-1)!;
	const newestReference = references.at(-1)!;
	const pairs = servers.flatMap(server =>
		references
			.filter(reference => mode === 'full' || server === newestServer || reference === newestReference)
			.map(referenceCliVersion => ({ server, referenceCliVersion }))
	);
	if (servers.length > 256 || pairs.length > 256) {
		throw new Error(
			`Compatibility plan needs ${servers.length} server jobs and ${pairs.length} pair jobs; GitHub's limit is 256 per matrix. Split the matrix instead of dropping versions.`,
		);
	}
	// Resolve once per server, never once per CLI pairing.
	const images = new Map<string, string>();
	for (const server of servers) {
		const image = Object.hasOwn(targets.servers, server) ? targets.servers[server]! : await resolveImage(server);
		images.set(server, resolveCompatibilityTarget(targets, server, image).image);
	}
	const row = (server: string) => ({ server, node: targets.nodeVersion, image: images.get(server)! });
	return {
		mode,
		servers: { include: servers.map(row) },
		matrix: {
			include: pairs.map(pair => ({
				...row(pair.server),
				referenceCliVersion: pair.referenceCliVersion,
				expectedFailure: targets.referenceIncompatibilities.find(entry =>
					entry.server === pair.server
					&& entry.referenceCliVersion === pair.referenceCliVersion
				)?.error ?? null,
			})),
		},
	};
}

export async function resolveReleaseImage(
	version: string,
	runCrane: (args: string[]) => Promise<string>,
): Promise<string> {
	assertStableVersion(version);
	const digest = (await runCrane(['digest', `vaultwarden/server:${version}`])).trim();
	if (!/^sha256:[a-f0-9]{64}$/.test(digest)) throw new Error('crane returned no valid immutable image digest.');
	return `vaultwarden/server@${digest}`;
}
