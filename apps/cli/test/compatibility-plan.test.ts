import { expect, test } from 'bun:test';
import {
	planCompatibility,
	latestStableVersion,
	resolveCompatibilityTarget,
	resolveReleaseImage,
	type CompatibilityTargets,
} from '#test/compatibility-plan';
import targets from '#fixtures/compatibility-targets.json' with { type: 'json' };

const image = `vaultwarden/server@sha256:${'a'.repeat(64)}`;
const tags = (...versions: string[]) => versions;

test('latest release already in the baselines produces exactly four unique jobs without resolving images again', async () => {
	let lookups = 0;
	const matrix = await planCompatibility(targets, tags('1.37.4', '1.37.4', 'latest', '1.37.4-alpine'), async () => {
		lookups++;
		return image;
	});
	expect(lookups).toBe(0);
	expect(matrix.include.map(row => [row.server, row.node, row.reference])).toEqual([
		['1.36.0', '24', false],
		['1.36.0', '26', false],
		['1.37.4', '24', true],
		['1.37.4', '26', true],
	]);
	expect(new Set(matrix.include.map(row => `${row.server}/${row.node}`)).size).toBe(4);
	expect(matrix.include.every(row => row.image === targets.servers[row.server as keyof typeof targets.servers])).toBe(
		true,
	);
});

test('a newer release resolves once and survives JSON output with an immutable image and reference settings', async () => {
	const requested: string[] = [];
	const matrix = await planCompatibility(targets, tags('1.38.0', '1.37.4', '1.38.0', '1.39.0-rc.1'), async version => {
		requested.push(version);
		return image;
	});
	expect(requested).toEqual(['1.38.0']);
	expect(matrix.include).toHaveLength(6);
	const parsed = JSON.parse(JSON.stringify(matrix));
	const future = parsed.include.filter((row: { server: string }) => row.server === '1.38.0');
	expect(future).toEqual(
		['24', '26'].map(node => ({
			server: '1.38.0',
			node,
			image,
			reference: true,
			referenceCliVersion: targets.referenceCliVersion,
		})),
	);
	for (const row of parsed.include) {
		expect(resolveCompatibilityTarget(targets, row.server, row.image)).toEqual({
			version: row.server,
			image: row.image,
		});
	}
});

test('release ordering is numeric and duplicate Node majors cannot duplicate jobs', async () => {
	const baseline = { ...targets, servers: { '1.9.0': image }, nodeVersions: ['24', '24', '26'] };
	const matrix = await planCompatibility(baseline, tags('1.9.0', '1.10.0'), async () => image);
	expect(matrix.include.map(row => `${row.server}/${row.node}`)).toEqual([
		'1.9.0/24',
		'1.9.0/26',
		'1.10.0/24',
		'1.10.0/26',
	]);
});

test('an older release cannot downgrade or add duplicate baseline jobs', async () => {
	const matrix = await planCompatibility(targets, tags('1.35.0'), async () => {
		throw new Error('Must not resolve an older release.');
	});
	expect(matrix.include).toHaveLength(4);
});

test('non-version aliases, image variants and prereleases cannot enter the matrix', async () => {
	const ignored = [
		'latest',
		'alpine',
		'testing',
		'testing-debian',
		'webauthn',
		'1.99.0-alpine',
		'1.99.0-arm32v6',
		'1.99.0-rc.1',
		'v1.99.0',
		'01.99.0',
	];
	expect(latestStableVersion(['1.37.4', ...ignored, '1.36.0'])).toBe('1.37.4');
	const matrix = await planCompatibility(targets, ['1.37.4', ...ignored], async () => {
		throw new Error('Must not resolve an image variant or prerelease.');
	});
	expect(matrix.include).toHaveLength(4);
});

test('an empty or malformed tag list fails planning before image resolution', async () => {
	let lookups = 0;
	for (
		const candidate of [[], tags('1.38.0-rc.1'), tags('latest'), tags('1.38.0\nmatrix=malicious'), tags('01.38.0')]
	) {
		await expect(planCompatibility(targets, candidate, async () => {
			lookups++;
			return image;
		})).rejects.toThrow();
	}
	expect(lookups).toBe(0);
});

test('release lookup failures and mutable images cannot silently remove the latest release from CI', async () => {
	await expect(planCompatibility(targets, tags('1.38.0'), async () => {
		throw new Error('Registry unavailable');
	})).rejects.toThrow('Registry unavailable');
	await expect(planCompatibility(targets, tags('1.38.0'), async () => 'vaultwarden/server:1.38.0')).rejects.toThrow(
		'pinned',
	);
});

test('bad or empty baselines, Node versions and oversized matrices fail planning', async () => {
	const cases: CompatibilityTargets[] = [
		{ ...targets, servers: {} },
		{ ...targets, servers: { invalid: image } },
		{ ...targets, nodeVersions: [] },
		{ ...targets, nodeVersions: ['$(bad)'] },
		{ ...targets, nodeVersions: Array.from({ length: 129 }, (_, i) => String(i + 1)) },
	];
	for (const candidate of cases) {
		await expect(planCompatibility(candidate, tags('1.37.4'), async () => image)).rejects.toThrow();
	}
});

test('the compatibility runner accepts unknown stable versions only with a pinned image', () => {
	expect(resolveCompatibilityTarget(targets, '1.38.0', image)).toEqual({ version: '1.38.0', image });
	expect(() => resolveCompatibilityTarget(targets, '1.38.0')).toThrow('VW_TEST_IMAGE');
	for (const override of ['vaultwarden/server:latest', `other/server@sha256:${'a'.repeat(64)}`, `${image}\n`]) {
		expect(() => resolveCompatibilityTarget(targets, '1.38.0', override)).toThrow('pinned');
	}
	expect(() => resolveCompatibilityTarget(targets, 'latest', image)).toThrow('Invalid stable');
});

test('crane resolves the official release tag to an immutable manifest digest', async () => {
	const requests: string[][] = [];
	const resolved = await resolveReleaseImage('1.38.0', async args => {
		requests.push(args);
		return `sha256:${'a'.repeat(64)}\n`;
	});
	expect(requests).toEqual([['digest', 'vaultwarden/server:1.38.0']]);
	expect(resolved).toBe(image);
});

test('crane failures and missing or invalid digests never yield mutable image fallbacks', async () => {
	for (const digest of ['', 'latest', 'sha256:invalid', `sha256:${'a'.repeat(64)}\nextra`]) {
		await expect(resolveReleaseImage('1.38.0', async () => digest)).rejects.toThrow('valid immutable image digest');
	}
	await expect(resolveReleaseImage('1.38.0', async () => {
		throw new Error('Registry unavailable');
	})).rejects.toThrow('Registry unavailable');
});
