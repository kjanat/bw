import { expect, test } from 'bun:test';
import {
	discoverReferenceVersions,
	planCompatibility,
	resolveReleaseImage,
	type CompatibilityTargets,
} from '#test/compatibility-plan';
import { classifyAuthentication } from '#test/reference-authentication';

const image = `vaultwarden/server@sha256:${'a'.repeat(64)}`;
const targets: CompatibilityTargets = {
	nodeVersion: '26',
	minimumServerVersion: '1.36.0',
	minimumReferenceCliVersion: '2026.10.0',
	servers: { '1.36.0': image },
	referenceIncompatibilities: [{ server: '1.36.0', referenceCliVersion: '2026.10.0', error: 'invalid-prelogin-kdf' }],
};
const servers = ['latest', '1.35.0', '1.36.0', '1.37.0', '1.37.1', '1.37.1', '1.38.0-beta', '1.37.1-alpine'];
const references = ['2026.9.0', '2026.10.0', '2026.10.1', '2026.11.0', '2026.12.0-beta.1'];
const pairs = (plan: Awaited<ReturnType<typeof planCompatibility>>) =>
	plan.matrix.include
		.map(row => `${row.server}/${row.referenceCliVersion}`);

test('full matrix retains every stable patch release and both CLI generations', async () => {
	const resolved: string[] = [];
	const plan = await planCompatibility(targets, servers, references, async version => {
		resolved.push(version);
		return image;
	});
	expect(plan.servers.include.map(row => row.server)).toEqual(['1.36.0', '1.37.0', '1.37.1']);
	expect(pairs(plan)).toEqual([
		'1.36.0/2026.10.0',
		'1.36.0/2026.10.1',
		'1.36.0/2026.11.0',
		'1.37.0/2026.10.0',
		'1.37.0/2026.10.1',
		'1.37.0/2026.11.0',
		'1.37.1/2026.10.0',
		'1.37.1/2026.10.1',
		'1.37.1/2026.11.0',
	]);
	expect(resolved).toEqual(['1.37.0', '1.37.1']);
	expect(plan.matrix.include.filter(row => row.expectedFailure !== null)).toEqual([
		{ server: '1.36.0', node: '26', image, referenceCliVersion: '2026.10.0', expectedFailure: 'invalid-prelogin-kdf' },
	]);
});

test('PR matrix covers all servers with newest CLI and all CLIs with newest server, without duplicate corner', async () => {
	const plan = await planCompatibility(targets, servers, references, async () => image, 'pr');
	expect(pairs(plan)).toEqual([
		'1.36.0/2026.11.0',
		'1.37.0/2026.11.0',
		'1.37.1/2026.10.0',
		'1.37.1/2026.10.1',
		'1.37.1/2026.11.0',
	]);
	expect(plan.servers.include).toHaveLength(3);
});

test('new releases expand coverage instead of replacing baselines', async () => {
	const plan = await planCompatibility(
		targets,
		[...servers, '1.38.0'],
		[...references, '2026.11.1'],
		async () => image,
	);
	expect(plan.matrix.include).toHaveLength(16);
	expect(pairs(plan)).toContain('1.36.0/2026.10.0');
	expect(pairs(plan)).toContain('1.38.0/2026.11.1');
});

test('missing registry baselines, failed image lookup and oversized matrices fail closed', async () => {
	await expect(planCompatibility(targets, [], references, async () => image)).rejects.toThrow(
		'minimum supported server',
	);
	await expect(planCompatibility(targets, servers, ['2026.10.1'], async () => image)).rejects.toThrow(
		'minimum supported CLI',
	);
	await expect(planCompatibility(targets, servers, references, async () => {
		throw new Error('registry offline');
	}))
		.rejects.toThrow('registry offline');
	await expect(planCompatibility(targets, servers, references, async () => 'vaultwarden/server:latest'))
		.rejects.toThrow('pinned');
	await expect(
		planCompatibility(targets, servers, Array.from({ length: 100 }, (_, index) => `2026.10.${index}`), async () => {
			throw new Error('must reject before resolving images');
		}),
	).rejects.toThrow('300 pair jobs');
});

test('reference discovery reads all published versions, not just the latest tag', async () => {
	const fakeFetch = async () =>
		Response.json({
			name: '@bitwarden/cli',
			versions: {
				'2026.10.0': {},
				'2026.10.1': {},
				'2026.11.0-beta': {},
			},
			'dist-tags': { latest: '2026.10.1' },
		});
	expect(await discoverReferenceVersions(fakeFetch)).toEqual(['2026.10.0', '2026.10.1', '2026.11.0-beta']);
	await expect(discoverReferenceVersions(async () => new Response('', { status: 503 })))
		.rejects.toThrow('HTTP 503');
	await expect(discoverReferenceVersions(async () => Response.json({ name: 'different', versions: {} })))
		.rejects.toThrow('metadata');
	await expect(resolveReleaseImage('1.38.0', async () => 'not a digest')).rejects.toThrow('digest');
});

test('only an exact known failure reproduced for both KDFs can omit reference comparisons', () => {
	const expected = targets.referenceIncompatibilities[0];
	expect(classifyAuthentication(['authenticated', 'authenticated'])).toBe('compatible');
	expect(classifyAuthentication(['invalid-prelogin-kdf', 'invalid-prelogin-kdf'], expected)).toBe('known-incompatible');
	expect(() => classifyAuthentication(['invalid-prelogin-kdf', 'invalid-prelogin-kdf'])).toThrow('Unexpected');
	expect(() => classifyAuthentication(['invalid-prelogin-kdf', 'failed'], expected)).toThrow('Unexpected');
	expect(() => classifyAuthentication(['authenticated', 'invalid-prelogin-kdf'], expected)).toThrow('Unexpected');
	expect(() => classifyAuthentication(['authenticated', 'authenticated'], expected)).toThrow('stale');
	expect(() => classifyAuthentication(['invalid-prelogin-kdf'], expected)).toThrow('Both KDF');
});
