import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { appendFile, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { repoRoot } from '../runtime.mjs';

export const workspaces = { vaultwarden: 'packages/vaultwarden', cli: 'apps/cli' } as const;
export type PackageId = keyof typeof workspaces;
export const packageIds: PackageId[] = ['vaultwarden', 'cli'];
export const releaseTagPattern = /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
export const artifacts = resolve(repoRoot, 'artifacts');
export const releaseAssets = ['vaultwarden.tgz', 'cli.tgz', 'SHA256SUMS', 'release.json'];
export interface ReleaseMetadata {
	tag: string;
	version: string;
	sha: string;
	run: number;
	packages: PackageId[];
	prerelease: boolean;
}
export function parseRelease(source: string): ReleaseMetadata {
	const value = JSON.parse(source) as ReleaseMetadata;
	assert(value && typeof value === 'object', 'Missing release metadata');
	assert(typeof value.tag === 'string' && releaseTagPattern.test(value.tag), 'Invalid release tag');
	assert.equal(value.version, value.tag.slice(1), 'Release version differs from tag');
	assert(typeof value.sha === 'string' && /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(value.sha), 'Invalid source commit');
	assert(Number.isSafeInteger(value.run) && value.run > 0, 'Invalid release workflow run');
	assert.deepEqual(value.packages, packageIds, 'Unexpected release packages');
	assert.equal(value.prerelease, value.version.split('+')[0]!.includes('-'), 'Incorrect prerelease status');
	return value;
}
export function run(command: string, args: string[], cwd = repoRoot): string {
	return execFileSync(command, args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] }).trim();
}
export const sourceCommit = () => run('git', ['rev-parse', 'HEAD']);
export async function emitRelease(release: ReleaseMetadata, output?: string) {
	const json = JSON.stringify(release);
	if (output) await appendFile(output, `release=${json}\n`);
	console.log(json);
}
export async function workspaceManifest(packageId: PackageId) {
	assert(Object.hasOwn(workspaces, packageId), 'Unknown release package');
	return JSON.parse(await readFile(resolve(repoRoot, workspaces[packageId], 'package.json'), 'utf8')) as {
		name: string;
		version: string;
		private?: boolean;
		publishConfig?: { access?: string };
	};
}
export async function archiveManifest(packageId: PackageId, version: string) {
	const expected = await workspaceManifest(packageId);
	const actual = JSON.parse(run('tar', ['-xOf', `${packageId}.tgz`, 'package/package.json'], artifacts));
	assert.equal(actual.name, expected.name, 'Archive package name mismatch');
	assert.equal(actual.version, version, 'Archive version mismatch');
	return expected;
}
export async function checksum(directory: string, file: string) {
	return createHash('sha256').update(await readFile(resolve(directory, file))).digest('hex');
}
export async function verifyChecksums(directory: string, manifest: string, files: readonly string[]) {
	const entries = new Map<string, string>();
	for (const line of (await readFile(resolve(directory, manifest), 'utf8')).trim().split('\n')) {
		const match = /^([a-f0-9]{64}) [ *]([A-Za-z0-9_.-]+)$/.exec(line);
		assert(match, `Invalid checksum entry in ${manifest}`);
		assert(!entries.has(match[2]!), `Duplicate checksum for ${match[2]}`);
		entries.set(match[2]!, match[1]!);
	}
	for (const file of files) {
		assert(entries.has(file), `Missing checksum for ${file}`);
		assert.equal(await checksum(directory, file), entries.get(file), `Checksum mismatch for ${file}`);
	}
}
