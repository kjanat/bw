#!/usr/bin/env bun
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { runDirect, repoRoot } from '../runtime.mjs';
import {
	artifacts,
	archiveManifest,
	parseRelease,
	run,
	sourceCommit,
	verifyChecksums,
	type PackageId,
} from './metadata.ts';

export function publicationNeeded(status: number | null, stdout: string, integrity: string): boolean {
	const result = JSON.parse(stdout);
	if (status === 0) {
		const published = Array.isArray(result) ? result.flat(Infinity) : [result];
		assert(published.length === 1 && typeof published[0] === 'string', 'Invalid published integrity');
		assert.equal(published[0], integrity, 'Published tarball differs from approved archive');
		return false;
	}
	assert(status !== null && status > 0 && result?.error?.code === 'E404', 'npm lookup failed without E404');
	return true;
}
export async function publishRelease(options: { packageId: PackageId; metadata: string; temporary: string }) {
	const release = parseRelease(options.metadata);
	assert.equal(sourceCommit(), release.sha, 'Checkout differs from release source');
	const file = `${options.packageId}.tgz`;
	await verifyChecksums(artifacts, 'SHA256SUMS', [file]);
	const archive = resolve(artifacts, file);
	const bytes = await readFile(archive);
	assert(bytes.equals(await readFile(resolve(repoRoot, 'tested', file))), 'Release archive differs from tested build');
	const manifest = await archiveManifest(options.packageId, release.version);
	const integrity = `sha512-${createHash('sha512').update(bytes).digest('base64')}`;
	const lookup = spawnSync('npm', [
		'--prefix',
		options.temporary,
		'view',
		`${manifest.name}@${release.version}`,
		'dist.integrity',
		'--json',
		'--registry',
		'https://registry.npmjs.org',
	], { cwd: artifacts, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] });
	if (lookup.error) throw lookup.error;
	if (!publicationNeeded(lookup.status, lookup.stdout, integrity)) {
		console.log(`Already published identical tarball: ${manifest.name}@${release.version}`);
		return;
	}
	run('npm', [
		'--prefix',
		options.temporary,
		'publish',
		archive,
		'--access',
		'public',
		'--provenance',
		'--ignore-scripts',
		'--tag',
		release.prerelease ? 'next' : 'latest',
	], artifacts);
	console.log(`Published ${manifest.name}@${release.version}`);
}
if (import.meta.main) await runDirect(['release', 'publish'], import.meta.url, { publishRelease });
