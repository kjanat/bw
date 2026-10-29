#!/usr/bin/env bun
import assert from 'node:assert/strict';
import { appendFile, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { runDirect } from '../runtime.mjs';
import {
	artifacts,
	archiveManifest,
	checksum,
	emitRelease,
	packageIds,
	parseRelease,
	releaseAssets,
	run,
	sourceCommit,
	verifyChecksums,
	workspaceManifest,
} from './metadata.ts';

export async function prepareDraft(options: { tag: string; ref: string; runId: string; output?: string }) {
	assert.equal(options.ref, `refs/tags/${options.tag}`, 'Release workflow must run from the release tag');
	const sha = sourceCommit();
	run('git', ['merge-base', '--is-ancestor', sha, 'origin/master']);
	const version = options.tag.slice(1);
	const release = parseRelease(
		JSON.stringify({
			tag: options.tag,
			version,
			sha,
			run: Number(options.runId),
			packages: packageIds,
			prerelease: version.split('+')[0]!.includes('-'),
		}),
	);
	for (const packageId of packageIds) {
		const manifest = await workspaceManifest(packageId);
		assert.equal(manifest.version, version, `${packageId} version differs from tag`);
		assert.notEqual(manifest.private, true, `${packageId} is private`);
		assert.equal(manifest.publishConfig?.access, 'public', `${packageId} must publish publicly`);
	}
	const releases = JSON.parse(run('gh', ['release', 'list', '--limit', '1000', '--json', 'tagName,isDraft'])) as {
		tagName: string;
		isDraft: boolean;
	}[];
	const existing = releases.filter(item => item.tagName === release.tag);
	if (existing.length === 0) {
		run('gh', [
			'release',
			'create',
			release.tag,
			'--draft',
			'--verify-tag',
			'--generate-notes',
			'--title',
			release.tag,
			...(release.prerelease ? ['--prerelease'] : []),
		]);
	} else {
		assert(existing.length === 1 && existing[0]!.isDraft, 'Existing release must be a draft');
	}
	await emitRelease(release, options.output);
}
export async function stageDraft(metadata: string) {
	const release = parseRelease(metadata);
	assert.equal(sourceCommit(), release.sha, 'Checkout differs from release source');
	for (const packageId of release.packages) {
		await verifyChecksums(artifacts, `${packageId}.tgz.sha256`, [`${packageId}.tgz`]);
		await archiveManifest(packageId, release.version);
	}
	await writeFile(resolve(artifacts, 'release.json'), `${JSON.stringify(release, null, 2)}\n`);
	const files = [...release.packages.map(id => `${id}.tgz`), 'release.json'];
	const lines = await Promise.all(files.map(async file => `${await checksum(artifacts, file)}  ${file}\n`));
	await writeFile(resolve(artifacts, 'SHA256SUMS'), lines.join(''));
	await verifyChecksums(artifacts, 'SHA256SUMS', files);
}
export async function attachDraft(metadata: string, summary?: string) {
	const release = parseRelease(metadata);
	assert.equal(sourceCommit(), release.sha, 'Checkout differs from release source');
	await verifyChecksums(artifacts, 'SHA256SUMS', [...release.packages.map(id => `${id}.tgz`), 'release.json']);
	assert.deepEqual(
		parseRelease(await readFile(resolve(artifacts, 'release.json'), 'utf8')),
		release,
		'Release metadata differs',
	);
	const existing = JSON.parse(run('gh', ['release', 'view', release.tag, '--json', 'isDraft'])) as { isDraft: boolean };
	assert.equal(existing.isDraft, true, 'Release must still be a draft');
	run('gh', ['release', 'upload', release.tag, ...releaseAssets, '--clobber'], artifacts);
	const message = `Draft ready for review: ${release.tag}`;
	if (summary) await appendFile(summary, `${message}\n`);
	console.log(message);
}
if (import.meta.main) await runDirect(['release', 'draft'], import.meta.url, { prepareDraft, stageDraft, attachDraft });
