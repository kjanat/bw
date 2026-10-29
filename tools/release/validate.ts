#!/usr/bin/env bun
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { repoRoot, runDirect } from '../runtime.mjs';
import { artifacts, emitRelease, packageIds, parseRelease, run, sourceCommit, verifyChecksums } from './metadata.ts';

export async function validateRelease(tag: string, output?: string) {
	await verifyChecksums(artifacts, 'SHA256SUMS', [...packageIds.map(id => `${id}.tgz`), 'release.json']);
	const release = parseRelease(await readFile(resolve(artifacts, 'release.json'), 'utf8'));
	assert.equal(release.tag, tag, 'Release tag mismatch');
	assert.equal(release.sha, sourceCommit(), 'Release source commit mismatch');
	execFileSync('gh', ['run', 'watch', String(release.run), '--exit-status', '--interval', '5'], {
		cwd: repoRoot,
		stdio: 'inherit',
	});
	const workflow = JSON.parse(run('gh', ['run', 'view', String(release.run), '--json', 'workflowName,conclusion'])) as {
		workflowName: string;
		conclusion: string;
	};
	assert.equal(workflow.workflowName, 'Release', 'Unexpected source workflow');
	assert.equal(workflow.conclusion, 'success', 'Release workflow did not succeed');
	await emitRelease(release, output);
}
if (import.meta.main) await runDirect(['release', 'validate'], import.meta.url, { validateRelease });
