#!/usr/bin/env bun
import { resolve } from 'node:path';
import { runDirect } from '../runtime.mjs';
import { artifacts, releaseAssets, run, sourceCommit } from './metadata.ts';

export function verifyAttestations(tag: string, repository: string) {
	const sha = sourceCommit();
	for (const asset of releaseAssets) {
		run('gh', [
			'attestation',
			'verify',
			resolve(artifacts, asset),
			'--repo',
			repository,
			'--signer-workflow',
			`${repository}/.github/workflows/release.yml`,
			'--source-ref',
			`refs/tags/${tag}`,
			'--source-digest',
			sha,
			'--deny-self-hosted-runners',
		]);
		console.log(`Verified attestation: ${asset}`);
	}
}
if (import.meta.main) await runDirect(['release', 'verify-attestations'], import.meta.url, { verifyAttestations });
