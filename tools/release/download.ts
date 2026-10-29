#!/usr/bin/env bun
import { runDirect } from '../runtime.mjs';
import { artifacts, releaseAssets, run, type PackageId } from './metadata.ts';

export function downloadRelease(tag: string, packageId?: PackageId) {
	const files = packageId ? [`${packageId}.tgz`, 'SHA256SUMS'] : releaseAssets;
	run('gh', ['release', 'download', tag, ...files.flatMap(file => ['--pattern', file]), '--dir', artifacts]);
}
if (import.meta.main) await runDirect(['release', 'download'], import.meta.url, { downloadRelease });
