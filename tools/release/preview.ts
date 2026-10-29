#!/usr/bin/env bun
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { runDirect, inDirectory, repoRoot } from '../runtime.mjs';

export async function fetchPreview(metadataPath: string) {
	return inDirectory(repoRoot, async () => {
		const metadata = JSON.parse(await readFile(metadataPath, 'utf8')) as {
			packages: { name: string; url: string; shasum: string }[];
		};
		const packages = ['vaultwarden', 'cli'];
		await Promise.all(packages.map(async (packageId) => {
			const manifestPath = packageId === 'vaultwarden' ? 'packages/vaultwarden/package.json' : 'apps/cli/package.json';
			const manifest = JSON.parse(await readFile(manifestPath, 'utf8')) as { name: string };
			const published = metadata.packages.find(pkg => pkg.name === manifest.name);
			assert(published, `Missing publication metadata for ${manifest.name}`);
			const { url, shasum } = published;
			const response = await fetch(url);
			assert(response.ok, `${url}: HTTP ${response.status}`);
			const archive = new Uint8Array(await response.arrayBuffer());
			const actual = createHash('sha1').update(archive).digest('hex');
			assert.equal(actual, shasum, `${packageId}: preview differs from its published archive`);
			await writeFile(`artifacts/${packageId}.tgz`, archive);
			console.log(`Verified preview archive: ${url}`);
		}));
	});
}

if (import.meta.main) await runDirect(['release', 'preview'], import.meta.url, { fetchPreview });
