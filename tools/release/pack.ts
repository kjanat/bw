#!/usr/bin/env bun
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { runDirect, inDirectory, repoRoot } from '../runtime.mjs';

export async function packRelease(packageId: 'vaultwarden' | 'cli') {
	return inDirectory(repoRoot, async () => {
		const workspaces = { vaultwarden: 'packages/vaultwarden', cli: 'apps/cli' } as const;
		assert(packageId in workspaces, 'Pass vaultwarden or cli');
		const workspace = workspaces[packageId];
		const manifest = JSON.parse(await readFile(resolve(workspace, 'package.json'), 'utf8')) as {
			name: string;
			version: string;
			private?: boolean;
			publishConfig?: { access?: string };
		};
		assert.notEqual(manifest.private, true, `${manifest.name} is private`);
		assert.equal(manifest.publishConfig?.access, 'public', `${manifest.name} must publish publicly`);

		const destination = resolve('artifacts');
		await mkdir(destination, { recursive: true });
		const archive = resolve(destination, `${packageId}.tgz`);
		execFileSync('bun', ['pm', 'pack', '--ignore-scripts', '--filename', archive], {
			cwd: resolve(workspace),
			stdio: 'inherit',
		});
		const digest = createHash('sha256').update(await readFile(archive)).digest('hex');
		await writeFile(`${archive}.sha256`, `${digest}  ${packageId}.tgz\n`);
		console.log(`Packed ${manifest.name}@${manifest.version}: ${archive}`);
	});
}

if (import.meta.main) await runDirect(['release', 'pack'], import.meta.url, { packRelease });
