import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { cp, mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const runtime = process.argv[2];
assert(runtime === 'node' || runtime === 'bun', 'Choose node or bun');
const workspaces = { vaultwarden: 'packages/vaultwarden', cli: 'apps/cli' } as const;
const packages = Object.fromEntries(
	await Promise.all(
		Object.entries(workspaces).map(async ([packageId, workspace]) => {
			const manifest = JSON.parse(await readFile(resolve(workspace, 'package.json'), 'utf8')) as { name: string };
			return [manifest.name, `file:${resolve('artifacts', `${packageId}.tgz`)}`];
		}),
	),
);
const consumerRoot = resolve('.cache');
await mkdir(consumerRoot, { recursive: true });
const consumer = await mkdtemp(resolve(consumerRoot, 'vw-package-consumer-'));
await writeFile(
	resolve(consumer, 'package.json'),
	JSON.stringify({
		private: true,
		type: 'module',
		dependencies: packages,
		overrides: packages,
	}),
);
await cp(fileURLToPath(new URL('./smoke.mjs', import.meta.url)), resolve(consumer, 'smoke.mjs'));
execFileSync('bun', ['install', '--ignore-scripts'], { cwd: consumer, stdio: 'inherit' });
execFileSync(runtime, ['smoke.mjs'], { cwd: consumer, stdio: 'inherit' });
