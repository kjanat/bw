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
const previewMetadataPath = process.env.PREVIEW_METADATA;
let dependencies = packages;
if (previewMetadataPath) {
	const metadata = JSON.parse(await readFile(previewMetadataPath, 'utf8')) as {
		packages: { name: string; url: string }[];
	};
	const cli = JSON.parse(await readFile(resolve(workspaces.cli, 'package.json'), 'utf8')) as { name: string };
	const published = metadata.packages.find(pkg => pkg.name === cli.name);
	assert(published, `Missing publication metadata for ${cli.name}`);
	dependencies = { [cli.name]: published.url };
}
const consumerRoot = resolve('.cache');
await mkdir(consumerRoot, { recursive: true });
const consumer = await mkdtemp(resolve(consumerRoot, 'vw-package-consumer-'));
await writeFile(
	resolve(consumer, 'package.json'),
	JSON.stringify({
		private: true,
		type: 'module',
		dependencies,
		...(previewMetadataPath ? {} : { overrides: packages }),
	}),
);
await cp(fileURLToPath(new URL('./smoke.mjs', import.meta.url)), resolve(consumer, 'smoke.mjs'));
await cp(resolve('apps/cli/test/fixtures/kdbx'), resolve(consumer, 'fixtures/kdbx'), { recursive: true });
execFileSync('bun', ['install', '--ignore-scripts'], { cwd: consumer, stdio: 'inherit' });
execFileSync(runtime, ['smoke.mjs'], { cwd: consumer, stdio: 'inherit' });
