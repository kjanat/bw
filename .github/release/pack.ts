import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const workspaces = { vaultwarden: 'packages/vaultwarden', cli: 'apps/cli' } as const;
const packageId = process.argv[2] as keyof typeof workspaces;
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
