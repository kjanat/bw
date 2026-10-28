import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';

const sha = process.argv[2] ?? process.env.PREVIEW_SHA;
assert(sha && /^[0-9a-f]{40}$/.test(sha), 'Choose the exact preview commit SHA');
const packages = ['vaultwarden', 'cli'];
await Promise.all(packages.map(async (packageId) => {
	const manifestPath = packageId === 'vaultwarden' ? 'packages/vaultwarden/package.json' : 'apps/cli/package.json';
	const manifest = JSON.parse(await readFile(manifestPath, 'utf8')) as { name: string };
	const url = `https://pkg.pr.new/${manifest.name}@${sha}`;
	const response = await fetch(url);
	assert(response.ok, `${url}: HTTP ${response.status}`);
	const archive = new Uint8Array(await response.arrayBuffer());
	const expected = (await readFile(`artifacts/${packageId}.tgz.sha256`, 'utf8')).split(/\s+/)[0];
	const actual = createHash('sha256').update(archive).digest('hex');
	assert.equal(actual, expected, `${packageId}: preview differs from its build artifact`);
	await writeFile(`artifacts/${packageId}.tgz`, archive);
	console.log(`Verified preview archive: ${url}`);
}));
