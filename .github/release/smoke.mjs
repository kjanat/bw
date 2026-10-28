import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { SDK_VERSION } from '@kjanat/vaultwarden';
import sdk from '@kjanat/vaultwarden/package.json' with { type: 'json' };
import cli from '@kjanat/vaultwarden-cli/package.json' with { type: 'json' };

assert.equal(SDK_VERSION, sdk.version);
assert.ok(import.meta.resolve('@kjanat/vaultwarden').startsWith(new URL('./node_modules/', import.meta.url).href));
for (const [command, expected] of [['--version', cli.version], ['sdk-version', sdk.version]]) {
	const output = execFileSync(process.execPath, [resolve('node_modules/.bin/vw'), command], { encoding: 'utf8' });
	assert.equal(output.trim(), expected);
}
