#!/usr/bin/env bun
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runDirect, inDirectory } from '../../tools/runtime.mjs';

export async function verifyRecorded(runtimes = ['node', 'bun']) {
	return inDirectory(fileURLToPath(new URL('.', import.meta.url)), async () => {
		for (const runtime of runtimes) {
			const read = directory =>
				JSON.parse(readFileSync(
					new URL(`${directory}/parity-${runtime}.json`, import.meta.url),
					'utf8',
				));
			assert.deepEqual(read('out'), read('results'), `${runtime}: compatibility findings changed`);
		}
		console.log(`${runtimes.join(' and ')} reproduced all recorded compatibility findings.`);
	});
}

if (import.meta.main) await runDirect(['experiment', 'sizes', 'verify-recorded'], import.meta.url, { verifyRecorded });
