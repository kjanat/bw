import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

for (const runtime of ['node', 'bun']) {
	const read = directory =>
		JSON.parse(readFileSync(
			new URL(`${directory}/parity-${runtime}.json`, import.meta.url),
			'utf8',
		));
	assert.deepEqual(read('out'), read('results'), `${runtime}: compatibility findings changed`);
}
console.log('Node and Bun reproduced all recorded compatibility findings.');
