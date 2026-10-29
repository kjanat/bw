#!/usr/bin/env bun
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { cases } from './cases.mjs';
import { runDirect, inDirectory } from '../../tools/runtime.mjs';

export async function benchmarkWorker(variant) {
	return inDirectory(fileURLToPath(new URL('.', import.meta.url)), async () => {
		const start = performance.now();
		const { score } = await import(`./dist/${variant}/index.mjs`);
		const imported = performance.now();
		score('VeryStrong123@#');
		const first = performance.now();
		const samples = cases.filter(({ password }) => password.length > 0 && password.length < 40);
		let checksum = 0;
		for (let i = 0; i < 64; i++) score(samples[i % samples.length].password, samples[i % samples.length].context);
		const warm = performance.now();
		for (let i = 0; i < 512; i++) {
			const { password, context } = samples[i % samples.length];
			checksum += score(password, context);
		}
		console.log(
			JSON.stringify({
				importMs: imported - start,
				firstScoreMs: first - imported,
				warmScoreMs: (performance.now() - warm) / 512,
				checksum,
			}),
		);
	});
}

if (import.meta.main) {
	await runDirect(['experiment', 'wasip2', 'benchmark-worker'], import.meta.url, { benchmarkWorker });
}
