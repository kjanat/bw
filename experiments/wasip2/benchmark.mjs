#!/usr/bin/env bun
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { runDirect, inDirectory } from '../../tools/runtime.mjs';

export async function benchmarkScorers() {
	return inDirectory(fileURLToPath(new URL('.', import.meta.url)), async () => {
		const results = {};
		for (const runtime of ['node', 'bun']) {
			const samples = { baseline: [], p2: [] };
			for (let i = 0; i < 5; i++) {
				for (const variant of i % 2 ? ['p2', 'baseline'] : ['baseline', 'p2']) {
					samples[variant].push(
						JSON.parse(execFileSync(runtime, ['benchmark-worker.mjs', '--variant', variant], { encoding: 'utf8' })),
					);
				}
			}
			assert.equal(new Set([...samples.baseline, ...samples.p2].map(x => x.checksum)).size, 1);
			results[runtime] = Object.fromEntries(
				Object.entries(samples).map((
					[variant, rows],
				) => [
					variant,
					Object.fromEntries(
						['importMs', 'firstScoreMs', 'warmScoreMs'].map(key => [
							key,
							rows.map(row => row[key]).sort((a, b) => a - b)[2],
						]),
					),
				]),
			);
		}
		results.bytes = {};
		for (const variant of ['baseline', 'p2']) {
			const buffers = readdirSync(`dist/${variant}`).filter(name => name.endsWith('.mjs') || name.endsWith('.br'))
				.map(name => readFileSync(`dist/${variant}/${name}`));
			results.bytes[variant] = {
				runtime: buffers.reduce((n, b) => n + b.length, 0),
				gzip: buffers.reduce((n, b) => n + gzipSync(b, { level: 9 }).length, 0),
			};
		}
		writeFileSync('results/benchmark.json', JSON.stringify(results, null, 2) + '\n');
		console.log(JSON.stringify(results, null, 2));
	});
}

if (import.meta.main) await runDirect(['experiment', 'wasip2', 'benchmark'], import.meta.url, { benchmarkScorers });
