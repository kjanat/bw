import { performance } from 'node:perf_hooks';
import { cases } from './cases.mjs';

const start = performance.now();
const { score } = await import(`./dist/${process.argv[2]}/index.mjs`);
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
