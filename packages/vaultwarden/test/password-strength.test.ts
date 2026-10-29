import { test, expect } from 'bun:test';
import { readFileSync } from 'node:fs';
import { brotliDecompressSync } from 'node:zlib';
import { createScoringHost } from '#password-strength-host';
import { instantiate } from '../src/generated/password-strength.js';

test('the component scores with only clocks and a hash seed', () => {
	const calls = new Set<string>();
	const scorer = instantiate(
		path =>
			new WebAssembly.Module(brotliDecompressSync(
				readFileSync(new URL(`../src/generated/${path}.br`, import.meta.url)),
			)),
		createScoringHost(name => calls.add(name)),
	);
	expect(scorer.score('x01011903', [])).toBeGreaterThanOrEqual(0);
	expect(scorer.score('asdfjkhkjwer!', ['asdfjkhkjwer'])).toBe(1);
	expect(scorer.score('asdfjkhkjwer!', [])).toBe(4);
	expect([...calls].sort()).toEqual(['clock.monotonic', 'clock.wall', 'random.hashSeed']);
});

test('the scoring host refuses process I/O and exposes no environment', () => {
	const host = createScoringHost();
	expect(host['wasi:cli/environment@0.2.12'].getEnvironment()).toEqual([]);
	expect(() => host['wasi:cli/stdout@0.2.12'].getStdout()).toThrow('Unexpected WASI operation');
	expect(() => host['wasi:cli/stderr@0.2.12'].getStderr()).toThrow('Unexpected WASI operation');
	expect(() => host['wasi:cli/stdin@0.2.12'].getStdin()).toThrow('Unexpected WASI operation');
	expect(() => host['wasi:io/poll@0.2.12'].poll([])).toThrow('Unexpected WASI operation');
});

test('the built SDK captures the UTC reference year across timezones', () => {
	// These date-pattern scores cross a threshold between reference years 2026/2027.
	// Fresh processes isolate the instance's lazily initialized reference year.
	const program = `
const { passwordStrength } = await import('./dist/index.mjs');
Date.now = () => Date.parse(process.env.SCORING_TIME);
const first = passwordStrength('x01011903');
Date.now = () => Date.parse('2027-01-01T00:00:01Z');
console.log(JSON.stringify([first, passwordStrength('x01011903')]));
`;
	for (const tz of ['UTC', 'Pacific/Kiritimati', 'America/Los_Angeles']) {
		for (const [time, expected] of [['2026-12-31T23:59:59Z', 1], ['2027-01-01T00:00:00Z', 2]] as const) {
			const result = Bun.spawnSync([process.execPath, '--eval', program], {
				cwd: new URL('..', import.meta.url).pathname,
				env: { ...process.env, TZ: tz, SCORING_TIME: time },
			});
			expect(result.exitCode).toBe(0);
			expect(JSON.parse(result.stdout.toString())).toEqual([expected, expected]);
		}
	}
}, 10_000);
