import { readFileSync } from 'node:fs';
import { brotliDecompressSync } from 'node:zlib';
import { instantiate } from './generated/p2/scorer.js';
import { createHost } from './host.mjs';

export function createScorer(onCall) {
	return instantiate(
		path => new WebAssembly.Module(brotliDecompressSync(readFileSync(new URL(`./${path}.br`, import.meta.url)))),
		createHost(onCall),
	).score;
}

let scorer;
export function score(password, context = []) {
	scorer ??= createScorer();
	return scorer(password, context);
}
