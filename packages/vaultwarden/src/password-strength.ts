import { readFileSync } from 'node:fs';
import { brotliDecompressSync } from 'node:zlib';
import { instantiate, type Root } from './generated/password-strength.js';
import { createScoringHost } from '#password-strength-host';

let scorer: Root | undefined;

/** Keep the public scoring API synchronous and load the local WASM only when needed. */
export function passwordScore(password: string, context: string[]): number {
	scorer ??= instantiate(
		path =>
			new WebAssembly.Module(
				brotliDecompressSync(readFileSync(new URL(`./generated/${path}.br`, import.meta.url))),
			),
		createScoringHost(),
	);
	return scorer.score(password, context);
}
