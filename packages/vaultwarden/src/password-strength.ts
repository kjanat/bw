import { readFileSync } from 'node:fs';
import { brotliDecompressSync } from 'node:zlib';
import { initSync, password_score } from './generated/password-strength.js';

let initialized = false;

/** Keep the public scoring API synchronous and load the local WASM only when needed. */
export function passwordScore(password: string, context: string[]): number {
	if (!initialized) {
		const compressed = readFileSync(new URL('./password-strength.wasm.br', import.meta.url));
		initSync({ module: brotliDecompressSync(compressed) });
		initialized = true;
	}
	return password_score(password, context);
}
