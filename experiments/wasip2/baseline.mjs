import { readFileSync } from 'node:fs';
import { brotliDecompressSync } from 'node:zlib';
import { initSync, password_score } from './generated/baseline/baseline.js';

let initialized = false;
export function score(password, context = []) {
	if (!initialized) {
		initSync({ module: brotliDecompressSync(readFileSync(new URL('./baseline_bg.wasm.br', import.meta.url))) });
		initialized = true;
	}
	return password_score(password, context);
}
