#!/usr/bin/env bun
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { brotliCompressSync, constants } from 'node:zlib';
import { runDirect, inDirectory } from '../../tools/runtime.mjs';

export async function optimizeScorers({ wasmOpt }) {
	return inDirectory(fileURLToPath(new URL('.', import.meta.url)), async () => {
		const root = dirname(fileURLToPath(import.meta.url));
		const version = execFileSync(wasmOpt, ['--version'], { encoding: 'utf8' }).trim();
		assert.match(version, /version 133\b/, 'Use the Binaryen version pinned in mise.toml');
		const profiles = { Os: ['-Os'], Oz: ['-Oz'], 'Oz-converge': ['-Oz', '--converge'] };
		const flags = ['--enable-bulk-memory', '--enable-reference-types', '--strip-debug', '--strip-producers'];
		const results = { version, flags, profiles: {} };
		mkdirSync(join(root, 'results'), { recursive: true });

		for (const [profile, passes] of Object.entries(profiles)) {
			const distribution = `dist/wasm-opt/${profile}`;
			const sizes = {};
			for (const variant of ['baseline', 'p2']) {
				const output = join(root, distribution, variant);
				cpSync(join(root, 'dist', variant), output, { recursive: true });
				const raw = join(root, 'generated/wasm-opt', profile, variant);
				mkdirSync(raw, { recursive: true });
				sizes[variant] = {};
				for (const file of readdirSync(join(root, 'generated', variant)).filter(file => file.endsWith('.wasm'))) {
					const input = join(root, 'generated', variant, file);
					const optimized = join(raw, file);
					console.log(`${profile}: ${variant}/${file}`);
					execFileSync(wasmOpt, [input, ...passes, ...flags, '-o', optimized], { stdio: 'inherit' });
					const before = readFileSync(input);
					const after = readFileSync(optimized);
					const beforeModule = new WebAssembly.Module(before);
					const afterModule = new WebAssembly.Module(after);
					const exports = module => WebAssembly.Module.exports(module).sort((a, b) => a.name.localeCompare(b.name));
					assert.deepEqual(exports(afterModule), exports(beforeModule), 'Preserve the generated JS export contract');
					const imports = WebAssembly.Module.imports(beforeModule).map(item => JSON.stringify(item));
					assert(
						WebAssembly.Module.imports(afterModule).every(item => imports.includes(JSON.stringify(item))),
						'No new host imports',
					);
					const compressed = brotliCompressSync(after, { params: { [constants.BROTLI_PARAM_QUALITY]: 11 } });
					writeFileSync(join(output, `${file}.br`), compressed);
					sizes[variant][file] = {
						before: before.length,
						after: after.length,
						brotliBefore: readFileSync(join(root, 'dist', variant, `${file}.br`)).length,
						brotliAfter: compressed.length,
					};
				}
			}
			for (const runtime of ['node', 'bun']) {
				execFileSync(runtime, ['verify.mjs', '--distribution', distribution], { cwd: root, stdio: 'inherit' });
			}
			results.profiles[profile] = { passes, sizes, node: true, bun: true, cases: 258 };
			writeFileSync(join(root, 'results/wasm-opt.json'), JSON.stringify(results, null, 2) + '\n');
		}
		console.log(JSON.stringify(results, null, 2));
	});
}

if (import.meta.main) await runDirect(['experiment', 'wasip2', 'optimize'], import.meta.url, { optimizeScorers });
