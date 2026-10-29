#!/usr/bin/env bun
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { runDirect, inDirectory } from '../../tools/runtime.mjs';

export async function buildDependencySize({ wasmOpt, cargoHome }) {
	return inDirectory(fileURLToPath(new URL('.', import.meta.url)), async () => {
		const root = fileURLToPath(new URL('.', import.meta.url));
		const version = (command, args, cwd = root) => execFileSync(command, args, { cwd, encoding: 'utf8' }).trim();
		const binaryen = version(wasmOpt, ['--version']);
		if (!/\bversion 133\b/.test(binaryen)) {
			throw new Error(`Expected Binaryen 133, found ${binaryen}`);
		}
		mkdirSync('out', { recursive: true });
		writeFileSync(
			'out/environment.json',
			JSON.stringify(
				{
					runtime: process.versions.bun ? 'bun' : 'node',
					runtimeVersion: process.versions.bun ?? process.version,
					nodeCompatibilityVersion: process.version,
					bun: version('bun', ['--version']),
					rustc: version('rustup', ['run', '1.99.1', 'rustc', '--version']),
					binaryen,
					platform: process.platform,
					arch: process.arch,
					versions: process.versions,
				},
				null,
				2,
			) + '\n',
		);

		for (const [name, feature] of [['psl', 'domain'], ['html', 'html']]) {
			execFileSync('cargo', [
				'+1.99.1',
				'build',
				'--locked',
				'--release',
				'--target',
				'wasm32-wasip2',
				'--target-dir',
				'target',
				'--no-default-features',
				'--features',
				feature,
			], {
				cwd: `${root}/rust`,
				stdio: 'inherit',
				env: cargoHome ? { ...process.env, CARGO_HOME: cargoHome } : process.env,
			});
			copyFileSync('rust/target/wasm32-wasip2/release/vw_size_probe.wasm', `out/${name}-component.wasm`);
		}
		await (await import('./probe.mjs')).probeJavaScript();
		await (await import('./wasm.mjs')).measureWasm({ wasmOpt });
	});
}

if (import.meta.main) await runDirect(['experiment', 'sizes', 'build'], import.meta.url, { buildDependencySize });
