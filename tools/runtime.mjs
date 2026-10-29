import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { isAbsolute, resolve, join, delimiter } from 'node:path';
import { fileURLToPath } from 'node:url';

export const repoRoot = fileURLToPath(new URL('..', import.meta.url));

export async function runDirect(prefix, source, operations) {
	const { runRepo } = await import('./repo.ts');
	await runRepo(prefix, { [source]: operations });
}

export async function inDirectory(directory, action) {
	const previous = process.cwd();
	try {
		process.chdir(directory);
		return await action();
	} finally {
		process.chdir(previous);
	}
}

export function resolveWasmOpt(requested) {
	let executable = requested;
	if (!executable) {
		try {
			const installation = execFileSync('mise', ['where', 'github:WebAssembly/binaryen@133'], {
				cwd: repoRoot,
				encoding: 'utf8',
				stdio: ['ignore', 'pipe', 'ignore'],
			}).trim();
			executable = join(installation, 'bin', 'wasm-opt');
		} catch {
			executable = 'wasm-opt';
		}
	}
	if (!isAbsolute(executable)) {
		executable = executable.includes('/') || executable.includes('\\')
			? resolve(executable)
			: (process.env.PATH ?? '').split(delimiter).map(directory => join(directory, executable))
				.find(path => existsSync(path)) ?? executable;
	}
	const version = execFileSync(executable, ['--version'], { encoding: 'utf8' }).trim();
	if (!/\bversion 133\b/.test(version)) {
		throw new Error(`Expected Binaryen 133, found ${version}. Select it with --wasm-opt /path/to/wasm-opt.`);
	}
	return executable;
}
