import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { brotliCompressSync, constants } from 'node:zlib';

const root = dirname(fileURLToPath(import.meta.url));
process.chdir(root);
const run = (command, args) => execFileSync(command, args, { cwd: root, stdio: 'inherit' });
const jco = join(root, 'node_modules/@bytecodealliance/jco/dist/jco.js');
mkdirSync('.cache', { recursive: true });
mkdirSync('results', { recursive: true });
const archive = '.cache/zxcvbn-3.1.1.crate';
if (!existsSync(archive)) {
	const response = await fetch('https://static.crates.io/crates/zxcvbn/zxcvbn-3.1.1.crate');
	assert(response.ok, `Crate download failed: ${response.status}`);
	writeFileSync(archive, Buffer.from(await response.arrayBuffer()));
}
assert.equal(
	createHash('sha256').update(readFileSync(archive)).digest('hex'),
	'f9eaee90f4a795d1eb4ba6c51e1c1721d4784d550e8efa7b2600f29c867365e0',
);

// Regenerate the owned, ignored vendor directory from the verified archive.
rmSync('vendor/zxcvbn', { recursive: true, force: true });
mkdirSync('vendor/zxcvbn', { recursive: true });
run('tar', ['-xf', archive, '-C', 'vendor/zxcvbn', '--strip-components=1']);
run('patch', ['--batch', '-d', 'vendor/zxcvbn', '-p1', '-i', resolve('zxcvbn-wasi.patch')]);
run('cargo', ['+1.99.1', 'build', '--locked', '--target', 'wasm32-wasip2', '--release']);

const component = 'target/wasm32-wasip2/release/vw_password_strength_component.wasm';
mkdirSync('dist', { recursive: true });
cpSync(component, 'dist/password-strength.component.wasm');
writeFileSync('results/component.wit', execFileSync('node', [jco, 'wit', component], { cwd: root }));
run('node', [
	jco,
	'transpile',
	component,
	'-o',
	'generated/p2',
	'--name',
	'scorer',
	'--instantiation',
	'sync',
	'--base64-cutoff',
	'0',
]);

// Rebuild the existing implementation with the exact same Rust compiler/profile.
run('cargo', [
	'+1.99.1',
	'build',
	'--locked',
	'--manifest-path',
	'../../packages/vaultwarden/wasm/Cargo.toml',
	'--target',
	'wasm32-unknown-unknown',
	'--target-dir',
	resolve('target/baseline'),
	'--release',
]);
run('wasm-bindgen', [
	'target/baseline/wasm32-unknown-unknown/release/vw_password_strength.wasm',
	'--target',
	'web',
	'--out-dir',
	'generated/baseline',
	'--out-name',
	'baseline',
]);

const sizes = {};
for (const variant of ['baseline', 'p2']) {
	const destination = `dist/${variant}`;
	mkdirSync(destination, { recursive: true });
	for (const name of readdirSync(`generated/${variant}`).filter(name => name.endsWith('.wasm'))) {
		const binary = readFileSync(`generated/${variant}/${name}`);
		writeFileSync(
			`${destination}/${name}.br`,
			brotliCompressSync(binary, {
				params: { [constants.BROTLI_PARAM_QUALITY]: 11 },
			}),
		);
	}
	const result = await Bun.build({
		entrypoints: [`${variant}.mjs`],
		outdir: destination,
		naming: 'index.mjs',
		target: 'node',
		minify: true,
	});
	assert(result.success, String(result.logs));
	writeFileSync(
		`${destination}/index.d.mts`,
		'export declare function score(password: string, context?: string[]): number;\n'
			+ (variant === 'p2'
				? 'export declare function createScorer(onCall?: (name: string) => void): (password: string, context: string[]) => number;\n'
				: ''),
	);
	cpSync(`generated/${variant}`, `${destination}/types`, {
		recursive: true,
		filter: path => !path.endsWith('.wasm') && !path.endsWith('.js'),
	});
	sizes[variant] = Object.fromEntries(
		readdirSync(destination).filter(name => name.endsWith('.mjs') || name.endsWith('.br'))
			.map(name => [name, readFileSync(`${destination}/${name}`).length]),
	);
}
writeFileSync('results/sizes.json', JSON.stringify(sizes, null, 2) + '\n');
console.log(sizes);
