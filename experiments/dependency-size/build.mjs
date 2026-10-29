import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('.', import.meta.url));
process.chdir(root);
const version = (command, args, cwd = root) => execFileSync(command, args, { cwd, encoding: 'utf8' }).trim();
const binaryen = version(process.env.WASM_OPT || 'wasm-opt', ['--version']);
if (!/\bversion 133\b/.test(binaryen)) {
	throw new Error(`Expected Binaryen 133, found ${binaryen}`);
}
mkdirSync('out', { recursive: true });
writeFileSync(
	'out/environment.json',
	JSON.stringify(
		{
			node: process.version,
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
	], { cwd: `${root}/rust`, stdio: 'inherit' });
	copyFileSync('rust/target/wasm32-wasip2/release/vw_size_probe.wasm', `out/${name}-component.wasm`);
}
for (const script of ['probe.mjs', 'wasm.mjs']) {
	execFileSync(process.execPath, [script], { cwd: root, stdio: 'inherit' });
}
