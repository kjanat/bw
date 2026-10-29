import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { brotliCompressSync, constants } from 'node:zlib';
import { transpile } from '@bytecodealliance/jco';

const root = dirname(fileURLToPath(import.meta.url));
const generated = resolve(root, '../src/generated');
const target = join(root, 'target');
const cargoArgs = ['--manifest-path', join(root, 'Cargo.toml'), '--locked'];
const run = (command: string, args: string[]) => execFileSync(command, args, { cwd: root, stdio: 'inherit' });
const binaryen = execFileSync('wasm-opt', ['--version'], { encoding: 'utf8' });
assert.match(binaryen, /version 133\b/, 'Install the Binaryen version pinned in mise.toml');

// Patch a verified release archive, never the shared Cargo registry source.
const archive = join(root, '.cache/zxcvbn-3.1.1.crate');
mkdirSync(dirname(archive), { recursive: true });
if (!existsSync(archive)) {
	const response = await fetch('https://static.crates.io/crates/zxcvbn/zxcvbn-3.1.1.crate');
	assert(response.ok, `zxcvbn download failed: ${response.status}`);
	writeFileSync(archive, Buffer.from(await response.arrayBuffer()));
}
assert.equal(
	createHash('sha256').update(readFileSync(archive)).digest('hex'),
	'f9eaee90f4a795d1eb4ba6c51e1c1721d4784d550e8efa7b2600f29c867365e0',
);
const vendor = join(root, 'vendor/zxcvbn');
rmSync(vendor, { recursive: true, force: true });
mkdirSync(vendor, { recursive: true });
run('tar', ['-xf', archive, '-C', vendor, '--strip-components=1']);
run('patch', ['--batch', '-d', vendor, '-p1', '-i', join(root, 'zxcvbn-wasi.patch')]);
run('cargo', ['build', ...cargoArgs, '--target', 'wasm32-wasip2', '--target-dir', target, '--release']);

const component = readFileSync(join(target, 'wasm32-wasip2/release/vw_password_strength.wasm'));
const { files } = await transpile(component, {
	name: 'password-strength',
	instantiation: 'sync',
	base64Cutoff: 0,
});
rmSync(generated, { recursive: true, force: true });
mkdirSync(generated, { recursive: true });
let shippedBytes = 0;
for (const [name, bytes] of Object.entries(files)) {
	const path = join(generated, name);
	mkdirSync(dirname(path), { recursive: true });
	writeFileSync(path, bytes);
	if (!name.endsWith('.wasm')) continue;
	const optimized = `${path}.optimized`;
	run('wasm-opt', [
		path,
		'-Oz',
		'--converge',
		'--enable-bulk-memory',
		'--enable-reference-types',
		'--strip-debug',
		'--strip-producers',
		'-o',
		optimized,
	]);
	const wasm = readFileSync(optimized);
	const before = new WebAssembly.Module(new Uint8Array(bytes));
	const after = new WebAssembly.Module(wasm);
	const exports = (module: WebAssembly.Module) =>
		WebAssembly.Module.exports(module)
			.sort((a, b) => a.name.localeCompare(b.name));
	assert.deepEqual(exports(after), exports(before), 'wasm-opt must preserve the Jco export contract');
	const imports = WebAssembly.Module.imports(before).map(value => JSON.stringify(value));
	assert(
		WebAssembly.Module.imports(after).every(value => imports.includes(JSON.stringify(value))),
		'No new host imports',
	);
	const compressed = brotliCompressSync(wasm, { params: { [constants.BROTLI_PARAM_QUALITY]: 11 } });
	writeFileSync(`${path}.br`, compressed);
	shippedBytes += compressed.length;
}
console.log(`Password-strength WASIp2: ${shippedBytes} bytes of compressed core modules.`);

// Include local patched zxcvbn as well as registry crates in the attribution.
const metadata = JSON.parse(execFileSync('cargo', [
	'metadata',
	...cargoArgs,
	'--format-version',
	'1',
	'--filter-platform',
	'wasm32-wasip2',
], { encoding: 'utf8' })) as {
	packages: { name: string; version: string; source: string | null; license: string; manifest_path: string }[];
};
const notices = new Map<string, string[]>();
const addNotice = (owner: string, license: string) => {
	const owners = notices.get(license) ?? [];
	owners.push(owner);
	notices.set(license, owners);
};
for (
	const pkg of metadata.packages.filter(pkg => pkg.source || pkg.name === 'zxcvbn')
		.sort((a, b) => a.name.localeCompare(b.name))
) {
	const directory = dirname(pkg.manifest_path);
	const licenses = readdirSync(directory).filter(name =>
		/^(licen[cs]e|copying|copyright|unlicense)([._-]|$)/i.test(name) && statSync(join(directory, name)).isFile()
	).sort();
	if (!licenses.length) throw new Error(`Missing license text for ${pkg.name}@${pkg.version}`);
	for (const name of licenses) {
		addNotice(`${pkg.name} ${pkg.version} (${pkg.license})`, readFileSync(join(directory, name), 'utf8').trim());
	}
}
// Jco's actual binding generator includes the license for its generated glue.
const jcoRequire = createRequire(import.meta.resolve('@bytecodealliance/jco'));
const bindgenRoot = resolve(dirname(jcoRequire.resolve('@bytecodealliance/jco-transpile')), '..');
const bindgen = JSON.parse(readFileSync(join(bindgenRoot, 'package.json'), 'utf8')) as {
	name: string;
	version: string;
	license: string;
};
addNotice(
	`${bindgen.name} ${bindgen.version} (${bindgen.license}) - generated JavaScript bindings`,
	readFileSync(join(bindgenRoot, 'LICENSE'), 'utf8').trim(),
);
writeFileSync(
	join(root, 'THIRD_PARTY_NOTICES.txt'),
	[...notices].map(([license, owners]) => `${owners.join('\n')}\n\n${license}`).join('\n\n') + '\n',
);
