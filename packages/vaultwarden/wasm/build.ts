import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { brotliCompressSync, constants } from 'node:zlib';

const root = dirname(fileURLToPath(import.meta.url));
const generated = resolve(root, '../src/generated');
const target = join(root, 'target');
const cargoArgs = ['--manifest-path', join(root, 'Cargo.toml'), '--locked'];

execFileSync('cargo', [
	'build',
	...cargoArgs,
	'--target',
	'wasm32-unknown-unknown',
	'--target-dir',
	target,
	'--release',
], {
	stdio: 'inherit',
});
mkdirSync(generated, { recursive: true });
execFileSync('wasm-bindgen', [
	join(target, 'wasm32-unknown-unknown/release/vw_password_strength.wasm'),
	'--target',
	'web',
	'--out-dir',
	generated,
	'--out-name',
	'password-strength',
], { stdio: 'inherit' });

const wasm = readFileSync(join(generated, 'password-strength_bg.wasm'));
const compressed = brotliCompressSync(wasm, { params: { [constants.BROTLI_PARAM_QUALITY]: 11 } });
writeFileSync(resolve(root, '../src/password-strength.wasm.br'), compressed);
console.log(`Password strength WASM: ${wasm.length} bytes; shipped: ${compressed.length} bytes (Brotli).`);

// Ship the license texts of the locked Rust dependencies alongside the binary.
const metadata = JSON.parse(execFileSync('cargo', [
	'metadata',
	...cargoArgs,
	'--format-version',
	'1',
	'--filter-platform',
	'wasm32-unknown-unknown',
], { encoding: 'utf8' })) as {
	packages: { name: string; version: string; source: string | null; license: string; manifest_path: string }[];
};
const notices = new Map<string, string[]>();
for (const pkg of metadata.packages.filter(pkg => pkg.source).sort((a, b) => a.name.localeCompare(b.name))) {
	const directory = dirname(pkg.manifest_path);
	const licenses = readdirSync(directory).filter(name =>
		/^(licen[cs]e|copying|copyright|unlicense)([._-]|$)/i.test(name)
	).sort();
	if (!licenses.length) throw new Error(`Missing license text for ${pkg.name}@${pkg.version}`);
	for (const name of licenses) {
		const license = readFileSync(join(directory, name), 'utf8').trim();
		const owners = notices.get(license) ?? [];
		owners.push(`${pkg.name} ${pkg.version} (${pkg.license})`);
		notices.set(license, owners);
	}
}
writeFileSync(
	join(root, 'THIRD_PARTY_NOTICES.txt'),
	[...notices].map(([license, owners]) => `${owners.join('\n')}\n\n${license}`).join('\n\n') + '\n',
);
