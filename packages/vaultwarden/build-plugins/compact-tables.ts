import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { brotliCompressSync, constants } from 'node:zlib';
import type { Rolldown } from 'tsdown';

type TableValue = number | string | Uint8Array | Uint16Array | Uint32Array;

export function encodeTable(exports: Record<string, TableValue>) {
	const bytes: number[] = [];
	const declarations: string[] = [];
	const integer = (value: number) => {
		assert(Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff, 'Expected an unsigned 32-bit value');
		while (value > 127) {
			bytes.push((value & 127) | 128);
			value >>>= 7;
		}
		bytes.push(value);
	};
	for (const [name, value] of Object.entries(exports)) {
		assert(/^[A-Za-z_$][\w$]*$/.test(name), `Unsupported table export: ${name}`);
		if (typeof value === 'number') {
			integer(value);
			declarations.push(`${name}:table.integer(),`);
		} else if (typeof value === 'string') {
			const text = Buffer.from(value, 'utf8');
			integer(text.length);
			for (const byte of text) bytes.push(byte);
			declarations.push(`${name}:table.text(),`);
		} else {
			assert(value instanceof Uint8Array || value instanceof Uint16Array || value instanceof Uint32Array);
			integer(value.length);
			for (const element of value) integer(element);
			declarations.push(`${name}:table.array(${value.constructor.name}),`);
		}
	}
	return { bytes: Buffer.from(bytes), declarations: declarations.join('\n') };
}

/** Replace only immutable data; upstream parser and suffix-lookup code are bundled unchanged. */
export function compactTables(): Rolldown.Plugin {
	const found = new Set<string>();
	return {
		name: 'vw-compact-tables',
		buildStart() {
			found.clear();
		},
		async load(id) {
			const path = id.replaceAll('\\', '/');
			const name = path.endsWith('/tldts/dist/es6/src/data/trie.js')
				? 'public-suffixes'
				: path.endsWith('/entities/dist/generated/decode-data-html.js')
				? 'html-entities'
				: undefined;
			if (!name) return;
			const source = await import(pathToFileURL(id).href) as Record<string, TableValue>;
			const encoded = encodeTable(source);
			const reference = this.emitFile({
				type: 'asset',
				fileName: `generated/${name}.bin.br`,
				source: brotliCompressSync(encoded.bytes, { params: { [constants.BROTLI_PARAM_QUALITY]: 11 } }),
			});
			found.add(name);
			const decoder = fileURLToPath(new URL('../src/binary-table.ts', import.meta.url));
			return {
				code: `import {readBinaryTable} from ${JSON.stringify(decoder)};\n`
					+ `const data=/* @__PURE__ */(()=>{const table=readBinaryTable(new URL(import.meta.ROLLUP_FILE_URL_${reference}),${encoded.bytes.length});\n`
					+ `const result={${encoded.declarations}};table.finish();return result;})();\n`
					+ Object.keys(source).map(name => `export const ${name}=data.${name};`).join('\n'),
				moduleSideEffects: false,
			};
		},
		async generateBundle() {
			assert.deepEqual(
				[...found].sort(),
				['html-entities', 'public-suffixes'],
				'Upstream table layout changed; review compression integration',
			);
			const require = createRequire(new URL('../package.json', import.meta.url));
			const parse5Require = createRequire(require.resolve('parse5'));
			const tldtsRequire = createRequire(require.resolve('tldts'));
			const roots = [
				['parse5', dirname(dirname(require.resolve('parse5')))],
				['entities', dirname(dirname(parse5Require.resolve('entities/decode')))],
				['tldts', dirname(dirname(dirname(require.resolve('tldts'))))],
				['tldts-core', dirname(dirname(dirname(tldtsRequire.resolve('tldts-core'))))],
			];
			const notices = await Promise.all(roots.map(async ([name, root]) => {
				const manifest = JSON.parse(await readFile(join(root!, 'package.json'), 'utf8'));
				assert.equal(manifest.name, name);
				return `${manifest.name} ${manifest.version}\n\n${await readFile(join(root!, 'LICENSE'), 'utf8')}`;
			}));
			this.emitFile({ type: 'asset', fileName: 'THIRD_PARTY_JAVASCRIPT_LICENSES.txt', source: notices.join('\n\n') });
		},
	};
}
