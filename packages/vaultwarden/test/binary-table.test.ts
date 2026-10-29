import { expect, test } from 'bun:test';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { brotliCompressSync } from 'node:zlib';
import { encodeTable } from '../build-plugins/compact-tables.ts';
import { readBinaryTable } from '#binary-table';

function withTable(bytes: Uint8Array, check: (table: ReturnType<typeof readBinaryTable>) => void) {
	const directory = mkdtempSync(join(tmpdir(), 'vw-table-'));
	try {
		const path = join(directory, 'table.br');
		writeFileSync(path, brotliCompressSync(bytes));
		check(readBinaryTable(pathToFileURL(path), bytes.length));
	} finally {
		rmSync(directory, { recursive: true, force: true });
	}
}

test('every upstream suffix and HTML entity table value survives packing exactly', async () => {
	const require = createRequire(import.meta.url);
	const parse5Require = createRequire(require.resolve('parse5'));
	const sources = [
		join(dirname(require.resolve('tldts')), '../es6/src/data/trie.js'),
		join(dirname(parse5Require.resolve('entities/decode')), 'generated/decode-data-html.js'),
	];
	for (const source of sources) {
		const original = await import(pathToFileURL(source).href) as Parameters<typeof encodeTable>[0];
		const { bytes } = encodeTable(original);
		withTable(bytes, table => {
			for (const value of Object.values(original)) {
				const decoded = typeof value === 'number'
					? table.integer()
					: typeof value === 'string'
					? table.text()
					: value instanceof Uint8Array
					? table.array(Uint8Array)
					: value instanceof Uint16Array
					? table.array(Uint16Array)
					: table.array(Uint32Array);
				expect<unknown>(decoded).toEqual(value);
			}
			table.finish();
		});
	}
});

test('unsigned integer boundaries, empty arrays and Unicode text round trip', () => {
	const values = new Uint32Array([0, 127, 128, 16383, 16384, 0x7fffffff, 0xffffffff]);
	const { bytes } = encodeTable({ values, empty: new Uint8Array(), text: '例え.🔑', last: 0xffffffff });
	withTable(bytes, table => {
		expect(table.array(Uint32Array)).toEqual(values);
		expect(table.array(Uint8Array)).toEqual(new Uint8Array());
		expect(table.text()).toBe('例え.🔑');
		expect(table.integer()).toBe(0xffffffff);
		table.finish();
	});
});

test('truncated, overflowing and trailing table data is rejected', () => {
	for (const bytes of [[128], [255, 255, 255, 255, 16]]) {
		withTable(Uint8Array.from(bytes), table => expect(() => table.integer()).toThrow('Invalid lookup table integer'));
	}
	withTable(Uint8Array.of(2, 1), table => expect(() => table.array(Uint16Array)).toThrow('Invalid lookup table array'));
	withTable(Uint8Array.of(2, 1), table => expect(() => table.text()).toThrow('Invalid lookup table string'));
	withTable(Uint8Array.of(0), table => expect(() => table.finish()).toThrow('Unexpected lookup table data'));
});
