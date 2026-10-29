import { readFileSync } from 'node:fs';
import { brotliDecompressSync } from 'node:zlib';

type IntegerArray = Uint8Array | Uint16Array | Uint32Array;

/** Decode build-generated unsigned LEB128 tables without changing upstream lookup algorithms. */
export function readBinaryTable(url: URL, expectedBytes: number) {
	const bytes = brotliDecompressSync(readFileSync(url), { maxOutputLength: expectedBytes });
	if (bytes.length !== expectedBytes) throw new Error('Invalid lookup table length.');
	let offset = 0;
	const integer = (): number => {
		let value = 0;
		for (let shift = 0; shift <= 28; shift += 7) {
			const byte = bytes[offset++];
			if (byte === undefined || (shift === 28 && byte > 15)) throw new Error('Invalid lookup table integer.');
			value |= (byte & 127) << shift;
			if (!(byte & 128)) return value >>> 0;
		}
		throw new Error('Invalid lookup table integer.');
	};
	return {
		integer,
		array<T extends IntegerArray>(Constructor: { new(length: number): T }): T {
			const length = integer();
			if (length > bytes.length - offset) throw new Error('Invalid lookup table array.');
			const result = new Constructor(length);
			for (let index = 0; index < length; index++) result[index] = integer();
			return result;
		},
		text(): string {
			const length = integer();
			if (length > bytes.length - offset) throw new Error('Invalid lookup table string.');
			const result = bytes.toString('utf8', offset, offset + length);
			offset += length;
			return result;
		},
		finish(): void {
			if (offset !== bytes.length) throw new Error('Unexpected lookup table data.');
		},
	};
}
