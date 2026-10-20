import { createHmac } from 'node:crypto';

function base32(value: string): Buffer {
	const clean = value.toUpperCase().replace(/[\s=-]/g, '');
	if (!clean || !/^[A-Z2-7]+$/.test(clean)) throw new Error('Invalid TOTP secret.');
	let bits = 0;
	let accumulator = 0;
	const result: number[] = [];
	for (const char of clean) {
		accumulator = (accumulator << 5) | 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(char);
		bits += 5;
		if (bits >= 8) {
			bits -= 8;
			result.push((accumulator >>> bits) & 255);
		}
	}
	if (!result.length) throw new Error('Invalid TOTP secret.');
	return Buffer.from(result);
}
/** RFC 6238 with SHA1/SHA256/SHA512, otpauth URIs, and Steam's five-character codes. */
export function totp(input: string, time = Date.now()): string {
	let secret = input;
	let algorithm = 'sha1';
	let digits = 6;
	let period = 30;
	let steam = false;
	if (input.startsWith('steam://')) {
		steam = true;
		secret = input.slice(8);
	} else if (input.startsWith('otpauth://')) {
		let uri: URL;
		try {
			uri = new URL(input);
		} catch {
			throw new Error('Invalid TOTP URI.');
		}
		if (uri.hostname !== 'totp') throw new Error('Expected a TOTP URI.');
		secret = uri.searchParams.get('secret') ?? '';
		algorithm = (uri.searchParams.get('algorithm') ?? 'sha1').toLowerCase();
		digits = Number(uri.searchParams.get('digits') ?? 6);
		period = Number(uri.searchParams.get('period') ?? 30);
		steam = uri.searchParams.get('encoder') === 'steam';
	}
	if (
		!['sha1', 'sha256', 'sha512'].includes(algorithm) || ![6, 7, 8].includes(digits) || !Number.isSafeInteger(period)
		|| period < 1 || period > 86400 || !Number.isSafeInteger(time) || time < 0
	) throw new Error('Unsupported TOTP parameters.');
	const key = base32(secret);
	try {
		const counter = Buffer.alloc(8);
		counter.writeBigUInt64BE(BigInt(Math.floor(time / 1000 / period)));
		const hmac = createHmac(algorithm, key).update(counter).digest();
		const offset = hmac[hmac.length - 1]! & 15;
		let number = hmac.readUInt32BE(offset) & 0x7fffffff;
		if (steam) {
			let code = '';
			const alphabet = '23456789BCDFGHJKMNPQRTVWXY';
			for (let i = 0; i < 5; i++) {
				code += alphabet[number % alphabet.length];
				number = Math.floor(number / alphabet.length);
			}
			return code;
		}
		return String(number % (10 ** digits)).padStart(digits, '0');
	} finally {
		key.fill(0);
	}
}
