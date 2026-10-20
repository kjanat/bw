import { createHash, createHmac } from 'node:crypto';
import { passphraseWords } from '#wordlist';

/** Public-key fingerprints use HKDF-expand directly and a big-endian integer rendered least-significant word first. */
export function fingerprintWords(identity: string, publicKey: Uint8Array): string[] {
	if (!identity || !(publicKey instanceof Uint8Array) || !publicKey.length) {
		throw new Error('A fingerprint identity and public key are required.');
	}
	const hash = createHash('sha256').update(publicKey).digest();
	const expanded = createHmac('sha256', hash).update(identity, 'utf8').update(Buffer.from([1])).digest();
	let value = BigInt(`0x${expanded.toString('hex')}`);
	const radix = BigInt(passphraseWords.length);
	return Array.from({ length: 5 }, () => {
		const word = passphraseWords[Number(value % radix)]!;
		value /= radix;
		return word;
	});
}
