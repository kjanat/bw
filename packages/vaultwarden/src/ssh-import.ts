import { createPrivateKey, createHash, randomBytes } from 'node:crypto';
import type { JsonObject } from '#client';

export class SshImportError extends Error {
	constructor(readonly reason: 'unsupportedType' | 'sshKeyParseFailed') {
		super('Could not import SSH key.');
	}
}
const uint = (n: number): Buffer => {
	const out = Buffer.alloc(4);
	out.writeUInt32BE(n);
	return out;
};
const string = (value: string | Uint8Array): Buffer => {
	const bytes = Buffer.from(value);
	return Buffer.concat([uint(bytes.length), bytes]);
};
function mpint(value: Buffer): Buffer {
	let offset = 0;
	while (offset < value.length && value[offset] === 0) offset++;
	const bytes = value.subarray(offset);
	return string(bytes[0]! & 128 ? Buffer.concat([Buffer.from([0]), bytes]) : bytes);
}
/** Convert unencrypted PKCS#8 keys from 1PUX metadata into OpenSSH vault fields. */
export function importSshPkcs8(pem: string): JsonObject {
	if (!pem.includes('-----BEGIN PRIVATE KEY-----')) throw new SshImportError('sshKeyParseFailed');
	const buffers: Buffer[] = [];
	try {
		const key = createPrivateKey(pem), jwk = key.export({ format: 'jwk' });
		const part = (name: 'n' | 'e' | 'd' | 'qi' | 'p' | 'q' | 'x' | 'y'): Buffer => {
			const value = jwk[name];
			if (typeof value !== 'string') throw new SshImportError('sshKeyParseFailed');
			const bytes = Buffer.from(value, 'base64url');
			buffers.push(bytes);
			return bytes;
		};
		let algorithm: string, publicData: Buffer, privateData: Buffer;
		if (key.asymmetricKeyType === 'rsa') {
			algorithm = 'ssh-rsa';
			publicData = Buffer.concat([string(algorithm), mpint(part('e')), mpint(part('n'))]);
			privateData = Buffer.concat([
				string(algorithm),
				...(['n', 'e', 'd', 'qi', 'p', 'q'] as const).map(name => mpint(part(name))),
			]);
		} else if (key.asymmetricKeyType === 'ed25519') {
			algorithm = 'ssh-ed25519';
			const publicKey = part('x'), secret = Buffer.concat([part('d'), publicKey]);
			buffers.push(secret);
			publicData = Buffer.concat([string(algorithm), string(publicKey)]);
			privateData = Buffer.concat([publicData, string(secret)]);
		} else if (key.asymmetricKeyType === 'ec') {
			const curve = ({ 'P-256': 'nistp256', 'P-384': 'nistp384', 'P-521': 'nistp521' } as Record<string, string>)[
				jwk.crv ?? ''
			];
			if (!curve) throw new SshImportError('unsupportedType');
			algorithm = `ecdsa-sha2-${curve}`;
			publicData = Buffer.concat([
				string(algorithm),
				string(curve),
				string(Buffer.concat([Buffer.from([4]), part('x'), part('y')])),
			]);
			privateData = Buffer.concat([publicData, mpint(part('d'))]);
		} else throw new SshImportError('unsupportedType');
		buffers.push(privateData);
		const check = randomBytes(4), body = Buffer.concat([check, check, privateData, string('')]);
		buffers.push(body);
		const padding = Buffer.from(Array.from({ length: 8 - body.length % 8 }, (_, i) => i + 1));
		const encoded = Buffer.concat([
			Buffer.from('openssh-key-v1\0'),
			string('none'),
			string('none'),
			string(''),
			uint(1),
			string(publicData),
			string(Buffer.concat([body, padding])),
		]);
		buffers.push(encoded);
		const lines = encoded.toString('base64').match(/.{1,70}/g)!.join('\n');
		return {
			privateKey: `-----BEGIN OPENSSH PRIVATE KEY-----\n${lines}\n-----END OPENSSH PRIVATE KEY-----\n`,
			publicKey: `${algorithm} ${publicData.toString('base64')}`,
			keyFingerprint: `SHA256:${createHash('sha256').update(publicData).digest('base64').replace(/=+$/, '')}`,
		};
	} catch (error) {
		throw error instanceof SshImportError ? error : new SshImportError('sshKeyParseFailed');
	} finally {
		for (const bytes of buffers) bytes.fill(0);
	}
}
