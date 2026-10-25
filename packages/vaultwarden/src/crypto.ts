import {
	createCipheriv,
	createDecipheriv,
	createHash,
	createHmac,
	pbkdf2,
	randomBytes,
	timingSafeEqual,
} from 'node:crypto';
import { promisify } from 'node:util';
import { deriveArgon2Key } from '#argon2';
import {
	generateKeyPair,
	importPkcs8DerOrThrow,
	importSpkiDerOrThrow,
	decryptRsaOaepOrThrow,
	encryptRsaOaepOrThrow,
} from 'micro509/keys';

const derive = promisify(pbkdf2);
export type Kdf =
	| { type: 0; iterations: number }
	| {
		type: 1;
		iterations: number;
		memory: number;
		parallelism: number;
	};

export function normalizeEmail(email: string): string {
	return email.trim().toLowerCase();
}
function integer(value: number, min: number, max: number): void {
	if (!Number.isSafeInteger(value) || value < min || value > max) {
		throw new Error('Unsupported KDF parameters.');
	}
}
/** Account salts are normalized email addresses; export salts are passed verbatim. */
export async function deriveMasterKey(password: string, email: string, kdf: Kdf): Promise<Buffer> {
	return deriveKdfKey(password, normalizeEmail(email), kdf);
}
/** Limits bound work requested by an unauthenticated server or imported file. */
export async function deriveKdfKey(password: string, salt: string, kdf: Kdf): Promise<Buffer> {
	if (kdf.type === 0) {
		integer(kdf.iterations, 1, 10_000_000);
		return derive(password, salt, kdf.iterations, 32, 'sha256');
	}
	if (kdf.type !== 1) throw new Error('Unsupported KDF type.');
	integer(kdf.iterations, 1, 20);
	integer(kdf.memory, 8, 256);
	integer(kdf.parallelism, 1, 16);
	return Buffer.from(
		await deriveArgon2Key({
			algorithm: 'argon2id',
			version: 0x13,
			password: Buffer.from(password),
			salt: createHash('sha256').update(salt).digest(),
			passes: kdf.iterations,
			memoryKiB: kdf.memory * 1024,
			parallelism: kdf.parallelism,
			outputBytes: 32,
		}),
	);
}
export async function masterPasswordHash(
	masterKey: Uint8Array,
	password: string,
): Promise<string> {
	return (await derive(masterKey, password, 1, 32, 'sha256')).toString(
		'base64',
	);
}
/** Bitwarden uses HKDF-expand directly, without an extract stage. */
export function stretchKey(masterKey: Uint8Array): Buffer {
	if (masterKey.length !== 32) {
		throw new Error('Expected a 256-bit master key.');
	}
	return Buffer.concat(
		['enc', 'mac'].map((info) =>
			createHmac('sha256', masterKey)
				.update(info)
				.update(Buffer.from([1]))
				.digest()
		),
	);
}
function b64(value: string): Buffer {
	if (
		!value
		|| !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
			value,
		)
	) {
		throw new Error('Invalid encrypted value encoding.');
	}
	return Buffer.from(value, 'base64');
}
/** Authenticated AES-256-CBC (EncString type 2). Verify the MAC before decrypting. */
export function decrypt(value: string, key: Uint8Array): Buffer {
	if (key.length !== 64) throw new Error('Expected a 512-bit vault key.');
	const parts = /^2\.([^|]+)\|([^|]+)\|([^|]+)$/.exec(value);
	if (!parts) {
		throw new Error('Unsupported encrypted value; expected EncString type 2.');
	}
	const iv = b64(parts[1]!);
	const ciphertext = b64(parts[2]!);
	const mac = b64(parts[3]!);
	if (iv.length !== 16 || mac.length !== 32 || ciphertext.length % 16 !== 0) {
		throw new Error('Invalid encrypted value.');
	}
	const expected = createHmac('sha256', key.subarray(32))
		.update(iv)
		.update(ciphertext)
		.digest();
	if (!timingSafeEqual(mac, expected)) {
		throw new Error('Encrypted value authentication failed.');
	}
	const cipher = createDecipheriv('aes-256-cbc', key.subarray(0, 32), iv);
	return Buffer.concat([cipher.update(ciphertext), cipher.final()]);
}
export function encrypt(value: Uint8Array, key: Uint8Array): string {
	if (key.length !== 64) throw new Error('Expected a 512-bit vault key.');
	const iv = randomBytes(16);
	const cipher = createCipheriv('aes-256-cbc', key.subarray(0, 32), iv);
	const ciphertext = Buffer.concat([cipher.update(value), cipher.final()]);
	const mac = createHmac('sha256', key.subarray(32))
		.update(iv)
		.update(ciphertext)
		.digest();
	return `2.${iv.toString('base64')}|${ciphertext.toString('base64')}|${mac.toString('base64')}`;
}

/** Create the locally generated material needed to initialize a new account. */
export async function createAccountKeyMaterial(password: string, email: string, kdf: Kdf): Promise<{
	userKey: Buffer;
	encryptedUserKey: string;
	masterPasswordHash: string;
	publicKey: string;
	encryptedPrivateKey: string;
}> {
	const pair = await generateKeyPair({ kind: 'rsa', modulusLength: 2048, scheme: 'oaep', hash: 'SHA-256' });
	const publicKey = Buffer.from(await pair.exportSpkiDer());
	const privateKey = await pair.exportPkcs8Der();
	const userKey = randomBytes(64);
	let master: Buffer | undefined;
	try {
		master = await deriveMasterKey(password, email, kdf);
		const stretched = stretchKey(master);
		try {
			return {
				userKey,
				encryptedUserKey: encrypt(userKey, stretched),
				masterPasswordHash: await masterPasswordHash(master, password),
				publicKey: publicKey.toString('base64'),
				encryptedPrivateKey: encrypt(privateKey, userKey),
			};
		} finally {
			stretched.fill(0);
		}
	} catch (error) {
		userKey.fill(0);
		throw error;
	} finally {
		master?.fill(0);
		privateKey.fill(0);
	}
}

/** Vaultwarden organization keys use RSA OAEP EncString types 3 (SHA256) or 4 (SHA1). */
export async function decryptSharedKey(value: string, privateKey: Uint8Array): Promise<Buffer> {
	const match = /^([34])\.([A-Za-z0-9+/]+={0,2})$/.exec(value);
	if (!match) throw new Error('Unsupported organization key envelope.');
	try {
		const material = await importPkcs8DerOrThrow(privateKey, {
			kind: 'rsa',
			scheme: 'oaep',
			hash: match[1] === '3' ? 'SHA-256' : 'SHA-1',
		});
		const decrypted = await decryptRsaOaepOrThrow(material, b64(match[2]!));
		return Buffer.from(decrypted.buffer, decrypted.byteOffset, decrypted.byteLength);
	} catch {
		throw new Error('Organization key authentication failed.');
	}
}

/** Wrap an organization key for a member without exposing it to the server. */
export async function encryptSharedKey(key: Uint8Array, publicKey: string): Promise<string> {
	if (key.length !== 64) throw new Error('Expected a 512-bit organization key.');
	try {
		const material = await importSpkiDerOrThrow(b64(publicKey), { kind: 'rsa', scheme: 'oaep', hash: 'SHA-256' });
		return `3.${Buffer.from(await encryptRsaOaepOrThrow(material, key)).toString('base64')}`;
	} catch {
		throw new Error('Invalid member public key.');
	}
}

/** Bitwarden binary attachments: type byte, 16-byte IV, 32-byte MAC, then ciphertext. */
export function encryptAttachment(value: Uint8Array, key: Uint8Array): Buffer {
	const parts = encrypt(value, key).slice(2).split('|');
	return Buffer.concat([
		Buffer.from([2]),
		Buffer.from(parts[0]!, 'base64'),
		Buffer.from(parts[2]!, 'base64'),
		Buffer.from(parts[1]!, 'base64'),
	]);
}
/** Type-2 attachment wire size, including its type byte, IV, MAC, and PKCS#7 padding. */
export function encryptedAttachmentSize(plaintextSize: number): number {
	if (!Number.isSafeInteger(plaintextSize) || plaintextSize < 0) throw new Error('Invalid attachment size.');
	return 49 + (Math.floor(plaintextSize / 16) + 1) * 16;
}
export function decryptAttachment(value: Uint8Array, key: Uint8Array): Buffer {
	if (value.length < 65 || value[0] !== 2 || (value.length - 49) % 16 !== 0) {
		throw new Error('Unsupported or malformed attachment encryption.');
	}
	const bytes = Buffer.from(value.buffer, value.byteOffset, value.byteLength);
	return decrypt(
		`2.${bytes.subarray(1, 17).toString('base64')}|${bytes.subarray(49).toString('base64')}|${
			bytes.subarray(17, 49).toString('base64')
		}`,
		key,
	);
}
