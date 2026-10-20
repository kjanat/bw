import { createHash, timingSafeEqual } from 'node:crypto';
import { decrypt, encrypt } from '#crypto';
import { object, type JsonObject } from '#client';

const sections: Record<string, string[]> = {
	login: ['username', 'password', 'totp'],
	card: ['cardholderName', 'brand', 'number', 'expMonth', 'expYear', 'code'],
	identity: [
		'title',
		'firstName',
		'middleName',
		'lastName',
		'address1',
		'address2',
		'address3',
		'city',
		'state',
		'postalCode',
		'country',
		'company',
		'email',
		'phone',
		'ssn',
		'username',
		'passportNumber',
		'licenseNumber',
	],
	sshKey: ['privateKey', 'publicKey', 'keyFingerprint'],
};
/** One field map serves both directions so writes cannot accidentally leave known secrets in plaintext. */
export function transformItem(input: JsonObject, key: Uint8Array, direction: 'encrypt' | 'decrypt'): JsonObject {
	const item = structuredClone(input);
	if (typeof item.type === 'number' && ![1, 2, 3, 4, 5].includes(item.type)) throw new Error('Unsupported item type.');
	const transform = (target: JsonObject, names: string[]) => {
		for (const name of names) {
			const value = target[name];
			if (value == null) continue;
			if (typeof value !== 'string') throw new Error('Encrypted item fields must be strings or null.');
			target[name] = direction === 'encrypt'
				? encrypt(Buffer.from(value, 'utf8'), key)
				: decrypt(value, key).toString('utf8');
		}
	};
	transform(item, ['name', 'notes']);
	for (const [section, names] of Object.entries(sections)) {
		if (item[section] != null) transform(object(item[section]), names);
	}
	if (item.login != null) {
		const login = object(item.login);
		if (Array.isArray(login.uris)) { for (const uri of login.uris) transform(object(uri), ['uri', 'uriChecksum']); }
		// Passkeys contain encrypted strings alongside public metadata.
		if (Array.isArray(login.fido2Credentials)) {
			for (const credential of login.fido2Credentials) {
				transform(object(credential), [
					'credentialId',
					'keyType',
					'keyAlgorithm',
					'keyCurve',
					'keyValue',
					'rpId',
					'userHandle',
					'userName',
					'counter',
					'rpName',
					'userDisplayName',
					'discoverable',
				]);
			}
		}
	}
	if (Array.isArray(item.fields)) { for (const custom of item.fields) transform(object(custom), ['name', 'value']); }
	if (Array.isArray(item.passwordHistory)) {
		for (const previous of item.passwordHistory) transform(object(previous), ['password']);
	}
	if (Array.isArray(item.attachments)) {
		for (const attachment of item.attachments) transform(object(attachment), ['fileName']);
	}
	return item;
}

/** Generate a fresh checksum for every URI before encryption, including when an edit changed its value. */
export function encryptItem(input: JsonObject, key: Uint8Array): JsonObject {
	const item = structuredClone(input);
	if (item.login != null) {
		const login = object(item.login);
		if (Array.isArray(login.uris)) {
			for (const value of login.uris) {
				const uri = object(value);
				if (typeof uri.uri === 'string') {
					uri.uriChecksum = createHash('sha256').update(uri.uri, 'utf8').digest('base64');
				} else if (uri.uri == null) delete uri.uriChecksum;
			}
		}
	}
	return transformItem(item, key, 'encrypt');
}
export function validUriChecksum(uri: JsonObject): boolean {
	if (
		typeof uri.uri !== 'string' || typeof uri.uriChecksum !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(uri.uriChecksum)
	) return false;
	const checksum = Buffer.from(uri.uriChecksum, 'base64');
	if (checksum.length !== 32 || checksum.toString('base64') !== uri.uriChecksum) return false;
	return timingSafeEqual(checksum, createHash('sha256').update(uri.uri, 'utf8').digest());
}
