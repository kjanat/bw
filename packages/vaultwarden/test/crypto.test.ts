import { expect, test } from 'bun:test';
import { decrypt, deriveMasterKey, encrypt, stretchKey, encryptAttachment, decryptAttachment } from '#crypto';
import { decryptItem, personalItems } from '#vault';

// Independent known-answer vectors from bitwarden/sdk-internal at 4ea5e6f.
test('PBKDF2 matches the Bitwarden SDK vector and normalizes the email', async () => {
	const key = await deriveMasterKey('67t9b5g67$%Dh89n', '  TEST_KEY ', {
		type: 0,
		iterations: 10000,
	});
	expect([...key]).toEqual(
		/* dprint-ignore */ [31,79,104,226,150,71,177,90,194,80,172,209,17,129,132,81,138,167,69,167,254,149,2,27,39,197,64,42,22,195,86,75],
	);
});
test('Argon2id matches the Bitwarden SDK vector (MiB conversion and hashed salt)', async () => {
	const key = await deriveMasterKey('67t9b5g67$%Dh89n', 'test_key', {
		type: 1,
		iterations: 4,
		memory: 32,
		parallelism: 2,
	});
	expect([...key]).toEqual(
		/* dprint-ignore */ [207,240,225,177,162,19,163,76,98,106,179,175,224,9,17,240,20,147,237,47,246,150,141,184,62,225,131,242,51,53,225,242],
	);
});
test('rejects excessive or malformed server KDF work', async () => {
	await expect(
		deriveMasterKey('x', 'x', { type: 0, iterations: Infinity }),
	).rejects.toThrow('KDF');
	await expect(
		deriveMasterKey('x', 'x', {
			type: 1,
			iterations: 3,
			memory: 1024,
			parallelism: 2,
		}),
	).rejects.toThrow('KDF');
});
test('authenticates encrypted data and rejects tampering, wrong keys, and downgrade', () => {
	const key = stretchKey(Buffer.alloc(32, 7));
	const encrypted = encrypt(Buffer.from('secret ✓'), key);
	expect(decrypt(encrypted, key).toString()).toBe('secret ✓');
	expect(() => decrypt(encrypted, Buffer.alloc(64, 8))).toThrow(
		'authentication',
	);
	const parts = encrypted.split('|');
	parts[1] = Buffer.alloc(16).toString('base64');
	expect(() => decrypt(parts.join('|'), key)).toThrow('authentication');
	expect(() => decrypt(encrypted.replace(/^2\./, '0.'), key)).toThrow(
		'Unsupported',
	);
});
test('decrypts personal items with a per-item key without mutating wire data', () => {
	const user = Buffer.alloc(64, 1);
	const item = Buffer.alloc(64, 2);
	const enc = (value: string) => encrypt(Buffer.from(value), item);
	const input = {
		id: 'id',
		key: encrypt(item, user),
		name: enc('Example'),
		notes: null,
		login: {
			username: enc('person'),
			password: enc('secret'),
			uris: [{ uri: enc('https://example.com'), match: 0 }],
		},
		fields: [{ name: enc('field'), value: enc('value'), type: 0 }],
	};
	const result = decryptItem(input, user);
	expect(result.name).toBe('Example');
	expect(result.key).toBeUndefined();
	expect((result.login as { password: string }).password).toBe('secret');
	expect(input.name).not.toBe('Example');
	expect(user.equals(Buffer.alloc(64, 1))).toBe(true);
});
test('reports excluded organization items and omits deleted items', () => {
	const user = Buffer.alloc(64, 1);
	expect(
		personalItems(
			{ ciphers: [{ organizationId: 'org' }, { deletedDate: 'date' }] },
			user,
		),
	).toEqual({
		items: [],
		excludedOrganizationItems: 1,
	});
	expect(() => decryptItem({ organizationId: 'org' }, user)).toThrow(
		'Organization',
	);
});

test('binary attachment encryption authenticates content and exact byte layout', () => {
	const key = Buffer.alloc(64, 4);
	const value = Buffer.from([0, 255, 128, 0, 17]);
	const encrypted = encryptAttachment(value, key);
	expect(encrypted[0]).toBe(2);
	expect(decryptAttachment(encrypted, key)).toEqual(value);
	const asText = `2.${encrypted.subarray(1, 17).toString('base64')}|${encrypted.subarray(49).toString('base64')}|${
		encrypted.subarray(17, 49).toString('base64')
	}`;
	expect(decrypt(asText, key)).toEqual(value);
	encrypted[encrypted.length - 1] = encrypted[encrypted.length - 1]! ^ 1;
	expect(() => decryptAttachment(encrypted, key)).toThrow('authentication');
	expect(() => decryptAttachment(Buffer.alloc(48), key)).toThrow('malformed');
});
