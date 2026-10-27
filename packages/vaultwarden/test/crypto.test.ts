import { expect, test } from 'bun:test';
import {
	decrypt,
	deriveMasterKey,
	encrypt,
	stretchKey,
	encryptAttachment,
	encryptedAttachmentSize,
	decryptAttachment,
} from '#crypto';
import { decryptItem, personalItems } from '#vault';
import { createAccountKeyMaterial, decryptSharedKey, encryptApprovedUserKey, encryptSharedKey } from '#crypto';
import { constants, createPrivateKey, createPublicKey, privateDecrypt, publicEncrypt } from 'node:crypto';

test('micro509 account keys interoperate with Node RSA-OAEP SHA-256 and legacy SHA-1', async () => {
	const material = await createAccountKeyMaterial('fixture-password', 'fixture@example.com', {
		type: 0,
		iterations: 1,
	});
	const privateDer = decrypt(material.encryptedPrivateKey, material.userKey);
	try {
		const privateKey = createPrivateKey({ key: privateDer, format: 'der', type: 'pkcs8' });
		const publicKey = createPublicKey({ key: Buffer.from(material.publicKey, 'base64'), format: 'der', type: 'spki' });
		expect(publicKey.asymmetricKeyDetails?.modulusLength).toBe(2048);
		expect(createPublicKey(privateKey).export({ format: 'der', type: 'spki' })).toEqual(
			Buffer.from(material.publicKey, 'base64'),
		);
		const sharedKey = Buffer.alloc(64, 42);
		for (const [type, oaepHash] of [[3, 'sha256'], [4, 'sha1']] as const) {
			const encrypted = publicEncrypt(
				{ key: publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash },
				sharedKey,
			);
			expect(await decryptSharedKey(`${type}.${encrypted.toString('base64')}`, privateDer)).toEqual(sharedKey);
			await expect(decryptSharedKey(`${type === 3 ? 4 : 3}.${encrypted.toString('base64')}`, privateDer))
				.rejects.toThrow('Organization key authentication failed.');
			encrypted[0] = encrypted[0]! ^ 1;
			await expect(decryptSharedKey(`${type}.${encrypted.toString('base64')}`, privateDer))
				.rejects.toThrow('Organization key authentication failed.');
		}
		const wrapped = await encryptSharedKey(sharedKey, material.publicKey);
		expect(wrapped.startsWith('3.')).toBe(true);
		expect(
			privateDecrypt(
				{ key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
				Buffer.from(wrapped.slice(2), 'base64'),
			),
		).toEqual(sharedKey);
		await expect(decryptSharedKey(wrapped, new Uint8Array([1, 2, 3])))
			.rejects.toThrow('Organization key authentication failed.');
		await expect(decryptSharedKey('2.invalid', privateDer)).rejects.toThrow('Unsupported organization key envelope.');
		await expect(decryptSharedKey('3.A===', privateDer)).rejects.toThrow('Unsupported organization key envelope.');
		await expect(encryptSharedKey(sharedKey, 'invalid')).rejects.toThrow('Invalid member public key.');
		await expect(encryptSharedKey(new Uint8Array(32), material.publicKey))
			.rejects.toThrow('Expected a 512-bit organization key.');
	} finally {
		privateDer.fill(0);
		material.userKey.fill(0);
	}
});

test('device approval moves a recovery-wrapped user key to the requesting device key', async () => {
	const organization = await createAccountKeyMaterial('organization-password', 'org@example.test', {
		type: 0,
		iterations: 1,
	});
	const device = await createAccountKeyMaterial('device-password', 'device@example.test', {
		type: 0,
		iterations: 1,
	});
	const organizationKey = Buffer.alloc(64, 31);
	const recoveredUserKey = Buffer.alloc(64, 47);
	const organizationPrivateKey = decrypt(organization.encryptedPrivateKey, organization.userKey);
	const devicePrivateKey = decrypt(device.encryptedPrivateKey, device.userKey);
	try {
		const result = await encryptApprovedUserKey(
			await encryptSharedKey(recoveredUserKey, organization.publicKey),
			encrypt(organizationPrivateKey, organizationKey),
			organizationKey,
			device.publicKey,
		);
		expect(await decryptSharedKey(result, devicePrivateKey)).toEqual(recoveredUserKey);
		await expect(encryptApprovedUserKey(
			await encryptSharedKey(recoveredUserKey, organization.publicKey),
			encrypt(organizationPrivateKey, organizationKey),
			Buffer.alloc(64, 32),
			device.publicKey,
		)).rejects.toThrow('Could not prepare the trusted-device approval key.');
	} finally {
		organizationKey.fill(0);
		recoveredUserKey.fill(0);
		organizationPrivateKey.fill(0);
		devicePrivateKey.fill(0);
		organization.userKey.fill(0);
		device.userKey.fill(0);
	}
});

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
	for (const size of [0, 1, 15, 16, 17, 31, 32]) {
		expect(encryptedAttachmentSize(size)).toBe(encryptAttachment(Buffer.alloc(size), key).length);
	}
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
