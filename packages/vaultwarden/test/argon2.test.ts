import { expect, spyOn, test } from 'bun:test';
import { deriveArgon2Key } from '#argon2';

const input = {
	password: Buffer.from('password'),
	salt: Buffer.from('salt1234'),
	memoryKiB: 32,
	passes: 2,
	parallelism: 2,
	outputBytes: 32,
};

// Independently generated with libargon2's argon2_hash, not either JavaScript backend.
for (
	const [version, algorithm, expected] of [
		[0x10, 'argon2d', 'c9da08c31fa64957a1bf63d30cc881474775ce827bc61b0128e5d07119c1e54a'],
		[0x10, 'argon2id', '190432db4cacd25d7f023c4eee4ccfa1ccd31e499daecd434e07aa005315edd1'],
		[0x13, 'argon2d', 'fa50b00aee2c79eb02a575fd1b54c8d3956b0c5ddfc6db886e2bda9e738e597d'],
		[0x13, 'argon2id', 'cb88616cdd8e3cd798580402fc2a39cccbb66568ae01f140a358d7fc5e5a210a'],
	] as const
) {
	test(`production Argon2 adapter matches libargon2: ${algorithm}, version ${version}`, async () => {
		const password = input.password.slice(), salt = input.salt.slice();
		const derived = await deriveArgon2Key({ ...input, version, algorithm });
		expect(Buffer.from(derived).toString('hex')).toBe(expected);
		expect(input.password).toEqual(password);
		expect(input.salt).toEqual(salt);
		derived.fill(0);
	});
}

test('Argon2 resource rejection does not dispatch native work', async () => {
	const native = spyOn(crypto.subtle, 'importKey');
	try {
		await expect(deriveArgon2Key({
			...input,
			version: 0x13,
			algorithm: 'argon2id',
			memoryKiB: 512 * 1024,
		})).rejects.toThrow('limit_exceeded');
		expect(native).not.toHaveBeenCalled();
	} finally {
		native.mockRestore();
	}
});

test('Argon2 native failures do not silently switch to the portable backend', async () => {
	const native = spyOn(crypto.subtle, 'importKey')
		.mockRejectedValue(new DOMException('Synthetic native failure', 'OperationError'));
	try {
		await expect(deriveArgon2Key({ ...input, version: 0x13, algorithm: 'argon2id' }))
			.rejects.toThrow('derivation_failed');
		expect(native).toHaveBeenCalledTimes(1);
	} finally {
		native.mockRestore();
	}
});
