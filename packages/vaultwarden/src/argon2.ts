import { deriveArgon2, type Argon2Input, type Argon2Options } from 'micro509/kdf';

const options: Argon2Options = {
	limits: {
		maxMemoryKiB: 256 * 1024,
		maxPasses: 20,
		maxParallelism: 16,
		maxOutputBytes: 32,
		maxInputBytes: 0xffffffff,
	},
};

/** Preserve Bun and legacy KDBX support when native WebCrypto cannot derive the exact request. */
export async function deriveArgon2Key(input: Argon2Input): Promise<Uint8Array> {
	let result = await deriveArgon2(input, options);
	if (!result.ok && result.error.code === 'unsupported') {
		const { argon2dAsync, argon2idAsync } = await import('@noble/hashes/argon2.js');
		result = await deriveArgon2(input, {
			...options,
			backend: async request => ({
				ok: true,
				value: await (request.algorithm === 'argon2d' ? argon2dAsync : argon2idAsync)(
					request.password,
					request.salt,
					{
						t: request.passes,
						m: request.memoryKiB,
						p: request.parallelism,
						dkLen: request.outputBytes,
						version: request.version,
						key: request.secret,
						personalization: request.associatedData,
						maxmem: 272 * 1024 * 1024,
					},
				),
			}),
		});
	}
	if (!result.ok) throw new Error(`Argon2 key derivation failed (${result.error.code}).`);
	return result.value;
}
