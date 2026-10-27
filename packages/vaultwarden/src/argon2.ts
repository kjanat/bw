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

/** micro509 selects native or portable Argon2 without changing the requested variant or version. */
export async function deriveArgon2Key(input: Argon2Input): Promise<Uint8Array> {
	const result = await deriveArgon2(input, options);
	if (!result.ok) throw new Error(`Argon2 key derivation failed (${result.error.code}).`);
	return result.value;
}
