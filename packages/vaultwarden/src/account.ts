import { VaultwardenClient, type Login } from '#client';
import { decrypt, deriveMasterKey, masterPasswordHash, normalizeEmail, stretchKey, type Kdf } from '#crypto';

export interface Account extends Login {
	email: string;
	kdf: Kdf;
}
/** Perform password authentication without exposing the master key or persisting the password. */
export async function loginWithPassword(
	client: VaultwardenClient,
	email: string,
	password: string,
	twoFactor?: { provider: number; token: string },
): Promise<Account> {
	const kdf = await client.prelogin(email);
	const master = await deriveMasterKey(password, email, kdf);
	try {
		const login = await client.login(
			email,
			await masterPasswordHash(master, password),
			twoFactor,
		);
		const stretched = stretchKey(master);
		try {
			const key = decrypt(login.encryptedUserKey, stretched);
			try {
				validateUserKey(key);
			} finally {
				key.fill(0);
			}
		} finally {
			stretched.fill(0);
		}
		return { ...login, email: normalizeEmail(email), kdf };
	} finally {
		master.fill(0);
	}
}
function validateUserKey(key: Uint8Array): void {
	if (key.length !== 64) {
		throw new Error(
			'Unsupported user key format; expected an encryption V1 vault.',
		);
	}
}
/** The caller owns the returned key and should overwrite it after use. */
export async function unlockAccount(
	account: Account,
	password: string,
): Promise<Buffer> {
	const master = await deriveMasterKey(password, account.email, account.kdf);
	try {
		const stretched = stretchKey(master);
		try {
			const key = decrypt(account.encryptedUserKey, stretched);
			try {
				validateUserKey(key);
				return key;
			} catch (error) {
				key.fill(0);
				throw error;
			}
		} finally {
			stretched.fill(0);
		}
	} finally {
		master.fill(0);
	}
}
