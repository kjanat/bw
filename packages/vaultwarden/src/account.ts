import { ApiError, VaultwardenClient, type Login, type ApiKeyLogin, type ApiKeyCredentials } from '#client';
import { decrypt, deriveMasterKey, masterPasswordHash, normalizeEmail, stretchKey, type Kdf } from '#crypto';

export interface PasswordAccount extends Login {
	email: string;
	kdf: Kdf;
	auth?: 'password';
}
export interface ApiKeyAccount extends ApiKeyLogin {
	auth: 'api-key';
	apiKey: ApiKeyCredentials;
}
export interface SsoAccount extends ApiKeyLogin, Login {
	auth: 'sso';
}
export type Account = PasswordAccount | ApiKeyAccount | SsoAccount;
export interface TwoFactorAnswer {
	provider: number;
	token: string;
}
export interface LoginChallenge {
	readonly providers: readonly number[];
	/** Sends an email code; no password or password hash is exposed to the callback. */
	requestEmail(): Promise<void>;
}
export interface PasswordLoginOptions {
	/** Called once after the server requests 2FA. Omit for a noninteractive login. */
	onTwoFactor?: (challenge: LoginChallenge) => Promise<TwoFactorAnswer>;
}
/** API keys authenticate access to encrypted data; they do not decrypt the vault. */
export async function loginWithApiKey(
	client: VaultwardenClient,
	credentials: ApiKeyCredentials,
): Promise<ApiKeyAccount> {
	return { ...await client.loginWithApiKey(credentials), auth: 'api-key', apiKey: { ...credentials } };
}
/** Callers persist the result and invalidate local unlock state if the wrapped key/KDF changes. */
export async function refreshAccount(client: VaultwardenClient, account: Account): Promise<Account> {
	return account.auth === 'api-key'
		? loginWithApiKey(client, account.apiKey)
		: { ...account, ...await client.refresh(account.refreshToken) };
}
/** Perform password authentication without exposing the master key or persisting the password. */
export async function loginWithPassword(
	client: VaultwardenClient,
	email: string,
	password: string,
	twoFactor?: TwoFactorAnswer,
	options: PasswordLoginOptions = {},
): Promise<PasswordAccount> {
	const kdf = await client.prelogin(email);
	const master = await deriveMasterKey(password, email, kdf);
	try {
		const passwordHash = await masterPasswordHash(master, password);
		let login: Login;
		try {
			login = await client.login(email, passwordHash, twoFactor);
		} catch (error) {
			if (!(error instanceof ApiError) || !error.twoFactorProviders.length || !options.onTwoFactor) throw error;
			const providers = Object.freeze([...error.twoFactorProviders]);
			const answer = await options.onTwoFactor({
				providers,
				requestEmail: async () => {
					if (!providers.includes(1)) {
						throw new Error('Email two-factor authentication is unavailable.', { cause: error });
					}
					await client.sendEmailLogin(email, passwordHash);
				},
			});
			if (!providers.includes(answer.provider) || !answer.token) {
				throw new Error('Invalid two-factor answer.', { cause: error });
			}
			login = await client.login(email, passwordHash, answer);
		}
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
