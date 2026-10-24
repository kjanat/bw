import {
	ApiError,
	type ApiKeyCredentials,
	type ApiKeyLogin,
	type JsonObject,
	type Login,
	VaultwardenClient,
} from '#client';
import { decrypt, deriveMasterKey, type Kdf, masterPasswordHash, normalizeEmail, stretchKey } from '#crypto';

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
export interface SsoPendingAccount extends Omit<import('#client').SsoLoginResult, 'encryptedUserKey'> {
	auth: 'sso';
	encryptedUserKey?: never;
}
export type Account = PasswordAccount | ApiKeyAccount | SsoAccount;
/** Read the authenticated subject from a Vaultwarden/Bitwarden access token for status reporting. */
export function accountUserId(account: Pick<Account, 'accessToken'>): string | undefined {
	const parts = account.accessToken.split('.');
	if (parts.length !== 3 || parts[1]!.length > 16_384) return undefined;
	try {
		const claims = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8')) as { sub?: unknown };
		return typeof claims.sub === 'string'
				&& /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(claims.sub)
			? claims.sub
			: undefined;
	} catch {
		return undefined;
	}
}
export interface TwoFactorAnswer {
	provider: number;
	token: string;
}
export interface LoginChallenge {
	readonly providers: readonly number[];
	/** Vaultwarden's short-lived Duo OIDC authorization URL, when provider 2 is offered. */
	readonly duoAuthUrl?: string;
	/** WebAuthn request options returned by Vaultwarden for provider 7. */
	readonly webAuthnOptions?: Readonly<JsonObject>;
	/** Origin used by Vaultwarden's WebAuthn relying-party configuration. */
	readonly webAuthnOrigin?: string;
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
			const webAuthn = webAuthnOptions(error);
			const answer = await options.onTwoFactor({
				providers,
				duoAuthUrl: duoAuthUrl(error),
				...(webAuthn ? { webAuthnOptions: webAuthn, webAuthnOrigin: await client.webAuthnOrigin() } : {}),
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
function duoAuthUrl(error: ApiError): string | undefined {
	const value = error.twoFactorProviderData[2];
	if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
	const url = (value as Record<string, unknown>).AuthUrl;
	return typeof url === 'string' ? url : undefined;
}
function webAuthnOptions(error: ApiError): Readonly<JsonObject> | undefined {
	const value = error.twoFactorProviderData[7];
	return value && typeof value === 'object' && !Array.isArray(value) ? value as JsonObject : undefined;
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
