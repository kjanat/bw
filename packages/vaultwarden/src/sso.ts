import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { ApiError, type JsonObject, type VaultwardenClient, type SsoCredentials } from '#client';
import { createAccountKeyMaterial } from '#crypto';
import type { PasswordLoginOptions, TwoFactorAnswer, SsoAccount, SsoPendingAccount } from '#account';

export interface SsoAuthorization {
	url: string;
	state: string;
	codeVerifier: string;
	redirectUri: string;
	issuer: string;
}
export class SsoAuthorizationDeclinedError extends Error {
	constructor() {
		super('SSO authorization was declined or failed.');
		this.name = 'SsoAuthorizationDeclinedError';
	}
}
/** Begin a Vaultwarden SSO flow. The caller must not write this short-lived object to persistent storage. */
export async function createSsoAuthorization(
	client: VaultwardenClient,
	redirectUri: string,
	organizationIdentifier?: string,
	signal?: AbortSignal,
): Promise<SsoAuthorization> {
	if (!/^http:\/\/localhost:(?:806[5-9]|8070)$/.test(redirectUri)) {
		throw new Error('SSO redirect must use localhost on ports 8065–8070.');
	}
	const token = await client.ssoPrevalidate(signal);
	const state = randomBytes(32).toString('base64url'), codeVerifier = randomBytes(64).toString('base64url');
	const query = new URLSearchParams({
		client_id: 'cli',
		redirect_uri: redirectUri,
		response_type: 'code',
		scope: 'api offline_access',
		state,
		code_challenge: createHash('sha256').update(codeVerifier).digest('base64url'),
		code_challenge_method: 'S256',
		ssoToken: token,
	});
	if (organizationIdentifier) query.set('domain_hint', organizationIdentifier);
	return {
		url: `${client.services.identity ?? `${client.server}/identity`}/connect/authorize?${query}`,
		state,
		codeVerifier,
		redirectUri,
		issuer: client.server,
	};
}
/** Validate the browser callback before exposing grant parameters to a token request. */
export function ssoCredentialsFromCallback(authorization: SsoAuthorization, callback: string): SsoCredentials {
	let url: URL;
	try {
		url = new URL(callback);
	} catch {
		throw new Error('Invalid SSO callback.');
	}
	const redirect = new URL(authorization.redirectUri);
	if (url.origin !== redirect.origin || url.pathname !== '/' || url.username || url.password || url.hash) {
		throw new Error('Invalid SSO callback destination.');
	}
	for (const parameter of ['code', 'state', 'iss', 'error']) {
		if (url.searchParams.getAll(parameter).length > 1) throw new Error('Duplicate SSO callback parameter.');
	}
	const state = url.searchParams.get('state');
	if (
		!state || Buffer.byteLength(state) !== Buffer.byteLength(authorization.state)
		|| !timingSafeEqual(Buffer.from(state), Buffer.from(authorization.state))
	) throw new Error('SSO callback state did not match.');
	const issuer = url.searchParams.get('iss');
	if (issuer !== null && issuer.replace(/\/$/, '') !== authorization.issuer) {
		throw new Error('SSO callback issuer did not match.');
	}
	if (url.searchParams.has('error')) throw new SsoAuthorizationDeclinedError();
	const code = url.searchParams.get('code');
	if (!code || code.length > 4096) throw new Error('SSO callback has no valid authorization code.');
	return { code, codeVerifier: authorization.codeVerifier, redirectUri: authorization.redirectUri };
}
/** Authenticate with SSO, including one optional 2FA challenge; vault decryption remains a separate password operation. */
export async function loginWithSso(
	client: VaultwardenClient,
	credentials: SsoCredentials,
	twoFactor?: TwoFactorAnswer,
	options: PasswordLoginOptions = {},
): Promise<SsoAccount | SsoPendingAccount> {
	try {
		return { ...await client.loginWithSso(credentials, twoFactor), auth: 'sso' };
	} catch (error) {
		if (!(error instanceof ApiError) || !error.twoFactorProviders.length || !options.onTwoFactor) throw error;
		const providers = Object.freeze([...error.twoFactorProviders]);
		const webAuthnData = error.twoFactorProviderData[7];
		const webAuthn = webAuthnData && typeof webAuthnData === 'object' && !Array.isArray(webAuthnData)
			? webAuthnData as JsonObject
			: undefined;
		const answer = await options.onTwoFactor({
			providers,
			duoAuthUrl: (() => {
				const value = error.twoFactorProviderData[2];
				if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
				const url = (value as Record<string, unknown>).AuthUrl;
				return typeof url === 'string' ? url : undefined;
			})(),
			...(webAuthn ? { webAuthnOptions: webAuthn, webAuthnOrigin: await client.webAuthnOrigin() } : {}),
			requestEmail: async () => {
				if (!providers.includes(1)) throw new Error('Email two-factor authentication is unavailable.');
				await client.sendSsoEmailLogin();
			},
		});
		// Recovery codes are accepted by Vaultwarden without being advertised as an enrolled factor.
		if ((answer.provider !== 8 && !providers.includes(answer.provider)) || !answer.token) {
			throw new Error('Invalid two-factor answer.', { cause: error });
		}
		return { ...await client.loginWithSso(credentials, answer), auth: 'sso' };
	}
}

/** Set a new master password and initialize keys for a JIT-provisioned Vaultwarden SSO account. */
export async function setupSsoAccount(
	client: VaultwardenClient,
	account: SsoAccount | SsoPendingAccount,
	password: string,
): Promise<SsoAccount> {
	if ('encryptedUserKey' in account && account.encryptedUserKey) throw new Error('SSO account is already initialized.');
	if (!password) throw new Error('A master password is required to initialize the SSO account.');
	const material = await createAccountKeyMaterial(password, account.email, account.kdf);
	try {
		await client.setSsoPassword(account.accessToken, account.kdf, {
			encryptedUserKey: material.encryptedUserKey,
			masterPasswordHash: material.masterPasswordHash,
			publicKey: material.publicKey,
			encryptedPrivateKey: material.encryptedPrivateKey,
		});
		return { ...account, encryptedUserKey: material.encryptedUserKey, auth: 'sso' };
	} finally {
		material.userKey.fill(0);
	}
}
