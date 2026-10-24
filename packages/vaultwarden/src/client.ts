import { randomUUID } from 'node:crypto';
import {
	isVaultwardenVersion,
	minimumVaultwardenVersionForCipherType,
	UnsupportedVaultwardenCapabilityError,
	vaultwardenVersionAtLeast,
} from '#capabilities';
import { normalizeEmail, type Kdf } from '#crypto';

export type JsonObject = { [key: string]: unknown };
export function object(value: unknown): JsonObject {
	if (!value || typeof value !== 'object' || Array.isArray(value)) {
		throw new Error('Invalid server response.');
	}
	return value as JsonObject;
}
export function text(value: unknown): string {
	if (typeof value !== 'string' || !value) {
		throw new Error('Missing server response field.');
	}
	return value;
}
export function field(value: JsonObject, name: string): unknown {
	return value[name] ?? value[name[0]!.toUpperCase() + name.slice(1)];
}
export class ApiError extends Error {
	constructor(
		public readonly status: number,
		public readonly twoFactorProviders: number[] = [],
		public readonly sendAccessError?:
			| 'password_hash_b64_required'
			| 'password_hash_b64_invalid'
			| 'send_id_invalid'
			| 'unsupported_grant',
		public readonly twoFactorProviderData: Readonly<Record<number, unknown>> = {},
	) {
		super(
			twoFactorProviders.length
				? 'Two-factor authentication is required; supply a provider and token.'
				: `Vaultwarden request failed (HTTP ${status}).`,
		);
	}
}
export function serverUrl(value: string): string {
	const url = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(value) ? value : `https://${value}`);
	if (url.username || url.password || url.search || url.hash) {
		throw new Error(
			'Server URL must not contain credentials, a query, or a fragment.',
		);
	}
	if (
		url.protocol !== 'https:'
		&& !(
			url.protocol === 'http:'
			&& ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
		)
	) {
		throw new Error('Use HTTPS, or HTTP on a loopback address.');
	}
	return url.toString().replace(/\/+$/, '');
}
export function parseKdf(data: JsonObject): Kdf {
	const settings = field(data, 'kdfSettings');
	const source = settings ? object(settings) : data;
	const type = settings ? field(source, 'kdfType') : field(source, 'kdf');
	const iterations = settings
		? field(source, 'iterations')
		: field(source, 'kdfIterations');
	if (typeof iterations !== 'number') {
		throw new Error('Missing KDF iterations.');
	}
	if (type === 0) return { type, iterations };
	const memory = settings
		? field(source, 'memory')
		: field(source, 'kdfMemory');
	const parallelism = settings
		? field(source, 'parallelism')
		: field(source, 'kdfParallelism');
	if (
		type !== 1
		|| typeof memory !== 'number'
		|| typeof parallelism !== 'number'
	) {
		throw new Error('Unsupported KDF settings.');
	}
	return { type, iterations, memory, parallelism };
}
export interface AccessToken {
	accessToken: string;
	expiresAt: number;
}
export interface Tokens extends AccessToken {
	refreshToken: string;
}
export interface ApiKeyCredentials {
	clientId: string;
	clientSecret: string;
}
export interface ApiKeyLogin extends AccessToken {
	email: string;
	kdf: Kdf;
	encryptedUserKey: string;
}
export interface Login extends Tokens {
	encryptedUserKey: string;
}
export interface SsoLoginResult extends Tokens {
	email: string;
	kdf: Kdf;
	/** Absent only for a new SSO-provisioned account that still needs password setup. */
	encryptedUserKey?: string;
}
export interface SsoCredentials {
	code: string;
	codeVerifier: string;
	redirectUri: string;
}
export interface ServiceUrls {
	webVault?: string;
	api?: string;
	identity?: string;
	icons?: string;
	notifications?: string;
	events?: string;
	keyConnector?: string;
}
export class VaultwardenClient {
	readonly server: string;
	readonly services: Readonly<ServiceUrls>;
	private readonly transport: typeof fetch;
	private serverVersionRequest?: Promise<string>;
	private serverIsVaultwardenRequest?: Promise<boolean>;
	private serverConfigRequest?: Promise<JsonObject>;
	constructor(
		server: string,
		options: { fetch?: typeof fetch; deviceId?: string; services?: ServiceUrls } = {},
	) {
		this.server = serverUrl(server);
		this.services = Object.freeze(Object.fromEntries(
			Object.entries(options.services ?? {}).map(([name, value]) => [name, serverUrl(value)]),
		));
		this.transport = options.fetch ?? fetch;
		this.deviceId = options.deviceId ?? randomUUID();
	}
	readonly deviceId: string;
	/** The server's configured web-vault origin, used to validate WebAuthn assertions. */
	async webAuthnOrigin(): Promise<string> {
		const environment = object(field(await this.serverConfig(), 'environment') ?? {});
		const vault = field(environment, 'vault');
		if (typeof vault !== 'string' || !vault) return new URL(this.server).origin;
		return new URL(serverUrl(vault)).origin;
	}
	/** The release version reported by Vaultwarden's public /api/version endpoint. */
	serverVersion(): Promise<string> {
		if (!this.serverVersionRequest) {
			const request = this.loadServerVersion();
			this.serverVersionRequest = request;
			void request.catch(() => {
				if (this.serverVersionRequest === request) this.serverVersionRequest = undefined;
			});
		}
		return this.serverVersionRequest;
	}
	/** Whether the connected server identifies itself as Vaultwarden in /api/config. */
	isVaultwardenServer(): Promise<boolean> {
		return this.serverIsVaultwarden();
	}
	/** Refuse writes for item kinds that the connected Vaultwarden release cannot store. */
	async assertCipherTypeSupported(type: number): Promise<void> {
		const minimumVersion = minimumVaultwardenVersionForCipherType(type);
		if (!minimumVersion) return;
		if (!(await this.isVaultwardenServer())) return;
		const serverVersion = await this.serverVersion();
		if (!vaultwardenVersionAtLeast(serverVersion, minimumVersion)) {
			throw new UnsupportedVaultwardenCapabilityError('cipher-type', {
				itemType: type,
				minimumVersion,
				serverVersion,
			});
		}
	}
	private serverIsVaultwarden(): Promise<boolean> {
		if (!this.serverIsVaultwardenRequest) {
			const request = this.loadServerIdentity();
			this.serverIsVaultwardenRequest = request;
			void request.catch(() => {
				if (this.serverIsVaultwardenRequest === request) this.serverIsVaultwardenRequest = undefined;
			});
		}
		return this.serverIsVaultwardenRequest;
	}
	private async loadServerIdentity(): Promise<boolean> {
		const server = field(await this.serverConfig(), 'server');
		return typeof server === 'object'
			&& server !== null
			&& !Array.isArray(server)
			&& typeof field(server as JsonObject, 'name') === 'string'
			&& (field(server as JsonObject, 'name') as string).toLowerCase() === 'vaultwarden';
	}
	private serverConfig(): Promise<JsonObject> {
		if (!this.serverConfigRequest) {
			const request = this.loadServerConfig();
			this.serverConfigRequest = request;
			void request.catch(() => {
				if (this.serverConfigRequest === request) this.serverConfigRequest = undefined;
			});
		}
		return this.serverConfigRequest;
	}
	private async loadServerConfig(): Promise<JsonObject> {
		const response = await this.requestRaw('/api/config');
		let config: unknown;
		try {
			config = await response.json();
		} catch {
			throw new Error('Server returned an invalid configuration response.');
		}
		return object(config);
	}
	private async loadServerVersion(): Promise<string> {
		const response = await this.requestRaw('/api/version');
		let version: unknown;
		try {
			version = await response.json();
		} catch {
			throw new Error('Vaultwarden returned an invalid server version.');
		}
		if (typeof version !== 'string' || !isVaultwardenVersion(version)) {
			throw new Error('Vaultwarden returned an invalid server version.');
		}
		return version;
	}
	private async requestRaw(
		path: string,
		init: RequestInit = {},
	): Promise<Response> {
		let response: Response;
		try {
			const service = path.startsWith('/identity/') ? 'identity' : path.startsWith('/api/') ? 'api' : undefined;
			const endpoint = service && this.services[service];
			const url = endpoint ? `${endpoint}${path.slice(service!.length + 1)}` : `${this.server}${path}`;
			response = await this.transport(url, {
				...init,
				redirect: 'error',
				signal: init.signal ?? AbortSignal.timeout(30_000),
				headers: {
					Accept: 'application/json',
					'Device-Type': '8',
					'Bitwarden-Client-Name': 'cli',
					// Vaultwarden gates sync fields (including SSH keys) on this protocol version.
					'Bitwarden-Client-Version': '2026.10.0',
					...init.headers,
				},
			});
		} catch {
			throw new Error(
				'Could not connect to Vaultwarden. Check the server URL and TLS configuration.',
			);
		}
		if (!response.ok) {
			let providers: number[] = [];
			const providerData: Record<number, unknown> = {};
			let sendError: ApiError['sendAccessError'];
			try {
				const error = object(await response.json());
				const code = error.send_access_error_type;
				if (
					code === 'password_hash_b64_required' || code === 'password_hash_b64_invalid' || code === 'send_id_invalid'
				) sendError = code;
				if (
					path === '/identity/connect/token' && init.body instanceof URLSearchParams
					&& init.body.get('grant_type') === 'send_access' && response.status === 400
					&& (error.message === 'Invalid type' || error.error === 'unsupported_grant_type')
				) {
					sendError = 'unsupported_grant';
				}
				if (path.startsWith('/api/sends/') && init.method === 'POST') {
					if (response.status === 401 && error.message === 'Password not provided') {
						sendError = 'password_hash_b64_required';
					}
					if (
						response.status === 400 && (error.message === 'Invalid password' || error.message === 'Invalid password.')
					) sendError = 'password_hash_b64_invalid';
				}
				const p = field(error, 'twoFactorProviders');
				if (Array.isArray(p)) {
					providers = p.filter((v): v is number => typeof v === 'number' && Number.isInteger(v) && v >= 0);
				}
				const details = field(error, 'twoFactorProviders2');
				if (details && typeof details === 'object' && !Array.isArray(details)) {
					for (const [key, value] of Object.entries(details)) {
						if (/^\d+$/.test(key) && Number.isSafeInteger(Number(key))) providerData[Number(key)] = value;
					}
					providers = [
						...new Set([
							...providers,
							...Object.keys(details)
								.filter(value => /^\d+$/.test(value)).map(Number).filter(Number.isSafeInteger),
						]),
					];
				}
			} catch {
				/* Never include server-controlled response text in errors. */
			}
			throw new ApiError(response.status, providers, sendError, providerData);
		}
		return response;
	}
	private async request(path: string, init: RequestInit = {}): Promise<JsonObject> {
		const response = await this.requestRaw(path, init);
		const payload = await response.text();
		if (!payload.trim()) return {};
		try {
			return object(JSON.parse(payload));
		} catch {
			throw new Error('Invalid server response.');
		}
	}
	async prelogin(email: string): Promise<Kdf> {
		const init = {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ email: normalizeEmail(email) }),
		};
		// Vaultwarden versions moved prelogin from /api to /identity.
		try {
			return parseKdf(await this.request('/identity/accounts/prelogin', init));
		} catch (error) {
			if (!(error instanceof ApiError) || ![404, 405].includes(error.status)) {
				throw error;
			}
		}
		return parseKdf(await this.request('/api/accounts/prelogin', init));
	}
	private access(data: JsonObject): AccessToken {
		if (
			typeof data.expires_in !== 'number'
			|| !Number.isFinite(data.expires_in)
			|| data.expires_in <= 0
		) {
			throw new Error('Invalid token expiry.');
		}
		return {
			accessToken: text(data.access_token),
			expiresAt: Date.now() + data.expires_in * 1000,
		};
	}
	private tokens(data: JsonObject): Tokens {
		return { ...this.access(data), refreshToken: text(data.refresh_token) };
	}
	async loginWithApiKey(credentials: ApiKeyCredentials): Promise<ApiKeyLogin> {
		if (
			!/^user\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(credentials.clientId)
			|| !credentials.clientId.startsWith('user.') || !credentials.clientSecret
		) throw new Error('A personal user API client ID and secret are required.');
		const data = await this.request('/identity/connect/token', {
			method: 'POST',
			body: new URLSearchParams({
				grant_type: 'client_credentials',
				client_id: credentials.clientId,
				client_secret: credentials.clientSecret,
				scope: 'api',
				deviceIdentifier: this.deviceId,
				deviceName: 'Vaultwarden CLI',
				deviceType: '8',
			}),
		});
		const tokens = this.access(data);
		const profile = await this.api(tokens.accessToken, 'GET', '/accounts/profile');
		if (`user.${text(field(profile, 'id'))}`.toLowerCase() !== credentials.clientId.toLowerCase()) {
			throw new Error('API key account identity does not match the requested user.');
		}
		const options = field(data, 'userDecryptionOptions');
		const unlock = options ? object(field(object(options), 'masterPasswordUnlock') ?? {}) : {};
		const wrapped = field(data, 'key') ?? field(unlock, 'masterKeyWrappedUserKey')
			?? field(unlock, 'masterKeyEncryptedUserKey');
		const settings = field(unlock, 'kdf');
		return {
			...tokens,
			email: normalizeEmail(text(field(profile, 'email'))),
			kdf: field(data, 'kdf') !== undefined ? parseKdf(data) : parseKdf({ kdfSettings: settings }),
			encryptedUserKey: text(wrapped),
		};
	}
	/** Request an email login code only after the caller explicitly selects email 2FA. */
	async sendEmailLogin(email: string, passwordHash: string): Promise<void> {
		await this.request('/api/two-factor/send-email-login', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				email: normalizeEmail(email),
				masterPasswordHash: passwordHash,
				deviceIdentifier: this.deviceId,
			}),
		});
	}
	async login(
		email: string,
		passwordHash: string,
		twoFactor?: { provider: number; token: string },
	): Promise<Login> {
		const body = new URLSearchParams({
			grant_type: 'password',
			client_id: 'cli',
			scope: 'api offline_access',
			username: normalizeEmail(email),
			password: passwordHash,
			deviceIdentifier: this.deviceId,
			deviceName: 'Vaultwarden CLI',
			deviceType: '8',
		});
		if (twoFactor) {
			body.set('twoFactorProvider', String(twoFactor.provider));
			body.set('twoFactorToken', twoFactor.token);
			body.set('twoFactorRemember', '0');
		}
		const data = await this.request('/identity/connect/token', {
			method: 'POST',
			body,
		});
		let encryptedUserKey = field(data, 'key');
		if (!encryptedUserKey) {
			const options = object(field(data, 'userDecryptionOptions'));
			const unlock = object(field(options, 'masterPasswordUnlock'));
			encryptedUserKey = field(unlock, 'masterKeyWrappedUserKey')
				?? field(unlock, 'masterKeyEncryptedUserKey');
		}
		return { ...this.tokens(data), encryptedUserKey: text(encryptedUserKey) };
	}
	async ssoPrevalidate(signal?: AbortSignal): Promise<string> {
		try {
			return text((await this.request('/identity/sso/prevalidate', { signal })).token);
		} catch (error) {
			if (error instanceof ApiError && error.status === 400) {
				throw new Error('SSO is not enabled on this Vaultwarden server.', { cause: error });
			}
			throw error;
		}
	}
	/** Email code for a pending SSO login, associated with this device's incomplete login. */
	async sendSsoEmailLogin(): Promise<void> {
		await this.request('/api/two-factor/send-email-login', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ deviceIdentifier: this.deviceId }),
		});
	}
	async loginWithSso(
		credentials: SsoCredentials,
		twoFactor?: { provider: number; token: string },
	): Promise<SsoLoginResult> {
		if (
			!/^http:\/\/localhost:(?:806[5-9]|8070)$/.test(credentials.redirectUri)
			|| !/^[A-Za-z0-9._~-]{43,128}$/.test(credentials.codeVerifier)
			|| !credentials.code || credentials.code.length > 4096
		) throw new Error('Invalid SSO grant parameters.');
		const body = new URLSearchParams({
			grant_type: 'authorization_code',
			client_id: 'cli',
			scope: 'api offline_access',
			code: credentials.code,
			code_verifier: credentials.codeVerifier,
			redirect_uri: credentials.redirectUri,
			deviceIdentifier: this.deviceId,
			deviceName: 'Vaultwarden CLI',
			deviceType: '8',
		});
		if (twoFactor) {
			body.set('twoFactorProvider', String(twoFactor.provider));
			body.set('twoFactorToken', twoFactor.token);
			body.set('twoFactorRemember', '0');
		}
		const data = await this.request('/identity/connect/token', { method: 'POST', body });
		const tokens = this.tokens(data), profile = await this.api(tokens.accessToken, 'GET', '/accounts/profile');
		const email = normalizeEmail(text(field(profile, 'email')));
		const decryption = field(data, 'userDecryptionOptions');
		const unlock = decryption ? object(field(object(decryption), 'masterPasswordUnlock') ?? {}) : {};
		const wrapped = field(data, 'key') ?? field(unlock, 'masterKeyWrappedUserKey')
			?? field(unlock, 'masterKeyEncryptedUserKey');
		const settings = field(unlock, 'kdf');
		const kdf = field(data, 'kdf') !== undefined
			? parseKdf(data)
			: settings
			? parseKdf({ kdfSettings: settings })
			: await this.prelogin(email);
		return { ...tokens, email, kdf, ...(typeof wrapped === 'string' && wrapped ? { encryptedUserKey: wrapped } : {}) };
	}
	/** Initialize a JIT-provisioned SSO account with a locally generated password and key set. */
	async setSsoPassword(
		accessToken: string,
		kdf: Kdf,
		input: { encryptedUserKey: string; masterPasswordHash: string; publicKey: string; encryptedPrivateKey: string },
	): Promise<void> {
		await this.api(accessToken, 'POST', '/accounts/set-password', {
			kdf: kdf.type,
			kdfIterations: kdf.iterations,
			...(kdf.type === 1 ? { kdfMemory: kdf.memory, kdfParallelism: kdf.parallelism } : {}),
			key: input.encryptedUserKey,
			masterPasswordHash: input.masterPasswordHash,
			keys: { publicKey: input.publicKey, encryptedPrivateKey: input.encryptedPrivateKey },
		});
	}
	async refresh(refreshToken: string): Promise<Tokens> {
		return this.tokens(
			await this.request('/identity/connect/token', {
				method: 'POST',
				body: new URLSearchParams({
					grant_type: 'refresh_token',
					client_id: 'cli',
					refresh_token: refreshToken,
				}),
			}),
		);
	}
	/** Authenticated API operation. The caller owns token refresh and retry policy. */
	async api(
		accessToken: string,
		method: string,
		path: string,
		data?: unknown,
		query?: Record<string, string>,
	): Promise<JsonObject> {
		if (!path.startsWith('/') || path.startsWith('//') || /[?#]/.test(path)) throw new Error('Invalid API path.');
		return this.request(`/api${path}${query ? `?${new URLSearchParams(query)}` : ''}`, {
			method,
			headers: {
				Authorization: `Bearer ${accessToken}`,
				...(data === undefined ? {} : { 'Content-Type': 'application/json' }),
			},
			...(data === undefined ? {} : { body: JSON.stringify(data) }),
		});
	}
	/** Anonymous Send credentials mint a short-lived token independent of account authentication. */
	async sendAccessToken(accessId: string, passwordHash?: string): Promise<string> {
		const data = await this.request('/identity/connect/token', {
			method: 'POST',
			body: new URLSearchParams({
				grant_type: 'send_access',
				client_id: 'send',
				scope: 'api.send.access',
				send_id: accessId,
				...(passwordHash === undefined ? {} : { password_hash_b64: passwordHash }),
			}),
		});
		return text(data.access_token);
	}
	/** Anonymous access on servers predating the send_access grant. Only the derived password proof is sent. */
	async legacySendAccess(accessId: string, passwordHash?: string): Promise<JsonObject> {
		return this.request(`/api/sends/access/${encodeURIComponent(accessId)}`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ password: passwordHash ?? null }),
		});
	}
	async legacySendFile(sendId: string, fileId: string, passwordHash?: string): Promise<JsonObject> {
		return this.request(`/api/sends/${encodeURIComponent(sendId)}/access/file/${encodeURIComponent(fileId)}`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ password: passwordHash ?? null }),
		});
	}
	async uploadSend(accessToken: string, sendId: string, fileId: string, body: FormData): Promise<void> {
		await this.requestRaw(`/api/sends/${encodeURIComponent(sendId)}/file/${encodeURIComponent(fileId)}`, {
			method: 'POST',
			signal: AbortSignal.timeout(120000),
			headers: { Authorization: `Bearer ${accessToken}` },
			body,
		});
	}
	async uploadAttachment(accessToken: string, itemId: string, attachmentId: string, body: FormData): Promise<void> {
		await this.requestRaw(`/api/ciphers/${encodeURIComponent(itemId)}/attachment/${encodeURIComponent(attachmentId)}`, {
			method: 'POST',
			signal: AbortSignal.timeout(120000),
			headers: { Authorization: `Bearer ${accessToken}` },
			body,
		});
	}
	/** Signed download URLs never receive the account bearer token, including on another origin. */
	async downloadAttachment(url: string): Promise<Buffer> {
		let location: URL;
		try {
			location = new URL(url);
		} catch {
			throw new Error('Invalid attachment URL.');
		}
		const base = new URL(this.services.api ?? this.server);
		if (
			location.username || location.password || location.hash
			|| (location.protocol !== 'https:' && !(location.protocol === 'http:' && location.origin === base.origin))
		) throw new Error('Invalid attachment URL.');
		let response: Response;
		try {
			response = await this.transport(location.toString(), {
				redirect: 'error',
				credentials: 'omit',
				signal: AbortSignal.timeout(120000),
			});
		} catch {
			throw new Error('Attachment download failed.');
		}
		if (!response.ok) throw new ApiError(response.status);
		const maximum = 525 * 1024 * 1024;
		if (Number(response.headers.get('content-length')) > maximum) {
			throw new Error('Attachment exceeds the supported size.');
		}
		if (!response.body) throw new Error('Attachment response has no body.');
		const reader = response.body.getReader();
		let size = 0;
		const chunks: Uint8Array[] = [];
		try {
			for (;;) {
				const { value, done } = await reader.read();
				if (done) break;
				size += value.length;
				if (size > maximum) {
					await reader.cancel();
					throw new Error('Attachment exceeds the supported size.');
				}
				chunks.push(value);
			}
			return Buffer.concat(chunks, size);
		} finally {
			reader.releaseLock();
		}
	}
	/** Account revision in Unix milliseconds; a negative value indicates a deleted account. */
	async accountRevisionDate(accessToken: string): Promise<number> {
		const response = await this.requestRaw('/api/accounts/revision-date', {
			headers: { Authorization: `Bearer ${accessToken}` },
		});
		let revision: unknown;
		try {
			revision = await response.json();
		} catch {
			throw new Error('Invalid account revision response.');
		}
		if (typeof revision !== 'number' || !Number.isSafeInteger(revision) || Math.abs(revision) > 8640000000000000) {
			throw new Error('Invalid account revision response.');
		}
		return revision;
	}
	async sync(accessToken: string): Promise<JsonObject> {
		const data = await this.request('/api/sync?excludeDomains=false', {
			headers: { Authorization: `Bearer ${accessToken}` },
		});
		if (!Array.isArray(field(data, 'ciphers')) || !field(data, 'profile')) {
			throw new Error('Invalid vault sync response.');
		}
		return data;
	}
}
