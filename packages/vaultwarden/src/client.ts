import { randomUUID } from 'node:crypto';
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
	) {
		super(
			twoFactorProviders.length
				? 'Two-factor authentication is required; supply a provider and token.'
				: `Vaultwarden request failed (HTTP ${status}).`,
		);
	}
}
export function serverUrl(value: string): string {
	const url = new URL(value);
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
export interface Tokens {
	accessToken: string;
	refreshToken: string;
	expiresAt: number;
}
export interface Login extends Tokens {
	encryptedUserKey: string;
}
export class VaultwardenClient {
	readonly server: string;
	private readonly transport: typeof fetch;
	constructor(
		server: string,
		options: { fetch?: typeof fetch; deviceId?: string } = {},
	) {
		this.server = serverUrl(server);
		this.transport = options.fetch ?? fetch;
		this.deviceId = options.deviceId ?? randomUUID();
	}
	readonly deviceId: string;
	private async requestRaw(
		path: string,
		init: RequestInit = {},
	): Promise<Response> {
		let response: Response;
		try {
			response = await this.transport(`${this.server}${path}`, {
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
			try {
				const error = object(await response.json());
				const p = field(error, 'twoFactorProviders');
				if (Array.isArray(p)) {
					providers = p.filter((v): v is number => typeof v === 'number');
				}
			} catch {
				/* Never include server-controlled response text in errors. */
			}
			throw new ApiError(response.status, providers);
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
	private tokens(data: JsonObject): Tokens {
		if (
			typeof data.expires_in !== 'number'
			|| !Number.isFinite(data.expires_in)
			|| data.expires_in <= 0
		) {
			throw new Error('Invalid token expiry.');
		}
		return {
			accessToken: text(data.access_token),
			refreshToken: text(data.refresh_token),
			expiresAt: Date.now() + data.expires_in * 1000,
		};
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
		const base = new URL(this.server);
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
	async sync(accessToken: string): Promise<JsonObject> {
		const data = await this.request('/api/sync?excludeDomains=true', {
			headers: { Authorization: `Bearer ${accessToken}` },
		});
		if (!Array.isArray(field(data, 'ciphers')) || !field(data, 'profile')) {
			throw new Error('Invalid vault sync response.');
		}
		return data;
	}
}
