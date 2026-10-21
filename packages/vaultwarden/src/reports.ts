import { createHash } from 'node:crypto';
import zxcvbn from 'zxcvbn';
import { object, text, serverUrl } from '#client';
import type { VaultItem } from '#models';

export interface PasswordHealthRow {
	object: 'password-health';
	id: string;
	name: string;
	passwordStrength: number;
	reuseCount: number | null;
	exposed: boolean;
	exposedCount: number | null;
	exposedError: string | null;
}
export interface ExposureOptions {
	/** HIBP-compatible range API base URL; HTTPS required outside loopback. */
	baseUrl?: string;
	fetch?: typeof fetch;
	timeoutMs?: number;
	maxConcurrent?: number;
}
/** Range queries accept only the five-character hash prefix. No vault/account credentials are used. */
export class PasswordExposureClient {
	private readonly baseUrl: string;
	private readonly transport: typeof fetch;
	private readonly timeout: number;
	private readonly limit: number;
	private active = 0;
	private readonly waiting: (() => void)[] = [];
	constructor(options: ExposureOptions = {}) {
		this.baseUrl = serverUrl(options.baseUrl ?? 'https://api.pwnedpasswords.com');
		this.transport = options.fetch ?? fetch;
		this.timeout = options.timeoutMs ?? 30000;
		this.limit = options.maxConcurrent ?? 100;
		if (!Number.isSafeInteger(this.timeout) || this.timeout < 1 || this.timeout > 120000) {
			throw new Error('Invalid exposure request timeout.');
		}
		if (!Number.isSafeInteger(this.limit) || this.limit < 1 || this.limit > 100) {
			throw new Error('Invalid exposure request concurrency.');
		}
	}
	private async acquire(): Promise<void> {
		if (this.active < this.limit) {
			this.active++;
			return;
		}
		await new Promise<void>(resolve => this.waiting.push(resolve));
	}
	private release(): void {
		const next = this.waiting.shift();
		if (next) next();
		else this.active--;
	}
	async count(password: string): Promise<number> {
		if (typeof password !== 'string' || password.length === 0) {
			throw new Error('A non-empty password is required for exposure checking.');
		}
		const hash = createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase();
		const prefix = hash.slice(0, 5);
		const suffix = hash.slice(5);
		await this.acquire();
		try {
			let response: Response;
			try {
				response = await this.transport(`${this.baseUrl}/range/${prefix}`, {
					method: 'GET',
					redirect: 'error',
					credentials: 'omit',
					signal: AbortSignal.timeout(this.timeout),
					headers: { 'Add-Padding': 'true', Accept: 'text/plain', 'User-Agent': 'vw' },
				});
			} catch {
				throw new Error('Password exposure request failed or timed out.');
			}
			if (!response.ok) {
				await response.body?.cancel();
				throw new Error(`Password exposure request failed (HTTP ${response.status}).`);
			}
			const limit = 4 * 1024 * 1024;
			if (Number(response.headers.get('content-length')) > limit) {
				await response.body?.cancel();
				throw new Error('Password exposure response exceeds the size limit.');
			}
			if (!response.body) return 0;
			const reader = response.body.getReader();
			let size = 0;
			const chunks: Uint8Array[] = [];
			try {
				for (;;) {
					const { value, done } = await reader.read();
					if (done) break;
					size += value.length;
					if (size > limit) {
						await reader.cancel();
						throw new Error('Password exposure response exceeds the size limit.');
					}
					chunks.push(value);
				}
			} catch {
				throw new Error('Password exposure response could not be read or exceeds the size limit.');
			} finally {
				reader.releaseLock();
			}
			return exposureCount(Buffer.concat(chunks, size).toString('utf8'), suffix);
		} finally {
			this.release();
		}
	}
}
/** Context and 100-Unicode-scalar cap match the SDK's password-health scoring path. */
export function passwordStrength(password: string, username?: string): number {
	let prefix = '';
	let characters = 0;
	for (const character of password) {
		if (characters++ === 100) break;
		prefix += character;
	}
	const context = (username?.split('@', 1)[0] ?? '').trim().toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(Boolean);
	return zxcvbn(prefix, context).score;
}
export interface PasswordHealthOptions {
	/** Defaults to true, like bw report password-health. Set false for an entirely offline report. */
	checkExposed?: boolean;
	exposure?: PasswordExposureClient;
	/** Called after eligible logins are selected and before any exposure requests begin. */
	onStart?: (loginCount: number) => void;
}

/** Match the pinned SDK: ignore unrelated rows and treat missing or invalid counts as zero. */
function exposureCount(source: string, suffix: string): number {
	for (const row of source.split(/\r?\n/)) {
		const separator = row.indexOf(':');
		if (separator < 0 || row.slice(0, separator).toUpperCase() !== suffix) continue;
		const rawCount = row.slice(separator + 1).trim();
		if (!/^\+?\d+$/.test(rawCount)) return 0;
		const significant = (rawCount.startsWith('+') ? rawCount.slice(1) : rawCount).replace(/^0+/, '') || '0';
		if (significant.length > 10) return 0;
		const count = Number(significant);
		return count <= 0xffff_ffff ? count : 0;
	}
	return 0;
}
/** Decrypted items are input only; result rows never include passwords, usernames, or hashes. */
export async function passwordHealth(
	items: readonly VaultItem[],
	options: PasswordHealthOptions = {},
): Promise<PasswordHealthRow[]> {
	const logins = items.filter(item =>
		item.type === 1 && !item.deletedDate && typeof item.login?.password === 'string' && item.login.password !== ''
	);
	options.onStart?.(logins.length);
	const reuse = new Map<string, number>();
	for (const item of logins) {
		const password = text(object(item.login).password);
		reuse.set(password, (reuse.get(password) ?? 0) + 1);
	}
	const exposure = options.checkExposed === false ? undefined : options.exposure ?? new PasswordExposureClient();
	const pending = new Map<string, Promise<number>>();
	try {
		return await Promise.all(logins.map(async item => {
			const login = object(item.login);
			const password = text(login.password);
			const count = reuse.get(password)!;
			const row: PasswordHealthRow = {
				object: 'password-health',
				id: text(item.id),
				name: item.name,
				passwordStrength: passwordStrength(password, typeof login.username === 'string' ? login.username : undefined),
				reuseCount: count > 1 ? count : null,
				exposed: false,
				exposedCount: null,
				exposedError: null,
			};
			if (exposure) {
				const hash = createHash('sha256').update(password).digest('hex');
				let request = pending.get(hash);
				if (!request) {
					request = exposure.count(password);
					pending.set(hash, request);
				}
				try {
					const found = await request;
					row.exposed = found > 0;
					row.exposedCount = found > 0 ? found : null;
				} catch (error) {
					// PasswordExposureClient maps transport and response failures to bounded,
					// non-body-bearing messages. Preserve them like bw's SDK response does.
					row.exposedError = error instanceof Error ? error.message : 'Password exposure check failed.';
				}
			}
			return row;
		}));
	} finally {
		reuse.clear();
		pending.clear();
	}
}
