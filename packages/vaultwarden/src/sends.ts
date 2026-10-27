import { hkdfSync, pbkdf2Sync, randomBytes } from 'node:crypto';
import { ApiError, VaultwardenClient, object, text, serverUrl, type JsonObject } from '#client';
import { vaultwardenCapabilities } from '#capabilities';
import { encrypt, decrypt, encryptAttachment, encryptedAttachmentSize, decryptAttachment } from '#crypto';
import { MultipleResultsError } from '#search';

export interface SendInput extends JsonObject {
	object?: 'send';
	type: 0 | 1;
	name: string;
	text?: { text: string; hidden?: boolean } | null;
	file?: { fileName: string } | null;
	emails?: string[] | null;
	password?: string | null;
	deletionDate?: string;
	expirationDate?: string | null;
	maxAccessCount?: number | null;
	disabled?: boolean;
	hideEmail?: boolean;
}
export class SendMutationFailure extends Error {}
export class SendPasswordRequired extends Error {
	constructor(readonly incorrect = false) {
		super(incorrect ? 'The Send password is incorrect.' : 'A Send password is required.');
	}
}
const maxBitwardenSendContentSize = 500 * 1024 * 1024;
export function assertSendFileSize(plaintextSize: number, vaultwarden: boolean): void {
	if (!Number.isSafeInteger(plaintextSize) || plaintextSize < 0) throw new Error('Invalid Send file size.');
	if (vaultwarden) {
		if (encryptedAttachmentSize(plaintextSize) > vaultwardenCapabilities.fileUploads.maximumEncryptedBytes) {
			throw new Error('Send file exceeds the 525 MiB Vaultwarden limit.');
		}
	} else if (plaintextSize > maxBitwardenSendContentSize) {
		throw new Error('Send file exceeds the 500 MiB limit.');
	}
}
/** Sends use full HKDF (extract and expand), unlike account master-key stretching. */
export function deriveSendKey(seed: Uint8Array): Buffer {
	if (seed.length !== 16) throw new Error('Invalid Send key seed.');
	return Buffer.from(hkdfSync('sha256', seed, 'bitwarden-send', 'send', 64));
}
export function hashSendPassword(password: string, seed: Uint8Array): string {
	if (seed.length !== 16) throw new Error('Invalid Send key seed.');
	return pbkdf2Sync(password, seed, 100000, 32, 'sha256').toString('base64');
}
export function sendTemplate(type: 0 | 1 = 0): SendInput {
	return {
		object: 'send',
		type,
		name: 'Send name',
		notes: 'Some notes about this send.',
		text: type === 0 ? { text: 'Text contained in the send.', hidden: false } : null,
		file: type === 1 ? { fileName: 'file attachment location' } : null,
		emails: null,
		maxAccessCount: null,
		deletionDate: new Date(Date.now() + 7 * 86400000).toISOString(),
		expirationDate: null,
		password: null,
		disabled: false,
		hideEmail: false,
	};
}
function decodedSend(raw: JsonObject, seed: Uint8Array, server?: string): JsonObject {
	const key = deriveSendKey(seed);
	const decode = (value: unknown) => value == null ? null : decrypt(text(value), key).toString('utf8');
	try {
		const result: JsonObject = { ...raw, name: decode(raw.name) };
		result.emails = typeof raw.emails === 'string'
			? raw.emails.split(',').map(email => email.trim()).filter(Boolean)
			: [];
		if (raw.notes != null) result.notes = decode(raw.notes);
		if (raw.type === 0) result.text = { ...object(raw.text), text: decode(object(raw.text).text) };
		else if (raw.type === 1) result.file = { ...object(raw.file), fileName: decode(object(raw.file).fileName) };
		else throw new Error('Unsupported Send type.');
		delete result.password;
		delete result.key;
		if (server) {
			result.key = Buffer.from(seed).toString('base64');
			result.passwordSet = raw.password != null;
			result.accessUrl = `${server}/#/send/${encodeURIComponent(text(raw.accessId))}/${
				Buffer.from(seed).toString('base64url')
			}`;
		}
		return result;
	} finally {
		key.fill(0);
	}
}
function validate(input: SendInput, requireFutureDeletion = false): void {
	if (input.type !== 0 && input.type !== 1) throw new Error('This server accepts text and file Sends only.');
	if (typeof input.name !== 'string' || !input.name.trim()) throw new Error('A Send name is required.');
	if (
		input.emails != null && (!Array.isArray(input.emails)
			|| input.emails.some(email => typeof email !== 'string' || !email.trim() || email.includes(',')))
	) {
		throw new Error('Invalid Send recipient email list.');
	}
	if (input.password != null && typeof input.password !== 'string') throw new Error('Invalid Send password.');
	if ((input.emails?.length ?? 0) > 0 && input.password != null && input.password.trim() !== '') {
		throw new Error('Send password and email verification are mutually exclusive.');
	}
	if (input.notes != null && typeof input.notes !== 'string') throw new Error('Invalid Send notes.');
	for (const flag of ['disabled', 'hideEmail']) {
		if (input[flag] != null && typeof input[flag] !== 'boolean') throw new Error(`Invalid Send ${flag}.`);
	}
	if (
		input.maxAccessCount != null
		&& (!Number.isSafeInteger(input.maxAccessCount) || input.maxAccessCount < 0 || input.maxAccessCount > 2147483647)
	) {
		throw new Error('Invalid Send access limit.');
	}
	const deletion = Date.parse(input.deletionDate ?? '');
	const now = Date.now();
	if (!Number.isFinite(deletion) || (requireFutureDeletion && deletion <= now)) {
		throw new Error('Must specify a valid deletion date after the current time');
	}
	if (deletion > now + 31 * 86400000) {
		throw new Error('Send deletion date must be within 31 days.');
	}
	if (input.expirationDate != null && !Number.isFinite(Date.parse(input.expirationDate))) {
		throw new Error('Invalid Send expiration date.');
	}
	if (input.type === 0 && typeof input.text?.text !== 'string') throw new Error('Send text is required.');
	if (input.type === 0 && input.text?.hidden != null && typeof input.text.hidden !== 'boolean') {
		throw new Error('Invalid Send hidden flag.');
	}
	if (input.type === 1 && input.file != null && typeof input.file.fileName !== 'string') {
		throw new Error('Invalid Send filename.');
	}
}
/** Owner operations over an encrypted sync snapshot. The caller owns the account key. */
export class SendService {
	constructor(
		readonly client: VaultwardenClient,
		readonly accessToken: string,
		readonly snapshot: JsonObject,
		private readonly userKey: Uint8Array,
	) {}
	private records(): JsonObject[] {
		if (!Array.isArray(this.snapshot.sends)) throw new Error('No cached Sends. Run vw sync first.');
		return this.snapshot.sends.map(object);
	}
	private hasPremiumAccess(): boolean {
		const profile = this.snapshot.profile == null ? {} : object(this.snapshot.profile);
		return profile.premium === true || profile.premiumPersonally === true
			|| profile.premiumFromOrganization === true;
	}
	private decode(raw: JsonObject): JsonObject {
		const seed = decrypt(text(raw.key), this.userKey);
		try {
			return decodedSend(raw, seed, this.client.services.webVault ?? this.client.server);
		} finally {
			seed.fill(0);
		}
	}
	list(): JsonObject[] {
		return this.records().map(raw => this.decode(raw));
	}
	private async canAccessFileSend(): Promise<boolean> {
		return this.hasPremiumAccess() || await this.client.isVaultwardenServer();
	}
	async assertCanCreate(type: 0 | 1): Promise<void> {
		if (type === 1 && !(await this.canAccessFileSend())) {
			throw new Error('Premium status is required to use this feature.');
		}
	}
	get(query: string, type?: 0 | 1): JsonObject {
		const records = this.records();
		const exact = records.find(value => typeof value.id === 'string' && value.id.toLowerCase() === query.toLowerCase());
		if (exact && (type === undefined || exact.type === type)) return this.decode(exact);
		if (exact) throw new Error('Not found.');
		const matches = records.map(value => this.decode(value)).filter(value =>
			(type === undefined || value.type === type)
			&& text(value.name).toLowerCase().includes(query.toLowerCase())
		);
		if (matches.length !== 1 || !query.trim()) {
			if (matches.length > 1) throw new MultipleResultsError(matches.map(value => text(value.id)));
			throw new Error('Not found.');
		}
		return matches[0]!;
	}
	async create(input: SendInput, file?: Uint8Array): Promise<JsonObject> {
		await this.assertCanCreate(input.type);
		return this.save(
			{ ...input, deletionDate: input.deletionDate ?? sendTemplate().deletionDate },
			randomBytes(16),
			undefined,
			file,
		);
	}
	async edit(id: string, patch: JsonObject): Promise<JsonObject> {
		const current = this.get(id);
		if (current.type === 1 && !(await this.canAccessFileSend())) {
			throw new Error('Premium status is required to use this feature.');
		}
		if (patch.type !== undefined && patch.type !== current.type) throw new Error('A Send cannot change type.');
		if (patch.key !== undefined && patch.key !== current.key) throw new Error('A Send cannot change its key.');
		const seed = Buffer.from(text(current.key), 'base64');
		const merged = { ...current, ...patch };
		return this.save({ ...merged, type: current.type as 0 | 1, name: text(merged.name) }, seed, text(current.id));
	}
	private async save(input: SendInput, seed: Buffer, id?: string, contents?: Uint8Array): Promise<JsonObject> {
		let key: Buffer | undefined;
		let encrypted: Buffer | undefined;
		try {
			validate(input, id === undefined);
			const emails = input.emails?.map(email => email.trim()).filter(Boolean) ?? [];
			if (emails.length > 0 && await this.client.isVaultwardenServer()) {
				throw new Error('Vaultwarden does not support email-verification Sends.');
			}
			key = deriveSendKey(seed);
			const enc = (value: string) => encrypt(Buffer.from(value), key!);
			const data: JsonObject = {
				type: input.type,
				name: enc(input.name),
				notes: input.notes == null ? null : enc(String(input.notes)),
				key: encrypt(seed, this.userKey),
				deletionDate: input.deletionDate,
				expirationDate: input.expirationDate ?? null,
				maxAccessCount: input.maxAccessCount ?? null,
				disabled: input.disabled ?? false,
				hideEmail: input.hideEmail ?? false,
			};
			if (emails.length > 0) {
				data.emails = emails.join(',').toLowerCase();
				data.password = null;
			} else if (input.password != null && input.password !== '') {
				data.password = hashSendPassword(input.password, seed);
			}
			if (input.type === 0) data.text = { text: enc(input.text!.text), hidden: input.text!.hidden ?? false };
			else if (!id) {
				if (contents === undefined || !input.file?.fileName) throw new Error('A Send file and filename are required.');
				const isVaultwarden = contents.length > maxBitwardenSendContentSize
					? await this.client.isVaultwardenServer()
					: false;
				assertSendFileSize(contents.length, isVaultwarden);
				encrypted = encryptAttachment(contents, key);
				data.file = { fileName: enc(input.file.fileName) };
				data.fileLength = encrypted.length;
			}
			if (id) {
				return this.decode(await this.client.api(this.accessToken, 'PUT', `/sends/${encodeURIComponent(id)}`, data));
			}
			if (input.type === 0) return this.decode(await this.client.api(this.accessToken, 'POST', '/sends', data));
			const upload = await this.client.api(this.accessToken, 'POST', '/sends/file/v2', data);
			const raw = object(upload.sendResponse);
			const sendId = text(raw.id);
			try {
				if (upload.fileUploadType === 0) {
					const form = new FormData();
					form.set('data', new Blob([new Uint8Array(encrypted!)]), text(object(data.file).fileName));
					await this.client.uploadSend(this.accessToken, sendId, text(object(raw.file).id), form);
				} else if (upload.fileUploadType === 1) {
					const fileId = text(object(raw.file).id);
					await this.client.uploadAzureFile(
						text(upload.url),
						encrypted!,
						async () =>
							text(
								(await this.client.api(
									this.accessToken,
									'GET',
									`/sends/${encodeURIComponent(sendId)}/file/${encodeURIComponent(fileId)}`,
								)).url,
							),
					);
				} else {
					throw new Error('Unsupported Send upload storage type.');
				}
			} catch {
				try {
					await this.client.api(this.accessToken, 'DELETE', `/sends/${encodeURIComponent(sendId)}`);
				} catch {
					throw new SendMutationFailure('Send file upload failed and metadata cleanup failed. Sync before retrying.');
				}
				throw new Error('Send file upload failed; incomplete Send removed.');
			}
			return this.decode(raw);
		} finally {
			seed.fill(0);
			key?.fill(0);
			encrypted?.fill(0);
		}
	}
	async delete(id: string): Promise<void> {
		await this.client.api(this.accessToken, 'DELETE', `/sends/${encodeURIComponent(text(this.get(id).id))}`);
	}
	async removePassword(id: string): Promise<JsonObject> {
		return this.decode(
			await this.client.api(
				this.accessToken,
				'PUT',
				`/sends/${encodeURIComponent(text(this.get(id).id))}/remove-password`,
			),
		);
	}
}
export interface ReceivedSend {
	send: JsonObject;
	contents?: Buffer;
	fileName?: string;
}
/** Fragment keys are parsed locally and never sent to the server. No account credentials are accepted. */
export async function receiveSend(
	url: string,
	options: { password?: string; download?: boolean; fetch?: typeof fetch } = {},
): Promise<ReceivedSend> {
	let link: URL;
	try {
		link = new URL(url);
	} catch {
		throw new Error('Invalid Send URL.');
	}
	const server = serverUrl(`${link.origin}${link.pathname}`);
	if (link.username || link.password || link.search) throw new Error('Invalid Send URL.');
	const match = /^#\/send\/([A-Za-z0-9_-]{22})\/([A-Za-z0-9_-]{22})\/?$/.exec(link.hash);
	if (!match) throw new Error('Send URL must contain an access ID and a 16-byte fragment key.');
	const seed = Buffer.from(match[2]!, 'base64url');
	if (seed.toString('base64url') !== match[2]) throw new Error('Invalid Send URL key.');
	const client = new VaultwardenClient(server, { fetch: options.fetch });
	const key = deriveSendKey(seed);
	try {
		let token: string | undefined;
		const passwordHash = options.password === undefined ? undefined : hashSendPassword(options.password, seed);
		try {
			token = await client.sendAccessToken(match[1]!, passwordHash);
		} catch (error) {
			if (
				error instanceof ApiError
				&& (error.sendAccessError === 'password_hash_b64_required'
					|| error.sendAccessError === 'password_hash_b64_invalid')
			) {
				throw new SendPasswordRequired(error.sendAccessError === 'password_hash_b64_invalid');
			}
			if (!(error instanceof ApiError && error.sendAccessError === 'unsupported_grant')) throw error;
		}
		const legacy = async (operation: () => Promise<JsonObject>): Promise<JsonObject> => {
			try {
				return await operation();
			} catch (error) {
				if (
					error instanceof ApiError
					&& (error.sendAccessError === 'password_hash_b64_required'
						|| error.sendAccessError === 'password_hash_b64_invalid')
				) {
					throw new SendPasswordRequired(error.sendAccessError === 'password_hash_b64_invalid');
				}
				throw error;
			}
		};
		const raw = token === undefined
			? await legacy(() => client.legacySendAccess(match[1]!, passwordHash))
			: await client.api(token, 'POST', '/sends/access');
		const send = decodedSend(raw, seed);
		if (raw.type !== 1 || options.download === false) return { send };
		const file = object(send.file);
		const response = token === undefined
			? await legacy(() => client.legacySendFile(text(raw.id), text(file.id), passwordHash))
			: await client.api(token, 'POST', `/sends/access/file/${encodeURIComponent(text(file.id))}`);
		const encrypted = await client.downloadAttachment(text(response.url));
		try {
			return { send, contents: decryptAttachment(encrypted, key), fileName: text(file.fileName) };
		} finally {
			encrypted.fill(0);
		}
	} finally {
		seed.fill(0);
		key.fill(0);
	}
}
