import { CryptoEngine, Kdbx, KdbxGroup, KdbxEntry, ProtectedValue } from 'kdbxweb';
import { argon2dAsync, argon2idAsync } from '@noble/hashes/argon2.js';
import { randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import type { JsonObject } from '#client';
import type { VaultItem } from '#models';

export class KdbxImportError extends Error {}
const integer = (value: number, min: number, max: number) =>
	Number.isSafeInteger(value) && value >= min && value <= max;
export function configureKdbxCrypto(): void {
	CryptoEngine.setArgon2Impl(async (password, salt, memory, iterations, length, parallelism, type, version) => {
		if (
			!integer(memory, 8 * parallelism, 256 * 1024) || !integer(iterations, 1, 20)
			|| !integer(parallelism, 1, 16) || length !== 32 || ![0, 2].includes(type) || ![0x10, 0x13].includes(version)
		) {
			throw new KdbxImportError('Unsupported KDBX KDF parameters.');
		}
		const hash = await (type === 0 ? argon2dAsync : argon2idAsync)(new Uint8Array(password), new Uint8Array(salt), {
			m: memory,
			t: iterations,
			p: parallelism,
			dkLen: length,
			version,
			maxmem: 272 * 1024 * 1024,
		});
		return hash.buffer as ArrayBuffer;
	});
}
const raw = (entry: KdbxEntry, key: string): string | undefined => {
	const value = entry.fields.get(key);
	return value instanceof ProtectedValue ? value.getText() : value;
};
const nonempty = (value: string | undefined) => value?.trim() ? value : null;
const otpKeys = [
	'otp',
	'TimeOtp-Secret',
	'TimeOtp-Secret-Hex',
	'TimeOtp-Secret-Base32',
	'TimeOtp-Secret-Base64',
	'TimeOtp-Period',
	'TimeOtp-Length',
	'TimeOtp-Algorithm',
];
function base32(bytes: Uint8Array): string {
	let bits = 0, value = 0, result = '';
	for (const byte of bytes) {
		value = (value << 8) | byte;
		bits += 8;
		while (bits >= 5) {
			bits -= 5;
			result += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[(value >>> bits) & 31];
		}
	}
	if (bits) result += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[(value << (5 - bits)) & 31];
	return result;
}
function decodeBase32(value: string): Uint8Array | undefined {
	const normalized = value.replace(/[\s=]/g, '').toUpperCase();
	if (!/^[A-Z2-7]+$/.test(normalized)) return undefined;
	let bits = 0, buffer = 0;
	const result: number[] = [];
	for (const char of normalized) {
		buffer = (buffer << 5) | 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(char);
		bits += 5;
		if (bits >= 8) {
			bits -= 8;
			result.push((buffer >>> bits) & 255);
		}
	}
	const bytes = new Uint8Array(result);
	return base32(bytes) === normalized ? bytes : undefined;
}
export function kdbxTotp(entry: KdbxEntry): string | null {
	const direct = nonempty(raw(entry, 'otp'));
	if (direct) return direct.startsWith('key=') ? direct.slice(4) : direct;
	let bytes: Uint8Array | undefined;
	const b32 = nonempty(raw(entry, 'TimeOtp-Secret-Base32')), b64 = nonempty(raw(entry, 'TimeOtp-Secret-Base64'));
	const hex = nonempty(raw(entry, 'TimeOtp-Secret-Hex')), utf8 = nonempty(raw(entry, 'TimeOtp-Secret'));
	if (b32) bytes = decodeBase32(b32);
	else if (b64) {
		const source = b64.trim(), decoded = Buffer.from(source, 'base64');
		if (decoded.toString('base64') === source) bytes = decoded;
	} else if (hex) { if (/^(?:[a-fA-F0-9]{2})+$/.test(hex.trim())) bytes = Buffer.from(hex.trim(), 'hex'); }
	else if (utf8) bytes = Buffer.from(utf8);
	if (!bytes) return null;
	const secret = base32(bytes);
	const period = raw(entry, 'TimeOtp-Period')?.trim(), digits = raw(entry, 'TimeOtp-Length')?.trim();
	const algorithm = raw(entry, 'TimeOtp-Algorithm')?.trim().toUpperCase();
	const hash = algorithm === 'HMAC-SHA-256' ? 'SHA256' : algorithm === 'HMAC-SHA-512' ? 'SHA512' : undefined;
	if ((!period || period === '30') && (!digits || digits === '6') && !hash) return secret;
	return `otpauth://totp/Imported?secret=${secret}${hash ? `&algorithm=${hash}` : ''}${
		digits && digits !== '6' ? `&digits=${digits}` : ''
	}${period && period !== '30' ? `&period=${period}` : ''}`;
}
function uri(value: string): string {
	try {
		if (new URL(value).hostname) return value;
	} catch { /* Apply the SDK fallback. */ }
	try {
		if (isIP(new URL(`http://${value}`).hostname) === 4) return `http://${value}`;
	} catch { /* Use HTTPS below. */ }
	return `https://${value}`;
}
export function mapKdbx(database: Kdbx, organization: boolean): JsonObject {
	const root = database.groups[0];
	if (!root) throw new KdbxImportError('KDBX database has no root group.');
	const recycle = database.meta.recycleBinEnabled === true ? database.meta.recycleBinUuid?.toString() : undefined;
	const groups: JsonObject[] = [], items: VaultItem[] = [];
	const stack: { group: KdbxGroup; path: string; root: boolean; depth: number }[] = [{
		group: root,
		path: '',
		root: true,
		depth: 0,
	}];
	while (stack.length) {
		const current = stack.pop()!;
		if (current.depth > 256) throw new KdbxImportError('KDBX group nesting exceeds the supported depth.');
		if (current.group.uuid.toString() === recycle) continue;
		let path = current.path, groupId: string | null = null;
		if (!current.root) {
			path = `${path ? `${path}/` : ''}${nonempty(current.group.name) ?? '-'}`;
			groupId = randomUUID();
			groups.push({ id: groupId, name: path });
		}
		for (const entry of current.group.entries) {
			const url = nonempty(raw(entry, 'URL'));
			const fields: JsonObject[] = [];
			for (const [key, value] of entry.fields) {
				if (['Title', 'UserName', 'Password', 'URL', 'Notes', ...otpKeys].includes(key)) continue;
				const content = value instanceof ProtectedValue ? value.getText() : value;
				if (content.trim()) fields.push({ name: key, value: content, type: value instanceof ProtectedValue ? 1 : 0 });
			}
			items.push({
				type: 1,
				name: nonempty(raw(entry, 'Title')) ?? '--',
				notes: nonempty(raw(entry, 'Notes')),
				favorite: false,
				reprompt: 0,
				folderId: organization ? null : groupId,
				collectionIds: organization && groupId ? [groupId] : [],
				fields,
				login: {
					username: nonempty(raw(entry, 'UserName')),
					password: nonempty(raw(entry, 'Password')),
					totp: kdbxTotp(entry),
					uris: url ? [{ uri: uri(url), match: null }] : [],
				},
			});
		}
		for (const group of [...current.group.groups].reverse()) {
			stack.push({ group, path, root: false, depth: current.depth + 1 });
		}
	}
	return { encrypted: false, items, [organization ? 'collections' : 'folders']: groups };
}
