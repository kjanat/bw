import type { JsonObject } from '#client';
import type { VaultItem } from '#models';

const passwordFields = new Set([
	'password',
	'pass word',
	'passphrase',
	'pass phrase',
	'pass',
	'code',
	'code word',
	'codeword',
	'secret',
	'secret word',
	'personpwd',
	'key',
	'keyword',
	'key word',
	'keyphrase',
	'key phrase',
	'form_pw',
	'wppassword',
	'pin',
	'pwd',
	'pw',
	'pword',
	'passwd',
	'p',
	'serial',
	'serial#',
	'license key',
	'reg #',
	'passwort',
]);
const usernameFields = new Set([
	'user',
	'name',
	'user name',
	'username',
	'login name',
	'email',
	'e-mail',
	'id',
	'userid',
	'user id',
	'login',
	'form_loginname',
	'wpname',
	'mail',
	'loginid',
	'login id',
	'log',
	'personlogin',
	'first name',
	'last name',
	'card#',
	'account #',
	'member',
	'member #',
	'nom',
	'benutzername',
]);
const uriFields = new Set([
	'url',
	'hyper link',
	'hyperlink',
	'link',
	'host',
	'hostname',
	'host name',
	'server',
	'address',
	'hyper ref',
	'href',
	'web',
	'website',
	'web site',
	'site',
	'web-site',
	'uri',
	'ort',
	'adresse',
]);
const blank = (value: string | null | undefined) => !value || !value.trim();
const text = (value: unknown): string | null => typeof value === 'string' ? value : null;
const htmlEntities: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: '\u00a0' };
function decodeHtmlText(value: string): string {
	return value.replace(/&(#x[\da-f]+|#\d+|[a-z][\da-z]+);/gi, (entity, name: string) => {
		if (name[0] === '#') {
			const code = name[1]?.toLowerCase() === 'x'
				? Number.parseInt(name.slice(2), 16)
				: Number.parseInt(name.slice(1), 10);
			try {
				return Number.isFinite(code) ? String.fromCodePoint(code) : entity;
			} catch {
				return entity;
			}
		}
		return htmlEntities[name.toLowerCase()] ?? entity;
	});
}

/** Parse Clipperz XHTML exports, whose textarea contains the actual JSON document. */
export function parseClipperzHtml(source: string): JsonObject {
	const match = /<textarea\b[^>]*>([\s\S]*?)<\/textarea\s*>/i.exec(source);
	if (!match || blank(match[1])) throw new Error('Missing Clipperz textarea.');
	let parsed: unknown;
	try {
		parsed = JSON.parse(decodeHtmlText(match[1]!));
	} catch {
		throw new Error('Invalid Clipperz JSON.');
	}
	if (!Array.isArray(parsed)) throw new Error('Invalid Clipperz JSON.');
	const items: VaultItem[] = [];
	for (const raw of parsed) {
		if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('Invalid Clipperz entry.');
		const entry = raw as Record<string, unknown>;
		const data = entry.data && typeof entry.data === 'object' && !Array.isArray(entry.data)
			? entry.data as Record<string, unknown>
			: undefined;
		const cipher: VaultItem = {
			type: 1,
			name: '--',
			favorite: false,
			reprompt: 0,
			notes: null,
			fields: [],
			login: { username: null, password: null, totp: null, uris: [] },
		};
		const label = text(entry.label);
		if (!blank(label)) cipher.name = label!.split(' \uE009')[0]!;
		const rawNotes = text(data?.notes);
		if (!blank(rawNotes)) cipher.notes = rawNotes!.split('\\n').join('\n');
		const version = entry.currentVersion && typeof entry.currentVersion === 'object'
				&& !Array.isArray(entry.currentVersion)
			? entry.currentVersion as Record<string, unknown>
			: undefined;
		const fields = version?.fields;
		if (fields != null && (typeof fields !== 'object' || Array.isArray(fields))) {
			throw new Error('Invalid Clipperz fields.');
		}
		for (const rawField of Object.values(fields ?? {})) {
			if (!rawField || typeof rawField !== 'object' || Array.isArray(rawField)) continue;
			const field = rawField as Record<string, unknown>;
			const value = text(field.value);
			const action = text(field.actionType)?.toLowerCase() ?? null;
			if (action === 'password') {
				cipher.login!.password = blank(value) ? null : value;
				continue;
			}
			if (action === 'email' || action === 'username' || action === 'user' || action === 'name') {
				cipher.login!.username = blank(value) ? null : value;
				continue;
			}
			if (action === 'url') {
				const uri = value?.trim();
				cipher.login!.uris = uri
					? [{ uri: uri.includes('://') || !uri.includes('.') ? uri : `http://${uri}`, match: null }]
					: [];
				continue;
			}
			const fieldLabel = text(field.label), normalized = fieldLabel?.toLowerCase() ?? null;
			if (cipher.login!.password == null && normalized != null && passwordFields.has(normalized)) {
				cipher.login!.password = blank(value) ? null : value;
			} else if (cipher.login!.username == null && normalized != null && usernameFields.has(normalized)) {
				cipher.login!.username = blank(value) ? null : value;
			} else if (
				(!Array.isArray(cipher.login!.uris) || cipher.login!.uris.length === 0) && normalized != null
				&& uriFields.has(normalized)
			) {
				const uri = value?.trim();
				cipher.login!.uris = uri
					? [{ uri: uri.includes('://') || !uri.includes('.') ? uri : `http://${uri}`, match: null }]
					: [];
			} else if (!blank(value)) {
				const fieldName = fieldLabel ?? '';
				if (value!.length > 200 || /[\r\n]/.test(value!.trim())) {
					cipher.notes = `${cipher.notes ?? ''}${fieldName.trim() ? `${fieldName}: ` : ''}${
						value!.replace(/\r\n|\r/g, '\n')
					}\n`;
				} else cipher.fields!.push({ name: fieldName, value, type: 0 });
			}
		}
		if (
			cipher.login!.username == null && cipher.login!.password == null
			&& (!Array.isArray(cipher.login!.uris) || cipher.login!.uris.length === 0)
		) {
			cipher.type = 2;
			delete cipher.login;
			cipher.secureNote = { type: 0 };
		}
		if (!cipher.notes?.trim()) cipher.notes = null;
		items.push(cipher);
	}
	return { encrypted: false, items };
}
