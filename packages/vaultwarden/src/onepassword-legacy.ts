import type { JsonObject } from '#client';
import type { VaultItem } from '#models';
import { parseCsv } from '#csv';

const present = (v: unknown): v is string => typeof v === 'string' && !!v.trim();
const lookup = (map: Record<string, string>, key: unknown): string | undefined =>
	typeof key === 'string' && Object.hasOwn(map, key) ? map[key] : undefined;
function object(v: unknown): JsonObject {
	if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('Invalid 1Password record.');
	return v as JsonObject;
}
function rows(v: unknown): JsonObject[] {
	if (v == null) return [];
	if (!Array.isArray(v)) throw new Error('Invalid 1Password record list.');
	return v.map(object);
}
function login(): VaultItem {
	return {
		type: 1,
		name: '--',
		favorite: false,
		reprompt: 0,
		notes: null,
		fields: [],
		login: { username: null, password: null, totp: null, uris: [] },
	};
}
function uris(values: unknown[]): JsonObject[] {
	return values.filter(present).map(uri => {
		uri = uri.trim();
		if (!uri.includes('://') && uri.includes('.')) uri = `http://${uri}`;
		return { uri: uri.slice(0, 1000), match: null };
	});
}
function custom(item: VaultItem, key: string, value: string, type = 0): void {
	if (!present(value)) return;
	if (value.length > 200 || /\r|\n/.test(value.trim())) {
		item.notes = `${item.notes ?? ''}${key}: ${value.replace(/\r\n|\r/g, '\n')}\n`;
	} else item.fields!.push({ name: key, value, type });
}
function brand(number: string): string | null {
	const n = number.replace(/\s/g, '');
	if (/^4/.test(n)) return 'Visa';
	if (/^5[1-5]/.test(n) || Number(n.slice(0, 4)) >= 2221 && Number(n.slice(0, 4)) <= 2720) return 'Mastercard';
	if (/^3[47]/.test(n)) return 'Amex';
	if (/^6(?:011|5|4[4-9])/.test(n)) return 'Discover';
	if (/^35/.test(n)) return 'JCB';
	if (/^3(?:0[0-5]|[68])/.test(n)) return 'Diners Club';
	if (/^62/.test(n)) return 'UnionPay';
	return null;
}
function finish(item: VaultItem): VaultItem {
	if (
		item.type === 1 && !present(item.login!.username) && !present(item.login!.password)
		&& !(item.login!.uris as unknown[]).length
	) {
		item.type = 2;
		item.secureNote = { type: 0 };
	}
	if (item.type !== 1) delete item.login;
	if (!present(item.notes)) item.notes = null;
	return item;
}
function history(value: unknown): JsonObject[] {
	return rows(value).filter(h => present(h.value) && h.time != null).sort((a, b) => Number(b.time) - Number(a.time))
		.slice(0, 5).map(h => ({
			password: h.value,
			lastUsedDate: new Date(String(h.time).length >= 13 ? Number(h.time) : Number(h.time) * 1000).toISOString(),
		}));
}
function fields(item: VaultItem, values: JsonObject[], section: boolean): void {
	for (const field of values) {
		const raw = field[section ? 'v' : 'value'];
		if (raw == null || !String(raw).trim()) continue;
		const value = field.k === 'date' ? new Date(Number(raw) * 1000).toUTCString() : String(raw);
		const designation = field[section ? 'n' : 'designation'];
		const target = item.type === 1 ? item.login! : item.type === 3 ? item.card! : item.identity!;
		let key: string | undefined;
		if (item.type === 1) {
			if (designation === 'username' || designation === 'password') key = designation;
			else if (typeof designation === 'string' && designation.startsWith('TOTP_')) key = 'totp';
		} else if (item.type === 3) {
			key = lookup({ ccnum: 'number', cvv: 'code', cardholder: 'cardholderName' }, designation);
			if (designation === 'type') continue;
			if (designation === 'expiry' && !present(target.expMonth) && !present(target.expYear) && value.length === 6) {
				target.expYear = value.slice(0, 4);
				target.expMonth = value.slice(4, 6).replace(/^0/, '');
				continue;
			}
		} else if (item.type === 4) {
			key = lookup({
				firstname: 'firstName',
				lastname: 'lastName',
				initial: 'middleName',
				defphone: 'phone',
				company: 'company',
				email: 'email',
				username: 'username',
			}, designation);
			if (designation === 'address') {
				const address = object(raw);
				for (const [from, to] of Object.entries({ street: 'address1', city: 'city', zip: 'postalCode' })) {
					target[to] = present(address[from]) ? address[from] : null;
				}
				if (present(address.country)) target.country = address.country.toUpperCase();
				continue;
			}
		}
		if (key && !present(target[key])) {
			target[key] = value;
			if (item.type === 3 && key === 'number') target.brand = brand(value);
			continue;
		}
		const name = field[section ? 't' : 'name'];
		if (name === 'password' && item.passwordHistory?.some(h => h.password === value)) continue;
		custom(item, present(name) ? name : 'no_name', value, field.k === 'concealed' ? 1 : 0);
	}
}
/** 1PIF's record separators are non-JSON lines; each JSON object occupies one physical line. */
export function parseOnePassword1Pif(source: string, organization = false): JsonObject {
	const items: VaultItem[] = [];
	for (const line of source.split(/\r\n|\r|\n/)) {
		if (!line.startsWith('{')) continue;
		let raw: JsonObject;
		try {
			raw = object(JSON.parse(line));
		} catch {
			throw new Error('Invalid 1PIF JSON record.');
		}
		if (raw.trashed === true) continue;
		const item = login();
		const opvault = present(raw.hmac);
		const overview = opvault ? object(raw.overview ?? {}) : raw;
		item.name = present(overview.title) ? overview.title : '--';
		const details = object((opvault ? raw.details : raw.secureContents) ?? {});
		if (opvault) {
			item.login!.uris = uris(rows(overview.URLs).map(v => v.u));
			if (present(details.ccnum) || present(details.cvv)) item.type = 3;
			else if (present(details.firstname) || present(details.address1)) item.type = 4;
		} else {
			item.favorite = !!(raw.openContents && object(raw.openContents).faveIndex);
			if (raw.typeName === 'securenotes.SecureNote') item.type = 2;
			else if (raw.typeName === 'wallet.financial.CreditCard') item.type = 3;
			else if (raw.typeName === 'identities.Identity') item.type = 4;
			else item.login!.uris = uris([raw.location]);
		}
		if (item.type === 2) item.secureNote = { type: 0 };
		if (item.type === 3) item.card = {};
		if (item.type === 4) item.identity = {};
		if (details.passwordHistory != null) item.passwordHistory = history(details.passwordHistory);
		if (present(details.notesPlain)) item.notes = details.notesPlain.replace(/\r\n|\r/g, '\n') + '\n';
		if (item.type === 1) {
			if (present(details.password)) item.login!.password = details.password;
			if (!opvault) {
				const urls = uris(rows(details.URLs).map(v => v.url));
				if (urls.length) item.login!.uris = urls;
			}
		}
		fields(item, rows(details.fields), false);
		for (const section of rows(details.sections)) fields(item, rows(section.fields), true);
		items.push(finish(item));
	}
	return { encrypted: false, items, [organization ? 'collections' : 'folders']: [] };
}

export type OnePasswordCsvFormat = '1passwordmaccsv' | '1passwordwincsv';
/** Legacy CSV uses vendor-specific headings and backslash-escaped quote characters. */
export function parseOnePasswordCsv(format: OnePasswordCsvFormat, source: string, organization = false): JsonObject {
	const parsed = parseCsv(source, '\\'), header = parsed.shift();
	if (!header?.length || !header.some(h => h.toLowerCase() === 'title')) {
		throw new Error('Missing 1Password CSV title column.');
	}
	if (new Set(header.map(h => h.toLowerCase())).size !== header.length) {
		throw new Error('Duplicate 1Password CSV headers.');
	}
	const windows = format === '1passwordwincsv', items: VaultItem[] = [];
	const ignored = new Set(['ainfo', 'autosubmit', 'notesplain', 'ps', 'scope', 'tags', 'title', 'uuid', 'notes']);
	for (const row of parsed) {
		if (row.every(v => !v)) continue;
		if (row.length !== header.length) throw new Error('Invalid 1Password CSV record width.');
		const pairs = header.map((key, i) => [key, row[i]!] as const);
		const value = (name: string): string => pairs.find(([key]) => key.toLowerCase() === name)?.[1] ?? '';
		if (!present(value('title'))) continue;
		const match = (re: RegExp): boolean => pairs.some(([key, v]) => re.test(key) && present(v));
		const item = login();
		item.name = value('title');
		item.notes = `${present(value('notesplain')) ? value('notesplain') : ''}\n${
			present(value('notes')) ? value('notes') : ''
		}\n`;
		const type = value('type') || 'Login';
		if (windows) {
			if (type === 'Credit Card' || match(/\d+: (?:number|verification number|expiry date)(?:$|\s)/i)) item.type = 3;
			if (match(/name \d+: (first name|initial|last name)/i) || match(/internet \d+: email/i)) item.type = 4;
		} else if (type === 'Credit Card') item.type = 3;
		else if (type === 'Identity') item.type = 4;
		if (item.type === 3) item.card = {};
		if (item.type === 4) item.identity = {};
		let alternate: string | null = null;
		for (const [name, v] of pairs) {
			if (!present(v)) continue;
			const lower = name.toLowerCase();
			const target = item.type === 1 ? item.login! : item.type === 3 ? item.card! : item.identity!;
			let key: string | undefined;
			if (item.type === 1) {
				if (lower === 'username' || lower === 'password') key = lower;
				else if (lower === 'urls' && !(target.uris as unknown[]).length) {
					target.uris = uris(v.split(/\r\n|\r|\n/));
					continue;
				} else if (lower === 'url') {
					// Preserve the URL; the reference's unassigned concat loses this value.
					target.uris = [...target.uris as JsonObject[], ...uris([v])];
					continue;
				}
			} else if (item.type === 3) {
				if (
					(windows ? /:\s*(?:card )?number$/.test(lower) : /^(?:card )?number$/.test(lower)) && !present(target.number)
				) {
					target.number = v;
					target.brand = brand(v);
					continue;
				}
				if (lower.includes('verification number')) key = 'code';
				else if (lower.includes('cardholder name')) key = 'cardholderName';
				else if (lower.includes('expiry date') && !present(target.expMonth) && !present(target.expYear)) {
					if (windows) {
						const parts = v.split('/');
						if (parts.length < 3) throw new Error('Invalid Windows 1Password card expiry date.');
						target.expMonth = parts[0]!.replace(/^0(?=\d$)/, '');
						target.expYear = parts[2]!.slice(0, 4);
						continue;
					} else if (v.length === 7) {
						target.expMonth = v.slice(0, 2).replace(/^0/, '');
						target.expYear = v.slice(3, 7);
						continue;
					}
				}
			} else if (item.type === 4) {
				for (
					const [part, mapped] of Object.entries({
						'first name': 'firstName',
						initial: 'middleName',
						'last name': 'lastName',
						username: 'username',
						email: 'email',
						'default phone': 'phone',
						company: 'company',
					})
				) {
					if (lower.includes(part) && !present(target[mapped])) {
						key = mapped;
						break;
					}
				}
				if (!key && windows && /address \d+: address/i.test(lower)) {
					custom(item, 'address', v);
					continue;
				}
			}
			if (key && !present(target[key])) {
				target[key] = v;
				continue;
			}
			if (
				ignored.has(lower) || lower.startsWith('section:') || lower.startsWith('section ')
				|| !windows && lower === 'type' && ['Login', 'Secure Note', 'Credit Card', 'Identity'].includes(type)
			) {
				alternate = null;
				continue;
			}
			if (alternate == null && lower === 'email') {
				alternate = v;
				continue;
			}
			if (lower === 'created date' || lower === 'modified date') {
				custom(item, `1Password ${name}`, new Date(parseInt(v, 10) * 1000).toUTCString());
			} else custom(item, name, v, /password|key|secret/.test(lower) ? 1 : 0);
			alternate = null;
		}
		if (item.type === 1 && alternate && !alternate.includes('://') && !present(item.login!.username)) {
			item.login!.username = alternate;
		}
		items.push(finish(item));
	}
	return { encrypted: false, items, [organization ? 'collections' : 'folders']: [] };
}
