import { randomUUID } from 'node:crypto';
import { getHostname } from 'tldts';
import { parseCsv } from '#csv';
import type { JsonObject } from '#client';
import type { VaultItem } from '#models';

export const externalCsvFormats = [
	'chromecsv',
	'edgecsv',
	'operacsv',
	'vivaldicsv',
	'bravecsv',
	'arccsv',
	'aviracsv',
	'firefoxcsv',
	'safaricsv',
	'keepassxcsv',
	'lastpasscsv',
	'passboltcsv',
	'nordpasscsv',
] as const;
export type ExternalCsvFormat = typeof externalCsvFormats[number];
export function isExternalCsvFormat(value: string): value is ExternalCsvFormat {
	return (externalCsvFormats as readonly string[]).includes(value);
}
const present = (value: string | undefined): string | null => value?.trim() ? value : null;
function uris(value?: string): JsonObject[] {
	let uri = value?.trim();
	if (!uri) return [];
	if (!uri.includes('://') && uri.includes('.')) uri = `http://${uri}`;
	return [{ uri: uri.slice(0, 1000), match: null }];
}
function login(name?: string): VaultItem {
	return {
		type: 1,
		name: present(name) ?? '--',
		favorite: false,
		reprompt: 0,
		notes: null,
		fields: [],
		login: { username: null, password: null, totp: null, uris: [] },
	};
}
function brand(number: string | null): string | null {
	if (!number) return null;
	const n = number.replace(/\s/g, '');
	if (/^4/.test(n)) return 'Visa';
	if (/^5[1-5]/.test(n) || (Number(n.slice(0, 4)) >= 2221 && Number(n.slice(0, 4)) <= 2720)) return 'Mastercard';
	if (/^3[47]/.test(n)) return 'Amex';
	if (/^6(?:011|5|4[4-9])/.test(n)) return 'Discover';
	if (/^35/.test(n)) return 'JCB';
	if (/^3(?:0[0-5]|[68])/.test(n)) return 'Diners Club';
	if (/^62/.test(n)) return 'UnionPay';
	return null;
}
function lastPassCard(row: Record<string, string>): JsonObject {
	const number = present(row.ccnum),
		result: JsonObject = {
			cardholderName: present(row.ccname),
			number,
			code: present(row.cccsc),
			brand: brand(number),
		};
	const expiration = row.ccexp?.split('-');
	if (expiration && expiration.length > 1) {
		result.expYear = expiration[0];
		result.expMonth = expiration[1]!.replace(/^0/, '');
	}
	return result;
}
const identityColumns: Record<string, string> = {
	title: 'title',
	firstname: 'firstName',
	middlename: 'middleName',
	lastname: 'lastName',
	username: 'username',
	company: 'company',
	ssn: 'ssn',
	address1: 'address1',
	address2: 'address2',
	address3: 'address3',
	city: 'city',
	state: 'state',
	zip: 'postalCode',
	country: 'country',
	email: 'email',
	phone: 'phone',
};
const addressFields: Record<string, string> = {
	Title: 'title',
	'First Name': 'firstName',
	'Last Name': 'lastName',
	'Middle Name': 'middleName',
	Company: 'company',
	'Address 1': 'address1',
	'Address 2': 'address2',
	'Address 3': 'address3',
	'City / Town': 'city',
	State: 'state',
	'Zip / Postal Code': 'postalCode',
	Country: 'country',
	'Email Address': 'email',
	Username: 'username',
};
/** Structured notes retain unknown fields and every continuation after Notes:. */
function structuredNote(item: VaultItem, extra: string): void {
	const lines = extra.split(/\r\n|\r|\n/), type = lines[0]?.slice('NoteType:'.length);
	if (!lines[0]?.startsWith('NoteType:') || !['Credit Card', 'Address'].includes(type!)) {
		item.type = 2;
		delete item.login;
		item.secureNote = { type: 0 };
		item.notes = present(extra);
		return;
	}
	const mapping: Record<string, string> = type === 'Address' ? addressFields : {
		Number: 'number',
		'Name on Card': 'cardholderName',
		'Security Code': 'code',
		'Expiration Date': 'expiration',
	};
	const values: JsonObject = {};
	let notes = false;
	for (const line of lines.slice(1)) {
		if (notes) {
			item.notes = `${item.notes ?? ''}\n${line}`;
			continue;
		}
		const colon = line.indexOf(':');
		if (colon < 0) continue;
		const key = line.slice(0, colon), value = line.slice(colon + 1);
		if (!present(value)) continue;
		if (key === 'Notes') {
			item.notes = `${item.notes ? `${item.notes}\n` : ''}${value}`;
			notes = true;
		} else if (Object.hasOwn(mapping, key)) values[mapping[key]!] = value;
		else if (value.length > 200) item.notes = `${item.notes ?? ''}${key}: ${value}\n`;
		else item.fields!.push({ name: key, value, type: 0 });
	}
	delete item.login;
	if (type === 'Address') {
		item.type = 4;
		item.identity = values;
		return;
	}
	item.type = 3;
	const expiration = typeof values.expiration === 'string' ? values.expiration.split(',') : [];
	delete values.expiration;
	const months = [
		'january',
		'february',
		'march',
		'april',
		'may',
		'june',
		'july',
		'august',
		'september',
		'october',
		'november',
		'december',
	];
	const month = months.indexOf(expiration[0]?.trim().toLowerCase() ?? '');
	if (month >= 0) values.expMonth = String(month + 1);
	if (present(expiration[1])) values.expYear = expiration[1];
	item.card = values;
}
function lastPass(row: Record<string, string>, organization: boolean, formFill: boolean): VaultItem[] {
	const item = login(formFill ? row.profilename : row.name);
	if (formFill) {
		const identity = ['title', 'firstname', 'lastname', 'address1', 'phone', 'username', 'email'].some(key =>
			present(row[key])
		);
		item.type = identity ? 4 : 3;
		delete item.login;
		item.notes = present(row.notes);
		if (!identity) {
			item.card = lastPassCard(row);
			return [item];
		}
		item.identity = Object.fromEntries(
			Object.entries(identityColumns).map(([source, target]) => [target, present(row[source])]),
		);
		const title = item.identity.title;
		if (typeof title === 'string' && title) item.identity.title = title[0]!.toUpperCase() + title.slice(1);
		return present(row.ccnum) ? [{ ...item, type: 3, identity: undefined, card: lastPassCard(row) }, item] : [item];
	}
	item.favorite = !organization && row.fav === '1';
	if (row.url === 'http://sn') structuredNote(item, row.extra ?? '');
	else {
		item.notes = present(row.extra);
		item.login = {
			username: present(row.username),
			password: present(row.password),
			totp: present(row.totp),
			uris: uris(row.url),
		};
	}
	return [item];
}
function nordPassArray(value: string, column: string): unknown[] {
	let result: unknown;
	try {
		result = JSON.parse(value);
	} catch {
		throw new Error(`Invalid NordPass ${column} JSON.`);
	}
	if (!Array.isArray(result)) throw new Error(`Invalid NordPass ${column} array.`);
	return result;
}
function nordPass(row: Record<string, string>): VaultItem[] {
	if (!['password', 'credit_card', 'identity', 'note'].includes(row.type ?? '')) return [];
	const item = login(row.name);
	item.notes = present(row.note);
	if (row.custom_fields) {
		for (const field of nordPassArray(row.custom_fields, 'custom_fields')) {
			if (!field || typeof field !== 'object') throw new Error('Invalid NordPass custom field.');
			const { label, value, type } = field as Record<string, unknown>;
			if (typeof value !== 'string' || (label != null && typeof label !== 'string')) {
				throw new Error('Invalid NordPass custom field.');
			}
			if (!present(value)) continue;
			const name = typeof label === 'string' && label.trim() ? label : '';
			if (value.length > 200 || /[\r\n]/.test(value.trim())) {
				item.notes = `${item.notes ?? ''}${name}: ${value.replace(/\r\n|\r/g, '\n')}\n`;
			} else item.fields!.push({ name, value, type: type === 'hidden' ? 1 : 0 });
		}
	}
	if (row.type === 'password') {
		const additional = row.additional_urls ? nordPassArray(row.additional_urls, 'additional_urls') : [];
		if (additional.some(value => typeof value !== 'string')) throw new Error('Invalid NordPass additional URL.');
		item.login = {
			username: present(row.username),
			password: present(row.password),
			totp: null,
			uris: [row.url, ...additional as string[]].flatMap(value => uris(value)),
		};
		return [item];
	}
	delete item.login;
	if (row.type === 'note') {
		item.type = 2;
		item.secureNote = { type: 0 };
	} else if (row.type === 'credit_card') {
		item.type = 3;
		const number = present(row.cardnumber);
		item.card = { cardholderName: present(row.cardholdername), number, code: present(row.cvc), brand: brand(number) };
		const expiry = row.expirydate?.replace(/\s/g, '').match(/^0?([1-9]|1[0-2])\/((?:[1-2][0-9])?[0-9]{2})$/);
		if (expiry) {
			item.card.expMonth = expiry[1];
			item.card.expYear = expiry[2]!.length === 2
				? `${String(new Date().getFullYear()).slice(0, 2)}${expiry[2]}`
				: expiry[2];
		}
	} else {
		item.type = 4;
		const parts = present(row.full_name)?.split(' ') ?? [];
		item.identity = {
			firstName: present(parts[0]),
			middleName: parts.length >= 3 ? present(parts[1]) : null,
			lastName: parts.length >= 3 ? parts.slice(2).join(' ') : present(parts[1]),
			address1: present(row.address1),
			address2: present(row.address2),
			city: present(row.city),
			state: present(row.state),
			postalCode: present(row.zipcode),
			country: present(row.country)?.toUpperCase() ?? null,
			email: present(row.email),
			phone: present(row.phone_number),
		};
	}
	return [item];
}
/** Parse external CSV into the same document consumed by the native encrypted importer. */
export function parseExternalCsv(format: ExternalCsvFormat, source: string, organization = false): JsonObject {
	// The reference routes these vendor IDs through the same parsers.
	if (format === 'edgecsv' || format === 'operacsv' || format === 'vivaldicsv' || format === 'bravecsv') {
		format = 'chromecsv';
	}
	if (format === 'passboltcsv') format = 'lastpasscsv';
	const rows = parseCsv(source), header = rows.shift();
	if (!header?.length) throw new Error('CSV is empty.');
	if (new Set(header).size !== header.length) throw new Error('Duplicate CSV headers.');
	const formFill = format === 'lastpasscsv' && header.includes('profilename') && header.includes('profilelanguage');
	const required = format === 'nordpasscsv'
		? ['type']
		: format === 'keepassxcsv'
		? ['Title', 'Username', 'Password', 'URL']
		: format === 'safaricsv'
		? ['Title', 'Username', 'Password']
		: formFill
		? ['profilename', 'profilelanguage']
		: format === 'lastpasscsv'
		? ['url', 'username', 'password', 'name', 'extra']
		: ['username', 'password'];
	if (!required.every(value => header.includes(value))) throw new Error(`Missing required ${format} CSV columns.`);
	if (
		!formFill && format !== 'nordpasscsv' && !(format === 'safaricsv'
			? ['Url', 'URL']
			: format === 'keepassxcsv'
			? ['URL']
			: format === 'aviracsv'
			? ['website']
			: ['url', ...(format === 'firefoxcsv' ? ['hostname'] : [])]).some(value => header.includes(value))
	) {
		throw new Error(`Missing ${format} URL column.`);
	}
	const items: VaultItem[] = [], groups: JsonObject[] = [], groupIds = new Map<string, string>();
	for (const row of rows) {
		if (row.every(value => !value)) continue;
		if (row.length !== header.length) throw new Error('CSV row has an unexpected number of fields.');
		const values: Record<string, string> = Object.create(null);
		header.forEach((name, i) => {
			values[name] = row[i]!;
		});
		if (format === 'firefoxcsv' && values.url === 'chrome://FirefoxAccounts') continue;
		if (format === 'keepassxcsv' && !present(values.Title)) continue;
		let entries: VaultItem[], folder: string | null = null;
		if (format === 'nordpasscsv') {
			entries = nordPass(values);
			if (!entries.length) continue;
			folder = present(values.folder?.replace(/\\/g, '/').replace(/^\/+/, ''));
		} else if (format === 'lastpasscsv') {
			entries = lastPass(values, organization, formFill);
			folder = present(values.grouping?.replace(/\\/g, '/').replace(/\p{Cc}/gu, ''));
			if (folder === '(none)') folder = null;
		} else {
			let url = format === 'aviracsv' ? values.website : values.url ?? values.hostname;
			let name = values.name;
			if (format === 'chromecsv' && url?.startsWith('android://')) {
				const at = url.indexOf('@');
				if (at >= 0) {
					const end = url.indexOf('/', at + 1), app = url.slice(at + 1, end < 0 ? undefined : end);
					url = `androidapp://${app}`;
					if (!present(name)) name = app;
				}
			}
			if (format === 'firefoxcsv' || format === 'arccsv') name = getHostname(url ?? '')?.replace(/^www\./, '');
			if (format === 'aviracsv' && !present(name)) name = getHostname(url ?? '')?.replace(/^www\./, '');
			if (format === 'safaricsv' || format === 'keepassxcsv') {
				name = values.Title;
				url = values.Url ?? values.URL;
			}
			const item = login(name);
			const upper = format === 'safaricsv' || format === 'keepassxcsv';
			item.login = {
				username: present(upper ? values.Username : values.username),
				password: present(upper ? values.Password : values.password),
				totp: present(format === 'safaricsv' ? values.OTPAuth : format === 'keepassxcsv' ? values.TOTP : undefined),
				uris: uris(url),
			};
			item.notes = present(
				format === 'chromecsv' || format === 'arccsv' ? values.note : upper ? values.Notes : undefined,
			);
			if (format === 'aviracsv') {
				if (!present(values.username) && present(values.secondary_username)) {
					item.login.username = values.secondary_username;
				} else item.notes = present(values.secondary_username);
			}
			if (format === 'keepassxcsv') {
				folder = present(values.Group?.replace(/^Root\//, '')?.replace(/\\/g, '/')?.replace(/^\/+/, ''));
			}
			entries = [item];
		}
		let groupId: string | null = null;
		if (folder) {
			groupId = groupIds.get(folder) ?? randomUUID();
			if (!groupIds.has(folder)) {
				groupIds.set(folder, groupId);
				groups.push({ id: groupId, name: folder });
			}
		}
		for (const item of entries) {
			item.folderId = organization ? null : groupId;
			item.collectionIds = organization && groupId ? [groupId] : [];
			items.push(item);
		}
	}
	return { encrypted: false, items, [organization ? 'collections' : 'folders']: groups };
}
