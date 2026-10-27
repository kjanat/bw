import { randomUUID } from 'node:crypto';
import { parse as parseHtml } from 'parse5';
import type { DefaultTreeAdapterTypes } from 'parse5';
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
	'encryptrcsv',
	'passkeepcsv',
	'passwordwallettxt',
	'passpackcsv',
	'ascendocsv',
	'blackberrycsv',
	'blurcsv',
	'codebookcsv',
	'avastcsv',
	'buttercupcsv',
	'padlockcsv',
	'yoticsv',
	'saferpasscsv',
	'securesafecsv',
	'meldiumcsv',
	'splashidcsv',
	'truekeycsv',
	'remembearcsv',
	'upmcsv',
	'logmeoncecsv',
	'mykicsv',
	'msecurecsv',
	'enpasscsv',
	'passwordagentcsv',
	'dashlanecsv',
	'delineacsv',
	'zohovaultcsv',
	'roboformcsv',
	'keepercsv',
	'passwordxpcsv',
	'netwrixpasswordsecure',
] as const;

function lastPassCsv(source: string): string {
	// LastPass exports can be downloaded as an HTML page whose CSV is held in a
	// <pre>. Parse it as inert HTML so entities are decoded just as they are by
	// the reference importer's DOM text extraction.
	if (!/<\s*(?:!doctype\s+html|html|body|pre)\b/i.test(source)) return source;
	const findPre = (node: DefaultTreeAdapterTypes.Node): DefaultTreeAdapterTypes.Element | undefined => {
		if ('tagName' in node && node.tagName === 'pre') return node;
		const children = 'childNodes' in node ? node.childNodes : [];
		for (const child of children) {
			const match = findPre(child);
			if (match) return match;
		}
		return undefined;
	};
	const textContent = (node: DefaultTreeAdapterTypes.Node): string => {
		if (node.nodeName === '#text' && 'value' in node) return node.value;
		const children = 'childNodes' in node ? node.childNodes : [];
		return children.map(textContent).join('');
	};
	const pre = findPre(parseHtml(source));
	if (!pre) throw new Error('LastPass HTML export is missing its CSV data.');
	return textContent(pre);
}
export type ExternalCsvFormat = typeof externalCsvFormats[number];
export function isExternalCsvFormat(value: string): value is ExternalCsvFormat {
	return (externalCsvFormats as readonly string[]).includes(value);
}
const present = (value: string | undefined): string | null => value?.trim() ? value : null;
const genericPasswordFields = new Set([
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
const genericUsernameFields = new Set([
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
const genericUriFields = new Set([
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
/** Structured notes include unknown fields and every continuation after Notes:. */
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
function encryptr(row: Record<string, string>): VaultItem {
	const item = login(row.Label);
	item.notes = present(row.Notes);
	const text = present(row.Text);
	if (text) item.notes = item.notes ? `${item.notes}\n\n${text}` : text;
	if (row['Entry Type'] === 'Password') {
		item.login = {
			username: present(row.Username),
			password: present(row.Password),
			totp: null,
			uris: uris(row['Site URL']),
		};
	} else if (row['Entry Type'] === 'Credit Card') {
		const number = present(row['Card Number']);
		item.type = 3;
		delete item.login;
		const card: JsonObject = {
			cardholderName: present(row['Name on card']),
			brand: brand(number),
			number,
			code: present(row.CVV),
		};
		const expiry = present(row.Expiry);
		if (expiry) {
			const [month, year] = expiry.split('/');
			if (year !== undefined) {
				card.expMonth = String(Number.parseInt(month!, 10));
				card.expYear = String(2000 + Number.parseInt(year, 10));
			}
		}
		item.card = card;
	} else if (row['Entry Type'] !== 'Password') {
		item.type = 2;
		delete item.login;
		item.secureNote = { type: 0 };
	}
	return item;
}
function passKeep(row: Record<string, string>): VaultItem {
	const value = (key: string) => row[key] ?? row[` ${key}`];
	const item = login(value('title'));
	item.notes = present(value('description'));
	item.login = {
		username: present(value('username')),
		password: present(value('password')),
		totp: null,
		uris: uris(value('site')),
	};
	const password2 = present(value('password2'));
	if (password2) item.fields!.push({ name: 'Password 2', value: password2, type: 0 });
	return item;
}
function passPack(row: Record<string, string>): { item: VaultItem; tags: string[] } {
	const parse = (column: string): Record<string, unknown> | null => {
		const source = present(row[column]);
		if (!source) return null;
		try {
			const value: unknown = JSON.parse(source);
			return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
		} catch {
			throw new Error(`Invalid Passpack ${column} JSON.`);
		}
	};
	const tagsDocument = parse('Tags'), tagValues = Array.isArray(tagsDocument?.tags) ? tagsDocument.tags : [];
	const tags = tagValues.flatMap(value => {
		if (typeof value !== 'string') return [];
		try {
			const tag: unknown = JSON.parse(value);
			return tag && typeof tag === 'object' && typeof (tag as Record<string, unknown>).tag === 'string'
				? [(tag as Record<string, string>).tag]
				: [];
		} catch {
			return [];
		}
	}).filter((value): value is string => !!present(value));
	const item = login(row['Entry Name']);
	item.notes = `${row.Notes ?? ''}\n\n${row['Shared Notes'] ?? ''}\n`;
	item.login = {
		username: present(row['User ID']),
		password: present(row.Password),
		totp: null,
		uris: uris(row.URL),
	};
	const fieldsDocument = parse('Extra Fields'),
		fieldValues = Array.isArray(fieldsDocument?.extraFields)
			? fieldsDocument.extraFields
			: [];
	for (const value of fieldValues) {
		if (typeof value !== 'string') continue;
		let fieldValue: unknown;
		try {
			fieldValue = JSON.parse(value);
		} catch {
			continue;
		}
		if (!fieldValue || typeof fieldValue !== 'object') continue;
		const field = fieldValue as Record<string, unknown>;
		if (typeof field.data === 'string' && present(field.data)) {
			const name = typeof field.name === 'string' ? field.name : '';
			if (field.data.length > 200 || /[\r\n]/.test(field.data)) {
				item.notes += `${name}: ${field.data.replace(/\r\n|\r/g, '\n')}\n`;
			} else item.fields!.push({ name, value: field.data, type: 0 });
		}
	}
	return { item, tags };
}
function trueKey(row: Record<string, string>): VaultItem {
	const item = login(row.kind === 'login' ? row.name : row.title);
	item.favorite = row.favorite?.toLowerCase() === 'true';
	item.notes = present(row.kind === 'login' ? row.memo : row.note);
	item.login = {
		username: present(row.login),
		password: present(row.password),
		totp: null,
		uris: uris(row.url),
	};
	if (row.kind === 'cc') {
		const number = present(row.number);
		item.type = 3;
		delete item.login;
		item.card = { cardholderName: present(row.cardholder), number, brand: brand(number) };
		if (present(row.expiryDate)) {
			const date = new Date(row.expiryDate!);
			item.card.expYear = String(date.getFullYear());
			item.card.expMonth = String(date.getMonth() + 1);
		}
	} else if (row.kind !== 'login') {
		item.type = 2;
		delete item.login;
		item.secureNote = { type: 0 };
		if (present(item.notes as string | undefined)) item.notes = present(row.document_content);
		const ignored = new Set([
			'kind',
			'autologin',
			'favorite',
			'hexcolor',
			'protectedwithpassword',
			'subdomainonly',
			'type',
			'tk_export_version',
			'note',
			'title',
			'document_content',
		]);
		for (const [name, value] of Object.entries(row)) {
			if (!ignored.has(name.toLowerCase())) customField(item, name, value);
		}
	}
	return item;
}
function customField(item: VaultItem, name: string, value: string): void {
	if (!present(name) || !present(value)) return;
	if (value.length > 200 || /[\r\n]/.test(value.trim())) {
		item.notes = `${item.notes ?? ''}${name}: ${value.replace(/\r\n|\r/g, '\n')}\n`;
	} else item.fields!.push({ name, value, type: 0 });
}
function enpassFieldName(value: string): string {
	return value.replace(/^\*/, '').trim().toLowerCase();
}
function enpassCsv(rows: string[][], organization: boolean): JsonObject {
	const items: VaultItem[] = [];
	let firstRow = true;
	for (const row of rows) {
		if (row.length < 2 || (firstRow && (row[0] === 'Title' || row[0] === 'title'))) {
			firstRow = false;
			continue;
		}
		firstRow = false;
		const item = login(row[0]);
		const hasTrailingNote = row.length % 2 === 0;
		if (hasTrailingNote) item.notes = present(row.at(-1));
		const pairsEnd = hasTrailingNote ? row.length - 1 : row.length;
		const labels = row.filter((_, index) => index % 2 === 1 && index < pairsEnd);
		if (
			row.length === 2
			|| !['username', 'password', 'email', 'e-mail', 'url', 'website'].some(key =>
				labels.some(label => enpassFieldName(label) === key)
			)
		) {
			item.type = 2;
			delete item.login;
			item.secureNote = { type: 0 };
		}
		if (
			['cardholder', 'number', 'expiry date'].every(key => labels.some(label => enpassFieldName(label) === key))
		) {
			item.type = 3;
			delete item.login;
			item.card = {};
			delete item.secureNote;
		}
		if (pairsEnd > 2) {
			for (let index = 0; index < pairsEnd - 1; index += 2) {
				const value = row[index + 2]!, fieldName = row[index + 1]!, normalized = enpassFieldName(fieldName);
				if (!value.trim()) continue;
				if (item.type === 1) {
					if (normalized === 'url' || normalized === 'website') {
						(item.login!.uris as JsonObject[]).push(...uris(value));
						continue;
					}
					if (
						(normalized === 'username' || normalized === 'email' || normalized === 'e-mail')
						&& !present(item.login!.username as string | undefined)
					) {
						item.login!.username = value;
						continue;
					}
					if (normalized === 'password' && !present(item.login!.password as string | undefined)) {
						item.login!.password = value;
						continue;
					}
					if (
						(normalized === 'totp' || normalized === 'one-time code')
						&& !present(item.login!.totp as string | undefined)
					) {
						item.login!.totp = value;
						continue;
					}
				} else if (item.type === 3) {
					const card = item.card!;
					if (normalized === 'cardholder' && !present(card.cardholderName as string | undefined)) {
						card.cardholderName = value;
						continue;
					}
					if (normalized === 'number' && !present(card.number as string | undefined)) {
						card.number = value;
						card.brand = brand(value);
						continue;
					}
					if (normalized === 'cvc' && !present(card.code as string | undefined)) {
						card.code = value;
						continue;
					}
					if (
						normalized === 'expiry date' && !present(card.expMonth as string | undefined)
						&& !present(card.expYear as string | undefined)
					) {
						const expiration = value.replace(/\s/g, '').match(/^0?([1-9]|1[0-2])\/((?:[1-2][0-9])?[0-9]{2})$/);
						if (expiration) {
							card.expMonth = expiration[1]!;
							card.expYear = expiration[2]!.length === 2
								? `${String(new Date().getFullYear()).slice(0, 2)}${expiration[2]}`
								: expiration[2]!;
							continue;
						}
					}
					if (normalized === 'type') continue;
				}
				const sensitive = fieldName.startsWith('*'), name = sensitive ? fieldName.slice(1).trim() : fieldName;
				if (value.length > 200 || /[\r\n]/.test(value.trim())) {
					item.notes = `${item.notes ?? ''}${name}: ${value.replace(/\r\n|\r/g, '\n')}\n`;
				} else item.fields!.push({ name, value, type: sensitive ? 1 : 0 });
			}
		}
		if (item.type !== 1) delete item.login;
		items.push(item);
	}
	return { encrypted: false, items, [organization ? 'collections' : 'folders']: [] };
}
function noteIfEmpty(item: VaultItem): void {
	const username = item.login?.username, password = item.login?.password, uris = item.login?.uris;
	if (
		item.login && !(typeof username === 'string' && present(username))
		&& !(typeof password === 'string' && present(password))
		&& !(Array.isArray(uris) && uris.length)
	) {
		item.type = 2;
		delete item.login;
		item.secureNote = { type: 0 };
	}
}
function myki(row: Record<string, string>): VaultItem | null {
	const item = login(row.nickname);
	item.notes = present(row.additionalInfo)?.trimEnd() ?? null;
	const base = ['nickname', 'additionalInfo'];
	let mapped: Set<string>;
	if (row.url !== undefined) {
		item.login = {
			username: present(row.username),
			password: present(row.password),
			totp: present(row.twofaSecret),
			uris: uris(row.url),
		};
		mapped = new Set([...base, 'url', 'username', 'password', 'twofaSecret']);
	} else if (row.authToken !== undefined) {
		item.login!.totp = present(row.authToken);
		mapped = new Set([...base, 'authToken']);
	} else if (row.cardNumber !== undefined) {
		const number = present(row.cardNumber), month = present(row.exp_month), year = present(row.exp_year);
		item.type = 3;
		delete item.login;
		item.card = {
			cardholderName: present(row.cardName),
			number,
			brand: brand(number),
			expMonth: month,
			expYear: year,
			code: present(row.cvv),
		};
		mapped = new Set([...base, 'cardNumber', 'cardName', 'exp_month', 'exp_year', 'cvv']);
	} else if (row.firstName !== undefined) {
		item.type = 4;
		delete item.login;
		item.identity = {
			title: present(row.title),
			firstName: present(row.firstName),
			middleName: present(row.middleName),
			lastName: present(row.lastName),
			phone: present(row.number),
			email: present(row.email),
			address1: present(row.firstAddressLine),
			address2: present(row.secondAddressLine),
			city: present(row.city),
			country: present(row.country),
			postalCode: present(row.zipCode),
		};
		mapped = new Set([
			...base,
			'title',
			'firstName',
			'middleName',
			'lastName',
			'email',
			'firstAddressLine',
			'secondAddressLine',
			'city',
			'country',
			'zipCode',
		]);
	} else if (row.idType !== undefined) {
		const parts = present(row.idName)?.split(' ') ?? [];
		item.type = 4;
		delete item.login;
		item.identity = {
			firstName: present(parts[0]),
			middleName: parts.length >= 3 ? present(parts[1]) : null,
			lastName: parts.length >= 3 ? parts.slice(2).join(' ') : present(parts[1]),
			country: present(row.idCountry),
		};
		if (row.idType === 'Passport') item.identity.passportNumber = present(row.idNumber);
		else if (row.idType === 'Social Security') item.identity.ssn = present(row.idNumber);
		else item.identity.licenseNumber = present(row.idNumber);
		mapped = new Set([...base, 'idName', 'idNumber', 'idCountry']);
	} else if (row.content !== undefined) {
		item.type = 2;
		delete item.login;
		item.secureNote = { type: 0 };
		item.notes = present(row.content)?.trimEnd() ?? null;
		mapped = new Set([...base, 'content']);
	} else return null;
	for (const [key, value] of Object.entries(row)) {
		if (!mapped.has(key)) customField(item, key, value);
	}
	return item;
}
function msecureValue(value: string | undefined): string | null {
	if (value === undefined) return null;
	const parts = value.split('|');
	return parts.length > 2 ? parts.slice(2).join('|') : parts.at(-1) ?? null;
}
function dashlaneCsv(header: string[], rows: string[][], organization: boolean): JsonObject {
	if (new Set(header).size !== header.length) throw new Error('Duplicate CSV headers.');
	const records = rows.filter(row => !row.every(value => !value)).map(row => {
		if (row.length !== header.length) throw new Error('CSV row has an unexpected number of fields.');
		const record: Record<string, string> = Object.create(null);
		header.forEach((key, i) => record[key] = row[i]!);
		return record;
	});
	const items: VaultItem[] = [], groups: JsonObject[] = [], groupIds = new Map<string, string>();
	const addFields = (item: VaultItem, record: Record<string, string>, mapped: Set<string>) => {
		for (const [key, value] of Object.entries(record)) {
			if (!mapped.has(key)) customField(item, key, value);
		}
	};
	if (
		records[0]?.type && records[0].title
		&& records.filter(record => record.type === 'name').length === 1
	) {
		const identity = login();
		identity.type = 4;
		delete identity.login;
		identity.identity = {};
		const mapped = new Set([
			'type',
			'title',
			'first_name',
			'middle_name',
			'last_name',
			'login',
			'email',
			'phone_number',
			'address',
			'country',
			'state',
			'city',
			'zip',
			'item_name',
		]);
		for (const record of records) {
			switch (record.type) {
				case 'name': {
					const firstName = present(record.first_name),
						middleName = present(record.middle_name),
						lastName = present(record.last_name);
					identity.identity.firstName = firstName;
					identity.identity.middleName = middleName;
					identity.identity.lastName = lastName;
					identity.identity.title = present(record.title);
					identity.identity.username = present(record.login);
					identity.name = [firstName, middleName, lastName].filter(Boolean).join(' ') || '--';
					break;
				}
				case 'email':
					identity.identity.email = present(record.email);
					break;
				case 'number':
					identity.identity.phone = present(record.phone_number);
					break;
				case 'address':
					identity.identity.address1 = present(record.address);
					identity.identity.city = present(record.city);
					identity.identity.postalCode = present(record.zip);
					identity.identity.state = present(record.state);
					identity.identity.country = present(record.country);
					break;
			}
			addFields(identity, record, mapped);
		}
		items.push(identity);
	} else {
		for (const record of records) {
			const item = login(), keys = Object.keys(record);
			let folder: string | null = null;
			if (keys[0] === 'username') {
				item.name = present(record.title) ?? '--';
				item.login = {
					username: present(record.username),
					password: present(record.password),
					totp: present(Object.hasOwn(record, 'otpUrl') ? record.otpUrl : record.otpSecret),
					uris: uris(record.url),
				};
				item.notes = present(record.note);
				folder = present(record.category);
				addFields(item, record, new Set(['title', 'note', 'username', 'password', 'url', 'otpSecret', 'category']));
			} else if (keys[0] === 'type' && keys[1] === 'account_name') {
				item.type = 3;
				delete item.login;
				item.name = present(record.account_name) ?? '--';
				item.card = {};
				let mapped: string[] = [];
				if (record.type === 'credit_card') {
					const number = present(record.cc_number),
						expiry = `${record.expiration_month ?? ''}/${record.expiration_year ?? ''}`
							.replace(/\s/g, '').match(/^0?([1-9]|1[0-2])\/((?:[1-2][0-9])?[0-9]{2})$/);
					item.card = {
						cardholderName: present(record.account_name),
						number,
						brand: brand(number),
						code: present(record.code),
					};
					if (expiry) {
						const digits = expiry[2]!.replace(/[^\d]/g, '').replace(/^[0]+(?=.)/, '');
						item.card.expMonth = expiry[1];
						item.card.expYear = digits.length === 4
							? digits
							: `${String(new Date().getFullYear()).slice(0, 2)}${digits.slice(-2)}`;
					}
					mapped = ['account_name', 'account_holder', 'cc_number', 'code', 'expiration_month', 'expiration_year'];
				} else if (record.type === 'bank') {
					item.card = {
						cardholderName: present(record.account_holder),
						number: present(record.account_number),
					};
					mapped = ['account_name', 'account_holder', 'account_number'];
				}
				addFields(item, record, new Set(mapped));
			} else if (keys[0] === 'type' && keys[1] === 'number') {
				item.type = 4;
				delete item.login;
				item.identity = {};
				const name = present(record.name), parts = name?.split(' ') ?? [];
				if (
					record.type === 'card' || record.type === 'passport' || record.type === 'license'
					|| record.type === 'social_security'
				) {
					item.name = `${name ?? ''} ${record.type}`.trim();
				}
				if (record.type === 'tax_number') item.name = record.type;
				if (
					record.type === 'card' || record.type === 'passport' || record.type === 'license'
					|| record.type === 'social_security'
				) {
					item.identity.firstName = present(parts[0]);
					item.identity.middleName = parts.length >= 3 ? present(parts[1]) : null;
					item.identity.lastName = parts.length >= 3 ? parts.slice(2).join(' ') : present(parts[1]);
				}
				if (record.type === 'card' || record.type === 'license') item.identity.licenseNumber = present(record.number);
				else if (record.type === 'passport') item.identity.passportNumber = present(record.number);
				else if (record.type === 'social_security') item.identity.ssn = present(record.number);
				else if (record.type === 'tax_number') item.identity.licenseNumber = present(record.number);
				if (record.type === 'license') item.identity.state = present(record.state);
				const mapped = ['name', 'number'];
				if (record.type === 'license') mapped.push('state');
				addFields(item, record, new Set(mapped));
			} else if (keys[0] === 'type' && keys[1] === 'title') {
				item.type = 2;
				delete item.login;
				item.secureNote = { type: 0 };
				if (record.type === 'name') {
					item.name = `${record.title} ${record.first_name} ${record.middle_name} ${record.last_name}`
						.replace('  ', ' ').trim();
				} else item.name = present(record.item_name) ?? '--';
				addFields(item, record, new Set());
			} else if (keys[0] === 'title' && keys[1] === 'note') {
				item.type = 2;
				delete item.login;
				item.secureNote = { type: 0 };
				item.name = present(record.title) ?? '--';
				item.notes = present(record.note);
				addFields(item, record, new Set(['title', 'note']));
			}
			noteIfEmpty(item);
			let groupId: string | null = null;
			if (folder) {
				groupId = groupIds.get(folder) ?? randomUUID();
				if (!groupIds.has(folder)) {
					groupIds.set(folder, groupId);
					groups.push({ id: groupId, name: folder });
				}
			}
			item.folderId = organization ? null : groupId;
			item.collectionIds = organization && groupId ? [groupId] : [];
			items.push(item);
		}
	}
	return { encrypted: false, items, [organization ? 'collections' : 'folders']: groups };
}
function delineaCsv(header: string[], rows: string[][], organization: boolean): JsonObject {
	const items: VaultItem[] = [], groups: JsonObject[] = [], groupIds = new Map<string, string>();
	for (const row of rows) {
		const values = Object.fromEntries(header.map((key, index) => [key, row[index] ?? '']));
		const result = login(values['Secret Name']);
		if (values.URL) {
			result.login!.uris = uris(values.URL);
		} else {
			result.type = 2;
			delete result.login;
			result.secureNote = { type: 0 };
		}
		for (const [key, value] of Object.entries(values)) {
			if (key === 'Secret Name') continue;
			if (key === 'Password' && result.type === 1) result.login!.password = value;
			else if (key === 'URL' && result.type === 1) result.login!.uris = uris(value);
			else if (key === 'Username' && result.type === 1) result.login!.username = value;
			else if (key === 'Folder') {
				if (present(value)) {
					const folder = value.replace(/\\/g, '/').replace(/^\/+/, ''), id = groupIds.get(folder) ?? randomUUID();
					if (!groupIds.has(folder)) {
						groupIds.set(folder, id);
						groups.push({ id, name: folder });
					}
					const parts = folder.split('/');
					for (let index = parts.length - 1; index > 0; index--) {
						const parent = parts.slice(0, index).join('/');
						if (!groupIds.has(parent)) {
							const parentId = randomUUID();
							groupIds.set(parent, parentId);
							groups.push({ id: parentId, name: parent });
						}
					}
					if (organization) result.collectionIds = [id];
					else result.folderId = id;
				}
			} else if (key === 'Notes') result.notes = present(value);
			else if (present(value)) result.fields!.push({ name: key, value, type: key === 'Password' ? 1 : 0 });
		}
		items.push(result);
	}
	return { encrypted: false, items, [organization ? 'collections' : 'folders']: groups };
}
function zohoVaultCsv(header: string[], rows: string[][], organization: boolean): JsonObject {
	const items: VaultItem[] = [], groups: JsonObject[] = [], groupIds = new Map<string, string>();
	const addField = (item: VaultItem, name: string, value: string): void => {
		if (value.length > 200 || /[\r\n]/.test(value.trim())) {
			item.notes = `${item.notes ?? ''}${name}: ${value.replace(/\r\n|\r/g, '\n')}\n`;
		} else item.fields!.push({ name, value, type: 0 });
	};
	const parseData = (item: VaultItem, data: string): void => {
		if (!present(data)) return;
		for (const line of data.replace(/\r\n|\r/g, '\n').split('\n')) {
			const colon = line.indexOf(':');
			if (colon < 0) continue;
			const field = line.slice(0, colon), value = line.length > colon ? line.slice(colon + 1) : '';
			if (!field.trim() || !value.trim() || field === 'SecretType') continue;
			const fieldLower = field.toLowerCase();
			if (item.login!.username == null && genericUsernameFields.has(fieldLower)) item.login!.username = value;
			else if (item.login!.password == null && genericPasswordFields.has(fieldLower)) item.login!.password = value;
			else addField(item, field, value);
		}
	};
	for (const row of rows) {
		const value = Object.fromEntries(header.map((key, index) => [key, row[index] ?? ''])) as Record<string, string>;
		const passwordName = present(value['Password Name']), secretName = present(value['Secret Name']);
		if (!passwordName && !secretName) continue;
		const result = login(passwordName ?? secretName ?? '--');
		result.favorite = (present(value.Favorite) ?? '0') === '1';
		result.notes = present(value.Notes);
		result.login!.uris = uris(present(value['Password URL']) ?? present(value['Secret URL']) ?? undefined);
		result.login!.totp = present(value.TOTP) ?? present(value.login_totp);
		parseData(result, value.SecretData ?? '');
		parseData(result, value.CustomData ?? '');
		const username = result.login!.username, password = result.login!.password, itemUris = result.login!.uris;
		if (
			!(typeof username === 'string' && present(username))
			&& !(typeof password === 'string' && present(password))
			&& !(Array.isArray(itemUris) && itemUris.length > 0)
		) {
			result.type = 2;
			delete result.login;
			result.secureNote = { type: 0 };
		}
		const folder = present(value['Folder Name']);
		if (folder) {
			const name = folder.replace(/\\/g, '/').replace(/^\/+/, ''), id = groupIds.get(name) ?? randomUUID();
			if (!groupIds.has(name)) {
				groupIds.set(name, id);
				groups.push({ id, name });
			}
			const parts = name.split('/');
			for (let index = parts.length - 1; index > 0; index--) {
				const parent = parts.slice(0, index).join('/');
				if (!groupIds.has(parent)) {
					const parentId = randomUUID();
					groupIds.set(parent, parentId);
					groups.push({ id: parentId, name: parent });
				}
			}
			if (organization) result.collectionIds = [id];
			else result.folderId = id;
		}
		items.push(result);
	}
	return { encrypted: false, items, [organization ? 'collections' : 'folders']: groups };
}
function roboFormCsv(header: string[], rows: string[][], organization: boolean): JsonObject {
	const items: VaultItem[] = [], groups: JsonObject[] = [], groupIds = new Map<string, string>();
	const addField = (item: VaultItem, key: string | null, value: string, hidden = false): void => {
		if (!value.trim()) return;
		const name = key ?? '';
		if (value.length > 200 || /[\r\n]/.test(value.trim())) {
			item.notes = `${item.notes ?? ''}${name}: ${value.replace(/\r\n|\r/g, '\n')}\n`;
		} else item.fields!.push({ name, value, type: hidden ? 1 : 0 });
	};
	const addFolder = (folder: string): string => {
		const id = groupIds.get(folder) ?? randomUUID();
		if (!groupIds.has(folder)) {
			groupIds.set(folder, id);
			groups.push({ id, name: folder });
		}
		const parts = folder.split('/');
		for (let index = parts.length - 1; index > 0; index--) {
			const parent = parts.slice(0, index).join('/');
			if (!groupIds.has(parent)) {
				const parentId = randomUUID();
				groupIds.set(parent, parentId);
				groups.push({ id: parentId, name: parent });
			}
		}
		return id;
	};
	let acceptedRows = 0;
	for (const row of rows) {
		const value = Object.fromEntries(header.map((key, index) => [key, row[index] ?? ''])) as Record<string, string>;
		const extra = row.slice(header.length), result = login(value.Name);
		result.notes = present(value.Note);
		result.login!.username = present(value.Login);
		result.login!.password = present(value.Pwd) ?? present(value.Password);
		result.login!.uris = uris(present(value.Url) ?? present(value.URL) ?? undefined);
		let folder = value.Folder ?? '';
		if (!folder.trim()) folder = '';
		else if (folder.startsWith('/')) folder = folder.replace('/', '');
		if (folder) {
			const id = addFolder(folder);
			if (organization) result.collectionIds = [id];
			else result.folderId = id;
		}
		if (present(value.Rf_fields)) {
			for (const field of [value.Rf_fields ?? '', ...extra]) {
				const parts = field.split(':');
				if (parts.length < 3) continue;
				const key = parts[0] === '-no-name-' ? null : parts[0]!;
				const fieldValue = parts.length === 4 && parts[2] === 'rck' ? parts[1]! : parts[2]!;
				addField(result, key, fieldValue);
			}
		} else if (present(value.RfFieldsV2)) {
			let userIdCount = 1, passwordCount = 1;
			for (const field of [value.RfFieldsV2 ?? '', ...extra]) {
				const parts = field.split(',');
				if (parts.length < 5) continue;
				const key = parts[0] === '-no-name-' ? null : parts[0]!;
				const fieldValue = parts[4]!;
				if (key === 'TOTP KEY$') {
					result.login!.totp = fieldValue;
					continue;
				}
				if (key === 'User ID$' && fieldValue === result.login!.username) continue;
				if (key === 'Password$' && fieldValue === result.login!.password) continue;
				let displayKey = key;
				if (key === 'User ID$') displayKey = `Alternate User ID ${userIdCount++}`;
				else if (key === 'Password$') displayKey = `Alternate Password ${passwordCount++}`;
				addField(result, displayKey, fieldValue, parts[3] === 'pwd');
			}
		}
		const loginData = result.login!, username = loginData.username, password = loginData.password;
		if (
			!(typeof username === 'string' && present(username))
			&& !(typeof password === 'string' && present(password))
			&& !(Array.isArray(loginData.uris) && loginData.uris.length > 0)
		) {
			result.type = 2;
			delete result.login;
			result.secureNote = { type: 0 };
		}
		const remainingPassword = result.login?.password;
		if (
			acceptedRows === rows.length - 1 && result.name === '--'
			&& !(typeof remainingPassword === 'string' && present(remainingPassword))
		) continue;
		items.push(result);
		acceptedRows++;
	}
	return { encrypted: false, items, [organization ? 'collections' : 'folders']: groups };
}
function keeperCsv(rows: string[][], organization: boolean): JsonObject {
	const items: VaultItem[] = [], groups: JsonObject[] = [], groupIds = new Map<string, string>();
	const addFolder = (folder: string): string => {
		const name = folder.replace(/\\/g, '/').replace(/^\/+/, ''), id = groupIds.get(name) ?? randomUUID();
		if (!groupIds.has(name)) {
			groupIds.set(name, id);
			groups.push({ id, name });
		}
		const parts = name.split('/');
		for (let index = parts.length - 1; index > 0; index--) {
			const parent = parts.slice(0, index).join('/');
			if (!groupIds.has(parent)) {
				const parentId = randomUUID();
				groupIds.set(parent, parentId);
				groups.push({ id: parentId, name: parent });
			}
		}
		return id;
	};
	const addField = (item: VaultItem, key: string, value: string): void => {
		if (!value.trim()) return;
		if (value.length > 200 || /[\r\n]/.test(value.trim())) {
			item.notes = `${item.notes ?? ''}${key}: ${value.replace(/\r\n|\r/g, '\n')}\n`;
		} else item.fields!.push({ name: key, value, type: 0 });
	};
	for (const row of rows) {
		if (row.length < 6) continue;
		const result = login(row[1]);
		result.login!.username = present(row[2]);
		result.login!.password = present(row[3]);
		result.login!.uris = uris(present(row[4]) ?? undefined);
		result.notes = present(row[5])?.trimEnd() ?? null;
		const folder = present(row[0]);
		if (folder) {
			const id = addFolder(folder);
			if (organization) result.collectionIds = [id];
			else result.folderId = id;
		}
		for (let index = 7; index < row.length; index += 2) {
			const fieldName = row[index] ?? '', fieldValue = row[index + 1] ?? '';
			if (fieldName === 'TFC:Keeper') result.login!.totp = fieldValue;
			else addField(result, fieldName, fieldValue);
		}
		const username = result.login!.username, password = result.login!.password, itemUris = result.login!.uris;
		if (
			!(typeof username === 'string' && present(username))
			&& !(typeof password === 'string' && present(password))
			&& !(Array.isArray(itemUris) && itemUris.length > 0)
		) {
			result.type = 2;
			delete result.login;
			result.secureNote = { type: 0 };
		}
		items.push(result);
	}
	return { encrypted: false, items, [organization ? 'collections' : 'folders']: groups };
}
function passwordXpCsv(rows: string[][], organization: boolean): JsonObject {
	const translations: Record<string, string> = {
		'Titel': 'Title',
		'Gebruikersnaam': 'Username',
		'Wachtwoord': 'Password',
		Gewijzigd: 'Modified',
		Gemaakt: 'Created',
		'Verloopt op': 'Expire on',
		Beschrijving: 'Description',
		'Gewijzigd door': 'Modified by',
		Benutzername: 'Username',
		Konto: 'Account',
		Passwort: 'Password',
		'Geändert am': 'Modified',
		'Erstellt am': 'Created',
		'Läuft ab am': 'Expire on',
		Beschreibung: 'Description',
		'Geändert von': 'Modified by',
	};
	const header = rows.shift()?.map(value => value === 'User name' ? 'Username' : translations[value] ?? value);
	if (!header?.length || !header.includes('Title')) throw new Error('Invalid PasswordXP CSV header.');
	const items: VaultItem[] = [], groups: JsonObject[] = [], groupIds = new Map<string, string>();
	const addFolder = (folder: string): string => {
		const name = folder.replace(/\\/g, '/').replace(/^\/+/, ''), id = groupIds.get(name) ?? randomUUID();
		if (!groupIds.has(name)) {
			groupIds.set(name, id);
			groups.push({ id, name });
		}
		const parts = name.split('/');
		for (let index = parts.length - 1; index > 0; index--) {
			const parent = parts.slice(0, index).join('/');
			if (!groupIds.has(parent)) {
				const parentId = randomUUID();
				groupIds.set(parent, parentId);
				groups.push({ id: parentId, name: parent });
			}
		}
		return id;
	};
	let currentFolder = '';
	for (const row of rows) {
		if (!row.some(value => value.trim())) continue;
		const record: Record<string, string> = Object.fromEntries(header.map((key, index) => [key, row[index] ?? '']));
		const title = record.Title ?? '';
		if (title === '>>>') continue;
		if (title.startsWith('[') && title.endsWith(']')) {
			currentFolder = title.startsWith('/') ? title.replace('/', '') : title.slice(1, -1);
			continue;
		}
		const result = login(title);
		result.login!.username = present(record.Username);
		result.login!.password = present(record.Password);
		result.login!.uris = uris(record.URL);
		result.notes = present(record.Description);
		for (const [key, value] of Object.entries(record)) {
			if (['Title', 'Username', 'URL', 'Password', 'Description'].includes(key) || !value.trim()) continue;
			if (value.length > 200 || /[\r\n]/.test(value.trim())) {
				result.notes = `${result.notes ?? ''}${key}: ${value.replace(/\r\n|\r/g, '\n')}\n`;
			} else result.fields!.push({ name: key, value, type: 0 });
		}
		if (currentFolder) {
			const id = addFolder(currentFolder);
			if (organization) result.collectionIds = [id];
			else result.folderId = id;
		}
		if (
			!present(record.Username) && !present(record.Password) && !present(record.URL)
		) {
			result.type = 2;
			delete result.login;
			result.secureNote = { type: 0 };
		}
		items.push(result);
	}
	return { encrypted: false, items, [organization ? 'collections' : 'folders']: groups };
}
function netwrixPasswordSecureCsv(source: string, organization: boolean): JsonObject {
	const delimiter = ';', rows = parseCsv(source, '"', delimiter);
	if (!rows.length) throw new Error('Netwrix Password Secure CSV is empty.');
	const header = rows.shift()!;
	const records = rows;
	if (header.length === 1 && header[0]!.includes(delimiter)) {
		const wrapped = parseCsv([header[0]!, ...rows.map(row => row[0] ?? '')].join('\n'), '"', delimiter);
		if (wrapped.length) {
			const wrappedHeader = wrapped.shift()!;
			return netwrixPasswordSecureRows(wrappedHeader, wrapped, organization);
		}
	}
	return netwrixPasswordSecureRows(header, records, organization);
}
function netwrixPasswordSecureRows(header: string[], rows: string[][], organization: boolean): JsonObject {
	const folders: JsonObject[] = [], groupIds = new Map<string, string>(), items: VaultItem[] = [];
	const folderColumns = ['Organisationseinheit', 'Organisational unit'];
	const nameColumns = ['Beschreibung'];
	const usernameColumns = ['Benutzername'];
	const passwordColumns = ['Passwort'];
	const uriColumns = [
		'Internetseite',
		'Internetadresse',
		'Webseite',
		'Webseite1',
		'Website',
		'Webmail',
		'Web page',
		'URL',
	];
	const notesColumns = ['Informationen', 'Kommentare'];
	const totpColumns = ['One-Time Passwort'];
	const mapped = new Set([
		...folderColumns,
		...nameColumns,
		...usernameColumns,
		...passwordColumns,
		...uriColumns,
		...notesColumns,
		...totpColumns,
	]);
	const addFolder = (raw: string, result: VaultItem): void => {
		if (!raw.trim()) return;
		const name = raw.replace(/\\/g, '/').replace(/^\/+/, ''), id = groupIds.get(name) ?? randomUUID();
		if (!groupIds.has(name)) {
			groupIds.set(name, id);
			folders.push({ id, name });
		}
		const parts = name.split('/');
		for (let index = parts.length - 1; index > 0; index--) {
			const parent = parts.slice(0, index).join('/');
			if (!groupIds.has(parent)) {
				const parentId = randomUUID();
				groupIds.set(parent, parentId);
				folders.push({ id: parentId, name: parent });
			}
		}
		if (organization) result.collectionIds = [id];
		else result.folderId = id;
	};
	const data = rows.filter(row => row.some(value => value.trim())).map(row =>
		Object.fromEntries(header.map((key, index) => [key, row[index] ?? ''])) as Record<string, string>
	);
	const first = (record: Record<string, string>, columns: string[]) =>
		columns.map(key => record[key]).find(value => value?.trim()) ?? '';
	for (const record of data) {
		const result = login(first(record, nameColumns) || '--');
		addFolder(first(record, folderColumns), result);
		result.login!.username = present(first(record, usernameColumns));
		result.login!.password = present(first(record, passwordColumns));
		result.login!.uris = uriColumns.flatMap(key => record[key]?.trim() ? uris(record[key]) : []);
		result.login!.totp = present(first(record, totpColumns));
		result.notes = present(first(record, notesColumns))?.trimEnd() ?? null;
		for (const [key, value] of Object.entries(record)) {
			if (mapped.has(key) || !value.trim()) continue;
			if (value.length > 200 || /[\r\n]/.test(value.trim())) {
				result.notes = `${result.notes ?? ''}${key}: ${value.replace(/\r\n|\r/g, '\n')}\n`;
			} else result.fields!.push({ name: key, value, type: 0 });
		}
		items.push(result);
	}
	return { encrypted: false, items, [organization ? 'collections' : 'folders']: folders };
}
/** Parse external CSV into the same document consumed by the native encrypted importer. */
export function parseExternalCsv(format: ExternalCsvFormat, source: string, organization = false): JsonObject {
	if (format === 'enpasscsv') return enpassCsv(parseCsv(source), organization);
	if (format === 'keepercsv') return keeperCsv(parseCsv(source.trim()), organization);
	if (format === 'passwordxpcsv') return passwordXpCsv(parseCsv(source), organization);
	if (format === 'netwrixpasswordsecure') return netwrixPasswordSecureCsv(source, organization);
	if (format === 'lastpasscsv') source = lastPassCsv(source);
	// The reference routes these vendor IDs through the same parsers.
	if (format === 'edgecsv' || format === 'operacsv' || format === 'vivaldicsv' || format === 'bravecsv') {
		format = 'chromecsv';
	}
	if (format === 'passboltcsv') format = 'lastpasscsv';
	// The reference importer trims the complete document before PapaParse; this
	// also removes whitespace at the end of an unquoted final CSV field.
	const rows = parseCsv(source.trim()), header = rows.shift();
	if (!header?.length) throw new Error('CSV is empty.');
	if (format === 'delineacsv') return delineaCsv(header, rows, organization);
	if (format === 'zohovaultcsv') return zohoVaultCsv(header, rows, organization);
	if (format === 'roboformcsv') return roboFormCsv(header, rows, organization);
	if (format === 'dashlanecsv') return dashlaneCsv(header, rows, organization);
	if (format === 'msecurecsv') {
		const items: VaultItem[] = [], groups: JsonObject[] = [], groupIds = new Map<string, string>();
		for (const row of [header, ...rows]) {
			if (row.length < 3) continue;
			const folder = row[2] !== 'Unassigned' ? present(row[2]) : null,
				item = login(row[0]?.split('|')[0]);
			if (row[1] === 'Web Logins' || row[1] === 'Login') {
				item.login = {
					username: present(msecureValue(row[5]) ?? undefined),
					password: present(msecureValue(row[6]) ?? undefined),
					totp: null,
					uris: uris(msecureValue(row[4]) ?? undefined),
				};
				item.notes = present(row[3]?.replaceAll('\\n', '\n'));
			} else if (row[1] === 'Credit Card') {
				const number = present(msecureValue(row[4]) ?? undefined),
					[month, year] = (msecureValue(row[5]) ?? '').split('/');
				item.type = 3;
				delete item.login;
				const securityCode = row.find(entry => /^Security Code\|\d*\|/.test(entry));
				const cardholder = row.find(entry => /^Name on Card\|\d*\|/.test(entry));
				item.card = {
					number,
					expMonth: month?.trim() ?? '',
					expYear: year?.trim() ?? '',
					code: msecureValue(securityCode),
					cardholderName: msecureValue(cardholder),
					brand: msecureValue(row[9]) ?? '',
				};
				const noteRegex = /\|\d*\|/,
					rawNotes = row.slice(2).filter(entry => present(entry) && !noteRegex.test(entry));
				const indexedNotes = [8, 10, 11]
					.filter(index => row[index] && noteRegex.test(row[index]!))
					.map(index => `${row[index]!.split('|')[0]}: ${msecureValue(row[index]) ?? ''}`);
				item.notes = present([...rawNotes, ...indexedNotes].join('\n'));
			} else {
				if (row.length > 3) {
					item.type = 2;
					delete item.login;
					item.secureNote = { type: 0 };
					item.notes = present(row.slice(3).filter(value => present(value)).map(value => `${value}\n`).join(''));
				}
				if (present(row[1]) && item.type !== 1 && item.type !== 3) item.name = `${row[1]}: ${item.name}`;
			}
			let groupId: string | null = null;
			if (folder) {
				groupId = groupIds.get(folder) ?? randomUUID();
				if (!groupIds.has(folder)) {
					groupIds.set(folder, groupId);
					groups.push({ id: groupId, name: folder });
				}
			}
			item.folderId = organization ? null : groupId;
			item.collectionIds = organization && groupId ? [groupId] : [];
			items.push(item);
		}
		return { encrypted: false, items, [organization ? 'collections' : 'folders']: groups };
	}
	if (format === 'passwordagentcsv') {
		const items: VaultItem[] = [], groups: JsonObject[] = [], groupIds = new Map<string, string>();
		let newVersion = true;
		for (const row of [header, ...rows]) {
			if (row.length !== 5 && row.length < 9) continue;
			const altFormat = row.length === 10 && row[0] === '0',
				nameIndex = altFormat ? 1 : 0,
				usernameIndex = altFormat ? 2 : 1,
				passwordIndex = altFormat ? 3 : 2,
				item = login(row[nameIndex]);
			item.login = {
				username: present(row[usernameIndex]),
				password: present(row[passwordIndex]),
				totp: null,
				uris: [],
			};
			let folder: string | null = null;
			if (row.length === 5) {
				newVersion = false;
				item.notes = present(row[4]);
				item.login.uris = uris(row[3]);
			} else {
				const rawFolder = row[altFormat ? 9 : 8] ?? '(None)';
				if (rawFolder !== '(None)') {
					folder = rawFolder.split(' > ').join('/').split('>').join('/');
				}
				item.notes = present(row[altFormat ? 5 : 3]);
				item.login.uris = uris(row[4]);
			}
			noteIfEmpty(item);
			let groupId: string | null = null;
			if (folder) {
				groupId = groupIds.get(folder) ?? randomUUID();
				if (!groupIds.has(folder)) {
					groupIds.set(folder, groupId);
					groups.push({ id: groupId, name: folder });
				}
			}
			item.folderId = groupId;
			item.collectionIds = [];
			items.push(item);
		}
		if (organization && newVersion) {
			for (const item of items) {
				item.collectionIds = item.folderId ? [item.folderId] : [];
				item.folderId = null;
			}
		}
		return { encrypted: false, items, [organization && newVersion ? 'collections' : 'folders']: groups };
	}
	if (format === 'passwordwallettxt') {
		const items: VaultItem[] = [], groups: JsonObject[] = [], groupIds = new Map<string, string>();
		for (const row of [header, ...rows]) {
			if (row.every(value => !value)) continue;
			const item = login(row[0]);
			if (row.length > 1) item.login!.uris = uris(row[1]);
			if (row.length > 2) item.login!.username = present(row[2]);
			if (row.length > 3) item.login!.password = present(row[3]);
			if (row.length > 4) item.notes = present(row[4]?.split('¬').join('\n'));
			const folder = row.length > 5 ? present(row[5]?.replace(/\\/g, '/').replace(/^\/+/, '')) : null;
			let groupId: string | null = null;
			if (folder) {
				groupId = groupIds.get(folder) ?? randomUUID();
				if (!groupIds.has(folder)) {
					groupIds.set(folder, groupId);
					groups.push({ id: groupId, name: folder });
				}
			}
			item.folderId = organization ? null : groupId;
			item.collectionIds = organization && groupId ? [groupId] : [];
			items.push(item);
		}
		return { encrypted: false, items, [organization ? 'collections' : 'folders']: groups };
	}
	if (format === 'splashidcsv') {
		const items: VaultItem[] = [], groups: JsonObject[] = [], groupIds = new Map<string, string>();
		for (const row of [header, ...rows]) {
			if (row.length < 3) continue;
			const folder = present(row.at(-1)), groupId = folder ? groupIds.get(folder) ?? randomUUID() : null;
			if (folder && !groupIds.has(folder)) {
				groupIds.set(folder, groupId!);
				groups.push({ id: groupId, name: folder });
			}
			const item = login(row[1]);
			item.notes = present(row.at(-2));
			if (['Web Logins', 'Servers', 'Email Accounts'].includes(row[0]!)) {
				item.login!.username = present(row[2]);
				item.login!.password = present(row[3]);
				item.login!.uris = uris(row[4]);
				for (let i = 5; i < row.length - 3; i++) {
					if (present(row[i])) item.notes = `${item.notes ?? ''}${row[i]}\n`;
				}
			} else {
				for (let i = 2; i < row.length - 3; i++) {
					if (present(row[i])) item.notes = `${item.notes ?? ''}${row[i]}\n`;
				}
			}
			noteIfEmpty(item);
			item.folderId = organization ? null : groupId;
			item.collectionIds = organization && groupId ? [groupId] : [];
			items.push(item);
		}
		return { encrypted: false, items, [organization ? 'collections' : 'folders']: groups };
	}
	if (format === 'upmcsv') {
		const items: VaultItem[] = [];
		for (const row of [header, ...rows]) {
			if (row.length !== 5) continue;
			const item = login(row[0]);
			item.login = {
				username: present(row[1]),
				password: present(row[2]),
				totp: null,
				uris: uris(row[3]),
			};
			item.notes = present(row[4]);
			items.push(item);
		}
		return { encrypted: false, items, [organization ? 'collections' : 'folders']: [] };
	}
	if (format === 'ascendocsv') {
		const items: VaultItem[] = [];
		for (const row of [header, ...rows]) {
			if (row.length < 2) continue;
			const item = login(row[0]);
			item.notes = present(row.at(-1));
			if (row.length > 2 && row.length % 2 === 0) {
				for (let i = 0; i < row.length - 2; i += 2) {
					const name = row[i + 1]!, value = row[i + 2]!, key = name.toLowerCase();
					if (!present(name) || !present(value)) continue;
					if (!(item.login!.password as string | null) && genericPasswordFields.has(key)) {
						item.login!.password = value;
					} else if (!(item.login!.username as string | null) && genericUsernameFields.has(key)) {
						item.login!.username = value;
					} else if (!(item.login!.uris as JsonObject[]).length && genericUriFields.has(key)) {
						item.login!.uris = uris(value);
					} else customField(item, name, value);
				}
			}
			noteIfEmpty(item);
			items.push(item);
		}
		return { encrypted: false, items, [organization ? 'collections' : 'folders']: [] };
	}
	if (format === 'padlockcsv') {
		const items: VaultItem[] = [], groups: JsonObject[] = [], groupIds = new Map<string, string>();
		const headers = header;
		for (const row of rows) {
			if (row.length < 2 || row.length !== headers.length) continue;
			const item = login(row[0]),
				tags = present(row[1]) ? row[1]!.split(',').map(value => value.trim()).filter(Boolean) : [];
			const names = organization ? tags : tags.slice(0, 1), ids: string[] = [];
			for (const name of names) {
				const id = groupIds.get(name) ?? randomUUID();
				if (!groupIds.has(name)) {
					groupIds.set(name, id);
					groups.push({ id, name });
				}
				ids.push(id);
			}
			for (let i = 2; i < row.length; i++) {
				const name = headers[i]!.trim(), value = row[i]!, key = name.toLowerCase();
				if (!present(name) || !present(value)) continue;
				if (genericUsernameFields.has(key)) item.login!.username = value;
				else if (genericPasswordFields.has(key)) item.login!.password = value;
				else if (genericUriFields.has(key)) item.login!.uris = uris(value);
				else customField(item, name, value);
			}
			item.folderId = organization ? null : ids[0] ?? null;
			item.collectionIds = organization ? ids : [];
			items.push(item);
		}
		return { encrypted: false, items, [organization ? 'collections' : 'folders']: groups };
	}
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
		: format === 'encryptrcsv'
		? []
		: format === 'passkeepcsv'
		? []
		: format === 'logmeoncecsv'
		? []
		: format === 'mykicsv'
		? []
		: format === 'passpackcsv' || format === 'blackberrycsv' || format === 'blurcsv' || format === 'codebookcsv'
				|| format === 'avastcsv' || format === 'buttercupcsv' || format === 'yoticsv'
				|| format === 'saferpasscsv' || format === 'securesafecsv' || format === 'meldiumcsv'
				|| format === 'truekeycsv' || format === 'remembearcsv'
		? []
		: ['username', 'password'];
	if (!required.every(value => header.includes(value))) throw new Error(`Missing required ${format} CSV columns.`);
	if (
		!formFill && format !== 'nordpasscsv' && format !== 'encryptrcsv' && format !== 'passkeepcsv'
		&& format !== 'passpackcsv'
		&& format !== 'blackberrycsv' && format !== 'blurcsv' && format !== 'codebookcsv'
		&& format !== 'avastcsv' && format !== 'buttercupcsv'
		&& format !== 'yoticsv'
		&& format !== 'logmeoncecsv'
		&& format !== 'mykicsv'
		&& format !== 'saferpasscsv' && format !== 'securesafecsv' && format !== 'meldiumcsv'
		&& format !== 'remembearcsv'
		&& !(format === 'safaricsv'
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
		let entries: VaultItem[], folder: string | null = null, extraCollections: string[] = [];
		if (format === 'mykicsv') {
			const item = myki(values);
			entries = item ? [item] : [];
		} else if (format === 'logmeoncecsv') {
			if (!present(values.name)) continue;
			const item = login(values.name);
			item.login = {
				username: present(values.username),
				password: present(values.password),
				totp: null,
				uris: uris(values.url),
			};
			folder = present(values.group);
			entries = [item];
		} else if (format === 'remembearcsv') {
			if (values.trash === 'true') continue;
			const item = login(values.name);
			item.notes = present(values.notes);
			if (values.type === 'LoginItem') {
				item.login = {
					username: present(values.username),
					password: present(values.password),
					totp: null,
					uris: uris(values.website),
				};
			} else if (values.type === 'CreditCardItem') {
				const number = present(values.number);
				item.type = 3;
				delete item.login;
				item.card = {
					cardholderName: present(values.cardholder),
					number,
					brand: brand(number),
					code: present(values.verification),
				};
				const month = Number.parseInt(values.expiryMonth ?? '', 10),
					year = Number.parseInt(values.expiryYear ?? '', 10);
				if (month >= 1 && month <= 12) item.card.expMonth = String(month);
				if (Number.isFinite(year)) item.card.expYear = String(year);
				customField(item, 'PIN', values.pin ?? '');
				customField(item, 'Zip Code', values.zipCode ?? '');
			}
			entries = [item];
		} else if (format === 'truekeycsv') {
			entries = [trueKey(values)];
		} else if (format === 'saferpasscsv') {
			const url = values.url;
			const item = login(url ? getHostname(url)?.replace(/^www\./, '') : undefined);
			item.notes = present(values.notes);
			item.login = {
				username: present(values.username),
				password: present(values.password),
				totp: null,
				uris: uris(url),
			};
			entries = [item];
		} else if (format === 'securesafecsv') {
			const urlColumn = header.find(value => /url/i.test(value));
			const item = login(values.Title);
			item.notes = present(values.Comment);
			item.login = {
				username: present(values.Username),
				password: present(values.Password),
				totp: null,
				uris: uris(urlColumn ? values[urlColumn] : undefined),
			};
			entries = [item];
		} else if (format === 'meldiumcsv') {
			const item = login(values.DisplayName);
			item.notes = present(values.Notes);
			item.login = {
				username: present(values.UserName),
				password: present(values.Password),
				totp: null,
				uris: uris(values.Url),
			};
			entries = [item];
		} else if (format === 'yoticsv') {
			const item = login(values.Name);
			item.login = {
				username: present(values['User name']),
				password: present(values.Password),
				totp: null,
				uris: uris(values.URL),
			};
			entries = [item];
		} else if (format === 'avastcsv') {
			const item = login(values.name);
			item.login = {
				username: present(values.login),
				password: present(values.password),
				totp: null,
				uris: uris(values.web),
			};
			entries = [item];
		} else if (format === 'buttercupcsv') {
			const item = login(values.title);
			item.login = {
				username: present(values.username),
				password: present(values.password),
				totp: null,
				uris: uris(values.URL || values.url || values.Url),
			};
			item.notes = present(values.note || values.Note || values.notes || values.Notes);
			const official = new Set([
				'!group_id',
				'!group_name',
				'!type',
				'title',
				'username',
				'password',
				'url',
				'note',
				'id',
			]);
			for (const [key, value] of Object.entries(values)) {
				if (!official.has(key.toLowerCase()) && present(value)) customField(item, key, value);
			}
			entries = [item];
			folder = present(values['!group_name']);
		} else if (format === 'blackberrycsv') {
			if (values.grouping === 'list') continue;
			const item = login(values.name);
			item.favorite = values.fav === '1';
			item.notes = present(values.extra);
			if (values.grouping !== 'note') {
				item.login = {
					username: present(values.username),
					password: present(values.password),
					totp: null,
					uris: uris(values.url),
				};
			}
			noteIfEmpty(item);
			entries = [item];
		} else if (format === 'blurcsv') {
			const domain = values.domain, label = values.label === 'null' ? undefined : values.label;
			const item = login(present(label) ?? (domain ? getHostname(domain)?.replace(/^www\./, '') : undefined));
			item.login = { username: null, password: present(values.password), totp: null, uris: uris(domain) };
			if (!present(values.email) && present(values.username)) item.login.username = values.username;
			else {
				item.login.username = present(values.email);
				item.notes = present(values.username);
			}
			entries = [item];
		} else if (format === 'codebookcsv') {
			const item = login(values.Entry);
			item.favorite = values.Favorite === 'True';
			item.notes = present(values.Note);
			item.login = {
				username: present(values.Username) ?? present(values.Email),
				password: present(values.Password),
				totp: present(values.TOTP),
				uris: uris(values.Website),
			};
			if (present(values.Username)) customField(item, 'Email', values.Email ?? '');
			for (const name of ['Phone', 'PIN', 'Account', 'Date']) customField(item, name, values[name] ?? '');
			noteIfEmpty(item);
			entries = [item];
			folder = present(values.Category);
		} else if (format === 'nordpasscsv') {
			entries = nordPass(values);
			if (!entries.length) continue;
			folder = present(values.folder?.replace(/\\/g, '/').replace(/^\/+/, ''));
		} else if (format === 'encryptrcsv') {
			const item = encryptr(values);
			if (
				item.type === 1 && !present(item.login?.username as string | undefined)
				&& !present(item.login?.password as string | undefined)
				&& !(item.login?.uris as JsonObject[] | undefined)?.length
			) {
				item.type = 2;
				delete item.login;
				item.secureNote = { type: 0 };
			}
			entries = [item];
		} else if (format === 'passkeepcsv') {
			const item = passKeep(values);
			entries = [item];
			folder = present((values.category ?? values[' category'])?.replace(/\\/g, '/').replace(/^\/+/, ''));
		} else if (format === 'passpackcsv') {
			const result = passPack(values);
			entries = [result.item];
			if (organization) extraCollections = result.tags;
			else folder = present(result.tags[0]);
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
		const collectionIds = new Set(groupId ? [groupId] : []);
		if (organization) {
			for (const name of extraCollections) {
				const id = groupIds.get(name) ?? randomUUID();
				if (!groupIds.has(name)) {
					groupIds.set(name, id);
					groups.push({ id, name });
				}
				collectionIds.add(id);
			}
		}
		for (const item of entries) {
			item.folderId = organization ? null : groupId;
			item.collectionIds = organization ? [...collectionIds] : [];
			items.push(item);
		}
	}
	return { encrypted: false, items, [organization ? 'collections' : 'folders']: groups };
}
