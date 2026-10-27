import { DOMParser, type Document, type Element } from '@xmldom/xmldom';
import type { JsonObject } from '#client';
import type { VaultItem } from '#models';

const children = (element: Element, tag: string): Element[] => {
	const result: Element[] = [];
	for (let index = 0; index < element.childNodes.length; index++) {
		const node = element.childNodes.item(index);
		if (node?.nodeType === 1 && (node as Element).tagName === tag) result.push(node as Element);
	}
	return result;
};
const content = (element: Element | undefined) => element?.textContent ?? '';
const blank = (value: string | null | undefined) => !value || !value.trim();
const passwordFieldNames = new Set([
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
function cardBrand(number: string): string | undefined {
	if (/^4/.test(number)) return 'Visa';
	if (/^(?:5[1-5]\d{14}|2(?:22[1-9]\d{12}|2[3-9]\d{13}|[3-6]\d{14}|7[01]\d{13}|720\d{12}))$/.test(number)) {
		return 'Mastercard';
	}
	if (/^3[47]/.test(number)) return 'Amex';
	if (/^(?:6011|622(?:12[6-9]|1[3-9]\d|[2-8]\d{2}|9[0-1]\d|92[0-5]|64[4-9])|65)/.test(number)) {
		return 'Discover';
	}
	if (/^36/.test(number) || /^30[0-5]/.test(number)) return 'Diners Club';
	if (/^35(?:2[89]|[3-8]\d)/.test(number)) return 'JCB';
	if (/^(?:4026|417500|4508|4844|491[37])/.test(number)) return 'Visa';
	return undefined;
}

/** Parse SafeInCloud's XML card database using the reference importer's field mapping. */
export function parseSafeInCloudXml(source: string): JsonObject {
	if (/<!ENTITY/i.test(source)) throw new Error('XML entity declarations are not supported.');
	for (const declaration of source.matchAll(/<!DOCTYPE[^>[]*/gi)) {
		if (/\b(?:SYSTEM|PUBLIC)\b/i.test(declaration[0])) {
			throw new Error('External XML document types are not supported.');
		}
	}
	let document: Document;
	try {
		document = new DOMParser({
			onError: () => {
				throw new Error('Malformed XML.');
			},
		})
			.parseFromString(source.replace(/^[\s\uFEFF]+/, ''), 'application/xml');
	} catch (error) {
		throw new Error('Invalid SafeInCloud XML.', { cause: error });
	}
	const databases = document.getElementsByTagName('database');
	if (databases.length === 0) throw new Error('Missing database node.');
	const items: VaultItem[] = [];
	for (const cardElement of Array.from(databases).flatMap(database => children(database, 'card'))) {
		if (cardElement.getAttribute('template') === 'true' || cardElement.getAttribute('deleted') === 'true') continue;
		const name = cardElement.getAttribute('title');
		const item: VaultItem = {
			type: cardElement.getAttribute('type') === 'note' ? 2 : 1,
			name: blank(name) ? '--' : name!,
			favorite: cardElement.getAttribute('star') === 'true',
			reprompt: 0,
			notes: null,
			fields: [],
			...(cardElement.getAttribute('type') === 'note'
				? { secureNote: { type: 0 } }
				: { login: { username: null, password: null, totp: null, uris: [] } }),
		};
		const fields = children(cardElement, 'field').map(element => ({
			element,
			name: element.getAttribute('name'),
			value: content(element),
			type: (element.getAttribute('type') ?? '').toLowerCase(),
			autofill: element.getAttribute('autofill'),
		}));
		const isCard = item.type === 1 && fields.some(field => field.autofill === 'cc-number' && !blank(field.value));
		if (isCard) {
			item.type = 3;
			item.card = {};
			delete item.login;
		}
		const addNote = (value: string) => {
			item.notes = `${item.notes ?? ''}${value.replace(/\r\n|\r/g, '\n').split('\n').join('\n')}\n`;
		};
		const addFieldNote = (key: string, value: string) => {
			item.notes = `${item.notes ?? ''}${key}: ${value.replace(/\r\n|\r/g, '\n').split('\n').join('\n')}\n`;
		};
		const addField = (key: string | null, value: string, type = 0) => {
			if (blank(value)) return;
			if (value.length > 200 || /[\r\n]/.test(value.trim())) addFieldNote(blank(key) ? '' : key!, value);
			else item.fields!.push({ name: blank(key) ? '' : key, value, type });
		};
		if (isCard) {
			for (const field of fields) {
				if (blank(field.value)) continue;
				if (field.autofill === 'cc-number') {
					item.card!.number = field.value;
					const brand = cardBrand(field.value);
					if (brand) item.card!.brand = brand;
					continue;
				}
				if (field.autofill === 'cc-name') item.card!.cardholderName = field.value;
				else if (field.autofill === 'cc-exp') {
					const match = field.value.replace(/\s/g, '').match(/^0?([1-9]|1[0-2])\/(?:([1-2]\d)?(\d{2}))$/);
					if (match) {
						item.card!.expMonth = match[1];
						item.card!.expYear = `${match[2] ?? '20'}${match[3]}`;
					} else addField(field.name, field.value);
				} else if (field.autofill === 'cc-csc') item.card!.code = field.value;
				else if (field.type === 'notes') addNote(field.value);
				else addField(field.name, field.value, field.type === 'pin' ? 1 : 0);
			}
		} else if (item.type === 1) {
			const login = item.login!;
			const uris = login.uris as JsonObject[];
			for (const field of fields) {
				if (blank(field.value)) continue;
				if (field.type === 'login' && blank(login.username as string | null)) login.username = field.value;
				else if (field.type === 'password' || field.type === 'secret') addField(field.name, field.value, 1);
				else if (field.type === 'one_time_password') login.totp = field.value;
				else if (field.type === 'notes') addNote(field.value);
				else if (field.type === 'weblogin' || field.type === 'website') {
					let uri = field.value.trim();
					if (!uri.includes('://') && uri.includes('.')) uri = `http://${uri}`;
					if (uri) uris.push({ uri: uri.slice(0, 1000), match: null });
				} else addField(field.name, field.value);
			}
			const hidden = item.fields!.filter(field => field.type === 1);
			const password = hidden.find(field => passwordFieldNames.has(String(field.name).toLowerCase()));
			const selected = password ?? hidden[0];
			if (selected) {
				login.password = selected.value;
				if (password) item.fields = item.fields!.filter(field => field !== selected);
			}
		}
		for (const note of children(cardElement, 'notes')) addNote(content(note));
		if (!item.notes?.trim()) item.notes = null;
		items.push(item);
	}
	return { encrypted: false, items };
}
