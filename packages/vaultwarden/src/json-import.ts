import type { JsonObject } from '#client';
import type { VaultItem } from '#models';
import { randomUUID } from 'node:crypto';

export const externalJsonFormats = [
	'avastjson',
	'enpassjson',
	'gnomejson',
	'passkyjson',
	'passmanjson',
	'keeperjson',
	'dashlanejson',
	'passwordbossjson',
	'psonojson',
	'fsecurefsk',
	'protonpass',
] as const;
export type ExternalJsonFormat = typeof externalJsonFormats[number];
export function isExternalJsonFormat(value: string): value is ExternalJsonFormat {
	return (externalJsonFormats as readonly string[]).includes(value);
}

const present = (value: unknown): string | null => {
	if (typeof value === 'string') return value.trim() ? value : null;
	if (typeof value === 'number' && Number.isFinite(value)) return String(value);
	return null;
};
function brand(number: string | null): string | null {
	if (!number) return null;
	const value = number.replace(/\s/g, '');
	if (/^4/.test(value)) return 'Visa';
	if (/^5[1-5]/.test(value) || (Number(value.slice(0, 4)) >= 2221 && Number(value.slice(0, 4)) <= 2720)) {
		return 'Mastercard';
	}
	if (/^3[47]/.test(value)) return 'Amex';
	if (/^6(?:011|5|4[4-9])/.test(value)) return 'Discover';
	if (/^35/.test(value)) return 'JCB';
	if (/^3(?:0[0-5]|[68])/.test(value)) return 'Diners Club';
	if (/^62/.test(value)) return 'UnionPay';
	return null;
}
function item(name?: unknown): VaultItem {
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
function uris(value: unknown): JsonObject[] {
	const values = typeof value === 'string' ? [value] : Array.isArray(value) ? value : [];
	return values.flatMap(entry => {
		if (typeof entry !== 'string' || !entry.trim()) return [];
		let uri = entry.trim();
		if (!uri.includes('://') && uri.includes('.')) uri = `http://${uri}`;
		return [{ uri: uri.slice(0, 1000), match: null }];
	});
}
function entries(value: unknown, key: string): Record<string, unknown>[] {
	if (value == null) return [];
	if (!Array.isArray(value)) throw new Error(`Invalid Avast JSON ${key} records.`);
	return value.map(record => {
		if (!record || typeof record !== 'object' || Array.isArray(record)) {
			throw new Error(`Invalid Avast JSON ${key} record.`);
		}
		return record as Record<string, unknown>;
	});
}
function enpassRows(value: unknown, key: string): Record<string, unknown>[] {
	if (value == null) return [];
	if (!Array.isArray(value)) throw new Error(`Invalid Enpass JSON ${key} records.`);
	return value.map(record => {
		if (!record || typeof record !== 'object' || Array.isArray(record)) {
			throw new Error(`Invalid Enpass JSON ${key} record.`);
		}
		return record as Record<string, unknown>;
	});
}
function enpassText(value: unknown): string | null {
	return typeof value === 'string' && value.trim() ? value : null;
}
function enpassCustom(item: VaultItem, label: unknown, value: unknown, sensitive: unknown): void {
	if (typeof value !== 'string' || !value.trim()) return;
	const name = typeof label === 'string' && label.trim() ? label : '';
	if (value.length > 200 || /\r|\n/.test(value.trim())) {
		item.notes = `${item.notes ?? ''}${name}: ${value.replace(/\r\n|\r/g, '\n').split('\n').join('\n')}\n`;
	} else item.fields!.push({ name, value, type: sensitive === 1 ? 1 : 0 });
}
function enpassCardExpiry(value: string): { month: string; year: string } | null {
	const match = value.replace(/\s/g, '').match(/^0?([1-9]|1[0-2])\/((?:[1-2][0-9])?[0-9]{2})$/);
	if (!match) return null;
	let year = match[2]!;
	if (year.length === 2) year = `${Number(year) < 50 ? '20' : '19'}${year}`;
	return { month: match[1]!, year };
}
function parseEnpassJson(source: string): JsonObject {
	let parsed: unknown;
	try {
		parsed = JSON.parse(source);
	} catch {
		throw new Error('Invalid Enpass JSON.');
	}
	if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Invalid Enpass JSON.');
	const document = parsed as Record<string, unknown>;
	const sourceItems = enpassRows(document.items, 'item');
	if (sourceItems.length === 0) throw new Error('Enpass JSON contains no items.');
	const sourceFolders = enpassRows(document.folders, 'folder');
	const foldersById = new Map<string, Record<string, unknown>>();
	for (const folder of sourceFolders) {
		if (typeof folder.uuid !== 'string' || !folder.uuid || typeof folder.title !== 'string') {
			throw new Error('Invalid Enpass JSON folder.');
		}
		foldersById.set(folder.uuid, folder);
	}
	const namesById = new Map<string, string>(), idsBySourceId = new Map<string, string>();
	const resolveName = (id: string, path = new Set<string>()): string | null => {
		if (namesById.has(id)) return namesById.get(id)!;
		const folder = foldersById.get(id);
		if (!folder || path.has(id) || typeof folder.title !== 'string' || !folder.title.trim()) return null;
		path.add(id);
		const parentId = typeof folder.parent_uuid === 'string' ? folder.parent_uuid : '';
		const parent = parentId && foldersById.has(parentId) ? resolveName(parentId, path) : null;
		path.delete(id);
		if (parentId && foldersById.has(parentId) && !parent) return null;
		const name = [parent, folder.title.trim()].filter(Boolean).join('/');
		namesById.set(id, name);
		return name;
	};
	const folders: JsonObject[] = [];
	for (const folder of sourceFolders) {
		const name = resolveName(String(folder.uuid));
		if (!name) continue;
		const id = randomUUID();
		idsBySourceId.set(String(folder.uuid), id);
		folders.push({ id, name });
	}
	const items: VaultItem[] = sourceItems.map(sourceItem => {
		const result = item(sourceItem.title);
		result.favorite = typeof sourceItem.favorite === 'number' && sourceItem.favorite > 0;
		const fields = enpassRows(sourceItem.fields, 'field');
		const template = typeof sourceItem.template_type === 'string' ? sourceItem.template_type : '';
		const kind = template.startsWith('login.') || template.startsWith('password.')
			? 'login'
			: template.startsWith('creditcard.')
			? 'card'
			: !template.includes('identity.') && fields.some(field => field.type === 'password' && enpassText(field.value))
			? 'login'
			: 'note';
		if (fields.length) {
			if (kind === 'login') {
				const urls: string[] = [];
				for (const field of fields) {
					const value = enpassText(field.value);
					if (!value || field.type === 'section') continue;
					if ((field.type === 'username' || field.type === 'email') && !result.login!.username) {
						result.login!.username = value;
					} else if (field.type === 'password' && !result.login!.password) {
						result.login!.password = value;
					} else if (field.type === 'totp' && !result.login!.totp) {
						result.login!.totp = value;
					} else if (field.type === 'url') urls.push(value);
					else if (field.type === '.Android#') {
						let uri = value.startsWith('androidapp://') ? value : `androidapp://${value}`;
						uri = uri.replace('android://', '').replace(/androidapp:\/\/[A-Za-z0-9\-_+/]*==@/g, 'androidapp://');
						urls.push(uri);
					} else enpassCustom(result, field.label, value, field.sensitive);
				}
				result.login!.uris = uris(urls);
			} else if (kind === 'card') {
				result.type = 3;
				delete result.login;
				const card: JsonObject = {
					cardholderName: null,
					brand: null,
					number: null,
					expMonth: null,
					expYear: null,
					code: null,
				};
				for (const field of fields) {
					const value = enpassText(field.value);
					if (!value || field.type === 'section' || field.type === 'ccType') continue;
					if (field.type === 'ccName' && !card.cardholderName) card.cardholderName = value;
					else if (field.type === 'ccNumber' && !card.number) {
						card.number = value;
						card.brand = brand(value);
					} else if (field.type === 'ccCvc' && !card.code) card.code = value;
					else if (field.type === 'ccExpiry' && !card.expYear) {
						const expiry = enpassCardExpiry(value);
						if (expiry) Object.assign(card, { expMonth: expiry.month, expYear: expiry.year });
						else enpassCustom(result, field.label, value, field.sensitive);
					} else enpassCustom(result, field.label, value, field.sensitive);
				}
				result.card = card;
			} else {
				for (const field of fields) {
					if (field.type !== 'section') enpassCustom(result, field.label, field.value, field.sensitive);
				}
			}
		}
		if (typeof sourceItem.note === 'string' && sourceItem.note.trim()) result.notes = sourceItem.note.trimEnd();
		if (
			result.type === 1 && !enpassText(result.login!.username) && !enpassText(result.login!.password)
			&& !(result.login!.uris as unknown[]).length
		) {
			result.type = 2;
			delete result.login;
			result.secureNote = { type: 0 };
		}
		const linked = Array.isArray(sourceItem.folders) ? sourceItem.folders[0] : undefined;
		if (typeof linked === 'string' && idsBySourceId.has(linked)) result.folderId = idsBySourceId.get(linked)!;
		return result;
	});
	return { encrypted: false, items, folders };
}
function parseGnomeJson(source: string, organization: boolean): JsonObject {
	let parsed: unknown;
	try {
		parsed = JSON.parse(source);
	} catch {
		throw new Error('Invalid GNOME Passwords JSON.');
	}
	if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || Object.keys(parsed).length === 0) {
		throw new Error('Invalid GNOME Passwords JSON.');
	}
	const keyrings = parsed as Record<string, unknown>, items: VaultItem[] = [], groups: JsonObject[] = [];
	const groupIds = new Map<string, string>();
	const addFolder = (keyring: string): string | null => {
		if (!keyring.trim()) return null;
		const folderName = keyring.replace(/\\/g, '/').replace(/^\/+/, '');
		let id = groupIds.get(folderName);
		if (!id) {
			id = randomUUID();
			groupIds.set(folderName, id);
			groups.push({ id, name: folderName });
		}
		const parts = folderName.split('/');
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
	for (const keyring in keyrings) {
		if (!Object.hasOwn(keyrings, keyring) || !keyring.trim()) continue;
		const entries = keyrings[keyring];
		if (!Array.isArray(entries)) throw new Error('Invalid GNOME Passwords keyring records.');
		if (entries.length === 0) continue;
		for (const entry of entries) {
			if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
				throw new Error('Invalid GNOME Passwords record.');
			}
			const value = entry as Record<string, unknown>;
			if (
				typeof value.display_name !== 'string' || !value.display_name.trim() || !value.display_name.startsWith('http')
			) {
				continue;
			}
			const folderId = addFolder(keyring),
				result = item(value.display_name.replace('http://', '').replace('https://', '').slice(0, 30));
			result.login!.password = present(value.secret);
			result.login!.uris = uris(value.display_name);
			if (value.attributes != null) {
				if (typeof value.attributes !== 'object') throw new Error('Invalid GNOME Passwords attributes.');
				const attributes = value.attributes as Record<string, unknown>;
				result.login!.username = present(attributes.username_value);
				for (const attribute in attributes) {
					if (!Object.hasOwn(attributes, attribute) || attribute === 'username_value' || attribute === 'xdg:schema') {
						continue;
					}
					const fieldValue = attributes[attribute];
					if (typeof fieldValue !== 'string' || !fieldValue.trim()) continue;
					if (fieldValue.length > 200 || /\r|\n/.test(fieldValue.trim())) {
						result.notes = `${result.notes ?? ''}${attribute}: ${fieldValue.replace(/\r\n|\r/g, '\n')}\n`;
					} else result.fields!.push({ name: attribute, value: fieldValue, type: 0 });
				}
			}
			if (folderId) {
				if (organization) result.collectionIds = [folderId];
				else result.folderId = folderId;
			}
			items.push(result);
		}
	}
	return { encrypted: false, items, [organization ? 'collections' : 'folders']: groups };
}
function parsePassmanJson(source: string, organization: boolean): JsonObject {
	let parsed: unknown;
	try {
		parsed = JSON.parse(source);
	} catch {
		throw new Error('Invalid Passman JSON.');
	}
	if (!Array.isArray(parsed) || parsed.length === 0) throw new Error('Passman JSON contains no items.');
	const items: VaultItem[] = [], groups: JsonObject[] = [], groupIds = new Map<string, string>();
	const addFolder = (folder: string): string | null => {
		if (!folder.trim()) return null;
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
	for (const entry of parsed) {
		if (!entry || typeof entry !== 'object' || Array.isArray(entry)) throw new Error('Invalid Passman JSON item.');
		const sourceItem = entry as Record<string, unknown>;
		const tags = sourceItem.tags;
		if (tags != null && !Array.isArray(tags)) throw new Error('Invalid Passman JSON tags.');
		const firstTag = Array.isArray(tags) ? tags[0] : undefined;
		if (firstTag != null && (typeof firstTag !== 'object' || Array.isArray(firstTag))) {
			throw new Error('Invalid Passman JSON tag.');
		}
		const folderId = firstTag && typeof (firstTag as Record<string, unknown>).text === 'string'
			? addFolder((firstTag as Record<string, string>).text!)
			: null;
		const result = item(sourceItem.label);
		result.notes = '';
		const username = present(sourceItem.username), email = present(sourceItem.email);
		if (username) {
			result.login!.username = username;
			if (email) result.notes += `Email: ${email}\n`;
		} else result.login!.username = email;
		result.login!.password = present(sourceItem.password);
		result.login!.uris = uris(sourceItem.url);
		result.notes += present(sourceItem.description) ?? '';
		if (sourceItem.otp != null) {
			if (typeof sourceItem.otp !== 'object' || Array.isArray(sourceItem.otp)) {
				throw new Error('Invalid Passman JSON OTP.');
			}
			result.login!.totp = present((sourceItem.otp as Record<string, unknown>).secret);
		}
		if (sourceItem.custom_fields != null) {
			if (!Array.isArray(sourceItem.custom_fields)) throw new Error('Invalid Passman JSON custom fields.');
			for (const field of sourceItem.custom_fields) {
				if (!field || typeof field !== 'object' || Array.isArray(field)) {
					throw new Error('Invalid Passman JSON custom field.');
				}
				const custom = field as Record<string, unknown>;
				if (custom.field_type === 'text' || custom.field_type === 'password') {
					enpassCustom(result, custom.label, custom.value, 0);
				}
			}
		}
		if (
			!present(result.login!.username) && !present(result.login!.password)
			&& !(result.login!.uris as unknown[]).length
		) {
			result.type = 2;
			delete result.login;
			result.secureNote = { type: 0 };
		}
		if (!result.notes?.trim()) result.notes = null;
		if (folderId) {
			if (organization) result.collectionIds = [folderId];
			else result.folderId = folderId;
		}
		items.push(result);
	}
	return { encrypted: false, items, [organization ? 'collections' : 'folders']: groups };
}
function parsePasskyJson(source: string): JsonObject {
	let parsed: unknown;
	try {
		parsed = JSON.parse(source);
	} catch {
		throw new Error('Invalid Passky JSON.');
	}
	if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Invalid Passky JSON.');
	const document = parsed as Record<string, unknown>, passwords = document.passwords;
	if (!Array.isArray(passwords) || passwords.length === 0) throw new Error('Passky JSON contains no passwords.');
	if (document.encrypted === true) throw new Error('Unable to import an encrypted Passky backup.');
	const items: VaultItem[] = passwords.map(value => {
		if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid Passky JSON password.');
		const password = value as Record<string, unknown>, result = item(password.website);
		result.login!.username = present(password.username);
		result.login!.password = present(password.password);
		result.login!.uris = uris(password.website);
		result.notes = present(password.message);
		if (
			!present(result.login!.username) && !present(result.login!.password)
			&& !(result.login!.uris as unknown[]).length
		) {
			result.type = 2;
			delete result.login;
			result.secureNote = { type: 0 };
		}
		return result;
	});
	return { encrypted: false, items, folders: [] };
}
type KeeperRecord = Record<string, unknown>;
function keeperRows(value: unknown, key: string): KeeperRecord[] {
	if (value == null) return [];
	if (!Array.isArray(value)) throw new Error(`Invalid Keeper JSON ${key} records.`);
	return value.map(entry => {
		if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
			throw new Error(`Invalid Keeper JSON ${key} record.`);
		}
		return entry as KeeperRecord;
	});
}
function keeperValue(value: unknown): string {
	if (typeof value === 'string') return value;
	if (value == null) return '';
	try {
		return JSON.stringify(value) ?? '';
	} catch {
		return '';
	}
}
function keeperFieldKey(key: string): [string, string] {
	if (!key.trim()) return ['', ''];
	let type: string, name = '';
	if (key.startsWith('$')) {
		const separator = key.indexOf(':');
		if (separator > 0) {
			type = key.slice(1, separator).trim();
			name = key.slice(separator + 1).trim();
		} else type = key.slice(1).trim();
	} else type = name = key;
	if (/:[0-9]$/.test(name)) name = name.slice(0, -2);
	return [type, name];
}
function parseKeeperJson(source: string, organization: boolean): JsonObject {
	let parsed: unknown;
	try {
		parsed = JSON.parse(source);
	} catch {
		throw new Error('Invalid Keeper JSON.');
	}
	if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Invalid Keeper JSON.');
	const document = parsed as KeeperRecord, records = keeperRows(document.records, 'record');
	if (records.length === 0) throw new Error('Keeper JSON contains no records.');
	const sourceFolders = keeperRows(document.shared_folders, 'shared folder');
	const items: VaultItem[] = [], groups: JsonObject[] = [], groupIds = new Map<string, string>();
	const addFolder = (raw: string, relationship = true): string | null => {
		if (!raw.trim()) return null;
		const name = raw.replaceAll('\\\\', '-').replaceAll('/', '-').replace(/\\/g, '/').replace(/^\/+/, '');
		let id = groupIds.get(name);
		if (!id) {
			id = randomUUID();
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
		return relationship ? id : null;
	};
	for (const folder of sourceFolders) if (typeof folder.path === 'string') addFolder(folder.path, false);
	const byUid = new Map<string, VaultItem>(), pendingReferences: { item: VaultItem; refs: [string, string][] }[] = [];
	const addField = (target: VaultItem, name: string, value: unknown, type = 0): void => {
		if (value == null || value === '') return;
		const textValue = keeperValue(value);
		if (!textValue) return;
		target.fields!.push({ name, value: textValue, type });
	};
	for (const record of records) {
		const result = item(record.title);
		result.notes = typeof record.notes === 'string' && record.notes.trim() ? record.notes : null;
		result.login!.username = present(record.login);
		result.login!.password = present(record.password);
		result.login!.uris = uris(record.login_url);
		const custom = record.custom_fields;
		if (custom != null && (typeof custom !== 'object' || Array.isArray(custom))) {
			throw new Error('Invalid Keeper JSON custom fields.');
		}
		const fields = custom as Record<string, unknown> | undefined;
		const find = (path: string): unknown => {
			let current: unknown = fields;
			for (const part of path.split('/')) {
				if (!current || typeof current !== 'object' || Array.isArray(current)) return undefined;
				const object = current as Record<string, unknown>;
				const key = Object.keys(object).find(candidate => candidate.replace(/:?:\\d$/, '') === part);
				if (!key) return undefined;
				current = object[key];
			}
			return current;
		};
		const take = (path: string): string => keeperValue(find(path));
		const kind = record.$type;
		if (kind === 'bankCard') {
			result.type = 3;
			delete result.login;
			const number = take('$paymentCard/cardNumber');
			result.card = {
				cardholderName: take('$text:cardholderName') || null,
				number: number || null,
				code: take('$paymentCard/cardSecurityCode') || null,
				brand: brand(number || null),
			};
			const expiration = take('$paymentCard/cardExpirationDate').split('/');
			if (expiration.length === 2) Object.assign(result.card, { expMonth: expiration[0], expYear: expiration[1] });
			addField(result, 'PIN', take('$pinCode'), 1);
			addField(result, 'Username', record.login, 0);
			addField(result, 'Password', record.password, 1);
			for (const uri of uris(record.login_url)) addField(result, 'URL', uri.uri);
		} else if (kind === 'driverLicense' || kind === 'passport' || kind === 'ssnCard') {
			result.type = 4;
			delete result.login;
			result.identity = {};
			if (kind === 'driverLicense') {
				result.identity.licenseNumber = take('$accountNumber:dlNumber') || null;
			} else if (kind === 'passport') {
				result.identity.passportNumber = take('$accountNumber:passportNumber') || null;
			} else result.identity.ssn = take('$accountNumber:identityNumber') || null;
			result.identity.firstName = take('$name/first') || null;
			result.identity.middleName = take('$name/middle') || null;
			result.identity.lastName = take('$name/last') || null;
			addField(result, 'Username', record.login);
			addField(result, 'Password', record.password, 1);
			for (const uri of uris(record.login_url)) addField(result, 'URL', uri.uri);
		} else if (kind === 'sshKeys') {
			result.type = 2;
			delete result.login;
			result.secureNote = { type: 0 };
			addField(result, 'Username', record.login);
			addField(result, 'Passphrase', record.password, 1);
			for (const uri of uris(record.login_url)) addField(result, 'URL', uri.uri);
		}
		if (fields) {
			for (const [key, raw] of Object.entries(fields)) {
				const normalizedKey = key.replace(/:?:\d$/, '');
				if (
					(kind === 'bankCard' && ['$paymentCard', '$text:cardholderName', '$pinCode'].includes(normalizedKey))
					|| (kind === 'driverLicense' && ['$accountNumber:dlNumber', '$name'].includes(normalizedKey))
					|| (kind === 'passport' && ['$accountNumber:passportNumber', '$name'].includes(normalizedKey))
					|| (kind === 'ssnCard' && ['$accountNumber:identityNumber', '$name'].includes(normalizedKey))
				) continue;
				const [type, label] = keeperFieldKey(key), fieldName = label || type || key;
				const values = Array.isArray(raw) ? raw : [raw];
				for (const value of values) {
					if (value == null || value === '') continue;
					if (type === 'appFiller') continue;
					if (type === 'oneTimeCode') {
						const code = keeperValue(value);
						if (result.login && !present(result.login.totp)) result.login.totp = code;
						else addField(result, 'TOTP', code, 1);
						continue;
					}
					if (type === 'url') {
						const values = uris(value);
						if (result.login && Array.isArray(result.login.uris)) result.login.uris.push(...values);
						else for (const uri of values) addField(result, 'URL', uri.uri);
						continue;
					}
					if (['host', 'keyPair', 'securityQuestion'].includes(type)) {
						const object = value && typeof value === 'object' && !Array.isArray(value)
							? value as Record<string, unknown>
							: {};
						if (type === 'host') {
							addField(result, 'Hostname', object.hostName);
							addField(result, 'Port', object.port);
						} else if (type === 'keyPair') {
							addField(result, 'Public key', object.publicKey);
							addField(result, 'Private key', object.privateKey, 1);
						} else {
							const questions = Array.isArray(value) ? value : [value];
							for (const question of questions) {
								if (question && typeof question === 'object' && !Array.isArray(question)) {
									const entry = question as Record<string, unknown>;
									addField(result, 'Security question', entry.question);
									addField(result, 'Security question answer', entry.answer, 1);
								}
							}
						}
						continue;
					}
					if (type === 'name' && value && typeof value === 'object') {
						const name = value as Record<string, unknown>;
						addField(result, fieldName, [name.first, name.middle, name.last].filter(Boolean).join(' '));
						continue;
					}
					if (type === 'address' && value && typeof value === 'object') {
						const address = value as Record<string, unknown>;
						addField(
							result,
							fieldName,
							[address.street1, address.street2, address.city, address.state, address.zip, address.country].filter(
								Boolean,
							).join(', '),
						);
						continue;
					}
					if (type === 'phone' && value && typeof value === 'object') {
						const phone = value as Record<string, unknown>;
						addField(
							result,
							fieldName,
							[
								phone.region && `(${phone.region})`,
								phone.number,
								phone.ext && `ext. ${phone.ext}`,
								phone.type && `(${phone.type})`,
							].filter(Boolean).join(' '),
						);
						continue;
					}
					if (type === 'bankAccount' && value && typeof value === 'object') {
						const account = value as Record<string, unknown>;
						addField(
							result,
							fieldName,
							[
								account.otherType || account.accountType ? `Type: ${account.otherType || account.accountType}` : '',
								account.accountNumber && `Account Number: ${account.accountNumber}`,
								account.routingNumber && `Routing Number: ${account.routingNumber}`,
							].filter(Boolean).join(', '),
						);
						continue;
					}
					let fieldValue = keeperValue(value);
					if (['date', 'birthDate', 'expirationDate'].includes(type)) {
						const date = new Date(fieldValue);
						fieldValue = Number.isNaN(date.getTime()) ? '' : date.toUTCString();
					}
					addField(result, fieldName, fieldValue, ['pinCode', 'secret'].includes(type) ? 1 : 0);
				}
			}
		}
		const referenceData: [string, string][] = [];
		if (record.references != null) {
			if (typeof record.references !== 'object' || Array.isArray(record.references)) {
				throw new Error('Invalid Keeper JSON references.');
			}
			for (const [key, targetIds] of Object.entries(record.references as Record<string, unknown>)) {
				const [rawType] = keeperFieldKey(key), type = rawType.endsWith('Ref') ? rawType.slice(0, -3) : rawType;
				for (const id of Array.isArray(targetIds) ? targetIds : [targetIds]) {
					if (typeof id === 'string') referenceData.push([id, type]);
				}
			}
		}
		if (referenceData.length && typeof record.uid === 'string') {
			pendingReferences.push({ item: result, refs: referenceData });
		}
		for (const folder of keeperRows(record.folders, 'folder')) {
			for (const path of [folder.folder, folder.shared_folder]) {
				if (typeof path !== 'string') continue;
				const id = addFolder(path);
				if (id) {
					if (organization) result.collectionIds = [...(result.collectionIds ?? []), id];
					else result.folderId = id;
				}
			}
		}
		if (
			result.type === 1 && !present(result.login!.username) && !present(result.login!.password)
			&& !(result.login!.uris as unknown[]).length
		) {
			result.type = 2;
			delete result.login;
			result.secureNote = { type: 0 };
		}
		if (typeof record.uid === 'string') byUid.set(record.uid, result);
		items.push(result);
	}
	for (const { item: target, refs } of pendingReferences) {
		for (const [id, type] of refs) {
			const sourceItem = byUid.get(id);
			const field = sourceItem?.fields?.find(value => value.name === type);
			if (field?.value) addField(target, type, field.value);
		}
	}
	return { encrypted: false, items, [organization ? 'collections' : 'folders']: groups };
}
function parseDashlaneJson(source: string): JsonObject {
	let parsed: unknown;
	try {
		parsed = JSON.parse(source);
	} catch {
		throw new Error('Invalid Dashlane JSON.');
	}
	if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || Object.keys(parsed).length === 0) {
		throw new Error('Invalid Dashlane JSON.');
	}
	const document = parsed as Record<string, unknown>, items: VaultItem[] = [];
	const rows = (key: string): Record<string, unknown>[] => {
		const value = document[key];
		if (value == null) return [];
		if (!Array.isArray(value)) throw new Error(`Invalid Dashlane JSON ${key} records.`);
		return value.map(entry => {
			if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
				throw new Error(`Invalid Dashlane JSON ${key} record.`);
			}
			return entry as Record<string, unknown>;
		});
	};
	const addNote = (entry: Record<string, unknown>, nameProperty: string | null, fixedName?: string): void => {
		const result = item(fixedName ?? (nameProperty ? entry[nameProperty] : undefined));
		result.type = 2;
		delete result.login;
		result.secureNote = { type: 0 };
		for (const [key, value] of Object.entries(entry)) {
			if (key === nameProperty || value == null) continue;
			const valueText = typeof value === 'string' ? value : String(value);
			if (valueText.length > 200 || /[\r\n]/.test(valueText.trim())) {
				result.notes = `${result.notes ?? ''}${key}: ${valueText.replace(/\r\n|\r/g, '\n')}\n`;
			} else result.fields!.push({ name: key, value: valueText, type: 0 });
		}
		items.push(result);
	};
	for (const address of rows('ADDRESS')) {
		const result = item(address.addressName);
		result.type = 4;
		delete result.login;
		result.identity = {
			address1: present(address.addressFull),
			city: present(address.city),
			state: present(address.state),
			postalCode: present(address.zipcode),
			country: present(address.country)?.toUpperCase() ?? null,
		};
		items.push(result);
	}
	for (const credential of rows('AUTHENTIFIANT')) {
		const result = item(credential.title);
		const login = present(credential.login) ?? present(credential.secondaryLogin);
		result.login!.username = login ?? present(credential.email);
		result.login!.password = present(credential.password);
		result.login!.uris = uris(credential.domain);
		const notes = [];
		if (login && present(credential.email)) notes.push(`Email: ${present(credential.email)}\n`);
		if (present(credential.note)) notes.push(present(credential.note)!);
		result.notes = notes.length ? notes.join('') : null;
		if (
			!present(result.login!.username) && !present(result.login!.password) && !(result.login!.uris as unknown[]).length
		) {
			result.type = 2;
			delete result.login;
			result.secureNote = { type: 0 };
		}
		items.push(result);
	}
	for (const [key, name] of [['BANKSTATEMENT', 'BankAccountName'], ['IDCARD', 'Fullname']] as const) {
		for (const entry of rows(key)) addNote(entry, name);
	}
	for (const card of rows('PAYMENTMEANS_CREDITCARD')) {
		const number = present(card.cardNumber), brandName = brand(number), bank = present(card.bank);
		const result = item(bank ? `${bank}${brandName ? ` - ${brandName}` : ''}` : brandName);
		result.type = 3;
		delete result.login;
		result.card = { cardholderName: present(card.owner), number, brand: brandName };
		items.push(result);
	}
	for (const identity of rows('IDENTITY')) {
		const result = item(identity.fullName);
		result.type = 4;
		delete result.login;
		const parts = typeof identity.fullName === 'string' ? identity.fullName.split(' ') : [];
		result.identity = {
			firstName: parts[0] || null,
			middleName: parts.length === 3 ? parts[1] : null,
			lastName: parts.length === 2 ? parts[1] : parts.length === 3 ? parts[2] : null,
			username: present(identity.pseudo),
		};
		items.push(result);
	}
	const handled = new Set([
		'ADDRESS',
		'AUTHENTIFIANT',
		'BANKSTATEMENT',
		'IDCARD',
		'IDENTITY',
		'PAYMENTMEANS_CREDITCARD',
		'PAYMENTMEAN_PAYPAL',
		'EMAIL',
	]);
	for (const [key, value] of Object.entries(document)) {
		if (handled.has(key)) continue;
		if (!Array.isArray(value)) throw new Error(`Invalid Dashlane JSON ${key} records.`);
		for (const entry of rows(key)) addNote(entry, null, 'Generic Note');
	}
	return { encrypted: false, items, folders: [] };
}
function parsePasswordBossJson(source: string, organization: boolean): JsonObject {
	let parsed: unknown;
	try {
		parsed = JSON.parse(source);
	} catch {
		throw new Error('Invalid Password Boss JSON.');
	}
	const items: VaultItem[] = [], folders: JsonObject[] = [], folderIds = new Map<string, string>();
	const addField = (target: VaultItem, name: string, rawValue: unknown, type = 0): void => {
		if (rawValue == null || !String(rawValue).trim()) return;
		const value = typeof rawValue === 'string' ? rawValue : String(rawValue);
		if (value.length > 200 || /[\r\n]/.test(value.trim())) {
			target.notes = `${target.notes ?? ''}${name}: ${value.replace(/\r\n|\r/g, '\n')}\n`;
		} else target.fields!.push({ name, value, type });
	};
	const addFolder = (raw: unknown, target: VaultItem): void => {
		const value = present(raw);
		if (!value) return;
		const name = value.replace(/\\/g, '/').replace(/^\/+/, ''), id = folderIds.get(name) ?? randomUUID();
		if (!folderIds.has(name)) {
			folderIds.set(name, id);
			folders.push({ id, name });
		}
		const parts = name.split('/');
		for (let index = parts.length - 1; index > 0; index--) {
			const parent = parts.slice(0, index).join('/');
			if (!folderIds.has(parent)) {
				const parentId = randomUUID();
				folderIds.set(parent, parentId);
				folders.push({ id: parentId, name: parent });
			}
		}
		if (organization) target.collectionIds = [id];
		else target.folderId = id;
	};
	const process = (raw: unknown, legacy = false): void => {
		if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('Invalid Password Boss JSON item.');
		const record = raw as Record<string, unknown>;
		const identifiers = legacy
			? record.identifiers && typeof record.identifiers === 'object' && !Array.isArray(record.identifiers)
				? record.identifiers as Record<string, unknown>
				: null
			: record;
		if (!identifiers) return;
		const isCard = legacy ? record.type === 'CreditCard' : record.itemTypeName === 'CreditCard';
		const result = item(record.name);
		result.notes = present(legacy ? identifiers.notes : record.notes);
		addFolder(
			legacy && typeof record.folder === 'string'
				? (folders.find(folder => folder.id === record.folder)?.name ?? null)
				: record.folder,
			result,
		);
		if (isCard) {
			result.type = 3;
			delete result.login;
			const number = present(identifiers.cardNumber);
			result.card = { number, brand: brand(number) };
			if (legacy) {
				result.card.cardholderName = present(identifiers.nameOnCard);
				result.card.code = present(identifiers.security_code);
				const expiration = present(identifiers.expires);
				if (expiration) {
					const date = new Date(expiration);
					if (!Number.isNaN(date.getTime())) {
						result.card.expYear = String(date.getUTCFullYear());
						result.card.expMonth = String(date.getUTCMonth() + 1);
					}
				}
			} else {
				result.card.cardholderName = present(identifiers.nameOnCard);
				result.card.code = present(identifiers.securityCode);
				const expiration = present(identifiers.expirationDate);
				if (expiration) {
					const date = new Date(expiration);
					if (!Number.isNaN(date.getTime())) {
						result.card.expYear = String(date.getUTCFullYear());
						result.card.expMonth = String(date.getUTCMonth() + 1);
					}
				}
				for (
					const [key, value, type] of [
						['Issuing Bank', identifiers.issuingBank, 0],
						['Issue Date', identifiers.issueDate, 0],
						['PIN', identifiers.pin, 1],
					] as [string, unknown, number][]
				) addField(result, key, value, type);
			}
		} else {
			const username = present(identifiers.username) ?? present(identifiers.email);
			result.login!.username = username;
			result.login!.password = present(identifiers.password);
			result.login!.totp = present(identifiers.totp);
			result.login!.uris = uris(
				legacy
					? (typeof record.login_url === 'string' ? record.login_url : undefined)
					: present(identifiers.url) ?? undefined,
			);
			if (legacy && !(result.login!.uris as unknown[]).length) {
				const uriNames = new Set([
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
				const alternate = Object.entries(identifiers).find(([key, value]) =>
					uriNames.has(key.toLowerCase()) && present(value)
				);
				if (alternate) result.login!.uris = uris(present(alternate[1]) ?? undefined);
			}
			if (legacy && !present(identifiers.username)) result.login!.username = present(identifiers.email);
		}
		const customKey = legacy ? 'custom_fields' : 'customFields';
		const customFields = identifiers[customKey];
		if (customFields != null) {
			if (!Array.isArray(customFields)) throw new Error('Invalid Password Boss JSON custom fields.');
			for (const field of customFields) {
				if (!field || typeof field !== 'object' || Array.isArray(field)) {
					throw new Error('Invalid Password Boss JSON custom field.');
				}
				const entry = field as Record<string, unknown>;
				addField(result, present(entry.name) ?? '', entry.value);
			}
		}
		if (!legacy && Array.isArray(record.tags) && record.tags.length) addField(result, 'Tags', record.tags.join(', '));
		if (legacy) {
			const normalizedNotes = typeof identifiers.notes === 'string'
				? identifiers.notes.split('\\r\\n').join('\n').split('\\n').join('\n')
				: '';
			result.notes = present(normalizedNotes);
			for (const [key, value] of Object.entries(identifiers)) {
				if (['notes', 'ignoreItemInSecurityScore', customKey].includes(key) || value == null || !String(value).trim()) {
					continue;
				}
				if (isCard && ['cardNumber', 'nameOnCard', 'security_code', 'expires', 'cardType'].includes(key)) continue;
				if (!isCard && ['username', 'email', 'password', 'totp'].includes(key)) continue;
				addField(result, key, value);
			}
		} else {
			const handled = new Set([
				'id',
				'itemType',
				'itemTypeName',
				'logoColor',
				'folder',
				'name',
				'notes',
				'customFields',
				'tags',
				...(isCard
					? [
						'cardNumber',
						'nameOnCard',
						'securityCode',
						'expirationDate',
						'cardType',
						'issuingBank',
						'issueDate',
						'pin',
					]
					: ['url', 'username', 'password', 'totp']),
			]);
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
			for (const [key, value] of Object.entries(record)) {
				if (
					handled.has(key) || value == null
					|| (key === 'email' && !present(identifiers.username) && !!present(identifiers.email))
				) continue;
				addField(result, key, String(value), passwordFields.has(key.toLowerCase()) ? 1 : 0);
			}
		}
		if (
			result.type === 1 && !present(result.login!.username) && !present(result.login!.password)
			&& !(result.login!.uris as unknown[]).length
		) {
			result.type = 2;
			delete result.login;
			result.secureNote = { type: 0 };
		}
		items.push(result);
	};
	if (Array.isArray(parsed)) {
		for (const record of parsed) process(record);
	} else if (parsed && typeof parsed === 'object') {
		const document = parsed as Record<string, unknown>;
		if (!Array.isArray(document.items)) throw new Error('Invalid Password Boss JSON items.');
		if (document.folders != null) {
			if (!Array.isArray(document.folders)) throw new Error('Invalid Password Boss JSON folders.');
			for (const folder of document.folders) {
				if (!folder || typeof folder !== 'object' || Array.isArray(folder)) {
					throw new Error('Invalid Password Boss JSON folder.');
				}
				const value = folder as Record<string, unknown>;
				const id = present(value.id), name = present(value.name);
				if (id && name) {
					folderIds.set(id, name);
					const currentId = folderIds.get(name);
					if (!currentId) {
						folderIds.set(name, id);
						folders.push({ id, name });
					}
				}
			}
		}
		for (const record of document.items) process(record, true);
	} else throw new Error('Invalid Password Boss JSON.');
	return { encrypted: false, items, [organization ? 'collections' : 'folders']: folders };
}
function parsePsonoJson(source: string, organization: boolean): JsonObject {
	let document: unknown;
	try {
		document = JSON.parse(source);
	} catch {
		throw new Error('Invalid Psono JSON.');
	}
	if (!document || typeof document !== 'object' || Array.isArray(document)) throw new Error('Invalid Psono JSON.');
	const root = document as Record<string, unknown>;
	const items: VaultItem[] = [], folders: JsonObject[] = [], folderIds = new Map<string, string>();
	const groups = (raw: unknown, parent = ''): void => {
		if (raw == null) return;
		if (!Array.isArray(raw)) throw new Error('Invalid Psono folders.');
		for (const value of raw) {
			if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid Psono folder.');
			const folder = value as Record<string, unknown>;
			if (typeof folder.name !== 'string' || !folder.name.trim()) throw new Error('Invalid Psono folder name.');
			const name = parent ? `${parent}/${folder.name}` : folder.name;
			const folderItems = folder.items == null ? [] : folder.items;
			const folderChildren = folder.folders == null ? [] : folder.folders;
			if (!Array.isArray(folderItems) || !Array.isArray(folderChildren)) {
				throw new Error('Invalid Psono folder contents.');
			}
			if (!folderItems.length && !folderChildren.length) continue;
			groups(folderChildren, name);
			if (folderItems.length) parseItems(folderItems, name);
			else addFolder(name, null);
		}
	};
	const addFolder = (name: string, target: VaultItem | null): void => {
		if (!name.trim()) return;
		const add = (path: string) => {
			let id = folderIds.get(path);
			if (!id) {
				id = randomUUID();
				folderIds.set(path, id);
				folders.push({ id, name: path });
			}
			return id;
		};
		const id = add(name);
		const parts = name.split('/');
		for (let index = parts.length - 1; index > 0; index--) add(parts.slice(0, index).join('/'));
		if (target) {
			if (organization) target.collectionIds = [id];
			else target.folderId = id;
		}
	};
	const processKvp = (target: VaultItem, key: string, raw: unknown, type = 0): void => {
		if (raw == null) return;
		const value = String(raw);
		if (!value.trim()) return;
		if (value.length > 200 || /[\r\n]/.test(value.trim())) {
			target.notes = `${target.notes ?? ''}${key.trim() ? `${key}: ` : ''}${value.replace(/\r\n|\r/g, '\n')}\n`;
		} else target.fields!.push({ name: key.trim() ? key : '', value, type });
	};
	const parseItems = (raw: unknown[], folder?: string): void => {
		for (const value of raw) {
			if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid Psono item.');
			const entry = value as Record<string, unknown>, type = entry.type;
			const result = item();
			let mapped = new Set(['type', 'name']);
			let includeUnmapped = false;
			const assignUnmapped = () => {
				for (const key of Object.keys(entry)) if (!mapped.has(key)) processKvp(result, key, entry[key]);
			};
			if (type === 'website_password') {
				includeUnmapped = true;
				mapped = new Set([
					'type',
					'name',
					'website_password_title',
					'website_password_notes',
					'website_password_username',
					'website_password_password',
					'website_password_url',
					'autosubmit',
					'website_password_auto_submit',
					'urlfilter',
					'website_password_url_filter',
				]);
				result.name = present(entry.website_password_title) ?? '--';
				result.notes = present(entry.website_password_notes);
				result.login!.username = present(entry.website_password_username);
				result.login!.password = present(entry.website_password_password);
				const uri = present(entry.website_password_url);
				result.login!.uris = uri
					? [{
						uri: uri.trim().includes('://') || !uri.trim().includes('.') ? uri.trim() : `http://${uri.trim()}`,
						match: null,
					}]
					: [];
				if (entry.website_password_auto_submit != null) {
					processKvp(result, 'website_password_auto_submit', entry.website_password_auto_submit, 2);
				}
				processKvp(result, 'website_password_url_filter', entry.website_password_url_filter);
			} else if (type === 'application_password') {
				includeUnmapped = true;
				mapped = new Set([
					'type',
					'name',
					'application_password_title',
					'application_password_notes',
					'application_password_username',
					'application_password_password',
				]);
				result.name = present(entry.application_password_title) ?? '--';
				result.notes = present(entry.application_password_notes);
				result.login!.username = present(entry.application_password_username);
				result.login!.password = present(entry.application_password_password);
			} else if (type === 'bookmark') {
				includeUnmapped = true;
				mapped = new Set([
					'type',
					'name',
					'bookmark_title',
					'bookmark_notes',
					'bookmark_url',
					'urlfilter',
					'bookmark_url_filter',
				]);
				result.name = present(entry.bookmark_title) ?? '--';
				result.notes = present(entry.bookmark_notes);
				const uri = present(entry.bookmark_url);
				result.login!.uris = uri
					? [{
						uri: uri.trim().includes('://') || !uri.trim().includes('.') ? uri.trim() : `http://${uri.trim()}`,
						match: null,
					}]
					: [];
			} else if (type === 'note') {
				includeUnmapped = true;
				mapped = new Set(['type', 'name', 'note_title', 'note_notes']);
				result.type = 2;
				delete result.login;
				result.secureNote = { type: 0 };
				result.name = present(entry.note_title) ?? '--';
				result.notes = present(entry.note_notes);
			} else if (type === 'totp') {
				includeUnmapped = true;
				mapped = new Set(['type', 'name', 'totp_title', 'totp_notes', 'totp_code']);
				result.name = present(entry.totp_title) ?? '--';
				result.notes = present(entry.totp_notes);
				result.login!.totp = present(entry.totp_code);
			} else if (type === 'environment_variables') {
				includeUnmapped = true;
				mapped = new Set([
					'type',
					'name',
					'environment_variables_title',
					'environment_variables_notes',
					'environment_variables_variables',
				]);
				result.type = 2;
				delete result.login;
				result.secureNote = { type: 0 };
				result.name = present(entry.environment_variables_title) ?? '--';
				result.notes = present(entry.environment_variables_notes);
				if (entry.environment_variables_variables != null) {
					if (!Array.isArray(entry.environment_variables_variables)) {
						throw new Error('Invalid Psono environment variables.');
					}
					for (const pair of entry.environment_variables_variables) {
						if (!pair || typeof pair !== 'object' || Array.isArray(pair)) {
							throw new Error('Invalid Psono environment variable.');
						}
						const field = pair as Record<string, unknown>;
						processKvp(result, String(field.key ?? ''), field.value);
					}
				}
			}
			// GPG entries are intentionally represented as the reference importer emits them (an empty login item).
			if (includeUnmapped) assignUnmapped();
			if (!result.name.trim()) result.name = '--';
			if (!result.notes?.trim()) result.notes = null;
			if (folder) addFolder(folder, result);
			items.push(result);
		}
	};
	groups(root.folders);
	if (root.items != null) {
		if (!Array.isArray(root.items)) throw new Error('Invalid Psono items.');
		parseItems(root.items);
	}
	return { encrypted: false, items, [organization ? 'collections' : 'folders']: folders };
}
function parseProtonPassJson(source: string, organization: boolean): JsonObject {
	let parsed: unknown;
	try {
		parsed = JSON.parse(source);
	} catch {
		throw new Error('Invalid Proton Pass JSON.');
	}
	if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Invalid Proton Pass JSON.');
	const document = parsed as Record<string, unknown>;
	if (document.encrypted === true) throw new Error('Encrypted Proton Pass exports are unsupported.');
	if (!document.vaults || typeof document.vaults !== 'object' || Array.isArray(document.vaults)) {
		throw new Error('Invalid Proton Pass vaults.');
	}
	const items: VaultItem[] = [], folders: JsonObject[] = [], folderIds = new Map<string, string>();
	const assignFolder = (name: unknown, target: VaultItem): void => {
		if (typeof name !== 'string' || !name.trim()) return;
		let id = folderIds.get(name);
		if (!id) {
			id = randomUUID();
			folderIds.set(name, id);
			folders.push({ id, name });
		}
		if (organization) target.collectionIds = [id];
		else target.folderId = id;
	};
	const custom = (target: VaultItem, name: unknown, value: unknown, hidden = false): void => {
		const textValue = typeof value === 'string' ? value : typeof value === 'number' ? String(value) : '';
		enpassCustom(target, name, textValue, hidden ? 1 : 0);
	};
	const extraValue = (field: Record<string, unknown>): unknown => {
		const data = field.data && typeof field.data === 'object' && !Array.isArray(field.data)
			? field.data as Record<string, unknown>
			: {};
		return field.type === 'totp' ? data.totpUri : field.type === 'timestamp' ? data.timestamp : data.content;
	};
	const extras = (target: VaultItem, fields: unknown): void => {
		if (fields == null) return;
		if (!Array.isArray(fields)) throw new Error('Invalid Proton Pass extra fields.');
		for (const value of fields) {
			if (!value || typeof value !== 'object' || Array.isArray(value)) {
				throw new Error('Invalid Proton Pass extra field.');
			}
			const field = value as Record<string, unknown>;
			custom(target, field.fieldName, extraValue(field), field.type === 'hidden' || field.type === 'totp');
		}
	};
	const sections = (target: VaultItem, values: unknown): void => {
		if (values == null) return;
		if (!Array.isArray(values)) throw new Error('Invalid Proton Pass sections.');
		for (const section of values) {
			if (!section || typeof section !== 'object' || Array.isArray(section)) {
				throw new Error('Invalid Proton Pass section.');
			}
			extras(target, (section as Record<string, unknown>).sectionFields);
		}
	};
	for (const rawVault of Object.values(document.vaults)) {
		if (!rawVault || typeof rawVault !== 'object' || Array.isArray(rawVault)) {
			throw new Error('Invalid Proton Pass vault.');
		}
		const vault = rawVault as Record<string, unknown>;
		if (!Array.isArray(vault.items)) throw new Error('Invalid Proton Pass items.');
		for (const rawItem of vault.items) {
			if (!rawItem || typeof rawItem !== 'object' || Array.isArray(rawItem)) {
				throw new Error('Invalid Proton Pass item.');
			}
			const sourceItem = rawItem as Record<string, unknown>;
			if (sourceItem.state === 2) continue;
			const data = sourceItem.data && typeof sourceItem.data === 'object' && !Array.isArray(sourceItem.data)
				? sourceItem.data as Record<string, unknown>
				: undefined;
			const metadata = data?.metadata && typeof data.metadata === 'object' && !Array.isArray(data.metadata)
				? data.metadata as Record<string, unknown>
				: {};
			const content = data?.content && typeof data.content === 'object' && !Array.isArray(data.content)
				? data.content as Record<string, unknown>
				: {};
			const result = item(metadata.name);
			result.notes = present(metadata.note);
			result.favorite = sourceItem.pinned === true;
			const type = data?.type;
			if (type === 'login') {
				const username = present(content.itemUsername), email = present(content.itemEmail);
				result.login = {
					username: username ?? email,
					password: present(content.password),
					totp: present(content.totpUri),
					uris: uris(content.urls),
				};
				if (username && email) custom(result, 'email', email);
				extras(result, data?.extraFields);
			} else if (type === 'note') {
				result.type = 2;
				delete result.login;
				result.secureNote = { type: 0 };
				extras(result, data?.extraFields);
			} else if (type === 'creditCard') {
				result.type = 3;
				delete result.login;
				const expiry = present(content.expirationDate);
				result.card = {
					cardholderName: present(content.cardholderName),
					number: present(content.number),
					brand: brand(present(content.number)),
					code: present(content.verificationNumber),
					expMonth: expiry ? expiry.substring(5, 7).replace(/^0+/, '') : null,
					expYear: expiry ? expiry.substring(0, 4) : null,
				};
				custom(result, 'PIN', content.pin, true);
				extras(result, data?.extraFields);
			} else if (type === 'identity') {
				result.type = 4;
				delete result.login;
				const fullName = present(content.fullName)?.trim().split(/\s+/).filter(Boolean) ?? [];
				const firstName = present(content.firstName),
					middleName = present(content.middleName),
					lastName = present(content.lastName);
				const mappedFirst = fullName.length ? fullName[0]! : firstName;
				const mappedLast = fullName.length > 1 ? fullName.at(-1)! : lastName;
				const mappedMiddle = fullName.length > 2 ? fullName.slice(1, -1).join(' ') : middleName;
				const identity: JsonObject = {
					firstName: mappedFirst,
					middleName: mappedMiddle,
					lastName: mappedLast,
					email: present(content.email),
					phone: present(content.phoneNumber),
					company: present(content.company),
					ssn: present(content.socialSecurityNumber),
					passportNumber: present(content.passportNumber),
					licenseNumber: present(content.licenseNumber),
					address1: present(content.organization),
					address2: present(content.streetAddress),
					address3: [present(content.floor), present(content.county)].filter(Boolean).join(' ') || null,
					city: present(content.city),
					state: present(content.stateOrProvince),
					postalCode: present(content.zipOrPostalCode),
					country: present(content.countryOrRegion),
				};
				result.identity = identity;
				const mapped = new Set([
					'fullName',
					'firstName',
					'middleName',
					'lastName',
					'email',
					'phoneNumber',
					'company',
					'socialSecurityNumber',
					'passportNumber',
					'licenseNumber',
					'organization',
					'streetAddress',
					'floor',
					'county',
					'city',
					'stateOrProvince',
					'zipOrPostalCode',
					'countryOrRegion',
					'extraPersonalDetails',
					'extraAddressDetails',
					'extraContactDetails',
					'extraWorkDetails',
					'extraSections',
				]);
				for (const [key, value] of Object.entries(content)) {
					if (mapped.has(key)) {
						if (key === 'extraSections') sections(result, value);
						else if (key.startsWith('extra')) extras(result, value);
					} else custom(result, key, value);
				}
				extras(result, data?.extraFields);
			} else if (type === 'alias') {
				result.login!.username = present(sourceItem.aliasEmail);
				extras(result, data?.extraFields);
			} else if (type === 'sshKey') {
				result.type = 5;
				delete result.login;
				result.sshKey = {
					privateKey: present(content.privateKey) ?? '',
					publicKey: present(content.publicKey) ?? '',
					keyFingerprint: present(content.fingerprint) ?? '',
				};
				extras(result, data?.extraFields);
				sections(result, content.sections);
			} else {
				result.type = 2;
				delete result.login;
				result.secureNote = { type: 0 };
				if (type === 'wifi') {
					custom(result, 'Password', content.password, true);
					custom(result, 'SSID', content.ssid);
					const security = content.security;
					if (security != null) {
						custom(
							result,
							'Security',
							({ 1: 'WPA', 2: 'WPA2', 3: 'WPA3', 4: 'WEP' } as Record<number, string>)[Number(security)] ?? 'Unknown',
						);
					}
					sections(result, content.sections);
				} else {
					extras(result, data?.extraFields);
					for (const [key, value] of Object.entries(content)) {
						if (key === 'sections') sections(result, value);
						else custom(result, key, value);
					}
				}
			}
			assignFolder(vault.name, result);
			items.push(result);
		}
	}
	return { encrypted: false, items, [organization ? 'collections' : 'folders']: folders };
}

function parseFSecureFsk(source: string): JsonObject {
	let parsed: unknown;
	try {
		parsed = JSON.parse(source);
	} catch {
		throw new Error('Invalid F-Secure FSK JSON.');
	}
	if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Invalid F-Secure FSK JSON.');
	const data = (parsed as Record<string, unknown>).data;
	if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Invalid F-Secure FSK JSON.');
	const items: VaultItem[] = [];
	for (const raw of Object.values(data)) {
		if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('Invalid F-Secure FSK entry.');
		const entry = raw as Record<string, unknown>;
		if (entry.type !== 1 && entry.type !== 2) continue;
		const result = item(entry.service);
		result.notes = present(entry.notes);
		result.favorite = typeof entry.favorite === 'number' && entry.favorite > 0;
		if (entry.type === 1) {
			const loginUris = uris(entry.url);
			result.login = {
				username: present(entry.username),
				password: present(entry.password),
				totp: null,
				uris: loginUris,
			};
			if (!result.login.username && !result.login.password && loginUris.length === 0) {
				result.type = 2;
				delete result.login;
				result.secureNote = { type: 0 };
			}
		} else {
			result.type = 3;
			delete result.login;
			const number = present(entry.creditNumber);
			result.card = {
				cardholderName: present(entry.username),
				number,
				brand: brand(number),
				code: present(entry.creditCvv),
				expMonth: null,
				expYear: null,
			};
			const expiry = present(entry.creditExpiry);
			const match = expiry?.replace(/\s/g, '').match(/^0?([1-9]|1[0-2])\/((?:[1-2][0-9])?[0-9]{2})$/);
			if (match) {
				result.card.expMonth = match[1]!;
				const year = match[2]!;
				result.card.expYear = year.length === 2 ? `${Number(year) < 50 ? '20' : '19'}${year}` : year;
			} else if (expiry) enpassCustom(result, 'Expiration', expiry, 0);
			const pin = present(entry.password);
			if (pin) enpassCustom(result, 'PIN', pin, 0);
		}
		items.push(result);
	}
	return { encrypted: false, items };
}

/** Parse the Avast Passwords JSON shape used by the reference importer. */
export function parseExternalJson(format: ExternalJsonFormat, source: string, organization = false): JsonObject {
	if (format === 'protonpass') return parseProtonPassJson(source, organization);
	if (format === 'fsecurefsk') return parseFSecureFsk(source);
	if (format === 'keeperjson') return parseKeeperJson(source, organization);
	if (format === 'dashlanejson') return parseDashlaneJson(source);
	if (format === 'passwordbossjson') return parsePasswordBossJson(source, organization);
	if (format === 'gnomejson') return parseGnomeJson(source, organization);
	if (format === 'passkyjson') return parsePasskyJson(source);
	if (format === 'passmanjson') return parsePassmanJson(source, organization);
	if (format === 'psonojson') return parsePsonoJson(source, organization);
	if (format === 'enpassjson') return parseEnpassJson(source);
	if (format !== 'avastjson') throw new Error('Unsupported external JSON format.');
	let parsed: unknown;
	try {
		parsed = JSON.parse(source);
	} catch {
		throw new Error('Invalid Avast JSON.');
	}
	if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Invalid Avast JSON.');
	const document = parsed as Record<string, unknown>, items: VaultItem[] = [];
	for (const value of entries(document.logins, 'login')) {
		const result = item(value.custName);
		result.notes = present(value.note);
		result.login = {
			username: present(value.loginName),
			password: present(value.pwd),
			totp: null,
			uris: uris(value.url),
		};
		items.push(result);
	}
	for (const value of entries(document.notes, 'note')) {
		const result = item(value.label);
		result.type = 2;
		delete result.login;
		result.secureNote = { type: 0 };
		result.notes = present(value.text);
		items.push(result);
	}
	for (const value of entries(document.cards, 'card')) {
		const result = item(value.custName), number = present(value.cardNumber);
		result.type = 3;
		delete result.login;
		result.notes = present(value.note);
		const card: JsonObject = {
			cardholderName: present(value.holderName),
			number,
			code: present(value.cvv),
			brand: brand(number),
		};
		if (value.expirationDate && typeof value.expirationDate === 'object' && !Array.isArray(value.expirationDate)) {
			const expiration = value.expirationDate as Record<string, unknown>;
			if (expiration.month != null) card.expMonth = String(expiration.month);
			if (expiration.year != null) card.expYear = String(expiration.year);
		}
		result.card = card;
		items.push(result);
	}
	return { encrypted: false, items, folders: [] };
}
