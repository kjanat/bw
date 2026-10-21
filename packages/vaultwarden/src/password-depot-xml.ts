import { DOMParser, type Element } from '@xmldom/xmldom';
import type { JsonObject } from '#client';
import type { VaultItem } from '#models';
import { randomUUID } from 'node:crypto';

const direct = (parent: Element, tag: string): Element[] => {
	const values: Element[] = [];
	for (let index = 0; index < parent.childNodes.length; index++) {
		const node = parent.childNodes.item(index);
		if (node?.nodeType === 1 && (node as Element).tagName === tag) values.push(node as Element);
	}
	return values;
};
const child = (parent: Element, tag: string) => direct(parent, tag)[0];
const value = (element?: Element | null) => element?.textContent ?? '';
const loginTypes = new Set(['0', '5', '6', '8', '9', '10', '11']);
const secureNoteTypes = new Set(['2', '4', '7']);

/** Parse Password Depot 17 XML using its Windows child-field and macOS attribute variants. */
export function parsePasswordDepot17Xml(source: string, organization = false): JsonObject {
	if (/<!ENTITY/i.test(source)) throw new Error('XML entity declarations are not supported.');
	for (const declaration of source.matchAll(/<!DOCTYPE[^>[]*/gi)) {
		if (/\b(?:SYSTEM|PUBLIC)\b/i.test(declaration[0])) {
			throw new Error('External XML document types are not supported.');
		}
	}
	let root: Element | null;
	try {
		root = new DOMParser({
			onError: () => {
				throw new Error('Malformed XML.');
			},
		})
			.parseFromString(source, 'application/xml').documentElement;
	} catch (error) {
		throw new Error('Invalid Password Depot XML.', { cause: error });
	}
	if (!root) throw new Error('Invalid Password Depot XML.');
	const find = (element: Element, tag: string): Element | undefined => {
		if (element.tagName === tag) return element;
		for (let index = 0; index < element.childNodes.length; index++) {
			const node = element.childNodes.item(index);
			if (node?.nodeType !== 1) continue;
			const match = find(node as Element, tag);
			if (match) return match;
		}
		return undefined;
	};
	const rootNode = find(root, 'passwordfile');
	if (!rootNode) throw new Error('Missing passwordfile root node.');
	const header = child(rootNode, 'header');
	if (!header) throw new Error('Missing Password Depot header.');
	const versionNode = child(header, 'version') ?? child(header, 'dataformat');
	const version = value(versionNode);
	if (!version) throw new Error('Missing Password Depot version.');
	if (!version.startsWith('17')) throw new Error('Unsupported Password Depot version.');
	if (value(child(header, 'encrypted')) === 'True') throw new Error('Encrypted Password Depot files are unsupported.');
	const passwords = find(rootNode, 'passwords');
	if (!passwords) throw new Error('Missing Password Depot passwords node.');
	const favorites = new Set<string>();
	const favoriteNode = child(rootNode, 'favorites');
	if (favoriteNode) {
		let decoded: string;
		try {
			decoded = Buffer.from(value(favoriteNode), 'base64').toString('utf8');
		} catch {
			throw new Error('Invalid Password Depot favorites.');
		}
		for (const line of decoded.split(/\r?\n/)) favorites.add(line);
	}
	const items: VaultItem[] = [], folders: JsonObject[] = [], folderIds = new Map<string, string>();
	const addCustom = (item: VaultItem, name: string, rawValue: string, type = 0): void => {
		if (!rawValue.trim()) return;
		if (rawValue.length > 200 || /[\r\n]/.test(rawValue.trim())) {
			item.notes = `${item.notes ?? ''}${name}: ${rawValue.replace(/\r\n|\r/g, '\n').split('\n').join('\n')}\n`;
		} else item.fields!.push({ name, value: rawValue, type });
	};
	const fieldValue = (field: Element): JsonObject | null => {
		const attributes = field.attributes;
		let name: string | null, content: string | null, kind: string, visible: string | null;
		if (attributes?.length) {
			name = field.getAttribute('name');
			content = field.getAttribute('value');
			kind = field.getAttribute('type') ?? '2';
			visible = field.getAttribute('visible');
		} else {
			name = child(field, 'name')?.textContent ?? null;
			content = child(field, 'value')?.textContent ?? null;
			kind = child(field, 'type')?.textContent ?? '2';
			visible = child(field, 'visible')?.textContent ?? null;
		}
		if (name == null) return null;
		if (kind === '3' && content != null && !Number.isNaN(Number(content))) {
			content = new Date((Number.parseInt(content, 10) - 25569) * 86400000).toLocaleDateString();
		}
		return { name, value: content ?? '', type: kind === '1' || visible === '0' ? 1 : kind === '5' ? 2 : 0 };
	};
	const mapFullName = (item: VaultItem, name: string) => {
		const parts = name.split(' ');
		if (parts[0]?.trim()) item.identity!.firstName = parts[0];
		if (parts.length === 2) item.identity!.lastName = parts[1];
		else if (parts.length >= 3) {
			item.identity!.middleName = parts[1];
			item.identity!.lastName = parts.slice(2).join(' ');
		}
	};
	const parseCustomFields = (fieldsElement: Element, sourceType: string, item: VaultItem) => {
		for (const fieldElement of direct(fieldsElement, 'field')) {
			const field = fieldValue(fieldElement);
			if (!field) continue;
			const name = String(field.name), content = String(field.value), type = Number(field.type);
			if (sourceType === '1') {
				const mapped: Record<string, string> = {
					IDS_CardHolder: 'cardholderName',
					IDS_CardNumber: 'number',
					IDS_CardCode: 'code',
				};
				if (mapped[name]) {
					item.card![mapped[name]!] = content;
					if (name === 'IDS_CardNumber') item.card!.brand = brand(content);
				} else if (name === 'IDS_CardExpires') {
					const match = content.replace(/\s/g, '').match(/^0?([1-9]|1[0-2])\/((?:[1-2][0-9])?[0-9]{2})$/);
					if (match) {
						item.card!.expMonth = match[1]!;
						const year = match[2]!;
						item.card!.expYear = year.length === 2 ? `${Number(year) < 50 ? '20' : '19'}${year}` : year;
					}
				} else addCustom(item, name, content, type);
			} else if (sourceType === '3') {
				const mapped: Record<string, string> = {
					IDS_IdentityEmail: 'email',
					IDS_IdentityFirstName: 'firstName',
					IDS_IdentityLastName: 'lastName',
					IDS_IdentityCompany: 'company',
					IDS_IdentityAddress1: 'address1',
					IDS_IdentityAddress2: 'address2',
					IDS_IdentityCity: 'city',
					IDS_IdentityState: 'state',
					IDS_IdentityZIP: 'postalCode',
					IDS_IdentityCountry: 'country',
					IDS_IdentityPhone: 'phone',
				};
				if (name === 'IDS_IdentityName') mapFullName(item, content);
				else if (mapped[name]) item.identity![mapped[name]!] = content;
				else addCustom(item, name, content, type);
			} else if (sourceType === '4' && name === 'IDS_InformationText') {
				item.notes = content;
			} else addCustom(item, name, content, type);
		}
	};
	const traverse = (group: Element, parentName = ''): void => {
		let groupName = parentName;
		const fingerprint = group.getAttribute('fingerprint');
		if (fingerprint && fingerprint !== 'null') {
			const name = group.getAttribute('name') ?? '-';
			groupName = [parentName, name].filter(Boolean).join('/');
		}
		const folderIndex = groupName
			? folders.findIndex(folder => folder.name === groupName) < 0
				? (folders.push({ id: randomUUID(), name: groupName }), folders.length - 1)
				: folders.findIndex(folder => folder.name === groupName)
			: -1;
		if (groupName && folderIndex >= 0) folderIds.set(groupName, String(folders[folderIndex]!.id));
		for (const entry of direct(group, 'item')) {
			const result: VaultItem = {
				type: 1,
				name: '--',
				favorite: false,
				reprompt: 0,
				notes: null,
				fields: [],
				login: { username: null, password: null, totp: null, uris: [] },
			};
			let sourceType = '0';
			for (let index = 0; index < entry.childNodes.length; index++) {
				const node = entry.childNodes.item(index);
				if (node?.nodeType !== 1) continue;
				const element = node as Element, key = element.tagName, content = element.textContent ?? '';
				if (key === 'hitems') continue;
				if (key === 'description') {
					result.name = content;
					continue;
				}
				if (key === 'comment') {
					result.notes = content;
					continue;
				}
				if (key === 'type') {
					sourceType = content;
					if (sourceType === '1') {
						result.type = 3;
						delete result.login;
						result.card = {};
					} else if (sourceType === '3') {
						result.type = 4;
						delete result.login;
						result.identity = {};
					} else if (secureNoteTypes.has(sourceType)) {
						result.type = 2;
						delete result.login;
						result.secureNote = { type: 0 };
					} else if (!loginTypes.has(sourceType)) result.type = 1;
					continue;
				}
				if (key === 'fingerprint') {
					result.favorite = favorites.has(content);
				}
				if (key === 'customfields') {
					parseCustomFields(element, sourceType, result);
					continue;
				}
				if (sourceType === '5' && key === 'tans') {
					for (const tan of direct(element, 'tan')) {
						let number = '0';
						for (let childIndex = 0; childIndex < tan.childNodes.length; childIndex++) {
							const part = tan.childNodes.item(childIndex);
							if (part?.nodeType !== 1) continue;
							const field = part as Element;
							if (field.tagName === 'number') number = field.textContent ?? '0';
							else addCustom(result, `tan_${number}_${field.tagName}`, field.textContent ?? '');
						}
					}
					continue;
				}
				if (loginTypes.has(sourceType) && ['username', 'password', 'url'].includes(key)) {
					if (key === 'username') result.login!.username = content;
					else if (key === 'password') result.login!.password = content;
					else result.login!.uris = makeUris(content);
					continue;
				}
				addCustom(result, key, content);
			}
			if (groupName) {
				const folderId = folderIds.get(groupName);
				if (folderId) {
					if (organization) result.collectionIds = [folderId];
					else result.folderId = folderId;
				}
			}
			if (!result.name.trim()) result.name = '--';
			if (!result.notes?.trim()) result.notes = null;
			items.push(result);
		}
		for (const subgroup of direct(group, 'group')) traverse(subgroup, groupName);
	};
	for (const group of direct(passwords, 'group')) traverse(group);
	return { encrypted: false, items, [organization ? 'collections' : 'folders']: folders };
}

function brand(number: string): string | null {
	if (/^4/.test(number)) return 'Visa';
	if (/^(5[1-5]|2(22[1-9]|2[3-9]|[3-6]|7[0-1]|720))/.test(number)) return 'Mastercard';
	if (/^3[47]/.test(number)) return 'Amex';
	if (/^(6011|622(12[6-9]|1[3-9][0-9]|[2-8][0-9]{2}|9[0-1][0-9]|92[0-5])|64[4-9]|65)/.test(number)) {
		return 'Discover';
	}
	if (/^36|^30[0-5]/.test(number)) return 'Diners Club';
	if (/^35(2[89]|[3-8][0-9])/.test(number)) return 'JCB';
	return null;
}
function makeUris(value: string): JsonObject[] {
	const uri = value.trim();
	if (!uri) return [];
	return [{ uri: uri.includes('://') || !uri.includes('.') ? uri : `http://${uri}`, match: null }];
}
