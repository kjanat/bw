import { DOMParser, type Element } from '@xmldom/xmldom';
import type { JsonObject } from '#client';
import type { VaultItem } from '#models';
import { randomUUID } from 'node:crypto';

function children(element: Element, tag: string): Element[] {
	const result: Element[] = [];
	for (let index = 0; index < element.childNodes.length; index++) {
		const node = element.childNodes.item(index);
		if (node?.nodeType === 1 && (node as Element).tagName === tag) result.push(node as Element);
	}
	return result;
}
const child = (element: Element, tag: string) => children(element, tag)[0];
const content = (element: Element | undefined) => element?.textContent ?? '';

/** Parse Password Dragon XML exports using the reference importer's direct-child field rules. */
export function parsePasswordDragonXml(source: string, organization = false): JsonObject {
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
		throw new Error('Invalid Password Dragon XML.', { cause: error });
	}
	if (!root) throw new Error('Invalid Password Dragon XML.');
	const records: Element[] = [];
	let hasManager = false;
	const collectRecords = (element: Element): void => {
		if (element.tagName === 'PasswordManager') hasManager = true;
		for (let index = 0; index < element.childNodes.length; index++) {
			const node = element.childNodes.item(index);
			if (node?.nodeType !== 1) continue;
			const childElement = node as Element;
			if (element.tagName === 'PasswordManager' && childElement.tagName === 'record') records.push(childElement);
			collectRecords(childElement);
		}
	};
	collectRecords(root);
	if (!hasManager) throw new Error('Missing PasswordManager root node.');
	const folders: JsonObject[] = [], folderIds = new Map<string, string>(), items: VaultItem[] = [];
	const addFolder = (raw: string, result: VaultItem): void => {
		const name = raw.replace(/\\/g, '/').replace(/^\/+/, ''), id = folderIds.get(name) ?? randomUUID();
		if (!name) return;
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
		if (organization) result.collectionIds = [id];
		else result.folderId = id;
	};
	for (const record of records) {
		const category = content(child(record, 'Category'));
		const accountName = content(child(record, 'Account-Name'));
		const name = accountName.trim() ? accountName : '--';
		const notes = content(child(record, 'Notes'));
		const result: VaultItem = {
			type: 1,
			name,
			favorite: false,
			reprompt: 0,
			notes: notes.trim() ? notes : null,
			fields: [],
			login: {
				username: content(child(record, 'User-Id')).trim() ? content(child(record, 'User-Id')) : null,
				password: content(child(record, 'Password')).trim() ? content(child(record, 'Password')) : null,
				totp: null,
				uris: null,
			},
		};
		const url = content(child(record, 'URL'));
		if (url.trim()) {
			let uri = url.trim();
			if (!uri.includes('://') && uri.includes('.')) uri = `http://${uri}`;
			result.login!.uris = [{ uri: uri.slice(0, 1000), match: null }];
		}
		if (category.trim() && category !== 'Unfiled') addFolder(category, result);
		const attributes: Element[] = [];
		for (let index = 0; index < record.childNodes.length; index++) {
			const node = record.childNodes.item(index);
			if (node?.nodeType === 1 && /^Attribute-(?:[1-9]|10)$/.test((node as Element).tagName)) {
				attributes.push(node as Element);
			}
		}
		for (const attribute of attributes) {
			const key = attribute.tagName, value = content(attribute);
			if (!value.trim() || value === 'null') continue;
			if (value.length > 200 || /[\r\n]/.test(value.trim())) {
				result.notes = `${result.notes ?? ''}${key}: ${value.replace(/\r\n|\r/g, '\n')}\n`;
			} else result.fields!.push({ name: key, value, type: 0 });
		}
		items.push(result);
	}
	return { encrypted: false, items, [organization ? 'collections' : 'folders']: folders };
}
