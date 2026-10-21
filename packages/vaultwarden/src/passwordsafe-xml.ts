import { DOMParser, type Element } from '@xmldom/xmldom';
import type { JsonObject } from '#client';
import type { VaultItem } from '#models';
import { randomUUID } from 'node:crypto';

const children = (element: Element, tag: string): Element[] => {
	const result: Element[] = [];
	for (let index = 0; index < element.childNodes.length; index++) {
		const node = element.childNodes.item(index);
		if (node?.nodeType === 1 && (node as Element).tagName === tag) result.push(node as Element);
	}
	return result;
};
const child = (element: Element, tag: string) => children(element, tag)[0];
const value = (element: Element | undefined) => element?.textContent ?? '';
const blank = (input: string) => !input.trim();

/** Parse pwsafe.org XML exports using the reference field and email fallback rules. */
export function parsePasswordSafeXml(source: string, organization = false): JsonObject {
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
		throw new Error('Invalid Password Safe XML.', { cause: error });
	}
	if (!root) throw new Error('Invalid Password Safe XML.');
	const find = (element: Element): Element | undefined => {
		if (element.tagName === 'passwordsafe') return element;
		for (let index = 0; index < element.childNodes.length; index++) {
			const node = element.childNodes.item(index);
			if (node?.nodeType !== 1) continue;
			const match = find(node as Element);
			if (match) return match;
		}
		return undefined;
	};
	const safe = find(root);
	if (!safe) throw new Error('Missing passwordsafe node.');
	const folders: JsonObject[] = [], folderIds = new Map<string, string>(), items: VaultItem[] = [];
	const addFolder = (name: string, item: VaultItem): void => {
		if (!name.trim()) return;
		const path = name.split('.').join('/');
		let id = folderIds.get(path);
		if (!id) {
			id = randomUUID();
			folderIds.set(path, id);
			folders.push({ id, name: path });
		}
		const parts = path.split('/');
		for (let index = parts.length - 1; index > 0; index--) {
			const parent = parts.slice(0, index).join('/');
			if (!folderIds.has(parent)) {
				const parentId = randomUUID();
				folderIds.set(parent, parentId);
				folders.push({ id: parentId, name: parent });
			}
		}
		if (organization) item.collectionIds = [id];
		else item.folderId = id;
	};
	// Match bw's String.split(null) coercion when the optional XML attribute is absent.
	const delimiter = safe.getAttribute('delimiter') ?? 'null';
	for (const entry of children(safe, 'entry')) {
		const group = value(child(entry, 'group'));
		const title = value(child(entry, 'title'));
		const username = value(child(entry, 'username'));
		const email = value(child(entry, 'email'));
		const notesNode = child(entry, 'notes');
		const rawNotes = notesNode ? value(notesNode) : '';
		let notes = notesNode ? (blank(rawNotes) ? '' : rawNotes.split(delimiter).join('\n')) : '';
		const loginUsername = blank(username) && child(entry, 'email')
			? (blank(email) ? null : email)
			: blank(username)
			? null
			: username;
		if (!blank(email) && !blank(username)) notes = blank(notes) ? `Email: ${email}` : `${notes}\nEmail: ${email}`;
		const uriValue = value(child(entry, 'url')).trim();
		let uri: string | null = uriValue ? uriValue : null;
		if (uri && !uri.includes('://') && uri.includes('.')) uri = `http://${uri}`;
		if (uri && uri.length > 1000) uri = uri.slice(0, 1000);
		const item: VaultItem = {
			type: 1,
			name: blank(title) ? '--' : title,
			favorite: false,
			reprompt: 0,
			notes: blank(notes) ? null : notes,
			fields: [],
			login: {
				username: loginUsername,
				password: blank(value(child(entry, 'password'))) ? null : value(child(entry, 'password')),
				totp: null,
				uris: uri ? [{ uri, match: null }] : [],
			},
		};
		addFolder(group, item);
		items.push(item);
	}
	return { encrypted: false, items, [organization ? 'collections' : 'folders']: folders };
}
