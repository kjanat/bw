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
const blank = (value: string | null | undefined) => !value || !value.trim();

/** Parse Sticky Password XML using its linked-login and group ancestry mapping. */
export function parseStickyPasswordXml(source: string, organization = false): JsonObject {
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
		throw new Error('Invalid Sticky Password XML.', { cause: error });
	}
	if (!root) throw new Error('Invalid Sticky Password XML.');
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
	const database = find(root, 'Database');
	if (!database) throw new Error('Missing Database node.');
	const groupsNode = child(database, 'Groups');
	const groupById = new Map<string, Element>();
	if (groupsNode) {
		for (const group of children(groupsNode, 'Group')) {
			const id = group.getAttribute('ID');
			if (id) groupById.set(id, group);
		}
	}
	const folderList: JsonObject[] = [], folderIds = new Map<string, string>(), items: VaultItem[] = [];
	const addFolder = (path: string, item: VaultItem) => {
		let id = folderIds.get(path);
		if (!id) {
			id = randomUUID();
			folderIds.set(path, id);
			folderList.push({ id, name: path });
		}
		const parts = path.split('/');
		for (let index = parts.length - 1; index > 0; index--) {
			const parent = parts.slice(0, index).join('/');
			if (!folderIds.has(parent)) {
				const parentId = randomUUID();
				folderIds.set(parent, parentId);
				folderList.push({ id: parentId, name: parent });
			}
		}
		if (organization) item.collectionIds = [id];
		else item.folderId = id;
	};
	const groupsText = (id: string | null, seen = new Set<string>()): string => {
		if (blank(id) || seen.has(id!)) return '';
		seen.add(id!);
		const group = groupById.get(id!);
		if (!group) return '';
		const name = group.getAttribute('Name') ?? '';
		const parent = groupsText(group.getAttribute('ParentID'), seen);
		return parent ? `${parent}/${name}` : name;
	};
	const logins = find(database, 'Logins');
	const accounts = find(database, 'Accounts');
	const loginNodes = logins ? children(logins, 'Login') : [];
	const accountNodes = accounts ? children(accounts, 'Account') : [];
	for (const login of loginNodes) {
		const id = login.getAttribute('ID');
		if (blank(id)) continue;
		let account: Element | undefined;
		for (const candidate of accountNodes) {
			const links = child(candidate, 'LoginLinks');
			if (links && children(links, 'Login').some(link => link.getAttribute('SourceLoginID') === id)) {
				account = candidate;
				break;
			}
		}
		const title = account?.getAttribute('Name') ?? '';
		const notes = account?.getAttribute('Comments') ?? '';
		const groupId = account?.getAttribute('ParentID') ?? '';
		const groupPath = blank(groupId) ? '' : groupsText(groupId);
		const item: VaultItem = {
			type: 1,
			name: blank(title) ? '--' : title,
			favorite: false,
			reprompt: 0,
			notes: blank(notes) ? null : notes.split('/n').join('\n'),
			fields: [],
			login: {
				username: blank(login.getAttribute('Name')) ? null : login.getAttribute('Name'),
				password: blank(login.getAttribute('Password')) ? null : login.getAttribute('Password'),
				totp: null,
				uris: [],
			},
		};
		const link = account?.getAttribute('Link') ?? '';
		let uri = blank(link) ? null : link.trim();
		if (uri && !uri.includes('://') && uri.includes('.')) uri = `http://${uri}`;
		if (uri && uri.length > 1000) uri = uri.slice(0, 1000);
		if (uri) item.login!.uris = [{ uri, match: null }];
		if (!blank(groupPath)) addFolder(groupPath, item);
		items.push(item);
	}
	return { encrypted: false, items, [organization ? 'collections' : 'folders']: folderList };
}
