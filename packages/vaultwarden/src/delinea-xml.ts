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
const text = (element: Element | undefined) => element?.textContent ?? '';

/** Parse Delinea Secret Server's XML export according to the Bitwarden importer mapping. */
export function parseDelineaXml(source: string, organization = false): JsonObject {
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
		throw new Error('Invalid Delinea XML.', { cause: error });
	}
	if (!root) throw new Error('Invalid Delinea XML.');
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
	const importFile = find(root, 'ImportFile');
	if (!importFile) throw new Error('Missing ImportFile node.');
	const items: VaultItem[] = [], groups: JsonObject[] = [], groupIds = new Map<string, string>();
	const addFolder = (path: string, assign: VaultItem | null): void => {
		if (!path.trim()) return;
		let id = groupIds.get(path);
		if (!id) {
			id = randomUUID();
			groupIds.set(path, id);
			groups.push({ id, name: path });
		}
		const parts = path.split('/');
		for (let index = parts.length - 1; index > 0; index--) {
			const parent = parts.slice(0, index).join('/');
			if (!groupIds.has(parent)) {
				const parentId = randomUUID();
				groupIds.set(parent, parentId);
				groups.push({ id: parentId, name: parent });
			}
		}
		if (assign) {
			if (organization) assign.collectionIds = [...(assign.collectionIds ?? []), id];
			else assign.folderId = id;
		}
	};
	const folders = child(importFile, 'Folders');
	if (folders) {
		for (const folder of children(folders, 'Folder')) addFolder(text(child(folder, 'FolderPath')), null);
	}
	const secrets = child(importFile, 'Secrets');
	if (secrets) {
		for (const secret of children(secrets, 'Secret')) {
			const fields: { slug: string; value: string }[] = [], secretItems = child(secret, 'SecretItems');
			if (secretItems) {
				for (const entry of children(secretItems, 'SecretItem')) {
					const slug = text(child(entry, 'Slug')).trim(), value = text(child(entry, 'Value'));
					if (slug && value.trim()) fields.push({ slug, value });
				}
			}
			const isLogin = fields.some(field => field.slug === 'url');
			const result: VaultItem = {
				type: isLogin ? 1 : 2,
				name: text(child(secret, 'SecretName')) || '--',
				favorite: false,
				reprompt: 0,
				notes: null,
				fields: [],
				...(isLogin
					? { login: { username: null, password: null, totp: null, uris: [] } }
					: { secureNote: { type: 0 } }),
			};
			for (const field of fields) {
				if (field.slug === 'notes') result.notes = field.value;
				else if (field.slug === 'password' && isLogin) result.login!.password = field.value;
				else if (field.slug === 'url' && isLogin) {
					result.login!.uris = field.value.trim()
						? [{ uri: field.value.trim(), match: null }]
						: [];
				} else if (field.slug === 'username' && isLogin) result.login!.username = field.value;
				else result.fields!.push({ name: field.slug, value: field.value, type: field.slug === 'password' ? 1 : 0 });
			}
			addFolder(text(child(secret, 'FolderPath')), result);
			items.push(result);
		}
	}
	return { encrypted: false, items, [organization ? 'collections' : 'folders']: groups };
}
