import { randomUUID } from 'node:crypto';
import { DOMParser, type Element } from '@xmldom/xmldom';
import type { JsonObject } from '#client';
import type { VaultItem } from '#models';

function children(element: Element, tag: string): Element[] {
	const result: Element[] = [];
	for (let i = 0; i < element.childNodes.length; i++) {
		const child = element.childNodes.item(i);
		if (child?.nodeType === 1 && (child as Element).tagName === tag) result.push(child as Element);
	}
	return result;
}
const child = (element: Element, tag: string) => children(element, tag)[0];
const content = (element: Element | undefined): string | null => element?.textContent ?? null;

/** Parse a plaintext KeePass 2 XML export using the reference importer's direct-child semantics. */
export function parseKeePassXml(source: string, organization = false): JsonObject {
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
		}).parseFromString(source, 'application/xml').documentElement;
	} catch (error) {
		throw new Error('Invalid KeePass XML.', { cause: error });
	}
	if (root?.tagName !== 'KeePassFile') throw new Error('Missing KeePassFile root node.');
	const container = child(root, 'Root');
	const rootGroup = container && child(container, 'Group');
	if (!rootGroup) throw new Error('Missing KeePassFile > Root > Group node.');
	const items: VaultItem[] = [], groups: JsonObject[] = [];
	const stack: { node: Element; root: boolean; prefix: string }[] = [{ node: rootGroup, root: true, prefix: '' }];
	while (stack.length) {
		const current = stack.pop()!;
		let name = current.prefix, groupId: string | null = null;
		if (!current.root) {
			const groupName = child(current.node, 'Name');
			name = `${name ? `${name}/` : ''}${groupName ? content(groupName) ?? '' : '-'}`;
			groupId = randomUUID();
			groups.push({ id: groupId, name });
		}
		for (const entry of children(current.node, 'Entry')) {
			const login: JsonObject = { username: null, password: null, totp: null, uris: [] };
			const item: VaultItem = {
				type: 1,
				name: '--',
				notes: '',
				favorite: false,
				reprompt: 0,
				fields: [],
				login,
				folderId: organization ? null : groupId,
				collectionIds: organization && groupId ? [groupId] : [],
			};
			for (const field of children(entry, 'String')) {
				const valueNode = child(field, 'Value'), value = content(valueNode), key = content(child(field, 'Key'));
				if (value == null || !value.trim()) continue;
				if (key === 'URL') {
					let uri = value.trim();
					if (!uri.includes('://') && uri.includes('.')) uri = `http://${uri}`;
					login.uris = [{ uri: uri.slice(0, 1000), match: null }];
				} else if (key === 'UserName') login.username = value;
				else if (key === 'Password') login.password = value;
				else if (key === 'otp') login.totp = value.replace('key=', '');
				else if (key === 'Title') item.name = value;
				else if (key === 'Notes') item.notes += `${value}\n`;
				else if (valueNode?.getAttribute('ProtectInMemory') === 'True') {
					item.fields!.push({ name: key, value, type: 1 });
				} else if (value.length > 200 || /\r|\n/.test(value.trim())) {
					item.notes += `${key ?? ''}: ${value.replace(/\r\n|\r/g, '\n')}\n`;
				} else item.fields!.push({ name: key ?? '', value, type: 0 });
			}
			if (!item.notes?.trim()) item.notes = null;
			items.push(item);
		}
		// Reverse only the stack insertion order to match the source's depth-first grouping order.
		for (const node of children(current.node, 'Group').reverse()) stack.push({ node, root: false, prefix: name });
	}
	return { encrypted: false, items, [organization ? 'collections' : 'folders']: groups };
}
