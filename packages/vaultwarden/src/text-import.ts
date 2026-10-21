import type { JsonObject } from '#client';
import type { VaultItem } from '#models';

const present = (value: string | undefined): string | null => value?.trim() ? value : null;
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
function uri(value: string | undefined): JsonObject[] {
	let result = value?.trim();
	if (!result) return [];
	if (!result.includes('://') && result.includes('.')) result = `http://${result}`;
	return [{ uri: result.slice(0, 1000), match: null }];
}
function parseDataCategory(data: string | undefined): Map<string, string | undefined>[] {
	if (!data?.trim() || !data.includes('\n---\n')) return [];
	const items: Map<string, string | undefined>[] = [];
	for (const part of data.split('\n---\n')) {
		if (!part.includes('\n')) continue;
		const item = new Map<string, string | undefined>();
		let comment: string | undefined, commentKey: string | undefined;
		for (const line of part.split('\n')) {
			if (comment !== undefined) {
				comment += `\n${line}`;
				continue;
			}
			const colon = line.indexOf(':');
			if (colon === -1) continue;
			const key = line.slice(0, colon), value = line.length > colon + 1 ? line.slice(colon + 2) : undefined;
			item.set(key, value);
			if (key === 'Comment' || key === 'Text') {
				comment = value;
				commentKey = key;
			}
		}
		if (comment !== undefined && commentKey !== undefined) item.set(commentKey, comment);
		if (item.size) items.push(item);
	}
	return items;
}
/** Parse the sectioned Kaspersky Password Manager text export. */
export function parseKasperskyTxt(source: string): JsonObject {
	let working = source.replace(/\r\n|\r/g, '\n');
	const extract = (header: string): string | undefined => {
		if (!working.includes(header)) return undefined;
		const parts = working.split(header);
		if (parts.length < 2) return undefined;
		working = parts[0]!;
		return parts[1];
	};
	const notesData = extract('Notes\n\n');
	const applicationsData = extract('Applications\n\n');
	const websitesData = working.startsWith('Websites\n\n') ? extract('Websites\n\n') : undefined;
	const items: VaultItem[] = [];
	for (const entry of parseDataCategory(notesData)) {
		const item = login(entry.get('Name'));
		item.notes = present(entry.get('Text'));
		items.push(item);
	}
	for (const entry of [...parseDataCategory(websitesData), ...parseDataCategory(applicationsData)]) {
		const nameKey = entry.has('Website name') ? 'Website name' : 'Application';
		let name = present(entry.get(nameKey)) ?? '';
		const loginName = entry.get('Login name');
		if (loginName?.trim()) name += `${name ? ': ' : ''}${loginName}`;
		const item = login(name);
		item.notes = present(entry.get('Comment'));
		if (entry.has('Website URL')) item.login!.uris = uri(entry.get('Website URL'));
		item.login!.username = present(entry.get('Login'));
		item.login!.password = present(entry.get('Password'));
		items.push(item);
	}
	return { encrypted: false, items, folders: [] };
}
