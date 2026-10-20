import { randomBytes, randomUUID } from 'node:crypto';
import { zipSync, unzipSync } from 'fflate';
import { decrypt, encrypt, deriveKdfKey, stretchKey, type Kdf } from '#crypto';
import { object, text, parseKdf, type JsonObject } from '#client';
import { decryptOwnedItem } from '#vault';
import { transformItem } from '#item-codec';
import type { VaultService } from '#vault-service';

export interface TransferOptions {
	organizationId?: string;
	password?: string;
	kdf?: Kdf;
}
export class ImportFailure extends Error {
	readonly serverMayHaveChanged = true;
}
export interface ImportResult {
	items: number;
	folders: number;
	collections: number;
	attachments: number;
}
export const importFormats = [
	'bitwardenjson',
	'bitwardencsv',
	'bitwardenzip',
	'chromecsv',
	'firefoxcsv',
] as const;
export type ImportFormat = typeof importFormats[number];
export type ExportFormat = 'json' | 'csv' | 'encrypted_json' | 'zip';
function records(value: unknown): JsonObject[] {
	if (!Array.isArray(value)) throw new Error('Invalid vault export structure.');
	return value.map(object);
}
function json(value: string): JsonObject {
	try {
		return object(JSON.parse(value));
	} catch {
		throw new Error('Invalid vault export JSON.');
	}
}
function selectFields(item: JsonObject, encrypted = false): JsonObject {
	const result: JsonObject = {};
	for (
		const key of [
			'id',
			'organizationId',
			'folderId',
			'collectionIds',
			'type',
			'reprompt',
			'name',
			'notes',
			'favorite',
			'fields',
			'login',
			'secureNote',
			'card',
			'identity',
			'sshKey',
			'passwordHistory',
			'creationDate',
			'revisionDate',
			'deletedDate',
			'archivedDate',
			...(encrypted ? ['key'] : []),
		]
	) if (item[key] !== undefined) result[key] = structuredClone(item[key]);
	result.collectionIds = item.organizationId ? item.collectionIds ?? [] : null;
	return result;
}
/** RFC 4180 records, including quoted newlines and doubled quotes. */
export function parseCsv(input: string): string[][] {
	const rows: string[][] = [];
	let row: string[] = [];
	let field = '';
	let quoted = false;
	let closed = false;
	input = input.replace(/^\uFEFF/, '');
	for (let i = 0; i < input.length; i++) {
		const char = input[i]!;
		if (quoted) {
			if (char === '"') {
				if (input[i + 1] === '"') {
					field += '"';
					i++;
				} else {
					quoted = false;
					closed = true;
				}
			} else field += char;
			continue;
		}
		if (char === '"') {
			if (field || closed) throw new Error('Invalid CSV quoting.');
			quoted = true;
			continue;
		}
		if (char === ',') {
			row.push(field);
			field = '';
			closed = false;
			continue;
		}
		if (char === '\r' || char === '\n') {
			if (char === '\r' && input[i + 1] === '\n') i++;
			row.push(field);
			rows.push(row);
			row = [];
			field = '';
			closed = false;
			continue;
		}
		if (closed) throw new Error('Invalid CSV quoting.');
		field += char;
	}
	if (quoted) throw new Error('Unterminated CSV field.');
	if (field || row.length || closed) {
		row.push(field);
		rows.push(row);
	}
	return rows;
}
function csvCell(value: unknown): string {
	const v = value == null ? '' : String(value);
	return /[",\r\n]/.test(v) ? `"${v.replaceAll('"', '""')}"` : v;
}
export function writeCsv(rows: unknown[][]): string {
	return rows.map(row => row.map(csvCell).join(',')).join('\r\n');
}
function csvDocument(source: string, format: string, organization = false): JsonObject {
	const rows = parseCsv(source);
	if (!rows.length) throw new Error('CSV is empty.');
	const header = rows.shift()!;
	if (new Set(header).size !== header.length) throw new Error('Duplicate CSV headers.');
	const groups: JsonObject[] = [];
	const ids = new Map<string, string>();
	const items: JsonObject[] = [];
	const grouping = (name: string): string => {
		let id = ids.get(name);
		if (!id) {
			id = randomUUID();
			ids.set(name, id);
			groups.push({ id, name });
		}
		return id;
	};
	for (const row of rows) {
		if (row.every(v => !v)) continue;
		if (row.length !== header.length) throw new Error('CSV row has an unexpected number of fields.');
		const values: Record<string, string> = Object.create(null);
		header.forEach((key, i) => values[key] = row[i]!);
		if (format === 'bitwardencsv' && !header.includes('name')) throw new Error('Missing Bitwarden CSV name column.');
		const name = values.name || values.title || values.url || values.login_uri || '--';
		const type = values.type?.toLowerCase() === 'note' ? 2 : 1;
		const group = values.folder ?? (format === 'lastpasscsv' ? values.grouping : undefined) ?? '';
		const collections = organization
			? (values.collections ? parseCsv(values.collections)[0] ?? [] : group ? [group] : [])
			: [];
		const fields = (values.fields ?? '').split(/\r?\n/).filter(Boolean).flatMap(line => {
			const index = line.lastIndexOf(': ');
			return index < 0 ? [] : [{ name: line.slice(0, index), value: line.slice(index + 2) || null, type: 0 }];
		});
		const uri = values.login_uri ?? values.url ?? values.uri ?? '';
		const uris = (uri ? parseCsv(uri)[0] ?? [] : []).filter(Boolean).map(uri => ({ uri, match: null }));
		items.push({
			type,
			name,
			notes: values.notes ?? values.note ?? values.extra ?? null,
			folderId: !organization && group ? grouping(group) : null,
			collectionIds: collections.map(grouping),
			favorite: !!values.favorite && values.favorite !== '0',
			reprompt: Number(values.reprompt) || 0,
			fields,
			...(type === 2
				? { secureNote: { type: 0 } }
				: {
					login: {
						username: values.login_username ?? values.username ?? null,
						password: values.login_password ?? values.password ?? null,
						totp: values.login_totp ?? values.totp ?? null,
						uris,
					},
				}),
			archivedDate: values.archivedDate || null,
		});
	}
	return { encrypted: false, items, ...(organization ? { collections: groups } : { folders: groups }) };
}
function csvExport(document: JsonObject, organization = false): string {
	const groupKey = organization ? 'collections' : 'folders';
	const groups = new Map(records(document[groupKey] ?? []).map(group => [group.id, group.name]));
	const headers = organization
		? [
			'collections',
			'type',
			'name',
			'notes',
			'fields',
			'reprompt',
			'archivedDate',
			'login_uri',
			'login_username',
			'login_password',
			'login_totp',
		]
		: [
			'folder',
			'favorite',
			'type',
			'name',
			'notes',
			'fields',
			'reprompt',
			'archivedDate',
			'login_uri',
			'login_username',
			'login_password',
			'login_totp',
		];
	const rows: unknown[][] = [headers];
	for (const item of records(document.items)) {
		if (item.type !== 1 && item.type !== 2) continue;
		const login = object(item.login ?? {});
		const fields = records(item.fields ?? []).map(f => `${f.name ?? ''}: ${f.value ?? ''}`).join('\n');
		const uris = records(login.uris ?? []).map(uri => uri.uri ?? '');
		const cells: JsonObject = {
			folder: groups.get(item.folderId),
			favorite: item.favorite ? 1 : null,
			collections: Array.isArray(item.collectionIds)
				? writeCsv([item.collectionIds.map(id => groups.get(id) ?? '')])
				: '',
			type: item.type === 1 ? 'login' : 'note',
			name: item.name,
			notes: item.notes,
			fields,
			reprompt: item.reprompt ?? 0,
			archivedDate: item.archivedDate,
			login_uri: writeCsv([uris]),
			login_username: login.username,
			login_password: login.password,
			login_totp: login.totp,
		};
		rows.push(headers.map(header => cells[header]));
	}
	return writeCsv(rows);
}
function exportKdf(vault: VaultService, options: TransferOptions): Kdf {
	if (options.kdf) return options.kdf;
	const decryption = vault.snapshot.userDecryption;
	if (decryption) {
		const unlock = object(object(decryption).masterPasswordUnlock ?? {});
		if (unlock.kdf) return parseKdf({ kdfSettings: unlock.kdf });
	}
	return { type: 0, iterations: 600000 };
}
async function exportKey(password: string, salt: string, kdf: Kdf): Promise<Buffer> {
	const master = await deriveKdfKey(password, salt, kdf);
	try {
		return stretchKey(master);
	} finally {
		master.fill(0);
	}
}
export async function decryptExportDocument(
	source: JsonObject,
	ownerKey: Uint8Array,
	password?: string,
): Promise<JsonObject> {
	if (source.encrypted !== true) return source;
	if (source.passwordProtected === true) {
		if (password === undefined) throw new Error('An import password is required.');
		const kdf = parseKdf({
			kdf: source.kdfType,
			kdfIterations: source.kdfIterations,
			kdfMemory: source.kdfMemory,
			kdfParallelism: source.kdfParallelism,
		});
		const key = await exportKey(password, text(source.salt), kdf);
		try {
			decrypt(text(source.encKeyValidation_DO_NOT_EDIT), key);
			return json(decrypt(text(source.data), key).toString('utf8'));
		} finally {
			key.fill(0);
		}
	}
	decrypt(text(source.encKeyValidation_DO_NOT_EDIT), ownerKey);
	const output: JsonObject = { ...source, encrypted: false };
	for (const grouping of ['folders', 'collections']) {
		if (source[grouping]) {
			output[grouping] = records(source[grouping]).map(group => ({
				...group,
				name: decrypt(text(group.name), ownerKey).toString('utf8'),
			}));
		}
	}
	output.items = records(source.items).map(item => decryptOwnedItem(item, ownerKey));
	return output;
}
interface TransferKeys {
	user: Uint8Array;
	organization: (id: string) => Uint8Array;
}
function scopeKey(keys: TransferKeys, organizationId?: string): Uint8Array {
	return organizationId ? keys.organization(organizationId) : keys.user;
}
async function sourceForExport(vault: VaultService, organizationId?: string): Promise<JsonObject> {
	if (!organizationId) return vault.snapshot;
	const response = await vault.client.api(
		vault.accessToken,
		'GET',
		`/organizations/${encodeURIComponent(organizationId)}/export`,
	);
	return { ...response, profile: vault.snapshot.profile };
}
// Bitwarden ZIPs group attachments by sanitized item name and contain no ID manifest.
function zipItemName(name: string): string {
	return name.replace(/[/\\><:"|?*]/g, '_').replace(/__+/g, '_');
}
function officialZipAttachments(items: JsonObject[], zip: Record<string, Uint8Array>): JsonObject[] {
	const result: JsonObject[] = [];
	for (const path of Object.keys(zip)) {
		if (!path.startsWith('attachments/') || path.endsWith('/')) continue;
		const parts = path.split('/');
		if (parts.length !== 3 || !parts[1] || !parts[2]) throw new Error('Unsupported ZIP attachment layout.');
		const matches = items.filter(item => typeof item.name === 'string' && zipItemName(item.name) === parts[1]);
		// The official format loses original IDs and names when sanitized names collide.
		// Refuse an ambiguous restoration instead of associating a file with the wrong secret.
		if (matches.length !== 1) throw new Error('ZIP attachment item names are ambiguous or missing.');
		result.push({ itemId: text(matches[0]!.id), fileName: parts[2], path });
	}
	return result;
}
export async function exportVault(
	vault: VaultService,
	keys: TransferKeys,
	format: ExportFormat,
	options: TransferOptions = {},
): Promise<Buffer> {
	if (!['json', 'csv', 'encrypted_json', 'zip'].includes(format)) throw new Error('Unsupported export format.');
	const source = await sourceForExport(vault, options.organizationId);
	const owner = scopeKey(keys, options.organizationId);
	const items = records(source.ciphers).filter(item =>
		!item.deletedDate && (item.organizationId ?? null) === (options.organizationId ?? null)
	);
	const groupKey = options.organizationId ? 'collections' : 'folders';
	const grouping = records(source[groupKey] ?? []).filter(group =>
		!options.organizationId || !group.organizationId || group.organizationId === options.organizationId
	);
	const encrypted = format === 'encrypted_json' && options.password === undefined;
	const document: JsonObject = {
		encrypted,
		...(encrypted ? { encKeyValidation_DO_NOT_EDIT: encrypt(Buffer.from(randomUUID()), owner) } : {}),
		[groupKey]: grouping.map(group => ({
			id: group.id,
			name: encrypted ? group.name : decrypt(text(group.name), owner).toString('utf8'),
			...(options.organizationId ? { organizationId: options.organizationId } : {}),
		})),
		items: items.map(item => selectFields(encrypted ? item : decryptOwnedItem(item, owner), encrypted)),
	};
	if (format === 'csv') return Buffer.from(csvExport(document, !!options.organizationId));
	if (format === 'encrypted_json' && options.password !== undefined) {
		const kdf = exportKdf(vault, options);
		const salt = randomBytes(16).toString('base64');
		const key = await exportKey(options.password, salt, kdf);
		try {
			return Buffer.from(JSON.stringify(
				{
					encrypted: true,
					passwordProtected: true,
					salt,
					kdfType: kdf.type,
					kdfIterations: kdf.iterations,
					...(kdf.type === 1 ? { kdfMemory: kdf.memory, kdfParallelism: kdf.parallelism } : {}),
					encKeyValidation_DO_NOT_EDIT: encrypt(Buffer.from(randomUUID()), key),
					data: encrypt(Buffer.from(JSON.stringify(document)), key),
				},
				null,
				2,
			));
		} finally {
			key.fill(0);
		}
	}
	if (format !== 'zip') return Buffer.from(JSON.stringify(document, null, 2));
	const archive: Record<string, Uint8Array> = Object.create(null);
	archive['data.json'] = Buffer.from(JSON.stringify(document, null, 2));
	const manifest: { itemId: string; attachmentId: string; fileName: string; path: string }[] = [];
	for (const item of items) {
		for (const attachment of records(item.attachments ?? [])) {
			const downloaded = await vault.getAttachment(text(item.id), text(attachment.id));
			const name = downloaded.fileName.replace(/[\\/<>:"|?*\p{Cc}]/gu, '_') || 'attachment';
			const path = `attachments/${text(item.id)}/${text(attachment.id)}_${name}`;
			archive[path] = downloaded.contents;
			manifest.push({ itemId: text(item.id), attachmentId: text(attachment.id), fileName: downloaded.fileName, path });
		}
	}
	archive['vw-manifest.json'] = Buffer.from(JSON.stringify({ version: 1, attachments: manifest }));
	try {
		return Buffer.from(zipSync(archive, { level: 6 }));
	} finally {
		for (const [path, value] of Object.entries(archive)) if (path.startsWith('attachments/')) value.fill(0);
	}
}
export async function importVault(
	vault: VaultService,
	keys: TransferKeys,
	format: ImportFormat,
	input: Uint8Array | string,
	options: TransferOptions = {},
): Promise<ImportResult> {
	if (!importFormats.includes(format)) throw new Error('Unsupported import format.');
	let source = format === 'bitwardenzip' ? '' : typeof input === 'string' ? input : Buffer.from(input).toString('utf8');
	let zip: Record<string, Uint8Array> | undefined;
	let manifest: JsonObject | undefined;
	if (format === 'bitwardenzip') {
		let total = 0;
		try {
			zip = unzipSync(typeof input === 'string' ? Buffer.from(input, 'binary') : input, {
				filter: entry => {
					total += entry.originalSize;
					if (total > 1024 * 1024 * 1024 || entry.originalSize > 525 * 1024 * 1024) throw new Error();
					return true;
				},
			});
		} catch {
			throw new Error('Invalid ZIP archive or archive exceeds size limits.');
		}
		if (!zip['data.json']) throw new Error('ZIP export has no data.json.');
		source = Buffer.from(zip['data.json']).toString('utf8');
		if (zip['vw-manifest.json']) {
			manifest = json(Buffer.from(zip['vw-manifest.json']).toString('utf8'));
			if (manifest.version !== 1) throw new Error('Unsupported ZIP manifest.');
		}
	}
	const owner = scopeKey(keys, options.organizationId);
	const document = await decryptExportDocument(
		format.endsWith('csv') ? csvDocument(source, format, !!options.organizationId) : json(source),
		owner,
		options.password,
	);
	const rawItems = records(document.items);
	const groups = records(
		document[options.organizationId ? 'collections' : 'folders']
			?? document[options.organizationId ? 'folders' : 'collections'] ?? [],
	);
	const groupIds = new Map<unknown, number>();
	const encryptedGroups = groups.map((group, index) => {
		if (group.id != null) {
			if (groupIds.has(group.id)) throw new Error('Duplicate grouping ID.');
			groupIds.set(group.id, index);
		}
		const name = text(group.name);
		return {
			name: encrypt(Buffer.from(name), owner),
			...(options.organizationId ? { externalId: group.externalId ?? null } : {}),
		};
	});
	const relationships: { key: number; value: number }[] = [];
	const ciphers: JsonObject[] = rawItems.map((raw, index) => {
		const item = structuredClone(raw);
		if (item.deletedDate) throw new Error('Import contains a deleted item.');
		if (typeof item.type !== 'number' || ![1, 2, 3, 4, 5].includes(item.type)) {
			throw new Error('Unsupported imported item type.');
		}
		item.name = typeof item.name === 'string' && item.name ? item.name : '--';
		item.organizationId = options.organizationId ?? null;
		item.folderId = null;
		const refs = options.organizationId
			? (Array.isArray(raw.collectionIds) ? raw.collectionIds : raw.folderId ? [raw.folderId] : [])
			: raw.folderId
			? [raw.folderId]
			: [];
		for (const ref of refs) {
			const group = groupIds.get(ref);
			if (group !== undefined) relationships.push({ key: index, value: group });
		}
		for (const field of ['id', 'key', 'attachments', 'revisionDate', 'creationDate', 'deletedDate', 'collectionIds']) {
			delete item[field];
		}
		const key = randomBytes(64);
		try {
			return {
				...transformItem(item, key, 'encrypt'),
				key: encrypt(key, owner),
				encryptedFor: text(object(vault.snapshot.profile).id),
				lastKnownRevisionDate: null,
			};
		} finally {
			key.fill(0);
		}
	});
	// Validate attachment mappings before changing the server. No ZIP paths are extracted to the filesystem.
	const attachments = manifest ? records(manifest.attachments) : zip ? officialZipAttachments(rawItems, zip) : [];
	for (const attachment of attachments) {
		if (
			typeof attachment.path !== 'string' || !attachment.path.startsWith('attachments/') || !zip?.[attachment.path]
			|| !rawItems.some(item => item.id === attachment.itemId)
		) throw new Error('Invalid ZIP attachment manifest.');
		text(attachment.itemId);
		text(attachment.fileName);
	}
	try {
		await vault.client.api(
			vault.accessToken,
			'POST',
			options.organizationId ? '/ciphers/import-organization' : '/ciphers/import',
			options.organizationId
				? { ciphers, collections: encryptedGroups, collectionRelationships: relationships }
				: { ciphers, folders: encryptedGroups, folderRelationships: relationships },
			options.organizationId ? { organizationId: options.organizationId } : undefined,
		);
	} catch {
		throw new ImportFailure('Import request failed. The server may have imported some data; sync before retrying.');
	}
	// Server bulk import returns no IDs. Refresh and match imported ciphertexts to avoid confusing pre-existing names.
	let importedAttachments = 0;
	if (attachments.length) {
		let snapshot: JsonObject;
		try {
			snapshot = await vault.client.sync(vault.accessToken);
		} catch {
			throw new ImportFailure(
				'Items were imported, but syncing for attachment restoration failed. Sync before retrying.',
			);
		}
		const created = records(snapshot.ciphers);
		const byOldId = new Map<unknown, JsonObject>();
		rawItems.forEach((item, index) => {
			const result = created.find(candidate => candidate.name === ciphers[index]!.name);
			if (result) byOldId.set(item.id, result);
		});
		const child = vault.withSnapshot(snapshot);
		try {
			for (const attachment of attachments) {
				const item = byOldId.get(attachment.itemId);
				if (!item) throw new Error('Imported item could not be located for attachment restoration.');
				await child.createAttachment(text(item.id), text(attachment.fileName), zip![text(attachment.path)]!);
				importedAttachments++;
			}
		} catch {
			throw new ImportFailure(
				`Items were imported, but attachment restoration stopped after ${importedAttachments} file(s). Sync before retrying.`,
			);
		} finally {
			child.dispose();
		}
	}
	return {
		items: ciphers.length,
		folders: options.organizationId ? 0 : encryptedGroups.length,
		collections: options.organizationId ? encryptedGroups.length : 0,
		attachments: importedAttachments,
	};
}
