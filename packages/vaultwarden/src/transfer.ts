import { type JsonObject, object, parseKdf, text } from '#client';
import { parseClipperzHtml } from '#clipperz-html';
import { decrypt, deriveKdfKey, encrypt, type Kdf, stretchKey } from '#crypto';
import { parseCsv, writeCsv } from '#csv';
import { externalCsvFormats, isExternalCsvFormat, parseExternalCsv } from '#csv-import';
import { parseDelineaXml } from '#delinea-xml';
import { encryptItem } from '#item-codec';
import { externalJsonFormats, isExternalJsonFormat, parseExternalJson } from '#json-import';
import { parseKdbx } from '#kdbx';
import { parseKeePassXml } from '#keepass-xml';
import { type ImportRecordError, parseOnePassword1Pux } from '#onepassword';
import { parseOnePassword1Pif, parseOnePasswordCsv } from '#onepassword-legacy';
import { parsePasswordDepot17Xml } from '#password-depot-xml';
import { parsePasswordDragonXml } from '#password-dragon-xml';
import { parsePasswordSafeXml } from '#passwordsafe-xml';
import { parseSafeInCloudXml } from '#safeincloud-xml';
import { parseStickyPasswordXml } from '#stickypassword-xml';
import { parseKasperskyTxt } from '#text-import';
import { decryptOwnedItem } from '#vault';
import type { VaultService } from '#vault-service';
import { unzipSync, zipSync } from 'fflate';
import { randomBytes, randomUUID } from 'node:crypto';

export interface TransferOptions {
	organizationId?: string;
	password?: string;
	/** Source path used by bw-compatible format autodetection (currently unified Keeper). */
	fileName?: string;
	/** Optional KeePass key-file bytes; used only by keepasskdbx imports. */
	keyFile?: Uint8Array;
	kdf?: Kdf;
	/** Called when ZIP export cannot download/decrypt an attachment and skips it. */
	onAttachmentSkipped?: (itemId: string, attachmentId: string) => void;
}
export class ImportFailure extends Error {
	readonly serverMayHaveChanged = true;
}
export interface ImportResult {
	items: number;
	folders: number;
	collections: number;
	attachments: number;
	/** Records skipped before upload, identified by source UID rather than vault contents. */
	errors?: ImportRecordError[];
}
export const importFormats = [
	'bitwardenjson',
	'bitwardencsv',
	'bitwardenzip',
	'kasperskytxt',
	...externalCsvFormats,
	...externalJsonFormats,
	'keepass2xml',
	'keepasskdbx',
	'1password1pux',
	'1password1pif',
	'1passwordmaccsv',
	'1passwordwincsv',
	'delineaxml',
	'passworddragonxml',
	'safeincloudxml',
	'pwsafexml',
	'stickypasswordxml',
	'clipperzhtml',
	'keeper',
	'passworddepot17xml',
] as const;
export type ImportFormat = typeof importFormats[number];
export type ExportFormat = 'json' | 'csv' | 'encrypted_json' | 'zip';
export function resolveImportFormat(format: ImportFormat, fileName?: string): ImportFormat {
	if (format !== 'keeper') return format;
	const path = fileName?.toLowerCase();
	if (path?.endsWith('.csv')) return 'keepercsv';
	if (path?.endsWith('.json')) return 'keeperjson';
	throw new Error('Cannot determine Keeper file type. Use a .csv or .json file.');
}
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
			'bankAccount',
			'driversLicense',
			'passport',
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
export { parseCsv, writeCsv } from '#csv';
function csvDocument(source: string, organization = false): JsonObject {
	const rows = parseCsv(source);
	if (!rows.length) throw new Error('CSV is empty.');
	const header = rows.shift()!;
	if (new Set(header).size !== header.length) throw new Error('Duplicate CSV headers.');
	if (!header.includes('name')) throw new Error('Missing Bitwarden CSV name column.');
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
		const name = values.name || values.title || values.url || values.login_uri || '--';
		const type = values.type?.toLowerCase() === 'note' ? 2 : 1;
		const group = values.folder ?? '';
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
export function officialZipAttachments(items: JsonObject[], zip: Record<string, Uint8Array>): JsonObject[] {
	const result: JsonObject[] = [];
	const names = new Map<string, number>();
	const folderItems = new Map<string, JsonObject[]>();
	for (const item of items) {
		const name = text(item.name);
		const count = names.get(name) ?? 0;
		names.set(name, count + 1);
		const folder = `${zipItemName(name)}${count ? `_${count}` : ''}`;
		folderItems.set(folder, [...(folderItems.get(folder) ?? []), item]);
	}
	for (const path of Object.keys(zip)) {
		if (!path.startsWith('attachments/') || path.endsWith('/')) continue;
		const parts = path.split('/');
		if (parts.length !== 3 || !parts[1] || !parts[2]) throw new Error('Unsupported ZIP attachment layout.');
		const matches = folderItems.get(parts[1]) ?? [];
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
	if (format === 'zip' && options.organizationId) throw new Error('Zip export not supported for organization.');
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
	const data = Buffer.from(JSON.stringify(document, null, 2));
	archive['data.json'] = data;
	archive['attachments/'] = new Uint8Array();
	try {
		const itemNames = new Map<string, number>();
		for (const encryptedItem of items) {
			const item = decryptOwnedItem(encryptedItem, owner);
			const itemName = text(item.name);
			const itemNameCount = itemNames.get(itemName) ?? 0;
			itemNames.set(itemName, itemNameCount + 1);
			let folderName = zipItemName(itemName);
			if (itemNameCount) folderName += `_${itemNameCount}`;
			const attachmentNames = new Map<string, number>();
			for (const attachment of records(item.attachments ?? [])) {
				let contents: Buffer | undefined;
				try {
					const downloaded = await vault.getAttachment(text(item.id), text(attachment.id));
					contents = downloaded.contents;
					const parts = downloaded.fileName.split('.');
					let baseName = parts.length > 1 ? parts.slice(0, -1).join('') : downloaded.fileName;
					const suffix = parts.length > 1 ? `.${parts.at(-1)}` : '';
					baseName = baseName.replace(/[\\/<>:"|?*.]/g, '_').replace(/__+/g, '_');
					let name = `${baseName}${suffix}`;
					const nameCount = attachmentNames.get(name) ?? 0;
					attachmentNames.set(name, nameCount + 1);
					if (nameCount) name = `${baseName}_${nameCount}${suffix}`;
					const path = `attachments/${folderName}/${name}`;
					archive[path] = contents;
					contents = undefined;
				} catch {
					options.onAttachmentSkipped?.(text(item.id), text(attachment.id));
				} finally {
					contents?.fill(0);
				}
			}
		}
		return Buffer.from(zipSync(archive, { level: 6 }));
	} finally {
		data.fill(0);
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
	if (format === 'keeper') {
		return importVault(vault, keys, resolveImportFormat(format, options.fileName), input, options);
	}
	if (format === 'keepasskdbx' && typeof input === 'string') throw new Error('KDBX input must be binary bytes.');
	let source = format === 'bitwardenzip' || format === 'keepasskdbx' || format === '1password1pux'
		? ''
		: typeof input === 'string'
		? input
		: Buffer.from(input).toString('utf8');
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
		format === '1password1pux'
			? parseOnePassword1Pux(input, !!options.organizationId)
			: format === '1password1pif'
			? parseOnePassword1Pif(source, !!options.organizationId)
			: format === '1passwordmaccsv' || format === '1passwordwincsv'
			? parseOnePasswordCsv(format, source, !!options.organizationId)
			: format === 'keepasskdbx'
			? await parseKdbx(input as Uint8Array, {
				password: options.password,
				keyFile: options.keyFile,
				organization: !!options.organizationId,
			})
			: isExternalCsvFormat(format)
			? parseExternalCsv(format, source, !!options.organizationId)
			: isExternalJsonFormat(format)
			? parseExternalJson(format, source, !!options.organizationId)
			: format === 'kasperskytxt'
			? parseKasperskyTxt(source)
			: format === 'bitwardencsv'
			? csvDocument(source, !!options.organizationId)
			: format === 'keepass2xml'
			? parseKeePassXml(source, !!options.organizationId)
			: format === 'delineaxml'
			? parseDelineaXml(source, !!options.organizationId)
			: format === 'passworddragonxml'
			? parsePasswordDragonXml(source, !!options.organizationId)
			: format === 'safeincloudxml'
			? parseSafeInCloudXml(source)
			: format === 'pwsafexml'
			? parsePasswordSafeXml(source, !!options.organizationId)
			: format === 'stickypasswordxml'
			? parseStickyPasswordXml(source, !!options.organizationId)
			: format === 'clipperzhtml'
			? parseClipperzHtml(source)
			: format === 'passworddepot17xml'
			? parsePasswordDepot17Xml(source, !!options.organizationId)
			: json(source),
		owner,
		options.password,
	);
	const rawItems = records(document.items);
	const groups = records(
		document[options.organizationId ? 'collections' : 'folders']
			?? document[options.organizationId ? 'folders' : 'collections'] ?? [],
	);
	if (rawItems.length === 0 && groups.length === 0) throw new Error('Nothing to import.');
	for (const item of rawItems) {
		if (typeof item.type !== 'number' || ![1, 2, 3, 4, 5, 6, 7, 8].includes(item.type)) {
			throw new Error('Unsupported imported item type.');
		}
		await vault.client.assertCipherTypeSupported(item.type);
	}
	if (rawItems.length > 0) {
		const middle = Math.floor(rawItems.length / 2);
		const samples = [rawItems[0]!, rawItems[middle]!, rawItems[rawItems.length - 1]!];
		const hasPlaceholderLogin = (candidate: JsonObject) => {
			if (candidate.type !== 1 || candidate.login == null || typeof candidate.login !== 'object') return false;
			const login = object(candidate.login);
			const password = login.password;
			return (candidate.name == null || candidate.name === '--')
				&& (typeof password !== 'string' || !password.trim());
		};
		if (samples.every(hasPlaceholderLogin)) throw new Error('Invalid vault export or import format.');
	}
	const groupIds = new Map<unknown, number>();
	const encryptedGroups = groups.map((group, index) => {
		if (group.id != null) {
			if (groupIds.has(group.id)) throw new Error('Duplicate grouping ID.');
			groupIds.set(group.id, index);
		}
		if (typeof group.name !== 'string') throw new Error('Imported group name must be a string.');
		const name = group.name;
		return {
			name: encrypt(Buffer.from(name), owner),
			// Older Vaultwarden imports deserialize the full collection request shape.
			...(options.organizationId ? { externalId: group.externalId ?? null, groups: [], users: [] } : {}),
		};
	});
	const relationships: { key: number; value: number }[] = [];
	const ciphers: JsonObject[] = rawItems.map((raw, index) => {
		const item = structuredClone(raw);
		if (item.deletedDate) throw new Error('Import contains a deleted item.');
		item.name = typeof item.name === 'string' && item.name ? item.name : '--';
		if (
			(format === 'bitwardenjson' || format === 'bitwardenzip')
			&& Array.isArray(item.passwordHistory)
			&& item.passwordHistory.length > 5
		) {
			item.passwordHistory = item.passwordHistory.slice(0, 5);
		}
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
				...encryptItem(item, key),
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
		...(Array.isArray(document.errors) && document.errors.length
			? { errors: document.errors as ImportRecordError[] }
			: {}),
	};
}
