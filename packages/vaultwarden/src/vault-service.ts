import {
	exportVault,
	importVault,
	type TransferOptions,
	type ExportFormat,
	type ImportFormat,
	type ImportResult,
} from '#transfer';
import { randomBytes } from 'node:crypto';
import { VaultwardenClient, field, object, text, type JsonObject } from '#client';
import { decrypt, encrypt, decryptSharedKey, encryptSharedKey, encryptAttachment, decryptAttachment } from '#crypto';
import { decryptOwnedItem } from '#vault';
import { transformItem } from '#item-codec';
import type { ItemFilter, VaultFolder, VaultItem } from '#models';

const idPath = (id: string) => encodeURIComponent(text(id));
function array(value: unknown): JsonObject[] {
	if (!Array.isArray(value)) throw new Error('Missing vault objects. Sync first.');
	return value.map(object);
}
function matchesId(value: unknown, filter: string): boolean {
	return filter === 'null' ? value == null : filter === 'notnull' ? value != null : value === filter;
}
/** Operates on an encrypted snapshot. No storage or terminal dependencies. Caller owns key lifetime. */
export class VaultService {
	constructor(
		readonly client: VaultwardenClient,
		readonly accessToken: string,
		readonly snapshot: JsonObject,
		private readonly userKey: Uint8Array,
	) {}
	exportVault(format: ExportFormat, options: TransferOptions = {}): Promise<Buffer> {
		return exportVault(
			this,
			{ user: this.userKey, organization: id => this.ownerKey({ organizationId: id }) },
			format,
			options,
		);
	}
	importVault(format: ImportFormat, input: Uint8Array | string, options: TransferOptions = {}): Promise<ImportResult> {
		return importVault(
			this,
			{ user: this.userKey, organization: id => this.ownerKey({ organizationId: id }) },
			format,
			input,
			options,
		);
	}
	/** Create an independent key-cache view over a refreshed encrypted snapshot. */
	withSnapshot(snapshot: JsonObject): VaultService {
		return new VaultService(this.client, this.accessToken, snapshot, this.userKey);
	}
	private readonly organizationKeys = new Map<string, Buffer>();
	dispose(): void {
		for (const key of this.organizationKeys.values()) key.fill(0);
		this.organizationKeys.clear();
	}
	private ownerKey(item: JsonObject): Uint8Array {
		if (!item.organizationId) return this.userKey;
		const id = text(item.organizationId);
		const cached = this.organizationKeys.get(id);
		if (cached) return cached;
		const profile = object(field(this.snapshot, 'profile'));
		const organization = array(profile.organizations ?? []).find(org => org.id === id);
		if (!organization) throw new Error('Organization key is not available. Sync first.');
		const pair = profile.accountKeys ? object(object(profile.accountKeys).publicKeyEncryptionKeyPair ?? {}) : {};
		const wrappedPrivateKey = text(profile.privateKey ?? pair.wrappedPrivateKey);
		const privateKey = decrypt(wrappedPrivateKey, this.userKey);
		try {
			const key = decryptSharedKey(text(organization.key), privateKey);
			if (key.length !== 64) {
				key.fill(0);
				throw new Error('Unsupported organization key length.');
			}
			this.organizationKeys.set(id, key);
			return key;
		} finally {
			privateKey.fill(0);
		}
	}
	listOrganizations(): JsonObject[] {
		return structuredClone(array(object(field(this.snapshot, 'profile')).organizations ?? [])).map(org => {
			delete org.key;
			return org;
		});
	}
	listCollections(): JsonObject[] {
		return array(field(this.snapshot, 'collections') ?? []).map(collection => ({
			...collection,
			name: decrypt(text(collection.name), this.ownerKey(collection)).toString('utf8'),
		}));
	}
	async listOrganizationCollections(organizationId: string): Promise<JsonObject[]> {
		const response = await this.client.api(
			this.accessToken,
			'GET',
			`/organizations/${idPath(organizationId)}/collections`,
		);
		return array(response.data).map(collection => this.decodeCollection({ ...collection, organizationId }));
	}
	private decodeCollection(collection: JsonObject): JsonObject {
		return { ...collection, name: decrypt(text(collection.name), this.ownerKey(collection)).toString('utf8') };
	}
	async getOrganizationCollection(organizationId: string, id: string): Promise<JsonObject> {
		const response = await this.client.api(
			this.accessToken,
			'GET',
			`/organizations/${idPath(organizationId)}/collections/${idPath(id)}/details`,
		);
		return this.decodeCollection({ ...response, organizationId });
	}
	async createCollection(organizationId: string, input: JsonObject): Promise<JsonObject> {
		return this.saveCollection(organizationId, undefined, input);
	}
	async editCollection(organizationId: string, id: string, input: JsonObject): Promise<JsonObject> {
		return this.saveCollection(organizationId, id, input);
	}
	private async saveCollection(organizationId: string, id: string | undefined, input: JsonObject): Promise<JsonObject> {
		if (typeof input.name !== 'string' || !input.name.trim()) throw new Error('Collection name is required.');
		if (input.organizationId && input.organizationId !== organizationId) {
			throw new Error('Collection organization does not match.');
		}
		const existing = id ? await this.getOrganizationCollection(organizationId, id) : {};
		const body = {
			name: encrypt(Buffer.from(input.name), this.ownerKey({ organizationId })),
			groups: input.groups ?? existing.groups ?? [],
			users: input.users ?? existing.users ?? [],
			externalId: input.externalId === undefined ? (existing.externalId ?? null) : input.externalId,
		};
		if (!Array.isArray(body.groups) || !Array.isArray(body.users)) {
			throw new Error('Collection users and groups must be arrays.');
		}
		const response = await this.client.api(
			this.accessToken,
			id ? 'PUT' : 'POST',
			`/organizations/${idPath(organizationId)}/collections${id ? `/${idPath(id)}` : ''}`,
			body,
		);
		return this.decodeCollection({ ...response, organizationId });
	}
	async deleteCollection(organizationId: string, id: string): Promise<void> {
		await this.client.api(
			this.accessToken,
			'DELETE',
			`/organizations/${idPath(organizationId)}/collections/${idPath(id)}`,
		);
	}
	async listOrganizationMembers(organizationId: string): Promise<JsonObject[]> {
		return array(
			(await this.client.api(this.accessToken, 'GET', `/organizations/${idPath(organizationId)}/users`)).data,
		);
	}
	async confirmMember(organizationId: string, id: string): Promise<void> {
		const member = await this.client.api(
			this.accessToken,
			'GET',
			`/organizations/${idPath(organizationId)}/users/${idPath(id)}`,
		);
		if (member.status !== 1) {
			throw new Error(
				member.status === 2 ? 'Member is already confirmed.' : 'Member must accept the invitation before confirmation.',
			);
		}
		const user = await this.client.api(this.accessToken, 'GET', `/users/${idPath(text(member.userId))}/public-key`);
		const key = encryptSharedKey(this.ownerKey({ organizationId }), text(user.publicKey));
		await this.client.api(
			this.accessToken,
			'POST',
			`/organizations/${idPath(organizationId)}/users/${idPath(id)}/confirm`,
			{ key },
		);
	}
	private validateCollections(organizationId: string, collections: string[]): void {
		if (!Array.isArray(collections) || collections.some(id => typeof id !== 'string' || !id)) {
			throw new Error('Expected an array of collection IDs.');
		}
		for (const id of collections) {
			if (
				!array(field(this.snapshot, 'collections') ?? []).some(collection =>
					collection.id === id && collection.organizationId === organizationId
				)
			) throw new Error('Collection is unavailable or belongs to another organization. Sync first.');
		}
	}
	async editItemCollections(id: string, collections: string[]): Promise<void> {
		const wire = this.wire(id);
		const org = text(wire.organizationId);
		this.validateCollections(org, collections);
		await this.client.api(this.accessToken, 'PUT', `/ciphers/${idPath(id)}/collections`, {
			collectionIds: collections,
		});
	}
	async moveItem(id: string, organizationId: string, collectionIds: string[]): Promise<VaultItem> {
		if (!collectionIds.length) throw new Error('At least one collection ID is required when moving an item.');
		const existing = this.wire(id);
		if (existing.organizationId) throw new Error('Only personal items can be moved to an organization.');
		this.validateCollections(organizationId, collectionIds);
		const owner = this.ownerKey({ organizationId });
		const key = existing.key ? decrypt(text(existing.key), this.userKey) : randomBytes(64);
		try {
			// For legacy items, generate a fresh item key; never wrap the user's account key for an organization.
			const cipher = existing.key
				? structuredClone(existing)
				: transformItem(decryptOwnedItem(existing, this.userKey), key, 'encrypt');
			cipher.organizationId = organizationId;
			cipher.key = encrypt(key, owner);
			cipher.encryptedFor = text(object(field(this.snapshot, 'profile')).id);
			cipher.lastKnownRevisionDate = text(existing.revisionDate);
			if (!existing.key && Array.isArray(existing.attachments)) {
				const attachments: JsonObject = {};
				for (const value of existing.attachments) {
					const attachment = object(value);
					if (!attachment.key) {
						throw new Error('Legacy attachments without individual keys must be migrated before moving this item.');
					}
					const attachmentKey = decrypt(text(attachment.key), this.userKey);
					try {
						attachments[text(attachment.id)] = {
							fileName: encrypt(decrypt(text(attachment.fileName), this.userKey), key),
							key: encrypt(attachmentKey, key),
						};
					} finally {
						attachmentKey.fill(0);
					}
				}
				cipher.attachments2 = attachments;
			}
			delete cipher.attachments;
			delete cipher.id;
			delete cipher.revisionDate;
			const response = await this.client.api(this.accessToken, 'PUT', `/ciphers/${idPath(id)}/share`, {
				cipher,
				collectionIds,
			});
			return decryptOwnedItem(response, owner) as VaultItem;
		} finally {
			key.fill(0);
		}
	}
	private wire(id: string): JsonObject {
		const found = array(field(this.snapshot, 'ciphers')).find(item => item.id === id);
		if (!found) throw new Error('Item not found. Sync and use its ID.');
		return found;
	}
	listItems(filter: ItemFilter = {}): VaultItem[] {
		return array(field(this.snapshot, 'ciphers')).filter(item => {
			if (Boolean(item.deletedDate) !== Boolean(filter.trash)) return false;
			if (!filter.trash && Boolean(item.archivedDate) !== Boolean(filter.archived)) return false;
			const filters = [
				filter.folderId === undefined ? undefined : matchesId(item.folderId, filter.folderId),
				filter.organizationId === undefined ? undefined : matchesId(item.organizationId, filter.organizationId),
				filter.collectionId === undefined
					? undefined
					: Array.isArray(item.collectionIds) && item.collectionIds.includes(filter.collectionId),
			].filter(value => value !== undefined);
			return !filters.length || filters.some(Boolean);
		}).map(item => decryptOwnedItem(item, this.ownerKey(item)) as VaultItem).filter(item => {
			if (!filter.search) return true;
			const login = item.login ?? {};
			const values = [
				item.id,
				item.name,
				item.notes,
				login.username,
				...(Array.isArray(login.uris) ? login.uris.map(uri => object(uri).uri) : []),
			];
			return values.some(value =>
				typeof value === 'string' && value.toLowerCase().includes(filter.search!.toLowerCase())
			);
		});
	}
	getItem(id: string): VaultItem {
		const wire = this.wire(id);
		return decryptOwnedItem(wire, this.ownerKey(wire)) as VaultItem;
	}
	listFolders(): VaultFolder[] {
		return array(field(this.snapshot, 'folders') ?? []).map(folder => ({
			...folder,
			name: decrypt(text(folder.name), this.userKey).toString('utf8'),
		}));
	}
	getFolder(id: string): VaultFolder {
		const folder = this.listFolders().find(folder => folder.id === id);
		if (!folder) throw new Error('Folder not found.');
		return folder;
	}
	private encodeItem(input: VaultItem, existing?: JsonObject): JsonObject {
		if (typeof input.name !== 'string' || !input.name.trim()) throw new Error('Item name is required.');
		if (!Number.isInteger(input.type) || ![1, 2, 3, 4, 5].includes(input.type)) {
			throw new Error('Unsupported item type.');
		}
		const owner = this.ownerKey(input);
		if (existing && (input.organizationId ?? null) !== (existing.organizationId ?? null)) {
			throw new Error('Use move to change item ownership.');
		}
		let itemKey: Buffer | undefined;
		try {
			// Keep the current item key on edits: attachment keys and unknown encrypted data depend on it.
			itemKey = existing ? (existing.key ? decrypt(text(existing.key), owner) : undefined) : randomBytes(64);
			const plain = { ...input };
			delete plain.key;
			if (existing?.attachments) plain.attachments = undefined; // Attachment metadata has its own endpoint.
			const encoded = transformItem(plain, itemKey ?? owner, 'encrypt');
			encoded.key = existing ? (existing.key ?? null) : encrypt(itemKey!, owner);
			encoded.encryptedFor = text(object(field(this.snapshot, 'profile')).id);
			const revision = existing ? text(input.revisionDate ?? existing.revisionDate) : null;
			if (revision && !Number.isFinite(Date.parse(revision))) throw new Error('Invalid item revision date.');
			encoded.lastKnownRevisionDate = revision;
			delete encoded.revisionDate;
			delete encoded.id;
			delete encoded.deletedDate;
			return encoded;
		} finally {
			itemKey?.fill(0);
		}
	}
	async createItem(input: VaultItem): Promise<VaultItem> {
		const encoded = this.encodeItem(input);
		const wire = await this.client.api(
			this.accessToken,
			'POST',
			input.organizationId ? '/ciphers/create' : '/ciphers',
			input.organizationId ? { cipher: encoded, collectionIds: input.collectionIds ?? [] } : encoded,
		);
		return decryptOwnedItem(wire, this.ownerKey(wire)) as VaultItem;
	}
	async editItem(id: string, input: VaultItem): Promise<VaultItem> {
		const existing = this.wire(id);
		const wire = await this.client.api(
			this.accessToken,
			'PUT',
			`/ciphers/${idPath(id)}`,
			this.encodeItem(input, existing),
		);
		return decryptOwnedItem(wire, this.ownerKey(wire)) as VaultItem;
	}
	async deleteItem(id: string, permanent = false): Promise<void> {
		this.wire(id);
		await this.client.api(
			this.accessToken,
			permanent ? 'DELETE' : 'PUT',
			`/ciphers/${idPath(id)}${permanent ? '' : '/delete'}`,
		);
	}
	async restoreItem(id: string): Promise<void> {
		const wire = this.wire(id);
		await this.client.api(
			this.accessToken,
			'PUT',
			`/ciphers/${idPath(id)}/${wire.deletedDate ? 'restore' : 'unarchive'}`,
		);
	}
	async archiveItem(id: string): Promise<void> {
		this.wire(id);
		await this.client.api(this.accessToken, 'PUT', `/ciphers/${idPath(id)}/archive`);
	}
	private itemKey(wire: JsonObject): Buffer {
		const owner = this.ownerKey(wire);
		return wire.key ? decrypt(text(wire.key), owner) : Buffer.from(owner);
	}
	async createAttachment(itemId: string, fileName: string, contents: Uint8Array): Promise<JsonObject> {
		if (!fileName || fileName.includes('\0')) throw new Error('Attachment file name is required.');
		if (contents.length > 525 * 1024 * 1024 - 65) throw new Error('Attachment exceeds the supported size.');
		const item = this.wire(itemId);
		const itemKey = this.itemKey(item);
		const attachmentKey = randomBytes(64);
		try {
			const ciphertext = encryptAttachment(contents, attachmentKey);
			const response = await this.client.api(this.accessToken, 'POST', `/ciphers/${idPath(itemId)}/attachment/v2`, {
				fileName: encrypt(Buffer.from(fileName), itemKey),
				key: encrypt(attachmentKey, itemKey),
				fileSize: ciphertext.length,
			});
			const attachmentId = text(response.attachmentId);
			try {
				if (response.fileUploadType !== 0) throw new Error('Unsupported attachment upload provider.');
				const form = new FormData();
				form.set('data', new Blob([new Uint8Array(ciphertext)]), 'encrypted');
				await this.client.uploadAttachment(this.accessToken, itemId, attachmentId, form);
			} catch {
				try {
					await this.client.api(
						this.accessToken,
						'DELETE',
						`/ciphers/${idPath(itemId)}/attachment/${idPath(attachmentId)}`,
					);
				} catch {
					throw new Error(`Attachment upload failed; cleanup also failed. Sync and delete attachment ${attachmentId}.`);
				}
				throw new Error('Attachment upload failed; incomplete metadata was removed.');
			}
			const wire = object(response.cipherResponse ?? response.cipherMiniResponse);
			return decryptOwnedItem(wire, this.ownerKey(wire));
		} finally {
			itemKey.fill(0);
			attachmentKey.fill(0);
		}
	}
	async getAttachment(itemId: string, idOrName: string): Promise<{ fileName: string; contents: Buffer }> {
		const item = this.wire(itemId);
		const itemKey = this.itemKey(item);
		try {
			const attachments = array(item.attachments ?? []);
			let attachment = attachments.find(a => a.id === idOrName);
			if (!attachment) {
				const matches = attachments.filter(a => decrypt(text(a.fileName), itemKey).toString('utf8') === idOrName);
				if (matches.length !== 1) {
					throw new Error(matches.length ? 'Multiple matching attachments. Use an ID.' : 'Attachment not found.');
				}
				attachment = matches[0]!;
			}
			const metadata = await this.client.api(
				this.accessToken,
				'GET',
				`/ciphers/${idPath(itemId)}/attachment/${idPath(text(attachment.id))}`,
			);
			const key = metadata.key ? decrypt(text(metadata.key), itemKey) : Buffer.from(itemKey);
			try {
				return {
					fileName: decrypt(text(metadata.fileName), itemKey).toString('utf8'),
					contents: decryptAttachment(await this.client.downloadAttachment(text(metadata.url)), key),
				};
			} finally {
				key.fill(0);
			}
		} finally {
			itemKey.fill(0);
		}
	}
	async deleteAttachment(itemId: string, id: string): Promise<void> {
		this.wire(itemId);
		await this.client.api(this.accessToken, 'DELETE', `/ciphers/${idPath(itemId)}/attachment/${idPath(id)}`);
	}
	async createFolder(input: VaultFolder): Promise<VaultFolder> {
		return this.saveFolder('POST', '/folders', input);
	}
	async editFolder(id: string, input: VaultFolder): Promise<VaultFolder> {
		this.getFolder(id);
		return this.saveFolder('PUT', `/folders/${idPath(id)}`, input);
	}
	private async saveFolder(method: string, path: string, input: VaultFolder): Promise<VaultFolder> {
		if (typeof input.name !== 'string' || !input.name.trim()) throw new Error('Folder name is required.');
		const wire = await this.client.api(this.accessToken, method, path, {
			name: encrypt(Buffer.from(input.name), this.userKey),
		});
		return { ...wire, name: decrypt(text(wire.name), this.userKey).toString('utf8') };
	}
	async deleteFolder(id: string): Promise<void> {
		this.getFolder(id);
		await this.client.api(this.accessToken, 'DELETE', `/folders/${idPath(id)}`);
	}
}
