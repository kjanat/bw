import { object, text, type JsonObject } from '#client';
import type { VaultService } from '#vault-service';
import type { VaultItem, VaultFolder, ItemFilter } from '#models';
import type { SendInput } from '#sends';
import type { GeneratorOptions } from '#generator';
import { template } from '#templates';
import { totp } from '#totp';
import { PasswordExposureClient } from '#reports';
import { localApiObject as apiObject } from '#local-api-models';

/** The host application owns account persistence, unlock credentials and serialization. */
export interface LocalApiBackend {
	status(): Promise<JsonObject>;
	sync(): Promise<void>;
	lock(): Promise<void>;
	unlock(password: string): Promise<string>;
	generate(options: GeneratorOptions): Promise<string>;
	run<T>(mutate: boolean, operation: (vault: VaultService) => T | Promise<T>, online?: boolean): Promise<T>;
}
export interface LocalApiOptions {
	hostname?: string;
	port?: number;
	disableOriginProtection?: boolean;
	/** Includes multipart headers and fields, as well as the file. */
	maxUploadBytes?: number;
}
export function localApiAllowedHosts(hostname: string, port: number): ReadonlySet<string> {
	const hosts = ['localhost', '127.0.0.1', '[::1]', hostname];
	return new Set(hosts.flatMap(host => [
		`${host}:${port}`.toLowerCase(),
		...(port === 80 || port === 443 ? [host.toLowerCase()] : []),
	]));
}
export function localApiRequestAllowed(request: Request, options: LocalApiOptions): boolean {
	if (options.disableOriginProtection) return true;
	if (request.headers.has('Origin')) return false;
	return options.hostname === 'all' || localApiAllowedHosts(options.hostname ?? 'localhost', options.port ?? 8087)
		.has((request.headers.get('Host') ?? '').toLowerCase());
}
const stringResult = (data: string) => ({ object: 'string', data });
const messageResult = (title: string) => ({ object: 'message', title, message: null, noColor: false });
const templateResult = (template: unknown) => ({ object: 'template', template });
const listResult = (data: unknown[]) => ({ object: 'list', data });
const success = (data?: unknown) => Response.json({ success: true, ...(data === undefined ? {} : { data }) });
const failure = (message: string, status = 400) => Response.json({ success: false, message }, { status });
function routeMethods(parts: string[]): string[] {
	if (parts.length === 1 && ['status', 'generate'].includes(parts[0]!)) return ['GET', 'HEAD'];
	if (parts.length === 1 && ['sync', 'lock', 'unlock', 'attachment'].includes(parts[0]!)) return ['POST'];
	if (parts.length === 3 && parts[0] === 'list' && parts[1] === 'object') return ['GET', 'HEAD'];
	if (parts.length === 2 && parts[0] === 'send' && parts[1] === 'list') return ['GET', 'HEAD'];
	if (parts.length === 3 && parts[0] === 'send' && parts[2] === 'remove-password') return ['POST'];
	if (parts[0] === 'object' && parts.length === 2) return ['POST'];
	if (parts[0] === 'object' && parts.length === 3) return ['GET', 'HEAD', 'PUT', 'DELETE'];
	if (parts.length === 3 && ['move', 'restore', 'archive', 'confirm'].includes(parts[0]!)) return ['POST'];
	return [];
}
function boolean(query: URLSearchParams, key: string): boolean {
	const value = query.get(key);
	if (value === null) return false;
	if (value === '' || value === 'true' || value === '1') return true;
	if (value === 'false' || value === '0') return false;
	throw new Error(`Invalid ${key}.`);
}
function required(query: URLSearchParams, key: string): string {
	return text(query.get(key));
}
async function bodyBytes(request: Request, maximum: number): Promise<Uint8Array> {
	if (Number(request.headers.get('Content-Length')) > maximum) throw new Error('Request body is too large.');
	if (!request.body) return new Uint8Array();
	const reader = request.body.getReader(), parts: Uint8Array[] = [];
	let size = 0;
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			size += value.byteLength;
			if (size > maximum) {
				await reader.cancel();
				throw new Error('Request body is too large.');
			}
			parts.push(value);
		}
		return Buffer.concat(parts, size);
	} finally {
		reader.releaseLock();
	}
}
async function jsonBody(request: Request): Promise<unknown> {
	if (!request.headers.get('Content-Type')?.split(';')[0]?.trim().endsWith('/json')) {
		throw new Error('A JSON request body is required.');
	}
	const bytes = await bodyBytes(request, 1024 * 1024);
	try {
		return JSON.parse(new TextDecoder().decode(bytes));
	} finally {
		bytes.fill(0);
	}
}
function select(values: JsonObject[], id: string): JsonObject {
	const exact = values.find(value => value.id === id);
	if (exact) return exact;
	const matches = values.filter(value => typeof value.name === 'string' && value.name === id);
	if (matches.length !== 1) throw new Error(matches.length ? 'Multiple matching objects. Use an ID.' : 'Not found.');
	return matches[0]!;
}
function stringArray(value: unknown): string[] {
	if (!Array.isArray(value) || !value.every(part => typeof part === 'string')) {
		throw new Error('Expected collection IDs.');
	}
	return value;
}
function generatorOptions(query: URLSearchParams): GeneratorOptions {
	const result: Record<string, unknown> = {};
	for (
		const name of [
			'passphrase',
			'uppercase',
			'lowercase',
			'number',
			'special',
			'capitalize',
			'includeNumber',
			'avoidAmbiguous',
		]
	) {
		if (query.has(name)) result[name] = boolean(query, name);
	}
	for (const name of ['length', 'words', 'minNumber', 'minSpecial']) {
		if (query.has(name)) result[name] = Number(query.get(name));
	}
	if (query.has('separator')) result.separator = query.get('separator');
	return result as GeneratorOptions;
}
async function list(vault: VaultService, kind: string, query: URLSearchParams): Promise<unknown[]> {
	if (kind === 'items') {
		const filter: ItemFilter = {
			search: query.get('search') ?? undefined,
			folderId: query.get('folderid') ?? undefined,
			organizationId: query.get('organizationid') ?? undefined,
			collectionId: query.get('collectionid') ?? undefined,
			trash: boolean(query, 'trash'),
			archived: boolean(query, 'archived'),
		};
		const items = query.get('url') ? await vault.listItemsForUrl(query.get('url')!, filter) : vault.listItems(filter);
		return items.map(value => apiObject('item', value));
	}
	const values = kind === 'folders'
		? vault.listFolders()
		: kind === 'collections'
		? vault.listCollections()
		: kind === 'organizations'
		? vault.listOrganizations()
		: kind === 'org-collections'
		? await vault.listOrganizationCollections(required(query, 'organizationid'))
		: kind === 'org-members'
		? await vault.listOrganizationMembers(required(query, 'organizationid'))
		: kind === 'send'
		? vault.sends.list()
		: undefined;
	if (!values) throw new Error('Unknown object type.');
	return values.filter(value =>
		(!query.get('search') || [value.name, value.email]
			.some(part => typeof part === 'string' && part.toLowerCase().includes(query.get('search')!.toLowerCase())))
		&& (!query.get('organizationid') || kind === 'org-members' || kind === 'org-collections'
			|| (value.organizationId ?? (kind === 'organizations' ? value.id : undefined)) === query.get('organizationid'))
	).map(value =>
		apiObject(
			kind === 'folders'
				? 'folder'
				: kind === 'collections'
				? 'collection'
				: kind === 'organizations'
				? 'organization'
				: kind === 'org-collections'
				? 'org-collection'
				: kind === 'org-members'
				? 'org-member'
				: 'send',
			value,
		)
	);
}
async function get(vault: VaultService, kind: string, id: string, query: URLSearchParams): Promise<unknown> {
	if (kind === 'template') return templateResult(template(id));
	if (kind === 'folder') return apiObject(kind, select(vault.listFolders(), id));
	if (kind === 'collection') return apiObject(kind, select(vault.listCollections(), id));
	if (kind === 'organization') return apiObject(kind, select(vault.listOrganizations(), id));
	if (kind === 'org-collection') {
		return apiObject(kind, await vault.getOrganizationCollection(required(query, 'organizationid'), id));
	}
	if (kind === 'send') return { ...vault.sends.get(id), object: 'send' };
	if (kind === 'fingerprint') return stringResult(await vault.fingerprint(id));
	if (kind === 'attachment') {
		const file = await vault.getAttachment(required(query, 'itemid'), id);
		try {
			return new Response(new Uint8Array(file.contents), {
				headers: {
					'Content-Type': 'application/octet-stream',
					'Content-Length': String(file.contents.length),
					'Content-Disposition': `attachment; filename*=UTF-8''${encodeURIComponent(file.fileName)}`,
				},
			});
		} finally {
			file.contents.fill(0);
		}
	}
	if (kind === 'item') return apiObject('item', vault.findItem(id));
	if (!['password', 'username', 'uri', 'notes', 'totp', 'exposed'].includes(kind)) {
		throw new Error('Unknown object type.');
	}
	const field = kind === 'exposed' ? 'password' : kind;
	const value = (item: VaultItem): unknown =>
		kind === 'notes'
			? item.notes
			: kind === 'uri'
			? (Array.isArray(item.login?.uris) ? object(item.login.uris[0] ?? {}).uri : undefined)
			: item.type === 1
			? item.login?.[field]
			: undefined;
	const item = vault.findItem(
		id,
		item =>
			!(['password', 'totp', 'exposed'].includes(kind) && item.viewPassword === false)
			&& typeof value(item) === 'string' && (value(item) as string).trim().length > 0,
	);
	const raw = text(value(item));
	return stringResult(
		kind === 'totp' ? totp(raw) : kind === 'exposed' ? String(await new PasswordExposureClient().count(raw)) : raw,
	);
}
/** A bw-compatible local API handler. It never reads passwords from host files or environment variables. */
export function createLocalApiHandler(
	backend: LocalApiBackend,
	options: LocalApiOptions = {},
): (request: Request) => Promise<Response> {
	let tail = Promise.resolve();
	return async request => {
		if (!localApiRequestAllowed(request, options)) return failure('Forbidden.', 403);
		// Lock, unlock and mutations share the host application's session. Keep their ordering deterministic.
		const previous = tail;
		let release!: () => void;
		tail = new Promise(resolve => {
			release = resolve;
		});
		await previous;
		try {
			const url = new URL(request.url), query = url.searchParams;
			const parts = url.pathname.split('/').slice(1).map(decodeURIComponent),
				method = request.method === 'HEAD' ? 'GET' : request.method;
			const allowed = routeMethods(parts);
			if (!allowed.length) return failure('Not found.', 404);
			if (request.method === 'OPTIONS') {
				return new Response(null, { status: 204, headers: { Allow: allowed.join(', ') } });
			}
			if (!allowed.includes(request.method)) {
				return new Response(null, { status: 405, headers: { Allow: allowed.join(', ') } });
			}
			let result: unknown;
			if (parts.length === 1 && method === 'GET' && parts[0] === 'status') {
				result = templateResult(await backend.status());
			} else if (parts.length === 1 && method === 'GET' && parts[0] === 'generate') {
				result = stringResult(await backend.generate(generatorOptions(query)));
			} else if (parts.length === 1 && method === 'POST' && parts[0] === 'sync') {
				await backend.sync();
				result = messageResult('Sync complete.');
			} else if (parts.length === 1 && method === 'POST' && parts[0] === 'lock') {
				await backend.lock();
				result = messageResult('Vault locked.');
			} else if (parts.length === 1 && method === 'POST' && parts[0] === 'unlock') {
				const body = object(await jsonBody(request));
				result = { ...messageResult('Vault unlocked.'), raw: await backend.unlock(text(body.password)) };
			} else if (parts[0] === 'list' && parts[1] === 'object' && parts.length === 3 && method === 'GET') {
				result = listResult(
					await backend.run(false, vault => list(vault, parts[2]!, query), parts[2]!.startsWith('org-')),
				);
			} else if (parts[0] === 'send' && parts[1] === 'list' && parts.length === 2 && method === 'GET') {
				result = listResult(await backend.run(false, vault => list(vault, 'send', query)));
			} else if (parts[0] === 'send' && parts[2] === 'remove-password' && parts.length === 3 && method === 'POST') {
				result = await backend.run(true, vault => vault.sends.removePassword(parts[1]!));
			} else if (parts[0] === 'attachment' && parts.length === 1 && method === 'POST') {
				const bytes = await bodyBytes(request, options.maxUploadBytes ?? 526 * 1024 * 1024);
				try {
					const form = await new Request(request.url, {
						method: 'POST',
						headers: request.headers,
						body: new Uint8Array(bytes),
					})
						.formData();
					const file = form.get('file');
					if (!file || typeof file === 'string') throw new Error('A multipart file field is required.');
					const contents = new Uint8Array(await file.arrayBuffer());
					try {
						result = await backend.run(
							true,
							vault => vault.createAttachment(required(query, 'itemid'), file.name, contents),
						);
						result = apiObject('item', object(result));
					} finally {
						contents.fill(0);
					}
				} finally {
					bytes.fill(0);
				}
			} else if (parts[0] === 'object' && parts.length === 3 && method === 'GET') {
				result = await backend.run(
					false,
					vault => get(vault, parts[1]!, parts[2]!, query),
					parts[1] === 'attachment' || parts[1] === 'org-collection' || parts[1] === 'fingerprint',
				);
			} else if (
				parts[0] === 'object' && ((parts.length === 2 && method === 'POST') || (parts.length === 3 && method === 'PUT'))
			) {
				const body = await jsonBody(request), kind = parts[1]!, id = parts[2];
				result = await backend.run<unknown>(true, vault => {
					if (kind === 'item-collections' && id) return vault.editItemCollections(id, stringArray(body));
					const data = object(body);
					if (kind === 'item') return id ? vault.editItem(id, data as VaultItem) : vault.createItem(data as VaultItem);
					if (kind === 'folder') {
						return id
							? vault.editFolder(id, data as VaultFolder)
							: vault.createFolder(data as VaultFolder);
					}
					if (kind === 'org-collection') {
						return id
							? vault.editCollection(required(query, 'organizationid'), id, data)
							: vault.createCollection(required(query, 'organizationid'), data);
					}
					if (kind === 'send') {
						if (
							!id
							&& (typeof data.deletionDate !== 'string' || !Number.isFinite(Date.parse(data.deletionDate))
								|| Date.parse(data.deletionDate) <= Date.now())
						) {
							throw new Error('Must specify a valid deletion date after the current time');
						}
						if (!id && data.type === 1) {
							throw new Error('Creating a file-based Send is unsupported through the `serve` command at this time.');
						}
						return id ? vault.sends.edit(id, data) : vault.sends.create(data as SendInput);
					}
					throw new Error('Unknown object type.');
				});
				if (result && typeof result === 'object') result = apiObject(parts[1]!, object(result));
			} else if (parts[0] === 'object' && parts.length === 3 && method === 'DELETE') {
				await backend.run(true, async vault => {
					const kind = parts[1]!, id = parts[2]!;
					if (kind === 'item') await vault.deleteItem(id, boolean(query, 'permanent'));
					else if (kind === 'folder') await vault.deleteFolder(id);
					else if (kind === 'org-collection') await vault.deleteCollection(required(query, 'organizationid'), id);
					else if (kind === 'attachment') await vault.deleteAttachment(required(query, 'itemid'), id);
					else if (kind === 'send') await vault.sends.delete(id);
					else throw new Error('Unknown object type.');
				});
				result = messageResult('Deleted.');
			} else if (parts[0] === 'move' && parts.length === 3 && method === 'POST') {
				const collections = stringArray(await jsonBody(request));
				result = await backend.run(true, vault => vault.moveItem(parts[1]!, parts[2]!, collections));
				result = apiObject('item', object(result));
			} else if (['restore', 'archive', 'confirm'].includes(parts[0]!) && parts.length === 3 && method === 'POST') {
				await backend.run(true, async vault => {
					if (parts[0] === 'confirm' && parts[1] === 'org-member') {
						await vault.confirmMember(required(query, 'organizationid'), parts[2]!);
					} else if (parts[0] === 'restore' && parts[1] === 'item') await vault.restoreItem(parts[2]!);
					else if (parts[0] === 'archive' && parts[1] === 'item') await vault.archiveItem(parts[2]!);
					else throw new Error('Unknown object type.');
				});
				result = messageResult('Updated.');
			} else return failure('Not found.', 404);
			const response = result instanceof Response ? result : success(result);
			return request.method === 'HEAD'
				? new Response(null, { status: response.status, headers: response.headers })
				: response;
		} catch (error) {
			return failure(
				error instanceof SyntaxError || error instanceof URIError
					? 'Invalid request.'
					: error instanceof Error
					? error.message
					: 'Request failed.',
			);
		} finally {
			release();
		}
	};
}
