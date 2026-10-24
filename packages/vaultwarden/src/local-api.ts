import type { JsonObject } from '#client';
import { object, text } from '#client';
import type { GeneratorOptions } from '#generator';
import { parseGeneratorNumber } from '#generator';
import { localApiObject as apiObject } from '#local-api-models';
import type { EditVaultItem, ItemFilter, VaultFolder, VaultItem } from '#models';
import { PasswordExposureClient } from '#reports';
import type { SendInput } from '#sends';
import { templateForServer } from '#templates';
import { totp } from '#totp';
import { MultipleResultsError, VaultObjectNotFoundError } from '#search';
import type { VaultService } from '#vault-service';
import { basename } from 'node:path';

/** The host application owns account persistence, unlock credentials and serialization. */
export interface LocalApiBackend {
	status(): Promise<JsonObject>;
	sync(force: boolean): Promise<void>;
	lock(): Promise<void>;
	unlock(password: string | null): Promise<string>;
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
const stringResult = (data: string | null) => ({ object: 'string', data });
const messageResult = (title: string, message: string | null = null) => ({
	object: 'message',
	title,
	message,
	noColor: false,
});
const templateResult = (template: unknown) => ({ object: 'template', template });
const listResult = (data: unknown[]) => ({ object: 'list', data });
const jsonMediaTypes = new Set([
	'application/json',
	'application/json-patch+json',
	'application/vnd.api+json',
	'application/csp-report',
	'application/scim+json',
]);
const success = (data?: unknown) => Response.json({ success: true, ...(data === undefined ? {} : { data }) });
const failure = (message: string, status = 400, data?: unknown) =>
	Response.json({ success: false, message, ...(data === undefined ? {} : { data }) }, { status });
function routeMethods(parts: string[]): string[] {
	if (parts.length === 1 && ['status', 'generate'].includes(parts[0]!)) return ['HEAD', 'GET'];
	if (parts.length === 1 && ['sync', 'lock', 'unlock', 'attachment'].includes(parts[0]!)) return ['POST'];
	if (parts.length === 3 && parts[0] === 'list' && parts[1] === 'object') return ['HEAD', 'GET'];
	if (parts.length === 2 && parts[0] === 'send' && parts[1] === 'list') return ['HEAD', 'GET'];
	if (parts.length === 3 && parts[0] === 'send' && parts[2] === 'remove-password') return ['POST'];
	if (parts[0] === 'object' && parts.length === 2) return ['POST'];
	if (parts[0] === 'object' && parts.length === 3) return ['HEAD', 'GET', 'PUT', 'DELETE'];
	if (parts.length === 3 && ['move', 'restore', 'archive', 'confirm'].includes(parts[0]!)) return ['POST'];
	return [];
}
function boolean(query: URLSearchParams, key: string): boolean {
	const values = query.getAll(key);
	// Koa's query parser passes repeated keys as arrays; bw's boolean converter
	// treats every non-string/non-boolean value as false.
	if (values.length !== 1) return false;
	const value = values[0]!;
	return value === '' || value.toLowerCase() === 'true';
}
function queryValue(query: URLSearchParams, key: string): string | null {
	const camel = key.replace(/id$/, 'Id');
	return query.get(key) ?? (camel === key ? null : query.get(camel));
}
function listFilterValue(query: URLSearchParams, key: string): string | null {
	const camel = key.replace(/id$/, 'Id');
	const values = query.getAll(key);
	if (values.length > 1) return '\0';
	if (values[0]) return values[0];
	if (camel === key) return values[0] ?? null;
	const camelValues = query.getAll(camel);
	if (camelValues.length > 1) return '\0';
	return camelValues[0] ?? values[0] ?? null;
}
function requiredOption(query: URLSearchParams, key: string, message: string): string {
	const value = queryValue(query, key);
	if (!value) throw new Error(message);
	return value;
}
const isGuid = (value: string) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
function sameIdentifier(value: unknown, id: string): boolean {
	return typeof value === 'string' && value.toLowerCase() === id.toLowerCase();
}
function requiredGuidOption(query: URLSearchParams, key: string, plural = false): string {
	const value = queryValue(query, key);
	if (!value) throw new Error(`\`${key}\` ${plural ? 'options' : 'option'} is required.`);
	if (!isGuid(value)) throw new Error(`\`${value}\` is not a GUID.`);
	return value;
}
function collectionOrganizationId(query: URLSearchParams, data: JsonObject): string {
	const option = queryValue(query, 'organizationid') ?? undefined;
	const organizationId = option || data.organizationId;
	if (typeof organizationId !== 'string' || !organizationId.trim()) {
		throw new Error(
			'An organization id is required, either via the organizationid query option or request organizationId property.',
		);
	}
	if (!isGuid(organizationId)) throw new Error(`\`${organizationId}\` is not a GUID.`);
	if (
		option && typeof data.organizationId === 'string' && data.organizationId.trim()
		&& !sameIdentifier(option, data.organizationId)
	) {
		throw new Error('The organizationid query option does not match the request organizationId property.');
	}
	const normalized = organizationId.toLowerCase();
	data.organizationId = normalized;
	return normalized;
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
function formSegments(key: string): string[] | undefined {
	const match = /^([^\x5B\x5D]+)((?:\x5B[^\x5B\x5D]*\x5D)*)$/.exec(key);
	if (!match) return undefined;
	const brackets = [...match[2]!.matchAll(/\x5B([^\x5B\x5D]*)\x5D/g)].map(bracket => bracket[1]!);
	// koa-bodyparser's qs parser defaults to depth 5. It keeps deeper brackets
	// as a literal final key instead of discarding the parameter.
	const segments = [match[1]!, ...brackets.slice(0, 5)];
	if (brackets.length > 5) segments.push(brackets.slice(5).map(segment => `[${segment}]`).join(''));
	if (segments.some(segment => Object.prototype.hasOwnProperty.call(Object.prototype, segment))) {
		return undefined;
	}
	return segments;
}
function formArraySegment(segment: string | undefined): boolean {
	return segment === '' || (segment !== undefined && /^\d+$/.test(segment) && Number(segment) <= 20);
}
function assignFormValue(root: Record<string, unknown>, segments: string[], value: string): void {
	let target: Record<string, unknown> | unknown[] = root;
	for (let index = 0; index < segments.length; index++) {
		const segment = segments[index]!;
		const last = index === segments.length - 1;
		if (Array.isArray(target)) {
			const slot = segment === '' ? target.length : /^\d+$/.test(segment) ? Number(segment) : -1;
			if (slot < 0 || slot > 20) return;
			if (last) {
				const previous = target[slot];
				target[slot] = previous === undefined
					? value
					: Array.isArray(previous)
					? [...previous, value]
					: [previous, value];
				return;
			}
			const nextArray = formArraySegment(segments[index + 1]);
			const existing: unknown = target[slot];
			const child: Record<string, unknown> | unknown[] = existing && typeof existing === 'object'
				? existing as Record<string, unknown> | unknown[]
				: nextArray
				? []
				: Object.create(null) as Record<string, unknown>;
			if (existing === undefined) target[slot] = child;
			target = child;
			continue;
		}
		if (!segment) return;
		if (last) {
			const previous = target[segment];
			target[segment] = previous === undefined
				? value
				: Array.isArray(previous)
				? [...previous, value]
				: [previous, value];
			return;
		}
		const nextArray = formArraySegment(segments[index + 1]);
		const existing: unknown = target[segment];
		const child: Record<string, unknown> | unknown[] = existing && typeof existing === 'object'
			? existing as Record<string, unknown> | unknown[]
			: nextArray
			? []
			: Object.create(null) as Record<string, unknown>;
		if (existing === undefined) target[segment] = child;
		target = child;
	}
}
function compactFormArrays(value: unknown): unknown {
	if (Array.isArray(value)) return value.filter(entry => entry !== undefined).map(compactFormArrays);
	if (value && typeof value === 'object') {
		for (const key of Object.keys(value)) {
			(value as Record<string, unknown>)[key] = compactFormArrays((value as Record<string, unknown>)[key]);
		}
	}
	return value;
}
async function parsedBody(request: Request): Promise<unknown> {
	const mediaType = request.headers.get('Content-Type')?.split(';')[0]?.trim().toLowerCase();
	// Match koa-bodyparser 4.4.1 defaults used by the pinned bw serve command.
	if (
		!mediaType
		|| (!jsonMediaTypes.has(mediaType) && mediaType !== 'application/x-www-form-urlencoded')
	) return {};
	const maximum = mediaType === 'application/x-www-form-urlencoded' ? 56 * 1024 : 1024 * 1024;
	const bytes = await bodyBytes(request, maximum);
	try {
		const source = new TextDecoder().decode(bytes);
		if (jsonMediaTypes.has(mediaType)) {
			if (source.length === 0) return {};
			const first = source.trimStart()[0];
			if (first !== '{' && first !== '[') throw new SyntaxError('Invalid JSON body.');
			return JSON.parse(source);
		}
		const form = new URLSearchParams(source), result: Record<string, unknown> = Object.create(null);
		let parameters = 0;
		for (const [key, value] of form) {
			if (parameters++ >= 1000) break;
			const segments = formSegments(key);
			if (segments) assignFormValue(result, segments, value);
		}
		return compactFormArrays(result);
	} finally {
		bytes.fill(0);
	}
}
function stringArray(value: unknown): string[] {
	if (!Array.isArray(value) || !value.every(part => typeof part === 'string')) {
		throw new Error('Expected collection IDs.');
	}
	return value;
}
function unlockGuidance(session: string): string {
	return [
		'\nTo unlock your vault, set your session key to the `BW_SESSION` environment variable. ex:\n',
		`$ export BW_SESSION="${session}"\n`,
		`> $env:BW_SESSION="${session}"\n\n`,
		'You can also pass the session key to any command with the `--session` option. ex:\n',
		`$ bw list items --session ${session}`,
	].join('');
}
function attachmentDisposition(fileName: string): string {
	const name = basename(fileName);
	const fallback = name.replace(/[\s\S]/g, char => char.charCodeAt(0) > 0xff ? '?' : char);
	const quoted = /^[\x20-\x7e\x80-\xff]+$/.test(name);
	const params = new Map<string, string>();
	if (fallback !== name || !quoted || /%[\da-f]{2}/i.test(name)) {
		params.set(
			'filename*',
			`UTF-8''${
				encodeURIComponent(name).replace(/[!'()*]/g, char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`)
			}`,
		);
	}
	if (quoted || fallback !== name) {
		params.set('filename', fallback !== name ? fallback : name);
	}
	const formatted = [...params].sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) =>
		`${key}=${key.endsWith('*') ? value : `"${value.replace(/[\\"]/g, '\\$&')}"`}`
	);
	return `attachment${formatted.map(value => `; ${value}`).join('')}`;
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
	// The bw CLI exposes `ambiguous` as an opt-in that excludes ambiguous
	// characters; its generator service uses the inverse `avoidAmbiguous` name.
	if (query.has('ambiguous')) result.avoidAmbiguous = boolean(query, 'ambiguous');
	for (const name of ['length', 'words', 'minNumber', 'minSpecial']) {
		if (query.has(name)) {
			const fallback = name === 'length' ? 14 : name === 'words' ? 6 : name === 'minNumber' ? 1 : 0;
			result[name] = parseGeneratorNumber(query.get(name), fallback);
		}
	}
	if (query.has('separator')) result.separator = query.get('separator');
	return result as GeneratorOptions;
}
async function list(
	vault: VaultService,
	kind: string,
	query: URLSearchParams,
): Promise<unknown[]> {
	if (kind === 'items') {
		const filter: ItemFilter = {
			search: query.get('search') ?? undefined,
			folderId: listFilterValue(query, 'folderid') ?? undefined,
			organizationId: listFilterValue(query, 'organizationid') ?? undefined,
			collectionId: listFilterValue(query, 'collectionid') ?? undefined,
			trash: boolean(query, 'trash'),
			archived: boolean(query, 'archived'),
		};
		const url = query.get('url');
		const items = url?.trim() ? await vault.listItemsForUrl(url, filter) : await vault.listItems(filter);
		return items.map(value => apiObject('item', value));
	}
	const values = kind === 'folders'
		? vault.listFolders()
		: kind === 'collections'
		? await vault.listCollections()
		: kind === 'organizations'
		? vault.listOrganizations()
		: kind === 'org-collections'
		? await vault.listOrganizationCollections(requiredGuidOption(query, 'organizationid'))
		: kind === 'org-members'
		? await vault.listOrganizationMembers(requiredGuidOption(query, 'organizationid'))
		: kind === 'send'
		? vault.sends.list()
		: undefined;
	if (!values) throw new Error('Unknown object.');
	const sendSearch = query.get('search');
	const filtered = kind === 'send' && sendSearch?.trim()
		? searchSends(values, sendSearch)
		: values.filter(value =>
			(kind === 'org-members' || !query.get('search')?.trim()
				|| (typeof value.name === 'string' && value.name.toLowerCase().includes(query.get('search')!.toLowerCase())))
			&& (!queryValue(query, 'organizationid') || kind !== 'collections'
				|| value.organizationId === queryValue(query, 'organizationid'))
		);
	return filtered.map(value =>
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
/** Match the pinned CLI's Send search fields and name-first result ordering. */
function searchSends(values: JsonObject[], rawQuery: string): JsonObject[] {
	const query = rawQuery.trim().toLocaleLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
	const named: JsonObject[] = [], other: JsonObject[] = [];
	for (const send of values) {
		if (typeof send.name === 'string' && send.name.toLowerCase().includes(query)) {
			named.push(send);
			continue;
		}
		const file = object(send.file ?? {}), content = object(send.text ?? {});
		if (
			(query.length >= 8 && (
				(typeof send.id === 'string' && send.id.toLowerCase().startsWith(query))
				|| (typeof send.accessId === 'string' && send.accessId.toLocaleLowerCase().startsWith(query))
				|| (typeof file.id === 'string' && file.id.toLowerCase().startsWith(query))
			))
			|| (typeof send.notes === 'string' && send.notes.toLowerCase().includes(query))
			|| (typeof content.text === 'string' && content.text.toLowerCase().includes(query))
			|| (typeof file.fileName === 'string' && file.fileName.toLowerCase().includes(query))
		) other.push(send);
	}
	return [...named, ...other];
}
async function get(
	vault: VaultService,
	kind: string,
	id: string,
	query: URLSearchParams,
	originalId = id,
): Promise<unknown> {
	if (kind === 'template') return templateResult(await templateForServer(id, () => vault.client));
	if (kind === 'folder') return apiObject(kind, vault.findFolder(id));
	if (kind === 'collection') return apiObject(kind, await vault.findCollection(id));
	if (kind === 'organization') return apiObject(kind, vault.findOrganization(id));
	if (kind === 'org-collection') {
		if (!isGuid(id)) throw new Error(`\`${id}\` is not a GUID.`);
		return apiObject(kind, await vault.getOrganizationCollection(requiredGuidOption(query, 'organizationid'), id));
	}
	if (kind === 'send') {
		if (!isGuid(originalId)) throw new Error(`\`${originalId}\` is not a GUID.`);
		return apiObject('send', vault.sends.get(id));
	}
	if (kind === 'fingerprint') return stringResult(await vault.fingerprint(id));
	if (kind === 'attachment') {
		const itemId = requiredOption(query, 'itemid', '--itemid <itemid> required.');
		const file = await vault.getAttachment(itemId, id);
		try {
			return new Response(new Uint8Array(file.contents), {
				headers: {
					'Content-Type': 'application/octet-stream',
					'Content-Length': String(file.contents.length),
					'Content-Disposition': attachmentDisposition(file.fileName),
				},
			});
		} finally {
			file.contents.fill(0);
		}
	}
	if (kind === 'item') return apiObject('item', await vault.findItem(id));
	if (!['password', 'username', 'uri', 'notes', 'totp', 'exposed'].includes(kind)) {
		throw new Error('Unknown object.');
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
	const item = await vault.findItem(
		id,
		item => {
			const found = value(item);
			return typeof found === 'string' && (kind === 'uri' ? found !== '' : found.trim().length > 0);
		},
	);
	if (item.viewPassword === false && ['password', 'totp', 'exposed'].includes(kind)) {
		throw new Error(kind === 'totp' ? 'No TOTP available for this login.' : 'No password available for this login.');
	}
	const raw = text(value(item));
	if (kind === 'totp') {
		const code = totp(raw);
		if (!vault.canAccessTotp(text(item.id))) throw new Error('Premium status is required to use this feature.');
		return stringResult(code);
	}
	return stringResult(
		kind === 'exposed' ? String(await new PasswordExposureClient().count(raw)) : raw,
	);
}
/** A bw-compatible local API handler. It never reads passwords from host files or environment variables. */
export function createLocalApiHandler(
	backend: LocalApiBackend,
	options: LocalApiOptions = {},
): (request: Request) => Promise<Response> {
	let tail = Promise.resolve();
	return async request => {
		if (!localApiRequestAllowed(request, options)) {
			return new Response('Forbidden', { status: 403, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
		}
		// Lock, unlock and mutations share the host application's session. Keep their ordering deterministic.
		const previous = tail;
		let release!: () => void;
		tail = new Promise(resolve => {
			release = resolve;
		});
		await previous;
		try {
			const url = new URL(request.url), query = url.searchParams;
			const pathname = url.pathname.replace(/\/$/, '');
			const rawParts = pathname.split('/').slice(1);
			const parts = rawParts.map(decodeURIComponent);
			const route = rawParts.map(part => part.toLowerCase());
			const method = request.method === 'HEAD' ? 'GET' : request.method;
			const allowed = routeMethods(route);
			if (!allowed.length) {
				return new Response('Not Found', { status: 404, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
			}
			if (request.method === 'OPTIONS') {
				return new Response('', { status: 200, headers: { Allow: allowed.join(', ') } });
			}
			if (!allowed.includes(request.method)) {
				return new Response('Method Not Allowed', {
					status: 405,
					headers: { Allow: allowed.join(', '), 'Content-Type': 'text/plain; charset=utf-8' },
				});
			}
			let result: unknown;
			if (route.length === 1 && method === 'GET' && route[0] === 'status') {
				result = templateResult(await backend.status());
			} else if (route.length === 1 && method === 'GET' && route[0] === 'generate') {
				result = stringResult(await backend.generate(generatorOptions(query)));
			} else if (route.length === 1 && method === 'POST' && route[0] === 'sync') {
				if (boolean(query, 'last')) {
					const status = await backend.status();
					result = stringResult(typeof status.lastSync === 'string' ? status.lastSync : null);
				} else {
					try {
						await backend.sync(boolean(query, 'force'));
					} catch (error) {
						throw new Error(
							`Syncing failed: ${error instanceof Error ? error.message : 'Request failed.'}`,
							{ cause: error },
						);
					}
					result = messageResult('Syncing complete.');
				}
			} else if (route.length === 1 && method === 'POST' && route[0] === 'lock') {
				await backend.lock();
				result = messageResult('Your vault is locked.');
			} else if (route.length === 1 && method === 'POST' && route[0] === 'unlock') {
				const body = object(await parsedBody(request));
				const password = typeof body.password === 'string' && body.password.length ? body.password : null;
				const session = await backend.unlock(password);
				result = {
					...messageResult('Your vault is now unlocked!', unlockGuidance(session)),
					raw: session,
				};
			} else if (route[0] === 'list' && route[1] === 'object' && route.length === 3 && method === 'GET') {
				const kind = parts[2]!.toLowerCase();
				result = listResult(
					await backend.run(false, vault => list(vault, kind, query), kind.startsWith('org-')),
				);
			} else if (route[0] === 'send' && route[1] === 'list' && route.length === 2 && method === 'GET') {
				result = listResult(await backend.run(false, vault => list(vault, 'send', query)));
			} else if (route[0] === 'send' && route[2] === 'remove-password' && route.length === 3 && method === 'POST') {
				result = await backend.run(true, vault => vault.sends.removePassword(parts[1]!));
			} else if (route[0] === 'attachment' && route.length === 1 && method === 'POST') {
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
							vault =>
								vault.createAttachment(
									requiredOption(query, 'itemid', '`itemid` option is required.'),
									file.name,
									contents,
								),
						);
						result = apiObject('item', object(result));
					} finally {
						contents.fill(0);
					}
				} finally {
					bytes.fill(0);
				}
			} else if (route[0] === 'object' && route.length === 3 && method === 'GET') {
				const kind = parts[1]!.toLowerCase(), id = parts[2]!.toLowerCase();
				result = await backend.run(
					false,
					vault => get(vault, kind, id, query, parts[2]!),
					kind === 'attachment' || kind === 'org-collection' || kind === 'fingerprint',
				);
			} else if (
				route[0] === 'object' && ((route.length === 2 && method === 'POST') || (route.length === 3 && method === 'PUT'))
			) {
				const body = await parsedBody(request), kind = parts[1]!.toLowerCase(), id = parts[2]?.toLowerCase();
				result = await backend.run<unknown>(true, vault => {
					if (kind === 'item-collections' && id) return vault.editItemCollections(id, stringArray(body));
					const data = object(body);
					if (kind === 'item') {
						return id
							? vault.editItem(id, data as EditVaultItem)
							: vault.createItem(data as VaultItem);
					}
					if (kind === 'folder') {
						return id
							? vault.editFolder(id, data as VaultFolder)
							: vault.createFolder(data as VaultFolder);
					}
					if (kind === 'org-collection') {
						if (id && !isGuid(id)) throw new Error(`\`${id}\` is not a GUID.`);
						const organizationId = collectionOrganizationId(query, data);
						return id
							? vault.editCollection(organizationId, id, data)
							: vault.createCollection(organizationId, data);
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
					throw new Error('Unknown object.');
				});
				if (result && typeof result === 'object') result = apiObject(kind, object(result));
			} else if (route[0] === 'object' && route.length === 3 && method === 'DELETE') {
				await backend.run(true, async vault => {
					const kind = parts[1]!.toLowerCase(), id = parts[2]!.toLowerCase();
					if (kind === 'item') await vault.deleteItem(id, boolean(query, 'permanent'));
					else if (kind === 'folder') await vault.deleteFolder(id);
					else if (kind === 'org-collection') {
						const organizationId = requiredGuidOption(query, 'organizationid', true);
						if (!isGuid(id)) throw new Error(`\`${id}\` is not a GUID.`);
						await vault.deleteCollection(organizationId, id);
					} else if (kind === 'attachment') {
						await vault.deleteAttachment(requiredOption(query, 'itemid', '`itemid` option is required.'), id);
					} else if (kind === 'send') await vault.sends.delete(id);
					else throw new Error('Unknown object.');
				});
				result = undefined;
			} else if (route[0] === 'move' && route.length === 3 && method === 'POST') {
				// The pinned Serve route passes Koa's parsed body to ShareCommand as-is;
				// collection values are checked during access lookup, not prevalidated here.
				const collections = await parsedBody(request) as string[];
				result = await backend.run(true, vault => vault.moveItem(parts[1]!, parts[2]!, collections));
				result = apiObject('item', object(result));
			} else if (['restore', 'archive', 'confirm'].includes(route[0]!) && route.length === 3 && method === 'POST') {
				await backend.run(true, async vault => {
					const kind = parts[1]!.toLowerCase(), id = parts[2]!.toLowerCase();
					if (route[0] === 'confirm' && kind === 'org-member') {
						await vault.confirmMember(
							requiredOption(query, 'organizationid', '--organizationid <organizationid> required.'),
							id,
						);
					} else if (route[0] === 'restore' && kind === 'item') await vault.restoreItem(id);
					else if (route[0] === 'archive' && kind === 'item') await vault.archiveItem(id);
					else throw new Error('Unknown object.');
				});
				result = undefined;
			} else return failure('Not found.', 404);
			const response = result instanceof Response ? result : success(result);
			let formattedResponse = response;
			if (query.has('pretty') && response.headers.get('content-type')?.includes('json')) {
				const headers = new Headers(response.headers);
				headers.delete('content-length');
				formattedResponse = new Response(JSON.stringify(await response.json(), null, 2), {
					status: response.status,
					headers,
				});
			}
			return request.method === 'HEAD'
				? new Response(null, { status: formattedResponse.status, headers: formattedResponse.headers })
				: formattedResponse;
		} catch (error) {
			if (error instanceof MultipleResultsError) return failure(error.message, 400, error.ids);
			return failure(
				error instanceof SyntaxError || error instanceof URIError
					? 'Invalid request.'
					: error instanceof VaultObjectNotFoundError
					? 'Not found.'
					: error instanceof Error
					? error.message
					: 'Request failed.',
			);
		} finally {
			release();
		}
	};
}
