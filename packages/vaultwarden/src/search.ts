import { getHostname } from 'tldts';
import lunr from 'lunr';
import { object } from '#client';
import type { VaultItem } from '#models';

/** A query matched multiple objects; callers can present the exact IDs for disambiguation. */
export class MultipleResultsError extends Error {
	constructor(readonly ids: string[]) {
		super(
			'More than one result was found. Try getting a specific object by `id` instead. '
				+ 'The following objects were found:\n'
				+ ids.join('\n'),
		);
		this.name = 'MultipleResultsError';
	}
}
/** A vault object lookup did not resolve; Serve maps this to bw's generic not-found response. */
export class VaultObjectNotFoundError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'VaultObjectNotFoundError';
	}
}

export function normalizeSearch(value: string): string {
	return value.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
}
const string = (value: unknown): string => typeof value === 'string' ? value : '';
/** Folder, collection and organization lookups use a whole substring, unlike item term search. */
export function findNamedObject<T extends { id?: unknown; name?: unknown }>(values: readonly T[], query: string): T {
	const normalized = query.toLowerCase();
	const guid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(query);
	const matches = !query.trim() ? [] : values.filter(value =>
		guid
			? typeof value.id === 'string' && value.id.toLowerCase() === normalized
			: typeof value.name === 'string' && value.name.toLowerCase().includes(normalized)
	);
	if (matches.length !== 1) {
		if (matches.length > 1) {
			throw new MultipleResultsError(matches.flatMap(value => typeof value.id === 'string' ? [value.id] : []));
		}
		throw new VaultObjectNotFoundError('Object not found.');
	}
	return matches[0]!;
}
function subtitle(item: VaultItem): string {
	if (item.type === 1) {
		const login = item.login ?? {};
		if (login.username) return string(login.username);
		return Array.isArray(login.fido2Credentials) && login.fido2Credentials.length
			? string(object(login.fido2Credentials[0]).userName)
			: '';
	}
	if (item.type === 3) {
		const card = item.card ?? {}, number = string(card.number);
		const suffix = number.length >= 4 ? '*' + number.slice(/^3[47]/.test(number) && number.length >= 5 ? -5 : -4) : '';
		return [string(card.brand), suffix].filter(Boolean).join(', ');
	}
	if (item.type === 4) {
		return [item.identity?.firstName, item.identity?.lastName]
			.filter((value): value is string => typeof value === 'string' && value.length > 0).join(' ');
	}
	if (item.type === 5) return string(item.sshKey?.keyFingerprint);
	if (item.type === 6) return string(item.bankAccount?.bankName);
	if (item.type === 7) {
		const name = [item.driversLicense?.firstName, item.driversLicense?.lastName]
			.filter((value): value is string => typeof value === 'string' && Boolean(value)).join(' ');
		const state = string(item.driversLicense?.issuingState);
		return name && state ? `${name}, ${state}` : name || state;
	}
	if (item.type === 8) {
		const name = [item.passport?.givenName, item.passport?.surname]
			.filter((value): value is string => typeof value === 'string' && Boolean(value)).join(' ');
		const country = string(item.passport?.issuingCountry);
		return [name, country].filter(Boolean).join(', ');
	}
	return '';
}
/** Basic CLI search uses AND across terms and OR across non-secret display fields. */
export function searchItems(items: readonly VaultItem[], query: string): VaultItem[] {
	const terms = normalizeSearch(query.trim()).split(/\s+/).filter(Boolean);
	return items.filter(item => {
		const hosts = item.type === 1 && Array.isArray(item.login?.uris)
			? item.login.uris.flatMap(value => {
				if (!value || typeof value !== 'object' || Array.isArray(value)) return [];
				const uri = value as { match?: unknown; uri?: unknown };
				if (
					uri.match === 4 || typeof uri.uri !== 'string' || !uri.uri.trim()
					|| /^(data|about|file):/i.test(uri.uri.trim())
				) return [];
				return [getHostname(uri.uri, { validHosts: ['localhost'] }) ?? ''];
			})
			: [];
		const targets = [string(item.name), subtitle(item), string(item.notes), ...hosts].map(normalizeSearch);
		return terms.every(term =>
			targets.some(target => target.includes(term)) || (term.length >= 8 && item.id?.toLowerCase().startsWith(term))
		);
	});
}

/** Lunr-style search for callers that explicitly opt into the extended syntax. */
export function searchItemsAdvanced(items: readonly VaultItem[], query: string): VaultItem[] {
	const builder = new lunr.Builder();
	builder.ref('id');
	builder.field('shortid', { boost: 100 });
	builder.field('name', { boost: 10 });
	builder.field('subtitle', { boost: 5 });
	builder.field('notes');
	builder.field('login.username');
	builder.field('login.uris', { boost: 2 });
	builder.field('fields');
	builder.field('fields_joined');
	builder.field('attachments');
	builder.field('attachments_joined');
	builder.field('organizationid');
	const indexed = new Map<string, VaultItem>();
	for (const item of items) {
		if (typeof item.id !== 'string') continue;
		indexed.set(item.id, item);
		const login = object(item.login ?? {});
		const customFields = Array.isArray(item.fields)
			? item.fields.flatMap(field => {
				if (!field || typeof field !== 'object' || Array.isArray(field)) return [];
				const values = typeof field.name === 'string' ? [field.name] : [];
				if (typeof field.value === 'string' && (field.type === undefined || field.type === 0)) values.push(field.value);
				return values.filter(value => value.trim());
			})
			: [];
		const attachments = Array.isArray(item.attachments)
			? item.attachments.flatMap(value => {
				if (!value || typeof value !== 'object' || Array.isArray(value)) return [];
				const fileName = value.fileName;
				return typeof fileName === 'string' && fileName.trim() ? [fileName] : [];
			})
			: [];
		const uris = item.type === 1 && Array.isArray(login.uris)
			? login.uris.flatMap(value => {
				if (!value || typeof value !== 'object' || Array.isArray(value)) return [];
				const uri = value as { match?: unknown; uri?: unknown };
				if (typeof uri.uri !== 'string' || !uri.uri) return [];
				const source = uri.uri;
				const regex = uri.match === 4;
				const host = regex ? undefined : getHostname(source, { validHosts: ['localhost'] });
				const port = source.match(/:(\d+)(?:[/?#]|$)/)?.[1];
				let processed = source;
				if (!regex) {
					const protocolIndex = processed.indexOf('://');
					if (protocolIndex > -1) processed = processed.slice(protocolIndex + 3);
					const queryIndex = processed.search(/[?&#]/);
					if (queryIndex > -1) processed = processed.slice(0, queryIndex);
				}
				return [
					...(host ? [host, ...(port ? [`${host}:${port}`, port] : [])] : []),
					processed,
				];
			})
			: [];
		const name = string(item.name);
		const itemSubtitle = item.type === 3 ? subtitle(item).replace(/\*/g, '') : subtitle(item);
		const notes = string(item.notes);
		builder.add({
			id: item.id,
			shortid: item.id.slice(0, 8),
			name: normalizeSearch(name),
			subtitle: normalizeSearch(itemSubtitle),
			notes: normalizeSearch(notes),
			'login.username': normalizeSearch(string(login.username)),
			'login.uris': uris,
			fields: customFields,
			fields_joined: customFields.join(' '),
			attachments,
			attachments_joined: attachments.map(fileName => {
				const extension = fileName.lastIndexOf('.');
				return extension > -1 ? fileName.slice(0, extension) : fileName;
			}).join(' '),
			organizationid: string(item.organizationId),
		});
	}
	try {
		const results = builder.build().search(normalizeSearch(query.trim()));
		return results.flatMap(result => {
			const item = indexed.get(result.ref);
			return item ? [item] : [];
		});
	} catch {
		return [];
	}
}
