import { object, type JsonObject } from '#client';

function pick(value: JsonObject, names: readonly string[]): JsonObject {
	return Object.fromEntries(names.filter(name => value[name] != null).map(name => [name, value[name]]));
}
function dates(value: JsonObject, names: readonly string[]): void {
	for (const name of names) {
		if (typeof value[name] === 'string') value[name] = new Date(value[name]).toISOString();
	}
}
/** Match the CLI response models, rather than returning server wire metadata. */
export function localApiObject(kind: string, value: JsonObject): JsonObject {
	if (kind === 'folder') return { object: kind, ...pick(value, ['id', 'name']) };
	if (kind === 'organization') return { object: kind, ...pick(value, ['id', 'name', 'status', 'type', 'enabled']) };
	if (kind === 'org-member') {
		return { object: kind, ...pick(value, ['id', 'email', 'name', 'status', 'type', 'twoFactorEnabled']) };
	}
	if (kind !== 'item') {
		const result: JsonObject = { ...value, object: kind };
		if (kind !== 'send') delete result.key;
		return result;
	}
	const result: JsonObject = {
		object: 'item',
		id: value.id ?? '',
		type: value.type ?? 1,
		reprompt: value.reprompt ?? 0,
		name: value.name ?? '',
		favorite: value.favorite ?? false,
		collectionIds: value.collectionIds ?? [],
		fields: value.fields ?? [],
		passwordHistory: value.passwordHistory ?? [],
		...pick(value, [
			'organizationId',
			'folderId',
			'notes',
			'revisionDate',
			'creationDate',
			'deletedDate',
			'archivedDate',
		]),
	};
	dates(result, ['revisionDate', 'creationDate', 'deletedDate', 'archivedDate']);
	const section = value.type === 1 ? 'login' : value.type === 2 ? 'secureNote' : value.type === 3
		? 'card'
		: value.type === 4
		? 'identity'
		: value.type === 5
		? 'sshKey'
		: undefined;
	if (section && value[section] != null) {
		const data = object(value[section]);
		if (section === 'login') {
			const login: JsonObject = {
				...pick(data, ['username', 'password', 'totp']),
				uris: Array.isArray(data.uris)
					? data.uris.map(value => {
						const uri = object(value);
						return { ...pick(uri, ['uri']), ...(uri.match === undefined ? {} : { match: uri.match }) };
					})
					: [],
				fido2Credentials: data.fido2Credentials ?? [],
				passwordRevisionDate: data.passwordRevisionDate ?? null,
			};
			dates(login, ['passwordRevisionDate']);
			if (value.viewPassword === false) {
				login.password = null;
				login.totp = null;
			}
			result.login = login;
		} else result[section] = Object.fromEntries(Object.entries(data).filter(([, value]) => value != null));
	}
	result.attachments = Array.isArray(value.attachments)
		? value.attachments.map(value => pick(object(value), ['id', 'fileName', 'size', 'sizeName', 'url']))
		: [];
	if (Array.isArray(result.passwordHistory)) {
		result.passwordHistory = result.passwordHistory.map(value => {
			const history = pick(object(value), ['password', 'lastUsedDate']);
			dates(history, ['lastUsedDate']);
			return history;
		});
	}
	if (value.viewPassword === false) {
		delete result.passwordHistory;
		if (Array.isArray(result.fields)) {
			result.fields = result.fields.map(value => {
				const field = object(value);
				return field.type === 1 ? { ...field, value: null } : field;
			});
		}
	}
	return result;
}
