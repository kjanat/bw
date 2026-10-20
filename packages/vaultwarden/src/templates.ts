import type { JsonObject } from '#client';

export function template(name: string): JsonObject {
	const templates: Record<string, JsonObject> = {
		item: {
			organizationId: null,
			collectionIds: [],
			folderId: null,
			type: 1,
			name: 'Item name',
			notes: null,
			favorite: false,
			fields: [],
			login: { uris: [], username: null, password: null, totp: null },
			reprompt: 0,
		},
		folder: { name: 'Folder name' },
		'org-collection': { name: 'Collection name', organizationId: null, groups: [], users: [], externalId: null },
		'item.login': { uris: [], username: null, password: null, totp: null },
		'item.login.uri': { match: null, uri: null },
		'item.field': { name: null, value: null, type: 0, linkedId: null },
		'item.card': { cardholderName: null, brand: null, number: null, expMonth: null, expYear: null, code: null },
		'item.identity': Object.fromEntries(
			[
				'title',
				'firstName',
				'middleName',
				'lastName',
				'address1',
				'address2',
				'address3',
				'city',
				'state',
				'postalCode',
				'country',
				'company',
				'email',
				'phone',
				'ssn',
				'username',
				'passportNumber',
				'licenseNumber',
			].map(key => [key, null]),
		),
		'item.secureNote': { type: 0 },
		'item.sshKey': { privateKey: null, publicKey: null, keyFingerprint: null },
	};
	if (!templates[name]) throw new Error('Unknown template.');
	return structuredClone(templates[name]);
}
export function decodeJson(value: string): JsonObject {
	try {
		const encoded = value.trim();
		if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) throw new Error();
		const parsed: unknown = JSON.parse(Buffer.from(encoded, 'base64').toString('utf8'));
		if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error();
		return parsed as JsonObject;
	} catch {
		throw new Error('Expected a base64-encoded JSON object. Pipe JSON through vw encode first.');
	}
}

export function decodeStringArray(value: string): string[] {
	try {
		const encoded = value.trim();
		if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) throw new Error();
		const result: unknown = JSON.parse(Buffer.from(encoded, 'base64').toString('utf8'));
		if (!Array.isArray(result) || result.some(v => typeof v !== 'string' || !v)) throw new Error();
		return result;
	} catch {
		throw new Error('Expected a base64-encoded JSON array of collection IDs.');
	}
}
