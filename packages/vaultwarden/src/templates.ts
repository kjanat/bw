import type { JsonObject } from '#client';

export function template(name: string): unknown {
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
		collection: {
			organizationId: '00000000-0000-0000-0000-000000000000',
			name: 'Collection name',
			externalId: null,
		},
		'org-collection': { name: 'Collection name', organizationId: null, groups: [], users: [], externalId: null },
		'item.login': { uris: [], username: null, password: null, totp: null },
		'item.login.uri': { match: null, uri: null },
		'item.field': { name: null, value: null, type: 0, linkedId: null },
		'item.card': { cardholderName: null, brand: null, number: null, expMonth: null, expYear: null, code: null },
		'item.bankaccount': {
			bankName: 'Acme Bank',
			nameOnAccount: 'John Doe',
			accountType: 'checking',
			accountNumber: '000123456789',
			routingNumber: '000000000',
			branchNumber: '000',
			pin: '1234',
			swiftCode: 'ACMEUS33',
			iban: 'GB00ACME12345600000001',
			bankContactPhone: '1-800-123-4567',
		},
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
		'item.securenote': { type: 0 },
		'item.driverslicense': {
			firstName: 'Jane',
			middleName: 'A.',
			lastName: 'Smith',
			dateOfBirth: '1990-01-15',
			licenseNumber: 'D12345678',
			issuingCountry: 'US',
			issuingState: 'CA',
			issueDate: '2020-06-01',
			expirationDate: '2028-06-01',
			issuingAuthority: 'California DMV',
			licenseClass: 'C',
		},
		'item.passport': {
			surname: 'Smith',
			givenName: 'Jane',
			dateOfBirth: '1990-01-15',
			sex: 'F',
			birthPlace: 'Los Angeles, CA',
			nationality: 'USA',
			issuingCountry: 'US',
			passportNumber: 'A12345678',
			passportType: 'P',
			nationalIdentificationNumber: '123-45-6789',
			issuingAuthority: 'U.S. Department of State',
			issueDate: '2020-06-01',
			expirationDate: '2030-06-01',
		},
	};
	const normalizedName = name.toLowerCase();
	if (normalizedName === 'item-collections') return ['collection-id1', 'collection-id2'];
	if (!templates[normalizedName]) throw new Error('Unknown template.');
	return structuredClone(templates[normalizedName]);
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
