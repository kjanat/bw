import type { JsonObject } from '#client';
import { UnsupportedVaultwardenCapabilityError } from '#capabilities';
import type { VaultwardenClient } from '#client';

export function template(name: string): unknown {
	const templates: Record<string, JsonObject> = {
		item: {
			type: 1,
			name: 'Item name',
			notes: 'Some notes about this item.',
			favorite: false,
			fields: [],
			reprompt: 0,
			passwordHistory: [],
		},
		folder: { name: 'Folder name' },
		collection: {
			organizationId: '00000000-0000-0000-0000-000000000000',
			name: 'Collection name',
			externalId: null,
		},
		'org-collection': {
			organizationId: '00000000-0000-0000-0000-000000000000',
			name: 'Collection name',
			externalId: null,
			groups: Array.from({ length: 2 }, () => ({
				id: '00000000-0000-0000-0000-000000000000',
				readOnly: false,
				hidePasswords: false,
				manage: false,
			})),
			users: Array.from({ length: 2 }, () => ({
				id: '00000000-0000-0000-0000-000000000000',
				readOnly: false,
				hidePasswords: false,
				manage: false,
			})),
		},
		'item.login': {
			uris: [],
			username: 'jdoe',
			password: 'myp@ssword123',
			totp: 'JBSWY3DPEHPK3PXP',
			fido2Credentials: [],
		},
		'item.login.uri': { uri: 'https://google.com' },
		'item.field': { name: 'Field name', value: 'Some value', type: 0 },
		'item.card': {
			cardholderName: 'John Doe',
			brand: 'visa',
			number: '4242424242424242',
			expMonth: '04',
			expYear: '2023',
			code: '123',
		},
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
		'item.identity': {
			title: 'Mr',
			firstName: 'John',
			middleName: 'William',
			lastName: 'Doe',
			address1: '123 Any St',
			address2: 'Apt #123',
			city: 'New York',
			state: 'NY',
			postalCode: '10001',
			country: 'US',
			company: 'Acme Inc.',
			email: 'john@company.com',
			phone: '5555551234',
			ssn: '000-123-4567',
			username: 'jdoe',
			passportNumber: 'US-123456789',
			licenseNumber: 'D123-12-123-12333',
		},
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
	if (normalizedName === 'send.file' || normalizedName === 'send.text') {
		throw new Error(`Invalid template object. Use \`bw send template ${normalizedName}\` instead.`);
	}
	if (!templates[normalizedName]) throw new Error('Unknown template object.');
	return structuredClone(templates[normalizedName]);
}

/** Return a template only when its cipher type is supported by the configured server. */
export async function templateForServer(name: string, getClient: () => VaultwardenClient): Promise<unknown> {
	const normalizedName = name.toLowerCase();
	const cipherTypes: Record<string, number> = {
		'item.bankaccount': 6,
		'item.driverslicense': 7,
		'item.passport': 8,
	};
	const cipherType = cipherTypes[normalizedName];
	if (cipherType !== undefined) {
		try {
			await getClient().assertCipherTypeSupported(cipherType);
		} catch (error) {
			if (!(error instanceof UnsupportedVaultwardenCapabilityError)) throw error;
			const label = cipherType === 6 ? 'Bank account' : cipherType === 7 ? "Driver's license" : 'Passport';
			throw new Error(`${label} item type is not available.`, { cause: error });
		}
	}
	return template(normalizedName);
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
