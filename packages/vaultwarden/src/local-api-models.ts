import { object, type JsonObject } from '#client';

function pick(value: JsonObject, names: readonly string[]): JsonObject {
	return Object.fromEntries(names.filter(name => value[name] != null).map(name => [name, value[name]]));
}
function defined(value: JsonObject, names: readonly string[]): JsonObject {
	return Object.fromEntries(names.filter(name => value[name] !== undefined).map(name => [name, value[name]]));
}
function dates(value: JsonObject, names: readonly string[]): void {
	for (const name of names) {
		if (typeof value[name] === 'string') value[name] = new Date(value[name]).toISOString();
	}
}
function fido2CredentialResponse(value: unknown): JsonObject {
	const source = object(value);
	const result: JsonObject = {
		credentialId: typeof source.credentialId === 'string' ? source.credentialId : '',
		keyType: typeof source.keyType === 'string' ? source.keyType : '',
		keyAlgorithm: typeof source.keyAlgorithm === 'string' ? source.keyAlgorithm : '',
		keyCurve: typeof source.keyCurve === 'string' ? source.keyCurve : '',
		keyValue: typeof source.keyValue === 'string' ? source.keyValue : '',
		rpId: typeof source.rpId === 'string' ? source.rpId : '',
		counter: source.counter == null ? '' : String(source.counter),
		discoverable: source.discoverable == null ? 'false' : String(source.discoverable),
	};
	for (const name of ['userHandle', 'userName', 'rpName', 'userDisplayName']) {
		if (typeof source[name] === 'string') result[name] = source[name];
	}
	if (source.creationDate !== undefined) {
		const creationDate = source.creationDate == null ? NaN : Date.parse(String(source.creationDate));
		result.creationDate = Number.isFinite(creationDate) ? new Date(creationDate).toISOString() : null;
	}
	return result;
}
/** Project a decrypted item into the CLI response shape and enforce password visibility. */
export function vaultItemResponse(value: JsonObject): JsonObject {
	const result: JsonObject = {
		object: 'item',
		id: value.id ?? '',
		type: value.type ?? 1,
		reprompt: value.reprompt ?? 0,
		name: value.name ?? '',
		favorite: value.favorite ?? false,
		collectionIds: Array.isArray(value.collectionIds) ? value.collectionIds : [],
		fields: Array.isArray(value.fields)
			? value.fields.map(field => {
				const fieldValue = object(field);
				return {
					...pick(fieldValue, ['name', 'value']),
					type: fieldValue.type === undefined ? 0 : fieldValue.type,
					linkedId: fieldValue.linkedId,
				};
			})
			: [],
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
		: value.type === 6
		? 'bankAccount'
		: value.type === 7
		? 'driversLicense'
		: value.type === 8
		? 'passport'
		: undefined;
	if (section) {
		const data = object(value[section] ?? {});
		if (section === 'login') {
			const login: JsonObject = {
				...pick(data, ['username', 'password', 'totp']),
				uris: Array.isArray(data.uris)
					? data.uris.map(value => {
						const uri = object(value);
						return { ...pick(uri, ['uri']), ...(uri.match === undefined ? {} : { match: uri.match }) };
					})
					: [],
				fido2Credentials: Array.isArray(data.fido2Credentials)
					? data.fido2Credentials.map(fido2CredentialResponse)
					: [],
				passwordRevisionDate: data.passwordRevisionDate ?? null,
			};
			dates(login, ['passwordRevisionDate']);
			if (value.viewPassword === false) {
				login.password = null;
				login.totp = null;
				for (const credential of login.fido2Credentials as JsonObject[] ?? []) {
					credential.keyValue = null;
				}
			}
			result.login = login;
		} else if (section === 'secureNote') {
			result.secureNote = { type: data.type ?? 0 };
		} else if (section === 'card') {
			result.card = pick(data, ['cardholderName', 'brand', 'number', 'expMonth', 'expYear', 'code']);
		} else if (section === 'identity') {
			result.identity = pick(data, [
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
			]);
		} else if (section === 'sshKey') {
			result.sshKey = {
				privateKey: typeof data.privateKey === 'string' ? data.privateKey : '',
				publicKey: typeof data.publicKey === 'string' ? data.publicKey : '',
				keyFingerprint: typeof data.keyFingerprint === 'string' ? data.keyFingerprint : '',
			};
		} else if (section === 'bankAccount') {
			result.bankAccount = pick(data, [
				'bankName',
				'nameOnAccount',
				'accountType',
				'accountNumber',
				'routingNumber',
				'branchNumber',
				'pin',
				'swiftCode',
				'iban',
				'bankContactPhone',
			]);
		} else if (section === 'driversLicense') {
			result.driversLicense = pick(data, [
				'firstName',
				'middleName',
				'lastName',
				'dateOfBirth',
				'licenseNumber',
				'issuingCountry',
				'issuingState',
				'issueDate',
				'expirationDate',
				'issuingAuthority',
				'licenseClass',
			]);
		} else {
			result.passport = pick(data, [
				'surname',
				'givenName',
				'dateOfBirth',
				'sex',
				'birthPlace',
				'nationality',
				'issuingCountry',
				'passportNumber',
				'passportType',
				'nationalIdentificationNumber',
				'issuingAuthority',
				'issueDate',
				'expirationDate',
			]);
		}
	}
	result.attachments = Array.isArray(value.attachments)
		? value.attachments.map(value => {
			const attachment = object(value);
			return {
				id: attachment.id,
				fileName: attachment.fileName,
				size: attachment.size,
				sizeName: attachment.sizeName,
				url: attachment.url,
			};
		})
		: [];
	if (Array.isArray(result.passwordHistory)) {
		result.passwordHistory = result.passwordHistory.map(value => {
			const entry = object(value);
			const history: JsonObject = {
				lastUsedDate: entry.lastUsedDate,
				password: entry.password,
			};
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

/** Project collection details into the CLI and bw Serve response model. */
export function organizationCollectionResponse(source: JsonObject): JsonObject {
	const selections = (values: unknown) =>
		values == null
			? null
			: Array.isArray(values)
			? values.map(selection => {
				const fields = selection && typeof selection === 'object' && !Array.isArray(selection)
					? selection as JsonObject
					: {};
				return {
					id: fields.id,
					readOnly: fields.readOnly,
					hidePasswords: fields.hidePasswords ?? false,
					manage: fields.manage,
				};
			})
			: values;
	return {
		object: 'org-collection',
		...defined(source, ['id', 'organizationId', 'name', 'externalId']),
		groups: selections(source.groups),
		users: selections(source.users),
	};
}

/** Project owned and received Sends through their pinned response fields. */
export function sendObjectResponse(send: JsonObject, objectType = 'send'): JsonObject {
	const sendFields = (value: unknown, fields: readonly string[]) => {
		const source = value && typeof value === 'object' && !Array.isArray(value) ? value as JsonObject : {};
		return defined(source, fields);
	};
	if (objectType === 'send-access') {
		return {
			object: objectType,
			...sendFields(send, ['id', 'name', 'type']),
			...(send.type === 0 && send.text != null ? { text: sendFields(send.text, ['text', 'hidden']) } : {}),
			...(send.type === 1 && send.file != null
				? { file: sendFields(send.file, ['id', 'size', 'sizeName', 'fileName']) }
				: {}),
		};
	}
	return {
		object: 'send',
		...sendFields(send, [
			'id',
			'accessId',
			'accessUrl',
			'name',
			'notes',
			'key',
			'type',
			'maxAccessCount',
			'accessCount',
			'revisionDate',
			'deletionDate',
			'expirationDate',
			'passwordSet',
			'disabled',
			'hideEmail',
			'authType',
		]),
		emails: send.emails ?? [],
		...(send.type === 0 && send.text != null ? { text: sendFields(send.text, ['text', 'hidden']) } : {}),
		...(send.type === 1 && send.file != null
			? { file: sendFields(send.file, ['id', 'size', 'sizeName', 'fileName']) }
			: {}),
	};
}

/** Build other list response models while sharing the CLI item serializer. */
export function localApiObject(kind: string, value: JsonObject): JsonObject {
	if (kind === 'folder') return { object: kind, ...defined(value, ['id', 'name']) };
	if (kind === 'collection') return { object: kind, ...defined(value, ['id', 'organizationId', 'name', 'externalId']) };
	if (kind === 'org-collection') return organizationCollectionResponse(value);
	if (kind === 'organization') return { object: kind, ...defined(value, ['id', 'name', 'status', 'type', 'enabled']) };
	if (kind === 'org-member') {
		return { object: kind, ...defined(value, ['id', 'email', 'name', 'status', 'type', 'twoFactorEnabled']) };
	}
	if (kind === 'item') return vaultItemResponse(value);
	if (kind === 'send') return sendObjectResponse(value);
	const result: JsonObject = { ...value, object: kind };
	delete result.key;
	return result;
}
