import { decrypt } from '#crypto';
import { field, object, text, type JsonObject } from '#client';

import { transformItem, validUriChecksum } from '#item-codec';

/** Decrypt an item with its owner key, unwrapping a per-item key when present. */
export function decryptItem(input: JsonObject, ownerKey: Uint8Array): JsonObject {
	if (field(input, 'organizationId')) throw new Error('Organization items require organization keys.');
	return decryptOwnedItem(input, ownerKey);
}
export function decryptOwnedItem(input: JsonObject, ownerKey: Uint8Array): JsonObject {
	let key: Buffer = Buffer.from(ownerKey);
	try {
		if (input.key) {
			const unwrapped = decrypt(text(input.key), key);
			key.fill(0);
			key = unwrapped;
		}
		const item = transformItem(input, key, 'decrypt');
		// Modern per-item-key ciphers require authenticated URI hashes. Legacy owner-key ciphers retain compatibility.
		if (input.key && item.login != null) {
			const login = object(item.login);
			if (Array.isArray(login.uris)) login.uris = login.uris.filter(value => validUriChecksum(object(value)));
		}

		delete item.key;
		return item;
	} finally {
		key.fill(0);
	}
}
export function personalItems(
	sync: JsonObject,
	userKey: Uint8Array,
): { items: JsonObject[]; excludedOrganizationItems: number } {
	const ciphers = field(sync, 'ciphers');
	if (!Array.isArray(ciphers)) throw new Error('Invalid vault sync response.');
	const personal = ciphers
		.map(object)
		.filter(
			(item) => !field(item, 'organizationId') && !field(item, 'deletedDate'),
		);
	return {
		items: personal.map((item) => decryptItem(item, userKey)),
		excludedOrganizationItems: ciphers
			.map(object)
			.filter((item) => !!field(item, 'organizationId')).length,
	};
}
