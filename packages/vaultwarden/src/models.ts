import type { JsonObject } from '#client';

export interface VaultItem extends JsonObject {
	id?: string;
	type: number;
	name: string;
	notes?: string | null;
	organizationId?: string | null;
	folderId?: string | null;
	collectionIds?: string[];
	favorite?: boolean;
	reprompt?: number;
	login?: JsonObject | null;
	secureNote?: JsonObject | null;
	card?: JsonObject | null;
	identity?: JsonObject | null;
	sshKey?: JsonObject | null;
	bankAccount?: JsonObject | null;
	driversLicense?: JsonObject | null;
	passport?: JsonObject | null;
	fields?: JsonObject[] | null;
	passwordHistory?: JsonObject[] | null;
	revisionDate?: string;
	deletedDate?: string | null;
	archivedDate?: string | null;
}
/** An item update overlays supplied fields on the current decrypted item. */
export interface EditVaultItem extends JsonObject {
	type: number;
	key?: string | null;
	name?: string;
	notes?: string | null;
	organizationId?: string | null;
	folderId?: string | null;
	collectionIds?: string[];
	favorite?: boolean;
	reprompt?: number;
	login?: JsonObject | null;
	secureNote?: JsonObject | null;
	card?: JsonObject | null;
	identity?: JsonObject | null;
	sshKey?: JsonObject | null;
	bankAccount?: JsonObject | null;
	driversLicense?: JsonObject | null;
	passport?: JsonObject | null;
	fields?: JsonObject[] | null;
	passwordHistory?: JsonObject[] | null;
	revisionDate?: string;
	deletedDate?: string | null;
	archivedDate?: string | null;
}
export interface VaultFolder extends JsonObject {
	id?: string;
	name: string;
}
export interface ItemFilter {
	search?: string;
	folderId?: string;
	organizationId?: string;
	collectionId?: string;
	trash?: boolean;
	archived?: boolean;
}
