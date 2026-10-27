import { field, object, text, type JsonObject, type VaultwardenClient } from '#client';
import { vaultwardenCapabilities, UnsupportedVaultwardenCapabilityError } from '#capabilities';
import { encryptApprovedUserKey } from '#crypto';
import { fingerprintWords } from '#fingerprint';

export interface DeviceApprovalRequest extends JsonObject {
	id: string;
	userId: string;
	organizationUserId: string;
	email: string;
	requestDeviceIdentifier: string;
	requestDeviceType: number;
	requestIpAddress: string | null;
	creationDate: string;
	fingerprintPhrase: string;
}

const guid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const idPath = (value: string) => encodeURIComponent(value.toLowerCase());

function recordList(value: unknown): JsonObject[] {
	if (!Array.isArray(value)) throw new Error('Invalid device approval response.');
	return value.map(object);
}

function stringField(value: JsonObject, name: string): string {
	return text(field(value, name));
}

function numberField(value: JsonObject, name: string): number {
	const result = field(value, name);
	if (typeof result !== 'number' || !Number.isSafeInteger(result)) {
		throw new Error('Invalid device approval response.');
	}
	return result;
}

function optionalString(value: JsonObject, name: string): string | null {
	const result = field(value, name);
	if (result == null) return null;
	if (typeof result !== 'string') throw new Error('Invalid device approval response.');
	return result;
}

function publicKeyBytes(value: string): Buffer {
	if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw new Error('Invalid device approval public key.');
	const key = Buffer.from(value, 'base64');
	if (!key.length || key.toString('base64').replace(/=+$/, '') !== value.replace(/=+$/, '')) {
		throw new Error('Invalid device approval public key.');
	}
	return key;
}

function dateField(value: JsonObject): string {
	const raw = field(value, 'creationDate');
	if (typeof raw !== 'string') throw new Error('Invalid device approval response.');
	const date = new Date(raw);
	if (!Number.isFinite(date.getTime())) throw new Error('Invalid device approval response.');
	return date.toISOString();
}

/** Bitwarden organization trusted-device requests; Vaultwarden support is checked by release. */
export class DeviceApprovalService {
	constructor(
		private readonly client: VaultwardenClient,
		private readonly accessToken: string,
		private readonly snapshot: JsonObject,
		private readonly organizationKey: (organizationId: string) => Promise<Uint8Array>,
	) {}

	private async assertServerSupport(): Promise<void> {
		if (!(await this.client.isVaultwardenServer())) return;
		const version = await this.client.serverVersion();
		if ((vaultwardenCapabilities.organizationDeviceApproval.verifiedVersions as readonly string[]).includes(version)) {
			throw new UnsupportedVaultwardenCapabilityError('organization-device-approval');
		}
	}

	private async authorizedOrganization(organizationId: string): Promise<string> {
		if (!guid.test(organizationId)) throw new Error(`\`${organizationId}\` is not a GUID.`);
		const profile = object(field(this.snapshot, 'profile'));
		const organizations = field(profile, 'organizations');
		const organization = Array.isArray(organizations)
			? organizations.map(object).find(value =>
				typeof field(value, 'id') === 'string'
				&& (field(value, 'id') as string).toLowerCase() === organizationId.toLowerCase()
			)
			: undefined;
		if (field(organization ?? {}, 'canManageUsersPassword') !== true) {
			throw new Error('You do not have permission to approve pending device authorization requests.');
		}
		return organizationId.toLowerCase();
	}

	private async requests(organizationId: string): Promise<JsonObject[]> {
		const response = await this.client.api(
			this.accessToken,
			'GET',
			`/organizations/${idPath(organizationId)}/auth-requests`,
		);
		return recordList(field(response, 'data'));
	}

	private view(value: JsonObject): DeviceApprovalRequest {
		const email = stringField(value, 'email');
		const publicKey = publicKeyBytes(stringField(value, 'publicKey'));
		try {
			return {
				object: 'auth-request',
				id: stringField(value, 'id'),
				userId: stringField(value, 'userId'),
				organizationUserId: stringField(value, 'organizationUserId'),
				email,
				requestDeviceIdentifier: stringField(value, 'requestDeviceIdentifier'),
				requestDeviceType: numberField(value, 'requestDeviceType'),
				requestIpAddress: optionalString(value, 'requestIpAddress'),
				creationDate: dateField(value),
				fingerprintPhrase: fingerprintWords(email, publicKey).join('-'),
			};
		} finally {
			publicKey.fill(0);
		}
	}

	async list(organizationId: string): Promise<DeviceApprovalRequest[]> {
		await this.assertServerSupport();
		const id = await this.authorizedOrganization(organizationId);
		return (await this.requests(id)).map(request => this.view(request));
	}

	private async pendingRequest(organizationId: string, requestId: string): Promise<JsonObject> {
		if (!guid.test(requestId)) throw new Error(`\`${requestId}\` is not a GUID.`);
		const request = (await this.requests(organizationId)).find(value =>
			typeof field(value, 'id') === 'string'
			&& (field(value, 'id') as string).toLowerCase() === requestId.toLowerCase()
		);
		if (!request) throw new Error('The request id is invalid.');
		return request;
	}

	private async recoveryDetails(organizationId: string, organizationUserId: string): Promise<JsonObject> {
		const response = await this.client.api(
			this.accessToken,
			'GET',
			`/organizations/${idPath(organizationId)}/users/${idPath(organizationUserId)}/reset-password-details`,
		);
		return object(field(response, 'data') ?? response);
	}

	private async encryptedDeviceKey(organizationId: string, request: JsonObject, details: JsonObject): Promise<string> {
		const resetPasswordKey = field(details, 'resetPasswordKey');
		const encryptedPrivateKey = field(details, 'encryptedPrivateKey');
		if (
			typeof resetPasswordKey !== 'string' || !resetPasswordKey || typeof encryptedPrivateKey !== 'string'
			|| !encryptedPrivateKey
		) {
			throw new Error(
				'The user must be enrolled in account recovery (password reset) in order for the request to be approved.',
			);
		}
		const devicePublicKey = stringField(request, 'publicKey');
		const key = await this.organizationKey(organizationId);
		return encryptApprovedUserKey(resetPasswordKey, encryptedPrivateKey, key, devicePublicKey);
	}

	async approve(organizationId: string, requestId: string): Promise<void> {
		await this.assertServerSupport();
		const id = await this.authorizedOrganization(organizationId);
		const request = await this.pendingRequest(id, requestId);
		const organizationUserId = stringField(request, 'organizationUserId');
		const details = await this.recoveryDetails(id, organizationUserId);
		if (stringField(details, 'organizationUserId').toLowerCase() !== organizationUserId.toLowerCase()) {
			throw new Error('Invalid account recovery details response.');
		}
		const key = await this.encryptedDeviceKey(id, request, details);
		await this.client.api(this.accessToken, 'POST', `/organizations/${idPath(id)}/auth-requests/${idPath(requestId)}`, {
			requestApproved: true,
			encryptedUserKey: key,
		});
	}

	async deny(organizationId: string, requestId: string): Promise<void> {
		await this.assertServerSupport();
		const id = await this.authorizedOrganization(organizationId);
		await this.pendingRequest(id, requestId);
		await this.client.api(this.accessToken, 'POST', `/organizations/${idPath(id)}/auth-requests/${idPath(requestId)}`, {
			requestApproved: false,
		});
	}

	async approveAll(organizationId: string): Promise<boolean> {
		await this.assertServerSupport();
		const id = await this.authorizedOrganization(organizationId);
		const pending = await this.requests(id);
		if (pending.length === 0) return false;
		const userIds = [...new Set(pending.map(request => stringField(request, 'organizationUserId')))].sort();
		const recovery = await this.client.api(
			this.accessToken,
			'POST',
			`/organizations/${idPath(id)}/users/account-recovery-details`,
			{ ids: userIds },
		);
		const details = recordList(field(recovery, 'data'));
		const detailsByUser = new Map<string, JsonObject>();
		for (const detail of details) {
			const userId = stringField(detail, 'organizationUserId').toLowerCase();
			if (detailsByUser.has(userId)) throw new Error('Invalid account recovery details response.');
			detailsByUser.set(userId, detail);
		}
		if (userIds.some(userId => !detailsByUser.has(userId.toLowerCase()))) {
			throw new Error(
				'All users must be enrolled in account recovery (password reset) in order for the requests to be approved.',
			);
		}
		const entries: JsonObject[] = [];
		for (const request of pending) {
			const userId = stringField(request, 'organizationUserId').toLowerCase();
			const detail = detailsByUser.get(userId)!;
			entries.push({
				id: stringField(request, 'id'),
				approved: true,
				key: await this.encryptedDeviceKey(id, request, detail),
			});
		}
		await this.client.api(this.accessToken, 'POST', `/organizations/${idPath(id)}/auth-requests`, entries);
		return true;
	}

	async denyAll(organizationId: string): Promise<boolean> {
		await this.assertServerSupport();
		const id = await this.authorizedOrganization(organizationId);
		const pending = await this.requests(id);
		if (pending.length === 0) return false;
		const ids = pending.map(request => stringField(request, 'id'));
		await this.client.api(this.accessToken, 'POST', `/organizations/${idPath(id)}/auth-requests/deny`, { ids });
		return true;
	}
}
