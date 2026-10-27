import { expect, test } from 'bun:test';
import { generateKeyPairSync } from 'node:crypto';
import { VaultwardenClient } from '#client';
import { decryptSharedKey, encrypt, encryptSharedKey } from '#crypto';
import { fingerprintWords } from '#fingerprint';
import { VaultService } from '#vault-service';

const organizationId = '11111111-1111-1111-1111-111111111111';
const organizationUserId = '22222222-2222-2222-2222-222222222222';
const requestId = '33333333-3333-3333-3333-333333333333';
const pair = () =>
	generateKeyPairSync('rsa', {
		modulusLength: 2048,
		publicKeyEncoding: { type: 'spki', format: 'der' },
		privateKeyEncoding: { type: 'pkcs8', format: 'der' },
	});

test('device approval list projects trusted-device requests and their public-key fingerprints', async () => {
	const device = pair();
	const requests: string[] = [];
	const request = {
		id: requestId,
		userId: '44444444-4444-4444-4444-444444444444',
		organizationUserId,
		email: 'new-device@example.test',
		publicKey: device.publicKey.toString('base64'),
		requestDeviceIdentifier: 'device-identifier',
		requestDeviceType: 8,
		requestIpAddress: '192.0.2.10',
		requestCountryName: null,
		creationDate: '2026-10-27T10:00:00.000Z',
	};
	const client = new VaultwardenClient('https://vault.example.test', {
		fetch: Object.assign(async (input: URL | RequestInfo) => {
			const path = new URL(String(input)).pathname;
			requests.push(path);
			if (path === '/api/config') return Response.json({ server: { name: 'Bitwarden' } });
			if (path === `/api/organizations/${organizationId}/auth-requests`) return Response.json({ data: [request] });
			return Response.json({});
		}, { preconnect: () => {} }),
	});
	const service = new VaultService(client, 'synthetic-token', {
		profile: { organizations: [{ id: organizationId, canManageUsersPassword: true }] },
	}, Buffer.alloc(64, 1));
	const result = await service.deviceApprovals.list(organizationId);
	expect(result).toEqual([{
		object: 'auth-request',
		id: requestId,
		userId: request.userId,
		organizationUserId,
		email: request.email,
		requestDeviceIdentifier: request.requestDeviceIdentifier,
		requestDeviceType: 8,
		requestIpAddress: '192.0.2.10',
		creationDate: request.creationDate,
		fingerprintPhrase: fingerprintWords(request.email, device.publicKey).join('-'),
	}]);
	expect(JSON.stringify(result)).not.toContain('publicKey');
	expect(requests).toEqual(['/api/config', `/api/organizations/${organizationId}/auth-requests`]);
});

test('device approval decrypts recovery material locally and encrypts only the user key to the request device', async () => {
	const administrator = pair(), device = pair();
	const userKey = Buffer.alloc(64, 17), organizationKey = Buffer.alloc(64, 29), requestedUserKey = Buffer.alloc(64, 43);
	const encryptedOrganizationPrivateKey = encrypt(administrator.privateKey, organizationKey);
	const request = {
		id: requestId,
		userId: '44444444-4444-4444-4444-444444444444',
		organizationUserId,
		email: 'new-device@example.test',
		publicKey: device.publicKey.toString('base64'),
		requestDeviceIdentifier: 'device-identifier',
		requestDeviceType: 8,
		requestIpAddress: null,
		requestCountryName: null,
		creationDate: '2026-10-27T10:00:00.000Z',
	};
	let submitted: Record<string, unknown> | undefined;
	const paths: string[] = [];
	const client = new VaultwardenClient('https://vault.example.test', {
		fetch: Object.assign(async (input: URL | RequestInfo, init?: RequestInit) => {
			const path = new URL(String(input)).pathname;
			paths.push(path);
			if (path === '/api/config') return Response.json({ server: { name: 'Bitwarden' } });
			if (path === `/api/organizations/${organizationId}/auth-requests`) {
				return Response.json({ data: [request] });
			}
			if (path === `/api/organizations/${organizationId}/users/${organizationUserId}/reset-password-details`) {
				return Response.json({
					organizationUserId,
					resetPasswordKey: await encryptSharedKey(requestedUserKey, administrator.publicKey.toString('base64')),
					encryptedPrivateKey: encryptedOrganizationPrivateKey,
				});
			}
			if (path === `/api/organizations/${organizationId}/auth-requests/${requestId}`) {
				submitted = JSON.parse(String(init?.body)) as Record<string, unknown>;
				return Response.json({});
			}
			return Response.json({}, { status: 404 });
		}, { preconnect: () => {} }),
	});
	const service = new VaultService(client, 'synthetic-token', {
		profile: {
			privateKey: encrypt(administrator.privateKey, userKey),
			organizations: [{
				id: organizationId,
				key: await encryptSharedKey(organizationKey, administrator.publicKey.toString('base64')),
				canManageUsersPassword: true,
			}],
		},
	}, userKey);
	try {
		await service.deviceApprovals.approve(organizationId, requestId);
		expect(submitted).toMatchObject({ requestApproved: true });
		expect(Object.keys(submitted ?? {}).sort()).toEqual(['encryptedUserKey', 'requestApproved']);
		expect(await decryptSharedKey(String(submitted?.encryptedUserKey), device.privateKey)).toEqual(requestedUserKey);
		expect(paths).toEqual([
			'/api/config',
			`/api/organizations/${organizationId}/auth-requests`,
			`/api/organizations/${organizationId}/users/${organizationUserId}/reset-password-details`,
			`/api/organizations/${organizationId}/auth-requests/${requestId}`,
		]);
	} finally {
		userKey.fill(0);
		organizationKey.fill(0);
		requestedUserKey.fill(0);
		service.dispose();
	}
});

test('single device denial uses the API update request fields rather than the bulk request shape', async () => {
	let submitted: Record<string, unknown> | undefined;
	const client = new VaultwardenClient('https://vault.example.test', {
		fetch: Object.assign(async (input: URL | RequestInfo, init?: RequestInit) => {
			const path = new URL(String(input)).pathname;
			if (path === '/api/config') return Response.json({ server: { name: 'Bitwarden' } });
			if (path === `/api/organizations/${organizationId}/auth-requests`) {
				return Response.json({ data: [{ id: requestId, organizationUserId }] });
			}
			if (path === `/api/organizations/${organizationId}/auth-requests/${requestId}`) {
				submitted = JSON.parse(String(init?.body)) as Record<string, unknown>;
				return Response.json({});
			}
			return Response.json({}, { status: 404 });
		}, { preconnect: () => {} }),
	});
	const service = new VaultService(client, 'synthetic-token', {
		profile: { organizations: [{ id: organizationId, canManageUsersPassword: true }] },
	}, Buffer.alloc(64, 1));
	try {
		await service.deviceApprovals.deny(organizationId, requestId);
		expect(submitted).toEqual({ requestApproved: false });
	} finally {
		service.dispose();
	}
});

test('device approval batch sends the expected bulk update request fields', async () => {
	const administrator = pair(), device = pair();
	const userKey = Buffer.alloc(64, 17), organizationKey = Buffer.alloc(64, 29), requestedUserKey = Buffer.alloc(64, 43);
	const encryptedOrganizationPrivateKey = encrypt(administrator.privateKey, organizationKey);
	const request = {
		id: requestId,
		organizationUserId,
		publicKey: device.publicKey.toString('base64'),
	};
	let submitted: Record<string, unknown>[] | undefined;
	const client = new VaultwardenClient('https://vault.example.test', {
		fetch: Object.assign(async (input: URL | RequestInfo, init?: RequestInit) => {
			const path = new URL(String(input)).pathname;
			if (path === '/api/config') return Response.json({ server: { name: 'Bitwarden' } });
			if (path === `/api/organizations/${organizationId}/auth-requests` && init?.method === 'GET') {
				return Response.json({ data: [request] });
			}
			if (path === `/api/organizations/${organizationId}/users/account-recovery-details`) {
				return Response.json({
					data: [{
						organizationUserId,
						resetPasswordKey: await encryptSharedKey(requestedUserKey, administrator.publicKey.toString('base64')),
						encryptedPrivateKey: encryptedOrganizationPrivateKey,
					}],
				});
			}
			if (path === `/api/organizations/${organizationId}/auth-requests` && init?.method === 'POST') {
				submitted = JSON.parse(String(init.body)) as Record<string, unknown>[];
				return Response.json({});
			}
			return Response.json({}, { status: 404 });
		}, { preconnect: () => {} }),
	});
	const service = new VaultService(client, 'synthetic-token', {
		profile: {
			privateKey: encrypt(administrator.privateKey, userKey),
			organizations: [{
				id: organizationId,
				key: await encryptSharedKey(organizationKey, administrator.publicKey.toString('base64')),
				canManageUsersPassword: true,
			}],
		},
	}, userKey);
	try {
		expect(await service.deviceApprovals.approveAll(organizationId)).toBe(true);
		expect(submitted).toHaveLength(1);
		expect(Object.keys(submitted![0]!).sort()).toEqual(['approved', 'id', 'key']);
		expect(submitted![0]).toMatchObject({ id: requestId, approved: true });
		expect(await decryptSharedKey(String(submitted![0]!.key), device.privateKey)).toEqual(requestedUserKey);
	} finally {
		userKey.fill(0);
		organizationKey.fill(0);
		requestedUserKey.fill(0);
		service.dispose();
	}
});

test('device approval rejects the two verified Vaultwarden releases before organization routes', async () => {
	const paths: string[] = [];
	const client = new VaultwardenClient('https://vault.example.test', {
		fetch: Object.assign(async (input: URL | RequestInfo) => {
			const path = new URL(String(input)).pathname;
			paths.push(path);
			if (path === '/api/config') return Response.json({ server: { name: 'Vaultwarden' } });
			if (path === '/api/version') return Response.json('1.37.4');
			return Response.json({}, { status: 404 });
		}, { preconnect: () => {} }),
	});
	const service = new VaultService(client, 'synthetic-token', {
		profile: { organizations: [{ id: organizationId, canManageUsersPassword: true }] },
	}, Buffer.alloc(64, 1));
	await expect(service.deviceApprovals.list(organizationId)).rejects.toMatchObject({
		code: 'UNSUPPORTED_VAULTWARDEN_CAPABILITY',
		capability: 'organization-device-approval',
	});
	expect(paths).toEqual(['/api/config', '/api/version']);
	service.dispose();
});

test('device approval batch actions use organization endpoints and do not partially approve missing recovery data', async () => {
	const paths: string[] = [];
	let denied: unknown;
	let approvalWrite = false;
	const pending = [requestId, '55555555-5555-5555-5555-555555555555'].map((id, index) => ({
		id,
		organizationUserId: index ? '66666666-6666-6666-6666-666666666666' : organizationUserId,
	}));
	const client = new VaultwardenClient('https://vault.example.test', {
		fetch: Object.assign(async (input: URL | RequestInfo, init?: RequestInit) => {
			const path = new URL(String(input)).pathname;
			paths.push(path);
			if (path === '/api/config') return Response.json({ server: { name: 'Bitwarden' } });
			if (path === `/api/organizations/${organizationId}/auth-requests` && init?.method === 'GET') {
				return Response.json({ data: pending });
			}
			if (path === `/api/organizations/${organizationId}/auth-requests/deny`) {
				denied = JSON.parse(String(init?.body));
				return Response.json({});
			}
			if (path === '/api/organizations/' + organizationId + '/users/account-recovery-details') {
				return Response.json({ data: [{ organizationUserId }] });
			}
			if (path === `/api/organizations/${organizationId}/auth-requests` && init?.method === 'POST') {
				approvalWrite = true;
			}
			return Response.json({}, { status: 404 });
		}, { preconnect: () => {} }),
	});
	const service = new VaultService(client, 'synthetic-token', {
		profile: { organizations: [{ id: organizationId, canManageUsersPassword: true }] },
	}, Buffer.alloc(64, 1));
	expect(await service.deviceApprovals.denyAll(organizationId)).toBe(true);
	expect(denied).toEqual({ ids: pending.map(request => request.id) });
	await expect(service.deviceApprovals.approveAll(organizationId)).rejects.toThrow('All users must be enrolled');
	expect(approvalWrite).toBe(false);
	expect(paths.filter(path => path.endsWith('/auth-requests/deny'))).toHaveLength(1);
	service.dispose();
});
