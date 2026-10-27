import { createHash } from 'node:crypto';
import { expect, test } from 'bun:test';
import { createWebAuthnToken, type Fido2Runner, type VaultwardenWebAuthnOptions } from '#webauthn';

const challenge = Buffer.from('synthetic-challenge').toString('base64url');
const credentialId = Buffer.from('synthetic-credential-id').toString('base64url');
const options: VaultwardenWebAuthnOptions = {
	challenge,
	rpId: 'vault.example.test',
	allowCredentials: [{ id: credentialId, type: 'public-key' }],
	userVerification: 'discouraged',
	extensions: { appid: 'https://vault.example.test/app-id.json' },
};
function successfulRunner(u2f = false, verifyUser = false): Fido2Runner {
	return {
		listDevices: async () => ['/dev/mock-key'],
		assert: async (_device, input, useU2f, useVerification) => {
			expect(useU2f).toBe(u2f);
			expect(useVerification).toBe(verifyUser);
			const [hash, rpId] = input.split('\n');
			return [
				hash!,
				u2f ? options.extensions!.appid! : rpId!,
				Buffer.alloc(37, 1).toString('base64'),
				Buffer.from([5, 6, 7]).toString('base64'),
			];
		},
	};
}
test('FIDO2 result becomes the WebAuthn JSON accepted by Vaultwarden', async () => {
	const token = JSON.parse(await createWebAuthnToken(options, 'https://vault.example.test', successfulRunner())) as {
		id: string;
		rawId: string;
		type: string;
		response: Record<string, string | null>;
		extensions: Record<string, boolean>;
	};
	const clientDataJSON = Buffer.from(token.response.clientDataJSON!, 'base64url');
	expect(JSON.parse(clientDataJSON.toString('utf8'))).toEqual({
		type: 'webauthn.get',
		challenge,
		origin: 'https://vault.example.test',
		crossOrigin: false,
	});
	expect(token.id).toBe(credentialId);
	expect(token.rawId).toBe(credentialId);
	expect(token.type).toBe('public-key');
	expect(token.response).toMatchObject({
		authenticatorData: Buffer.alloc(37, 1).toString('base64url'),
		signature: Buffer.from([5, 6, 7]).toString('base64url'),
		userHandle: null,
	});
	expect(token.extensions).toEqual({});
});
test('legacy U2F assertion retries with AppID and reports the signed extension result', async () => {
	let calls = 0;
	const runner: Fido2Runner = {
		listDevices: async () => ['/dev/mock-key'],
		assert: async (_device, input, u2f) => {
			calls++;
			if (!u2f) throw new Error('no FIDO2 credential');
			const [hash, appId] = input.split('\n');
			return [hash!, appId!, Buffer.alloc(37, 1).toString('base64'), Buffer.from([3, 4]).toString('base64')];
		},
	};
	const result = JSON.parse(await createWebAuthnToken(options, 'https://vault.example.test', runner)) as {
		extensions: Record<string, boolean>;
	};
	expect(calls).toBe(2);
	expect(result.extensions).toEqual({ appid: true });
});
test('required WebAuthn user verification is delegated to the system helper', async () => {
	await expect(createWebAuthnToken(
		{ ...options, userVerification: 'required' },
		'https://vault.example.test',
		successfulRunner(false, true),
	)).resolves.toContain('"type":"public-key"');
});
test('WebAuthn rejects a mismatched origin, RP ID and challenge before invoking a hardware helper', async () => {
	const runner: Fido2Runner = {
		listDevices: async () => {
			throw new Error('must not enumerate');
		},
		assert: async () => {
			throw new Error('must not assert');
		},
	};
	await expect(createWebAuthnToken(options, 'https://attacker.example', runner)).rejects.toThrow('origin');
	await expect(createWebAuthnToken({ ...options, rpId: 'attacker.example' }, 'https://vault.example.test', runner))
		.rejects.toThrow('origin');
	await expect(createWebAuthnToken({ ...options, challenge: 'not valid' }, 'https://vault.example.test', runner))
		.rejects.toThrow('challenge');
});
test('WebAuthn hashes the exact client data bytes passed to libfido2', async () => {
	let assertionInput = '';
	const runner: Fido2Runner = {
		listDevices: async () => ['/dev/mock-key'],
		assert: async (_device, input) => {
			assertionInput = input;
			const [hash, rpId] = input.split('\n');
			return [hash!, rpId!, Buffer.alloc(37, 1).toString('base64'), Buffer.from([2]).toString('base64')];
		},
	};
	const token = JSON.parse(await createWebAuthnToken(options, 'https://vault.example.test', runner)) as {
		response: { clientDataJSON: string };
	};
	const clientData = Buffer.from(token.response.clientDataJSON, 'base64url');
	expect(assertionInput.split('\n')[0]).toBe(createHash('sha256').update(clientData).digest('base64'));
});
