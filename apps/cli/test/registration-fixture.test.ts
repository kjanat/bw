import { expect, test } from 'bun:test';
import { registrationVerificationToken } from '#test/fixtures/registration';

test('registration fixture reads JSON-string and plain-text verification tokens', async () => {
	const token = 'header.payload.signature';
	expect(await registrationVerificationToken(Response.json(token))).toBe(token);
	expect(await registrationVerificationToken(new Response(token))).toBe(token);
});

test('registration fixture rejects malformed verification responses', async () => {
	await expect(registrationVerificationToken(new Response('{"token":true}'))).rejects.toThrow(
		'Invalid registration verification response.',
	);
	await expect(registrationVerificationToken(new Response('not-a-token'))).rejects.toThrow(
		'Invalid registration verification response.',
	);
});
