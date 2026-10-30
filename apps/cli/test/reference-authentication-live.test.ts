import { beforeAll, expect, test } from 'bun:test';
import { checkReferenceAuthentication, type AuthenticationOutcome } from '#test/reference-authentication';

const server = process.env.VW_TEST_SERVER;
const reference = process.env.VW_TEST_BW;
const directory = process.env.VW_TEST_REFERENCE_DIRECTORY;
const expected = process.env.VW_TEST_REFERENCE_FAILURE;
const enabled = Boolean(server && reference && directory);
let outcomes: AuthenticationOutcome[] = [];

beforeAll(async () => {
	if (!enabled) return;
	// Setup failures must never be inverted into expected login failures.
	outcomes = await checkReferenceAuthentication({
		server: server!,
		reference: reference!,
		directory: directory!,
		signal: AbortSignal.timeout(240000),
	});
}, 250000);

const kdfs = [{ index: 0, kdf: 'PBKDF2' }, { index: 1, kdf: 'Argon2id' }];
test.skipIf(!enabled).each(kdfs)('reference $kdf: no unexpected authentication failure', ({ index }) => {
	expect<string | undefined>(outcomes[index]).toBeOneOf(['authenticated', ...(expected ? [expected] : [])]);
});
test.skipIf(!enabled).failingIf(Boolean(expected)).each(kdfs)(
	`reference $kdf: login and unlock${expected ? ` (expected failure: ${expected})` : ''}`,
	({ index }) => {
		expect(outcomes[index]).toBe('authenticated');
	},
);
