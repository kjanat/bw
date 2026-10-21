import { expect, test } from 'bun:test';
import { parseSafeInCloudXml } from '#safeincloud-xml';
import type { JsonObject } from '#client';

const items = (value: JsonObject) => value.items as JsonObject[];
const source = `\uFEFF <?xml version="1.0"?>
<database><card title="Bank" star="true"><field name="Username" type="login">alice</field>
<field name="Password" type="password">  secret  </field><field name="Website" type="website">bank.example.test</field>
<field name="OTP" type="one_time_password">SAFEIN_TEST_SEED</field><field name="Comment" type="notes">login note</field>
<field name="Recovery" type="text">recovery code</field><notes>extra note</notes></card>
<card title="Card" type="credit"><field name="Cardholder" autofill="cc-name">Alice Example</field>
<field name="Number" autofill="cc-number">4111111111111111</field><field name="Expiration" autofill="cc-exp">06/2030</field>
<field name="CVC" autofill="cc-csc">123</field><field name="PIN" type="pin">1234</field></card>
<card title="Secure note" type="note"><notes>private note</notes></card>
<card title="Deleted" deleted="true"><field name="Password" type="password">discard</field></card>
<card title="Template" template="true"/></database>`;

test('SafeInCloud XML maps login, card, notes, and excludes deleted/template cards', () => {
	const result = items(parseSafeInCloudXml(source));
	expect(result).toHaveLength(3);
	expect(result[0]).toMatchObject({
		type: 1,
		name: 'Bank',
		favorite: true,
		notes: 'login note\nextra note',
		login: {
			username: 'alice',
			password: '  secret  ',
			totp: 'SAFEIN_TEST_SEED',
			uris: [{ uri: 'http://bank.example.test' }],
		},
		fields: [{ name: 'Recovery', value: 'recovery code', type: 0 }],
	});
	expect(result[1]).toMatchObject({
		type: 3,
		card: {
			brand: 'Visa',
			number: '4111111111111111',
			cardholderName: 'Alice Example',
			expMonth: '6',
			expYear: '2030',
			code: '123',
		},
		fields: [{ name: 'PIN', value: '1234', type: 1 }],
	});
	expect(result[2]).toMatchObject({ type: 2, name: 'Secure note', secureNote: { type: 0 }, notes: 'private note' });
});

test('SafeInCloud XML rejects malformed, missing-database, and entity-bearing documents', () => {
	expect(() => parseSafeInCloudXml('<database')).toThrow('Invalid SafeInCloud XML.');
	expect(() => parseSafeInCloudXml('<root/>')).toThrow('Missing database node.');
	expect(() => parseSafeInCloudXml('<!DOCTYPE x [<!ENTITY secret "private">]><database/>'))
		.toThrow('XML entity declarations are not supported.');
});
