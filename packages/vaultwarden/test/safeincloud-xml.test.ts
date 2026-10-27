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
		notes: 'login note\nextra note\n',
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
	expect(result[2]).toMatchObject({ type: 2, name: 'Secure note', secureNote: { type: 0 }, notes: 'private note\n' });
});

test('SafeInCloud XML rejects malformed, missing-database, and entity-bearing documents', () => {
	expect(() => parseSafeInCloudXml('<database')).toThrow('Invalid SafeInCloud XML.');
	expect(() => parseSafeInCloudXml('<root/>')).toThrow('Missing database node.');
	expect(() => parseSafeInCloudXml('<!DOCTYPE x [<!ENTITY secret "private">]><database/>'))
		.toThrow('XML entity declarations are not supported.');
});

test('SafeInCloud XML imports exact note text and appends the reference newline', () => {
	const result = items(
		parseSafeInCloudXml('<database><card title="Trailing"><notes>note&#10;</notes></card></database>'),
	);
	expect(result[0]?.notes).toBe('note\n\n');
});

test('SafeInCloud XML maps card brands using the full reference patterns', () => {
	const cards = items(parseSafeInCloudXml(
		'<database><card title="Amex"><field name="Number" autofill="cc-number">378282246310005</field></card>'
			+ '<card title="Discover"><field name="Number" autofill="cc-number">6011111111111117</field></card>'
			+ '<card title="Formatted"><field name="Number" autofill="cc-number">4111 1111 1111 1111</field></card></database>',
	));
	expect(cards.map(card => (card.card as JsonObject).brand)).toEqual(['Amex', 'Discover', 'Visa']);
});

test('SafeInCloud XML selects the first hidden field with any pinned password alias', () => {
	const result = items(parseSafeInCloudXml(
		'<database><card title="Aliases">'
			+ '<field name="Other" type="secret">first hidden value</field>'
			+ '<field name="Pass Phrase" type="password">matching alias</field>'
			+ '</card></database>',
	));
	expect(result[0]?.login).toMatchObject({ password: 'matching alias' });
	expect(result[0]?.fields).toEqual([{ name: 'Other', value: 'first hidden value', type: 1 }]);
});

test('SafeInCloud XML maps the fallback hidden field to the password', () => {
	const result = items(parseSafeInCloudXml(
		'<database><card title="Fallback"><field name="Secret value" type="secret">first hidden value</field></card></database>',
	));
	expect(result[0]?.login).toMatchObject({ password: 'first hidden value' });
	expect(result[0]?.fields).toEqual([{ name: 'Secret value', value: 'first hidden value', type: 1 }]);
});

test('SafeInCloud XML prefixes multiline fields with the reference blank-name label', () => {
	const value = 'x'.repeat(201);
	const result = items(parseSafeInCloudXml(
		`<database><card title="Long"><field name="">${value}</field></card></database>`,
	));
	expect(result[0]?.notes).toBe(`: ${value}\n`);
});

test('SafeInCloud XML trims, prefixes, and truncates website URIs in reference order', () => {
	const domain = `${'a'.repeat(995)}.com`;
	const result = items(parseSafeInCloudXml(
		`<database><card title="Long URI"><field name="Website" type="website">  ${domain}  </field></card></database>`,
	));
	const uri = ((result[0]?.login as JsonObject).uris as JsonObject[])[0]?.uri;
	expect(uri).toBe(`http://${domain}`.slice(0, 1000));
	expect(String(uri)).toHaveLength(1000);
});

test('SafeInCloud XML imports cards under every database node like the reference selector', () => {
	const result = items(parseSafeInCloudXml(
		'<root><database><card title="First"/></database><database><card title="Second"/></database></root>',
	));
	expect(result.map(item => item.name)).toEqual(['First', 'Second']);
});
