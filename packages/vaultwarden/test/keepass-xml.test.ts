import { expect, test } from 'bun:test';
import { parseKeePassXml } from '#keepass-xml';
import { VaultwardenClient, object, type JsonObject } from '#client';
import { VaultService } from '#vault-service';
import { decrypt } from '#crypto';
import { decryptOwnedItem } from '#vault';

const wrap = (entries: string) =>
	`<?xml version="1.0" encoding="utf-8"?><KeePassFile><Root><Group><Name>Ignored root</Name>${entries}</Group></Root></KeePassFile>`;
test('KeePass XML traverses direct entries and nested folders, preserving XML text and protected fields', () => {
	const hidden = 'hidden\n' + 'x'.repeat(220);
	const document = parseKeePassXml(wrap(`
<Entry><String><Key>Title</Key><Value>Root login</Value></String><String><Key>Password</Key><Value>  secret  </Value></String>
<History><Entry><String><Key>Title</Key><Value>Old entry must not import</Value></String></Entry></History></Entry>
<Group><Name>Work &amp; personal</Name><Entry>
<String><Key>Title</Key><Value><![CDATA[Café <login>]]></Value></String>
<String><Key>URL</Key><Value>example.com/a,b</Value></String><String><Key>UserName</Key><Value>alice</Value></String>
<String><Key>otp</Key><Value>key=JBSWY3DPEHPK3PXP</Value></String><String><Key>Notes</Key><Value>first&#10;second</Value></String>
<String><Key>Protected</Key><Value ProtectInMemory="True">${hidden}</Value></String>
<String><Key>Long</Key><Value>${'x'.repeat(201)}</Value></String>
<String><Key>Custom</Key><Value>text:kept</Value></String></Entry>
<Group><Name>Web</Name><Entry><String><Key>Title</Key><Value>Nested login</Value></String></Entry></Group>
</Group>`));
	const items = document.items as JsonObject[], folders = document.folders as JsonObject[];
	expect(items).toHaveLength(3);
	expect(folders.map(folder => folder.name)).toEqual(['Work & personal', 'Work & personal/Web']);
	expect(items[0]).toMatchObject({ name: 'Root login', folderId: null, login: { password: '  secret  ' } });
	expect(items[1]).toMatchObject({
		name: 'Café <login>',
		folderId: folders[0]!.id,
		login: { username: 'alice', totp: 'JBSWY3DPEHPK3PXP', uris: [{ uri: 'http://example.com/a,b' }] },
		fields: [{ name: 'Protected', value: hidden, type: 1 }, { name: 'Custom', value: 'text:kept', type: 0 }],
	});
	expect(items[1]!.notes).toBe(`first\nsecond\nLong: ${'x'.repeat(201)}\n`);
	expect(items[2]!.folderId).toBe(folders[1]!.id);
});
test('KeePass XML converts folder relationships to collections and supports unnamed groups', () => {
	const document = parseKeePassXml(wrap('<Group><Entry/></Group><Group><Name></Name><Entry/></Group>'), true);
	const collections = document.collections as JsonObject[], items = document.items as JsonObject[];
	expect(collections.map(collection => collection.name)).toEqual(['-', '']);
	expect(items[0]).toMatchObject({ name: '--', folderId: null, collectionIds: [collections[0]!.id] });
	expect(items[1]!.collectionIds).toEqual([collections[1]!.id]);
});
test('invalid or externally dependent KeePass XML fails before any mutation and does not echo source text', async () => {
	let calls = 0;
	const client = new VaultwardenClient('https://example.com', {
		fetch: (async () => {
			calls++;
			return Response.json({});
		}) as unknown as typeof fetch,
	});
	const vault = new VaultService(client, 'access', { profile: { id: 'fixture' }, ciphers: [] }, Buffer.alloc(64, 7));
	for (
		const source of [
			'<KeePassFile><Root><Group><Value>synthetic-secret</Group>',
			'<Other/>',
			'<KeePassFile><Root/></KeePassFile>',
			'<!DOCTYPE KeePassFile SYSTEM "file:///etc/passwd">' + wrap(''),
			'<!DOCTYPE KeePassFile [<!ENTITY external SYSTEM "https://example.com/private">]>' + wrap(''),
			wrap('<Entry><String><Key>Title</Key><Value>&undeclared;</Value></String></Entry>'),
		]
	) {
		try {
			await vault.importVault('keepass2xml', source);
			throw new Error('Expected rejection.');
		} catch (error) {
			expect(error).toBeInstanceOf(Error);
			expect(String(error)).not.toContain('synthetic-secret');
			expect(String(error)).not.toBe('Error: Expected rejection.');
		}
	}
	expect(calls).toBe(0);
	vault.dispose();
});
test('KeePass XML imports encrypt hidden fields and preserve empty folder names through bulk remapping', async () => {
	const key = Buffer.alloc(64, 7);
	let calls = 0;
	const client = new VaultwardenClient('https://example.com', {
		fetch: (async (_url: unknown, init?: RequestInit) => {
			calls++;
			const body = JSON.parse(String(init!.body));
			expect(body.folderRelationships).toEqual([{ key: 0, value: 0 }]);
			expect(decrypt(body.folders[0].name, key).toString()).toBe('');
			const cipher = object(body.ciphers[0]);
			expect(decryptOwnedItem(cipher, key)).toMatchObject({
				name: 'Imported',
				fields: [{ name: 'Private', value: 'synthetic-private', type: 1 }],
			});
			expect(String(init!.body)).not.toContain('synthetic-private');
			return new Response(null, { status: 204 });
		}) as typeof fetch,
	});
	const vault = new VaultService(client, 'access', { profile: { id: 'fixture' }, ciphers: [] }, key);
	expect(
		await vault.importVault(
			'keepass2xml',
			wrap(
				'<Group><Name/><Entry><String><Key>Title</Key><Value>Imported</Value></String><String><Key>Private</Key><Value ProtectInMemory="True">synthetic-private</Value></String></Entry></Group>',
			),
		),
	).toEqual({ items: 1, folders: 1, collections: 0, attachments: 0 });
	expect(calls).toBe(1);
	vault.dispose();
});
