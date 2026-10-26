import { expect, test } from 'bun:test';
import { zipSync } from 'fflate';
import { VaultwardenClient, type JsonObject } from '#client';
import { VaultService } from '#vault-service';
import { importVault, ImportFailure } from '#transfer';

const key = Buffer.alloc(64, 11);
const entries = [{ id: 'old-first', type: 1, name: 'First', login: { password: 'synthetic-first' } }, {
	id: 'old-second',
	type: 1,
	name: 'Second',
	login: { password: 'synthetic-second' },
}];
const profile = { id: 'user', premium: true, organizations: [{ id: 'org', status: 2, type: 0 }] };

test('every imported type requires its data section before any server mutation', async () => {
	let requests = 0;
	const vault = new VaultService(
		new VaultwardenClient('https://example.test', {
			fetch: (async () => {
				requests++;
				throw new Error('No request should be made.');
			}) as unknown as typeof fetch,
		}),
		'access',
		{ profile, ciphers: [] },
		key,
	);
	try {
		for (
			const [index, section] of [
				'login',
				'secureNote',
				'card',
				'identity',
				'sshKey',
				'bankAccount',
				'driversLicense',
				'passport',
			].entries()
		) {
			for (const value of [undefined, null, [], 'invalid']) {
				await expect(
					vault.importVault(
						'bitwardenjson',
						JSON.stringify({
							items: [entries[0], { type: index + 1, name: 'Invalid later record', [section]: value }],
						}),
					),
				)
					.rejects.toThrow(`missing its ${section} data`);
			}
		}
		expect(requests).toBe(0);
	} finally {
		vault.dispose();
	}
});

for (const organizationId of [undefined, 'org']) {
	for (
		const defect of [
			'missing-item',
			'wrong-key',
			'ambiguous-item',
			'duplicate-server-id',
			'missing-group',
			'malformed-record',
			'sync-failure',
			'none',
		]
	) {
		test(`${organizationId ? 'organization' : 'personal'} import verifies saved records: ${defect}`, async () => {
			let submitted: JsonObject | undefined, mutations = 0, syncs = 0;
			const vault = new VaultService(
				new VaultwardenClient('https://example.test', {
					fetch: (async (url: unknown, init: RequestInit) => {
						const path = new URL(String(url)).pathname;
						if (path === '/api/config') return Response.json({ server: { name: 'Vaultwarden' } });
						if (path === '/api/version') {
							return Response.json('1.37.4');
						}
						if (path.startsWith('/api/ciphers/import') && init.method === 'POST') {
							submitted = JSON.parse(String(init.body));
							mutations++;
							return new Response(null, { status: 204 });
						}
						if (path !== '/api/sync' || !submitted) throw new Error('Unexpected request.');
						syncs++;
						if (defect === 'sync-failure') return Response.json({}, { status: 503 });
						if (defect === 'malformed-record') return Response.json({ profile, ciphers: [null] });
						let ciphers: JsonObject[] = (submitted.ciphers as JsonObject[]).map((cipher, index) => ({
							...cipher,
							id: `created-${index}`,
						}));
						if (defect === 'missing-item') ciphers = ciphers.slice(0, 1);
						if (defect === 'wrong-key') ciphers[1]!.key = 'different-encrypted-key';
						if (defect === 'ambiguous-item') ciphers.push({ ...ciphers[1]!, id: 'duplicate' });
						if (defect === 'duplicate-server-id') ciphers[1]!.id = ciphers[0]!.id;
						const kind = organizationId ? 'collections' : 'folders';
						const groups = defect === 'missing-group'
							? []
							: (submitted[kind] as JsonObject[]).map(group => ({
								...group,
								id: 'created-group',
								...(organizationId ? { organizationId } : {}),
							}));
						return Response.json({ profile, ciphers, [kind]: groups });
					}) as typeof fetch,
				}),
				'access',
				{ profile, ciphers: [], collections: [] },
				key,
			);
			try {
				const input = JSON.stringify({
					items: entries,
					[organizationId ? 'collections' : 'folders']: [{ id: 'source-group', name: 'Group' }],
				});
				const operation = importVault(vault, { user: key, organization: () => key }, 'bitwardenjson', input, {
					organizationId,
				});
				if (defect === 'none') {
					expect(await operation).toMatchObject({
						items: 2,
						folders: organizationId ? 0 : 1,
						collections: organizationId ? 1 : 0,
					});
				} else {
					try {
						await operation;
						throw new Error('Unverified import reported success.');
					} catch (error) {
						expect(error).toBeInstanceOf(ImportFailure);
						expect((error as ImportFailure).serverMayHaveChanged).toBe(true);
					}
				}
				expect(mutations).toBe(1);
				expect(syncs).toBe(1);
			} finally {
				vault.dispose();
			}
		});
	}
}

for (const ids of [['duplicate', 'duplicate'], ['CASE-ID', 'case-id']]) {
	test(`ZIP duplicate source IDs are rejected before mutation: ${ids.join(', ')}`, async () => {
		let requests = 0;
		const vault = new VaultService(
			new VaultwardenClient('https://example.test', {
				fetch: (async () => {
					requests++;
					throw new Error('No request should be made.');
				}) as unknown as typeof fetch,
			}),
			'access',
			{ profile, ciphers: [] },
			key,
		);
		try {
			const zip = zipSync({
				'data.json': Buffer.from(
					JSON.stringify({ folders: [], items: entries.map((item, index) => ({ ...item, id: ids[index] })) }),
				),
				'attachments/First/first.txt': Buffer.from('first-file'),
				'attachments/Second/second.txt': Buffer.from('second-file'),
			});
			await expect(vault.importVault('bitwardenzip', zip)).rejects.toThrow('Duplicate ZIP item ID');
			expect(requests).toBe(0);
		} finally {
			vault.dispose();
		}
	});
}
