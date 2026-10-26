import type { JsonObject } from '#client';

/** A minimal bulk-import transport: accepted encrypted records appear in the next sync. */
export function withImportSync(
	handler: (url: unknown, init: RequestInit) => Response | Promise<Response>,
): typeof fetch {
	const ciphers: JsonObject[] = [], folders: JsonObject[] = [], collections: JsonObject[] = [];
	let sequence = 0;
	return (async (url: unknown, init: RequestInit) => {
		const location = new URL(String(url));
		if (location.pathname === '/api/sync') {
			return Response.json({ profile: { id: 'account', premium: true }, ciphers, folders, collections });
		}
		const response = await handler(url, init);
		if (
			response.ok && init.method === 'POST'
			&& ['/api/ciphers/import', '/api/ciphers/import-organization'].includes(location.pathname)
		) {
			const data = JSON.parse(String(init.body));
			const batch = sequence++;
			ciphers.push(
				...data.ciphers.map((cipher: JsonObject, index: number) => ({ ...cipher, id: `import-${batch}-${index}` })),
			);
			folders.push(
				...(data.folders ?? []).map((folder: JsonObject, index: number) => ({
					...folder,
					id: `folder-${batch}-${index}`,
				})),
			);
			collections.push(
				...(data.collections ?? []).map((collection: JsonObject, index: number) => ({
					...collection,
					id: collection.id ?? `collection-${batch}-${index}`,
					organizationId: location.searchParams.get('organizationId'),
				})),
			);
		}
		return response;
	}) as typeof fetch;
}
