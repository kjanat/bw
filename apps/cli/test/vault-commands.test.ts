import { expect, test } from 'bun:test';
import { prepareArchivedItemEdit } from '#vault-commands';

test('archived edits move back automatically without interaction', async () => {
	const data = { archivedDate: '2026-01-01T00:00:00Z' };
	const messages: string[] = [];
	let prompted = false;
	await prepareArchivedItemEdit({ shouldUnarchiveBeforeEdit: async () => true }, 'item', data, {
		noInteraction: true,
		isTTY: true,
		ask: async () => {
			prompted = true;
			return 'cancel';
		},
		write: message => messages.push(message),
	});
	expect(data.archivedDate).toBeNull();
	expect(prompted).toBe(false);
	expect(messages[0]).toContain('moved back to your vault');
});

test('interactive archived edit can be cancelled without changing the submitted item', async () => {
	const data = { archivedDate: '2026-01-01T00:00:00Z' };
	await expect(prepareArchivedItemEdit({ shouldUnarchiveBeforeEdit: async () => true }, 'item', data, {
		noInteraction: false,
		isTTY: true,
		ask: async () => 'cancel',
		write: () => {},
	})).rejects.toThrow('Edit cancelled.');
	expect(data.archivedDate).toBe('2026-01-01T00:00:00Z');
});

test('interactive archived edit clears archive state after confirmation', async () => {
	const data = { archivedDate: '2026-01-01T00:00:00Z' };
	await prepareArchivedItemEdit({ shouldUnarchiveBeforeEdit: async () => true }, 'item', data, {
		noInteraction: false,
		isTTY: true,
		ask: async () => 'confirmed',
		write: () => {},
	});
	expect(data.archivedDate).toBeNull();
});
