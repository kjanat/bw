import { expect, test } from 'bun:test';
import { mkdtemp, readFile, rm, stat, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openSession, sealSession, withStore, type State } from '#store';

test('session wrapping requires the token, and lock invalidates old tokens', () => {
	const state = { version: 1, deviceId: 'device', account: {} } as State;
	const key = Buffer.alloc(64, 7);
	const token = sealSession(state, key);
	expect(openSession(state, token)).toEqual(key);
	expect(() => openSession(state, Buffer.alloc(32, 8).toString('base64'))).toThrow('Invalid session');
	delete state.session;
	expect(() => openSession(state, token)).toThrow('locked');
});
test('state writes are private and atomic, concurrent commands fail safely', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-store-'));
	try {
		await withStore(dir, async (state, save) => {
			state.server = 'https://example.com';
			await save();
			await expect(withStore(dir, async () => {})).rejects.toThrow(
				'Another vw command',
			);
		});
		expect((await stat(dir)).mode & 0o777).toBe(0o700);
		expect((await stat(join(dir, 'state.json'))).mode & 0o777).toBe(0o600);
		expect(
			JSON.parse(await readFile(join(dir, 'state.json'), 'utf8')).server,
		).toBe('https://example.com');
		await withStore(dir, async (state) => {
			expect(state.server).toBe('https://example.com');
		});
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});
test('state directories cannot be symlinks', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-symlink-'));
	try {
		await symlink(dir, join(dir, 'link'));
		await expect(withStore(join(dir, 'link'), async () => {})).rejects.toThrow(
			'owned directory',
		);
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});
