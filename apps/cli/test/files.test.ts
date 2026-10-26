import { test, expect } from 'bun:test';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { writeAttachment } from '#files';

test('attachment output strips remote path components, stays private, and refuses overwrite', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-file-'));
	try {
		const file = await writeAttachment(dir, '../../private.bin', Buffer.from([0, 255, 17]));
		expect(file).toBe(join(dir, 'private.bin'));
		expect(await readFile(file)).toEqual(Buffer.from([0, 255, 17]));
		expect((await stat(file)).mode & 0o777).toBe(0o600);
		await expect(writeAttachment(dir, 'private.bin', Buffer.from('replacement'))).rejects.toThrow();
		expect(await readFile(file)).toEqual(Buffer.from([0, 255, 17]));
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test('explicit output files override unusable remote filenames without weakening directory checks', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-output-override-'));
	try {
		for (const [index, remote] of ['..', '.', '', 'nested/..', '\0'].entries()) {
			const path = join(dir, `saved-${index}.bin`);
			expect(await writeAttachment(path, remote, Buffer.from('original'))).toBe(path);
			expect((await stat(path)).mode & 0o777).toBe(0o600);
			await expect(writeAttachment(path, remote, Buffer.from('replacement'))).rejects.toThrow();
			expect((await readFile(path)).toString()).toBe('original');
			await expect(writeAttachment(dir, remote, Buffer.from('invalid'))).rejects.toThrow('filename is invalid');
			await expect(writeAttachment(undefined, remote, Buffer.from('invalid'))).rejects.toThrow('filename is invalid');
		}
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});
