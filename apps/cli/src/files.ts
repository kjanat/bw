import { stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

/** Server-supplied filenames are used only as a single path component. */
export async function writeAttachment(
	output: string | undefined,
	fileName: string,
	contents: Uint8Array,
): Promise<string> {
	const name = fileName.split(/[\\/]/).at(-1);
	if (!name || name === '.' || name === '..' || name.includes('\0')) {
		throw new Error('Attachment filename is invalid. Specify a file with --output.');
	}
	let path = output ?? name;
	if (output) {
		try {
			if ((await stat(output)).isDirectory()) path = join(output, name);
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
		}
	}
	await writeFile(path, contents, { mode: 0o600, flag: 'wx' });
	return path;
}
