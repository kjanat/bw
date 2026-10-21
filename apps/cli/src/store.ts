import { chmod, lstat, mkdir, open, readFile, rename, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from 'node:crypto';
import type { Account, JsonObject, ServiceUrls } from '@kjanat/vaultwarden';

export interface State {
	version: 1;
	server?: string;
	services?: ServiceUrls;
	deviceId: string;
	account?: Account;
	vault?: JsonObject;
	lastSync?: string;
	session?: { iv: string; ciphertext: string; tag: string };
}
export function dataDirectory(): string {
	return (
		process.env.VW_APPDATA_DIR
			?? join(
				process.env.XDG_CONFIG_HOME ?? join(homedir(), '.config'),
				'vaultwarden-cli',
			)
	);
}
/** An exclusive command lock prevents refresh rotation and logout/save races. */
export async function withStore<T>(
	directory: string,
	action: (state: State, save: () => Promise<void>) => Promise<T>,
): Promise<T> {
	await mkdir(directory, { recursive: true, mode: 0o700 });
	const stat = await lstat(directory);
	if (
		!stat.isDirectory()
		|| stat.isSymbolicLink()
		|| (process.getuid && stat.uid !== process.getuid())
	) {
		throw new Error('State directory must be an owned directory.');
	}
	await chmod(directory, 0o700);
	const lock = join(directory, '.lock');
	try {
		await mkdir(lock, { mode: 0o700 });
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
			throw new Error(
				'Another vw command is running, or a stale lock exists in the state directory.',
			);
		}
		throw error;
	}
	try {
		let state: State = { version: 1, deviceId: randomUUID() };
		const path = join(directory, 'state.json');
		try {
			const stat = await lstat(path);
			if (
				!stat.isFile()
				|| stat.isSymbolicLink()
				|| (process.getuid && stat.uid !== process.getuid())
			) {
				throw new Error('State file must be an owned regular file.');
			}
			await chmod(path, 0o600);
			const data = JSON.parse(await readFile(path, 'utf8')) as State;
			if (data.version !== 1 || typeof data.deviceId !== 'string') {
				throw new Error('Unsupported state format.');
			}
			state = data;
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
				throw new Error(
					'Could not read CLI state. Check its format and permissions.',
				);
			}
		}
		const save = async () => {
			const temporary = join(directory, `.state-${randomUUID()}`);
			try {
				const handle = await open(temporary, 'wx', 0o600);
				try {
					await handle.writeFile(JSON.stringify(state));
					await handle.sync();
				} finally {
					await handle.close();
				}
				await rename(temporary, path);
			} finally {
				await rm(temporary, { force: true });
			}
		};
		return await action(state, save);
	} finally {
		await rm(lock, { recursive: true });
	}
}
export function sealSession(state: State, userKey: Uint8Array): string {
	const session = randomBytes(32);
	const iv = randomBytes(12);
	const cipher = createCipheriv('aes-256-gcm', session, iv);
	const ciphertext = Buffer.concat([cipher.update(userKey), cipher.final()]);
	state.session = {
		iv: iv.toString('base64'),
		ciphertext: ciphertext.toString('base64'),
		tag: cipher.getAuthTag().toString('base64'),
	};
	const token = session.toString('base64');
	session.fill(0);
	return token;
}
export function openSession(state: State, token?: string): Buffer {
	if (!state.account || !state.session || !token) {
		throw new Error(
			'Vault is locked. Run vw unlock --raw and supply VW_SESSION.',
		);
	}
	try {
		if (!/^[A-Za-z0-9+/]{43}=$/.test(token)) throw new Error();
		const session = Buffer.from(token, 'base64');
		try {
			const cipher = createDecipheriv(
				'aes-256-gcm',
				session,
				Buffer.from(state.session.iv, 'base64'),
			);
			cipher.setAuthTag(Buffer.from(state.session.tag, 'base64'));
			const key = Buffer.concat([
				cipher.update(Buffer.from(state.session.ciphertext, 'base64')),
				cipher.final(),
			]);
			if (key.length !== 64) {
				key.fill(0);
				throw new Error();
			}
			return key;
		} finally {
			session.fill(0);
		}
	} catch {
		throw new Error('Invalid session. Run vw unlock --raw again.');
	}
}
