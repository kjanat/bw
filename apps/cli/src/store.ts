import { chmod, lstat, mkdir, mkdtemp, open, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir, hostname } from 'node:os';
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

function lockOwnerUnknown(): Error {
	return new Error('State lock has no verifiable owner. Confirm no vw command is running before removing .lock.');
}

/** Claim the exact dead owner's token before atomically detaching its lock. */
async function recoverStoreLock(lock: string): Promise<void> {
	try {
		const info = await lstat(lock);
		if (!info.isDirectory() || info.isSymbolicLink() || (process.getuid && info.uid !== process.getuid())) {
			throw lockOwnerUnknown();
		}
		const entries = await readdir(lock);
		const token = entries.length === 1 && /^(owner|recovery)-(\d+)-[0-9a-f-]{36}\.json$/.exec(entries[0]!);
		if (!token) throw lockOwnerUnknown();
		const ownerPid = Number(token[2]);
		const path = join(lock, entries[0]!);
		const ownerInfo = await lstat(path);
		if (!ownerInfo.isFile() || ownerInfo.isSymbolicLink() || (process.getuid && ownerInfo.uid !== process.getuid())) {
			throw lockOwnerUnknown();
		}
		let owner: { pid?: unknown; host?: unknown };
		try {
			owner = JSON.parse(await readFile(path, 'utf8'));
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === 'ENOENT') return;
			throw lockOwnerUnknown();
		}
		if (
			!owner || typeof owner.pid !== 'number' || !Number.isSafeInteger(owner.pid) || owner.pid <= 0
			|| owner.host !== hostname() || !Number.isSafeInteger(ownerPid) || ownerPid <= 0
			|| token[1] === 'owner' && owner.pid !== ownerPid
		) throw lockOwnerUnknown();
		try {
			process.kill(ownerPid, 0);
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== 'ESRCH') throw new Error('Another vw command is running.');
			// Only one reclaimer can rename this unique token. Other reclaimers see
			// our live PID, or can reclaim our recovery token if we are interrupted.
			await rename(path, join(lock, `recovery-${process.pid}-${randomUUID()}.json`));
			const retired = `${lock}-${randomUUID()}.retired`;
			await rename(lock, retired);
			await rm(retired, { recursive: true, force: true });
			return;
		}
		throw new Error('Another vw command is running.');
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
	}
}

async function acquireStoreLock(directory: string): Promise<() => Promise<void>> {
	const lock = join(directory, '.lock');
	const claim = await mkdtemp(join(directory, '.lock-'));
	const ownerFile = `owner-${process.pid}-${randomUUID()}.json`;
	let acquired = false;
	try {
		await writeFile(join(claim, ownerFile), JSON.stringify({ pid: process.pid, host: hostname() }), {
			flag: 'wx',
			mode: 0o600,
		});
		for (let attempt = 0; attempt < 8; attempt++) {
			await recoverStoreLock(lock);
			try {
				// Publishing a nonempty directory makes the owner visible atomically with the lock.
				await rename(claim, lock);
				acquired = true;
				return async () => {
					// Leave the published lock attached to its owner until the atomic detach completes.
					// Interruption during deletion then leaves only an unused claim directory.
					await rename(lock, claim);
					await rm(claim, { recursive: true, force: true });
				};
			} catch (error) {
				if (!['EEXIST', 'ENOTEMPTY', 'EPERM'].includes((error as NodeJS.ErrnoException).code ?? '')) throw error;
			}
		}
		throw new Error('Another vw command is running.');
	} finally {
		if (!acquired) await rm(claim, { recursive: true, force: true });
	}
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
	const release = await acquireStoreLock(directory);
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
		await release();
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
