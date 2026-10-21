import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

interface AllowCredential {
	id: string;
	type?: string;
}
export interface VaultwardenWebAuthnOptions {
	challenge: string;
	rpId: string;
	allowCredentials: AllowCredential[];
	userVerification?: string;
	extensions?: { appid?: string };
}
export interface Fido2Runner {
	listDevices(): Promise<string[]>;
	assert(device: string, input: string, u2f: boolean, verifyUser: boolean): Promise<string[]>;
}
function decodeBase64Url(value: string): Buffer {
	if (!/^[\da-zA-Z_-]+={0,2}$/.test(value)) throw new Error('Invalid WebAuthn challenge.');
	const bytes = Buffer.from(value, 'base64url');
	if (!bytes.length || bytes.toString('base64url') !== value.replace(/=+$/, '')) {
		throw new Error('Invalid WebAuthn challenge.');
	}
	return bytes;
}
function command(
	file: string,
	args: string[],
	options: { inheritStdin?: boolean; inheritStderr?: boolean; timeoutMs?: number } = {},
): Promise<{ code: number; stdout: string }> {
	return new Promise((resolve, reject) => {
		let child;
		try {
			child = spawn(file, args, {
				stdio: [options.inheritStdin ? 'inherit' : 'ignore', 'pipe', options.inheritStderr ? 'inherit' : 'ignore'],
				env: process.env.PATH ? { PATH: process.env.PATH } : {},
			});
		} catch {
			reject(new Error('Could not start the system FIDO2 helper.'));
			return;
		}
		const chunks: Buffer[] = [];
		let size = 0, settled = false;
		const finish = (error?: Error, code = 1) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			if (error) reject(error);
			else resolve({ code, stdout: Buffer.concat(chunks, size).toString('utf8') });
		};
		const timer = setTimeout(() => {
			child.kill('SIGTERM');
			finish(new Error('Security-key assertion timed out.'));
		}, options.timeoutMs ?? 120_000);
		child.stdout.on('data', (chunk: Buffer) => {
			size += chunk.length;
			if (size > 64 * 1024) {
				child.kill('SIGTERM');
				finish(new Error('FIDO2 helper returned an oversized assertion.'));
			} else chunks.push(chunk);
		});
		child.once(
			'error',
			() => finish(new Error('Install libfido2 tools (`fido2-token` and `fido2-assert`) to use WebAuthn login.')),
		);
		child.once('close', code => finish(undefined, code ?? 1));
	});
}
const systemFido2: Fido2Runner = {
	async listDevices() {
		const result = await command('fido2-token', ['-L'], { timeoutMs: 10_000 });
		if (result.code !== 0) throw new Error('Could not enumerate FIDO2 security keys.');
		return result.stdout.split(/\r?\n/).flatMap(line => {
			const match = /^(.+?): vendor=0x[\da-f]+, product=0x[\da-f]+/i.exec(line);
			return match ? [match[1]!] : [];
		});
	},
	async assert(device, input, u2f, verifyUser) {
		const directory = await mkdtemp(join(tmpdir(), 'vw-fido2-'));
		const inputPath = join(directory, 'assertion.txt');
		try {
			await writeFile(inputPath, input, { mode: 0o600, flag: 'wx' });
			const result = await command(
				'fido2-assert',
				['-G', '-p', ...(verifyUser ? ['-v'] : []), ...(u2f ? ['-u'] : []), '-i', inputPath, device],
				{ inheritStdin: true, inheritStderr: true },
			);
			if (result.code !== 0) throw new Error('The security key did not produce an assertion for this credential.');
			return result.stdout.trimEnd().split(/\r?\n/);
		} finally {
			await rm(directory, { recursive: true, force: true });
		}
	},
};
function assertionInput(clientDataHash: Buffer, rpId: string, credentialId: Buffer): string {
	if (/[\n\0]/.test(rpId)) throw new Error('Invalid WebAuthn relying party ID.');
	return `${clientDataHash.toString('base64')}\n${rpId}\n${credentialId.toString('base64')}\n`;
}
/** Build the Vaultwarden PasswordOrOtpData JSON token from a real libfido2 assertion. */
export async function createWebAuthnToken(
	options: VaultwardenWebAuthnOptions,
	originValue: string,
	runner: Fido2Runner = systemFido2,
): Promise<string> {
	if (
		typeof options.challenge !== 'string' || typeof options.rpId !== 'string'
		|| !Array.isArray(options.allowCredentials) || !options.allowCredentials.length
	) throw new Error('Vaultwarden returned incomplete WebAuthn request options.');
	const challenge = decodeBase64Url(options.challenge);
	if (
		options.userVerification !== undefined
		&& !['discouraged', 'preferred', 'required'].includes(options.userVerification)
	) throw new Error('Vaultwarden returned an invalid WebAuthn user-verification policy.');
	const verifyUser = options.userVerification === 'required';
	const origin = new URL(originValue);
	const rpId = options.rpId.toLowerCase();
	if (
		origin.origin !== originValue.replace(/\/$/, '')
		|| (origin.protocol !== 'https:'
			&& !(origin.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(origin.hostname)))
		|| (origin.hostname !== rpId && !origin.hostname.toLowerCase().endsWith(`.${rpId}`))
	) throw new Error('Vaultwarden WebAuthn origin does not match its relying party ID.');
	const appId = options.extensions?.appid;
	if (appId !== undefined) {
		const appUrl = new URL(appId);
		if (appUrl.origin !== origin.origin || appUrl.protocol !== origin.protocol) {
			throw new Error('Vaultwarden returned a WebAuthn AppID on a different origin.');
		}
	}
	const credentials = options.allowCredentials.filter(value => value.type === undefined || value.type === 'public-key')
		.map(value => ({ id: decodeBase64Url(value.id), encoded: value.id.replace(/=+$/, '') }));
	if (!credentials.length) throw new Error('Vaultwarden returned no usable WebAuthn credentials.');
	const clientDataJSON = Buffer.from(JSON.stringify({
		type: 'webauthn.get',
		challenge: challenge.toString('base64url'),
		origin: origin.origin,
		crossOrigin: false,
	}));
	const clientDataHash = createHash('sha256').update(clientDataJSON).digest();
	const devices = await runner.listDevices();
	if (!devices.length) throw new Error('No FIDO2 security key is available.');
	for (const device of devices) {
		for (const credential of credentials) {
			let result: string[] | undefined, isU2f = false;
			try {
				result = await runner.assert(device, assertionInput(clientDataHash, rpId, credential.id), false, verifyUser);
			} catch {
				if (!appId || verifyUser) continue;
				try {
					result = await runner.assert(device, assertionInput(clientDataHash, appId, credential.id), true, false);
					isU2f = true;
				} catch {
					continue;
				}
			}
			if (!result || result.length < 4) continue;
			const authData = Buffer.from(result[2]!, 'base64');
			const signature = Buffer.from(result[3]!, 'base64');
			const actualHash = Buffer.from(result[0]!, 'base64');
			if (
				!actualHash.equals(clientDataHash) || result[1] !== (isU2f ? appId : rpId)
				|| authData.length < 37 || !signature.length
			) continue;
			return JSON.stringify({
				id: credential.encoded,
				rawId: credential.encoded,
				type: 'public-key',
				response: {
					authenticatorData: authData.toString('base64url'),
					clientDataJSON: clientDataJSON.toString('base64url'),
					signature: signature.toString('base64url'),
					userHandle: null,
				},
				extensions: isU2f ? { appid: true } : {},
			});
		}
	}
	throw new Error('No available security key has a usable credential for this Vaultwarden account.');
}
