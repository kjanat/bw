import { createPrivateKey } from 'node:crypto';
import { derivePublicKey, importPkcs8PemOrThrow } from 'micro509/keys';
import { exportOpenSshPrivateKey, exportSshPublicKey, sshFingerprintSha256 } from 'micro509/ssh';
import type { JsonObject } from '#client';

export class SshImportError extends Error {
	constructor(readonly reason: 'unsupportedType' | 'sshKeyParseFailed') {
		super('Could not import SSH key.');
	}
}
/** Convert unencrypted PKCS#8 keys from 1PUX metadata into OpenSSH vault fields. */
export async function importSshPkcs8(pem: string): Promise<JsonObject> {
	if (!pem.includes('-----BEGIN PRIVATE KEY-----')) throw new SshImportError('sshKeyParseFailed');
	try {
		// Keep the reference importer's unsupported-algorithm classification before WebCrypto import.
		const source = createPrivateKey(pem);
		if (
			!['rsa', 'ed25519', 'ec'].includes(source.asymmetricKeyType ?? '')
			|| source.asymmetricKeyType === 'ec'
				&& !['prime256v1', 'secp384r1', 'secp521r1'].includes(source.asymmetricKeyDetails?.namedCurve ?? '')
		) throw new SshImportError('unsupportedType');
		const privateKey = await importPkcs8PemOrThrow(pem);
		const publicKey = await derivePublicKey(privateKey);
		return {
			privateKey: await exportOpenSshPrivateKey(privateKey),
			publicKey: await exportSshPublicKey(publicKey),
			keyFingerprint: await sshFingerprintSha256(publicKey),
		};
	} catch (error) {
		throw error instanceof SshImportError ? error : new SshImportError('sshKeyParseFailed');
	}
}
