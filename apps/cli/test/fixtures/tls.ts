import { createSelfSignedCertificate } from 'micro509/x509';
import { writeFile } from 'node:fs/promises';

/** Ephemeral loopback certificate trusted by the independent Node CLI. */
export async function writeTestCertificate(certificatePath: string, keyPath: string): Promise<void> {
	const { certificate, keyPair } = await createSelfSignedCertificate({
		subject: { commonName: 'localhost' },
		algorithm: { kind: 'rsa', modulusLength: 2048, hash: 'SHA-256' },
		validity: { days: 1 },
		extensions: {
			basicConstraints: { ca: true },
			subjectAltNames: [{ type: 'ip', value: '127.0.0.1' }, { type: 'dns', value: 'localhost' }],
		},
	});
	await writeFile(keyPath, await keyPair.exportPkcs8Pem(), { mode: 0o600 });
	await writeFile(certificatePath, certificate.pem, { mode: 0o600 });
}
