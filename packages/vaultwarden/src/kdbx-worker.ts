import { parentPort, workerData } from 'node:worker_threads';
import { DOMParser, XMLSerializer } from '@xmldom/xmldom';
import { Kdbx, Credentials, ProtectedValue, KdbxHeader, KdbxContext, BinaryStream, Int64 } from 'kdbxweb';
import { configureKdbxCrypto, KdbxImportError, mapKdbx } from '#kdbx-codec';

// kdbxweb accepts host DOM implementations. Use the current parser only in this worker.
class StrictParser extends DOMParser {
	constructor() {
		super({
			onError: () => {
				throw new Error('Malformed KDBX XML.');
			},
		});
	}
	override parseFromString(source: string, mimeType: Parameters<DOMParser['parseFromString']>[1]) {
		if (/<!DOCTYPE|<!ENTITY/i.test(source)) throw new Error('KDBX XML declarations are unsupported.');
		return super.parseFromString(source, mimeType);
	}
}
const host = globalThis as unknown as { DOMParser: typeof DOMParser; XMLSerializer: typeof XMLSerializer };
host.DOMParser = StrictParser;
host.XMLSerializer = XMLSerializer;
configureKdbxCrypto();
const data = workerData as {
	bytes: Uint8Array<ArrayBuffer>;
	keyFile?: Uint8Array<ArrayBuffer>;
	password?: string;
	organization: boolean;
};
try {
	const password = data.password === undefined ? null : ProtectedValue.fromString(data.password);
	const credentials = new Credentials(password, data.keyFile?.buffer);
	await credentials.ready;
	const context = new KdbxContext({ kdbx: Kdbx.create(credentials, 'preflight') });
	const header = KdbxHeader.read(new BinaryStream(data.bytes.buffer), context);
	const rounds = header.versionMajor === 3 ? header.keyEncryptionRounds : header.kdfParameters?.get('R');
	if (rounds !== undefined) {
		const value = rounds instanceof Int64 ? rounds.value : rounds;
		if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1 || value > 100_000_000) {
			throw new KdbxImportError('Unsupported KDBX AES work factor.');
		}
	}
	const database = await Kdbx.load(data.bytes.buffer, credentials);
	parentPort!.postMessage({ document: mapKdbx(database, data.organization) });
} catch (error) {
	const code = error && typeof error === 'object' && 'code' in error ? error.code : undefined;
	parentPort!.postMessage({
		error: error instanceof KdbxImportError
			? error.message
			: code === 'InvalidKey'
			? 'KDBX password or key file is incorrect.'
			: 'KDBX database is corrupt or unsupported.',
	});
} finally {
	data.bytes.fill(0);
	data.keyFile?.fill(0);
}
