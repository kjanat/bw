import { Worker } from 'node:worker_threads';
import type { JsonObject } from '#client';

export interface KdbxImportOptions {
	password?: string;
	keyFile?: Uint8Array;
	organization?: boolean;
}
/** Decode an encrypted KeePass 3.1/4 database without blocking the caller's event loop. */
export function parseKdbx(input: Uint8Array, options: KdbxImportOptions = {}): Promise<JsonObject> {
	if (input.byteLength > 10 * 1024 * 1024) return Promise.reject(new Error('KDBX files must not exceed 10 MiB.'));
	if (input.length < 4 || input[0] !== 3 || input[1] !== 217 || input[2] !== 162 || input[3] !== 154) {
		return Promise.reject(new Error('Invalid KDBX file signature.'));
	}
	if (options.keyFile && options.keyFile.length > 10 * 1024 * 1024) {
		return Promise.reject(new Error('KDBX key files must not exceed 10 MiB.'));
	}
	const bytes = new Uint8Array(input), keyFile = options.keyFile && new Uint8Array(options.keyFile);
	return new Promise((resolve, reject) => {
		const worker = new Worker(new URL(import.meta.resolve('@kjanat/vaultwarden/kdbx-worker')), {
			workerData: { bytes, keyFile, password: options.password, organization: options.organization ?? false },
			transferList: [bytes.buffer, ...(keyFile ? [keyFile.buffer] : [])],
			execArgv: [],
		});
		let settled = false;
		const finish = (document?: JsonObject, error?: Error) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			void worker.terminate().catch(() => {});
			if (error) reject(error);
			else resolve(document!);
		};
		const timer = setTimeout(() => finish(undefined, new Error('KDBX decoding exceeded its execution limit.')), 60000);
		worker.once(
			'message',
			(result: { document?: JsonObject; error?: string }) =>
				result.document
					? finish(result.document)
					: finish(undefined, new Error(result.error ?? 'KDBX decoding failed.')),
		);
		worker.once('error', () => finish(undefined, new Error('KDBX decoding failed.')));
		worker.once('exit', () => {
			if (!settled) finish(undefined, new Error('KDBX worker stopped unexpectedly.'));
		});
	});
}
