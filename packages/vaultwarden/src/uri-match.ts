import { domainToUnicode } from 'node:url';
import { Worker } from 'node:worker_threads';
import { parse } from 'tldts';
import { object, type JsonObject } from '#client';
import type { VaultItem } from '#models';

export type UriMatch = 0 | 1 | 2 | 3 | 4 | 5;
export interface UriMatchOptions {
	defaultMatch?: UriMatch;
	equivalentDomains?: readonly (readonly string[])[];
}
function domain(uri: string): string | undefined {
	if (/^(data|about):/.test(uri.trim())) return undefined;
	const result = parse(uri.trim(), { validHosts: ['localhost'], allowPrivateDomains: true });
	const value = result.isIp || result.hostname === 'localhost' ? result.hostname : result.domain;
	return value ? domainToUnicode(value).toLowerCase() : undefined;
}
function host(uri: string): string | undefined {
	let source = uri.trim();
	if (!source.includes('://')) {
		if (!source.includes('.')) return undefined;
		source = `http://${source}`;
	}
	try {
		return new URL(source).host || undefined;
	} catch {
		return undefined;
	}
}
/** Run ECMAScript regexes off the main thread; a pathological pattern fails the query instead of hanging it. */
export function matchUriRegex(pattern: string, target: string): Promise<boolean> {
	return new Promise((resolve, reject) => {
		let settled = false;
		let timer: ReturnType<typeof setTimeout>;
		const worker = new Worker(
			`const {parentPort} = require('node:worker_threads'); parentPort.on('message', ({pattern,target}) => {let value=false; try {value=new RegExp(pattern,'i').test(target)} catch {} parentPort.postMessage(value)});`,
			{ eval: true, execArgv: [] },
		);
		const finish = (value?: boolean, error?: Error) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			void worker.terminate().catch(() => {});
			if (error) reject(error);
			else resolve(value!);
		};
		timer = setTimeout(() => finish(undefined, new Error('URI regex worker could not start.')), 5000);
		worker.once('online', () => {
			clearTimeout(timer);
			timer = setTimeout(
				() => finish(undefined, new Error('URI regular expression exceeded its execution limit.')),
				200,
			);
			worker.postMessage({ pattern, target });
		});
		worker.once('message', value => finish(value === true));
		worker.once('error', () => finish(undefined, new Error('URI regex evaluation failed.')));
		worker.once('exit', () => {
			if (!settled) finish(undefined, new Error('URI regex worker stopped unexpectedly.'));
		});
	});
}
export async function matchesUri(saved: JsonObject, target: string, options: UriMatchOptions = {}): Promise<boolean> {
	if (typeof saved.uri !== 'string' || !saved.uri || !target) return false;
	const strategy = saved.match ?? options.defaultMatch ?? 0;
	if (strategy === 1) {
		const targetHost = host(target);
		return !!targetHost && targetHost === host(saved.uri);
	}
	if (strategy === 2) return target.startsWith(saved.uri);
	if (strategy === 3) return target === saved.uri;
	if (strategy === 4) return matchUriRegex(saved.uri, target);
	if (strategy !== 0) return false;
	const targetDomain = domain(target), savedDomain = domain(saved.uri);
	if (!targetDomain || !savedDomain) return false;
	const equivalents = new Set([targetDomain]);
	for (const group of options.equivalentDomains ?? []) {
		const normalized = group.map(value => domainToUnicode(value).toLowerCase());
		if (normalized.includes(targetDomain)) { for (const value of normalized) equivalents.add(value); }
	}
	if (!equivalents.has(savedDomain)) return false;
	return !(savedDomain === 'google.com' && host(target) === 'script.google.com');
}
export async function filterItemsByUrl(
	items: readonly VaultItem[],
	target: string,
	options: UriMatchOptions = {},
): Promise<VaultItem[]> {
	const output: VaultItem[] = [];
	for (const item of items) {
		if (item.type !== 1 || item.deletedDate || item.archivedDate || !Array.isArray(item.login?.uris)) continue;
		for (const uri of item.login.uris) {
			if (await matchesUri(object(uri), target, options)) {
				output.push(item);
				break;
			}
		}
	}
	return output;
}
