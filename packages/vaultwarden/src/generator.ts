import { randomInt } from 'node:crypto';
import { passphraseWords } from '#wordlist';
import { object, type JsonObject } from '#client';
import { applicableOrganizationPolicies } from '#policy';

export interface GeneratorOptions {
	passphrase?: boolean;
	uppercase?: boolean;
	lowercase?: boolean;
	number?: boolean;
	special?: boolean;
	length?: number;
	words?: number;
	minNumber?: number;
	minSpecial?: number;
	separator?: string;
	capitalize?: boolean;
	includeNumber?: boolean;
	avoidAmbiguous?: boolean;
}
/** Match bw's CLI/query parsing: parseInt prefixes and fall back when no number is present. */
export function parseGeneratorNumber(value: unknown, fallback: number): number {
	if (value == null) return fallback;
	try {
		const parsed = Number.parseInt(String(value));
		return Number.isNaN(parsed) ? fallback : parsed;
	} catch {
		return fallback;
	}
}
function count(value: number, min: number, name: string): number {
	if (!Number.isSafeInteger(value) || value < min) throw new Error(`Invalid ${name}.`);
	return value;
}
/** Applies cached organization policies without requiring a decrypted vault. */
export function enforceGeneratorPolicies(input: GeneratorOptions, policies: JsonObject[] = []): GeneratorOptions {
	const options = { ...input };
	for (const policy of policies) {
		if (policy.type !== 2 || policy.enabled !== true) continue;
		const data = object(policy.data ?? {});
		if (options.passphrase) {
			if (data.capitalize === true) options.capitalize = true;
			if (data.includeNumber === true) options.includeNumber = true;
			if (typeof data.minNumberWords === 'number' && Number.isSafeInteger(data.minNumberWords)) {
				options.words = Math.max(options.words ?? 6, data.minNumberWords);
			}
			continue;
		}
		if (typeof data.minLength === 'number' && Number.isSafeInteger(data.minLength)) {
			options.length = Math.max(options.length ?? 14, data.minLength);
		}
		if (data.useUpper === true) options.uppercase = true;
		if (data.useLower === true) options.lowercase = true;
		if (data.useNumbers === true) options.number = true;
		if (data.useSpecial === true) options.special = true;
		if (typeof data.minNumbers === 'number' && Number.isSafeInteger(data.minNumbers) && data.minNumbers > 0) {
			options.minNumber = Math.max(options.minNumber ?? 0, data.minNumbers);
			options.number = true;
		}
		if (typeof data.minSpecial === 'number' && Number.isSafeInteger(data.minSpecial) && data.minSpecial > 0) {
			options.minSpecial = Math.max(options.minSpecial ?? 0, data.minSpecial);
			options.special = true;
		}
	}
	return options;
}
/** All selections and the shuffle use Node's rejection-sampled CSPRNG. */
export function generatePassword(input: GeneratorOptions = {}): string {
	const options = { ...input };
	if (!options.uppercase && !options.lowercase && !options.number && !options.special) {
		options.uppercase = true;
		options.lowercase = true;
		options.number = true;
	}
	const requestedLength = count(Math.max(5, options.length ?? 14), 5, 'password length');
	const groups: [string, number][] = [];
	if (options.uppercase) {
		groups.push([options.avoidAmbiguous ? 'ABCDEFGHJKLMNPQRSTUVWXYZ' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 1]);
	}
	if (options.lowercase) {
		groups.push([options.avoidAmbiguous ? 'abcdefghijkmnopqrstuvwxyz' : 'abcdefghijklmnopqrstuvwxyz', 1]);
	}
	if (options.number) {
		groups.push([
			options.avoidAmbiguous ? '23456789' : '0123456789',
			count(options.minNumber ?? 1, 0, 'minimum number count'),
		]);
	}
	if (options.special) groups.push(['!@#$%^&*', count(options.minSpecial ?? 0, 0, 'minimum special count')]);
	const length = Math.max(requestedLength, groups.reduce((n, [, minimum]) => n + minimum, 0));
	const alphabet = groups.map(([characters]) => characters).join('');
	const result: string[] = [];
	for (const [characters, minimum] of groups) {
		for (let i = 0; i < minimum; i++) result.push(characters[randomInt(characters.length)]!);
	}
	while (result.length < length) result.push(alphabet[randomInt(alphabet.length)]!);
	for (let i = result.length - 1; i > 0; i--) {
		const j = randomInt(i + 1);
		[result[i], result[j]] = [result[j]!, result[i]!];
	}
	return result.join('');
}
export function generatePassphrase(options: GeneratorOptions = {}): string {
	const countWords = count(Math.max(3, options.words ?? 6), 3, 'word count');
	let separator = options.separator ?? '-';
	separator = separator === 'space' ? ' ' : separator === 'empty' ? '' : separator.slice(0, 1);
	const words = Array.from({ length: countWords }, () => {
		const word = passphraseWords[randomInt(passphraseWords.length)]!;
		return options.capitalize ? word[0]!.toUpperCase() + word.slice(1) : word;
	});
	if (options.includeNumber) {
		const index = randomInt(words.length);
		words[index] += String(randomInt(10));
	}
	return words.join(separator);
}
export function generateSecret(input: GeneratorOptions = {}, policies: JsonObject[] = []): string {
	const defaults = { ...input };
	if (!defaults.uppercase && !defaults.lowercase && !defaults.number && !defaults.special) {
		defaults.uppercase = true;
		defaults.lowercase = true;
		defaults.number = true;
	}
	const options = enforceGeneratorPolicies(defaults, policies);
	return options.passphrase ? generatePassphrase(options) : generatePassword(options);
}

/** Use the same synced policy sources and membership exemptions for every frontend. */
export function generateVaultSecret(input: GeneratorOptions, snapshot?: JsonObject): string {
	const policies = snapshot
		? applicableOrganizationPolicies(snapshot, 2).map(({ policy }) => policy)
		: [];
	return generateSecret(input, policies);
}
