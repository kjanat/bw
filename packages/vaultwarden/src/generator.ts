import { randomInt } from 'node:crypto';
import { passphraseWords } from '#wordlist';
import { object, type JsonObject } from '#client';

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
function count(value: number, min: number, max: number, name: string): number {
	if (!Number.isSafeInteger(value) || value < min || value > max) throw new Error(`Invalid ${name}.`);
	return value;
}
/** Applies cached organization policies without requiring a decrypted vault. */
export function enforceGeneratorPolicies(input: GeneratorOptions, policies: JsonObject[] = []): GeneratorOptions {
	const options = { ...input };
	let forced: string | undefined;
	for (const policy of policies) {
		if (policy.type !== 2 || policy.enabled === false) continue;
		const data = object(policy.data ?? {});
		const override = data.overridePasswordType;
		if (override === 'password' || override === 'passphrase') {
			if (forced && forced !== override) throw new Error('Conflicting password generator policies.');
			forced = override;
			options.passphrase = override === 'passphrase';
		}
		for (
			const [field, target] of [['minLength', 'length'], ['minNumberWords', 'words'], ['numberCount', 'minNumber'], [
				'specialCount',
				'minSpecial',
			]] as const
		) {
			const value = data[field];
			if (typeof value === 'number' && Number.isSafeInteger(value) && value > 0) {
				{
					options[target] = Math.max(options[target] ?? (target === 'length' ? 14 : target === 'words' ? 6 : 0), value);
					if (target === 'minNumber') options.number = true;
					if (target === 'minSpecial') options.special = true;
				}
			}
		}
		for (
			const [field, target] of [
				['useUppercase', 'uppercase'],
				['useLowercase', 'lowercase'],
				['useNumbers', 'number'],
				['useSpecial', 'special'],
				['capitalize', 'capitalize'],
				['includeNumber', 'includeNumber'],
			] as const
		) if (data[field] === true) options[target] = true;
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
	const length = count(Math.max(5, options.length ?? 14), 5, 4096, 'password length');
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
			count(options.minNumber ?? 1, 0, 4096, 'minimum number count'),
		]);
	}
	if (options.special) groups.push(['!@#$%^&*', count(options.minSpecial ?? 1, 0, 4096, 'minimum special count')]);
	if (groups.reduce((n, [, minimum]) => n + minimum, 0) > length) {
		throw new Error('Password length is shorter than the required character counts.');
	}
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
	const countWords = count(Math.max(3, options.words ?? 6), 3, 128, 'word count');
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
