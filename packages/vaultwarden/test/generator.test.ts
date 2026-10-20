import { test, expect } from 'bun:test';
import { generatePassword, generatePassphrase, generateSecret, enforceGeneratorPolicies } from '#generator';
import { passphraseWords } from '#wordlist';

test('generation honors character sets, minima, and ambiguous-character exclusion', () => {
	for (let i = 0; i < 30; i++) {
		const secret = generatePassword({
			length: 24,
			uppercase: true,
			lowercase: true,
			number: true,
			special: true,
			minNumber: 4,
			minSpecial: 3,
			avoidAmbiguous: true,
		});
		expect(secret.length).toBe(24);
		expect(secret).toMatch(/[A-Z]/);
		expect(secret).toMatch(/[a-z]/);
		expect(secret.match(/[0-9]/g)!.length).toBeGreaterThanOrEqual(4);
		expect(secret.match(/[!@#$%^&*]/g)!.length).toBeGreaterThanOrEqual(3);
		expect(secret).not.toMatch(/[IOl01]/);
	}
	expect(generatePassword().length).toBe(14);
	expect(generatePassword({ length: 1 }).length).toBe(5);
	expect(() => generatePassword({ length: 5, number: true, minNumber: 6 })).toThrow('shorter');
	expect(() => generatePassword({ length: Infinity })).toThrow('length');
});
test('passphrases use all 7776 EFF words and honor separator, casing, number, and minimum word count', () => {
	expect(passphraseWords.length).toBe(7776);
	expect(new Set(passphraseWords).size).toBe(7776);
	const phrase = generatePassphrase({ words: 6, separator: 'space', capitalize: true, includeNumber: true });
	const words = phrase.split(' ');
	expect(words.length).toBe(6);
	for (const word of words) {
		expect(word).toMatch(/^[A-Z]/);
		expect(passphraseWords).toContain(word.replace(/[0-9]/g, '').toLowerCase());
	}
	expect(phrase).toMatch(/[0-9]/);
	expect(generatePassphrase({ words: 1 }).split('-').length).toBe(3);
});
test('cached generator policies add requirements without dropping default character classes', () => {
	const policy = { type: 2, enabled: true, data: { minLength: 25, useSpecial: true, specialCount: 3 } };
	const secret = generateSecret({}, [policy]);
	expect(secret.length).toBe(25);
	expect(secret).toMatch(/[A-Z]/);
	expect(secret).toMatch(/[a-z]/);
	expect(secret).toMatch(/[0-9]/);
	expect(secret.match(/[!@#$%^&*]/g)!.length).toBeGreaterThanOrEqual(3);
	const passphrase = generateSecret({}, [{
		type: 2,
		enabled: true,
		data: { overridePasswordType: 'passphrase', minNumberWords: 8 },
	}]);
	expect(passphrase.split('-').length).toBe(8);
	expect(enforceGeneratorPolicies({ length: 20 }, [{ ...policy, enabled: false }]).length).toBe(20);
});
