import { createHash } from 'node:crypto';

export const cases = [
	...[
		'',
		'password',
		'password11',
		'Weakpass2',
		'GoodPass3!',
		'VeryStrong123@#',
		'asdfjkhkjwer!',
		'bitwarden',
		'𐰊𐰂𐰄𐰀𐰁',
		'08märz2010',
		'r0sebudmaelstrom丂/20/91aaaa',
		'!QASW@#EDFR$%TGHY^&UJKI*(OL',
		'a\0b',
		'x\ud800y',
		'🔑'.repeat(100),
		'🔑'.repeat(100) + 'NeverScored',
		'é'.repeat(101),
		'a'.repeat(100),
		'a'.repeat(100) + 'SECRET',
	].map(password => ({ password, context: [] })),
	{ password: 'asdfjkhkjwer!', context: ['asdfjkhkjwer'] },
	{ password: 'asdfjkhkjwer!', context: ['unrelated'] },
	{ password: 'asdfjkhkjwer!', context: [] },
];
for (const year of [1900, 1999, 2000, 2016, 2025, 2026, 2027, 2030, 2050]) {
	for (const prefix of ['', 'alice', 'Password!', 'pässwörd']) {
		for (const suffix of ['', '!', '-12-31']) {
			cases.push({ password: `${prefix}${year}${suffix}`, context: prefix ? [prefix.toLowerCase()] : [] });
		}
	}
}
for (let i = 0; i < 128; i++) {
	const value = createHash('sha256').update(`synthetic-vw-wasip2-${i}`).digest('base64url').slice(0, 4 + i % 28);
	cases.push({ password: value, context: i % 3 === 0 ? [value.slice(0, 6).toLowerCase()] : [] });
}
