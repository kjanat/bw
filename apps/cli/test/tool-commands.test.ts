import { expect, test } from 'bun:test';
import { resolvedExportFormat } from '#tool-commands';
import { reportProgressMessage } from '#report-commands';

test('JSON export with a password selects encrypted JSON like bw', () => {
	expect(resolvedExportFormat('json', true)).toBe('encrypted_json');
	expect(resolvedExportFormat('json', false)).toBe('json');
	expect(resolvedExportFormat('encrypted_json', false)).toBe('encrypted_json');
	expect(resolvedExportFormat('csv', true)).toBe('csv');
});

test('password-health progress text reports the exact riskable login count like bw', () => {
	expect(reportProgressMessage(3, true)).toBe('Checking 3 logins against Have I Been Pwned...');
	expect(reportProgressMessage(0, false)).toBe('Analyzing 0 logins...');
});
