import { expect, test } from 'bun:test';
import { createTestAdapter } from '@kjanat/dreamcli/testkit';
import { prompt, PromptCancelledError } from '@kjanat/dreamcli/prompt';
import { createCliPromptSession } from '#prompts';

test('CLI secret prompts use the hidden reader, retry empty entry, and preserve literal whitespace', async () => {
	const answers = ['', '  synthetic-secret  '], rendered: string[] = [];
	let visibleReads = 0;
	const session = createCliPromptSession(createTestAdapter({
		stdin: async () => {
			visibleReads++;
			return 'must not read visibly';
		},
		readSecret: async () => answers.shift() ?? null,
		stderr: value => {
			rendered.push(value);
		},
	}));
	expect(await session.ask(prompt.password({ message: 'Password' }))).toBe('  synthetic-secret  ');
	expect(visibleReads).toBe(0);
	expect(answers).toHaveLength(0);
	expect(rendered.join('')).not.toContain('synthetic-secret');
});
test('CLI prompting fails before visible input when hidden reading is unsupported and propagates cancellation', async () => {
	let reads = 0;
	const unsupported = createCliPromptSession(createTestAdapter({
		stdin: async () => {
			reads++;
			return 'unsafe';
		},
	}));
	await expect(unsupported.ask(prompt.password({ message: 'Password' }))).rejects.toThrow();
	expect(reads).toBe(0);
	const cancelled = createCliPromptSession(createTestAdapter({ readSecret: async () => null }));
	await expect(cancelled.ask(prompt.password({ message: 'Password' }))).rejects.toBeInstanceOf(PromptCancelledError);
});

const terminalTest = process.platform !== 'win32' && Bun.which('python3') ? test : test.skip;
terminalTest(
	'compiled Node prompt host restores terminal modes after answer, interrupt, and sequential questions',
	async () => {
		const child = Bun.spawn([
			'python3',
			new URL('./fixtures/prompt-terminal.py', import.meta.url).pathname,
			new URL('../dist/prompts.js', import.meta.url).href,
		], { stdout: 'pipe', stderr: 'pipe' });
		const [code, stdout, stderr] = await Promise.all([
			child.exited,
			new Response(child.stdout).text(),
			new Response(child.stderr).text(),
		]);
		expect(stderr).toBe('');
		expect(code).toBe(0);
		expect(JSON.parse(stdout)).toEqual({
			answer: true,
			interrupt: true,
			sequential: true,
			challenge: true,
			cli_interrupt: true,
		});
	},
	30000,
);
