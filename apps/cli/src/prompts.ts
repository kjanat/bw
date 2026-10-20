import { createPromptSession, createTerminalPrompter, prompt, type PromptSession } from '@kjanat/dreamcli/prompt';
import { createAdapter, type RuntimeAdapter } from '@kjanat/dreamcli/runtime';

/** One reader owns both ordinary and hidden input so sequential questions share buffered state. */
export function createCliPromptSession(adapter: RuntimeAdapter): PromptSession {
	return createPromptSession({
		prompter: createTerminalPrompter(adapter.stdin, adapter.stderr, { readSecret: adapter.readSecret }),
		write: adapter.stderr,
	});
}
let terminalSession: PromptSession | undefined;
export function cliPromptSession(): PromptSession {
	return terminalSession ??= createCliPromptSession(createAdapter());
}
export function secretPrompt(message: string): Promise<string> {
	return cliPromptSession().ask(prompt.password({ message }));
}
