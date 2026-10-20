import { readFile } from 'node:fs/promises';
import { type ResolvedPromptConfig } from '@kjanat/dreamcli/prompt';
import { cliPromptSession, secretPrompt } from '#prompts';
import type { LoginChallenge, TwoFactorAnswer } from '@kjanat/vaultwarden';

async function terminalPrompt(config: ResolvedPromptConfig): Promise<unknown> {
	return cliPromptSession().ask(config);
}
async function inputPrompt(message: string): Promise<string | undefined> {
	const value = await terminalPrompt({ kind: 'input', message });
	return value === undefined ? undefined : String(value);
}
export async function answerLoginChallenge(
	challenge: LoginChallenge,
	preferred?: number,
	noInteraction = false,
): Promise<TwoFactorAnswer> {
	if (noInteraction || !process.stdin.isTTY) {
		throw new Error('Two-factor authentication is required. Supply --method and --code (or VW_2FA_TOKEN).');
	}
	const names: Record<number, string> = { 0: 'Authenticator (TOTP)', 1: 'Email code', 3: 'YubiKey OTP' };
	const supported = challenge.providers.filter(provider => names[provider]);
	let provider = preferred;
	if (provider === undefined) {
		if (supported.length === 1) provider = supported[0];
		else if (supported.length > 1) {
			const choices = supported.map(value => ({ value: String(value), label: names[value]! }));
			const answer = await terminalPrompt({
				kind: 'select',
				message: 'Two-factor method',
				choices: [choices[0]!, ...choices.slice(1)],
			});
			if (answer === undefined) throw new Error('Two-factor authentication cancelled.');
			provider = Number(answer);
		}
	}
	if (provider === undefined || !supported.includes(provider)) {
		throw new Error('No supported two-factor method selected. Supported methods: TOTP, email, and YubiKey OTP.');
	}
	if (provider === 1) await challenge.requestEmail();
	const token = await secretPrompt('Verification code:');
	if (!token) throw new Error('A verification code is required.');
	return { provider, token };
}

export interface PasswordSource {
	positional?: string;
	envName?: string;
	file?: string;
	noInteraction?: boolean;
}
/** bw precedence: a positional value, then the file's first line, then a named environment variable. */
export async function masterPassword(source: PasswordSource): Promise<string> {
	let value = source.positional;
	if (!value && source.file) value = (await readFile(source.file, 'utf8')).split(/\r?\n/, 1)[0];
	else if (!value && !source.file) value = process.env[source.envName ?? 'VW_PASSWORD'];
	if (value === undefined && !source.noInteraction && process.stdin.isTTY) {
		value = await secretPrompt('Master password:');
	}
	if (!value) {
		throw new Error('A master password is required. Use --passwordenv, --passwordfile, or an interactive terminal.');
	}
	return value;
}
export async function loginEmail(value?: string, noInteraction = false): Promise<string> {
	if (!value && !noInteraction && process.stdin.isTTY) {
		value = await inputPrompt('Email address');
	}
	if (!value?.trim() || !value.includes('@')) throw new Error('A valid email address is required.');
	return value.trim();
}
export async function apiCredentials(
	clientIdEnv = 'VW_CLIENTID',
	clientSecretEnv = 'VW_CLIENTSECRET',
	noInteraction = false,
) {
	let clientId = process.env[clientIdEnv];
	let clientSecret = process.env[clientSecretEnv];
	if (!clientId && !noInteraction && process.stdin.isTTY) {
		clientId = await inputPrompt('client_id');
	}
	if (!clientSecret && !noInteraction && process.stdin.isTTY) {
		clientSecret = await secretPrompt('client_secret:');
	}
	if (!clientId || !clientSecret) {
		throw new Error(
			'API credentials are required. Set VW_CLIENTID and VW_CLIENTSECRET or select named environment variables.',
		);
	}
	return { clientId: clientId.trim(), clientSecret };
}
