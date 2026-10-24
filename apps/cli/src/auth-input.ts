import { readFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { type ResolvedPromptConfig } from '@kjanat/dreamcli/prompt';
import { cliPromptSession, secretPrompt } from '#prompts';
import type { LoginChallenge, TwoFactorAnswer } from '@kjanat/vaultwarden';
import { createWebAuthnToken, type VaultwardenWebAuthnOptions } from '#webauthn';

async function terminalPrompt(config: ResolvedPromptConfig): Promise<unknown> {
	return cliPromptSession().ask(config);
}
async function inputPrompt(message: string): Promise<string | undefined> {
	const value = await terminalPrompt({ kind: 'input', message });
	return value === undefined ? undefined : String(value);
}
function openBrowser(url: string): void {
	const [binary, args] = process.platform === 'win32'
		? ['rundll32', ['url.dll,FileProtocolHandler', url]] as const
		: process.platform === 'darwin'
		? ['open', [url]] as const
		: ['xdg-open', [url]] as const;
	const child = spawn(binary, [...args], { stdio: 'ignore', detached: true });
	child.on('error', () => {/* The URL remains available in the terminal for manual opening. */});
	child.unref();
}
function duoAuthorizationUrl(value: string): URL {
	const url = new URL(value);
	if (
		url.protocol !== 'https:' || url.username || url.password || (url.port && url.port !== '443')
		|| url.pathname !== '/oauth/v1/authorize'
		|| !/^api-[a-zA-Z0-9]+\.(?:duosecurity|duofederal)\.com$/.test(url.hostname)
	) throw new Error('Vaultwarden returned an invalid Duo authorization URL.');
	return url;
}
/** Extract the one-time Duo code/state from the Vaultwarden redirect without accepting another origin. */
export function duoCallbackToken(input: string, authorizationUrl: string): string {
	const authorization = duoAuthorizationUrl(authorizationUrl);
	const request = authorization.searchParams.get('request');
	const encodedClaims = request?.split('.')[1];
	if (!encodedClaims || encodedClaims.length > 16_384) throw new Error('Duo authorization request is invalid.');
	let redirectUri: URL;
	try {
		const claims = JSON.parse(Buffer.from(encodedClaims, 'base64url').toString('utf8')) as { redirect_uri?: unknown };
		if (typeof claims.redirect_uri !== 'string') throw new Error();
		redirectUri = new URL(claims.redirect_uri);
	} catch {
		throw new Error('Duo authorization request is invalid.');
	}
	let callback: URL;
	try {
		callback = new URL(input.trim());
	} catch {
		throw new Error('Paste the complete Vaultwarden Duo callback URL.');
	}
	if (
		callback.origin !== redirectUri.origin || callback.pathname !== redirectUri.pathname
		|| callback.searchParams.get('client') !== redirectUri.searchParams.get('client')
	) throw new Error('Duo callback URL does not match this Vaultwarden login.');
	const code = callback.searchParams.get('code');
	const state = callback.searchParams.get('state');
	if (!code || !state || code.length > 4096 || state.length > 4096) {
		throw new Error('Duo callback URL is missing its authorization code or state.');
	}
	return `${code}|${state}`;
}
const twoFactorProviderNames: Record<number, string> = {
	0: 'Authenticator (TOTP)',
	1: 'Email code',
	2: 'Duo (browser)',
	3: 'YubiKey OTP',
	7: 'Security key (WebAuthn)',
	8: 'Recovery code',
};
export function supportedLoginProviders(challenge: LoginChallenge): number[] {
	return challenge.providers.filter(provider =>
		twoFactorProviderNames[provider]
		&& (provider !== 2 || challenge.duoAuthUrl)
		&& (provider !== 7 || (challenge.webAuthnOptions && challenge.webAuthnOrigin))
	);
}
export async function answerLoginChallenge(
	challenge: LoginChallenge,
	preferred?: number,
	noInteraction = false,
): Promise<TwoFactorAnswer> {
	if (noInteraction || !process.stdin.isTTY) {
		throw new Error('Two-factor authentication is required. Supply --method and --code (or VW_2FA_TOKEN).');
	}
	const supported = supportedLoginProviders(challenge);
	let provider = preferred;
	if (provider === undefined) {
		if (supported.length === 1) provider = supported[0];
		else if (supported.length > 1) {
			const choices = supported.map(value => ({ value: String(value), label: twoFactorProviderNames[value]! }));
			const answer = await terminalPrompt({
				kind: 'select',
				message: 'Two-factor method',
				choices: [choices[0]!, ...choices.slice(1)],
			});
			if (answer === undefined) throw new Error('Two-factor authentication cancelled.');
			provider = Number(answer);
		}
	}
	// Recovery is an explicit choice (--method 8); Vaultwarden does not advertise it in challenges.
	if (provider === undefined || (provider !== 8 && !supported.includes(provider))) {
		throw new Error(
			'No supported two-factor method selected. Supported methods: TOTP, email, Duo, YubiKey OTP, WebAuthn, and recovery code.',
		);
	}
	if (provider === 1) await challenge.requestEmail();
	let token: string;
	if (provider === 2) {
		const authorizationUrl = duoAuthorizationUrl(challenge.duoAuthUrl!);
		process.stderr.write('Complete Duo authentication in your browser, then paste the Vaultwarden callback URL.\n');
		openBrowser(authorizationUrl.href);
		const callback = await secretPrompt('Duo callback URL:');
		if (!callback) throw new Error('A Duo callback URL is required.');
		token = duoCallbackToken(callback, authorizationUrl.href);
	} else if (provider === 7) {
		process.stderr.write(
			'Use your registered FIDO2 security key when prompted. A PIN may be requested by the system helper.\n',
		);
		token = await createWebAuthnToken(
			challenge.webAuthnOptions as unknown as VaultwardenWebAuthnOptions,
			challenge.webAuthnOrigin!,
		);
	} else {
		if (provider === 8) process.stderr.write("Using a recovery code disables the account's two-step login methods.\n");
		token = await secretPrompt(provider === 8 ? 'Recovery code:' : 'Verification code:');
	}
	if (!token) throw new Error(provider === 8 ? 'A recovery code is required.' : 'A verification code is required.');
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
	if (!value && source.file) value = (await readFile(source.file, 'utf8')).split(/\r\n|\n|\r/, 1)[0];
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
