import { createServer, type Server } from 'node:http';
import { spawn } from 'node:child_process';
import {
	createSsoAuthorization,
	ssoCredentialsFromCallback,
	SsoAuthorizationDeclinedError,
	type SsoAuthorization,
	type SsoCredentials,
	type VaultwardenClient,
} from '@kjanat/vaultwarden';

/** DreamCLI 4.1 has no optional-value flags; normalize bw's --sso [identifier] at the executable boundary. */
export function normalizeSsoArguments(argv: readonly string[]): string[] {
	let commandIndex = 0;
	while (/^(?:--(?:help|version|json|quiet|pretty)(?:=.*)?|-[hqV])$/.test(argv[commandIndex] ?? '')) commandIndex++;
	if (argv[commandIndex] !== 'login') return [...argv];
	const result: string[] = argv.slice(0, commandIndex);
	for (let i = commandIndex; i < argv.length; i++) {
		const value = argv[i]!;
		if (value === '--') {
			result.push(...argv.slice(i));
			break;
		}
		if (value.startsWith('--sso=')) result.push('--sso', '--identifier', value.slice('--sso='.length));
		else if (value === '--sso') {
			result.push(value);
			if (argv[i + 1] && !argv[i + 1]!.startsWith('-')) result.push('--identifier', argv[++i]!);
		} else result.push(value);
	}
	return result;
}
function openBrowser(url: string): void {
	const [binary, args] = process.platform === 'win32'
		? ['rundll32', ['url.dll,FileProtocolHandler', url]] as const
		: process.platform === 'darwin'
		? ['open', [url]] as const
		: ['xdg-open', [url]] as const;
	const child = spawn(binary, [...args], { stdio: 'ignore', detached: true });
	child.on('error', () => {/* The printed link remains available when no browser launcher exists. */});
	child.unref();
}
/** A loopback listener receives only a code; it never receives the master password or vault key. */
export async function authorizeSso(client: VaultwardenClient, options: {
	organizationIdentifier?: string;
	openBrowser?: boolean;
	onAuthorization?: (url: string) => void | Promise<void>;
	timeoutMs?: number;
} = {}): Promise<SsoCredentials> {
	const complete = Promise.withResolvers<SsoCredentials>();
	// Avoid an unhandled rejection if cancellation happens while prevalidation is still in flight.
	void complete.promise.catch(() => {});
	let authorization: SsoAuthorization | undefined, server: Server | undefined;
	let redirectUri = '';
	const controller = new AbortController();
	let cancelled = false;
	const cancel = () => {
		cancelled = true;
		controller.abort();
		complete.reject(new Error('SSO login cancelled.'));
	};
	process.on('SIGINT', cancel);
	process.on('SIGTERM', cancel);
	const timer = setTimeout(() => {
		cancelled = true;
		controller.abort();
		complete.reject(new Error('SSO login timed out.'));
	}, options.timeoutMs ?? 240000);
	try {
		for (let port = 8065; port <= 8070; port++) {
			const candidate = createServer((request, response) => {
				response.setHeader('Content-Type', 'text/plain; charset=utf-8');
				response.setHeader('Cache-Control', 'no-store');
				response.setHeader('Content-Security-Policy', "default-src 'none'");
				if (!authorization) {
					response.writeHead(503).end('SSO is starting.');
					return;
				}
				if (
					request.method !== 'GET' || request.headers.host !== new URL(authorization.redirectUri).host
					|| request.headers.origin
				) {
					response.writeHead(400).end('Invalid SSO callback.');
					return;
				}
				try {
					const callback = new URL(request.url ?? '/', authorization.redirectUri).href;
					const credentials = ssoCredentialsFromCallback(authorization, callback);
					response.end(
						'SSO authentication received. Return to the terminal to unlock the vault.',
						() => complete.resolve(credentials),
					);
				} catch (error) {
					response.writeHead(400).end('Invalid SSO callback.', () => {
						if (error instanceof SsoAuthorizationDeclinedError) complete.reject(error);
					});
				}
			});
			try {
				await new Promise<void>((resolve, reject) => {
					candidate.once('error', reject);
					candidate.listen(port, '127.0.0.1', resolve);
				});
				server = candidate;
				redirectUri = `http://localhost:${port}`;
				break;
			} catch (error) {
				candidate.close();
				if ((error as NodeJS.ErrnoException).code !== 'EADDRINUSE') {
					throw new Error('Could not open the SSO callback listener.');
				}
			}
		}
		if (!server) throw new Error('No SSO callback port is available (8065–8070).');
		try {
			authorization = await createSsoAuthorization(
				client,
				redirectUri,
				options.organizationIdentifier,
				controller.signal,
			);
		} catch (error) {
			if (cancelled) return await complete.promise;
			throw error;
		}
		if (cancelled) return await complete.promise;
		if (options.onAuthorization) await options.onAuthorization(authorization.url);
		else {
			process.stderr.write(`Complete SSO authentication in your browser:\n${authorization.url}\n`);
			if (options.openBrowser !== false) openBrowser(authorization.url);
		}
		return await complete.promise;
	} finally {
		clearTimeout(timer);
		process.off('SIGINT', cancel);
		process.off('SIGTERM', cancel);
		server?.closeAllConnections();
		if (server?.listening) await new Promise<void>(resolve => server!.close(() => resolve()));
	}
}
