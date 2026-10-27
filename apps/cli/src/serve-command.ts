import { outputCommand as command } from '#output';
import { timingSafeEqual } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { isIP, Socket } from 'node:net';
import { chmod } from 'node:fs/promises';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { flag } from '@kjanat/dreamcli';
import { createLocalApiHandler, generateVaultSecret } from '@kjanat/vaultwarden';
import { accountUserId, unlockAccount, type JsonObject } from '@kjanat/vaultwarden';
import { openSession, sealSession, withStore, type State } from '#store';
import type { VaultRuntime } from '#vault-commands';

export function effectiveServePort(port: number): number {
	return port || 8087;
}

function loopbackHost(hostname: string): boolean {
	const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
	if (host === 'localhost' || host === '::1') return true;
	const ipv4 = host.startsWith('::ffff:') ? host.slice('::ffff:'.length) : host;
	return isIP(ipv4) === 4 && Number(ipv4.split('.')[0]) === 127;
}

export function serveRequiresToken(hostname: string, descriptor = false): boolean {
	if (descriptor || hostname === 'all') return true;
	if (hostname.startsWith('unix://')) return false;
	return !loopbackHost(hostname);
}

/**
 * Bind a Unix socket that only its owner can connect to. File permissions are the socket's only
 * access control and are checked at connect time. The owner-only umask is the protection: it keeps
 * the socket private from bind onward. Destroying connections seen before the chmod completes is a
 * backup only, since the kernel can queue a connection early that Node accepts after `ready` is set.
 */
export async function listenOwnerOnlyUnixSocket(
	server: Server,
	socketPath: string,
	restrict: (path: string) => Promise<void> = path => chmod(path, 0o600),
): Promise<void> {
	let ready = false;
	server.on('connection', (socket: Socket) => {
		if (!ready) socket.destroy();
	});
	const previousUmask = process.umask(0o177);
	try {
		await new Promise<void>((resolve, reject) => {
			server.once('error', reject);
			server.listen(socketPath, () => {
				server.off('error', reject);
				resolve();
			});
		});
	} finally {
		process.umask(previousUmask);
	}
	try {
		await restrict(socketPath);
	} catch (error) {
		await new Promise<void>(resolve => server.close(() => resolve()));
		throw error;
	}
	ready = true;
}

function authorizedServeRequest(header: string | string[] | undefined, token: string): boolean {
	if (typeof header !== 'string') return false;
	const match = /^Bearer ([\x21-\x7e]+)$/i.exec(header);
	if (!match) return false;
	const supplied = Buffer.from(match[1]!, 'ascii');
	const expected = Buffer.from(token, 'ascii');
	return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

export function serveCommand(
	runtime: VaultRuntime,
	directory: string,
	sync: (state: State, save: () => Promise<void>, force?: boolean) => Promise<void>,
) {
	return command('serve').description('Serve the local vault through the bw-compatible REST API')
		.flag(
			'hostname',
			flag.string().default('localhost').describe(
				'Non-loopback listeners require VW_SERVE_TOKEN with at least 32 ASCII characters',
			),
		)
		.flag('port', flag.number({ int: true, min: 0, max: 65535 }).default(8087))
		.flag('disable-origin-protection', flag.boolean())
		.flag('token', flag.string().sensitive().env('SERVE_TOKEN'))
		.flag('session', flag.string().sensitive().env('SESSION'))
		.action(async ({ flags, out }) => {
			let session = flags.session;
			await withStore(directory, async state => {
				if (state.account && session) openSession(state, session).fill(0);
			});
			let port = effectiveServePort(flags.port);
			const hostname = flags.hostname;
			const descriptor = /^fd\+(connected|listening):\/\/(\d+)$/.exec(hostname);
			if (hostname.startsWith('fd+') && (!descriptor || !Number.isSafeInteger(Number(descriptor[2])))) {
				throw new Error('Use fd+connected://NUMBER or fd+listening://NUMBER.');
			}
			const socketPath = hostname.startsWith('unix://') ? hostname.slice('unix://'.length) : undefined;
			if (socketPath !== undefined && (!socketPath || socketPath.includes('\0'))) {
				throw new Error('A Unix socket path is required.');
			}
			const token = flags.token;
			if (token !== undefined && !/^[\x21-\x7e]{32,}$/.test(token)) {
				throw new Error('VW_SERVE_TOKEN must contain at least 32 ASCII characters without whitespace.');
			}
			if (serveRequiresToken(hostname, descriptor !== null) && token === undefined) {
				throw new Error('VW_SERVE_TOKEN is required for non-loopback listeners.');
			}
			const handler = createLocalApiHandler({
				status: () =>
					withStore(directory, async state => {
						let unlocked = false;
						try {
							openSession(state, session).fill(0);
							unlocked = true;
						} catch { /* Report the current locked state. */ }
						return {
							serverUrl: state.server ?? null,
							lastSync: state.lastSync ?? null,
							userEmail: state.account?.email ?? null,
							userId: (state.vault?.profile as JsonObject | undefined)?.id
								?? (state.account ? accountUserId(state.account) ?? null : null),
							status: !state.account ? 'unauthenticated' : unlocked ? 'unlocked' : 'locked',
						};
					}),
				sync: (force) => withStore(directory, (state, save) => sync(state, save, force)),
				lock: () =>
					withStore(directory, async (state, save) => {
						delete state.session;
						await save();
						session = undefined;
					}),
				unlock: password =>
					withStore(directory, async (state, save) => {
						if (!state.account) throw new Error('No active account found');
						if (password === null) {
							throw new Error(
								'Master password is required. Try again in interactive mode or provide a password file or environment variable.',
							);
						}
						const key = await unlockAccount(state.account, password);
						try {
							const token = sealSession(state, key);
							await save();
							session = token;
							return token;
						} finally {
							key.fill(0);
						}
					}),
				generate: options =>
					withStore(
						directory,
						async state => generateVaultSecret(options, state.account ? state.vault : undefined),
					),
				run: (mutate, operation, online) => runtime.run(session, mutate, operation, online),
			}, {
				hostname: descriptor ? 'all' : hostname,
				get port() {
					return port;
				},
				disableOriginProtection: flags['disable-origin-protection'],
			});
			const server = createServer(async (incoming, outgoing) => {
				try {
					if (token !== undefined && !authorizedServeRequest(incoming.headers.authorization, token)) {
						outgoing.writeHead(401, {
							'Cache-Control': 'no-store',
							'Content-Type': 'application/json',
							'WWW-Authenticate': 'Bearer',
						});
						outgoing.end(JSON.stringify({ success: false, message: 'Unauthorized.' }));
						return;
					}
					const headers = new Headers();
					for (const [name, value] of Object.entries(incoming.headers)) {
						if (value !== undefined) headers.set(name, Array.isArray(value) ? value.join(', ') : value);
					}
					const init: RequestInit & { duplex?: string } = { method: incoming.method, headers };
					if (incoming.method !== 'GET' && incoming.method !== 'HEAD') {
						init.body = Readable.toWeb(incoming) as unknown as ReadableStream<Uint8Array>;
						init.duplex = 'half';
					}
					const response = await handler(new Request(`http://localhost:${port}${incoming.url ?? '/'}`, init));
					outgoing.writeHead(response.status, { ...Object.fromEntries(response.headers), 'Cache-Control': 'no-store' });
					if (response.body && incoming.method !== 'HEAD') {
						await pipeline(Readable.from(response.body), outgoing);
					}
					outgoing.end();
				} catch {
					if (!outgoing.headersSent) outgoing.writeHead(400, { 'Content-Type': 'application/json' });
					outgoing.end(JSON.stringify({ success: false, message: 'Invalid request.' }));
				}
			});
			let connected: Socket | undefined;
			if (socketPath !== undefined) {
				await listenOwnerOnlyUnixSocket(server, socketPath);
			} else {
				await new Promise<void>((resolve, reject) => {
					server.once('error', reject);
					const listening = () => {
						server.off('error', reject);
						const address = server.address();
						if (address && typeof address !== 'string') port = address.port;
						resolve();
					};
					if (descriptor?.[1] === 'connected') {
						connected = new Socket({ fd: Number(descriptor[2]), readable: true, writable: true });
						server.keepAliveTimeout = 0;
						server.headersTimeout = 0;
						server.requestTimeout = 0;
						server.timeout = 0;
						connected.pause();
						server.emit('connection', connected);
						connected.resume();
						listening();
					} else if (descriptor) server.listen({ fd: Number(descriptor[2]) }, listening);
					else server.listen(port, hostname === 'all' ? undefined : hostname, listening);
				});
			}
			out.status(
				descriptor || socketPath !== undefined ? `Listening on ${hostname}` : `Listening on http://${hostname}:${port}`,
			);
			await new Promise<void>((resolve, reject) => {
				let stopping = false;
				const stop = () => {
					if (stopping) return;
					stopping = true;
					connected?.destroy();
					server.close();
					server.closeAllConnections();
				};
				process.once('SIGINT', stop);
				process.once('SIGTERM', stop);
				connected?.once('close', stop);
				const cleanup = () => {
					process.off('SIGINT', stop);
					process.off('SIGTERM', stop);
				};
				server.once('close', () => {
					cleanup();
					resolve();
				});
				server.once('error', error => {
					cleanup();
					reject(error);
				});
			});
		});
}
