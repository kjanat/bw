import { outputCommand as command } from '#output';
import { createServer } from 'node:http';
import { Socket } from 'node:net';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { flag } from '@kjanat/dreamcli';
import { createLocalApiHandler, generateSecret } from '@kjanat/vaultwarden';
import { accountUserId, unlockAccount, type JsonObject } from '@kjanat/vaultwarden';
import { openSession, sealSession, withStore, type State } from '#store';
import type { VaultRuntime } from '#vault-commands';

export function effectiveServePort(port: number): number {
	return port || 8087;
}

export function serveCommand(
	runtime: VaultRuntime,
	directory: string,
	sync: (state: State, save: () => Promise<void>, force?: boolean) => Promise<void>,
) {
	return command('serve').description('Serve the local vault through the bw-compatible REST API')
		.flag('hostname', flag.string().default('localhost'))
		.flag('port', flag.number({ int: true, min: 0, max: 65535 }).default(8087))
		.flag('disable-origin-protection', flag.boolean())
		.flag('session', flag.string().sensitive().env('VW_SESSION'))
		.action(async ({ flags, out }) => {
			let session = flags.session;
			await withStore(directory, async state => {
				if (!state.account) throw new Error('Log in before starting the local API.');
				if (session) openSession(state, session).fill(0);
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
						if (!state.account) throw new Error('Log in first.');
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
						async state => generateSecret(options, state.vault?.policies as JsonObject[] | undefined),
					),
				run: (mutate, operation, online) => runtime.run(session, mutate, operation, online),
			}, {
				hostname,
				get port() {
					return port;
				},
				disableOriginProtection: flags['disable-origin-protection'],
			});
			const server = createServer(async (incoming, outgoing) => {
				try {
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
				else if (socketPath !== undefined) server.listen(socketPath, listening);
				else server.listen(port, hostname === 'all' ? undefined : hostname, listening);
			});
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
