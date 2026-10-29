import { randomBytes } from 'node:crypto';
import { hrtime } from 'node:process';

// A deliberately restricted host for this scorer, not a general WASI shim.
// Unused standard-library imports are present but trap if the guest calls them.
export function createHost(onCall = () => {}) {
	const call = (name, fn) => (...args) => {
		onCall(name);
		return fn(...args);
	};
	const deny = name =>
		call(name, () => {
			throw new Error(`Unexpected WASI operation: ${name}`);
		});
	class Pollable {
		block() {
			return deny('poll.block')();
		}
	}
	class InputStream {}
	class OutputStream {
		checkWrite() {
			return deny('stream.checkWrite')();
		}
		write() {
			return deny('stream.write')();
		}
		blockingFlush() {
			return deny('stream.blockingFlush')();
		}
		subscribe() {
			return deny('stream.subscribe')();
		}
	}
	class IoError {}
	class TerminalInput {}
	class TerminalOutput {}
	return {
		'wasi:clocks/monotonic-clock': {
			now: call('clock.monotonic', () => hrtime.bigint()),
			subscribeDuration: deny('clock.subscribeDuration'),
		},
		'wasi:clocks/wall-clock': {
			now: call('clock.wall', () => {
				const milliseconds = Date.now();
				return { seconds: BigInt(Math.floor(milliseconds / 1000)), nanoseconds: (milliseconds % 1000) * 1_000_000 };
			}),
		},
		'wasi:random/insecure-seed': {
			insecureSeed: call('random.hashSeed', () => {
				const bytes = randomBytes(16);
				return [bytes.readBigUInt64LE(0), bytes.readBigUInt64LE(8)];
			}),
		},
		'wasi:cli/environment': { getEnvironment: call('environment.empty', () => []) },
		'wasi:cli/exit': { exit: deny('exit') },
		'wasi:cli/stdin': { getStdin: deny('stdin') },
		'wasi:cli/stdout': { getStdout: deny('stdout') },
		'wasi:cli/stderr': { getStderr: deny('stderr') },
		'wasi:cli/terminal-input': { TerminalInput },
		'wasi:cli/terminal-output': { TerminalOutput },
		'wasi:cli/terminal-stdin': { getTerminalStdin: deny('terminal.stdin') },
		'wasi:cli/terminal-stdout': { getTerminalStdout: deny('terminal.stdout') },
		'wasi:cli/terminal-stderr': { getTerminalStderr: deny('terminal.stderr') },
		'wasi:io/error': { Error: IoError },
		'wasi:io/poll': { Pollable, poll: deny('poll') },
		'wasi:io/streams': { InputStream, OutputStream },
	};
}
