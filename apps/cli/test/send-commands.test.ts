import { expect, test } from 'bun:test';
import { runCommand } from '@kjanat/dreamcli/testkit';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { receiveCommand, sendCommands, sendPassword } from '#send-commands';
import type { VaultRuntime } from '#vault-commands';

function sendCli(requests: Array<Record<string, unknown>>) {
	const vault = {
		sends: {
			create: async (request: Record<string, unknown>) => {
				requests.push(request);
				return {
					id: 'synthetic-send-id',
					name: request.name,
					type: request.type,
					accessUrl: 'https://vault.example/#/send/id/key',
					passwordSet: request.password !== undefined,
				};
			},
		},
	};
	const runtime = {
		run: async (_session: string | undefined, _mutate: boolean, operation: (value: never) => unknown) =>
			await operation(vault as never),
	} as unknown as VaultRuntime;
	return sendCommands(runtime);
}

test('Send password uses DreamCLI env binding, while explicit and named values take priority', async () => {
	const requests: Array<Record<string, unknown>> = [];
	const cli = sendCli(requests);
	const fromDefault = await runCommand(cli, ['synthetic payload'], {
		env: { SEND_PASSWORD: 'static send secret' },
	});
	expect(fromDefault.exitCode).toBe(0);
	expect(requests.at(-1)?.password).toBe('static send secret');

	const fromArgv = await runCommand(cli, ['synthetic payload', '--password', 'argv send secret'], {
		env: { SEND_PASSWORD: 'static send secret' },
	});
	expect(fromArgv.exitCode).toBe(0);
	expect(requests.at(-1)?.password).toBe('argv send secret');

	const previous = process.env.NAMED_SEND_SECRET;
	process.env.NAMED_SEND_SECRET = 'named send secret';
	try {
		const fromNamedEnvironment = await runCommand(cli, ['synthetic payload', '--passwordenv', 'NAMED_SEND_SECRET'], {
			env: { SEND_PASSWORD: 'static send secret' },
		});
		expect(fromNamedEnvironment.exitCode).toBe(0);
		expect(requests.at(-1)?.password).toBe('named send secret');
	} finally {
		if (previous === undefined) delete process.env.NAMED_SEND_SECRET;
		else process.env.NAMED_SEND_SECRET = previous;
	}
});

test('Send password sources follow bw priority and treat empty values as absent', async () => {
	const directory = await mkdtemp(join(tmpdir(), 'vw-send-password-'));
	const file = join(directory, 'password.txt');
	const envName = 'VW_TEST_SEND_PASSWORD';
	const previous = process.env[envName];
	process.env[envName] = 'named send secret';
	try {
		await writeFile(file, 'file send secret\nignored line\n', { mode: 0o600 });
		expect(await sendPassword('explicit send secret', 'cli', envName, file)).toBe('explicit send secret');
		expect(await sendPassword('static send secret', 'env', envName, file)).toBe('file send secret');
		expect(await sendPassword('static send secret', 'env', envName)).toBe('named send secret');
		await writeFile(file, '\nignored line', { mode: 0o600 });
		expect(await sendPassword(undefined, undefined, envName, file)).toBeUndefined();
		process.env[envName] = '';
		expect(await sendPassword(undefined, undefined, envName)).toBeUndefined();
		await expect(sendPassword(undefined, undefined, envName, undefined, true)).rejects.toThrow('unset');
	} finally {
		if (previous === undefined) delete process.env[envName];
		else process.env[envName] = previous;
		await rm(directory, { recursive: true, force: true });
	}
});

test('receive rejects an explicitly named password variable that is unset', async () => {
	const envName = `VW_TEST_MISSING_RECEIVE_SEND_PASSWORD_${process.pid}`;
	delete process.env[envName];
	const result = await runCommand(receiveCommand(), [
		'https://vault.example/#/send/id/key',
		'--passwordenv',
		envName,
	]);
	expect(result.exitCode).toBe(1);
	expect(result.stderr.join('')).toContain('selected Send password environment variable is unset');
});
