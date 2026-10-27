import { mkdtemp, open, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/** Capture child output through files because Bun's readable child pipes can be empty on some hosts. */
export async function runCapturedProcess(
	command: string[],
	options: { env?: Record<string, string | undefined> },
	stdinData?: string,
): Promise<{ code: number; stdout: string; stderr: string }> {
	const directory = await mkdtemp(join(tmpdir(), 'vw-cli-process-'));
	const stdoutFile = await open(join(directory, 'stdout'), 'w');
	const stderrFile = await open(join(directory, 'stderr'), 'w');
	const stdinPath = join(directory, 'stdin');
	let stdinFile: Awaited<ReturnType<typeof open>> | undefined;
	try {
		if (stdinData !== undefined) {
			await writeFile(stdinPath, stdinData);
			stdinFile = await open(stdinPath, 'r');
		}
		const child = Bun.spawn(command, {
			...options,
			stdin: stdinFile?.fd ?? 'ignore',
			stdout: stdoutFile.fd,
			stderr: stderrFile.fd,
		});
		const code = await child.exited;
		await Promise.all([stdoutFile.close(), stderrFile.close()]);
		const [stdout, stderr] = await Promise.all([
			readFile(join(directory, 'stdout'), 'utf8'),
			readFile(join(directory, 'stderr'), 'utf8'),
		]);
		return { code, stdout, stderr };
	} finally {
		await Promise.allSettled([stdoutFile.close(), stderrFile.close(), stdinFile?.close()]);
		await rm(directory, { recursive: true, force: true });
	}
}
