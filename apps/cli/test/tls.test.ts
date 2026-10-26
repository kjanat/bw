import { expect, test } from 'bun:test';
import { X509Certificate } from 'node:crypto';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { writeTestCertificate } from '#test/fixtures/tls';

test('micro509 loopback certificate is trusted by Node through NODE_EXTRA_CA_CERTS', async () => {
	const directory = await mkdtemp(join(tmpdir(), 'vw-tls-test-'));
	let server: ReturnType<typeof Bun.serve> | undefined;
	try {
		const certificatePath = join(directory, 'ca.pem'), keyPath = join(directory, 'key.pem');
		await writeTestCertificate(certificatePath, keyPath);
		const certificate = new X509Certificate(await readFile(certificatePath));
		expect(certificate.checkIP('127.0.0.1')).toBe('127.0.0.1');
		expect(certificate.checkHost('localhost')).toBe('localhost');
		expect(certificate.checkHost('example.com')).toBeUndefined();
		expect(certificate.verify(certificate.publicKey)).toBe(true);
		expect((await stat(keyPath)).mode & 0o777).toBe(0o600);
		server = Bun.serve({
			hostname: '127.0.0.1',
			port: 0,
			tls: { cert: Bun.file(certificatePath), key: Bun.file(keyPath) },
			fetch: () => new Response('trusted fixture'),
		});
		const child = Bun.spawn([
			'node',
			'--input-type=module',
			'-e',
			'const response = await fetch(process.argv[1]); console.log(await response.text());',
			`https://127.0.0.1:${server.port}`,
		], {
			env: { PATH: process.env.PATH, NODE_EXTRA_CA_CERTS: certificatePath },
			stdout: 'pipe',
			stderr: 'pipe',
		});
		const [code, stdout, stderr] = await Promise.all([
			child.exited,
			new Response(child.stdout).text(),
			new Response(child.stderr).text(),
		]);
		expect(stderr).toBe('');
		expect(code).toBe(0);
		expect(stdout.trim()).toBe('trusted fixture');
	} finally {
		server?.stop(true);
		await rm(directory, { recursive: true, force: true });
	}
});
