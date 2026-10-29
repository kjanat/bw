import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import cli from '@kjanat/vaultwarden-cli/package.json' with { type: 'json' };

const requireFromCli = createRequire(import.meta.resolve('@kjanat/vaultwarden-cli/package.json'));
const sdkUrl = pathToFileURL(requireFromCli.resolve('@kjanat/vaultwarden'));
const sdk = requireFromCli('@kjanat/vaultwarden/package.json');
const {
	SDK_VERSION,
	VaultwardenClient,
	decrypt,
	deriveMasterKey,
	encrypt,
	parseKdbx,
	stretchKey,
} = await import(sdkUrl.href);

assert.equal(SDK_VERSION, sdk.version);
assert.equal(sdk.version, process.env.EXPECTED_SDK_VERSION);
assert.ok(sdkUrl.href.startsWith(new URL('./node_modules/', import.meta.url).href));
for (const [command, expected] of [['--version', cli.version], ['sdk-version', sdk.version]]) {
	const output = execFileSync(process.execPath, [resolve('node_modules/.bin/vw'), command], { encoding: 'utf8' });
	assert.equal(output.trim(), expected);
}

const password = '67t9b5g67$%Dh89n';
for (
	const [kdf, expected] of [
		[{ type: 0, iterations: 10000 }, '1f4f68e29647b15ac250acd1118184518aa745a7fe95021b27c5402a16c3564b'],
		[
			{ type: 1, iterations: 4, memory: 32, parallelism: 2 },
			'cff0e1b1a213a34c626ab3afe00911f01493ed2ff6968db83ee183f23335e1f2',
		],
	]
) {
	const master = await deriveMasterKey(password, '  TEST_KEY ', kdf);
	assert.equal(master.toString('hex'), expected);
	const key = stretchKey(master);
	const ciphertext = encrypt(Buffer.from('runtime fixture'), key);
	assert.equal(decrypt(ciphertext, key).toString(), 'runtime fixture');
	assert.throws(() => decrypt(ciphertext, Buffer.alloc(64, 8)), /authentication/);
	master.fill(0);
	key.fill(0);
}

for (
	const [fixture, keyFile] of [
		['aes3', undefined],
		['aes4', 'keyfile-v2.bin'],
		['argon2d', 'keyfile-raw.bin'],
		['argon2id', undefined],
	]
) {
	const document = await parseKdbx(await readFile(`fixtures/kdbx/${fixture}.kdbx`), {
		password: fixture === 'argon2d' ? undefined : 'synthetic-database-password',
		keyFile: keyFile ? await readFile(`fixtures/kdbx/${keyFile}`) : undefined,
	});
	assert.equal(document.items.length, 2);
	const root = document.items.find(item => item.name === 'KDBX compatibility root');
	assert.equal(root?.notes, 'exact\tnotes\nsecond line');
	assert.equal(root?.login.password, '  synthetic-secret  ');
}

// Exercise actual HTTP and fetch under each runtime with an isolated protocol fixture.
const requests = [];
let fixtureError;
const server = createServer(async (request, response) => {
	try {
		requests.push(request.url);
		const chunks = [];
		for await (const chunk of request) chunks.push(chunk);
		const body = Buffer.concat(chunks).toString();
		let data;
		switch (request.url) {
			case '/identity/accounts/prelogin':
				assert.equal(JSON.parse(body).email, 'fixture@example.test');
				data = { kdf: 0, kdfIterations: 10000 };
				break;
			case '/identity/connect/token':
				assert.equal(new URLSearchParams(body).get('grant_type'), 'password');
				assert.equal(new URLSearchParams(body).get('password'), 'synthetic-password-hash');
				data = {
					access_token: 'synthetic-access',
					refresh_token: 'synthetic-refresh',
					expires_in: 3600,
					key: 'synthetic-key',
				};
				break;
			case '/api/sync?excludeDomains=false':
				assert.equal(request.headers.authorization, 'Bearer synthetic-access');
				data = { profile: { id: 'runtime-fixture' }, ciphers: [] };
				break;
			default:
				throw new Error(`Unexpected fixture request: ${request.url}`);
		}
		response.writeHead(200, { 'Content-Type': 'application/json' });
		response.end(JSON.stringify(data));
	} catch (error) {
		fixtureError = error;
		response.writeHead(500);
		response.end('{}');
	}
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
try {
	const client = new VaultwardenClient(`http://127.0.0.1:${server.address().port}`);
	assert.deepEqual(await client.prelogin(' Fixture@Example.Test '), { type: 0, iterations: 10000 });
	const login = await client.login('fixture@example.test', 'synthetic-password-hash');
	assert.equal(login.encryptedUserKey, 'synthetic-key');
	assert.deepEqual(await client.sync(login.accessToken), { profile: { id: 'runtime-fixture' }, ciphers: [] });
	assert.equal(fixtureError, undefined);
	assert.deepEqual(requests, [
		'/identity/accounts/prelogin',
		'/identity/connect/token',
		'/api/sync?excludeDomains=false',
	]);
} finally {
	await new Promise(resolve => server.close(resolve));
}
console.log(
	`Installed packages verified: ${process.versions.bun ? 'Bun' : 'Node'} ${
		process.versions.bun ?? process.version
	} / ${process.arch}; crypto, KDBX workers, login and sync.`,
);
