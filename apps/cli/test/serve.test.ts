import { expect, test } from 'bun:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createApp } from '#app';
import { withStore } from '#store';
import { effectiveServePort, rejectUnreadyUnixSocket, serveRequiresToken } from '#serve-command';
import { runCapturedProcess } from '#test/process';

test('serve uses the reference default port when zero is supplied', () => {
	expect(effectiveServePort(0)).toBe(8087);
	expect(effectiveServePort(8087)).toBe(8087);
	expect(effectiveServePort(9090)).toBe(9090);
});
test('serve requires a bearer token for listeners that can accept peer connections', () => {
	for (const host of ['localhost', '127.0.0.1', '127.20.30.40', '::1', '[::1]']) {
		expect(serveRequiresToken(host)).toBe(false);
	}
	for (const host of ['all', '0.0.0.0', '192.0.2.10', 'vault.example', 'fd+listening://3']) {
		expect(serveRequiresToken(host)).toBe(true);
	}
	expect(serveRequiresToken('fd+connected://3', true)).toBe(true);
	expect(serveRequiresToken('unix:///tmp/vw.sock')).toBe(false);
});
test('unix socket requests receive no API data until owner-only permissions are applied', () => {
	let resumed = false;
	let status = 0;
	let headers: Record<string, string> = {};
	let body = '';
	const incoming = { resume: () => resumed = true } as never;
	const outgoing = {
		writeHead: (code: number, value: Record<string, string>) => {
			status = code;
			headers = value;
		},
		end: (value: string) => body = value,
	} as never;
	expect(rejectUnreadyUnixSocket(false, incoming, outgoing)).toBe(true);
	expect(resumed).toBe(true);
	expect(status).toBe(503);
	expect(headers).toMatchObject({ 'Cache-Control': 'no-store', Connection: 'close' });
	expect(JSON.parse(body)).toEqual({ success: false, message: 'Listener is starting.' });
	expect(rejectUnreadyUnixSocket(true, incoming, outgoing)).toBe(false);
});
test('serve refuses an exposed TCP listener before binding when its token is absent', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-serve-token-'));
	try {
		const executable = new URL('../dist/main.js', import.meta.url).pathname;
		const result = await runCapturedProcess(['node', executable, 'serve', '--hostname', 'all'], {
			env: { PATH: process.env.PATH, VW_APPDATA_DIR: dir },
		});
		expect(result.code).not.toBe(0);
		expect(result.stderr).toContain('VW_SERVE_TOKEN is required for non-loopback listeners.');
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test('application env prefix resolves VW_SERVE_TOKEN and redacts it in validation errors', async () => {
	const directory = await mkdtemp(join(tmpdir(), 'vw-serve-env-prefix-'));
	try {
		const result = await createApp(directory).execute(['serve', '--hostname', 'all'], {
			env: { VW_SERVE_TOKEN: 'synthetic-short-token' },
		});
		expect(result.exitCode).toBe(1);
		expect(result.error?.message).toContain('VW_SERVE_TOKEN must contain at least 32 ASCII characters');
		expect(result.error?.message).not.toContain('synthetic-short-token');
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});

// The listener fixtures run under Node, matching the installed CLI runtime.
// Native handle access is confined to the fixture that supplies inherited descriptors.
const harness = String.raw`
import net from 'node:net';
import http from 'node:http';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {lstat,stat} from 'node:fs/promises';
const [mode, executable, directory] = process.argv.slice(1);
let parent, peer, accepted, child;
const timeout=setTimeout(()=>{ child?.kill('SIGKILL'); peer?.destroy(); accepted?.destroy(); parent?.close(); console.error('Listener fixture timed out'); process.exitCode=1; },10000);
try {
  let address, port, path;
  if(mode==='unix') { path=directory+'/api.sock'; address='unix://'+path; }
  else {
    parent=net.createServer();
    parent.listen(0,'127.0.0.1'); await once(parent,'listening');
    port=parent.address().port;
    if(mode==='connected') {
      const connection=once(parent,'connection');
      peer=net.connect(port,'127.0.0.1'); await once(peer,'connect');
      [accepted]=await connection; accepted.pause();
      address='fd+connected://3';
    } else if(mode==='listening') address='fd+listening://3';
    else { address='127.0.0.1'; await new Promise(resolve=>parent.close(resolve)); parent=undefined; }
  }
  const stdio=['ignore','pipe','pipe'];
  if(mode==='connected'||mode==='listening') stdio.push((mode==='connected'?accepted:parent)._handle.fd);
  const exposed=mode==='exposed';
  const tokenRequired=exposed||mode==='connected'||mode==='listening';
  const bindAddress=exposed?'all':address;
  const args=[executable,'serve','--hostname',bindAddress];
  if(mode==='unauth'||mode==='policy'||exposed) args.push('--port',String(port));
  child=spawn(process.execPath,args,{
    env:{PATH:process.env.PATH,VW_APPDATA_DIR:directory,VW_SERVE_TOKEN:tokenRequired?'0123456789abcdef0123456789abcdef':undefined},stdio,
  });
  const exited=once(child,'exit');
  child.stdout.resume();
  if(accepted) accepted.destroy();
  parent?.close();
  await new Promise((resolve,reject)=>{
    let output='';
    const ready=exposed?'Listening on http://all:'+port:
      (mode==='unauth'||mode==='policy')?'Listening on http://'+address+':'+port:'Listening on '+address;
    child.stderr.on('data',data=>{ output+=data; if(output.includes(ready)) resolve(); });
    child.once('error',reject); child.once('exit',()=>reject(Error('Listener exited before startup')));
  });
  if(path) { const socket=await stat(path); if((socket.mode&0o777)!==0o600) throw Error('Unix socket permissions are not owner-only'); }
  let result;
  if(mode==='unauth'||mode==='policy'||exposed) {
    const request=(path,authorization)=>new Promise((resolve,reject)=>{
      const headers={Host:'localhost:'+port,Connection:'close'};
      if(authorization) headers.Authorization=authorization;
      const incoming=http.get({host:'127.0.0.1',port,path,headers},response=>{
        let output=''; response.setEncoding('utf8'); response.on('data',data=>output+=data);
        response.on('end',()=>resolve({status:response.statusCode,body:JSON.parse(output)}));
      }); incoming.on('error',reject);
    });
    if(exposed) {
      for(const authorization of [undefined,'Bearer wrong-token']) {
        result=await request('/status',authorization);
        if(result.status!==401) throw Error('Exposed listener accepted a request without its bearer token');
      }
      result=await request('/status','Bearer 0123456789abcdef0123456789abcdef');
      if(result.status!==200) throw Error('Exposed listener rejected its configured bearer token');
      child.kill('SIGTERM');
    } else {
    result=await request('/status');
    if(result.status!==200||result.body.data.template.status!==(mode==='policy'?'locked':'unauthenticated')) throw Error('Unexpected unauthenticated status');
    result=await request('/generate?length=8');
    if(result.status!==200||result.body.data.data.length!==(mode==='policy'?32:8)) throw Error('Public generation failed while logged out');
    result=await request('/list/object/items');
    if(result.status!==400||result.body.message!==(mode==='policy'?'Vault is locked. Run vw unlock --raw and supply VW_SESSION.':'You are not logged in.')) throw Error('Vault route did not report the logged-out state');
    child.kill('SIGTERM');
    }
  } else if(mode==='connected') {
    let output=''; peer.setEncoding('utf8'); peer.on('data',data=>output+=data);
    const ended=once(peer,'end');
    peer.write('GET /status HTTP/1.1\r\nHost: localhost:8087\r\nAuthorization: Bearer 0123456789abcdef0123456789abcdef\r\nConnection: close\r\n\r\n');
    await ended;
    if(!output.startsWith('HTTP/1.1 200 ')) throw Error('Unexpected connected response');
    // Node may use a chunked response: assert the JSON content independently of framing.
    if(!output.includes('"status":"locked"')||!output.includes('"userId":"11111111-1111-1111-1111-111111111111"')) throw Error('Missing connected status identity');
  } else {
    result=await new Promise((resolve,reject)=>{
      const headers={Host:'localhost:8087'};
      if(mode==='listening') headers.Authorization='Bearer 0123456789abcdef0123456789abcdef';
      const request=http.get(path?{socketPath:path,path:'/status',headers}:
        {host:'127.0.0.1',port,path:'/status',headers},response=>{
          let output=''; response.setEncoding('utf8'); response.on('data',data=>output+=data);
          response.on('end',()=>resolve({status:response.statusCode,body:JSON.parse(output)}));
        }); request.on('error',reject);
    });
    if(result.status!==200||result.body.data.template.status!=='locked'||result.body.data.template.userId!=='11111111-1111-1111-1111-111111111111') throw Error('Unexpected status response');
    child.kill('SIGTERM');
  }
  const [code,signal]=await exited;
  if(code!==0||signal) throw Error('Listener failed to close cleanly');
  if(path) { try { await lstat(path); throw Error('Socket path remains after close'); } catch(error) { if(error.code!=='ENOENT') throw error; } }
  console.log('PASS '+mode);
} catch(error) { console.error(error.message); process.exitCode=1; }
finally { clearTimeout(timeout); child?.kill('SIGKILL'); peer?.destroy(); accepted?.destroy(); parent?.close(); }
`;
for (const mode of ['unix', 'listening', 'connected', 'unauth', 'policy', 'exposed']) {
	test(
		`built Node serve supports ${mode === 'unauth' ? 'logged-out startup' : `${mode} sockets`} and closes cleanly`,
		async () => {
			const dir = await mkdtemp(join(tmpdir(), 'vw-listener-'));
			try {
				if (mode !== 'unauth') {
					await withStore(dir, async (state, save) => {
						state.server = 'https://example.com';
						state.account = {
							email: 'fixture@example.com',
							kdf: { type: 0, iterations: 600000 },
							accessToken: `header.${
								Buffer.from(JSON.stringify({ sub: '11111111-1111-1111-1111-111111111111' })).toString('base64url')
							}.signature`,
							refreshToken: 'synthetic-refresh',
							expiresAt: Date.now() + 3600000,
							encryptedUserKey: 'locked-fixture-key',
						};
						if (mode === 'policy') {
							state.vault = {
								profile: {
									id: 'user',
									organizations: [{ id: 'org', status: 2, type: 2, enabled: true, usePolicies: true }],
								},
								policiesNew: [{ organizationId: 'org', type: 2, enabled: true, data: { minLength: 32 } }],
							};
						}
						await save();
					});
				}
				const executable = new URL('../dist/main.js', import.meta.url).pathname;
				const result = await runCapturedProcess(
					['node', '--input-type=module', '-e', harness, mode, executable, dir],
					{ env: { PATH: process.env.PATH } },
				);
				expect(result.stderr).toBe('');
				expect(result.code).toBe(0);
				expect(result.stdout.trim()).toBe(`PASS ${mode}`);
			} finally {
				await rm(dir, { recursive: true, force: true });
			}
		},
		15000,
	);
}
