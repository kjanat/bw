import { expect, test } from 'bun:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { withStore } from '#store';
import { effectiveServePort } from '#serve-command';

test('serve uses the reference default port when zero is supplied', () => {
	expect(effectiveServePort(0)).toBe(8087);
	expect(effectiveServePort(8087)).toBe(8087);
	expect(effectiveServePort(9090)).toBe(9090);
});

// The listener fixtures run under Node, matching the installed CLI runtime.
// Native handle access is confined to the fixture that supplies inherited descriptors.
const harness = String.raw`
import net from 'node:net';
import http from 'node:http';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {lstat} from 'node:fs/promises';
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
  const args=[executable,'serve','--hostname',address];
  if(mode==='unauth'||mode==='policy') args.push('--port',String(port));
  child=spawn(process.execPath,args,{
    env:{PATH:process.env.PATH,VW_APPDATA_DIR:directory},stdio,
  });
  const exited=once(child,'exit');
  child.stdout.resume();
  if(accepted) accepted.destroy();
  parent?.close();
  await new Promise((resolve,reject)=>{
    let output='';
    const ready=(mode==='unauth'||mode==='policy')?'Listening on http://'+address+':'+port:'Listening on '+address;
    child.stderr.on('data',data=>{ output+=data; if(output.includes(ready)) resolve(); });
    child.once('error',reject); child.once('exit',()=>reject(Error('Listener exited before startup')));
  });
  let result;
  if(mode==='unauth'||mode==='policy') {
    const request=path=>new Promise((resolve,reject)=>{
      const incoming=http.get({host:'127.0.0.1',port,path,headers:{Host:'localhost:'+port,Connection:'close'}},response=>{
        let output=''; response.setEncoding('utf8'); response.on('data',data=>output+=data);
        response.on('end',()=>resolve({status:response.statusCode,body:JSON.parse(output)}));
      }); incoming.on('error',reject);
    });
    result=await request('/status');
    if(result.status!==200||result.body.data.template.status!==(mode==='policy'?'locked':'unauthenticated')) throw Error('Unexpected unauthenticated status');
    result=await request('/generate?length=8');
    if(result.status!==200||result.body.data.data.length!==(mode==='policy'?32:8)) throw Error('Public generation failed while logged out');
    result=await request('/list/object/items');
    if(result.status!==400||result.body.message!==(mode==='policy'?'Vault is locked. Run vw unlock --raw and supply VW_SESSION.':'You are not logged in.')) throw Error('Vault route did not report the logged-out state');
    child.kill('SIGTERM');
  } else if(mode==='connected') {
    let output=''; peer.setEncoding('utf8'); peer.on('data',data=>output+=data);
    const ended=once(peer,'end');
    peer.write('GET /status HTTP/1.1\r\nHost: localhost:8087\r\nConnection: close\r\n\r\n');
    await ended;
    if(!output.startsWith('HTTP/1.1 200 ')) throw Error('Unexpected connected response');
    // Node may use a chunked response: assert the JSON content independently of framing.
    if(!output.includes('"status":"locked"')||!output.includes('"userId":"11111111-1111-1111-1111-111111111111"')) throw Error('Missing connected status identity');
  } else {
    result=await new Promise((resolve,reject)=>{
      const request=http.get(path?{socketPath:path,path:'/status',headers:{Host:'localhost:8087'}}:
        {host:'127.0.0.1',port,path:'/status'},response=>{
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
for (const mode of ['unix', 'listening', 'connected', 'unauth', 'policy']) {
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
				const child = Bun.spawn(['node', '--input-type=module', '-e', harness, mode, executable, dir], {
					stdout: 'pipe',
					stderr: 'pipe',
					env: { PATH: process.env.PATH },
				});
				const [code, stdout, stderr] = await Promise.all([
					child.exited,
					new Response(child.stdout).text(),
					new Response(child.stderr).text(),
				]);
				expect(stderr).toBe('');
				expect(code).toBe(0);
				expect(stdout.trim()).toBe(`PASS ${mode}`);
			} finally {
				await rm(dir, { recursive: true, force: true });
			}
		},
		15000,
	);
}
