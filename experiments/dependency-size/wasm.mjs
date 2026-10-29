import { fileURLToPath } from 'node:url';
process.chdir(fileURLToPath(new URL('.', import.meta.url)));
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { brotliCompressSync, gzipSync, constants } from 'node:zlib';
import { build } from 'esbuild';
import { transpile } from '@bytecodealliance/jco';
const sizes = [];
for (const name of ['psl', 'html']) {
	const dir = resolve('out', name + '-wasm');
	mkdirSync(dir, { recursive: true });
	const { files } = await transpile(readFileSync(`out/${name}-component.wasm`), {
		name: 'probe',
		instantiation: 'sync',
		base64Cutoff: 0,
	});
	let wasmRaw = 0, sidecar = 0;
	for (const [file, bytes] of Object.entries(files)) {
		const path = resolve(dir, file);
		mkdirSync(resolve(path, '..'), { recursive: true });
		writeFileSync(path, bytes);
		if (!file.endsWith('.wasm')) continue;
		execFileSync(process.env.WASM_OPT || 'wasm-opt', [
			path,
			'-Oz',
			'--converge',
			'--enable-bulk-memory',
			'--enable-reference-types',
			'--strip-debug',
			'--strip-producers',
			'-o',
			`${path}.opt`,
		]);
		const optimized = readFileSync(`${path}.opt`);
		const compressed = brotliCompressSync(optimized, { params: { [constants.BROTLI_PARAM_QUALITY]: 11 } });
		writeFileSync(`${path}.br`, compressed);
		wasmRaw += optimized.length;
		sidecar += compressed.length;
	}
	const source =
		`import{instantiate}from'./probe.js';import{readFileSync}from'node:fs';import{brotliDecompressSync}from'node:zlib';import{createScoringHost}from'../../host.ts';let instance;function get(){return instance??=instantiate(path=>new WebAssembly.Module(brotliDecompressSync(readFileSync(new URL(path+'.br',import.meta.url)))),createScoringHost())};`
		+ (name === 'html'
			? `export function extract(html){if(!/<\\s*(?:!doctype\\s+html|html|body|pre)\\b/i.test(html))return html;return get().extract(html)}`
			: `import{parseImpl,getEmptyResult}from'tldts-core';export function getHostname(url,options){return parseImpl(url,0,()=>{},options,getEmptyResult()).hostname};export function domain(url){const r=parseImpl(url,0,()=>{},{validHosts:['localhost']},getEmptyResult());const h=r.hostname;if(!h)return null;if(r.isIp||h==='localhost')return h;if(h.endsWith('.localhost'))return 'localhost';return get().domain(h)??null}`);
	await build({
		stdin: { contents: source, resolveDir: dir, sourcefile: 'entry.js' },
		bundle: true,
		minify: true,
		platform: 'node',
		format: 'esm',
		target: 'node24',
		mainFields: ['module', 'main'],
		outfile: resolve(dir, 'entry.mjs'),
	});
	const js = readFileSync(resolve(dir, 'entry.mjs'));
	sizes.push({
		name: name + '-wasip2',
		js: js.length,
		gzipJs: gzipSync(js, { level: 9 }).length,
		brotliJs: brotliCompressSync(js, { params: { [constants.BROTLI_PARAM_QUALITY]: 11 } }).length,
		wasmRaw,
		sidecar,
		totalGzip: gzipSync(js, { level: 9 }).length + sidecar,
		totalBrotli: brotliCompressSync(js, { params: { [constants.BROTLI_PARAM_QUALITY]: 11 } }).length + sidecar,
	});
}
console.table(sizes);
writeFileSync('out/wasm-sizes.json', JSON.stringify(sizes, null, 2) + '\n');
