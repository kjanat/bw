import { fileURLToPath } from 'node:url';
process.chdir(fileURLToPath(new URL('.', import.meta.url)));
import { build } from 'esbuild';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { gzipSync, brotliCompressSync, constants } from 'node:zlib';
import { resolve } from 'node:path';
const out = resolve('out');
await mkdir(out, { recursive: true });
const br = bytes => brotliCompressSync(bytes, { params: { [constants.BROTLI_PARAM_QUALITY]: 11 } });
const trie = await import('./node_modules/tldts/dist/es6/src/data/trie.js');
const data = Object.fromEntries(
	Object.entries(trie).map(([key, value]) => [key, ArrayBuffer.isView(value) ? Array.from(value) : value]),
);
const dataBytes = Buffer.from(JSON.stringify(data));
await writeFile(`${out}/suffix-data.json.br`, br(dataBytes));
const loader =
	`import{readFileSync}from'node:fs';import{brotliDecompressSync}from'node:zlib';const d=JSON.parse(brotliDecompressSync(readFileSync(new URL('./suffix-data.json.br',import.meta.url))).toString());\n`
	+ Object.entries(trie).map(([key, value]) =>
		`export const ${key}=${ArrayBuffer.isView(value) ? `new ${value.constructor.name}(d.${key})` : `d.${key}`};`
	).join('\n');
const binary = [];
const integer = n => {
	while (n > 127) {
		binary.push((n & 127) | 128);
		n >>>= 7;
	}
	binary.push(n);
};
let binaryLoader =
	`import{readFileSync}from'node:fs';import{brotliDecompressSync}from'node:zlib';const b=brotliDecompressSync(readFileSync(new URL('./suffix-data.bin.br',import.meta.url)));let p=0;function integer(){let n=0,s=0,v;do{v=b[p++];n|=(v&127)<<s;s+=7}while(v&128);return n>>>0}function array(C){const a=new C(integer());for(let i=0;i<a.length;i++)a[i]=integer();return a}function text(){const n=integer(),s=b.subarray(p,p+n).toString();p+=n;return s}\n`;
for (const [key, value] of Object.entries(trie)) {
	if (ArrayBuffer.isView(value)) {
		integer(value.length);
		for (const n of value) integer(n);
		binaryLoader += `export const ${key}=array(${value.constructor.name});\n`;
	} else if (typeof value === 'string') {
		const text = Buffer.from(value);
		integer(text.length);
		binary.push(...text);
		binaryLoader += `export const ${key}=text();\n`;
	} else {
		integer(value);
		binaryLoader += `export const ${key}=integer();\n`;
	}
}
const binaryBytes = Buffer.from(binary);
await writeFile(`${out}/suffix-data.bin.br`, br(binaryBytes));
const prelude = `const marker=/<\\s*(?:!doctype\\s+html|html|body|pre)\\b/i;`;
const baseline =
	`import{parse}from'parse5';${prelude}export function extract(source){if(!marker.test(source))return source;const find=n=>{if(n.tagName==='pre')return n;for(const c of n.childNodes??[]){const found=find(c);if(found)return found}};const text=n=>n.nodeName==='#text'?n.value:(n.childNodes??[]).map(text).join('');const pre=find(parse(source));if(!pre)throw Error('missing pre');return text(pre)}`;
const hp2 =
	`import{Parser}from'htmlparser2';${prelude}export function extract(source){if(!marker.test(source))return source;let seen=false,done=false,depth=0,template=0,result='',first=false;const parser=new Parser({onopentag(name){if(name==='template')template++;if(!seen&&!template&&name==='pre'){seen=true;depth=1;first=true}else if(seen&&!done){depth++;first=false}},onclosetag(name){if(seen&&!done&&!--depth)done=true;if(name==='template')template--},ontext(text){if(seen&&!done){if(first){text=text.replace(/^\\n/,'');first=false}result+=text}},oncomment(){first=false}});parser.end(source.replace(/\\r\\n?/g,'\\n').replace(/\\0/g,'�'));if(!seen)throw Error('missing pre');return result}`;
const sax =
	`import{SAXParser}from'parse5-sax-parser';${prelude}export function extract(source){if(!marker.test(source))return source;let seen=false,done=false,result='';const parser=new SAXParser();parser.on('startTag',t=>{if(!seen&&t.tagName==='pre')seen=true});parser.on('endTag',t=>{if(seen&&t.tagName==='pre')done=true});parser.on('text',t=>{if(seen&&!done)result+=t.text});parser.end(source);if(!seen)throw Error('missing pre');return result}`;
const scenarios = [
	['parse5', baseline],
	['htmlparser2', hp2],
	['parse5-sax', sax],
	['tldts', `export {parse,getHostname} from 'tldts'`],
	['tldts-experimental', `export {parse,getHostname} from 'tldts-experimental'`],
	['tldts-compressed-data', `export {parse,getHostname} from 'tldts'`, [{
		name: 'compressed-trie',
		setup(b) {
			b.onLoad({ filter: /tldts\/dist\/es6\/src\/data\/trie\.js$/ }, () => ({ contents: loader, loader: 'js' }));
		},
	}]],
	['tldts-binary-data', `export {parse,getHostname} from 'tldts'`, [{
		name: 'binary-trie',
		setup(b) {
			b.onLoad({ filter: /tldts\/dist\/es6\/src\/data\/trie\.js$/ }, () => ({ contents: binaryLoader, loader: 'js' }));
		},
	}]],
];
const results = [];
for (const [name, source, plugins = []] of scenarios) {
	const outfile = `${out}/${name}.mjs`;
	await build({
		stdin: { contents: source, resolveDir: process.cwd(), sourcefile: name + '.js' },
		bundle: true,
		minify: true,
		platform: 'node',
		format: 'esm',
		target: 'node24',
		mainFields: ['module', 'main'],
		outfile,
		plugins,
	});
	const bytes = await readFile(outfile);
	const sidecar = name === 'tldts-compressed-data'
		? br(dataBytes).length
		: name === 'tldts-binary-data'
		? br(binaryBytes).length
		: 0;
	results.push({
		name,
		js: bytes.length,
		gzipJs: gzipSync(bytes, { level: 9 }).length,
		brotliJs: br(bytes).length,
		sidecar,
		totalGzip: gzipSync(bytes, { level: 9 }).length + sidecar,
		totalBrotli: br(bytes).length + sidecar,
	});
}
console.table(results);
await writeFile('out/sizes.json', JSON.stringify(results, null, 2) + '\n');
await writeFile('out/baseline-source.mjs', baseline + '\n');
await writeFile('out/htmlparser2-source.mjs', hp2 + '\n');
await writeFile('out/parse5-sax-source.mjs', sax + '\n');
