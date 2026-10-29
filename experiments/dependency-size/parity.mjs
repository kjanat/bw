import { fileURLToPath } from 'node:url';
process.chdir(fileURLToPath(new URL('.', import.meta.url)));
import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import * as baseline from './out/parse5.mjs';
import * as htmlparser2 from './out/htmlparser2.mjs';
import * as sax from './out/parse5-sax.mjs';
import * as wasmHtml from './out/html-wasm/entry.mjs';
import * as wasmDomain from './out/psl-wasm/entry.mjs';
import * as domains from './out/tldts.mjs';
import * as compressed from './out/tldts-compressed-data.mjs';
import * as binary from './out/tldts-binary-data.mjs';
import * as experimental from './out/tldts-experimental.mjs';
import * as trie from './node_modules/tldts/dist/es6/src/data/trie.js';
const inputs = [
	'url,password\nhttps://example.com,secret',
	'<!doctype html><html><body><pre>url,username,password,extra,name,grouping,fav\nhttps://example.com,alice,secret,&lt;notes&gt;,Tea &amp; Coffee,Personal,1</pre></body></html>',
	'<html><body>no export</body></html>',
	'<pre>one</pre><pre>two</pre>',
	'<PRE class="csv">&notin; &#x1f642; &#0; &#128;</PRE>',
	'<pre>\nfirst\nsecond</pre>',
	'<pre>\r\nfirst\rsecond</pre>',
	'<pre><!-- comment -->\nkeep newline</pre>',
	'<pre>\0nul</pre>',
	'<pre>a<br>b</pre>',
	'<pre>a<div>b</div>c</pre>',
	'<pre>a<pre>b</pre>c</pre>',
	'<table><pre>a<tr><td>b</td></tr>c</pre></table>',
	'<pre>a<table>b<tr><td>c</td></tr>d</table>e</pre>',
	'<template><pre>hidden</pre></template><pre>visible</pre>',
	'<pre>a<template>hidden</template>b</pre>',
	'<textarea><pre>fake</pre></textarea><pre>real</pre>',
	'<script>"<pre>fake</pre>"</script><pre>real</pre>',
	'<pre>before<script>&amp;</script>after</pre>',
	'<pre><p>first<p>second</pre>',
	'<pre><svg><![CDATA[x<y]]></svg></pre>',
	'<pre><svg><foreignObject><div>x</div></foreignObject></svg></pre>',
	'<select><pre>invalid</pre></select><pre>real</pre>',
	'<pre>a</p>b</pre>',
	'<!-- <pre>fake</pre> --><pre>real</pre>',
	'<pre>unterminated',
	'<pre>a<b><i>x</b>y</i>z</pre>',
	'<pre>a&amp;b&copy=1&unknown;</pre>',
];
const outcome = (fn, input) => {
	try {
		return { value: fn(input) };
	} catch {
		return { error: true };
	}
};
const mismatches = { htmlparser2: [], sax: [], wasmHtml: [] };
for (const [name, library] of Object.entries({ htmlparser2, sax, wasmHtml })) {
	for (const input of inputs) {
		const expected = outcome(baseline.extract, input), actual = outcome(library.extract, input);
		if (JSON.stringify(expected) !== JSON.stringify(actual)) mismatches[name].push({ input, expected, actual });
	}
}
const offsets = [];
let offset = 0;
for (const len of trie.edgeLength) {
	offsets.push(offset);
	offset += len;
}
const rules = [];
function walk(node, labels = []) {
	if (trie.nodeFlags[node] && labels.length) rules.push(labels.join('.'));
	for (let edge = trie.edgeStart[node]; edge < trie.edgeStart[node + 1]; edge++) {
		const label = trie.labelText.slice(offsets[edge], offsets[edge] + trie.edgeLength[edge]);
		walk(trie.edgeChild[edge], [label, ...labels]);
	}
}
walk(trie.rulesRoot);
walk(trie.exceptionsRoot);
const hosts = [
	'https://login.example.co.uk/a',
	'https://alice.github.io',
	'https://bob.github.io',
	'http://localhost:8080',
	'127.0.0.1',
	'http://[::1]:8080',
	'https://食狮.公司.cn',
	'xn--bcher-kva.de',
	'EXAMPLE.COM.',
	'user:password@a.example.com:80/path',
	'about:blank',
	'data:text/plain,foo',
	'invalid host',
	'foo..bar',
	'https://city.kawasaki.jp',
	'https://www.ck',
	...rules.flatMap(rule => {
		const r = rule.replaceAll('*', 'wildcard');
		return [r, `login.${r}`, `https://user:pass@a.b.${r}:8080/path?q=x`];
	}),
];
let domainChecks = 0, experimentalMismatches = 0, experimentalDomainMismatches = 0;
for (const host of hosts) {
	for (const allowPrivateDomains of [true, false]) {
		const opts = { allowPrivateDomains, validHosts: ['localhost'] };
		const expected = domains.parse(host, opts);
		assert.deepEqual(compressed.parse(host, opts), expected, host);
		assert.deepEqual(binary.parse(host, opts), expected, host);
		assert.equal(binary.getHostname(host, opts), domains.getHostname(host, opts));
		if (JSON.stringify(experimental.parse(host, opts)) !== JSON.stringify(expected)) experimentalMismatches++;
		if (experimental.parse(host, opts).domain !== expected.domain) experimentalDomainMismatches++;
		domainChecks++;
	}
}
let wasmDomainMismatches = 0;
const wasmDomainExamples = [];
for (const host of hosts) {
	const parsed = domains.parse(host, { allowPrivateDomains: true, validHosts: ['localhost'] });
	const expected = parsed.isIp || parsed.hostname === 'localhost' ? parsed.hostname : parsed.domain;
	const actual = wasmDomain.domain(host);
	if (actual !== expected) {
		wasmDomainMismatches++;
		if (wasmDomainExamples.length < 5) wasmDomainExamples.push({ host, expected, actual });
	}
}
const result = {
	runtime: process.versions.bun ? 'bun' : 'node',
	htmlCases: inputs.length,
	htmlMismatches: mismatches,
	domainRules: rules.length,
	domainChecks,
	experimentalMismatches,
	experimentalDomainMismatches,
	wasmDomainChecks: hosts.length,
	wasmDomainMismatches,
	wasmDomainExamples,
};
console.log(JSON.stringify(result, null, 2));
await writeFile(`out/parity-${result.runtime}.json`, JSON.stringify(result, null, 2) + '\n');
