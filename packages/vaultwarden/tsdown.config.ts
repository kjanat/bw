import { defineConfig } from 'tsdown';
import { compactTables } from './build-plugins/compact-tables.ts';

export default defineConfig({
	entry: ['src/index.ts', 'src/kdbx-worker.ts'],
	platform: 'node',
	inputOptions: { resolve: { mainFields: ['module', 'main'] } },
	dts: true,
	minify: true,
	sourcemap: false,
	exports: true,
	copy: [
		{ from: 'src/generated/*.wasm.br', to: 'dist/generated' },
		'wasm/THIRD_PARTY_NOTICES.txt',
	],
	// Ship the patched decoder rather than reinstalling the unpatched npm dependency.
	deps: {
		alwaysBundle: ['kdbxweb', 'parse5', 'entities', 'tldts', 'tldts-core'],
		onlyBundle: ['kdbxweb', 'parse5', 'entities', 'tldts', 'tldts-core'],
	},
	plugins: [compactTables()],
});
