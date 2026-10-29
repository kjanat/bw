import { defineConfig } from 'tsdown';

export default defineConfig({
	entry: ['src/index.ts', 'src/kdbx-worker.ts'],
	platform: 'node',
	dts: true,
	minify: true,
	sourcemap: false,
	exports: true,
	copy: [
		{ from: 'src/generated/*.wasm.br', to: 'dist/generated' },
		'wasm/THIRD_PARTY_NOTICES.txt',
	],
	// Ship the patched decoder rather than reinstalling the unpatched npm dependency.
	deps: { alwaysBundle: ['kdbxweb'], onlyBundle: ['kdbxweb'] },
});
