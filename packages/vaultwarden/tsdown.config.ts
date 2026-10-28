import { defineConfig } from 'tsdown';

export default defineConfig({
	entry: ['src/index.ts', 'src/kdbx-worker.ts'],
	platform: 'node',
	dts: true,
	exports: true,
	// Ship the patched decoder rather than reinstalling the unpatched npm dependency.
	deps: { alwaysBundle: ['kdbxweb'], onlyBundle: ['kdbxweb'] },
});
