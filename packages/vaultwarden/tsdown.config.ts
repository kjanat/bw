import { defineConfig } from 'tsdown';

export default defineConfig({
	entry: ['src/index.ts', 'src/kdbx-worker.ts'],
	platform: 'node',
	dts: true,
	exports: true,
	copy: ['src/password-strength.wasm.br', 'wasm/THIRD_PARTY_NOTICES.txt'],
	// Ship the patched decoder rather than reinstalling the unpatched npm dependency.
	deps: { alwaysBundle: ['kdbxweb'], onlyBundle: ['kdbxweb'] },
});
