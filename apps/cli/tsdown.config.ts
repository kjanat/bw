import { defineConfig } from 'tsdown';

export default defineConfig({
	entry: ['src/main.ts'],
	platform: 'node',
	dts: false,
	exports: { bin: { vw: './src/main.ts' } },
});
