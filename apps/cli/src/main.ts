#!/usr/bin/env node
import { createApp } from '#app';
import { normalizeSsoArguments } from '#sso-login';
import { createAdapter } from '@kjanat/dreamcli/runtime';
import { withOutputPolicy } from '#output';
try {
	const adapter = createAdapter();
	const app = createApp();
	await withOutputPolicy(adapter, adapter =>
		app.run({
			adapter: {
				...adapter,
				argv: [
					...adapter.argv.slice(0, 2),
					...normalizeSsoArguments(adapter.argv.slice(2)),
				],
			},
			verbosity: process.env.VW_QUIET === 'true' ? 'quiet' : 'normal',
		}));
} catch (error) {
	console.error(error instanceof Error ? error.message : 'Command failed.');
	process.exitCode = 1;
}
