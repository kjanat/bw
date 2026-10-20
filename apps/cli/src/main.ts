#!/usr/bin/env node
import { createApp } from '#app';
try {
	await createApp().run();
} catch (error) {
	console.error(error instanceof Error ? error.message : 'Command failed.');
	process.exitCode = 1;
}
