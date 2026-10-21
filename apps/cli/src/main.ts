#!/usr/bin/env node
import { createApp } from '#app';
import { normalizeSsoArguments } from '#sso-login';
import { createAdapter } from '@kjanat/dreamcli/runtime';
import { withOutputPolicy } from '#output';

for (
	const [vwName, bwName] of [
		['VW_SESSION', 'BW_SESSION'],
		['VW_PASSWORD', 'BW_PASSWORD'],
		['VW_EMAIL', 'BW_EMAIL'],
		['VW_2FA_TOKEN', 'BW_2FA_TOKEN'],
		['VW_CLIENTID', 'BW_CLIENTID'],
		['VW_CLIENTSECRET', 'BW_CLIENTSECRET'],
		['VW_IMPORT_PASSWORD', 'BW_IMPORT_PASSWORD'],
		['VW_EXPORT_PASSWORD', 'BW_EXPORT_PASSWORD'],
		['VW_PRETTY', 'BW_PRETTY'],
		['VW_QUIET', 'BW_QUIET'],
		['VW_NOINTERACTION', 'BW_NOINTERACTION'],
		['VW_CLEANEXIT', 'BW_CLEANEXIT'],
		['VW_RESPONSE', 'BW_RESPONSE'],
	] as const
) {
	if (process.env[vwName] === undefined && process.env[bwName] !== undefined) {
		process.env[vwName] = process.env[bwName];
	}
}

function cleanExitArguments(argv: readonly string[]): { argv: string[]; enabled: boolean } {
	const result: string[] = [];
	let enabled = Boolean(process.env.VW_CLEANEXIT);
	let afterSeparator = false;
	for (const token of argv) {
		if (token === '--') afterSeparator = true;
		if (!afterSeparator && token === '--cleanexit') {
			enabled = true;
			continue;
		}
		if (!afterSeparator && token === '--cleanexit=true') {
			enabled = true;
			continue;
		}
		if (!afterSeparator && token === '--cleanexit=false') {
			enabled = false;
			continue;
		}
		result.push(token);
	}
	return { argv: result, enabled };
}

function responseArguments(argv: readonly string[]): { argv: string[]; enabled: boolean } {
	const result: string[] = [];
	let enabled = process.env.VW_RESPONSE === 'true';
	let afterSeparator = false;
	for (const token of argv) {
		if (token === '--') afterSeparator = true;
		if (!afterSeparator && token === '--response') {
			enabled = true;
			continue;
		}
		if (!afterSeparator && token === '--response=true') {
			enabled = true;
			continue;
		}
		if (!afterSeparator && token === '--response=false') {
			enabled = false;
			continue;
		}
		result.push(token);
	}
	return { argv: result, enabled };
}

let cleanExit = Boolean(process.env.VW_CLEANEXIT);
try {
	const adapter = createAdapter();
	const app = createApp();
	const parsed = cleanExitArguments(adapter.argv.slice(2));
	const response = responseArguments(parsed.argv);
	cleanExit = parsed.enabled;
	const cliAdapter = {
		...adapter,
		argv: [...adapter.argv.slice(0, 2), ...normalizeSsoArguments(response.argv)],
		exit: (code: number) => adapter.exit(cleanExit ? 0 : code),
	};
	await withOutputPolicy(cliAdapter, adapter =>
		app.run({
			adapter,
			verbosity: process.env.VW_QUIET === 'true' ? 'quiet' : 'normal',
		}), response.enabled);
} catch (error) {
	console.error(error instanceof Error ? error.message : 'Command failed.');
	process.exitCode = cleanExit ? 0 : 1;
}
