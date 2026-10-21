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
		['VW_RAW', 'BW_RAW'],
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

function noInteractionArguments(argv: readonly string[]): { argv: string[]; enabled: boolean } {
	const result: string[] = [];
	let enabled = process.env.VW_NOINTERACTION === 'true';
	let afterSeparator = false;
	for (const token of argv) {
		if (token === '--') afterSeparator = true;
		if (!afterSeparator && token === '--nointeraction') {
			enabled = true;
			continue;
		}
		result.push(token);
	}
	return { argv: result, enabled };
}

/** DreamCLI scopes declared flags to commands; lift bw's global --session into env-backed command flags. */
function globalSessionArguments(argv: readonly string[]): { argv: string[]; session?: string } {
	const result: string[] = [];
	let session: string | undefined;
	for (let index = 0; index < argv.length; index++) {
		const token = argv[index]!;
		if (token === '--') {
			result.push(...argv.slice(index));
			break;
		}
		if (token === '--session') {
			const value = argv[index + 1];
			if (value === undefined || value === '--' || value.startsWith('-')) {
				result.push(token);
				continue;
			}
			session = value;
			index++;
		} else if (token.startsWith('--session=')) {
			const value = token.slice('--session='.length);
			if (value) session = value;
			else result.push(token);
		} else result.push(token);
	}
	return { argv: result, session };
}

function normalizeNegativeGeneratorValues(argv: readonly string[]): string[] {
	const result: string[] = [];
	for (let i = 0; i < argv.length; i++) {
		const token = argv[i]!;
		if (
			['--length', '--words'].includes(token)
			&& /^-\d+$/.test(argv[i + 1] ?? '')
		) {
			result.push(`${token}=${argv[++i]}`);
		} else result.push(token);
	}
	return result;
}

/** The reference CLI lowercases object names and IDs before command dispatch. */
function normalizeObjectArguments(argv: readonly string[]): string[] {
	const result = [...argv];
	const positions: Record<string, { object: number; id?: number }> = {
		list: { object: 1 },
		get: { object: 1, id: 2 },
		create: { object: 1 },
		edit: { object: 1, id: 2 },
		delete: { object: 1, id: 2 },
		restore: { object: 1, id: 2 },
		archive: { object: 1, id: 2 },
		confirm: { object: 1, id: 2 },
		report: { object: 1 },
	};
	for (let index = 0; index < result.length; index++) {
		const token = result[index]!;
		if (token === '--') return result;
		if (token.startsWith('-')) {
			if (token === '--session') index++;
			continue;
		}
		const positionsForCommand = positions[token];
		if (positionsForCommand) {
			const objectIndex = index + positionsForCommand.object;
			if (result[objectIndex] && !result[objectIndex]!.startsWith('-')) {
				result[objectIndex] = result[objectIndex]!.toLowerCase();
			}
			if (positionsForCommand.id !== undefined) {
				const idIndex = index + positionsForCommand.id;
				if (result[idIndex] && !result[idIndex]!.startsWith('-')) result[idIndex] = result[idIndex]!.toLowerCase();
			}
		}
		return result;
	}
	return result;
}

let cleanExit = Boolean(process.env.VW_CLEANEXIT);
try {
	const adapter = createAdapter();
	const app = createApp();
	const parsed = cleanExitArguments(adapter.argv.slice(2));
	const response = responseArguments(parsed.argv);
	const noInteraction = noInteractionArguments(response.argv);
	const globalSession = globalSessionArguments(noInteraction.argv);
	if (globalSession.session !== undefined) process.env.VW_SESSION = globalSession.session;
	cleanExit = parsed.enabled;
	if (noInteraction.enabled) process.env.VW_NOINTERACTION = 'true';
	const cliAdapter = {
		...adapter,
		argv: [
			...adapter.argv.slice(0, 2),
			...normalizeNegativeGeneratorValues(
				normalizeObjectArguments(normalizeSsoArguments(globalSession.argv)),
			),
		],
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
