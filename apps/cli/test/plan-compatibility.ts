#!/usr/bin/env bun
import { appendFile } from 'node:fs/promises';
import {
	planCompatibility,
	resolveReleaseImage,
	discoverReferenceVersions,
	type CompatibilityTargets,
	type CompatibilityMode,
} from '#test/compatibility-plan';
import { runDirect } from '../../../tools/runtime.mjs';

export async function planCompatibilityMatrix(mode: CompatibilityMode = 'full') {
	const targets = await Bun.file(new URL('./fixtures/compatibility-targets.json', import.meta.url))
		.json() as CompatibilityTargets;
	async function runCrane(args: string[]): Promise<string> {
		const query = Bun.spawn(['crane', ...args], { stdout: 'pipe', stderr: 'pipe', timeout: 60000 });
		const [code, stdout, stderr] = await Promise.all([
			query.exited,
			new Response(query.stdout).text(),
			new Response(query.stderr).text(),
		]);
		if (code !== 0) throw new Error(`crane ${args[0]} failed: ${stderr.trim()}`);
		return stdout;
	}
	const [tagOutput, referenceVersions] = await Promise.all([
		runCrane(['ls', 'vaultwarden/server', '-O']),
		discoverReferenceVersions(),
	]);
	const tags = tagOutput.split(/\r?\n/).map(tag => tag.trim()).filter(Boolean);
	const plan = await planCompatibility(
		targets,
		tags,
		referenceVersions,
		version => resolveReleaseImage(version, runCrane),
		mode,
	);
	if (process.env.GITHUB_OUTPUT) {
		await appendFile(
			process.env.GITHUB_OUTPUT,
			`matrix=${JSON.stringify(plan.matrix)}\nservers=${JSON.stringify(plan.servers)}\n`,
		);
	}

	if (process.env.GITHUB_STEP_SUMMARY) {
		await appendFile(
			process.env.GITHUB_STEP_SUMMARY,
			[
				`### Vaultwarden compatibility: ${mode}`,
				'',
				'| Server | Node | Immutable image | Reference comparison |',
				'| --- | --- | --- | --- |',
				...plan.matrix.include.map(row =>
					`| ${row.server} | ${row.node} | \`${row.image}\` | ${`bw ${row.referenceCliVersion}${
						row.expectedFailure ? ` (known: ${row.expectedFailure}; must reproduce under both KDFs)` : ''
					}`} |`
				),
				'',
			].join('\n'),
		);
	}
	console.log(JSON.stringify(plan));
	return plan;
}

if (import.meta.main) await runDirect(['compat', 'plan'], import.meta.url, { planCompatibilityMatrix });
