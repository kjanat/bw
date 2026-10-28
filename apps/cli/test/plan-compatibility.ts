import { appendFile } from 'node:fs/promises';
import { planCompatibility, resolveReleaseImage, type CompatibilityTargets } from '#test/compatibility-plan';

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
const tags = (await runCrane(['ls', 'vaultwarden/server', '-O'])).split(/\r?\n/).map(tag => tag.trim()).filter(Boolean);
const matrix = await planCompatibility(targets, tags, version => resolveReleaseImage(version, runCrane));
const json = JSON.stringify(matrix);
if (process.env.GITHUB_OUTPUT) await appendFile(process.env.GITHUB_OUTPUT, `matrix=${json}\n`);
if (process.env.GITHUB_STEP_SUMMARY) {
	await appendFile(
		process.env.GITHUB_STEP_SUMMARY,
		[
			'### Vaultwarden compatibility plan',
			'',
			'| Server | Node | Immutable image | Reference comparison |',
			'| --- | --- | --- | --- |',
			...matrix.include.map(row =>
				`| ${row.server} | ${row.node} | \`${row.image}\` | ${
					row.reference ? `bw ${row.referenceCliVersion}` : 'disabled'
				} |`
			),
			'',
		].join('\n'),
	);
}
console.log(json);
