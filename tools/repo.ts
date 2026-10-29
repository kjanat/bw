#!/usr/bin/env bun
import { cli, command, group, arg, flag } from '@kjanat/dreamcli';
import { createAdapter } from '@kjanat/dreamcli/runtime';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { repoRoot, resolveWasmOpt } from './runtime.mjs';

const wasmOptFlag = () =>
	flag.string({ nonEmpty: true })
		.describe('Binaryen 133 executable; defaults to the mise pin, then PATH');
const cargoHomeFlag = () => flag.path({ type: 'directory' }).describe('Cargo registry/cache directory');
const runtimeFlag = () => flag.enum(['node', 'bun', 'both']).default('both').describe('JavaScript runtime(s)');
const measurementRuntimeFlag = () =>
	flag.enum(['node', 'bun']).default('node')
		.describe('Runtime/compressor for size measurements; original results use Node');
const runtimes = (runtime: 'node' | 'bun' | 'both'): ('node' | 'bun')[] =>
	runtime === 'both' ? ['node', 'bun'] : [runtime];
function runScript(runtime: string, script: string, args: string[] = []) {
	execFileSync(runtime, [resolve(repoRoot, script), ...args], { cwd: repoRoot, stdio: 'inherit' });
}

export function createRepoCLI(direct: Record<string, unknown> = {}) {
	// A directly executed module is still evaluating its main guard. Reuse its
	// exported operation instead of awaiting an import of that same module.
	async function load<T>(path: string, importer: () => Promise<T>): Promise<T> {
		const supplied = direct[new URL(path, import.meta.url).href];
		return supplied === undefined ? importer() : supplied as T;
	}
	const sizes = group('sizes').description('Compare HTML parser and public suffix implementations')
		.command(
			command('build').description('Build and measure the JavaScript and WASIp2 candidates')
				.flag('wasm-opt', wasmOptFlag()).flag('cargo-home', cargoHomeFlag())
				.flag('runtime', measurementRuntimeFlag())
				.flag('js-only', flag.boolean().describe('Measure JavaScript candidates without Rust or Binaryen'))
				.action(async ({ flags }) => {
					if (flags.runtime !== (process.versions.bun ? 'bun' : 'node')) {
						const args = ['--runtime', flags.runtime];
						if (flags['js-only']) args.push('--js-only');
						if (flags['wasm-opt']) args.push('--wasm-opt', resolveWasmOpt(flags['wasm-opt']));
						if (flags['cargo-home']) args.push('--cargo-home', resolve(flags['cargo-home']));
						runScript(flags.runtime, 'experiments/dependency-size/build.mjs', args);
						return;
					}
					if (flags['js-only']) {
						return (await load(
							'../experiments/dependency-size/probe.mjs',
							() => import('../experiments/dependency-size/probe.mjs'),
						)).probeJavaScript();
					}
					await (await load(
						'../experiments/dependency-size/build.mjs',
						() => import('../experiments/dependency-size/build.mjs'),
					)).buildDependencySize({
						wasmOpt: resolveWasmOpt(flags['wasm-opt']),
						cargoHome: flags['cargo-home'] ? resolve(flags['cargo-home']) : undefined,
					});
				}),
		)
		.command(
			command('wasm').description('Transpile, optimize and measure already-built components')
				.flag('wasm-opt', wasmOptFlag())
				.flag('runtime', measurementRuntimeFlag())
				.action(async ({ flags }) => {
					if (flags.runtime !== (process.versions.bun ? 'bun' : 'node')) {
						runScript(flags.runtime, 'experiments/dependency-size/wasm.mjs', [
							'--runtime',
							flags.runtime,
							'--wasm-opt',
							resolveWasmOpt(flags['wasm-opt']),
						]);
						return;
					}
					return (
						(await load(
							'../experiments/dependency-size/wasm.mjs',
							() => import('../experiments/dependency-size/wasm.mjs'),
						))
							.measureWasm({ wasmOpt: resolveWasmOpt(flags['wasm-opt']) })
					);
				}),
		)
		.command(
			command('test').description('Run compatibility cases and compare recorded findings')
				.flag('runtime', runtimeFlag())
				.action(async ({ flags }) => {
					for (const runtime of runtimes(flags.runtime)) runScript(runtime, 'experiments/dependency-size/parity.mjs');
					await (await load(
						'../experiments/dependency-size/verify-recorded.mjs',
						() => import('../experiments/dependency-size/verify-recorded.mjs'),
					))
						.verifyRecorded(runtimes(flags.runtime));
				}),
		)
		.command(
			command('parity').description('Run the corpus in the current process runtime')
				.action(async () =>
					(await load(
						'../experiments/dependency-size/parity.mjs',
						() => import('../experiments/dependency-size/parity.mjs'),
					)).checkParity()
				),
		)
		.command(
			command('verify-recorded').description('Compare fresh Node/Bun reports with recorded results')
				.action(async () =>
					(await load(
						'../experiments/dependency-size/verify-recorded.mjs',
						() => import('../experiments/dependency-size/verify-recorded.mjs'),
					)).verifyRecorded()
				),
		);

	const wasip2 = group('wasip2').description('Compare password-scoring WASM implementations')
		.command(
			command('build').description('Build the baseline and WASIp2 scorers')
				.action(async () =>
					(await load('../experiments/wasip2/build.mjs', () => import('../experiments/wasip2/build.mjs')))
						.buildScorers()
				),
		)
		.command(
			command('optimize').description('Compare Binaryen optimization profiles')
				.flag('wasm-opt', wasmOptFlag())
				.action(async ({ flags }) =>
					(await load('../experiments/wasip2/optimize.mjs', () => import('../experiments/wasip2/optimize.mjs')))
						.optimizeScorers({ wasmOpt: resolveWasmOpt(flags['wasm-opt']) })
				),
		)
		.command(
			command('benchmark').description('Benchmark import, cold scoring and warm scoring')
				.action(async () =>
					(await load('../experiments/wasip2/benchmark.mjs', () => import('../experiments/wasip2/benchmark.mjs')))
						.benchmarkScorers()
				),
		)
		.command(
			command('benchmark-worker').description('Measure a single scorer in the current runtime')
				.flag('variant', flag.enum(['baseline', 'p2']).required())
				.action(async ({ flags }) =>
					(await load(
						'../experiments/wasip2/benchmark-worker.mjs',
						() => import('../experiments/wasip2/benchmark-worker.mjs'),
					))
						.benchmarkWorker(flags.variant)
				),
		)
		.command(
			command('verify').description('Check scorer parity and lazy initialization in this runtime')
				.flag(
					'distribution',
					flag.string({ nonEmpty: true }).default('dist').describe('Directory relative to the experiment'),
				)
				.action(async ({ flags }) =>
					(await load('../experiments/wasip2/verify.mjs', () => import('../experiments/wasip2/verify.mjs')))
						.verifyScorers(flags.distribution)
				),
		)
		.command(
			command('test').description('Verify scorers with Node and Bun')
				.flag('runtime', runtimeFlag())
				.flag('distribution', flag.string({ nonEmpty: true }).default('dist'))
				.action(({ flags }) => {
					for (const runtime of runtimes(flags.runtime)) {
						runScript(runtime, 'experiments/wasip2/verify.mjs', ['--distribution', flags.distribution]);
					}
				}),
		)
		.command(
			command('verify-sdk').description('Test an alternate scorer through packed SDK and CLI installations')
				.flag('variant', flag.enum(['baseline', 'p2']).default('p2'))
				.flag('mode', flag.enum(['default', 'minified', 'minified-no-maps']).default('default'))
				.flag('optimization', flag.enum(['none', 'Os', 'Oz', 'Oz-converge']).default('none'))
				.action(async ({ flags }) =>
					(await load('../experiments/wasip2/verify-sdk.mjs', () => import('../experiments/wasip2/verify-sdk.mjs')))
						.verifySdk(flags)
				),
		);

	const release = group('release').description('Pack and verify release archives')
		.command(
			command('pack').description('Pack a public workspace and write its SHA-256 checksum')
				.arg('package', arg.enum(['vaultwarden', 'cli']))
				.action(async ({ args }) =>
					(await load('../.github/release/pack.ts', () => import('../.github/release/pack.ts'))).packRelease(
						args.package,
					)
				),
		)
		.command(
			command('verify').description('Verify isolated installations of archives or published previews')
				.flag('runtime', runtimeFlag())
				.flag('preview-metadata', flag.path({ type: 'file' }).describe('Preview publication metadata'))
				.action(async ({ flags }) => {
					const metadata = flags['preview-metadata'] ? resolve(flags['preview-metadata']) : undefined;
					for (const runtime of runtimes(flags.runtime)) {
						await (await load('../.github/release/verify.ts', () => import('../.github/release/verify.ts')))
							.verifyRelease(runtime, metadata);
					}
				}),
		)
		.command(
			command('preview').description('Download preview archives and verify their published hashes')
				.flag('metadata', flag.path({ type: 'file' }).default(resolve(repoRoot, 'artifacts/preview.json')))
				.action(async ({ flags }) =>
					(await load('../.github/release/preview.ts', () => import('../.github/release/preview.ts'))).fetchPreview(
						resolve(flags.metadata),
					)
				),
		);

	return cli('vw-repo').description('Builds, experiments and release tooling for the vw repository')
		.builtins({ json: 'off', quiet: 'off' })
		.command(group('experiment').description('Reproducible implementation comparisons').command(sizes).command(wasip2))
		.command(
			group('wasm').description('Production password-scoring component')
				.command(
					command('build').description('Build and optimize the SDK WASIp2 scorer')
						.flag('wasm-opt', wasmOptFlag())
						.action(async ({ flags }) =>
							(await load(
								'../packages/vaultwarden/wasm/build.ts',
								() => import('../packages/vaultwarden/wasm/build.ts'),
							))
								.buildPasswordStrength({ wasmOpt: resolveWasmOpt(flags['wasm-opt']) })
						),
				),
		)
		.command(release)
		.command(
			group('compat').description('Disposable Vaultwarden compatibility runs')
				.command(
					command('plan').description('Discover supported server images and print the CI matrix')
						.action(async () =>
							(await load(
								'../apps/cli/test/plan-compatibility.ts',
								() => import('../apps/cli/test/plan-compatibility.ts'),
							)).planCompatibilityMatrix()
						),
				)
				.command(
					command('run').description('Run the managed compatibility suite in disposable containers')
						.flag('server-version', flag.string({ pattern: /^\d+\.\d+\.\d+$/ }).default('1.37.4'))
						.flag('image', flag.string({ nonEmpty: true }).describe('Immutable Vaultwarden image override'))
						.flag('reference', flag.path({ type: 'file' }).describe('Independent Bitwarden CLI executable'))
						.flag('reference-version', flag.string({ pattern: /^\d+\.\d+\.\d+$/ }))
						.flag('protocol-only', flag.boolean().describe('Run without reference CLI comparisons'))
						.flag('smtp', flag.boolean().describe('Exercise delivered email codes with Mailpit'))
						.flag('sso', flag.boolean().describe('Exercise OIDC SSO'))
						.flag('case', flag.string({ nonEmpty: true }).describe('Test name pattern'))
						.flag('import-format', flag.string({ nonEmpty: true }))
						.flag('import-shard', flag.string({ pattern: /^\d+\/[1-9]\d*$/ }))
						.flag('skip-imports', flag.boolean())
						.flag('focused-import', flag.boolean())
						.flag('list-filters-only', flag.boolean())
						.flag('policy-redaction-only', flag.boolean())
						.derive(({ flags }) => {
							if (flags.smtp && flags.sso) throw new Error('--smtp and --sso are mutually exclusive');
							if (flags['import-shard']) {
								const [index, count] = flags['import-shard'].split('/').map(Number);
								if (index! >= count!) throw new Error('--import-shard index must be smaller than its count');
							}
							return {};
						})
						.action(async ({ flags, out }) => {
							execFileSync('bun', ['run', 'build'], { cwd: repoRoot, stdio: 'inherit' });
							const code = await (await load('../apps/cli/test/run-compatibility.ts', () =>
								import('../apps/cli/test/run-compatibility.ts'))).runCompatibility({
									version: flags['server-version'],
									image: flags.image,
									reference: flags.reference ? resolve(flags.reference) : undefined,
									referenceVersion: flags['reference-version'],
									protocolOnly: flags['protocol-only'],
									smtp: flags.smtp,
									sso: flags.sso,
									testCase: flags.case,
									importFormat: flags['import-format'],
									importShard: flags['import-shard'],
									skipImports: flags['skip-imports'],
									focusedImport: flags['focused-import'],
									listFiltersOnly: flags['list-filters-only'],
									policyRedactionOnly: flags['policy-redaction-only'],
								});
							out.setExitCode(code);
						}),
				),
		)
		.completions();
}

export async function runRepo(prefix: string[] = [], direct: Record<string, unknown> = {}) {
	const adapter = createAdapter();
	await createRepoCLI(direct).run({
		adapter: { ...adapter, argv: [...adapter.argv.slice(0, 2), ...prefix, ...adapter.argv.slice(2)] },
	});
}

if (import.meta.main) await runRepo();
