# WASIp2 password-strength experiment

This directory preserves the experiment that led to the SDK's WASIp2 backend.
The original `wasm32-unknown-unknown` wrapper is retained in `core-wasm/` so the
comparison remains reproducible. The tables below describe the historical
prototype builds, not the current release artifact. See the
[production build](../../packages/vaultwarden/wasm/README.md) for current behavior.

## What changes

`wit/password-strength.wit` defines a synchronous `score(string, list<string>) -> u8`
export. A Rust 2024 wrapper implements it with `wit-bindgen` and zxcvbn 3.1.1.
Rust 1.99.1 compiles it directly to a WASIp2 component. Jco 1.40.0 produces
JavaScript bindings, TypeScript declarations, and three core WASM modules for
JavaScript hosts. No Wasmtime or general WASI shim ships in the runtime payload.

`p2.mjs` lazily reads and decompresses the three local assets, then synchronously
instantiates and caches the component. `host.mjs` supplies its WASI imports:

- Monotonic and wall clocks use the host clock APIs.
- The hash-map seed uses two random 64-bit values from Node's crypto API.
- Environment reads return an empty list.
- Standard I/O, polling, terminal access, and exit operations trap if requested.
- The component imports no filesystem or network interface.

The component declares 16 interface imports because Rust's standard library
retains diagnostics and related plumbing. Across the 258-case correctness corpus,
actual calls were 514 monotonic-clock reads, one wall-clock read, and one seed
request. The restricted host succeeds without the general `preview2-shim` package.
It is specific to this scorer and is not a complete WASI implementation.

The standalone component remains available at `dist/password-strength.component.wasm`.
The same artifact passed eight direct invocations in Wasmtime 50.0.0, covering
all five score levels, empty input, username context, and Unicode. This runs the
component independently of the npm-specific transpiled output, without rebuilding:

```sh
wasmtime run --invoke 'score("password", [])' experiments/wasip2/dist/password-strength.component.wasm
# 0
wasmtime run --invoke 'score("asdfjkhkjwer!", ["asdfjkhkjwer"])' experiments/wasip2/dist/password-strength.component.wasm
# 1
```

## The upstream wrinkle

Unmodified zxcvbn treats every `wasm32` target as a JavaScript host. The first
P2 build compiled but panicked at its imported JavaScript performance object.
Enabling `custom_wasm_env` instead left a raw `zxcvbn` clock import which the
component linker could not resolve, even with a same-named Rust definition.

`zxcvbn-wasi.patch` narrows the JavaScript target checks to exclude WASI.
WASI then uses the crate's existing native `Instant` and UTC reference-year paths.
It changes platform selection, not the scoring algorithm or dictionaries.
The build downloads the exact published crate, verifies its crates.io SHA-256,
and applies the patch to an ignored local vendor directory. The production crate
and Cargo cache sources are not modified.

One semantic difference identified during the experiment: the native path uses
the UTC year, whereas the JavaScript path uses the local year. They can disagree
near New Year; the corpus verifies matching scores at the test date, not every
timezone/year boundary. The production implementation explicitly adopts UTC
and adds regression tests across the boundary and multiple host timezones.

## Reproduce

From the repository root, with the normal mise tools installed:

```sh
rustup target add --toolchain 1.99.1 wasm32-wasip2 wasm32-unknown-unknown
bun install --cwd experiments/wasip2 --frozen-lockfile --ignore-scripts
bun run --cwd experiments/wasip2 build
bun run --cwd experiments/wasip2 test
bun run --cwd experiments/wasip2 benchmark
bun run build
bun run --cwd experiments/wasip2 test:sdk
```

The build requires `cargo`, `wasm-bindgen` 0.2.129, Node, Bun, `tar`, and `patch`.
Both Rust variants use compiler 1.99.1, size optimization, LTO, one codegen unit,
and aborting panics. Both JavaScript adapters are bundled/minified with Bun, and
both sets of WASM assets use Brotli quality 11. Generated files and Rust build
outputs are ignored; the Cargo and Bun lockfiles are retained.

`verify-sdk.mjs` copies the current SDK into an isolated workspace, substitutes
the P2 adapter, builds the SDK with declarations, and runs the nine existing
report tests. It packs that SDK and the existing CLI, installs those archives,
and runs the repository's consumer smoke tests under Node and Bun. Pass
`baseline` to test the comparison backend through the identical packaging path:

```sh
node experiments/wasip2/verify-sdk.mjs baseline
```

The optional second argument selects final SDK minification. Both modes retain
TypeScript declarations; `minified` retains source maps, while
`minified-no-maps` disables JavaScript and declaration maps in the isolated build:

```sh
node experiments/wasip2/verify-sdk.mjs baseline minified
node experiments/wasip2/verify-sdk.mjs p2 minified
node experiments/wasip2/verify-sdk.mjs baseline minified-no-maps
node experiments/wasip2/verify-sdk.mjs p2 minified-no-maps
```

These temporary archives are test artifacts, not release candidates. In
particular, the integration fixture reuses the existing SDK notices; a production
migration must generate notices for the added component-toolchain dependencies.

The original consumer smoke results below predate an explicit SDK override in
the installation fixture: the CLI could resolve a published SDK of the same
version. Those historical success flags alone do not establish which SDK was
executed. Package-size measurements and direct backend/report tests are
unaffected. The corrected verifier forces the local SDK archive throughout the
dependency tree; production consumer checks also assert lazy WASM compilation.

## Measurements

Recorded on 2026-10-29, Linux ARM64, Node 26.7.0 and Bun 1.4.4. See
`measurements.json` for exact values. Sizes below use decimal units.

| Measurement                                     | Original core-WASM backend | WASIp2 prototype |
| ----------------------------------------------- | -------------------------: | ---------------: |
| Runtime JS and compressed WASM assets           |                   637.2 KB |         762.4 KB |
| Sum of gzip-compressed runtime files            |                   634.9 KB |         672.3 KB |
| Complete SDK tarball                            |            1,131,712 bytes |  1,213,090 bytes |
| Complete SDK unpacked                           |            2,976,197 bytes |  3,358,159 bytes |
| Node module import                              |                    5.55 ms |         13.01 ms |
| Node first score, including WASM initialization |                  116.21 ms |        109.34 ms |
| Node warm score                                 |                   0.558 ms |         0.671 ms |
| Bun module import                               |                    8.03 ms |         10.11 ms |
| Bun first score, including WASM initialization  |                   94.81 ms |        105.13 ms |
| Bun warm score                                  |                   0.605 ms |         0.675 ms |

The complete SDK download grows by 81,378 bytes (7.2%). Most additional runtime
code is Jco's generated JavaScript: 115,138 bytes versus 2,901 bytes for the
baseline adapter/bindings. SDK source maps and unminified build output also
contribute to the package increase.

### Final tsdown minification

The SDK already passes the generated bindings through tsdown. Enabling
`minify: true` there keeps the final bundle minified, including the rest of the
SDK and its KDBX worker. Pre-minifying the adapters with Bun alone does not keep
the final tsdown output minified.

| Complete SDK tarball          | Core-WASM backend | WASIp2 prototype |
| ----------------------------- | ----------------: | ---------------: |
| Existing build, maps retained |   1,131,712 bytes |  1,213,090 bytes |
| Minified, maps retained       |   1,136,089 bytes |  1,214,512 bytes |
| Minified, no maps             |     795,303 bytes |    830,400 bytes |

Minification with maps reduces unpacked WASIp2 size from 3,358,159 to 3,053,252
bytes, but the npm tarball grows slightly. Without maps it is 1,377,652 bytes
unpacked and 830,400 bytes packed: a 31.5% download reduction from the existing
P2 build. P2's packed overhead relative to the equivalently minified core backend
is then 35,097 bytes (4.4%).

The shared TypeScript config enables `declarationMap`, which also enables
tsdown's JavaScript source maps. Those JS maps can help debug the generated glue
and original SDK sources; they do not map the WASM back to Rust. Removing them
trades that debugging support for smaller packages. It does not remove types:
both builds still ship approximately 39 KB of `.d.mts` declarations. WASM assets
are unchanged by JavaScript minification and remain separately Brotli-compressed.

All four minification builds passed the nine report tests and installed SDK/CLI
consumer checks under Node and Bun. These options are confined to the experiment;
these historical measurements predate their adoption in the normal SDK build.

### Binaryen wasm-opt

`optimize.mjs` uses Binaryen 133, pinned in the root `mise.toml` using the same
GitHub backend configuration as Statute. Run it after the experiment build:

```sh
bun run --cwd experiments/wasip2 optimize
node experiments/wasip2/verify-sdk.mjs baseline minified-no-maps Os
node experiments/wasip2/verify-sdk.mjs p2 minified-no-maps Oz-converge
```

The pipeline is Rust → wasm-bindgen/Jco → wasm-opt → Brotli. For P2, optimization
runs on Jco's three extracted core modules; the standalone component artifact
is unchanged. The JavaScript bindings and declarations are copied unchanged.
Outputs are isolated under `dist/wasm-opt/<profile>/`, preserving the original
comparison builds.

Each profile enables bulk memory and reference types for the existing Rust/Jco
instructions, and strips debug and producer sections. No assumptions about
traps or a closed world are added. The script checks that exports are preserved,
no host imports are added, and all 258 cases match the unoptimized reference
under Node and Bun, including lazy initialization and instance reuse.

| WASM assets, Brotli quality 11 | Core-WASM backend | WASIp2 prototype |
| ------------------------------ | ----------------: | ---------------: |
| Before wasm-opt                |     634,259 bytes |    647,274 bytes |
| `-Os`                          |     632,853 bytes |    639,569 bytes |
| `-Oz`                          |     633,317 bytes |    641,902 bytes |
| `-Oz --converge`               |     633,357 bytes |    639,078 bytes |

Smallest raw output does not imply smallest compressed output: core WASM favors
`-Os`, while P2 favors `-Oz --converge` here. P2's combined raw modules shrink from
2,059,072 to 1,897,251 bytes (7.9%), but their Brotli payload shrinks only 1.3%.
Before optimization, the main P2 module has a 1,174,079-byte data section and an
879,211-byte code section; code optimization leaves substantial static data.

With final JS minification and no maps, the complete core SDK tarball changes
from 795,303 to 794,548 bytes with `-Os`. P2 changes from 830,400 to 822,348 bytes
with `-Oz --converge`, saving 8,052 bytes (1.0%). P2 with `-Os` is 822,856 bytes.
All three packaged candidates passed the nine report tests and installed SDK/CLI
smoke checks under Node and Bun. These are size and correctness results; runtime
timings in the table above were measured before wasm-opt and have not been rerun.
The production SDK now uses the converged `-Oz` pipeline as well.

Timings are medians of five fresh processes per variant and runtime, alternating
variant order. Warm timings average 512 calls after 64 warmup calls. These are
local observations, not statistically established performance guarantees. The
runtime-only gzip measurement sums individual files; it is not an npm tarball
measurement. Runtime-only sizes exclude types and notices. The complete SDK
figures include the normal package files and the fixture's notices.

Verification passed:

- 258 synthetic cases match under both Node and Bun, including empty input,
  context isolation, dates, Unicode, malformed UTF-16, and the 100-character cap.
- Module import performs no WASM compilation; repeated score calls reuse the instance.
- The existing nine SDK report tests pass with each backend.
- Eight standalone component invocations pass in Wasmtime 50.0.0.
- Installed SDK/CLI smoke tests pass with each backend under both runtimes:
  scoring, offline reports, executable version commands, crypto, KDBX workers,
  login, and sync.

This makes P2 a practical portability option at a measured size/performance cost.
The production migration applies the verified platform patch, documents and
tests UTC year semantics, and generates the added dependency notices. The
existing consumer CI matrix covers Node versions and architectures; the
measurements here remain local Linux ARM64 results.

References: [Rust components](https://component-model.bytecodealliance.org/language-support/building-a-simple-component/rust.html),
[Jco transpilation and synchronous instantiation](https://bytecodealliance.github.io/jco/transpiling.html),
[tsdown minification](https://tsdown.dev/options/minification),
[tsdown source maps](https://tsdown.dev/options/sourcemap),
[Binaryen optimization options](https://github.com/WebAssembly/binaryen/blob/version_133/src/tools/optimization-options.h).
