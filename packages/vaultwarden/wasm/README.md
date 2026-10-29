# Password-strength WASIp2 component

The SDK compiles the [zxcvbn Rust crate](https://crates.io/crates/zxcvbn) to
`wasm32-wasip2`. The WIT wrapper exports only a strength score from 0 to 4;
it does not serialize matches, feedback, or crack-time estimates. The crate's
default builder feature is disabled. `Cargo.lock` pins the full dependency graph.

From the repository root:

```sh
mise install
bun install --frozen-lockfile
bun run build
```

To rebuild only the WASM and bindings:

```sh
bun run --cwd packages/vaultwarden build:wasm
```

`build.ts` verifies the SHA-256 of the published zxcvbn 3.1.1 crate, extracts it
into an ignored vendor directory, and applies `zxcvbn-wasi.patch`. The patch
excludes WASI from the upstream assumption that every wasm32 target is a JS
host. It uses the crate's existing native clock and UTC-year implementations.
The shared Cargo registry source is never modified. The build needs `tar` and
`patch`; `mise install` supplies Rust 1.99.1 and Binaryen 133, while `bun install`
supplies Jco 1.40.0. wasm-bindgen remains installed only for the comparison
experiment's original core-WASM backend.

Rust uses size optimization and LTO. Jco generates synchronous JS bindings,
TypeScript declarations, and three core modules. Each core module passes through
`wasm-opt -Oz --converge`, with existing bulk-memory/reference-type features
enabled and debug/producer sections removed, then Brotli quality 11. Export
contracts and host imports are checked after optimization. The original WASIp2
component is retained at `target/wasm32-wasip2/release/vw_password_strength.wasm`.

Generated bindings and compressed assets are ignored by Git and included in the
Turbo cache. tsdown minifies the SDK and worker, retains `.d.mts` declarations,
and omits JavaScript/declaration source maps. It copies compressed modules to
`dist/generated` and dependency license texts to `dist/THIRD_PARTY_NOTICES.txt`.
Notices include locally patched zxcvbn, wit-bindgen and its dependencies, and
Jco's binding generator. npm consumers need no compiler or separate WASI runtime.

The synchronous TypeScript adapter reads, decompresses, and initializes the local
assets once, on the first score request. It never fetches a module over the network.
The typed host supplies monotonic and UTC wall clocks plus a random hash seed,
returns an empty environment, and traps unused I/O, polling and exit operations.
The component has no filesystem or network imports. The adapter reads only the
bundled modules; guest code does not receive that filesystem capability.

The reference year follows the crate's native UTC semantics and is initialized
once per instance when needed. Near New Year this may differ from the previous
JS-host backend's local year. Regression tests exercise a score threshold at
UTC midnight in UTC, Pacific/Kiritimati and America/Los_Angeles, including
instance reuse across midnight. This is an intentional, documented choice.
Username tokenization and the 100-Unicode-scalar cap remain in `reports.ts`.
Tests cover all five score levels, username context isolation, Unicode, and offline
reports. The installed-package smoke test checks lazy compilation and instance
reuse and exercises the shipped assets under Node
and Bun, independently of source files and build tools.

The local production migration produced an 823,608-byte SDK tarball, including
types and regenerated notices. Installed SDK/CLI checks passed on Linux ARM64
with Node 24.8.0, Node 26.7.0 and Bun 1.4.4. The package-test installer overrides
the CLI's SDK dependency with the built archive, preventing a published package
with the same version from satisfying that dependency. Preview verification
continues to exercise the SDK resolved from the published preview.
