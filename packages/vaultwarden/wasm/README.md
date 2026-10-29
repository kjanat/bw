# Password-strength WASM

The SDK compiles the [zxcvbn Rust crate](https://crates.io/crates/zxcvbn) to
`wasm32-unknown-unknown`. The wrapper exports only a strength score from 0 to 4;
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

`build.ts` compiles with size optimization and link-time optimization, generates
bindings using the wasm-bindgen version pinned in `mise.toml` and `Cargo.toml`,
and compresses the binary with Brotli. Generated bindings and the compressed
asset are ignored by Git and included in the Turbo build cache. tsdown bundles
the bindings and copies the compressed asset and Rust dependency license texts
into `dist`. No Rust compiler or build scripts are needed by npm consumers.

The synchronous TypeScript adapter reads, decompresses, and initializes the local
asset once, on the first score request. It never fetches a module over the network.
Username tokenization and the 100-Unicode-scalar cap remain in `reports.ts`.
Tests cover all five score levels, username context isolation, Unicode, and offline
reports. The installed-package smoke test exercises the shipped asset under Node
and Bun, independently of source files and build tools.
