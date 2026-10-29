# Contributing

## Setup

Install [mise](https://mise.jdx.dev/), then run:

```sh
mise install
bun install --frozen-lockfile
bun run build
```

The SDK build compiles its password-strength estimator from Rust to WebAssembly. `mise install` provides the pinned Rust toolchain, WASM target, and matching wasm-bindgen CLI. npm consumers use the prebuilt asset and need no Rust tools. See [WASM build details](packages/vaultwarden/wasm/README.md).

## Packages

- `packages/vaultwarden` — the SDK.
- `apps/cli` — the `vw` command.
- `packages/typescript-config` — shared compiler settings.

## Build and checks

```sh
bun run build
bun run typecheck
bun run lint
bun run test
bun run format
```

## Compatibility tests

Requires Docker, OpenSSH and `envctl`. For comparison with the Bitwarden CLI, set `VW_TEST_BW` to its executable. Use the version specified in [compatibility-targets.json](apps/cli/test/fixtures/compatibility-targets.json).

```sh
VW_TEST_BW=/absolute/path/to/bw bun run test:compat
VW_TEST_VERSION=1.36.0 bun run test:compat
```

See [implementation status](docs/implementation-status.md) and [Vaultwarden compatibility notes](docs/vaultwarden-deviations.md).
