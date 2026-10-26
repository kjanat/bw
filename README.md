# Vaultwarden CLI

An independent TypeScript client built for Vaultwarden, with a reusable library
and a command-line frontend built on `@kjanat/dreamcli`.

- `packages/vaultwarden` — authentication, protocol, cryptography, vault management, generation, and transfers.
- `apps/cli` — the `vw` executable, encrypted local cache, and unlock sessions.
- `packages/typescript-config` — shared compiler settings.

Requires Bun for dependency management and tests, and Node.js 24.8.0+ for the compiled CLI.

```sh
bun install
bun run build
node apps/cli/dist/main.js --help
```

```sh
node apps/cli/dist/main.js config server https://vault.example.com
export VW_SESSION="$(node apps/cli/dist/main.js login you@example.com --raw)"
node apps/cli/dist/main.js list items
node apps/cli/dist/main.js lock
unset VW_SESSION
```

Development checks:

```sh
bun run check-types
bun run lint
bun run test
bun run format
```

Formatting uses the project's dprint configuration.

Run the managed disposable-server checks with Docker, OpenSSH and
`envctl` installed:

```sh
VW_TEST_BW=/absolute/path/to/bw bun run test:compat
VW_TEST_VERSION=1.36.0 bun run test:compat
```

The current-server comparison requires independent `bw` 2026.10.0. The older
server runs our protocol checks; that reference CLI cannot parse its prelogin
response. The runner uses immutable images, creates an ephemeral loopback server,
and removes it afterward. CI's planner combines the pinned baseline servers with
the latest stable Vaultwarden release, deduplicates versions, resolves any new
release to an image digest, and emits the JSON matrix for Node 24/26.

See the [usage guide](docs/README.md) and [compatibility contract](docs/compatibility.md)
for supported commands, real-server tests, and remaining work. The implementation is in progress against the full CLI scope;
[implementation status](docs/implementation-status.md) records completed behavior and outstanding work.
The [Vaultwarden accommodations inventory](docs/vaultwarden-deviations.md) explains
intentional differences from Bitwarden and the production rules that select them.
