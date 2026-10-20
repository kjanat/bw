# Vaultwarden CLI

An independent TypeScript client built for Vaultwarden, with a reusable library
and a command-line frontend built on `@kjanat/dreamcli`.

- `packages/vaultwarden` — authentication, protocol, cryptography, vault management, generation, and transfers.
- `apps/cli` — the `vw` executable, encrypted local cache, and unlock sessions.
- `packages/typescript-config` — shared compiler settings.

Requires Bun for dependency management and tests, and Node.js 24+ for the compiled CLI.

```sh
bun install
bun run build
node apps/cli/dist/main.js --help
```

```sh
node apps/cli/dist/main.js config server https://vault.example.com
node apps/cli/dist/main.js login you@example.com
node apps/cli/dist/main.js sync
export VW_SESSION="$(node apps/cli/dist/main.js unlock --raw)"
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

See the [usage guide](docs/README.md) and [compatibility contract](docs/compatibility.md)
for supported commands, real-server tests, and remaining work. The implementation is in progress against the full CLI scope;
[implementation status](docs/implementation-status.md) records completed behavior and outstanding work.
