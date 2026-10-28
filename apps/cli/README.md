# @kjanat/vaultwarden-cli

[![NPM Version](https://img.shields.io/npm/v/@kjanat/vaultwarden-cli?logo=npm&labelColor=CB3837&color=black)](https://npm.im/@kjanat/vaultwarden-cli)

An independent command-line client for Vaultwarden. The executable is `vw`.
It uses the [@kjanat/vaultwarden SDK](https://www.npmjs.com/package/@kjanat/vaultwarden)
directly and does not invoke the Bitwarden CLI.

Requires Node.js 24.8.0+.

## Run or install

Run without a global installation using either form:

```sh
npx @kjanat/vaultwarden-cli
npx --package=@kjanat/vaultwarden-cli vw
```

To install the `vw` command globally:

```sh
npm install --global @kjanat/vaultwarden-cli
```

## Usage

```sh
vw --help
vw config server https://vault.example.com
export VW_SESSION="$(vw login you@example.com --raw)"
vw list items
vw lock
unset VW_SESSION
vw logout
```

The CLI supports vault management, password generation, imports, exports,
organizations, and Sends. Run `vw COMMAND --help` for command options.

See the [usage guide](https://github.com/kjanat/vw/blob/master/docs/README.md),
[Vaultwarden compatibility notes](https://github.com/kjanat/vw/blob/master/docs/vaultwarden-deviations.md),
and [implementation status](https://github.com/kjanat/vw/blob/master/docs/implementation-status.md).

For direct TypeScript integration, use the
[@kjanat/vaultwarden SDK](https://github.com/kjanat/vw/blob/master/packages/vaultwarden/README.md).

[Sponsor on GitHub](https://github.com/sponsors/kjanat).

Report vulnerabilities through the repository's
[security policy](https://github.com/kjanat/vw/security/policy).
