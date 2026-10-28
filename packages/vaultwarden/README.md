# @kjanat/vaultwarden

[![NPM Version](https://img.shields.io/npm/v/@kjanat/vaultwarden?logo=npm&labelColor=CB3837&color=black)](https://npm.im/@kjanat/vaultwarden)

An independent TypeScript SDK for Vaultwarden: authentication, cryptography,
vault operations, password generation, imports, exports, and Sends.

Requires Node.js 24.8.0+. This package does not invoke the Bitwarden CLI.

## Install

```sh
npm install @kjanat/vaultwarden
```

## Usage

```ts
import {
  VaultwardenClient,
  loginWithPassword,
  unlockAccount,
  personalItems,
} from '@kjanat/vaultwarden';

async function readVault(email: string, password: string) {
  const client = new VaultwardenClient('https://vault.example.com');
  const account = await loginWithPassword(client, email, password);
  const encryptedVault = await client.sync(account.accessToken);
  const key = await unlockAccount(account, password);
  try {
    return personalItems(encryptedVault, key);
  } finally {
    key.fill(0);
  }
}
```

See the [usage guide](https://github.com/kjanat/vw/blob/master/docs/README.md#library),
[Vaultwarden compatibility notes](https://github.com/kjanat/vw/blob/master/docs/vaultwarden-deviations.md),
and [implementation status](https://github.com/kjanat/vw/blob/master/docs/implementation-status.md).

For the `vw` executable, use
[@kjanat/vaultwarden-cli](https://www.npmjs.com/package/@kjanat/vaultwarden-cli)
([CLI guide](https://github.com/kjanat/vw/blob/master/apps/cli/README.md)):

```sh
npx @kjanat/vaultwarden-cli
```

[Sponsor on GitHub](https://github.com/sponsors/kjanat).

Report vulnerabilities through the repository's
[security policy](https://github.com/kjanat/vw/security/policy).
