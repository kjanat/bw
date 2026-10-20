# Vaultwarden compatibility contract

Vaultwarden is the primary compatibility target. Protocol decisions are based on
its server handlers, with the official Bitwarden CLI and crypto SDK as behavioral
references. This implementation does not copy the official client's application
architecture or import Bitwarden packages. A change to the latest Bitwarden CLI
alone is not a reason to drop a working Vaultwarden protocol path.

## Reference revisions

Investigated on 2026-10-20:

- [Vaultwarden `58a980f`](https://github.com/dani-garcia/vaultwarden/tree/58a980f850464f7d9cdc99a765df36f0a3308b91):
  `src/api/identity.rs`, `src/api/core/accounts.rs`, `src/api/core/ciphers.rs`.
- [Bitwarden clients `ce5386b`](https://github.com/bitwarden/clients/tree/ce5386b939062d9535cdf1a998101d25194908d0):
  CLI login/unlock command behavior, legacy key stretching, and HTTP handling.
- [Bitwarden SDK `4ea5e6f`](https://github.com/bitwarden/sdk-internal/tree/4ea5e6f669bb8ad053c715224f8afbf0ad8aadc8):
  `crates/bitwarden-crypto/src/keys/kdf.rs` and `master_key.rs` for independent
  KDF test vectors, normalization, salt hashing, and password-hash purposes.
- Real-server tests use Vaultwarden **1.37.4**, image
  `vaultwarden/server@sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055`.

## Current behavior

| Area                      | Coverage                                                                                                                       |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| Server selection          | Explicit URL; path prefixes; no cloud fallback                                                                                 |
| Prelogin                  | Identity endpoint with legacy API fallback only on 404/405                                                                     |
| Password authentication   | PBKDF2 and Argon2id, stable CLI device ID, refresh and 401 recovery                                                            |
| Two-factor                | Provider/token submission; challenge flows remain in progress                                                                  |
| User keys                 | Legacy Key and modern wrapped-key response fields                                                                              |
| Encryption                | Encryption V1 EncString type 2; verify MAC before decrypting                                                                   |
| Organization keys         | Account private-key decryption and RSA OAEP key types 3/4                                                                      |
| Item reads/writes         | Login, secure note, card, identity, SSH key; per-item keys; custom fields and password history                                 |
| Edit conflicts            | Preserve current item key; send lastKnownRevisionDate; reject stale edits                                                      |
| Item lifecycle            | Create, edit, soft/permanent delete, restore, archive/unarchive                                                                |
| Folders                   | Create, list, get, edit, delete with encrypted names                                                                           |
| Organizations/collections | Collection CRUD with access preservation; member listing and confirmation; item moves and collection assignments               |
| Attachments               | Type-2 binary encryption, multipart upload, signed downloads, raw bytes, private file output, deletion, upload-failure cleanup |
| Filtering                 | Search, folder/organization/collection IDs, trash and archive                                                                  |
| Templates/encoding/TOTP   | Item/folder templates, stdin base64 encoding; RFC 6238 and Steam TOTP                                                          |
| Local state               | Atomic private storage, encrypted cache, offline reads, session invalidation                                                   |
| Protocol version          | Bitwarden-Client-Version 2026.10.0; required for Vaultwarden to include SSH keys in sync                                       |

KDF work is bounded: PBKDF2 at most 10,000,000 iterations; Argon2id at most
20 iterations, 256 MiB, and 16 lanes. Unsupported formats fail explicitly.
See [implementation status](implementation-status.md) for the full command target.

## Verification

```sh
bun run build --filter=@kjanat/vaultwarden-cli
bun run check-types --filter=@kjanat/vaultwarden-cli
bun run lint --filter=@kjanat/vaultwarden-cli
bun run test --filter=@kjanat/vaultwarden --filter=@kjanat/vaultwarden-cli
```

Normal tests cover independent SDK KDF vectors, tampering/wrong-key/downgrade
rejection, per-item keys, protocol fallback, modern response shapes, error
redaction, private state, session invalidation, and the compiled Node CLI.
Real-server tests are opt-in and skipped by default.

Run a **disposable** loopback instance with volatile storage:

```sh
docker run --rm --name vw-compat \
  -p 127.0.0.1:18229:80 \
  -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e SIGNUPS_ALLOWED=true -e SIGNUPS_VERIFY=false \
  -e LOGIN_RATELIMIT_MAX_BURST=200 \
  vaultwarden/server@sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055
```

Once it is ready, in another terminal:

```sh
VW_TEST_SERVER=http://127.0.0.1:18229 \
  bun run test --filter=@kjanat/vaultwarden --filter=@kjanat/vaultwarden-cli
```

The live tests create synthetic PBKDF2 and Argon2id accounts and an encrypted
per-item-key login. They exercise HTTPS using an ephemeral local TLS proxy and
trusted test certificate (requires `openssl`), built Node commands, token refresh,
401 recovery, incorrect-password rejection, decryption, offline reads, private
storage, locking, and logout. They only accept an HTTP `127.0.0.1` fixture server.
Stop the container afterward; its accounts and keys are disposable.

Set `VW_TEST_BW=/absolute/path/to/bw` as well to compare decrypted passwords with
an independently installed official Bitwarden CLI in a separate temporary
profile. This executable is used solely by the optional compatibility tests.

Verified on 2026-10-20: 23 library tests and 7 CLI tests passed, including both
real-server KDF flows with `/usr/bin/bw` **2026.10.0** as the independent client.
Both clients decrypted the same synthetic per-item-key passwords over HTTPS,
including secrets and folders written by the new CLI and an organization-owned
item. Live tests cover all five supported item types, stale-edit rejection, and
trash/archive/restore/permanent-delete transitions. Collection CRUD, assignment,
member confirmation, binary attachments, and item moves are also live tested.
A separately registered and confirmed account can unwrap the organization key;
official bw can read moved secrets and the uploaded binary attachment.
Attachment checks compare 128 KiB of binary data, including raw stdout output.
Build, type checks, lint, and formatting checks passed for the new packages.

## Remaining work

The complete scope is tracked in [implementation status](implementation-status.md).
Outstanding work includes the remaining import adapters, transfer edge cases, Sends,
reports, the local API, legacy attachment migration coverage,
additional authentication flows, global flag parity, newer item/encryption types,
and an automated multi-version compatibility matrix.

Before claiming an operation is supported, implement it in the library, exercise
it against disposable Vaultwarden, and add CLI coverage where applicable. Mocked
protocol responses alone do not establish real-server compatibility.
