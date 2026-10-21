# Vaultwarden compatibility contract

Vaultwarden is the primary compatibility target. Protocol decisions are based on
its server handlers, with the official Bitwarden CLI and crypto SDK as behavioral
references. This implementation does not copy the official client's application
architecture or import Bitwarden packages. A change to the latest Bitwarden CLI
alone is not a reason to drop a working Vaultwarden protocol path.

## Reference revisions

Investigated on 2026-10-20:

- [Vaultwarden `58a980f`](https://github.com/dani-garcia/vaultwarden/tree/58a980f850464f7d9cdc99a765df36f0a3308b91):
  `src/api/identity.rs`, `src/api/core/accounts.rs`, `src/api/core/ciphers.rs`,
  `src/api/core/sends.rs`, `src/auth/send.rs`, and `src/db/models/send.rs`.
- [Bitwarden clients `ce5386b`](https://github.com/bitwarden/clients/tree/ce5386b939062d9535cdf1a998101d25194908d0):
  CLI command behavior, legacy key stretching, Send key derivation/password
  proofs, transfer formats, password-health response fields, and HTTP handling.
- [Bitwarden SDK `4ea5e6f`](https://github.com/bitwarden/sdk-internal/tree/4ea5e6f669bb8ad053c715224f8afbf0ad8aadc8):
  `crates/bitwarden-crypto/src/keys/kdf.rs` and `master_key.rs` for independent
  KDF test vectors, normalization, salt hashing, and password-hash purposes;
  `crates/bitwarden-vault/src/cipher_risk/` for report filtering, reuse,
  exposure checks, and username context.
- Real-server tests use Vaultwarden **1.37.4**, image
  `vaultwarden/server@sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055`.
- The older compatibility target is Vaultwarden **1.36.0**, image
  `vaultwarden/server@sha256:d626d04934cd1192ad8ced1adb975099fca78cec33ab467d2d3c923cde7f3b0c`.

The fingerprint and URI implementations additionally reference
`libs/legacy-crypto/src/services/legacy-compat-key.service.ts`,
`libs/common/src/vault/models/view/login-uri.view.ts`, and
`libs/common/src/vault/services/search.service.ts` at the client revision above.
URI checksum generation and validation follow
`crates/bitwarden-vault/src/cipher/login.rs` and `cipher.rs` at the SDK revision.

## Current behavior

The reference organization SSO `device-approval` flow uses
[`OrganizationAuthRequestApiService`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/bitwarden_license/bit-common/src/admin-console/auth-requests/organization-auth-request-api.service.ts)
under `/organizations/{id}/auth-requests`, with individual and bulk approval/denial
routes. Neither pinned Vaultwarden target implements these organization routes.
On a valid, newly created organization, the list route returned HTTP 404 on
both servers; the authenticated personal `/auth-requests` route returned HTTP
200 with an empty list. Both PBKDF2 fixture runs passed with these checks in
about 45 seconds. Source auditing covered each target's organization handlers
and the personal handlers in
[`accounts.rs`](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs).
The SDK capability metadata records the two verified versions. All five CLI
subcommands return a typed unsupported-capability error without reading account
credentials, posting a response, or presenting an empty list as success. Future
server support requires a new capability audit; personal requests are not an
implementation of organization SSO trusted-device approvals.

`sdk-version` identifies the independent library version and is checked against
its package manifest by a compiled CLI test. `--version` reads the CLI package's
own version. `update` reports the current private development build without
network access. For public packages it reads that package's npm `latest` channel,
distinguishing updates, matching/ahead versions, unpublished packages and request
failures. Tests cover SemVer prerelease/build ordering, credential-free requests,
redirect rejection configuration and sanitized error handling. No self-update
or Bitwarden product-update request occurs.

| Area                      | Coverage                                                                                                                                                                |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Server selection          | Explicit URL; path prefixes; no cloud fallback                                                                                                                          |
| Prelogin                  | Identity endpoint with legacy API fallback only on 404/405                                                                                                              |
| Password authentication   | PBKDF2 and Argon2id, stable CLI device ID, initial sync/unlock, password inputs, refresh and 401 recovery                                                               |
| API-key authentication    | Personal user client credentials, authenticated principal/KDF lookup, locked login, repeated-grant renewal, master-password unlock                                      |
| Two-factor                | Provider/token submission and supported TOTP/email challenges; the reference CLI's separate new-device email-OTP challenge is not emitted by pinned Vaultwarden targets |
| User keys                 | Legacy Key and modern wrapped-key response fields                                                                                                                       |
| Encryption                | Encryption V1 EncString type 2; verify MAC before decrypting                                                                                                            |
| Organization keys         | Account private-key decryption and RSA OAEP key types 3/4                                                                                                               |
| Item reads/writes         | Login, secure note, card, identity, SSH key; per-item keys; custom fields and password history                                                                          |
| Edit conflicts            | Preserve current item key; send lastKnownRevisionDate; reject stale edits                                                                                               |
| Item lifecycle            | Create, edit, soft/permanent delete, restore, archive/unarchive                                                                                                         |
| Folders                   | Create, list, get, edit, delete with encrypted names                                                                                                                    |
| Organizations/collections | Collection CRUD with access preservation; member listing and confirmation; item moves and collection assignments                                                        |
| Attachments               | Type-2 binary encryption, multipart upload, signed downloads, raw bytes, private file output, deletion, upload-failure cleanup                                          |
| Sends                     | Text/file creation, owner reads, metadata/text edits, password removal, deletion, anonymous receive; separate fragment-key and account-key handling                     |
| Filtering                 | Search, folder/organization/collection IDs, trash and archive                                                                                                           |
| Templates/encoding/TOTP   | Item/folder templates, stdin base64 encoding; RFC 6238 and Steam TOTP                                                                                                   |
| Reports                   | Password-health strength/reuse, archived and organization logins, optional HIBP range checks; get exposed occurrence counts                                             |
| Local state               | Atomic private storage, encrypted cache, offline reads, session invalidation                                                                                            |
| Protocol version          | Bitwarden-Client-Version 2026.10.0; required for Vaultwarden to include SSH keys in sync                                                                                |

KDF work is bounded: PBKDF2 at most 10,000,000 iterations; Argon2id at most
20 iterations, 256 MiB, and 16 lanes. Unsupported formats fail explicitly.
See [implementation status](implementation-status.md) for the full command target.

The pinned Vaultwarden identity handler sends a new-device notification after
successful authentication when email is configured; its token response does not
include `requiresDeviceVerification`. The official CLI's follow-up OTP prompt is
therefore a cloud-specific branch, not a Vaultwarden login challenge. See the
[Vaultwarden response handler](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/identity.rs#L500-L608)
and the [reference CLI branch](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/apps/cli/src/auth/commands/login.command.ts#L340-L356).

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

The managed runner builds the CLI, starts a disposable loopback container on an
automatically assigned port, waits for health, runs the live fixtures, and removes
the container and temporary profile on completion or interruption:

```sh
VW_TEST_BW=/absolute/path/to/bw bun run test:compat
VW_TEST_VERSION=1.36.0 bun run test:compat
VW_TEST_BW=/absolute/path/to/bw VW_TEST_CASE=Argon2id bun run test:compat
VW_TEST_BW=/absolute/path/to/bw VW_TEST_CASE='authentication, external' \
  VW_TEST_IMPORT_FORMAT=keepasskdbx bun run test:compat
```

It requires a POSIX host, Docker, Bun, Node, OpenSSL, OpenSSH and `envctl`. Docker output is
passed through `envctl redact` before display or capture; redactor failure
withholds that output. The selected image must be an immutable digest from
`apps/cli/test/fixtures/compatibility-targets.json`. `test:compat` is an uncached
Turbo package task and forwards only its named test configuration variables.
For the 1.37.4 reference run, the managed runner executes KDF/vault checks once,
then divides the external-import matrix into eight independently reported
shards, and runs authentication/REST parity separately. This keeps each Bun
test below its per-test timeout without dropping importer cases. The disposable
server raises its unauthenticated request burst limit for the repeated synthetic
registrations; this setting applies only to the managed test container. A shard
can be rerun with `VW_TEST_IMPORT_SHARD=INDEX/8`, and REST/authentication checks
alone with `VW_TEST_SKIP_IMPORTS=1`.

The 1.37.4 run requires the independent **bw 2026.10.0** executable and checks its
version in an isolated profile. That reference client cannot parse 1.36.0's
prelogin KDF response: an actual login attempt failed with “KDF config response
does not contain a valid KDF type”. Therefore 1.36.0 runs our protocol checks
without the reference-dependent sections. Version-matched reference comparisons
and external-format comparisons on that older server remain required work.

[The CI workflow](../.github/workflows/ci.yml) defines unit/build/type/lint checks
and a compatibility matrix for Node 24/26 against both pinned servers. It installs
the reference npm CLI independently, verifies the redactor's published checksum,
and uses the same managed runner. The workflow has been validated locally with
Actionlint; a hosted Actions run has not been triggered or observed.

Local runner evidence on 2026-10-20: all three protocol fixtures passed on
1.36.0 under Node **26.11.1** in 104 seconds and **24.22.0** in 106 seconds,
with 301 expectations per run. Reference-dependent sections were not executed
for that server. These runs exercised both KDFs, organizations and collection
imports, attachments, legacy anonymous text/file Sends, session/cache handling,
item lifecycle, two-factor authentication and REST. On 1.37.4 under Node 26.11.1,
the independently npm-installed bw 2026.10.0 passed the full Argon2id comparison
in 335 seconds. The managed focused KDBX/authentication/REST run passed in 88
seconds with `/usr/bin/bw`; the same focused cases passed under Node 24.22.0 in
86 seconds with the independently npm-installed reference CLI. A deliberate SIGINT probe exited 130 and the fixture
container was confirmed absent afterward; cancellation terminates the owned
test process group before container cleanup.

For manual control, run a **disposable** loopback instance with volatile storage:

```sh
docker run --rm --name vw-compat \
  -p 127.0.0.1:18229:80 \
  -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e SIGNUPS_ALLOWED=true -e SIGNUPS_VERIFY=false \
  -e LOGIN_RATELIMIT_MAX_BURST=10000 \
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

Verified on 2026-10-21: 128 library tests and 33 non-live CLI tests passed,
along with a build, type check, and lint. Both expanded real-server KDF cases
passed against `/usr/bin/bw` **2026.10.0**: PBKDF2 in 281 seconds and Argon2id
in a separate focused run in 317 seconds. The latter exceeded the earlier
300-second deadline; the live test deadline is now 600 seconds.
Both cases cover cross-client search, URI matching, fingerprints, URI checksums,
and 2 MiB binary fixtures. A separate real-server TOTP test verifies library
challenge completion, explicit-code CLI login through custom API/identity URLs,
and noninteractive missing-code rejection. A pseudo-terminal probe of the built
Node helper verifies provider selection and masked code entry. Email login-code
requests are protocol tested, including cancellation and unavailable providers;
SMTP delivery and email-code completion are now live tested on 1.36.0 and
1.37.4 under both PBKDF2 and Argon2id. The email fixture enrolls a verification
address different from the account email, captures real SMTP delivery, completes
the library's `requestEmail()` callback, verifies the recovered vault key, and
logs in through the compiled Node CLI with an explicit code. Replayed and
incorrect codes are rejected; noninteractive missing-code failure leaves the
captured-message count unchanged. Passwords and codes stay out of CLI diagnostics.

Run this dedicated suite with:

```sh
VW_TEST_SMTP=1 bun run test:compat
VW_TEST_VERSION=1.36.0 VW_TEST_SMTP=1 bun run test:compat
```

SMTP mode requires no reference CLI. It starts a pinned Mailpit image from the
target configuration on a dedicated Docker network, publishes its API only on
loopback, and configures Vaultwarden to send to that capture-only receiver with
no relay. The test mailbox and server have no mounted persistent storage. Both
containers and their network are removed afterward. `VW_TEST_SMTP` is forwarded
by Turbo; direct fixture runs can instead provide `VW_TEST_SERVER` and
`VW_TEST_MAILPIT`, both disposable HTTP loopback URLs. The normal runner keeps
SMTP disabled and uses its existing fixtures. CI adds the SMTP suite to each
server/Node matrix cell. These email tests use library and compiled CLI login;
they do not compare against the reference client or test interactive terminal
entry. Normal tests skip them unless the mailbox is explicitly provided.
The dedicated mode passed on both pinned servers under Node 26.11.1 on
2026-10-20: two cases and 34 expectations per server, about 22 seconds of test
execution per run. Its containers and dedicated networks were confirmed absent
after completion.
Existing-account SSO has a separate capture-only OIDC fixture. Run it with:

```sh
VW_TEST_SSO=1 bun run test:compat
VW_TEST_VERSION=1.36.0 VW_TEST_SSO=1 bun run test:compat
```

SSO mode requires Linux and runs separately from SMTP mode. Its synthetic OIDC
provider and Vaultwarden bind to loopback; the server uses Docker host networking
so it can reach the temporary provider. No reference CLI is required. The fixture
uses ephemeral RSA signing keys, OIDC discovery/JWKS, authorization codes, and
refresh tokens. It exercises real Vaultwarden OIDC redirects and PKCE, rather
than replacing the server token endpoint with a stub. The runner stops the
provider and removes the server and CLI profiles after the tests.

Both KDF cases verify library authorization and refresh, exact vault-key recovery,
compiled Node `login --sso` through the localhost callback, encrypted item reads,
TOTP completion, and rejection of a wrong PKCE verifier. They also JIT-provision
fresh SSO users and exercise the compiled CLI's first-login path: it sets a master
password, initializes vault/RSA keys through `/api/accounts/set-password`, syncs,
and unlocks the account. The browser is simulated by following HTTP redirects; an
OS browser launcher and a vendor identity provider's UI are not exercised. SSO
email delivery is protocol tested, with real-server SSO email coverage still
pending. The CI matrix includes this suite in each server/Node cell; hosted
execution remains unobserved.

Verified locally on 2026-10-21 under Node 26.11.1 and Bun 1.4.3: both SSO
cases passed on 1.36.0 (12.39 seconds, 82 expectations) and 1.37.4 (12.26
seconds, 82 expectations). Both fixture containers were removed after the runs.

The subsequent sync parity change adds `--last`, `--force`/`-f`, and account
revision checks. Internal post-login and post-mutation refreshes still download
the full cache. The reference behavior is grounded in
[`SyncCommand`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/apps/cli/src/vault/sync.command.ts)
and the packaged reference's `needsSyncing` implementation. A built-CLI fixture
verifies skipped downloads, forced downloads, offline dates, renewal after 401,
invalid-revision failures, account deletion, and preserving the sync start time.
Real-server verification passed on 1.36.0 with password login (PBKDF2, 136
expectations in 42.82 seconds), and on 1.37.4 through SSO under both KDFs (54
expectations in 13.57 seconds). These focused runs used Node 26.11.1 and did not
compare sync output against a separately logged-in reference client.

Named-object lookup follows the reference
[`GetCommand`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/apps/cli/src/commands/get.command.ts)
and its `CliUtils.searchFolders`, `searchCollections`, and `searchOrganizations`
helpers. Folder, collection, and organization names match a case-insensitive
substring, preserving accents and whitespace. An exact name has no preference
over another name containing it. UUID queries perform only ID lookup, including
case-insensitive UUID comparison, and cannot select an object whose name is the
missing UUID. The library provides `findNamedObject` and the three `VaultService`
lookup methods; the CLI uses those methods. Unit fixtures cover decrypted folder
and collection names, ambiguity, and omission of organization key material.
On 2026-10-21, the expanded PBKDF2 fixture passed under Node 26.11.1 on both
servers: 139 expectations in 45.26 seconds on 1.36.0, and 340 expectations in
342.66 seconds on 1.37.4 with `/usr/bin/bw` 2026.10.0. The latter compares
substring lookups, uppercase UUIDs, overlapping names, and missing UUIDs directly
against the independent client, alongside the existing protocol/transfer checks.
The older server run does not include reference-client comparisons.

The same real-server fixture now starts the compiled Node `serve` command on an
ephemeral TCP port and verifies item/folder CRUD, exact secret strings, 256 KiB
multipart attachment round-trips, text Sends, archive/restore, lock/unlock,
sync while locked, and Origin/Host rejection. Handler tests cover bounded JSON
bodies, queue recovery after invalid requests, and binary buffer lifetime.
The reference routes and guards come from
[`OssServeConfigurator`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/apps/cli/src/oss-serve-configurator.ts)
and [`ServeCommand`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/apps/cli/src/commands/serve.command.ts).
Compiled Node integration tests also verify Unix, inherited listening-fd and
connected-fd HTTP requests, clean shutdown, and Unix socket removal. With
`VW_TEST_BW` set, the live fixture starts the reference local API in an isolated
profile through a trusted loopback TLS proxy. Status/template envelopes, the full
login-item JSON response in this fixture, exact secret responses and file Send
rejection match in that comparison. The response model omits server-only fields,
normalizes dates to milliseconds, supplies SDK defaults and excludes item and
attachment key metadata. Handler tests also verify hidden-password redaction.
File Send creation is explicitly unsupported by
[`SendCreateCommand` in serve mode](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/apps/cli/src/tools/send/commands/create.command.ts);
the HTTP API rejects it without reading the supplied host filename. The CLI and
library still support file Sends. Broader exact-field and error-message parity
remains under audit.
The same fixture also imports six external CSV files through both compiled vw
and `/usr/bin/bw`, comparing decrypted fields, notes, favorites, OTPs, and folder
assignments after separate imports. These cover Chrome (including Android),
Firefox (including its excluded internal account), Safari, KeePassX, and two
LastPass export shapes. Card/address structured notes, generic notes, and form-fill
cards are included. This external-format comparison currently uses the PBKDF2
fixture; it is separate from the native transfer tests under both KDFs. The
expanded focused test, now including a seventh file in KeePass 2 XML format,
passed in 168 seconds. The focused test deadline is now 600 seconds to accommodate
the additional KDBX and 1PUX cases.
Vendor mappings follow the pinned
[`Chrome`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/libs/importer/src/importers/chrome-csv-importer.ts),
[`Firefox`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/libs/importer/src/importers/firefox-csv-importer.ts),
[`Safari`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/libs/importer/src/importers/safari-csv-importer.ts),
[`KeePassX`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/libs/importer/src/importers/keepassx-csv-importer.ts),
and [`LastPass`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/libs/importer/src/importers/lastpass/lastpass-csv-importer.ts)
importers. LastPass HTML and newer dedicated-type conversions still need coverage.
KeePass XML uses the pinned
[`KeePass2XmlImporter`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/libs/importer/src/importers/keepass2-xml-importer.ts)
as its mapping reference. Its live fixture includes root/nested groups, an empty
folder name, Unicode/CDATA, hidden multiline custom fields, literal entities,
OTP conversion, note continuations and nested history. Both clients produced
matching decrypted data and folder assignments. Parser and pipeline tests independently
verify collection mapping, encrypted writes, and rejection of malformed XML,
undeclared entities, entity declarations and external DTDs before mutation.
History and embedded binaries are intentionally outside the reference XML
importer's mapping; they are not restored as entries or attachments.

KDBX parsing follows the pinned SDK's
[`kdbx.rs`](https://github.com/bitwarden/sdk-internal/blob/4ea5e6f669bb8ad053c715224f8afbf0ad8aadc8/crates/bitwarden-importers/src/importers/kdbx.rs).
Library tests cover AES KDFs in KDBX 3.1 and 4, Argon2d/Argon2id, password/key-file
combinations, a ChaCha20 payload, disabled recycle bins, TOTP secret encodings,
protected/multiline fields, invalid credentials, and encrypted bulk submission.
The compiled Node CLI imports four synthetic databases from
`apps/cli/test/fixtures/kdbx`. Three password-bearing files are independently
compared with `/usr/bin/bw`; key-file-only Argon2d is verified through vw. The
reference CLI's password collector rejects a missing/empty password before its
SDK, although the SDK supports key-file-only input. The focused real-server run
passed in 79 seconds, including field/OTP/folder comparisons and tab preservation.

`VW_TEST_IMPORT_FORMAT=keepasskdbx` selects that adapter in the focused live test;
unset it for the full external-format matrix. The variable is forwarded by Turbo.
The worker uses a 60-second execution limit. Files and key files are bounded to
10 MiB; the reference SDK also caps database input at 10 MiB. Group depth is 256,
matching the SDK. Argon2 is limited to 256 MiB, 20 iterations and 16 lanes, and
AES KDF work to 100 million rounds. Larger work factors remain part of the wider
compatibility/limits audit. Worker-local decoding uses the current XML parser.
The Bun dependency patch changes the decoder's C0 filter to preserve XML-valid
tabs; an unpatched fixture reproduced the lost tab before the patch was added.
1Password 8 import uses the pinned
[`OnePassword1PuxImporter`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/libs/importer/src/importers/onepassword/onepassword-1pux-importer.ts)
and its base field/folder mappings as behavior references. The compiled Node CLI
imports `apps/cli/test/fixtures/onepassword/synthetic.1pux` on the PBKDF2 fixture.
An independent `/usr/bin/bw` import produced matching decrypted names, types,
notes, credentials, URIs, OTP, fields, favorites, reprompt settings, password
history, archive state, folder assignments, and SSH public keys/fingerprints for
all 11 accepted records. Both clients skipped the malformed SSH record. The
focused live run passed in 71 seconds; select it with
`VW_TEST_IMPORT_FORMAT=1password1pux` using the same loopback server setup.

Ten library tests additionally cover the remaining legacy category mappings,
organization collections, encrypted upload, malformed containers, multiple
accounts/vaults, and skipped-record reporting. OpenSSH independently reads keys
converted from PKCS#8 for Ed25519, RSA, and NIST P-256/P-384/P-521; its SHA256
fingerprints match the importer. Private OpenSSH encodings have random check
integers and are not compared byte for byte with bw. Unlike the pinned client,
the parser processes every source account. Document binaries remain outside the
reference mapping, and dedicated bank/passport/license types remain under the
wider server capability audit. Archive decoding reads only `export.data`,
bounded to 100 MiB, without filesystem extraction. Broader 1PUX conformance/limits
remain required work.

Legacy 1Password mappings follow
[`OnePassword1PifImporter`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/libs/importer/src/importers/onepassword/onepassword-1pif-importer.ts),
[`OnePasswordCsvImporter`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/libs/importer/src/importers/onepassword/onepassword-csv-importer.ts),
and its Mac/Windows subclasses. Eight library tests cover standard/OPVault
records, trash exclusion, dates, notes, passwords/history, OTP, hidden fields,
card/identity mappings, backslash-escaped CSV quotes, malformed input rejection,
and encrypted submission. The singular CSV `URL` column intentionally preserves
its value: the pinned reference calls `concat` without assigning its result and
silently drops the URI. Plural `URLs` keeps the reference mapping. Synthetic
fixtures are in `apps/cli/test/fixtures/onepassword`.

A focused real-server run for all three legacy adapters passed in 105 seconds:
seven 1PIF, four Mac CSV and three Windows CSV fixture records produced matching
decrypted items in vw and `/usr/bin/bw`. Comparisons include item types, credentials,
URIs, notes, hidden/custom fields, OTP, favorites, password history, cards and
identities. It uses the PBKDF2 account and compiled Node CLI. The singular-URL
correction is unit tested separately because it intentionally differs from bw.

`VW_TEST_IMPORT_FORMAT` also accepts comma-separated format IDs to focus a
single live run on several adapters without repeating account setup.

Both clients decrypted the same synthetic per-item-key passwords over HTTPS,
including secrets and folders written by the new CLI and an organization-owned
item. Live tests cover all five supported item types, stale-edit rejection, and
trash/archive/restore/permanent-delete transitions. Collection CRUD, assignment,
member confirmation, binary attachments, and item moves are also live tested.
A separately registered and confirmed account can unwrap the organization key;
official bw can read moved secrets and the uploaded binary attachment.
Attachment checks compare 2 MiB of binary data, including raw stdout output.
Native JSON, CSV, account-encrypted JSON, and password-encrypted JSON transfers
are tested in both directions with official bw under PBKDF2 and Argon2id. The
live tests also verify bulk organization import/export collection relationships,
and 2 MiB attachment restoration from both vw and official bw ZIP exports.
Official ZIPs with ambiguous sanitized item names are rejected before mutation;
vw ZIPs include a manifest preserving exact attachment names and item mappings.
Local tests cover generation, cached policy constraints, CSV quoting, raw KDF
salts, wrong export passwords/keys, and failed-import cache invalidation signals.

Sends are live tested under both account KDFs: text/file creation, cached owner
reads, metadata edits, password-protected anonymous access, password removal,
max-access enforcement, expiration, disabling, and deletion. Official bw reads
our text/file Sends, and this CLI receives protected text created by bw. Binary
Send downloads are compared byte for byte. Local tests verify independent
HKDF/password-proof vectors, token isolation, fragment-key handling, multipart
filenames, signed downloads, and rollback failures. This evidence covers the
pinned server's `send_access` token protocol. Recipient access also supports
the older anonymous JSON-body protocol used by 1.36.0. A fallback occurs only
when the token endpoint explicitly rejects the grant (`Invalid type` or
`unsupported_grant_type`), and never on unrelated password/authentication,
rate-limit, transport, or server errors. The legacy calls carry the derived
password proof with no account token; fragment keys remain local, and signed
file downloads receive neither password proofs nor authentication headers.
Missing/incorrect legacy passwords retain the same typed challenge errors.

Older organization imports require each collection to include `groups: []`
and `users: []`. The importer supplies these fields for both server versions,
preserving fresh collection IDs and encrypted names. The requirement comes from
[`FullCollectionData` in 1.36.0](https://github.com/dani-garcia/vaultwarden/blob/1.36.0/src/api/core/organizations.rs)
and was reproduced as an HTTP 422 before the payload correction. Legacy Send
endpoints follow
[`sends.rs` in 1.36.0](https://github.com/dani-garcia/vaultwarden/blob/1.36.0/src/api/core/sends.rs).

Password-health reports match official bw field for field for the live fixture
corpus under both KDFs. The corpus includes reused, empty, contextual, Unicode,
oversized, archived, and deleted login passwords, plus a non-login item.
Organization logins are included. A loopback HIBP-compatible range service tests
positive counts, no-network mode, failed lookups, and absence of account
credentials. `get exposed` prints a positive count and fails on service errors.
Local tests cover padded replies, malformed/oversized bodies, timeouts,
concurrency, and duplicate-password request coalescing. The built Node library
also queried the production HIBP service once with the known dummy value
`password`, confirming a positive match; production data is not a CI fixture.

Both account KDFs also cover API-key authentication in an isolated CLI profile:
incorrect-secret rejection, locked login, sync without a master password,
expiry/401 renewal through client credentials, master-password-file unlock,
login/unlock checks, changed-wrapper session invalidation, and credential
removal on logout. The same personal API key authenticates official bw, which
unlocks and reads the fixture password. Initial password login now syncs and
returns a usable raw unlock session. Unit tests verify legacy and modern API-key
responses, principal matching, absence of refresh tokens, unchanged password
refresh semantics, password-source precedence, and noninteractive failures.
A built-CLI test verifies that status checks ignore unused password-file paths.

Build, type checks, lint, and formatting checks passed for the new packages.

## Remaining work

The complete scope is tracked in [implementation status](implementation-status.md).
Outstanding work includes the remaining import adapters, transfer edge cases,
legacy Send access protocols, remaining local API parity, live verification of
legacy attachment migration during moves, additional authentication flows,
global flag parity, newer item/encryption types, and an automated multi-version
compatibility matrix.

Before claiming an operation is supported, implement it in the library, exercise
it against disposable Vaultwarden, and add CLI coverage where applicable. Mocked
protocol responses alone do not establish real-server compatibility.

## Reference CLI domain-setting limitation

The pinned client API service selects `/sync?excludeDomains=true` when
`supportsAutofill()` is false, which the CLI platform reports. Its equivalent-
domain state therefore lacks the server's saved groups. vw sync includes those
settings and honors the groups for URL matching. The live fixture checks this
intentional difference separately from the other URI-strategy comparisons.

Source: [`ApiService.getSync`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/libs/common/src/services/api.service.ts)
and [`CliPlatformUtilsService.supportsAutofill`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/apps/cli/src/platform/services/cli-platform-utils.service.ts).

Attachment lookup now supports case-insensitive IDs and filename substrings,
unique exact-filename preference, and item search queries for the owning item.
Protocol fixtures reject ambiguous and duplicate filenames before network access.
They cover metadata responses containing only a URL, cached per-attachment keys,
and fallback to the snapshot URL only after metadata HTTP 404; 401/403/429/500
never trigger that fallback. Signed download requests omit account credentials.
The expanded built-CLI PBKDF2 case passed on 1.36.0 under Node 26.11.1 on
2026-10-21 (139 expectations, 44.04 seconds), retrieving a moved organization
attachment by uppercase filename substring and owning-item name. Legacy metadata
fallback is protocol tested; this focused run did not compare against `bw`.

NordPass CSV (`nordpasscsv`) maps logins with additional URLs, credit cards,
identities, secure notes, folders/collections, and typed custom fields. Invalid
embedded JSON is rejected before mutation without exposing its contents in
errors. A focused 1.37.4 run under Node 26.11.1 compared decrypted results and
folder relationships against independent `/usr/bin/bw` 2026.10.0 on 2026-10-21:
56 expectations passed in 47.47 seconds, including the fixture's authentication
and REST checks. Organization grouping has unit coverage; that focused import
comparison used personal scope.

The pinned [file-format inventory](reference/bw-import-formats-2026.10.0.json)
contains 72 IDs extracted from the reference's canonical `importOptionsById`,
filtering nonempty `acceptedFileTypes` exactly as its CLI listing does. This is
source-derived: the reference refuses `import --formats` while logged out.
Our importer list now covers all 72 reference IDs and adds the Vaultwarden
`bitwardenzip` backup format. Password Depot 17 XML has fixture-based unit
coverage and a completed live comparison with `bw` on Vaultwarden 1.37.4. The
unified Keeper ID selects its CSV or JSON importer from the file content, and
Proton Pass uses the canonical `protonpass` ID. F-Secure FSK and Proton Pass
have passing focused comparisons against `bw` 2026.10.0 on Vaultwarden 1.37.4.
Clipperz HTML has a passing focused comparison against `bw` 2026.10.0 after
the fixture was corrected to include the XHTML public doctype used by actual
exports.

Encryptr CSV (`encryptrcsv`) follows the pinned reference importer for password,
credit-card, unknown and empty-login records. Its `Notes` and `Text` columns
join with a blank line; card brand and expiry fields use the reference mapping.
Unit fixtures cover those cases, and the disposable-server cross-client matrix
compared its imported, decrypted records with independent `/usr/bin/bw`
2026.10.0 on Vaultwarden 1.37.4 under PBKDF2, including the password, card,
secure-note and empty-login cases. The focused run passed three live tests and
739 expectations total, including baseline protocol and REST checks.

PassKeep CSV (`passkeepcsv`) maps its category, login fields, description, and
second password as a custom field. PasswordWallet text CSV (`passwordwallettxt`)
uses positional columns for name, URL, username, password, notes, and folder;
its `¬` note separator becomes a newline. Both adapters have personal and
organization grouping unit coverage. They also passed the compiled CLI and
independent `/usr/bin/bw` comparison on Vaultwarden 1.37.4 under PBKDF2,
including decrypted item fields and folder relationships, as part of the
2026-10-21 compatibility run (851 expectations across the live suites).

Passpack CSV (`passpackcsv`) reads its JSON-encoded tags and extra fields,
retains shared notes, and maps tags to folders or multiple organization
collections. Unit coverage includes malformed JSON handling and collection
relationships. It passed the compiled CLI and independent `/usr/bin/bw`
comparison on Vaultwarden 1.37.4 under PBKDF2, including decrypted fields and
folder relationships, in the 2026-10-21 focused compatibility run.

Ascendo (`ascendocsv`), BlackBerry (`blackberrycsv`), Blur (`blurcsv`),
Codebook (`codebookcsv`), Avast (`avastcsv`), Buttercup (`buttercupcsv`),
Padlock (`padlockcsv`), and Yoti (`yoticsv`) CSV adapters map credentials,
notes, favorites, generic fields, and folders according to their pinned
reference importers. All eight passed a focused compiled-CLI and independent
`/usr/bin/bw` comparison on Vaultwarden 1.37.4 under PBKDF2 on 2026-10-21,
including decrypted item fields and folder relationships where applicable.

SaferPass (`saferpasscsv`), SecureSafe (`securesafecsv`), and Meldium
(`meldiumcsv`) CSV imports cover URL/name derivation, case-insensitive URL
headers, notes, and credentials. All three passed a focused compiled-CLI and
independent `/usr/bin/bw` comparison on Vaultwarden 1.37.4 under PBKDF2 on
2026-10-21, including decrypted fields.

True Key (`truekeycsv`) and SplashID (`splashidcsv`) now map login, note, and
card records or positional categories as applicable. Both passed focused
compiled-CLI and independent `/usr/bin/bw` comparisons on Vaultwarden 1.37.4
under PBKDF2 on 2026-10-21, including decrypted fields and folder relations.

RememBear (`remembearcsv`) now maps active logins and cards, skips trashed
records, and preserves card PIN/ZIP fields. UPM (`upmcsv`) maps its positional
login export. Both passed focused compiled-CLI and independent `/usr/bin/bw`
comparisons on Vaultwarden 1.37.4 under PBKDF2 on 2026-10-21, including
decrypted item fields.

LogMeOnce (`logmeoncecsv`) maps named login columns and folder groups. Unit
coverage checks personal folders and organization collections. It passed a
focused compiled-CLI and independent `/usr/bin/bw` comparison on Vaultwarden
1.37.4 under PBKDF2 on 2026-10-21, including decrypted fields and folder
relationships.

Myki (`mykicsv`) maps the distinct account, credit-card, identity, ID-card,
two-factor, and secure-note exports, preserving additional values as custom
fields. Fixtures follow the pinned reference importer and its source fixtures.
All six variants passed focused compiled-CLI comparisons with independent
`/usr/bin/bw` on Vaultwarden 1.37.4 under PBKDF2 on 2026-10-21, including
decrypted fields.

mSecure (`msecurecsv`) maps legacy pipe-encoded values within CSV fields,
including logins, cards, secure notes, and tag folders. Unit coverage includes
personal folders and organization collections. It passed a focused compiled-CLI
and independent `/usr/bin/bw` comparison on Vaultwarden 1.37.4 under PBKDF2 on
2026-10-21, including decrypted item fields and folder relationships.

Password Agent (`passwordagentcsv`) supports its five-column legacy layout and
both current layouts, converts credential-free rows to secure notes, and maps
folders to organization collections. It passed a focused compiled-CLI and
independent `/usr/bin/bw` comparison on Vaultwarden 1.37.4 under PBKDF2 on
2026-10-21, including decrypted fields and folder relationships.

Dashlane (`dashlanecsv`) maps credential, payment, identity, personal-info,
and secure-note exports, retaining unmapped columns as custom fields. It passed
a focused compiled-CLI and independent `/usr/bin/bw` comparison on Vaultwarden
1.37.4 under PBKDF2 on 2026-10-21, including decrypted fields and folder
relationships.

Avast Passwords JSON (`avastjson`) maps login, secure-note, and card records.
It passed focused compiled-CLI and independent `/usr/bin/bw` comparisons on
Vaultwarden 1.37.4 under PBKDF2 on 2026-10-21, including decrypted fields.

Enpass JSON (`enpassjson`) maps login, secure-note, and card records, including
nested folders, TOTP, hidden custom fields, Android app URIs, and card expiry.
The compiled CLI's imported, decrypted records and folder links matched
independent `/usr/bin/bw` 2026.10.0 on Vaultwarden 1.37.4 under PBKDF2 in a
focused 2026-10-21 run (41 expectations across the live authentication/import
fixture). The fixture needed an explicit signal to stop its local REST sidecar
during teardown; the Enpass import and comparison assertions had completed.

Enpass CSV (`enpasscsv`) follows the pinned pair-based export format, including
multiple Website URIs, trailing notes, starred sensitive fields, one-time codes,
and payment cards. The compiled CLI's imported, decrypted records matched
independent `/usr/bin/bw` 2026.10.0 on Vaultwarden 1.37.4 under PBKDF2 in a
focused 2026-10-21 run (39 expectations across the live authentication/import
fixture). As with Enpass JSON, I stopped the local REST sidecar after the import
comparisons because its graceful teardown stalled.

GNOME Passwords JSON (`gnomejson`) maps URL credentials, usernames, custom
attributes, multiline notes, and keyring paths to folders or organization
collections. A focused 2026-10-21 compiled-CLI run on Vaultwarden 1.37.4 under
PBKDF2 matched the imported, decrypted records and folder links from independent
`/usr/bin/bw` 2026.10.0 (39 expectations across the live fixture). The fixture's
local REST sidecar required an explicit signal during teardown; the test then
reported success and removed the temporary Vaultwarden container.

Passman JSON (`passmanjson`) maps login credentials, email fallback, TOTP,
descriptions, custom fields, and the first tag as a folder or collection. Unit
coverage includes multiline custom values and conversion to secure notes when
login credentials and URLs are absent. Its focused 2026-10-21 compiled-CLI
comparison against independent `/usr/bin/bw` 2026.10.0 on Vaultwarden 1.37.4
matched decrypted items and folder links (39 expectations across the live
fixture). The fixture's local REST sidecar required an explicit signal during
teardown; the test then reported success and removed the temporary container.

Passky JSON (`passkyjson`) imports unencrypted website, username, password, and
message records, converting entries without login data or a URL to secure notes.
Encrypted backups fail explicitly. A focused 2026-10-21 compiled-CLI comparison
against independent `/usr/bin/bw` 2026.10.0 on Vaultwarden 1.37.4 matched the
decrypted records (37 expectations across the live fixture). The test-owned
local REST sidecar required an explicit signal during teardown; the runner
reported success and removed the temporary container.

Delinea CSV (`delineacsv`) maps URL-bearing rows to logins and rows without a
URL to secure notes. It retains custom fields, treats Password fields as hidden,
and maps folders to organization collections when requested. A focused
2026-10-21 compiled-CLI run matched the decrypted records and folders from
independent `/usr/bin/bw` 2026.10.0 on Vaultwarden 1.37.4 (40 expectations
across the live fixture); the test-owned local REST sidecar needed an explicit
signal during teardown before the runner reported success and removed the
temporary container.

Kaspersky Password Manager TXT (`kasperskytxt`) parses its Websites,
Applications, and Notes sections, preserving credential fields and multiline
comments. A focused 2026-10-21 compiled-CLI comparison matched independent
`/usr/bin/bw` 2026.10.0 on Vaultwarden 1.37.4 (39 expectations across the live
fixture). The test-owned local REST sidecar needed an explicit signal during
teardown before the test reported success and removed its container.

Zoho Vault CSV (`zohovaultcsv`) maps names, URL fallback, TOTP fallback,
favorites, folder paths, and Zoho's line-based SecretData/CustomData records.
The focused 2026-10-21 compiled-CLI comparison matched independent
`/usr/bin/bw` 2026.10.0 on Vaultwarden 1.37.4 (40 expectations across the live
fixture). Its test-owned REST sidecar needed an explicit signal during teardown;
the runner then reported success and removed the temporary container.

RoboForm CSV (`roboformcsv`) maps the legacy `Rf_fields` and `RfFieldsV2`
encodings, including alternate credentials, hidden password fields, TOTP, and
folder paths. Its focused 2026-10-21 compiled-CLI comparison matched independent
`/usr/bin/bw` 2026.10.0 on Vaultwarden 1.37.4 (40 expectations across the live
fixture). The test-owned REST sidecar required an explicit signal during
teardown before the runner reported success and removed its container.

Keeper CSV (`keepercsv`) uses Keeper's headerless layout, preserves credential
whitespace, maps `TFC:Keeper` to TOTP, retains additional fields, and converts
folder paths to folders or collections. Unit fixtures cover login and secure
note rows. Its focused 2026-10-21 compiled-CLI comparison matched independent
`/usr/bin/bw` 2026.10.0 on Vaultwarden 1.37.4 (39 expectations across the live
fixture). The test-owned REST sidecar required an explicit signal during
teardown before the runner reported success and removed its container.

Keeper JSON (`keeperjson`) maps logins, payment cards, and legacy identity
records, Keeper's structured custom fields, TOTP, folder relationships, and
cross-record references. Its focused 2026-10-21 compiled-CLI comparison matched
independent `/usr/bin/bw` 2026.10.0 on Vaultwarden 1.37.4 (41 expectations
across the live fixture), including preserved password whitespace, TOTP, card
details, and Keeper folder sanitization. The test-owned REST sidecar required
an explicit signal during teardown before the runner reported success and
removed its container.

Dashlane JSON (`dashlanejson`) maps logins, addresses, identities, payment
cards, and the reference's generic-note fallback. Its focused 2026-10-21
compiled-CLI comparison matched independent `/usr/bin/bw` 2026.10.0 on
Vaultwarden 1.37.4 (39 expectations across the live fixture), including
credential whitespace and the supported legacy card/identity fields. The
test-owned REST sidecar required an explicit signal during teardown before the
runner reported success and removed its container.

PasswordXP CSV (`passwordxpcsv`) supports English, Dutch, and German headers,
folder marker rows, credential fields, descriptions, and additional custom
columns. Its focused 2026-10-21 compiled-CLI comparison matched independent
`/usr/bin/bw` 2026.10.0 on Vaultwarden 1.37.4 (40 expectations across the live
fixture), including significant password whitespace, folder relationships,
and custom data. The test-owned REST sidecar required an explicit signal during
teardown before the runner reported success and removed its container.

Delinea XML (`delineaxml`) imports direct-child secret fields as logins when a
URL slug exists and as secure notes otherwise. It retains custom fields,
password field sensitivity, notes, and folder relationships. Its focused
2026-10-21 compiled-CLI comparison matched independent `/usr/bin/bw` 2026.10.0
on Vaultwarden 1.37.4 (45 expectations across the combined PasswordXP and
Delinea XML live fixture). The test-owned REST sidecar required an explicit
signal during teardown before the runner reported success and removed its
container.

Netwrix Password Secure CSV (`netwrixpasswordsecure`) supports the reference's
semicolon delimiter, language-specific column aliases, multiple URL columns,
TOTP, folders, custom fields, and exports with an additional enclosing quote
layer. Its focused 2026-10-21 compiled-CLI comparison matched independent
`/usr/bin/bw` 2026.10.0 on Vaultwarden 1.37.4 (39 expectations across the live
fixture). The test-owned REST sidecar required an explicit signal during
teardown before the runner reported success and removed its container.

Password Boss JSON (`passwordbossjson`) has parser and unit fixtures for the
current flat-array export and legacy nested `items`/`folders` export, including
logins, cards, notes, tags, custom fields, and folder relationships. Both the
Password Boss and Password Dragon routes now have high-level import tests that
verify their parsed items are encrypted and sent through Vaultwarden's bulk
import endpoint. A revised flat-array Password Boss fixture and a Password
Dragon XML fixture are in the focused live comparison harness. The earlier and
revised Password Boss flat-array fixtures were rejected by `/usr/bin/bw`
2026.10.0 with its generic “Data is not formatted correctly” error. The managed
Vaultwarden suite therefore exercises our Password Boss parser and encrypted
server import while deliberately skipping that reference comparison; no parity
claim is made for this format until a reference-accepted export fixture is found.

Password Depot 17 XML (`passworddepot17xml`) maps login, card, identity, and
secure-note records; favorites, nested groups, custom-field types, and both
Windows child-field and macOS attribute-field layouts are supported. Unit tests
cover XML entity rejection and personal/organization grouping. The focused
Vaultwarden 1.37.4 comparison matched the independent `/usr/bin/bw` 2026.10.0
import for login/card data, favorites, custom fields, and folder membership.

Clipperz HTML (`clipperzhtml`) reads the JSON held in the export's textarea and
maps action types, recognized labels, custom fields, notes, and login-to-note
conversion. The focused comparison against `/usr/bin/bw` 2026.10.0 on
Vaultwarden 1.37.4 passes with the XHTML public doctype present in real exports.

F-Secure FSK (`fsecurefsk`) imports login and credit-card records, favorite
timestamps, URI values, and card custom fields. Its focused Vaultwarden 1.37.4
comparison matched the independent `/usr/bin/bw` 2026.10.0 import, including
the reference's plain-text PIN field behavior.

Proton Pass (`protonpass`) maps unencrypted vault exports into supported
Vaultwarden login, card, note, identity, and SSH-key types, skips trashed items,
and maps vault membership to folders or collections. Its focused Vaultwarden
1.37.4 comparison matched the independent `/usr/bin/bw` 2026.10.0 import for
login, card, note, trash filtering, and vault-folder membership.

Password Dragon XML (`passworddragonxml`) maps login fields, attributes, and
category paths to folders or collections. Unit fixtures cover both ownership
modes, malformed XML, and entity-declaration rejection. Its focused
Vaultwarden 1.37.4 live suite previously reached its 10-minute timeout before
producing a completed cross-client comparison. A smaller fixture is now in the
focused comparison harness; live parity remains unverified.

SafeInCloud XML (`safeincloudxml`) maps login and secure-note cards, detects
payment cards from their autofill fields, handles hidden passwords and OTPs,
and skips deleted/template cards. Unit fixtures cover a BOM-prefixed export,
all three item kinds, and XML rejection cases. A focused 2026-10-21 live run
against Vaultwarden 1.37.4 and `/usr/bin/bw` 2026.10.0 matched three imported
items after removing one trailing line feed from notes in the comparison; the
raw CLI note strings differ by that final line feed. The focused comparison
path in `test/run-compatibility.ts` avoids the slower unrelated REST suite.

Psono JSON (`psonojson`) maps website and application passwords, bookmarks,
TOTP records, secure notes, environment variables, custom values, and nested
folders. Empty folders are skipped as in the reference importer; organization
imports turn folder membership into collections. Its focused 2026-10-21 live
comparison matched both fixture items against `/usr/bin/bw` 2026.10.0 on
Vaultwarden 1.37.4.

Password Safe XML (`pwsafexml`) converts dotted groups into folder paths,
expands the export's notes delimiter, and uses email as the username when the
username is blank. Its focused 2026-10-21 live comparison matched imported
items and folder relationships against `/usr/bin/bw` 2026.10.0 on Vaultwarden
1.37.4.

Sticky Password XML (`stickypasswordxml`) resolves login records through
account links, maps account comments and URLs, and follows group parent IDs to
build folder paths. Its focused 2026-10-21 live comparison matched imported
items and folders against `/usr/bin/bw` 2026.10.0 on Vaultwarden 1.37.4.

Edge (`edgecsv`), Opera (`operacsv`), Vivaldi (`vivaldicsv`), and Brave (`bravecsv`)
share the reference Chrome adapter; Passbolt (`passboltcsv`) shares LastPass.
Arc (`arccsv`) derives its name from the URL hostname and retains notes, while
Avira (`aviracsv`) maps `website` and preserves primary/secondary usernames.
The reference dispatch is in
[`ImportService`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/libs/importer/src/services/import.service.ts),
with distinct Arc and Avira mapping classes. All seven new IDs were exercised
through the compiled Node CLI and independently imported by `/usr/bin/bw`
2026.10.0 on Vaultwarden 1.37.4 under Node 26.11.1 on 2026-10-21. The focused
fixture passed 73 expectations in 162.72 seconds, comparing decrypted fields
and folder relationships alongside its authentication/REST checks. It includes
Android URL conversion, literal URI commas, notes, whitespace-sensitive secrets,
Avira alternate usernames, and structured LastPass/Passbolt records. The
fixture container was removed. This comparison used personal imports under
PBKDF2; broader server/KDF/scope coverage remains required work.

Quiet output now follows the executable's output policy across DreamCLI results
and raw secret/export/Send/attachment writers. The policy is scoped to a command
execution with AsyncLocalStorage; stdout is not globally monkey-patched. The
DreamCLI lifecycle activates it immediately before the action, preserving parser
errors and help/version output. Built-CLI tests cover nested commands, side
effects, failures, literal flags after `--`, named environment defaults, raw
secret values, and raw JSON exports without altering encrypted cache state.
Independent `/usr/bin/bw` 2026.10.0 probes in disposable profiles verified silent
status/generation and authentication failures, visible version output, and
visible parser errors. A 1.36.0 PBKDF2 run under Node 26.11.1 passed 141
expectations in 44.76 seconds on 2026-10-21, including silent password/raw
attachment reads and a quiet download whose written file was checked byte for
byte. That server fixture did not use the independent reference client.

The CLI now depends on the published `@kjanat/dreamcli` 4.2.0 release rather than
the temporary PR preview. Both CI jobs use plain `bun install`; the workaround
that updated the moving preview before installation has been removed.
Against 4.2.0, a clean-cache installation, build, types, lint, 128 library tests
and 33 non-live CLI tests passed; seven opt-in live cases were skipped.
Earlier preview verification covered build, types, lint and all 128 library/30
non-live CLI tests. The real 1.37.4 SSO fixture also passed under both KDFs (54 expectations
in 14.43 seconds), including compiled `--pretty login --sso identifier --raw`.

Pretty output is a declared boolean flag on each command, created before actions
or child registrations, and on the root help surface. DreamCLI handles flag
parsing and routing, including leading and nested occurrences. The output hook
serializes structured JSON with two-space indentation; it never attempts to
parse stdout to guess its type. Tests verify compact defaults, `VW_PRETTY`,
explicit false overrides, quiet precedence, nested templates, schema-derived
completions, JSON mode, literal flags after `--`, and unchanged raw secret/export
bytes. Response envelopes and clean-exit behavior remain required work.

All terminal prompts now use DreamCLI's shared prompt
session. Hidden password entry replaces `@inquirer/password` for login, API
secrets, two-factor codes, Send passwords, and protected imports; its dependency
and transitive lockfile entries were removed. Ordinary and hidden input share
one adapter reader. Unsupported hidden input fails before reading visibly;
empty submissions retry, whitespace is preserved, and cancellation propagates.
The CLI fixture exercises a real POSIX PTY with the compiled Node prompt host:
secret entry, backspace editing, Ctrl+C, consecutive visible/hidden questions,
email-provider selection followed by a hidden code, and cancellation through
compiled `login`. It verifies absence of secret text in the terminal transcript,
restoration of ECHO/ICANON, natural process exit, cancellation exit 130, and an
unauthenticated profile afterward. Synthetic data only is used. PTY tests require
POSIX and Python 3, and skip on unsupported hosts; CI explicitly checks for
Python 3. The fixture is included in the hosted unit-test job.
