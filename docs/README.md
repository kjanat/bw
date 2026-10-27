# Vaultwarden TypeScript client

An independent client with an explicit commitment to Vaultwarden compatibility.
The TypeScript library implements the protocol and cryptography; a DreamCLI
frontend supplies commands and local state. Neither package invokes `bw`.

See [intentional accommodations for Vaultwarden](vaultwarden-deviations.md) for
the differences from the Bitwarden reference, their server/version conditions,
and the source and test evidence for each.

The implementation is being developed against the full Vaultwarden-supported
`bw` command surface tracked in [implementation status](implementation-status.md).
Both packages are private while the API and compatibility coverage develop. The executable is `vw` to avoid colliding
with an installed Bitwarden CLI.

## Packages

- `packages/vaultwarden` — `@kjanat/vaultwarden`: transport, authentication,
  PBKDF2/Argon2id, master-password hashing, user-key unwrapping, authenticated
  EncString encryption/decryption, per-item and organization keys, and vault operations.
- `apps/cli` — `@kjanat/vaultwarden-cli`: DreamCLI commands, private atomic
  local storage, encrypted cache, and revocable local unlock sessions.
- `packages/typescript-config` — shared TypeScript compiler settings.

## Run

Requires Bun for dependency management/tests and Node 24.8.0+ for the compiled CLI.

```sh
bun install
bun run build --filter=@kjanat/vaultwarden-cli
node apps/cli/dist/main.js --help
node apps/cli/dist/main.js config server https://vault.example.com
export VW_SESSION="$(node apps/cli/dist/main.js login you@example.com --raw)"
node apps/cli/dist/main.js list items
node apps/cli/dist/main.js list items --search example
node apps/cli/dist/main.js get password ITEM_ID
node apps/cli/dist/main.js lock
unset VW_SESSION
node apps/cli/dist/main.js logout
```

`--quiet` suppresses command results on stdout and command-error diagnostics on
stderr, including raw secrets, attachment bytes, and raw exports. Downloads to
`--output` still write files, and command exit codes do not change. Help, version,
and argument-parser errors stay visible, matching the reference CLI. Set
`VW_QUIET=true` for the default; pass `--quiet=false` to override it. After `--`,
`--quiet` is treated as an argument.
`--pretty` formats structured JSON with two-space indentation. Raw secrets,
attachments, exports, and text bypass formatting and write their original bytes.
The flag works before or after a command, including nested commands.
`VW_PRETTY=true` sets the default and `--pretty=false` overrides it.
`--response` emits success/data and failure/message JSON envelopes. Response
payloads for some commands still need parity checks. `--cleanexit` makes command
errors return status 0; `--cleanexit=false`
restores the normal failure status. `VW_CLEANEXIT` accepts `true` or `false` as
the default. Environment variables use the `VW_` prefix derived from the CLI
name.

Environment reads have five roles:

| Values                                                                                                                                                                                                                 | Read path                                                                                                                 | Purpose                                                                                                       |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `VW_SESSION`, `VW_PASSWORD`, `VW_EMAIL`, `VW_2FA_TOKEN`, `VW_CLIENTID`, `VW_CLIENTSECRET`, `VW_IMPORT_PASSWORD`, `VW_EXPORT_PASSWORD`, `VW_SEND_PASSWORD`, `VW_SERVE_TOKEN`, `VW_PRETTY`, `VW_RAW`, `VW_NOINTERACTION` | DreamCLI `.env()` bindings on command inputs; `cli('vw').envPrefix('VW_')` maps `.env('SERVE_TOKEN')` to `VW_SERVE_TOKEN` | Resolve fixed-name command inputs. Credential values also use `.sensitive()` so parser diagnostics omit them. |
| `VW_CLEANEXIT`, `VW_RESPONSE`, `VW_NOINTERACTION`, `VW_QUIET` and their `BW_*` aliases                                                                                                                                 | `apps/cli/src/main.ts`                                                                                                    | Apply process-wide exit, response, prompt, and output behavior before command execution.                      |
| Names supplied to `--passwordenv`, `--clientidenv`, and `--clientsecretenv`                                                                                                                                            | `apps/cli/src/auth-input.ts`, `tool-commands.ts`, and `send-commands.ts`                                                  | Read a variable chosen at runtime; `.env()` takes a fixed name declared in the command schema.                |
| `VW_APPDATA_DIR`, `XDG_CONFIG_HOME`                                                                                                                                                                                    | `apps/cli/src/store.ts`                                                                                                   | Select the local account-state directory; `VW_APPDATA_DIR` wins, then the XDG default.                        |
| `PATH`                                                                                                                                                                                                                 | `apps/cli/src/webauthn.ts`                                                                                                | Give the system WebAuthn helper access to installed commands.                                                 |

The CLI depends on `@kjanat/dreamcli` 5.0.0, as recorded in the Bun lockfile. Its
prompt session and password factory handle master passwords, API secrets,
verification codes, Send passwords, and protected-import passwords. The hidden
prompt accepts whitespace as entered and restores terminal state after submission
or cancellation. Cancelling login exits with status 130 before authentication.

Password login syncs the vault, unlocks it, and prints a session token. `--raw`
prints only that token. Login and unlock accept a positional password,
`--passwordfile PATH` (first line), or `--passwordenv NAME` (default `VW_PASSWORD`),
in that order of precedence. Without a supplied password they prompt on an
interactive terminal; `--nointeraction` disables prompting. The CLI does not
store master passwords. An omitted login email comes from `VW_EMAIL` or a prompt.
`login --check` checks authentication; `unlock --check --session TOKEN` checks a
local unlock token without prompting or changing it.
For two-factor login, pass `--method 0 --code TOKEN` for TOTP, or use another
provider ID. `VW_2FA_TOKEN` supplies the code. On an interactive terminal, the
CLI offers methods that Vaultwarden reports with the required challenge data:
TOTP, email, Duo, YubiKey OTP, WebAuthn, and recovery code. Choose one from the
prompt or pass `--method` in advance. Email selection requests a login code
before prompting. With `--nointeraction`, pass both the method and code; the CLI
does not request an email code. Code entry is hidden.

Use `login --sso [organization-identifier]` for an existing SSO account or a
Vaultwarden JIT-provisioned account. The CLI opens the authorization URL and
receives the callback on localhost ports 8065–8070, then uses the master password
to unlock the vault. On first login, if Vaultwarden has not initialized the
account's wrapped user key, the CLI initializes the master password and account
keys through Vaultwarden's set-password endpoint before syncing and unlocking.
`--nointeraction` prints the URL without opening a browser; complete it externally
and supply a password through the normal input sources. Authorization uses S256
PKCE and random state; callback validation happens before the code exchange. The
code and verifier are not stored in the account profile.

The library exposes `createSsoAuthorization`, `ssoCredentialsFromCallback`, and
`loginWithSso`. Callers own the browser and callback transport; the returned
authorization object is short-lived secret-bearing state. `loginWithSso` accepts
the same optional two-factor callback contract as password login. Email delivery
for a pending SSO challenge uses the pending device identifier, without sending
a master password hash. Existing-account and JIT SSO, refresh, TOTP, PKCE
rejection, and compiled CLI first-login setup are live tested; SSO email
challenges are currently protocol tested only.

Library callers can pass a fifth argument to `loginWithPassword(client, email,
password, twoFactor, { onTwoFactor })`. The callback receives the server's provider
IDs and an explicit `requestEmail()` operation, without receiving the password
or password hash. Return `{ provider, token }` to retry once, or throw to cancel.
Callers can omit the callback and handle two-factor interaction in their own code.
TOTP challenge completion is live verified. Email challenges are also live
verified with a capture-only SMTP receiver on Vaultwarden 1.36.0 and 1.37.4 under
both PBKDF2 and Argon2id.
The tests cover a separate verification address, delivered-code login through
the library and compiled CLI, replay/wrong-code rejection, and noninteractive
missing-code failure without a new email request.

`vw sync --last` reads the last successful sync timestamp locally, including
while locked. It requires a logged-in account and makes no server request.
Ordinary `sync` checks the account revision and skips the cache write when the
revisions match. `sync --force` (or `-f`) downloads the full vault. Both work
without an unlock token. A failed request does not update the last successful timestamp.
That timestamp marks the start of synchronization, so server changes made during
the request appear in the next revision check. Mutations and login request a full
cache refresh.

`vw --version` reports this CLI package's version; `vw sdk-version` reports the
independent TypeScript library's `SDK_VERSION`. These are separate from the
Bitwarden protocol version sent in request headers. `vw update` checks this
CLI's own npm package channel when it is public. The current package is private,
so it reports that no public update channel is configured and makes no network
request. Update checks do not install software or change the vault.

The reference `device-approval` command manages organization SSO trusted-device
requests. On Bitwarden-compatible servers, the CLI lists pending requests and
can approve or deny them after checking the signed-in organization's password
management permission. Approval decrypts account-recovery material locally and
encrypts the user key to the requesting device. Vaultwarden 1.36.0 and 1.37.4
are identified by `/api/config` and rejected with a typed capability error
because they do not implement these organization routes. Synthetic API and
cryptographic tests cover the Bitwarden request flow; live Bitwarden Cloud
verification has not been run. Personal `/auth-requests` are not substituted.

For installations with separate services, configure their full endpoint URLs:

```sh
node apps/cli/dist/main.js config server https://vault.example.com \
  --api https://api.example.com/api \
  --identity https://auth.example.com/identity \
  --web-vault https://web.example.com
```

API and identity overrides replace the base URL plus `/api` or `/identity`, and
their configured paths are used as supplied. Prelogin's older API fallback uses
the API override.
`--web-vault` supplies the base for generated Send access links. The CLI also
stores the `--icons`, `--notifications`, `--events`, and `--key-connector` URLs.
See the implementation inventory for command coverage of those services.
Read the base with `config server`. Each config update replaces the override
set, so setting a base URL without flags clears prior overrides. Log out before
changing any endpoint. All endpoints require HTTPS except HTTP on loopback.
Library callers pass the same overrides through `new VaultwardenClient(base,
{ services: { api, identity, webVault } })`.

`get` accepts `item`, `password`, `username`, `uri`, `notes`, `totp`, `folder`,
`collection`, and `organization`, followed by an
item ID or a unique search query. `list items` and `get item` return JSON, including
secrets. `get password` prints the requested value. Password login returns an
unlock session; API-key login leaves the vault locked. Sync downloads encrypted data and can run while locked; list/get
work offline after a successful sync. `status` reports `unauthenticated`, `locked`,
or `unlocked` for the supplied `VW_SESSION` or `--session` token.

## API-key authentication

```sh
node apps/cli/dist/main.js login --apikey --nointeraction
node apps/cli/dist/main.js sync
export VW_SESSION="$(node apps/cli/dist/main.js unlock --passwordenv VW_PASSWORD --raw)"
node apps/cli/dist/main.js get password ITEM_ID
```

API-key login uses `VW_CLIENTID` (`user.USER_UUID`) and `VW_CLIENTSECRET`.
`--clientidenv NAME` and `--clientsecretenv NAME` select other environment
variables.
Missing values prompt interactively, with the secret hidden. Only personal user
API keys can access the vault; organization API keys use a separate server scope.
The client resolves the email and KDF from authenticated server responses and
verifies that the profile ID matches the requested API principal. An API key
retrieves encrypted data; the master password is still needed for unlock.

Vaultwarden returns no refresh token for this grant. The private state file
stores the client ID, client secret, and bearer token so sync
and other online operations can renew via `client_credentials` while locked.
The CLI retries sync once after HTTP 401. If renewal returns different wrapped
key/KDF settings, it invalidates the local cache and unlock session and requires
a fresh sync and unlock. Logout deletes the local API credentials. The API key
on the server stays active.

## Vault management

`get template NAME` returns a JSON template while the vault is locked; it requires
a logged-in account. Bank-account, driver's-license, and passport templates are
available on Vaultwarden 1.37.4 and newer. `encode` reads UTF-8 stdin and emits
base64; create/edit accept that encoded JSON as an argument or from stdin. The
same command pattern applies to items and folders:

```sh
node apps/cli/dist/main.js get template folder
printf '%s' '{"name":"Work"}' | node apps/cli/dist/main.js encode | node apps/cli/dist/main.js create folder
node apps/cli/dist/main.js get item ITEM_ID
# Edit the returned JSON without changing its revisionDate, then encode it:
node apps/cli/dist/main.js edit item ITEM_ID ENCODED_JSON
node apps/cli/dist/main.js archive item ITEM_ID
node apps/cli/dist/main.js list items --archived
node apps/cli/dist/main.js restore item ITEM_ID
node apps/cli/dist/main.js delete item ITEM_ID
node apps/cli/dist/main.js list items --trash
node apps/cli/dist/main.js restore item ITEM_ID
node apps/cli/dist/main.js delete item ITEM_ID --permanent
```

Item writes cover login, secure note, card, identity, and SSH-key data. Edits
reuse each item's key and send the caller's revision date to Vaultwarden for
conflict detection. Successful mutations refresh the encrypted local cache.
If a server change succeeds but cache refresh fails, the command reports that
specific outcome and invalidates the cache instead of retrying the write.

`list` also supports `folders`, `collections`, and `organizations`. Item filters
include `--folderid`, `--organizationid`, `--collectionid`, `--trash`, and
`--archived`; ID filters combine with OR, while `--search` combines with AND.
Organization keys are unwrapped using the account RSA private key. Creating an
organization-owned item requires `organizationId` and `collectionIds` in the
item JSON. `get totp ITEM_ID` supports base32 secrets, otpauth URIs, and Steam
secrets. Source imports consistently use package-local `#` aliases, with Bun and
TypeScript selecting source files and compiled Node selecting `dist` files.

## Generation and transfers

```sh
node apps/cli/dist/main.js generate --length 24 -u -l -n -s
node apps/cli/dist/main.js generate --passphrase --words 6 --capitalize
node apps/cli/dist/main.js import --formats
node apps/cli/dist/main.js export --format json --output ./vault.json
node apps/cli/dist/main.js export --format encrypted_json --passwordenv EXPORT_PASSWORD --output ./vault.encrypted.json
node apps/cli/dist/main.js import bitwardenjson ./vault.encrypted.json --passwordenv EXPORT_PASSWORD
node apps/cli/dist/main.js export --format zip --output ./vault.zip
node apps/cli/dist/main.js import bitwardenzip ./vault.zip
```

Generation uses cryptographic randomness and the 7,776-word EFF list for
passphrases. Enabled generator policies from the encrypted cache enforce their
minimums. Without a logged-in cache, generation uses local defaults. Cached
policies may be stale until the next sync.
CLI and local API generation read both `policies` and `policiesNew`, with the
same organization membership exemptions.
To bound input-driven allocation, password output is limited to 65,536
characters and passphrases to 8,192 words; larger requests return an error.

Exports support CSV, JSON, account-encrypted JSON, password-encrypted JSON,
and ZIP with decrypted attachments. Without an export password, encrypted JSON
is bound to the current account key. Password exports use an independent salt
and the account KDF parameters. `--passwordenv` and `--passwordfile` select a
password source; `VW_EXPORT_PASSWORD` and `VW_IMPORT_PASSWORD` are the default
variables for those operations. Plain exports contain vault secrets. File
output uses mode 0600 and refuses overwrite; `--raw` writes directly to stdout.

Imports validate every item's type-specific data before uploading, then sync
and verify all submitted content, folder/collection records, and each item's
folder/collection assignments before reporting success. Verification allows
server-added metadata and equivalent date/empty-array representations. An
incomplete or unverifiable import raises an error and invalidates
the CLI cache; inspect the server vault before retrying to avoid duplicates.
ZIP imports reject duplicate source item IDs before changing the server.

Imports currently accept Bitwarden JSON/CSV/ZIP, Avast JSON (`avastjson`),
Enpass JSON (`enpassjson`), GNOME Passwords JSON (`gnomejson`), Passky JSON (`passkyjson`),
Passman JSON (`passmanjson`), Enpass CSV (`enpasscsv`), Delinea CSV (`delineacsv`),
Kaspersky Password Manager TXT (`kasperskytxt`), Chrome/Edge/Opera/Vivaldi/Brave,
Zoho Vault CSV (`zohovaultcsv`), RoboForm CSV (`roboformcsv`),
Firefox/Safari/Arc CSV, Avira CSV,
KeePassX/KeePassXC CSV (`keepassxcsv`),
LastPass/Passbolt CSV (`lastpasscsv`, `passboltcsv`), NordPass CSV
(`nordpasscsv`), Encryptr CSV (`encryptrcsv`), PassKeep CSV (`passkeepcsv`),
PasswordWallet text CSV (`passwordwallettxt`), Passpack CSV (`passpackcsv`),
Ascendo (`ascendocsv`), BlackBerry (`blackberrycsv`), Blur (`blurcsv`),
Codebook (`codebookcsv`), Avast (`avastcsv`), Buttercup (`buttercupcsv`),
Padlock (`padlockcsv`), Yoti (`yoticsv`), SaferPass (`saferpasscsv`),
SecureSafe (`securesafecsv`), Meldium (`meldiumcsv`), True Key (`truekeycsv`),
SplashID (`splashidcsv`), RememBear (`remembearcsv`), UPM (`upmcsv`), LogMeOnce
(`logmeoncecsv`), Myki (`mykicsv`), mSecure (`msecurecsv`), Password Agent
(`passwordagentcsv`), Dashlane (`dashlanecsv`), plaintext
KeePass 2 XML (`keepass2xml`), encrypted
KeePass databases (`keepasskdbx`), and
1Password 8 archives or extracted `export.data` JSON (`1password1pux`), 1PIF
(`1password1pif`), and Mac/Windows CSV (`1passwordmaccsv`, `1passwordwincsv`).
This CLI supports every import format listed by bw 2026.10.0 and also supports
`bitwardenzip` for native ZIP backups. Items receive fresh encryption keys and
IDs, and folder/collection relationships are remapped. Imports add data;
they do not deduplicate existing items. Personal exports omit organization items
and trash. Use `--organizationid ORG_ID` for organization imports and exports.
Organization export uses the server's administrative export endpoint.

```sh
node apps/cli/dist/main.js import 1password1pux ./backup.1pux
```

1PUX imports map logins, passwords, cards, identities, secure notes, and SSH keys
to Vaultwarden's supported item types. Bank accounts become cards with remaining
values in custom fields; passports and licenses become identities. The first
tag supplies the folder/collection path, including parent folders. The importer
copies favorites, archive state, OTPs, guarded custom fields, and the latest
five password-history records. Ed25519, RSA and NIST P-256/P-384/P-521 PKCS#8 SSH
keys become OpenSSH keys with derived public keys and SHA256 fingerprints.

The library exposes `parseOnePassword1Pux(bytesOrJson, organization?)` for preview.
Each failed item appears in the import result's optional `errors` array, with
its source UID and a reason; it creates no dangling folder relationship. ZIP
input reads only the root `export.data` entry, bounded to 100 MiB, without
extracting paths. Document binaries are not restored by this reference mapping.
The importer processes every source account and vault. The reference CLI reads
only the first account.

```sh
node apps/cli/dist/main.js import 1password1pif ./data.1pif
node apps/cli/dist/main.js import 1passwordmaccsv ./export.csv
node apps/cli/dist/main.js import 1passwordwincsv ./export.csv
```

1PIF imports standard and Windows OPVault-shaped records, skips trash, and adds
notes, hidden custom fields, OTPs, and up to five password-history entries.
Source markers and separate JSON records are parsed as a stream, not as one JSON
document. Tags do not create folders in these reference mappings. Mac and Windows CSV use their respective
type detection, card expiration and identity headings, including multiline
Windows addresses. CSV quote escaping uses backslashes for these two adapters;
other CSV formats use doubled-quote escaping. Singular `URL` columns are
read correctly, fixing the pinned reference client's unassigned-concatenation
bug; plural `URLs` columns produce every entry. Library previews are
available through `parseOnePassword1Pif(text, organization?)` and
`parseOnePasswordCsv(format, text, organization?)`.

External CSV formats use separate vendor mappings. Commas in a URL are parsed
as URL characters, not CSV separators. Chrome Android URLs become `androidapp://` URIs. Firefox
entry names come from hostnames; its internal Firefox Accounts entry is skipped.
Edge, Opera, Vivaldi, and Brave use the Chrome mapping, including notes and
Android URL handling. Arc derives its entry name from the URL hostname and
copies notes. Avira maps its `website` column, falls back to a secondary
username when the primary is blank, and records the secondary username in notes
when both exist. Passbolt uses the LastPass mapping, including structured notes.
Safari OTP fields and notes are imported. KeePassX groups drop the exported
`Root/` prefix and become folders, or collections for organization imports.
LastPass supports sites, generic secure notes, structured credit-card/address
notes, and form-fill profiles, including a card accompanying an identity.
Folder paths, favorites, unknown structured-note fields, and note continuations
are imported. The importer rejects malformed headers and row widths before it
contacts the server.

NordPass CSV maps password, credit-card, identity, and note records, skipping
unknown types. It copies additional URLs, secret whitespace, custom fields,
card expiration, and address data. Hidden custom fields stay hidden unless long
or multiline: those move into notes following the reference mapping. Folder
paths become collections for organization imports. Invalid embedded JSON or
malformed URL/custom-field arrays fail before any upload, even after valid rows.

Encryptr CSV maps password and credit-card records, joins its Notes and Text
columns with a blank line, and converts other record types or empty passwords
into secure notes, matching the reference importer. Card brands and `MM/YY` expiry
values are populated from the exported fields.

`parseExternalCsv(format, text, organization?)` lets library callers inspect the
native document before importing it. The import operation encrypts it through
the same bulk pipeline as Bitwarden JSON. LastPass HTML files extract and decode
the CSV from their `<pre>` block. The reference CLI gates conversion into bank,
passport, and license item types behind a feature flag. This importer creates
complete secure notes for those records by default.

```sh
node apps/cli/dist/main.js import keepass2xml ./keepass-backup.xml
```

KeePass XML entries become logins. The root group's name is omitted; nested
groups become slash-separated folder paths, or collections with `--organizationid`.
Title, URL, UserName, Password, Notes, and `otp` fields use the reference mappings.
`ProtectInMemory="True"` custom values stay hidden fields even when multiline or
longer than 200 characters. Other long/multiline custom values move into notes.
Predefined/numeric XML entities and CDATA decode as text, while entity declarations, external DTDs,
and malformed XML are rejected before mutation. The library exposes
`parseKeePassXml(text, organization?)` for inspecting the document first.
As in the reference importer, nested history and embedded binaries are ignored;
this format does not restore KeePass attachment files.

```sh
node apps/cli/dist/main.js import keepasskdbx ./vault.kdbx --passwordenv DATABASE_PASSWORD
node apps/cli/dist/main.js import keepasskdbx ./vault.kdbx --keyfile ./vault.keyx --passwordenv DATABASE_PASSWORD
```

KDBX 3.1 and 4 imports accept passwords, key files, or both. Omitting a password
with a key file selects key-file-only access. Without either input, an interactive
terminal prompts for the database password. `--passwordfile` reads its first
line; `VW_IMPORT_PASSWORD` is the default environment source. Library callers
use `parseKdbx(bytes, { password, keyFile, organization })`, or pass `password`
and `keyFile` bytes to `importVault`.

KDBX follows its own reference mappings: enabled recycle bins are omitted, long
and multiline custom values import as fields, and protected values import as
hidden fields.
KeePassXC `otp` and KeePass `TimeOtp-*` secrets/settings become login OTP values.
AES, Argon2d and Argon2id KDFs are supported, with AES and ChaCha20 payloads.
History and binary attachments are outside the reference KDBX import mapping.
Decoding runs in an isolated worker; input size, group depth, KDF work and runtime
are bounded as documented in the compatibility notes. `bun install` applies a
decoder patch that prevents tabs in unprotected text from becoming spaces.

ZIP backups use the Bitwarden `data.json` and sanitized attachment-path layout.
Final attachment paths are unique, even when generated suffixes collide with
existing filenames. Export and import apply the same item-folder ambiguity
checks. Export rejects conflicting sanitized names and duplicate names paired
with incomplete attachment folders. Rename conflicting items before retrying.
Import also accepts older vw manifests.
Backup downloads use exact item and attachment IDs, without filename searches.
Any attachment download or decryption failure aborts the export before it writes
a backup. To create a partial backup, pass `--allow-partial`; the CLI lists each
skipped attachment on stderr. SDK callers must provide both
`allowPartial: true` and `onAttachmentSkipped`. JSON and attachment export apply
the same item-policy filter.
Archives are read in memory without extracting their paths to the filesystem.
The total inflated ZIP limit is 1 GiB, with a 525 MiB limit per entry. A bulk
import or attachment restoration can partially succeed on the server; failures
invalidate the local cache and instruct the caller to sync before retrying.

For attachment downloads, an explicit `--output /path/to/file` overrides even an
unusable remote filename. Directory/default output still validates that remote
name, and all file output refuses overwrite.

## Item lookup and URI matching

```sh
node apps/cli/dist/main.js get password 'work alice'
node apps/cli/dist/main.js list items --search 'cafe company'
node apps/cli/dist/main.js list items --url https://login.example.com
node apps/cli/dist/main.js get fingerprint me
node apps/cli/dist/main.js get fingerprint USER_UUID
```

Basic item search matches every query term against at least one display field:
name, notes, username/subtitle, URI hostname, or an ID prefix of at least eight
characters. It ignores case and common combining diacritics. Passwords, card
security codes, full card numbers, identity secrets, and URI paths/query strings
are not search targets. A missing full UUID never falls back to a name search.

Name searches consider active items. A full item ID can retrieve archived or
trashed items. Secret-field queries filter candidates before deciding whether
the search is ambiguous; for example, a note with the same name does not make a
password query ambiguous. Multiple eligible results require an item ID.

Folder, collection, and organization reads accept a UUID or a unique,
case-insensitive name substring. These searches match accents and whitespace
literally and compare the entire substring instead of splitting it into item search terms.
An exact name remains ambiguous when another object's name contains it. A UUID
is always an ID lookup and never falls back to an object named after that UUID.
Library callers use `findFolder`, `findCollection`, and `findOrganization` on
`VaultService`; mutations continue to require IDs.

Vault reads that can decrypt organization data are asynchronous: await
`getItem`, `findItem`, `listItems`, `findCollection`, and `listCollections`.
The `decryptSharedKey` and `encryptSharedKey` helpers also return promises.
Organization envelopes use `micro509` RSA-OAEP with SHA-256 for type 3 and
explicit legacy SHA-1 imports for type 4. Dispose the service after awaited
operations finish to clear cached organization keys; disposal also invalidates
pending key decryptions.

`list items --url` honors each saved URI's match setting:

| Value | Mode               | Behavior                                                               |
| ----- | ------------------ | ---------------------------------------------------------------------- |
| 0     | Domain             | Registrable domain, with private suffixes and equivalent-domain groups |
| 1     | Host               | URL host, including a non-default port; paths and schemes may differ   |
| 2     | Starts with        | The target starts with the saved string                                |
| 3     | Exact              | The strings are equal                                                  |
| 4     | Regular expression | Case-insensitive ECMAScript regex                                      |
| 5     | Never              | Excluded from URL matching                                             |

The default is domain matching unless an applicable URI-default policy or
library caller specifies another default. URL matching excludes trash and
archived items, including when combined with those flags. Other ID filters
combine with OR; URL and text search combine with them using AND. Collection
filters accept `null` and `notnull` for unassigned/assigned items.

New and edited login URIs receive an encrypted SHA-256 checksum. Reads of items
with per-item keys discard URIs whose checksum is missing or invalid, matching
the SDK's integrity check. Legacy owner-key items use the older URI handling.
The same write helper is used by item creation, editing, legacy-item moves, and
bulk imports, so peer clients receive the URI after decryption.

Sync includes Vaultwarden's equivalent-domain settings. The pinned bw CLI
excludes those settings from its sync response because its platform does not
support autofill, so equivalent-domain matching differs deliberately: vw honors
the server's groups. Private suffixes distinguish unrelated tenants (for
example, `alice.github.io` and `bob.github.io`), Unicode/punycode domains compare
equally, and the reference `script.google.com` domain exclusion also applies.
Regexes run in an isolated worker with a 200 ms execution limit; a timeout fails
the query rather than returning an incomplete result.

Fingerprints hash the public-key bytes with SHA-256, use HKDF-expand with the
user ID, and encode the result as five EFF words. `me` uses cached account key
metadata when present. Other user IDs retrieve the public key from Vaultwarden;
no private key is required for this calculation.

## Local REST API

```sh
node apps/cli/dist/main.js serve --hostname 127.0.0.1 --port 8087
curl -fsS http://127.0.0.1:8087/status
curl -fsS 'http://127.0.0.1:8087/list/object/items?search=example'
```

Log in before starting the server. `--session TOKEN` or `VW_SESSION` starts it
unlocked; without a session it starts locked and accepts `POST /unlock` with a
JSON `{ "password": "..." }` body. Unlock never reads a file or environment
variable named by an HTTP request. The active token stays in the server process;
`POST /lock` invalidates the persisted unlock session too. Sync works while locked.
Local API access uses this process's logged-in account and unlock state, with
no per-request credential on loopback unless `VW_SERVE_TOKEN` is set.
`POST /attachment` accepts exactly one multipart file part named `file`; duplicate
or differently named file parts return HTTP 400 without uploading a file.

The default bind is `localhost:8087`. `--hostname all`, any non-loopback bind,
and inherited network sockets require `VW_SERVE_TOKEN` with at least 32 printable
ASCII characters. Each request then needs `Authorization: Bearer $VW_SERVE_TOKEN`.
For example, generate a token with `openssl rand -hex 32`, set it in the server's
environment, and send it in the Authorization header. The server never prints
the token. If `VW_SERVE_TOKEN` is set for a loopback listener, requests there
also require the token. Unix sockets are created with owner-only permissions.

`--port 0` falls back to `8087`. Origin headers are rejected by default,
including empty Origin values. Host headers must identify localhost, a loopback
address, or the configured hostname with the listening port. The `all` binding
accepts other Host values, after bearer authentication. `--disable-origin-protection`
disables the Origin and Host checks; bearer authentication still applies.
Responses include `Cache-Control: no-store`.

Unix sockets and inherited descriptors use the reference hostname forms:

```sh
node apps/cli/dist/main.js serve --hostname unix:///absolute/path/vw.sock
curl --unix-socket /absolute/path/vw.sock http://localhost:8087/status
```

`fd+listening://3` accepts an inherited listening socket; `fd+connected://3`
serves one inherited connected socket. The parent process must pass the named
descriptor. Connected mode exits when that connection closes. Node listener
tests exercise both descriptor modes and verify Unix socket permissions and removal.

| Method | Route                                                 | Operation                                                             |
| ------ | ----------------------------------------------------- | --------------------------------------------------------------------- |
| GET    | `/status`, `/generate`                                | State and password/passphrase generation                              |
| POST   | `/sync`, `/lock`, `/unlock`                           | Cache and session lifecycle                                           |
| GET    | `/list/object/:object`                                | Items, folders, collections, organizations, members, Sends            |
| GET    | `/object/:object/:id`                                 | Vault objects, secret fields, templates, fingerprints, attachments    |
| POST   | `/object/:object`                                     | Create an item, folder, organization collection, or text Send         |
| PUT    | `/object/:object/:id`                                 | Edit an object or item collection assignments                         |
| DELETE | `/object/:object/:id`                                 | Delete/trash an object; `?permanent=true` permanently deletes an item |
| POST   | `/archive/item/:id`, `/restore/item/:id`              | Archive and restore                                                   |
| POST   | `/move/:id/:organizationId`                           | Move with a JSON array of collection IDs                              |
| POST   | `/confirm/org-member/:id`                             | Confirm membership with `?organizationid=...`                         |
| POST   | `/attachment?itemid=...`                              | Upload a multipart `file` field                                       |
| GET    | `/send/list`                                          | List Sends                                                            |
| POST   | `/send/:id/remove-password`                           | Remove a Send password                                                |
| GET    | `/device-approval/:organizationId`                    | List pending organization device approvals                            |
| POST   | `/device-approval/:organizationId/approve/:requestId` | Approve one request                                                   |
| POST   | `/device-approval/:organizationId/deny/:requestId`    | Deny one request                                                      |
| POST   | `/device-approval/:organizationId/approve-all`        | Approve all pending requests                                          |
| POST   | `/device-approval/:organizationId/deny-all`           | Deny all pending requests                                             |

JSON requests use unencoded objects rather than the CLI's base64 input.
Responses use `{ "success": true, "data": ... }`; lists and strings have
`{ "object": "list"|"string", "data": ... }` inside that envelope. Attachment
downloads return binary bytes with an attachment disposition. Command errors
return HTTP 400 with `{ "success": false, "message": "..." }`; rejected guards
return 403 and unknown routes return 404. Status and template results use
`{ "object": "template", "template": ... }`. Objects carry `item`, `folder`,
`collection`, `org-collection`, `organization`, `org-member`, or `send`
discriminators. GET routes support HEAD; OPTIONS describes allowed methods,
and unsupported methods return 405. JSON bodies are limited to 1 MiB;
URL-encoded form bodies use the pinned parser's 56 KiB limit.
Item responses use the reference client model: inactive sections and server-only
permissions metadata are omitted, dates use millisecond precision, attachment
keys are excluded, and hidden-password metadata redacts the protected values.

Send creation through REST requires an explicit future `deletionDate`. File Send
creation through `serve` is rejected, matching the pinned reference CLI; use the
ordinary CLI or library for file Sends. An HTTP file Send request never causes
the server to read a named host file.
Device-approval routes use the same organization permission and recovery-key
checks as the CLI. On Vaultwarden 1.36.0 and 1.37.4, they return the explicit
unsupported-capability error before sending an organization request.

Library integrations can use `createLocalApiHandler(backend, options)` with
standard Fetch requests and responses. The backend supplies state/session
operations and a `run` callback that owns each `VaultService` and its key lifetime.
Requests run one at a time so lock/unlock and mutations arrive in order. The
compiled CLI's TCP lifecycle is live tested, and Unix and inherited-descriptor
listeners have compiled Node integration tests. An optional independent bw local
server compares response contracts using the same disposable vault. Remaining
exact-field and error-message parity is tracked in the implementation inventory.

## Shell completion

```sh
node apps/cli/dist/main.js completions zsh > ./_vw
node apps/cli/dist/main.js completions bash > ./vw.bash
node apps/cli/dist/main.js completions fish > ./vw.fish
node apps/cli/dist/main.js completions powershell > ./vw.ps1
```

Completion scripts target the `vw` executable. Install or source the generated
script using the selected shell's completion setup. They are generated from the
same DreamCLI schema that defines the commands, subcommands, enum arguments,
and flags, so additions to the command definitions appear in completion output.
Generation does not require login or read vault data.

## Organization administration

Use `--organizationid` with organization collection and member commands:

```sh
node apps/cli/dist/main.js list org-collections --organizationid ORG_ID
node apps/cli/dist/main.js get org-collection COLLECTION_ID --organizationid ORG_ID
node apps/cli/dist/main.js create org-collection ENCODED_JSON --organizationid ORG_ID
node apps/cli/dist/main.js edit org-collection COLLECTION_ID ENCODED_JSON --organizationid ORG_ID
node apps/cli/dist/main.js delete org-collection COLLECTION_ID --organizationid ORG_ID
node apps/cli/dist/main.js list org-members --organizationid ORG_ID
node apps/cli/dist/main.js confirm org-member MEMBER_ID --organizationid ORG_ID
printf '%s' '["COLLECTION_ID"]' | node apps/cli/dist/main.js encode | node apps/cli/dist/main.js move ITEM_ID ORG_ID
node apps/cli/dist/main.js edit item-collections ITEM_ID ENCODED_COLLECTION_IDS
```

When collection edits omit group/user access fields, the CLI sends the collection's
current group and user assignments. Member confirmation requires an accepted
invitation and wraps the
organization key for the member's public key. Moving is supported for personal
items into an organization; at least one target collection is required. `share`
is the deprecated alias for `move`. Items with per-item keys use that key; legacy
items receive a new item key. The personal account key is never shared.

## Password health and exposure

```sh
node apps/cli/dist/main.js report password-health --no-check-exposed
node apps/cli/dist/main.js report password-health
node apps/cli/dist/main.js get exposed ITEM_ID
node apps/cli/dist/main.js report password-health --hibp-url https://mirror.example.com
```

`password-health` reports every non-deleted login with a non-empty password,
including archived and organization-owned items. Each JSON row contains the
item ID/name, a strength score from 0 to 4, `reuseCount` (null for a unique
password), and `exposed`, `exposedCount`, and `exposedError`. Comparisons for
reuse are case-sensitive. Report rows omit passwords, usernames, and hashes.

Scoring uses zxcvbn with the login username's tokens as context, matching the
SDK report path rather than the password-generator UI's global brand words.
Only the first 100 Unicode characters are scored, matching the Rust estimator's
work limit. Exposure and reuse checks use the entire password.

Exposure checking is enabled by default. `--no-check-exposed` makes the report
entirely offline. Checks use the [HIBP Pwned Passwords range API](https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange):
only five SHA-1 hash characters leave the client; suffix matching happens
locally. Requests ask for padded responses, omit account credentials, reject
redirects, time out after 30 seconds, and cap concurrent requests at 100.
Duplicate passwords share one lookup within a report. `--hibp-url` explicitly
selects a compatible mirror; HTTPS is required except on loopback.

`get exposed ITEM_ID` prints the occurrence count for one login's password.
It fails if the check fails. A lookup error affects only its row; successful
lookups appear alongside rows with `exposedError`. An error, empty/malformed reply,
or oversized reply is never treated as a successful negative exposure result.
Counts are occurrences in the password corpus; they are not a list of breached
accounts or a count of distinct breached websites. This password-only service
is separate from Vaultwarden's authenticated breached-account proxy.

## Sends

```sh
node apps/cli/dist/main.js send 'Text to share' --name 'One-time note' --maxAccessCount 1
node apps/cli/dist/main.js send ./document.pdf --file --fullObject
node apps/cli/dist/main.js send 'Protected text' --passwordenv SEND_PASSWORD
node apps/cli/dist/main.js send template text
node apps/cli/dist/main.js send create ENCODED_SEND_JSON
node apps/cli/dist/main.js send list
node apps/cli/dist/main.js send get SEND_ID
node apps/cli/dist/main.js send get SEND_ID --text
node apps/cli/dist/main.js send edit ENCODED_SEND_JSON --itemid SEND_ID
node apps/cli/dist/main.js send remove-password SEND_ID
node apps/cli/dist/main.js send delete SEND_ID
node apps/cli/dist/main.js receive 'https://vault.example.com/#/send/ACCESS_ID/KEY' --passwordenv SEND_PASSWORD
node apps/cli/dist/main.js receive 'https://vault.example.com/#/send/ACCESS_ID/KEY' --output ./received.pdf
```

`VW_SEND_PASSWORD` supplies the default recipient or new-Send password.
`--password` overrides that value; `--passwordenv NAME`
selects another environment variable.

The quick `send` command accepts text from stdin when its data argument is
omitted and returns the decrypted Send object, including its access URL, like
the pinned CLI response path. `--fullObject` remains accepted for command-line
compatibility. Text Sends support `--hidden`; both types support `--deleteInDays` (default 7,
maximum 31), `--maxAccessCount`, `--name`, `--notes`, and an optional password.
JSON creation supports `expirationDate`, `disabled`, and `hideEmail` as well.
Send edits use the same key seed and password unless a new password is supplied.
File contents cannot be edited; delete and recreate a file Send to replace
them. `send list/get` read the encrypted cache and work offline after sync.

`receive` and `send receive` work without login. The URL fragment holds a
16-byte seed used to derive the content key through HKDF-SHA256. That seed stays
local. Recipient password proofs use PBKDF2-SHA256 with the seed and 100,000
iterations. The current recipient flow mints a separate short-lived Send token;
servers explicitly rejecting that grant use the older anonymous JSON-body
access endpoints. Both flows send only a derived password proof and never read
or send an account token. The Send URL grants access to its secret;
quote it when passing it through a shell. Owner JSON also contains the seed and
access URL, matching the information exposed by bw.

Recipient passwords can come from `VW_SEND_PASSWORD`, `--password`,
`--passwordenv`, or `--passwordfile`; an interactive terminal prompts when needed. `--obj` returns
metadata and decrypted text/filename without downloading a file. Text content
is printed without an added newline. Files use private output and refuse
overwrite, or can be streamed as binary stdout with `--raw`. Signed downloads
receive no bearer token. File Sends currently process up to 500 MiB in memory.
Failed uploads attempt to delete incomplete metadata and invalidate the cache
if that cleanup fails.

Vaultwarden 1.37.4 supports text and file Sends. It rejects email-verification
Sends and item Sends. The legacy body-based receive protocol is live verified
against Vaultwarden 1.36.0 for text and binary files, including password errors,
password removal, access limits, expiry, disabling and deletion.

## Attachments

```sh
node apps/cli/dist/main.js create attachment --file ./document.pdf --itemid ITEM_ID
node apps/cli/dist/main.js get attachment ATTACHMENT_ID --itemid ITEM_ID --output ./download.pdf
node apps/cli/dist/main.js get attachment document.pdf --itemid ITEM_ID --raw > ./download.pdf
node apps/cli/dist/main.js delete attachment ATTACHMENT_ID --itemid ITEM_ID
```

Attachment reads accept an ID or a case-insensitive filename substring. A unique
exact filename takes priority over other substring matches; otherwise multiple
matches require an attachment ID. `--itemid` accepts an item ID or unique item
search query. Ambiguity is resolved before requesting metadata or downloading.

Uploads encrypt both filename and file contents locally. Each new attachment has
an independent encryption key, wrapped by the item key. Attachment reads require
an online metadata request to obtain a current signed URL. A metadata 404 falls
back to the cached attachment URL and key, matching the legacy reference path;
other HTTP failures stop without attempting that fallback. Signed downloads never
receive the account bearer token and do not follow redirects. The CLI supports
binary stdout with `--raw`; file output uses mode 0600, strips server-provided
path components, and refuses to overwrite an existing file. Failed uploads try
to remove incomplete metadata and report whether cleanup succeeded. Files are
currently processed in memory, bounded by Vaultwarden's 525 MiB encrypted-file
limit. A move carries readable attachments for items with per-item keys.

State defaults to `$XDG_CONFIG_HOME/vaultwarden-cli/state.json`, falling back to
`~/.config/vaultwarden-cli/state.json`. `VW_APPDATA_DIR` selects an isolated profile.
Directories use mode 0700 and files 0600. Locking removes the encrypted session
wrapper; unlocking again replaces it, invalidating the previous token. A command
lock prevents concurrent refresh/logout writes. Its local process owner is
published atomically with the lock; subsequent commands recover the lock when
that owner is no longer running, including after SIGINT, SIGTERM or SIGKILL.
Release atomically detaches the lock before deleting its owner metadata. An
interrupted cleanup can leave an unused `.lock-*` directory, which does not
block subsequent commands.
Stale-lock recovery first replaces the exact dead-owner token with a token
identifying the recovering process, then detaches the directory atomically.
An interrupted recovery can itself be recovered without displacing a live
command or leaving a published lock without ownership metadata.
Live or inaccessible owners are not displaced. Legacy locks without owner
metadata and locks from another host require confirming that no command still
uses that profile before manually removing `.lock`.
Logout removes local tokens and cache; it does not revoke server-side sessions.

The state file contains bearer/refresh tokens, API credentials for API-key
accounts, the encrypted user key, and the encrypted sync response. The session token is a random AES-GCM wrapping key and
is never written to state. Decrypted vault keys are overwritten after use where
possible; JavaScript strings and runtime copies cannot be reliably zeroized.
Use the same care with session tokens and command output as with vault secrets.
TLS verification is enabled. Private CAs can be supplied through
`NODE_EXTRA_CA_CERTS`. HTTPS is required except on loopback test servers;
redirects are rejected to avoid forwarding credentials to a different endpoint.

## Library

```ts
import {
  VaultwardenClient,
  loginWithPassword,
  unlockAccount,
  personalItems,
} from '@kjanat/vaultwarden';

const client = new VaultwardenClient('https://vault.example.com');
const account = await loginWithPassword(client, email, password);
const encryptedVault = await client.sync(account.accessToken);
const key = await unlockAccount(account, password);
try {
  const { items, excludedOrganizationItems } = personalItems(
    encryptedVault,
    key,
  );
  // Consume items without logging secrets unintentionally.
} finally {
  key.fill(0);
}
```

`loginWithApiKey(client, { clientId, clientSecret })` returns an `ApiKeyAccount`;
password login returns a `PasswordAccount`. Both support `unlockAccount`.
`refreshAccount(client, account)` dispatches to the appropriate renewal grant;
callers must persist its result and invalidate local unlock state when the
wrapped key or KDF settings change. `client.refresh(refreshToken)` remains
available for password accounts and returns rotated refresh credentials. The CLI refreshes before expiry
and retries an authenticated sync once after HTTP 401. The transport accepts an
injected `fetch` and a stable `deviceId` for embedding and contract tests.

See [implementation status](implementation-status.md) for current test coverage
and outstanding work, and [Vaultwarden accommodations](vaultwarden-deviations.md)
for server-specific behavior and its selection rules.
