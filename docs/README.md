# Vaultwarden TypeScript client

An independent client with an explicit commitment to Vaultwarden compatibility.
The TypeScript library implements the protocol and cryptography; a DreamCLI
frontend supplies commands and local state. Neither package invokes `bw`.

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

Requires Bun for dependency management/tests and Node 24+ for the compiled CLI.

```sh
bun install
bun run build --filter=@kjanat/vaultwarden-cli
node apps/cli/dist/main.js --help
node apps/cli/dist/main.js config server https://vault.example.com
node apps/cli/dist/main.js login you@example.com
node apps/cli/dist/main.js sync
export VW_SESSION="$(node apps/cli/dist/main.js unlock --raw)"
node apps/cli/dist/main.js list items
node apps/cli/dist/main.js list items --search example
node apps/cli/dist/main.js get password ITEM_ID
node apps/cli/dist/main.js lock
unset VW_SESSION
node apps/cli/dist/main.js logout
```

Login and unlock use a masked prompt on an interactive terminal. For automation,
`--passwordenv NAME` selects a named environment variable (default `VW_PASSWORD`).
The master password is never a positional argument or a persisted setting.
For two-factor login, supply `--method 0 --code TOKEN` (TOTP), or another supported
provider ID; `VW_2FA_TOKEN` can supply the code. Initiating an email challenge,
WebAuthn, and Duo browser flows are not implemented.

`get` accepts `item`, `password`, `username`, `uri`, `notes`, `totp`, `folder`,
`collection`, and `organization`, followed by an
item ID or an exact unique name. `list items` and `get item` return JSON, including
secrets. `get password` prints the requested value. A successful login leaves the
vault locked. Sync downloads encrypted data and can run while locked; list/get
work offline after a successful sync. `status` reports `unauthenticated`, `locked`,
or `unlocked` for the supplied `VW_SESSION` or `--session` token.

## Vault management

`get template NAME` returns a JSON template without logging in. `encode` reads
UTF-8 stdin and emits base64; create/edit accept that encoded JSON as an argument
or from stdin. The same command pattern applies to items and folders:

```sh
node apps/cli/dist/main.js get template folder
printf '%s' '{"name":"Work"}' | node apps/cli/dist/main.js encode | node apps/cli/dist/main.js create folder
node apps/cli/dist/main.js get item ITEM_ID
# Edit the returned JSON, keeping its revisionDate, then encode it:
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
preserve per-item keys and send the caller's revision date to Vaultwarden for
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

Exports support CSV, JSON, account-encrypted JSON, password-encrypted JSON,
and ZIP with decrypted attachments. Without an export password, encrypted JSON
is bound to the current account key. Password exports use an independent salt
and the account KDF parameters. `--passwordenv` and `--passwordfile` select a
password source; `VW_EXPORT_PASSWORD` and `VW_IMPORT_PASSWORD` are the default
variables for those operations. Plain exports contain vault secrets. File
output uses mode 0600 and refuses overwrite; `--raw` writes directly to stdout.

Imports currently accept Bitwarden JSON/CSV/ZIP and Chrome/Firefox CSV. Other
reference adapters remain required work. Items receive fresh encryption keys
and IDs, and folder/collection relationships are remapped. Imports add data;
they do not deduplicate existing items. Personal exports omit organization items
and trash. Use `--organizationid ORG_ID` for organization imports and exports.
Organization export uses the server's administrative export endpoint.

ZIP backups produced here include an attachment manifest retaining original
filenames and item IDs. Official bw ZIPs use sanitized item names instead;
restoration rejects ambiguous item-name mappings before importing anything.
Archives are read in memory without extracting their paths to the filesystem.
The total inflated ZIP limit is 1 GiB, with a 525 MiB limit per entry. A bulk
import or attachment restoration can partially succeed on the server; failures
invalidate the local cache and instruct the caller to sync before retrying.

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

Collection edits retain existing group/user access assignments when those fields
are omitted. Member confirmation requires an accepted invitation and wraps the
organization key for the member's public key. Moving is supported for personal
items into an organization; at least one target collection is required. `share`
is the deprecated alias for `move`. Items with per-item keys retain them; legacy
items receive a new item key. The personal account key is never shared.

## Attachments

```sh
node apps/cli/dist/main.js create attachment --file ./document.pdf --itemid ITEM_ID
node apps/cli/dist/main.js get attachment ATTACHMENT_ID --itemid ITEM_ID --output ./download.pdf
node apps/cli/dist/main.js get attachment document.pdf --itemid ITEM_ID --raw > ./download.pdf
node apps/cli/dist/main.js delete attachment ATTACHMENT_ID --itemid ITEM_ID
```

Uploads encrypt both filename and file contents locally. Each new attachment has
an independent encryption key, wrapped by the item key. Attachment reads require
an online metadata request to obtain a current signed URL. Signed downloads never
receive the account bearer token and do not follow redirects. The CLI supports
binary stdout with `--raw`; file output uses mode 0600, strips server-provided
path components, and refuses to overwrite an existing file. Failed uploads try
to remove incomplete metadata and report whether cleanup succeeded. Files are
currently processed in memory, bounded by Vaultwarden's 525 MiB encrypted-file
limit. A move retains readable attachments for items with per-item keys.

State defaults to `$XDG_CONFIG_HOME/vaultwarden-cli/state.json`, falling back to
`~/.config/vaultwarden-cli/state.json`. `VW_APPDATA_DIR` selects an isolated profile.
Directories use mode 0700 and files 0600. Locking removes the encrypted session
wrapper; unlocking again replaces it, invalidating the previous token. A command
lock prevents concurrent refresh/logout writes. If a command is killed, verify
that no command still uses that profile before removing its `.lock` directory.
Logout removes local tokens and cache; it does not revoke server-side sessions.

The state file contains bearer/refresh tokens, the encrypted user key, and the
encrypted sync response. The session token is a random AES-GCM wrapping key and
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

`client.refresh(refreshToken)` returns rotated tokens and an expiry timestamp;
consumers must save the returned refresh token. The CLI refreshes before expiry
and retries an authenticated sync once after HTTP 401. The transport accepts an
injected `fetch` and a stable `deviceId` for embedding and contract tests.

See [the compatibility contract](compatibility.md) for exact coverage, source
revisions, tests, and the remaining implementation work.
