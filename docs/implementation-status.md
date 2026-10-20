# Implementation scope and evidence

The target is an independent TypeScript implementation of the Bitwarden CLI's
Vaultwarden-supported behavior, with a reusable library and DreamCLI frontend.
This file tracks the full target. An unfinished row remains required work; it
is not an exclusion from the product scope.

The reference command surface is captured from `/usr/bin/bw` 2026.10.0 in
[the command inventory](reference/bw-cli-2026.10.0.json). Server-specific behavior
is checked against Vaultwarden handlers, not inferred solely from the official
client. Bitwarden cloud-only flows must be classified from server evidence.

| Command family                     | Required behavior                                                                                               | Current evidence                                                                                                                                                       |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| config                             | Server/custom service URLs, CLI settings                                                                        | Server selection tested; remaining settings pending                                                                                                                    |
| login/unlock                       | Password, API key, supported 2FA and server auth flows, input sources                                           | Password/KDF live tests; remaining flows pending                                                                                                                       |
| sync/status/lock/logout            | Cache, refresh, offline state, session invalidation                                                             | Live tests cover existing password flow                                                                                                                                |
| list/get                           | Items, folders, organizations, collections, members, filters, templates, secret fields, attachment, fingerprint | Items/folders/collections/members, attachment downloads, templates and TOTP tested; URL/fingerprint/exposure/Send reads pending                                        |
| create/edit/delete/restore/archive | Items, folders, collections, attachments, trash/archive, conflicts                                              | Items/folders/collections and attachment lifecycle cross-client live tested                                                                                            |
| move/share/confirm                 | Organization sharing, collections, member confirmation                                                          | Move, reassignment, and member confirmation live tested; share alias implemented; legacy attachment migration coverage pending                                         |
| generate/encode                    | Passwords, passphrases, unbiased randomness, stdin encoding                                                     | Encoding and cryptographic password/passphrase generation tested, including cached policy constraints                                                                  |
| import/export                      | Documented formats, encrypted exports, attachments, organization scope                                          | Native JSON/CSV and encrypted JSON implemented; independent bw transfer matrix in live tests; ZIP and organization coverage being verified; remaining adapters pending |
| send/receive                       | Text/file Sends, access limits, passwords, expiry, management                                                   | Pending                                                                                                                                                                |
| report                             | Supported reports and secret exposure queries                                                                   | Pending                                                                                                                                                                |
| serve                              | Authenticated local REST interface to library operations                                                        | Pending                                                                                                                                                                |
| completion                         | Shell completions from command definitions                                                                      | Pending                                                                                                                                                                |
| update/sdk-version                 | Version metadata and appropriate update behavior for independent packages                                       | Pending                                                                                                                                                                |
| device-approval                    | Determine Vaultwarden support and implement supported operations                                                | Pending server capability audit                                                                                                                                        |
| global flags/input/output          | Raw/JSON, quiet, noninteractive, session, error/exit semantics                                                  | Partial; command-by-command audit pending                                                                                                                              |
| compatibility maintenance          | Repeatable real-server matrix, cross-client reads/writes, release gates                                         | One pinned server tested; matrix and CI pending                                                                                                                        |

Completion requires library and CLI tests for each supported operation, real
Vaultwarden evidence for server mutations, a documented disposition for every
reference command, and removal of partial-reader restrictions. A green subset
of tests does not establish full completion.
