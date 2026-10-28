# Synthetic KDBX interoperability fixtures

These files contain synthetic entries used by the Node CLI's real-server
compatibility test. They were generated with `kdbxweb` 2.1.1 and the project's
Argon2 adapter. The password-bearing files use `synthetic-database-password`.

| File            | Database format and credentials                       |
| --------------- | ----------------------------------------------------- |
| `aes3.kdbx`     | KDBX 3.1, AES KDF, password                           |
| `aes4.kdbx`     | KDBX 4, AES KDF, password plus `keyfile-v2.bin`       |
| `argon2d.kdbx`  | KDBX 4, Argon2d, `keyfile-raw.bin` without a password |
| `argon2id.kdbx` | KDBX 4, Argon2id, password                            |

The fixtures use small work factors for test execution: 1,000 AES rounds or
8 MiB/one iteration/one lane for Argon2. They include a root entry, a grouped
entry, protected and multiline fields, a tab in unprotected notes, KeePass
`TimeOtp-*` fields, and an enabled recycle bin containing an excluded entry.

The reference CLI requires a nonempty password before invoking its SDK, so its
automated comparison covers the three password-bearing fixtures. Our CLI also
imports the key-file-only fixture. Library tests separately generate databases
for all four KDF cases and a ChaCha20 payload.
