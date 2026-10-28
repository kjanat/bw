# Synthetic 1Password fixture

`export.data` contains invented vault data and disposable generated SSH keys.
`synthetic.1pux` packages that JSON plus an ignored document entry as a ZIP archive.
It contains no real credentials. The live test packages it as a `.1pux` archive
with an ignored document entry, then imports it through the `vw` CLI
and an independent `bw` CLI on a disposable Vaultwarden account.

The corpus covers logins, cards, identity/address, passport, bank account,
API credentials, notes, archive state, tags, guarded fields, checkboxes, OTP,
password history, RSA/Ed25519/P-256 SSH keys, and a malformed SSH record that
must be reported and skipped. Unit tests additionally cover P-384/P-521 keys
and the remaining legacy identity category mappings.

`legacy.1pif` adds standard and Windows OPVault-shaped records for logins,
cards, identities and notes, plus an excluded trashed record. `mac.csv` and
`windows.csv` use legacy vendor headings and backslash-escaped quote characters.
They cover multiple URLs, card expiry formats, unknown hidden fields, identity
inference, multiline notes/addresses, and date fields. These contain only
invented credentials and are separate from the 1PUX corpus.
