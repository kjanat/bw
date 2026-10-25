# Third-party notices

## EFF Long Wordlist

Copyright Electronic Frontier Foundation. Licensed under [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/), under [EFF's copyright policy](https://www.eff.org/copyright).

Source: [EFF Dice-Generated Passphrases](https://www.eff.org/dice), [original word list](https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt).

The bundled TypeScript representation removes the dice indices and retains all 7,776 words in order. No endorsement by EFF is implied.

Original file SHA256: `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`.

## zxcvbn

Password-strength estimation uses the npm dependency
[`zxcvbn` 4.4.2](https://github.com/dropbox/zxcvbn), licensed under MIT.
Copyright (c) 2012-2016 Dan Wheeler and Dropbox, Inc. The dependency's
`LICENSE.txt` contains its complete license notice. The client supplies
login-specific context and bounds the scored input to 100 Unicode characters.

## tldts

URI domain and hostname parsing uses the npm dependency
[`tldts` 7.4.19](https://github.com/remusao/tldts), licensed under MIT.
Its package retains its license notice and Public Suffix List data attribution.

## @xmldom/xmldom

KeePass XML parsing uses [`@xmldom/xmldom` 0.9.12](https://github.com/xmldom/xmldom),
licensed under MIT. Copyright 2019-present Christopher J. Brody and other
contributors; copyright 2012-2017 @jindw and other contributors. Its package
contains the complete license notice. The importer rejects entity declarations
and external DTDs before parsing and does not resolve external resources.

## kdbxweb

KDBX database decoding uses [`kdbxweb` 2.1.1](https://github.com/keeweb/kdbxweb),
licensed under MIT, copyright (c) 2021 Antelle. Its package contains the complete
license notice. Decoding runs in an isolated worker with the project's current
XML parser and `micro509/kdf` Argon2 adapter. The adapter uses native WebCrypto
where available and loads `@noble/hashes` only for unsupported runtime/version
combinations, including Bun and Argon2 version `0x10`. The Bun patch
`patches/kdbxweb@2.1.1.patch` preserves XML-valid horizontal tabs that the
dependency otherwise strips from unprotected values; `bun install` applies it.
