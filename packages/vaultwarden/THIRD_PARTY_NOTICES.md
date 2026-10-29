# Third-party notices

## EFF Long Wordlist

Copyright Electronic Frontier Foundation. Licensed under [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/), under [EFF's copyright policy](https://www.eff.org/copyright).

Source: [EFF Dice-Generated Passphrases](https://www.eff.org/dice), [original word list](https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt).

The bundled TypeScript representation removes the dice indices and includes all 7,776 words in order. No endorsement by EFF is implied.

Original file SHA256: `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`.

## zxcvbn

Password-strength estimation bundles [`zxcvbn` 3.1.1](https://crates.io/crates/zxcvbn),
the MIT-licensed Rust port by Joshua Holmer of Dropbox's zxcvbn, as WebAssembly.
The score-only WASIp2 wrapper uses wit-bindgen and Jco-generated JavaScript
bindings (Apache-2.0 WITH LLVM-exception). Rust dependencies are pinned in
`wasm/Cargo.lock`. The published SDK includes their complete license texts and
the Jco binding-generator license in `dist/THIRD_PARTY_NOTICES.txt`.
`wasm/zxcvbn-wasi.patch` modifies zxcvbn's platform selection so WASI uses native
clocks and the UTC reference year instead of JavaScript-specific imports.
The client supplies login-specific context and
bounds the scored input to 100 Unicode characters. The module is Brotli-compressed
on disk and initialized locally on the first strength check. No general WASI
shim is bundled; the SDK supplies only the scorer's required host capabilities.

## tldts

URI domain and hostname parsing uses the npm dependency
[`tldts` 7.4.19](https://github.com/remusao/tldts), licensed under MIT.
Its package includes its license notice and Public Suffix List data attribution.

## @xmldom/xmldom

KeePass XML parsing uses [`@xmldom/xmldom` 0.9.12](https://github.com/xmldom/xmldom),
licensed under MIT. Copyright 2019-present Christopher J. Brody and other
contributors; copyright 2012-2017 @jindw and other contributors. Its package
contains the complete license notice. The importer rejects entity declarations
and external DTDs before parsing and does not resolve external resources.

## kdbxweb

KDBX database decoding uses [`kdbxweb` 2.1.1](https://github.com/keeweb/kdbxweb),
licensed under MIT, copyright (c) 2021 Antelle. The patched decoder is bundled
with the SDK. Decoding runs in an isolated worker with the project's current
XML parser and `micro509/kdf` Argon2 implementation. micro509 uses native
WebCrypto where available and its own portable TypeScript implementation for
unsupported runtime/version combinations, including Bun and Argon2 version
`0x10`. No separate Argon2 dependency is required. The Bun patch
`patches/kdbxweb@2.1.1.patch` allows XML-valid horizontal tabs that the
dependency otherwise strips from unprotected values; `bun install` applies it.

```text
Copyright (C) 2021 Antelle

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```
