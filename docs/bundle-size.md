# Production bundle size versus 0.1.2

The SDK build now bundles the existing parse5/entities and tldts/tldts-core
implementations and stores their immutable lookup tables as compressed binary
assets. It restores every original value and typed-array type. The parsers,
Public Suffix List snapshot, private-domain rules and HTML decoding behavior
remain unchanged.

This is applied to the production build, not just the isolated experiments.
The package version has not been bumped or published by this change.

## Measured result

Both the published 0.1.2 release archive and the candidate archive were installed
in isolated consumers and bundled with esbuild 0.28.2, targeting Node 24.8.
Compression used Node 26.7.0, gzip level 9 and Brotli quality 11. All numbers
below are bytes. These are controlled esbuild measurements, not Bundlephobia
results; do not compare them directly with Bundlephobia's webpack totals.

| Measurement                         | Released 0.1.2 |   Candidate |              Saved |
| ----------------------------------- | -------------: | ----------: | -----------------: |
| All-export JavaScript, minified     |        876,368 |     733,173 |            143,195 |
| All-export JavaScript, gzip         |        273,250 |     213,939 |             59,311 |
| All-export JavaScript, Brotli       |        231,417 |     180,238 |             51,179 |
| Separate KDBX worker, gzip          |         77,004 |      77,004 |                  0 |
| Separate KDBX worker, Brotli        |         65,544 |      65,544 |                  0 |
| All compressed runtime assets       |        639,609 |     688,549 |            -48,940 |
| **Gzip JS + worker + all assets**   |    **989,863** | **979,492** | **10,371 (1.05%)** |
| **Brotli JS + worker + all assets** |    **936,570** | **934,331** |  **2,239 (0.24%)** |

The new tables occupy 49,483 bytes: 36,838 for public suffixes and 12,645 for
HTML entities. The rebuilt WASM assets are also 543 bytes smaller than the
release assets. Holding WASM size constant, the table/build change saves
**9,828 bytes with gzip JS** or **1,696 bytes with Brotli JS**. The much larger
JavaScript-only reduction must not be presented as the total saving.

An encrypt/decrypt-only bundle also falls from 114,467 to 75,053 gzip bytes.
That is a JavaScript-only tree-shaking probe; it is not another full-package total.
Package metadata, declarations and license texts are excluded from runtime
transfer totals. Every shipped `.br` asset is included, even if a particular
application never loads it.

Full measurements and archive/asset SHA256 values are committed in
[production-bundle.json](../experiments/dependency-size/results/production-bundle.json).

## Runtime and compatibility

Tables are loaded synchronously from local files and decompressed when their
modules initialize. This exchanges JavaScript parsing for local I/O and binary
decoding; it is a size optimization, not a measured startup-speed improvement.
Custom application bundlers must retain `generated/` next to the resulting SDK
JavaScript, as already required for the password-strength WASM assets.

Tests compare every upstream table value after encoding and decoding. Installed
SDK/CLI tarballs are checked under Node and Bun, including private suffixes,
wildcards/exceptions, LastPass HTML entity decoding, password-strength WASM,
cryptography, KDBX workers, login and sync. Upstream module-layout changes fail
the build rather than silently skipping compression. License texts for all four
newly bundled packages are shipped in the distribution.

## Reproduce

After installing the repository's pinned build tools and dependencies:

```sh
mkdir -p .cache/release-0.1.2
gh release download v0.1.2 --repo kjanat/vw \
  --pattern vaultwarden.tgz --dir .cache/release-0.1.2
bun run build
bun run repo release pack vaultwarden
bun run repo bundle compare \
  --baseline .cache/release-0.1.2/vaultwarden.tgz \
  --candidate artifacts/vaultwarden.tgz \
  --output artifacts/bundle-size.json
bun run repo release pack cli
bun run repo release verify --runtime both
```

The comparison runs under Node even when invoked through Bun. Compressor and
build-tool versions can change byte counts, so the report includes runtime and
esbuild versions and hashes of both input archives and every runtime asset.
