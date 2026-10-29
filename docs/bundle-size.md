# Smaller bundles in 0.1.3

Compressing the domain and HTML entity tables saves about 59 kB of gzipped
JavaScript. The tables now live in separate files; counting those files, the
WASM and the KDBX worker, the total saving is about 10 kB.

We compared the 0.1.2 release archive with the new build using esbuild 0.28.2,
targeting Node 24.8. Both were compressed under Node 26.7.0 with gzip level 9
and Brotli quality 11. These figures use a different bundler from Bundlephobia.
All sizes below are in bytes.

| Bundle                              |       0.1.2 |   New build |              Saved |
| ----------------------------------- | ----------: | ----------: | -----------------: |
| SDK JavaScript, minified            |     876,368 |     733,173 |            143,195 |
| SDK JavaScript, gzip                |     273,250 |     213,939 |             59,311 |
| SDK JavaScript, Brotli              |     231,417 |     180,238 |             51,179 |
| KDBX worker, gzip                   |      77,004 |      77,004 |                  0 |
| KDBX worker, Brotli                 |      65,544 |      65,544 |                  0 |
| Compressed data and WASM            |     639,609 |     688,549 |            -48,940 |
| **Gzip JS + worker + all assets**   | **989,863** | **979,492** | **10,371 (1.05%)** |
| **Brotli JS + worker + all assets** | **936,570** | **934,331** |  **2,239 (0.24%)** |

The two new data files take 49,483 bytes: 36,838 for domain suffixes and 12,645
for HTML entities. Rebuilding the WASM also saved 543 bytes. Excluding that
WASM difference, the saving is **9,828 bytes with gzip** or **1,696 with Brotli**.
Totals include every shipped `.br` file, but exclude package metadata, type
declarations and license texts.

Importing only `encrypt` and `decrypt` produces 75,053 bytes of gzipped
JavaScript, down from 114,467.

The [raw results](../experiments/dependency-size/results/production-bundle.json)
include archive and asset hashes. They were recorded before the version bump,
when the new build's manifest still said 0.1.2.

The parsers and their data stay the same. Tests check every table value after
decoding, and the packed SDK and CLI pass their Node and Bun checks. Loading
the tables now requires two local file reads and decompression during module
initialization. Startup time has not been benchmarked.

If you bundle the SDK yourself, copy the complete `generated/` directory next
to its JavaScript, including the new `.bin.br` files.

To run the comparison yourself:

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

The comparison command uses Node for compression. Different tool versions can
produce slightly different sizes; each report records the versions and hashes.
