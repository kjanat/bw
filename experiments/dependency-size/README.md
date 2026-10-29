# Dependency size probes for vw 0.1.2

These are isolated functional slices, not a prediction of the full SDK Bundlephobia result. Production source and dependencies were not changed.

All JavaScript was bundled with esbuild 0.28.2, minified for Node 24, compressed with gzip level 9 or Brotli quality 11. External files use Brotli quality 11, matching the existing WASM distribution approach. The totals include external files; they are not simply the initial JavaScript download. The all-Brotli column provides the fairer compression-to-compression comparison.

| Probe                 | Minified JS bytes | Gzip JS bytes | Brotli sidecar bytes | Gzip JS + sidecars | Brotli JS + sidecars |
| --------------------- | ----------------: | ------------: | -------------------: | -----------------: | -------------------: |
| parse5                |           151,718 |        42,133 |                    0 |             42,133 |               36,523 |
| htmlparser2           |            52,284 |        22,291 |                    0 |             22,291 |               20,648 |
| parse5-sax            |           102,190 |        33,381 |                    0 |             33,381 |               28,834 |
| tldts                 |           131,726 |        46,414 |                    0 |             46,414 |               40,563 |
| tldts-experimental    |           107,885 |        47,256 |                    0 |             47,256 |               33,577 |
| tldts-compressed-data |             8,804 |         3,206 |               37,456 |             40,662 |               40,347 |
| tldts-binary-data     |             8,941 |         3,254 |               36,838 |             40,092 |               39,794 |
| psl-wasip2            |           117,476 |        27,983 |              191,675 |            219,658 |              215,969 |
| html-wasip2           |           116,973 |        26,221 |              152,351 |            178,572 |              174,936 |

## What was tested

- parse5 8.0.1: existing first-pre/textContent extraction, including the existing HTML marker detection.
- htmlparser2 12.0.0: streaming first-pre extraction prototype with basic newline and template handling.
- parse5-sax-parser 8.0.0: streaming first-pre extraction prototype.
- tldts 7.4.19: parse and getHostname, retaining all ICANN/private suffix data.
- tldts-experimental 7.4.19: upstream alternative. Its README describes a probabilistic lookup with possible false positives. It is not assumed to be an exact substitute.
- Compressed tldts variants: encode and restore exactly the same exported typed arrays, text and root indices. The lookup algorithm and tldts-core hostname parsing are unchanged. These prototypes load the sidecar during module initialization; they do not yet implement lazy table initialization.
- Rust PSL: psl 2.1.245 plus the existing tldts-core hostname normalization and local/IP handling. Public suffix snapshots are not identical between this crate and tldts.
- Rust HTML: html5ever 0.39.0 and markup5ever_rcdom 0.39.0+unofficial, preserving first-pre DOM traversal and text collection.
- Both Rust components use Rust 1.99.1, edition 2024, wit-bindgen 0.63.0, wasm32-wasip2, opt-level z, LTO, panic abort, Jco 1.40.0 synchronous instantiation, Binaryen 133 -Oz --converge, and the existing SDK WASI host. Components are built separately. Each probe WIT world also contains a disabled stub for the other operation; these are prototypes, not exhaustive minimum-size Rust implementations.

## Compatibility results

Node and Bun produced the same results:

- Exact-table JSON and binary variants: all 65,174 full-result comparisons matched, covering 10,857 suffix rule paths, direct and prefixed hosts, URL forms, private-domain flags, and selected edge cases. getHostname was checked for the binary variant as well.
- htmlparser2 extraction: 5 differences among 28 selected HTML inputs. These include foster-parented table text, template content and pre inside select. Passing ordinary LastPass exports does not establish equivalence for all existing accepted input.
- parse5 SAX extraction: 7 differences among the same inputs. A tokenizer stream is not a DOM tree builder.
- Rust HTML extraction: 1 difference among those inputs; see [results/parity-node.json](results/parity-node.json) for the exact case.
- tldts-experimental: 0 domain-string differences in the selected corpus, but 14,261 full-result differences, including ICANN classification. This is distinct from the upstream warning about possible false positives.
- Rust PSL: 6 differences in 32,587 domain comparisons. The examples involve oya.to and aliases121.com, which are suffix rules in the current tldts snapshot but not recognized as such by this Rust crate.

## Interpretation

The htmlparser2 prototype saves about 47% gzip for the extraction slice, but is not yet behavior-equivalent. Switching the dependency directly would change some import results.

The exact binary tldts prototype saves about 14% against gzip JS, but only about 2% when both approaches use Brotli. The larger apparent reduction in JavaScript alone mostly moves data into a separate file.

These two Rust/WASIp2 prototypes are substantially larger in total than the equivalent JavaScript slices. This does not prove that every possible Rust implementation is larger; it rules out adopting these specific prototypes as a straightforward size improvement.

Useful next approaches are feature-level imports/lazy loading for rarely used importers and an explicitly specified smaller LastPass parser with demonstrated compatibility. Such changes require separate SDK-level measurements; the isolated savings cannot simply be subtracted from Bundlephobia's full-package gzip number.

## Reproduction

The committed `results/` files preserve the original measurements and compatibility findings from the 2026-10-29 experiment against SDK commit `36a71fc58f33c7cd696355e8b4aef08b23b92f9b`. Build products and fresh measurements go to ignored `out/`; rerunning does not overwrite the recorded evidence. Generated bundles and WASM binaries are rebuilt, not committed.

Prerequisites: Node 24 or newer, Bun, rustup, and Binaryen **133** (`wasm-opt` on PATH). The Rust toolchain file pins Rust **1.99.1** and the `wasm32-wasip2` target. JavaScript packages and Rust crates are pinned through the included manifests and lockfiles; the build uses Cargo's `--locked` option. The original JavaScript measurements ran on Node 26.7.0; the output target is Node 24. Compression bytes can vary with runtime/compressor versions.

From the repository root, using mise to select Binaryen 133 (install with `mise install binaryen@133` if needed). Without mise, set `WASM_OPT` to the absolute path of your Binaryen 133 executable. This avoids Jco's transitive Binaryen executable taking precedence in Bun scripts:

```sh
cd experiments/dependency-size
bun install --frozen-lockfile --ignore-scripts
WASM_OPT="$(mise where binaryen@133)/bin/wasm-opt" bun run build
bun run test
```

`build.mjs` builds each Rust feature separately, saves its component, bundles all JavaScript variants, runs Jco and `wasm-opt`, and measures the compressed outputs. It records tool versions in `out/environment.json`. `host.ts` is a snapshot of the SDK host at the commit above, with generated type references removed; the experiment does not import production files.

`bun run test` runs the compatibility corpus under both Node and Bun, asserting exact-table parity and comparing the complete reports with the recorded findings. A successful run means the known candidate mismatches were reproduced, not that every candidate is interchangeable with production. Inspect `out/sizes.json`, `out/wasm-sizes.json`, and `out/parity-{node,bun}.json` for fresh results. To explore only the JavaScript sizes, run `bun run build:js` without the Rust/Binaryen prerequisites.

## Primary references

- https://github.com/fb55/htmlparser2
- https://github.com/remusao/tldts/blob/master/packages/tldts-experimental/README.md
- https://github.com/servo/html5ever
- https://github.com/addr-rs/psl
