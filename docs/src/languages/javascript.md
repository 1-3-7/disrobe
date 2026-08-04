# JavaScript / TypeScript

`disrobe` deobfuscates obfuscated JS/TS, splits bundled output back into per-module sources, and inspects packaged JS runtimes, all behind a deterministic codegen.

## At a glance

| Layer | Coverage |
|---|---|
| Family detector | obfuscator.io, Jscrambler, jsobfu, plus bundler and minified-only classification, each with confidence and markers |
| obfuscator.io (`--full`) | string-array decode, control-flow unflattening, opaque-predicate folding, packing expansion, dead-code and debug-protection strip, iterated to a fixpoint |
| Reverser library | JS-Confuser (string encoding/compression, dispatcher, flatten, opaque predicates, RGF, shuffle, variable masking, locks and integrity) and Jscrambler template reversals; Arxan-JS, JSDefender, and PACE protector detectors |
| Esoteric encoders | jsfuck, JJEncode, AAEncode, JSFiretruck, Dean Edwards Packer, atob/eval indirection |
| Renaming | `--rename` (hex idents to `var_N`) and `--rename-scope-aware` (oxc_semantic, conflict-checked) |
| Bundlers | Webpack 4/5, Vite, Rollup, Rolldown, esbuild, Turbopack, Bun, Browserify, Parcel, SystemJS, AMD |
| Packaged runtimes | V8 cached-data `.jsc` (bytenode), Node SEA blobs, nexe, nw.js zip-suffix, Electron `.asar` |

## Commands

```sh
disrobe js deob bundle.min.js --out clean.js --full --rename-scope-aware
disrobe js deob legacy.js --out clean.js --legacy auto --unminify
disrobe js unbundle app.bundle.js --out src/
disrobe js unbundle app.bundle.js --out src/ --emit sourcemap
disrobe js v8 app.jsc
disrobe js v8 app.asar --json-out report.json
disrobe auto app.asar --out recovered/        # Electron and Node packaging chains run end to end
```

The default `deob` path runs string-array recovery and writes a `detection.json` sidecar naming the matched family. `--full` runs the complete obfuscator.io reversal pipeline and records per-stage statistics in a `pipeline.json` (string-array call sites inlined, dispatch blocks collapsed, opaque predicates folded, packed blocks expanded). `--legacy jsobfu|jscrambler-free|auto` targets the older families; `--unminify` adds the `!0`/`void 0`/string-concat peepholes.

For Rust callers, `AstRuleId::AsyncRestore` is a selector-compatibility no-op: Babel-style async wrappers are preserved. Any call carrying an exact Babel async-helper specifier quarantines the entire AST and preset-env pass, without assuming the callee is CommonJS `require`. `AstRuleId::ArgumentSpread` and `AstRuleId::TemplateLiteral` are disabled-by-default selector-compatibility no-ops, with stable zero-valued report counters. `AstRuleId::RegeneratorRestore` is a disabled-by-default selector-compatibility no-op with a stable zero-valued report counter; regenerator state machines are preserved. `undo_preset_env` keeps `helpers_removed` empty and its spread, class, and async counters at zero; it currently reports only AST-proven optional-chain and nullish-coalescing restoration.

`unbundle` auto-detects the bundler runtime from its markers (the full table above) or forces one with `--target auto|webpack|webpack4|webpack5|vite|rollup|esbuild|turbopack|bun`. Modules land as separate files with chunk and module identifiers preserved, plus a `manifest.json`. `--emit sourcemap` synthesizes per-chunk v3 source maps and decodes embedded data-url maps.

## Coverage and fidelity

`js v8` classifies the artifact and prints real detection: bytenode header layout and Node version for `.jsc`, SEA flags and code length, nexe/nw.js payload geometry, or the `.asar` entry listing.

For `.jsc`, `disrobe` is the self-contained, static, offline option: it recovers the user-string layer plus structure and detects the serializer version across Node 18-24, with no patched V8 binary (View8), Ghidra (ghidra_nodejs), or online service (jscdecompiler.com) required.

## Limits

- `.jsc` internalized identifiers (most variable and property names, for example `console` and `log`) are serialized as references into V8's read-only snapshot heap, not as inline bytes in the `.jsc`. Resolving them needs the exact V8 binary's RO heap. `disrobe` reports that as a lossy-internalized-roots boundary rather than fabricating past it.
- For V8 snapshots `disrobe` reports a `SnapshotDeserializeWall`: the format prevents full bytecode recovery, so it scrapes the string pool (tunable via `--scrape-min`) and states the boundary rather than fabricating past it.
