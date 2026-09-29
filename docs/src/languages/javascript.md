# JavaScript / TypeScript

`disrobe` reverses supported JavaScript and TypeScript obfuscation, extracts modules from recognized bundle layouts, and inspects packaged JavaScript runtimes. Recovery uses static parsers and bounded transformations.

## At a glance

| Layer | Coverage |
|---|---|
| Family detector | obfuscator.io, Jscrambler, jsobfu, plus bundler and minified-only classification, each with confidence and markers |
| obfuscator.io (`--full`) | string-array decode, control-flow unflattening, opaque-predicate folding, packing expansion, dead-code and debug-protection strip, iterated to a fixpoint |
| Reverser library | JS-Confuser (string encoding/compression, dispatcher, flatten, opaque predicates, RGF, shuffle, variable masking, locks and integrity) and Jscrambler template reversals; Arxan-JS, JSDefender, and PACE protector detectors |
| Esoteric encoders | jsfuck, JJEncode, AAEncode, JSFiretruck, Dean Edwards Packer, atob/eval indirection |
| Renaming | `--rename` (hex idents to `var_N`) and `--rename-scope-aware` (oxc_semantic, conflict-checked) |
| TypeScript helpers (`--unminify`) | `__awaiter` with `__generator` (inline, `tslib` namespace, or renamed), identified by helper body shape, rewritten to `async`/`await`: 41 of 41 async functions across 9 authored programs compiled by tsc 6.0.3 for ES5 and ES2015, and for the ES2015 output after terser 5.51.2 compress and compress-plus-mangle; 3 of 41 for terser-minified ES5 state machines. Node output of every rewritten program matches the compiled original |
| Bundlers | Webpack 4/5, Vite, Rollup, Rolldown, esbuild, Turbopack, Bun, Browserify, Parcel, SystemJS, AMD |
| Packaged runtimes | V8 cached-data `.jsc` (bytenode), Node SEA blobs, nexe, nw.js zip-suffix, Electron `.asar` |
| Deno | `deno compile` executables and bare eszip archives through `disrobe auto`: every embedded module becomes an output file (see [Deno](#deno)) |
| Compiled webview hosts | Electron ASAR plus embedded Tauri and Wails frontend trees through the direct `webview` command |

## Commands

```sh
disrobe js deob bundle.min.js --out clean.js --full --rename-scope-aware
disrobe js deob legacy.js --out clean.js --legacy auto --unminify
disrobe js unbundle app.bundle.js --out src/
disrobe js unbundle app.bundle.js --out src/ --emit sourcemap
disrobe js v8 app.jsc
disrobe js v8 app.asar --json-out report.json
disrobe auto app.asar --out recovered/        # Electron and Node packaging chains run end to end
disrobe auto app.exe --out recovered/         # deno compile executable
disrobe auto modules.eszip --out recovered/   # bare eszip archive
disrobe webview desktop.exe --out frontend/    # Electron, Tauri, or Wails assets
```

Use `js v8` to inspect a packaged JavaScript runtime and `webview` to recover the shipped frontend tree from a desktop binary. The standard CLI also routes supported desktop layouts through `auto`. See [Webview desktop frontends](./webview.md).

The default `deob` path runs string-array recovery and writes a `detection.json` sidecar naming the matched family. `--full` runs the complete obfuscator.io reversal pipeline and records per-stage statistics in a `pipeline.json` (string-array call sites inlined, dispatch blocks collapsed, opaque predicates folded, packed blocks expanded). `--legacy jsobfu|jscrambler-free|auto` targets the older families; `--unminify` adds constant folding and the AST unminify rules (`!0` to `true`, `void 0` to `undefined` where `undefined` is not shadowed, bracket to dot access, string concatenation).

For Rust callers, `AstRuleId::AsyncRestore` is a selector-compatibility no-op: Babel-style async wrappers are preserved. Any call carrying an exact Babel async-helper specifier quarantines the entire AST and preset-env pass, without assuming the callee is CommonJS `require`. `AstRuleId::ArgumentSpread` and `AstRuleId::TemplateLiteral` are disabled-by-default selector-compatibility no-ops, with stable zero-valued report counters. `AstRuleId::RegeneratorRestore` is a disabled-by-default selector-compatibility no-op with a stable zero-valued report counter; regenerator state machines are preserved. `undo_preset_env` keeps `helpers_removed` empty and its spread, class, and async counters at zero; it currently reports only AST-proven optional-chain and nullish-coalescing restoration.

`unbundle` auto-detects the bundler runtime from its markers (the full table above) or forces one with `--target auto|webpack|webpack4|webpack5|vite|rollup|esbuild|turbopack|bun`. Modules land as separate files with chunk and module identifiers preserved, plus a `manifest.json`. `--emit sourcemap` synthesizes per-chunk v3 source maps and decodes embedded data-url maps.

## Coverage and fidelity

`js v8` classifies the artifact and prints real detection: bytenode header layout and Node version for `.jsc`, SEA flags and code length, nexe/nw.js payload geometry, or the `.asar` entry listing.

For `.jsc`, Disrobe detects the serializer version across Node 18-24, recovers user strings and every serialized bytecode array, and `disrobe auto` reports each function's Ignition disassembly with registers named as `node --print-bytecode` names them, together with a JavaScript lift of it (`lifted_js`). Each function states `lift_complete` and its reversible, lossy and runtime-opaque line counts; an instruction without a lift rule is kept as a comment and its accumulator reads as `__unlifted_<op>`, so an incomplete lift fails when run instead of computing a wrong value. The path runs locally without a patched V8 binary or an external decompiler. Branches and loops lower to a `for (;;) switch (__pc)` dispatcher over the bytecode offsets, so a lifted function keeps its control flow; functions with jump tables, generators, `try`/`catch`, `for`-`in` or constant-pool jump offsets keep their jumps as comments and are not complete. It does not rebuild the original source: functions are named `function_<index>` in serialization order, and loops are not restructured into `for` or `while`.

## Deno

`disrobe auto` recognizes the data section `deno compile` embeds in the executable and extracts each module as its own output file. The section is found by its `d3n0l4nd` markers and a complete structural parse, not by the host executable format; only Windows x64 executables have been checked. Two section layouts are parsed:

- Deno 2.x module store, checked against Deno 2.9.7 output. Local files come out of the embedded virtual file system at their paths relative to the program root, with the source bytes Deno stored, which for TypeScript is the original TypeScript. Remote modules, such as `https:` imports cached at compile time, come out at a path built from the specifier without its scheme; only synthetic payloads cover them. For the checked program the output matches the authored sources byte for byte.
- Deno 1.x section, a 40-byte `d3n0l4nd` header followed by an eszip, checked against Deno 1.46.3 output. Modules come out as the eszip stores them: JavaScript and JSON verbatim, TypeScript as Deno's transpiled JavaScript with its source map written beside it as `<module>.map`. The map's `sourcesContent` carries the original TypeScript.

A bare eszip file (versions `ESZIP_V2`, `ESZIP2.1`, `ESZIP2.2` and `ESZIP2.3`) is extracted the same way; a real archive has been checked only for `ESZIP2.2` from Deno 1.46.3. SHA-256 checksums are verified when the archive carries them, and a module whose checksum does not match is dropped.

## Limits

- Deno 2.x payloads also hold the transpiled JavaScript and source map of each TypeScript module; `auto` writes only the original source. Symlinks in the embedded file system are parsed but not written.
- Deno 1.x executables that bundle npm packages keep those packages in a separate directory after the eszip. `auto` does not extract it and records a refusal saying so.
- Only Deno 1.46.3 and 2.9.7 output has been checked. Other releases, including earlier 1.x releases that wrote a different section layout, are recognized only if their section matches one of the two layouts; a section that differs fails to parse and the input is not reported as a Deno executable.

- `.jsc` internalized identifiers (most variable and property names, for example `console` and `log`) are serialized as references into V8's read-only snapshot heap, not as inline bytes in the `.jsc`. Resolving them needs the exact V8 binary's RO heap. `disrobe` reports that as a lossy-internalized-roots boundary and does not decode past it.
- TypeScript `async` recovery assumes the global `Promise` is the built-in one when the module runs. A module that visibly rebinds `Promise` is left compiled; a replacement installed by another script (for example zone.js) is outside a single-file check. State-machine shapes the rule cannot prove equivalent, such as terser's conditional instruction returns, also stay compiled.
- For V8 snapshots `disrobe` reports a `SnapshotDeserializeWall`: the format prevents full bytecode recovery, so it scrapes the string pool (tunable via `--scrape-min`) and states the boundary; it does not decode past it.
