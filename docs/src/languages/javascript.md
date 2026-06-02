# JavaScript / TypeScript

disrobe deobfuscates obfuscated JS/TS, splits bundled output back into per-module sources, and inspects packaged JS runtimes.

## Deobfuscation

```sh
disrobe js deob bundle.min.js --out clean.js
```

Reverses the full obfuscator.io stack (9-stage), JS-Confuser, Jscrambler (36 transforms), and the esoteric encoders — jsfuck, JJEncode, AAEncode, Dean Edwards Packer, and others. Renaming is scope-aware, so recovered identifiers respect lexical scope rather than colliding globally.

## Unbundling

```sh
disrobe js unbundle app.bundle.js --out src/
```

Splits a bundled file back into per-module sources across Webpack 4/5, Vite, Rollup, Rolldown (the Rust-based Vite 8+ backend), esbuild, Turbopack, Bun, Parcel 2, Browserify, and the classic SystemJS / RequireJS / AMD module systems.

## Packaged JS runtimes

```sh
disrobe js inspect app.jsc
```

Inspects V8 cached-data (`.jsc`), Node SEA blobs, nexe-built executables, nw.js zip-suffix bundles, and Electron `.asar` containers. It prints real detection plus an honest snapshot-deserialize wall where the V8 snapshot format prevents full recovery — disrobe reports the boundary rather than fabricating past it.

## Chaining

Electron and Node packaging chains run end to end:

```sh
disrobe auto app.asar --out recovered/     # Electron .asar -> webcrack -> source
```
