# JavaScript playground

Hand-authored JS sources fed through `disrobe-pass-js-deob` (string-array recovery, unminify, control-flow unflatten, scope-aware rename).

| file | target | how to feed disrobe |
|------|--------|---------------------|
| `string-array-basic.js` | minimal obfuscator.io string-array IIFE with rotator | `disrobe js deob string-array-basic.js` |
| `full-pipeline.js` | end-to-end obfuscator.io fixture (string array + rotator + bool shorthand + atob + dead branches + setInterval watchdog + switch flatten) | `disrobe js deob full-pipeline.js` |
| `minified-bundle.js` | terser/webpack-style single-line bundle with mangled idents | `disrobe js deob minified-bundle.js` |
| `obfuscator-io-high.js` | clean calculator program, feed through `npx javascript-obfuscator --options-preset high-obfuscation` then disrobe | `npx javascript-obfuscator obfuscator-io-high.js --output out.js --options-preset high-obfuscation && disrobe js deob out.js` |
| `jsconfuser-target.js` | crypto-style routine with rotates + state mixing, feed through js-confuser then disrobe | `npx js-confuser jsconfuser-target.js -o out.js && disrobe js deob out.js` |
| `webpack4-multichunk.js` | webpack 4 bundle with iife array + `__webpack_require__.e` dynamic chunks + jsonp push, exercises chunk-graph reconstruction | `disrobe js unbundle webpack4-multichunk.js --graph` |
| `webpack5-splitchunks.js` | webpack 5 bundle with split chunks (main + vendor) using `webpackChunkapp.push`, exercises chunk-graph reconstruction | `disrobe js unbundle webpack5-splitchunks.js --graph` |
| `vite-multichunk.js` | vite bundle with `__vitePreload` + `import.meta.glob` + dynamic `import()`, exercises module-graph reconstruction | `disrobe js unbundle vite-multichunk.js --graph` |
| `jsconfuser-multi-transform.js` | jsconfuser-style payload mixing variable-masking, string-encoding, string-compression, lock guard, opaque predicate | `disrobe js deob --legacy jsconfuser-all jsconfuser-multi-transform.js` |
