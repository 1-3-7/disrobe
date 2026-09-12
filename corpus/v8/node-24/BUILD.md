# node-24 V8 .jsc fixture provenance

`hello-24.jsc` is a real V8 `ScriptCompiler::CachedData` (CodeSerializer output) buffer, the
same format `bytenode` and Electron ship. It was produced from `hello-24.js` on this host.

## Toolchain

| field | value |
|-------|-------|
| node | v24.16.0 |
| v8 | 13.6.233.17-node.49 |
| arch / platform | x64 / win32 |
| v8 build flags | pointer compression OFF, sandbox OFF (`kTaggedSize` = 8) |

## Exact generation command

`hello-24.jsc` mirrors `bytenode.compileCode`: compile the source as a `vm.Script` with the
same V8 flags bytenode sets (`--no-lazy`, `--no-flush-bytecode`) so inner functions are
eagerly compiled and present in the cache, then take `createCachedData()`.

```js
const fs = require('node:fs');
const vm = require('node:vm');
const v8 = require('node:v8');
v8.setFlagsFromString('--no-lazy');
v8.setFlagsFromString('--no-flush-bytecode');
const src = fs.readFileSync('hello-24.js', 'utf8');
const script = new vm.Script(src, { produceCachedData: true });
fs.writeFileSync('hello-24.jsc', script.createCachedData());
```

## Hashes

| file | sha256 | bytes |
|------|--------|-------|
| hello-24.js | e78e20e3502c2b4eeee06e0ea0c32f99c262d83d0fe4838b1a335bbc4e00bd00 | 240 |
| hello-24.jsc | 6b339cf7f005eedd9489e0f1704aefc79a8e3634db199a5c96f5f2cb74d534d3 | 928 |

V8 cache data embeds a per-process source/flag hash, so re-running the command yields a
different byte buffer (a handful of hash bytes change). The serialized object graph layout
and the recovered BytecodeArray bytes are stable, so the parser and its tests do not depend
on the file sha.

## Ground truth

The recovered bytecode is validated against V8's own disassembler, captured with the same
flags so the compilation unit matches the one serialized into the .jsc:

```
node --no-lazy --no-flush-bytecode --print-bytecode --print-bytecode-filter="*" driver.js hello-24.js
```

where `driver.js` does `new vm.Script(fs.readFileSync(process.argv[2],'utf8'), {produceCachedData:true})`.
Two user BytecodeArrays appear: the top-level script (81 bytes, frame size 40, parameter
count 1) and `greet` (33 bytes, frame size 24, parameter count 2). Both match disrobe's
recovery and disassembly byte-for-byte and mnemonic-for-mnemonic (see
`crates/disrobe-pass-js-deob/tests/v8_codeserializer_real.rs`).
