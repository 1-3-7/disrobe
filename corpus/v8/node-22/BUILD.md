# node-22 V8 .jsc fixture provenance

`hello-22.jsc` is a real V8 `ScriptCompiler::CachedData` (CodeSerializer output) buffer, the
same format `bytenode` and Electron ship. It was produced from `hello-22.js` (byte-identical
to the node-18/20/24 source) on this host.

## Toolchain

| field | value |
|-------|-------|
| node | v22.22.3 |
| v8 | 12.4.254.21-node.56 |
| arch / platform | x64 / win32 |
| v8 build flags | pointer compression OFF, sandbox OFF (`kTaggedSize` = 8, `process.config.variables.v8_enable_pointer_compression` = 0, `v8_enable_sandbox` = 0) |

## Exact generation command

`hello-22.jsc` mirrors `bytenode.compileCode`: compile the source as a `vm.Script` with the
same V8 flags bytenode sets (`--no-lazy`, `--no-flush-bytecode`) so inner functions are
eagerly compiled and present in the cache, then take `createCachedData()`.

```js
const fs = require('node:fs');
const vm = require('node:vm');
const v8 = require('node:v8');
v8.setFlagsFromString('--no-lazy');
v8.setFlagsFromString('--no-flush-bytecode');
const src = fs.readFileSync('hello-22.js', 'utf8');
const script = new vm.Script(src, { produceCachedData: true });
fs.writeFileSync('hello-22.jsc', script.createCachedData());
```

## Hashes

| file | sha256 | bytes |
|------|--------|-------|
| hello-22.js | e78e20e3502c2b4eeee06e0ea0c32f99c262d83d0fe4838b1a335bbc4e00bd00 | 240 |
| hello-22.jsc | 109f9e441228c5f8323031c10d9e2b0fedc8b5638bf0cb3832c891f3310a3ee0 | 928 |

V8 cache data embeds a per-process source/flag hash, so re-running the command yields a
different byte buffer (a handful of hash bytes change). The serialized object graph layout
and the recovered BytecodeArray bytes are stable, so the parser and its tests do not depend
on the file sha.

## Ground truth

The recovered bytecode is validated against V8's own disassembler, captured under node 22 so
the compilation unit matches the one serialized into the .jsc:

```
node --no-lazy --no-flush-bytecode --print-bytecode --print-bytecode-filter="*" driver.js hello-22.js
```

where `driver.js` does `new vm.Script(fs.readFileSync(process.argv[2],'utf8'), {produceCachedData:true})`.
Two user BytecodeArrays appear: the top-level script (81 bytes, frame size 40, parameter
count 1) and `greet` (33 bytes, frame size 24, parameter count 2). Both match disrobe's
recovery and disassembly byte-for-byte and mnemonic-for-mnemonic (see
`crates/disrobe-pass-js-deob/tests/v8_codeserializer_real.rs`). v8 12.4 introduces the
script-context-slot opcodes (StaCurrentScriptContextSlot) and renumbers both the Ignition
table (Return = 0xAE, Star0 = 0xC9) and the CodeSerializer opcodes relative to 11.3 and 13.6,
which the per-version tables encode.
