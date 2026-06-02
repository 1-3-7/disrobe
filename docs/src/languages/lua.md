# Lua

disrobe decompiles Lua bytecode across every common dialect and peels the major Lua obfuscators.

```sh
disrobe lua decompile script.luac --out script.lua
disrobe lua deob obfuscated.luac --out clean.luac
disrobe lua detect script.luac
```

`decompile` handles Lua 5.1, 5.2, 5.3, 5.4, LuaJIT 2.0/2.1, Luau, and GLua with per-dialect lifters. `detect` reports the dialect and header fields. `deob` peels obfuscator wrappers — Prometheus, MoonSec v1/v2/v3, Ironbrew2, and others.

Honesty note: where an obfuscator wraps the bytecode behind a custom VM (the strongest tier), disrobe detects and reports it rather than claiming a peel it cannot deliver. WeAreDevs-class wrappers are reversed; VM-walled families are detected.
