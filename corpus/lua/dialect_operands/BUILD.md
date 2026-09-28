# dialect_operands

Programs written for this repository that exercise the Lua operand encodings whose meaning differs by dialect: upvalue capture after `CLOSURE`, `LOADNIL` spans above register 0, and the `SETLIST` base of a constructor's second flush. `crates/disrobe-pass-lua/tests/dialect_operand_reexec_oracle.rs` decompiles each build and compares the recovered program's output with the source's under a real interpreter.

The Lua 5.1 and 5.4 builds are produced at test time by `luac5.1` and `luac5.4`. The Lua 5.3 builds are committed because CI installs no Lua 5.3 toolchain; the test runs their recovered source under Lua 5.4, where these programs print the same values.

| Source | sha256 |
| --- | --- |
| `upvalue_capture.lua` | `f34569bb69ecfc97bbb0be7be1dc670765240f76e8dc731deffc54046e9b4b07` |
| `loadnil_above_r0.lua` | `839bf616322e65b746bb5fea44445cecd411dd4dc3440214b4318835d44453d1` |
| `constructor_75.lua` | `6ea2b7054b4a3d810a7296a10156ca5511722904d4902bf98bcb9f02675b4506` |

## Lua 5.3 chunks

Toolchain: `luac5.3` 5.3.6 from the MSYS2 package `mingw-w64-ucrt-x86_64-lua53` 5.3.6-6 (UCRT64, x86_64). Each chunk was compiled from inside this directory, so the recorded chunk name is the bare file name:

```sh
luac5.3 -o upvalue_capture.5_3.luac upvalue_capture.lua
luac5.3 -o loadnil_above_r0.5_3.luac loadnil_above_r0.lua
luac5.3 -o constructor_75.5_3.luac constructor_75.lua
```

| Chunk | Bytes | sha256 |
| --- | --- | --- |
| `upvalue_capture.5_3.luac` | 815 | `31ef6ec7a860ca7cd1913d2e3d1660a801448d8646631fc46ea79d1c2cabe078` |
| `loadnil_above_r0.5_3.luac` | 506 | `91c59a5a8b7d1997fbc72f484f7f42f1eb540ae923b6c31cc5eb167162d76fa4` |
| `constructor_75.5_3.luac` | 1677 | `c4f38310751c4d52e3da8e9235da37e769af1f9cc6cc01f32184c2c4759190e0` |
