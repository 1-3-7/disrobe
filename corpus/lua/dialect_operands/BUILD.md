# dialect_operands

Programs written for this repository that exercise the Lua operand encodings whose meaning differs by dialect: upvalue capture after `CLOSURE`, `LOADNIL` spans above register 0, the `SETLIST` base of a constructor's second flush, and the extended `SETLIST` block number of a constructor with more than 25,550 items. `crates/disrobe-pass-lua/tests/dialect_operand_reexec_oracle.rs` decompiles each build and compares the recovered program's output with the source's under a real interpreter.

The Lua 5.1 and 5.4 builds are produced at test time by `luac5.1` and `luac5.4`. The Lua 5.2 and 5.3 builds are committed because CI installs no Lua 5.2 or 5.3 toolchain; the test runs their recovered source under Lua 5.4, where these programs print the same values.

| Source | sha256 |
| --- | --- |
| `upvalue_capture.lua` | `f34569bb69ecfc97bbb0be7be1dc670765240f76e8dc731deffc54046e9b4b07` |
| `loadnil_above_r0.lua` | `839bf616322e65b746bb5fea44445cecd411dd4dc3440214b4318835d44453d1` |
| `constructor_75.lua` | `6ea2b7054b4a3d810a7296a10156ca5511722904d4902bf98bcb9f02675b4506` |
| `constructor_25600.lua` | `0e8dd977a8cb63de2589000bb57417c8a376d48c3547656203f9aa26c6105382` |

`constructor_25600.lua` holds one constructor of 25,600 items in 512 flushes of 50: every fiftieth item is its block number and the rest are `nil`, so each flush is one `LOADNIL` spanning 49 registers above register 0 followed by a constant, and a wrong `SETLIST` base or `LOADNIL` span moves a block number to another index and changes the printed count and weighted sum.

## Lua 5.2 chunks

Toolchain: `luac5.2` 5.2.4 built from `lua-5.2.4.tar.gz` (lua.org, 252,651 bytes, sha256 `b9e2e4aad6789b3b63a056d442f7b39f0ecfca3ae0f1fc0ae4e9614401b69f4b`, the sum lua.org publishes) with MSYS2 UCRT64 `gcc` 16.2.0: `gcc -O2 -std=gnu99 -DLUA_COMPAT_ALL -o luac5.2.exe luac.c` plus every core and library source except `lua.c`. Each chunk was compiled from inside this directory:

```sh
luac5.2 -o upvalue_capture.5_2.luac upvalue_capture.lua
luac5.2 -o loadnil_above_r0.5_2.luac loadnil_above_r0.lua
luac5.2 -o constructor_75.5_2.luac constructor_75.lua
luac5.2 -o constructor_25600.5_2.luac constructor_25600.lua
```

| Chunk | Bytes | sha256 |
| --- | --- | --- |
| `upvalue_capture.5_2.luac` | 1031 | `d663dfd396970d246a0b2172cf8ef8b4ca5f28d4d6c5bd23019d53aa9dc74bcb` |
| `loadnil_above_r0.5_2.luac` | 578 | `69ab276e3bb04688725ad9317235243a299262f22473591ca4c43bf308261b9d` |
| `constructor_75.5_2.luac` | 1733 | `b8ac8f3df5c993cde0cf8ac2ed62d2d205b316a77208304db918b0b759ab63e3` |
| `constructor_25600.5_2.luac` | 17524 | `69e6ef8c7fab64463358ea5616c2a46c2c80b4ba72f7d9a286a1e8d8dab8fe82` |

## Lua 5.3 chunks

Toolchain: `luac5.3` 5.3.6 from the MSYS2 package `mingw-w64-ucrt-x86_64-lua53` 5.3.6-6 (UCRT64, x86_64). Each chunk was compiled from inside this directory, so the recorded chunk name is the bare file name:

```sh
luac5.3 -o upvalue_capture.5_3.luac upvalue_capture.lua
luac5.3 -o loadnil_above_r0.5_3.luac loadnil_above_r0.lua
luac5.3 -o constructor_75.5_3.luac constructor_75.lua
luac5.3 -o constructor_25600.5_3.luac constructor_25600.lua
```

| Chunk | Bytes | sha256 |
| --- | --- | --- |
| `upvalue_capture.5_3.luac` | 815 | `31ef6ec7a860ca7cd1913d2e3d1660a801448d8646631fc46ea79d1c2cabe078` |
| `loadnil_above_r0.5_3.luac` | 506 | `91c59a5a8b7d1997fbc72f484f7f42f1eb540ae923b6c31cc5eb167162d76fa4` |
| `constructor_75.5_3.luac` | 1677 | `c4f38310751c4d52e3da8e9235da37e769af1f9cc6cc01f32184c2c4759190e0` |
| `constructor_25600.5_3.luac` | 17453 | `71b6f1f2eb45acbd4b3255a348818bb7f91e5dba7ddc7a4d372f30dee8bed2c5` |
