# Lua reference decode corpus

`tests/lua_opcode_completeness.rs` grades the Lua lifter against these files. The reference decoder
is the reference `luac` program for each version, which this project does not own. The reference
opcode space for each version comes from the official Lua source release for that exact point
release. The test reads only committed files. It never runs a tool and never fetches anything, and
it fails by name when a committed reference is missing.

## Tools

| Band | Program | Reported version | Location |
| --- | --- | --- | --- |
| 5.1 | `luac5.1` | Lua 5.1.5 | MSYS2 UCRT64 `lua51` package |
| 5.3 | `luac5.3` | Lua 5.3.6 | MSYS2 UCRT64 `lua53` package |
| 5.4 | `luac5.4` | Lua 5.4.8 | MSYS2 UCRT64 `lua` package |

## Regeneration

Run the generator from any directory. It refuses to run when a `luac` reports a version other than
the one pinned above, and when a downloaded source release does not match its pinned SHA-256.

```text
python crates/disrobe-nir-lift/tests/fixtures/lua/generate_luac_reference.py
```

The generator stages each Lua source in a temporary directory under a neutral file name, so a
compiled chunk records only `@hello.lua` or `@edge_cases.lua` as its source name. Two runs produced
byte-identical output for every file listed below.

## Graded chunks

Each band grades three chunks: `hello`, `edge_cases`, and `forms`.

`hello.5_1.luac` and `edge_cases.5_1.luac` are compiled here by `luac5.1` from
`corpus/lua/baseline/hello.lua` and `corpus/lua/megafile/edge_cases.lua`. The committed 5.1 chunks
under `corpus/lua/luac` were produced by a 32-bit build of the same compiler version, and a 64-bit
`luac5.1` refuses to load them. `the_thirty_two_bit_five_one_chunk_agrees_with_the_reference_stream`
grades the 32-bit chunk by requiring its lifted stream to equal the reference listing of the 64-bit
chunk of the same source.

The 5.3 and 5.4 bands grade the committed `hello` and `edge_cases` chunks in `corpus/lua/luac`
directly, because the local `luac5.3` and `luac5.4` load them.

`forms.5_1.lua`, `forms.5_3.lua`, and `forms.5_4.lua` are written for this gate and compiled here by
the matching `luac`. They exist to reach the parts of each opcode space the megafile corpus never
compiles to, which are the global assignment forms, the boolean complement, the upvalue close, the
bitwise and floor division operators, the constant and immediate operand forms, and the
to-be-closed variable. One source is kept per band, because each band accepts different syntax.

```text
luac5.1 -o <stem>.5_1.luac <stem>.lua
luac5.<minor> -p -l <chunk>
```

Each listing is reduced to one mnemonic per line in decode order, with a `function <index>` marker
before each function. The marker order is the order the reference decoder prints functions, which is
the same pre-order walk the lifter uses.

## Opcode space

Each `opcode_space.5_<minor>.txt` file holds the opcode name table of the matching Lua release, one
name per line, in opcode order. The 5.1 and 5.3 tables come from the `luaP_opnames` array in
`src/lopcodes.c`. The 5.4 table comes from the `opnames` array in `src/lopnames.h`.

| Release | Source archive | Archive SHA-256 | Member | Member SHA-256 | Names |
| --- | --- | --- | --- | --- | --- |
| 5.1.5 | `https://www.lua.org/ftp/lua-5.1.5.tar.gz` | `2640fc56a795f29d28ef15e13c34a47e223960b0240e8cb0a82d9b0738695333` | `src/lopcodes.c` | `63cd74edc75970092a8ce078c4ab970efa1ee18de960d00eb826d49fe98d8a76` | 38 |
| 5.3.6 | `https://www.lua.org/ftp/lua-5.3.6.tar.gz` | `fc5fd69bb8736323f026672b1b7235da613d7177e72558893a0bdcd320466d60` | `src/lopcodes.c` | `01ec54f3c53e2485e2ed43e396e9460f393e3db21782901dc656df6f41cee7e7` | 47 |
| 5.4.8 | `https://www.lua.org/ftp/lua-5.4.8.tar.gz` | `4f18ddae154e793e46eeab727c59ef1c0c0c2b744e7b94219710d76f530629ae` | `src/lopnames.h` | `fbdbebc96b136efc6165cba1ac2b311b0c52413aaef59ae9ec750748f13c9e9a` | 83 |

## Committed files

SHA-256 records:

- `generate_luac_reference.py` produces every file below except the three `forms.5_<minor>.lua`
  sources, which are written by hand and are inputs to it.
- `opcode_space.5_1.txt`: `cd48431ccadc37eee7050eff273e446fd12ea88bc785edfcdb05f4a5a9fc8cad`
- `opcode_space.5_3.txt`: `bf056ab5663d0145b9474b14ebebf6fec40132e264970add6a8588a2b7ebec10`
- `opcode_space.5_4.txt`: `128f875c6e3e31d5d762c4205bcd1df0e3355351cb0e25487f24f62ed384d3c8`
- `hello.5_1.luac`: `046b759eb62b3dfdfcc5e52d8c585a385fcf28e7a43b8d5f274801d8aec71e9a`
- `edge_cases.5_1.luac`: `59626c4ddda5f41a27998efe916877bc9d3f61d7b9c480ec9b9ebb1eceb24404`
- `hello.5_1.mnemonics`: `5866a062b4ec22e83881cbb13464b9f4a8e0b4808f0f297d80c226db28e1d0ca`
- `edge_cases.5_1.mnemonics`: `fd7f9738722e7df2036a14fb4d510194d1b45eb72bf3bf80ff46b861a2bd1b4d`
- `hello.5_3.mnemonics`: `0eb1861715b64c7b8937f75209ec989e8325a45d01c02ef83fefec289d42b012`
- `edge_cases.5_3.mnemonics`: `013d257a227f942915550b0880eebf6a00aa43b056033239df93d7d0ecfcfd72`
- `hello.5_4.mnemonics`: `be1ef6a5911f86d05499eb5ba5bfd14989c7285fba716070fbdfe5b6881dae2f`
- `edge_cases.5_4.mnemonics`: `b5eba7bd02533b22f4f21a7e037987d6ee59544d607fff1daa0968588a67e6aa`
- `forms.5_1.lua`: `b9d9985cb67eb90531daff843131e07285bfc5b17452689efae8bdb534dbd04b`
- `forms.5_1.luac`: `33e0b2ad98ebc71e364ad6ff6406702f40c78141164af2dcb030019dcf2b46a5`
- `forms.5_1.mnemonics`: `330766e7ee08e5cdba9e8442d797ba2e4b45df1e832d864090e1132c1f085efc`
- `forms.5_3.lua`: `7fa629520a8f0f74386047f3e4454b5ba256d1a1c082f77a231067a529dea2ae`
- `forms.5_3.luac`: `8a82e6a50344fc9b84ba3b6bf917d27a4493180ccfcddb217430fc66a2e846c6`
- `forms.5_3.mnemonics`: `a4dc8d8b39f54504868051232e14673767973b2fa2e5945c7acf28d56da78a22`
- `forms.5_4.lua`: `11a7a3c00156ece2082bbcd6f0bd64e45ade07c3d37eb38061d724ed3ad301d3`
- `forms.5_4.luac`: `18931eb69e0fc3a9fa1de270d212323133dca2395303a7abe478af38329dc341`
- `forms.5_4.mnemonics`: `c5855540efb8ac13682bb0d22bc4137cd3b5d921e7fc49d2f3ad3fe820fc742e`

The test pins the BLAKE3 hash of every graded chunk and every reference file, including the four
graded chunks under `corpus/lua/luac`. A changed input fails the inventory check instead of being
scored again.

## Measured coverage

The test prints and pins these numbers. Coverage is the count of distinct opcodes the reference
decoder produces over the graded chunks, split into the ones that reach a modelled NIR operation
and the ones the lifter reports as declined under their real mnemonic.

A modelled opcode is one the lifter lowers to something other than an unmodelled or effect-free
operation. The gate does not check that the chosen operation matches the opcode's meaning in the
language, so a coarse or wrong operation choice still counts as modelled here.

| Band | Opcode space | Corpus reach | Modelled | Declined | Graded instructions |
| --- | --- | --- | --- | --- | --- |
| 5.1 | 38 | 38 | 35 | 3 | 3493 |
| 5.3 | 47 | 45 | 43 | 2 | 3415 |
| 5.4 | 83 | 82 | 72 | 10 | 3829 |

`LOADKX` in 5.3 and 5.4, and `EXTRAARG` in 5.3, stay corpus-absent. They need a constant table or a
table constructor far larger than any source here, so no hand-written program reaches them.

## Bands with no committed reference

- Lua 5.2. The committed `corpus/lua/luac/*.5_2.luac` chunks stay graded only by the internal
  consistency test, because no `luac` 5.2 is available here to produce a reference listing.
- LuaJIT and Luau. The reader accepts both, and neither `luajit` nor `luau` is available here to
  produce a reference listing.
