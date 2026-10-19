# Function-scoped native output and address queries

`scope.c` was written for this repository. Its MSVC build, `scope.dll`, is the input for `crates/disrobe-cli/tests/native_function_scope.rs`, which grades `disrobe native disasm --function/--range`, `disrobe native decompile --function/--range` and the `xrefs-to 0x<rva>`, `const-users` and `field-users` queries. The DLL is parsed, never run.

The source holds a settings record whose constructor stores float, double and integer defaults as immediates and string pointers through `lea`, readers that load float and double constants from `.rdata` through RIP-relative operands, a global counter written and read by several functions, and a float table read through a register base. Two functions call others and so carry `.pdata` unwind entries (`settings_apply`, `settings_blend`); the rest are leaves without unwind data, and two of those (`counter_add`, `curve_at`) are neither exported nor named anywhere in the image, so only function discovery finds them. MSVC inlines `settings_luma` into `settings_blend`.

## Build

Toolchain: Visual Studio Build Tools 2022, MSVC 14.44.35207 (`cl` 19.44.35229, `link` 14.44.35229.0), x64 host and target. No headers or libraries are used, so `INCLUDE` and `LIB` play no part; `_fltused` is defined in the source because no CRT is linked.

```sh
cl /nologo /c /O2 /GS- /Gy /Brepro /Fo:scope.obj scope.c
link /nologo /DLL /NOENTRY /NODEFAULTLIB /DYNAMICBASE:NO /BASE:0x180000000 /Brepro /OPT:REF /OPT:NOICF /MAP:scope.map /OUT:scope.dll scope.obj
```

`/Brepro` makes the build reproducible: rebuilding with these commands gives the same `scope.dll` bytes. The import library and export file the linker also writes are not kept.

## Independent references

The test grades disrobe against these files, none of which disrobe produced:

| File | Producer | Command |
| --- | --- | --- |
| `scope.map` | the MSVC linker | `/MAP:scope.map` above; line endings converted from CRLF to LF |
| `scope.unwind.txt` | LLVM 19.1.7 `llvm-readobj` | `llvm-readobj --unwind scope.dll` |
| `scope.objdump.txt` | LLVM 19.1.7 `llvm-objdump` | `llvm-objdump -d --no-show-raw-insn -M intel scope.dll` |

The linker map gives every function's start address, including the two that the image does not name. `llvm-readobj --unwind` gives each `.pdata` entry's start and end. `llvm-objdump` gives the instruction stream, each RIP-relative operand's target address and each direct call or jump target. Constant values come from the source literals and from the bytes `llvm-objdump` shows each operand reading.

## Hashes

The test checks each file against this table before trusting it.

| File | Bytes | sha256 |
| --- | --- | --- |
| `scope.c` | 1905 | `573bebd58663cfa0a905a1c025f4be77600897c7250f0765dd29ab9bf79b69d1` |
| `scope.dll` | 3072 | `79041dbfac70a3882982d2a6fedff44ef6ce01c4867833c963715aff6b39fe2f` |
| `scope.map` | 5904 | `ed5f5102c6fc182e54c213c75838dbc4ea2748d88ba76f58b942a12081a65582` |
| `scope.unwind.txt` | 986 | `53654be472ec346ca7d4a745d0f7b2afd52deda3efe1f105e4f179e9f180d344` |
| `scope.objdump.txt` | 5576 | `7e0a02ce68a864620b57add5240274e015472ebd116fea2c27f6e9febf37aff2` |
