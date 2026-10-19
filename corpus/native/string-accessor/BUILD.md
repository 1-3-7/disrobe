# Indexed string-accessor fixtures

`string_accessor.c` is an authored static-analysis fixture. It contains 64 distinct plaintext reference strings inside a disabled `REFERENCE_SOURCE` block, two encrypted byte-blob and `uint32` offset-table variants, and 64 exported noinline wrappers per image. Each wrapper supplies a distinct constant index in `ecx` before calling `indexed_string_accessor`; the zero index can use `xor ecx, ecx`.

Variant 1 seeds xorshift32 with `(index + 1) * 0x9e3779b9 ^ start ^ (length << 12) ^ (length >> 1) ^ 0xa5c39e17`, uses shifts 13, 17, and 5, and decodes with `rol8(byte, 5) ^ low8(state >> 8 ^ state)`. Variant 2 uses a different seed expression and shifts 7, 9, and 13. The plaintext table in the source is the independent reference; it is excluded from each compilation.

The DLLs are parsed, never run.

## Toolchains

MSVC Build Tools 2022 14.44.35207 provided `cl` 19.44.35229 and `link` 14.44.35229.0. LLVM 19.1.7 provided `clang`, `lld-link`, `llvm-readobj`, and `llvm-objdump`.

## Build

Run from this fixture directory with the named compiler and linker on `PATH`. In MSYS2 Bash, `MSYS2_ARG_CONV_EXCL='*'` preserves Microsoft-style linker arguments. The build produces DLLs for static inspection.

```sh
MSYS2_ARG_CONV_EXCL='*' cl /nologo /c /O2 /GS- /Gy /Brepro /DACCESSOR_VARIANT=1 /Fomsvc-v1.obj string_accessor.c
MSYS2_ARG_CONV_EXCL='*' link /nologo /DLL /NOENTRY /NODEFAULTLIB /DYNAMICBASE:NO /BASE:0x180000000 /Brepro /OPT:REF /OPT:NOICF /OUT:string-accessor-msvc-v1.dll msvc-v1.obj
```

Repeat the MSVC commands with `ACCESSOR_VARIANT=2`, `msvc-v2.obj`, and `string-accessor-msvc-v2.dll`. The Clang commands are:

```sh
clang --target=x86_64-pc-windows-msvc -c -O2 -fno-stack-protector -DACCESSOR_VARIANT=1 -o clang-v1.obj string_accessor.c
MSYS2_ARG_CONV_EXCL='*' lld-link /nologo /DLL /NOENTRY /NODEFAULTLIB /DYNAMICBASE:NO /BASE:0x180000000 /Brepro /OPT:REF /OPT:NOICF /OUT:string-accessor-clang-v1.dll clang-v1.obj
```

Repeat the Clang commands with `ACCESSOR_VARIANT=2`, `clang-v2.obj`, and `string-accessor-clang-v2.dll`.

## Static verification

`llvm-readobj --coff-exports` reports 64 `string_call_<index>` exports in each DLL. `llvm-objdump -d --no-show-raw-insn -M intel` shows each wrapper setting its constant index in `ecx` with `mov` or a self-XOR and issuing a direct `call` to the accessor.

## Hashes

| File | Bytes | sha256 |
| --- | ---: | --- |
| `string_accessor.c` | 14743 | `0b81a872bb902d4565568fb9c3b40939119a97556d1a6c8e1716f9c2ed9ebd8b` |
| `string-accessor-msvc-v1.dll` | 9728 | `5d6657b4c34d51de4af9d5687207300a0863016090dcff0fdd4399a8416efca6` |
| `string-accessor-msvc-v2.dll` | 9728 | `06b89e1d87df63620b6d8c982c6f2b67485d22cb90d4cd641c94a9859da5f04a` |
| `string-accessor-clang-v1.dll` | 8192 | `f130fa0df3375b6091e4908c36629771ed42d3f34ec80c15aedd2234cab9e1e3` |
| `string-accessor-clang-v2.dll` | 8192 | `43f1709dea4a4b15a3120396f030fff8cc8209bd2253f08324a41bae74504aeb` |
