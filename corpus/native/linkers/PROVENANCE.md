# Linker twin fixtures

`base32-clang19-gnuld.exe` and `base32-clang19-lld.exe` are the same program compiled by the same
compiler and linked by two different linkers. They are benign console programs built from the
committed similarity corpus source and are never executed by any test.

## Why two linkers

GNU ld marks most MinGW import thunks, such as `strlen`, `malloc` and `_initterm`, as COFF function
symbols (derived type `0x20`). LLD writes those thunks with type `0`, so a reader that trusts only the
type field loses them. Exactly 28 global symbols in `.text` differ in type between the two images,
and each is a six-byte `jmp qword ptr [rip+disp32]` into an import address table slot that also
carries an `__imp_` symbol.

GNU ld does not type every thunk. Its image has 7 untyped global `.text` symbols: the thunks
`memset`, `VirtualQuery`, `VirtualProtect`, `Sleep`, `SetUnhandledExceptionFilter` and
`GetLastError`, which are untyped under both linkers, and `___chkstk_ms`. The thunk predicate
therefore also adds those 6 thunks on the GNU ld image. `___chkstk_ms` is untyped assembly code
under both linkers; it is not a thunk, so the predicate does not prove it is code.

## i386 thunk image

`i386-thunks-clang19-lld.exe` is a 4096-byte PE32 image linked by LLD 19.1.7. It exercises the
32-bit absolute form `jmp dword ptr [disp32]`. `_GetTickCount@0` and `_ExitProcess@4` are untyped
global thunks into the import address table, whose slots carry `__imp_` symbols. `_local_jump` is an
untyped global in `.text` that jumps through `_local_slot` in `.data`, which is neither an import
slot nor an import address table entry. The image has no C runtime and is never executed by any
test.

`thunk32.c`:

    void __stdcall ExitProcess(unsigned int code);
    unsigned long __stdcall GetTickCount(void);
    void local_jump(void);

    int __stdcall entry(void) {
        if (GetTickCount() == 0) {
            local_jump();
        }
        ExitProcess((unsigned int)GetTickCount());
        return 0;
    }

`thunks32.s`:

        .text
        .globl "_GetTickCount@0"
    "_GetTickCount@0":
        jmp *"__imp__GetTickCount@0"
        .p2align 2, 0x90
        .globl "_ExitProcess@4"
    "_ExitProcess@4":
        jmp *"__imp__ExitProcess@4"
        .p2align 2, 0x90
        .globl _local_jump
    _local_jump:
        jmp *_local_slot
        .p2align 2, 0x90

        .data
        .globl _local_slot
    _local_slot:
        .long 0

`kernel32.def` exports both functions as `DATA`, so the import library provides only the `__imp_`
slots and the thunks come from `thunks32.s`:

    LIBRARY kernel32.dll
    EXPORTS
    ExitProcess@4 DATA
    GetTickCount@0 DATA

Build commands, run in the directory holding the three inputs:

    llvm-dlltool -m i386 -k -d kernel32.def -l libkernel32.a
    clang --target=i686-w64-windows-gnu -O2 -ffreestanding -fno-asynchronous-unwind-tables \
      -c thunk32.c -o thunk32.o
    clang --target=i686-w64-windows-gnu -c thunks32.s -o thunks32.o
    clang --target=i686-w64-windows-gnu -nostdlib -fuse-ld=lld -Wl,--entry=entry@0 \
      -Wl,--no-insert-timestamp -Wl,--build-id=none -Wl,--subsystem,console \
      -o i386-thunks-clang19-lld.exe thunk32.o thunks32.o libkernel32.a

Two consecutive builds produced identical bytes, SHA-256
`46db95916a51a9f30643fb9a494246afc4dd44abe62bf6bda9eea9bf83a88db7`.

## Sources

The inputs live in `crates/disrobe-pass-native/tests/fixtures/similarity_corpus/`.

| File | SHA-256 |
| --- | --- |
| `base32.c` | `8a3bade6d27a134c00a44388720597eecf244328a4e4d9183b19615ccae26e51` |
| `harness_hosted.c` | `30ab0666644caab37a772eb709413dc948393ec45149cbdfeb7205a5c41b5c20` |
| `corpus.h` | `7467c953f157c713ce3f6feadee158fcdfa03f45ab1b50da6b13180daf25d5a8` |

## Toolchain

- clang 19.1.7 (LLVM release build for Windows), driving LLD 19.1.7
- GNU ld 2.47 from MSYS2 `mingw-w64-ucrt-x86_64-binutils 2.47-3`
- MinGW-w64 runtime from MSYS2 `mingw-w64-ucrt-x86_64-crt 14.0.0.r262.g5ea8e9fac-1` and
  `mingw-w64-ucrt-x86_64-gcc 16.2.0-3`, found by clang through `C:/msys64/ucrt64/bin` on `PATH`

## Build commands

Both commands run in the similarity corpus directory so no absolute source path enters the images.
Without `-fuse-ld`, clang's MinGW driver links with GNU ld. `--no-insert-timestamp` keeps the PE
header timestamp at zero, and two consecutive builds produced identical bytes.

    clang --target=x86_64-w64-windows-gnu -I. -O2 -Wl,--no-insert-timestamp \
      -o base32-clang19-gnuld.exe base32.c harness_hosted.c

    clang --target=x86_64-w64-windows-gnu -I. -O2 -fuse-ld=lld -Wl,--no-insert-timestamp \
      -o base32-clang19-lld.exe base32.c harness_hosted.c

The optional header's `MajorLinkerVersion` is 2 for the GNU ld image and 14 for the LLD image.

| Image | Size | SHA-256 |
| --- | --- | --- |
| `base32-clang19-gnuld.exe` | 113432 bytes | `2bce68595769b36c145f16b9f89df43a8dfc6891f0f0c3189908907d7a4cb4b2` |
| `base32-clang19-lld.exe` | 92672 bytes | `32501e6dfe4a9a48ad2722d2b5e15bc77714bb148912830f9d120fa68ee114e1` |
