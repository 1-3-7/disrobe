# ARM mode fixtures

`thumb_forms` and `arm32_mixed_modes` were produced with clang 19.1.7 and LLD 19.1.7 on Windows.
Both are freestanding static images with no libc, so their `.text` holds only the committed source.

## Build commands

Each command runs in this directory. `clang` drives the linker through `-fuse-ld=lld`.

    clang --target=armv7-none-eabi -mthumb -march=armv7-a -O2 -ffreestanding \
      -nostdlib -fuse-ld=lld -Wl,-e,_start -o thumb_forms.elf thumb_forms.c

    clang --target=armv7-none-eabi -marm -march=armv7-a -O2 -ffreestanding \
      -nostdlib -fuse-ld=lld -Wl,-e,_start -o arm32_mixed_modes.elf arm32_mixed_modes.c

`thumb_forms.c` compiles whole in Thumb. `arm32_mixed_modes.c` carries a per-function
`__attribute__((target("thumb")))` and `__attribute__((target("arm")))` so one source file produces
both a `$t` and a `$a` region, which is what a mode-selection reader must handle.

## What each image covers

`thumb_forms.elf` holds three Thumb functions in 64 bytes of `.text` at `0x200f4`. `checksum`
contains an `it le` / `movle` block and the wide forms `add.w` and `subs.w`. `scale` is a three
instruction leaf. `_start` reads and writes a stack slot.

`arm32_mixed_modes.elf` holds four functions in 104 bytes of `.text` at `0x200fc`. `thumb_scale` is
Thumb, opens the image at `0x200fc` behind a `$t` symbol, and carries an `it le` / `movle` block.
`arm_add`, `arm_pick` and `_start` are A32 behind a `$a` symbol at `0x2010c`. `_start` calls
`thumb_scale` through `blx`, so the image also holds a real A32 to Thumb interworking call.

## Reference disassembly

The `.objdump` listings are the unedited output of llvm-objdump 19.1.7. LLVM does not read the
vendored Ghidra language files, so it grades the decoder rather than restating the same
specification.

    llvm-objdump -d --no-show-raw-insn thumb_forms.elf > thumb_forms.objdump
    llvm-objdump -d --no-show-raw-insn arm32_mixed_modes.elf > arm32_mixed_modes.objdump
    llvm-objdump -d --no-show-raw-insn arm32_forms.elf > arm32_forms.objdump

`arm32_forms.objdump` grades the A32 image that already sat here, so a change to ARM decode-mode
selection has to prove it left pure A32 alone.

## SHA-256

- `thumb_forms.elf`: `7F29144FD73A7939B4F5A3F76FC09CDAE22D0880D076E7CA08070139049E4606`
- `arm32_mixed_modes.elf`: `F1C354F757A09088B2CFCCD8292DCBE0DB7C0408A1DAE432CDA012CC05AE4ADD`
- `thumb_forms.objdump`: `1B405F1579EA3AA7A35937710DEF84B1D6BC6B1411261D483E4AB157BFABFC00`
- `arm32_mixed_modes.objdump`: `6236162EDDBF5635A40C5DF40C4DCFDD93BB87EB1509D862C3CADFF09EEBF5DF`
- `arm32_forms.objdump`: `9C70A141F1693CB1B4DBEF5D07BFBDF463B34E6BDAD510556C318EC731196E27`

## Not recorded here

`arm32_forms.c` and `arm32_forms.elf` predate this record and their build environment is not known
to it. Only the listing derived from that binary is recorded above.
