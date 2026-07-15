# AArch64 compiler corpus

These `.text` files and mnemonic sequences were produced by Arm GNU Toolchain 15.2.Rel1 build arm-15.86. GCC reports version 15.2.1 20251203 and GNU objdump reports version 2.45.1.20251203.

`aarch64_oracle_o0.text` and `aarch64_oracle_o2.text` were compiled from `tests/fixtures/aarch64_oracle.c` with the matching optimization flag plus `-fno-asynchronous-unwind-tables -fno-stack-protector -fno-optimize-sibling-calls`. `aarch64_forms.text` was assembled from `tests/fixtures/aarch64_forms.s`. Each `.text` file was extracted with `objcopy -O binary -j .text`. Each mnemonic sequence was extracted from `objdump -d` in instruction order.

SHA-256 records:

- `aarch64_oracle.c`: `3D2FE84D5868565521EE060C4EC8DCB314B8997FC53D129F216AB379F42E142F`
- `aarch64_forms.s`: `3864C332662B764A857884274718300E33556DCFF355AAF5FC84B56914EDEF11`
- `aarch64_oracle_o0.text`: `1F0F19B5B2FEB427464A4B3863F5583CA55AB96AE5088CC5A9C15C1710B04D93`
- `aarch64_oracle_o2.text`: `536D7543FF9EEC120F5FADD63FFB3E58B57F7CE007FA77E429F821E53F1C6B97`
- `aarch64_forms.text`: `65432FEE6EAAD1877D82540AB0AA20E7AF0440E7A379046DA53B690F37C6A8E9`

The tests always decode the committed compiler artifacts and compare them with the committed GNU objdump results. When AArch64 GCC, objcopy, and objdump executables are available, the tests also compile and grade fresh output against the objdump from that same toolchain. Live code generation is not required to match the pinned 15.2 artifacts byte for byte.

# AArch64 P-code corpus

`aarch64_pypcode.raw` and `aarch64_pypcode.tsv` were produced from every instruction in `aarch64_forms.text` with pypcode 4.0.0 and its `AARCH64:LE:64:v8A` Ghidra language. The wheel used for this run was `pypcode-4.0.0-cp314-cp314-win_amd64.whl` with SHA-256 `B9EF032EE56A6FA59753B092463059C56338D3EDFC30582C9D44B4DDA772F098`.

The generator is reproducible from the crate directory:

```text
python -m pip install --require-hashes -r tests/fixtures/pypcode-requirements.txt
python tests/fixtures/generate_pypcode_oracle.py
```

The raw file preserves pypcode's rendered translation for all 64 instructions. The table removes instruction markers and non-architectural temporary writes, inlines temporary definitions, keeps the final value of each architectural register, folds constant-only operations, orders commutative operands, and records RAM operations and control-flow effects. Independent facts are canonicalized within each control-flow segment while segment order remains intact across transfers. An instruction with no architectural effect uses `none`. Shift counts use four-byte constants in the normalized form. Pypcode's internal conditional branch for `csel` becomes `select(condition, true, false)`. Its unsigned subtraction carry form `right <= left` becomes the equivalent `boolnot(ult(left, right))`.

- `generate_pypcode_oracle.py`: `5E770757089F683383F12A3091A6750A950CF657E0FB6F74FFB951D88F196040`
- `aarch64_pypcode.raw`: `80611969425580A1A213B8FF7D30E4158A51DB21827F07E00F9C1656CB8D32B7`
- `aarch64_pypcode.tsv`: `2A0E78B211244BB70F2DA7AA7B981371ED8C40942C06BB93970B5D1570DEC81A`

`tests/pcode_oracle.rs` independently normalizes this crate's emitted P-code and compares all 64 architectural-effect records with the pypcode-derived table.

# ARM32 and MIPS32 compiler corpora

The ARM32 and MIPS32 files were produced by the GNU cross-toolchains in the official Android NDK r16b Windows x86-64 archive. ARM GCC reports `4.9.x 20150123 (prerelease)` and its GNU objdump reports `2.27.0.20170315`. MIPS GCC reports `4.9.x 20150123 (prerelease)` and its GNU objdump reports `2.25.51.20141117`.

The A32 and Thumb matrices were assembled with `-march=armv7-a` and their respective `-marm` or `-mthumb` mode. The MIPS matrices were assembled twice with `-mips32 -mno-abicalls -fno-pic` and `-EL` or `-EB`. The C fixtures were compiled with the same architecture flags plus `-std=c11 -O2 -fno-asynchronous-unwind-tables -fno-stack-protector -fno-unwind-tables`. Each `.text` file was extracted with the matching `objcopy -O binary -j .text`; mnemonic sequences came from the matching `objdump -d -z`.

SHA-256 records:

- `arm32_a32_forms.s`: `288DEC6A44E06C24A0CE7B454F4E1C7D0578C9CE9A1D7C5100889C62FDE6DBF8`
- `arm32_thumb_forms.s`: `EE5D7F8AE10B499C0F2725F099FA499F2471692A58A28FF26513ECC843329E61`
- `arm32_oracle.c`: `547AE77CA49B3CB3E50CD35326C6A12B64BB9AE4BE1F68E94E8463D5AB2FDE23`
- `mips32_forms.s`: `4C997CC1EBC093F321D4478C99C2009E4AFBDB5110B29E9521532D695FF1A094`
- `mips32_oracle.c`: `B7D837BE5DB0D12DC011D40163EB1D6DE4594FD13A71FB32E61A38F41D981B44`
- `arm32_a32_forms.text`: `181EFD8A05C8FCD6E27C132ED6B4831924F3A1F8B4FE31EAEFDDF27A8C967771`
- `arm32_thumb_forms.text`: `08EA8C39C476A241F2655133A3EF3A7C60D26F0B98827B5434B369D7E7E20C07`
- `arm32_a32_oracle_o2.text`: `38B09FABAB32D888C145E234BDDA916F4FE91F802482FBA4BB0CD1F2FF16E6CF`
- `arm32_thumb_oracle_o2.text`: `47D0B4AD20E0823CC92D624BC587482012CEFB377F17311C3FB87BFAA2F7A3C0`
- `mips32le_forms.text`: `6D133085C578A003DC4C0C701F049974C4E495049A5C9BABBAD1838E28D64BE8`
- `mips32be_forms.text`: `9139878AE9049A62AE9820170BA1DB9D352CAA4DD183A536F257A5106142AE6E`
- `mips32le_oracle_o2.text`: `A753AE811D35E802BD069E31B6D34576E38804F32EC5D9EC5F60DA8ECDFF4AA1`
- `mips32be_oracle_o2.text`: `4E3E29C5D213B41011F7514B16CA76BAFDFCA43E19E472388E179C3C9BB1394F`

The committed form matrices contain 20 A32 instructions, 23 Thumb instructions, and 28 instructions in each MIPS byte order. The committed C corpora contain 19 A32 instructions, 22 Thumb instructions, and 20 instructions in each MIPS byte order. The tests optionally repeat all eight builds and compare fresh output with the same toolchain's objdump.

# ARM32 and MIPS32 P-code corpus

`multiarch_pypcode.raw` and `multiarch_pypcode.tsv` were produced with pypcode 4.0.0 from the committed form matrices. The languages are `ARM:LE:32:v7`, `ARM:LE:32:v8T`, `MIPS:LE:32:default`, and `MIPS:BE:32:default`.

The 31 records cover arithmetic, moves, loads, stores, wide moves, multiplication, direct calls, ARM branch exchange and stack returns, Thumb PC reads and writes, both MIPS byte orders, and a MIPS conditional branch whose delay-slot write precedes the transfer. The table retains final architectural register values, flags, RAM effects, and control-flow effects while removing instruction markers, internal temporaries, and decoder-context pcodeops. Independent facts are canonicalized within each control-flow segment while segment order remains intact across transfers.

The generator is reproducible after the pinned pypcode installation:

```text
python tests/fixtures/generate_multiarch_pypcode_oracle.py
```

- `generate_multiarch_pypcode_oracle.py`: `30CEAFD226EBC7EDB607E0856CE2E676EDB005645EC1A008977153AD0C65CF3B`
- `multiarch_pypcode.raw`: `1825B26D8B0784FF962859422483051616DD1CEADA2C86C189648AE1FF50491A`
- `multiarch_pypcode.tsv`: `46DA12279AD8949B92F101444EE6A443E8C698BB614584269A60B545415A2F8D`

`tests/pcode_oracle.rs` independently normalizes this crate's ordered P-code stream and compares every record with the pypcode-derived table.
