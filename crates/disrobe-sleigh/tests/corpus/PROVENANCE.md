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

The raw file preserves pypcode's rendered translation for all 64 instructions. The table removes instruction markers and non-architectural temporary writes, inlines temporary definitions, keeps the final value of each architectural register, folds constant-only operations, orders commutative operands, and records RAM operations and control-flow effects. An instruction with no architectural effect uses `none`. Shift counts use four-byte constants in the normalized form. Pypcode's internal conditional branch for `csel` becomes `select(condition, true, false)`. Its unsigned subtraction carry form `right <= left` becomes the equivalent `boolnot(ult(left, right))`.

- `generate_pypcode_oracle.py`: `7162E2D8804462B258E59D346B2FBDBA0DC92A42882961635E7A045CD1A68EAA`
- `aarch64_pypcode.raw`: `80611969425580A1A213B8FF7D30E4158A51DB21827F07E00F9C1656CB8D32B7`
- `aarch64_pypcode.tsv`: `3D88A9B2FDED3BE86047F4CFCEC4E0C82D76E9A916F0CB4228447C0C3D35525C`

`tests/pcode_oracle.rs` independently normalizes this crate's emitted P-code and compares all 64 architectural-effect records with the pypcode-derived table.
