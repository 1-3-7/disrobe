# x86-64 GCC oracle corpus

The GCC oracle corpus was produced on Windows with Strawberry Perl's MinGW-w64 toolchain. GCC reports `gcc.exe (MinGW-W64 x86_64-ucrt-posix-seh, built by Brecht Sanders, r8) 13.2.0`. GNU objcopy and GNU objdump report Binutils 2.42.

`x86_64_oracle_o2.text` was compiled from `tests/fixtures/x86_64_oracle.c` with:

```text
gcc -std=c11 -O2 -m64 -fcf-protection=branch -fno-if-conversion -fno-if-conversion2 -fno-asynchronous-unwind-tables -fno-stack-protector -fno-unwind-tables -fno-optimize-sibling-calls -c x86_64_oracle.c -o x86_64_oracle_o2.o
objcopy -O binary -j .text x86_64_oracle_o2.o x86_64_oracle_o2.text
objdump -d -z -M intel-mnemonic,intel x86_64_oracle_o2.o
```

The `.mnemonics` file preserves the GNU objdump instruction sequence. The `.boundaries` file preserves each hexadecimal section offset, decimal instruction length, and mnemonic. When GCC, GNU objcopy, and GNU objdump are available, the live test repeats the compile, extraction, and disassembly, then compares every iced-x86 boundary and mnemonic with that fresh GNU objdump output. GNU objdump can print encoding prefixes such as `data16` and `cs` before the instruction mnemonic. The comparison treats those tokens as prefixes and compares the following mnemonic.

Executable SHA-256 records:

- `gcc.exe`: `34A92E71F6814BD936135D0BD82B80B63DAAF445791BBA4A6BBA93075235E8A4`
- `objcopy.exe`: `F01DF90D135D603C4DC9DA2E669E7A3994EED34117E0275119122C74B26CC30E`
- `objdump.exe`: `73A20B926E92C319D24A7B4F7919334CC62EDBD7C43A261982484D96F4385A23`

Corpus SHA-256 records:

- `x86_64_oracle.c`: `B9F818CB110680B3BE39CA9D232401E1762B52B0CBCF15BF4D35C8C1864EA568`
- `x86_64_oracle_o2.text`: `D6B673E78E2D979E91F8353903FF25B9357AEDD0893ACAEE7C20842B40899304`
- `x86_64_oracle_o2.mnemonics`: `E63D0473016471BECD84C43301F7C2F796555CB848D6060A6C138FA102FBC861`
- `x86_64_oracle_o2.boundaries`: `2FD3330949453761345C733BA57C02B1EAFE25867CD5277E06B03AB36C7DA424`

The corpus contains 95 instructions. All 95 decode to explicit records and match GNU objdump boundaries and mnemonics. There are 92 `Supported` records and 3 `CallOther` records. The three typed contracts cover unsigned division, signed division, and `cqo`.

# P-code effects corpus

`x86_64_pypcode.raw` and `x86_64_pypcode.tsv` were produced with Python 3.14.5, pypcode 4.0.0, and its `x86:LE:64:default` Ghidra language. `python.exe` has SHA-256 `3ADBBF2AF609E206E3CA18CD55FC7C4B52F5C8BB8218DD99FD5A9E50D7A193CD`. The wheel was `pypcode-4.0.0-cp314-cp314-win_amd64.whl` with SHA-256 `B9EF032EE56A6FA59753B092463059C56338D3EDFC30582C9D44B4DDA772F098`. The pinned environment can be installed with:

```text
python -m pip install --require-hashes -r tests/fixtures/pypcode-requirements.txt
```

The checked verifier accepts the corpus directory and an output directory:

```text
python tests/pypcode_oracle.py tests/corpus OUTPUT_DIRECTORY
```

The live Rust test runs this command when pypcode 4.0.0 is available and requires the regenerated raw translation and normalized effect table to match both committed files byte-for-byte. The committed artifacts remain tested when the external interpreter or package is unavailable.

Each boundary record was checked with `Context.disassemble(..., max_instructions=1)` before `Context.translate(..., max_instructions=1)`. The raw file preserves pypcode's rendered translation for all 95 instructions. The table removes `IMARK` operations and unique temporaries, inlines temporary definitions, folds constant and identity operations, canonicalizes commutative operations and address sums, keeps final full-width GPR writes, and records RAM and control-flow effects in order.

The comparison records the defined write set for CF, PF, ZF, SF, and OF. AF is omitted only from the pypcode comparison because the Ghidra x86 translation does not emit it for these arithmetic forms. The lifter still emits AF mechanically from iced-x86 metadata, and focused tests check that output. Undefined flag `CALLOTHER` outputs are omitted from the equality record. PF's expanded pypcode popcount expression and the lifter's typed `x86_parity8_pure_v1` operation both remain represented by the PF write record. Immediate shifts greater than one leave pypcode's OF input unchanged, while the lifter explicitly marks OF undefined; neither is counted as a defined OF write. These normalizations do not remove GPR, RAM, branch, call, or return effects.

pypcode disassembles `66 90` as the semantic alias `nop`; GNU objdump and iced-x86 report `xchg ax,ax`. The record retains the GNU objdump mnemonic and requires the same empty architectural effect.

The Rust test independently normalizes this crate's shared `PcodeOp` values and compares all 92 modeled instruction records with the pypcode-derived table. Division and `cqo` remain explicit `CALLOTHER` boundaries and are not included in the effect-agreement numerator.

- `x86_64_pypcode.raw`: `07F6090F52A183BEED70C0152ACF2EF7D4FC79E13F776E99578F6AC6D6FADEF8`
- `x86_64_pypcode.tsv`: `631B368B799393BE949C70FE859CA977A7398E226EF38FABC5500D33ADE45936`
- `pypcode_oracle.py`: `2D31FE305FF2748D18C19AAA213967BEC2F161857F720FB44E0812A9A786BB2E`
- `pypcode-requirements.txt`: `6FFF231C68BF648A6882DADCFC6FED003C6DCCBDD6E0E51201BE0FFD17F0C3EC`

The measured effect agreement is 92 of 92 fully modeled instructions.
