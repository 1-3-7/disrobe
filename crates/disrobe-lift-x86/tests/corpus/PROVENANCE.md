# x86-64 GCC oracle corpus

The GCC oracle corpus was produced on Windows with Strawberry Perl's MinGW-w64 toolchain. GCC reports `gcc.exe (MinGW-W64 x86_64-ucrt-posix-seh, built by Brecht Sanders, r8) 13.2.0`. GNU objcopy and GNU objdump report Binutils 2.42.

`x86_64_oracle_o2.text` was compiled from `tests/fixtures/x86_64_oracle.c` with:

```text
gcc -std=c11 -O2 -m64 -march=x86-64-v2 -mno-avx -fcf-protection=branch -fno-if-conversion -fno-if-conversion2 -fno-asynchronous-unwind-tables -fno-stack-protector -fno-unwind-tables -fno-optimize-sibling-calls -c x86_64_oracle.c -o x86_64_oracle_o2.o
objcopy -O binary -j .text x86_64_oracle_o2.o x86_64_oracle_o2.text
objdump -d -z -M intel-mnemonic,intel x86_64_oracle_o2.o
```

The `.mnemonics` file preserves the GNU objdump instruction sequence. The `.boundaries` file preserves each hexadecimal section offset, decimal instruction length, and mnemonic. When GCC, GNU objcopy, and GNU objdump are available, the live test repeats the compile, extraction, and disassembly, then compares every iced-x86 boundary and mnemonic with that fresh GNU objdump output. GNU objdump can print encoding prefixes such as `data16` and `cs` before the instruction mnemonic. The comparison treats those tokens as prefixes and compares the following mnemonic. GNU objdump prints `movs`, `stos`, `lods`, `cmps`, and `scas` without a width suffix in Intel mode, so the comparison derives `b`, `w`, `d`, or `q` only from objdump's explicit memory operand width.

Executable SHA-256 records:

- `gcc.exe`: `34A92E71F6814BD936135D0BD82B80B63DAAF445791BBA4A6BBA93075235E8A4`
- `objcopy.exe`: `F01DF90D135D603C4DC9DA2E669E7A3994EED34117E0275119122C74B26CC30E`
- `objdump.exe`: `73A20B926E92C319D24A7B4F7919334CC62EDBD7C43A261982484D96F4385A23`

Corpus SHA-256 records:

- `x86_64_oracle.c`: `32FDCD6E2E85329B2A685E17989A9A6858F69437A1A7E99BF8E971BEBA5573A3`
- `x86_64_oracle_o2.text`: `0B9642412F2AC7A96F21B57FBA55959E7596863DBA00AB3826AEFDD94CCCC0EC`
- `x86_64_oracle_o2.mnemonics`: `719EC72DD94CB77768934141E753D2B8A07E026B094173D7B391D48A7D55402A`
- `x86_64_oracle_o2.boundaries`: `87D5F689F3AF8260BF6F47183584AFAAD59D4FD72F28CD0BA8219B058E06CD57`

The corpus contains 281 instructions. All 281 decode to explicit records and match GNU objdump boundaries and mnemonics. There are 223 `Supported` records and 58 `CallOther` records. The added fixture region contains 186 instructions, of which 130 are modeled and 56 use typed contracts. The modeled records now include memory `bt`, `bts`, `btr`, and `btc`, CL-controlled `shl`, `shr`, `sar`, `shld`, and `shrd`, and memory `movaps`. The contract records cover checked division, bit scans and counts, MXCSR-sensitive scalar floating-point operations and conversions, REP string loops, locked operations, memory exchanges, compare-exchanges, and fences.

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

Each boundary record was checked with `Context.disassemble(..., max_instructions=1)` before `Context.translate(..., max_instructions=1)`. The raw file preserves pypcode's rendered translation for all 281 instructions. The table removes `IMARK` operations and unique temporaries, inlines temporary definitions, folds constant and identity operations, canonicalizes commutative operations and address sums, keeps final full-width GPR writes, records XMM0 through XMM15 and their scalar lanes, and records RAM and control-flow effects in order.

The comparison records the defined write set for CF, PF, ZF, SF, and OF. AF is omitted only from the pypcode comparison because the Ghidra x86 translation does not emit it for these arithmetic forms. The lifter still emits AF mechanically from iced-x86 metadata, and focused tests check that output. Undefined flag `CALLOTHER` outputs are omitted from the equality record. PF's expanded pypcode popcount expression and the lifter's typed `x86_parity8_pure_v1` operation both remain represented by the PF write record. Immediate shifts greater than one leave pypcode's OF input unchanged, while the lifter explicitly marks OF undefined; neither is counted as a defined OF write. These normalizations do not remove GPR, RAM, branch, call, or return effects.

On x86-64 hosts, a separate test executes register XADD natively for eight carry, overflow, auxiliary-carry, zero, sign, and parity edge cases. A test-only evaluator runs the emitted P-code from the same starting registers and compares both result registers plus all six arithmetic flag values with the hardware result.

pypcode disassembles `66 90` as the semantic alias `nop`; GNU objdump and iced-x86 report `xchg ax,ax`. The record retains the GNU objdump mnemonic and requires the same empty architectural effect. pypcode condition aliases such as `setc` and `cmovz` are normalized to the GNU and iced-x86 names. Its `.rep`, `.repne`, and `.lock` suffixes are treated as encoding prefixes because the boundary mnemonic is stored separately from prefixes. pypcode 4.0.0 reports REX.W `48 a7` as `cmpsd`; only that exact byte-qualified form, including REP-prefixed encodings, is accepted as the `cmpsq` alias established by GNU objdump and iced-x86.

One-byte flag inequality and boolean XOR are canonicalized together, as are flag equality and negated boolean XOR. A De Morgan rewrite canonicalizes the equivalent signed-condition predicates. Ghidra's instruction-local CMOV branch and the lifter's branchless bitmask choice are both recorded as a select expression. A subpiece of an XMM register is canonicalized to the same register-space byte slice used by the lifter. Aligned 32-bit GPR writes are recorded as their architecture-required zero-extension to the full 64-bit register; this makes pypcode's partial `lodsd` write explicit. These rules preserve the selected value and all architectural writes.

The Rust test independently normalizes this crate's shared `PcodeOp` values and compares all 223 modeled instruction records with the pypcode-derived table. Typed `CALLOTHER` boundaries remain in the raw and normalized pypcode corpus but are not included in the effect-agreement numerator.

- `x86_64_pypcode.raw`: `C25AB30869D96655E62619A95EB27462862F6EA82A2FE0B434674E85EB9FE289`
- `x86_64_pypcode.tsv`: `11CC7B843035F56F759DFF38FB79F2B5DBC05AF2E9EAD0D10EC3089F449DCDA8`
- `pypcode_oracle.py`: `D0BA61A80F16C1038D45A2D8A6EFC9E362CD87314FCE9CF200C74F4B0A4F8667`
- `pypcode-requirements.txt`: `6FFF231C68BF648A6882DADCFC6FED003C6DCCBDD6E0E51201BE0FFD17F0C3EC`

The measured effect agreement is 223 of 223 fully modeled instructions. The added fixture region contributes 130 of those agreements.
