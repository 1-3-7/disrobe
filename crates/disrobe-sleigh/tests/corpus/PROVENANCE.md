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

The raw file preserves pypcode's rendered translation for all 64 instructions. The table removes instruction markers and non-architectural temporary writes, inlines temporary definitions, keeps the final value of each architectural register, folds constant-only operations, orders commutative operands, and records RAM operations and control-flow effects. Independent facts are canonicalized within each control-flow segment while segment order remains intact across transfers. An instruction with no architectural effect uses `none`. Shift counts use four-byte constants in the normalized form. pypcode's internal conditional branch for `csel` becomes `select(condition, true, false)`. Its unsigned subtraction carry form `right <= left` becomes the equivalent `boolnot(ult(left, right))`.

- `generate_pypcode_oracle.py`: `2B781A33F96BC497CDA408986124772CE7AC94729FBA7D1A1E8ABC8EFEDB06B8`
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

# RISC-V compiler corpora

The RISC-V files were produced by the MSYS2 UCRT64 `riscv64-unknown-elf` GNU cross-toolchain. GCC reports version 16.1.0. GNU objcopy and objdump report Binutils 2.46.1. The compiler targets both widths through `-march=rv32im -mabi=ilp32` and `-march=rv64im -mabi=lp64`.

Executable SHA-256 records:

- `riscv64-unknown-elf-gcc.exe`: `188B5E309C52532D4B86F3CC8735036040CA4336EBA3F1E4F7EABD01C124F67A`
- `riscv64-unknown-elf-objcopy.exe`: `F4E1B715E9B21D3E1F4A4591C27E1344A65B18955B626905342DBABFB685E7C7`
- `riscv64-unknown-elf-objdump.exe`: `E5283CEF88C639A55C73F852F89F3AADA54F875926FC4A98F0BC1F73DEF973CD`

The assembly matrices were compiled with their width-specific `-march` and `-mabi` flags. The C fixture was compiled with the same flags plus `-std=c11 -O2 -fno-asynchronous-unwind-tables -fno-stack-protector -fno-unwind-tables`. Each `.text` file was extracted with the matching `objcopy -O binary -j .text`; mnemonics came from the matching `objdump -d -z`.

SHA-256 records:

- `riscv32_forms.s`: `F03D3E0E7B78F40CF41121846244F323297E32AB07B86EFAE35BBE2B21DDED7B`
- `riscv64_forms.s`: `1AF775D0528DBA78BD9C4DB9DE1AD8FEF2F00434D23A5E3C026A9DDE4E5B6466`
- `riscv_oracle.c`: `6C6439AECFB59C6533CA659998C5EE19A06E55A3E53940F28ADA1C81EFB649C8`
- `riscv32_forms.text`: `E760444C7FC25054384CB92B41DBDD8E305E29412D0362CD956F8B9CF739DB54`
- `riscv64_forms.text`: `F72DDE0F5B70115FB6E1AE10EAF30FAD3A3259BE17AE03D656B5E3648A74B6FC`
- `riscv32_oracle_o2.text`: `7BDFFECAF6CE953AD80386A6FCDF08100FF6D587108417474C6F21AEF33842CA`
- `riscv64_oracle_o2.text`: `53FFE9E8CD1881895720549AF231502A53FD670E7897512001A3EE80BE1884DD`

The RV32IM matrix contains 31 instructions and the RV64IM matrix contains 33. Both reach 100 percent constructor matching and exact objdump mnemonic agreement. Their `jalr`, `div`, `divu`, `rem`, `remu`, and `ret` forms are the six `CALLOTHER` records. Each `-O2` C corpus contains 11 instructions with one `divu` and three `ret` `CALLOTHER` records. The control-flow markers preserve the four-byte alignment boundary of the I/M-only profiles.

# PPC32 big-endian compiler corpus

The PPC corpus uses the Sysprogs PowerPC EABI GNU suite because the apt `powerpc-linux-gnu` package is not installable on Windows. GCC reports version 4.9.0. GNU objcopy and objdump report Binutils 2.24. The compiler emits `elf32-powerpc` big-endian objects. The downloaded installer SHA-256 was `E63904AEFCBFAB25022BC042445B4816AE996DE73A59D5D62FCD086D8E2079D6`.

Executable SHA-256 records:

- `powerpc-eabi-gcc.exe`: `F69422BAF96D5621DB1559C5080DA371735740D33B218105DBC7C3B79A8BCA67`
- `powerpc-eabi-objcopy.exe`: `BA070B69A361AF0EC38F7F0243CBD583381350B16B4F5B95A174B09191611734`
- `powerpc-eabi-objdump.exe`: `C46D73602190D543FC02ABCD3BE6039EB03D3865F6A55541BC6839E2281FB39F`

The assembly matrix was compiled with `-mcpu=powerpc -m32 -mbig`. The C fixture was compiled with `-O2 -ffreestanding -fno-builtin -mcpu=powerpc -m32 -mbig`. Each `.text` file was extracted with the matching `objcopy -O binary -j .text`; mnemonics came from the matching `objdump -d -z`.

SHA-256 records:

- `powerpc32_forms.s`: `6C17372578D1245B124F478A8741E8AEE6774C377AF6C27C9CB981D1F016C22F`
- `powerpc_oracle.c`: `F2C30FC7CDBA777E6B925C099628ACE0E2F5ABE0B9A67EFB0249EDF12A6338A4`
- `powerpc32_forms.text`: `9A8FC4FBF455B27D5F008A2B21E47149EE1D0E7B19659C157E9C07111AD088D6`
- `powerpc32_oracle_o2.text`: `6120A3F057A84ECB60673848284E129C77350C1B886DB3F8729634954D673AC3`

The assembly matrix contains 32 instructions and the `-O2` C corpus contains 11. Both reach 100 percent constructor matching and exact objdump mnemonic agreement. `divw` is the sole `CALLOTHER` record in each corpus.

# Multi-architecture P-code corpus

`multiarch_pypcode.raw` and `multiarch_pypcode.tsv` were produced with pypcode 4.0.0 from the committed form matrices. The languages are `ARM:LE:32:v7`, `ARM:LE:32:v8T`, `MIPS:LE:32:default`, `MIPS:BE:32:default`, `RISCV:LE:32:default`, `RISCV:LE:64:default`, and `PowerPC:BE:32:default`.

The 118 records contain 31 ARM/MIPS cases, 56 RISC-V cases, and 31 PPC32 cases. They cover arithmetic, loads, stores, multiplication, direct and indirect control flow, ARM branch exchange and stack returns, Thumb PC reads and writes, both MIPS byte orders, a MIPS delayed conditional transfer, RISC-V width-dependent effects and all multiply variants, PowerPC CR writes, PowerPC BO/BI plus CTR conditions, fall-through linking, nonzero BH, and absolute direct branches. The table retains final architectural register values, flags, RAM effects, and control-flow effects while removing instruction markers, internal temporaries, decoder-context pcodeops, and the separately asserted RISC-V alignment marker. Independent facts are canonicalized within each control-flow segment while segment order remains intact across transfers.

The generator is reproducible after the pinned pypcode installation:

```text
python tests/fixtures/generate_multiarch_pypcode_oracle.py
```

The generator disassembles every selected byte slice with the matching pypcode language and rejects instruction-count or length drift before translation. The Rust comparison requires one raw translation header for every table row and checks each row's decoded mnemonic.

- `generate_multiarch_pypcode_oracle.py`: `06943F1700DA369279141D812CBF5B104CAD2E83ECCD1F621B3B9AAE4207B1FF`
- `multiarch_pypcode.raw`: `4AA9C29B4941F1BC48A15C91005C021EEC0D67E9A455BB2F1B0D2D25A466C7F8`
- `multiarch_pypcode.tsv`: `2BAFF19B2B616751EAC19D07DDD1FA1DD3F7279969E29780C26C523652275294`

`tests/pcode_oracle.rs` independently normalizes this crate's ordered P-code stream and compares every record with the pypcode-derived table.
