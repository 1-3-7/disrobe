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

- `generate_pypcode_oracle.py`: `E4B77DCC5A21E2D6C8C7C2C648B560A84B4494A62F2F2C4C0E37AAEBF27163C2`
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

The RISC-V files were produced by the MSYS2 UCRT64 `riscv64-unknown-elf` GNU cross-toolchain. GCC reports version 16.1.0. GNU objcopy and objdump report Binutils 2.46.1. The base compiler targets use `-march=rv32im -mabi=ilp32` and `-march=rv64im -mabi=lp64`. The compressed and atomic targets use `-march=rv32imc` or `-march=rv32imac` with `-mabi=ilp32`, and `-march=rv64imac -mabi=lp64`.

Executable SHA-256 records:

- `riscv64-unknown-elf-gcc.exe`: `188B5E309C52532D4B86F3CC8735036040CA4336EBA3F1E4F7EABD01C124F67A`
- `riscv64-unknown-elf-objcopy.exe`: `F4E1B715E9B21D3E1F4A4591C27E1344A65B18955B626905342DBABFB685E7C7`
- `riscv64-unknown-elf-objdump.exe`: `E5283CEF88C639A55C73F852F89F3AADA54F875926FC4A98F0BC1F73DEF973CD`

The assembly matrices were compiled with their width-specific `-march` and `-mabi` flags. `riscv_oracle.c` was compiled at `-Os` for the compressed corpora. `riscv_atomic_oracle.c` was compiled at `-O2` for the atomic corpora. The C commands also used `-std=c11 -fno-asynchronous-unwind-tables -fno-stack-protector -fno-unwind-tables`. Each `.text` file was extracted with the matching `objcopy -O binary -j .text`; mnemonics came from the matching `objdump -d -z`.

SHA-256 records:

- `riscv32_forms.s`: `F03D3E0E7B78F40CF41121846244F323297E32AB07B86EFAE35BBE2B21DDED7B`
- `riscv64_forms.s`: `1AF775D0528DBA78BD9C4DB9DE1AD8FEF2F00434D23A5E3C026A9DDE4E5B6466`
- `riscv32c_forms.s`: `03D271BBE731438D31B1F7972C4C889BC2AF988A5385BFC9AA3D1F6C883FD0E8`
- `riscv64c_forms.s`: `EFD18F11267D6939C748CFE6A0600884D551FFFCEF940FB6B5E04B8419F79E4B`
- `riscv32a_forms.s`: `E7ADE4FA74B261F667E6F781268238D21CE55D886785CB3559A146E672FC20DD`
- `riscv64a_forms.s`: `0BBA03ECEE0936665D2C974E5AC66F4671726C95BD7731A0EDE9676D049AE293`
- `riscv_oracle.c`: `6C6439AECFB59C6533CA659998C5EE19A06E55A3E53940F28ADA1C81EFB649C8`
- `riscv_atomic_oracle.c`: `59BBC48D8F07CA56F5C8775AB4053AD9ECAF6B87DCD668BDB569F4470C22442D`
- `riscv32_forms.text`: `E760444C7FC25054384CB92B41DBDD8E305E29412D0362CD956F8B9CF739DB54`
- `riscv64_forms.text`: `F72DDE0F5B70115FB6E1AE10EAF30FAD3A3259BE17AE03D656B5E3648A74B6FC`
- `riscv32c_forms.text`: `04CB400C42F63B12E13C8DC665FEDAECCC9CCD06CB25930FE42856C3B67C3186`
- `riscv64c_forms.text`: `81DD9AE5659F3F5E1C9C34296CE73590D8B2A66835DDE1AAADEDBEBCBE58211F`
- `riscv32a_forms.text`: `163B3F5325A506E7D1F257654CE6A9B7501F446C20821D3571BB5C7056EF7475`
- `riscv64a_forms.text`: `81538CBC4CED405651D847B87E7EA9E5EA386A59B2769433B51B6551FB479CFD`
- `riscv32_oracle_o2.text`: `7BDFFECAF6CE953AD80386A6FCDF08100FF6D587108417474C6F21AEF33842CA`
- `riscv64_oracle_o2.text`: `53FFE9E8CD1881895720549AF231502A53FD670E7897512001A3EE80BE1884DD`
- `riscv32c_oracle_os.text`: `798BB6C7849623635805117A33FBD9E999C37FD5519754C4AB8716FF574C876E`
- `riscv64c_oracle_os.text`: `79518F68C2CF0744DE58CC7DD3800140264676BCB202DE5C81B6C91B9AAD0B58`
- `riscv32a_oracle_o2.text`: `CBE01C7BCAD77E31CF81FC4F79E8AD3C435FE13317636F0EB0CBA18389FE4311`
- `riscv64a_oracle_o2.text`: `EC0FC0F638B639FAE147F812A91B7EF0F3C2C3F792F8B7A93F0978EF9126D69F`

The RV32IM matrix contains 31 instructions and the RV64IM matrix contains 33. The RV32 compressed matrix contains 19 instructions and the RV64 compressed matrix contains 20. The RV32 atomic matrix contains 10 instructions and the RV64 atomic matrix contains 12. Every matrix reaches 100 percent constructor matching and exact objdump mnemonic agreement. Each compressed `-Os` C corpus contains 11 instructions. Each atomic `-O2` C corpus contains 18 instructions and preserves the compiler-emitted acquire and release suffixes. The compressed profiles use two-byte instruction alignment.

# PowerPC big-endian compiler corpora

The PPC corpus uses the Sysprogs PowerPC EABI GNU suite because the apt `powerpc-linux-gnu` package is not installable on Windows. GCC reports version 4.9.0. GNU objcopy and objdump report Binutils 2.24. The compiler emits `elf32-powerpc` big-endian objects. The downloaded installer SHA-256 was `E63904AEFCBFAB25022BC042445B4816AE996DE73A59D5D62FCD086D8E2079D6`.

Executable SHA-256 records:

- `powerpc-eabi-gcc.exe`: `F69422BAF96D5621DB1559C5080DA371735740D33B218105DBC7C3B79A8BCA67`
- `powerpc-eabi-objcopy.exe`: `BA070B69A361AF0EC38F7F0243CBD583381350B16B4F5B95A174B09191611734`
- `powerpc-eabi-objdump.exe`: `C46D73602190D543FC02ABCD3BE6039EB03D3865F6A55541BC6839E2281FB39F`

The assembly matrix was compiled with `-mcpu=powerpc -m32 -mbig`. The C fixture was compiled with `-O2 -ffreestanding -fno-builtin -mcpu=powerpc -m32 -mbig`. Each `.text` file was extracted with the matching `objcopy -O binary -j .text`; mnemonics came from the matching `objdump -d -z`.

No `powerpc64-linux-gnu-gcc` or other PPC64 ABI C compiler is installed in this Windows environment. The installed PowerPC EABI assembler accepts the 64-bit ISA through `-mppc64`, so `powerpc64_forms.s` was assembled through the GCC driver with `-mcpu=powerpc64 -m32 -mbig -Wa,-mppc64`. It produces an `elf32-powerpc` container whose `.text` holds PPC64 instructions. The matching GNU objdump verifies every committed encoding and mnemonic. No PPC64 C-compiler coverage is claimed.

PPC64 word-result widths are also checked against Book I of the [Power ISA Version 3.1C](https://openpowerfoundation.org/specifications/isa/) and the matching pypcode language. In particular, `mullw` uses the low 32 bits of each source as signed operands and writes their full 64-bit product in 64-bit mode.

SHA-256 records:

- `powerpc32_forms.s`: `6C17372578D1245B124F478A8741E8AEE6774C377AF6C27C9CB981D1F016C22F`
- `powerpc_oracle.c`: `F2C30FC7CDBA777E6B925C099628ACE0E2F5ABE0B9A67EFB0249EDF12A6338A4`
- `powerpc64_forms.s`: `414385D3DD80BE35E7EACC892815594A8A04712E33167AC8A59818C991F76CC0`
- `powerpc32_forms.text`: `9A8FC4FBF455B27D5F008A2B21E47149EE1D0E7B19659C157E9C07111AD088D6`
- `powerpc32_oracle_o2.text`: `6120A3F057A84ECB60673848284E129C77350C1B886DB3F8729634954D673AC3`
- `powerpc64_forms.text`: `96C8B1DA12C8AB141C5950D82AFC0D608F3A9751E61BB18F01B4C77D5A7FEB10`

The PPC32 assembly matrix contains 32 instructions and its `-O2` C corpus contains 11. The PPC64 hand-assembled matrix contains 30 instructions. All three reach 100 percent constructor matching and exact objdump mnemonic agreement. `divw` is the sole `CALLOTHER` record in each PPC32 corpus. `divw` and `divd` are the two `CALLOTHER` records in the PPC64 matrix.

# Multi-architecture P-code corpus

`multiarch_pypcode.raw` and `multiarch_pypcode.tsv` were produced with pypcode 4.0.0 from the committed form matrices. The languages are `ARM:LE:32:v7`, `ARM:LE:32:v8T`, `MIPS:LE:32:default`, `MIPS:BE:32:default`, `RISCV:LE:32:default`, `RISCV:LE:64:default`, `PowerPC:BE:32:default`, and `PowerPC:BE:64:default`.

The 209 records contain 31 ARM/MIPS cases, 117 RISC-V cases, and 61 PowerPC cases. The added records cover compressed RISC-V arithmetic, memory, stack, direct control, and indirect control effects, all 22 atomic matrix records, and 30 PPC64 arithmetic, memory, rotate, compare, multiply, divide, and BO/BI branch records. The atomic comparison checks the encoded register fields, operation code, access width, acquire and release bits, result, address, operand, and pypcode reference access shape against `riscv_atomic_memory_v1`. It does not claim that pypcode's load and store expansion preserves atomicity. Its compressed `C.JR` and `C.JALR` translations omit the least-significant-bit clear emitted by its base `JALR` translation and required by the compressed instructions' base expansion. Its PowerPC `bclr`, `bctr`, and `blr` translations likewise omit the architectural low-two-bit target clear. The raw corpus preserves those outputs. The Rust comparison applies only the missing target masks before comparing the affected records. The table retains final architectural register values, flags, RAM effects, and control-flow effects while removing instruction markers, internal temporaries, decoder-context pcodeops, and separately asserted `CALLOTHER` markers. Independent facts are canonicalized within each control-flow segment while segment order remains intact across transfers.

The generator is reproducible after the pinned pypcode installation:

```text
python tests/fixtures/generate_multiarch_pypcode_oracle.py
```

The generator disassembles every selected byte slice with the matching pypcode language and rejects instruction-count or length drift before translation. The Rust comparison requires one raw translation header for every table row and checks each row's decoded mnemonic.

- `generate_multiarch_pypcode_oracle.py`: `A68D961CECF94A292AA0FE4AFFAD5DDD4642447B9D51911E6A345ABEBF858163`
- `multiarch_pypcode.raw`: `CDAD6FC056612BCA823034A622BC530E98271D1821AC316351A7A93E0EAD7DC3`
- `multiarch_pypcode.tsv`: `88EC792F9AB5850B805E7E95F80DA547FFD88E8C6D1B6BABD5DE6F3D3D4FACD4`

`tests/pcode_oracle.rs` independently normalizes this crate's ordered P-code stream and compares every record with the pypcode-derived table.
