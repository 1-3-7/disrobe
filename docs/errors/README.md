# Error codes

Each `DR-<DOMAIN>-<NNNN>` code in the in-tree registry (`crates/disrobe-cli/src/cli/explain/codes/`) has a page here and resolves at runtime with `disrobe explain <code>`. Other passes raise further errors through their own types that are not part of this curated registry.

| Code | Title |
|---|---|
| [DR-BINFMT-0065](./DR-BINFMT-0065.md) | eszip module-graph archive parse failed |
| [DR-BINFMT-0066](./DR-BINFMT-0066.md) | .NET single-file bundle parse failed |
| [DR-BINFMT-0067](./DR-BINFMT-0067.md) | cython extension recovery failed |
| [DR-BINFMT-0068](./DR-BINFMT-0068.md) | minidump parse failed |
| [DR-CLI-0001](./DR-CLI-0001.md) | cannot read pyarmor wrapper file |
| [DR-CLI-0002](./DR-CLI-0002.md) | cannot create pyarmor output directory |
| [DR-CLI-0003](./DR-CLI-0003.md) | cannot write pyarmor manifest |
| [DR-CLI-0004](./DR-CLI-0004.md) | cannot write decrypted plaintext |
| [DR-CLI-0005](./DR-CLI-0005.md) | cannot write reconstructed pyc |
| [DR-CLI-0011](./DR-CLI-0011.md) | cannot read pyinstaller input |
| [DR-CLI-0012](./DR-CLI-0012.md) | cannot read pyinstaller archive for extract |
| [DR-CLI-0013](./DR-CLI-0013.md) | cannot create pyinstaller out dir |
| [DR-CLI-0014](./DR-CLI-0014.md) | cannot write pyinstaller manifest |
| [DR-CLI-0015](./DR-CLI-0015.md) | cannot write pyinstaller entry |
| [DR-CLI-0016](./DR-CLI-0016.md) | cannot read nuitka input |
| [DR-CLI-0017](./DR-CLI-0017.md) | input is not a nuitka --onefile build |
| [DR-CLI-0018](./DR-CLI-0018.md) | cannot create nuitka out dir |
| [DR-CLI-0019](./DR-CLI-0019.md) | cannot write nuitka entry |
| [DR-CLI-0020](./DR-CLI-0020.md) | cannot read nuitka symbols input |
| [DR-CLI-0021](./DR-CLI-0021.md) | cannot create nuitka symbols dir |
| [DR-CLI-0022](./DR-CLI-0022.md) | cannot write nuitka symbols json |
| [DR-CLI-0030](./DR-CLI-0030.md) | cannot read py-deob input |
| [DR-CLI-0031](./DR-CLI-0031.md) | cannot create py-deob out dir |
| [DR-CLI-0032](./DR-CLI-0032.md) | cannot write deobfuscated python |
| [DR-CLI-0033](./DR-CLI-0033.md) | cannot write py-deob manifest |
| [DR-CLI-0034](./DR-CLI-0034.md) | cannot read sourcedefender input |
| [DR-CLI-0035](./DR-CLI-0035.md) | cannot create sourcedefender out dir |
| [DR-CLI-0036](./DR-CLI-0036.md) | cannot write sourcedefender plaintext |
| [DR-CLI-0037](./DR-CLI-0037.md) | cannot read js-deob input |
| [DR-CLI-0038](./DR-CLI-0038.md) | cannot create js-deob out dir |
| [DR-CLI-0039](./DR-CLI-0039.md) | cannot write js detection json |
| [DR-CLI-0040](./DR-CLI-0040.md) | cannot read wasm input |
| [DR-CLI-0041](./DR-CLI-0041.md) | cannot create wasm out dir |
| [DR-CLI-0042](./DR-CLI-0042.md) | non utf-8 source / write failed |
| [DR-CLI-0043](./DR-CLI-0043.md) | cannot write deobfuscated js |
| [DR-CLI-0044](./DR-CLI-0044.md) | cannot write js recovery json |
| [DR-CLI-0050](./DR-CLI-0050.md) | cannot read pyc input |
| [DR-CLI-0051](./DR-CLI-0051.md) | input is not a valid pyc |
| [DR-CLI-0052](./DR-CLI-0052.md) | pyc body is not a code object |
| [DR-CLI-0053](./DR-CLI-0053.md) | cannot create disasm dir |
| [DR-CLI-0054](./DR-CLI-0054.md) | cannot write disasm text |
| [DR-CLI-0055](./DR-CLI-0055.md) | cannot write disasm json |
| [DR-CLI-0060](./DR-CLI-0060.md) | cannot create pyfreeze out dir |
| [DR-CLI-0061](./DR-CLI-0061.md) | cannot write pyfreeze manifest |
| [DR-CLI-0062](./DR-CLI-0062.md) | pyfreeze manifest serialize failed |
| [DR-CLI-0080](./DR-CLI-0080.md) | cannot read envelope |
| [DR-CLI-0081](./DR-CLI-0081.md) | malformed envelope sidecar |
| [DR-CLI-0082](./DR-CLI-0082.md) | only --rung raw is implemented |
| [DR-CLI-0083](./DR-CLI-0083.md) | cannot read source for envelope create |
| [DR-CLI-0084](./DR-CLI-0084.md) | rkyv encode failed |
| [DR-CLI-0085](./DR-CLI-0085.md) | postcard encode failed |
| [DR-CLI-0086](./DR-CLI-0086.md) | cannot write envelope |
| [DR-CLI-0087](./DR-CLI-0087.md) | envelope verification failed |
| [DR-CLI-0088](./DR-CLI-0088.md) | cannot read envelope for diff/migrate-check |
| [DR-CLI-0089](./DR-CLI-0089.md) | envelope migration is unsound |
| [DR-CLI-0090](./DR-CLI-0090.md) | auto sniff: cannot read input |
| [DR-CLI-0091](./DR-CLI-0091.md) | machine-format serialize failed |
| [DR-CLI-0092](./DR-CLI-0092.md) | stdout write failed |
| [DR-CLI-0093](./DR-CLI-0093.md) | sarif inner serialize failed |
| [DR-CLI-0094](./DR-CLI-0094.md) | sarif envelope serialize failed |
| [DR-CLI-0100](./DR-CLI-0100.md) | auto: chain exceeded max depth |
| [DR-CLI-0101](./DR-CLI-0101.md) | auto: cycle detected |
| [DR-CLI-0102](./DR-CLI-0102.md) | explain: unknown DR code |
| [DR-CLI-0110](./DR-CLI-0110.md) | init: target .disrobe already exists |
| [DR-CLI-0111](./DR-CLI-0111.md) | init: cannot create .disrobe dir |
| [DR-CLI-0112](./DR-CLI-0112.md) | init: cannot write scaffold file |
| [DR-CLI-0120](./DR-CLI-0120.md) | bug-report: cannot write report |
| [DR-CLI-0130](./DR-CLI-0130.md) | man: cannot create output dir |
| [DR-CLI-0131](./DR-CLI-0131.md) | man: render failed |
| [DR-CLI-0132](./DR-CLI-0132.md) | man: cannot write page |
| [DR-CLI-0140](./DR-CLI-0140.md) | completions install: cannot locate shell config |
| [DR-CLI-0141](./DR-CLI-0141.md) | completions install: cannot write rc file |
| [DR-CLI-0150](./DR-CLI-0150.md) | status: cannot read out/ tree |
| [DR-CLI-0320](./DR-CLI-0320.md) | guard denied write to ground-truth stage path |
| [DR-CLI-0321](./DR-CLI-0321.md) | guard: cannot resolve --root |
| [DR-JSDEOB-0001](./DR-JSDEOB-0001.md) | no JS obfuscator family matched |
| [DR-JSDEOB-0002](./DR-JSDEOB-0002.md) | js-deob I/O error |
| [DR-JSDEOB-0003](./DR-JSDEOB-0003.md) | js-deob oxc parse error |
| [DR-JSDEOB-0004](./DR-JSDEOB-0004.md) | js-deob invalid utf-8 |
| [DR-MARSHAL-0001](./DR-MARSHAL-0001.md) | marshal EOF |
| [DR-MARSHAL-0002](./DR-MARSHAL-0002.md) | marshal unknown tag |
| [DR-MARSHAL-0003](./DR-MARSHAL-0003.md) | marshal invalid utf-8 |
| [DR-MARSHAL-0004](./DR-MARSHAL-0004.md) | marshal ref-table OOB |
| [DR-MARSHAL-0005](./DR-MARSHAL-0005.md) | code object shape mismatch |
| [DR-MARSHAL-0006](./DR-MARSHAL-0006.md) | unsupported python version |
| [DR-MARSHAL-0007](./DR-MARSHAL-0007.md) | pyc header too short |
| [DR-MARSHAL-0008](./DR-MARSHAL-0008.md) | unknown pyc magic |
| [DR-MARSHAL-0009](./DR-MARSHAL-0009.md) | marshal depth limit exceeded |
| [DR-MARSHAL-0010](./DR-MARSHAL-0010.md) | long-int digit count too large |
| [DR-MARSHAL-0011](./DR-MARSHAL-0011.md) | container length too large |
| [DR-MARSHAL-0012](./DR-MARSHAL-0012.md) | marshal writer length overflow |
| [DR-NUITKA-0001](./DR-NUITKA-0001.md) | not a Nuitka build |
| [DR-NUITKA-0002](./DR-NUITKA-0002.md) | nuitka I/O error |
| [DR-NUITKA-0003](./DR-NUITKA-0003.md) | PE/ELF/Mach-O parse error |
| [DR-NUITKA-0004](./DR-NUITKA-0004.md) | nuitka onefile magic mismatch |
| [DR-NUITKA-0005](./DR-NUITKA-0005.md) | nuitka zstd decompression failed |
| [DR-NUITKA-0006](./DR-NUITKA-0006.md) | nuitka entry record truncated |
| [DR-NUITKA-0007](./DR-NUITKA-0007.md) | nuitka source text not present |
| [DR-NUITKA-0008](./DR-NUITKA-0008.md) | nuitka build-info missing |
| [DR-NUITKA-0009](./DR-NUITKA-0009.md) | nuitka build-info malformed |
| [DR-NUITKA-0010](./DR-NUITKA-0010.md) | nuitka reassembly needs >=1 entry |
| [DR-PYARM-0001](./DR-PYARM-0001.md) | input does not appear to be a PyArmor wrapper |
| [DR-PYARM-0002](./DR-PYARM-0002.md) | unknown PyArmor wrapper format |
| [DR-PYARM-0003](./DR-PYARM-0003.md) | payload bytes literal missing |
| [DR-PYARM-0004](./DR-PYARM-0004.md) | PyArmor runtime extension not found |
| [DR-PYARM-0005](./DR-PYARM-0005.md) | PyArmor v8/v9 header truncated |
| [DR-PYARM-0006](./DR-PYARM-0006.md) | PyArmor v8/v9 magic mismatch |
| [DR-PYARM-0007](./DR-PYARM-0007.md) | PyArmor v6/v7 magic mismatch |
| [DR-PYARM-0008](./DR-PYARM-0008.md) | runtime DLL parse failed |
| [DR-PYARM-0009](./DR-PYARM-0009.md) | AES key extraction failed |
| [DR-PYARM-0010](./DR-PYARM-0010.md) | AES decryption failed |
| [DR-PYARM-0011](./DR-PYARM-0011.md) | marshal decode error after decrypt |
| [DR-PYARM-0012](./DR-PYARM-0012.md) | pyarmor I/O error |
| [DR-PYARM-0013](./DR-PYARM-0013.md) | PyArmor v3/v4/v5 capsule walled on the RSA-wrapped key |
| [DR-PYARM-0014](./DR-PYARM-0014.md) | BCC mode is partial-only |
| [DR-PYARM-0015](./DR-PYARM-0015.md) | hex/escape decoding of wrapper bytes failed |
| [DR-PYARM-0016](./DR-PYARM-0016.md) | dynamic hook required but not allowed |
| [DR-PYARM-0017](./DR-PYARM-0017.md) | no usable Python found for dynamic hook |
| [DR-PYARM-0018](./DR-PYARM-0018.md) | dynamic hook timed out |
| [DR-PYARM-0019](./DR-PYARM-0019.md) | dynamic hook subprocess error |
| [DR-PYARM-0020](./DR-PYARM-0020.md) | dynamic hook produced zero captures |
| [DR-PYARM-0021](./DR-PYARM-0021.md) | dynamic hook found python too old |
| [DR-PYDEOB-0001](./DR-PYDEOB-0001.md) | no obfuscation family matched |
| [DR-PYDEOB-0002](./DR-PYDEOB-0002.md) | py-deob I/O error |
| [DR-PYDEOB-0003](./DR-PYDEOB-0003.md) | py-deob depth limit reached |
| [DR-PYDEOB-0004](./DR-PYDEOB-0004.md) | py-deob base64 decode failed |
| [DR-PYDEOB-0005](./DR-PYDEOB-0005.md) | py-deob zlib decompression failed |
| [DR-PYDEOB-0006](./DR-PYDEOB-0006.md) | py-deob lzma decompression failed |
| [DR-PYDEOB-0007](./DR-PYDEOB-0007.md) | py-deob bytes literal not found |
| [DR-PYDEOB-0008](./DR-PYDEOB-0008.md) | py-deob invalid utf-8 in output |
| [DR-PYDEOB-0009](./DR-PYDEOB-0009.md) | py-deob AST cleanup failed |
| [DR-PYFRZ-0001](./DR-PYFRZ-0001.md) | not a recognized python freezer container |
| [DR-PYFRZ-0002](./DR-PYFRZ-0002.md) | pyfreeze I/O error |
| [DR-PYFRZ-0003](./DR-PYFRZ-0003.md) | cx_Freeze missing sibling layout |
| [DR-PYFRZ-0004](./DR-PYFRZ-0004.md) | py2exe PYTHONSCRIPT resource missing |
| [DR-PYFRZ-0005](./DR-PYFRZ-0005.md) | py2exe scriptinfo tag mismatch |
| [DR-PYFRZ-0006](./DR-PYFRZ-0006.md) | py2exe scriptinfo truncated |
| [DR-PYFRZ-0007](./DR-PYFRZ-0007.md) | shiv missing _bootstrap/ |
| [DR-PYFRZ-0008](./DR-PYFRZ-0008.md) | shiv missing environment.json |
| [DR-PYFRZ-0009](./DR-PYFRZ-0009.md) | pex missing PEX-INFO |
| [DR-PYFRZ-0010](./DR-PYFRZ-0010.md) | trailing zip EOCD missing |
| [DR-PYFRZ-0011](./DR-PYFRZ-0011.md) | zip parse failed |
| [DR-PYFRZ-0012](./DR-PYFRZ-0012.md) | zip entry extraction failed |
| [DR-PYFRZ-0013](./DR-PYFRZ-0013.md) | pyfreeze PE parse failed |
| [DR-PYFRZ-0014](./DR-PYFRZ-0014.md) | shebang invalid |
| [DR-PYFRZ-0015](./DR-PYFRZ-0015.md) | unsafe archive entry path |
| [DR-PYFRZ-0016](./DR-PYFRZ-0016.md) | payload decompression failed |
| [DR-PYFRZ-0017](./DR-PYFRZ-0017.md) | json manifest parse failed |
| [DR-PYFRZ-0018](./DR-PYFRZ-0018.md) | pyfreeze quota exceeded |
| [DR-PYFRZ-0019](./DR-PYFRZ-0019.md) | PyOxidizer config block missing |
| [DR-PYFRZ-0020](./DR-PYFRZ-0020.md) | Briefcase missing sibling layout |
| [DR-PYINST-0001](./DR-PYINST-0001.md) | PyInstaller MEI cookie not found |
| [DR-PYINST-0002](./DR-PYINST-0002.md) | PyInstaller cookie truncated |
| [DR-PYINST-0003](./DR-PYINST-0003.md) | PyInstaller I/O error |
| [DR-PYINST-0004](./DR-PYINST-0004.md) | PyInstaller TOC walk failed |
| [DR-PYINST-0005](./DR-PYINST-0005.md) | zlib inflate failed for entry |
| [DR-PYINST-0006](./DR-PYINST-0006.md) | PyInstaller AES decrypt failed |
| [DR-PYINST-0007](./DR-PYINST-0007.md) | PyInstaller bad PYZ magic |
| [DR-PYINST-0008](./DR-PYINST-0008.md) | PyInstaller PYZ TOC marshal decode |
| [DR-PYINST-0009](./DR-PYINST-0009.md) | PyInstaller path traversal |
| [DR-PYINST-0010](./DR-PYINST-0010.md) | PyInstaller bad pyver |
| [DR-SDEF-0001](./DR-SDEF-0001.md) | not a sourcedefender .pye |
| [DR-SDEF-0002](./DR-SDEF-0002.md) | sourcedefender I/O error |
| [DR-SDEF-0003](./DR-SDEF-0003.md) | sourcedefender empty filename |
| [DR-SDEF-0004](./DR-SDEF-0004.md) | sourcedefender base85 decode failed |
| [DR-SDEF-0005](./DR-SDEF-0005.md) | sourcedefender bad IV length |
| [DR-SDEF-0006](./DR-SDEF-0006.md) | sourcedefender blake2 error |
| [DR-SDEF-0007](./DR-SDEF-0007.md) | sourcedefender not UTF-8 |
| [DR-SDEF-0008](./DR-SDEF-0008.md) | sourcedefender msgpack decode failed |
| [DR-SDEF-0009](./DR-SDEF-0009.md) | sourcedefender inlined filename missing |
| [DR-SDEF-0010](./DR-SDEF-0010.md) | sourcedefender inlined no decrypt |
| [DR-WASMDEOB-0001](./DR-WASMDEOB-0001.md) | not a valid WebAssembly module |
| [DR-WASMDEOB-0002](./DR-WASMDEOB-0002.md) | wasm-deob I/O error |
