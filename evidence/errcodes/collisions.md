# Error-code census

`cargo run -p xtask -- errcodes` writes this file, and `cargo run -p xtask -- errcodes --check` fails when it differs from a fresh scan. The scan reads every string literal, including format strings and attribute arguments, in the Rust sources under `crates/*/src/`. It skips comments, doc comments, `#[cfg(test)]` items, test functions, test-only module files and the explain registry in `crates/disrobe-cli/src/cli/explain/codes/`. A code at the start of a literal carries the text after its colon; a code elsewhere in a literal carries the whole literal; a literal holding only the code carries no message and is not compared. Format placeholders compare as `{}` and whitespace runs as one space.

| Measure | Count |
| --- | ---: |
| Scanned source files | 1969 |
| Emission sites | 2355 |
| Sites carrying a message | 2272 |
| Distinct emitted codes | 1803 |
| Registered codes | 177 |
| Codes with two or more distinct messages | 255 |
| Emitted codes missing from the registry | 1626 |
| Registered codes no source emits | 0 |

## Codes with two or more distinct messages (255)

### `DR-BINFMT-0009`

- `` "extraction quota exceeded on entry `" ``: `crates/disrobe-pass-pyfreeze/src/cxfreeze/library_zip.rs:68`
- `` "extraction quota exceeded on entry `{}`: {}" ``: `crates/disrobe-binfmt/src/error.rs:60`

### `DR-CLI-0001`

- `"DR error code, e.g. DR-CLI-0001 or just CLI-1"`: `crates/disrobe-cli/src/main.rs:1042`
- `"cannot read wrapper at {}: {}"`: `crates/disrobe-cli/src/cli/pyarmor.rs:163`

### `DR-CLI-0016`

- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:111`
- `"serialize manifest: {}"`: `crates/disrobe-cli/src/cli/pyinstaller.rs:117`

### `DR-CLI-0017`

- `"cannot create dir: {}"`: `crates/disrobe-cli/src/cli/pyinstaller.rs:140`
- `` "input is not a Nuitka --onefile build (no KA[XY] payload detected); use `nuitka symbols` for --standalone builds" ``: `crates/disrobe-cli/src/cli/nuitka.rs:116`

### `DR-CLI-0020`

- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:186`
- `"invalid --mode value: {}"`: `crates/disrobe-cli/src/cli/pyarmor.rs:201`

### `DR-CLI-0021`

- `"cannot create dir: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:198`
- `"invalid --target value: {}"`: `crates/disrobe-cli/src/cli/pyarmor.rs:205`

### `DR-CLI-0022`

- `"cannot create cache dir {}: {}"`: `crates/disrobe-cli/src/cli/pyarmor.rs:212`
- `"cannot write symbols: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:203`

### `DR-CLI-0023`

- `"cannot write emit stub {}: {}"`: `crates/disrobe-cli/src/cli/pyarmor.rs:443`
- `"refusing unsafe payload path '{}' (traversal)"`: `crates/disrobe-cli/src/cli/nuitka.rs:139`

### `DR-CLI-0024`

- `"cannot write emit report: {}"`: `crates/disrobe-cli/src/cli/pyarmor.rs:463`
- `"serialize symbols: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:201`

### `DR-CLI-0026`

- `"BCC artifact path has no parent: {}"`: `crates/disrobe-cli/src/cli/pyarmor.rs:366`
- `"cannot create dir: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:239`, `crates/disrobe-cli/src/cli/nuitka.rs:994`

### `DR-CLI-0027`

- `"cannot create BCC publication directory {}: {}"`: `crates/disrobe-cli/src/cli/pyarmor.rs:372`
- `"cannot serialize decompilation: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:241`
- `"cannot serialize pool: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:997`

### `DR-CLI-0028`

- `"cannot write BCC publication {}: {}"`: `crates/disrobe-cli/src/cli/pyarmor.rs:378`
- `"cannot write decompilation: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:243`
- `"cannot write pool: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:999`

### `DR-CLI-0030`

- `"--python requested but no surface or skeleton was recovered"`: `crates/disrobe-cli/src/cli/nuitka.rs:401`
- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/py/deob.rs:58`
- `"out dir {} already exists; pass --force to overwrite"`: `crates/disrobe-cli/src/cli/pyarmor.rs:187`

### `DR-CLI-0031`

- `"cannot create dir: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:408`, `crates/disrobe-cli/src/cli/py/deob.rs:94`
- `"out dir {} already exists; pass --force to overwrite"`: `crates/disrobe-cli/src/cli/pyinstaller.rs:84`

### `DR-CLI-0032`

- `"cannot write output: {}"`: `crates/disrobe-cli/src/cli/py/deob.rs:104`
- `"cannot write python skeleton: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:411`
- `"out dir {} already exists; pass --force to overwrite"`: `crates/disrobe-cli/src/cli/js.rs:1695`

### `DR-CLI-0033`

- `"cannot write manifest: {}"`: `crates/disrobe-cli/src/cli/py/deob.rs:116`
- `"cannot write {}: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:923`, `crates/disrobe-cli/src/cli/nuitka.rs:932`

### `DR-CLI-0034`

- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/py/extract.rs:68`
- `"cannot write surface skeleton: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:956`
- `"serialize manifest: {}"`: `crates/disrobe-cli/src/cli/py/deob.rs:114`

### `DR-CLI-0035`

- `` "--pyver major `{}` is not a number" ``: `crates/disrobe-cli/src/cli/py/deob.rs:252`
- `` "--pyver minor `{}` is not a number" ``: `crates/disrobe-cli/src/cli/py/deob.rs:256`
- `` "--pyver must be MAJOR.MINOR (e.g. 3.12), got `{}`" ``: `crates/disrobe-cli/src/cli/py/deob.rs:247`
- `"cannot create dir: {}"`: `crates/disrobe-cli/src/cli/py/extract.rs:112`
- `"cannot create skeleton dir: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:891`

### `DR-CLI-0036`

- `"cannot write output: {}"`: `crates/disrobe-cli/src/cli/py/extract.rs:115`
- `"cannot write {}: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:895`
- `` "py deob needs an input file (or `--list` to show supported obfuscators)" ``: `crates/disrobe-cli/src/cli/py/deob.rs:49`

### `DR-CLI-0037`

- `"cannot re-read input for carving: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:742`
- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/js.rs:1091`
- `"cannot write source: {}"`: `crates/disrobe-cli/src/cli/py/extract.rs:126`

### `DR-CLI-0038`

- `"--key is not valid hex: {}"`: `crates/disrobe-cli/src/cli/py/extract.rs:159`
- `"cannot create dir: {}"`: `crates/disrobe-cli/src/cli/js.rs:1121`
- `"refusing unsafe bundled path '{}' (traversal)"`: `crates/disrobe-cli/src/cli/nuitka.rs:784`

### `DR-CLI-0039`

- `"--key must decode to exactly 32 bytes (aes-256), got {}"`: `crates/disrobe-cli/src/cli/py/extract.rs:162`
- `"cannot create carve dir: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:790`
- `"cannot write detection: {}"`: `crates/disrobe-cli/src/cli/js.rs:1129`

### `DR-CLI-0040`

- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/wasm.rs:445`
- `"cannot write {}: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:793`
- `"modern .pye produced neither a recovered body nor a wall"`: `crates/disrobe-cli/src/cli/py/extract.rs:226`

### `DR-CLI-0041`

- `"cannot create dir: {}"`: `crates/disrobe-cli/src/cli/wasm.rs:171`, `crates/disrobe-cli/src/cli/wasm.rs:194`, `crates/disrobe-cli/src/cli/wasm.rs:243`, `crates/disrobe-cli/src/cli/wasm.rs:459`
- `"cannot create frozen dir: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:682`
- `"modern v16 body is an aes-256-gcm wall ({}); supply the 32-byte key via --key to decrypt statically"`: `crates/disrobe-cli/src/cli/py/extract.rs:252`
- `"modern v16 body is an aes-256-gcm wall ({}); the supplied --key did not authenticate it"`: `crates/disrobe-cli/src/cli/py/extract.rs:247`

### `DR-CLI-0042`

- `"cannot create dir: {}"`: `crates/disrobe-cli/src/cli/py/extract.rs:269`
- `"cannot write boundary links: {}"`: `crates/disrobe-cli/src/cli/wasm.rs:188`
- `"cannot write deobfuscated wat: {}"`: `crates/disrobe-cli/src/cli/wasm.rs:174`
- `"cannot write lifted output: {}"`: `crates/disrobe-cli/src/cli/wasm.rs:246`
- `"cannot write output: {}"`: `crates/disrobe-cli/src/cli/wasm.rs:464`
- `"cannot write {}: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:687`
- `"input is not UTF-8: {}"`: `crates/disrobe-cli/src/cli/js.rs:1094`
- `"serialize capabilities: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:836`

### `DR-CLI-0043`

- `"cannot create native dir: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:655`
- `"cannot write deobfuscated source: {}"`: `crates/disrobe-cli/src/cli/js.rs:1172`
- `"cannot write recovered wasm: {}"`: `crates/disrobe-cli/src/cli/wasm.rs:197`
- `"cannot write {}: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:838`, `crates/disrobe-cli/src/cli/py/extract.rs:272`
- `"serialize: {}"`: `crates/disrobe-cli/src/cli/wasm.rs:462`

### `DR-CLI-0044`

- `"cannot write recovery: {}"`: `crates/disrobe-cli/src/cli/js.rs:1191`
- `"embedded {} byte range {}..{} is out of bounds (file is {} bytes)"`: `crates/disrobe-cli/src/cli/wasm.rs:410`
- `"serialize recon: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:847`

### `DR-CLI-0045`

- `"cannot create dir: {}"`: `crates/disrobe-cli/src/cli/js.rs:1424`, `crates/disrobe-cli/src/cli/js.rs:1518`
- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/js.rs:1673`
- `"cannot write {}: {}"`: `crates/disrobe-cli/src/cli/wasm.rs:421`
- `"recovery-manifest serialize: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:546`

### `DR-CLI-0046`

- `"cannot write deobfuscated source: {}"`: `crates/disrobe-cli/src/cli/js.rs:1427`, `crates/disrobe-cli/src/cli/js.rs:1521`
- `"cannot write recovery-manifest: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:548`
- `"input is not UTF-8: {}"`: `crates/disrobe-cli/src/cli/js.rs:1675`
- `` "wasm deob needs an input file (or `--list` to show supported obfuscators)" ``: `crates/disrobe-cli/src/cli/wasm.rs:149`

### `DR-CLI-0047`

- `"cannot create native dir: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:564`
- `"cannot create out dir: {}"`: `crates/disrobe-cli/src/cli/js.rs:1701`
- `"gc-hir serialize: {}"`: `crates/disrobe-cli/src/cli/wasm.rs:50`
- `` "pyarmor unpack needs an input file (or `--list` to show supported versions)" ``: `crates/disrobe-cli/src/cli/pyarmor.rs:158`
- `"serialize pipeline: {}"`: `crates/disrobe-cli/src/cli/js.rs:1441`, `crates/disrobe-cli/src/cli/js.rs:1535`

### `DR-CLI-0048`

- `"auto-unbundle failed: {}"`: `crates/disrobe-cli/src/cli/js.rs:1705`
- `"cannot create out dir: {}"`: `crates/disrobe-cli/src/cli/wasm.rs:57`
- `"cannot write pipeline: {}"`: `crates/disrobe-cli/src/cli/js.rs:1443`, `crates/disrobe-cli/src/cli/js.rs:1537`
- `"serialize name map: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:566`

### `DR-CLI-0049`

- `"cannot write gc rust source: {}"`: `crates/disrobe-cli/src/cli/wasm.rs:62`
- `"cannot write name-map.json: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:568`
- `"webpack4 unbundle failed: {}"`: `crates/disrobe-cli/src/cli/js.rs:1708`

### `DR-CLI-0050`

- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/py/disasm.rs:17`
- `"cannot write gc ts source: {}"`: `crates/disrobe-cli/src/cli/wasm.rs:65`
- `"cannot write name-map.txt: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:602`
- `"webpack5 unbundle failed: {}"`: `crates/disrobe-cli/src/cli/js.rs:1712`

### `DR-CLI-0051`

- `"cannot write {}: {}"`: `crates/disrobe-cli/src/cli/nuitka.rs:849`
- `"not a valid .pyc: {}"`: `crates/disrobe-cli/src/cli/py/decompile.rs:67`, `crates/disrobe-cli/src/cli/py/disasm.rs:19`
- `"vite unbundle failed: {}"`: `crates/disrobe-cli/src/cli/js.rs:1716`

### `DR-CLI-0052`

- `".pyc body is not a code object"`: `crates/disrobe-cli/src/cli/py/decompile.rs:72`, `crates/disrobe-cli/src/cli/py/disasm.rs:24`
- `"rollup unbundle failed: {}"`: `crates/disrobe-cli/src/cli/js.rs:1720`

### `DR-CLI-0053`

- `"cannot create dir: {}"`: `crates/disrobe-cli/src/cli/py/disasm.rs:41`
- `"esbuild unbundle failed: {}"`: `crates/disrobe-cli/src/cli/js.rs:1724`

### `DR-CLI-0054`

- `"cannot write disasm: {}"`: `crates/disrobe-cli/src/cli/py/disasm.rs:44`
- `"turbopack unbundle failed: {}"`: `crates/disrobe-cli/src/cli/js.rs:1730`

### `DR-CLI-0055`

- `"bun unbundle failed: {}"`: `crates/disrobe-cli/src/cli/js.rs:1733`
- `"cannot write disasm json: {}"`: `crates/disrobe-cli/src/cli/py/disasm.rs:49`

### `DR-CLI-0056`

- `"cannot write modules: {}"`: `crates/disrobe-cli/src/cli/js.rs:1747`
- `"serialize disasm json: {}"`: `crates/disrobe-cli/src/cli/py/disasm.rs:47`

### `DR-CLI-0060`

- `"cannot create out dir: {}"`: `crates/disrobe-cli/src/cli/pyfreeze.rs:58`
- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/js.rs:524`, `crates/disrobe-cli/src/cli/py/decompile.rs:37`

### `DR-CLI-0061`

- `"cannot create json dir: {}"`: `crates/disrobe-cli/src/cli/js.rs:687`
- `"cannot create out dir: {}"`: `crates/disrobe-cli/src/cli/py/decompile.rs:62`, `crates/disrobe-cli/src/cli/py/decompile.rs:180`
- `"cannot write manifest: {}"`: `crates/disrobe-cli/src/cli/pyfreeze.rs:65`

### `DR-CLI-0062`

- `"cannot write decompiled source: {}"`: `crates/disrobe-cli/src/cli/py/decompile.rs:82`, `crates/disrobe-cli/src/cli/py/decompile.rs:184`
- `"manifest serialize: {}"`: `crates/disrobe-cli/src/cli/pyfreeze.rs:63`
- `"serialize v8 report: {}"`: `crates/disrobe-cli/src/cli/js.rs:692`

### `DR-CLI-0063`

- `"cannot write v8 report json: {}"`: `crates/disrobe-cli/src/cli/js.rs:695`
- `"manifest serialize: {}"`: `crates/disrobe-cli/src/cli/py/decompile.rs:97`, `crates/disrobe-cli/src/cli/py/decompile.rs:196`

### `DR-CLI-0064`

- `"cannot create carve dir {}: {}"`: `crates/disrobe-cli/src/cli/js.rs:710`
- `"cannot write manifest: {}"`: `crates/disrobe-cli/src/cli/py/decompile.rs:99`, `crates/disrobe-cli/src/cli/py/decompile.rs:198`

### `DR-CLI-0065`

- `"native decompile engine failed: {}"`: `crates/disrobe-cli/src/cli/py/decompile.rs:252`
- `"re-parse asar for carve: {}"`: `crates/disrobe-cli/src/cli/js.rs:722`

### `DR-CLI-0066`

- `"carve asar entry: {}"`: `crates/disrobe-cli/src/cli/js.rs:726`
- `` "py decompile needs an input .pyc (or `--list` to show supported obfuscators)" ``: `crates/disrobe-cli/src/cli/py/decompile.rs:32`

### `DR-CLI-0067`

- `"could not decompile: input is neither a known obfuscator nor a decodable .pyc"`: `crates/disrobe-cli/src/cli/py/decompile.rs:55`
- `"nexe footer vanished on re-parse"`: `crates/disrobe-cli/src/cli/js.rs:739`

### `DR-CLI-0068`

- `"carve nexe payload: {}"`: `crates/disrobe-cli/src/cli/js.rs:742`
- `"deobfuscation produced no source"`: `crates/disrobe-cli/src/cli/py/decompile.rs:177`

### `DR-CLI-0070`

- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/py/extract.rs:6`
- `"carve sea main code: {}"`: `crates/disrobe-cli/src/cli/js.rs:763`

### `DR-CLI-0071`

- `"cannot create out dir: {}"`: `crates/disrobe-cli/src/cli/py/extract.rs:14`
- `"cannot write jsc disassembly: {}"`: `crates/disrobe-cli/src/cli/js.rs:799`

### `DR-CLI-0072`

- `"input {} is not a recognized archive (.whl/.zip/.tar/.tar.gz/.7z/.asar/...)"`: `crates/disrobe-cli/src/cli/py/extract.rs:18`
- `"refusing to carve member with traversal/absolute path: {}"`: `crates/disrobe-cli/src/cli/js.rs:822`

### `DR-CLI-0073`

- `"cannot create dir {}: {}"`: `crates/disrobe-cli/src/cli/js.rs:831`
- `"extract failed: {}"`: `crates/disrobe-cli/src/cli/py/extract.rs:24`

### `DR-CLI-0074`

- `"cannot write {}: {}"`: `crates/disrobe-cli/src/cli/js.rs:835`
- `"manifest serialize: {}"`: `crates/disrobe-cli/src/cli/py/extract.rs:42`

### `DR-CLI-0075`

- `"cannot write manifest: {}"`: `crates/disrobe-cli/src/cli/py/extract.rs:44`
- `"nw.js zip open: {}"`: `crates/disrobe-cli/src/cli/js.rs:852`

### `DR-CLI-0080`

- `` "Run `disrobe envelope verify $1` & report the result. Surface DR-CODES (e.g. DR-CLI-0080, DR-CLI-0087) verbatim." ``: `crates/disrobe-cli/src/cli/init.rs:160`
- `"cannot read envelope: {}"`: `crates/disrobe-cli/src/cli/envelope.rs:474`
- `"write {}: {}"`: `crates/disrobe-cli/src/cli/js.rs:909`

### `DR-CLI-0081`

- `"malformed sidecar: {}"`: `crates/disrobe-cli/src/cli/envelope.rs:476`
- `"nw.js zip entry count {} exceeds cap {}"`: `crates/disrobe-cli/src/cli/js.rs:856`

### `DR-CLI-0082`

- `"nw.js zip output exceeds total cap {}"`: `crates/disrobe-cli/src/cli/js.rs:881`
- `"only --rung raw is implemented in v0.1; got {}"`: `crates/disrobe-cli/src/cli/envelope.rs:516`

### `DR-CLI-0083`

- `"cannot read source: {}"`: `crates/disrobe-cli/src/cli/envelope.rs:520`
- `"nw.js zip entry {} declared size {} exceeds cap {}"`: `crates/disrobe-cli/src/cli/js.rs:887`

### `DR-CLI-0084`

- `"nw.js zip copy cap overflow for {}"`: `crates/disrobe-cli/src/cli/js.rs:902`
- `"rkyv encode failed: {}"`: `crates/disrobe-cli/src/cli/envelope.rs:560`

### `DR-CLI-0085`

- `"nw.js zip entry {} exceeds cap {}"`: `crates/disrobe-cli/src/cli/js.rs:914`
- `"postcard encode failed: {}"`: `crates/disrobe-cli/src/cli/envelope.rs:569`

### `DR-CLI-0086`

- `"cannot encode envelope: {}"`: `crates/disrobe-cli/src/cli/envelope.rs:573`
- `"cannot write envelope: {}"`: `crates/disrobe-cli/src/cli/envelope.rs:593`, `crates/disrobe-cli/src/cli/envelope.rs:595`, `crates/disrobe-cli/src/cli/envelope.rs:597`
- `"nw.js zip output byte counter overflow"`: `crates/disrobe-cli/src/cli/js.rs:919`

### `DR-CLI-0087`

- `` "Run `disrobe envelope verify $1` & report the result. Surface DR-CODES (e.g. DR-CLI-0080, DR-CLI-0087) verbatim." ``: `crates/disrobe-cli/src/cli/init.rs:160`
- `"envelope failed verification: {}"`: `crates/disrobe-cli/src/cli/envelope.rs:461`

### `DR-CLI-0088`

- `"cannot read envelope {}: {}"`: `crates/disrobe-cli/src/cli/envelope.rs:148`, `crates/disrobe-cli/src/cli/envelope.rs:150`
- `"malformed sidecar in {}: {}"`: `crates/disrobe-cli/src/cli/envelope.rs:152`, `crates/disrobe-cli/src/cli/envelope.rs:154`

### `DR-CLI-0092`

- `"cannot read referenced map {}: {}"`: `crates/disrobe-cli/src/cli/js.rs:240`
- `"stdout write: {}"`: `crates/disrobe-cli/src/cli/output.rs:55`, `crates/disrobe-cli/src/cli/output.rs:61`

### `DR-CLI-0093`

- `` "input references external map `{}` which was not found next to {}; fetch it and pass the .map directly" ``: `crates/disrobe-cli/src/cli/js.rs:246`
- `"sarif inner deserialize: {}"`: `crates/disrobe-cli/src/cli/output.rs:99`
- `"sarif inner serialize: {}"`: `crates/disrobe-cli/src/cli/output.rs:92`
- `"sarif spool: {}"`: `crates/disrobe-cli/src/cli/output.rs:89`, `crates/disrobe-cli/src/cli/output.rs:96`, `crates/disrobe-cli/src/cli/output.rs:104`

### `DR-CLI-0102`

- `"input is not UTF-8: {}"`: `crates/disrobe-cli/src/cli/js.rs:335`
- `"{}"`: `crates/disrobe-cli/src/cli/explain/mod.rs:48`

### `DR-CLI-0111`

- `"cannot create .disrobe/notes: {}"`: `crates/disrobe-cli/src/cli/init.rs:484`
- `"cannot create {}: {}"`: `crates/disrobe-cli/src/cli/init.rs:490`
- `"cannot read cwd: {}"`: `crates/disrobe-cli/src/cli/init.rs:468`

### `DR-CLI-0115`

- `"cannot alias {} -> {}: {}"`: `crates/disrobe-cli/src/cli/init.rs:371`
- `"cannot replace {}: {}"`: `crates/disrobe-cli/src/cli/init.rs:359`

### `DR-CLI-0141`

- `"cannot append to {}: {}"`: `crates/disrobe-cli/src/cli/completions.rs:51`
- `"cannot open {}: {}"`: `crates/disrobe-cli/src/cli/completions.rs:48`

### `DR-CLI-0150`

- `"cannot read cwd: {}"`: `crates/disrobe-cli/src/cli/status.rs:29`
- `"cannot read out/: {}"`: `crates/disrobe-cli/src/cli/status.rs:63`

### `DR-CLI-0161`

- `"emit payload serialize: {}"`: `crates/disrobe-cli/src/cli/emit.rs:193`
- `"emit stub serialize: {}"`: `crates/disrobe-cli/src/cli/emit.rs:176`

### `DR-CLI-0162`

- `"cannot write emit payload: {}"`: `crates/disrobe-cli/src/cli/emit.rs:195`
- `"cannot write emit stub: {}"`: `crates/disrobe-cli/src/cli/emit.rs:178`

### `DR-CLI-0231`

- `"cannot remove symlink {}: {}"`: `crates/disrobe-cli/src/cli/path_ops.rs:89`
- `"cannot resolve stage dir {}: {}"`: `crates/disrobe-cli/src/cli/path_ops.rs:24`

### `DR-CLI-0309`

- `"cannot create extracted directory {}: {}"`: `crates/disrobe-cli/src/cli/chain_materialization.rs:257`
- `"cannot inspect extracted path {}: {}"`: `crates/disrobe-cli/src/cli/chain_materialization.rs:227`
- `"cannot resolve extracted directory: {}"`: `crates/disrobe-cli/src/cli/chain_materialization.rs:266`
- `"cannot resolve extraction root: {}"`: `crates/disrobe-cli/src/cli/chain_materialization.rs:263`
- `"extracted directory escaped its root: {}"`: `crates/disrobe-cli/src/cli/chain_materialization.rs:235`
- `"extracted directory is a file or link: {}"`: `crates/disrobe-cli/src/cli/chain_materialization.rs:251`
- `"extracted directory resolves outside its root"`: `crates/disrobe-cli/src/cli/chain_materialization.rs:270`
- `"extracted file has no parent"`: `crates/disrobe-cli/src/cli/chain_materialization.rs:67`
- `"unsafe extracted directory"`: `crates/disrobe-cli/src/cli/chain_materialization.rs:241`

### `DR-CLI-0310`

- `"cannot create extracted file {}: {}"`: `crates/disrobe-cli/src/cli/chain_materialization.rs:75`
- `"cannot read chain.json {}: {}"`: `crates/disrobe-cli/src/cli/chain_compare.rs:37`
- `"cannot set extracted mode for {}: {}"`: `crates/disrobe-cli/src/cli/chain_materialization.rs:285`
- `"cannot write extracted file {}: {}"`: `crates/disrobe-cli/src/cli/chain_materialization.rs:82`
- `"duplicate extracted group path: {}"`: `crates/disrobe-cli/src/cli/chain_materialization.rs:198`
- `"extracted directory carries file bytes: {}"`: `crates/disrobe-cli/src/cli/chain_materialization.rs:55`
- `"extracted group file is an ancestor of {}"`: `crates/disrobe-cli/src/cli/chain_materialization.rs:210`
- `"no free extraction namespace for node {} after {} attempts"`: `crates/disrobe-cli/src/cli/chain_materialization.rs:149`
- `"unsafe extracted path: {}"`: `crates/disrobe-cli/src/cli/chain_materialization.rs:186`

### `DR-CLI-0319`

- `"cannot read {}: {}"`: `crates/disrobe-cli/src/cli/context.rs:72`
- `"{} is not a valid disrobe.run/v1 record: {}"`: `crates/disrobe-cli/src/cli/context.rs:81`

### `DR-CLI-0320`

- `"download body for {} declares {} bytes, exceeding cap {}"`: `crates/disrobe-cli/src/cli/install_deps.rs:294`
- `"download body for {} exceeded cap {}"`: `crates/disrobe-cli/src/cli/install_deps.rs:310`
- `"guard denied write to ground-truth stage path {}"`: `crates/disrobe-cli/src/cli/guard.rs:209`
- `` "no recovery.json at {} - run `disrobe chain <input>` or `disrobe auto <input>` first, then pass --out <its out dir>" ``: `crates/disrobe-cli/src/cli/context.rs:53`

### `DR-CLI-0321`

- `"ghidra archive declared total {} bytes, exceeding cap {}"`: `crates/disrobe-cli/src/cli/install_deps.rs:368`
- `"ghidra archive entry {} declares {} bytes, exceeding per-entry cap {}"`: `crates/disrobe-cli/src/cli/install_deps.rs:358`
- `"ghidra archive entry {} expanded past cap"`: `crates/disrobe-cli/src/cli/install_deps.rs:405`
- `"ghidra archive has {} entries, exceeding cap {}"`: `crates/disrobe-cli/src/cli/install_deps.rs:343`
- `"ghidra archive size total overflow"`: `crates/disrobe-cli/src/cli/install_deps.rs:365`
- `"guard cannot resolve --root {}"`: `crates/disrobe-cli/src/cli/guard.rs:183`
- `"{} is not a valid disrobe.recovery/v2 report: {}"`: `crates/disrobe-cli/src/cli/context.rs:59`

### `DR-CLI-0322`

- `"cannot read cwd: {}"`: `crates/disrobe-cli/src/cli/annot.rs:35`
- `` "no recovery.json under {}, so there is no chain verdict to grade against `--fail-on {}`; run `disrobe chain <input>` or `disrobe auto <input>` first" ``: `crates/disrobe-cli/src/cli/context.rs:127`

### `DR-CLI-0323`

- `` "chain verdict {} grades {} across {} report(s), which meets `--fail-on {}`" ``: `crates/disrobe-cli/src/cli/context.rs:164`
- `` "no `.disrobe/` workspace in {} - run `disrobe init` first" ``: `crates/disrobe-cli/src/cli/annot.rs:39`

### `DR-CLI-0324`

- `` "`--fail-on {}` is not one of never, incomplete, failed, any" ``: `crates/disrobe-cli/src/cli/context.rs:186`
- `"cannot read target {}: {}"`: `crates/disrobe-cli/src/cli/annot.rs:89`
- `"target {} has no usable file stem"`: `crates/disrobe-cli/src/cli/annot.rs:52`, `crates/disrobe-cli/src/cli/annot.rs:120`

### `DR-CLI-0325`

- `"cannot create .disrobe/annotations: {}"`: `crates/disrobe-cli/src/cli/annot.rs:64`
- `"{} report(s) were found under {} but none could be graded"`: `crates/disrobe-cli/src/cli/context.rs:145`

### `DR-CLI-0326`

- `"annotation serialize: {}"`: `crates/disrobe-cli/src/cli/annot.rs:68`
- `` "this binary was built without the `server` feature, so it carries no HTTP daemon, no gRPC surface and no LSP-over-stdio. rebuild with `--features server`, or use the default build which enables it" ``: `crates/disrobe-cli/src/main.rs:2145`

### `DR-CLI-0327`

- `"cannot write {}: {}"`: `crates/disrobe-cli/src/cli/annot.rs:71`
- `` "this binary was built without the `prowl` feature, so it carries no archive and threat-intel harvester and no keyring for provider credentials. rebuild with `--features prowl`, or use the default build which enables it" ``: `crates/disrobe-cli/src/main.rs:1857`

### `DR-CLI-0328`

- `` "this binary was built without the `net-fetch` feature, so it carries no HTTP client and cannot query {}. rebuild with `--features net-fetch`, or use the default build which enables it, or install ghidra yourself and put its support/ directory on PATH" ``: `crates/disrobe-cli/src/cli/install_deps.rs:227`
- `"{} is not a valid disrobe.annotations/v1 file: {}"`: `crates/disrobe-cli/src/cli/annot.rs:81`

### `DR-CLI-0329`

- `"annotation validation failed: {}"`: `crates/disrobe-cli/src/cli/annot.rs:107`, `crates/disrobe-cli/src/cli/annot.rs:131`, `crates/disrobe-cli/src/cli/annot.rs:150`
- `` "this binary was built without the `net-fetch` feature, so it carries no HTTP client and cannot download {}. rebuild with `--features net-fetch`, or use the default build which enables it, or fetch the archive yourself" ``: `crates/disrobe-cli/src/cli/install_deps.rs:277`

### `DR-CLI-0330`

- `` "malformed `.disrobe.toml` at {}: {}" ``: `crates/disrobe-cli/src/cli/config.rs:145`
- `"{} is not a valid disrobe.renames/v1 file: {}"`: `crates/disrobe-cli/src/cli/rename.rs:54`

### `DR-CLI-0331`

- `"cannot read config file {}: {}"`: `crates/disrobe-cli/src/cli/config.rs:154`
- `"cannot read cwd: {}"`: `crates/disrobe-cli/src/cli/rename.rs:67`

### `DR-CLI-0332`

- `"--config path does not exist: {}"`: `crates/disrobe-cli/src/cli/config.rs:189`
- `` "no `.disrobe/` workspace in {} - run `disrobe init` first" ``: `crates/disrobe-cli/src/cli/rename.rs:71`

### `DR-CLI-0333`

- `"cannot create .disrobe/notes: {}"`: `crates/disrobe-cli/src/cli/rename.rs:77`
- `"cannot read cwd: {}"`: `crates/disrobe-cli/src/cli/config.rs:200`

### `DR-CLI-0334`

- `"renames serialize: {}"`: `crates/disrobe-cli/src/cli/rename.rs:88`
- `"{} already exists; pass --force to overwrite"`: `crates/disrobe-cli/src/cli/config.rs:278`

### `DR-CLI-0335`

- `"cannot create config parent dir {}: {}"`: `crates/disrobe-cli/src/cli/config.rs:287`
- `"cannot write {}: {}"`: `crates/disrobe-cli/src/cli/rename.rs:90`

### `DR-CLI-0362`

- `"report serialize"`: `crates/disrobe-cli/src/cli/chain_v1.rs:1035`
- `"report serialize: {}"`: `crates/disrobe-cli/src/cli/chain_v1.rs:1430`

### `DR-CLI-0363`

- `"report redaction"`: `crates/disrobe-cli/src/cli/chain_v1.rs:1048`
- `"report redaction: {}"`: `crates/disrobe-cli/src/cli/chain_v1.rs:1436`

### `DR-CLI-0408`

- `"--backend {} decompiles DEX and APK input, not class or jar files"`: `crates/disrobe-cli/src/cli/jvm.rs:1749`
- `"--backend {} decompiles class and jar files, not DEX or APK input"`: `crates/disrobe-cli/src/cli/jvm.rs:1777`

### `DR-CLI-0410`

- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:1564`
- `` "unknown category in --metadata-exclude `{}`: {}" ``: `crates/disrobe-cli/src/cli/llm.rs:256`
- `` "unknown category in --metadata-include `{}`: {}" ``: `crates/disrobe-cli/src/cli/llm.rs:242`

### `DR-CLI-0420`

- `"--decryption-keys requires --i-have-authorization"`: `crates/disrobe-cli/src/cli/llm.rs:274`
- `"backend {} failed: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:1704`
- `"cannot read mapping file: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:554`
- `"cannot write native source: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:2183`

### `DR-CLI-0421`

- `"android backend {} failed: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:1732`
- `"cannot write native disasm: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:2188`
- `"proguard mapping parse: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:556`

### `DR-CLI-0422`

- `"cannot write native dex source: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:2163`
- `"name-restoration serialize: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:1115`

### `DR-CLI-0423`

- `"cannot create class out dir: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:2230`
- `"cannot write name-restoration.json: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:1117`

### `DR-CLI-0430`

- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:317`
- `"cannot read library jar: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:1181`
- `"write LLM bundle failed: {}"`: `crates/disrobe-cli/src/cli/llm.rs:374`

### `DR-CLI-0431`

- `"--metadata-out {} exists; pass --force to overwrite"`: `crates/disrobe-cli/src/cli/llm.rs:338`
- `"dotnet analyze: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:346`
- `"library classfile parse: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:1184`

### `DR-CLI-0432`

- `"cannot create out dir: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:348`
- `"library jar extract: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:1189`
- `"write LLM briefs failed: {}"`: `crates/disrobe-cli/src/cli/llm.rs:384`

### `DR-CLI-0434`

- `"cannot write library-fingerprint.json: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:1240`
- `"cannot write manifest: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:379`

### `DR-CLI-0435`

- `"--format requires a standalone DEX input because class, JAR, and APK identifiers use different source keys"`: `crates/disrobe-cli/src/cli/jvm.rs:1273`
- `"cannot write native decompilation: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:967`

### `DR-CLI-0436`

- `"Dalvik symbol export: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:1882`, `crates/disrobe-cli/src/cli/jvm.rs:1884`, `crates/disrobe-cli/src/cli/jvm.rs:1886`
- `"serialize manifest: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:377`

### `DR-CLI-0438`

- `"Dalvik symbol export path has no parent: {}"`: `crates/disrobe-cli/src/cli/backend_export.rs:110`
- `"Dalvik symbol export path must be a normalized relative path: {}"`: `crates/disrobe-cli/src/cli/backend_export.rs:88`
- `"Dalvik symbol export path must not be empty"`: `crates/disrobe-cli/src/cli/backend_export.rs:96`

### `DR-CLI-0440`

- `` "--metadata-format `{}` is unsupported; valid: json | jsonl | cbor | msgpack" ``: `crates/disrobe-cli/src/cli/llm.rs:308`
- `"build LLM bundle failed: {}"`: `crates/disrobe-cli/src/cli/llm.rs:363`
- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:973`
- `"cannot write Dalvik symbol export {}: {}"`: `crates/disrobe-cli/src/cli/backend_export.rs:122`
- `"protector-peel serialize: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:1492`
- `"serialize LLM bundle failed: {}"`: `crates/disrobe-cli/src/cli/llm.rs:369`

### `DR-CLI-0441`

- `"cannot write protector-peel.json: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:1494`
- `"dotnet analyze: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:975`
- `` "this binary was built without the `jvm` and `flutter` features, so it cannot emit a requested symbol export" ``: `crates/disrobe-cli/src/cli/auto.rs:50`
- `` "this binary was built without the `jvm` feature, so it cannot emit a requested Dalvik symbol export" ``: `crates/disrobe-cli/src/cli/chain_v1.rs:586`

### `DR-CLI-0442`

- `"cannot create dir: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:985`
- `"peel-summary serialize: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:1518`
- `` "requested Dalvik symbol export requires a successful direct root `jvm.classify` android-dex node for the original input" ``: `crates/disrobe-cli/src/cli/chain_v1.rs:569`

### `DR-CLI-0443`

- `"cannot write peel-summary: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:1520`
- `"requested Dalvik symbol export cannot parse the classified root DEX: {}"`: `crates/disrobe-cli/src/cli/chain_v1.rs:573`
- `"serialize: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:988`

### `DR-CLI-0444`

- `"cannot assign a collision-free batch output directory for {}"`: `crates/disrobe-cli/src/cli/batch.rs:125`
- `"cannot write output: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:990`

### `DR-CLI-0446`

- `"--engine-symbol-map requires a successful direct root Flutter AOT classification for the original input"`: `crates/disrobe-cli/src/cli/chain_v1.rs:519`
- `` "`auto --engine-symbol-map` requires a single matching Flutter ELF input" ``: `crates/disrobe-cli/src/cli/auto.rs:66`

### `DR-CLI-0450`

- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/hermes.rs:73`
- `"unknown protector '{}'; expected kebab-case (e.g. confuser-ex2, obfuscar, smart-assembly, dotnet-reactor, themida-dotnet, ilprotector, max-to-code)"`: `crates/disrobe-cli/src/cli/dotnet.rs:679`

### `DR-CLI-0451`

- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:687`
- `"hermes parse: {}"`: `crates/disrobe-cli/src/cli/hermes.rs:87`

### `DR-CLI-0453`

- `"cannot write lifted source: {}"`: `crates/disrobe-cli/src/cli/hermes.rs:96`
- `"peel of {} failed: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:734`

### `DR-CLI-0454`

- `"cannot write manifest: {}"`: `crates/disrobe-cli/src/cli/hermes.rs:120`
- `"no peel routine registered for {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:740`

### `DR-CLI-0455`

- `"cannot create out dir: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:747`
- `"serialize manifest: {}"`: `crates/disrobe-cli/src/cli/hermes.rs:118`

### `DR-CLI-0459`

- `"cannot read native library {}: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:635`
- `"cannot write recovered CIL: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:894`

### `DR-CLI-0460`

- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/hermes.rs:154`
- `"dex parse: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:777`
- `"dotnet decompile --recover-iterators needs an input file"`: `crates/disrobe-cli/src/cli/dotnet.rs:625`

### `DR-CLI-0461`

- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:629`
- `"hermes parse: {}"`: `crates/disrobe-cli/src/cli/hermes.rs:156`
- `"native method scan: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:779`

### `DR-CLI-0462`

- `"cannot create dir: {}"`: `crates/disrobe-cli/src/cli/hermes.rs:171`
- `"classfile parse: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:789`
- `"dotnet decompile: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:631`

### `DR-CLI-0463`

- `"iterator serialize: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:657`
- `"jar extract: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:799`
- `"serialize: {}"`: `crates/disrobe-cli/src/cli/hermes.rs:174`

### `DR-CLI-0464`

- `"apk extract: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:814`
- `"cannot create output parent: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:44`
- `"cannot write output: {}"`: `crates/disrobe-cli/src/cli/hermes.rs:176`

### `DR-CLI-0465`

- `"aab extract: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:830`
- `"bundle stage has no file name"`: `crates/disrobe-cli/src/cli/dotnet.rs:55`
- `"cannot allocate bundle stage: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:50`
- `"cannot create bundle stage: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:65`

### `DR-CLI-0466`

- `"bundle output must name a directory"`: `crates/disrobe-cli/src/cli/dotnet.rs:58`
- `"input does not look like a .class/.jar/.dex/.apk/.aab/.aar/.apks/.oat file"`: `crates/disrobe-cli/src/cli/jvm.rs:893`

### `DR-CLI-0467`

- `"cannot inspect bundle output: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:77`
- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:987`

### `DR-CLI-0468`

- `"bundle output directory is not empty: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:81`
- `"jni link serialize: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:1014`

### `DR-CLI-0469`

- `"aar extract: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:847`
- `"cannot replace empty bundle output: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:86`

### `DR-CLI-0470`

- `"apks extract: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:863`
- `"cannot publish bundle output atomically: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:90`
- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/hermes.rs:307`

### `DR-CLI-0471`

- `"hermes parse: {}"`: `crates/disrobe-cli/src/cli/hermes.rs:309`
- `"oat dex extract: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:879`
- `"parse .NET bundle: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:456`

### `DR-CLI-0472`

- `"--native apk extract for {}: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:648`
- `"extract .NET bundle: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:479`

### `DR-CLI-0473`

- `"--native apks extract for {}: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:659`
- `".NET bundle extraction failed integrity checks: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:483`

### `DR-CLI-0479`

- `` "native CIL decompilation failed for `{}`: {}" ``: `crates/disrobe-cli/src/cli/dotnet.rs:921`
- `` "native CIL decompilation failed for `{}`: {} {} failed" ``: `crates/disrobe-cli/src/cli/dotnet.rs:916`

### `DR-CLI-0480`

- `"cannot read DEX input: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:216`, `crates/disrobe-cli/src/cli/jvm.rs:222`
- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/macho.rs:196`
- `"invalid .NET bundle member path: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:492`

### `DR-CLI-0481`

- `` ".NET bundle member paths collide after sanitization: `{}`" ``: `crates/disrobe-cli/src/cli/dotnet.rs:500`
- `"DEX input size overflow"`: `crates/disrobe-cli/src/cli/jvm.rs:229`
- `"macho analyze: {}"`: `crates/disrobe-cli/src/cli/macho.rs:198`

### `DR-CLI-0482`

- `"DEX input exceeds the {}-byte input limit"`: `crates/disrobe-cli/src/cli/jvm.rs:232`
- `"cannot create dir: {}"`: `crates/disrobe-cli/src/cli/macho.rs:208`
- `` "extracted .NET bundle member is absent from the manifest: `{}`" ``: `crates/disrobe-cli/src/cli/dotnet.rs:509`

### `DR-CLI-0483`

- `` "declared managed assembly `{}` is invalid or unsupported: {}" ``: `crates/disrobe-cli/src/cli/dotnet.rs:538`
- `"dex2jar requires a standalone DEX input"`: `crates/disrobe-cli/src/cli/jvm.rs:329`
- `"serialize: {}"`: `crates/disrobe-cli/src/cli/macho.rs:211`

### `DR-CLI-0484`

- `"DEX-to-JAR output directory already exists: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:346`
- `"DEX-to-JAR output directory appeared before finalization: {}; staging directory: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:311`
- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:1049`
- `"cannot stat input: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:1041`
- `"cannot write output: {}"`: `crates/disrobe-cli/src/cli/macho.rs:213`
- `"input is {} bytes, above the {} byte cap for a NativeAOT image"`: `crates/disrobe-cli/src/cli/dotnet.rs:1044`

### `DR-CLI-0486`

- `"in-house class path validation: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:359`
- `"serialize: {}"`: `crates/disrobe-cli/src/cli/dotnet.rs:1053`, `crates/disrobe-cli/src/cli/dotnet.rs:1069`

### `DR-CLI-0490`

- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/macho.rs:235`
- `"in-house JAR assembly: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:361`

### `DR-CLI-0491`

- `"cannot create out dir: {}"`: `crates/disrobe-cli/src/cli/macho.rs:250`
- `"in-house JAR output reached {} bytes, exceeding the {}-byte output limit"`: `crates/disrobe-cli/src/cli/jvm.rs:364`

### `DR-CLI-0492`

- `"cannot allocate a DEX-to-JAR staging directory"`: `crates/disrobe-cli/src/cli/jvm.rs:269`
- `"cannot create DEX-to-JAR output parent {} before staging: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:247`
- `"cannot create DEX-to-JAR staging directory: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:263`
- `"cannot write objc dump: {}"`: `crates/disrobe-cli/src/cli/macho.rs:263`

### `DR-CLI-0493`

- `"cannot create class output directory: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:375`
- `"cannot write swift dump: {}"`: `crates/disrobe-cli/src/cli/macho.rs:267`

### `DR-CLI-0494`

- `"cannot exclusively create staged DEX-to-JAR file {}: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:289`
- `"cannot write manifest: {}"`: `crates/disrobe-cli/src/cli/macho.rs:299`
- `"cannot write staged DEX-to-JAR file {}: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:295`

### `DR-CLI-0495`

- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/macho.rs:103`
- `"serialize objc dump: {}"`: `crates/disrobe-cli/src/cli/macho.rs:261`

### `DR-CLI-0496`

- `"cannot check DEX-to-JAR destination {} before finalizing staging directory {}: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:304`
- `"cannot finalize DEX-to-JAR output: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:396`
- `"cannot finalize DEX-to-JAR output: {}; {}"`: `crates/disrobe-cli/src/cli/jvm.rs:392`
- `"cannot finalize DEX-to-JAR staging directory {} as {}: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:318`
- `"input is not a dyld shared cache (missing dyld_v1 magic)"`: `crates/disrobe-cli/src/cli/macho.rs:106`
- `"serialize swift dump: {}"`: `crates/disrobe-cli/src/cli/macho.rs:265`

### `DR-CLI-0497`

- `"cannot remove DEX-to-JAR staging directory {}: {}"`: `crates/disrobe-cli/src/cli/jvm.rs:276`
- `"dyld cache parse: {}"`: `crates/disrobe-cli/src/cli/macho.rs:110`
- `"serialize manifest: {}"`: `crates/disrobe-cli/src/cli/macho.rs:297`

### `DR-CLI-0498`

- `"cannot write objc header: {}"`: `crates/disrobe-cli/src/cli/macho.rs:273`
- `"dyld image reconstruct: {}"`: `crates/disrobe-cli/src/cli/macho.rs:131`

### `DR-CLI-0499`

- `"cannot create out dir: {}"`: `crates/disrobe-cli/src/cli/macho.rs:140`
- `"cannot write swift declarations: {}"`: `crates/disrobe-cli/src/cli/macho.rs:280`

### `DR-CLI-0500`

- `"cannot create dir: {}"`: `crates/disrobe-cli/src/cli/macho.rs:147`
- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/macho.rs:324`

### `DR-CLI-0501`

- `"cannot write dylib: {}"`: `crates/disrobe-cli/src/cli/macho.rs:150`
- `"input is not a Mach-O / fat Mach-O binary"`: `crates/disrobe-cli/src/cli/macho.rs:326`

### `DR-CLI-0502`

- `` "input is a thin Mach-O ({}); use `disrobe macho dump` instead" ``: `crates/disrobe-cli/src/cli/macho.rs:329`
- `"the cache holds no image named {}"`: `crates/disrobe-cli/src/cli/macho.rs:124`

### `DR-CLI-0522`

- `"--opcode-map and --build-id must be supplied together"`: `crates/disrobe-cli/src/cli/lua.rs:176`
- `"apply Lua opcode map: {}"`: `crates/disrobe-cli/src/cli/lua.rs:168`
- `"empty Luau input"`: `crates/disrobe-cli/src/cli/lua.rs:164`
- `"load Lua opcode map: {}"`: `crates/disrobe-cli/src/cli/lua.rs:166`
- `"lua decompile: {}"`: `crates/disrobe-cli/src/cli/lua.rs:170`, `crates/disrobe-cli/src/cli/lua.rs:173`

### `DR-CLI-0605`

- `"cannot remove stale decompiled ruby: {}"`: `crates/disrobe-cli/src/cli/ruby.rs:113`
- `"cannot write decompiled ruby: {}"`: `crates/disrobe-cli/src/cli/ruby.rs:106`

### `DR-CLI-0650`

- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/go.rs:52`
- `"cannot write erlang source: {}"`: `crates/disrobe-cli/src/cli/beam.rs:163`

### `DR-CLI-0651`

- `"cannot write disasm listing: {}"`: `crates/disrobe-cli/src/cli/beam.rs:238`
- `"go analyze: {}"`: `crates/disrobe-cli/src/cli/go.rs:54`

### `DR-CLI-0660`

- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/go.rs:292`
- `"cannot read {}: {}"`: `crates/disrobe-cli/src/cli/pickle.rs:120`

### `DR-CLI-0661`

- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/pickle.rs:104`
- `"cannot stat input: {}"`: `crates/disrobe-cli/src/cli/pickle.rs:97`
- `"go analyze: {}"`: `crates/disrobe-cli/src/cli/go.rs:294`
- `"input exceeds pickle cap {} bytes"`: `crates/disrobe-cli/src/cli/pickle.rs:100`
- `"{} exceeds pickle cap {} bytes"`: `crates/disrobe-cli/src/cli/pickle.rs:124`
- `"{} read limit overflow"`: `crates/disrobe-cli/src/cli/pickle.rs:115`

### `DR-CLI-0700`

- `"cannot read apk: {}"`: `crates/disrobe-cli/src/cli/apk.rs:84`
- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/swift.rs:68`

### `DR-CLI-0701`

- `"apk resource analysis: {}"`: `crates/disrobe-cli/src/cli/apk.rs:86`
- `"input is not a Mach-O binary"`: `crates/disrobe-cli/src/cli/swift.rs:70`

### `DR-CLI-0702`

- `"cannot create out dir {}: {}"`: `crates/disrobe-cli/src/cli/apk.rs:101`
- `` "input is a fat Mach-O; use `disrobe macho classdump` for fat binaries" ``: `crates/disrobe-cli/src/cli/swift.rs:73`

### `DR-CLI-0703`

- `"cannot write {}: {}"`: `crates/disrobe-cli/src/cli/apk.rs:108`
- `"parse slice: {}"`: `crates/disrobe-cli/src/cli/swift.rs:77`

### `DR-CLI-0704`

- `"cannot create dir: {}"`: `crates/disrobe-cli/src/cli/swift.rs:88`
- `"cannot write {}: {}"`: `crates/disrobe-cli/src/cli/apk.rs:120`

### `DR-CLI-0760`

- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/flutter.rs:597`
- `"cannot store Flutter engine symbol cache: {}"`: `crates/disrobe-cli/src/cli/flutter.rs:540`

### `DR-CLI-0761`

- `"Flutter engine cache identity: {}"`: `crates/disrobe-cli/src/cli/flutter.rs:549`
- `"dart snapshot parse: {}"`: `crates/disrobe-cli/src/cli/flutter.rs:604`

### `DR-CLI-0762`

- `"cannot read Flutter engine symbol cache: {}"`: `crates/disrobe-cli/src/cli/flutter.rs:551`
- `"dart aot decompile: {}"`: `crates/disrobe-cli/src/cli/flutter.rs:606`

### `DR-CLI-0767`

- `"ELF does not contain a parseable Dart AOT snapshot"`: `crates/disrobe-cli/src/cli/flutter.rs:755`
- `"Flutter AOT layout: {}"`: `crates/disrobe-cli/src/cli/flutter.rs:759`
- `"Flutter AOT lift: {}"`: `crates/disrobe-cli/src/cli/flutter.rs:705`
- `"Flutter AOT snapshot section {} is missing"`: `crates/disrobe-cli/src/cli/flutter.rs:780`

### `DR-CLI-0814`

- `"flutter apk parse: {}"`: `crates/disrobe-cli/src/cli/mobile.rs:520`
- `"libapp parse: {}"`: `crates/disrobe-cli/src/cli/mobile.rs:517`

### `DR-CLI-0817`

- `"android dex extract: {}"`: `crates/disrobe-cli/src/cli/mobile.rs:219`
- `"webview extract failed: {}"`: `crates/disrobe-cli/src/cli/mobile.rs:322`

### `DR-CLI-0818`

- `"apk contains no top-level classes*.dex entries"`: `crates/disrobe-cli/src/cli/mobile.rs:222`
- `"cannot create asset dir: {}"`: `crates/disrobe-cli/src/cli/mobile.rs:328`

### `DR-CLI-0819`

- `"cannot write asset: {}"`: `crates/disrobe-cli/src/cli/mobile.rs:331`
- `"cannot write {}: {}"`: `crates/disrobe-cli/src/cli/mobile.rs:229`

### `DR-CLI-0820`

- `"android bundle extract: {}"`: `crates/disrobe-cli/src/cli/mobile.rs:189`
- `"nativescript extract failed: {}"`: `crates/disrobe-cli/src/cli/mobile.rs:360`

### `DR-CLI-0821`

- `"bundle contains no inner apk or dex entries"`: `crates/disrobe-cli/src/cli/mobile.rs:192`
- `"cannot create bundle dir: {}"`: `crates/disrobe-cli/src/cli/mobile.rs:366`

### `DR-CLI-0822`

- `"cannot write bundle: {}"`: `crates/disrobe-cli/src/cli/mobile.rs:369`
- `"cannot write {}: {}"`: `crates/disrobe-cli/src/cli/mobile.rs:200`

### `DR-CLI-0826`

- `"flutter apk parse: {}"`: `crates/disrobe-cli/src/cli/mobile.rs:251`
- `"libapp parse: {}"`: `crates/disrobe-cli/src/cli/mobile.rs:247`

### `DR-CLI-0830`

- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/mobile.rs:561`
- `"cannot read {}: {}"`: `crates/disrobe-cli/src/cli/query.rs:135`, `crates/disrobe-cli/src/cli/query.rs:196`, `crates/disrobe-cli/src/cli/query.rs:200`, `crates/disrobe-cli/src/cli/query.rs:264`

### `DR-CLI-0831`

- `"apk recon failed: {}"`: `crates/disrobe-cli/src/cli/mobile.rs:565`
- `"{} is a .dr envelope but not queryable: {}"`: `crates/disrobe-cli/src/cli/query.rs:268`

### `DR-CLI-0832`

- `` "invalid query `{}`: {}" ``: `crates/disrobe-cli/src/cli/query.rs:40`
- `"recon serialize: {}"`: `crates/disrobe-cli/src/cli/mobile.rs:583`, `crates/disrobe-cli/src/cli/mobile.rs:600`

### `DR-CLI-0833`

- `"recon render: {}"`: `crates/disrobe-cli/src/cli/mobile.rs:585`
- `"{} is neither a Disasm- or Mir-rung .dr envelope nor a disassemblable native binary: {}"`: `crates/disrobe-cli/src/cli/query.rs:275`

### `DR-CLI-0834`

- `"cannot parse JVM class {}: {}"`: `crates/disrobe-cli/src/cli/query.rs:211`
- `"cannot read JVM hierarchy {}: {}"`: `crates/disrobe-cli/src/cli/query.rs:217`

### `DR-CLI-0836`

- `"JVM query support is not enabled in this build"`: `crates/disrobe-cli/src/cli/query.rs:245`
- `"{} is not a JVM .class or Android .dex input"`: `crates/disrobe-cli/src/cli/query.rs:235`

### `DR-CLI-0840`

- `"cannot read {}: {}"`: `crates/disrobe-cli/src/cli/capabilities.rs:14`
- `"{} contains more than {} directory entries"`: `crates/disrobe-cli/src/cli/query.rs:109`

### `DR-CLI-0841`

- `"{} exceeds the {} directory-depth limit"`: `crates/disrobe-cli/src/cli/query.rs:115`
- `"{} is a .dr envelope but not a Disasm or Mir rung the capabilities engine can read: {}"`: `crates/disrobe-cli/src/cli/capabilities.rs:28`

### `DR-CLI-0842`

- `"{} exceeds the {} byte JVM directory-input limit"`: `crates/disrobe-cli/src/cli/query.rs:141`
- `"{} is neither a Disasm- or Mir-rung .dr envelope nor a disassemblable native binary: {}"`: `crates/disrobe-cli/src/cli/capabilities.rs:41`

### `DR-CLI-0843`

- `` "`auto --llm` / `--metadata-pack-N` is not supported; the chain engine writes a single chain.json. Run the matching per-language subcommand (e.g. `disrobe py decompile <input> --llm`) to emit the llm metadata bundle." ``: `crates/disrobe-cli/src/main.rs:2050`
- `"{} exceeds the {} JVM hierarchy-edge limit"`: `crates/disrobe-cli/src/cli/query.rs:173`

### `DR-CLI-0844`

- `"LUKS1 input cap is not addressable"`: `crates/disrobe-cli/src/cli/luks1_input.rs:43`
- `"LUKS1 input {} changed or exceeded its bounds while reading: {}"`: `crates/disrobe-cli/src/cli/luks1_input.rs:62`
- `"LUKS1 input {} was refused before payload allocation: {}"`: `crates/disrobe-cli/src/cli/chain_v1.rs:620`, `crates/disrobe-cli/src/cli/extract.rs:40`
- `"cannot read bounded LUKS1 input {}: {}"`: `crates/disrobe-cli/src/cli/luks1_input.rs:55`
- `"cannot reopen input {}: {}"`: `crates/disrobe-cli/src/cli/luks1_input.rs:46`
- `` "the requested metadata selects no category `taint` can produce; it contributes cfg and dfg, so pass --cfg, --dfg, --metadata-pack-2, --metadata-pack-3 or --llm" ``: `crates/disrobe-cli/src/cli/taint.rs:244`
- `"{} exceeds the {} JVM hierarchy-node limit"`: `crates/disrobe-cli/src/cli/query.rs:180`

### `DR-CLI-0855`

- `"cannot read {} metadata: {}"`: `crates/disrobe-cli/src/cli/vulnmatch.rs:204`
- `"cannot read {}: allocation of {} bytes failed"`: `crates/disrobe-cli/src/cli/vulnmatch.rs:232`
- `"cannot read {}: file changed while reading"`: `crates/disrobe-cli/src/cli/vulnmatch.rs:242`
- `"cannot read {}: file exceeds the {}-byte limit"`: `crates/disrobe-cli/src/cli/vulnmatch.rs:216`
- `"cannot read {}: file size cannot be represented in memory"`: `crates/disrobe-cli/src/cli/vulnmatch.rs:222`
- `"cannot read {}: path is not a regular file"`: `crates/disrobe-cli/src/cli/vulnmatch.rs:210`
- `"cannot read {}: {}"`: `crates/disrobe-cli/src/cli/vulnmatch.rs:200`, `crates/disrobe-cli/src/cli/vulnmatch.rs:238`
- `"vulnmatch input limit overflowed"`: `crates/disrobe-cli/src/cli/vulnmatch.rs:228`

### `DR-CLI-0861`

- `"--openvex cannot be combined with --json, --ndjson, or --sarif"`: `crates/disrobe-cli/src/cli/vulnmatch.rs:63`
- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/flutter.rs:827`
- `"offline vulnerability match failed: {}"`: `crates/disrobe-cli/src/cli/vulnmatch.rs:108`

### `DR-CLI-0862`

- `"--openvex requires --author IDENTITY"`: `crates/disrobe-cli/src/cli/vulnmatch.rs:68`
- `"dart pinned graph recovery: {}"`: `crates/disrobe-cli/src/cli/flutter.rs:833`
- `"offline package vulnerability matching supports text, JSON, and NDJSON output"`: `crates/disrobe-cli/src/cli/vulnmatch.rs:103`

### `DR-CLI-0863`

- `"--openvex requires --timestamp YYYY-MM-DDTHH:MM:SSZ"`: `crates/disrobe-cli/src/cli/vulnmatch.rs:70`
- `"cannot read vm data blob: {}"`: `crates/disrobe-cli/src/cli/flutter.rs:854`

### `DR-CLI-0864`

- `"OpenVEX 0.2.0: {}"`: `crates/disrobe-cli/src/cli/vulnmatch.rs:79`
- `"cannot read vm instructions blob: {}"`: `crates/disrobe-cli/src/cli/flutter.rs:856`

### `DR-CLI-0865`

- `"OpenVEX 0.2.0: {}"`: `crates/disrobe-cli/src/cli/vulnmatch.rs:81`
- `"cannot read isolate data blob: {}"`: `crates/disrobe-cli/src/cli/flutter.rs:858`

### `DR-CLI-0866`

- `"cannot read isolate instructions blob: {}"`: `crates/disrobe-cli/src/cli/flutter.rs:860`
- `"write OpenVEX output: {}"`: `crates/disrobe-cli/src/cli/vulnmatch.rs:87`

### `DR-CLI-0870`

- `"--osv-db cannot be combined with --openvex"`: `crates/disrobe-cli/src/cli/vulnmatch.rs:53`
- `"cannot read {}: {}"`: `crates/disrobe-cli/src/cli/semdiff.rs:550`, `crates/disrobe-cli/src/cli/semdiff.rs:560`
- `"cannot write output: {}"`: `crates/disrobe-cli/src/cli/flutter.rs:895`

### `DR-CLI-0871`

- `"taint call-edge analysis: {}"`: `crates/disrobe-cli/src/cli/taint.rs:149`
- `"{} is {} bytes, over the {} byte semantic diff input cap"`: `crates/disrobe-cli/src/cli/semdiff.rs:554`

### `DR-CLI-0872`

- `"navigation returned an empty ambiguous call target set at {}"`: `crates/disrobe-cli/src/cli/taint.rs:208`
- `"semdiff pairs exactly two builds, got {} OTHER argument(s); pass --lineage to track one base across several builds at once"`: `crates/disrobe-cli/src/cli/semdiff.rs:100`

### `DR-CLI-0875`

- `"Hermes function index {} exceeds the supported index range"`: `crates/disrobe-cli/src/cli/hermes.rs:190`
- `"Hermes function index {} is negative; indexes are zero-based"`: `crates/disrobe-cli/src/cli/hermes.rs:201`
- `"Hermes function name {} is ambiguous across {} entries; select a zero-based index"`: `crates/disrobe-cli/src/cli/hermes.rs:223`
- `"function index {} is invalid because this bundle declares 0 functions"`: `crates/disrobe-cli/src/cli/hermes.rs:285`
- `"function index {} is past the end of this bundle, which declares {} function(s) numbered 0 to {}"`: `crates/disrobe-cli/src/cli/hermes.rs:289`
- `"no Hermes function has the exact name {}"`: `crates/disrobe-cli/src/cli/hermes.rs:219`

### `DR-CLI-0912`

- `"cannot clear the earlier run's {}: {}"`: `crates/disrobe-cli/src/cli/chain_v1.rs:1518`
- `"cannot read output directory {}: {}"`: `crates/disrobe-cli/src/cli/chain_v1.rs:1498`

### `DR-DOTNET-0039`

- `"RVA 0x{}: {}"`: `crates/disrobe-pass-dotnet/src/aot/method_bodies.rs:28`, `crates/disrobe-pass-dotnet/src/aot/method_bodies.rs:33`
- `"invalid ahead-of-time method body at RVA 0x{}: {}"`: `crates/disrobe-pass-dotnet/src/error.rs:145`

### `DR-DOTNET-0920`

- `"NativeAOT type nesting depth overflowed"`: `crates/disrobe-pass-dotnet/src/chain_detector.rs:554`
- `"NativeAOT type nesting exceeds {} levels"`: `crates/disrobe-pass-dotnet/src/chain_detector.rs:559`

### `DR-DOTNET-0921`

- `"NativeAOT method owner count overflowed"`: `crates/disrobe-pass-dotnet/src/chain_detector.rs:811`
- `"NativeAOT symbol work count overflowed"`: `crates/disrobe-pass-dotnet/src/chain_detector.rs:496`, `crates/disrobe-pass-dotnet/src/chain_detector.rs:604`, `crates/disrobe-pass-dotnet/src/chain_detector.rs:618`, `crates/disrobe-pass-dotnet/src/chain_detector.rs:624`
- `"NativeAOT symbol work exceeds {} items"`: `crates/disrobe-pass-dotnet/src/chain_detector.rs:501`

### `DR-DOTNET-0922`

- `"NativeAOT qualified name size overflowed"`: `crates/disrobe-pass-dotnet/src/chain_detector.rs:513`, `crates/disrobe-pass-dotnet/src/chain_detector.rs:544`, `crates/disrobe-pass-dotnet/src/chain_detector.rs:573`, `crates/disrobe-pass-dotnet/src/chain_detector.rs:665`, `crates/disrobe-pass-dotnet/src/chain_detector.rs:678`
- `"NativeAOT qualified names exceed {} bytes"`: `crates/disrobe-pass-dotnet/src/chain_detector.rs:518`

### `DR-DOTNET-0924`

- `"NativeAOT method owner index is absent"`: `crates/disrobe-pass-dotnet/src/chain_detector.rs:805`, `crates/disrobe-pass-dotnet/src/chain_detector.rs:847`, `crates/disrobe-pass-dotnet/src/chain_detector.rs:893`
- `"NativeAOT method owner record 0x{} is absent"`: `crates/disrobe-pass-dotnet/src/chain_detector.rs:798`
- `"NativeAOT method owner storage for record 0x{} is absent"`: `crates/disrobe-pass-dotnet/src/chain_detector.rs:840`, `crates/disrobe-pass-dotnet/src/chain_detector.rs:884`

### `DR-EXTRACT-0063`

- `"cannot read LUKS1 header before key input: {}"`: `crates/disrobe-cli/src/cli/extract.rs:79`
- `"unsupported LUKS1 header before key input: {}"`: `crates/disrobe-cli/src/cli/extract.rs:83`

### `DR-EXTRACT-0064`

- `"cannot report LUKS1 wall: {}"`: `crates/disrobe-cli/src/cli/extract.rs:179`
- `"malformed detected LUKS1 header: {}"`: `crates/disrobe-cli/src/cli/extract.rs:175`

### `DR-EXTRACT-0065`

- `"cannot open raw LUKS1 volume-key file {}: {}"`: `crates/disrobe-cli/src/cli/extract.rs:134`
- `"cannot read raw LUKS1 volume key from {}: {}"`: `crates/disrobe-cli/src/cli/extract.rs:143`
- `"raw LUKS1 volume key must contain exactly {} bytes; read {}"`: `crates/disrobe-cli/src/cli/extract.rs:153`
- `"raw volume-key size is not addressable"`: `crates/disrobe-cli/src/cli/extract.rs:124`

### `DR-EXTRACT-0067`

- `"decrypted LUKS1 payload did not enter the container pipeline: container not recognized"`: `crates/disrobe-cli/src/cli/extract.rs:102`
- `"decrypted LUKS1 payload did not enter the container pipeline: {}"`: `crates/disrobe-cli/src/cli/extract.rs:113`

### `DR-JVM-0034`

- `"annotation attribute lookup failed"`: `crates/disrobe-pass-jvm/src/attributes.rs:981`
- `"malformed declaration annotation attribute: duplicate {} attributes"`: `crates/disrobe-pass-jvm/src/attributes.rs:972`
- `"malformed declaration annotation attribute: {}"`: `crates/disrobe-pass-jvm/src/attributes.rs:31`
- `"not an Android Archive (missing classes.jar entry at the .aar zip root)"`: `crates/disrobe-pass-jvm/src/error.rs:164`

### `DR-JVM-0093`

- `"DEX code parser produced no body for a method requiring code"`: `crates/disrobe-pass-jvm/src/dex2jar.rs:1749`
- `"JVM emitter refusal: width-conflict"`: `crates/disrobe-pass-jvm/src/dex2jar.rs:1732`
- `"method body not recovered: {}"`: `crates/disrobe-pass-jvm/src/error.rs:126`
- `"{} JVM emitter refusal: {}"`: `crates/disrobe-pass-jvm/src/dex2jar.rs:1676`
- `"{} JVM emitter refused opcode {}"`: `crates/disrobe-pass-jvm/src/dex2jar.rs:1682`

### `DR-MCP-0330`

- `"cannot read {}: {}"`: `crates/disrobe-mcp/src/lib.rs:1341`
- `"{} is not a valid disrobe.renames/v1 file: {}"`: `crates/disrobe-mcp/src/lib.rs:1351`

### `DR-MCP-0340`

- `"renames file already has {} records"`: `crates/disrobe-mcp/src/lib.rs:721`
- `"renames file exceeds {} records"`: `crates/disrobe-mcp/src/lib.rs:1359`

### `DR-MCP-0656`

- `"multiple functions start at {}"`: `crates/disrobe-mcp/src/navigation.rs:706`
- `"no function starts at {}"`: `crates/disrobe-mcp/src/navigation.rs:702`

### `DR-MCP-0660`

- `"bounded navigation response needs {} bytes but budget is {}"`: `crates/disrobe-mcp/src/navigation.rs:813`
- `"cannot account for the bytes of this input: {}"`: `crates/disrobe-mcp/src/lib.rs:944`
- `"navigation response serialize: {}"`: `crates/disrobe-mcp/src/navigation.rs:47`, `crates/disrobe-mcp/src/navigation.rs:53`, `crates/disrobe-mcp/src/navigation.rs:803`

### `DR-MCP-0661`

- `"navigation analysis limit exceeded: {}"`: `crates/disrobe-mcp/src/navigation.rs:626`
- `"neighborhood exceeds the bounded analysis record limit"`: `crates/disrobe-mcp/src/navigation.rs:507`

### `DR-MCP-0680`

- `"native match report serialization failed: {}"`: `crates/disrobe-mcp/src/lib.rs:670`
- `"native match report serialization produced a non-object value"`: `crates/disrobe-mcp/src/lib.rs:666`

### `DR-NAT-0944`

- `"native.image-classify: build {} function inventory: {}"`: `crates/disrobe-pass-native/src/chain_detector.rs:253`
- `"native.image-classify: child count is not representable: {}"`: `crates/disrobe-pass-native/src/chain_detector.rs:653`

### `DR-NATIVE-0001`

- `"I/O error: {}"`: `crates/disrobe-pass-native/src/error.rs:9`
- `` "ghidra-headless not on PATH (set GHIDRA_HOME or run `disrobe install-deps ghidra`). Native decompile uses Ghidra-headless to lift PE/ELF/Mach-O binaries to a pseudo-C-source." ``: `crates/disrobe-cli/src/cli/native.rs:1335`

### `DR-NATIVE-0002`

- `"cannot create out dir: {}"`: `crates/disrobe-cli/src/cli/native.rs:1346`
- `"input shorter than required ({} bytes, had {})"`: `crates/disrobe-pass-native/src/error.rs:12`

### `DR-NATIVE-0003`

- `"cannot create ghidra project dir: {}"`: `crates/disrobe-cli/src/cli/native.rs:1349`, `crates/disrobe-cli/src/cli/native.rs:1353`
- `"unrecognized native container (no PE/ELF/Mach-O/COFF/MZ/NE/LE/LX magic)"`: `crates/disrobe-pass-native/src/error.rs:16`

### `DR-NATIVE-0004`

- `"ghidra-headless spawn failed: {}"`: `crates/disrobe-cli/src/cli/native.rs:40`
- `"object-crate parse failure: {}"`: `crates/disrobe-pass-native/src/error.rs:20`

### `DR-NATIVE-0005`

- `"goblin parse failure: {}"`: `crates/disrobe-pass-native/src/error.rs:23`
- `"manifest serialize: {}"`: `crates/disrobe-cli/src/cli/native.rs:1411`

### `DR-NATIVE-0006`

- `"cannot write manifest: {}"`: `crates/disrobe-cli/src/cli/native.rs:1413`
- `"gimli DWARF read failure: {}"`: `crates/disrobe-pass-native/src/error.rs:26`

### `DR-NATIVE-0007`

- `"PDB read failure: {}"`: `crates/disrobe-pass-native/src/error.rs:29`
- `"ghidra-headless exited with status {}; see {}"`: `crates/disrobe-cli/src/cli/native.rs:1417`

### `DR-NATIVE-0008`

- `"STABS table malformed at offset {}"`: `crates/disrobe-pass-native/src/error.rs:32`
- `"cannot create scripts dir: {}"`: `crates/disrobe-cli/src/cli/native.rs:1357`

### `DR-NATIVE-0009`

- `"cannot write decompile script {}: {}"`: `crates/disrobe-cli/src/cli/native.rs:1478`
- `"ghidra-headless exceeded the {}s decompile budget and was terminated"`: `crates/disrobe-cli/src/cli/native.rs:1381`
- `"unsupported architecture {} for disasm dispatch"`: `crates/disrobe-pass-native/src/error.rs:35`

### `DR-NATIVE-0010`

- `"cannot read input for sourcemap: {}"`: `crates/disrobe-cli/src/cli/native.rs:1454`
- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/native.rs:2636`
- `"disassembler error in {}: {}"`: `crates/disrobe-pass-native/src/error.rs:38`

### `DR-NATIVE-0011`

- `"cannot create out dir: {}"`: `crates/disrobe-cli/src/cli/native.rs:2647`
- `"native --emit sourcemap: no recoverable DWARF in {}: {}"`: `crates/disrobe-cli/src/cli/native.rs:1458`

### `DR-NATIVE-0030`

- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/native.rs:1684`
- `"{} unpacking refused by its output budget: {}"`: `crates/disrobe-pass-native/src/error.rs:95`

### `DR-NATIVE-0050`

- `"aspack unpack failed: {}"`: `crates/disrobe-cli/src/cli/native.rs:1590`
- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/native.rs:2500`, `crates/disrobe-cli/src/cli/native.rs:3311`

### `DR-NATIVE-0052`

- `"pecompact unpack failed: {}"`: `crates/disrobe-cli/src/cli/native.rs:1599`
- `"serialize: {}"`: `crates/disrobe-cli/src/cli/native.rs:2545`, `crates/disrobe-cli/src/cli/native.rs:3395`, `crates/disrobe-cli/src/cli/native.rs:3446`

### `DR-NATIVE-0053`

- `"cannot write entropy dump: {}"`: `crates/disrobe-cli/src/cli/native.rs:3397`, `crates/disrobe-cli/src/cli/native.rs:3448`
- `"cannot write signatures: {}"`: `crates/disrobe-cli/src/cli/native.rs:2547`

### `DR-NATIVE-0054`

- `"cannot create out dir: {}"`: `crates/disrobe-cli/src/cli/native.rs:3355`
- `"cannot read .sig: {}"`: `crates/disrobe-cli/src/cli/native.rs:2507`
- `` "yoda's crypter recovery is diff-based against the original binary (unpack_yodas_crypter needs both the packed and original images); single-file `native unpack` cannot recover it. detection works on the packed file alone; supply the original for a comparison-based carve." ``: `crates/disrobe-cli/src/cli/native.rs:1608`

### `DR-NATIVE-0055`

- `"FLIRT parse: {}"`: `crates/disrobe-cli/src/cli/native.rs:2509`
- `"cannot write entropy svg: {}"`: `crates/disrobe-cli/src/cli/native.rs:3358`

### `DR-NATIVE-0060`

- `"cannot read input metadata: {}"`: `crates/disrobe-cli/src/cli/native.rs:2045`
- `"cannot read input: allocation of {} bytes failed"`: `crates/disrobe-cli/src/cli/native.rs:2073`, `crates/disrobe-cli/src/cli/native.rs:2082`, `crates/disrobe-cli/src/cli/native.rs:2120`
- `"cannot read input: allocation size overflowed"`: `crates/disrobe-cli/src/cli/native.rs:2116`
- `"cannot read input: configured size limit cannot be represented in memory"`: `crates/disrobe-cli/src/cli/native.rs:2064`
- `"cannot read input: configured size limit overflowed"`: `crates/disrobe-cli/src/cli/native.rs:2068`
- `"cannot read input: file exceeds the {}-byte limit"`: `crates/disrobe-cli/src/cli/native.rs:2053`, `crates/disrobe-cli/src/cli/native.rs:2106`
- `"cannot read input: file size cannot be represented in memory"`: `crates/disrobe-cli/src/cli/native.rs:2059`
- `"cannot read input: file size overflowed"`: `crates/disrobe-cli/src/cli/native.rs:2092`, `crates/disrobe-cli/src/cli/native.rs:2102`
- `"cannot read input: path is not a regular file"`: `crates/disrobe-cli/src/cli/native.rs:2048`
- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/native.rs:2042`, `crates/disrobe-cli/src/cli/native.rs:2097`, `crates/disrobe-cli/src/cli/native.rs:2595`
- `"{} is a managed CLR wrapper; route the image through dotnet.classify for metadata, constants, strings, and IL body recovery"`: `crates/disrobe-cli/src/cli/native.rs:1626`

### `DR-NATIVE-0061`

- `"cannot read .sig: {}"`: `crates/disrobe-cli/src/cli/native.rs:2599`
- `"parse auditable section: {}"`: `crates/disrobe-cli/src/cli/native.rs:1982`

### `DR-NATIVE-0062`

- `"FLIRT parse: {}"`: `crates/disrobe-cli/src/cli/native.rs:2602`
- `"cannot create out dir: {}"`: `crates/disrobe-cli/src/cli/native.rs:2027`

### `DR-NATIVE-0063`

- `"cannot create fingerprint dir: {}"`: `crates/disrobe-cli/src/cli/native.rs:2617`
- `"serialize: {}"`: `crates/disrobe-cli/src/cli/native.rs:2004`, `crates/disrobe-cli/src/cli/native.rs:2019`

### `DR-NATIVE-0064`

- `"cannot write sbom: {}"`: `crates/disrobe-cli/src/cli/native.rs:2030`
- `"serialize: {}"`: `crates/disrobe-cli/src/cli/native.rs:2620`

### `DR-NATIVE-0065`

- `"cannot write fingerprints: {}"`: `crates/disrobe-cli/src/cli/native.rs:2622`
- `"{}"`: `crates/disrobe-cli/src/cli/native.rs:1997`

### `DR-NATIVE-0066`

- `"SPDX 2.3 output requires --timestamp YYYY-MM-DDTHH:MM:SSZ"`: `crates/disrobe-cli/src/cli/native.rs:2009`
- `` "native unpack needs an input file (or `--list` to show supported packers)" ``: `crates/disrobe-cli/src/cli/native.rs:1680`

### `DR-NATIVE-0067`

- `"SPDX 2.3: {}"`: `crates/disrobe-cli/src/cli/native.rs:2014`
- `"document timestamp: {}"`: `crates/disrobe-cli/src/cli/native.rs:1994`

### `DR-NATIVE-0105`

- `"symbol export: {}"`: `crates/disrobe-cli/src/cli/native.rs:1888`, `crates/disrobe-cli/src/cli/native.rs:1890`
- `"symbol-map serialize: {}"`: `crates/disrobe-cli/src/cli/native.rs:1892`

### `DR-NATIVE-0161`

- `"cannot parse native object: {}"`: `crates/disrobe-cli/src/cli/native.rs:202`
- `"{}"`: `crates/disrobe-cli/src/cli/native.rs:3888`

### `DR-NATIVE-0162`

- `"empty --nop-range span"`: `crates/disrobe-cli/src/cli/native.rs:3890`
- `"the in-tree decompiler supports x86-64, aarch64, arm32 and mips32 (got {}); use --backend ghidra for other architectures"`: `crates/disrobe-cli/src/cli/native.rs:206`

### `DR-NATIVE-0163`

- `"cannot create out dir: {}"`: `crates/disrobe-cli/src/cli/native.rs:229`
- `"supply --bytes XX,XX and/or --nop-range A:B"`: `crates/disrobe-cli/src/cli/native.rs:3895`

### `DR-NATIVE-0164`

- `"cannot write decompiled output: {}"`: `crates/disrobe-cli/src/cli/native.rs:418`
- `"patch failed: {}"`: `crates/disrobe-cli/src/cli/native.rs:3900`

### `DR-NATIVE-0165`

- `"cannot create out dir: {}"`: `crates/disrobe-cli/src/cli/native.rs:3911`
- `"serialize manifest: {}"`: `crates/disrobe-cli/src/cli/native.rs:449`

### `DR-NATIVE-0166`

- `"cannot write manifest: {}"`: `crates/disrobe-cli/src/cli/native.rs:451`
- `"cannot write patched image: {}"`: `crates/disrobe-cli/src/cli/native.rs:3914`

### `DR-NATIVE-0167`

- `"serialize recovered types: {}"`: `crates/disrobe-cli/src/cli/native.rs:400`
- `"{}"`: `crates/disrobe-cli/src/cli/native.rs:3883`

### `DR-NATIVE-0170`

- `"cannot create out dir: {}"`: `crates/disrobe-cli/src/cli/native.rs:986`
- `"cannot read input: {}"`: `crates/disrobe-cli/src/cli/native.rs:3935`

### `DR-NATIVE-0171`

- `"cannot write decompiled output: {}"`: `crates/disrobe-cli/src/cli/native.rs:1184`
- `"signature generation failed: {}"`: `crates/disrobe-cli/src/cli/native.rs:3937`

### `DR-NATIVE-0209`

- `"function and stage cannot be combined"`: `crates/disrobe-pass-native/src/native_match.rs:46`
- `` "unsupported stage `{}`; expected data-reference, control-flow, propagation, or refused" ``: `crates/disrobe-python/src/native.rs:67`

### `DR-PYARM-0050`

- `"BCC native body present, lift requires --allow-bcc"`: `crates/disrobe-pass-pyarmor/src/error.rs:119`
- `"permit opt-in in-tree static analysis of embedded BCC native code; it does not execute the sample or invoke external tools; without this flag, BCC protection returns DR-PYARM-0050"`: `crates/disrobe-cli/src/cli/pyarmor.rs:50`

### `DR-WASMDEOB-0001`

- `"boundary links: {}"`: `crates/disrobe-cli/src/cli/wasm.rs:163`
- `"cfg fn {}: {}"`: `crates/disrobe-cli/src/cli/wasm.rs:350`
- `"input is not a valid WebAssembly module: {}"`: `crates/disrobe-pass-wasm-deob/src/error.rs:99`
- `"parse: {}"`: `crates/disrobe-cli/src/cli/wasm.rs:347`
- `"the module could not be printed as WAT: a section does not parse or the code section disagrees with the function section"`: `crates/disrobe-cli/src/cli/wasm.rs:260`
- `"{}"`: `crates/disrobe-cli/src/cli/wasm.rs:159`
- no message: `crates/disrobe-python/src/wasm.rs:55`

## Emitted codes missing from the registry (1626)

- `DR-AS3-0001`: `crates/disrobe-pass-as3/src/error.rs:8`
- `DR-AS3-0002`: `crates/disrobe-pass-as3/src/error.rs:11`
- `DR-AS3-0003`: `crates/disrobe-pass-as3/src/error.rs:14`
- `DR-AS3-0004`: `crates/disrobe-pass-as3/src/error.rs:21`
- `DR-AS3-0005`: `crates/disrobe-pass-as3/src/error.rs:24`
- `DR-AS3-0006`: `crates/disrobe-pass-as3/src/error.rs:27`
- `DR-AS3-0007`: `crates/disrobe-pass-as3/src/error.rs:30`
- `DR-AS3-0010`: `crates/disrobe-pass-as3/src/error.rs:34`
- `DR-AS3-0011`: `crates/disrobe-pass-as3/src/error.rs:38`
- `DR-AS3-0012`: `crates/disrobe-pass-as3/src/error.rs:45`
- `DR-AS3-0013`: `crates/disrobe-pass-as3/src/error.rs:48`
- `DR-AS3-0015`: `crates/disrobe-pass-as3/src/error.rs:55`
- `DR-AS3-0016`: `crates/disrobe-pass-as3/src/error.rs:58`
- `DR-AS3-0017`: `crates/disrobe-pass-as3/src/error.rs:61`
- `DR-AS3-0018`: `crates/disrobe-pass-as3/src/error.rs:65`
- `DR-AS3-0019`: `crates/disrobe-pass-as3/src/error.rs:74`
- `DR-AS3-0020`: `crates/disrobe-pass-as3/src/error.rs:78`
- `DR-AS3-0021`: `crates/disrobe-pass-as3/src/error.rs:81`
- `DR-AS3-0022`: `crates/disrobe-pass-as3/src/error.rs:85`
- `DR-AS3-0902`: `crates/disrobe-pass-as3/src/chain_detector.rs:86`
- `DR-AS3-0904`: `crates/disrobe-pass-as3/src/chain_detector.rs:95`
- `DR-AS3-0905`: `crates/disrobe-pass-as3/src/chain_detector.rs:126`
- `DR-AS3-0906`: `crates/disrobe-pass-as3/src/chain_detector.rs:129`
- `DR-AS3-0907`: `crates/disrobe-pass-as3/src/chain_detector.rs:139`
- `DR-AS3-0908`: `crates/disrobe-pass-as3/src/chain_detector.rs:151`
- `DR-AS3-0909`: `crates/disrobe-pass-as3/src/chain_detector.rs:158`
- `DR-AS3-0910`: `crates/disrobe-pass-as3/src/chain_detector.rs:165`
- `DR-BEAM-0001`: `crates/disrobe-pass-beam/src/error.rs:8`
- `DR-BEAM-0002`: `crates/disrobe-pass-beam/src/error.rs:11`
- `DR-BEAM-0003`: `crates/disrobe-pass-beam/src/error.rs:14`
- `DR-BEAM-0004`: `crates/disrobe-pass-beam/src/error.rs:17`
- `DR-BEAM-0005`: `crates/disrobe-pass-beam/src/error.rs:24`
- `DR-BEAM-0006`: `crates/disrobe-pass-beam/src/error.rs:27`
- `DR-BEAM-0007`: `crates/disrobe-pass-beam/src/error.rs:34`
- `DR-BEAM-0008`: `crates/disrobe-pass-beam/src/error.rs:37`
- `DR-BEAM-0009`: `crates/disrobe-pass-beam/src/error.rs:40`
- `DR-BEAM-0010`: `crates/disrobe-pass-beam/src/error.rs:43`
- `DR-BEAM-0011`: `crates/disrobe-pass-beam/src/error.rs:46`
- `DR-BEAM-0012`: `crates/disrobe-pass-beam/src/error.rs:50`
- `DR-BEAM-0013`: `crates/disrobe-pass-beam/src/error.rs:58`
- `DR-BEAM-0014`: `crates/disrobe-pass-beam/src/error.rs:61`
- `DR-BEAM-0015`: `crates/disrobe-pass-beam/src/error.rs:64`
- `DR-BEAM-0016`: `crates/disrobe-pass-beam/src/error.rs:67`
- `DR-BEAM-0017`: `crates/disrobe-pass-beam/src/error.rs:70`
- `DR-BEAM-0018`: `crates/disrobe-pass-beam/src/error.rs:73`
- `DR-BEAM-0019`: `crates/disrobe-pass-beam/src/error.rs:76`
- `DR-BEAM-0020`: `crates/disrobe-pass-beam/src/error.rs:79`
- `DR-BEAM-0021`: `crates/disrobe-pass-beam/src/error.rs:82`
- `DR-BEAM-0022`: `crates/disrobe-pass-beam/src/error.rs:85`
- `DR-BEAM-0023`: `crates/disrobe-pass-beam/src/error.rs:88`
- `DR-BEAM-0024`: `crates/disrobe-pass-beam/src/error.rs:92`
- `DR-BEAM-0025`: `crates/disrobe-pass-beam/src/error.rs:101`
- `DR-BEAM-0901`: `crates/disrobe-pass-beam/src/chain_detector.rs:79`
- `DR-BEAM-0903`: `crates/disrobe-pass-beam/src/chain_detector.rs:106`
- `DR-BEAM-0904`: `crates/disrobe-pass-beam/src/chain_detector.rs:147`
- `DR-BEAM-0906`: `crates/disrobe-pass-beam/src/chain_detector.rs:162`
- `DR-BEAM-0907`: `crates/disrobe-pass-beam/src/chain_detector.rs:186`
- `DR-BEAM-0908`: `crates/disrobe-pass-beam/src/chain_detector.rs:172`
- `DR-BEAM-0909`: `crates/disrobe-pass-beam/src/chain_detector.rs:176`
- `DR-BEH-0050`: `crates/disrobe-cli/src/cli/behavior.rs:230`
- `DR-BEH-0051`: `crates/disrobe-cli/src/cli/behavior.rs:249`
- `DR-BINFMT-0001`: `crates/disrobe-binfmt/src/error.rs:36`
- `DR-BINFMT-0002`: `crates/disrobe-binfmt/src/error.rs:39`
- `DR-BINFMT-0003`: `crates/disrobe-binfmt/src/error.rs:42`
- `DR-BINFMT-0004`: `crates/disrobe-binfmt/src/error.rs:45`
- `DR-BINFMT-0005`: `crates/disrobe-binfmt/src/error.rs:48`
- `DR-BINFMT-0006`: `crates/disrobe-binfmt/src/error.rs:51`
- `DR-BINFMT-0007`: `crates/disrobe-binfmt/src/error.rs:54`
- `DR-BINFMT-0008`: `crates/disrobe-binfmt/src/error.rs:57`
- `DR-BINFMT-0009`: `crates/disrobe-binfmt/src/error.rs:60`, `crates/disrobe-pass-pyfreeze/src/cxfreeze/library_zip.rs:68`
- `DR-BINFMT-0010`: `crates/disrobe-binfmt/src/error.rs:63`
- `DR-BINFMT-0011`: `crates/disrobe-binfmt/src/error.rs:66`
- `DR-BINFMT-0012`: `crates/disrobe-binfmt/src/error.rs:69`
- `DR-BINFMT-0013`: `crates/disrobe-binfmt/src/error.rs:72`
- `DR-BINFMT-0015`: `crates/disrobe-binfmt/src/error.rs:76`
- `DR-BINFMT-0016`: `crates/disrobe-binfmt/src/error.rs:80`
- `DR-BINFMT-0017`: `crates/disrobe-binfmt/src/error.rs:83`
- `DR-BINFMT-0018`: `crates/disrobe-binfmt/src/error.rs:86`
- `DR-BINFMT-0022`: `crates/disrobe-binfmt/src/error.rs:89`
- `DR-BINFMT-0023`: `crates/disrobe-binfmt/src/error.rs:92`
- `DR-BINFMT-0024`: `crates/disrobe-binfmt/src/error.rs:95`
- `DR-BINFMT-0025`: `crates/disrobe-binfmt/src/error.rs:102`
- `DR-BINFMT-0026`: `crates/disrobe-binfmt/src/error.rs:105`
- `DR-BINFMT-0029`: `crates/disrobe-binfmt/src/error.rs:111`
- `DR-BINFMT-0030`: `crates/disrobe-binfmt/src/error.rs:114`
- `DR-BINFMT-0031`: `crates/disrobe-binfmt/src/error.rs:117`
- `DR-BINFMT-0032`: `crates/disrobe-binfmt/src/error.rs:120`
- `DR-BINFMT-0033`: `crates/disrobe-binfmt/src/error.rs:123`
- `DR-BINFMT-0034`: `crates/disrobe-binfmt/src/error.rs:126`
- `DR-BINFMT-0035`: `crates/disrobe-binfmt/src/error.rs:129`
- `DR-BINFMT-0036`: `crates/disrobe-binfmt/src/error.rs:132`
- `DR-BINFMT-0037`: `crates/disrobe-binfmt/src/error.rs:135`
- `DR-BINFMT-0038`: `crates/disrobe-binfmt/src/error.rs:138`
- `DR-BINFMT-0039`: `crates/disrobe-binfmt/src/error.rs:141`
- `DR-BINFMT-0040`: `crates/disrobe-binfmt/src/error.rs:144`
- `DR-BINFMT-0042`: `crates/disrobe-binfmt/src/error.rs:147`
- `DR-BINFMT-0043`: `crates/disrobe-binfmt/src/error.rs:150`
- `DR-BINFMT-0044`: `crates/disrobe-binfmt/src/error.rs:153`
- `DR-BINFMT-0045`: `crates/disrobe-binfmt/src/error.rs:156`
- `DR-BINFMT-0046`: `crates/disrobe-binfmt/src/error.rs:159`
- `DR-BINFMT-0047`: `crates/disrobe-binfmt/src/error.rs:162`
- `DR-BINFMT-0048`: `crates/disrobe-binfmt/src/error.rs:165`
- `DR-BINFMT-0049`: `crates/disrobe-binfmt/src/error.rs:168`
- `DR-BINFMT-0050`: `crates/disrobe-binfmt/src/error.rs:171`
- `DR-BINFMT-0051`: `crates/disrobe-binfmt/src/error.rs:174`
- `DR-BINFMT-0052`: `crates/disrobe-binfmt/src/error.rs:177`
- `DR-BINFMT-0053`: `crates/disrobe-binfmt/src/error.rs:180`
- `DR-BINFMT-0054`: `crates/disrobe-binfmt/src/error.rs:183`
- `DR-BINFMT-0055`: `crates/disrobe-binfmt/src/error.rs:186`
- `DR-BINFMT-0056`: `crates/disrobe-binfmt/src/error.rs:189`
- `DR-BINFMT-0057`: `crates/disrobe-binfmt/src/error.rs:192`
- `DR-BINFMT-0058`: `crates/disrobe-binfmt/src/error.rs:195`
- `DR-BINFMT-0059`: `crates/disrobe-binfmt/src/error.rs:198`
- `DR-BINFMT-0060`: `crates/disrobe-binfmt/src/error.rs:201`
- `DR-BINFMT-0061`: `crates/disrobe-binfmt/src/error.rs:204`
- `DR-BINFMT-0062`: `crates/disrobe-binfmt/src/error.rs:207`
- `DR-BINFMT-0063`: `crates/disrobe-binfmt/src/error.rs:210`
- `DR-BINFMT-0064`: `crates/disrobe-binfmt/src/error.rs:213`
- `DR-BINFMT-0069`: `crates/disrobe-binfmt/src/error.rs:228`
- `DR-BINFMT-0070`: `crates/disrobe-binfmt/src/error.rs:231`
- `DR-BINFMT-0071`: `crates/disrobe-binfmt/src/error.rs:234`
- `DR-BINFMT-0072`: `crates/disrobe-binfmt/src/error.rs:237`
- `DR-BINFMT-0073`: `crates/disrobe-binfmt/src/error.rs:240`
- `DR-BINFMT-0074`: `crates/disrobe-binfmt/src/error.rs:246`
- `DR-BINFMT-0075`: `crates/disrobe-binfmt/src/error.rs:250`
- `DR-BINFMT-0076`: `crates/disrobe-binfmt/src/error.rs:8`
- `DR-BINFMT-0077`: `crates/disrobe-binfmt/src/error.rs:10`
- `DR-BINFMT-0078`: `crates/disrobe-binfmt/src/error.rs:12`
- `DR-BINFMT-0079`: `crates/disrobe-binfmt/src/error.rs:15`
- `DR-BINFMT-0080`: `crates/disrobe-binfmt/src/error.rs:18`
- `DR-BINFMT-0081`: `crates/disrobe-binfmt/src/error.rs:20`
- `DR-BINFMT-0082`: `crates/disrobe-binfmt/src/error.rs:22`
- `DR-BINFMT-0083`: `crates/disrobe-binfmt/src/error.rs:24`
- `DR-BINFMT-0084`: `crates/disrobe-binfmt/src/error.rs:26`
- `DR-BINFMT-0085`: `crates/disrobe-binfmt/src/error.rs:29`
- `DR-BINFMT-0086`: `crates/disrobe-binfmt/src/error.rs:33`
- `DR-BINFMT-0901`: `crates/disrobe-binfmt/src/chain_detector.rs:394`, `crates/disrobe-binfmt/src/chain_detector.rs:399`
- `DR-BINFMT-0903`: `crates/disrobe-binfmt/src/chain_detector.rs:365`
- `DR-BINFMT-0904`: `crates/disrobe-binfmt/src/chain_detector.rs:89`
- `DR-BINFMT-0905`: `crates/disrobe-binfmt/src/chain_detector.rs:96`
- `DR-BINFMT-0906`: `crates/disrobe-binfmt/src/chain_detector.rs:100`
- `DR-BINFMT-0907`: `crates/disrobe-binfmt/src/chain_detector.rs:211`
- `DR-BINFMT-0908`: `crates/disrobe-binfmt/src/chain_detector.rs:182`
- `DR-BINFMT-0960`: `crates/disrobe-binfmt/src/chain_detector.rs:768`
- `DR-CATALOG-0001`: `crates/disrobe-cli/src/cli/catalog.rs:40`
- `DR-CATALOG-0002`: `crates/disrobe-cli/src/cli/catalog.rs:52`
- `DR-CLI-0023`: `crates/disrobe-cli/src/cli/nuitka.rs:139`, `crates/disrobe-cli/src/cli/pyarmor.rs:443`
- `DR-CLI-0024`: `crates/disrobe-cli/src/cli/nuitka.rs:201`, `crates/disrobe-cli/src/cli/pyarmor.rs:463`
- `DR-CLI-0025`: `crates/disrobe-cli/src/cli/pyarmor.rs:480`
- `DR-CLI-0026`: `crates/disrobe-cli/src/cli/nuitka.rs:239`, `crates/disrobe-cli/src/cli/nuitka.rs:994`, `crates/disrobe-cli/src/cli/pyarmor.rs:366`
- `DR-CLI-0027`: `crates/disrobe-cli/src/cli/nuitka.rs:241`, `crates/disrobe-cli/src/cli/nuitka.rs:997`, `crates/disrobe-cli/src/cli/pyarmor.rs:372`
- `DR-CLI-0028`: `crates/disrobe-cli/src/cli/nuitka.rs:243`, `crates/disrobe-cli/src/cli/nuitka.rs:999`, `crates/disrobe-cli/src/cli/pyarmor.rs:378`
- `DR-CLI-0029`: `crates/disrobe-cli/src/cli/nuitka.rs:981`
- `DR-CLI-0045`: `crates/disrobe-cli/src/cli/js.rs:1424`, `crates/disrobe-cli/src/cli/js.rs:1518`, `crates/disrobe-cli/src/cli/js.rs:1673`, `crates/disrobe-cli/src/cli/nuitka.rs:546`, `crates/disrobe-cli/src/cli/wasm.rs:421`
- `DR-CLI-0046`: `crates/disrobe-cli/src/cli/js.rs:1427`, `crates/disrobe-cli/src/cli/js.rs:1521`, `crates/disrobe-cli/src/cli/js.rs:1675`, `crates/disrobe-cli/src/cli/nuitka.rs:548`, `crates/disrobe-cli/src/cli/wasm.rs:149`
- `DR-CLI-0047`: `crates/disrobe-cli/src/cli/js.rs:1441`, `crates/disrobe-cli/src/cli/js.rs:1535`, `crates/disrobe-cli/src/cli/js.rs:1701`, `crates/disrobe-cli/src/cli/nuitka.rs:564`, `crates/disrobe-cli/src/cli/pyarmor.rs:158`, `crates/disrobe-cli/src/cli/wasm.rs:50`
- `DR-CLI-0048`: `crates/disrobe-cli/src/cli/js.rs:1443`, `crates/disrobe-cli/src/cli/js.rs:1537`, `crates/disrobe-cli/src/cli/js.rs:1705`, `crates/disrobe-cli/src/cli/nuitka.rs:566`, `crates/disrobe-cli/src/cli/wasm.rs:57`
- `DR-CLI-0049`: `crates/disrobe-cli/src/cli/js.rs:1708`, `crates/disrobe-cli/src/cli/nuitka.rs:568`, `crates/disrobe-cli/src/cli/wasm.rs:62`
- `DR-CLI-0056`: `crates/disrobe-cli/src/cli/js.rs:1747`, `crates/disrobe-cli/src/cli/py/disasm.rs:47`
- `DR-CLI-0057`: `crates/disrobe-cli/src/cli/js.rs:1752`
- `DR-CLI-0058`: `crates/disrobe-cli/src/cli/js.rs:1825`
- `DR-CLI-0059`: `crates/disrobe-cli/src/cli/js.rs:1828`
- `DR-CLI-0063`: `crates/disrobe-cli/src/cli/js.rs:695`, `crates/disrobe-cli/src/cli/py/decompile.rs:97`, `crates/disrobe-cli/src/cli/py/decompile.rs:196`
- `DR-CLI-0064`: `crates/disrobe-cli/src/cli/js.rs:710`, `crates/disrobe-cli/src/cli/py/decompile.rs:99`, `crates/disrobe-cli/src/cli/py/decompile.rs:198`
- `DR-CLI-0065`: `crates/disrobe-cli/src/cli/js.rs:722`, `crates/disrobe-cli/src/cli/py/decompile.rs:252`
- `DR-CLI-0066`: `crates/disrobe-cli/src/cli/js.rs:726`, `crates/disrobe-cli/src/cli/py/decompile.rs:32`
- `DR-CLI-0067`: `crates/disrobe-cli/src/cli/js.rs:739`, `crates/disrobe-cli/src/cli/py/decompile.rs:55`
- `DR-CLI-0068`: `crates/disrobe-cli/src/cli/js.rs:742`, `crates/disrobe-cli/src/cli/py/decompile.rs:177`
- `DR-CLI-0069`: `crates/disrobe-cli/src/cli/js.rs:761`
- `DR-CLI-0070`: `crates/disrobe-cli/src/cli/js.rs:763`, `crates/disrobe-cli/src/cli/py/extract.rs:6`
- `DR-CLI-0071`: `crates/disrobe-cli/src/cli/js.rs:799`, `crates/disrobe-cli/src/cli/py/extract.rs:14`
- `DR-CLI-0072`: `crates/disrobe-cli/src/cli/js.rs:822`, `crates/disrobe-cli/src/cli/py/extract.rs:18`
- `DR-CLI-0073`: `crates/disrobe-cli/src/cli/js.rs:831`, `crates/disrobe-cli/src/cli/py/extract.rs:24`
- `DR-CLI-0074`: `crates/disrobe-cli/src/cli/js.rs:835`, `crates/disrobe-cli/src/cli/py/extract.rs:42`
- `DR-CLI-0075`: `crates/disrobe-cli/src/cli/js.rs:852`, `crates/disrobe-cli/src/cli/py/extract.rs:44`
- `DR-CLI-0076`: `crates/disrobe-cli/src/cli/js.rs:864`
- `DR-CLI-0077`: `crates/disrobe-cli/src/cli/js.rs:872`
- `DR-CLI-0078`: `crates/disrobe-cli/src/cli/js.rs:893`
- `DR-CLI-0079`: `crates/disrobe-cli/src/cli/js.rs:898`
- `DR-CLI-0095`: `crates/disrobe-cli/src/cli/js.rs:265`
- `DR-CLI-0096`: `crates/disrobe-cli/src/cli/js.rs:272`
- `DR-CLI-0097`: `crates/disrobe-cli/src/cli/js.rs:276`
- `DR-CLI-0098`: `crates/disrobe-cli/src/cli/js.rs:303`
- `DR-CLI-0099`: `crates/disrobe-cli/src/cli/js.rs:310`
- `DR-CLI-0103`: `crates/disrobe-cli/src/cli/js.rs:357`
- `DR-CLI-0104`: `crates/disrobe-cli/src/cli/js.rs:364`
- `DR-CLI-0105`: `crates/disrobe-cli/src/cli/js.rs:387`
- `DR-CLI-0106`: `crates/disrobe-cli/src/cli/js.rs:435`
- `DR-CLI-0107`: `crates/disrobe-cli/src/cli/js.rs:443`
- `DR-CLI-0108`: `crates/disrobe-cli/src/cli/js.rs:231`, `crates/disrobe-cli/src/cli/js.rs:236`
- `DR-CLI-0109`: `crates/disrobe-cli/src/cli/js.rs:351`
- `DR-CLI-0114`: `crates/disrobe-cli/src/cli/init.rs:409`
- `DR-CLI-0115`: `crates/disrobe-cli/src/cli/init.rs:359`, `crates/disrobe-cli/src/cli/init.rs:371`
- `DR-CLI-0160`: `crates/disrobe-cli/src/cli/emit.rs:166`, `crates/disrobe-cli/src/cli/emit.rs:190`
- `DR-CLI-0161`: `crates/disrobe-cli/src/cli/emit.rs:176`, `crates/disrobe-cli/src/cli/emit.rs:193`
- `DR-CLI-0162`: `crates/disrobe-cli/src/cli/emit.rs:178`, `crates/disrobe-cli/src/cli/emit.rs:195`
- `DR-CLI-0163`: `crates/disrobe-cli/src/cli/emit.rs:136`
- `DR-CLI-0164`: `crates/disrobe-cli/src/cli/auto.rs:58`
- `DR-CLI-0171`: `crates/disrobe-cli/src/cli/serve/mod.rs:47`
- `DR-CLI-0172`: `crates/disrobe-cli/src/cli/serve/mod.rs:51`
- `DR-CLI-0173`: `crates/disrobe-cli/src/cli/serve/mod.rs:161`
- `DR-CLI-0174`: `crates/disrobe-cli/src/cli/serve/mod.rs:190`
- `DR-CLI-0175`: `crates/disrobe-cli/src/cli/serve/mod.rs:128`
- `DR-CLI-0181`: `crates/disrobe-cli/src/cli/serve/util.rs:32`
- `DR-CLI-0182`: `crates/disrobe-cli/src/cli/grpc.rs:251`, `crates/disrobe-cli/src/cli/serve/util.rs:26`
- `DR-CLI-0184`: `crates/disrobe-cli/src/cli/grpc.rs:95`, `crates/disrobe-cli/src/cli/serve/handlers.rs:262`
- `DR-CLI-0186`: `crates/disrobe-cli/src/cli/grpc.rs:131`, `crates/disrobe-cli/src/cli/serve/handlers.rs:316`
- `DR-CLI-0187`: `crates/disrobe-cli/src/cli/grpc.rs:145`, `crates/disrobe-cli/src/cli/serve/handlers.rs:329`
- `DR-CLI-0188`: `crates/disrobe-cli/src/cli/grpc.rs:150`, `crates/disrobe-cli/src/cli/serve/handlers.rs:335`
- `DR-CLI-0189`: `crates/disrobe-cli/src/cli/serve/ws.rs:34`
- `DR-CLI-0201`: `crates/disrobe-cli/src/cli/serve/lsp.rs:28`
- `DR-CLI-0202`: `crates/disrobe-cli/src/cli/serve/lsp.rs:31`
- `DR-CLI-0203`: `crates/disrobe-cli/src/cli/serve/lsp.rs:48`
- `DR-CLI-0210`: `crates/disrobe-cli/src/cli/serve/lsp.rs:75`
- `DR-CLI-0211`: `crates/disrobe-cli/src/cli/serve/lsp.rs:91`
- `DR-CLI-0212`: `crates/disrobe-cli/src/cli/serve/lsp.rs:102`
- `DR-CLI-0220`: `crates/disrobe-cli/src/cli/grpc.rs:236`
- `DR-CLI-0221`: `crates/disrobe-cli/src/cli/grpc.rs:243`
- `DR-CLI-0222`: `crates/disrobe-cli/src/cli/serve/mod.rs:63`
- `DR-CLI-0223`: `crates/disrobe-cli/src/cli/serve/mod.rs:64`
- `DR-CLI-0230`: `crates/disrobe-cli/src/cli/path_ops.rs:36`
- `DR-CLI-0231`: `crates/disrobe-cli/src/cli/path_ops.rs:24`, `crates/disrobe-cli/src/cli/path_ops.rs:89`
- `DR-CLI-0232`: `crates/disrobe-cli/src/cli/path_ops.rs:95`
- `DR-CLI-0233`: `crates/disrobe-cli/src/cli/path_ops.rs:98`
- `DR-CLI-0234`: `crates/disrobe-cli/src/cli/path_ops.rs:106`
- `DR-CLI-0235`: `crates/disrobe-cli/src/cli/path_ops.rs:108`
- `DR-CLI-0236`: `crates/disrobe-cli/src/cli/path_ops.rs:111`
- `DR-CLI-0237`: `crates/disrobe-cli/src/cli/path_ops.rs:118`
- `DR-CLI-0238`: `crates/disrobe-cli/src/cli/path_ops.rs:126`
- `DR-CLI-0239`: `crates/disrobe-cli/src/cli/path_ops.rs:130`
- `DR-CLI-0240`: `crates/disrobe-cli/src/cli/path_ops.rs:138`
- `DR-CLI-0250`: `crates/disrobe-cli/src/cli/install_deps.rs:98`
- `DR-CLI-0251`: `crates/disrobe-cli/src/cli/install_deps.rs:112`
- `DR-CLI-0252`: `crates/disrobe-cli/src/cli/install_deps.rs:117`
- `DR-CLI-0253`: `crates/disrobe-cli/src/cli/install_deps.rs:122`
- `DR-CLI-0254`: `crates/disrobe-cli/src/cli/install_deps.rs:208`
- `DR-CLI-0255`: `crates/disrobe-cli/src/cli/install_deps.rs:213`
- `DR-CLI-0256`: `crates/disrobe-cli/src/cli/install_deps.rs:216`
- `DR-CLI-0257`: `crates/disrobe-cli/src/cli/install_deps.rs:221`
- `DR-CLI-0258`: `crates/disrobe-cli/src/cli/install_deps.rs:254`
- `DR-CLI-0259`: `crates/disrobe-cli/src/cli/install_deps.rs:258`
- `DR-CLI-0260`: `crates/disrobe-cli/src/cli/install_deps.rs:261`
- `DR-CLI-0261`: `crates/disrobe-cli/src/cli/install_deps.rs:306`
- `DR-CLI-0262`: `crates/disrobe-cli/src/cli/install_deps.rs:339`
- `DR-CLI-0263`: `crates/disrobe-cli/src/cli/install_deps.rs:351`
- `DR-CLI-0264`: `crates/disrobe-cli/src/cli/install_deps.rs:375`
- `DR-CLI-0265`: `crates/disrobe-cli/src/cli/install_deps.rs:380`
- `DR-CLI-0266`: `crates/disrobe-cli/src/cli/install_deps.rs:384`
- `DR-CLI-0267`: `crates/disrobe-cli/src/cli/install_deps.rs:397`
- `DR-CLI-0268`: `crates/disrobe-cli/src/cli/install_deps.rs:106`
- `DR-CLI-0269`: `crates/disrobe-cli/src/cli/self_update.rs:45`
- `DR-CLI-0270`: `crates/disrobe-cli/src/cli/install/mod.rs:120`
- `DR-CLI-0271`: `crates/disrobe-cli/src/main.rs:2197`
- `DR-CLI-0290`: `crates/disrobe-cli/src/main.rs:2161`
- `DR-CLI-0291`: `crates/disrobe-cli/src/cli/chain_v1.rs:612`, `crates/disrobe-cli/src/cli/chain_v1.rs:1320`
- `DR-CLI-0292`: `crates/disrobe-cli/src/cli/chain_v1.rs:616`, `crates/disrobe-cli/src/cli/chain_v1.rs:628`
- `DR-CLI-0293`: `crates/disrobe-cli/src/cli/chain_v1.rs:651`, `crates/disrobe-cli/src/cli/chain_v1.rs:758`, `crates/disrobe-cli/src/cli/chain_v1.rs:1379`
- `DR-CLI-0294`: `crates/disrobe-cli/src/cli/chain_v1.rs:761`, `crates/disrobe-cli/src/cli/chain_v1.rs:1381`
- `DR-CLI-0295`: `crates/disrobe-cli/src/cli/chain_v1.rs:763`, `crates/disrobe-cli/src/cli/chain_v1.rs:1383`
- `DR-CLI-0296`: `crates/disrobe-cli/src/cli/chain_v1.rs:1600`
- `DR-CLI-0297`: `crates/disrobe-cli/src/cli/chain_v1.rs:1604`
- `DR-CLI-0298`: `crates/disrobe-cli/src/cli/chain_v1.rs:1588`
- `DR-CLI-0299`: `crates/disrobe-cli/src/cli/chain_v1.rs:167`
- `DR-CLI-0301`: `crates/disrobe-cli/src/cli/chain_v1.rs:1541`
- `DR-CLI-0302`: `crates/disrobe-cli/src/cli/chain_v1.rs:1548`
- `DR-CLI-0305`: `crates/disrobe-cli/src/cli/chain_v1.rs:766`, `crates/disrobe-cli/src/cli/chain_v1.rs:1385`
- `DR-CLI-0306`: `crates/disrobe-cli/src/cli/chain_v1.rs:768`, `crates/disrobe-cli/src/cli/chain_v1.rs:1387`
- `DR-CLI-0307`: `crates/disrobe-cli/src/cli/chain_v1.rs:772`, `crates/disrobe-cli/src/cli/chain_v1.rs:1389`
- `DR-CLI-0308`: `crates/disrobe-cli/src/cli/chain_v1.rs:774`, `crates/disrobe-cli/src/cli/chain_v1.rs:1391`
- `DR-CLI-0309`: `crates/disrobe-cli/src/cli/chain_materialization.rs:67`, `crates/disrobe-cli/src/cli/chain_materialization.rs:227`, `crates/disrobe-cli/src/cli/chain_materialization.rs:235`, `crates/disrobe-cli/src/cli/chain_materialization.rs:241`, `crates/disrobe-cli/src/cli/chain_materialization.rs:251`, `crates/disrobe-cli/src/cli/chain_materialization.rs:257`, `crates/disrobe-cli/src/cli/chain_materialization.rs:263`, `crates/disrobe-cli/src/cli/chain_materialization.rs:266`, `crates/disrobe-cli/src/cli/chain_materialization.rs:270`
- `DR-CLI-0310`: `crates/disrobe-cli/src/cli/chain_compare.rs:37`, `crates/disrobe-cli/src/cli/chain_materialization.rs:55`, `crates/disrobe-cli/src/cli/chain_materialization.rs:75`, `crates/disrobe-cli/src/cli/chain_materialization.rs:82`, `crates/disrobe-cli/src/cli/chain_materialization.rs:149`, `crates/disrobe-cli/src/cli/chain_materialization.rs:186`, `crates/disrobe-cli/src/cli/chain_materialization.rs:198`, `crates/disrobe-cli/src/cli/chain_materialization.rs:210`, `crates/disrobe-cli/src/cli/chain_materialization.rs:285`
- `DR-CLI-0311`: `crates/disrobe-cli/src/cli/chain_compare.rs:43`
- `DR-CLI-0313`: `crates/disrobe-cli/src/cli/chain_compare.rs:216`
- `DR-CLI-0314`: `crates/disrobe-cli/src/cli/chain_v1.rs:781`
- `DR-CLI-0315`: `crates/disrobe-cli/src/cli/chain_v1.rs:783`
- `DR-CLI-0316`: `crates/disrobe-cli/src/cli/chain_v1.rs:1298`
- `DR-CLI-0317`: `crates/disrobe-cli/src/cli/chain_v1.rs:1300`
- `DR-CLI-0318`: `crates/disrobe-cli/src/cli/util.rs:33`
- `DR-CLI-0319`: `crates/disrobe-cli/src/cli/context.rs:72`, `crates/disrobe-cli/src/cli/context.rs:81`
- `DR-CLI-0322`: `crates/disrobe-cli/src/cli/annot.rs:35`, `crates/disrobe-cli/src/cli/context.rs:127`
- `DR-CLI-0323`: `crates/disrobe-cli/src/cli/annot.rs:39`, `crates/disrobe-cli/src/cli/context.rs:164`
- `DR-CLI-0324`: `crates/disrobe-cli/src/cli/annot.rs:52`, `crates/disrobe-cli/src/cli/annot.rs:89`, `crates/disrobe-cli/src/cli/annot.rs:120`, `crates/disrobe-cli/src/cli/context.rs:186`
- `DR-CLI-0325`: `crates/disrobe-cli/src/cli/annot.rs:64`, `crates/disrobe-cli/src/cli/context.rs:145`
- `DR-CLI-0326`: `crates/disrobe-cli/src/cli/annot.rs:68`, `crates/disrobe-cli/src/main.rs:2145`
- `DR-CLI-0327`: `crates/disrobe-cli/src/cli/annot.rs:71`, `crates/disrobe-cli/src/main.rs:1857`
- `DR-CLI-0328`: `crates/disrobe-cli/src/cli/annot.rs:81`, `crates/disrobe-cli/src/cli/install_deps.rs:227`
- `DR-CLI-0329`: `crates/disrobe-cli/src/cli/annot.rs:107`, `crates/disrobe-cli/src/cli/annot.rs:131`, `crates/disrobe-cli/src/cli/annot.rs:150`, `crates/disrobe-cli/src/cli/install_deps.rs:277`
- `DR-CLI-0330`: `crates/disrobe-cli/src/cli/config.rs:145`, `crates/disrobe-cli/src/cli/rename.rs:54`
- `DR-CLI-0331`: `crates/disrobe-cli/src/cli/config.rs:154`, `crates/disrobe-cli/src/cli/rename.rs:67`
- `DR-CLI-0332`: `crates/disrobe-cli/src/cli/config.rs:189`, `crates/disrobe-cli/src/cli/rename.rs:71`
- `DR-CLI-0333`: `crates/disrobe-cli/src/cli/config.rs:200`, `crates/disrobe-cli/src/cli/rename.rs:77`
- `DR-CLI-0334`: `crates/disrobe-cli/src/cli/config.rs:278`, `crates/disrobe-cli/src/cli/rename.rs:88`
- `DR-CLI-0335`: `crates/disrobe-cli/src/cli/config.rs:287`, `crates/disrobe-cli/src/cli/rename.rs:90`
- `DR-CLI-0336`: `crates/disrobe-cli/src/cli/config.rs:294`
- `DR-CLI-0337`: `crates/disrobe-cli/src/main.rs:1703`
- `DR-CLI-0340`: `crates/disrobe-cli/src/cli/batch.rs:405`
- `DR-CLI-0341`: `crates/disrobe-cli/src/cli/batch.rs:418`
- `DR-CLI-0342`: `crates/disrobe-cli/src/cli/batch.rs:420`
- `DR-CLI-0343`: `crates/disrobe-cli/src/cli/batch.rs:490`
- `DR-CLI-0344`: `crates/disrobe-cli/src/cli/batch.rs:508`
- `DR-CLI-0345`: `crates/disrobe-cli/src/cli/batch.rs:509`
- `DR-CLI-0346`: `crates/disrobe-cli/src/cli/auto.rs:71`
- `DR-CLI-0350`: `crates/disrobe-cli/src/cli/report.rs:1205`
- `DR-CLI-0351`: `crates/disrobe-cli/src/cli/report.rs:1078`
- `DR-CLI-0352`: `crates/disrobe-cli/src/cli/report.rs:1081`
- `DR-CLI-0353`: `crates/disrobe-cli/src/cli/report.rs:1090`
- `DR-CLI-0354`: `crates/disrobe-cli/src/cli/report.rs:1093`
- `DR-CLI-0355`: `crates/disrobe-cli/src/cli/report.rs:1102`
- `DR-CLI-0356`: `crates/disrobe-cli/src/cli/report.rs:1105`
- `DR-CLI-0357`: `crates/disrobe-cli/src/cli/report.rs:1738`, `crates/disrobe-cli/src/cli/report.rs:1743`, `crates/disrobe-cli/src/cli/report.rs:1746`
- `DR-CLI-0358`: `crates/disrobe-cli/src/cli/report.rs:1180`
- `DR-CLI-0359`: `crates/disrobe-cli/src/cli/report_forensic.rs:1044`
- `DR-CLI-0360`: `crates/disrobe-cli/src/cli/report.rs:1067`, `crates/disrobe-cli/src/cli/report.rs:1071`
- `DR-CLI-0361`: `crates/disrobe-cli/src/cli/report.rs:1060`, `crates/disrobe-cli/src/cli/report.rs:1684`, `crates/disrobe-cli/src/cli/report.rs:1741`, `crates/disrobe-cli/src/cli/report.rs:1756`
- `DR-CLI-0362`: `crates/disrobe-cli/src/cli/chain_v1.rs:1035`, `crates/disrobe-cli/src/cli/chain_v1.rs:1430`
- `DR-CLI-0363`: `crates/disrobe-cli/src/cli/chain_v1.rs:1048`, `crates/disrobe-cli/src/cli/chain_v1.rs:1436`
- `DR-CLI-0364`: `crates/disrobe-cli/src/cli/chain_v1.rs:1447`
- `DR-CLI-0365`: `crates/disrobe-cli/src/cli/chain_v1.rs:1461`
- `DR-CLI-0366`: `crates/disrobe-cli/src/cli/chain_v1.rs:1194`
- `DR-CLI-0400`: `crates/disrobe-cli/src/cli/jvm.rs:1262`
- `DR-CLI-0401`: `crates/disrobe-cli/src/cli/jvm.rs:1286`
- `DR-CLI-0402`: `crates/disrobe-cli/src/cli/jvm.rs:1297`
- `DR-CLI-0403`: `crates/disrobe-cli/src/cli/jvm.rs:1316`
- `DR-CLI-0404`: `crates/disrobe-cli/src/cli/jvm.rs:1342`
- `DR-CLI-0405`: `crates/disrobe-cli/src/cli/jvm.rs:1370`
- `DR-CLI-0406`: `crates/disrobe-cli/src/cli/jvm.rs:1376`
- `DR-CLI-0407`: `crates/disrobe-cli/src/cli/jvm.rs:1378`
- `DR-CLI-0408`: `crates/disrobe-cli/src/cli/jvm.rs:1749`, `crates/disrobe-cli/src/cli/jvm.rs:1777`
- `DR-CLI-0409`: `crates/disrobe-cli/src/cli/dotnet.rs:1141`, `crates/disrobe-cli/src/cli/jvm.rs:1757`, `crates/disrobe-cli/src/cli/jvm.rs:1785`
- `DR-CLI-0410`: `crates/disrobe-cli/src/cli/jvm.rs:1564`, `crates/disrobe-cli/src/cli/llm.rs:242`, `crates/disrobe-cli/src/cli/llm.rs:256`
- `DR-CLI-0411`: `crates/disrobe-cli/src/cli/jvm.rs:1580`
- `DR-CLI-0412`: `crates/disrobe-cli/src/cli/jvm.rs:1582`
- `DR-CLI-0413`: `crates/disrobe-cli/src/cli/jvm.rs:1587`
- `DR-CLI-0414`: `crates/disrobe-cli/src/cli/jvm.rs:1593`
- `DR-CLI-0415`: `crates/disrobe-cli/src/cli/jvm.rs:1606`
- `DR-CLI-0416`: `crates/disrobe-cli/src/cli/jvm.rs:1604`
- `DR-CLI-0420`: `crates/disrobe-cli/src/cli/jvm.rs:554`, `crates/disrobe-cli/src/cli/jvm.rs:1704`, `crates/disrobe-cli/src/cli/jvm.rs:2183`, `crates/disrobe-cli/src/cli/llm.rs:274`
- `DR-CLI-0421`: `crates/disrobe-cli/src/cli/jvm.rs:556`, `crates/disrobe-cli/src/cli/jvm.rs:1732`, `crates/disrobe-cli/src/cli/jvm.rs:2188`
- `DR-CLI-0422`: `crates/disrobe-cli/src/cli/jvm.rs:1115`, `crates/disrobe-cli/src/cli/jvm.rs:2163`
- `DR-CLI-0423`: `crates/disrobe-cli/src/cli/jvm.rs:1117`, `crates/disrobe-cli/src/cli/jvm.rs:2230`
- `DR-CLI-0424`: `crates/disrobe-cli/src/cli/jvm.rs:2234`
- `DR-CLI-0425`: `crates/disrobe-cli/src/cli/jvm.rs:529`
- `DR-CLI-0430`: `crates/disrobe-cli/src/cli/dotnet.rs:317`, `crates/disrobe-cli/src/cli/jvm.rs:1181`, `crates/disrobe-cli/src/cli/llm.rs:374`
- `DR-CLI-0431`: `crates/disrobe-cli/src/cli/dotnet.rs:346`, `crates/disrobe-cli/src/cli/jvm.rs:1184`, `crates/disrobe-cli/src/cli/llm.rs:338`
- `DR-CLI-0432`: `crates/disrobe-cli/src/cli/dotnet.rs:348`, `crates/disrobe-cli/src/cli/jvm.rs:1189`, `crates/disrobe-cli/src/cli/llm.rs:384`
- `DR-CLI-0433`: `crates/disrobe-cli/src/cli/jvm.rs:1238`
- `DR-CLI-0434`: `crates/disrobe-cli/src/cli/dotnet.rs:379`, `crates/disrobe-cli/src/cli/jvm.rs:1240`
- `DR-CLI-0435`: `crates/disrobe-cli/src/cli/dotnet.rs:967`, `crates/disrobe-cli/src/cli/jvm.rs:1273`
- `DR-CLI-0436`: `crates/disrobe-cli/src/cli/dotnet.rs:377`, `crates/disrobe-cli/src/cli/jvm.rs:1882`, `crates/disrobe-cli/src/cli/jvm.rs:1884`, `crates/disrobe-cli/src/cli/jvm.rs:1886`
- `DR-CLI-0437`: `crates/disrobe-cli/src/cli/dotnet.rs:949`
- `DR-CLI-0438`: `crates/disrobe-cli/src/cli/backend_export.rs:88`, `crates/disrobe-cli/src/cli/backend_export.rs:96`, `crates/disrobe-cli/src/cli/backend_export.rs:110`
- `DR-CLI-0439`: `crates/disrobe-cli/src/cli/backend_export.rs:116`
- `DR-CLI-0440`: `crates/disrobe-cli/src/cli/backend_export.rs:122`, `crates/disrobe-cli/src/cli/dotnet.rs:973`, `crates/disrobe-cli/src/cli/jvm.rs:1492`, `crates/disrobe-cli/src/cli/llm.rs:308`, `crates/disrobe-cli/src/cli/llm.rs:363`, `crates/disrobe-cli/src/cli/llm.rs:369`
- `DR-CLI-0441`: `crates/disrobe-cli/src/cli/auto.rs:50`, `crates/disrobe-cli/src/cli/chain_v1.rs:586`, `crates/disrobe-cli/src/cli/dotnet.rs:975`, `crates/disrobe-cli/src/cli/jvm.rs:1494`
- `DR-CLI-0442`: `crates/disrobe-cli/src/cli/chain_v1.rs:569`, `crates/disrobe-cli/src/cli/dotnet.rs:985`, `crates/disrobe-cli/src/cli/jvm.rs:1518`
- `DR-CLI-0443`: `crates/disrobe-cli/src/cli/chain_v1.rs:573`, `crates/disrobe-cli/src/cli/dotnet.rs:988`, `crates/disrobe-cli/src/cli/jvm.rs:1520`
- `DR-CLI-0444`: `crates/disrobe-cli/src/cli/batch.rs:125`, `crates/disrobe-cli/src/cli/dotnet.rs:990`
- `DR-CLI-0445`: `crates/disrobe-cli/src/cli/chain_v1.rs:528`
- `DR-CLI-0446`: `crates/disrobe-cli/src/cli/auto.rs:66`, `crates/disrobe-cli/src/cli/chain_v1.rs:519`
- `DR-CLI-0447`: `crates/disrobe-cli/src/cli/chain_v1.rs:550`
- `DR-CLI-0450`: `crates/disrobe-cli/src/cli/dotnet.rs:679`, `crates/disrobe-cli/src/cli/hermes.rs:73`
- `DR-CLI-0451`: `crates/disrobe-cli/src/cli/dotnet.rs:687`, `crates/disrobe-cli/src/cli/hermes.rs:87`
- `DR-CLI-0452`: `crates/disrobe-cli/src/cli/dotnet.rs:710`, `crates/disrobe-cli/src/cli/hermes.rs:91`
- `DR-CLI-0453`: `crates/disrobe-cli/src/cli/dotnet.rs:734`, `crates/disrobe-cli/src/cli/hermes.rs:96`
- `DR-CLI-0454`: `crates/disrobe-cli/src/cli/dotnet.rs:740`, `crates/disrobe-cli/src/cli/hermes.rs:120`
- `DR-CLI-0455`: `crates/disrobe-cli/src/cli/dotnet.rs:747`, `crates/disrobe-cli/src/cli/hermes.rs:118`
- `DR-CLI-0456`: `crates/disrobe-cli/src/cli/dotnet.rs:828`
- `DR-CLI-0457`: `crates/disrobe-cli/src/cli/dotnet.rs:830`
- `DR-CLI-0458`: `crates/disrobe-cli/src/cli/dotnet.rs:872`
- `DR-CLI-0459`: `crates/disrobe-cli/src/cli/dotnet.rs:894`, `crates/disrobe-cli/src/cli/jvm.rs:635`
- `DR-CLI-0460`: `crates/disrobe-cli/src/cli/dotnet.rs:625`, `crates/disrobe-cli/src/cli/hermes.rs:154`, `crates/disrobe-cli/src/cli/jvm.rs:777`
- `DR-CLI-0461`: `crates/disrobe-cli/src/cli/dotnet.rs:629`, `crates/disrobe-cli/src/cli/hermes.rs:156`, `crates/disrobe-cli/src/cli/jvm.rs:779`
- `DR-CLI-0462`: `crates/disrobe-cli/src/cli/dotnet.rs:631`, `crates/disrobe-cli/src/cli/hermes.rs:171`, `crates/disrobe-cli/src/cli/jvm.rs:789`
- `DR-CLI-0463`: `crates/disrobe-cli/src/cli/dotnet.rs:657`, `crates/disrobe-cli/src/cli/hermes.rs:174`, `crates/disrobe-cli/src/cli/jvm.rs:799`
- `DR-CLI-0464`: `crates/disrobe-cli/src/cli/dotnet.rs:44`, `crates/disrobe-cli/src/cli/hermes.rs:176`, `crates/disrobe-cli/src/cli/jvm.rs:814`
- `DR-CLI-0465`: `crates/disrobe-cli/src/cli/dotnet.rs:50`, `crates/disrobe-cli/src/cli/dotnet.rs:55`, `crates/disrobe-cli/src/cli/dotnet.rs:65`, `crates/disrobe-cli/src/cli/jvm.rs:830`
- `DR-CLI-0466`: `crates/disrobe-cli/src/cli/dotnet.rs:58`, `crates/disrobe-cli/src/cli/jvm.rs:893`
- `DR-CLI-0467`: `crates/disrobe-cli/src/cli/dotnet.rs:77`, `crates/disrobe-cli/src/cli/jvm.rs:987`
- `DR-CLI-0468`: `crates/disrobe-cli/src/cli/dotnet.rs:81`, `crates/disrobe-cli/src/cli/jvm.rs:1014`
- `DR-CLI-0469`: `crates/disrobe-cli/src/cli/dotnet.rs:86`, `crates/disrobe-cli/src/cli/jvm.rs:847`
- `DR-CLI-0470`: `crates/disrobe-cli/src/cli/dotnet.rs:90`, `crates/disrobe-cli/src/cli/hermes.rs:307`, `crates/disrobe-cli/src/cli/jvm.rs:863`
- `DR-CLI-0471`: `crates/disrobe-cli/src/cli/dotnet.rs:456`, `crates/disrobe-cli/src/cli/hermes.rs:309`, `crates/disrobe-cli/src/cli/jvm.rs:879`
- `DR-CLI-0472`: `crates/disrobe-cli/src/cli/dotnet.rs:479`, `crates/disrobe-cli/src/cli/jvm.rs:648`
- `DR-CLI-0473`: `crates/disrobe-cli/src/cli/dotnet.rs:483`, `crates/disrobe-cli/src/cli/jvm.rs:659`
- `DR-CLI-0474`: `crates/disrobe-cli/src/cli/dotnet.rs:531`
- `DR-CLI-0475`: `crates/disrobe-cli/src/cli/dotnet.rs:549`
- `DR-CLI-0476`: `crates/disrobe-cli/src/cli/dotnet.rs:605`
- `DR-CLI-0477`: `crates/disrobe-cli/src/cli/dotnet.rs:582`
- `DR-CLI-0478`: `crates/disrobe-cli/src/cli/dotnet.rs:585`
- `DR-CLI-0479`: `crates/disrobe-cli/src/cli/dotnet.rs:916`, `crates/disrobe-cli/src/cli/dotnet.rs:921`
- `DR-CLI-0480`: `crates/disrobe-cli/src/cli/dotnet.rs:492`, `crates/disrobe-cli/src/cli/jvm.rs:216`, `crates/disrobe-cli/src/cli/jvm.rs:222`, `crates/disrobe-cli/src/cli/macho.rs:196`
- `DR-CLI-0481`: `crates/disrobe-cli/src/cli/dotnet.rs:500`, `crates/disrobe-cli/src/cli/jvm.rs:229`, `crates/disrobe-cli/src/cli/macho.rs:198`
- `DR-CLI-0482`: `crates/disrobe-cli/src/cli/dotnet.rs:509`, `crates/disrobe-cli/src/cli/jvm.rs:232`, `crates/disrobe-cli/src/cli/macho.rs:208`
- `DR-CLI-0483`: `crates/disrobe-cli/src/cli/dotnet.rs:538`, `crates/disrobe-cli/src/cli/jvm.rs:329`, `crates/disrobe-cli/src/cli/macho.rs:211`
- `DR-CLI-0484`: `crates/disrobe-cli/src/cli/dotnet.rs:1041`, `crates/disrobe-cli/src/cli/dotnet.rs:1044`, `crates/disrobe-cli/src/cli/dotnet.rs:1049`, `crates/disrobe-cli/src/cli/jvm.rs:311`, `crates/disrobe-cli/src/cli/jvm.rs:346`, `crates/disrobe-cli/src/cli/macho.rs:213`
- `DR-CLI-0485`: `crates/disrobe-cli/src/cli/dotnet.rs:1066`
- `DR-CLI-0486`: `crates/disrobe-cli/src/cli/dotnet.rs:1053`, `crates/disrobe-cli/src/cli/dotnet.rs:1069`, `crates/disrobe-cli/src/cli/jvm.rs:359`
- `DR-CLI-0487`: `crates/disrobe-cli/src/cli/dotnet.rs:1071`
- `DR-CLI-0489`: `crates/disrobe-cli/src/cli/jvm.rs:357`
- `DR-CLI-0490`: `crates/disrobe-cli/src/cli/jvm.rs:361`, `crates/disrobe-cli/src/cli/macho.rs:235`
- `DR-CLI-0491`: `crates/disrobe-cli/src/cli/jvm.rs:364`, `crates/disrobe-cli/src/cli/macho.rs:250`
- `DR-CLI-0492`: `crates/disrobe-cli/src/cli/jvm.rs:247`, `crates/disrobe-cli/src/cli/jvm.rs:263`, `crates/disrobe-cli/src/cli/jvm.rs:269`, `crates/disrobe-cli/src/cli/macho.rs:263`
- `DR-CLI-0493`: `crates/disrobe-cli/src/cli/jvm.rs:375`, `crates/disrobe-cli/src/cli/macho.rs:267`
- `DR-CLI-0494`: `crates/disrobe-cli/src/cli/jvm.rs:289`, `crates/disrobe-cli/src/cli/jvm.rs:295`, `crates/disrobe-cli/src/cli/macho.rs:299`
- `DR-CLI-0495`: `crates/disrobe-cli/src/cli/macho.rs:103`, `crates/disrobe-cli/src/cli/macho.rs:261`
- `DR-CLI-0496`: `crates/disrobe-cli/src/cli/jvm.rs:304`, `crates/disrobe-cli/src/cli/jvm.rs:318`, `crates/disrobe-cli/src/cli/jvm.rs:392`, `crates/disrobe-cli/src/cli/jvm.rs:396`, `crates/disrobe-cli/src/cli/macho.rs:106`, `crates/disrobe-cli/src/cli/macho.rs:265`
- `DR-CLI-0497`: `crates/disrobe-cli/src/cli/jvm.rs:276`, `crates/disrobe-cli/src/cli/macho.rs:110`, `crates/disrobe-cli/src/cli/macho.rs:297`
- `DR-CLI-0498`: `crates/disrobe-cli/src/cli/macho.rs:131`, `crates/disrobe-cli/src/cli/macho.rs:273`
- `DR-CLI-0499`: `crates/disrobe-cli/src/cli/macho.rs:140`, `crates/disrobe-cli/src/cli/macho.rs:280`
- `DR-CLI-0500`: `crates/disrobe-cli/src/cli/macho.rs:147`, `crates/disrobe-cli/src/cli/macho.rs:324`
- `DR-CLI-0501`: `crates/disrobe-cli/src/cli/macho.rs:150`, `crates/disrobe-cli/src/cli/macho.rs:326`
- `DR-CLI-0502`: `crates/disrobe-cli/src/cli/macho.rs:124`, `crates/disrobe-cli/src/cli/macho.rs:329`
- `DR-CLI-0503`: `crates/disrobe-cli/src/cli/macho.rs:333`
- `DR-CLI-0510`: `crates/disrobe-cli/src/cli/macho.rs:358`
- `DR-CLI-0511`: `crates/disrobe-cli/src/cli/macho.rs:362`
- `DR-CLI-0512`: `crates/disrobe-cli/src/cli/macho.rs:372`
- `DR-CLI-0513`: `crates/disrobe-cli/src/cli/macho.rs:387`
- `DR-CLI-0520`: `crates/disrobe-cli/src/cli/lua.rs:155`
- `DR-CLI-0522`: `crates/disrobe-cli/src/cli/lua.rs:164`, `crates/disrobe-cli/src/cli/lua.rs:166`, `crates/disrobe-cli/src/cli/lua.rs:168`, `crates/disrobe-cli/src/cli/lua.rs:170`, `crates/disrobe-cli/src/cli/lua.rs:173`, `crates/disrobe-cli/src/cli/lua.rs:176`
- `DR-CLI-0524`: `crates/disrobe-cli/src/cli/lua.rs:158`
- `DR-CLI-0525`: `crates/disrobe-cli/src/cli/lua.rs:188`
- `DR-CLI-0526`: `crates/disrobe-cli/src/cli/lua.rs:191`
- `DR-CLI-0527`: `crates/disrobe-cli/src/cli/lua.rs:203`
- `DR-CLI-0528`: `crates/disrobe-cli/src/cli/lua.rs:201`
- `DR-CLI-0530`: `crates/disrobe-cli/src/cli/lua.rs:257`
- `DR-CLI-0531`: `crates/disrobe-cli/src/cli/lua.rs:273`
- `DR-CLI-0532`: `crates/disrobe-cli/src/cli/lua.rs:290`
- `DR-CLI-0533`: `crates/disrobe-cli/src/cli/lua.rs:293`
- `DR-CLI-0540`: `crates/disrobe-cli/src/cli/lua.rs:323`
- `DR-CLI-0541`: `crates/disrobe-cli/src/cli/lua.rs:231`
- `DR-CLI-0542`: `crates/disrobe-cli/src/cli/lua.rs:233`
- `DR-CLI-0543`: `crates/disrobe-cli/src/cli/lua.rs:235`
- `DR-CLI-0544`: `crates/disrobe-cli/src/cli/lua.rs:239`
- `DR-CLI-0550`: `crates/disrobe-cli/src/cli/php.rs:112`
- `DR-CLI-0551`: `crates/disrobe-cli/src/cli/php.rs:133`
- `DR-CLI-0552`: `crates/disrobe-cli/src/cli/php.rs:145`
- `DR-CLI-0553`: `crates/disrobe-cli/src/cli/php.rs:149`
- `DR-CLI-0554`: `crates/disrobe-cli/src/cli/php.rs:153`
- `DR-CLI-0555`: `crates/disrobe-cli/src/cli/php.rs:157`
- `DR-CLI-0556`: `crates/disrobe-cli/src/cli/php.rs:196`
- `DR-CLI-0557`: `crates/disrobe-cli/src/cli/php.rs:205`
- `DR-CLI-0558`: `crates/disrobe-cli/src/cli/php.rs:203`
- `DR-CLI-0560`: `crates/disrobe-cli/src/cli/php.rs:221`
- `DR-CLI-0561`: `crates/disrobe-cli/src/cli/php.rs:236`
- `DR-CLI-0562`: `crates/disrobe-cli/src/cli/php.rs:239`
- `DR-CLI-0563`: `crates/disrobe-cli/src/cli/php.rs:242`
- `DR-CLI-0564`: `crates/disrobe-cli/src/cli/php.rs:256`
- `DR-CLI-0565`: `crates/disrobe-cli/src/cli/php.rs:254`
- `DR-CLI-0570`: `crates/disrobe-cli/src/cli/php.rs:272`
- `DR-CLI-0571`: `crates/disrobe-cli/src/cli/php.rs:274`
- `DR-CLI-0572`: `crates/disrobe-cli/src/cli/php.rs:282`
- `DR-CLI-0573`: `crates/disrobe-cli/src/cli/php.rs:286`
- `DR-CLI-0574`: `crates/disrobe-cli/src/cli/php.rs:290`
- `DR-CLI-0575`: `crates/disrobe-cli/src/cli/php.rs:293`
- `DR-CLI-0576`: `crates/disrobe-cli/src/cli/php.rs:305`
- `DR-CLI-0577`: `crates/disrobe-cli/src/cli/php.rs:303`
- `DR-CLI-0580`: `crates/disrobe-cli/src/cli/php.rs:353`
- `DR-CLI-0581`: `crates/disrobe-cli/src/cli/php.rs:362`
- `DR-CLI-0582`: `crates/disrobe-cli/src/cli/php.rs:367`, `crates/disrobe-cli/src/cli/php.rs:376`
- `DR-CLI-0583`: `crates/disrobe-cli/src/cli/php.rs:411`
- `DR-CLI-0590`: `crates/disrobe-cli/src/cli/shell.rs:54`
- `DR-CLI-0591`: `crates/disrobe-cli/src/cli/shell.rs:58`
- `DR-CLI-0592`: `crates/disrobe-cli/src/cli/shell.rs:87`
- `DR-CLI-0593`: `crates/disrobe-cli/src/cli/shell.rs:90`
- `DR-CLI-0594`: `crates/disrobe-cli/src/cli/shell.rs:103`
- `DR-CLI-0595`: `crates/disrobe-cli/src/cli/shell.rs:101`
- `DR-CLI-0596`: `crates/disrobe-cli/src/cli/shell.rs:118`
- `DR-CLI-0600`: `crates/disrobe-cli/src/cli/detect.rs:68`, `crates/disrobe-cli/src/cli/ruby.rs:72`
- `DR-CLI-0601`: `crates/disrobe-cli/src/cli/ruby.rs:76`
- `DR-CLI-0602`: `crates/disrobe-cli/src/cli/ruby.rs:93`
- `DR-CLI-0603`: `crates/disrobe-cli/src/cli/ruby.rs:96`
- `DR-CLI-0604`: `crates/disrobe-cli/src/cli/ruby.rs:98`
- `DR-CLI-0605`: `crates/disrobe-cli/src/cli/ruby.rs:106`, `crates/disrobe-cli/src/cli/ruby.rs:113`
- `DR-CLI-0606`: `crates/disrobe-cli/src/cli/ruby.rs:52`
- `DR-CLI-0610`: `crates/disrobe-cli/src/cli/ruby.rs:198`
- `DR-CLI-0611`: `crates/disrobe-cli/src/cli/ruby.rs:201`
- `DR-CLI-0620`: `crates/disrobe-cli/src/cli/beam.rs:75`
- `DR-CLI-0621`: `crates/disrobe-cli/src/cli/beam.rs:77`
- `DR-CLI-0622`: `crates/disrobe-cli/src/cli/beam.rs:86`
- `DR-CLI-0623`: `crates/disrobe-cli/src/cli/beam.rs:110`
- `DR-CLI-0625`: `crates/disrobe-cli/src/cli/beam.rs:183`
- `DR-CLI-0630`: `crates/disrobe-cli/src/cli/beam.rs:127`
- `DR-CLI-0631`: `crates/disrobe-cli/src/cli/beam.rs:129`
- `DR-CLI-0632`: `crates/disrobe-cli/src/cli/beam.rs:131`
- `DR-CLI-0633`: `crates/disrobe-cli/src/cli/beam.rs:133`
- `DR-CLI-0634`: `crates/disrobe-cli/src/cli/beam.rs:147`
- `DR-CLI-0635`: `crates/disrobe-cli/src/cli/beam.rs:167`
- `DR-CLI-0636`: `crates/disrobe-cli/src/cli/beam.rs:171`
- `DR-CLI-0637`: `crates/disrobe-cli/src/cli/beam.rs:185`
- `DR-CLI-0640`: `crates/disrobe-cli/src/cli/beam.rs:210`
- `DR-CLI-0641`: `crates/disrobe-cli/src/cli/beam.rs:212`
- `DR-CLI-0642`: `crates/disrobe-cli/src/cli/beam.rs:217`
- `DR-CLI-0643`: `crates/disrobe-cli/src/cli/beam.rs:219`
- `DR-CLI-0644`: `crates/disrobe-cli/src/cli/beam.rs:229`
- `DR-CLI-0645`: `crates/disrobe-cli/src/cli/beam.rs:232`
- `DR-CLI-0646`: `crates/disrobe-cli/src/cli/beam.rs:234`
- `DR-CLI-0647`: `crates/disrobe-cli/src/cli/beam.rs:108`
- `DR-CLI-0648`: `crates/disrobe-cli/src/cli/beam.rs:165`
- `DR-CLI-0649`: `crates/disrobe-cli/src/cli/beam.rs:169`
- `DR-CLI-0650`: `crates/disrobe-cli/src/cli/beam.rs:163`, `crates/disrobe-cli/src/cli/go.rs:52`
- `DR-CLI-0651`: `crates/disrobe-cli/src/cli/beam.rs:238`, `crates/disrobe-cli/src/cli/go.rs:54`
- `DR-CLI-0652`: `crates/disrobe-cli/src/cli/go.rs:63`
- `DR-CLI-0653`: `crates/disrobe-cli/src/cli/go.rs:66`
- `DR-CLI-0654`: `crates/disrobe-cli/src/cli/go.rs:68`
- `DR-CLI-0655`: `crates/disrobe-cli/src/cli/go.rs:131`
- `DR-CLI-0656`: `crates/disrobe-cli/src/cli/go.rs:137`
- `DR-CLI-0657`: `crates/disrobe-cli/src/cli/go.rs:140`
- `DR-CLI-0660`: `crates/disrobe-cli/src/cli/go.rs:292`, `crates/disrobe-cli/src/cli/pickle.rs:120`
- `DR-CLI-0661`: `crates/disrobe-cli/src/cli/go.rs:294`, `crates/disrobe-cli/src/cli/pickle.rs:97`, `crates/disrobe-cli/src/cli/pickle.rs:100`, `crates/disrobe-cli/src/cli/pickle.rs:104`, `crates/disrobe-cli/src/cli/pickle.rs:115`, `crates/disrobe-cli/src/cli/pickle.rs:124`
- `DR-CLI-0662`: `crates/disrobe-cli/src/cli/pickle.rs:132`
- `DR-CLI-0663`: `crates/disrobe-cli/src/cli/pickle.rs:140`
- `DR-CLI-0664`: `crates/disrobe-cli/src/cli/pickle.rs:159`
- `DR-CLI-0665`: `crates/disrobe-cli/src/cli/pickle.rs:164`
- `DR-CLI-0666`: `crates/disrobe-cli/src/cli/pickle.rs:267`
- `DR-CLI-0668`: `crates/disrobe-cli/src/cli/pickle.rs:291`
- `DR-CLI-0669`: `crates/disrobe-cli/src/cli/pickle.rs:293`
- `DR-CLI-0670`: `crates/disrobe-cli/src/cli/pickle.rs:329`
- `DR-CLI-0671`: `crates/disrobe-cli/src/cli/pickle.rs:252`
- `DR-CLI-0672`: `crates/disrobe-cli/src/cli/pickle.rs:255`
- `DR-CLI-0700`: `crates/disrobe-cli/src/cli/apk.rs:84`, `crates/disrobe-cli/src/cli/swift.rs:68`
- `DR-CLI-0701`: `crates/disrobe-cli/src/cli/apk.rs:86`, `crates/disrobe-cli/src/cli/swift.rs:70`
- `DR-CLI-0702`: `crates/disrobe-cli/src/cli/apk.rs:101`, `crates/disrobe-cli/src/cli/swift.rs:73`
- `DR-CLI-0703`: `crates/disrobe-cli/src/cli/apk.rs:108`, `crates/disrobe-cli/src/cli/swift.rs:77`
- `DR-CLI-0704`: `crates/disrobe-cli/src/cli/apk.rs:120`, `crates/disrobe-cli/src/cli/swift.rs:88`
- `DR-CLI-0705`: `crates/disrobe-cli/src/cli/swift.rs:91`
- `DR-CLI-0706`: `crates/disrobe-cli/src/cli/swift.rs:93`
- `DR-CLI-0707`: `crates/disrobe-cli/src/cli/swift.rs:98`
- `DR-CLI-0710`: `crates/disrobe-cli/src/cli/swift.rs:144`
- `DR-CLI-0711`: `crates/disrobe-cli/src/cli/swift.rs:155`
- `DR-CLI-0712`: `crates/disrobe-cli/src/cli/swift.rs:158`
- `DR-CLI-0713`: `crates/disrobe-cli/src/cli/swift.rs:160`
- `DR-CLI-0720`: `crates/disrobe-cli/src/cli/swift.rs:170`
- `DR-CLI-0721`: `crates/disrobe-cli/src/cli/swift.rs:187`
- `DR-CLI-0722`: `crates/disrobe-cli/src/cli/swift.rs:190`
- `DR-CLI-0723`: `crates/disrobe-cli/src/cli/swift.rs:192`
- `DR-CLI-0730`: `crates/disrobe-cli/src/cli/as3.rs:51`
- `DR-CLI-0731`: `crates/disrobe-cli/src/cli/as3.rs:52`
- `DR-CLI-0732`: `crates/disrobe-cli/src/cli/as3.rs:60`
- `DR-CLI-0733`: `crates/disrobe-cli/src/cli/as3.rs:65`
- `DR-CLI-0734`: `crates/disrobe-cli/src/cli/as3.rs:69`
- `DR-CLI-0735`: `crates/disrobe-cli/src/cli/as3.rs:75`
- `DR-CLI-0736`: `crates/disrobe-cli/src/cli/as3.rs:85`
- `DR-CLI-0737`: `crates/disrobe-cli/src/cli/as3.rs:90`
- `DR-CLI-0738`: `crates/disrobe-cli/src/cli/as3.rs:115`
- `DR-CLI-0739`: `crates/disrobe-cli/src/cli/as3.rs:149`
- `DR-CLI-0740`: `crates/disrobe-cli/src/cli/as3.rs:220`
- `DR-CLI-0741`: `crates/disrobe-cli/src/cli/as3.rs:221`
- `DR-CLI-0742`: `crates/disrobe-cli/src/cli/as3.rs:126`
- `DR-CLI-0743`: `crates/disrobe-cli/src/cli/as3.rs:129`
- `DR-CLI-0744`: `crates/disrobe-cli/src/cli/as3.rs:113`
- `DR-CLI-0745`: `crates/disrobe-cli/src/cli/as3.rs:147`
- `DR-CLI-0746`: `crates/disrobe-cli/src/cli/as3.rs:120`
- `DR-CLI-0750`: `crates/disrobe-cli/src/cli/flutter.rs:333`
- `DR-CLI-0751`: `crates/disrobe-cli/src/cli/flutter.rs:335`
- `DR-CLI-0752`: `crates/disrobe-cli/src/cli/flutter.rs:347`
- `DR-CLI-0753`: `crates/disrobe-cli/src/cli/flutter.rs:350`
- `DR-CLI-0754`: `crates/disrobe-cli/src/cli/flutter.rs:352`
- `DR-CLI-0755`: `crates/disrobe-cli/src/cli/flutter.rs:492`, `crates/disrobe-cli/src/cli/flutter.rs:494`, `crates/disrobe-cli/src/cli/flutter.rs:496`
- `DR-CLI-0756`: `crates/disrobe-cli/src/cli/flutter.rs:416`
- `DR-CLI-0757`: `crates/disrobe-cli/src/cli/flutter.rs:517`
- `DR-CLI-0758`: `crates/disrobe-cli/src/cli/flutter.rs:522`
- `DR-CLI-0759`: `crates/disrobe-cli/src/cli/flutter.rs:525`
- `DR-CLI-0760`: `crates/disrobe-cli/src/cli/flutter.rs:540`, `crates/disrobe-cli/src/cli/flutter.rs:597`
- `DR-CLI-0761`: `crates/disrobe-cli/src/cli/flutter.rs:549`, `crates/disrobe-cli/src/cli/flutter.rs:604`
- `DR-CLI-0762`: `crates/disrobe-cli/src/cli/flutter.rs:551`, `crates/disrobe-cli/src/cli/flutter.rs:606`
- `DR-CLI-0763`: `crates/disrobe-cli/src/cli/flutter.rs:616`, `crates/disrobe-cli/src/cli/flutter.rs:723`
- `DR-CLI-0764`: `crates/disrobe-cli/src/cli/flutter.rs:619`, `crates/disrobe-cli/src/cli/flutter.rs:719`
- `DR-CLI-0765`: `crates/disrobe-cli/src/cli/flutter.rs:621`, `crates/disrobe-cli/src/cli/flutter.rs:727`
- `DR-CLI-0766`: `crates/disrobe-cli/src/cli/flutter.rs:693`
- `DR-CLI-0767`: `crates/disrobe-cli/src/cli/flutter.rs:705`, `crates/disrobe-cli/src/cli/flutter.rs:755`, `crates/disrobe-cli/src/cli/flutter.rs:759`, `crates/disrobe-cli/src/cli/flutter.rs:780`
- `DR-CLI-0768`: `crates/disrobe-cli/src/cli/flutter.rs:731`
- `DR-CLI-0770`: `crates/disrobe-cli/src/cli/flutter.rs:800`
- `DR-CLI-0771`: `crates/disrobe-cli/src/cli/flutter.rs:802`
- `DR-CLI-0772`: `crates/disrobe-cli/src/cli/flutter.rs:812`
- `DR-CLI-0773`: `crates/disrobe-cli/src/cli/flutter.rs:815`
- `DR-CLI-0774`: `crates/disrobe-cli/src/cli/flutter.rs:817`
- `DR-CLI-0780`: `crates/disrobe-cli/src/cli/flutter.rs:241`
- `DR-CLI-0781`: `crates/disrobe-cli/src/cli/flutter.rs:244`
- `DR-CLI-0782`: `crates/disrobe-cli/src/cli/flutter.rs:248`
- `DR-CLI-0783`: `crates/disrobe-cli/src/cli/flutter.rs:258`
- `DR-CLI-0784`: `crates/disrobe-cli/src/cli/flutter.rs:261`
- `DR-CLI-0785`: `crates/disrobe-cli/src/cli/flutter.rs:263`
- `DR-CLI-0786`: `crates/disrobe-cli/src/cli/flutter.rs:266`
- `DR-CLI-0790`: `crates/disrobe-cli/src/cli/flutter.rs:287`
- `DR-CLI-0791`: `crates/disrobe-cli/src/cli/flutter.rs:289`
- `DR-CLI-0792`: `crates/disrobe-cli/src/cli/flutter.rs:299`
- `DR-CLI-0793`: `crates/disrobe-cli/src/cli/flutter.rs:302`
- `DR-CLI-0794`: `crates/disrobe-cli/src/cli/flutter.rs:304`
- `DR-CLI-0795`: `crates/disrobe-cli/src/cli/flutter.rs:313`
- `DR-CLI-0800`: `crates/disrobe-cli/src/cli/mobile.rs:131`
- `DR-CLI-0801`: `crates/disrobe-cli/src/cli/mobile.rs:154`
- `DR-CLI-0802`: `crates/disrobe-cli/src/cli/mobile.rs:288`
- `DR-CLI-0803`: `crates/disrobe-cli/src/cli/mobile.rs:160`
- `DR-CLI-0804`: `crates/disrobe-cli/src/cli/mobile.rs:297`
- `DR-CLI-0805`: `crates/disrobe-cli/src/cli/mobile.rs:458`
- `DR-CLI-0806`: `crates/disrobe-cli/src/cli/mobile.rs:460`
- `DR-CLI-0807`: `crates/disrobe-cli/src/cli/mobile.rs:466`
- `DR-CLI-0808`: `crates/disrobe-cli/src/cli/mobile.rs:473`
- `DR-CLI-0809`: `crates/disrobe-cli/src/cli/mobile.rs:478`
- `DR-CLI-0810`: `crates/disrobe-cli/src/cli/mobile.rs:104`
- `DR-CLI-0811`: `crates/disrobe-cli/src/cli/mobile.rs:107`
- `DR-CLI-0812`: `crates/disrobe-cli/src/cli/mobile.rs:108`
- `DR-CLI-0813`: `crates/disrobe-cli/src/cli/mobile.rs:513`
- `DR-CLI-0814`: `crates/disrobe-cli/src/cli/mobile.rs:517`, `crates/disrobe-cli/src/cli/mobile.rs:520`
- `DR-CLI-0815`: `crates/disrobe-cli/src/cli/mobile.rs:530`
- `DR-CLI-0816`: `crates/disrobe-cli/src/cli/mobile.rs:177`
- `DR-CLI-0817`: `crates/disrobe-cli/src/cli/mobile.rs:219`, `crates/disrobe-cli/src/cli/mobile.rs:322`
- `DR-CLI-0818`: `crates/disrobe-cli/src/cli/mobile.rs:222`, `crates/disrobe-cli/src/cli/mobile.rs:328`
- `DR-CLI-0819`: `crates/disrobe-cli/src/cli/mobile.rs:229`, `crates/disrobe-cli/src/cli/mobile.rs:331`
- `DR-CLI-0820`: `crates/disrobe-cli/src/cli/mobile.rs:189`, `crates/disrobe-cli/src/cli/mobile.rs:360`
- `DR-CLI-0821`: `crates/disrobe-cli/src/cli/mobile.rs:192`, `crates/disrobe-cli/src/cli/mobile.rs:366`
- `DR-CLI-0822`: `crates/disrobe-cli/src/cli/mobile.rs:200`, `crates/disrobe-cli/src/cli/mobile.rs:369`
- `DR-CLI-0823`: `crates/disrobe-cli/src/cli/mobile.rs:391`
- `DR-CLI-0824`: `crates/disrobe-cli/src/cli/mobile.rs:397`
- `DR-CLI-0825`: `crates/disrobe-cli/src/cli/mobile.rs:400`
- `DR-CLI-0826`: `crates/disrobe-cli/src/cli/mobile.rs:247`, `crates/disrobe-cli/src/cli/mobile.rs:251`
- `DR-CLI-0827`: `crates/disrobe-cli/src/cli/mobile.rs:482`
- `DR-CLI-0828`: `crates/disrobe-cli/src/cli/mobile.rs:574`, `crates/disrobe-cli/src/cli/mobile.rs:603`
- `DR-CLI-0829`: `crates/disrobe-cli/src/cli/mobile.rs:605`
- `DR-CLI-0830`: `crates/disrobe-cli/src/cli/mobile.rs:561`, `crates/disrobe-cli/src/cli/query.rs:135`, `crates/disrobe-cli/src/cli/query.rs:196`, `crates/disrobe-cli/src/cli/query.rs:200`, `crates/disrobe-cli/src/cli/query.rs:264`
- `DR-CLI-0831`: `crates/disrobe-cli/src/cli/mobile.rs:565`, `crates/disrobe-cli/src/cli/query.rs:268`
- `DR-CLI-0832`: `crates/disrobe-cli/src/cli/mobile.rs:583`, `crates/disrobe-cli/src/cli/mobile.rs:600`, `crates/disrobe-cli/src/cli/query.rs:40`
- `DR-CLI-0833`: `crates/disrobe-cli/src/cli/mobile.rs:585`, `crates/disrobe-cli/src/cli/query.rs:275`
- `DR-CLI-0834`: `crates/disrobe-cli/src/cli/query.rs:211`, `crates/disrobe-cli/src/cli/query.rs:217`
- `DR-CLI-0835`: `crates/disrobe-cli/src/cli/query.rs:226`
- `DR-CLI-0836`: `crates/disrobe-cli/src/cli/query.rs:235`, `crates/disrobe-cli/src/cli/query.rs:245`
- `DR-CLI-0837`: `crates/disrobe-cli/src/cli/query.rs:129`
- `DR-CLI-0838`: `crates/disrobe-cli/src/cli/query.rs:104`
- `DR-CLI-0839`: `crates/disrobe-cli/src/cli/query.rs:203`
- `DR-CLI-0840`: `crates/disrobe-cli/src/cli/capabilities.rs:14`, `crates/disrobe-cli/src/cli/query.rs:109`
- `DR-CLI-0841`: `crates/disrobe-cli/src/cli/capabilities.rs:28`, `crates/disrobe-cli/src/cli/query.rs:115`
- `DR-CLI-0842`: `crates/disrobe-cli/src/cli/capabilities.rs:41`, `crates/disrobe-cli/src/cli/query.rs:141`
- `DR-CLI-0843`: `crates/disrobe-cli/src/cli/query.rs:173`, `crates/disrobe-cli/src/main.rs:2050`
- `DR-CLI-0844`: `crates/disrobe-cli/src/cli/chain_v1.rs:620`, `crates/disrobe-cli/src/cli/extract.rs:40`, `crates/disrobe-cli/src/cli/luks1_input.rs:43`, `crates/disrobe-cli/src/cli/luks1_input.rs:46`, `crates/disrobe-cli/src/cli/luks1_input.rs:55`, `crates/disrobe-cli/src/cli/luks1_input.rs:62`, `crates/disrobe-cli/src/cli/query.rs:180`, `crates/disrobe-cli/src/cli/taint.rs:244`
- `DR-CLI-0850`: `crates/disrobe-cli/src/cli/taint.rs:101`
- `DR-CLI-0851`: `crates/disrobe-cli/src/cli/nir_source.rs:33`
- `DR-CLI-0852`: `crates/disrobe-cli/src/cli/nir_source.rs:44`
- `DR-CLI-0853`: `crates/disrobe-cli/src/cli/nir_source.rs:51`
- `DR-CLI-0854`: `crates/disrobe-cli/src/cli/nir_source.rs:58`
- `DR-CLI-0855`: `crates/disrobe-cli/src/cli/vulnmatch.rs:200`, `crates/disrobe-cli/src/cli/vulnmatch.rs:204`, `crates/disrobe-cli/src/cli/vulnmatch.rs:210`, `crates/disrobe-cli/src/cli/vulnmatch.rs:216`, `crates/disrobe-cli/src/cli/vulnmatch.rs:222`, `crates/disrobe-cli/src/cli/vulnmatch.rs:228`, `crates/disrobe-cli/src/cli/vulnmatch.rs:232`, `crates/disrobe-cli/src/cli/vulnmatch.rs:238`, `crates/disrobe-cli/src/cli/vulnmatch.rs:242`
- `DR-CLI-0856`: `crates/disrobe-cli/src/cli/vulnmatch.rs:146`
- `DR-CLI-0857`: `crates/disrobe-cli/src/cli/vulnmatch.rs:164`
- `DR-CLI-0858`: `crates/disrobe-cli/src/cli/vulnmatch.rs:172`
- `DR-CLI-0859`: `crates/disrobe-cli/src/cli/vulnmatch.rs:180`
- `DR-CLI-0860`: `crates/disrobe-cli/src/cli/vulnmatch.rs:186`
- `DR-CLI-0861`: `crates/disrobe-cli/src/cli/flutter.rs:827`, `crates/disrobe-cli/src/cli/vulnmatch.rs:63`, `crates/disrobe-cli/src/cli/vulnmatch.rs:108`
- `DR-CLI-0862`: `crates/disrobe-cli/src/cli/flutter.rs:833`, `crates/disrobe-cli/src/cli/vulnmatch.rs:68`, `crates/disrobe-cli/src/cli/vulnmatch.rs:103`
- `DR-CLI-0863`: `crates/disrobe-cli/src/cli/flutter.rs:854`, `crates/disrobe-cli/src/cli/vulnmatch.rs:70`
- `DR-CLI-0864`: `crates/disrobe-cli/src/cli/flutter.rs:856`, `crates/disrobe-cli/src/cli/vulnmatch.rs:79`
- `DR-CLI-0865`: `crates/disrobe-cli/src/cli/flutter.rs:858`, `crates/disrobe-cli/src/cli/vulnmatch.rs:81`
- `DR-CLI-0866`: `crates/disrobe-cli/src/cli/flutter.rs:860`, `crates/disrobe-cli/src/cli/vulnmatch.rs:87`
- `DR-CLI-0867`: `crates/disrobe-cli/src/cli/flutter.rs:872`
- `DR-CLI-0868`: `crates/disrobe-cli/src/cli/flutter.rs:890`
- `DR-CLI-0869`: `crates/disrobe-cli/src/cli/flutter.rs:893`
- `DR-CLI-0870`: `crates/disrobe-cli/src/cli/flutter.rs:895`, `crates/disrobe-cli/src/cli/semdiff.rs:550`, `crates/disrobe-cli/src/cli/semdiff.rs:560`, `crates/disrobe-cli/src/cli/vulnmatch.rs:53`
- `DR-CLI-0871`: `crates/disrobe-cli/src/cli/semdiff.rs:554`, `crates/disrobe-cli/src/cli/taint.rs:149`
- `DR-CLI-0872`: `crates/disrobe-cli/src/cli/semdiff.rs:100`, `crates/disrobe-cli/src/cli/taint.rs:208`
- `DR-CLI-0873`: `crates/disrobe-cli/src/cli/semdiff.rs:276`
- `DR-CLI-0874`: `crates/disrobe-cli/src/cli/semdiff.rs:542`
- `DR-CLI-0875`: `crates/disrobe-cli/src/cli/hermes.rs:190`, `crates/disrobe-cli/src/cli/hermes.rs:201`, `crates/disrobe-cli/src/cli/hermes.rs:219`, `crates/disrobe-cli/src/cli/hermes.rs:223`, `crates/disrobe-cli/src/cli/hermes.rs:285`, `crates/disrobe-cli/src/cli/hermes.rs:289`
- `DR-CLI-0876`: `crates/disrobe-cli/src/cli/hermes.rs:237`
- `DR-CLI-0911`: `crates/disrobe-cli/src/cli/pickle.rs:184`, `crates/disrobe-cli/src/cli/pickle.rs:193`
- `DR-CLI-0912`: `crates/disrobe-cli/src/cli/chain_v1.rs:1498`, `crates/disrobe-cli/src/cli/chain_v1.rs:1518`
- `DR-CLI-0913`: `crates/disrobe-cli/src/cli/chain_v1.rs:1508`
- `DR-CORE-0003`: `crates/disrobe-core/src/error.rs:8`
- `DR-CORE-0004`: `crates/disrobe-core/src/error.rs:12`
- `DR-CORE-0101`: `crates/disrobe-core/src/chain/spec.rs:158`
- `DR-CORE-0102`: `crates/disrobe-core/src/chain/spec.rs:160`
- `DR-CORE-0103`: `crates/disrobe-core/src/chain/spec.rs:162`
- `DR-CORE-0104`: `crates/disrobe-core/src/chain/spec.rs:164`
- `DR-CORE-0105`: `crates/disrobe-core/src/chain/spec.rs:166`
- `DR-CORE-0106`: `crates/disrobe-core/src/chain/spec.rs:168`
- `DR-CORE-0107`: `crates/disrobe-core/src/chain/spec.rs:170`
- `DR-CORE-0108`: `crates/disrobe-core/src/chain/spec.rs:172`
- `DR-CORE-0109`: `crates/disrobe-core/src/chain/spec.rs:175`
- `DR-DOTNET-0001`: `crates/disrobe-pass-dotnet/src/error.rs:9`
- `DR-DOTNET-0002`: `crates/disrobe-pass-dotnet/src/error.rs:12`
- `DR-DOTNET-0003`: `crates/disrobe-pass-dotnet/src/error.rs:15`
- `DR-DOTNET-0004`: `crates/disrobe-pass-dotnet/src/error.rs:18`
- `DR-DOTNET-0005`: `crates/disrobe-pass-dotnet/src/error.rs:21`
- `DR-DOTNET-0006`: `crates/disrobe-pass-dotnet/src/error.rs:28`
- `DR-DOTNET-0007`: `crates/disrobe-pass-dotnet/src/error.rs:31`
- `DR-DOTNET-0008`: `crates/disrobe-pass-dotnet/src/error.rs:34`
- `DR-DOTNET-0009`: `crates/disrobe-pass-dotnet/src/error.rs:38`
- `DR-DOTNET-0010`: `crates/disrobe-pass-dotnet/src/error.rs:42`
- `DR-DOTNET-0011`: `crates/disrobe-pass-dotnet/src/error.rs:45`
- `DR-DOTNET-0012`: `crates/disrobe-pass-dotnet/src/error.rs:48`
- `DR-DOTNET-0013`: `crates/disrobe-pass-dotnet/src/error.rs:51`
- `DR-DOTNET-0014`: `crates/disrobe-pass-dotnet/src/error.rs:54`
- `DR-DOTNET-0015`: `crates/disrobe-pass-dotnet/src/error.rs:57`
- `DR-DOTNET-0016`: `crates/disrobe-pass-dotnet/src/error.rs:60`
- `DR-DOTNET-0017`: `crates/disrobe-pass-dotnet/src/error.rs:63`
- `DR-DOTNET-0018`: `crates/disrobe-pass-dotnet/src/error.rs:66`
- `DR-DOTNET-0019`: `crates/disrobe-pass-dotnet/src/error.rs:69`
- `DR-DOTNET-0020`: `crates/disrobe-pass-dotnet/src/error.rs:72`
- `DR-DOTNET-0021`: `crates/disrobe-pass-dotnet/src/error.rs:75`
- `DR-DOTNET-0022`: `crates/disrobe-pass-dotnet/src/error.rs:82`
- `DR-DOTNET-0023`: `crates/disrobe-pass-dotnet/src/error.rs:85`
- `DR-DOTNET-0024`: `crates/disrobe-pass-dotnet/src/error.rs:88`
- `DR-DOTNET-0025`: `crates/disrobe-pass-dotnet/src/error.rs:91`
- `DR-DOTNET-0026`: `crates/disrobe-pass-dotnet/src/error.rs:94`
- `DR-DOTNET-0027`: `crates/disrobe-pass-dotnet/src/error.rs:97`
- `DR-DOTNET-0028`: `crates/disrobe-pass-dotnet/src/error.rs:104`
- `DR-DOTNET-0029`: `crates/disrobe-pass-dotnet/src/error.rs:107`
- `DR-DOTNET-0030`: `crates/disrobe-pass-dotnet/src/error.rs:110`
- `DR-DOTNET-0031`: `crates/disrobe-pass-dotnet/src/error.rs:113`
- `DR-DOTNET-0032`: `crates/disrobe-pass-dotnet/src/error.rs:117`
- `DR-DOTNET-0033`: `crates/disrobe-pass-dotnet/src/error.rs:121`
- `DR-DOTNET-0034`: `crates/disrobe-pass-dotnet/src/error.rs:124`
- `DR-DOTNET-0035`: `crates/disrobe-pass-dotnet/src/error.rs:127`
- `DR-DOTNET-0036`: `crates/disrobe-pass-dotnet/src/error.rs:131`
- `DR-DOTNET-0037`: `crates/disrobe-pass-dotnet/src/error.rs:136`
- `DR-DOTNET-0038`: `crates/disrobe-pass-dotnet/src/error.rs:141`
- `DR-DOTNET-0039`: `crates/disrobe-pass-dotnet/src/aot/method_bodies.rs:28`, `crates/disrobe-pass-dotnet/src/aot/method_bodies.rs:33`, `crates/disrobe-pass-dotnet/src/error.rs:145`
- `DR-DOTNET-0040`: `crates/disrobe-pass-dotnet/src/error.rs:148`
- `DR-DOTNET-0041`: `crates/disrobe-pass-dotnet/src/error.rs:151`
- `DR-DOTNET-0042`: `crates/disrobe-pass-dotnet/src/error.rs:154`
- `DR-DOTNET-0902`: `crates/disrobe-pass-dotnet/src/chain_detector.rs:115`
- `DR-DOTNET-0903`: `crates/disrobe-pass-dotnet/src/chain_detector.rs:122`
- `DR-DOTNET-0905`: `crates/disrobe-pass-dotnet/src/chain_detector.rs:140`
- `DR-DOTNET-0906`: `crates/disrobe-pass-dotnet/src/chain_detector.rs:154`
- `DR-DOTNET-0907`: `crates/disrobe-pass-dotnet/src/chain_detector.rs:131`
- `DR-DOTNET-0908`: `crates/disrobe-pass-dotnet/src/chain_detector.rs:135`
- `DR-DOTNET-0910`: `crates/disrobe-pass-dotnet/src/chain_detector.rs:983`, `crates/disrobe-pass-dotnet/src/chain_detector.rs:1000`
- `DR-DOTNET-0913`: `crates/disrobe-pass-dotnet/src/chain_detector.rs:565`, `crates/disrobe-pass-dotnet/src/chain_detector.rs:651`
- `DR-DOTNET-0914`: `crates/disrobe-pass-dotnet/src/chain_detector.rs:965`
- `DR-DOTNET-0916`: `crates/disrobe-pass-dotnet/src/chain_detector.rs:970`
- `DR-DOTNET-0917`: `crates/disrobe-pass-dotnet/src/chain_detector.rs:831`
- `DR-DOTNET-0918`: `crates/disrobe-pass-dotnet/src/chain_detector.rs:862`
- `DR-DOTNET-0919`: `crates/disrobe-pass-dotnet/src/chain_detector.rs:988`
- `DR-DOTNET-0920`: `crates/disrobe-pass-dotnet/src/chain_detector.rs:554`, `crates/disrobe-pass-dotnet/src/chain_detector.rs:559`
- `DR-DOTNET-0921`: `crates/disrobe-pass-dotnet/src/chain_detector.rs:496`, `crates/disrobe-pass-dotnet/src/chain_detector.rs:501`, `crates/disrobe-pass-dotnet/src/chain_detector.rs:604`, `crates/disrobe-pass-dotnet/src/chain_detector.rs:618`, `crates/disrobe-pass-dotnet/src/chain_detector.rs:624`, `crates/disrobe-pass-dotnet/src/chain_detector.rs:811`
- `DR-DOTNET-0922`: `crates/disrobe-pass-dotnet/src/chain_detector.rs:513`, `crates/disrobe-pass-dotnet/src/chain_detector.rs:518`, `crates/disrobe-pass-dotnet/src/chain_detector.rs:544`, `crates/disrobe-pass-dotnet/src/chain_detector.rs:573`, `crates/disrobe-pass-dotnet/src/chain_detector.rs:665`, `crates/disrobe-pass-dotnet/src/chain_detector.rs:678`
- `DR-DOTNET-0923`: `crates/disrobe-pass-dotnet/src/chain_detector.rs:527`
- `DR-DOTNET-0924`: `crates/disrobe-pass-dotnet/src/chain_detector.rs:798`, `crates/disrobe-pass-dotnet/src/chain_detector.rs:805`, `crates/disrobe-pass-dotnet/src/chain_detector.rs:840`, `crates/disrobe-pass-dotnet/src/chain_detector.rs:847`, `crates/disrobe-pass-dotnet/src/chain_detector.rs:884`, `crates/disrobe-pass-dotnet/src/chain_detector.rs:893`
- `DR-DOTNET-0925`: `crates/disrobe-pass-dotnet/src/chain_detector.rs:1005`
- `DR-DOTNET-0930`: `crates/disrobe-pass-dotnet/src/chain_detector.rs:423`
- `DR-EXTRACT-0050`: `crates/disrobe-cli/src/cli/extract.rs:36`, `crates/disrobe-cli/src/cli/extract.rs:54`
- `DR-EXTRACT-0051`: `crates/disrobe-cli/src/cli/extract.rs:347`
- `DR-EXTRACT-0052`: `crates/disrobe-cli/src/cli/extract.rs:374`
- `DR-EXTRACT-0053`: `crates/disrobe-cli/src/cli/extract.rs:391`
- `DR-EXTRACT-0054`: `crates/disrobe-cli/src/cli/extract.rs:393`
- `DR-EXTRACT-0055`: `crates/disrobe-cli/src/cli/extract.rs:428`
- `DR-EXTRACT-0056`: `crates/disrobe-cli/src/cli/extract.rs:250`
- `DR-EXTRACT-0057`: `crates/disrobe-cli/src/cli/extract.rs:271`
- `DR-EXTRACT-0058`: `crates/disrobe-cli/src/cli/extract.rs:278`
- `DR-EXTRACT-0059`: `crates/disrobe-cli/src/cli/extract.rs:288`
- `DR-EXTRACT-0060`: `crates/disrobe-cli/src/cli/extract.rs:294`
- `DR-EXTRACT-0061`: `crates/disrobe-cli/src/cli/extract.rs:298`
- `DR-EXTRACT-0062`: `crates/disrobe-cli/src/cli/extract.rs:302`
- `DR-EXTRACT-0063`: `crates/disrobe-cli/src/cli/extract.rs:79`, `crates/disrobe-cli/src/cli/extract.rs:83`
- `DR-EXTRACT-0064`: `crates/disrobe-cli/src/cli/extract.rs:175`, `crates/disrobe-cli/src/cli/extract.rs:179`
- `DR-EXTRACT-0065`: `crates/disrobe-cli/src/cli/extract.rs:124`, `crates/disrobe-cli/src/cli/extract.rs:134`, `crates/disrobe-cli/src/cli/extract.rs:143`, `crates/disrobe-cli/src/cli/extract.rs:153`
- `DR-EXTRACT-0066`: `crates/disrobe-cli/src/cli/extract.rs:93`
- `DR-EXTRACT-0067`: `crates/disrobe-cli/src/cli/extract.rs:102`, `crates/disrobe-cli/src/cli/extract.rs:113`
- `DR-FRISK-0050`: `crates/disrobe-cli/src/cli/frisk.rs:301`
- `DR-FRISK-0051`: `crates/disrobe-cli/src/cli/frisk.rs:347`
- `DR-FRISK-0052`: `crates/disrobe-cli/src/cli/frisk.rs:321`
- `DR-FRISK-0060`: `crates/disrobe-cli/src/cli/frisk.rs:27`
- `DR-FRISK-0061`: `crates/disrobe-cli/src/cli/frisk.rs:36`
- `DR-FRISK-0062`: `crates/disrobe-cli/src/cli/frisk.rs:41`
- `DR-FRISK-0063`: `crates/disrobe-cli/src/cli/frisk.rs:49`
- `DR-FRISK-0064`: `crates/disrobe-cli/src/cli/frisk.rs:51`
- `DR-FRISK-0070`: `crates/disrobe-cli/src/cli/frisk.rs:162`
- `DR-FRISK-0071`: `crates/disrobe-cli/src/cli/frisk.rs:189`
- `DR-FRISK-0080`: `crates/disrobe-cli/src/cli/frisk.rs:275`
- `DR-GO-0001`: `crates/disrobe-pass-go/src/error.rs:8`
- `DR-GO-0002`: `crates/disrobe-pass-go/src/error.rs:11`
- `DR-GO-0003`: `crates/disrobe-pass-go/src/error.rs:14`
- `DR-GO-0004`: `crates/disrobe-pass-go/src/error.rs:17`
- `DR-GO-0005`: `crates/disrobe-pass-go/src/error.rs:20`
- `DR-GO-0007`: `crates/disrobe-pass-go/src/error.rs:24`
- `DR-GO-0008`: `crates/disrobe-pass-go/src/error.rs:28`
- `DR-GO-0009`: `crates/disrobe-pass-go/src/error.rs:32`
- `DR-GO-0010`: `crates/disrobe-pass-go/src/error.rs:40`
- `DR-GO-0902`: `crates/disrobe-pass-go/src/chain_detector.rs:127`
- `DR-GO-0903`: `crates/disrobe-pass-go/src/chain_detector.rs:132`
- `DR-HL-0001`: `crates/disrobe-pass-scriptlang/src/lang/hashlink.rs:152`
- `DR-HL-0002`: `crates/disrobe-pass-scriptlang/src/lang/hashlink.rs:154`
- `DR-HL-0003`: `crates/disrobe-pass-scriptlang/src/lang/hashlink.rs:156`
- `DR-HL-0004`: `crates/disrobe-pass-scriptlang/src/lang/hashlink.rs:158`
- `DR-HL-0005`: `crates/disrobe-pass-scriptlang/src/lang/hashlink.rs:160`
- `DR-HL-0006`: `crates/disrobe-pass-scriptlang/src/lang/hashlink.rs:162`
- `DR-HL-0007`: `crates/disrobe-pass-scriptlang/src/lang/hashlink.rs:164`
- `DR-HL-0008`: `crates/disrobe-pass-scriptlang/src/lang/hashlink.rs:166`
- `DR-HL-0009`: `crates/disrobe-pass-scriptlang/src/lang/hashlink.rs:168`
- `DR-IDENTIFY-0050`: `crates/disrobe-cli/src/cli/identify.rs:18`
- `DR-IDENTIFY-0051`: `crates/disrobe-cli/src/cli/identify.rs:24`
- `DR-IND-0060`: `crates/disrobe-cli/src/cli/indicators.rs:69`
- `DR-IND-0061`: `crates/disrobe-cli/src/cli/indicators.rs:75`
- `DR-IND-0062`: `crates/disrobe-cli/src/cli/indicators.rs:82`
- `DR-IND-0063`: `crates/disrobe-cli/src/cli/indicators.rs:109`
- `DR-IOC-0050`: `crates/disrobe-cli/src/cli/ioc.rs:135`
- `DR-IOC-0051`: `crates/disrobe-cli/src/cli/ioc.rs:163`
- `DR-IOS-0001`: `crates/disrobe-pass-swift-objc/src/error.rs:9`
- `DR-IOS-0002`: `crates/disrobe-pass-swift-objc/src/error.rs:12`
- `DR-IOS-0003`: `crates/disrobe-pass-swift-objc/src/error.rs:15`
- `DR-IOS-0004`: `crates/disrobe-pass-swift-objc/src/error.rs:18`
- `DR-IOS-0005`: `crates/disrobe-pass-swift-objc/src/error.rs:21`
- `DR-IOS-0006`: `crates/disrobe-pass-swift-objc/src/error.rs:24`
- `DR-IOS-0007`: `crates/disrobe-pass-swift-objc/src/error.rs:27`
- `DR-IOS-0008`: `crates/disrobe-pass-swift-objc/src/error.rs:30`
- `DR-IOS-0009`: `crates/disrobe-pass-swift-objc/src/error.rs:33`
- `DR-IOS-0011`: `crates/disrobe-pass-swift-objc/src/error.rs:36`
- `DR-IOS-0012`: `crates/disrobe-pass-swift-objc/src/error.rs:39`
- `DR-IOS-0013`: `crates/disrobe-pass-swift-objc/src/error.rs:43`
- `DR-IOS-0014`: `crates/disrobe-pass-swift-objc/src/error.rs:47`
- `DR-IOS-0015`: `crates/disrobe-pass-swift-objc/src/error.rs:50`
- `DR-IOS-0016`: `crates/disrobe-pass-swift-objc/src/error.rs:53`
- `DR-IOS-0017`: `crates/disrobe-pass-swift-objc/src/error.rs:57`
- `DR-IOS-0018`: `crates/disrobe-pass-swift-objc/src/error.rs:66`
- `DR-IOS-0019`: `crates/disrobe-pass-swift-objc/src/error.rs:70`
- `DR-IOS-0020`: `crates/disrobe-pass-swift-objc/src/error.rs:76`
- `DR-IOS-0021`: `crates/disrobe-pass-swift-objc/src/error.rs:82`
- `DR-JS-0901`: `crates/disrobe-pass-js-deob/src/chain_detector.rs:311`
- `DR-JS-0902`: `crates/disrobe-pass-js-deob/src/chain_detector.rs:699`
- `DR-JS-0903`: `crates/disrobe-pass-js-deob/src/chain_detector.rs:702`
- `DR-JS-0904`: `crates/disrobe-pass-js-deob/src/chain_detector.rs:710`
- `DR-JS-0905`: `crates/disrobe-pass-js-deob/src/chain_detector.rs:723`
- `DR-JS-0906`: `crates/disrobe-pass-js-deob/src/chain_detector.rs:726`
- `DR-JS-0907`: `crates/disrobe-pass-js-deob/src/chain_detector.rs:868`
- `DR-JS-0908`: `crates/disrobe-pass-js-deob/src/chain_detector.rs:871`
- `DR-JS-0909`: `crates/disrobe-pass-js-deob/src/chain_detector.rs:884`
- `DR-JS-0910`: `crates/disrobe-pass-js-deob/src/chain_detector.rs:646`
- `DR-JS-0911`: `crates/disrobe-pass-js-deob/src/chain_detector.rs:648`
- `DR-JS-0912`: `crates/disrobe-pass-js-deob/src/chain_detector.rs:650`
- `DR-JS-0913`: `crates/disrobe-pass-js-deob/src/chain_detector.rs:756`
- `DR-JS-0914`: `crates/disrobe-pass-js-deob/src/chain_detector.rs:764`
- `DR-JS-0915`: `crates/disrobe-pass-js-deob/src/chain_detector.rs:758`
- `DR-JS-0916`: `crates/disrobe-pass-js-deob/src/chain_detector.rs:811`
- `DR-JS-0917`: `crates/disrobe-pass-js-deob/src/chain_detector.rs:898`
- `DR-JS-0918`: `crates/disrobe-pass-js-deob/src/chain_detector.rs:736`
- `DR-JS-0919`: `crates/disrobe-pass-js-deob/src/chain_detector.rs:743`
- `DR-JS-0920`: `crates/disrobe-pass-js-deob/src/chain_detector.rs:635`
- `DR-JS-0921`: `crates/disrobe-pass-js-deob/src/chain_detector.rs:704`
- `DR-JS-0922`: `crates/disrobe-pass-js-deob/src/chain_detector.rs:713`
- `DR-JS-0930`: `crates/disrobe-pass-js-deob/src/jscrambler/templates/mod.rs:129`
- `DR-JS-0940`: `crates/disrobe-pass-js-deob/src/esoteric/jsfuck.rs:35`
- `DR-JSDEOB-0005`: `crates/disrobe-pass-js-deob/src/error.rs:23`
- `DR-JSDEOB-0006`: `crates/disrobe-pass-js-deob/src/error.rs:31`
- `DR-JSDEOB-0007`: `crates/disrobe-pass-js-deob/src/error.rs:34`
- `DR-JSDEOB-0010`: `crates/disrobe-pass-js-deob/src/error.rs:38`
- `DR-JSDEOB-0011`: `crates/disrobe-pass-js-deob/src/error.rs:43`
- `DR-JSDEOB-0012`: `crates/disrobe-pass-js-deob/src/error.rs:47`
- `DR-JVM-0001`: `crates/disrobe-pass-jvm/src/error.rs:10`
- `DR-JVM-0002`: `crates/disrobe-pass-jvm/src/error.rs:13`
- `DR-JVM-0003`: `crates/disrobe-pass-jvm/src/error.rs:17`
- `DR-JVM-0004`: `crates/disrobe-pass-jvm/src/error.rs:25`
- `DR-JVM-0005`: `crates/disrobe-pass-jvm/src/error.rs:28`
- `DR-JVM-0006`: `crates/disrobe-pass-jvm/src/error.rs:31`
- `DR-JVM-0007`: `crates/disrobe-pass-jvm/src/error.rs:34`
- `DR-JVM-0008`: `crates/disrobe-pass-jvm/src/error.rs:37`
- `DR-JVM-0009`: `crates/disrobe-pass-jvm/src/error.rs:40`
- `DR-JVM-0010`: `crates/disrobe-pass-jvm/src/error.rs:43`
- `DR-JVM-0011`: `crates/disrobe-pass-jvm/src/error.rs:46`
- `DR-JVM-0012`: `crates/disrobe-pass-jvm/src/error.rs:49`
- `DR-JVM-0013`: `crates/disrobe-pass-jvm/src/error.rs:52`
- `DR-JVM-0014`: `crates/disrobe-pass-jvm/src/error.rs:55`
- `DR-JVM-0015`: `crates/disrobe-pass-jvm/src/error.rs:58`
- `DR-JVM-0016`: `crates/disrobe-pass-jvm/src/error.rs:67`
- `DR-JVM-0017`: `crates/disrobe-pass-jvm/src/error.rs:74`
- `DR-JVM-0018`: `crates/disrobe-pass-jvm/src/error.rs:77`
- `DR-JVM-0019`: `crates/disrobe-pass-jvm/src/error.rs:80`
- `DR-JVM-0020`: `crates/disrobe-pass-jvm/src/error.rs:83`
- `DR-JVM-0021`: `crates/disrobe-pass-jvm/src/error.rs:86`
- `DR-JVM-0022`: `crates/disrobe-pass-jvm/src/error.rs:89`
- `DR-JVM-0023`: `crates/disrobe-pass-jvm/src/error.rs:92`
- `DR-JVM-0024`: `crates/disrobe-pass-jvm/src/error.rs:104`
- `DR-JVM-0025`: `crates/disrobe-pass-jvm/src/error.rs:107`
- `DR-JVM-0026`: `crates/disrobe-pass-jvm/src/error.rs:61`
- `DR-JVM-0027`: `crates/disrobe-pass-jvm/src/error.rs:132`
- `DR-JVM-0028`: `crates/disrobe-pass-jvm/src/error.rs:135`
- `DR-JVM-0029`: `crates/disrobe-pass-jvm/src/error.rs:138`
- `DR-JVM-0030`: `crates/disrobe-pass-jvm/src/error.rs:142`
- `DR-JVM-0031`: `crates/disrobe-pass-jvm/src/error.rs:148`
- `DR-JVM-0032`: `crates/disrobe-pass-jvm/src/error.rs:153`
- `DR-JVM-0033`: `crates/disrobe-pass-jvm/src/error.rs:161`
- `DR-JVM-0034`: `crates/disrobe-pass-jvm/src/attributes.rs:31`, `crates/disrobe-pass-jvm/src/attributes.rs:972`, `crates/disrobe-pass-jvm/src/attributes.rs:981`, `crates/disrobe-pass-jvm/src/error.rs:164`
- `DR-JVM-0035`: `crates/disrobe-pass-jvm/src/error.rs:167`
- `DR-JVM-0036`: `crates/disrobe-pass-jvm/src/error.rs:171`
- `DR-JVM-0090`: `crates/disrobe-pass-jvm/src/error.rs:96`
- `DR-JVM-0091`: `crates/disrobe-pass-jvm/src/error.rs:101`
- `DR-JVM-0092`: `crates/disrobe-pass-jvm/src/error.rs:129`
- `DR-JVM-0093`: `crates/disrobe-pass-jvm/src/dex2jar.rs:1676`, `crates/disrobe-pass-jvm/src/dex2jar.rs:1682`, `crates/disrobe-pass-jvm/src/dex2jar.rs:1732`, `crates/disrobe-pass-jvm/src/dex2jar.rs:1749`, `crates/disrobe-pass-jvm/src/error.rs:126`
- `DR-JVM-0094`: `crates/disrobe-pass-jvm/src/error.rs:110`
- `DR-JVM-0095`: `crates/disrobe-pass-jvm/src/error.rs:123`
- `DR-JVM-0096`: `crates/disrobe-pass-jvm/src/error.rs:117`
- `DR-JVM-0097`: `crates/disrobe-pass-jvm/src/error.rs:120`
- `DR-JVM-0098`: `crates/disrobe-pass-jvm/src/error.rs:177`
- `DR-JVM-0099`: `crates/disrobe-pass-jvm/src/error.rs:180`
- `DR-JVM-0902`: `crates/disrobe-pass-jvm/src/chain_detector.rs:106`
- `DR-JVM-0906`: `crates/disrobe-pass-jvm/src/chain_detector.rs:174`
- `DR-JVM-0907`: `crates/disrobe-pass-jvm/src/chain_detector.rs:181`, `crates/disrobe-pass-jvm/src/chain_detector.rs:243`
- `DR-JVM-0908`: `crates/disrobe-pass-jvm/src/chain_detector.rs:200`, `crates/disrobe-pass-jvm/src/chain_detector.rs:315`
- `DR-JVM-0910`: `crates/disrobe-pass-jvm/src/chain_detector.rs:192`
- `DR-JVM-0911`: `crates/disrobe-pass-jvm/src/chain_detector.rs:205`
- `DR-JVM-0912`: `crates/disrobe-pass-jvm/src/chain_detector/containers.rs:135`
- `DR-JVM-0913`: `crates/disrobe-pass-jvm/src/chain_detector/containers.rs:146`
- `DR-JVM-0914`: `crates/disrobe-pass-jvm/src/chain_detector/containers.rs:300`
- `DR-LUA-0001`: `crates/disrobe-pass-lua/src/error.rs:8`
- `DR-LUA-0002`: `crates/disrobe-pass-lua/src/error.rs:11`
- `DR-LUA-0003`: `crates/disrobe-pass-lua/src/error.rs:14`
- `DR-LUA-0004`: `crates/disrobe-pass-lua/src/error.rs:17`
- `DR-LUA-0005`: `crates/disrobe-pass-lua/src/error.rs:24`
- `DR-LUA-0006`: `crates/disrobe-pass-lua/src/error.rs:28`
- `DR-LUA-0007`: `crates/disrobe-pass-lua/src/error.rs:32`
- `DR-LUA-0008`: `crates/disrobe-pass-lua/src/error.rs:35`
- `DR-LUA-0009`: `crates/disrobe-pass-lua/src/error.rs:38`
- `DR-LUA-0010`: `crates/disrobe-pass-lua/src/error.rs:41`
- `DR-LUA-0011`: `crates/disrobe-pass-lua/src/error.rs:44`
- `DR-LUA-0012`: `crates/disrobe-pass-lua/src/error.rs:47`
- `DR-LUA-0013`: `crates/disrobe-pass-lua/src/error.rs:50`
- `DR-LUA-0014`: `crates/disrobe-pass-lua/src/error.rs:53`
- `DR-LUA-0015`: `crates/disrobe-pass-lua/src/error.rs:56`
- `DR-LUA-0016`: `crates/disrobe-pass-lua/src/error.rs:60`
- `DR-LUA-0017`: `crates/disrobe-pass-lua/src/error.rs:64`
- `DR-LUA-0018`: `crates/disrobe-pass-lua/src/error.rs:67`
- `DR-LUA-0019`: `crates/disrobe-pass-lua/src/error.rs:70`
- `DR-LUA-0020`: `crates/disrobe-pass-lua/src/error.rs:73`
- `DR-LUA-0021`: `crates/disrobe-pass-lua/src/error.rs:76`
- `DR-LUA-0022`: `crates/disrobe-pass-lua/src/error.rs:79`
- `DR-LUA-0023`: `crates/disrobe-pass-lua/src/error.rs:82`
- `DR-LUA-0024`: `crates/disrobe-pass-lua/src/error.rs:85`
- `DR-LUA-0025`: `crates/disrobe-pass-lua/src/error.rs:88`
- `DR-LUA-0026`: `crates/disrobe-pass-lua/src/error.rs:91`
- `DR-LUA-0027`: `crates/disrobe-pass-lua/src/error.rs:94`
- `DR-LUA-0028`: `crates/disrobe-pass-lua/src/error.rs:101`
- `DR-LUA-0029`: `crates/disrobe-pass-lua/src/error.rs:104`
- `DR-LUA-0030`: `crates/disrobe-pass-lua/src/error.rs:107`
- `DR-LUA-0031`: `crates/disrobe-pass-lua/src/error.rs:111`
- `DR-LUA-0032`: `crates/disrobe-pass-lua/src/error.rs:115`
- `DR-LUA-0033`: `crates/disrobe-pass-lua/src/error.rs:119`
- `DR-LUA-0034`: `crates/disrobe-pass-lua/src/error.rs:127`
- `DR-LUA-0035`: `crates/disrobe-pass-lua/src/error.rs:130`
- `DR-LUA-0036`: `crates/disrobe-pass-lua/src/error.rs:137`
- `DR-LUA-0037`: `crates/disrobe-pass-lua/src/error.rs:141`
- `DR-LUA-0902`: `crates/disrobe-pass-lua/src/chain_detector.rs:128`
- `DR-LUA-0903`: `crates/disrobe-pass-lua/src/chain_detector.rs:371`
- `DR-LUA-0904`: `crates/disrobe-pass-lua/src/chain_detector.rs:412`
- `DR-LUA-0905`: `crates/disrobe-pass-lua/src/chain_detector.rs:382`
- `DR-LUA-0906`: `crates/disrobe-pass-lua/src/chain_detector.rs:92`
- `DR-MARSHAL-0013`: `crates/disrobe-py-marshal/src/error.rs:69`
- `DR-MARSHAL-0014`: `crates/disrobe-py-marshal/src/error.rs:74`
- `DR-MARSHAL-0015`: `crates/disrobe-py-marshal/src/error.rs:79`
- `DR-MARSHAL-0016`: `crates/disrobe-py-marshal/src/error.rs:89`
- `DR-MARSHAL-0017`: `crates/disrobe-py-marshal/src/error.rs:99`
- `DR-MARSHAL-0018`: `crates/disrobe-py-marshal/src/error.rs:108`
- `DR-MARSHAL-0019`: `crates/disrobe-py-marshal/src/error.rs:112`
- `DR-MARSHAL-0020`: `crates/disrobe-py-marshal/src/error.rs:116`
- `DR-MARSHAL-0021`: `crates/disrobe-py-marshal/src/error.rs:19`
- `DR-MARSHAL-0022`: `crates/disrobe-py-marshal/src/error.rs:9`
- `DR-MCP-0001`: `crates/disrobe-mcp/src/lib.rs:1425`
- `DR-MCP-0002`: `crates/disrobe-mcp/src/lib.rs:1431`
- `DR-MCP-0003`: `crates/disrobe-mcp/src/lib.rs:1435`
- `DR-MCP-0181`: `crates/disrobe-mcp/src/lib.rs:1114`
- `DR-MCP-0182`: `crates/disrobe-mcp/src/lib.rs:1091`
- `DR-MCP-0183`: `crates/disrobe-mcp/src/lib.rs:1099`
- `DR-MCP-0184`: `crates/disrobe-mcp/src/lib.rs:687`
- `DR-MCP-0185`: `crates/disrobe-mcp/src/lib.rs:1121`
- `DR-MCP-0322`: `crates/disrobe-mcp/src/lib.rs:1198`
- `DR-MCP-0323`: `crates/disrobe-mcp/src/lib.rs:1203`
- `DR-MCP-0324`: `crates/disrobe-mcp/src/lib.rs:1295`
- `DR-MCP-0325`: `crates/disrobe-mcp/src/lib.rs:1278`
- `DR-MCP-0326`: `crates/disrobe-mcp/src/lib.rs:1284`
- `DR-MCP-0327`: `crates/disrobe-mcp/src/lib.rs:1288`
- `DR-MCP-0329`: `crates/disrobe-mcp/src/lib.rs:1330`
- `DR-MCP-0330`: `crates/disrobe-mcp/src/lib.rs:1341`, `crates/disrobe-mcp/src/lib.rs:1351`
- `DR-MCP-0331`: `crates/disrobe-mcp/src/lib.rs:1260`
- `DR-MCP-0333`: `crates/disrobe-mcp/src/lib.rs:713`
- `DR-MCP-0334`: `crates/disrobe-mcp/src/lib.rs:733`
- `DR-MCP-0335`: `crates/disrobe-mcp/src/lib.rs:737`
- `DR-MCP-0336`: `crates/disrobe-mcp/src/lib.rs:1243`
- `DR-MCP-0337`: `crates/disrobe-mcp/src/lib.rs:1225`
- `DR-MCP-0338`: `crates/disrobe-mcp/src/lib.rs:1152`, `crates/disrobe-mcp/src/lib.rs:1153`, `crates/disrobe-mcp/src/lib.rs:1155`
- `DR-MCP-0339`: `crates/disrobe-mcp/src/lib.rs:1234`
- `DR-MCP-0340`: `crates/disrobe-mcp/src/lib.rs:721`, `crates/disrobe-mcp/src/lib.rs:1359`
- `DR-MCP-0341`: `crates/disrobe-mcp/src/lib.rs:1346`
- `DR-MCP-0342`: `crates/disrobe-mcp/src/lib.rs:1370`
- `DR-MCP-0343`: `crates/disrobe-mcp/src/lib.rs:1375`, `crates/disrobe-mcp/src/lib.rs:1376`, `crates/disrobe-mcp/src/lib.rs:1378`
- `DR-MCP-0530`: `crates/disrobe-mcp/src/lib.rs:787`
- `DR-MCP-0531`: `crates/disrobe-mcp/src/lib.rs:782`
- `DR-MCP-0532`: `crates/disrobe-mcp/src/lib.rs:794`
- `DR-MCP-0610`: `crates/disrobe-mcp/src/lib.rs:820`
- `DR-MCP-0611`: `crates/disrobe-mcp/src/lib.rs:818`
- `DR-MCP-0612`: `crates/disrobe-mcp/src/lib.rs:833`
- `DR-MCP-0620`: `crates/disrobe-mcp/src/lib.rs:873`
- `DR-MCP-0621`: `crates/disrobe-mcp/src/lib.rs:871`
- `DR-MCP-0640`: `crates/disrobe-mcp/src/lib.rs:964`
- `DR-MCP-0641`: `crates/disrobe-mcp/src/lib.rs:1161`
- `DR-MCP-0642`: `crates/disrobe-mcp/src/lib.rs:1163`
- `DR-MCP-0650`: `crates/disrobe-mcp/src/navigation.rs:597`
- `DR-MCP-0651`: `crates/disrobe-mcp/src/navigation.rs:607`
- `DR-MCP-0652`: `crates/disrobe-mcp/src/navigation.rs:733`, `crates/disrobe-mcp/src/navigation.rs:778`
- `DR-MCP-0653`: `crates/disrobe-mcp/src/navigation.rs:751`
- `DR-MCP-0654`: `crates/disrobe-mcp/src/navigation.rs:688`, `crates/disrobe-mcp/src/navigation.rs:691`
- `DR-MCP-0655`: `crates/disrobe-mcp/src/navigation.rs:698`
- `DR-MCP-0656`: `crates/disrobe-mcp/src/navigation.rs:702`, `crates/disrobe-mcp/src/navigation.rs:706`
- `DR-MCP-0657`: `crates/disrobe-mcp/src/navigation.rs:466`
- `DR-MCP-0658`: `crates/disrobe-mcp/src/navigation.rs:460`
- `DR-MCP-0659`: `crates/disrobe-mcp/src/navigation.rs:718`
- `DR-MCP-0660`: `crates/disrobe-mcp/src/lib.rs:944`, `crates/disrobe-mcp/src/navigation.rs:47`, `crates/disrobe-mcp/src/navigation.rs:53`, `crates/disrobe-mcp/src/navigation.rs:803`, `crates/disrobe-mcp/src/navigation.rs:813`
- `DR-MCP-0661`: `crates/disrobe-mcp/src/navigation.rs:507`, `crates/disrobe-mcp/src/navigation.rs:626`
- `DR-MCP-0662`: `crates/disrobe-mcp/src/navigation.rs:641`
- `DR-MCP-0670`: `crates/disrobe-mcp/src/lib.rs:1037`
- `DR-MCP-0680`: `crates/disrobe-mcp/src/lib.rs:666`, `crates/disrobe-mcp/src/lib.rs:670`
- `DR-MOB-0001`: `crates/disrobe-pass-mobile/src/error.rs:8`
- `DR-MOB-0002`: `crates/disrobe-pass-mobile/src/error.rs:11`
- `DR-MOB-0003`: `crates/disrobe-pass-mobile/src/error.rs:14`
- `DR-MOB-0004`: `crates/disrobe-pass-mobile/src/error.rs:17`
- `DR-MOB-0005`: `crates/disrobe-pass-mobile/src/error.rs:20`
- `DR-MOB-0006`: `crates/disrobe-pass-mobile/src/error.rs:23`
- `DR-MOB-0007`: `crates/disrobe-pass-mobile/src/error.rs:31`
- `DR-MOB-0008`: `crates/disrobe-pass-mobile/src/error.rs:34`
- `DR-MOB-0009`: `crates/disrobe-pass-mobile/src/error.rs:38`
- `DR-MOB-0010`: `crates/disrobe-pass-mobile/src/error.rs:46`
- `DR-MOB-0011`: `crates/disrobe-pass-mobile/src/error.rs:55`
- `DR-MOB-0012`: `crates/disrobe-pass-mobile/src/error.rs:59`
- `DR-MOB-0013`: `crates/disrobe-pass-mobile/src/error.rs:62`
- `DR-MOB-0014`: `crates/disrobe-pass-mobile/src/error.rs:65`
- `DR-MOB-0015`: `crates/disrobe-pass-mobile/src/error.rs:68`
- `DR-MOB-0016`: `crates/disrobe-pass-mobile/src/error.rs:71`
- `DR-MOB-0017`: `crates/disrobe-pass-mobile/src/error.rs:74`
- `DR-MOB-0018`: `crates/disrobe-pass-mobile/src/error.rs:77`
- `DR-MOB-0019`: `crates/disrobe-pass-mobile/src/error.rs:80`
- `DR-MOB-0020`: `crates/disrobe-pass-mobile/src/error.rs:86`
- `DR-MOB-0021`: `crates/disrobe-pass-mobile/src/error.rs:89`
- `DR-MOB-0022`: `crates/disrobe-pass-mobile/src/error.rs:27`
- `DR-MOB-0023`: `crates/disrobe-pass-mobile/src/error.rs:92`
- `DR-MOB-0024`: `crates/disrobe-pass-mobile/src/error.rs:95`
- `DR-MOB-0025`: `crates/disrobe-pass-mobile/src/error.rs:98`
- `DR-MOB-0026`: `crates/disrobe-pass-mobile/src/error.rs:101`
- `DR-MOB-0027`: `crates/disrobe-pass-mobile/src/error.rs:104`
- `DR-MOB-0028`: `crates/disrobe-pass-mobile/src/error.rs:107`
- `DR-MOB-0029`: `crates/disrobe-pass-mobile/src/error.rs:110`
- `DR-MOB-0030`: `crates/disrobe-pass-mobile/src/error.rs:113`
- `DR-MOB-0031`: `crates/disrobe-pass-mobile/src/error.rs:83`
- `DR-MOB-0032`: `crates/disrobe-pass-mobile/src/error.rs:116`
- `DR-MOB-0033`: `crates/disrobe-pass-mobile/src/error.rs:120`
- `DR-MOB-0034`: `crates/disrobe-pass-mobile/src/error.rs:125`
- `DR-MOB-0035`: `crates/disrobe-pass-mobile/src/error.rs:133`
- `DR-MOB-0036`: `crates/disrobe-pass-mobile/src/error.rs:143`
- `DR-MOB-0037`: `crates/disrobe-pass-mobile/src/error.rs:152`
- `DR-MOB-0038`: `crates/disrobe-pass-mobile/src/error.rs:162`
- `DR-MOB-0039`: `crates/disrobe-pass-mobile/src/error.rs:167`
- `DR-MOB-0040`: `crates/disrobe-pass-mobile/src/error.rs:176`
- `DR-MOB-0041`: `crates/disrobe-pass-mobile/src/error.rs:186`
- `DR-MOB-0042`: `crates/disrobe-pass-mobile/src/error.rs:195`
- `DR-MOB-0043`: `crates/disrobe-pass-mobile/src/error.rs:205`
- `DR-MOB-0044`: `crates/disrobe-pass-mobile/src/error.rs:209`
- `DR-MOB-0045`: `crates/disrobe-pass-mobile/src/error.rs:218`
- `DR-MOB-0046`: `crates/disrobe-pass-mobile/src/error.rs:223`
- `DR-MOB-0047`: `crates/disrobe-pass-mobile/src/error.rs:227`
- `DR-MOB-0048`: `crates/disrobe-pass-mobile/src/error.rs:230`
- `DR-MOB-0049`: `crates/disrobe-pass-mobile/src/error.rs:234`
- `DR-MOB-0050`: `crates/disrobe-pass-mobile/src/error.rs:243`
- `DR-MOB-0051`: `crates/disrobe-pass-mobile/src/error.rs:251`
- `DR-MOB-0052`: `crates/disrobe-pass-mobile/src/error.rs:254`
- `DR-MOB-0053`: `crates/disrobe-pass-mobile/src/error.rs:258`
- `DR-MOB-0054`: `crates/disrobe-pass-mobile/src/error.rs:263`
- `DR-MOB-0055`: `crates/disrobe-pass-mobile/src/error.rs:267`
- `DR-MOB-0056`: `crates/disrobe-pass-mobile/src/error.rs:271`
- `DR-MOB-0057`: `crates/disrobe-pass-mobile/src/error.rs:276`
- `DR-MOB-0058`: `crates/disrobe-pass-mobile/src/error.rs:280`
- `DR-MOB-0059`: `crates/disrobe-pass-mobile/src/error.rs:283`
- `DR-MOB-0060`: `crates/disrobe-pass-mobile/src/error.rs:287`
- `DR-MOB-0061`: `crates/disrobe-pass-mobile/src/error.rs:291`
- `DR-MOB-0062`: `crates/disrobe-pass-mobile/src/error.rs:295`
- `DR-MOB-0063`: `crates/disrobe-pass-mobile/src/error.rs:50`
- `DR-MOB-0064`: `crates/disrobe-pass-mobile/src/error.rs:181`
- `DR-MOB-0902`: `crates/disrobe-pass-mobile/src/chain_detector.rs:94`
- `DR-MOB-0905`: `crates/disrobe-pass-mobile/src/chain_detector.rs:115`
- `DR-MOB-0906`: `crates/disrobe-pass-mobile/src/chain_detector.rs:126`
- `DR-NAT-0901`: `crates/disrobe-pass-native/src/chain_detector.rs:494`
- `DR-NAT-0902`: `crates/disrobe-pass-native/src/chain_detector.rs:764`
- `DR-NAT-0907`: `crates/disrobe-pass-native/src/chain_detector.rs:775`
- `DR-NAT-0908`: `crates/disrobe-pass-native/src/chain_detector.rs:780`
- `DR-NAT-0909`: `crates/disrobe-pass-native/src/chain_detector.rs:790`
- `DR-NAT-0910`: `crates/disrobe-pass-native/src/chain_detector.rs:865`
- `DR-NAT-0911`: `crates/disrobe-pass-native/src/chain_detector.rs:871`
- `DR-NAT-0912`: `crates/disrobe-pass-native/src/chain_detector.rs:876`
- `DR-NAT-0913`: `crates/disrobe-pass-native/src/chain_detector.rs:881`
- `DR-NAT-0914`: `crates/disrobe-pass-native/src/chain_detector.rs:913`
- `DR-NAT-0915`: `crates/disrobe-pass-native/src/chain_detector.rs:921`, `crates/disrobe-pass-native/src/chain_detector.rs:942`
- `DR-NAT-0916`: `crates/disrobe-pass-native/src/chain_detector.rs:886`
- `DR-NAT-0917`: `crates/disrobe-pass-native/src/chain_detector.rs:860`
- `DR-NAT-0918`: `crates/disrobe-pass-native/src/chain_detector.rs:891`
- `DR-NAT-0919`: `crates/disrobe-pass-native/src/chain_detector.rs:896`
- `DR-NAT-0920`: `crates/disrobe-pass-native/src/chain_detector.rs:902`
- `DR-NAT-0921`: `crates/disrobe-pass-native/src/chain_detector.rs:908`
- `DR-NAT-0928`: `crates/disrobe-pass-native/src/chain_detector.rs:960`
- `DR-NAT-0930`: `crates/disrobe-pass-native/src/chain_detector.rs:770`
- `DR-NAT-0931`: `crates/disrobe-pass-native/src/chain_detector.rs:853`
- `DR-NAT-0933`: `crates/disrobe-pass-native/src/chain_detector.rs:525`
- `DR-NAT-0940`: `crates/disrobe-pass-native/src/chain_detector.rs:133`
- `DR-NAT-0941`: `crates/disrobe-pass-native/src/chain_detector.rs:365`
- `DR-NAT-0942`: `crates/disrobe-pass-native/src/chain_detector.rs:173`
- `DR-NAT-0943`: `crates/disrobe-pass-native/src/chain_detector.rs:180`
- `DR-NAT-0944`: `crates/disrobe-pass-native/src/chain_detector.rs:253`, `crates/disrobe-pass-native/src/chain_detector.rs:653`
- `DR-NATIVE-0001`: `crates/disrobe-cli/src/cli/native.rs:1335`, `crates/disrobe-pass-native/src/error.rs:9`
- `DR-NATIVE-0002`: `crates/disrobe-cli/src/cli/native.rs:1346`, `crates/disrobe-pass-native/src/error.rs:12`
- `DR-NATIVE-0003`: `crates/disrobe-cli/src/cli/native.rs:1349`, `crates/disrobe-cli/src/cli/native.rs:1353`, `crates/disrobe-pass-native/src/error.rs:16`
- `DR-NATIVE-0004`: `crates/disrobe-cli/src/cli/native.rs:40`, `crates/disrobe-pass-native/src/error.rs:20`
- `DR-NATIVE-0005`: `crates/disrobe-cli/src/cli/native.rs:1411`, `crates/disrobe-pass-native/src/error.rs:23`
- `DR-NATIVE-0006`: `crates/disrobe-cli/src/cli/native.rs:1413`, `crates/disrobe-pass-native/src/error.rs:26`
- `DR-NATIVE-0007`: `crates/disrobe-cli/src/cli/native.rs:1417`, `crates/disrobe-pass-native/src/error.rs:29`
- `DR-NATIVE-0008`: `crates/disrobe-cli/src/cli/native.rs:1357`, `crates/disrobe-pass-native/src/error.rs:32`
- `DR-NATIVE-0009`: `crates/disrobe-cli/src/cli/native.rs:1381`, `crates/disrobe-cli/src/cli/native.rs:1478`, `crates/disrobe-pass-native/src/error.rs:35`
- `DR-NATIVE-0010`: `crates/disrobe-cli/src/cli/native.rs:1454`, `crates/disrobe-cli/src/cli/native.rs:2636`, `crates/disrobe-pass-native/src/error.rs:38`
- `DR-NATIVE-0011`: `crates/disrobe-cli/src/cli/native.rs:1458`, `crates/disrobe-cli/src/cli/native.rs:2647`
- `DR-NATIVE-0012`: `crates/disrobe-cli/src/cli/native.rs:2650`
- `DR-NATIVE-0013`: `crates/disrobe-cli/src/cli/native.rs:2652`
- `DR-NATIVE-0015`: `crates/disrobe-pass-native/src/error.rs:45`
- `DR-NATIVE-0016`: `crates/disrobe-pass-native/src/error.rs:50`
- `DR-NATIVE-0017`: `crates/disrobe-pass-native/src/error.rs:54`
- `DR-NATIVE-0018`: `crates/disrobe-pass-native/src/error.rs:57`
- `DR-NATIVE-0019`: `crates/disrobe-pass-native/src/error.rs:60`
- `DR-NATIVE-0020`: `crates/disrobe-cli/src/cli/native.rs:3550`
- `DR-NATIVE-0022`: `crates/disrobe-pass-native/src/error.rs:63`
- `DR-NATIVE-0023`: `crates/disrobe-pass-native/src/error.rs:66`
- `DR-NATIVE-0024`: `crates/disrobe-pass-native/src/error.rs:69`
- `DR-NATIVE-0025`: `crates/disrobe-pass-native/src/error.rs:72`
- `DR-NATIVE-0026`: `crates/disrobe-pass-native/src/error.rs:75`
- `DR-NATIVE-0027`: `crates/disrobe-pass-native/src/error.rs:79`
- `DR-NATIVE-0028`: `crates/disrobe-pass-native/src/error.rs:87`
- `DR-NATIVE-0029`: `crates/disrobe-pass-native/src/error.rs:91`
- `DR-NATIVE-0030`: `crates/disrobe-cli/src/cli/native.rs:1684`, `crates/disrobe-pass-native/src/error.rs:95`
- `DR-NATIVE-0031`: `crates/disrobe-cli/src/cli/native.rs:1531`
- `DR-NATIVE-0035`: `crates/disrobe-cli/src/cli/native.rs:1548`
- `DR-NATIVE-0036`: `crates/disrobe-cli/src/cli/native.rs:1553`
- `DR-NATIVE-0037`: `crates/disrobe-cli/src/cli/native.rs:1558`
- `DR-NATIVE-0038`: `crates/disrobe-cli/src/cli/native.rs:1565`
- `DR-NATIVE-0039`: `crates/disrobe-cli/src/cli/native.rs:1570`
- `DR-NATIVE-0040`: `crates/disrobe-cli/src/cli/native.rs:1613`
- `DR-NATIVE-0041`: `crates/disrobe-cli/src/cli/native.rs:1620`
- `DR-NATIVE-0042`: `crates/disrobe-cli/src/cli/native.rs:1632`
- `DR-NATIVE-0043`: `crates/disrobe-cli/src/cli/native.rs:1638`
- `DR-NATIVE-0044`: `crates/disrobe-cli/src/cli/native.rs:1644`
- `DR-NATIVE-0045`: `crates/disrobe-cli/src/cli/native.rs:1652`
- `DR-NATIVE-0046`: `crates/disrobe-cli/src/cli/native.rs:1699`
- `DR-NATIVE-0047`: `crates/disrobe-cli/src/cli/native.rs:1702`
- `DR-NATIVE-0048`: `crates/disrobe-cli/src/cli/native.rs:1543`
- `DR-NATIVE-0049`: `crates/disrobe-cli/src/cli/native.rs:1575`
- `DR-NATIVE-0050`: `crates/disrobe-cli/src/cli/native.rs:1590`, `crates/disrobe-cli/src/cli/native.rs:2500`, `crates/disrobe-cli/src/cli/native.rs:3311`
- `DR-NATIVE-0051`: `crates/disrobe-cli/src/cli/native.rs:2542`, `crates/disrobe-cli/src/cli/native.rs:3392`, `crates/disrobe-cli/src/cli/native.rs:3443`
- `DR-NATIVE-0052`: `crates/disrobe-cli/src/cli/native.rs:1599`, `crates/disrobe-cli/src/cli/native.rs:2545`, `crates/disrobe-cli/src/cli/native.rs:3395`, `crates/disrobe-cli/src/cli/native.rs:3446`
- `DR-NATIVE-0053`: `crates/disrobe-cli/src/cli/native.rs:2547`, `crates/disrobe-cli/src/cli/native.rs:3397`, `crates/disrobe-cli/src/cli/native.rs:3448`
- `DR-NATIVE-0054`: `crates/disrobe-cli/src/cli/native.rs:1608`, `crates/disrobe-cli/src/cli/native.rs:2507`, `crates/disrobe-cli/src/cli/native.rs:3355`
- `DR-NATIVE-0055`: `crates/disrobe-cli/src/cli/native.rs:2509`, `crates/disrobe-cli/src/cli/native.rs:3358`
- `DR-NATIVE-0059`: `crates/disrobe-cli/src/cli/native.rs:1578`
- `DR-NATIVE-0060`: `crates/disrobe-cli/src/cli/native.rs:1626`, `crates/disrobe-cli/src/cli/native.rs:2042`, `crates/disrobe-cli/src/cli/native.rs:2045`, `crates/disrobe-cli/src/cli/native.rs:2048`, `crates/disrobe-cli/src/cli/native.rs:2053`, `crates/disrobe-cli/src/cli/native.rs:2059`, `crates/disrobe-cli/src/cli/native.rs:2064`, `crates/disrobe-cli/src/cli/native.rs:2068`, `crates/disrobe-cli/src/cli/native.rs:2073`, `crates/disrobe-cli/src/cli/native.rs:2082`, `crates/disrobe-cli/src/cli/native.rs:2092`, `crates/disrobe-cli/src/cli/native.rs:2097`, `crates/disrobe-cli/src/cli/native.rs:2102`, `crates/disrobe-cli/src/cli/native.rs:2106`, `crates/disrobe-cli/src/cli/native.rs:2116`, `crates/disrobe-cli/src/cli/native.rs:2120`, `crates/disrobe-cli/src/cli/native.rs:2595`
- `DR-NATIVE-0061`: `crates/disrobe-cli/src/cli/native.rs:1982`, `crates/disrobe-cli/src/cli/native.rs:2599`
- `DR-NATIVE-0062`: `crates/disrobe-cli/src/cli/native.rs:2027`, `crates/disrobe-cli/src/cli/native.rs:2602`
- `DR-NATIVE-0063`: `crates/disrobe-cli/src/cli/native.rs:2004`, `crates/disrobe-cli/src/cli/native.rs:2019`, `crates/disrobe-cli/src/cli/native.rs:2617`
- `DR-NATIVE-0064`: `crates/disrobe-cli/src/cli/native.rs:2030`, `crates/disrobe-cli/src/cli/native.rs:2620`
- `DR-NATIVE-0065`: `crates/disrobe-cli/src/cli/native.rs:1997`, `crates/disrobe-cli/src/cli/native.rs:2622`
- `DR-NATIVE-0066`: `crates/disrobe-cli/src/cli/native.rs:1680`, `crates/disrobe-cli/src/cli/native.rs:2009`
- `DR-NATIVE-0067`: `crates/disrobe-cli/src/cli/native.rs:1994`, `crates/disrobe-cli/src/cli/native.rs:2014`
- `DR-NATIVE-0070`: `crates/disrobe-cli/src/cli/native.rs:2861`
- `DR-NATIVE-0071`: `crates/disrobe-cli/src/cli/native.rs:2863`
- `DR-NATIVE-0072`: `crates/disrobe-cli/src/cli/native.rs:2883`
- `DR-NATIVE-0073`: `crates/disrobe-cli/src/cli/native.rs:2886`
- `DR-NATIVE-0090`: `crates/disrobe-cli/src/cli/native.rs:2817`
- `DR-NATIVE-0091`: `crates/disrobe-cli/src/cli/native.rs:2829`
- `DR-NATIVE-0092`: `crates/disrobe-cli/src/cli/native.rs:2832`
- `DR-NATIVE-0093`: `crates/disrobe-cli/src/cli/native.rs:2834`
- `DR-NATIVE-0100`: `crates/disrobe-cli/src/cli/native.rs:1853`
- `DR-NATIVE-0101`: `crates/disrobe-cli/src/cli/native.rs:1834`
- `DR-NATIVE-0102`: `crates/disrobe-cli/src/cli/native.rs:1867`
- `DR-NATIVE-0103`: `crates/disrobe-cli/src/cli/native.rs:1878`
- `DR-NATIVE-0104`: `crates/disrobe-cli/src/cli/native.rs:1882`
- `DR-NATIVE-0105`: `crates/disrobe-cli/src/cli/native.rs:1888`, `crates/disrobe-cli/src/cli/native.rs:1890`, `crates/disrobe-cli/src/cli/native.rs:1892`
- `DR-NATIVE-0106`: `crates/disrobe-cli/src/cli/native.rs:1895`
- `DR-NATIVE-0107`: `crates/disrobe-cli/src/cli/native.rs:1900`
- `DR-NATIVE-0108`: `crates/disrobe-cli/src/cli/native.rs:1902`
- `DR-NATIVE-0109`: `crates/disrobe-cli/src/cli/native.rs:1942`
- `DR-NATIVE-0110`: `crates/disrobe-cli/src/cli/native.rs:1944`
- `DR-NATIVE-0111`: `crates/disrobe-cli/src/cli/native.rs:1823`
- `DR-NATIVE-0112`: `crates/disrobe-cli/src/cli/native.rs:1827`
- `DR-NATIVE-0120`: `crates/disrobe-cli/src/cli/native.rs:2743`
- `DR-NATIVE-0121`: `crates/disrobe-cli/src/cli/native.rs:2745`
- `DR-NATIVE-0122`: `crates/disrobe-cli/src/cli/native.rs:2757`
- `DR-NATIVE-0123`: `crates/disrobe-cli/src/cli/native.rs:2772`
- `DR-NATIVE-0124`: `crates/disrobe-cli/src/cli/native.rs:2776`
- `DR-NATIVE-0125`: `crates/disrobe-cli/src/cli/native.rs:2779`
- `DR-NATIVE-0126`: `crates/disrobe-cli/src/cli/native.rs:2795`
- `DR-NATIVE-0127`: `crates/disrobe-cli/src/cli/native.rs:2797`
- `DR-NATIVE-0140`: `crates/disrobe-cli/src/cli/native.rs:2968`
- `DR-NATIVE-0141`: `crates/disrobe-cli/src/cli/native.rs:2983`, `crates/disrobe-cli/src/cli/native.rs:3052`
- `DR-NATIVE-0142`: `crates/disrobe-cli/src/cli/native.rs:2989`
- `DR-NATIVE-0143`: `crates/disrobe-cli/src/cli/native.rs:3005`
- `DR-NATIVE-0144`: `crates/disrobe-cli/src/cli/native.rs:3013`
- `DR-NATIVE-0145`: `crates/disrobe-cli/src/cli/native.rs:3016`
- `DR-NATIVE-0146`: `crates/disrobe-cli/src/cli/native.rs:3083`
- `DR-NATIVE-0147`: `crates/disrobe-cli/src/cli/native.rs:3091`
- `DR-NATIVE-0148`: `crates/disrobe-cli/src/cli/native.rs:2996`
- `DR-NATIVE-0149`: `crates/disrobe-cli/src/cli/native.rs:3046`
- `DR-NATIVE-0150`: `crates/disrobe-cli/src/cli/native.rs:3197`
- `DR-NATIVE-0151`: `crates/disrobe-cli/src/cli/native.rs:3209`
- `DR-NATIVE-0152`: `crates/disrobe-cli/src/cli/native.rs:3215`
- `DR-NATIVE-0153`: `crates/disrobe-cli/src/cli/native.rs:3218`
- `DR-NATIVE-0160`: `crates/disrobe-cli/src/cli/native.rs:199`, `crates/disrobe-cli/src/cli/native.rs:3878`
- `DR-NATIVE-0161`: `crates/disrobe-cli/src/cli/native.rs:202`, `crates/disrobe-cli/src/cli/native.rs:3888`
- `DR-NATIVE-0162`: `crates/disrobe-cli/src/cli/native.rs:206`, `crates/disrobe-cli/src/cli/native.rs:3890`
- `DR-NATIVE-0163`: `crates/disrobe-cli/src/cli/native.rs:229`, `crates/disrobe-cli/src/cli/native.rs:3895`
- `DR-NATIVE-0164`: `crates/disrobe-cli/src/cli/native.rs:418`, `crates/disrobe-cli/src/cli/native.rs:3900`
- `DR-NATIVE-0165`: `crates/disrobe-cli/src/cli/native.rs:449`, `crates/disrobe-cli/src/cli/native.rs:3911`
- `DR-NATIVE-0166`: `crates/disrobe-cli/src/cli/native.rs:451`, `crates/disrobe-cli/src/cli/native.rs:3914`
- `DR-NATIVE-0167`: `crates/disrobe-cli/src/cli/native.rs:400`, `crates/disrobe-cli/src/cli/native.rs:3883`
- `DR-NATIVE-0168`: `crates/disrobe-cli/src/cli/native.rs:402`
- `DR-NATIVE-0169`: `crates/disrobe-cli/src/cli/native.rs:1274`
- `DR-NATIVE-0170`: `crates/disrobe-cli/src/cli/native.rs:986`, `crates/disrobe-cli/src/cli/native.rs:3935`
- `DR-NATIVE-0171`: `crates/disrobe-cli/src/cli/native.rs:1184`, `crates/disrobe-cli/src/cli/native.rs:3937`
- `DR-NATIVE-0172`: `crates/disrobe-cli/src/cli/native.rs:1240`
- `DR-NATIVE-0173`: `crates/disrobe-cli/src/cli/native.rs:1242`
- `DR-NATIVE-0174`: `crates/disrobe-cli/src/cli/native.rs:970`
- `DR-NATIVE-0175`: `crates/disrobe-cli/src/cli/native.rs:975`
- `DR-NATIVE-0180`: `crates/disrobe-cli/src/cli/native.rs:4039`
- `DR-NATIVE-0181`: `crates/disrobe-cli/src/cli/native.rs:4041`
- `DR-NATIVE-0182`: `crates/disrobe-cli/src/cli/native.rs:4046`
- `DR-NATIVE-0190`: `crates/disrobe-cli/src/cli/native.rs:2369`
- `DR-NATIVE-0191`: `crates/disrobe-cli/src/cli/native.rs:2373`
- `DR-NATIVE-0192`: `crates/disrobe-cli/src/cli/native.rs:2389`
- `DR-NATIVE-0193`: `crates/disrobe-cli/src/cli/native.rs:2397`
- `DR-NATIVE-0194`: `crates/disrobe-cli/src/cli/native.rs:2428`
- `DR-NATIVE-0195`: `crates/disrobe-cli/src/cli/native.rs:2431`
- `DR-NATIVE-0200`: `crates/disrobe-cli/src/cli/native_match.rs:65`
- `DR-NATIVE-0201`: `crates/disrobe-cli/src/cli/native_match.rs:67`
- `DR-NATIVE-0202`: `crates/disrobe-pass-native/src/native_match.rs:31`
- `DR-NATIVE-0203`: `crates/disrobe-pass-native/src/native_match.rs:33`
- `DR-NATIVE-0204`: `crates/disrobe-pass-native/src/native_match.rs:36`
- `DR-NATIVE-0205`: `crates/disrobe-cli/src/cli/native_match.rs:156`
- `DR-NATIVE-0206`: `crates/disrobe-cli/src/cli/native_match.rs:166`
- `DR-NATIVE-0207`: `crates/disrobe-cli/src/cli/native_match.rs:159`, `crates/disrobe-cli/src/cli/native_match.rs:164`, `crates/disrobe-cli/src/cli/native_match.rs:170`
- `DR-NATIVE-0208`: `crates/disrobe-pass-native/src/native_match.rs:44`
- `DR-NATIVE-0209`: `crates/disrobe-pass-native/src/native_match.rs:46`, `crates/disrobe-python/src/native.rs:67`
- `DR-NATIVE-0210`: `crates/disrobe-cli/src/cli/native.rs:4098`
- `DR-NATIVE-0211`: `crates/disrobe-cli/src/cli/native.rs:4123`
- `DR-NATIVE-0212`: `crates/disrobe-cli/src/cli/native.rs:4103`, `crates/disrobe-cli/src/cli/native.rs:4126`
- `DR-NATIVE-0213`: `crates/disrobe-cli/src/cli/native.rs:4128`
- `DR-NATIVE-0214`: `crates/disrobe-cli/src/cli/native.rs:2205`
- `DR-NATIVE-0215`: `crates/disrobe-cli/src/cli/native.rs:2208`
- `DR-NATIVE-0216`: `crates/disrobe-cli/src/cli/native.rs:2267`
- `DR-NATIVE-0217`: `crates/disrobe-cli/src/cli/native.rs:2296`
- `DR-NATIVE-0218`: `crates/disrobe-cli/src/cli/native.rs:2299`
- `DR-NATIVELANG-0001`: `crates/disrobe-pass-nativelang/src/error.rs:8`
- `DR-NATIVELANG-0002`: `crates/disrobe-pass-nativelang/src/error.rs:11`
- `DR-NATIVELANG-0003`: `crates/disrobe-pass-nativelang/src/error.rs:14`
- `DR-NATIVELANG-0004`: `crates/disrobe-pass-nativelang/src/error.rs:18`
- `DR-NLANG-0901`: `crates/disrobe-pass-nativelang/src/chain_detector.rs:73`
- `DR-NLANG-0902`: `crates/disrobe-pass-nativelang/src/chain_detector.rs:79`
- `DR-NUITKA-0011`: `crates/disrobe-pass-nuitka/src/error.rs:40`
- `DR-NUITKA-0012`: `crates/disrobe-pass-nuitka/src/error.rs:43`
- `DR-NUITKA-0013`: `crates/disrobe-pass-nuitka/src/error.rs:47`
- `DR-NUITKA-0014`: `crates/disrobe-pass-nuitka/src/error.rs:51`
- `DR-NUITKA-0015`: `crates/disrobe-pass-nuitka/src/error.rs:54`
- `DR-NUITKA-0016`: `crates/disrobe-pass-nuitka/src/error.rs:57`
- `DR-NUITKA-0017`: `crates/disrobe-pass-nuitka/src/error.rs:60`
- `DR-NUITKA-0018`: `crates/disrobe-pass-nuitka/src/error.rs:63`
- `DR-NUITKA-0019`: `crates/disrobe-pass-nuitka/src/error.rs:66`
- `DR-NUITKA-0020`: `crates/disrobe-pass-nuitka/src/error.rs:69`
- `DR-NUITKA-0021`: `crates/disrobe-pass-nuitka/src/error.rs:72`
- `DR-NUITKA-0022`: `crates/disrobe-pass-nuitka/src/error.rs:76`
- `DR-NUITKA-0023`: `crates/disrobe-pass-nuitka/src/error.rs:80`
- `DR-NUITKA-0024`: `crates/disrobe-pass-nuitka/src/error.rs:83`
- `DR-NUITKA-0025`: `crates/disrobe-pass-nuitka/src/error.rs:86`
- `DR-NUITKA-0026`: `crates/disrobe-pass-nuitka/src/error.rs:89`
- `DR-NUITKA-0027`: `crates/disrobe-pass-nuitka/src/error.rs:96`
- `DR-NUITKA-0028`: `crates/disrobe-pass-nuitka/src/error.rs:104`
- `DR-NUITKA-0029`: `crates/disrobe-pass-nuitka/src/error.rs:109`
- `DR-NUITKA-0030`: `crates/disrobe-pass-nuitka/src/error.rs:114`
- `DR-NUITKA-0031`: `crates/disrobe-pass-nuitka/src/error.rs:118`
- `DR-NUITKA-0032`: `crates/disrobe-pass-nuitka/src/error.rs:124`
- `DR-NUITKA-0033`: `crates/disrobe-pass-nuitka/src/error.rs:131`
- `DR-NUITKA-0904`: `crates/disrobe-pass-nuitka/src/chain_detector.rs:78`
- `DR-NUITKA-0906`: `crates/disrobe-pass-nuitka/src/chain_detector.rs:196`
- `DR-NUITKA-0907`: `crates/disrobe-pass-nuitka/src/chain_detector.rs:300`
- `DR-PHP-0001`: `crates/disrobe-pass-php/src/error.rs:8`
- `DR-PHP-0010`: `crates/disrobe-pass-php/src/error.rs:11`
- `DR-PHP-0011`: `crates/disrobe-pass-php/src/error.rs:14`
- `DR-PHP-0012`: `crates/disrobe-pass-php/src/error.rs:17`
- `DR-PHP-0013`: `crates/disrobe-pass-php/src/error.rs:20`
- `DR-PHP-0020`: `crates/disrobe-pass-php/src/error.rs:23`
- `DR-PHP-0021`: `crates/disrobe-pass-php/src/error.rs:27`
- `DR-PHP-0022`: `crates/disrobe-pass-php/src/error.rs:31`
- `DR-PHP-0023`: `crates/disrobe-pass-php/src/error.rs:34`
- `DR-PHP-0024`: `crates/disrobe-pass-php/src/error.rs:37`
- `DR-PHP-0025`: `crates/disrobe-pass-php/src/error.rs:40`
- `DR-PHP-0026`: `crates/disrobe-pass-php/src/error.rs:43`
- `DR-PHP-0027`: `crates/disrobe-pass-php/src/error.rs:46`
- `DR-PHP-0028`: `crates/disrobe-pass-php/src/error.rs:50`
- `DR-PHP-0029`: `crates/disrobe-pass-php/src/error.rs:55`
- `DR-PHP-0030`: `crates/disrobe-pass-php/src/error.rs:69`
- `DR-PHP-0031`: `crates/disrobe-pass-php/src/error.rs:72`
- `DR-PHP-0032`: `crates/disrobe-pass-php/src/error.rs:75`
- `DR-PHP-0033`: `crates/disrobe-pass-php/src/error.rs:78`
- `DR-PHP-0034`: `crates/disrobe-pass-php/src/error.rs:81`
- `DR-PHP-0035`: `crates/disrobe-pass-php/src/error.rs:85`
- `DR-PHP-0036`: `crates/disrobe-pass-php/src/error.rs:89`
- `DR-PHP-0037`: `crates/disrobe-pass-php/src/error.rs:65`
- `DR-PHP-0040`: `crates/disrobe-pass-php/src/error.rs:92`
- `DR-PHP-0041`: `crates/disrobe-pass-php/src/error.rs:95`
- `DR-PHP-0060`: `crates/disrobe-pass-php/src/error.rs:99`
- `DR-PHP-0061`: `crates/disrobe-pass-php/src/error.rs:104`
- `DR-PHP-0062`: `crates/disrobe-pass-php/src/error.rs:108`
- `DR-PHP-0070`: `crates/disrobe-pass-php/src/error.rs:112`
- `DR-PHP-0071`: `crates/disrobe-pass-php/src/error.rs:117`
- `DR-PHP-0072`: `crates/disrobe-pass-php/src/error.rs:121`
- `DR-PHP-0080`: `crates/disrobe-pass-php/src/error.rs:125`
- `DR-PHP-0081`: `crates/disrobe-pass-php/src/error.rs:130`
- `DR-PHP-0082`: `crates/disrobe-pass-php/src/error.rs:134`
- `DR-PHP-0090`: `crates/disrobe-pass-php/src/error.rs:137`
- `DR-PHP-0091`: `crates/disrobe-pass-php/src/error.rs:141`
- `DR-PHP-0092`: `crates/disrobe-pass-php/src/error.rs:147`
- `DR-PHP-0093`: `crates/disrobe-pass-php/src/error.rs:150`
- `DR-PHP-0094`: `crates/disrobe-pass-php/src/error.rs:158`
- `DR-PHP-0095`: `crates/disrobe-pass-php/src/error.rs:162`
- `DR-PHP-0096`: `crates/disrobe-pass-php/src/error.rs:165`
- `DR-PHP-0097`: `crates/disrobe-pass-php/src/error.rs:168`
- `DR-PHP-0098`: `crates/disrobe-pass-php/src/error.rs:172`
- `DR-PHP-0100`: `crates/disrobe-pass-php/src/error.rs:180`
- `DR-PHP-0101`: `crates/disrobe-pass-php/src/error.rs:186`
- `DR-PHP-0102`: `crates/disrobe-pass-php/src/error.rs:194`
- `DR-PHP-0110`: `crates/disrobe-pass-php/src/error.rs:202`
- `DR-PHP-0120`: `crates/disrobe-pass-php/src/error.rs:205`
- `DR-PHP-0121`: `crates/disrobe-pass-php/src/error.rs:209`
- `DR-PHP-0122`: `crates/disrobe-pass-php/src/error.rs:219`
- `DR-PHP-0123`: `crates/disrobe-pass-php/src/error.rs:224`
- `DR-PHP-0124`: `crates/disrobe-pass-php/src/error.rs:228`
- `DR-PHP-0125`: `crates/disrobe-pass-php/src/error.rs:236`
- `DR-PHP-0126`: `crates/disrobe-pass-php/src/error.rs:240`
- `DR-PHP-0902`: `crates/disrobe-pass-php/src/chain_detector.rs:118`
- `DR-PHP-0904`: `crates/disrobe-pass-php/src/chain_detector.rs:128`
- `DR-PHP-0905`: `crates/disrobe-pass-php/src/chain_detector.rs:197`
- `DR-PICKLE-0001`: `crates/disrobe-pass-pickle/src/error.rs:8`
- `DR-PICKLE-0002`: `crates/disrobe-pass-pickle/src/error.rs:11`
- `DR-PICKLE-0003`: `crates/disrobe-pass-pickle/src/error.rs:15`
- `DR-PICKLE-0004`: `crates/disrobe-pass-pickle/src/error.rs:24`
- `DR-PICKLE-0005`: `crates/disrobe-pass-pickle/src/error.rs:27`
- `DR-PICKLE-0006`: `crates/disrobe-pass-pickle/src/error.rs:30`
- `DR-PICKLE-0007`: `crates/disrobe-pass-pickle/src/error.rs:37`
- `DR-PICKLE-0008`: `crates/disrobe-pass-pickle/src/error.rs:40`
- `DR-PICKLE-0009`: `crates/disrobe-pass-pickle/src/error.rs:43`
- `DR-PICKLE-0010`: `crates/disrobe-pass-pickle/src/error.rs:47`
- `DR-PICKLE-0011`: `crates/disrobe-pass-pickle/src/error.rs:55`
- `DR-PICKLE-0012`: `crates/disrobe-pass-pickle/src/error.rs:58`
- `DR-PICKLE-0013`: `crates/disrobe-pass-pickle/src/error.rs:61`
- `DR-PICKLE-0014`: `crates/disrobe-pass-pickle/src/error.rs:64`
- `DR-PICKLE-0015`: `crates/disrobe-pass-pickle/src/error.rs:67`
- `DR-PICKLE-0016`: `crates/disrobe-pass-pickle/src/error.rs:70`
- `DR-PICKLE-0017`: `crates/disrobe-pass-pickle/src/error.rs:74`
- `DR-PICKLE-0018`: `crates/disrobe-pass-pickle/src/error.rs:79`
- `DR-PICKLE-0019`: `crates/disrobe-pass-pickle/src/error.rs:83`
- `DR-PICKLE-0020`: `crates/disrobe-pass-pickle/src/error.rs:90`
- `DR-PICKLE-0021`: `crates/disrobe-pass-pickle/src/error.rs:94`
- `DR-PICKLE-0022`: `crates/disrobe-pass-pickle/src/error.rs:102`
- `DR-PICKLE-0023`: `crates/disrobe-pass-pickle/src/error.rs:110`
- `DR-PICKLE-0024`: `crates/disrobe-pass-pickle/src/error.rs:118`
- `DR-PICKLE-0901`: `crates/disrobe-pass-pickle/src/chain_detector.rs:78`
- `DR-PICKLE-0903`: `crates/disrobe-pass-pickle/src/chain_detector.rs:83`
- `DR-PICKLE-0904`: `crates/disrobe-pass-pickle/src/chain_detector.rs:91`
- `DR-PLAYGROUND-0100`: `crates/disrobe-playground/src/native_match.rs:29`
- `DR-PROWL-0040`: `crates/disrobe-cli/src/cli/prowl/harvest.rs:92`
- `DR-PROWL-0041`: `crates/disrobe-cli/src/cli/prowl/harvest.rs:437`
- `DR-PROWL-0042`: `crates/disrobe-cli/src/cli/prowl/harvest.rs:454`
- `DR-PROWL-0043`: `crates/disrobe-cli/src/cli/prowl/harvest.rs:107`
- `DR-PROWL-0044`: `crates/disrobe-cli/src/cli/prowl/harvest.rs:145`
- `DR-PROWL-0045`: `crates/disrobe-cli/src/cli/prowl/harvest.rs:223`
- `DR-PROWL-0046`: `crates/disrobe-cli/src/cli/prowl/harvest.rs:227`
- `DR-PROWL-0047`: `crates/disrobe-cli/src/cli/prowl/harvest.rs:240`
- `DR-PROWL-0048`: `crates/disrobe-cli/src/cli/prowl/harvest.rs:477`
- `DR-PROWL-0050`: `crates/disrobe-cli/src/cli/prowl/harvest.rs:274`
- `DR-PROWL-0051`: `crates/disrobe-cli/src/cli/prowl/harvest.rs:277`
- `DR-PROWL-0052`: `crates/disrobe-cli/src/cli/prowl/harvest.rs:315`
- `DR-PROWL-0053`: `crates/disrobe-cli/src/cli/prowl/harvest.rs:337`
- `DR-PROWL-0054`: `crates/disrobe-cli/src/cli/prowl/harvest.rs:344`
- `DR-PROWL-0055`: `crates/disrobe-cli/src/cli/prowl/harvest.rs:349`
- `DR-PROWL-0056`: `crates/disrobe-cli/src/cli/prowl/harvest.rs:361`
- `DR-PROWL-0057`: `crates/disrobe-cli/src/cli/prowl/harvest.rs:372`
- `DR-PROWL-0058`: `crates/disrobe-cli/src/cli/prowl/harvest.rs:324`
- `DR-PROWL-0059`: `crates/disrobe-cli/src/cli/prowl/harvest.rs:126`
- `DR-PROWL-0060`: `crates/disrobe-cli/src/cli/prowl/harvest.rs:128`, `crates/disrobe-cli/src/cli/prowl/harvest.rs:131`
- `DR-PROWL-0061`: `crates/disrobe-cli/src/cli/prowl/harvest.rs:135`
- `DR-PROWL-0062`: `crates/disrobe-cli/src/cli/prowl/harvest.rs:166`
- `DR-PY-0410`: `crates/disrobe-python/src/container.rs:146`
- `DR-PY-0420`: `crates/disrobe-python/src/wasm.rs:37`
- `DR-PY-0421`: `crates/disrobe-python/src/wasm.rs:77`
- `DR-PYALT-0001`: `crates/disrobe-pass-py-disasm/src/alt_runtimes/mod.rs:34`
- `DR-PYALT-0002`: `crates/disrobe-pass-py-disasm/src/alt_runtimes/mod.rs:41`
- `DR-PYALT-0003`: `crates/disrobe-pass-py-disasm/src/alt_runtimes/mod.rs:44`
- `DR-PYALT-0004`: `crates/disrobe-pass-py-disasm/src/alt_runtimes/mod.rs:47`
- `DR-PYALT-0005`: `crates/disrobe-pass-py-disasm/src/alt_runtimes/mod.rs:50`
- `DR-PYALT-0006`: `crates/disrobe-pass-py-disasm/src/alt_runtimes/mod.rs:56`
- `DR-PYALT-0007`: `crates/disrobe-pass-py-disasm/src/alt_runtimes/mod.rs:59`
- `DR-PYARM-0050`: `crates/disrobe-cli/src/cli/pyarmor.rs:50`, `crates/disrobe-pass-pyarmor/src/error.rs:119`
- `DR-PYARM-0052`: `crates/disrobe-pass-pyarmor/src/error.rs:123`
- `DR-PYARM-0053`: `crates/disrobe-pass-pyarmor/src/error.rs:128`
- `DR-PYARM-0054`: `crates/disrobe-pass-pyarmor/src/error.rs:134`
- `DR-PYARM-0055`: `crates/disrobe-pass-pyarmor/src/error.rs:137`
- `DR-PYARM-0060`: `crates/disrobe-pass-pyarmor/src/error.rs:140`
- `DR-PYARM-0061`: `crates/disrobe-pass-pyarmor/src/error.rs:143`
- `DR-PYARM-0062`: `crates/disrobe-pass-pyarmor/src/error.rs:146`
- `DR-PYARM-0063`: `crates/disrobe-pass-pyarmor/src/error.rs:149`
- `DR-PYARM-0064`: `crates/disrobe-pass-pyarmor/src/error.rs:152`
- `DR-PYARM-0066`: `crates/disrobe-pass-pyarmor/src/error.rs:156`
- `DR-PYARM-0067`: `crates/disrobe-pass-pyarmor/src/error.rs:165`
- `DR-PYARM-0068`: `crates/disrobe-pass-pyarmor/src/error.rs:169`
- `DR-PYARM-0069`: `crates/disrobe-pass-pyarmor/src/error.rs:172`
- `DR-PYARM-0070`: `crates/disrobe-pass-pyarmor/src/error.rs:175`
- `DR-PYARM-0071`: `crates/disrobe-pass-pyarmor/src/error.rs:178`
- `DR-PYARM-0901`: `crates/disrobe-pass-pyarmor/src/chain_detector.rs:112`
- `DR-PYARM-0902`: `crates/disrobe-pass-pyarmor/src/chain_detector.rs:117`
- `DR-PYARM-0904`: `crates/disrobe-pass-pyarmor/src/chain_detector.rs:129`
- `DR-PYARM-0905`: `crates/disrobe-pass-pyarmor/src/chain_detector.rs:134`
- `DR-PYARM-0906`: `crates/disrobe-pass-pyarmor/src/chain_detector.rs:190`
- `DR-PYARM-0907`: `crates/disrobe-pass-pyarmor/src/chain_detector.rs:199`
- `DR-PYARM-0908`: `crates/disrobe-pass-pyarmor/src/chain_detector.rs:203`
- `DR-PYARM-0909`: `crates/disrobe-pass-pyarmor/src/chain_detector.rs:216`
- `DR-PYARM-0910`: `crates/disrobe-pass-pyarmor/src/chain_detector.rs:237`
- `DR-PYARM-0911`: `crates/disrobe-pass-pyarmor/src/chain_detector.rs:241`
- `DR-PYARM-0912`: `crates/disrobe-pass-pyarmor/src/chain_detector.rs:258`
- `DR-PYARM-0913`: `crates/disrobe-pass-pyarmor/src/chain_detector.rs:269`
- `DR-PYARM-0914`: `crates/disrobe-pass-pyarmor/src/chain_detector.rs:424`
- `DR-PYDEC-0001`: `crates/disrobe-pass-py-decompile/src/error.rs:7`
- `DR-PYDEC-0002`: `crates/disrobe-pass-py-decompile/src/error.rs:11`
- `DR-PYDEC-0003`: `crates/disrobe-pass-py-decompile/src/error.rs:15`
- `DR-PYDEC-0004`: `crates/disrobe-pass-py-decompile/src/error.rs:19`
- `DR-PYDEC-0005`: `crates/disrobe-pass-py-decompile/src/error.rs:23`
- `DR-PYDEC-0006`: `crates/disrobe-pass-py-decompile/src/error.rs:27`
- `DR-PYDEC-0007`: `crates/disrobe-pass-py-decompile/src/error.rs:31`
- `DR-PYDEC-0008`: `crates/disrobe-pass-py-decompile/src/error.rs:47`
- `DR-PYDEC-0009`: `crates/disrobe-pass-py-decompile/src/error.rs:51`
- `DR-PYDEC-0010`: `crates/disrobe-pass-py-decompile/src/error.rs:70`
- `DR-PYDEC-0011`: `crates/disrobe-pass-py-decompile/src/error.rs:74`
- `DR-PYDEC-0012`: `crates/disrobe-pass-py-decompile/src/error.rs:35`
- `DR-PYDEC-0013`: `crates/disrobe-pass-py-decompile/src/error.rs:43`
- `DR-PYDEC-0014`: `crates/disrobe-pass-py-decompile/src/error.rs:59`
- `DR-PYDEC-0015`: `crates/disrobe-pass-py-decompile/src/error.rs:39`
- `DR-PYDEC-0016`: `crates/disrobe-pass-py-decompile/src/error.rs:66`
- `DR-PYDEC-0902`: `crates/disrobe-pass-py-decompile/src/chain_detector.rs:105`
- `DR-PYDEC-0908`: `crates/disrobe-pass-py-decompile/src/chain_detector.rs:119`
- `DR-PYDEC-0911`: `crates/disrobe-pass-py-decompile/src/chain_detector.rs:111`
- `DR-PYDEC-0912`: `crates/disrobe-pass-py-decompile/src/chain_detector.rs:115`
- `DR-PYDEC-0913`: `crates/disrobe-pass-py-decompile/src/engine.rs:46`
- `DR-PYDEOB-0010`: `crates/disrobe-pass-py-deob/src/error.rs:37`
- `DR-PYDEOB-0011`: `crates/disrobe-pass-py-deob/src/error.rs:40`
- `DR-PYDEOB-0012`: `crates/disrobe-pass-py-deob/src/error.rs:43`
- `DR-PYDEOB-0013`: `crates/disrobe-pass-py-deob/src/error.rs:47`
- `DR-PYDEOB-0014`: `crates/disrobe-pass-py-deob/src/error.rs:51`
- `DR-PYDEOB-0015`: `crates/disrobe-pass-py-deob/src/error.rs:54`
- `DR-PYDEOB-0902`: `crates/disrobe-pass-py-deob/src/chain_detector.rs:248`
- `DR-PYDEOB-0903`: `crates/disrobe-pass-py-deob/src/chain_detector.rs:236`
- `DR-PYDEOB-0904`: `crates/disrobe-pass-py-deob/src/chain_detector.rs:242`
- `DR-PYDIS-0902`: `crates/disrobe-pass-py-disasm/src/chain_detector.rs:98`
- `DR-PYDIS-0906`: `crates/disrobe-pass-py-disasm/src/chain_detector.rs:221`
- `DR-PYDIS-0907`: `crates/disrobe-pass-py-disasm/src/chain_detector.rs:228`
- `DR-PYDIS-0908`: `crates/disrobe-pass-py-disasm/src/chain_detector.rs:239`
- `DR-PYDIS-0909`: `crates/disrobe-pass-py-disasm/src/chain_detector.rs:248`
- `DR-PYDIS-0910`: `crates/disrobe-pass-py-disasm/src/chain_detector.rs:151`
- `DR-PYDIS-0911`: `crates/disrobe-pass-py-disasm/src/chain_detector.rs:286`
- `DR-PYFRZ-0021`: `crates/disrobe-pass-pyfreeze/src/error.rs:84`
- `DR-PYFRZ-0022`: `crates/disrobe-pass-pyfreeze/src/error.rs:88`
- `DR-PYFRZ-0023`: `crates/disrobe-pass-pyfreeze/src/error.rs:92`
- `DR-PYFRZ-0024`: `crates/disrobe-pass-pyfreeze/src/error.rs:95`
- `DR-PYFRZ-0025`: `crates/disrobe-pass-pyfreeze/src/error.rs:98`
- `DR-PYFRZ-0026`: `crates/disrobe-pass-pyfreeze/src/error.rs:102`
- `DR-PYFRZ-0027`: `crates/disrobe-pass-pyfreeze/src/error.rs:107`
- `DR-PYFRZ-0902`: `crates/disrobe-pass-pyfreeze/src/chain_detector.rs:76`
- `DR-PYFRZ-0903`: `crates/disrobe-pass-pyfreeze/src/chain_detector.rs:82`
- `DR-PYFRZ-0904`: `crates/disrobe-pass-pyfreeze/src/chain_detector.rs:168`
- `DR-PYINS-0902`: `crates/disrobe-pass-pyinstaller/src/chain_detector.rs:71`
- `DR-PYINS-0903`: `crates/disrobe-pass-pyinstaller/src/chain_detector.rs:75`
- `DR-PYINS-0904`: `crates/disrobe-pass-pyinstaller/src/chain_detector.rs:90`
- `DR-PYINST-0011`: `crates/disrobe-pass-pyinstaller/src/error.rs:45`
- `DR-PYINST-0012`: `crates/disrobe-pass-pyinstaller/src/error.rs:50`
- `DR-PYINST-0013`: `crates/disrobe-pass-pyinstaller/src/error.rs:54`
- `DR-RECON-0001`: `crates/disrobe-core/src/recon/mod.rs:164`
- `DR-RECON-0002`: `crates/disrobe-core/src/recon/mod.rs:168`
- `DR-RUBY-0001`: `crates/disrobe-pass-ruby/src/error.rs:8`
- `DR-RUBY-0002`: `crates/disrobe-pass-ruby/src/error.rs:11`
- `DR-RUBY-0003`: `crates/disrobe-pass-ruby/src/error.rs:14`
- `DR-RUBY-0010`: `crates/disrobe-pass-ruby/src/error.rs:17`
- `DR-RUBY-0011`: `crates/disrobe-pass-ruby/src/error.rs:20`
- `DR-RUBY-0012`: `crates/disrobe-pass-ruby/src/error.rs:23`
- `DR-RUBY-0013`: `crates/disrobe-pass-ruby/src/error.rs:26`
- `DR-RUBY-0020`: `crates/disrobe-pass-ruby/src/error.rs:29`
- `DR-RUBY-0021`: `crates/disrobe-pass-ruby/src/error.rs:32`
- `DR-RUBY-0022`: `crates/disrobe-pass-ruby/src/error.rs:35`
- `DR-RUBY-0023`: `crates/disrobe-pass-ruby/src/error.rs:38`
- `DR-RUBY-0024`: `crates/disrobe-pass-ruby/src/error.rs:41`
- `DR-RUBY-0025`: `crates/disrobe-pass-ruby/src/error.rs:44`
- `DR-RUBY-0026`: `crates/disrobe-pass-ruby/src/error.rs:47`
- `DR-RUBY-0027`: `crates/disrobe-pass-ruby/src/error.rs:50`
- `DR-RUBY-0030`: `crates/disrobe-pass-ruby/src/error.rs:53`
- `DR-RUBY-0040`: `crates/disrobe-pass-ruby/src/error.rs:56`
- `DR-RUBY-0050`: `crates/disrobe-pass-ruby/src/error.rs:59`
- `DR-RUBY-0060`: `crates/disrobe-pass-ruby/src/error.rs:62`
- `DR-RUBY-0061`: `crates/disrobe-pass-ruby/src/error.rs:65`
- `DR-RUBY-0062`: `crates/disrobe-pass-ruby/src/error.rs:68`
- `DR-RUBY-0063`: `crates/disrobe-pass-ruby/src/error.rs:71`
- `DR-RUBY-0064`: `crates/disrobe-pass-ruby/src/error.rs:74`
- `DR-RUBY-0099`: `crates/disrobe-pass-ruby/src/error.rs:77`
- `DR-RUBY-0902`: `crates/disrobe-pass-ruby/src/chain_detector.rs:138`
- `DR-RUBY-0903`: `crates/disrobe-pass-ruby/src/chain_detector.rs:150`
- `DR-RUBY-0904`: `crates/disrobe-pass-ruby/src/chain_detector.rs:161`
- `DR-SCAN-0050`: `crates/disrobe-cli/src/cli/scan.rs:33`
- `DR-SCRIPT-0001`: `crates/disrobe-pass-scriptlang/src/error.rs:8`
- `DR-SCRIPT-0100`: `crates/disrobe-pass-scriptlang/src/error.rs:11`
- `DR-SCRIPT-0200`: `crates/disrobe-pass-scriptlang/src/error.rs:14`
- `DR-SCRIPT-0201`: `crates/disrobe-pass-scriptlang/src/error.rs:17`
- `DR-SCRIPT-0210`: `crates/disrobe-pass-scriptlang/src/error.rs:20`
- `DR-SCRIPT-0211`: `crates/disrobe-pass-scriptlang/src/error.rs:23`
- `DR-SCRIPT-0212`: `crates/disrobe-pass-scriptlang/src/error.rs:26`
- `DR-SCRIPT-0213`: `crates/disrobe-pass-scriptlang/src/error.rs:29`
- `DR-SCRIPT-0214`: `crates/disrobe-pass-scriptlang/src/error.rs:32`
- `DR-SCRIPT-0300`: `crates/disrobe-pass-scriptlang/src/error.rs:39`
- `DR-SCRIPT-0301`: `crates/disrobe-pass-scriptlang/src/error.rs:42`
- `DR-SCRIPT-0302`: `crates/disrobe-pass-scriptlang/src/error.rs:45`
- `DR-SCRIPT-0303`: `crates/disrobe-pass-scriptlang/src/error.rs:52`
- `DR-SCRIPT-0304`: `crates/disrobe-pass-scriptlang/src/error.rs:55`
- `DR-SCRIPT-0305`: `crates/disrobe-pass-scriptlang/src/error.rs:58`
- `DR-SCRIPT-0306`: `crates/disrobe-pass-scriptlang/src/error.rs:64`
- `DR-SCRIPT-0307`: `crates/disrobe-pass-scriptlang/src/error.rs:67`
- `DR-SCRIPT-0308`: `crates/disrobe-pass-scriptlang/src/error.rs:74`
- `DR-SCRIPT-0309`: `crates/disrobe-pass-scriptlang/src/error.rs:77`
- `DR-SCRIPT-0310`: `crates/disrobe-pass-scriptlang/src/error.rs:83`
- `DR-SCRIPT-0400`: `crates/disrobe-pass-scriptlang/src/error.rs:89`
- `DR-SCRIPT-0401`: `crates/disrobe-pass-scriptlang/src/error.rs:92`
- `DR-SCRIPT-0402`: `crates/disrobe-pass-scriptlang/src/error.rs:96`
- `DR-SCRIPT-0403`: `crates/disrobe-pass-scriptlang/src/error.rs:100`
- `DR-SCRIPT-0404`: `crates/disrobe-pass-scriptlang/src/error.rs:103`
- `DR-SCRIPT-0405`: `crates/disrobe-pass-scriptlang/src/error.rs:106`
- `DR-SCRIPT-0500`: `crates/disrobe-pass-scriptlang/src/error.rs:109`
- `DR-SCRIPT-0902`: `crates/disrobe-pass-scriptlang/src/chain_detector.rs:129`
- `DR-SCRIPT-0903`: `crates/disrobe-pass-scriptlang/src/chain_detector.rs:134`
- `DR-SCRIPT-0905`: `crates/disrobe-pass-scriptlang/src/chain_detector.rs:182`
- `DR-SD-0901`: `crates/disrobe-pass-sourcedefender/src/chain_detector.rs:135`
- `DR-SD-0902`: `crates/disrobe-pass-sourcedefender/src/chain_detector.rs:152`
- `DR-SD-0903`: `crates/disrobe-pass-sourcedefender/src/chain_detector.rs:139`
- `DR-SDEF-0011`: `crates/disrobe-pass-sourcedefender/src/error.rs:36`
- `DR-SDEF-0012`: `crates/disrobe-pass-sourcedefender/src/error.rs:43`
- `DR-SDEF-0013`: `crates/disrobe-pass-sourcedefender/src/error.rs:47`
- `DR-SDEF-0014`: `crates/disrobe-pass-sourcedefender/src/error.rs:56`
- `DR-SHELL-0902`: `crates/disrobe-pass-shell/src/chain_detector.rs:84`
- `DR-SHELL-0909`: `crates/disrobe-pass-shell/src/chain_detector.rs:351`, `crates/disrobe-pass-shell/src/chain_detector.rs:360`
- `DR-SHELL-0910`: `crates/disrobe-pass-shell/src/chain_detector.rs:322`
- `DR-SHELL-0911`: `crates/disrobe-pass-shell/src/chain_detector.rs:323`
- `DR-SHELL-0912`: `crates/disrobe-pass-shell/src/chain_detector.rs:324`
- `DR-SHELL-0913`: `crates/disrobe-pass-shell/src/chain_detector.rs:325`
- `DR-SHELL-0914`: `crates/disrobe-pass-shell/src/chain_detector.rs:326`
- `DR-SHELL-0915`: `crates/disrobe-pass-shell/src/chain_detector.rs:327`
- `DR-SHELL-0916`: `crates/disrobe-pass-shell/src/chain_detector.rs:328`
- `DR-SHELL-0917`: `crates/disrobe-pass-shell/src/chain_detector.rs:329`
- `DR-SHELL-0918`: `crates/disrobe-pass-shell/src/chain_detector.rs:330`
- `DR-SHELL-0919`: `crates/disrobe-pass-shell/src/chain_detector.rs:331`
- `DR-SHELL-0920`: `crates/disrobe-pass-shell/src/chain_detector.rs:332`
- `DR-SHELL-0921`: `crates/disrobe-pass-shell/src/chain_detector.rs:336`
- `DR-SHELL-0922`: `crates/disrobe-pass-shell/src/chain_detector.rs:337`
- `DR-SHELL-0923`: `crates/disrobe-pass-shell/src/chain_detector.rs:338`
- `DR-SHELL-0924`: `crates/disrobe-pass-shell/src/chain_detector.rs:232`
- `DR-SHELL-0925`: `crates/disrobe-pass-shell/src/chain_detector.rs:243`
- `DR-SHELL-0926`: `crates/disrobe-pass-shell/src/chain_detector.rs:285`
- `DR-SHELL-0927`: `crates/disrobe-pass-shell/src/chain_detector.rs:221`
- `DR-SHELL-0928`: `crates/disrobe-pass-shell/src/chain_detector.rs:210`
- `DR-STR-0049`: `crates/disrobe-cli/src/cli/strings.rs:24`
- `DR-STR-0050`: `crates/disrobe-cli/src/cli/strings.rs:27`
- `DR-SWOBJ-0902`: `crates/disrobe-pass-swift-objc/src/chain_detector.rs:162`
- `DR-SWOBJ-0903`: `crates/disrobe-pass-swift-objc/src/chain_detector.rs:168`
- `DR-SWOBJ-0904`: `crates/disrobe-pass-swift-objc/src/chain_detector.rs:156`, `crates/disrobe-pass-swift-objc/src/chain_detector.rs:179`
- `DR-SWOBJ-0905`: `crates/disrobe-pass-swift-objc/src/chain_detector.rs:152`
- `DR-SWOBJ-0906`: `crates/disrobe-pass-swift-objc/src/chain_detector.rs:126`
- `DR-SWOBJ-0907`: `crates/disrobe-pass-swift-objc/src/chain_detector.rs:207`
- `DR-SWOBJ-0908`: `crates/disrobe-pass-swift-objc/src/chain_detector.rs:211`
- `DR-SWOBJ-0909`: `crates/disrobe-pass-swift-objc/src/chain_detector.rs:223`, `crates/disrobe-pass-swift-objc/src/chain_detector.rs:229`
- `DR-SWOBJ-0910`: `crates/disrobe-pass-swift-objc/src/chain_detector.rs:249`
- `DR-SWOBJ-0911`: `crates/disrobe-pass-swift-objc/src/chain_detector.rs:256`
- `DR-SWOBJ-0912`: `crates/disrobe-pass-swift-objc/src/chain_detector.rs:262`
- `DR-WASM-0902`: `crates/disrobe-pass-wasm-deob/src/chain_detector.rs:109`
- `DR-WASM-0903`: `crates/disrobe-pass-wasm-deob/src/chain_detector.rs:113`
- `DR-WASM-0906`: `crates/disrobe-pass-wasm-deob/src/chain_detector.rs:246`
- `DR-WASM-0908`: `crates/disrobe-pass-wasm-deob/src/chain_detector.rs:203`
- `DR-WASM-0909`: `crates/disrobe-pass-wasm-deob/src/chain_detector.rs:208`
- `DR-WASM-0910`: `crates/disrobe-pass-wasm-deob/src/chain_detector.rs:223`
- `DR-WASM-0911`: `crates/disrobe-pass-wasm-deob/src/chain_detector.rs:138`
- `DR-WASM-0921`: `crates/disrobe-pass-wasm-deob/src/chain_detector.rs:87`
- `DR-WASM-0922`: `crates/disrobe-pass-wasm-deob/src/chain_detector.rs:98`
- `DR-WASMDEOB-0003`: `crates/disrobe-pass-wasm-deob/src/error.rs:105`, `crates/disrobe-python/src/wasm.rs:57`
- `DR-WEBVIEW-0001`: `crates/disrobe-pass-webview/src/error.rs:11`
- `DR-WEBVIEW-0002`: `crates/disrobe-pass-webview/src/error.rs:15`
- `DR-WEBVIEW-0003`: `crates/disrobe-pass-webview/src/error.rs:22`
- `DR-WEBVIEW-0004`: `crates/disrobe-pass-webview/src/error.rs:25`
- `DR-WEBVIEW-0005`: `crates/disrobe-pass-webview/src/error.rs:28`
- `DR-WEBVIEW-0006`: `crates/disrobe-pass-webview/src/error.rs:31`
- `DR-WEBVIEW-0007`: `crates/disrobe-pass-webview/src/error.rs:34`
- `DR-WEBVIEW-0008`: `crates/disrobe-pass-webview/src/error.rs:37`
- `DR-WEBVIEW-0009`: `crates/disrobe-pass-webview/src/error.rs:40`
- `DR-WEBVIEW-0010`: `crates/disrobe-pass-webview/src/error.rs:43`
- `DR-WEBVIEW-0011`: `crates/disrobe-pass-webview/src/error.rs:47`
- `DR-WEBVIEW-0012`: `crates/disrobe-pass-webview/src/error.rs:52`
- `DR-WEBVIEW-0050`: `crates/disrobe-cli/src/cli/webview.rs:13`
- `DR-WEBVIEW-0051`: `crates/disrobe-cli/src/cli/webview.rs:24`
- `DR-WEBVIEW-0052`: `crates/disrobe-cli/src/cli/webview.rs:33`
- `DR-WEBVIEW-0053`: `crates/disrobe-cli/src/cli/webview.rs:41`
- `DR-WEBVIEW-0054`: `crates/disrobe-cli/src/cli/webview.rs:46`
- `DR-WEBVIEW-0055`: `crates/disrobe-cli/src/cli/webview.rs:50`
- `DR-WEBVIEW-0060`: `crates/disrobe-pass-webview/src/chain_detector.rs:103`
- `DR-WEBVIEW-0061`: `crates/disrobe-pass-webview/src/chain_detector.rs:109`
- `DR-WEBVIEW-0062`: `crates/disrobe-pass-webview/src/chain_detector.rs:135`
- `DR-YARA-0001`: `crates/disrobe-core/src/yara.rs:61`
- `DR-YARA-0002`: `crates/disrobe-core/src/yara.rs:64`
- `DR-YARA-0003`: `crates/disrobe-core/src/yara.rs:67`
- `DR-YARA-0004`: `crates/disrobe-core/src/yara.rs:70`
- `DR-YARA-0005`: `crates/disrobe-core/src/yara.rs:73`
- `DR-YARA-0006`: `crates/disrobe-core/src/yara.rs:77`
- `DR-YARA-0007`: `crates/disrobe-core/src/yara.rs:86`
- `DR-YARA-0008`: `crates/disrobe-core/src/yara.rs:95`
- `DR-YARA-0009`: `crates/disrobe-core/src/yara.rs:98`
- `DR-YARA-0010`: `crates/disrobe-core/src/yara.rs:101`
- `DR-YARA-0050`: `crates/disrobe-cli/src/cli/yara.rs:62`
- `DR-YARA-0051`: `crates/disrobe-cli/src/cli/yara.rs:64`
- `DR-YARA-0052`: `crates/disrobe-cli/src/cli/yara.rs:67`
- `DR-YARA-0053`: `crates/disrobe-cli/src/cli/yara.rs:96`
- `DR-YARA-0054`: `crates/disrobe-cli/src/cli/yara.rs:104`
- `DR-YARAGEN-0001`: `crates/disrobe-core/src/yara_gen.rs:51`
- `DR-YARAGEN-0002`: `crates/disrobe-core/src/yara_gen.rs:54`
- `DR-YARAGEN-0003`: `crates/disrobe-core/src/yara_gen.rs:58`
- `DR-YARAMATCH-0001`: `crates/disrobe-core/src/yara_match/mod.rs:18`

## Registered codes no source emits (0)

