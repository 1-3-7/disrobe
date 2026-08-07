# PHP

`disrobe` surfaces the three supported commercial encoder envelopes fully offline, recovering statically available layers and reporting when loader-resident keys keep payloads sealed; nothing is uploaded anywhere. It also peels stacked eval-chain obfuscation and walks Phar archives.

## At a glance

| Layer | Coverage |
|---|---|
| Commercial encoders | ionCube, SourceGuardian, Zend Guard: envelope detect and wall (the decrypt key is native-loader-resident); a partial `op_array` skeleton only for legacy statically-keyed cases (Zend legacy XOR), graded `StructuralOnly` otherwise |
| Phar archives | Manifest walker with path-sanitized extraction |
| Eval-chain layers | `base64_decode`, `gzinflate`, `gzuncompress`, `gzdecode`, `bzdecompress`, `str_rot13`, `strrev`, `str_replace`, `urldecode` / `rawurldecode`, hex and octal escapes, `pack`-hex, `chr()` concatenation, uudecode, single-key XOR, `create_function`, nested `eval`, FOPO, Better PHP Obfuscator |
| Decode loops | `for`, `while`, `do`-`while` and `foreach` over `str_split`, with modulo, plain, reversed, stride, rotating and nested indices, and XOR, add and subtract with wraparound, rotate, negate, table substitution and index-parity byte operations. The key must be present in the file. A bounded interpreter runs the loop body under explicit step, wall-clock, output-size, heap, expression-depth, frame-depth and loop-count budgets, and refuses every call outside a pure-function allowlist |
| Decode helpers | A helper function declared at the top level of the file, called directly or through a variable holding its name, including recursion, mutual recursion, default arguments and array arguments. The helper runs in its own scope, as php runs it, so it reads only what it is passed |
| Recovery grading | `EvalChainPeeled` / `OpArrayDecompiled` / `StructuralOnly` / `PlainSource` |

## Commands

```sh
disrobe php decode payload.php --out out/payload-php/
disrobe php decode payload.php --encoder ioncube --i-have-authorization
disrobe php deobfuscate obfuscated.php --out clean.php
disrobe php extract archive.phar --out extracted/
```

`--encoder` is `auto` (default), `phar`, `ioncube`, `sourceguardian`, or `zendguard`. Commercial encoders require the explicit `--i-have-authorization` flag. The output directory receives the decoded payload, a skeleton `.php` when an `op_array` was decompiled, and a `manifest.json` recording the encoder, version label, marker offset, ciphertext and plaintext byte counts, and the recovery stage.

Output shapes below are illustrative.

```text
php decode: OK
  input:        payload.php
  encoder:      Ioncube
  out dir:      ./out/payload-php
  manifest:     ./out/payload-php/manifest.json
```

`deobfuscate` unwraps stacked `eval()` layers until the residue is plain PHP. The manifest counts each layer kind that was peeled and flags whether any `eval` remains in the residue.

```text
php deobfuscate: OK
  input:        obfuscated.php
  layers:       3
  residual_eval:false
  wrote:        ./out/obfuscated.peeled.php
  manifest:     ./out/obfuscated.peeled.manifest.json
```

`extract` walks the Phar manifest and extracts every entry through a path-sanitizer (no `..` escapes), writing a `manifest.json` with the entry count and API version.

```text
php extract: OK
  input:        archive.phar
  entries:      14
  out dir:      ./out/archive-phar
  manifest:     ./out/archive-phar/manifest.json
```

## Coverage and fidelity

The commercial PHP encoder market has no maintained FOSS competition offline. Every recovery carries an explicit stage in its manifest: `EvalChainPeeled`, `OpArrayDecompiled`, `StructuralOnly`, or `PlainSource`, so a caller can tell a fully peeled payload from an envelope parse.

## Limits

- ionCube, SourceGuardian, and Zend Guard keys live in the native loader, not the file. Those envelopes are detected and walled. A partial `op_array` skeleton is recovered only for legacy statically-keyed cases (Zend legacy XOR).
- When an encoder's key lives only in its runtime loader, the decode is graded `StructuralOnly` and the manifest carries the residual ciphertext length rather than pretending at plaintext.
- A decode loop whose key arrives at run time, from `$_GET`, `$_POST`, a header or the network, is not statically recoverable. The loop is left in place and no plaintext is produced.
- A helper declared inside a conditional or inside another function is not evaluated. Only a declaration at the top level of the file is, which matches where php makes a function callable before its own text.
- A helper taking a parameter by reference, or a variadic parameter, is not evaluated, because the interpreter models values rather than references.
- The interpreter reads a variable only when the file defines it. An undefined read, a call outside the pure-function allowlist, or any exceeded budget abstains and leaves the loop in place.
