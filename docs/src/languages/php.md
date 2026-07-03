# PHP

The commercial PHP encoder market has no maintained FOSS competition offline. **disrobe** decodes all three dominant encoders fully offline: nothing is uploaded anywhere. It also peels stacked eval-chain obfuscation and walks Phar archives.

## At a glance

| Layer | Coverage |
|---|---|
| Commercial encoders | ionCube, SourceGuardian, Zend Guard: envelope detect and wall (the decrypt key is native-loader-resident); a partial `op_array` skeleton only for legacy statically-keyed cases (Zend legacy XOR), graded `StructuralOnly` otherwise |
| Phar archives | Manifest walker with path-sanitized extraction |
| Eval-chain layers | `base64_decode`, `gzinflate`, `gzuncompress`, `gzdecode`, `str_rot13`, `strrev`, `str_replace`, `urldecode` / `rawurldecode`, hex escapes, `pack`-hex, `chr()` concatenation, uudecode, single-key XOR, `create_function`, nested `eval`, FOPO, Better PHP Obfuscator |
| Recovery grading | `EvalChainPeeled` / `OpArrayDecompiled` / `StructuralOnly` / `PlainSource` |

## Decoding an encoder envelope

```sh
disrobe php decode payload.php --out out/payload-php/
disrobe php decode payload.php --encoder ioncube --i-have-authorization
```

`--encoder` is `auto` (default), `phar`, `ioncube`, `sourceguardian`, or `zendguard`. Commercial encoders require the explicit `--i-have-authorization` flag. The output directory receives the decoded payload, a skeleton `.php` when an `op_array` was decompiled, and a `manifest.json` recording the encoder, version label, marker offset, ciphertext and plaintext byte counts, and the recovery stage.

Output shape (illustrative):

```text
php decode: OK
  input:        payload.php
  encoder:      Ioncube
  out dir:      ./out/payload-php
  manifest:     ./out/payload-php/manifest.json
```

## Peeling eval chains

```sh
disrobe php deobfuscate obfuscated.php --out clean.php
```

Unwraps stacked `eval()` layers until the residue is plain PHP. Output shape (illustrative):

```text
php deobfuscate: OK
  input:        obfuscated.php
  layers:       3
  residual_eval:false
  wrote:        ./out/obfuscated.peeled.php
  manifest:     ./out/obfuscated.peeled.manifest.json
```

The manifest counts each layer kind that was peeled and flags whether any `eval` remains in the residue.

## Phar archives

```sh
disrobe php extract archive.phar --out extracted/
```

Walks the Phar manifest and extracts every entry through a path-sanitizer (no `..` escapes), writing a `manifest.json` with the entry count and API version.

Output shape (illustrative):

```text
php extract: OK
  input:        archive.phar
  entries:      14
  out dir:      ./out/archive-phar
  manifest:     ./out/archive-phar/manifest.json
```

When an encoder's key lives only in its runtime loader, the decode is graded `StructuralOnly` and the manifest carries the residual ciphertext length rather than pretending at plaintext.
