# Shell / PowerShell

`disrobe` deobfuscates PowerShell, Bash, Batch, VBScript, and VBA. It reverses every major PowerShell obfuscator family and Bashfuscator, recovers VBA source from Office documents, decompiles VBA p-code with stomp detection, and recovers Excel 4.0 (XLM) macro formulas.

## Commands

```sh
disrobe shell deob payload.ps1 --out recovered.ps1
disrobe shell detect payload.ps1
```

`deob` auto-detects the dialect and obfuscator family, applies the right reversal, and writes the recovered source plus a `manifest.json`. `detect` reports the dialect, family, confidence score, and detection markers without writing output.

Output shape (illustrative):

```text
shell deob: OK
  input:        payload.ps1
  dialect:      PowerShell
  family:       InvokeObfuscationToken
  confidence:   0.94
  markers:      ["iex", "token-replace"]
  wrote:        ./out/payload.deob.ps1
  manifest:     ./out/payload.deob.manifest.json
```

## Covered families

| Dialect | Families |
|---|---|
| PowerShell | Invoke-Obfuscation (Token, AST, String, Encoding, Compress, Launcher), Invoke-Stealth, PowerHell, Chameleon, psobf, ISESteroids |
| Bash | Bashfuscator (Token, String, Obfuscate, Compress modes), indirection peeler |
| Batch | `.bat` / `.cmd` random-char and set-indirection patterns |
| VBA / VBScript | VBA module source recovery, VBScript WSH patterns |

## VBA source and p-code

From a `.docm` / `.xlsm` / `.bin` Office container, `disrobe` parses the `dir` stream (MS-OVBA), maps each module to its stream and `TextOffset`, and MS-OVBA-decompresses the `CompressedSourceCode` at that offset to emit the original `.bas` / `.cls` text per module (multi-chunk compression and CopyToken bit-count edges handled). Validated against real Word and Excel documents authored via COM, byte-for-byte against the known module text.

The p-code path lifts a 264-opcode table across VBA3 / VBA5 / VBA6 / VBA7 (32-bit and 64-bit) with identifier resolution. VBA-stomping detection runs a p-code-vs-source classifier that flags modules whose compiled p-code diverges from the stored source and recovers the stomped behavior from the p-code.

## Excel 4.0 (XLM) macros

`disrobe shell deob book.xls` recovers Excel 4.0 macro-sheet formulas from a BIFF8 (`.xls`) or BIFF12 (`.xlsb`) workbook. It decodes the Ptg RPN token stream back to formula text over the full Ftab and Cetab function tables, resolves shared-formula masters to per-cell absolute references, and flags the built-in auto-run names (`Auto_Open`, `Auto_Close`, `Auto_Activate`, `Auto_Deactivate`) as execution entry points, so a `=EXEC("...")` or `=FORMULA(...)` macro reads back in full. A token the decoder does not recognize is emitted as an explicit unknown marker rather than a fabricated formula. Recovery is graded against hand-built BIFF fixtures with known formulas, covering BIFF12's wider reference fields, shared-formula relative-to-absolute resolution, and the `Auto_Open` entry point (`xlm_fixtures.rs`).

## PDF maldoc analysis

The shell pass carries a PDF analyzer (`disrobe_pass_shell::analyze_pdf`) for document-borne malware. It loads a PDF through both cross-reference forms (the classic `xref` table and cross-reference streams), transparently decrypts a Standard-security-handler document that uses RC4 or AESV2 under an empty user password (authenticating against `/U` per the PDF algorithms, with no password supplied), then walks the catalog, name trees, page annotations, and form fields to recover embedded JavaScript and every Launch, URI, GoToR, SubmitForm, ImportData, and EmbeddedFile action with its resolved target. Hex-escaped names, split or concatenated JavaScript strings, and Flate / LZW / ASCII85 filter chains are decoded along the way, and every decompression is bomb-bounded. It is graded against hand-crafted PDF fixtures that plant a known marker behind each path (classic-table and xref-stream JavaScript, RC4 and AESV2 empty-password decrypt, a launch target, an embedded file, name-tree and additional-action scripts), plus an RC4 published-vector check and an empty-password authentication test (`pdf_fixtures.rs`).

## Auto-dispatch

`disrobe auto` detects the dialect and routes obfuscated shell automatically:

```sh
disrobe auto payload.ps1 --out recovered/
```
