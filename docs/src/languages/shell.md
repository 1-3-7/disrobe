# Shell / PowerShell

`disrobe` deobfuscates PowerShell, Bash, Batch, VBScript, and VBA. It reverses every major PowerShell obfuscator family and Bashfuscator, recovers VBA source from Office documents, decompiles VBA p-code with stomp detection, recovers Excel 4.0 (XLM) macro formulas, and analyzes PDF maldocs.

## At a glance

| Dialect | Families |
|---|---|
| PowerShell | Invoke-Obfuscation (Token, AST, String, Encoding, Compress, Launcher), Invoke-Stealth, PowerHell, Chameleon, psobf, ISESteroids |
| Bash | Bashfuscator (Token, String, Obfuscate, Compress modes), indirection peeler |
| Batch | `.bat` / `.cmd` random-char and set-indirection patterns |
| VBA / VBScript | VBA module source recovery, VBScript WSH patterns |

| Other surface | Coverage |
|---|---|
| VBA p-code | 264-opcode table across VBA3 / VBA5 / VBA6 / VBA7 (32-bit and 64-bit) with identifier resolution, plus VBA-stomping detection |
| Excel 4.0 (XLM) | BIFF8 (`.xls`) and BIFF12 (`.xlsb`) macro sheets, full Ftab and Cetab function tables, shared-formula resolution, auto-run entry points |
| PDF maldocs | Both cross-reference forms, empty-password RC4 / AESV2 decrypt, embedded JavaScript and every Launch, URI, GoToR, SubmitForm, ImportData, and EmbeddedFile action |

## Commands

```sh
disrobe shell deob payload.ps1 --out recovered.ps1
disrobe shell detect payload.ps1
disrobe shell deob book.xls                    # Excel 4.0 macro-sheet formulas from BIFF8 or BIFF12
disrobe auto payload.ps1 --out recovered/      # detect the dialect and route obfuscated shell automatically
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

## Coverage and fidelity

### VBA source and p-code

From a `.docm` / `.xlsm` / `.bin` Office container, `disrobe` parses the `dir` stream (MS-OVBA), maps each module to its stream and `TextOffset`, and MS-OVBA-decompresses the `CompressedSourceCode` at that offset to emit the original `.bas` / `.cls` text per module (multi-chunk compression and CopyToken bit-count edges handled). Validated against real Word and Excel documents authored via COM, byte-for-byte against the known module text.

The p-code path lifts a 264-opcode table across VBA3 / VBA5 / VBA6 / VBA7 (32-bit and 64-bit) with identifier resolution. The disassembly is graded byte-for-byte against a real `pcodedmp` dump. The step above it, rebuilding VBA source from that p-code, is graded separately by comparing the recovered text line by line and in order against the authored `.bas`, keeping every operator and operand order: it recovers 100% of authored lines on both committed modules, 71 of 71 on SourceProbe and 552 of 552 on the wider EdgeCases. That is measured on two modules, not a claim about every VBA project, and the comparison is pinned so a regression fails rather than being printed. VBA-stomping detection runs a p-code-vs-source classifier that flags modules whose compiled p-code diverges from the stored source and recovers the stomped behavior from the p-code.

### Excel 4.0 (XLM) macros

`disrobe shell deob book.xls` recovers Excel 4.0 macro-sheet formulas from a BIFF8 (`.xls`) or BIFF12 (`.xlsb`) workbook. It decodes the Ptg RPN token stream back to formula text over the full Ftab and Cetab function tables, resolves shared-formula masters to per-cell absolute references, and flags the built-in auto-run names (`Auto_Open`, `Auto_Close`, `Auto_Activate`, `Auto_Deactivate`) as execution entry points, so a `=EXEC("...")` or `=FORMULA(...)` macro reads back in full. A token the decoder does not recognize is emitted as an explicit unknown marker rather than a fabricated formula. Recovery is graded against hand-built BIFF fixtures with known formulas, covering BIFF12's wider reference fields, shared-formula relative-to-absolute resolution, and the `Auto_Open` entry point (`xlm_fixtures.rs`).

### PDF maldoc analysis

The shell pass carries a PDF analyzer (`disrobe_pass_shell::analyze_pdf`) for document-borne malware. It loads a PDF through both cross-reference forms (the classic `xref` table and cross-reference streams), transparently decrypts a Standard-security-handler document that uses RC4 or AESV2 under an empty user password (authenticating against `/U` per the PDF algorithms, with no password supplied), then walks the catalog, name trees, page annotations, and form fields to recover embedded JavaScript and every Launch, URI, GoToR, SubmitForm, ImportData, and EmbeddedFile action with its resolved target. Hex-escaped names, split or concatenated JavaScript strings, and Flate / LZW / ASCII85 filter chains are decoded along the way, and every decompression is bomb-bounded. It is graded against hand-crafted PDF fixtures that plant a known marker behind each path (classic-table and xref-stream JavaScript, RC4 and AESV2 empty-password decrypt, a launch target, an embedded file, name-tree and additional-action scripts), plus an RC4 published-vector check and an empty-password authentication test (`pdf_fixtures.rs`).

## Limits

The XLM decoder is graded two ways that do not share a reading of the specification. Workbooks authored by real Microsoft Excel 16.0 are decoded and compared against the formulas as authored, across 99 cells in both directions so that a missing cell and an unexpected extra cell each fail, with every fixture pinned by length and sha256; a control flips one byte of the real `=SUM(1,2)` Ptg stream and must be rejected. The function tables are graded against an independent decoder's published snapshot, agreeing on 476 shared `Ftab` ids and 396 shared `Cetab` ids, which is what catches the wrong-index case where every `CALL` and `EXEC` an analyst reads would be renamed.

Two limits remain. Specification-assembled fixtures still cover shapes Excel will not author, and for those the same reading of the specification produces both the bytes and the expectation, so they catch a decoder that contradicts the specification but not a misreading shared by both sides. Breadth over arbitrary real-world workbooks is not graded, because the Excel-authored coverage comes from one producer version.

The VBA source-from-p-code line figure is measured on two committed modules, as stated above, not on every VBA project. A Ptg token the XLM decoder does not recognize is emitted as an explicit unknown marker rather than a fabricated formula.
