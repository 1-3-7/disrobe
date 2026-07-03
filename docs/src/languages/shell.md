# Shell / PowerShell

**disrobe** deobfuscates PowerShell, Bash, Batch, VBScript, and VBA. It reverses every major PowerShell obfuscator family and Bashfuscator, recovers VBA source from Office documents, and decompiles VBA p-code with stomp detection.

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

From a `.docm` / `.xlsm` / `.bin` Office container, **disrobe** parses the `dir` stream (MS-OVBA), maps each module to its stream and `TextOffset`, and MS-OVBA-decompresses the `CompressedSourceCode` at that offset to emit the original `.bas` / `.cls` text per module (multi-chunk compression and CopyToken bit-count edges handled). Validated against real Word and Excel documents authored via COM, byte-for-byte against the known module text.

The p-code path lifts a 264-opcode table across VBA3 / VBA5 / VBA6 / VBA7 (32-bit and 64-bit) with identifier resolution. VBA-stomping detection runs a p-code-vs-source classifier that flags modules whose compiled p-code diverges from the stored source and recovers the stomped behavior from the p-code.

## Auto-dispatch

`disrobe auto` detects the dialect and routes obfuscated shell automatically:

```sh
disrobe auto payload.ps1 --out recovered/
```
