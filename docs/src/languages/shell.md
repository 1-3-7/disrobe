# Shell / PowerShell

`disrobe` handles obfuscated PowerShell, Bash, batch, and VBA. PowerShell and shell deobfuscation route through the `py deob`-style peel machinery and the chain runner's detectors.

Coverage:

- **PowerShell** — Invoke-Obfuscation levels 1-6, round-trip deobfuscation.
- **Bash** — Bashfuscator round-trip.
- **Batch** — `.bat` / `.cmd` decode.
- **VBA** — p-code header parse and macro decompression. Full p-code opcode-table disassembly is honest detect-only (that is the pcodedmp-scope wall); `disrobe` parses the header and reports the boundary rather than emitting a fabricated listing.

Run obfuscated shell through `disrobe auto`, which detects the family and applies the right peel:

```sh
disrobe auto payload.ps1 --out recovered/
```
