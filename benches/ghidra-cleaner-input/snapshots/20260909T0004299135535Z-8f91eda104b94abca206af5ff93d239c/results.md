# disrobe feeds Ghidra cleaner input

Toolchain: Ghidra 12.1.2 from archive SHA-256 b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d; JVM 25.0.4 (Eclipse Adoptium); source d9d9a48384a4fc6239488b76991cfcacaf471804 with identity SHA-256 60d39a749a688db5c118db7a3660fd4eabee64a633e1f658242af9ce47d76677; 9 fixtures measured at 2026-09-09T00:04:29.6803478Z.

Ghidra 12.1.2, `analyzeHeadless` default analysis. Each fixture is a real benign packed PE from `corpus/native/packers/` (Sysinternals utilities and small hello programs; see `corpus/native/packers/MANIFEST.toml` for provenance and SHA-256). `analyzeHeadless` performs static analysis only and never executes the sample. The packed column is the original packed file; the unpacked column is the loadable PE that `disrobe native export --format ghidra` rebuilds from it. Metrics come from the committed `GhidraReport.java` post-script. Regenerate with `benches/ghidra-cleaner-input/run.ps1 -GhidraHome <dir> -GhidraArchive <zip>`.

| packer | binary | functions (packed -> unpacked) | instructions (packed -> unpacked) | defined bytes (packed -> unpacked) | strings (packed -> unpacked) |
|---|---|---|---|---|---|
| UPX | hello (Rust x64) | 4 -> 287 (+283) | 225 -> 19060 (+18835) | 9954 -> 89677 (+79723) | 23 -> 179 (+156) |
| ASPack | Clockres | 5 -> 243 (+238) | 58 -> 10544 (+10486) | 5664 -> 50491 (+44827) | 48 -> 116 (+68) |
| ASPack | AccessEnum | 5 -> 101 (+96) | 73 -> 5781 (+5708) | 13579 -> 50973 (+37394) | 62 -> 195 (+133) |
| PECompact | Clockres | 2 -> 306 (+304) | 148 -> 14603 (+14455) | 4816 -> 49366 (+44550) | 27 -> 27 (0) |
| PECompact | AccessEnum | 2 -> 186 (+184) | 155 -> 9278 (+9123) | 20630 -> 52185 (+31555) | 52 -> 53 (+1) |
| MEW | Clockres | 4 -> 333 (+329) | 125 -> 20990 (+20865) | 395 -> 82128 (+81733) | 3 -> 358 (+355) |
| MEW | AccessEnum | 4 -> 152 (+148) | 125 -> 9592 (+9467) | 6879 -> 146487 (+139608) | 3 -> 802 (+799) |
| MEW | Autologon | 4 -> 295 (+291) | 125 -> 19595 (+19470) | 559 -> 79842 (+79283) | 3 -> 406 (+403) |
| kkrunchy | hello (NASM PE32) | 4 -> 1 (-3) | 149 -> 10 (-139) | 534 -> 487 (-47) | 3 -> 4 (+1) |

Reproduce:

```
disrobe native export --format ghidra <packed> --out <dir>
analyzeHeadless <proj> <name> -import <bin> -postScript GhidraReport.java <out.json> -deleteProject -overwrite
```

This is a public export of the recorded measurement. Local installation paths use named placeholders. [Export provenance](public-export.json) retains the original checksums and describes the transformations; the full working-tree patch is omitted.
