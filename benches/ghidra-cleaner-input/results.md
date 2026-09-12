# disrobe feeds Ghidra cleaner input

Ghidra 12.1.2 PUBLIC (build 20260605, release zip SHA-256 `b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d`, JDK Temurin 25.0.3), `analyzeHeadless` default analysis with disrobe 0.10.0. Each fixture is a real benign packed PE from `corpus/native/packers/` (Sysinternals utilities and small hello programs; see `corpus/native/packers/MANIFEST.toml` for provenance and SHA-256). `analyzeHeadless` performs static analysis only and never executes the sample. The packed column is the original packed file; the unpacked column is the loadable PE that `disrobe native export --format ghidra` rebuilds from it. Metrics come from the committed `GhidraReport.java` post-script: functions excludes externals and thunks, instructions and defined bytes are the post-analysis listing totals, strings is the count of defined data with a string value. Regenerate with `benches/ghidra-cleaner-input/run.ps1 -GhidraHome <dir>`.

| packer | binary | functions (packed -> unpacked) | instructions (packed -> unpacked) | defined bytes (packed -> unpacked) | strings (packed -> unpacked) |
|---|---|---|---|---|---|
| UPX | hello (Rust x64) | 4 -> 287 (+283) | 225 -> 19124 (+18899) | 9954 -> 89922 (+79968) | 23 -> 179 (+156) |
| ASPack | Clockres | 5 -> 243 (+238) | 58 -> 10544 (+10486) | 5664 -> 50491 (+44827) | 48 -> 116 (+68) |
| ASPack | AccessEnum | 5 -> 101 (+96) | 73 -> 5781 (+5708) | 13579 -> 50973 (+37394) | 62 -> 195 (+133) |
| PECompact | Clockres | 2 -> 306 (+304) | 148 -> 14603 (+14455) | 4816 -> 49366 (+44550) | 27 -> 27 (0) |
| PECompact | AccessEnum | 2 -> 186 (+184) | 155 -> 9278 (+9123) | 20630 -> 52185 (+31555) | 52 -> 53 (+1) |
| MEW | Clockres | 4 -> 333 (+329) | 125 -> 20990 (+20865) | 395 -> 82128 (+81733) | 3 -> 358 (+355) |
| MEW | AccessEnum | 4 -> 152 (+148) | 125 -> 9592 (+9467) | 6879 -> 146487 (+139608) | 3 -> 802 (+799) |
| MEW | Autologon | 4 -> 295 (+291) | 125 -> 19595 (+19470) | 559 -> 79842 (+79283) | 3 -> 406 (+403) |
| kkrunchy | hello (NASM PE32) | 4 -> 1 (-3) | 149 -> 10 (-139) | 534 -> 487 (-47) | 3 -> 4 (+1) |

Reading: on eight of the nine samples disrobe's rebuilt PE gives Ghidra materially more to analyze, so the thesis holds. The packed files are near-opaque to static analysis: Ghidra finds 2 to 5 functions and a few dozen instructions on each, with the real code sitting in tens of thousands of undefined executable bytes (UPX 49451, PECompact Clockres 146074, ASPack AccessEnum 33815). The three MEW packed files are the extreme case, with `executable_block_bytes` of 0 because the original section is virtual-only, so Ghidra sees no code section at all (4 functions, all in the stub). After `disrobe native export` the same programs disassemble into 101 to 333 functions and 5781 to 20990 instructions, and string recovery jumps with them (MEW AccessEnum 3 to 802). kkrunchy is the one sample where the delta is negative: the packed hello carries 70474 undefined executable bytes that Ghidra's entry-point heuristics split into 4 nominal functions, while disrobe's classic-kkrunchy recovery rebuilds a 4096-byte single-section PE in which Ghidra cleanly finds the single real function (1 function, 10 instructions). That is an honest loss on the raw count, and it is consistent with the manifest's note that classic kkrunchy is a partial 17.77 percent decode of a 1 KB NASM program, not a full image rebuild. PECompact Clockres strings (27 to 27) and PECompact AccessEnum strings (52 to 53) are the other near-zero deltas: those binaries keep their string data in the carried-over data sections, so the string count barely moves even though the function and instruction counts climb sharply.

Reproduce:

```
disrobe native export --format ghidra <packed> --out <dir>
analyzeHeadless <proj> <name> -import <bin> -postScript GhidraReport.java <out.json> -deleteProject -overwrite
```
