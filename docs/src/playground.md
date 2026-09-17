# Browser playground

The [playground](https://1-3-7.github.io/disrobe/playground/) analyzes files in your
browser using the WebAssembly build of Disrobe. Your input stays on your device. Analysis runs
in a worker, with results displayed beside the input.

## Start with a sample

Find a mode by typing its language, name, or operation in the sidebar search. On a narrow
screen, type in the mode picker and use the arrow keys and Enter to select a result.
Each runnable mode loads its example and starts analysis. Use **Sample** to restore it,
**Upload** to choose a file, or drop a file into the input panel. Once you upload or edit
an input, switching modes keeps that input. Browser Back and Forward restore the selected
mode without discarding it. **Sample** explicitly replaces it with the mode's example.

Text inputs can be edited directly; **Run** or **Ctrl+Enter** analyzes the current input.
Binary uploads retain their original bytes, including when used with string or indicator
analysis. Recovered source and inspection reports can be downloaded.

Use **Stop** to cancel analysis and sample downloads. Switching modes or editing the input
also stops pending work and clears its result. Sample downloads and analyses each time out
after 30 seconds. The playground accepts files up to 64 MiB; use the CLI for larger inputs
or longer runs. The analysis engine has a 512 MiB WebAssembly memory limit. A stopped or
failed engine is discarded; the next request starts a fresh worker.

APK inspection accepts up to 4096 archive entries, 32 MiB of decoded data per entry, and
128 MiB across the archive. The decoded manifest is limited to 2 MiB. Resource-only APKs
are supported. Recovered manifests, resource XML, and reconstructed values files have
individual downloads; the JSON report retains the remaining metadata. APK signing blocks
are parsed without verifying signatures.

PHAR archives have a member selector, binary downloads, and **Use as input** to route an
extracted member to another pass. Extraction handles one member at a time, up to 32 MiB.
The archive list accepts up to 4096 members and 1 MiB of member names. Duplicate or
colliding names are rejected. The shared parser also limits declared aggregate output
to 256 MiB. Archive checksums and flags are metadata, not signature verification.

Dart Kernel recovery lists embedded source files individually, with Dart highlighting
and a download for each file. The JSON report includes libraries, classes, and procedures.
The browser accepts up to 4096 source records. Components with no recovered source retain
their structure report.

Go inspection accepts executables up to 16 MiB and exposes build information, searchable
functions, runtime types, and complete JSON downloads. Addresses use hexadecimal strings
to preserve all 64 bits. The browser accepts up to 65,536 function and source-file records,
16,384 type and interface links, and 131,072 nested type records. JSON results are limited
to 32 MiB; long previews are shortened while downloads retain the complete report.
Garble recovery, DWARF, and embedded-file extraction use the CLI.
The bundled Go example includes the Go runtime; its
[license](https://1-3-7.github.io/disrobe/playground/samples/GO-LICENSE.txt)
accompanies the sample.

PyArmor module recovery pairs a wrapper of up to 1 MiB with its runtime of up to 16 MiB.
Support covers standard PyArmor versions 8 and 9 outer modules. The result includes code-object counts,
names, strings, and downloads of the outer module, its marshal payload, and the JSON report.
Inner bytecode is unchanged. Replacing a sample wrapper clears its bundled runtime;
choose the runtime distributed with your input. Both files stay in the browser.

Source-map recovery accepts a JSON map or JavaScript with an inline map, up to 1 MiB.
It lists embedded originals with highlighted previews and exact file downloads, including
empty files. Indexed maps retain each section's source root and ignored-file metadata.
Missing originals are listed separately. External map references require an uploaded map
file; the browser does not fetch them. Recovery accepts up to 4096 sources, 1024 sections,
16 nesting levels, and 65,536 mapping segments. Shortened previews retain complete downloads.

JavaScript unbundling accepts bundles up to 1 MiB. Search module and chunk names, inspect
highlighted source, and download individual modules or the full JSON report. The browser
limits extraction to its configured module-count capacity and 8 MiB of module data; JSON output also has an 8 MiB
limit. Module bodies retain the bundler's transformations. Use source-map recovery for
embedded originals. The example was built with Webpack 5 from the geometry and inventory
fixtures in the repository.

Source formatting supports JavaScript, JSX, TypeScript and TSX with Prettier 3.9.6.
Choose the matching language to retain JSX and TypeScript syntax. Files up to 1 MiB
are formatted in a worker with a 30-second deadline and an 8 MiB output limit.
Downloads contain the complete output, including retained comments. Formatting does
not lint or type-check the code. Embedded languages inside template strings are unchanged.

Keyboard users can select **Skip to analysis** to bypass navigation. The binary viewer
supports arrow keys, Home, End, Page Up, Page Down, and Shift to extend a selection.

JVM class recovery accepts individual `.class` files up to 8 MiB. Inspect recovered
Java, select a method's bytecode, or download the full metadata report. The report
retains exception ranges, bodyless methods, fallback counts, and decoding errors.
Java downloads use the emitted class name. The bundled example comes from
[`Hierarchy.java`](https://github.com/1-3-7/disrobe/blob/main/crates/disrobe-pass-jvm/tests/fixtures/implementors/Hierarchy.java).
Browser limits are 1024 methods, 4096 fields, 16,384 constant-pool slots, 16,384
instructions per method, and 65,536 instructions per class. Each method may have
up to 256 exception handlers and 2048 branch targets. JSON output is capped at
8 MiB. JAR traversal and related-class discovery use the CLI.

.NET inspection accepts managed DLLs and executables up to 8 MiB. Select a method
to inspect its CIL or recovered C#, F#, and Visual Basic body. Each language retains
its emitted, bodyless, and failed method counts. Downloads contain the complete
selected method or assembly report, including exception regions and metadata.
Integer operands remain exact decimal text; floating-point operands retain their
bit patterns. The example comes from
[`Shapes.cs`](https://github.com/1-3-7/disrobe/blob/main/corpus/dotnet/shapes/Shapes.cs).
The browser accepts 512 types, 4096 fields, 1024 methods, and 32,768 metadata rows.
It rejects malformed definition signatures and repeated member tokens. Instruction,
exception, and branch limits match the JVM workspace; combined recovered source
and serialized JSON each have an 8 MiB limit. External .NET backends use the CLI.

The theme control offers **Dark** and **Light**. Dark is the default. Your selection is saved
locally when browser storage is available.

## Browser checks

The browser suite passes 310 desktop and mobile checks across 57 sample modes,
including single-classfile JVM recovery and managed .NET assembly recovery. Each
sample mode is analyzed again through **Run** and checked in both themes. The 228
catalog accessibility scans report no critical or serious violations.

Performance was measured on the PHP detection screen by editing its sample, running
analysis, and switching themes. On a Ryzen 9 9950X3D2 host with Chromium at 4× CPU
slowdown and the cache disabled,
the desktop and mobile runs measured LCP at 608 and 308 ms, CLS at 0.00065 and 0,
and INP at 144 and 48 ms. These are two local preview runs over an unthrottled loopback
connection. The [browser results](https://github.com/1-3-7/disrobe/blob/main/docs/demo/browser.json)
include the cases, conditions, report hashes, and reproduction commands.

## Available modes

| Input or task | Operations |
|---|---|
| General triage | File-signature identification, route suggestions, strings, indicators, behavior, anti-analysis signals, secrets, entropy, and YARA rule generation |
| Python `.pyc` | Disassembly and source recovery |
| JVM `.class` | Java recovery, method bytecode, class metadata, and complete source/report downloads |
| Managed `.dll` and `.exe` | C#, F#, and Visual Basic method recovery, CIL listings, and assembly metadata |
| Go executables | Build information, functions, source paths, runtime types, interface tables, and JSON downloads |
| PyArmor wrappers | Header inspection, version and protection detection, mode classification, and paired-runtime outer-module recovery |
| JavaScript and TypeScript | JS/JSX/TS/TSX formatting, bundle detection, module extraction, embedded originals from source maps, indexed sections, ignored-file metadata, source filtering, and individual downloads |
| Hermes bytecode | Recovered JavaScript structure, per-function instructions, recovery counts, and indexed strings with identifier kinds |
| Python pickle | Safety classification, disassembly, source rendering, symbolic trace, and polyglot detection |
| WebAssembly | Module analysis, obfuscator detection, WAT, Rust/TypeScript/C lifts, control-flow graphs, signatures, GC types, exception handling, memories, component manifests, source maps, and runtime preludes |
| Lua | Dialect detection and source recovery |
| PHP | Detection and supported wrapper peeling |
| PHAR | Member listing, selected-file extraction, binary downloads, and reuse as input |
| Dart Kernel | Embedded source files, individual downloads, and program structure |
| Ruby | YARV and mruby source recovery, YARV instructions, and artifact analysis |
| Android APK | Manifest and resource XML, reconstructed values, native library metadata, and signing blocks |
| Erlang and Elixir BEAM | Source recovery |
| Flash / ActionScript | ABC decompilation |
| Scripted languages | Artifact analysis |
| Shell and batch | Detection and deobfuscation |
| Mobile bundles | Bundle detection |
| Swift and Objective-C | Mach-O architecture, named types and fields, protocols, selectors, and symbol metadata |

Output varies by mode: decoded source, instructions, graphs, metadata, or findings. A detection
result identifies a format or protection mechanism; it does not mean the original source was recovered.

## Execution and scope

The browser passes inspect input bytes. Pickle tracing reconstructs an object graph symbolically
without importing its globals or invoking `__reduce__`. Python and WebAssembly recovery parse and
lower bytecode. The browser build excludes the PyArmor dynamic-capture path and native BCC lift.

Use the CLI for directories, recursive archive workflows, automatic recovery chains, native executable decompilation,
external backends, and offline forensic reports. Recompilation and runtime comparisons use
separate host toolchains; they are not performed by the playground. See the
[capability map](./capabilities.md) and [library APIs](./library.md) for those entry points.
