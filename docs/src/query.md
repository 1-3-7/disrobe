# Queryable IR and capabilities

`disrobe query` and `disrobe capabilities` turn a stripped binary into something you can interrogate. Both run over the same symbol-independent IR the native disassembler builds (`disrobe-query` and `disrobe-capabilities`), and both accept a raw binary or a `.dr` envelope.

## `disrobe query`: ask the IR a question

```sh
disrobe query app.exe functions                 # discovered functions, complexity, exports
disrobe query app.exe calls-to malloc           # call sites to a target
disrobe query app.exe xrefs-to sekret           # references to a symbol or address
disrobe query app.exe string-decoders           # decoder-shaped functions (loops + byte arith)
disrobe query app.exe complexity-over 20        # functions over a cyclomatic threshold
disrobe query app.exe capability network        # instructions tied to a capability
disrobe query classes implementors 'Lpkg/Root;' # concrete JVM/DEX implementors
```

The query layer is built on the same function discovery the disassembler uses (call-target and prologue scanning), so it works without a symbol table. It accepts a `.dr` envelope at the Disasm or Mir rung; an envelope at any other rung is rejected with an explicit unsupported-rung error rather than silently returning empty or wrong results. The six verbs are:

| Verb | Returns |
|---|---|
| `functions` | Every discovered function with its address, size, cyclomatic complexity, and any export name. |
| `calls-to <target>` | Call sites that reach a named import or address. |
| `xrefs-to <symbol>` | All references to a symbol or address, code and data. |
| `string-decoders` | Functions shaped like a string decoder: a loop plus byte arithmetic over a buffer. |
| `complexity-over <n>` | Functions whose cyclomatic complexity exceeds a threshold, to triage the dense routines first. |
| `capability <name>` | Instructions tied to a capability category (network, filesystem, process, crypto, and so on). |
| `implementors <descriptor>` | Concrete JVM or DEX classes reachable from an interface or abstract-class descriptor, with a child-to-target inheritance proof. |

Every query honors the global `--json` flag, so the output drops straight into a script.

`implementors` accepts a single `.class` or `.dex` file, or a directory containing `.class` and `.dex` files. JVM descriptors such as `Lpkg/Type;` use nonempty components and allow Unicode, hyphens, and control characters except `.`, `;`, `[`, and `/`. DEX descriptors follow the file version's `SimpleName` grammar: ASCII letters and digits, `$`, `-`, `_`, and the format's declared Unicode ranges are valid in every position; DEX 040 additionally admits its declared space characters. Controls, parentheses, and code points outside those ranges are rejected. Target descriptors are limited to 1,048,576 UTF-8 bytes. Quote descriptors at a shell prompt because the terminator is a semicolon. Text output escapes control characters; JSON preserves accepted descriptors. Results and proof paths are sorted by descriptor. The result records missing targets, duplicate definitions, malformed edges, cycles, rejected directory artifacts, and every traversal budget that produced a partial result. A rejected `.class` or `.dex` in a directory does not discard valid siblings. Malformed, missing-definition, and rejected-artifact identities are capped independently by count and byte length, with typed truncation diagnostics. APK and JAR containers are not query inputs, and DEX 041 container-relative layouts are rejected explicitly.

## Navigation through MCP

The MCP companion exposes the same module model through `call_graph`, `xrefs`, `function_summary`, and `neighborhood`. These tools use ids derived from the module source hash and function address rather than function names, so duplicate names remain addressable. Direct-call outcomes distinguish an exact function start, an address inside one function, an ambiguous overlap, a non-function symbol, and an unresolved address. Calls without a direct target remain explicit indirect-call records.

`call_graph`, `xrefs`, and `neighborhood` paginate deterministically. Each cursor binds the source hash and request parameters, and a cursor from another module or neighborhood is rejected. A content-derived discriminator keeps distinct same-address function records addressable without depending on their position in the module. Graph construction has fixed function, instruction, call, cross-reference, candidate-work, and retained-memory ceilings before response pagination. Neighborhood traversal records visited ids and bounds both depth and retained records, so recursion and mutual recursion terminate without dropping their cycle edges.

## `disrobe capabilities`: behavior to ATT&CK

```sh
disrobe capabilities app.exe
disrobe capabilities app.exe --json
```

`disrobe capabilities` runs a rule engine over the same IR and reports the behaviors it matched, each mapped to MITRE ATT&CK techniques and Malware Behavior Catalog (MBC) IDs. Every match carries the instruction offsets that triggered it as per-rule evidence, so a finding can be traced to the exact bytes rather than taken on faith.

The report names the detected format, the match count, and the per-rule evidence. It is the same engine surfaced through the [MCP server](./integrations/mcp.md) and the `--llm` sidecar, so an agent gets the capability surface without re-deriving it.

## Where the IR comes from

The native disassembler (an in-tree iced-x86 decoder, detailed in the [native guide](./languages/native.md)) discovers functions, partitions them into basic blocks, and records each instruction's register, memory, and rflags effects. The query and capability layers read that structure rather than the original symbols, which is why a stripped binary answers the same questions a symbol-rich one does. Pointing either tool at a `.dr` envelope reuses a cached disassembly instead of re-decoding the bytes.
