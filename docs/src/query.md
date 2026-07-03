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
```

The query layer is built on the same function discovery the disassembler uses (call-target and prologue scanning), so it works without a symbol table. The six verbs are:

| Verb | Returns |
|---|---|
| `functions` | Every discovered function with its address, size, cyclomatic complexity, and any export name. |
| `calls-to <target>` | Call sites that reach a named import or address. |
| `xrefs-to <symbol>` | All references to a symbol or address, code and data. |
| `string-decoders` | Functions shaped like a string decoder: a loop plus byte arithmetic over a buffer. |
| `complexity-over <n>` | Functions whose cyclomatic complexity exceeds a threshold, to triage the dense routines first. |
| `capability <name>` | Instructions tied to a capability category (network, filesystem, process, crypto, and so on). |

Every query honors the global `--json` flag, so the output drops straight into a script.

## `disrobe capabilities`: behavior to ATT&CK

```sh
disrobe capabilities app.exe
disrobe capabilities app.exe --json
```

`disrobe capabilities` runs a rule engine over the same IR and reports the behaviors it matched, each mapped to MITRE ATT&CK techniques and Malware Behavior Catalog (MBC) IDs. Every match carries the instruction offsets that triggered it as per-rule evidence, so a finding can be traced to the exact bytes rather than taken on faith.

The report names the detected format, the match count, and the per-rule evidence. It is the same engine surfaced through the [MCP server](./integrations/mcp.md) and the `--llm` sidecar, so an agent gets the capability surface without re-deriving it.

## Where the IR comes from

The native disassembler (an in-tree iced-x86 decoder, detailed in the [native guide](./languages/native.md)) discovers functions, partitions them into basic blocks, and records each instruction's register, memory, and rflags effects. The query and capability layers read that structure rather than the original symbols, which is why a stripped binary answers the same questions a symbol-rich one does. Pointing either tool at a `.dr` envelope reuses a cached disassembly instead of re-decoding the bytes.
