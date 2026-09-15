# MCP server

`disrobe` ships a [Model Context Protocol](https://modelcontextprotocol.io) server so MCP clients can drive deobfuscation and decompilation directly as tools. It speaks MCP over stdio via [rmcp](https://github.com/modelcontextprotocol/rust-sdk).

Analysis tools take **inline base64 bytes** and return **structured JSON**. Workspace and provenance tools also accept metadata such as symbol names or provenance maps. The `annot` workspace tool resolves its target beneath the current workspace before reading it and writing an annotation sidecar; `rename` uses the fixed `.disrobe/notes/renames.json` file. See the [security posture](../cli/serve.md#security-posture) for these path boundaries and the inline-byte analysis contract.

## Running it

Two equivalent entry points:

```sh
disrobe serve --mcp
disrobe-mcp
```

## Registering with an MCP client

Most clients accept a JSON server entry. Point `command` at `disrobe` (or `disrobe-mcp`) and run over stdio:

```json
{
  "mcpServers": {
    "disrobe": {
      "command": "disrobe",
      "args": ["serve", "--mcp"]
    }
  }
}
```

## Tool catalog

| Tool | Input | Output |
|---|---|---|
| `auto` | `bytes_b64`, optional `max_depth` | Chain verdict, detected formats, and per-pass recovery summary. Auto-detects and chains `disrobe`'s Python + native-packer passes. |
| `secret_scan` | `bytes_b64`, optional `redact` | Secret findings with byte offsets. `redact: true` replaces detected values throughout the response. Raw values remain the default. |
| `decompile` | `bytes_b64`, optional `max_depth` | Every terminal recovered-source artifact (language-keyed text), for example a `.pyc` decompiled to Python. |
| `native_match` | `a_bytes_b64`, `b_bytes_b64`, optional `stage`, `function`, `limit` | Function matches between two native images. |
| `wasm_lift` | `bytes_b64`, `target` | WebAssembly source lift with instruction coverage; available in builds with the `wasm` feature. |
| `ioc` | `bytes_b64` | Indicators of compromise: URLs, domains, IPs, emails, paths, registry keys, wallet addresses, crypto constants (one decode layer of base64/hex). |
| `behavior` | `bytes_b64`, optional `imports` | Static capability summary across network, filesystem, process-exec, registry-persistence, crypto, anti-analysis, and dynamic-code categories, with MITRE ATT&CK ids. |
| `strings` | `bytes_b64`, optional `min_len`, `decode` | Printable ASCII + UTF-16 strings, optionally decoding base64/rot/stack-string obfuscation, tagged with their encoding. |
| `coverage` | `bytes_b64` | Claimed, slack, unclaimed, and truncated byte ranges in an executable image, including overlaps and a coverage ratio. |
| `verify` | `bytes_b64` | Verify a `.dr` envelope: blake3 root hash, rung, hot/cold sizes. |
| `rename` | `old`, `new`, optional `note` | Append a symbol-rename record to `.disrobe/notes/renames.json`. |
| `annot` | `target` | Regenerate and validate an annotation sidecar under `.disrobe/annotations/`. |
| `provenance_lookup` | `map_json`, `line` | Look up the provenance entry for a line in a provenance-map document. |
| `call_graph` | `bytes_b64`, optional `token_budget`, optional `cursor` | Page through function summaries and classified calls. Direct calls distinguish function starts, function interiors, non-function symbols, unresolved addresses, ambiguous overlaps, and indirect calls. |
| `xrefs` | `bytes_b64`, `function_id`, optional `token_budget`, optional `cursor` | Return cross-references to the function identified by a content-bound id. |
| `function_summary` | `bytes_b64`, `function_id`, optional `token_budget` | Return address, extent, export state, instruction and block counts, complexity, and incoming, outgoing, and indirect-call counts. |
| `neighborhood` | `bytes_b64`, `entry_ids`, `depth`, optional `direction`, optional `token_budget`, optional `cursor` | Page through a cycle-safe caller, callee, or bidirectional neighborhood. |

The four navigation tools accept a Disasm- or Mir-rung `.dr` envelope. A function id binds the envelope source hash to the function address and adds a content-derived discriminator when multiple functions share that address, so an id or cursor from another input is rejected. Each response mirrors its structured JSON in a text content block for MCP client compatibility. The complete tool result enforces a 2,048 to 32,768-byte serialized UTF-8 ceiling and declares the corresponding `o200k_base` budget. The external tokenizer gate checks both representations for all four tools on a large committed image. A row that cannot fit the selected ceiling returns `DR-MCP-0662` instead of replaying the same cursor.

The committed recovery grade covers direct calls in one stripped x86-64 ELF against its distinct unstripped toolchain twin. Other architectures, executable formats, indirect-target recovery methods, and optimized call forms remain unmeasured by that grade. Disasm and Mir envelopes from those sources are accepted as typed input, but the server does not infer a missing format or architecture from the envelope payload.

The `auto` and `decompile` tools cover `disrobe`'s Python and native-packer surface (PyArmor, PyInstaller, SourceDefender, Nuitka, PyFreeze, `.pyc` disassembly + decompilation, native packers, and container formats). Use the [CLI](../cli/reference.md) for the full language matrix. The [HTTP daemon](../cli/serve.md) provides classification, routing information and envelope operations.

## Example call

A client calls `decompile` with the base64 of a `.pyc` and receives the recovered Python:

```json
{
  "name": "decompile",
  "arguments": { "bytes_b64": "4w0NCgAAAAA..." }
}
```

```json
{
  "schema": "disrobe.decompile/v1",
  "verdict": "Complete",
  "recovered": [
    { "pass": "py.decompile", "language": "Python", "formatted": true, "source": "x = a + b\n..." }
  ]
}
```

## Security posture

The server performs pure static analysis by default and never executes the supplied bytes. It rejects empty or malformed base64 with a typed error, and rejects unknown JSON fields on every tool. Analysis tools do not accept filesystem paths for sample input, so a client cannot redirect analysis to an arbitrary local file by passing a path-like string. See the [forensics and malware-safety posture](../forensics-safety.md) and the [threat model](../threat-model.md).
