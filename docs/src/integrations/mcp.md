# MCP server

`disrobe` ships a [Model Context Protocol](https://modelcontextprotocol.io) server so MCP clients can drive deobfuscation and decompilation directly as tools. It speaks MCP over stdio via [rmcp](https://github.com/modelcontextprotocol/rust-sdk).

Analysis tools take **inline base64 bytes** and return **structured JSON**. Workspace and provenance tools take structured metadata such as symbol names or provenance maps. The server never reads sample bytes from a client-controlled filesystem path. This is the same hard rule the HTTP/gRPC/LSP transports enforce; see the [security posture](../cli/serve.md#security-posture).

## Running it

Two equivalent entry points:

```sh
disrobe serve --mcp     # the CLI's MCP companion over stdio
disrobe-mcp             # the standalone MCP binary
```

## Registering with an MCP client

```sh
disrobe serve --mcp
```

Or run the standalone binary:

```sh
disrobe-mcp
```

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
| `decompile` | `bytes_b64`, optional `max_depth` | Every terminal recovered-source artifact (language-keyed text), for example a `.pyc` decompiled to Python. |
| `ioc` | `bytes_b64` | Indicators of compromise: URLs, domains, IPs, emails, paths, registry keys, wallet addresses, crypto constants (one decode layer of base64/hex). |
| `behavior` | `bytes_b64`, optional `imports` | Static capability summary across network, filesystem, process-exec, registry-persistence, crypto, anti-analysis, and dynamic-code categories, with MITRE ATT&CK ids. |
| `strings` | `bytes_b64`, optional `min_len`, `decode` | Printable ASCII + UTF-16 strings, optionally decoding base64/rot/stack-string obfuscation, tagged with their encoding. |
| `verify` | `bytes_b64` | Verify a `.dr` envelope: blake3 root hash, rung, hot/cold sizes. |
| `rename` | `old`, `new`, optional `note` | Append a symbol-rename record to `.disrobe/notes/renames.json`. |
| `annot` | `target` | Regenerate and validate an annotation sidecar under `.disrobe/annotations/`. |
| `provenance_lookup` | `map_json`, `line` | Look up the provenance entry for a line in a provenance-map document. |

The `auto` and `decompile` tools cover `disrobe`'s Python and native-packer surface (PyArmor, PyInstaller, SourceDefender, Nuitka, PyFreeze, `.pyc` disassembly + decompilation, native packers, and container formats), the highest-value chain for triaging an unknown blob. For the full language matrix, drive the [CLI](../cli/reference.md) or the [HTTP daemon](../cli/serve.md).

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
