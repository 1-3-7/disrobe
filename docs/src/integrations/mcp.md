# MCP server

`disrobe` ships a [Model Context Protocol](https://modelcontextprotocol.io) server so MCP clients can drive deobfuscation and decompilation directly as tools. It speaks MCP over stdio via [rmcp](https://github.com/modelcontextprotocol/rust-sdk).

Analysis tools take a file path inside the server's workspace roots, an opened `target_id`, or **inline base64 bytes**, and return **structured JSON**. Workspace and provenance tools also accept metadata such as symbol names or provenance maps. The `annot` workspace tool resolves its target beneath the current workspace before reading it and writing an annotation sidecar; `rename` uses the fixed `.disrobe/notes/renames.json` file. See the [security posture](../cli/serve.md#security-posture) for these path boundaries and the inline-byte analysis contract.

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

## Investigating a file on disk

`open_target` reads a file inside a workspace root and returns a `target_id` (its BLAKE3 hash), its size and SHA-256, and for a native PE, ELF or Mach-O image the format, architecture and counts of sections, symbols, imports, exports and discovered functions. The server keeps the analysis of the eight most recently used targets, so follow-up questions do not re-read or re-analyze the file.

| Tool | Input | Output |
|---|---|---|
| `open_target` | `path` | Target id, size, hashes, native identity or the reason the file is not a native image. |
| `identify_target` | `target_id` | Format plus each compiler, linker, packer, protector, installer, library and signature hit with evidence, confidence and the `disrobe` commands that handle it; Authenticode details for PE images. |
| `inspect_sqlite` | `path` or `target_id`, optional `wal_path`, `table`, `rows`, `recover` | A SQLite database read without SQLite: header, schema, row counts and rows, the write-ahead log applied up to its last commit, the freelist, and with `recover` the deleted records ([details](../languages/sqlite.md)). |
| `inspect_capture` | `path` or `target_id` | A pcap, pcapng, HAR or SAZ capture decoded: flows with reassembled TCP streams, DNS, TLS client hellos with SNI, ALPN and JA3, and HTTP exchanges ([details](../languages/captures.md)). |
| `inspect_crash` | `path` or `target_id` | A Linux ELF core or a minidump triaged: the signal or exception with its faulting instruction and data address as module+offset, every thread with registers, mapped modules with build IDs or PDB identities, and return-address candidates scanned from each stack ([details](../languages/crashes.md)). |
| `target_layout` | `target_id` | Sections with virtual address, size, file offset and file size; imports; exports. |
| `list_functions` | `target_id`, optional `name_contains`, `offset`, `limit` | Discovered functions with name, address, end, instruction count, export flag and the `function_id` the navigation tools accept. |
| `disassemble_function` | `target_id`, `function`, optional `max_instructions` | Instructions with branch and call targets resolved to names. |
| `decompile_function` | `target_id`, `function` | C for one x86-64 function, lifted with its direct callees, or the decompiler's named refusal. |
| `references_to` | `target_id`, `address` (hex address or function name) | Calls, jumps, switch targets and memory operands that reach the address, pointer-sized slots in data sections that hold it, and the instructions that read those slots, each with the containing function. |
| `find_strings` | `target_id`, optional `contains`, `min_len`, `referenced_only`, `offset`, `limit` | Strings with file offset, virtual address, section and the instructions that reference any byte of them, directly or through a pointer slot. |
| `call_path` | `target_id`, `from`, `to`, optional `max_depth` | The shortest chain of direct calls between two functions. |
| `read_bytes` | `target_id`, `address` or `offset`, optional `length` | Up to 64 KiB as hex and printable ASCII with the containing section. |
| `search_bytes` | `target_id`, `pattern` such as `48 8B 05 ?? ?? ?? ??`, optional `max_hits` | Matches with file offset, virtual address, section and function. |
| `locate` | `target_id`, `address` or `offset` | The matching offset or address, section and function. |
| `add_note` | `target_id`, `kind` (`rename`, `comment`, `bookmark`, `unknown`, `resolution`), `text`, optional `address`, `evidence`, `resolves` | Appends a record to `.disrobe/notes/targets/<target_id>.json` and returns every record with the unknowns still open. A resolution names the unknown it closes and must carry evidence. |
| `list_notes` | `target_id`, optional `kind` | The recorded notes and the open unknowns. |

`function` accepts a name, a `0x`-prefixed address inside the function, or a `function_id`. Every analysis tool in the catalog below also accepts `path` or `target_id` in place of `bytes_b64`; pass exactly one of the three. The navigation tools accept a native image by path or `target_id` as well as a `.dr` envelope.

## Tool catalog

| Tool | Input | Output |
|---|---|---|
| `auto` | `bytes_b64`, optional `max_depth` | Chain verdict, detected formats, and per-pass recovery summary. Auto-detects and chains `disrobe`'s Python + native-packer passes. |
| `secret_scan` | `bytes_b64`, optional `redact` | Secret findings with byte offsets. `redact: true` replaces detected values throughout the response. Raw values remain the default. |
| `decompile` | `bytes_b64`, optional `max_depth` | Every terminal recovered-source artifact (language-keyed text), for example a `.pyc` decompiled to Python. |
| `native_match` | each side as `a_bytes_b64`/`a_path`/`a_target_id` and `b_bytes_b64`/`b_path`/`b_target_id`, optional `stage`, `function`, `limit` | Function matches between two native images, for example two builds of one program. |
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

The four navigation tools accept a Disasm- or Mir-rung `.dr` envelope. A function id binds the envelope source hash to the function address and adds a content-derived discriminator when multiple functions share that address, so an id or cursor from another input is rejected. Each response mirrors its structured JSON in a text content block for MCP client compatibility. The complete tool result enforces a 2,048 to 32,768-byte serialized UTF-8 ceiling and declares the corresponding `o200k_base` budget. Every `o200k_base` token encodes at least one byte, so the byte ceiling also bounds the token count; the round-trip tests hold `call_graph` to the ceiling across two pages of a large committed image. A row that cannot fit the selected ceiling returns `DR-MCP-0662` instead of replaying the same cursor.

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

The server performs pure static analysis by default and never executes the supplied bytes. It rejects empty or malformed base64 with a typed error, and rejects unknown JSON fields on every tool. Paths are confined to the workspace roots: the directory the server starts in, each `--root` directory (`disrobe serve --mcp --root <dir>`) and each directory in `DISROBE_MCP_ROOTS`. A path is canonicalized before the check, so `..` segments and symbolic links that lead outside every root are refused with `DR-MCP-0703`. Files are read with a 512 MiB ceiling for `open_target` and 64 MiB for the other analysis tools, and are never executed. See the [forensics and malware-safety posture](../forensics-safety.md) and the [threat model](../threat-model.md).
