# The daemon: HTTP, gRPC, LSP, MCP

`disrobe serve` runs `disrobe` as a long-lived service over four protocols. The core capability is the same — analyze bytes, return recovered artifacts — exposed through whichever transport fits the caller.

```sh
disrobe serve                              # HTTP on 127.0.0.1:7373
disrobe serve --bind 0.0.0.0:7373          # HTTP on all interfaces (emits a warning banner)
disrobe serve --grpc                       # HTTP + gRPC
disrobe serve --stdio                      # LSP over stdio
disrobe serve --mcp                        # MCP companion over stdio (rmcp)
```

## HTTP

The default surface. Binds to loopback (`127.0.0.1:7373`) by default; a non-loopback bind emits a `tracing::warn!` banner at startup. Additional CORS origins are added with repeatable `--cors-origin`. The maximum request body size is `--max-body-size` (default 50 MiB).

## gRPC

Exposed alongside HTTP with `--grpc`. Includes health and reflection services.

## LSP over stdio

`--stdio` speaks the Language Server Protocol over stdin/stdout. The `disrobe/analyze` method takes recovered-bytes requests and returns structured analysis, suitable for editor integration.

## MCP companion

`--mcp` runs the rmcp-based Model Context Protocol companion, exposing `disrobe`'s capabilities as MCP tools — `verify`, `rename`, `annot`, and `provenance_lookup` — so an MCP-aware agent (Claude Code, Cursor, and others) can call `disrobe` directly as a tool server.

## Security posture

All four transports share one hard rule: **the server never reads a file from disk based on client input.** Requests carry `bytes_b64` only — never a filesystem path. Unknown JSON fields are rejected via `#[serde(deny_unknown_fields)]`. Any way to make the server read a file via a client-controlled string is a high-severity vulnerability under the [security policy](../security.md). Run the daemon on loopback unless you have a specific reason not to.
