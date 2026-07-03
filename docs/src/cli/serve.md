# The daemon: HTTP, gRPC, LSP, MCP

`disrobe serve` runs `disrobe` as a long-lived service over four protocols. The core capability is the same (analyze bytes, return recovered artifacts), exposed through whichever transport fits the caller.

```sh
disrobe serve                              # HTTP on 127.0.0.1:7373
disrobe serve --bind 0.0.0.0:7373          # HTTP on all interfaces (emits a warning banner)
disrobe serve --grpc                       # HTTP on :7373, gRPC on :7374
disrobe serve --stdio                      # LSP over stdio
disrobe serve --mcp                        # MCP companion over stdio (rmcp)
```

## Flags

| Flag | Default | Effect |
|---|---|---|
| `--bind <ADDR>` | `127.0.0.1:7373` | HTTP bind address. |
| `--stdio` | off | Serve LSP JSON-RPC over stdin/stdout instead of HTTP. |
| `--mcp` | off | Serve the MCP companion over stdio instead of HTTP/LSP. |
| `--grpc` | off | Expose the gRPC surface alongside HTTP (binds to `<bind-ip>:<bind-port+1>`). |
| `--cors-origin <ORIGIN>` | (none) | Additional CORS origin to allow. Repeatable. With no origins, all origins are allowed. |
| `--max-body-size <N>` | `52428800` (50 MiB) | Maximum request body size in bytes. |

## HTTP

The default surface. Binds to loopback (`127.0.0.1:7373`) by default; a non-loopback bind emits a warning at startup.

The API is versioned: `/v1/*` and `/v2/*` are aliases. The spec is served at `/openapi.json`.

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/health` | Server liveness (`{ status, version }`). |
| `GET` | `/v1/version` | Tool name, version, and API level (`{ name, version, api }`). |
| `GET` | `/v1/passes` | List registered passes (`{ passes: [{ name, description }] }`). |
| `POST` | `/v1/analyze` | Classify and route bytes. Body: `{ bytes_b64, hint? }`. Returns: `{ routed_action, bytes_read, blake3_hash, reason, candidates }`. |
| `POST` | `/v1/explain/{code}` | Look up a `DR-*` error code. Returns: `{ code, known, title?, description?, crate_path? }`. |
| `POST` | `/v1/envelope/verify` | Verify a `.dr` envelope. Body: `{ bytes_b64 }`. Returns: `{ verified, version, rung, hot_bytes, cold_bytes, root_hash_blake3 }`. |
| `POST` | `/v1/envelope/create` | Wrap raw bytes into a Raw-rung `.dr` envelope. Body: `{ bytes_b64, source_label?, produced_by?, detected_format? }`. Returns: `{ envelope_b64, envelope_bytes, bytes_in, root_hash_blake3, source_hash_blake3 }`. |
| `WS` | `/v1/stream` | WebSocket NDJSON stream (upgrade with `Sec-WebSocket-Protocol: disrobe-stream.v1`). Bytes are sent `bytes_b64`-only; the server never reads from disk. |
| `GET` | `/openapi.json` | OpenAPI 3 spec for the HTTP surface. |

## gRPC

Exposed alongside HTTP with `--grpc`. The gRPC server binds to the same IP as `--bind` but at `<port> + 1` (default `127.0.0.1:7374`). Includes health and reflection services.

## LSP over stdio

`--stdio` speaks JSON-RPC over stdin/stdout using the LSP framing and `initialize` handshake. It does not implement the standard `textDocument` surface. It advertises two custom methods under `capabilities.experimental.disrobe`:

| Method | Description |
|---|---|
| `disrobe/analyze` | Params: `{ bytes_b64, label? }`. Returns the same classification payload as `POST /v1/analyze`. |
| `disrobe/explain` | Params: `{ code }`. Returns the error-code lookup payload. |

Unknown fields in params are rejected (hard error). A `path` field is specifically rejected; all bytes are transmitted inline.

## MCP companion

`--mcp` runs the rmcp-based Model Context Protocol companion, exposing `disrobe`'s capabilities as MCP tools (`auto`, `decompile`, `ioc`, `behavior`, `strings`, `verify`, `rename`, `annot`, and `provenance_lookup`) over stdio. The standalone `disrobe-mcp` binary is equivalent. See the dedicated [MCP server integration page](../integrations/mcp.md) for the full tool catalog and client registration.

## Security posture

All four transports share one hard rule: the server never reads a file from disk based on client input. Requests carry `bytes_b64` only, never a filesystem path. Unknown JSON fields are rejected via `deny_unknown_fields`. Any way to make the server read a file via a client-controlled string is a high-severity vulnerability under the [security policy](../security.md). Run the daemon on loopback unless you have a specific reason not to.
