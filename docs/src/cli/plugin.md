# Signed WebAssembly plugins

`disrobe plugin` runs a third-party analysis component through the `disrobe-plugin-host` sandbox.
A plugin never runs with disrobe's own privileges: it is a WebAssembly component, signed by a key
you name explicitly, executed under a fuel budget, a wall-clock deadline, and a memory cap, with
every import denied unless a manifest grants it.

```sh
disrobe plugin verify my-plugin.wasm --trusted-key operator.pub
disrobe plugin run my-plugin.wasm --trusted-key operator.pub --out result.bin < input.bin
disrobe plugin list ./plugins --trusted-key operator.pub
```

## Bundle shape

A plugin bundle is three sibling files sharing one stem:

| File | Purpose |
|---|---|
| `<name>.wasm` | The signed WebAssembly component. |
| `<name>.wasm.minisig` | A minisign signature over the component bytes. |
| `<name>.toml` | The manifest: declared name, version, and the capability set the component may import. |

There is no registry and no distribution mechanism. `--trusted-key` always names an operator-
supplied minisign public key file, never one disrobe embeds.

## Commands

| Command | Purpose |
|---|---|
| `disrobe plugin run <component> --trusted-key <pubkey> --out <file> [--input <file>] [--fuel N] [--wall-deadline-ms MS] [--memory-cap-bytes N] [--format text\|json]` | Verify and run the component. Reads input from stdin when `--input` is omitted; writes output bytes to `--out`. |
| `disrobe plugin verify <component> --trusted-key <pubkey> [--format text\|json]` | Verify the signature and capability manifest without running the component. |
| `disrobe plugin list <dir> [--trusted-key <pubkey>] [--format text\|json]` | List every bundle in a directory. Each bundle is also signature- and capability-verified when `--trusted-key` is given. |

`--fuel`, `--wall-deadline-ms`, and `--memory-cap-bytes` each override the sandbox's default, and
are always clamped to its compiled-in ceiling regardless of what is requested.

## Guest contract

A component exports one function, `run: func(list<u8>) -> list<u8>`. It receives the input bytes
and returns output bytes; nothing else crosses the boundary. The component linker stays empty, so
a manifest capability grant permits validation but never actually supplies a host function to call.

## Provenance: authenticated versus declared

`--format json` reports two kinds of fields, and labels which is which:

- **Authenticated**, derived from the verified bytes: the component's BLAKE3 hash and the trusted
  signing key's id.
- **Declared, not authenticated**: the manifest's `name` and `version`. The signature covers the
  component bytes only, never the manifest, so an attacker who can place files next to a validly
  signed component can edit its declared name or version without invalidating the signature.
  `run`'s JSON output carries `manifest_version_authenticated: false` alongside those fields
  rather than presenting them as fact.

## Rejections

Every rejection is a distinct typed error surfaced before the guest ever executes: unsigned, wrong
key, over-size component, over-size signature, non-UTF-8 signature, missing manifest, malformed
manifest, an ungranted capability, a missing `run` export, or a wrongly typed one. At runtime, the
fuel, wall-clock, and memory caps each independently terminate a runaway guest.

## Scope

CLI-only today: a plugin invocation names an explicit local path an operator supplies, unlike
disrobe's own passes, so it is not reachable from `disrobe auto`, the MCP surface, or the python
bindings. See the [security policy](../security.md) for the full trust model, including what
resource sandboxing does and does not guarantee about a plugin's output correctness.
