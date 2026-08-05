# Global flags

These flags are accepted on every subcommand (they are declared `global = true` on the root parser).

## Output and verbosity

| Flag | Effect |
|---|---|
| `-v`, `-vv`, `-vvv` | Increase log verbosity. |
| `-q`, `--quiet` | Suppress non-error output. |
| `--color <auto\|always\|never>` | Control ANSI color in terminal output. |
| `--json` | Emit a structured JSON document instead of human text. |
| `--ndjson` | Emit newline-delimited JSON (streaming). |
| `--sarif` | Emit SARIF 2.1.0 (GitHub code scanning, etc.). |
| `--progress <auto\|always\|never>` | Progress-bar rendering. `auto` renders only on a TTY. |

## Execution control

| Flag | Effect |
|---|---|
| `--config <PATH>` | Load a `.disrobe.toml` config file. Without it, `disrobe` walks up from the CWD to discover one. See [project configuration](./config.md). |
| `--in-place` | Rewrite the input file in place. |
| `--force` | Overwrite existing outputs without prompting. |
| `-j`, `--threads <N>` | Worker thread-pool size (defaults to detected CPU count). |
| `--no-cache` | Bypass the `.dr` envelope cache. Output is identical with or without this; it is a performance toggle, not a correctness one. |
| `--dry-run` | Report what would happen without writing any output. |

## Debug tracing

| Variable | Effect |
|---|---|
| `DISROBE_DEBUG=<area>` | Stream every offset, size, candidate, and classification a pass walked to stderr. Takes `all` or a comma-separated area list. |
| `DISROBE_DEBUG_FORMAT=json` | Emit one JSON object per debug event instead of human text. |

Debug tracing is sample-sensitive. Only values emitted through explicitly guarded key/value events pass through the masking guard. After trimming surrounding whitespace, it masks a value only when the value is at least 20 characters, contains only ASCII letters, digits, `_`, `-`, `+`, `/`, or `=`, and mixes at least two of uppercase letters, lowercase letters, and digits. When the guard triggers, it preserves the first four trimmed characters and emits `…<redacted N chars>`, using a single Unicode ellipsis and the full trimmed character count. Ordinary messages, unguarded values, labels, and byte previews do not pass through this guard and may expose sample-derived data in either format. Review debug logs before sharing them.

This does not change scanner output: `scan` and `frisk` report full matched values by default. To mask detected secrets in `frisk`, pass `--redact` or `--redact-key <KEY>`.

## Metadata sidecar flags

The metadata bundle flags are also global. See [metadata sidecar and provenance](../llm-sidecar.md) for the complete pack/category model. Summary:

| Flag | Effect |
|---|---|
| `--llm` | Compatibility alias for `--metadata-pack-4` (full bundle, auth-gated categories included). |
| `--metadata-pack-1` | Pack-1: ast + disasm + symbols + strings. |
| `--metadata-pack-2` | Pack-2: pack-1 + cfg + types + imports + provenance. |
| `--metadata-pack-3` | Pack-3: pack-2 + dfg + signatures + constants + roundtrip + sourcemap + manifest. |
| `--metadata-pack-4` | Pack-4: pack-3 + confidence + opcode-coverage + pii-map + decryption-keys (auth-gated). |
| `--ast`, `--disasm`, `--cfg`, `--dfg` | Add individual AST / disassembly / CFG / DFG categories. |
| `--symbols`, `--strings`, `--types`, `--imports` | Add symbols / strings / recovered-types / imports categories. |
| `--constants`, `--signatures`, `--provenance` | Add constants / function-signatures / provenance categories. |
| `--roundtrip-verdict`, `--source-map`, `--manifest-cat` | Add roundtrip-verdict / source-map / manifest categories. |
| `--confidence`, `--opcode-coverage`, `--pii-map` | Add confidence-scores / opcode-coverage / pii-map categories. |
| `--decryption-keys` | Add decryption-keys category (requires `--i-have-authorization`). |
| `--metadata-include <cats>` / `--metadata-exclude <cats>` | Toggle comma-separated categories after applying a pack preset. |
| `--metadata-out <PATH>` | Override the bundle output path (default: `<stem>.disrobe.llm.json` next to the primary output). |
| `--metadata-format <json\|jsonl\|cbor\|msgpack>` | Bundle serialization format (default `json`). |
| `--llm-briefs` | Also emit `AGENTS.md` and `SKILL.md` reconstruction briefs next to the bundle. |
| `--i-have-authorization` | Unlocks auth-gated metadata categories and recovery paths that expose this gate. |

## The authorization gate

`--i-have-authorization` is the explicit assertion used by legally sensitive paths that expose an authorization gate. The `decryption-keys` metadata category refuses without it (`DR-CLI-0420`); language-specific commercial-protector paths document their own gate behavior. Passing the flag is your assertion that you are authorized to analyze the input under the statutory framing in [LEGAL.md](https://github.com/1-3-7/disrobe/blob/main/LEGAL.md).
