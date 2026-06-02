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
| `--seed <N>` | RNG seed for any non-deterministic backend (keeps runs reproducible). |
| `--config <PATH>` | Load a TOML config file. |
| `--in-place` | Rewrite the input file in place. |
| `--force` | Overwrite existing outputs without prompting. |
| `-j`, `--threads <N>` | Worker thread-pool size (defaults to detected CPU count). |
| `--no-cache` | Bypass the `.dr` envelope cache. Output is identical with or without this — it is a performance toggle, not a correctness one. |
| `--dry-run` | Report what would happen without writing any output. |

## LLM sidecar flags

The full `--llm` family is also global. See [LLM sidecar and provenance](../llm-sidecar.md) for the complete pack/category model. Summary:

| Flag | Effect |
|---|---|
| `--llm` | Alias for the full Pack-4 metadata bundle. |
| `--metadata-pack-1 .. --metadata-pack-4` | Cumulative category presets. |
| `--metadata-include <cats>` / `--metadata-exclude <cats>` | Toggle individual categories. |
| `--metadata-out <PATH>` | Override the bundle output path. |
| `--metadata-format <json\|jsonl\|cbor\|msgpack>` | Bundle serialization format. |
| `--llm-briefs` | Also emit `AGENTS.md` and `SKILL.md` reconstruction briefs. |
| `--i-have-authorization` | Unlocks the auth-gated `decryption-keys` category and grey-zone protector behavior. |

## The authorization gate

`--i-have-authorization` is the single gate guarding behavior that is legally sensitive: grey-zone commercial-protector reversal and the `decryption-keys` LLM category. Without it, those paths refuse to run (`DR-CLI-0420` for decryption keys). It is your assertion that you are authorized to analyze the input under the statutory framing in [LEGAL.md](https://github.com/1-3-7/disrobe/blob/main/LEGAL.md).
