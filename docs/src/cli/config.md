# Project configuration (`.disrobe.toml`)

`disrobe` reads an optional `.disrobe.toml` so a project can set its own defaults instead of repeating the same global flags on every invocation.

## Resolution order

Values are merged from three layers, lowest precedence first:

1. **Built-in defaults**: what `disrobe` does with no config and no flags.
2. **`.disrobe.toml`**: the discovered or explicitly named config file.
3. **CLI flags**: anything you type on the command line.

A flag you actually pass always wins over the config file; a flag you leave off falls back to the config value, and only then to the built-in default. "Did the user pass this flag" is decided by clap's value source, so there is no ambiguity between `--json` being absent and being `false`.

## Discovery

- With `--config <PATH>`, that file is loaded. A missing path is a hard error (`DR-CLI-0332`).
- Without `--config`, `disrobe` walks **up** from the current working directory looking for `.disrobe.toml`, exactly the way cargo finds `Cargo.toml`. The first one found wins. If none exists, the built-in defaults are used.

Malformed TOML (`DR-CLI-0330`) and unknown keys are hard errors: a typo fails fast instead of being silently ignored.

## The `config` command

| Command | Purpose |
|---|---|
| `disrobe config` / `disrobe config show` | Print the resolved effective config and the file it came from. Honors `--json`. |
| `disrobe config init [--out <PATH>] [--force]` | Write a fully documented `.disrobe.toml` template (default `./.disrobe.toml`). |

## Schema

```toml
[output]
dir = "out"                  # default output directory for chain/auto runs
emit = ["source", "manifest"] # default --emit kinds where a pass accepts them
json = false                 # default machine-output toggles (CLI flags still override)
ndjson = false
sarif = false
color = "auto"               # auto | always | never
progress = "auto"            # auto | always | never
verbosity = "warn"           # warn | info | debug | trace
quiet = false

[execution]
threads = 8                  # worker pool size (default: detected CPU count)
force = false
in_place = false
no_cache = false
cache_dir = "/var/cache/disrobe"  # content-addressed .dr envelope cache (default: OS cache dir)
dry_run = false
seed = 42                    # RNG seed for non-deterministic backends
max_depth = 8                # default chain depth for `auto`

[backends]
py = "native"                # native (in-tree CPython 1.0..3.15 engine; the only supported value)
jvm = "cfr"                  # cfr | vineflower | procyon | jadx
dotnet = "ilspy"             # ilspy | dnspy | dnspyex | de4dot
wasm = "wat"                 # json | rust | ts | wat | c
lua = "native"

[passes]
enable = ["pyarmor.unpack", "py.decompile"]  # restrict chain runs to these passes
disable = ["native.packer-unpack"]           # never run these passes
```

All tables and all keys are optional. An empty file is valid and resolves to the built-in defaults.
