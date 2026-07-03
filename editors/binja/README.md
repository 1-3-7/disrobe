# disrobe for Binary Ninja

A Binary Ninja Python plugin that drives the disrobe CLI from inside Binary Ninja. It registers plugin commands under the `disrobe` menu, resolves the open file path from `BinaryView.file.original_filename`, then shells out to disrobe and prints the recovered output to the Binary Ninja log.

## Requirements

- Binary Ninja 3.0 or later (Python 3 API).
- `disrobe` binary on your PATH, or edit `DISROBE_BINARY` at the top of `__init__.py`.

## Installation

Copy this `binja` directory (renamed to `disrobe`) into your Binary Ninja user plugins directory and restart Binary Ninja:

- Linux: `~/.binaryninja/plugins/disrobe`
- macOS: `~/Library/Application Support/Binary Ninja/plugins/disrobe`
- Windows: `%APPDATA%\Binary Ninja\plugins\disrobe`

The plugin loads automatically and the commands appear under `Plugins > disrobe`.

## Actions

| CLI invocation | Description |
|---|---|
| `disrobe auto` | Auto: run full deobfuscation pipeline |
| `disrobe detect` | Detect: identify obfuscator / packer |
| `disrobe strings` | Strings: extract and deobfuscate strings |
| `disrobe ioc` | IOC: extract indicators of compromise |
| `disrobe behavior` | Behavior: summarize binary capabilities (MITRE) |
| `disrobe identify` | Identify: compiler / packer / protector fingerprint |
| `disrobe scan` | Scan: leak credentials scanner |

## Notes

This scaffold is generated from the disrobe CLI command catalog. `__init__.py` is syntax-valid Python for the Binary Ninja API and `plugin.json` is a valid plugin metadata manifest (version 2). It has not been runtime-tested against a licensed Binary Ninja installation. The command handlers invoke the real disrobe CLI with no placeholder bodies; output appears in the Binary Ninja log via `log_info` / `log_warn` / `log_error`.
