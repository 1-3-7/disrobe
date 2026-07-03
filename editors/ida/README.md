# disrobe for IDA Pro

An IDAPython plugin that drives the disrobe CLI from inside IDA Pro. It registers menu actions and hotkeys under `Edit > Plugins > disrobe`, running each subcommand on `idaapi.get_input_file_path()` and printing the recovered output to the IDA output window.

## Requirements

- IDA Pro 7.6 or later (IDAPython 3 backend).
- `disrobe` binary on your PATH, or edit `DISROBE_BINARY` at the top of `disrobe_ida.py`.

## Installation

Copy `disrobe_ida.py` into your IDA plugins directory (typically `<IDA>/plugins/`) and restart IDA. The plugin loads automatically.

## Actions

| CLI invocation | Description | Default hotkey |
|---|---|---|
| `disrobe auto` | Auto: run full deobfuscation pipeline | Alt-Shift-A |
| `disrobe detect` | Detect: identify obfuscator / packer | Alt-Shift-D |
| `disrobe strings` | Strings: extract and deobfuscate strings | Alt-Shift-S |
| `disrobe ioc` | IOC: extract indicators of compromise | Alt-Shift-I |
| `disrobe behavior` | Behavior: summarize binary capabilities (MITRE) | Alt-Shift-B |
| `disrobe identify` | Identify: compiler / packer / protector fingerprint | Alt-Shift-F |
| `disrobe scan` | Scan: leak credentials scanner | Alt-Shift-C |

## Notes

This scaffold is generated from the disrobe CLI command catalog and is syntax-valid IDAPython. It has not been runtime-tested against a licensed IDA Pro installation. The action handlers invoke the real disrobe CLI with no placeholder bodies; the output appears in the IDA output window via `ida_kernwin.msg`.
