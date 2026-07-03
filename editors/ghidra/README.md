# disrobe for Ghidra

A GhidraScript (`DisrobeAnalyzer.java`) that drives the disrobe CLI from inside Ghidra. It reads `currentProgram.getExecutablePath()`, prompts the user to choose an action, then shells out to disrobe and prints the recovered output to the Ghidra console.

## Requirements

- Ghidra 10.3 or later (Script Manager).
- `disrobe` binary on your PATH, or edit the `BINARY` constant at the top of `DisrobeAnalyzer.java`.

## Installation

Copy `DisrobeAnalyzer.java` into a directory listed in Ghidra's Script Manager search paths (`Window > Script Manager > Manage Script Directories`). Refresh the script list and run it from there, or assign a keybinding.

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

This scaffold is generated from the disrobe CLI command catalog and is syntax-valid Java for the Ghidra GhidraScript API. It has not been runtime-tested against a Ghidra installation. The action handlers invoke the real disrobe CLI with no placeholder bodies; output appears in the Ghidra console via `println`.
