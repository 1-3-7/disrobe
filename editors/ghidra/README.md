# disrobe for Ghidra

A GhidraScript (`DisrobeAnalyzer.java`) that drives the disrobe CLI from inside Ghidra. It reads `currentProgram.getExecutablePath()`, accepts one validated action in headless mode or prompts for one in the interface, then prints the recovered output to the Ghidra console.

## Requirements

- Ghidra 10.3 or later (Script Manager).
- `disrobe` binary on your PATH, or edit the `BINARY` constant at the top of `DisrobeAnalyzer.java`.

## Installation

Copy `DisrobeAnalyzer.java` into a directory listed in Ghidra's Script Manager search paths (`Window > Script Manager > Manage Script Directories`). Refresh the script list and run it from there, or assign a keybinding.

## Headless use

Pass exactly one action after the script name. This example imports a binary without running Ghidra analyzers, invokes `disrobe detect`, and deletes the temporary project:

```text
analyzeHeadless.bat <project-directory> disrobe-check -import <binary> -noanalysis -scriptPath <script-directory> -postScript DisrobeAnalyzer.java detect -deleteProject -overwrite
```

The script stops the disrobe process tree when Ghidra cancels the task or when the command reaches 120 seconds. It retains at most 1 MiB of combined standard output and standard error while continuing to drain the process stream.

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
