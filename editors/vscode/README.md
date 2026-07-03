# disrobe for Visual Studio Code

This extension integrates disrobe into VS Code. It provides:

- An LSP client that starts `disrobe serve --stdio` and connects automatically.
- Editor context menu commands that run disrobe subcommands on the active file.

## Requirements

Build disrobe from source and ensure the `disrobe` binary is on your PATH, or set `disrobe.executablePath` to its absolute path.

The LSP surface (`disrobe serve --stdio`) exposes two custom methods: `disrobe/analyze` and `disrobe/explain`. It does not implement the standard `textDocument/hover` or `textDocument/definition` surfaces; those are on the roadmap pending capability expansion in the daemon.

## Settings

| Setting | Default | Description |
|---|---|---|
| `disrobe.executablePath` | `"disrobe"` | Path to the disrobe binary. |
| `disrobe.lsp.enable` | `true` | Start the LSP daemon on activation. |
| `disrobe.lsp.trace` | `"off"` | LSP trace level (`off`, `messages`, `verbose`). |
| `disrobe.auto.outDir` | `""` | Output directory for `disrobe auto`. |

## Commands

All commands are under the `disrobe` category and appear in the editor right-click context menu.

| Command | Description |
|---|---|
| `disrobe.auto` | Auto: run full deobfuscation pipeline |
| `disrobe.detect` | Detect: identify obfuscator / packer |
| `disrobe.strings` | Strings: extract and deobfuscate strings |
| `disrobe.ioc` | IOC: extract indicators of compromise |
| `disrobe.behavior` | Behavior: summarize binary capabilities (MITRE) |
| `disrobe.identify` | Identify: compiler / packer / protector fingerprint |
| `disrobe.scan` | Scan: leak credentials scanner |
| `disrobe.startServer` | Manually start the LSP daemon. |
| `disrobe.stopServer` | Stop the LSP daemon. |
| `disrobe.showOutput` | Open the disrobe output channel. |

## What is not wired yet

Marketplace publishing (`vsce package` / `vsce publish`) requires a publisher account and is not part of the generated scaffold. The extension can be installed locally via `vsce package` + `Extensions: Install from VSIX` once the marketplace step is completed.
