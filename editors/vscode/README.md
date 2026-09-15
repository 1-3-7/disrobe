# disrobe for Visual Studio Code

This extension integrates disrobe into VS Code. It provides:

- An LSP client that starts `disrobe serve --stdio` and connects automatically.
- Editor context menu commands that run disrobe subcommands on the active file.

## Requirements

Install disrobe and ensure the binary is on your PATH, or set `disrobe.executablePath` to its absolute path. LSP connections require a build with the `server` feature. To use only the CLI commands, set `disrobe.lsp.enable` to `false`.

The LSP surface (`disrobe serve --stdio`) provides byte classification through `disrobe/analyze` and error-code lookup through `disrobe/explain`. It does not provide hover information or go-to-definition. See the [service reference](https://1-3-7.github.io/disrobe/latest/cli/serve.html) for request and response fields.

## Settings

| Setting | Default | Description |
|---|---|---|
| `disrobe.executablePath` | `"disrobe"` | Path to the disrobe binary. |
| `disrobe.lsp.enable` | `true` | Start the LSP daemon on activation. |
| `disrobe.lsp.trace` | `"off"` | LSP trace level (`off`, `messages`, `verbose`). |
| `disrobe.auto.outDir` | `""` | Output directory for `disrobe auto`. |

## Commands

All commands appear under the `disrobe` category in the Command Palette. The seven file-analysis commands also appear in the editor right-click menu for files on disk. They read the saved file, so save pending edits before running them.

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

## Local installation

Run `npm ci --ignore-scripts` and `npm run package` in `editors/vscode`, then
`code --install-extension disrobe.vsix --force`. Packaging compiles the extension
and includes its runtime dependencies. Node.js 20 or later is required to build it.
Local VSIX installation needs no Marketplace account.
