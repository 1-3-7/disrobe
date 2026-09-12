use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};
use serde::Deserialize;

use crate::fileio::{read_bytes_bounded, read_text_bounded, tracked_or_nonignored_files};

const MAX_ECOSYSTEMS_JSON_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PLUGIN_FILE_BYTES: u64 = 8 * 1024 * 1024;
const PLUGIN_SOURCE_FILES: [&str; 1] = ["editors/vscode/tests/smoke.cjs"];

#[derive(Debug, Deserialize)]
struct EcosystemsDoc {
    cells: Vec<EcosystemCell>,
}

#[derive(Debug, Deserialize)]
struct EcosystemCell {
    label: String,
    kind: String,
    note: String,
}

#[derive(Debug)]
struct PluginArtifact {
    dir: &'static str,
    rel_path: &'static str,
    content: String,
}

pub(crate) fn run(root: &Path, check: bool) -> Result<()> {
    let ecosystems_path: PathBuf = root.join("xtask").join("data").join("ecosystems.json");
    let editors_dir: PathBuf = root.join("editors");

    let raw: String = read_text_bounded(&ecosystems_path, MAX_ECOSYSTEMS_JSON_BYTES)
        .wrap_err_with(|| format!("reading {}", ecosystems_path.display()))?;
    let ecosystems: EcosystemsDoc = serde_json::from_str(&raw)
        .wrap_err_with(|| format!("parsing {}", ecosystems_path.display()))?;

    let artifacts: Vec<PluginArtifact> = generate(&ecosystems);

    if check {
        verify(root, &editors_dir, &artifacts)
    } else {
        emit(&editors_dir, &artifacts)
    }
}

fn generate(ecosystems: &EcosystemsDoc) -> Vec<PluginArtifact> {
    let cmds: Vec<CliCommand> = build_cli_commands();
    let lang_labels: Vec<String> = build_lang_labels(ecosystems);
    vec![
        PluginArtifact {
            dir: "vscode",
            rel_path: "package.json",
            content: render_package_json(ecosystems, &cmds),
        },
        PluginArtifact {
            dir: "vscode",
            rel_path: "LICENSE",
            content: include_str!("../../LICENSE").to_owned(),
        },
        PluginArtifact {
            dir: "vscode",
            rel_path: ".vscodeignore",
            content: "src/**\nbuild.mjs\ntests/**\ntsconfig.json\npackage-lock.json\n*.vsix\nout/**/*.map\nout/**/*.d.ts\nnode_modules/**/*.js\nnode_modules/**/*.ts\nnode_modules/**/*.map\nnode_modules/**/*.json\nnode_modules/**/README*\nnode_modules/**/readme*\nnode_modules/**/CHANGELOG*\nnode_modules/**/changelog*\nnode_modules/**/*.cmd\nnode_modules/**/*.bnf\nnode_modules/**/*.sh\nnode_modules/**/.github/**\n".to_owned(),
        },
        PluginArtifact {
            dir: "vscode",
            rel_path: "build.mjs",
            content: include_str!("../templates/vscode-build.mjs").to_owned(),
        },
        PluginArtifact {
            dir: "vscode",
            rel_path: "src/extension.ts",
            content: render_extension_ts(&cmds),
        },
        PluginArtifact {
            dir: "vscode",
            rel_path: "tsconfig.json",
            content: render_tsconfig(),
        },
        PluginArtifact {
            dir: "vscode",
            rel_path: "README.md",
            content: render_vscode_readme(&cmds),
        },
        PluginArtifact {
            dir: "ida",
            rel_path: "disrobe_ida.py",
            content: render_ida_plugin(&cmds, &lang_labels),
        },
        PluginArtifact {
            dir: "ida",
            rel_path: "README.md",
            content: render_ida_readme(&cmds),
        },
        PluginArtifact {
            dir: "ghidra",
            rel_path: "DisrobeAnalyzer.java",
            content: render_ghidra_script(&cmds),
        },
        PluginArtifact {
            dir: "ghidra",
            rel_path: "README.md",
            content: render_ghidra_readme(&cmds),
        },
        PluginArtifact {
            dir: "binja",
            rel_path: "plugin.json",
            content: render_binja_plugin_json(&cmds),
        },
        PluginArtifact {
            dir: "binja",
            rel_path: "__init__.py",
            content: render_binja_plugin(&cmds, &lang_labels),
        },
        PluginArtifact {
            dir: "binja",
            rel_path: "README.md",
            content: render_binja_readme(&cmds),
        },
        PluginArtifact {
            dir: "",
            rel_path: "install.sh",
            content: render_install_sh(),
        },
        PluginArtifact {
            dir: "",
            rel_path: "install.ps1",
            content: render_install_ps1(),
        },
    ]
}

fn emit(editors_dir: &Path, artifacts: &[PluginArtifact]) -> Result<()> {
    for artifact in artifacts {
        let base: PathBuf = editors_dir.join(artifact.dir);
        let path: PathBuf = base.join(artifact.rel_path);
        let parent: &Path = path.parent().unwrap_or(&base);
        fs::create_dir_all(parent).wrap_err_with(|| format!("creating {}", parent.display()))?;
        fs::write(&path, artifact.content.as_bytes())
            .wrap_err_with(|| format!("writing {}", path.display()))?;
        println!("xtask plugins: wrote {}", path.display());
    }
    Ok(())
}

fn verify(root: &Path, editors_dir: &Path, artifacts: &[PluginArtifact]) -> Result<()> {
    let mut stale: Vec<String> = Vec::new();
    for artifact in artifacts {
        let path: PathBuf = editors_dir.join(artifact.dir).join(artifact.rel_path);
        match read_bytes_bounded(&path, MAX_PLUGIN_FILE_BYTES) {
            Ok(on_disk) if on_disk == artifact.content.as_bytes() => {}
            Ok(_) => stale.push(format!(
                "{} differs from regenerated output",
                path.display()
            )),
            Err(err) => stale.push(format!("{} unreadable: {err}", path.display())),
        }
    }
    let generated: BTreeSet<String> = artifacts
        .iter()
        .map(|artifact: &PluginArtifact| {
            if artifact.dir.is_empty() {
                format!("editors/{}", artifact.rel_path)
            } else {
                format!("editors/{}/{}", artifact.dir, artifact.rel_path)
            }
        })
        .collect();
    for path in tracked_or_nonignored_files(root)?
        .into_iter()
        .filter(|path: &String| path.starts_with("editors/"))
    {
        if !generated.contains(&path) && !PLUGIN_SOURCE_FILES.contains(&path.as_str()) {
            stale.push(format!(
                "{path} is a public editor file but is neither regenerated nor a checked plugin source"
            ));
        }
    }
    if stale.is_empty() {
        println!(
            "xtask plugins --check: {} committed file(s) match regeneration (vscode + ida + ghidra + binja)",
            artifacts.len()
        );
        Ok(())
    } else {
        bail!(
            "committed plugin files are stale; run `cargo run -p xtask -- plugins`:\n  {}",
            stale.join("\n  ")
        )
    }
}

struct CliCommand {
    subcommand: &'static str,
    title: &'static str,
    in_menu: bool,
    hotkey: &'static str,
}

fn build_cli_commands() -> Vec<CliCommand> {
    vec![
        CliCommand {
            subcommand: "auto",
            title: "Auto: run full deobfuscation pipeline",
            in_menu: true,
            hotkey: "Alt-Shift-A",
        },
        CliCommand {
            subcommand: "detect",
            title: "Detect: identify obfuscator / packer",
            in_menu: true,
            hotkey: "Alt-Shift-D",
        },
        CliCommand {
            subcommand: "strings",
            title: "Strings: extract and deobfuscate strings",
            in_menu: true,
            hotkey: "Alt-Shift-S",
        },
        CliCommand {
            subcommand: "ioc",
            title: "IOC: extract indicators of compromise",
            in_menu: true,
            hotkey: "Alt-Shift-I",
        },
        CliCommand {
            subcommand: "behavior",
            title: "Behavior: summarize binary capabilities (MITRE)",
            in_menu: true,
            hotkey: "Alt-Shift-B",
        },
        CliCommand {
            subcommand: "identify",
            title: "Identify: compiler / packer / protector fingerprint",
            in_menu: true,
            hotkey: "Alt-Shift-F",
        },
        CliCommand {
            subcommand: "scan",
            title: "Scan: leak credentials scanner",
            in_menu: true,
            hotkey: "Alt-Shift-C",
        },
    ]
}

fn build_lang_labels(ecosystems: &EcosystemsDoc) -> Vec<String> {
    let mut labels: Vec<String> = Vec::new();
    for cell in &ecosystems.cells {
        if !labels.contains(&cell.label) {
            labels.push(cell.label.clone());
        }
    }
    labels
}

fn build_language_filters(ecosystems: &EcosystemsDoc) -> Vec<String> {
    let mut filters: Vec<String> = Vec::new();
    for cell in &ecosystems.cells {
        for lang in ecosystem_vscode_languages(&cell.label, &cell.kind, &cell.note) {
            if !filters.contains(&lang) {
                filters.push(lang);
            }
        }
    }
    filters
}

fn ecosystem_vscode_languages(label: &str, kind: &str, _note: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    match label {
        "Python pyc" | "PyArmor" | "PyInstaller" | "Nuitka" | "Python pickle" => {
            push_lang(&mut out, "python", "py");
        }
        "JavaScript" => {
            push_lang(&mut out, "javascript", "js");
            push_lang(&mut out, "typescript", "ts");
        }
        "WebAssembly" => {
            push_lang(&mut out, "wat", "wat");
        }
        ".NET / CIL" => {
            push_lang(&mut out, "csharp", "cs");
        }
        "JVM classfile" | "Android DEX" => {
            push_lang(&mut out, "java", "java");
        }
        "Go" => {
            push_lang(&mut out, "go", "go");
        }
        "Lua" => {
            push_lang(&mut out, "lua", "lua");
        }
        "PHP" => {
            push_lang(&mut out, "php", "php");
        }
        "Ruby YARV" => {
            push_lang(&mut out, "ruby", "rb");
        }
        "Shell / PowerShell" => {
            push_lang(&mut out, "shellscript", "sh");
            push_lang(&mut out, "powershell", "ps1");
        }
        _ => if kind == "unpack" || kind == "carve" {},
    }
    out
}

fn push_lang(out: &mut Vec<String>, id: &str, ext: &str) {
    out.push(format!(
        "      {{\n        \"id\": \"{id}\",\n        \"extensions\": [\".{ext}\"]\n      }}"
    ));
}

fn render_package_json(ecosystems: &EcosystemsDoc, cmds: &[CliCommand]) -> String {
    let lang_filters: Vec<String> = build_language_filters(ecosystems);

    let commands_json: String = cmds
        .iter()
        .map(|c: &CliCommand| {
            let id: String = format!("disrobe.{}", c.subcommand);
            let title: &str = c.title;
            format!(
                "      {{\n        \"command\": \"{id}\",\n        \"title\": \"{title}\",\n        \"category\": \"disrobe\"\n      }}"
            )
        })
        .chain([
            "      {\n        \"command\": \"disrobe.startServer\",\n        \"title\": \"Start LSP daemon (disrobe serve --stdio)\",\n        \"category\": \"disrobe\"\n      }".to_owned(),
            "      {\n        \"command\": \"disrobe.stopServer\",\n        \"title\": \"Stop LSP daemon\",\n        \"category\": \"disrobe\"\n      }".to_owned(),
            "      {\n        \"command\": \"disrobe.showOutput\",\n        \"title\": \"Show output channel\",\n        \"category\": \"disrobe\"\n      }".to_owned(),
        ])
        .collect::<Vec<String>>()
        .join(",\n");

    let menus_json: String = cmds
        .iter()
        .filter(|c: &&CliCommand| c.in_menu)
        .map(|c: &CliCommand| {
            let id: String = format!("disrobe.{}", c.subcommand);
            format!(
                "      {{\n        \"command\": \"{id}\",\n        \"when\": \"resourceScheme == 'file'\"\n      }}"
            )
        })
        .collect::<Vec<String>>()
        .join(",\n");

    let lang_filter_json: String = lang_filters.join(",\n");

    format!(
        r#"{{
  "name": "disrobe",
  "displayName": "disrobe",
  "description": "Deobfuscate, decompile, and unpack compiled software via the disrobe CLI and LSP daemon.",
  "version": "0.1.0",
  "publisher": "disrobe",
  "repository": "https://github.com/1-3-7/disrobe",
  "license": "Elastic-2.0",
  "engines": {{
    "vscode": "^1.85.0"
  }},
  "categories": [
    "Other",
    "Linters",
    "Debuggers"
  ],
  "activationEvents": [
    "onStartupFinished"
  ],
  "main": "./out/extension.js",
  "contributes": {{
    "commands": [
{commands_json}
    ],
    "menus": {{
      "editor/context": [
{menus_json}
      ]
    }},
    "configuration": {{
      "title": "disrobe",
      "properties": {{
        "disrobe.executablePath": {{
          "type": "string",
          "default": "disrobe",
          "description": "Path to the disrobe binary. Defaults to 'disrobe' (resolved from PATH)."
        }},
        "disrobe.lsp.enable": {{
          "type": "boolean",
          "default": true,
          "description": "Start 'disrobe serve --stdio' and connect the LSP client on extension activation."
        }},
        "disrobe.lsp.trace": {{
          "type": "string",
          "enum": ["off", "messages", "verbose"],
          "default": "off",
          "description": "LSP trace level forwarded to the output channel."
        }},
        "disrobe.auto.outDir": {{
          "type": "string",
          "default": "",
          "description": "Output directory for 'disrobe auto'. Leave blank to use the default (./out/<stem>-auto)."
        }}
      }}
    }},
    "languages": [
{lang_filter_json}
    ]
  }},
  "scripts": {{
    "compile": "tsc --noEmit -p . && npm run bundle",
    "bundle": "node build.mjs",
    "watch": "npm run bundle -- --watch",
    "watch:types": "tsc --noEmit -watch -p .",
    "package": "vsce package --out disrobe.vsix",
    "vscode:prepublish": "npm run compile"
  }},
  "dependencies": {{
    "vscode-languageclient": "^9.0.1"
  }},
  "devDependencies": {{
    "@vscode/vsce": "3.9.2",
    "esbuild": "0.28.2",
    "@types/node": "^20.0.0",
    "@types/vscode": "^1.85.0",
    "typescript": "^5.4.0"
  }}
}}
"#,
    )
}

fn render_extension_ts(cmds: &[CliCommand]) -> String {
    let register_lines: String = cmds
        .iter()
        .map(|c: &CliCommand| {
            let sub: &str = c.subcommand;
            format!(
                "    vscode.commands.registerCommand(\"disrobe.{sub}\", () => runCliOnActiveFile(\"{sub}\")),",
            )
        })
        .collect::<Vec<String>>()
        .join("\n");

    let switch_cases: String = cmds
        .iter()
        .filter(|c: &&CliCommand| c.subcommand != "auto")
        .map(|c: &CliCommand| {
            let sub: &str = c.subcommand;
            format!("    case \"{sub}\":\n      return [\"{sub}\", filePath];")
        })
        .collect::<Vec<String>>()
        .join("\n");

    format!(
        r#"import * as vscode from "vscode";
import {{
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  Trace,
  TransportKind,
}} from "vscode-languageclient/node";

let client: LanguageClient | undefined;
let lifecycle: Promise<void> = Promise.resolve();
let outputChannel: vscode.OutputChannel;

export function activate(context: vscode.ExtensionContext): void {{
  outputChannel = vscode.window.createOutputChannel("disrobe");
  context.subscriptions.push(outputChannel);

  context.subscriptions.push(
    vscode.commands.registerCommand("disrobe.startServer", () => startLspClient(context)),
    vscode.commands.registerCommand("disrobe.stopServer", stopLspClient),
    vscode.commands.registerCommand("disrobe.showOutput", () => outputChannel.show()),
{register_lines}
  );

  const cfg: vscode.WorkspaceConfiguration = vscode.workspace.getConfiguration("disrobe");
  const lspEnabled: boolean = cfg.get<boolean>("lsp.enable", true);
  if (lspEnabled) {{
    startLspClient(context);
  }}
}}

export function deactivate(): Promise<void> {{
  return stopLspClient();
}}

function resolveExecutable(): string {{
  const cfg: vscode.WorkspaceConfiguration = vscode.workspace.getConfiguration("disrobe");
  return cfg.get<string>("executablePath", "disrobe") || "disrobe";
}}

function scheduleLsp(operation: () => Promise<void>): Promise<void> {{
  const next: Promise<void> = lifecycle.then(operation);
  lifecycle = next.catch((error: unknown): void => {{
    outputChannel.appendLine(`disrobe LSP operation failed: ${{error instanceof Error ? error.message : String(error)}}`);
  }});
  return next;
}}

function startLspClient(context: vscode.ExtensionContext): Promise<void> {{
  return scheduleLsp(async (): Promise<void> => {{
    if (client) {{
      outputChannel.appendLine("disrobe LSP client already running.");
      return;
    }}

    const exe: string = resolveExecutable();
    const cfg: vscode.WorkspaceConfiguration = vscode.workspace.getConfiguration("disrobe");
    const traceLevel: string = cfg.get<string>("lsp.trace", "off");

    const serverOptions: ServerOptions = {{
      command: exe,
      args: ["serve"],
      transport: TransportKind.stdio,
    }};

    const clientOptions: LanguageClientOptions = {{
      documentSelector: [
        {{ scheme: "file", language: "python" }},
        {{ scheme: "file", language: "javascript" }},
        {{ scheme: "file", language: "typescript" }},
        {{ scheme: "file", language: "java" }},
        {{ scheme: "file", language: "csharp" }},
        {{ scheme: "file", language: "go" }},
        {{ scheme: "file", language: "lua" }},
        {{ scheme: "file", language: "php" }},
        {{ scheme: "file", language: "ruby" }},
        {{ scheme: "file", language: "shellscript" }},
        {{ scheme: "file", language: "powershell" }},
      ],
      synchronize: {{}},
      outputChannel,
      traceOutputChannel: outputChannel,
    }};

    const startedClient: LanguageClient = new LanguageClient("disrobe", "disrobe LSP", serverOptions, clientOptions);
    await startedClient.setTrace(Trace.fromString(traceLevel));

    context.subscriptions.push(startedClient);
    await startedClient.start();
    client = startedClient;
    outputChannel.appendLine(`disrobe LSP client started (${{exe}} serve --stdio)`);
  }});
}}

function stopLspClient(): Promise<void> {{
  return scheduleLsp(async (): Promise<void> => {{
    if (!client) return;
    await client.stop();
    client = undefined;
  }});
}}

function runCliOnActiveFile(subcommand: string): void {{
  const editor: vscode.TextEditor | undefined = vscode.window.activeTextEditor;
  if (!editor) {{
    vscode.window.showWarningMessage("disrobe: no active file.");
    return;
  }}

  const filePath: string = editor.document.uri.fsPath;
  if (!filePath) {{
    vscode.window.showWarningMessage("disrobe: active document has no file path.");
    return;
  }}

  const exe: string = resolveExecutable();
  const args: string[] = buildArgs(subcommand, filePath);
  const label: string = `disrobe ${{subcommand}}`;

  outputChannel.show(true);
  outputChannel.appendLine(`\n$ ${{exe}} ${{args.join(" ")}}`);

  const terminal: vscode.Terminal = vscode.window.createTerminal({{
    name: label,
    shellPath: exe,
    shellArgs: args,
  }});
  terminal.show(true);
}}

function buildArgs(subcommand: string, filePath: string): string[] {{
  const cfg: vscode.WorkspaceConfiguration = vscode.workspace.getConfiguration("disrobe");

  switch (subcommand) {{
    case "auto": {{
      const outDir: string = cfg.get<string>("auto.outDir", "");
      const base: string[] = ["auto", filePath];
      return outDir ? [...base, "--out", outDir] : base;
    }}
{switch_cases}
    default:
      return [subcommand, filePath];
  }}
}}
"#
    )
}

fn render_tsconfig() -> String {
    r#"{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "lib": ["ES2020"],
    "outDir": "./out",
    "rootDir": "./src",
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true
  },
  "include": ["src/**/*.ts"],
  "exclude": ["node_modules", "out"]
}
"#
    .to_owned()
}

fn render_vscode_readme(cmds: &[CliCommand]) -> String {
    let cmd_list: String = cmds
        .iter()
        .map(|c: &CliCommand| {
            let id: String = format!("disrobe.{}", c.subcommand);
            let title: &str = c.title;
            format!("| `{id}` | {title} |")
        })
        .collect::<Vec<String>>()
        .join("\n");

    format!(
        r#"# disrobe for Visual Studio Code

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
{cmd_list}
| `disrobe.startServer` | Manually start the LSP daemon. |
| `disrobe.stopServer` | Stop the LSP daemon. |
| `disrobe.showOutput` | Open the disrobe output channel. |

## Local installation

Run `npm ci --ignore-scripts` and `npm run package` in `editors/vscode`, then
`code --install-extension disrobe.vsix --force`. Packaging compiles the extension
and includes its runtime dependencies. Node.js 20 or later is required to build it.
Local VSIX installation needs no Marketplace account.
"#
    )
}

fn render_ida_plugin(cmds: &[CliCommand], lang_labels: &[String]) -> String {
    let menu_items: String = cmds
        .iter()
        .map(|c: &CliCommand| {
            let sub: &str = c.subcommand;
            let title: &str = c.title;
            let hotkey: &str = c.hotkey;
            format!(
                "        ida_kernwin.register_action(ida_kernwin.action_desc_t(\n            \"disrobe:{sub}\",\n            \"{title}\",\n            DisrobeAction(\"{sub}\"),\n            \"{hotkey}\",\n        ))\n        ida_kernwin.attach_action_to_menu(\"Edit/Plugins/disrobe/{title}\", \"disrobe:{sub}\", 0)"
            )
        })
        .collect::<Vec<String>>()
        .join("\n\n");

    let unregister_items: String = cmds
        .iter()
        .map(|c: &CliCommand| {
            let sub: &str = c.subcommand;
            format!("        ida_kernwin.unregister_action(\"disrobe:{sub}\")")
        })
        .collect::<Vec<String>>()
        .join("\n");

    let ecosystems_comment: String = lang_labels
        .iter()
        .map(|l: &String| format!("# {l}"))
        .collect::<Vec<String>>()
        .join("\n");

    format!(
        r#"from __future__ import annotations

import subprocess
import shutil
import idaapi
import ida_kernwin


DISROBE_BINARY: str = "disrobe"


def _resolve_binary() -> str:
    found: str | None = shutil.which(DISROBE_BINARY)
    return found if found is not None else DISROBE_BINARY


def _run_disrobe(subcommand: str, path: str) -> None:
    exe: str = _resolve_binary()
    args: list[str]
    if subcommand == "auto":
        args = [exe, "auto", path]
    else:
        args = [exe, subcommand, path]
    result: subprocess.CompletedProcess[str] = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=300,
    )
    output: str = result.stdout + result.stderr
    ida_kernwin.msg(f"[disrobe] $ {{' '.join(args)}}\n{{output}}\n")
    if result.returncode != 0:
        ida_kernwin.warning(f"disrobe {{subcommand}} exited {{result.returncode}}")


class DisrobeAction(ida_kernwin.action_handler_t):
    def __init__(self, subcommand: str) -> None:
        super().__init__()
        self._subcommand: str = subcommand

    def activate(self, ctx: ida_kernwin.action_ctx_base_t) -> int:
        path: str = idaapi.get_input_file_path()
        if not path:
            ida_kernwin.warning("disrobe: no input file open")
            return 0
        _run_disrobe(self._subcommand, path)
        return 1

    def update(self, ctx: ida_kernwin.action_ctx_base_t) -> int:
        return ida_kernwin.AST_ENABLE_ALWAYS


class DisrobePlugin(idaapi.plugin_t):
    flags: int = idaapi.PLUGIN_KEEP
    comment: str = "disrobe: deobfuscate, decompile, and unpack via the disrobe CLI"
    help: str = ""
    wanted_name: str = "disrobe"
    wanted_hotkey: str = ""

    def init(self) -> int:
{menu_items}
        ida_kernwin.msg("[disrobe] plugin loaded\n")
        return idaapi.PLUGIN_KEEP

    def run(self, arg: int) -> None:
        pass

    def term(self) -> None:
{unregister_items}


def PLUGIN_ENTRY() -> idaapi.plugin_t:
    return DisrobePlugin()


# Supported ecosystems (derived from disrobe catalog):
{ecosystems_comment}
"#
    )
}

fn render_ida_readme(cmds: &[CliCommand]) -> String {
    let cmd_table: String = cmds
        .iter()
        .map(|c: &CliCommand| {
            let sub: &str = c.subcommand;
            let title: &str = c.title;
            let hotkey: &str = c.hotkey;
            format!("| `disrobe {sub}` | {title} | {hotkey} |")
        })
        .collect::<Vec<String>>()
        .join("\n");

    format!(
        r"# disrobe for IDA Pro

An IDAPython plugin that drives the disrobe CLI from inside IDA Pro. It registers menu actions and hotkeys under `Edit > Plugins > disrobe`, running each subcommand on `idaapi.get_input_file_path()` and printing the recovered output to the IDA output window.

## Requirements

- IDA Pro 7.6 or later with IDAPython 3. [IDA Free](https://hex-rays.com/ida-free) does not include IDAPython.
- `disrobe` binary on your PATH, or edit `DISROBE_BINARY` at the top of `disrobe_ida.py`.

## Installation

Copy `disrobe_ida.py` into your IDA plugins directory (typically `<IDA>/plugins/`) and restart IDA. The plugin loads automatically.

## Actions

| CLI invocation | Description | Default hotkey |
|---|---|---|
{cmd_table}
"
    )
}

fn render_ghidra_script(cmds: &[CliCommand]) -> String {
    let choices: String = cmds
        .iter()
        .map(|c: &CliCommand| format!("            \"{}\"", c.title))
        .collect::<Vec<String>>()
        .join(",\n");
    let subcommands: String = cmds
        .iter()
        .map(|c: &CliCommand| format!("            \"{}\"", c.subcommand))
        .collect::<Vec<String>>()
        .join(",\n");

    format!(
        r#"import ghidra.app.script.GhidraScript;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class DisrobeAnalyzer extends GhidraScript {{

    private static final String BINARY = "disrobe";
    private static final int OUTPUT_LIMIT_BYTES = 1024 * 1024;
    private static final long TIMEOUT_NANOS = TimeUnit.SECONDS.toNanos(120);
    private static final long POLL_MILLIS = 100;
    private static final long TERMINATION_GRACE_NANOS = TimeUnit.SECONDS.toNanos(2);
    private static final List<String> CHOICES = List.of(
{choices}
    );
    private static final List<String> SUBCOMMANDS = List.of(
{subcommands}
    );

    @Override
    public void run() throws Exception {{
        String path = currentProgram.getExecutablePath();
        if (path == null || path.isEmpty()) {{
            printerr("disrobe: no executable path available from currentProgram");
            return;
        }}
        if (File.separatorChar == '\\' && path.length() >= 3 && path.charAt(0) == '/'
            && Character.isLetter(path.charAt(1)) && path.charAt(2) == ':') {{
            path = path.substring(1);
        }}

        String subcommand;
        if (isRunningHeadless()) {{
            String[] args = getScriptArgs();
            if (args.length != 1 || !SUBCOMMANDS.contains(args[0])) {{
                throw new IllegalArgumentException(
                    "headless usage: DisrobeAnalyzer.java <" + String.join("|", SUBCOMMANDS) + ">"
                );
            }}
            subcommand = args[0];
        }}
        else {{
            String chosen = askChoice("disrobe", "Select action:", CHOICES, CHOICES.get(0));
            if (chosen == null) {{
                return;
            }}
            int selected = CHOICES.indexOf(chosen);
            if (selected < 0) {{
                throw new IllegalStateException("Ghidra returned an unknown disrobe action");
            }}
            subcommand = SUBCOMMANDS.get(selected);
        }}
        runDisrobe(subcommand, path);
    }}

    private void runDisrobe(String subcommand, String path) throws Exception {{
        List<String> cmd = List.of(BINARY, subcommand, path);
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process proc = pb.start();
        OutputCapture output = new OutputCapture();
        Thread reader = new Thread(
            () -> drainOutput(proc.getInputStream(), output),
            "disrobe-output"
        );
        reader.setDaemon(true);
        reader.start();
        Set<ProcessHandle> descendants = new LinkedHashSet<>();
        long deadline = System.nanoTime() + TIMEOUT_NANOS;
        boolean timedOut = false;
        boolean completed = false;
        try {{
            while (true) {{
                proc.descendants().forEach(descendants::add);
                completed = proc.waitFor(POLL_MILLIS, TimeUnit.MILLISECONDS);
                proc.descendants().forEach(descendants::add);
                if (completed) {{
                    break;
                }}
                monitor.checkCancelled();
                if (System.nanoTime() - deadline >= 0) {{
                    timedOut = true;
                    break;
                }}
            }}
        }}
        finally {{
            proc.descendants().forEach(descendants::add);
            Exception cleanupFailure = null;
            boolean restoreInterrupt = false;
            try {{
                terminateProcessTree(proc, descendants);
            }}
            catch (IOException | InterruptedException error) {{
                cleanupFailure = error;
                restoreInterrupt = Thread.interrupted() || error instanceof InterruptedException;
            }}
            try {{
                reader.join(TimeUnit.NANOSECONDS.toMillis(TERMINATION_GRACE_NANOS));
            }}
            catch (InterruptedException error) {{
                restoreInterrupt = true;
                if (cleanupFailure == null) {{
                    cleanupFailure = error;
                }}
                else {{
                    cleanupFailure.addSuppressed(error);
                }}
            }}
            if (reader.isAlive()) {{
                try {{
                    proc.getInputStream().close();
                }}
                catch (IOException error) {{
                    if (cleanupFailure == null) {{
                        cleanupFailure = error;
                    }}
                    else {{
                        cleanupFailure.addSuppressed(error);
                    }}
                }}
                try {{
                    reader.join(TimeUnit.NANOSECONDS.toMillis(TERMINATION_GRACE_NANOS));
                }}
                catch (InterruptedException error) {{
                    restoreInterrupt = true;
                    if (cleanupFailure == null) {{
                        cleanupFailure = error;
                    }}
                    else {{
                        cleanupFailure.addSuppressed(error);
                    }}
                }}
            }}
            if (reader.isAlive()) {{
                IOException error = new IOException("disrobe output reader did not stop");
                if (cleanupFailure == null) {{
                    cleanupFailure = error;
                }}
                else {{
                    cleanupFailure.addSuppressed(error);
                }}
            }}
            if (restoreInterrupt) {{
                Thread.currentThread().interrupt();
            }}
            if (cleanupFailure != null) {{
                throw cleanupFailure;
            }}
        }}
        String captured = output.text();
        println("[disrobe] $ " + String.join(" ", cmd));
        if (!captured.isEmpty()) {{
            println(captured);
        }}
        if (output.truncated) {{
            printerr("disrobe output truncated at " + OUTPUT_LIMIT_BYTES + " bytes");
        }}
        if (timedOut) {{
            throw new IOException("disrobe " + subcommand + " exceeded 120 seconds");
        }}
        if (output.failure != null) {{
            throw output.failure;
        }}
        if (!completed) {{
            throw new IOException("disrobe process ended without an exit status");
        }}
        int exit = proc.exitValue();
        if (exit != 0) {{
            throw new IOException("disrobe " + subcommand + " exited " + exit);
        }}
    }}

    private static void drainOutput(InputStream input, OutputCapture output) {{
        byte[] buffer = new byte[8192];
        try (input) {{
            int read;
            while ((read = input.read(buffer)) != -1) {{
                int remaining = OUTPUT_LIMIT_BYTES - output.bytes.size();
                int retained = Math.min(read, Math.max(remaining, 0));
                output.bytes.write(buffer, 0, retained);
                output.truncated |= retained < read;
            }}
        }}
        catch (IOException error) {{
            output.failure = error;
        }}
    }}

    private static void terminateProcessTree(Process proc, Set<ProcessHandle> descendants)
        throws IOException, InterruptedException {{
        Set<ProcessHandle> processes = new LinkedHashSet<>(descendants);
        processes.add(proc.toHandle());
        IOException completionFailure = null;
        InterruptedException interruption = null;
        for (int phase = 0; phase < 2; phase++) {{
            boolean force = phase == 1;
            processes.stream().filter(ProcessHandle::isAlive).forEach(handle -> {{
                if (force) {{
                    handle.destroyForcibly();
                }}
                else {{
                    handle.destroy();
                }}
            }});
            CompletableFuture<?>[] exits = processes.stream()
                .filter(ProcessHandle::isAlive)
                .map(ProcessHandle::onExit)
                .toArray(CompletableFuture<?>[]::new);
            if (exits.length == 0) {{
                break;
            }}
            try {{
                CompletableFuture.allOf(exits).get(
                    TERMINATION_GRACE_NANOS,
                    TimeUnit.NANOSECONDS
                );
                break;
            }}
            catch (InterruptedException error) {{
                if (interruption == null) {{
                    interruption = error;
                }}
                else {{
                    interruption.addSuppressed(error);
                }}
            }}
            catch (ExecutionException error) {{
                IOException failure = new IOException(
                    "waiting for the disrobe process tree failed",
                    error.getCause()
                );
                if (completionFailure == null) {{
                    completionFailure = failure;
                }}
                else {{
                    completionFailure.addSuppressed(failure);
                }}
            }}
            catch (TimeoutException error) {{
                if (force) {{
                    IOException failure = new IOException(
                        "timed out waiting for the forcibly terminated disrobe process tree",
                        error
                    );
                    if (completionFailure == null) {{
                        completionFailure = failure;
                    }}
                    else {{
                        completionFailure.addSuppressed(failure);
                    }}
                }}
            }}
        }}
        if (processes.stream().anyMatch(ProcessHandle::isAlive)) {{
            IOException failure = new IOException("disrobe process tree did not stop");
            if (completionFailure != null) {{
                failure.addSuppressed(completionFailure);
            }}
            if (interruption != null) {{
                failure.addSuppressed(interruption);
                Thread.currentThread().interrupt();
            }}
            throw failure;
        }}
        if (completionFailure != null) {{
            if (interruption != null) {{
                completionFailure.addSuppressed(interruption);
                Thread.currentThread().interrupt();
            }}
            throw completionFailure;
        }}
        if (interruption != null) {{
            Thread.currentThread().interrupt();
            throw interruption;
        }}
    }}

    private static final class OutputCapture {{
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        private IOException failure;
        private boolean truncated;

        private String text() {{
            return bytes.toString(StandardCharsets.UTF_8);
        }}
    }}
}}
"#
    )
}

fn render_ghidra_readme(cmds: &[CliCommand]) -> String {
    let cmd_table: String = cmds
        .iter()
        .map(|c: &CliCommand| {
            let sub: &str = c.subcommand;
            let title: &str = c.title;
            format!("| `disrobe {sub}` | {title} |")
        })
        .collect::<Vec<String>>()
        .join("\n");

    format!(
        r"# disrobe for Ghidra

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
{cmd_table}
"
    )
}

fn render_binja_plugin_json(cmds: &[CliCommand]) -> String {
    let menu_paths: String = cmds
        .iter()
        .map(|c: &CliCommand| format!("    \"disrobe \\\\ {}\"", c.title))
        .collect::<Vec<String>>()
        .join(",\n");

    format!(
        r#"{{
  "pluginmetadataversion": 2,
  "name": "disrobe",
  "type": [
    "helper",
    "binaryview"
  ],
  "api": [
    "python3"
  ],
  "description": "Deobfuscate, decompile, and unpack compiled software by driving the disrobe CLI from inside Binary Ninja.",
  "longdescription": "Registers Binary Ninja plugin commands under the `disrobe` menu that run disrobe subcommands on the open file and print the recovered output to the Binary Ninja log. Drives the real disrobe binary; no placeholder bodies.",
  "license": {{
    "name": "Elastic-2.0",
    "text": "Elastic License 2.0. See the disrobe repository LICENSE for terms."
  }},
  "platforms": [
    "Linux",
    "Darwin",
    "Windows"
  ],
  "installinstructions": {{
    "Linux": "Copy this directory into ~/.binaryninja/plugins/disrobe and restart Binary Ninja.",
    "Darwin": "Copy this directory into ~/Library/Application Support/Binary Ninja/plugins/disrobe and restart Binary Ninja.",
    "Windows": "Copy this directory into %APPDATA%\\Binary Ninja\\plugins\\disrobe and restart Binary Ninja."
  }},
  "dependencies": {{}},
  "version": "0.1.0",
  "author": "disrobe",
  "minimumbinaryninjaversion": 3000,
  "menupath": [
{menu_paths}
  ]
}}
"#
    )
}

fn render_binja_plugin(cmds: &[CliCommand], lang_labels: &[String]) -> String {
    let register_items: String = cmds
        .iter()
        .map(|c: &CliCommand| {
            let sub: &str = c.subcommand;
            let title: &str = c.title;
            format!(
                "PluginCommand.register(\n    \"disrobe \\\\ {title}\",\n    \"{title}\",\n    _make_action(\"{sub}\"),\n)"
            )
        })
        .collect::<Vec<String>>()
        .join("\n\n");

    let ecosystems_comment: String = lang_labels
        .iter()
        .map(|l: &String| format!("# {l}"))
        .collect::<Vec<String>>()
        .join("\n");

    format!(
        r#"from __future__ import annotations

import shutil
import subprocess
from typing import Callable

from binaryninja import BinaryView, PluginCommand, log_error, log_info, log_warn


DISROBE_BINARY: str = "disrobe"


def _resolve_binary() -> str:
    found: str | None = shutil.which(DISROBE_BINARY)
    return found if found is not None else DISROBE_BINARY


def _input_path(bv: BinaryView) -> str | None:
    original: str | None = bv.file.original_filename
    if original:
        return original
    fallback: str | None = bv.file.filename
    return fallback if fallback else None


def _run_disrobe(subcommand: str, path: str) -> None:
    exe: str = _resolve_binary()
    args: list[str] = [exe, subcommand, path]
    result: subprocess.CompletedProcess[str] = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=300,
    )
    log_info(f"[disrobe] $ {{' '.join(args)}}")
    if result.stdout:
        log_info(result.stdout)
    if result.stderr:
        log_warn(result.stderr)
    if result.returncode != 0:
        log_error(f"disrobe {{subcommand}} exited {{result.returncode}}")


def _make_action(subcommand: str) -> Callable[[BinaryView], None]:
    def _action(bv: BinaryView) -> None:
        path: str | None = _input_path(bv)
        if path is None:
            log_warn("disrobe: no input file path available from this BinaryView")
            return
        _run_disrobe(subcommand, path)

    return _action


{register_items}


log_info("[disrobe] plugin loaded")


# Supported ecosystems (derived from disrobe catalog):
{ecosystems_comment}
"#
    )
}

fn render_binja_readme(cmds: &[CliCommand]) -> String {
    let cmd_table: String = cmds
        .iter()
        .map(|c: &CliCommand| {
            let sub: &str = c.subcommand;
            let title: &str = c.title;
            format!("| `disrobe {sub}` | {title} |")
        })
        .collect::<Vec<String>>()
        .join("\n");

    format!(
        r"# disrobe for Binary Ninja

A Binary Ninja Python plugin that drives the disrobe CLI from inside Binary Ninja. It registers plugin commands under the `disrobe` menu, resolves the open file path from `BinaryView.file.original_filename`, then shells out to disrobe and prints the recovered output to the Binary Ninja log.

## Requirements

- Binary Ninja 3.0 or later with the Python 3 API and plugin support. [Binary Ninja Free](https://binary.ninja/free/) does not expose these APIs.
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
{cmd_table}
"
    )
}

fn render_install_sh() -> String {
    r#"#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    echo "usage: $0 <vscode|ida|ghidra|binja> [--ida-dir <path>] [--ghidra-scripts <path>] [--binja-plugins <path>]"
    echo
    echo "  vscode   install the VS Code extension to ~/.vscode/extensions/disrobe-vscode"
    echo "  ida      copy disrobe_ida.py to the IDA plugins directory"
    echo "  ghidra   copy DisrobeAnalyzer.java to the Ghidra scripts directory"
    echo "  binja    copy the binja plugin to the Binary Ninja user plugins directory"
    exit 1
}

if [ $# -lt 1 ]; then
    usage
fi

EDITOR="$1"
shift

IDA_DIR=""
GHIDRA_SCRIPTS=""
BINJA_PLUGINS=""

while [ $# -gt 0 ]; do
    case "$1" in
        --ida-dir)
            IDA_DIR="${2:-}"
            shift 2
            ;;
        --ghidra-scripts)
            GHIDRA_SCRIPTS="${2:-}"
            shift 2
            ;;
        --binja-plugins)
            BINJA_PLUGINS="${2:-}"
            shift 2
            ;;
        *)
            echo "unknown flag: $1" >&2
            usage
            ;;
    esac
done

install_vscode() {
    command -v npm >/dev/null || { echo "Node.js 20 or later and npm are required." >&2; exit 1; }
    command -v code >/dev/null || { echo "Add the VS Code 'code' command to PATH." >&2; exit 1; }
    npm --prefix "${SCRIPT_DIR}/vscode" ci --ignore-scripts --no-audit --no-fund
    npm --prefix "${SCRIPT_DIR}/vscode" run package
    code --install-extension "${SCRIPT_DIR}/vscode/disrobe.vsix" --force
    echo "disrobe installed. Reload VS Code to activate it."
}

install_ida() {
    if [ -z "${IDA_DIR}" ]; then
        if [ "$(uname)" = "Darwin" ]; then
            IDA_DIR="${HOME}/Library/Application Support/hex-rays/ida pro/plugins"
        else
            IDA_DIR="${HOME}/.idapro/plugins"
        fi
    fi
    local dst="${IDA_DIR}/disrobe_ida.py"
    echo "installing disrobe IDA plugin to ${dst}"
    mkdir -p "${IDA_DIR}"
    cp "${SCRIPT_DIR}/ida/disrobe_ida.py" "${dst}"
    echo "done: plugin copied to ${dst}"
    echo "restart IDA Pro to load the plugin"
}

install_ghidra() {
    if [ -z "${GHIDRA_SCRIPTS}" ]; then
        GHIDRA_SCRIPTS="${HOME}/ghidra_scripts"
    fi
    local dst="${GHIDRA_SCRIPTS}/DisrobeAnalyzer.java"
    echo "installing disrobe Ghidra script to ${dst}"
    mkdir -p "${GHIDRA_SCRIPTS}"
    cp "${SCRIPT_DIR}/ghidra/DisrobeAnalyzer.java" "${dst}"
    echo "done: script copied to ${dst}"
    echo "in Ghidra: Window > Script Manager, refresh the list, then run DisrobeAnalyzer"
}

install_binja() {
    if [ -z "${BINJA_PLUGINS}" ]; then
        if [ "$(uname)" = "Darwin" ]; then
            BINJA_PLUGINS="${HOME}/Library/Application Support/Binary Ninja/plugins"
        else
            BINJA_PLUGINS="${HOME}/.binaryninja/plugins"
        fi
    fi
    local dst="${BINJA_PLUGINS}/disrobe"
    echo "installing disrobe Binary Ninja plugin to ${dst}"
    rm -rf "${dst}"
    mkdir -p "${BINJA_PLUGINS}"
    cp -r "${SCRIPT_DIR}/binja" "${dst}"
    echo "done: plugin copied to ${dst}"
    echo "restart Binary Ninja to load the plugin"
}

case "${EDITOR}" in
    vscode) install_vscode ;;
    ida)    install_ida ;;
    ghidra) install_ghidra ;;
    binja)  install_binja ;;
    *)
        echo "unknown editor: ${EDITOR}" >&2
        usage
        ;;
esac
"#
    .to_owned()
}

fn render_install_ps1() -> String {
    r#"[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('vscode', 'ida', 'ghidra', 'binja')]
    [string]$Editor,

    [string]$IDADir = '',
    [string]$GhidraScripts = '',
    [string]$BinjaPlugins = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Install-VSCode {
    $Npm = (Get-Command npm.cmd -ErrorAction Stop).Source
    $Code = (Get-Command code.cmd -ErrorAction Stop).Source
    $Extension = Join-Path $ScriptDir 'vscode'
    & $Npm --prefix $Extension ci --ignore-scripts --no-audit --no-fund
    if ($LASTEXITCODE -ne 0) { throw 'Installing VS Code build dependencies failed.' }
    & $Npm --prefix $Extension run package
    if ($LASTEXITCODE -ne 0) { throw 'Packaging the VS Code extension failed.' }
    & $Code --install-extension (Join-Path $Extension 'disrobe.vsix') --force
    if ($LASTEXITCODE -ne 0) { throw 'Installing the VS Code extension failed.' }
    Write-Host 'disrobe installed. Reload VS Code to activate it.'
}

function Install-IDA {
    $Dir = if ($IDADir) { $IDADir } else {
        $CandidateAppData = Join-Path $env:APPDATA 'Hex-Rays\IDA Pro\plugins'
        $CandidateLocal   = Join-Path $env:LOCALAPPDATA 'Hex-Rays\IDA Pro\plugins'
        if (Test-Path $CandidateAppData) { $CandidateAppData }
        elseif (Test-Path $CandidateLocal) { $CandidateLocal }
        else { $CandidateAppData }
    }
    $Dst = Join-Path $Dir 'disrobe_ida.py'
    Write-Host "installing disrobe IDA plugin to $Dst"
    if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Force $Dir | Out-Null }
    Copy-Item (Join-Path $ScriptDir 'ida\disrobe_ida.py') $Dst -Force
    Write-Host "done: plugin copied to $Dst"
    Write-Host "restart IDA Pro to load the plugin"
}

function Install-Ghidra {
    $Dir = if ($GhidraScripts) { $GhidraScripts } else {
        Join-Path $env:USERPROFILE 'ghidra_scripts'
    }
    $Dst = Join-Path $Dir 'DisrobeAnalyzer.java'
    Write-Host "installing disrobe Ghidra script to $Dst"
    if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Force $Dir | Out-Null }
    Copy-Item (Join-Path $ScriptDir 'ghidra\DisrobeAnalyzer.java') $Dst -Force
    Write-Host "done: script copied to $Dst"
    Write-Host "in Ghidra: Window > Script Manager, refresh the list, then run DisrobeAnalyzer"
}

function Install-Binja {
    $Dir = if ($BinjaPlugins) { $BinjaPlugins } else {
        Join-Path $env:APPDATA 'Binary Ninja\plugins'
    }
    $Dst = Join-Path $Dir 'disrobe'
    Write-Host "installing disrobe Binary Ninja plugin to $Dst"
    if (Test-Path $Dst) { Remove-Item -Recurse -Force $Dst }
    if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Force $Dir | Out-Null }
    Copy-Item -Recurse (Join-Path $ScriptDir 'binja') $Dst
    Write-Host "done: plugin copied to $Dst"
    Write-Host "restart Binary Ninja to load the plugin"
}

switch ($Editor) {
    'vscode' { Install-VSCode }
    'ida'    { Install-IDA }
    'ghidra' { Install-Ghidra }
    'binja'  { Install-Binja }
}
"#
    .to_owned()
}
