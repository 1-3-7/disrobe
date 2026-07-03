use std::fs;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};
use serde::Deserialize;

use crate::fileio::{read_bytes_bounded, read_text_bounded};

const MAX_ECOSYSTEMS_JSON_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PLUGIN_FILE_BYTES: u64 = 8 * 1024 * 1024;

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
        verify(&editors_dir, &artifacts)
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
            content: render_ghidra_script(&cmds, &lang_labels),
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

fn verify(editors_dir: &Path, artifacts: &[PluginArtifact]) -> Result<()> {
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
  "description": "Deobfuscate, decompile, and unpack almost anything via the disrobe CLI and LSP daemon.",
  "version": "0.1.0",
  "publisher": "disrobe",
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
    "compile": "tsc -p .",
    "watch": "tsc -watch -p .",
    "vscode:prepublish": "npm run compile"
  }},
  "dependencies": {{
    "vscode-languageclient": "^9.0.1"
  }},
  "devDependencies": {{
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

export function deactivate(): Thenable<void> | undefined {{
  return stopLspClient();
}}

function resolveExecutable(): string {{
  const cfg: vscode.WorkspaceConfiguration = vscode.workspace.getConfiguration("disrobe");
  return cfg.get<string>("executablePath", "disrobe") || "disrobe";
}}

function startLspClient(context: vscode.ExtensionContext): void {{
  if (client) {{
    outputChannel.appendLine("disrobe LSP client already running.");
    return;
  }}

  const exe: string = resolveExecutable();
  const cfg: vscode.WorkspaceConfiguration = vscode.workspace.getConfiguration("disrobe");
  const traceLevel: string = cfg.get<string>("lsp.trace", "off");

  const serverOptions: ServerOptions = {{
    command: exe,
    args: ["serve", "--stdio"],
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

  client = new LanguageClient("disrobe", "disrobe LSP", serverOptions, clientOptions);
  client.setTrace(Trace.fromString(traceLevel));

  context.subscriptions.push(client);
  client.start().then(
    () => outputChannel.appendLine(`disrobe LSP client started (${{exe}} serve --stdio)`),
    (err: Error) => outputChannel.appendLine(`disrobe LSP client failed to start: ${{err.message}}`),
  );
}}

function stopLspClient(): Thenable<void> | undefined {{
  if (!client) {{
    return undefined;
  }}
  const stopping: Thenable<void> = client.stop();
  client = undefined;
  return stopping;
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
{cmd_list}
| `disrobe.startServer` | Manually start the LSP daemon. |
| `disrobe.stopServer` | Stop the LSP daemon. |
| `disrobe.showOutput` | Open the disrobe output channel. |

## What is not wired yet

Marketplace publishing (`vsce package` / `vsce publish`) requires a publisher account and is not part of the generated scaffold. The extension can be installed locally via `vsce package` + `Extensions: Install from VSIX` once the marketplace step is completed.
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

- IDA Pro 7.6 or later (IDAPython 3 backend).
- `disrobe` binary on your PATH, or edit `DISROBE_BINARY` at the top of `disrobe_ida.py`.

## Installation

Copy `disrobe_ida.py` into your IDA plugins directory (typically `<IDA>/plugins/`) and restart IDA. The plugin loads automatically.

## Actions

| CLI invocation | Description | Default hotkey |
|---|---|---|
{cmd_table}

## Notes

This scaffold is generated from the disrobe CLI command catalog and is syntax-valid IDAPython. It has not been runtime-tested against a licensed IDA Pro installation. The action handlers invoke the real disrobe CLI with no placeholder bodies; the output appears in the IDA output window via `ida_kernwin.msg`.
"
    )
}

fn render_ghidra_script(cmds: &[CliCommand], lang_labels: &[String]) -> String {
    let action_methods: String = cmds
        .iter()
        .map(|c: &CliCommand| {
            let sub: &str = c.subcommand;
            let title: &str = c.title;
            format!(
                "    private void run{title_camel}() throws Exception {{\n        runDisrobe(\"{sub}\");\n    }}",
                title_camel = to_camel_case(title),
            )
        })
        .collect::<Vec<String>>()
        .join("\n\n");

    let dispatch_cases: String = cmds
        .iter()
        .enumerate()
        .map(|(i, c): (usize, &CliCommand)| {
            let title: &str = c.title;
            let title_camel: String = to_camel_case(title);
            let choices_ref: String = format!("choices[{i}]");
            format!("        if (chosen.equals({choices_ref})) {{ run{title_camel}(); return; }}")
        })
        .collect::<Vec<String>>()
        .join("\n");

    let choices_array: String = cmds
        .iter()
        .map(|c: &CliCommand| format!("            \"{}\"", c.title))
        .collect::<Vec<String>>()
        .join(",\n");

    let ecosystems_comment: String = lang_labels
        .iter()
        .map(|l: &String| format!("    // {l}"))
        .collect::<Vec<String>>()
        .join("\n");

    format!(
        r#"import ghidra.app.script.GhidraScript;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class DisrobeAnalyzer extends GhidraScript {{

    private static final String BINARY = "disrobe";

    @Override
    public void run() throws Exception {{
        String path = currentProgram.getExecutablePath();
        if (path == null || path.isEmpty()) {{
            printerr("disrobe: no executable path available from currentProgram");
            return;
        }}

        String[] choices = {{
{choices_array}
        }};

        String chosen = askChoice("disrobe", "Select action:", choices, choices[0]);
        if (chosen == null) {{
            return;
        }}

{dispatch_cases}
    }}

    private void runDisrobe(String subcommand) throws Exception {{
        String path = currentProgram.getExecutablePath();
        List<String> cmd = new ArrayList<>();
        cmd.add(BINARY);
        cmd.add(subcommand);
        cmd.add(path);

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process proc = pb.start();

        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {{
            String line;
            while ((line = br.readLine()) != null) {{
                sb.append(line).append('\n');
            }}
        }}

        int exit = proc.waitFor();
        println("[disrobe] $ " + String.join(" ", cmd));
        println(sb.toString());
        if (exit != 0) {{
            printerr("disrobe " + subcommand + " exited " + exit);
        }}
    }}

{action_methods}

    // Supported ecosystems (derived from disrobe catalog):
{ecosystems_comment}
}}
"#
    )
}

fn to_camel_case(s: &str) -> String {
    let mut result: String = String::with_capacity(s.len());
    let mut cap_next: bool = true;
    for ch in s.chars() {
        if ch.is_alphanumeric() {
            if cap_next {
                result.extend(ch.to_uppercase());
                cap_next = false;
            } else {
                result.push(ch);
            }
        } else {
            cap_next = true;
        }
    }
    result
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

A GhidraScript (`DisrobeAnalyzer.java`) that drives the disrobe CLI from inside Ghidra. It reads `currentProgram.getExecutablePath()`, prompts the user to choose an action, then shells out to disrobe and prints the recovered output to the Ghidra console.

## Requirements

- Ghidra 10.3 or later (Script Manager).
- `disrobe` binary on your PATH, or edit the `BINARY` constant at the top of `DisrobeAnalyzer.java`.

## Installation

Copy `DisrobeAnalyzer.java` into a directory listed in Ghidra's Script Manager search paths (`Window > Script Manager > Manage Script Directories`). Refresh the script list and run it from there, or assign a keybinding.

## Actions

| CLI invocation | Description |
|---|---|
{cmd_table}

## Notes

This scaffold is generated from the disrobe CLI command catalog and is syntax-valid Java for the Ghidra GhidraScript API. It has not been runtime-tested against a Ghidra installation. The action handlers invoke the real disrobe CLI with no placeholder bodies; output appears in the Ghidra console via `println`.
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
  "description": "Deobfuscate, decompile, and unpack almost anything by driving the disrobe CLI from inside Binary Ninja.",
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
{cmd_table}

## Notes

This scaffold is generated from the disrobe CLI command catalog. `__init__.py` is syntax-valid Python for the Binary Ninja API and `plugin.json` is a valid plugin metadata manifest (version 2). It has not been runtime-tested against a licensed Binary Ninja installation. The command handlers invoke the real disrobe CLI with no placeholder bodies; output appears in the Binary Ninja log via `log_info` / `log_warn` / `log_error`.
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
    local target="${HOME}/.vscode/extensions/disrobe-vscode"
    echo "installing disrobe VS Code extension to ${target}"
    rm -rf "${target}"
    cp -r "${SCRIPT_DIR}/vscode" "${target}"
    echo "done: extension installed at ${target}"
    echo "reload VS Code or run 'code --install-extension ${target}' to activate"
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
    $Target = Join-Path $env:USERPROFILE '.vscode\extensions\disrobe-vscode'
    Write-Host "installing disrobe VS Code extension to $Target"
    if (Test-Path $Target) {
        Remove-Item -Recurse -Force $Target
    }
    Copy-Item -Recurse (Join-Path $ScriptDir 'vscode') $Target
    Write-Host "done: extension installed at $Target"
    Write-Host "reload VS Code or run: code --install-extension `"$Target`" to activate"
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
