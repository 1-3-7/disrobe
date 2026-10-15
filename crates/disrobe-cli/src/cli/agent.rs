use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::{IsTerminal as _, Read as _, Write as _};
use std::path::{Path, PathBuf};

use clap::{Subcommand, ValueEnum};
use serde::Serialize;

use crate::cli::output::{self, OutputFormat};

const SERVER_NAME: &str = "disrobe";
const SKILL_FILE: &str = "SKILL.md";
const MAX_CONFIG_BYTES: u64 = 64 * 1024 * 1024;
const MAX_JSON_DEPTH: usize = 512;
const DIFF_CONTEXT: usize = 3;
const CODEX_TOOL_TIMEOUT_SECS: i64 = 1800;
const CLAUDE_DESKTOP_FILE: &str = "claude_desktop_config.json";
const CLAUDE_DESKTOP_PACKAGE: &str = "Claude_pzs8sxrjxfjjc";
const ENV_VARS: &[&str] = &[
    "CLAUDE_CONFIG_DIR",
    "CODEX_HOME",
    "GEMINI_CLI_HOME",
    "COPILOT_HOME",
    "QWEN_HOME",
    "KIMI_CODE_HOME",
    "XDG_CONFIG_HOME",
    "APPDATA",
    "LOCALAPPDATA",
];

const SKILL_TEXT: &str = r#"---
name: disrobe
description: Investigate compiled, packed or obfuscated files with the disrobe MCP server. Opens a file as a target, maps its sections, imports and functions, disassembles and decompiles functions, follows callers, call paths and references, reads and searches bytes, and runs disrobe's unpackers, deobfuscators and decompilers. Use when asked to reverse engineer, unpack, deobfuscate, decompile or explain a binary, bytecode file, script bundle or application package.
---

# Investigating a file with disrobe

disrobe reads files statically. It never runs the file it analyzes, and it reads only inside the workspace roots the server was started with (the agent's working directory plus any `--root`).

## Workflow

1. `open_target` with the file's path. Keep the returned `target_id`; record the `sha256`, format and architecture it reports.
2. `target_layout` for sections, imports and exports; `list_functions` (page with `offset` and `limit`, filter with `name_contains`) for the function table.
3. `disassemble_function` for exact instructions and `decompile_function` for pseudo-C of the functions that matter: the entry point, functions behind interesting strings, exported functions.
4. Follow the code: `references_to` an address for the instructions and pointer slots that use it, `call_path` from one function to another, `neighborhood` for callers and callees, `xrefs` for cross-references by function id.
5. Look at data: `find_strings` (each string with the functions that reference it), `read_bytes` at an address or file offset, `search_bytes` with a hex pattern (`??` matches any byte), `locate` to convert between address, offset, section and function.
6. Everything else goes through `run_command`; `list_commands` shows what it accepts. Common runs: `["identify"]` for compiler, packer and protector evidence; `["auto"]` to unpack, deobfuscate and decompile layer by layer; `["native", "unpack"]`, `["py", "deob"]`, `["js", "deob"]` and the other per-format commands; `["strings"]` and `["ioc"]` over a whole file. Files a run writes appear in its `outputs` with sizes and sha256, under `.disrobe/mcp/`; open them with `open_target` to keep going.
7. Record what you learn with `add_note` (rename, comment, bookmark, unknown, resolution) and read it back with `list_notes`.

The prompts `triage`, `unpack_and_decompile`, `trace_feature` and `explain_function` lay out these steps for common questions.

## Reporting

- Cite evidence: virtual addresses, file offsets, section names, sha256 of inputs and recovered files, and the tool that produced each fact.
- A refusal is a finding. Tools refuse with a named `DR-*` code and a reason (input outside the workspace roots, a format disrobe does not handle, a protector it detects but cannot remove). Quote the code and reason instead of guessing past it.
- Say which results are recovered source and which are pseudo-code or partial, as each tool labels them.
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Agent {
    All,
    ClaudeCode,
    ClaudeDesktop,
    Codex,
    Cursor,
    Gemini,
    Vscode,
    Windsurf,
    Devin,
    Copilot,
    Qwen,
    Opencode,
    Kimi,
}

#[derive(Subcommand, Debug)]
pub(crate) enum AgentCmd {
    #[command(
        about = "register `disrobe mcp` in coding agents' MCP configuration and install the investigation skill, after showing the diff"
    )]
    Setup {
        #[arg(
            long = "agent",
            value_enum,
            value_name = "AGENT",
            help = "agent to configure (repeatable); default: every agent whose configuration directory exists"
        )]
        agents: Vec<Agent>,
        #[arg(
            long = "root",
            value_name = "DIR",
            help = "another directory the server may read besides the agent's working directory (repeatable)"
        )]
        roots: Vec<PathBuf>,
        #[arg(long, short = 'y', help = "apply the changes without asking")]
        yes: bool,
        #[arg(long, value_name = "DIR", hide = true)]
        home: Option<PathBuf>,
    },
    #[command(
        about = "report, per agent, whether its configuration registers this disrobe binary and whether the skill is installed"
    )]
    Status {
        #[arg(
            long = "agent",
            value_enum,
            value_name = "AGENT",
            help = "agent to report (repeatable); default: every known agent"
        )]
        agents: Vec<Agent>,
        #[arg(long, value_name = "DIR", hide = true)]
        home: Option<PathBuf>,
    },
    #[command(
        about = "remove the disrobe entry, and the skill once no agent uses it, from agents' configuration, after showing the diff"
    )]
    Remove {
        #[arg(
            long = "agent",
            value_enum,
            value_name = "AGENT",
            help = "agent to clean up (repeatable); default: every agent whose configuration registers disrobe"
        )]
        agents: Vec<Agent>,
        #[arg(long, short = 'y', help = "apply the changes without asking")]
        yes: bool,
        #[arg(long, value_name = "DIR", hide = true)]
        home: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Os {
    Windows,
    Mac,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Json,
    Toml,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    Plain,
    Stdio,
    CopilotLocal,
    OpenCodeLocal,
    CodexTable,
}

struct Client {
    agent: Agent,
    name: &'static str,
    config: fn(&Host) -> PathBuf,
    format: Format,
    container: &'static str,
    shape: Shape,
    skills: Option<fn(&Host) -> PathBuf>,
    paste: &'static str,
}

const CLIENTS: &[Client] = &[
    Client {
        agent: Agent::ClaudeCode,
        name: "Claude Code",
        config: claude_code_config,
        format: Format::Json,
        container: "mcpServers",
        shape: Shape::Stdio,
        skills: Some(claude_code_skills),
        paste: "",
    },
    Client {
        agent: Agent::ClaudeDesktop,
        name: "Claude Desktop",
        config: claude_desktop_config,
        format: Format::Json,
        container: "mcpServers",
        shape: Shape::Plain,
        skills: None,
        paste: "paste it into a project's instructions",
    },
    Client {
        agent: Agent::Codex,
        name: "Codex",
        config: codex_config,
        format: Format::Toml,
        container: "mcp_servers",
        shape: Shape::CodexTable,
        skills: Some(shared_agent_skills),
        paste: "",
    },
    Client {
        agent: Agent::Cursor,
        name: "Cursor",
        config: cursor_config,
        format: Format::Json,
        container: "mcpServers",
        shape: Shape::Stdio,
        skills: None,
        paste: "paste it into Settings > Rules > User Rules",
    },
    Client {
        agent: Agent::Gemini,
        name: "Gemini CLI",
        config: gemini_config,
        format: Format::Json,
        container: "mcpServers",
        shape: Shape::Plain,
        skills: Some(gemini_skills),
        paste: "",
    },
    Client {
        agent: Agent::Vscode,
        name: "VS Code",
        config: vscode_config,
        format: Format::Json,
        container: "servers",
        shape: Shape::Stdio,
        skills: None,
        paste: "paste it into a user-level instructions file for chat",
    },
    Client {
        agent: Agent::Windsurf,
        name: "Windsurf",
        config: windsurf_config,
        format: Format::Json,
        container: "mcpServers",
        shape: Shape::Plain,
        skills: Some(windsurf_skills),
        paste: "",
    },
    Client {
        agent: Agent::Devin,
        name: "Devin Desktop",
        config: devin_config,
        format: Format::Json,
        container: "mcpServers",
        shape: Shape::Plain,
        skills: Some(windsurf_skills),
        paste: "",
    },
    Client {
        agent: Agent::Copilot,
        name: "GitHub Copilot CLI",
        config: copilot_config,
        format: Format::Json,
        container: "mcpServers",
        shape: Shape::CopilotLocal,
        skills: Some(copilot_skills),
        paste: "",
    },
    Client {
        agent: Agent::Qwen,
        name: "Qwen Code",
        config: qwen_config,
        format: Format::Json,
        container: "mcpServers",
        shape: Shape::Plain,
        skills: Some(qwen_skills),
        paste: "",
    },
    Client {
        agent: Agent::Opencode,
        name: "OpenCode",
        config: opencode_config,
        format: Format::Json,
        container: "mcp",
        shape: Shape::OpenCodeLocal,
        skills: Some(opencode_skills),
        paste: "",
    },
    Client {
        agent: Agent::Kimi,
        name: "Kimi Code",
        config: kimi_config,
        format: Format::Json,
        container: "mcpServers",
        shape: Shape::Plain,
        skills: Some(shared_agent_skills),
        paste: "",
    },
];

struct Host {
    home: PathBuf,
    cwd: PathBuf,
    os: Os,
    vars: BTreeMap<&'static str, OsString>,
}

impl Host {
    fn detect(home: Option<PathBuf>) -> miette::Result<Self> {
        let cwd: PathBuf = std::env::current_dir().map_err(|error: std::io::Error| {
            miette::miette!("DR-CLI-0960: cannot read the working directory: {error}")
        })?;
        let injected: bool = home.is_some();
        let home: PathBuf = match home {
            Some(home) => home,
            None => std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
                .filter(|value: &OsString| !value.is_empty())
                .map(PathBuf::from)
                .ok_or_else(|| {
                    miette::miette!(
                        "DR-CLI-0960: cannot find the home directory: {} is not set",
                        if cfg!(windows) { "USERPROFILE" } else { "HOME" }
                    )
                })?,
        };
        let home: PathBuf = if home.is_absolute() {
            home
        } else {
            cwd.join(home)
        };
        let os: Os = if cfg!(windows) {
            Os::Windows
        } else if cfg!(target_os = "macos") {
            Os::Mac
        } else {
            Os::Other
        };
        let vars: BTreeMap<&'static str, OsString> = if injected {
            BTreeMap::new()
        } else {
            ENV_VARS
                .iter()
                .filter_map(|name: &&'static str| {
                    std::env::var_os(name).map(|value: OsString| (*name, value))
                })
                .collect()
        };
        Ok(Self {
            home,
            cwd,
            os,
            vars,
        })
    }

    fn dir_var(&self, name: &str) -> Option<PathBuf> {
        let raw: &OsString = self
            .vars
            .get(name)
            .filter(|value: &&OsString| !value.is_empty())?;
        if let Some(text) = raw.to_str() {
            if text == "~" {
                return Some(self.home.clone());
            }
            if let Some(rest) = text.strip_prefix("~/").or_else(|| text.strip_prefix("~\\")) {
                return Some(self.home.join(rest));
            }
        }
        let path: PathBuf = PathBuf::from(raw);
        Some(if path.is_absolute() {
            path
        } else {
            self.cwd.join(path)
        })
    }

    fn appdata(&self) -> PathBuf {
        self.dir_var("APPDATA")
            .unwrap_or_else(|| self.home.join("AppData").join("Roaming"))
    }

    fn local_appdata(&self) -> PathBuf {
        self.dir_var("LOCALAPPDATA")
            .unwrap_or_else(|| self.home.join("AppData").join("Local"))
    }

    fn xdg_config(&self) -> PathBuf {
        self.dir_var("XDG_CONFIG_HOME")
            .unwrap_or_else(|| self.home.join(".config"))
    }

    fn user_config(&self, app: &str) -> PathBuf {
        match self.os {
            Os::Windows => self.appdata().join(app),
            Os::Mac => self
                .home
                .join("Library")
                .join("Application Support")
                .join(app),
            Os::Other => self.xdg_config().join(app),
        }
    }
}

fn claude_code_dir(host: &Host) -> PathBuf {
    host.dir_var("CLAUDE_CONFIG_DIR")
        .unwrap_or_else(|| host.home.join(".claude"))
}

fn claude_code_config(host: &Host) -> PathBuf {
    host.dir_var("CLAUDE_CONFIG_DIR")
        .unwrap_or_else(|| host.home.clone())
        .join(".claude.json")
}

fn claude_code_skills(host: &Host) -> PathBuf {
    claude_code_dir(host).join("skills")
}

fn claude_desktop_config(host: &Host) -> PathBuf {
    if host.os == Os::Windows {
        let packaged: PathBuf = host
            .local_appdata()
            .join("Packages")
            .join(CLAUDE_DESKTOP_PACKAGE)
            .join("LocalCache")
            .join("Roaming")
            .join("Claude")
            .join(CLAUDE_DESKTOP_FILE);
        if packaged.is_file() {
            return packaged;
        }
    }
    host.user_config("Claude").join(CLAUDE_DESKTOP_FILE)
}

fn codex_config(host: &Host) -> PathBuf {
    host.dir_var("CODEX_HOME")
        .unwrap_or_else(|| host.home.join(".codex"))
        .join("config.toml")
}

fn shared_agent_skills(host: &Host) -> PathBuf {
    host.home.join(".agents").join("skills")
}

fn cursor_config(host: &Host) -> PathBuf {
    host.home.join(".cursor").join("mcp.json")
}

fn gemini_home(host: &Host) -> PathBuf {
    host.dir_var("GEMINI_CLI_HOME")
        .unwrap_or_else(|| host.home.clone())
}

fn gemini_config(host: &Host) -> PathBuf {
    gemini_home(host).join(".gemini").join("settings.json")
}

fn gemini_skills(host: &Host) -> PathBuf {
    gemini_home(host).join(".agents").join("skills")
}

fn vscode_config(host: &Host) -> PathBuf {
    host.user_config("Code").join("User").join("mcp.json")
}

fn windsurf_config(host: &Host) -> PathBuf {
    host.home
        .join(".codeium")
        .join("windsurf")
        .join("mcp_config.json")
}

fn windsurf_skills(host: &Host) -> PathBuf {
    host.home.join(".codeium").join("windsurf").join("skills")
}

fn devin_config(host: &Host) -> PathBuf {
    let dir: PathBuf = if host.os == Os::Windows {
        host.appdata()
    } else {
        host.xdg_config()
    };
    dir.join("devin").join("mcp_config.json")
}

fn copilot_home(host: &Host) -> PathBuf {
    host.dir_var("COPILOT_HOME")
        .unwrap_or_else(|| host.home.join(".copilot"))
}

fn copilot_config(host: &Host) -> PathBuf {
    copilot_home(host).join("mcp-config.json")
}

fn copilot_skills(host: &Host) -> PathBuf {
    copilot_home(host).join("skills")
}

fn qwen_home(host: &Host) -> PathBuf {
    host.dir_var("QWEN_HOME")
        .unwrap_or_else(|| host.home.join(".qwen"))
}

fn qwen_config(host: &Host) -> PathBuf {
    qwen_home(host).join("settings.json")
}

fn qwen_skills(host: &Host) -> PathBuf {
    qwen_home(host).join("skills")
}

fn opencode_config(host: &Host) -> PathBuf {
    let dir: PathBuf = host.xdg_config().join("opencode");
    let jsonc: PathBuf = dir.join("opencode.jsonc");
    let json: PathBuf = dir.join("opencode.json");
    if jsonc.is_file() && !json.is_file() {
        jsonc
    } else {
        json
    }
}

fn opencode_skills(host: &Host) -> PathBuf {
    host.xdg_config().join("opencode").join("skills")
}

fn kimi_config(host: &Host) -> PathBuf {
    host.dir_var("KIMI_CODE_HOME")
        .unwrap_or_else(|| host.home.join(".kimi-code"))
        .join("mcp.json")
}

impl Client {
    fn detected(&self, host: &Host) -> bool {
        let config: PathBuf = (self.config)(host);
        config.is_file()
            || config
                .parent()
                .is_some_and(|parent: &Path| parent != host.home && parent.is_dir())
    }

    fn skill_file(&self, host: &Host) -> Option<PathBuf> {
        self.skills
            .map(|dir: fn(&Host) -> PathBuf| dir(host).join(SERVER_NAME).join(SKILL_FILE))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Launch {
    command: String,
    args: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum JsonCommand<'a> {
    Program(&'a str),
    Argv(Vec<&'a str>),
}

#[derive(Debug, Serialize)]
struct JsonEntry<'a> {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    kind: Option<&'static str>,
    command: JsonCommand<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    args: Option<&'a [String]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<[&'static str; 1]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
}

fn json_entry(shape: Shape, launch: &Launch) -> JsonEntry<'_> {
    let standard = |kind: Option<&'static str>| JsonEntry {
        kind,
        command: JsonCommand::Program(&launch.command),
        args: Some(&launch.args),
        tools: None,
        enabled: None,
    };
    match shape {
        Shape::Plain | Shape::CodexTable => standard(None),
        Shape::Stdio => standard(Some("stdio")),
        Shape::CopilotLocal => JsonEntry {
            tools: Some(["*"]),
            ..standard(Some("local"))
        },
        Shape::OpenCodeLocal => JsonEntry {
            kind: Some("local"),
            command: JsonCommand::Argv(
                std::iter::once(launch.command.as_str())
                    .chain(launch.args.iter().map(String::as_str))
                    .collect(),
            ),
            args: None,
            tools: None,
            enabled: Some(true),
        },
    }
}

#[derive(Debug)]
enum ConfigError {
    Malformed(String),
    Container(String),
    Render(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(detail) => formatter.write_str(detail),
            Self::Container(name) => write!(formatter, "`{name}` is not a table of servers"),
            Self::Render(detail) => write!(formatter, "cannot render the disrobe entry: {detail}"),
        }
    }
}

fn render_error(error: &serde_json::Error) -> ConfigError {
    ConfigError::Render(error.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ChangeKind {
    Create,
    Update,
    Delete,
    Unchanged,
}

#[derive(Debug)]
struct Planned {
    label: String,
    path: PathBuf,
    old: Option<String>,
    new: Option<String>,
}

impl Planned {
    fn kind(&self) -> ChangeKind {
        match (&self.old, &self.new) {
            (None, Some(_)) => ChangeKind::Create,
            (Some(_), None) => ChangeKind::Delete,
            (Some(old), Some(new)) if old != new => ChangeKind::Update,
            _ => ChangeKind::Unchanged,
        }
    }
}

#[derive(Debug, Serialize)]
struct ChangeReport {
    label: String,
    path: String,
    change: ChangeKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    backup: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    diff: String,
}

#[derive(Debug, Serialize)]
struct PlanReport {
    schema: &'static str,
    action: &'static str,
    applied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    changes: Vec<ChangeReport>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    instructions: Vec<InstructionHint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    skill_text: Option<&'static str>,
}

#[derive(Debug)]
struct Guidance {
    instructions: Vec<InstructionHint>,
    skill_text: Option<&'static str>,
}

#[derive(Debug, Serialize)]
struct InstructionHint {
    agent: String,
    hint: String,
    skill: String,
}

#[derive(Debug, Serialize)]
struct StatusRow {
    agent: Agent,
    name: &'static str,
    config: String,
    config_found: bool,
    entry_present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    command: Option<String>,
    command_exists: bool,
    matches_this_binary: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    skill: Option<String>,
    skill_installed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct StatusReport {
    schema: &'static str,
    binary: String,
    agents: Vec<StatusRow>,
}

pub(crate) fn run(cmd: AgentCmd, dry_run: bool, fmt: OutputFormat) -> miette::Result<()> {
    match cmd {
        AgentCmd::Setup {
            agents,
            roots,
            yes,
            home,
        } => {
            let host: Host = Host::detect(home)?;
            setup(&host, &agents, &roots, yes, dry_run, fmt)
        }
        AgentCmd::Status { agents, home } => {
            let host: Host = Host::detect(home)?;
            status(&host, &agents, fmt)
        }
        AgentCmd::Remove { agents, yes, home } => {
            let host: Host = Host::detect(home)?;
            remove(&host, &agents, yes, dry_run, fmt)
        }
    }
}

fn selected(agents: &[Agent], fallback: impl Fn(&Client) -> bool) -> Vec<&'static Client> {
    let named: BTreeSet<Agent> = agents
        .iter()
        .copied()
        .filter(|agent: &Agent| *agent != Agent::All)
        .collect();
    let fall_back: bool = named.is_empty() || agents.contains(&Agent::All);
    CLIENTS
        .iter()
        .filter(|client: &&Client| named.contains(&client.agent) || (fall_back && fallback(client)))
        .collect()
}

fn this_binary() -> miette::Result<PathBuf> {
    let exe: PathBuf = std::env::current_exe().map_err(|error: std::io::Error| {
        miette::miette!("DR-CLI-0961: cannot locate the running disrobe executable: {error}")
    })?;
    exe.canonicalize().map_err(|error: std::io::Error| {
        miette::miette!(
            "DR-CLI-0961: cannot resolve the running disrobe executable {}: {error}",
            exe.display()
        )
    })
}

fn plain_path(path: &Path) -> String {
    let text: String = path.display().to_string();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    match text.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => rest.to_owned(),
        _ => text,
    }
}

fn launch(roots: &[PathBuf]) -> miette::Result<Launch> {
    let mut args: Vec<String> = vec!["mcp".to_owned()];
    for root in roots {
        let canonical: PathBuf = root.canonicalize().map_err(|error: std::io::Error| {
            miette::miette!(
                "DR-CLI-0962: --root {} cannot be resolved: {error}",
                root.display()
            )
        })?;
        if !canonical.is_dir() {
            return Err(miette::miette!(
                "DR-CLI-0962: --root {} is not a directory",
                root.display()
            ));
        }
        args.push("--root".to_owned());
        args.push(plain_path(&canonical));
    }
    Ok(Launch {
        command: plain_path(&this_binary()?),
        args,
    })
}

fn read_config(path: &Path) -> miette::Result<Option<String>> {
    let file: std::fs::File = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(miette::miette!(
                "DR-CLI-0963: cannot read {}: {error}",
                path.display()
            ));
        }
    };
    let mut bytes: Vec<u8> = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error: std::io::Error| {
            miette::miette!("DR-CLI-0963: cannot read {}: {error}", path.display())
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CONFIG_BYTES {
        return Err(miette::miette!(
            "DR-CLI-0963: {} exceeds {MAX_CONFIG_BYTES} bytes",
            path.display()
        ));
    }
    String::from_utf8(bytes).map(Some).map_err(|_| {
        miette::miette!(
            "DR-CLI-0964: {} is not UTF-8 text; refusing to edit it",
            path.display()
        )
    })
}

fn config_error(client: &Client, path: &Path, error: &ConfigError) -> miette::Report {
    miette::miette!(
        "DR-CLI-0964: {} configuration {} is malformed ({error}); fix or move it, then rerun; nothing was written",
        client.name,
        path.display()
    )
}

fn set_entry(client: &Client, text: Option<&str>, launch: &Launch) -> Result<String, ConfigError> {
    match client.format {
        Format::Json => json_set_entry(
            text.unwrap_or_default(),
            client.container,
            &json_entry(client.shape, launch),
        ),
        Format::Toml => toml_set_entry(text.unwrap_or_default(), client.container, launch),
    }
}

fn remove_entry(client: &Client, text: &str) -> Result<Option<String>, ConfigError> {
    match client.format {
        Format::Json => json_remove_entry(text, client.container),
        Format::Toml => toml_remove_entry(text, client.container),
    }
}

fn read_entry(client: &Client, text: &str) -> Result<Option<Launch>, ConfigError> {
    match client.format {
        Format::Json => json_read_entry(text, client.container),
        Format::Toml => Ok(toml_entry_fields(text, client.container)?
            .map(|(launch, _): (Launch, Option<i64>)| launch)),
    }
}

fn entry_matches(client: &Client, text: &str, launch: &Launch) -> Result<bool, ConfigError> {
    match client.format {
        Format::Json => {
            let wanted: serde_json::Value = serde_json::to_value(json_entry(client.shape, launch))
                .map_err(|error: serde_json::Error| render_error(&error))?;
            Ok(json_entry_value(text, client.container)? == Some(wanted))
        }
        Format::Toml => Ok(toml_entry_fields(text, client.container)?
            == Some((launch.clone(), Some(CODEX_TOOL_TIMEOUT_SECS)))),
    }
}

fn setup(
    host: &Host,
    agents: &[Agent],
    roots: &[PathBuf],
    yes: bool,
    dry_run: bool,
    fmt: OutputFormat,
) -> miette::Result<()> {
    if !cfg!(feature = "server") {
        return Err(miette::miette!(
            "DR-CLI-0965: this disrobe binary was built without the `server` feature, so `disrobe mcp` is unavailable and there is nothing to register"
        ));
    }
    let clients: Vec<&Client> = selected(agents, |client: &Client| client.detected(host));
    if clients.is_empty() {
        return Err(miette::miette!(
            "DR-CLI-0966: no agent configuration directory found under {}; name one with --agent (claude-code, codex, cursor, gemini, vscode, windsurf, ...)",
            host.home.display()
        ));
    }
    let launch: Launch = launch(roots)?;
    let mut planned: Vec<Planned> = Vec::new();
    let mut skills: BTreeSet<PathBuf> = BTreeSet::new();
    let mut instructions: Vec<InstructionHint> = Vec::new();
    for client in &clients {
        let path: PathBuf = (client.config)(host);
        let old: Option<String> = read_config(&path)?;
        let current: bool = match &old {
            Some(text) => entry_matches(client, text, &launch)
                .map_err(|error: ConfigError| config_error(client, &path, &error))?,
            None => false,
        };
        let new: Option<String> = if current {
            old.clone()
        } else {
            Some(
                set_entry(client, old.as_deref(), &launch)
                    .map_err(|error: ConfigError| config_error(client, &path, &error))?,
            )
        };
        planned.push(Planned {
            label: client.name.to_owned(),
            path,
            old,
            new,
        });
        match client.skill_file(host) {
            Some(skill) => {
                skills.insert(skill);
            }
            None => instructions.push(InstructionHint {
                agent: client.name.to_owned(),
                hint: client.paste.to_owned(),
                skill: String::new(),
            }),
        }
    }
    for skill in &skills {
        let old: Option<String> = read_config(skill)?;
        planned.push(Planned {
            label: "investigation skill".to_owned(),
            path: skill.clone(),
            new: Some(SKILL_TEXT.to_owned()),
            old,
        });
    }
    let skill_reference: String = skills.iter().next().map_or_else(
        || "the skill text printed below".to_owned(),
        |path: &PathBuf| plain_path(path),
    );
    for hint in &mut instructions {
        hint.skill.clone_from(&skill_reference);
    }
    let skill_text: Option<&'static str> =
        (skills.is_empty() && !instructions.is_empty()).then_some(SKILL_TEXT);
    execute_plan(
        "setup",
        planned,
        Guidance {
            instructions,
            skill_text,
        },
        yes,
        dry_run,
        fmt,
    )
}

fn remove(
    host: &Host,
    agents: &[Agent],
    yes: bool,
    dry_run: bool,
    fmt: OutputFormat,
) -> miette::Result<()> {
    let registered: BTreeSet<Agent> = CLIENTS
        .iter()
        .filter(|client: &&Client| {
            read_config(&(client.config)(host))
                .ok()
                .flatten()
                .is_some_and(|text: String| matches!(read_entry(client, &text), Ok(Some(_))))
        })
        .map(|client: &Client| client.agent)
        .collect();
    let clients: Vec<&Client> =
        selected(agents, |client: &Client| registered.contains(&client.agent));
    let removing: BTreeSet<Agent> = clients
        .iter()
        .map(|client: &&Client| client.agent)
        .collect();
    let mut planned: Vec<Planned> = Vec::new();
    for client in &clients {
        let path: PathBuf = (client.config)(host);
        let Some(text) = read_config(&path)? else {
            continue;
        };
        let new: Option<String> = remove_entry(client, &text)
            .map_err(|error: ConfigError| config_error(client, &path, &error))?;
        if let Some(new) = new {
            planned.push(Planned {
                label: client.name.to_owned(),
                path,
                old: Some(text),
                new: Some(new),
            });
        }
    }
    let skill_files: BTreeSet<PathBuf> = clients
        .iter()
        .filter_map(|client: &&Client| client.skill_file(host))
        .collect();
    for skill in skill_files {
        let still_used: bool = CLIENTS.iter().any(|client: &Client| {
            !removing.contains(&client.agent)
                && client.skill_file(host).as_ref() == Some(&skill)
                && registered.contains(&client.agent)
        });
        if still_used {
            continue;
        }
        if let Some(old) = read_config(&skill)?
            && old.starts_with("---\nname: disrobe\n")
        {
            planned.push(Planned {
                label: "investigation skill".to_owned(),
                path: skill,
                old: Some(old),
                new: None,
            });
        }
    }
    execute_plan(
        "remove",
        planned,
        Guidance {
            instructions: Vec::new(),
            skill_text: None,
        },
        yes,
        dry_run,
        fmt,
    )
}

fn execute_plan(
    action: &'static str,
    planned: Vec<Planned>,
    guidance: Guidance,
    yes: bool,
    dry_run: bool,
    fmt: OutputFormat,
) -> miette::Result<()> {
    let mut changes: Vec<ChangeReport> = planned
        .iter()
        .map(|item: &Planned| ChangeReport {
            label: item.label.clone(),
            path: plain_path(&item.path),
            change: item.kind(),
            backup: None,
            diff: if item.kind() == ChangeKind::Unchanged {
                String::new()
            } else {
                unified_diff(
                    &plain_path(&item.path),
                    item.old.as_deref(),
                    item.new.as_deref(),
                )
            },
        })
        .collect();
    let pending: bool = changes
        .iter()
        .any(|change: &ChangeReport| change.change != ChangeKind::Unchanged);
    if !fmt.is_machine() {
        print_plan(&changes, &guidance);
    }
    let decision: Result<(), &'static str> = if !pending {
        Err("nothing to change")
    } else if dry_run {
        Err("dry run")
    } else if yes {
        Ok(())
    } else if std::io::stdin().is_terminal() && !fmt.is_machine() {
        if confirm()? { Ok(()) } else { Err("declined") }
    } else {
        Err("not confirmed: rerun with --yes to apply")
    };
    if decision.is_ok() {
        let stamp: String = disrobe_core::time::WallClock::now()
            .rfc3339_millis()
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect();
        for (item, report) in planned.iter().zip(changes.iter_mut()) {
            if report.change != ChangeKind::Unchanged {
                report.backup = apply(item, &stamp)?.map(|backup: PathBuf| plain_path(&backup));
            }
        }
    }
    let report: PlanReport = PlanReport {
        schema: "disrobe.agent-plan/v1",
        action,
        applied: decision.is_ok(),
        reason: decision.err(),
        changes,
        instructions: guidance.instructions,
        skill_text: guidance.skill_text,
    };
    output::emit(fmt, &report, || match report.reason {
        None => {
            for change in &report.changes {
                if let Some(backup) = &change.backup {
                    println!("backed up {} to {backup}", change.path);
                }
            }
            println!("applied; restart the agents to load the change");
        }
        Some(reason) => println!("nothing written ({reason})"),
    })
}

fn print_plan(changes: &[ChangeReport], guidance: &Guidance) {
    for change in changes {
        let verb: &str = match change.change {
            ChangeKind::Create => "create",
            ChangeKind::Update => "update",
            ChangeKind::Delete => "delete",
            ChangeKind::Unchanged => "unchanged",
        };
        println!("{:<20} {verb:<9} {}", change.label, change.path);
    }
    for change in changes {
        if !change.diff.is_empty() {
            print!("\n{}", change.diff);
        }
    }
    for hint in &guidance.instructions {
        println!(
            "\n{} has no skill directory; to give it the investigation workflow, {} (the text is in {}).",
            hint.agent, hint.hint, hint.skill
        );
    }
    if let Some(text) = guidance.skill_text {
        print!("\n{text}");
    }
    println!();
}

fn confirm() -> miette::Result<bool> {
    eprint!("apply these changes? [y/N] ");
    let _: Result<(), std::io::Error> = std::io::stderr().flush();
    let mut answer: String = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(|error: std::io::Error| {
            miette::miette!("DR-CLI-0967: cannot read the answer: {error}")
        })?;
    let answer: &str = answer.trim();
    Ok(answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes"))
}

fn apply(item: &Planned, stamp: &str) -> miette::Result<Option<PathBuf>> {
    let on_disk: Option<String> = read_config(&item.path)?;
    if on_disk != item.old {
        return Err(miette::miette!(
            "DR-CLI-0968: {} changed while the diff was shown; nothing more was written, rerun to plan again",
            item.path.display()
        ));
    }
    let name: String = item
        .path
        .file_name()
        .map(|name: &std::ffi::OsStr| name.to_string_lossy().into_owned())
        .ok_or_else(|| miette::miette!("DR-CLI-0968: {} names no file", item.path.display()))?;
    let write_error = |action: &str, path: &Path, error: std::io::Error| {
        miette::miette!("DR-CLI-0968: cannot {action} {}: {error}", path.display())
    };
    if let Some(parent) = item.path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error: std::io::Error| write_error("create", parent, error))?;
    }
    let pristine_skill: bool = item.new.is_none() && item.old.as_deref() == Some(SKILL_TEXT);
    let backup: Option<PathBuf> = match &item.old {
        Some(old) if !pristine_skill => {
            let backup: PathBuf = item
                .path
                .with_file_name(format!("{name}.disrobe-backup-{stamp}"));
            let mut file: std::fs::File = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&backup)
                .map_err(|error: std::io::Error| write_error("create backup", &backup, error))?;
            file.write_all(old.as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|error: std::io::Error| write_error("write backup", &backup, error))?;
            Some(backup)
        }
        _ => None,
    };
    if let Some(new) = &item.new {
        let temp: PathBuf = item
            .path
            .with_file_name(format!(".{name}.disrobe-{}-{stamp}", std::process::id()));
        let mut file: std::fs::File = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|error: std::io::Error| write_error("create", &temp, error))?;
        let written: Result<(), std::io::Error> = file
            .write_all(new.as_bytes())
            .and_then(|()| file.sync_all());
        drop(file);
        if let Err(error) = written.and_then(|()| std::fs::rename(&temp, &item.path)) {
            let _: Result<(), std::io::Error> = std::fs::remove_file(&temp);
            return Err(write_error("replace", &item.path, error));
        }
    } else {
        std::fs::remove_file(&item.path)
            .map_err(|error: std::io::Error| write_error("delete", &item.path, error))?;
        if let Some(parent) = item.path.parent() {
            let empty: bool = std::fs::read_dir(parent)
                .map_err(|error: std::io::Error| write_error("list", parent, error))?
                .next()
                .is_none();
            if empty {
                std::fs::remove_dir(parent)
                    .map_err(|error: std::io::Error| write_error("delete", parent, error))?;
            }
        }
    }
    Ok(backup)
}

fn status(host: &Host, agents: &[Agent], fmt: OutputFormat) -> miette::Result<()> {
    let binary: PathBuf = this_binary()?;
    let clients: Vec<&Client> = selected(agents, |_: &Client| true);
    let mut rows: Vec<StatusRow> = Vec::with_capacity(clients.len());
    for client in clients {
        let path: PathBuf = (client.config)(host);
        let skill: Option<PathBuf> = client.skill_file(host);
        let mut row: StatusRow = StatusRow {
            agent: client.agent,
            name: client.name,
            config: plain_path(&path),
            config_found: path.is_file(),
            entry_present: false,
            command: None,
            command_exists: false,
            matches_this_binary: false,
            skill_installed: skill.as_deref().is_some_and(Path::is_file),
            skill: skill.as_deref().map(plain_path),
            error: None,
        };
        match read_config(&path) {
            Ok(Some(text)) => match read_entry(client, &text) {
                Ok(Some(entry)) => {
                    let command: PathBuf = PathBuf::from(&entry.command);
                    row.entry_present = true;
                    row.command_exists = command.is_file();
                    row.matches_this_binary = command
                        .canonicalize()
                        .is_ok_and(|resolved: PathBuf| resolved == binary);
                    row.command = Some(entry.command);
                }
                Ok(None) => {}
                Err(error) => row.error = Some(error.to_string()),
            },
            Ok(None) => {}
            Err(error) => row.error = Some(error.to_string()),
        }
        rows.push(row);
    }
    let report: StatusReport = StatusReport {
        schema: "disrobe.agent-status/v1",
        binary: plain_path(&binary),
        agents: rows,
    };
    output::emit(fmt, &report, || {
        println!("this binary: {}", report.binary);
        for row in &report.agents {
            let state: &str = match (row.config_found, row.entry_present, row.matches_this_binary) {
                (false, _, _) => "no config",
                (true, false, _) => "not registered",
                (true, true, true) => "registered",
                (true, true, false) if row.command_exists => "registered (another disrobe binary)",
                (true, true, false) => "registered (command missing)",
            };
            let skill: &str = match (&row.skill, row.skill_installed) {
                (None, _) => "skill: paste by hand",
                (Some(_), true) => "skill: installed",
                (Some(_), false) => "skill: not installed",
            };
            println!("{:<20} {state:<36} {skill:<22} {}", row.name, row.config);
            if let Some(error) = &row.error {
                println!("{:<20} error: {error}", "");
            }
        }
    })
}

fn unified_diff(path: &str, old: Option<&str>, new: Option<&str>) -> String {
    let old_lines: Vec<&str> =
        old.map_or_else(Vec::new, |text: &str| text.split_inclusive('\n').collect());
    let new_lines: Vec<&str> =
        new.map_or_else(Vec::new, |text: &str| text.split_inclusive('\n').collect());
    let prefix: usize = old_lines
        .iter()
        .zip(&new_lines)
        .take_while(|(a, b): &(&&str, &&str)| a == b)
        .count();
    let suffix: usize = old_lines[prefix..]
        .iter()
        .rev()
        .zip(new_lines[prefix..].iter().rev())
        .take_while(|(a, b): &(&&str, &&str)| a == b)
        .count();
    let start: usize = prefix.saturating_sub(DIFF_CONTEXT);
    let old_end: usize = (old_lines.len() - suffix + DIFF_CONTEXT).min(old_lines.len());
    let new_end: usize = (new_lines.len() - suffix + DIFF_CONTEXT).min(new_lines.len());
    let mut out: String = format!(
        "--- {}\n+++ {}\n@@ -{} +{} @@\n",
        if old.is_some() { path } else { "/dev/null" },
        if new.is_some() { path } else { "/dev/null" },
        hunk_range(start, old_end - start),
        hunk_range(start, new_end - start)
    );
    let mut line = |sign: char, text: &str| {
        out.push(sign);
        out.push_str(text.strip_suffix('\n').unwrap_or(text));
        out.push('\n');
        if !text.ends_with('\n') {
            out.push_str("\\ No newline at end of file\n");
        }
    };
    for text in &old_lines[start..prefix] {
        line(' ', text);
    }
    for text in &old_lines[prefix..old_lines.len() - suffix] {
        line('-', text);
    }
    for text in &new_lines[prefix..new_lines.len() - suffix] {
        line('+', text);
    }
    for text in &new_lines[new_lines.len() - suffix..new_end] {
        line(' ', text);
    }
    out
}

fn hunk_range(start: usize, len: usize) -> String {
    if len == 0 {
        format!("{start},0")
    } else {
        format!("{},{len}", start + 1)
    }
}

#[derive(Debug)]
struct Member {
    key: String,
    key_start: usize,
    value_start: usize,
    value_end: usize,
}

#[derive(Debug)]
struct ObjectSpan {
    open: usize,
    close: usize,
    members: Vec<Member>,
}

struct Scanner<'t> {
    text: &'t str,
    pos: usize,
    depth: usize,
}

impl<'t> Scanner<'t> {
    const fn at(text: &'t str, pos: usize) -> Self {
        Self {
            text,
            pos,
            depth: 0,
        }
    }

    fn error(&self, what: &str) -> ConfigError {
        let line: usize = self.text[..self.pos.min(self.text.len())]
            .matches('\n')
            .count()
            + 1;
        ConfigError::Malformed(format!("{what} at line {line}"))
    }

    fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.pos).copied()
    }

    fn skip_trivia(&mut self) -> Result<(), ConfigError> {
        let bytes: &[u8] = self.text.as_bytes();
        loop {
            match self.peek() {
                Some(b' ' | b'\t' | b'\r' | b'\n') => self.pos += 1,
                Some(b'/') => match bytes.get(self.pos + 1) {
                    Some(b'/') => {
                        self.pos = self.text[self.pos..]
                            .find('\n')
                            .map_or(self.text.len(), |offset: usize| self.pos + offset);
                    }
                    Some(b'*') => {
                        let end: usize = self.text[self.pos + 2..]
                            .find("*/")
                            .ok_or_else(|| self.error("unterminated comment"))?;
                        self.pos += end + 4;
                    }
                    _ => return Err(self.error("unexpected `/`")),
                },
                _ => return Ok(()),
            }
        }
    }

    fn string(&mut self) -> Result<(usize, usize), ConfigError> {
        let start: usize = self.pos;
        if self.peek() != Some(b'"') {
            return Err(self.error("expected a string"));
        }
        self.pos += 1;
        loop {
            match self.peek() {
                None => return Err(self.error("unterminated string")),
                Some(b'"') => {
                    self.pos += 1;
                    return Ok((start, self.pos));
                }
                Some(b'\\') => self.pos += 2,
                Some(byte) if byte < 0x20 => return Err(self.error("control character in string")),
                Some(_) => self.pos += 1,
            }
        }
    }

    fn scalar(&mut self) -> Result<(usize, usize), ConfigError> {
        let start: usize = self.pos;
        while self.peek().is_some_and(|byte: u8| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
        }) {
            self.pos += 1;
        }
        let token: &str = &self.text[start..self.pos];
        let valid: bool = matches!(token, "true" | "false" | "null")
            || (!token.is_empty() && serde_json::from_str::<serde_json::Number>(token).is_ok());
        if valid {
            Ok((start, self.pos))
        } else {
            self.pos = start;
            Err(self.error("unexpected value"))
        }
    }

    fn value(&mut self) -> Result<(usize, usize), ConfigError> {
        match self.peek() {
            Some(b'{') => self
                .object()
                .map(|object: ObjectSpan| (object.open, object.close + 1)),
            Some(b'[') => self.array(),
            Some(b'"') => self.string(),
            _ => self.scalar(),
        }
    }

    fn enter(&mut self) -> Result<(), ConfigError> {
        self.depth += 1;
        if self.depth > MAX_JSON_DEPTH {
            return Err(self.error("nesting deeper than 512 levels"));
        }
        Ok(())
    }

    fn array(&mut self) -> Result<(usize, usize), ConfigError> {
        self.enter()?;
        let start: usize = self.pos;
        self.pos += 1;
        loop {
            self.skip_trivia()?;
            if self.peek() == Some(b']') {
                self.pos += 1;
                self.depth -= 1;
                return Ok((start, self.pos));
            }
            self.value()?;
            self.skip_trivia()?;
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {}
                _ => return Err(self.error("expected `,` or `]`")),
            }
        }
    }

    fn object(&mut self) -> Result<ObjectSpan, ConfigError> {
        self.enter()?;
        let open: usize = self.pos;
        self.pos += 1;
        let mut members: Vec<Member> = Vec::new();
        loop {
            self.skip_trivia()?;
            if self.peek() == Some(b'}') {
                let close: usize = self.pos;
                self.pos += 1;
                self.depth -= 1;
                return Ok(ObjectSpan {
                    open,
                    close,
                    members,
                });
            }
            let (key_start, key_end): (usize, usize) = self.string()?;
            let key: String = serde_json::from_str::<String>(&self.text[key_start..key_end])
                .map_err(|_| self.error("invalid string escape"))?;
            self.skip_trivia()?;
            if self.peek() != Some(b':') {
                return Err(self.error("expected `:`"));
            }
            self.pos += 1;
            self.skip_trivia()?;
            let (value_start, value_end): (usize, usize) = self.value()?;
            members.push(Member {
                key,
                key_start,
                value_start,
                value_end,
            });
            self.skip_trivia()?;
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {}
                _ => return Err(self.error("expected `,` or `}`")),
            }
        }
    }
}

fn parse_document(text: &str) -> Result<Option<ObjectSpan>, ConfigError> {
    let start: usize = if text.starts_with('\u{feff}') { 3 } else { 0 };
    let mut scanner: Scanner<'_> = Scanner::at(text, start);
    scanner.skip_trivia()?;
    if scanner.peek().is_none() {
        return Ok(None);
    }
    if scanner.peek() != Some(b'{') {
        return Err(scanner.error("expected a top-level object"));
    }
    let object: ObjectSpan = scanner.object()?;
    scanner.skip_trivia()?;
    if scanner.peek().is_some() {
        return Err(scanner.error("unexpected content after the top-level object"));
    }
    Ok(Some(object))
}

fn container_object(
    text: &str,
    document: &ObjectSpan,
    container: &str,
) -> Result<Option<ObjectSpan>, ConfigError> {
    let Some(member) = document
        .members
        .iter()
        .find(|member: &&Member| member.key == container)
    else {
        return Ok(None);
    };
    if text.as_bytes().get(member.value_start) != Some(&b'{') {
        return Err(ConfigError::Container(container.to_owned()));
    }
    Scanner::at(text, member.value_start).object().map(Some)
}

fn line_indent(text: &str, pos: usize) -> Option<&str> {
    let line_start: usize = text[..pos].rfind('\n').map_or(0, |index: usize| index + 1);
    let before: &str = &text[line_start..pos];
    before
        .chars()
        .all(|c: char| c == ' ' || c == '\t')
        .then_some(before)
}

fn indent_unit(text: &str, document: &ObjectSpan) -> String {
    document
        .members
        .first()
        .and_then(|member: &Member| line_indent(text, member.key_start))
        .filter(|indent: &&str| !indent.is_empty())
        .unwrap_or("  ")
        .to_owned()
}

fn render_json<T: Serialize>(value: &T, unit: &str, indent: &str) -> Result<String, ConfigError> {
    let mut buffer: Vec<u8> = Vec::new();
    let formatter: serde_json::ser::PrettyFormatter<'_> =
        serde_json::ser::PrettyFormatter::with_indent(unit.as_bytes());
    let mut serializer: serde_json::Serializer<&mut Vec<u8>, serde_json::ser::PrettyFormatter<'_>> =
        serde_json::Serializer::with_formatter(&mut buffer, formatter);
    value
        .serialize(&mut serializer)
        .map_err(|error: serde_json::Error| render_error(&error))?;
    Ok(String::from_utf8_lossy(&buffer).replace('\n', &format!("\n{indent}")))
}

fn leading_whitespace(text: &str, pos: usize) -> &str {
    let line_start: usize = text[..pos].rfind('\n').map_or(0, |index: usize| index + 1);
    let line: &str = &text[line_start..pos];
    &line[..line.len() - line.trim_start_matches([' ', '\t']).len()]
}

fn insert_member<T: Serialize>(
    text: &str,
    object: &ObjectSpan,
    unit: &str,
    key: &str,
    value: &T,
) -> Result<String, ConfigError> {
    let key_json: String =
        serde_json::to_string(key).map_err(|error: serde_json::Error| render_error(&error))?;
    let Some(last) = object.members.last() else {
        let object_indent: &str = leading_whitespace(text, object.open);
        let member_indent: String = format!("{object_indent}{unit}");
        let member: String = format!("{key_json}: {}", render_json(value, unit, &member_indent)?);
        let interior: &str = &text[object.open + 1..object.close];
        return Ok(if interior.trim().is_empty() {
            format!(
                "{}\n{member_indent}{member}\n{object_indent}{}",
                &text[..=object.open],
                &text[object.close..]
            )
        } else {
            format!(
                "{}\n{member_indent}{member}{}",
                &text[..=object.open],
                &text[object.open + 1..]
            )
        });
    };
    let member_indent: Option<&str> = object
        .members
        .first()
        .and_then(|first: &Member| line_indent(text, first.key_start));
    let insertion: String = match member_indent {
        Some(indent) => format!(
            ",\n{indent}{key_json}: {}",
            render_json(value, unit, indent)?
        ),
        None => format!(
            ", {key_json}: {}",
            serde_json::to_string(value)
                .map_err(|error: serde_json::Error| render_error(&error))?
        ),
    };
    Ok(format!(
        "{}{insertion}{}",
        &text[..last.value_end],
        &text[last.value_end..]
    ))
}

fn json_set_entry<T: Serialize>(
    text: &str,
    container: &str,
    entry: &T,
) -> Result<String, ConfigError> {
    let mut servers: BTreeMap<&str, &T> = BTreeMap::new();
    servers.insert(SERVER_NAME, entry);
    let Some(document) = parse_document(text)? else {
        let mut root: BTreeMap<&str, BTreeMap<&str, &T>> = BTreeMap::new();
        root.insert(container, servers);
        return Ok(format!("{}\n", render_json(&root, "  ", "")?));
    };
    let unit: String = indent_unit(text, &document);
    let Some(object) = container_object(text, &document, container)? else {
        return insert_member(text, &document, &unit, container, &servers);
    };
    let Some(existing) = object
        .members
        .iter()
        .find(|member: &&Member| member.key == SERVER_NAME)
    else {
        return insert_member(text, &object, &unit, SERVER_NAME, entry);
    };
    let indent: &str = line_indent(text, existing.key_start).unwrap_or_default();
    Ok(format!(
        "{}{}{}",
        &text[..existing.value_start],
        render_json(entry, &unit, indent)?,
        &text[existing.value_end..]
    ))
}

fn json_remove_entry(text: &str, container: &str) -> Result<Option<String>, ConfigError> {
    let Some(document) = parse_document(text)? else {
        return Ok(None);
    };
    let Some(servers) = container_object(text, &document, container)? else {
        return Ok(None);
    };
    let Some(index) = servers
        .members
        .iter()
        .position(|member: &Member| member.key == SERVER_NAME)
    else {
        return Ok(None);
    };
    let members: &[Member] = &servers.members;
    let (start, end): (usize, usize) = match (index.checked_sub(1), members.get(index + 1)) {
        (Some(previous), _) => (members[previous].value_end, members[index].value_end),
        (None, Some(next)) => (members[index].key_start, next.key_start),
        (None, None) => (servers.open + 1, servers.close),
    };
    Ok(Some(format!("{}{}", &text[..start], &text[end..])))
}

fn strip_jsonc(text: &str) -> String {
    let mut out: String = String::with_capacity(text.len());
    let mut chars: std::iter::Peekable<std::str::Chars<'_>> = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                out.push(c);
                while let Some(inner) = chars.next() {
                    out.push(inner);
                    if inner == '\\' {
                        out.extend(chars.next());
                    } else if inner == '"' {
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'/') => {
                while chars.peek().is_some_and(|next: &char| *next != '\n') {
                    chars.next();
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut previous: char = '\0';
                for inner in chars.by_ref() {
                    if previous == '*' && inner == '/' {
                        break;
                    }
                    previous = inner;
                }
            }
            '}' | ']' => {
                let trimmed: usize = out.trim_end().len();
                if out[..trimmed].ends_with(',') {
                    out.truncate(trimmed - 1);
                }
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

fn json_entry_value(text: &str, container: &str) -> Result<Option<serde_json::Value>, ConfigError> {
    let Some(document) = parse_document(text)? else {
        return Ok(None);
    };
    let Some(servers) = container_object(text, &document, container)? else {
        return Ok(None);
    };
    let Some(entry) = servers
        .members
        .iter()
        .find(|member: &&Member| member.key == SERVER_NAME)
    else {
        return Ok(None);
    };
    serde_json::from_str(&strip_jsonc(&text[entry.value_start..entry.value_end]))
        .map(Some)
        .map_err(|error: serde_json::Error| {
            ConfigError::Malformed(format!("the disrobe entry: {error}"))
        })
}

fn json_strings(value: Option<&serde_json::Value>) -> Vec<String> {
    value
        .and_then(serde_json::Value::as_array)
        .map(|items: &Vec<serde_json::Value>| {
            items
                .iter()
                .filter_map(|item: &serde_json::Value| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn json_read_entry(text: &str, container: &str) -> Result<Option<Launch>, ConfigError> {
    let Some(value) = json_entry_value(text, container)? else {
        return Ok(None);
    };
    Ok(Some(match value.get("command") {
        Some(serde_json::Value::String(command)) => Launch {
            command: command.clone(),
            args: json_strings(value.get("args")),
        },
        argv @ Some(serde_json::Value::Array(_)) => {
            let mut argv: std::vec::IntoIter<String> = json_strings(argv).into_iter();
            Launch {
                command: argv.next().unwrap_or_default(),
                args: argv.collect(),
            }
        }
        _ => Launch {
            command: String::new(),
            args: Vec::new(),
        },
    }))
}

fn toml_document(text: &str) -> Result<toml_edit::DocumentMut, ConfigError> {
    text.parse::<toml_edit::DocumentMut>()
        .map_err(|error: toml_edit::TomlError| {
            ConfigError::Malformed(error.to_string().trim().to_owned())
        })
}

fn toml_set_entry(text: &str, container: &str, launch: &Launch) -> Result<String, ConfigError> {
    let mut document: toml_edit::DocumentMut = toml_document(text)?;
    let servers: &mut toml_edit::Item = document.entry(container).or_insert_with(|| {
        let mut table: toml_edit::Table = toml_edit::Table::new();
        table.set_implicit(true);
        toml_edit::Item::Table(table)
    });
    let servers: &mut dyn toml_edit::TableLike = servers
        .as_table_like_mut()
        .ok_or_else(|| ConfigError::Container(container.to_owned()))?;
    let mut entry: toml_edit::Table = toml_edit::Table::new();
    entry.insert("command", toml_edit::value(launch.command.as_str()));
    entry.insert(
        "args",
        toml_edit::value(
            launch
                .args
                .iter()
                .map(String::as_str)
                .collect::<toml_edit::Array>(),
        ),
    );
    entry.insert(
        "tool_timeout_sec",
        toml_edit::value(CODEX_TOOL_TIMEOUT_SECS),
    );
    servers.insert(SERVER_NAME, toml_edit::Item::Table(entry));
    Ok(document.to_string())
}

fn toml_remove_entry(text: &str, container: &str) -> Result<Option<String>, ConfigError> {
    let mut document: toml_edit::DocumentMut = toml_document(text)?;
    let Some(servers) = document.get_mut(container) else {
        return Ok(None);
    };
    let servers: &mut dyn toml_edit::TableLike = servers
        .as_table_like_mut()
        .ok_or_else(|| ConfigError::Container(container.to_owned()))?;
    if servers.remove(SERVER_NAME).is_none() {
        return Ok(None);
    }
    Ok(Some(document.to_string()))
}

fn toml_entry_fields(
    text: &str,
    container: &str,
) -> Result<Option<(Launch, Option<i64>)>, ConfigError> {
    let document: toml_edit::DocumentMut = toml_document(text)?;
    let Some(servers) = document.get(container) else {
        return Ok(None);
    };
    let servers: &dyn toml_edit::TableLike = servers
        .as_table_like()
        .ok_or_else(|| ConfigError::Container(container.to_owned()))?;
    let Some(entry) = servers.get(SERVER_NAME) else {
        return Ok(None);
    };
    let command: String = entry
        .get("command")
        .and_then(toml_edit::Item::as_str)
        .unwrap_or_default()
        .to_owned();
    let args: Vec<String> = entry
        .get("args")
        .and_then(toml_edit::Item::as_array)
        .map(|array: &toml_edit::Array| {
            array
                .iter()
                .filter_map(|value: &toml_edit::Value| value.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let timeout: Option<i64> = entry
        .get("tool_timeout_sec")
        .and_then(toml_edit::Item::as_integer);
    Ok(Some((Launch { command, args }, timeout)))
}
