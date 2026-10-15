use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use clap::builder::ValueHint;
use disrobe_tool_process::{CaptureOutcome, CommandSpec, Completion, Execution, ExecutionError};
use rmcp::ErrorData;
use rmcp::Json;
use rmcp::handler::server::wrapper::Parameters;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use super::{DisrobeMcp, hex32};

const DEFAULT_TIMEOUT_SECS: u64 = 300;
const MAX_TIMEOUT_SECS: u64 = 1800;
const MAX_CAPTURE_BYTES: usize = 16 * 1024 * 1024;
const MAX_COMMAND_WORDS: usize = 4;
const MAX_ARGS: usize = 256;
const MAX_ARG_BYTES: usize = 4096;
const MAX_FILTER_BYTES: usize = 256;
const MAX_POSSIBLE_VALUES: usize = 64;
const MAX_LISTED_OUTPUTS: usize = 1000;
const MAX_LISTING_DEPTH: usize = 16;
const MAX_HASHED_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RUN_DIR_ATTEMPTS: u64 = 64;
const RUN_DIR_PARENT: [&str; 2] = [".disrobe", "mcp"];

const ALLOWED_COMMANDS: &[&str] = &[
    "apk",
    "as3 disasm",
    "as3 tags",
    "auto",
    "beam disasm",
    "beam lift",
    "beam parse",
    "behavior",
    "capabilities",
    "capture",
    "catalog",
    "chain",
    "crash",
    "detect",
    "diff",
    "dotnet analyze",
    "dotnet decompile",
    "dotnet deobfuscate",
    "dotnet interop",
    "dotnet native-aot",
    "electron",
    "envelope create",
    "envelope diff",
    "envelope inspect",
    "envelope migrate-check",
    "envelope verify",
    "evm decompile",
    "evm disasm",
    "evm inspect",
    "explain",
    "extract",
    "flutter decompile",
    "flutter disasm",
    "flutter dump",
    "flutter identity",
    "flutter inventory",
    "flutter inventory-standalone",
    "flutter kernel",
    "flutter map",
    "frisk",
    "go info",
    "go recover",
    "guard verify",
    "hermes decompile",
    "hermes disasm",
    "hermes info",
    "identify",
    "indicators",
    "ioc",
    "js deob",
    "js sourcemap",
    "js unbundle",
    "js v8",
    "jvm decompile",
    "jvm dex2-jar",
    "jvm extract",
    "jvm jni",
    "jvm retrace",
    "lua decompile",
    "lua deobfuscate",
    "lua detect",
    "lua opcode-map",
    "macho car",
    "macho classdump",
    "macho dump",
    "macho dyldcache",
    "macho fat",
    "macho keyed-archive",
    "macho nib",
    "mobile detect",
    "mobile extract",
    "mobile flutter",
    "mobile hermes",
    "mobile recon",
    "native callgraph",
    "native decompile",
    "native delphi",
    "native devirt",
    "native diff",
    "native disasm",
    "native entropy",
    "native export",
    "native fingerprint",
    "native graph",
    "native identify",
    "native match",
    "native pdb",
    "native pdb-cxx",
    "native sbom",
    "native sigmaker",
    "native signatures",
    "native symbols",
    "native unpack",
    "nuitka constants",
    "nuitka decompile",
    "nuitka detect",
    "nuitka extract",
    "nuitka symbols",
    "passes",
    "php decode",
    "php deobfuscate",
    "php extract",
    "pickle decompile",
    "pickle disasm",
    "pickle ml-detect",
    "pickle polyglot",
    "pickle safety",
    "pickle trace",
    "py decompile",
    "py deob",
    "py disasm",
    "py extract",
    "py sourcedefender",
    "pyarmor unpack",
    "pyfreeze detect",
    "pyfreeze extract",
    "pyinstaller detect",
    "pyinstaller extract",
    "query",
    "report",
    "resources",
    "ruby decompile",
    "ruby detect",
    "scan",
    "semdiff",
    "shell deob",
    "shell detect",
    "sqlite",
    "strings",
    "swift classdump",
    "swift shield-undo",
    "swift xor-decrypt",
    "taint",
    "verify",
    "vulnmatch",
    "wasm component",
    "wasm decompile",
    "wasm deob",
    "wasm lift-gc",
    "wasm types",
    "webview",
    "yara generate",
    "yara parse",
];

const ALLOWED_GLOBALS: &[&str] = &[
    "verbose", "quiet", "json", "force", "threads", "no-cache", "dry-run",
];

const REFUSED_FLAGS: &[&str] = &["allow-dynamic", "allow-bcc", "in-place"];

const FORCED_FLAGS: &[&str] = &["json", "no-cache"];

const OUTPUT_FLAGS: &[&str] = &[
    "extract",
    "out",
    "out-dir",
    "output",
    "output-dir",
    "json-out",
    "svg",
    "python",
    "emit-wasm",
    "cache",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
#[serde(rename_all = "lowercase")]
pub(super) enum OutputKind {
    Dir,
    File,
}

#[derive(Debug, Clone, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct CatalogArg {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub long: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short: Option<char>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub help: String,
    pub positional: bool,
    pub takes_value: bool,
    pub required: bool,
    pub repeatable: bool,
    pub path: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<OutputKind>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
    #[serde(skip)]
    executable: bool,
}

#[derive(Debug, Clone, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct CatalogCommand {
    pub command: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub about: String,
    pub args: Vec<CatalogArg>,
}

#[derive(Debug)]
pub struct CommandCatalog {
    program: PathBuf,
    commands: BTreeMap<String, CatalogCommand>,
    globals: Vec<CatalogArg>,
    runs: AtomicU64,
}

impl CommandCatalog {
    #[must_use]
    pub fn from_clap(program: PathBuf, root: &clap::Command) -> Self {
        let mut commands: BTreeMap<String, CatalogCommand> = BTreeMap::new();
        collect_commands(root, &mut Vec::new(), &mut commands);
        let globals: Vec<CatalogArg> = root
            .get_arguments()
            .filter(|arg: &&clap::Arg| {
                arg.get_long()
                    .is_some_and(|long: &str| ALLOWED_GLOBALS.contains(&long))
            })
            .filter_map(catalog_arg)
            .collect();
        Self {
            program,
            commands,
            globals,
            runs: AtomicU64::new(0),
        }
    }

    fn command(&self, words: &[String]) -> Option<&CatalogCommand> {
        self.commands.get(&words.join(" "))
    }
}

fn collect_commands(
    command: &clap::Command,
    prefix: &mut Vec<String>,
    out: &mut BTreeMap<String, CatalogCommand>,
) {
    for sub in command.get_subcommands() {
        if sub.is_hide_set() {
            continue;
        }
        prefix.push(sub.get_name().to_owned());
        let key: String = prefix.join(" ");
        if ALLOWED_COMMANDS.contains(&key.as_str()) {
            out.insert(
                key,
                CatalogCommand {
                    command: prefix.clone(),
                    about: sub
                        .get_about()
                        .map_or_else(String::new, ToString::to_string),
                    args: sub.get_arguments().filter_map(catalog_arg).collect(),
                },
            );
        }
        collect_commands(sub, prefix, out);
        prefix.pop();
    }
}

fn catalog_arg(arg: &clap::Arg) -> Option<CatalogArg> {
    if arg.is_hide_set()
        || arg
            .get_long()
            .is_some_and(|long: &str| REFUSED_FLAGS.contains(&long))
    {
        return None;
    }
    let action: &clap::ArgAction = arg.get_action();
    if matches!(
        action,
        clap::ArgAction::Help
            | clap::ArgAction::HelpShort
            | clap::ArgAction::HelpLong
            | clap::ArgAction::Version
    ) {
        return None;
    }
    let hint: ValueHint = arg.get_value_hint();
    let long: Option<String> = arg.get_long().map(str::to_owned);
    let takes_value: bool = action.takes_values();
    let output: Option<OutputKind> = long
        .as_deref()
        .filter(|name: &&str| takes_value && OUTPUT_FLAGS.contains(name))
        .map(|_| {
            let dir_named: bool =
                arg.get_value_names()
                    .is_some_and(|names: &[clap::builder::Str]| {
                        names
                            .iter()
                            .any(|name: &clap::builder::Str| name.as_str().contains("DIR"))
                    });
            if dir_named || hint == ValueHint::DirPath {
                OutputKind::Dir
            } else {
                OutputKind::File
            }
        });
    let multiple: bool = arg
        .get_num_args()
        .is_some_and(|range: clap::builder::ValueRange| range.max_values() > 1);
    Some(CatalogArg {
        name: long
            .clone()
            .unwrap_or_else(|| arg.get_id().as_str().to_owned()),
        short: arg.get_short(),
        help: arg.get_help().map_or_else(String::new, ToString::to_string),
        positional: arg.is_positional(),
        takes_value,
        required: arg.is_required_set(),
        repeatable: multiple || matches!(action, clap::ArgAction::Append | clap::ArgAction::Count),
        path: matches!(
            hint,
            ValueHint::AnyPath
                | ValueHint::FilePath
                | ValueHint::DirPath
                | ValueHint::ExecutablePath
        ),
        output,
        values: arg
            .get_possible_values()
            .iter()
            .filter(|_| takes_value)
            .filter(|value: &&clap::builder::PossibleValue| !value.is_hide_set())
            .take(MAX_POSSIBLE_VALUES)
            .map(|value: &clap::builder::PossibleValue| value.get_name().to_owned())
            .collect(),
        executable: hint == ValueHint::ExecutablePath,
        long,
    })
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct ListCommandsParams {
    #[serde(default)]
    pub filter: Option<String>,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct ListCommandsOut {
    pub commands: Vec<CatalogCommand>,
    pub globals: Vec<CatalogArg>,
    pub forced_flags: Vec<String>,
    pub refused_flags: Vec<String>,
    pub output_root: String,
    pub default_timeout_secs: u64,
    pub max_timeout_secs: u64,
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct RunCommandParams {
    pub command: Vec<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct RunCommandOut {
    pub command: Vec<String>,
    pub argv: Vec<String>,
    pub run_dir: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub success: bool,
    pub timed_out: bool,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout: Option<String>,
    pub stdout_truncated: bool,
    pub stderr: String,
    pub stderr_truncated: bool,
    pub outputs: Vec<OutputFileOut>,
    pub outputs_truncated: bool,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct OutputFileOut {
    pub path: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Debug)]
struct RunPlan {
    program: PathBuf,
    command: Vec<String>,
    argv: Vec<String>,
    run_dir: PathBuf,
    timeout: Duration,
}

#[derive(Debug)]
struct ParsedArgs<'c> {
    options: Vec<(&'c CatalogArg, Option<String>)>,
    positionals: Vec<(&'c CatalogArg, String)>,
}

#[rmcp::tool_router(router = command_tool_router, vis = "pub(super)")]
impl DisrobeMcp {
    #[rmcp::tool(
        name = "list_commands",
        description = "List the read-only disrobe CLI subcommands run_command accepts, with each one's purpose and arguments (name, help, takes a value, required, repeatable, path, output redirection, allowed values). `filter` keeps commands whose words contain it. Available when the server runs as `disrobe mcp`."
    )]
    fn list_commands(
        &self,
        Parameters(p): Parameters<ListCommandsParams>,
    ) -> Result<Json<ListCommandsOut>, ErrorData> {
        let catalog: &CommandCatalog = self.catalog()?;
        let filter: Option<&str> = p
            .filter
            .as_deref()
            .map(str::trim)
            .filter(|f: &&str| !f.is_empty());
        if let Some(text) = filter {
            ensure_len("filter", text, MAX_FILTER_BYTES)?;
        }
        Ok(Json(ListCommandsOut {
            commands: catalog
                .commands
                .iter()
                .filter(|(key, _): &(&String, &CatalogCommand)| {
                    filter.is_none_or(|text: &str| key.contains(text))
                })
                .map(|(_, command): (&String, &CatalogCommand)| command.clone())
                .collect(),
            globals: catalog.globals.clone(),
            forced_flags: FORCED_FLAGS
                .iter()
                .map(|flag: &&str| format!("--{flag}"))
                .collect(),
            refused_flags: REFUSED_FLAGS
                .iter()
                .map(|flag: &&str| format!("--{flag}"))
                .chain(std::iter::once("--neutralize apply".to_owned()))
                .collect(),
            output_root: RUN_DIR_PARENT.join("/"),
            default_timeout_secs: DEFAULT_TIMEOUT_SECS,
            max_timeout_secs: MAX_TIMEOUT_SECS,
        }))
    }

    #[rmcp::tool(
        name = "run_command",
        description = "Run one read-only disrobe CLI subcommand from list_commands as a bounded child process of this server's executable: `command` is its words (e.g. [\"native\", \"symbols\"]), `args` its arguments. Input paths must resolve inside a workspace root (relative paths resolve against the first root); --json and --no-cache are forced; output options are redirected into a fresh .disrobe/mcp/<run>/ directory under the first root; --allow-dynamic, --allow-bcc, --in-place and --neutralize apply are refused. Returns the exit status, parsed JSON (or text) stdout, stderr, and the files the run wrote with sizes and sha256. `timeout_secs` defaults to 300 and is capped at 1800."
    )]
    async fn run_command(
        &self,
        Parameters(p): Parameters<RunCommandParams>,
    ) -> Result<Json<RunCommandOut>, ErrorData> {
        let plan: RunPlan = self.plan_run(p)?;
        tokio::task::spawn_blocking(move || plan.execute())
            .await
            .map_err(|error: tokio::task::JoinError| {
                ErrorData::internal_error(
                    format!("DR-MCP-0812: run_command worker failed: {error}"),
                    None,
                )
            })?
            .map(Json)
    }
}

impl DisrobeMcp {
    fn catalog(&self) -> Result<&CommandCatalog, ErrorData> {
        self.commands.as_deref().ok_or_else(|| {
            ErrorData::invalid_params(
                "DR-MCP-0800: list_commands and run_command need the command catalog that `disrobe mcp` provides; this server was started without one (the standalone disrobe-mcp binary carries none)",
                None,
            )
        })
    }

    fn plan_run(&self, p: RunCommandParams) -> Result<RunPlan, ErrorData> {
        let catalog: &CommandCatalog = self.catalog()?;
        let roots: &[PathBuf] = self
            .workspace
            .as_deref()
            .map(super::target::Workspace::roots)
            .filter(|roots: &&[PathBuf]| !roots.is_empty())
            .ok_or_else(|| {
                ErrorData::invalid_params(
                    "DR-MCP-0801: run_command needs a workspace root; start the server inside a directory or pass --root",
                    None,
                )
            })?;
        if p.command.is_empty() || p.command.len() > MAX_COMMAND_WORDS {
            return Err(ErrorData::invalid_params(
                format!(
                    "DR-MCP-0802: `command` must hold 1 to {MAX_COMMAND_WORDS} subcommand words, e.g. [\"native\", \"symbols\"]"
                ),
                None,
            ));
        }
        if p.args.len() > MAX_ARGS {
            return Err(ErrorData::invalid_params(
                format!("DR-MCP-0803: `args` exceeds {MAX_ARGS} entries"),
                None,
            ));
        }
        for word in p.command.iter().chain(&p.args) {
            ensure_len("argument", word, MAX_ARG_BYTES)?;
        }
        let command: &CatalogCommand = catalog.command(&p.command).ok_or_else(|| {
            ErrorData::invalid_params(
                format!(
                    "DR-MCP-0804: `{}` is not an allowlisted read-only command; list_commands shows the ones run_command accepts",
                    p.command.join(" ")
                ),
                None,
            )
        })?;
        let timeout_secs: u64 = p.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
        if timeout_secs == 0 || timeout_secs > MAX_TIMEOUT_SECS {
            return Err(ErrorData::invalid_params(
                format!("DR-MCP-0805: timeout_secs must be in 1..={MAX_TIMEOUT_SECS}"),
                None,
            ));
        }
        let mut parsed: ParsedArgs<'_> = parse_args(command, &catalog.globals, &p.args)?;
        confine_inputs(&mut parsed, roots)?;
        let run_dir: PathBuf = create_run_dir(&roots[0], &catalog.runs)?;
        let argv: Vec<String> = build_argv(command, parsed, &run_dir)?;
        Ok(RunPlan {
            program: catalog.program.clone(),
            command: command.command.clone(),
            argv,
            run_dir,
            timeout: Duration::from_secs(timeout_secs),
        })
    }
}

fn ensure_len(field: &str, value: &str, limit: usize) -> Result<(), ErrorData> {
    if value.len() > limit {
        return Err(ErrorData::invalid_params(
            format!("DR-MCP-0806: `{field}` exceeds {limit} bytes"),
            None,
        ));
    }
    Ok(())
}

fn refuse_arg(arg: &CatalogArg, value: Option<&str>) -> Result<(), ErrorData> {
    let long: &str = arg.long.as_deref().unwrap_or_default();
    if REFUSED_FLAGS.contains(&long) {
        return Err(ErrorData::invalid_params(
            format!(
                "DR-MCP-0807: run_command refuses --{long}: it executes or rewrites the input, which the agent surface never does"
            ),
            None,
        ));
    }
    if long == "neutralize" && value.is_some_and(|v: &str| v.eq_ignore_ascii_case("apply")) {
        return Err(ErrorData::invalid_params(
            "DR-MCP-0807: run_command refuses --neutralize apply: patching the input needs the owner's consent at the terminal; use --neutralize propose to see the patches",
            None,
        ));
    }
    if arg.executable {
        return Err(ErrorData::invalid_params(
            format!("DR-MCP-0807: run_command refuses --{long}: it names a program to launch"),
            None,
        ));
    }
    Ok(())
}

fn find_long<'c>(
    command: &'c CatalogCommand,
    globals: &'c [CatalogArg],
    long: &str,
) -> Option<&'c CatalogArg> {
    command
        .args
        .iter()
        .chain(globals)
        .find(|arg: &&CatalogArg| !arg.positional && arg.long.as_deref() == Some(long))
}

fn find_short<'c>(
    command: &'c CatalogCommand,
    globals: &'c [CatalogArg],
    short: char,
) -> Option<&'c CatalogArg> {
    command
        .args
        .iter()
        .chain(globals)
        .find(|arg: &&CatalogArg| !arg.positional && arg.short == Some(short))
}

fn parse_args<'c>(
    command: &'c CatalogCommand,
    globals: &'c [CatalogArg],
    args: &[String],
) -> Result<ParsedArgs<'c>, ErrorData> {
    let mut parsed: ParsedArgs<'c> = ParsedArgs {
        options: Vec::new(),
        positionals: Vec::new(),
    };
    let positional_slots: Vec<&CatalogArg> = command
        .args
        .iter()
        .filter(|arg: &&CatalogArg| arg.positional)
        .collect();
    let mut tokens: std::slice::Iter<'_, String> = args.iter();
    while let Some(token) = tokens.next() {
        let (arg, inline): (&CatalogArg, Option<String>) = if token == "--" {
            return Err(ErrorData::invalid_params(
                "DR-MCP-0808: `--` is not accepted; pass positional arguments directly",
                None,
            ));
        } else if let Some(body) = token.strip_prefix("--") {
            let (name, inline): (&str, Option<String>) = match body.split_once('=') {
                Some((name, value)) => (name, Some(value.to_owned())),
                None => (body, None),
            };
            if REFUSED_FLAGS.contains(&name) {
                return Err(ErrorData::invalid_params(
                    format!(
                        "DR-MCP-0807: run_command refuses --{name}: it executes or rewrites the input, which the agent surface never does"
                    ),
                    None,
                ));
            }
            let arg: &CatalogArg = find_long(command, globals, name).ok_or_else(|| {
                ErrorData::invalid_params(
                    format!(
                        "DR-MCP-0809: `{}` takes no option --{name}; list_commands shows its arguments",
                        command.command.join(" ")
                    ),
                    None,
                )
            })?;
            (arg, inline)
        } else if let Some(body) = token
            .strip_prefix('-')
            .filter(|body: &&str| !body.is_empty())
        {
            let mut chars: std::str::Chars<'_> = body.chars();
            let short: char = chars.next().unwrap_or_default();
            let rest: &str = chars.as_str();
            let arg: &CatalogArg = find_short(command, globals, short).ok_or_else(|| {
                ErrorData::invalid_params(
                    format!(
                        "DR-MCP-0809: `{}` takes no option -{short}; list_commands shows its arguments",
                        command.command.join(" ")
                    ),
                    None,
                )
            })?;
            let inline: Option<String> = if rest.is_empty() {
                None
            } else if arg.takes_value {
                Some(rest.strip_prefix('=').unwrap_or(rest).to_owned())
            } else {
                return Err(ErrorData::invalid_params(
                    format!(
                        "DR-MCP-0809: combined short flags `{token}` are not accepted; pass each flag separately"
                    ),
                    None,
                ));
            };
            (arg, inline)
        } else {
            let slot: &CatalogArg = positional_slots
                .get(parsed.positionals.len())
                .or_else(|| {
                    positional_slots
                        .last()
                        .filter(|last: &&&CatalogArg| last.repeatable)
                })
                .copied()
                .ok_or_else(|| {
                    ErrorData::invalid_params(
                        format!(
                            "DR-MCP-0810: `{}` takes no further positional argument `{token}`",
                            command.command.join(" ")
                        ),
                        None,
                    )
                })?;
            parsed.positionals.push((slot, token.clone()));
            continue;
        };
        let value: Option<String> = match (arg.takes_value, inline) {
            (true, Some(value)) => Some(value),
            (true, None) => Some(tokens.next().cloned().ok_or_else(|| {
                ErrorData::invalid_params(
                    format!("DR-MCP-0810: option --{} needs a value", arg.name),
                    None,
                )
            })?),
            (false, Some(_)) => {
                return Err(ErrorData::invalid_params(
                    format!("DR-MCP-0810: flag --{} takes no value", arg.name),
                    None,
                ));
            }
            (false, None) => None,
        };
        refuse_arg(arg, value.as_deref())?;
        parsed.options.push((arg, value));
    }
    Ok(parsed)
}

fn path_looking(value: &str) -> bool {
    let path: &Path = Path::new(value);
    path.is_absolute()
        || value.starts_with('~')
        || path.components().any(|component: Component<'_>| {
            matches!(
                component,
                Component::ParentDir | Component::Prefix(_) | Component::RootDir
            )
        })
}

fn confine(roots: &[PathBuf], raw: &str) -> Result<String, ErrorData> {
    if raw.starts_with('~') {
        return Err(ErrorData::invalid_params(
            format!(
                "DR-MCP-0811: {raw}: home-relative paths are not expanded; pass a path inside a workspace root"
            ),
            None,
        ));
    }
    let requested: &Path = Path::new(raw);
    let joined: PathBuf = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        roots[0].join(requested)
    };
    let canonical: PathBuf = joined.canonicalize().map_err(|error: std::io::Error| {
        ErrorData::invalid_params(format!("DR-MCP-0811: cannot locate {raw}: {error}"), None)
    })?;
    if !roots
        .iter()
        .any(|root: &PathBuf| canonical.starts_with(root))
    {
        return Err(ErrorData::invalid_params(
            format!(
                "DR-MCP-0811: {raw} resolves to {} outside every workspace root ({})",
                canonical.display(),
                roots
                    .iter()
                    .map(|root: &PathBuf| root.display().to_string())
                    .collect::<Vec<String>>()
                    .join(", ")
            ),
            None,
        ));
    }
    canonical.into_os_string().into_string().map_err(|_| {
        ErrorData::invalid_params(
            format!("DR-MCP-0811: {raw} resolves to a path that is not UTF-8"),
            None,
        )
    })
}

fn redirect_output(kind: OutputKind, raw: &str, run_dir: &Path) -> Result<String, ErrorData> {
    let target: PathBuf = match kind {
        OutputKind::Dir => run_dir.to_path_buf(),
        OutputKind::File if raw == "-" => return Ok(raw.to_owned()),
        OutputKind::File => {
            let name: &std::ffi::OsStr = Path::new(raw).file_name().ok_or_else(|| {
                ErrorData::invalid_params(
                    format!("DR-MCP-0813: output {raw} names no file; pass a file name for the run directory"),
                    None,
                )
            })?;
            run_dir.join(name)
        }
    };
    target.into_os_string().into_string().map_err(|_| {
        ErrorData::invalid_params("DR-MCP-0813: the run directory path is not UTF-8", None)
    })
}

fn confine_inputs(parsed: &mut ParsedArgs<'_>, roots: &[PathBuf]) -> Result<(), ErrorData> {
    for (arg, value) in &mut parsed.options {
        let Some(raw) = value.as_mut() else {
            continue;
        };
        match arg.output {
            Some(OutputKind::File)
                if raw != "-" && Path::new(raw.as_str()).file_name().is_none() =>
            {
                return Err(ErrorData::invalid_params(
                    format!(
                        "DR-MCP-0813: output {raw} names no file; pass a file name for the run directory"
                    ),
                    None,
                ));
            }
            None if arg.path || path_looking(raw) => *raw = confine(roots, raw)?,
            Some(_) | None => {}
        }
    }
    for (slot, raw) in &mut parsed.positionals {
        if slot.path || path_looking(raw) {
            *raw = confine(roots, raw)?;
        }
    }
    Ok(())
}

fn build_argv(
    command: &CatalogCommand,
    parsed: ParsedArgs<'_>,
    run_dir: &Path,
) -> Result<Vec<String>, ErrorData> {
    let mut argv: Vec<String> = command.command.clone();
    let mut outputs_given: Vec<&str> = Vec::new();
    for (arg, value) in parsed.options {
        let value: Option<String> = match (value, arg.output) {
            (Some(raw), Some(kind)) => {
                outputs_given.push(arg.name.as_str());
                Some(redirect_output(kind, &raw, run_dir)?)
            }
            (value, _) => value,
        };
        if arg
            .long
            .as_deref()
            .is_some_and(|long: &str| FORCED_FLAGS.contains(&long))
        {
            continue;
        }
        match (&arg.long, value) {
            (Some(long), Some(value)) => argv.push(format!("--{long}={value}")),
            (Some(long), None) => argv.push(format!("--{long}")),
            (None, value) => {
                argv.push(format!("-{}", arg.short.unwrap_or_default()));
                argv.extend(value);
            }
        }
    }
    for long in command
        .args
        .iter()
        .filter(|arg: &&CatalogArg| {
            arg.output == Some(OutputKind::Dir) && !outputs_given.contains(&arg.name.as_str())
        })
        .filter_map(|arg: &CatalogArg| arg.long.as_ref())
    {
        argv.push(format!(
            "--{long}={}",
            redirect_output(OutputKind::Dir, "", run_dir)?
        ));
    }
    argv.extend(FORCED_FLAGS.iter().map(|flag: &&str| format!("--{flag}")));
    if !parsed.positionals.is_empty() {
        argv.push("--".to_owned());
        argv.extend(
            parsed
                .positionals
                .into_iter()
                .map(|(_, raw): (&CatalogArg, String)| raw),
        );
    }
    Ok(argv)
}

fn create_run_dir(root: &Path, runs: &AtomicU64) -> Result<PathBuf, ErrorData> {
    let parent: PathBuf = RUN_DIR_PARENT
        .iter()
        .fold(root.to_path_buf(), |dir: PathBuf, part: &&str| {
            dir.join(part)
        });
    std::fs::create_dir_all(&parent).map_err(|error: std::io::Error| {
        ErrorData::internal_error(
            format!("DR-MCP-0814: cannot create {}: {error}", parent.display()),
            None,
        )
    })?;
    let stamp: u64 =
        disrobe_core::time::now_secs().map_err(|error: disrobe_core::time::SourceDateError| {
            ErrorData::internal_error(format!("DR-MCP-0814: cannot read the clock: {error}"), None)
        })?;
    for _ in 0..MAX_RUN_DIR_ATTEMPTS {
        let sequence: u64 = runs.fetch_add(1, Ordering::Relaxed);
        let candidate: PathBuf = parent.join(format!("{stamp}-{}-{sequence}", std::process::id()));
        match std::fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(ErrorData::internal_error(
                    format!(
                        "DR-MCP-0814: cannot create {}: {error}",
                        candidate.display()
                    ),
                    None,
                ));
            }
        }
    }
    Err(ErrorData::internal_error(
        format!(
            "DR-MCP-0814: no fresh run directory under {} after {MAX_RUN_DIR_ATTEMPTS} attempts",
            parent.display()
        ),
        None,
    ))
}

impl RunPlan {
    fn execute(self) -> Result<RunCommandOut, ErrorData> {
        let started: Instant = Instant::now();
        let execution: Execution = CommandSpec::new(&self.program, self.timeout)
            .args(&self.argv)
            .current_dir(self.run_dir.clone())
            .env("NO_COLOR", "1")
            .capture_limits(MAX_CAPTURE_BYTES, MAX_CAPTURE_BYTES)
            .reap_descendants_on_exit()
            .run()
            .map_err(|error: ExecutionError| {
                ErrorData::internal_error(
                    format!(
                        "DR-MCP-0815: cannot run {}: {error}",
                        self.program.display()
                    ),
                    None,
                )
            })?;
        let duration_ms: u64 = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let (status, timed_out): (std::process::ExitStatus, bool) = match execution.completion {
            Completion::Exited(status) => (status, false),
            Completion::TimedOut(status) => (status, true),
        };
        let (stdout, stdout_truncated): (Vec<u8>, bool) = captured(execution.stdout);
        let (stderr, stderr_truncated): (Vec<u8>, bool) = captured(execution.stderr);
        let json: Option<serde_json::Value> = if stdout_truncated {
            None
        } else {
            serde_json::from_slice::<serde_json::Value>(&stdout).ok()
        };
        let stdout_text: Option<String> = if json.is_some() || stdout.is_empty() {
            None
        } else {
            Some(String::from_utf8_lossy(&stdout).into_owned())
        };
        let mut outputs: BTreeMap<String, OutputFileOut> = BTreeMap::new();
        let outputs_truncated: bool = list_outputs(&self.run_dir, &self.run_dir, 0, &mut outputs);
        Ok(RunCommandOut {
            command: self.command,
            argv: self.argv,
            run_dir: self.run_dir.display().to_string(),
            exit_code: status.code(),
            success: status.success() && !timed_out,
            timed_out,
            duration_ms,
            json,
            stdout: stdout_text,
            stdout_truncated,
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            stderr_truncated,
            outputs: outputs.into_values().collect(),
            outputs_truncated,
        })
    }
}

fn captured(outcome: CaptureOutcome) -> (Vec<u8>, bool) {
    match outcome {
        CaptureOutcome::Complete(stream)
        | CaptureOutcome::Failed {
            captured: stream, ..
        } => (stream.bytes, stream.truncated),
        CaptureOutcome::NotStarted
        | CaptureOutcome::WorkerPanicked
        | CaptureOutcome::WorkerUnresponsive => (Vec::new(), true),
    }
}

fn list_outputs(
    base: &Path,
    dir: &Path,
    depth: usize,
    out: &mut BTreeMap<String, OutputFileOut>,
) -> bool {
    if depth > MAX_LISTING_DEPTH {
        return true;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return true;
    };
    let mut truncated: bool = false;
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry: std::fs::DirEntry| entry.path())
        .collect();
    paths.sort();
    for path in paths {
        if out.len() >= MAX_LISTED_OUTPUTS {
            return true;
        }
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            truncated = true;
            continue;
        };
        if metadata.is_dir() {
            truncated |= list_outputs(base, &path, depth + 1, out);
        } else if metadata.is_file() {
            let relative: String = path.strip_prefix(base).map_or_else(
                |_| path.display().to_string(),
                |rel: &Path| {
                    rel.components()
                        .map(|c: Component<'_>| c.as_os_str().to_string_lossy().into_owned())
                        .collect::<Vec<String>>()
                        .join("/")
                },
            );
            let sha256: Option<String> = (metadata.len() <= MAX_HASHED_FILE_BYTES)
                .then(|| hash_file(&path))
                .flatten();
            out.insert(
                relative.clone(),
                OutputFileOut {
                    path: relative,
                    size: metadata.len(),
                    sha256,
                },
            );
        }
    }
    truncated
}

fn hash_file(path: &Path) -> Option<String> {
    let mut file: std::fs::File = std::fs::File::open(path).ok()?;
    let mut hasher: sha2::Sha256 = sha2::Sha256::new();
    let mut buffer: Vec<u8> = vec![0; 64 * 1024];
    loop {
        let read: usize = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    Some(hex32(&digest))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use clap::{Arg, ArgAction, Command, value_parser};
    use disrobe_core::scratch::ScratchDir;

    fn input() -> Arg {
        Arg::new("path")
            .value_parser(value_parser!(PathBuf))
            .required(true)
    }

    fn catalog() -> CommandCatalog {
        let root: Command = Command::new("disrobe")
            .arg(
                Arg::new("json")
                    .long("json")
                    .global(true)
                    .action(ArgAction::SetTrue),
            )
            .arg(
                Arg::new("in_place")
                    .long("in-place")
                    .global(true)
                    .action(ArgAction::SetTrue),
            )
            .subcommand(
                Command::new("strings")
                    .arg(input())
                    .arg(Arg::new("min_len").long("min-len")),
            )
            .subcommand(
                Command::new("native")
                    .subcommand(
                        Command::new("unpack")
                            .arg(input())
                            .arg(
                                Arg::new("out")
                                    .short('o')
                                    .long("out")
                                    .value_parser(value_parser!(PathBuf)),
                            )
                            .arg(Arg::new("neutralize").long("neutralize"))
                            .arg(
                                Arg::new("allow_dynamic")
                                    .long("allow-dynamic")
                                    .action(ArgAction::SetTrue),
                            ),
                    )
                    .subcommand(Command::new("patch").arg(input())),
            )
            .subcommand(
                Command::new("extract").arg(input()).arg(
                    Arg::new("out")
                        .long("out")
                        .value_name("DIR")
                        .value_parser(value_parser!(PathBuf)),
                ),
            )
            .subcommand(Command::new("install").arg(Arg::new("tool")));
        CommandCatalog::from_clap(PathBuf::from("disrobe"), &root)
    }

    fn words(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    fn refusal<T: std::fmt::Debug>(result: Result<T, ErrorData>) -> String {
        match result {
            Ok(value) => panic!("expected a refusal, got {value:?}"),
            Err(error) => error.message.to_string(),
        }
    }

    #[test]
    fn the_catalog_keeps_allowlisted_leaves_and_drops_refused_flags() {
        let catalog: CommandCatalog = catalog();
        let keys: Vec<&str> = catalog.commands.keys().map(String::as_str).collect();
        assert_eq!(keys, ["extract", "native unpack", "strings"]);
        let unpack: &CatalogCommand = catalog.command(&words("native unpack")).unwrap();
        assert!(
            unpack
                .args
                .iter()
                .all(|arg: &CatalogArg| arg.name != "allow-dynamic")
        );
        let out: &CatalogArg = unpack
            .args
            .iter()
            .find(|arg: &&CatalogArg| arg.name == "out")
            .unwrap();
        assert_eq!(out.output, Some(OutputKind::File));
        let extract: &CatalogCommand = catalog.command(&words("extract")).unwrap();
        assert_eq!(extract.args[1].output, Some(OutputKind::Dir));
        let globals: Vec<&str> = catalog
            .globals
            .iter()
            .map(|arg: &CatalogArg| arg.name.as_str())
            .collect();
        assert_eq!(globals, ["json"]);
    }

    #[test]
    fn arguments_parse_against_the_subcommand_and_refuse_by_name() {
        let catalog: CommandCatalog = catalog();
        let unpack: &CatalogCommand = catalog.command(&words("native unpack")).unwrap();
        let parsed: ParsedArgs<'_> = parse_args(
            unpack,
            &catalog.globals,
            &words("in.bin -o x.bin --neutralize=propose --json"),
        )
        .unwrap();
        let options: Vec<(&str, Option<&str>)> = parsed
            .options
            .iter()
            .map(|(arg, value): &(&CatalogArg, Option<String>)| {
                (arg.name.as_str(), value.as_deref())
            })
            .collect();
        assert_eq!(
            options,
            [
                ("out", Some("x.bin")),
                ("neutralize", Some("propose")),
                ("json", None)
            ]
        );
        assert_eq!(parsed.positionals.len(), 1);
        for (args, code) in [
            ("in.bin --allow-dynamic", "DR-MCP-0807"),
            ("in.bin --in-place", "DR-MCP-0807"),
            ("in.bin --neutralize apply", "DR-MCP-0807"),
            ("in.bin --bogus", "DR-MCP-0809"),
            ("in.bin -x", "DR-MCP-0809"),
            ("in.bin -- more", "DR-MCP-0808"),
            ("in.bin second.bin", "DR-MCP-0810"),
            ("in.bin --out", "DR-MCP-0810"),
        ] {
            let message: String = refusal(parse_args(unpack, &catalog.globals, &words(args)));
            assert!(message.starts_with(code), "{args}: {message}");
        }
    }

    #[test]
    fn inputs_are_confined_to_the_roots_and_outputs_land_in_the_run_directory() {
        let root: ScratchDir = ScratchDir::create("mcp-command-unit").unwrap();
        let outside: ScratchDir = ScratchDir::create("mcp-command-unit-outside").unwrap();
        std::fs::write(root.path().join("in.bin"), b"x").unwrap();
        std::fs::write(outside.path().join("stray.bin"), b"x").unwrap();
        let roots: Vec<PathBuf> = vec![root.path().canonicalize().unwrap()];
        let catalog: CommandCatalog = catalog();
        let unpack: &CatalogCommand = catalog.command(&words("native unpack")).unwrap();
        let stray: String = outside.path().join("stray.bin").display().to_string();
        let mut escaping: ParsedArgs<'_> = parse_args(unpack, &catalog.globals, &[stray]).unwrap();
        assert!(refusal(confine_inputs(&mut escaping, &roots)).starts_with("DR-MCP-0811"));
        let mut climbing: ParsedArgs<'_> =
            parse_args(unpack, &catalog.globals, &words("../in.bin")).unwrap();
        assert!(refusal(confine_inputs(&mut climbing, &roots)).starts_with("DR-MCP-0811"));

        let mut parsed: ParsedArgs<'_> = parse_args(
            unpack,
            &catalog.globals,
            &words("in.bin -o ../../elsewhere/x.bin --json"),
        )
        .unwrap();
        confine_inputs(&mut parsed, &roots).unwrap();
        let run_dir: PathBuf = create_run_dir(&roots[0], &AtomicU64::new(0)).unwrap();
        assert!(run_dir.starts_with(roots[0].join(".disrobe").join("mcp")));
        let argv: Vec<String> = build_argv(unpack, parsed, &run_dir).unwrap();
        let input: String = roots[0].join("in.bin").display().to_string();
        let output: String = format!("--out={}", run_dir.join("x.bin").display());
        assert_eq!(
            argv,
            [
                "native",
                "unpack",
                output.as_str(),
                "--json",
                "--no-cache",
                "--",
                input.as_str()
            ]
        );

        let extract: &CatalogCommand = catalog.command(&words("extract")).unwrap();
        let parsed: ParsedArgs<'_> =
            parse_args(extract, &catalog.globals, &words("in.bin")).unwrap();
        let argv: Vec<String> = build_argv(extract, parsed, &run_dir).unwrap();
        assert!(
            argv.contains(&format!("--out={}", run_dir.display())),
            "{argv:?}"
        );
    }
}
