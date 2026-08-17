#![allow(clippy::needless_pass_by_value)]
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::output::{OutputFormat, emit};

pub(crate) const CONFIG_FILE_NAME: &str = ".disrobe.toml";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ConfigVerbosity {
    #[default]
    Warn,
    Info,
    Debug,
    Trace,
}

impl ConfigVerbosity {
    #[inline]
    pub(crate) const fn as_count(self) -> u8 {
        match self {
            Self::Warn => 0,
            Self::Info => 1,
            Self::Debug => 2,
            Self::Trace => 3,
        }
    }

    #[inline]
    const fn label(self) -> &'static str {
        match self {
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ConfigColor {
    #[default]
    Auto,
    Always,
    Never,
}

impl ConfigColor {
    #[inline]
    const fn label(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Always => "always",
            Self::Never => "never",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ConfigProgress {
    #[default]
    Auto,
    Always,
    Never,
}

impl ConfigProgress {
    #[inline]
    const fn label(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Always => "always",
            Self::Never => "never",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct OutputConfig {
    pub(crate) dir: Option<PathBuf>,
    pub(crate) emit: Option<Vec<String>>,
    pub(crate) json: Option<bool>,
    pub(crate) ndjson: Option<bool>,
    pub(crate) sarif: Option<bool>,
    pub(crate) color: Option<ConfigColor>,
    pub(crate) progress: Option<ConfigProgress>,
    pub(crate) verbosity: Option<ConfigVerbosity>,
    pub(crate) quiet: Option<bool>,
    pub(crate) redact: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ExecutionConfig {
    pub(crate) threads: Option<u32>,
    pub(crate) force: Option<bool>,
    pub(crate) in_place: Option<bool>,
    pub(crate) no_cache: Option<bool>,
    pub(crate) cache_dir: Option<PathBuf>,
    pub(crate) dry_run: Option<bool>,
    pub(crate) max_depth: Option<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct BackendsConfig {
    pub(crate) py: Option<String>,
    pub(crate) jvm: Option<String>,
    pub(crate) dotnet: Option<String>,
    pub(crate) wasm: Option<String>,
    pub(crate) lua: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct PassesConfig {
    pub(crate) enable: Option<Vec<String>>,
    pub(crate) disable: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct DisrobeConfig {
    pub(crate) output: OutputConfig,
    pub(crate) execution: ExecutionConfig,
    pub(crate) backends: BackendsConfig,
    pub(crate) passes: PassesConfig,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ResolvedConfig {
    pub(crate) config: DisrobeConfig,
    pub(crate) source: Option<PathBuf>,
}

impl DisrobeConfig {
    fn parse_str(text: &str, origin: &Path) -> miette::Result<Self> {
        toml::from_str::<Self>(text).map_err(|e: toml::de::Error| {
            miette::miette!(
                "DR-CLI-0330: malformed `.disrobe.toml` at {}: {e}",
                origin.display()
            )
        })
    }

    fn read_file(path: &Path) -> miette::Result<Self> {
        let text: String = std::fs::read_to_string(path).map_err(|e: std::io::Error| {
            miette::miette!(
                "DR-CLI-0331: cannot read config file {}: {e}",
                path.display()
            )
        })?;
        Self::parse_str(&text, path)
    }
}

fn discover_from(start: &Path) -> Option<PathBuf> {
    let mut cursor: Option<&Path> = Some(start);
    while let Some(dir) = cursor {
        let candidate: PathBuf = dir.join(CONFIG_FILE_NAME);
        if candidate.is_file() {
            return Some(candidate);
        }
        cursor = dir.parent();
    }
    None
}

pub(crate) fn resolve(explicit: Option<&Path>) -> miette::Result<ResolvedConfig> {
    if let Some(path) = explicit {
        if !path.is_file() {
            return Err(miette::miette!(
                "DR-CLI-0332: --config path does not exist: {}",
                path.display()
            ));
        }
        let config: DisrobeConfig = DisrobeConfig::read_file(path)?;
        return Ok(ResolvedConfig {
            config,
            source: Some(path.to_path_buf()),
        });
    }
    let cwd: PathBuf = std::env::current_dir()
        .map_err(|e: std::io::Error| miette::miette!("DR-CLI-0333: cannot read cwd: {e}"))?;
    match discover_from(&cwd) {
        Some(found) => {
            let config: DisrobeConfig = DisrobeConfig::read_file(&found)?;
            Ok(ResolvedConfig {
                config,
                source: Some(found),
            })
        }
        None => Ok(ResolvedConfig::default()),
    }
}

const TEMPLATE: &str = r#"# .disrobe.toml - disrobe project configuration
#
# Every key is optional. Values set here become the defaults for matching CLI
# flags; an explicit flag on the command line always wins. Unknown keys are a
# hard error, so a typo fails fast instead of being silently ignored.

[output]
# Default output directory for chain/auto runs (per-command default if unset).
# dir = "out"
# Default emit kinds for passes that accept --emit.
# emit = ["source", "manifest"]
# Force a machine-readable default (CLI --json/--ndjson/--sarif still override).
# json = false
# ndjson = false
# sarif = false
# ANSI color: "auto" | "always" | "never".
# color = "auto"
# Progress bar: "auto" | "always" | "never".
# progress = "auto"
# Log verbosity: "warn" | "info" | "debug" | "trace".
# verbosity = "warn"
# quiet = false
# Replace detected secret values with stable SHA-256 sentinels.
# redact = false

[execution]
# Worker thread-pool size (defaults to the detected CPU count).
# threads = 8
# force = false
# in_place = false
# no_cache = false
# Directory for the content-addressed .dr envelope cache (defaults to the OS cache dir).
# cache_dir = "/var/cache/disrobe"
# dry_run = false
# Default maximum chain depth for `auto`.
# max_depth = 8

[backends]
# Preferred external decompiler per language when a pass exposes --backend.
# py = "native"       # native (in-tree engine; the only supported Python decompiler)
# jvm = "cfr"         # cfr | vineflower | procyon | jadx
# dotnet = "ilspy"    # ilspy | dnspy | dnspyex | de4dot
# wasm = "wat"        # json | rust | ts | wat | c
# lua = "native"

[passes]
# Restrict chain runs to these passes (empty/unset means "all registered").
# enable = ["pyarmor.unpack", "py.decompile"]
# Never run these passes, even if a detector would pick them.
# disable = ["native.packer-unpack"]
"#;

#[derive(Debug, Serialize)]
struct ConfigInitReport {
    path: String,
    created: bool,
}

fn run_init(out: Option<PathBuf>, force: bool, fmt: OutputFormat) -> miette::Result<()> {
    let path: PathBuf = out.unwrap_or_else(|| PathBuf::from(CONFIG_FILE_NAME));
    if path.exists() && !force {
        return Err(miette::miette!(
            "DR-CLI-0334: {} already exists; pass --force to overwrite",
            path.display()
        ));
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e: std::io::Error| {
            miette::miette!(
                "DR-CLI-0335: cannot create config parent dir {}: {e}",
                parent.display()
            )
        })?;
    }
    std::fs::write(&path, TEMPLATE.as_bytes()).map_err(|e: std::io::Error| {
        miette::miette!(
            "DR-CLI-0336: cannot write config template {}: {e}",
            path.display()
        )
    })?;
    let report: ConfigInitReport = ConfigInitReport {
        path: path.display().to_string(),
        created: true,
    };
    emit(fmt, &report, || {
        println!("wrote config template: {}", report.path);
    })
}

#[derive(Debug, Serialize)]
struct ConfigShowReport {
    source: Option<String>,
    config: DisrobeConfig,
}

fn run_show(explicit: Option<&Path>, fmt: OutputFormat) -> miette::Result<()> {
    let resolved: ResolvedConfig = resolve(explicit)?;
    let report: ConfigShowReport = ConfigShowReport {
        source: resolved
            .source
            .as_ref()
            .map(|p: &PathBuf| p.display().to_string()),
        config: resolved.config,
    };
    emit(fmt, &report, || {
        println!("disrobe config");
        match report.source.as_deref() {
            Some(src) => println!("  source:     {src}"),
            None => println!("  source:     (built-in defaults; no .disrobe.toml discovered)"),
        }
        let c: &DisrobeConfig = &report.config;
        println!("  [output]");
        print_opt(
            "    dir",
            c.output
                .dir
                .as_ref()
                .map(|p: &PathBuf| p.display().to_string()),
        );
        print_opt(
            "    emit",
            c.output.emit.as_ref().map(|v: &Vec<String>| v.join(",")),
        );
        print_opt("    json", c.output.json.map(bool_label));
        print_opt("    ndjson", c.output.ndjson.map(bool_label));
        print_opt("    sarif", c.output.sarif.map(bool_label));
        print_opt(
            "    color",
            c.output.color.map(|v: ConfigColor| v.label().to_string()),
        );
        print_opt(
            "    progress",
            c.output
                .progress
                .map(|v: ConfigProgress| v.label().to_string()),
        );
        print_opt(
            "    verbosity",
            c.output
                .verbosity
                .map(|v: ConfigVerbosity| v.label().to_string()),
        );
        print_opt("    quiet", c.output.quiet.map(bool_label));
        print_opt("    redact", c.output.redact.map(bool_label));
        println!("  [execution]");
        print_opt(
            "    threads",
            c.execution.threads.map(|v: u32| v.to_string()),
        );
        print_opt("    force", c.execution.force.map(bool_label));
        print_opt("    in_place", c.execution.in_place.map(bool_label));
        print_opt("    no_cache", c.execution.no_cache.map(bool_label));
        print_opt(
            "    cache_dir",
            c.execution
                .cache_dir
                .as_ref()
                .map(|p: &PathBuf| p.display().to_string()),
        );
        print_opt("    dry_run", c.execution.dry_run.map(bool_label));
        print_opt(
            "    max_depth",
            c.execution.max_depth.map(|v: u8| v.to_string()),
        );
        println!("  [backends]");
        print_opt("    py", c.backends.py.clone());
        print_opt("    jvm", c.backends.jvm.clone());
        print_opt("    dotnet", c.backends.dotnet.clone());
        print_opt("    wasm", c.backends.wasm.clone());
        print_opt("    lua", c.backends.lua.clone());
        println!("  [passes]");
        print_opt(
            "    enable",
            c.passes.enable.as_ref().map(|v: &Vec<String>| v.join(",")),
        );
        print_opt(
            "    disable",
            c.passes.disable.as_ref().map(|v: &Vec<String>| v.join(",")),
        );
    })
}

#[inline]
const fn bool_label(b: bool) -> &'static str {
    if b { "true" } else { "false" }
}

fn print_opt<T: std::fmt::Display>(label: &str, value: Option<T>) {
    match value {
        Some(v) => println!("{label}: {v}"),
        None => println!("{label}: (unset)"),
    }
}

#[derive(clap::Subcommand, Debug)]
pub(crate) enum ConfigCmd {
    #[command(
        about = "print the resolved effective config (built-in defaults merged with the discovered or --config file)"
    )]
    Show,
    #[command(about = "write a documented `.disrobe.toml` template")]
    Init {
        #[arg(
            short,
            long,
            value_name = "PATH",
            help = "output path (default: ./.disrobe.toml)"
        )]
        out: Option<PathBuf>,
        #[arg(long, help = "overwrite an existing file")]
        force: bool,
    },
}

pub(crate) fn run(
    action: Option<ConfigCmd>,
    explicit: Option<&Path>,
    fmt: OutputFormat,
) -> miette::Result<()> {
    match action {
        None | Some(ConfigCmd::Show) => run_show(explicit, fmt),
        Some(ConfigCmd::Init { out, force }) => run_init(out, force, fmt),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use disrobe_core::scratch::ScratchDir;

    fn tmp_dir(stem: &str) -> ScratchDir {
        let purpose: String = format!("disrobe-cfg-{stem}");
        ScratchDir::create(&purpose).expect("create scratch directory")
    }

    #[test]
    fn empty_config_is_all_defaults() {
        let here_scratch: ScratchDir = tmp_dir("empty");
        let here: PathBuf = here_scratch.path().to_path_buf();
        let path: PathBuf = here.join(CONFIG_FILE_NAME);
        std::fs::write(&path, b"").expect("write empty");
        let resolved: ResolvedConfig = resolve(Some(&path)).expect("resolve empty");
        assert_eq!(resolved.config, DisrobeConfig::default());
        assert_eq!(resolved.source.as_deref(), Some(path.as_path()));
    }

    #[test]
    fn parses_full_document() {
        let doc: &str = r#"
            [output]
            dir = "build/out"
            emit = ["source", "manifest"]
            json = true
            color = "never"
            verbosity = "debug"
            redact = true

            [execution]
            threads = 4
            force = true
            max_depth = 16

            [backends]
            py = "native"

            [passes]
            disable = ["native.packer-unpack"]
        "#;
        let here_scratch: ScratchDir = tmp_dir("full");
        let here: PathBuf = here_scratch.path().to_path_buf();
        let cfg: DisrobeConfig = DisrobeConfig::parse_str(doc, &here).expect("parse full");
        assert_eq!(cfg.output.dir.as_deref(), Some(Path::new("build/out")));
        assert_eq!(
            cfg.output.emit.as_deref(),
            Some(["source".to_string(), "manifest".to_string()].as_slice())
        );
        assert_eq!(cfg.output.json, Some(true));
        assert_eq!(cfg.output.color, Some(ConfigColor::Never));
        assert_eq!(cfg.output.verbosity, Some(ConfigVerbosity::Debug));
        assert_eq!(cfg.output.redact, Some(true));
        assert_eq!(cfg.execution.threads, Some(4));
        assert_eq!(cfg.execution.force, Some(true));
        assert_eq!(cfg.execution.max_depth, Some(16));
        assert_eq!(cfg.backends.py.as_deref(), Some("native"));
        assert_eq!(
            cfg.passes.disable.as_deref(),
            Some(["native.packer-unpack".to_string()].as_slice())
        );
    }

    #[test]
    fn unknown_key_is_rejected() {
        let doc: &str = "[output]\nnonsense_key = 3\n";
        let here_scratch: ScratchDir = tmp_dir("unknown");
        let here: PathBuf = here_scratch.path().to_path_buf();
        let err: miette::Report = DisrobeConfig::parse_str(doc, &here).expect_err("must reject");
        let msg: String = format!("{err}");
        assert!(msg.contains("DR-CLI-0330"), "got: {msg}");
    }

    #[test]
    fn unknown_top_level_table_is_rejected() {
        let doc: &str = "[nope]\nx = 1\n";
        let here_scratch: ScratchDir = tmp_dir("unknown-top");
        let here: PathBuf = here_scratch.path().to_path_buf();
        assert!(DisrobeConfig::parse_str(doc, &here).is_err());
    }

    #[test]
    fn explicit_missing_path_errors() {
        let scratch: ScratchDir = ScratchDir::create("disrobe-cfg-definitely-missing-xyzzy")
            .expect("create scratch directory");
        let missing: PathBuf = scratch.path().join("missing.toml");
        let err: miette::Report = resolve(Some(&missing)).expect_err("missing explicit must error");
        assert!(format!("{err}").contains("DR-CLI-0332"));
    }

    #[test]
    fn discover_walks_up_to_ancestor() {
        let root_scratch: ScratchDir = tmp_dir("walkup");
        let root: PathBuf = root_scratch.path().to_path_buf();
        let nested: PathBuf = root.join("a").join("b").join("c");
        std::fs::create_dir_all(&nested).expect("mk nested");
        let cfg_path: PathBuf = root.join(CONFIG_FILE_NAME);
        std::fs::write(&cfg_path, b"[execution]\nthreads = 2\n").expect("write cfg");
        let found: PathBuf = discover_from(&nested).expect("should find ancestor cfg");
        assert_eq!(found, cfg_path);
    }

    #[test]
    fn discover_returns_none_when_absent() {
        let root_scratch: ScratchDir = tmp_dir("absent");
        let root: PathBuf = root_scratch.path().to_path_buf();
        assert!(discover_from(&root).is_none());
    }

    #[test]
    fn template_round_trips_through_parser() {
        let here_scratch: ScratchDir = tmp_dir("template");
        let here: PathBuf = here_scratch.path().to_path_buf();
        let parsed: DisrobeConfig =
            DisrobeConfig::parse_str(TEMPLATE, &here).expect("template parses");
        assert_eq!(parsed, DisrobeConfig::default());
    }

    #[test]
    fn verbosity_count_mapping() {
        assert_eq!(ConfigVerbosity::Warn.as_count(), 0);
        assert_eq!(ConfigVerbosity::Info.as_count(), 1);
        assert_eq!(ConfigVerbosity::Debug.as_count(), 2);
        assert_eq!(ConfigVerbosity::Trace.as_count(), 3);
    }
}
