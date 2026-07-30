#![deny(unreachable_pub)]
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::redundant_pub_crate
)]

mod attack_surface;
mod card;
mod catalog_counts;
mod codegen;
mod crossdata;
mod datamodel;
mod demo;
mod errdocs;
mod evidence;
mod evidence_tiers;
mod facts;
mod fileio;
mod floors;
mod fuzz_scope;
mod graphs;
mod local_tags;
mod metrics;
mod packer_roster;
#[cfg(feature = "playground")]
mod playground;
mod plugins;
mod prepush;
mod readme_stats;
mod regen;
mod sync;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use camino::Utf8PathBuf;
use clap::{Parser, Subcommand};
use eyre::{Result, WrapErr, bail};
use serde_json::{Map, Value, json};

use crate::codegen::{CodegenSummary, SchemaArtifact, load_schemas, write_bindings};

#[derive(Parser, Debug)]
#[command(name = "xtask", about = "disrobe repo automation")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    GenBindings {
        #[arg(long)]
        out_dir: Option<PathBuf>,
        #[arg(long, action = clap::ArgAction::SetTrue)]
        check: bool,
    },
    BakeFixtures {
        #[arg(long, action = clap::ArgAction::SetTrue)]
        dry_run: bool,
        #[arg(long, action = clap::ArgAction::SetTrue)]
        edge_cases: bool,
    },
    ReleasePackage,
    Schemas {
        #[arg(long, action = clap::ArgAction::SetTrue)]
        check: bool,
    },
    GenErrorDocs {
        #[arg(long, action = clap::ArgAction::SetTrue)]
        check: bool,
    },
    Regen {
        #[arg(long, action = clap::ArgAction::SetTrue)]
        check: bool,
    },
    Metrics {
        #[arg(long, action = clap::ArgAction::SetTrue)]
        write: bool,
        #[arg(long, action = clap::ArgAction::SetTrue)]
        check: bool,
    },
    Graphs {
        #[arg(long, action = clap::ArgAction::SetTrue)]
        check: bool,
    },
    Demo {
        #[arg(long, action = clap::ArgAction::SetTrue)]
        check: bool,
    },
    Card {
        #[arg(long, action = clap::ArgAction::SetTrue)]
        check: bool,
    },
    Plugins {
        #[arg(long, action = clap::ArgAction::SetTrue)]
        check: bool,
    },
    Sync {
        #[arg(long, action = clap::ArgAction::SetTrue)]
        check: bool,
    },
    Evidence {
        #[arg(long, action = clap::ArgAction::SetTrue)]
        check: bool,
        #[arg(long, action = clap::ArgAction::SetTrue)]
        list: bool,
    },
    Prepush {
        #[arg(long, action = clap::ArgAction::SetTrue)]
        full: bool,
    },
    SetupHooks,
    #[cfg(feature = "playground")]
    Playground {
        #[arg(long)]
        sample_per_kind: Option<usize>,
        #[arg(long, action = clap::ArgAction::SetTrue)]
        fail_on_circular: bool,
    },
}

fn main() -> ExitCode {
    let cli: Cli = Cli::parse();
    let result: Result<()> = match cli.command {
        Cmd::GenBindings { out_dir, check } => run_gen_bindings(out_dir, check),
        Cmd::BakeFixtures {
            dry_run,
            edge_cases,
        } => run_bake_fixtures(dry_run, edge_cases),
        Cmd::ReleasePackage => run_release_package(),
        Cmd::Schemas { check } => run_schemas(check),
        Cmd::GenErrorDocs { check } => run_gen_error_docs(check),
        Cmd::Regen { check } => run_regen(check),
        Cmd::Metrics { write, check } => run_metrics(write, check),
        Cmd::Graphs { check } => run_graphs(check),
        Cmd::Demo { check } => run_demo(check),
        Cmd::Card { check } => run_card(check),
        Cmd::Plugins { check } => run_plugins(check),
        Cmd::Sync { check } => run_sync(check),
        Cmd::Evidence { check, list } => run_evidence(check, list),
        Cmd::Prepush { full } => run_prepush(full),
        Cmd::SetupHooks => run_setup_hooks(),
        #[cfg(feature = "playground")]
        Cmd::Playground {
            sample_per_kind,
            fail_on_circular,
        } => run_playground(sample_per_kind, fail_on_circular),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("xtask: {err:?}");
            ExitCode::FAILURE
        }
    }
}

fn workspace_root() -> Result<PathBuf> {
    let manifest: &str = env!("CARGO_MANIFEST_DIR");
    let here: PathBuf = PathBuf::from(manifest);
    let Some(parent): Option<&Path> = here.parent() else {
        bail!("xtask manifest dir has no parent: {}", here.display());
    };
    Ok(parent.to_path_buf())
}

fn run_bake_fixtures(dry_run: bool, edge_cases: bool) -> Result<()> {
    let root: PathBuf = workspace_root()?;
    let corpus_dir: PathBuf = root.join("corpus");
    if !corpus_dir.is_dir() {
        bail!("corpus dir missing: {}", corpus_dir.display());
    }
    let plan: BakePlan = if cfg!(windows) {
        let script: PathBuf = corpus_dir.join("generate.ps1");
        if !script.is_file() {
            bail!("corpus/generate.ps1 missing");
        }
        let mut flags: Vec<&'static str> = Vec::with_capacity(2);
        if dry_run {
            flags.push("-DryRun");
        }
        if edge_cases {
            flags.push("-EdgeCases");
        }
        BakePlan {
            program: "powershell".to_owned(),
            script,
            extra_flags: flags,
            powershell_wrap: true,
        }
    } else {
        let script: PathBuf = corpus_dir.join("generate.sh");
        if !script.is_file() {
            bail!("corpus/generate.sh missing");
        }
        let mut flags: Vec<&'static str> = Vec::with_capacity(2);
        if dry_run {
            flags.push("--dry-run");
        }
        if edge_cases {
            flags.push("--edge-cases");
        }
        BakePlan {
            program: "bash".to_owned(),
            script,
            extra_flags: flags,
            powershell_wrap: false,
        }
    };

    let mut cmd: Command = Command::new(&plan.program);
    if plan.powershell_wrap {
        cmd.args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ]);
    }
    cmd.arg(&plan.script);
    for flag in &plan.extra_flags {
        cmd.arg(flag);
    }
    cmd.current_dir(&corpus_dir);
    cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    println!(
        "xtask bake-fixtures: invoking {} {} ({}dry-run{})",
        plan.program,
        plan.script.display(),
        if dry_run { "" } else { "no " },
        if edge_cases { ", edge-cases only" } else { "" }
    );
    let status: std::process::ExitStatus = cmd
        .status()
        .with_context_msg(|| format!("spawning {}", plan.program))?;
    if !status.success() {
        bail!("corpus generator exited with {status}");
    }
    Ok(())
}

#[derive(Debug)]
struct BakePlan {
    program: String,
    script: PathBuf,
    extra_flags: Vec<&'static str>,
    powershell_wrap: bool,
}

#[cfg(feature = "playground")]
fn run_playground(sample_per_kind: Option<usize>, fail_on_circular: bool) -> Result<()> {
    let root: PathBuf = workspace_root()?;
    let opts: playground::PlaygroundOptions = playground::PlaygroundOptions {
        sample_per_kind,
        fail_under_circularity: fail_on_circular,
    };
    playground::run(&root, &opts)
}

pub(crate) fn run_schemas(check: bool) -> Result<()> {
    let root: PathBuf = workspace_root()?;
    let out_dir: PathBuf = root.join("schemas").join("v0").join("json");
    let envelope: Value = envelope_schema();
    let manifest: Value = freezer_manifest_schema();
    let extraction: Value = extraction_result_schema();
    let detection: Value = pyarmor_detection_schema();
    let rendered: [(&str, &Value); 4] = [
        ("dr-envelope.schema.json", &envelope),
        ("freezer-manifest.schema.json", &manifest),
        ("extraction-result.schema.json", &extraction),
        ("pyarmor-detection.schema.json", &detection),
    ];

    if check {
        let tmp: tempfile::TempDir = tempfile::tempdir()
            .with_context_msg(|| "creating temp dir for schemas check".to_owned())?;
        for (name, value) in rendered {
            write_json(&tmp.path().join(name), value)?;
        }
        let mut stale: Vec<String> = Vec::new();
        fileio::diff_generated_tree(tmp.path(), &out_dir, &mut stale)?;
        if stale.is_empty() {
            println!(
                "xtask schemas --check: {} JSON Schema(s) match regeneration",
                rendered.len()
            );
            Ok(())
        } else {
            bail!(
                "committed JSON Schemas are stale; run `cargo run -p xtask -- schemas`:\n  {}",
                stale.join("\n  ")
            )
        }
    } else {
        fs::create_dir_all(&out_dir)
            .with_context_msg(|| format!("creating {}", out_dir.display()))?;
        for (name, value) in rendered {
            write_json(&out_dir.join(name), value)?;
        }
        println!(
            "xtask schemas: wrote {} JSON Schemas under {}",
            rendered.len(),
            out_dir.display()
        );
        Ok(())
    }
}

pub(crate) fn run_gen_error_docs(check: bool) -> Result<()> {
    let root: PathBuf = workspace_root()?;
    if check {
        let tmp: tempfile::TempDir = tempfile::tempdir()
            .with_context_msg(|| "creating temp dir for error-docs check".to_owned())?;
        let written: usize = errdocs::generate_into(&root, tmp.path())?;
        let mut stale: Vec<String> = Vec::new();
        fileio::diff_generated_tree(tmp.path(), &errdocs::errors_doc_dir(&root), &mut stale)?;
        if stale.is_empty() {
            println!(
                "xtask gen-error-docs --check: {written} error-code page(s) + index match regeneration"
            );
            Ok(())
        } else {
            bail!(
                "committed error docs are stale; run `cargo run -p xtask -- gen-error-docs`:\n  {}",
                stale.join("\n  ")
            )
        }
    } else {
        let written: usize = errdocs::generate(&root)?;
        println!(
            "xtask gen-error-docs: wrote {written} error-code page(s) + index under {}",
            errdocs::errors_doc_dir(&root).display()
        );
        Ok(())
    }
}

fn run_regen(check: bool) -> Result<()> {
    let root: PathBuf = workspace_root()?;
    regen::run(&root, check)
}

fn run_metrics(write: bool, check: bool) -> Result<()> {
    let root: PathBuf = workspace_root()?;
    let mode: metrics::Mode = match (write, check) {
        (_, true) => metrics::Mode::Check,
        (true, false) => metrics::Mode::Write,
        (false, false) => bail!("specify --write to rewrite markers or --check to verify them"),
    };
    metrics::run(&root, mode)
}

fn run_graphs(check: bool) -> Result<()> {
    let root: PathBuf = workspace_root()?;
    graphs::run(&root, check)
}

fn run_demo(check: bool) -> Result<()> {
    let root: PathBuf = workspace_root()?;
    demo::run(&root, check)
}

fn run_card(check: bool) -> Result<()> {
    let root: PathBuf = workspace_root()?;
    card::run(&root, check)
}

fn run_plugins(check: bool) -> Result<()> {
    let root: PathBuf = workspace_root()?;
    plugins::run(&root, check)
}

fn run_sync(check: bool) -> Result<()> {
    let root: PathBuf = workspace_root()?;
    sync::run(&root, check)
}

fn run_prepush(full: bool) -> Result<()> {
    let root: PathBuf = workspace_root()?;
    prepush::run(&root, full)
}

fn run_setup_hooks() -> Result<()> {
    let root: PathBuf = workspace_root()?;
    prepush::setup_hooks(&root)
}

fn run_evidence(check: bool, list: bool) -> Result<()> {
    let root: PathBuf = workspace_root()?;
    let mode: evidence::Mode = if list {
        evidence::Mode::List
    } else if check {
        evidence::Mode::Check
    } else {
        evidence::Mode::Render
    };
    evidence::run(&root, mode)
}

pub(crate) fn run_gen_bindings(out_dir: Option<PathBuf>, check: bool) -> Result<()> {
    let root: PathBuf = workspace_root()?;
    let schemas_dir: PathBuf = root.join("schemas").join("v0").join("json");
    if !schemas_dir.is_dir() {
        run_schemas(false)?;
    }
    let bindings_root: PathBuf = out_dir.unwrap_or_else(|| root.join("bindings"));
    let py_dir: PathBuf = bindings_root.join("python");
    let ts_dir: PathBuf = bindings_root.join("typescript");
    let schemas: Vec<SchemaArtifact> = load_schemas(&schemas_dir)?;

    if check {
        let tmp: tempfile::TempDir = tempfile::tempdir()
            .with_context_msg(|| "creating temp dir for bindings check".to_owned())?;
        let tmp_py: PathBuf = tmp.path().join("python");
        let tmp_ts: PathBuf = tmp.path().join("typescript");
        write_bindings(&schemas, &tmp_py, &tmp_ts)?;
        let mut stale: Vec<String> = Vec::new();
        fileio::diff_generated_flat(&tmp_py, &py_dir, is_python_binding_artifact, &mut stale)?;
        fileio::diff_generated_flat(&tmp_ts, &ts_dir, is_typescript_binding_artifact, &mut stale)?;
        if stale.is_empty() {
            println!(
                "xtask gen-bindings --check: {} schema(s) match regeneration",
                schemas.len()
            );
            Ok(())
        } else {
            bail!(
                "committed bindings are stale; run `cargo run -p xtask -- gen-bindings`:\n  {}",
                stale.join("\n  ")
            )
        }
    } else {
        let summary: CodegenSummary = write_bindings(&schemas, &py_dir, &ts_dir)?;
        println!(
            "xtask gen-bindings: python {written_py} written, {skipped_py} skipped in {py_path}; typescript {written_ts} written, {skipped_ts} skipped in {ts_path}",
            written_py = summary.py_written,
            skipped_py = summary.py_skipped,
            written_ts = summary.ts_written,
            skipped_ts = summary.ts_skipped,
            py_path = py_dir.display(),
            ts_path = ts_dir.display()
        );
        Ok(())
    }
}

fn has_suffix_ci(name: &str, suffix: &str) -> bool {
    let split_at: usize = name.len().saturating_sub(suffix.len());
    name.get(split_at..)
        .is_some_and(|candidate: &str| candidate.eq_ignore_ascii_case(suffix))
}

fn is_python_binding_artifact(name: &str) -> bool {
    has_suffix_ci(name, ".pyi") || name == ".checksum.json"
}

fn is_typescript_binding_artifact(name: &str) -> bool {
    has_suffix_ci(name, ".d.ts") || name == ".checksum.json"
}

fn run_release_package() -> Result<()> {
    let root: PathBuf = workspace_root()?;
    let dist_dir: PathBuf = root.join("dist");
    fs::create_dir_all(&dist_dir)
        .with_context_msg(|| format!("creating {}", dist_dir.display()))?;
    println!(
        "xtask release-package: running cargo build --release --workspace --bins (root {})",
        root.display()
    );
    let status: std::process::ExitStatus = Command::new(cargo_bin())
        .args(["build", "--release", "--workspace", "--bins"])
        .current_dir(&root)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context_msg(|| "spawning cargo build".to_owned())?;
    if !status.success() {
        bail!("cargo build exited with {status}");
    }
    let target_release: PathBuf = root.join("target").join("release");
    let mut copied: usize = 0;
    for entry in walkdir::WalkDir::new(&target_release)
        .min_depth(1)
        .max_depth(1)
    {
        let dirent: walkdir::DirEntry = entry?;
        let path: &Path = dirent.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.starts_with("disrobe") {
            continue;
        }
        let ext_lower: Option<String> = path
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase);
        let is_artifact: bool = !matches!(
            ext_lower.as_deref(),
            Some("d" | "pdb" | "rlib" | "rmeta" | "dwp")
        );
        if !is_artifact {
            continue;
        }
        let dst: PathBuf = dist_dir.join(name);
        fs::copy(path, &dst)
            .with_context_msg(|| format!("copying {} to {}", path.display(), dst.display()))?;
        copied += 1;
    }
    println!(
        "xtask release-package: copied {copied} artifact(s) into {}",
        dist_dir.display()
    );
    Ok(())
}

fn cargo_bin() -> Utf8PathBuf {
    let env_cargo: Option<String> = std::env::var("CARGO").ok();
    env_cargo.map_or_else(|| Utf8PathBuf::from("cargo"), Utf8PathBuf::from)
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    let pretty: String = serde_json::to_string_pretty(value)
        .with_context_msg(|| format!("serializing JSON for {}", path.display()))?;
    fs::write(path, format!("{pretty}\n"))
        .with_context_msg(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn envelope_schema() -> Value {
    let mut properties: Map<String, Value> = Map::new();
    properties.insert(
        "magic".to_owned(),
        json!({"type": "string", "const": "DISROBE\0"}),
    );
    properties.insert(
        "version".to_owned(),
        json!({"type": "integer", "minimum": 1, "maximum": 65535}),
    );
    properties.insert(
        "rung".to_owned(),
        json!({"type": "string", "enum": ["raw", "disasm", "mir", "hir", "surface"]}),
    );
    properties.insert(
        "flags".to_owned(),
        json!({"type": "integer", "minimum": 0, "maximum": 255}),
    );
    properties.insert(
        "hot_len".to_owned(),
        json!({"type": "integer", "minimum": 0}),
    );
    properties.insert(
        "cold_len".to_owned(),
        json!({"type": "integer", "minimum": 0}),
    );
    properties.insert(
        "root_hash".to_owned(),
        json!({"type": "string", "pattern": "^[0-9a-f]{64}$"}),
    );
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://disrobe.dev/schemas/v0/dr-envelope.schema.json",
        "title": "DrEnvelope",
        "description": "Header layout of the disrobe .dr envelope (rkyv hot + postcard cold + BLAKE3 root).",
        "type": "object",
        "additionalProperties": false,
        "required": ["magic", "version", "rung", "flags", "hot_len", "cold_len", "root_hash"],
        "properties": properties,
    })
}

fn freezer_manifest_schema() -> Value {
    let entry_schema: Value = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["name", "kind", "size", "origin"],
        "properties": {
            "name": {"type": "string"},
            "kind": {
                "type": "string",
                "enum": [
                    "python-module",
                    "python-byte-code",
                    "native-extension",
                    "resource",
                    "wheel",
                    "metadata",
                    "other"
                ]
            },
            "size": {"type": "integer", "minimum": 0},
            "compressed_size": {"type": ["integer", "null"], "minimum": 0},
            "python_major": {"type": ["integer", "null"], "minimum": 0},
            "python_minor": {"type": ["integer", "null"], "minimum": 0},
            "source_path": {"type": ["string", "null"]},
            "origin": {
                "type": "string",
                "enum": [
                    "library-zip",
                    "sibling-file",
                    "pe-resource",
                    "trailing-zip",
                    "deps",
                    "other"
                ]
            }
        }
    });
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://disrobe.dev/schemas/v0/freezer-manifest.schema.json",
        "title": "FreezerManifest",
        "description": "Normalized manifest emitted by pyfreeze passes (cx_freeze, py2exe, shiv, pex, pyoxidizer, briefcase).",
        "type": "object",
        "additionalProperties": false,
        "required": ["schema", "kind", "source_path", "entry_count", "entries"],
        "properties": {
            "schema": {"type": "string", "const": "disrobe.pyfreeze.manifest/v0"},
            "kind": {
                "type": "string",
                "enum": [
                    "cx-freeze",
                    "py2exe",
                    "shiv",
                    "pex",
                    "py-oxidizer",
                    "briefcase",
                    "unknown"
                ]
            },
            "source_path": {"type": "string"},
            "python_major": {"type": ["integer", "null"], "minimum": 0},
            "python_minor": {"type": ["integer", "null"], "minimum": 0},
            "interpreter_hint": {"type": ["string", "null"]},
            "entry_count": {"type": "integer", "minimum": 0},
            "primary_module": {"type": ["string", "null"]},
            "entries": {"type": "array", "items": entry_schema}
        }
    })
}

fn extraction_result_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://disrobe.dev/schemas/v0/extraction-result.schema.json",
        "title": "ExtractionResult",
        "description": "Result returned by disrobe-binfmt::extract for any container kind.",
        "type": "object",
        "additionalProperties": false,
        "required": ["kind", "entries", "encoding", "integrity_violations", "quota"],
        "properties": {
            "kind": {"type": "string"},
            "entries": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["name", "uncompressed_size", "compressed_size", "compression", "is_executable"],
                    "properties": {
                        "name": {"type": "string"},
                        "disk_path": {"type": ["string", "null"]},
                        "uncompressed_size": {"type": "integer", "minimum": 0},
                        "compressed_size": {"type": "integer", "minimum": 0},
                        "compression": {
                            "type": "string",
                            "enum": ["stored", "deflate", "deflate64", "bzip2", "lzma", "xz", "zstd", "other"]
                        },
                        "is_executable": {"type": "boolean"}
                    }
                }
            },
            "encoding": {
                "type": "object",
                "additionalProperties": {"type": "string"}
            },
            "integrity_violations": {"type": "array", "items": {"type": "string"}},
            "quota": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "entries_accepted",
                    "total_uncompressed_bytes",
                    "total_compressed_bytes",
                    "max_observed_ratio"
                ],
                "properties": {
                    "entries_accepted": {"type": "integer", "minimum": 0},
                    "total_uncompressed_bytes": {"type": "integer", "minimum": 0},
                    "total_compressed_bytes": {"type": "integer", "minimum": 0},
                    "max_observed_ratio": {"type": "integer", "minimum": 0}
                }
            }
        }
    })
}

fn pyarmor_detection_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://disrobe.dev/schemas/v0/pyarmor-detection.schema.json",
        "title": "PyarmorDetection",
        "description": "Detection summary emitted by disrobe-pass-pyarmor::detect.",
        "type": "object",
        "additionalProperties": false,
        "required": ["version", "protection", "confidence"],
        "properties": {
            "version": {"type": "string", "enum": ["v3", "v4", "v5", "v6", "v7", "v8", "v9"]},
            "protection": {
                "type": "string",
                "enum": ["standard", "super-mode", "bcc", "no-wrap"]
            },
            "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
            "serial": {"type": ["string", "null"]},
            "diagnostics": {"type": "array", "items": {"type": "string"}}
        }
    })
}

trait WithContext<T> {
    fn with_context_msg<F: FnOnce() -> String>(self, f: F) -> Result<T>;
}

impl<T, E> WithContext<T> for core::result::Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn with_context_msg<F: FnOnce() -> String>(self, f: F) -> Result<T> {
        self.wrap_err_with(f)
    }
}
