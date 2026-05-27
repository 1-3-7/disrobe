#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::redundant_pub_crate
)]

mod codegen;

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
    GenBindings,
    BakeFixtures {
        #[arg(long, action = clap::ArgAction::SetTrue)]
        dry_run: bool,
        #[arg(long, action = clap::ArgAction::SetTrue)]
        edge_cases: bool,
    },
    ReleasePackage,
    Schemas,
    Docs,
}

fn main() -> ExitCode {
    let cli: Cli = Cli::parse();
    let result: Result<()> = match cli.command {
        Cmd::GenBindings => run_gen_bindings(),
        Cmd::BakeFixtures {
            dry_run,
            edge_cases,
        } => run_bake_fixtures(dry_run, edge_cases),
        Cmd::ReleasePackage => run_release_package(),
        Cmd::Schemas => run_schemas(),
        Cmd::Docs => run_docs(),
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

fn run_schemas() -> Result<()> {
    let root: PathBuf = workspace_root()?;
    let out_dir: PathBuf = root.join("schemas").join("v0").join("json");
    fs::create_dir_all(&out_dir).with_context_msg(|| format!("creating {}", out_dir.display()))?;
    let envelope: Value = envelope_schema();
    let manifest: Value = freezer_manifest_schema();
    let extraction: Value = extraction_result_schema();
    let detection: Value = pyarmor_detection_schema();
    write_json(&out_dir.join("dr-envelope.schema.json"), &envelope)?;
    write_json(&out_dir.join("freezer-manifest.schema.json"), &manifest)?;
    write_json(&out_dir.join("extraction-result.schema.json"), &extraction)?;
    write_json(&out_dir.join("pyarmor-detection.schema.json"), &detection)?;
    println!(
        "xtask schemas: wrote 4 JSON Schemas under {}",
        out_dir.display()
    );
    Ok(())
}

fn run_gen_bindings() -> Result<()> {
    let root: PathBuf = workspace_root()?;
    let schemas_dir: PathBuf = root.join("schemas").join("v0").join("json");
    if !schemas_dir.is_dir() {
        run_schemas()?;
    }
    let py_dir: PathBuf = root.join("bindings").join("python");
    let ts_dir: PathBuf = root.join("bindings").join("typescript");
    let schemas: Vec<SchemaArtifact> = load_schemas(&schemas_dir)?;
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

fn run_docs() -> Result<()> {
    let root: PathBuf = workspace_root()?;
    let docs_dir: PathBuf = root.join("docs");
    if !docs_dir.is_dir() {
        println!(
            "xtask docs: no docs/ directory at {}; nothing to build",
            docs_dir.display()
        );
        return Ok(());
    }
    if which("mdbook").is_none() {
        println!("xtask docs: mdbook not on PATH; install via `cargo install mdbook` to enable");
        return Ok(());
    }
    let status: std::process::ExitStatus = Command::new("mdbook")
        .args(["build", "."])
        .current_dir(&docs_dir)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context_msg(|| "spawning mdbook build".to_owned())?;
    if !status.success() {
        bail!("mdbook exited with {status}");
    }
    println!(
        "xtask docs: mdbook build complete under {}",
        docs_dir.display()
    );
    Ok(())
}

fn cargo_bin() -> Utf8PathBuf {
    let env_cargo: Option<String> = std::env::var("CARGO").ok();
    env_cargo.map_or_else(|| Utf8PathBuf::from("cargo"), Utf8PathBuf::from)
}

fn which(exe: &str) -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) {
        &["", ".exe", ".bat", ".cmd"]
    } else {
        &[""]
    };
    for dir in std::env::split_paths(&path_var) {
        for ext in exts {
            let candidate: PathBuf = if ext.is_empty() {
                dir.join(exe)
            } else {
                dir.join(format!("{exe}{ext}"))
            };
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
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
