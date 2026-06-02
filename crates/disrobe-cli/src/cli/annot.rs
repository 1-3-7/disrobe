#![allow(clippy::needless_pass_by_value)]

use std::path::{Path, PathBuf};

use disrobe_core::chain::{ChainPassRecovery, ChainRecoveryReport};
use disrobe_core::recovery::ConfidenceTier;
use disrobe_llm_metadata::annotation::{ANNOTATION_SCHEMA, AnnotationFile, SymbolAnnotation};
use serde::Serialize;

use super::output::{OutputFormat, emit};

#[derive(clap::Subcommand, Debug)]
pub(crate) enum AnnotCmd {
    #[command(about = "reload, re-validate, and re-serialize an existing annotation file")]
    Refresh {
        #[arg(help = "target source/recovery file whose annotation sidecar to refresh")]
        file: PathBuf,
    },
    #[command(about = "rebuild the annotation file from scratch, deriving symbols from the target")]
    Regenerate {
        #[arg(help = "target source/recovery file to derive symbols from")]
        file: PathBuf,
    },
}

#[derive(Debug, Serialize)]
struct AnnotReport {
    action: &'static str,
    target: String,
    annotation_path: String,
    schema: &'static str,
    symbol_count: usize,
}

fn disrobe_dir() -> miette::Result<PathBuf> {
    let cwd: PathBuf = std::env::current_dir()
        .map_err(|e: std::io::Error| miette::miette!("DR-CLI-0322: cannot read cwd: {e}"))?;
    let dir: PathBuf = cwd.join(".disrobe");
    if !dir.is_dir() {
        return Err(miette::miette!(
            "DR-CLI-0323: no `.disrobe/` workspace in {} - run `disrobe init` first",
            cwd.display()
        ));
    }
    Ok(dir)
}

fn annotation_path(disrobe: &Path, target: &Path) -> miette::Result<PathBuf> {
    let stem: &str = target
        .file_stem()
        .and_then(|s: &std::ffi::OsStr| s.to_str())
        .ok_or_else(|| {
            miette::miette!(
                "DR-CLI-0324: target {} has no usable file stem",
                target.display()
            )
        })?;
    Ok(disrobe
        .join("annotations")
        .join(format!("{stem}.annot.json")))
}

fn write_annotation(path: &Path, file: &AnnotationFile) -> miette::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e: std::io::Error| {
            miette::miette!("DR-CLI-0325: cannot create .disrobe/annotations: {e}")
        })?;
    }
    let json: String = serde_json::to_string_pretty(file).map_err(|e: serde_json::Error| {
        miette::miette!("DR-CLI-0326: annotation serialize: {e}")
    })?;
    std::fs::write(path, json.as_bytes()).map_err(|e: std::io::Error| {
        miette::miette!("DR-CLI-0327: cannot write {}: {e}", path.display())
    })
}

fn load_or_empty(path: &Path, target: &Path) -> miette::Result<AnnotationFile> {
    let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(path) else {
        return Ok(AnnotationFile::new(target.display().to_string()));
    };
    serde_json::from_slice::<AnnotationFile>(&bytes).map_err(|e: serde_json::Error| {
        miette::miette!(
            "DR-CLI-0328: {} is not a valid disrobe.annotations/v1 file: {e}",
            path.display()
        )
    })
}

fn build_from_target(target: &Path) -> miette::Result<AnnotationFile> {
    let bytes: Vec<u8> = std::fs::read(target).map_err(|e: std::io::Error| {
        miette::miette!("DR-CLI-0324: cannot read target {}: {e}", target.display())
    })?;
    let mut file: AnnotationFile = AnnotationFile::new(target.display().to_string());
    if let Ok(report) = serde_json::from_slice::<ChainRecoveryReport>(&bytes) {
        for pass in &report.passes {
            let pass: &ChainPassRecovery = pass;
            let note: String = format!(
                "status={} format_out={}",
                pass.status.as_str(),
                pass.format_out.as_deref().unwrap_or("-")
            );
            file.push(SymbolAnnotation::new(
                pass.name.clone(),
                "pass",
                note,
                pass.confidence,
            ))
            .map_err(|e: disrobe_llm_metadata::AnnotationError| {
                miette::miette!("DR-CLI-0329: annotation validation failed: {e}")
            })?;
        }
        return Ok(file);
    }
    let text: String = String::from_utf8_lossy(&bytes).into_owned();
    let line_count: usize = text.lines().count();
    let byte_len: usize = bytes.len();
    let stem: &str = target
        .file_stem()
        .and_then(|s: &std::ffi::OsStr| s.to_str())
        .ok_or_else(|| {
            miette::miette!(
                "DR-CLI-0324: target {} has no usable file stem",
                target.display()
            )
        })?;
    file.push(SymbolAnnotation::new(
        stem,
        "module",
        format!("{line_count} lines, {byte_len} bytes"),
        ConfidenceTier::Skeleton,
    ))
    .map_err(|e: disrobe_llm_metadata::AnnotationError| {
        miette::miette!("DR-CLI-0329: annotation validation failed: {e}")
    })?;
    Ok(file)
}

pub(crate) fn run(action: AnnotCmd, fmt: OutputFormat) -> miette::Result<()> {
    let disrobe: PathBuf = disrobe_dir()?;
    let (target, regenerate): (PathBuf, bool) = match action {
        AnnotCmd::Refresh { file } => (file, false),
        AnnotCmd::Regenerate { file } => (file, true),
    };
    let path: PathBuf = annotation_path(&disrobe, &target)?;
    let file: AnnotationFile = if regenerate {
        build_from_target(&target)?
    } else {
        load_or_empty(&path, &target)?
    };
    file.validate()
        .map_err(|e: disrobe_llm_metadata::AnnotationError| {
            miette::miette!("DR-CLI-0329: annotation validation failed: {e}")
        })?;
    write_annotation(&path, &file)?;
    let report: AnnotReport = AnnotReport {
        action: if regenerate { "regenerate" } else { "refresh" },
        target: target.display().to_string(),
        annotation_path: path.display().to_string(),
        schema: ANNOTATION_SCHEMA,
        symbol_count: file.annotations.len(),
    };
    emit(fmt, &report, || {
        println!("disrobe annot {}: OK", report.action);
        println!("  target:     {}", report.target);
        println!("  annotation: {}", report.annotation_path);
        println!("  schema:     {}", report.schema);
        println!("  symbols:    {}", report.symbol_count);
    })
}
