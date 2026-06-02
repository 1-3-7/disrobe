use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use disrobe_llm_metadata::{LlmMetadataEmitter, MetadataSelection};

use super::super::globals;
use super::super::llm::{self as llm_cli, LlmFlags};

pub(super) fn deob(
    input: PathBuf,
    out: Option<PathBuf>,
    cleanup: bool,
    emit_kinds: Vec<String>,
    llm_flags: &LlmFlags,
) -> miette::Result<()> {
    let _: Option<MetadataSelection> = llm_flags.to_selection()?;
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0030: cannot read input: {e}"))?;
    let mut result: disrobe_pass_py_deob::PeelResult =
        disrobe_pass_py_deob::peel(&bytes).map_err(|e| miette::miette!("{e}"))?;

    let cleanup_stats: Option<disrobe_pass_py_deob::CleanupStats> = if cleanup {
        let (cleaned, stats): (String, disrobe_pass_py_deob::CleanupStats) =
            disrobe_pass_py_deob::cleanup_source(&result.final_source)
                .map_err(|e| miette::miette!("{e}"))?;
        result.final_source = cleaned;
        Some(stats)
    } else {
        None
    };

    let g: globals::Globals = globals::current();
    if g.dry_run {
        println!("py deob: DRY-RUN");
        println!("  input:        {}", input.display());
        println!("  steps:        {}", result.steps.len());
        return Ok(());
    }
    let out_path: PathBuf = if g.in_place {
        input.clone()
    } else {
        out.unwrap_or_else(|| {
            let stem: &str = input
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("py-deob");
            PathBuf::from(format!("./out/{stem}.deobfuscated.py"))
        })
    };
    if !g.in_place {
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| miette::miette!("DR-CLI-0031: cannot create dir: {e}"))?;
        }
        if out_path.exists() && !g.force {
            return Err(miette::miette!(
                "DR-CLI-0033B: out file {} already exists; pass --force to overwrite",
                out_path.display()
            ));
        }
    }
    std::fs::write(&out_path, result.final_source.as_bytes())
        .map_err(|e| miette::miette!("DR-CLI-0032: cannot write output: {e}"))?;
    let manifest_path: Option<PathBuf> = if g.in_place {
        None
    } else {
        let mp: PathBuf = out_path.with_extension("manifest.json");
        let manifest: serde_json::Value = serde_json::json!({
            "peel": &result,
            "cleanup": cleanup_stats,
        });
        std::fs::write(
            &mp,
            serde_json::to_vec_pretty(&manifest).unwrap_or_default(),
        )
        .map_err(|e| miette::miette!("DR-CLI-0033: cannot write manifest: {e}"))?;
        Some(mp)
    };
    println!("py deob: OK");
    println!("  family:       {:?}", result.initial.family);
    println!("  confidence:   {:.2}", result.initial.confidence);
    println!("  steps:        {}", result.steps.len());
    println!("  converged:    {}", result.converged);
    if let Some(stats) = cleanup_stats {
        println!("  cleanup:");
        println!("    outer passes:        {}", stats.outer_passes);
        println!("    fold replacements:   {}", stats.fold_replacements);
        println!("    if eliminated:       {}", stats.if_eliminated);
        println!("    while eliminated:    {}", stats.while_eliminated);
        println!("    branches pruned:     {}", stats.branches_pruned);
        println!("    converged:           {}", stats.converged);
    }
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("py-deob")
        .to_owned();
    let stub_dir: &Path = out_path.parent().unwrap_or_else(|| Path::new("."));
    if !g.in_place {
        super::super::emit::apply_not_applicable_stubs(
            &emit_kinds,
            stub_dir,
            &stem,
            "py-deob",
            "not implemented for the py pass in this build",
        )?;
    }

    let llm_out: Option<llm_cli::LlmOutputs> =
        maybe_emit_llm_deob(llm_flags, &input, &bytes, &out_path, &result)?;

    println!("  wrote:        {}", out_path.display());
    if let Some(mp) = manifest_path.as_ref() {
        println!("  manifest:     {}", mp.display());
    }
    if let Some(o) = llm_out.as_ref() {
        println!("  llm bundle:   {}", o.bundle.display());
        if let Some(a) = o.agents_md.as_ref() {
            println!("  agents.md:    {}", a.display());
        }
        if let Some(s) = o.skill_md.as_ref() {
            println!("  skill.md:     {}", s.display());
        }
    }
    Ok(())
}

fn maybe_emit_llm_deob(
    llm_flags: &LlmFlags,
    input: &Path,
    bytes: &[u8],
    out_path: &Path,
    peel: &disrobe_pass_py_deob::PeelResult,
) -> miette::Result<Option<llm_cli::LlmOutputs>> {
    let Some(selection): Option<MetadataSelection> = llm_flags.to_selection()? else {
        return Ok(None);
    };
    let started: std::time::Instant = std::time::Instant::now();
    let duration_ms: f64 = started.elapsed().as_secs_f64() * 1000.0_f64;
    let emitter: disrobe_pass_py_deob::PyDeobLlmInput = disrobe_pass_py_deob::PyDeobLlmInput {
        peel: peel.clone(),
        duration_ms,
    };
    let envelope_map: serde_json::Value = emitter.emit_metadata(&selection);
    let step: disrobe_llm_metadata::PipelineStep = llm_cli::make_step(
        "disrobe-pass-py-deob",
        disrobe_pass_py_deob::VERSION,
        "surface",
        "surface",
        duration_ms,
    );
    let outputs: llm_cli::LlmOutputs = llm_cli::write_llm_bundle(
        llm_flags,
        &selection,
        input,
        bytes,
        out_path,
        vec![(step, envelope_map)],
    )?;
    Ok(Some(outputs))
}
