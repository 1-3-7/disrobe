use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use disrobe_llm_metadata::{LlmMetadataEmitter, MetadataSelection};
use disrobe_pass_py_deob::SupportedObfuscator;

use super::super::globals;
use super::super::llm::{self as llm_cli, LlmFlags};

pub(crate) fn print_supported_obfuscators() {
    let supported: Vec<SupportedObfuscator> = disrobe_pass_py_deob::supported_obfuscators();
    println!("disrobe supports these Python source obfuscators:");
    for entry in &supported {
        if entry.aliases.is_empty() {
            println!("  - {}", entry.display_name);
        } else {
            println!(
                "  - {} (aka {})",
                entry.display_name,
                entry.aliases.join(", ")
            );
        }
    }
    println!(
        "plus generic exec/eval droppers and marshal/base64/base85/zlib/lzma/bz2 packers, and clean .pyc bytecode."
    );
    println!();
    println!("Deobfuscate + decompile in one step:");
    println!("  disrobe py decompile <input>");
    println!("Peel only (source out):");
    println!("  disrobe py deob <input> --out <output.py>");
}

pub(super) fn deob(
    input: Option<PathBuf>,
    out: Option<PathBuf>,
    cleanup: bool,
    pyver: Option<String>,
    list: bool,
    emit_kinds: Vec<String>,
    llm_flags: &LlmFlags,
) -> miette::Result<()> {
    if list {
        print_supported_obfuscators();
        return Ok(());
    }
    let Some(input): Option<PathBuf> = input else {
        return Err(miette::miette!(
            "DR-CLI-0036: py deob needs an input file (or `--list` to show supported obfuscators)"
        ));
    };
    let _: Option<MetadataSelection> = llm_flags.to_selection()?;
    let pyver_hint: Option<disrobe_py_marshal::PyVersion> = match pyver.as_deref() {
        Some(raw) => Some(parse_pyver(raw)?),
        None => None,
    };
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0030: cannot read input: {e}"))?;
    let mut result: disrobe_pass_py_deob::PeelResult =
        disrobe_pass_py_deob::peel_with_pyver(&bytes, pyver_hint)
            .map_err(|e| miette::miette!("{e}"))?;

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
        let manifest_bytes: Vec<u8> = serde_json::to_vec_pretty(&manifest)
            .map_err(|e| miette::miette!("DR-CLI-0034: serialize manifest: {e}"))?;
        std::fs::write(&mp, manifest_bytes)
            .map_err(|e| miette::miette!("DR-CLI-0033: cannot write manifest: {e}"))?;
        Some(mp)
    };
    if result.recovered {
        println!("py deob: RECOVERED");
    } else {
        println!("py deob: NO KNOWN OBFUSCATOR DETECTED");
        eprintln!();
        eprint!("{}", disrobe_pass_py_deob::unidentified_guidance(&bytes));
    }
    println!("  family:       {:?}", result.initial.family);
    println!("  confidence:   {:.2}", result.initial.confidence);
    if let Some(obf) = result.obfuscator.as_ref() {
        println!("  obfuscator:   {:?}", obf.obfuscator);
        println!("  quality:      {:?}", obf.quality);
        println!("  detect conf:  {:.2}", obf.detect_confidence);
        println!("  peel conf:    {:.2}", obf.peel_confidence);
        if !obf.stages_applied.is_empty() {
            println!("  stages:       {}", obf.stages_applied.join(" -> "));
        }
        for note in &obf.lossy_notes {
            println!("  note:         {note}");
        }
    }
    if let Some(m) = result.marshal.as_ref() {
        println!("  marshal:");
        println!("    chain:               {}", m.chain.join(" -> "));
        println!(
            "    python version:      {}.{}{}",
            m.version_major,
            m.version_minor,
            if m.version_inferred {
                " (inferred)"
            } else {
                " (hint)"
            }
        );
        println!("    code-object layers:  {}", m.layers.len());
        for layer in &m.layers {
            println!(
                "      depth {} `{}`: {} code objects, {} bytes bytecode, {}",
                layer.depth,
                layer.entry_name,
                layer.code_objects,
                layer.bytecode_len,
                if layer.recovered_directly {
                    "decompiled to source"
                } else {
                    "disassembled (source-level decompile unavailable)"
                }
            );
        }
    }
    println!("  recovered:    {}", result.recovered);
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

fn parse_pyver(raw: &str) -> miette::Result<disrobe_py_marshal::PyVersion> {
    let (major_str, minor_str): (&str, &str) = raw.split_once('.').ok_or_else(|| {
        miette::miette!("DR-CLI-0035: --pyver must be MAJOR.MINOR (e.g. 3.12), got `{raw}`")
    })?;
    let major: u8 = major_str
        .trim()
        .parse::<u8>()
        .map_err(|_| miette::miette!("DR-CLI-0035: --pyver major `{major_str}` is not a number"))?;
    let minor: u8 = minor_str
        .trim()
        .parse::<u8>()
        .map_err(|_| miette::miette!("DR-CLI-0035: --pyver minor `{minor_str}` is not a number"))?;
    Ok(disrobe_py_marshal::PyVersion::new(major, minor))
}
