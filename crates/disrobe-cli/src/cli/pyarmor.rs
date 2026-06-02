#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]

use std::path::PathBuf;
use std::time::Duration;

use clap::Subcommand;
use disrobe_core::progress::Progress as _;

use super::globals;
use super::progress_ui;

#[derive(Subcommand, Debug)]
pub(crate) enum PyarmorCmd {
    #[command(
        about = "unpack a PyArmor-protected wrapper to its original .pyc (v6 / v7 dynamic-hook + v8 / v9-pro static)"
    )]
    Unpack {
        #[arg(help = "PyArmor wrapper .py file to unpack")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output directory (default: ./out/<stem>-unpacked)"
        )]
        out: Option<PathBuf>,
        #[arg(long, value_delimiter = ',', help = "comma-separated emit kinds")]
        emit: Vec<String>,
        #[arg(
            long,
            help = "permit the v6 / v7 dynamic-hook fallback (runs the obfuscated wrapper in a subprocess to capture marshal streams); only enable on trusted samples or in an isolated sandbox"
        )]
        allow_dynamic: bool,
        #[arg(
            long,
            value_name = "SECS",
            help = "watchdog timeout for the dynamic-hook subprocess (default: 60s)"
        )]
        dynamic_timeout: Option<u64>,
        #[arg(
            long,
            value_name = "PYVER",
            help = "rewrite the emitted .pyc magic for the specified Python version (e.g. 3.11); defaults to the version detected in the wrapper"
        )]
        target: Option<String>,
        #[arg(
            long,
            help = "permit BCC native-body lift via Ghidra-headless on PATH; without this flag, BCC protection returns DR-PYARM-0050",
            default_value_t = false
        )]
        allow_bcc: bool,
        #[arg(
            long,
            value_name = "MODE",
            value_parser = ["auto", "standard", "super"],
            default_value = "auto",
            help = "override the detected mode (super = pyarmor(...) wrapper, standard = __pyarmor__(...))"
        )]
        mode: String,
        #[arg(
            long,
            help = "emit all 12 standardized --emit kinds; non-applicable emits become stub JSON with applicable=false",
            default_value_t = false
        )]
        all_emits: bool,
        #[arg(
            long,
            help = "exit non-zero on any partial / skeleton decode; default continues with degraded-confidence reporting",
            default_value_t = false
        )]
        strict: bool,
        #[arg(
            long,
            help = "disable the disrobe-pyarmor-cextract C-level intercept (PEP 669 / PyEval_SetProfile); the Python-level pytrace channel still runs",
            default_value_t = false
        )]
        no_cextract: bool,
        #[arg(
            long,
            help = "run ONLY the disrobe-pyarmor-cextract C-level intercept; disable disrobe-pyarmor-pytrace; mutually exclusive with --no-cextract",
            default_value_t = false,
            conflicts_with = "no_cextract"
        )]
        cextract_only: bool,
        #[arg(
            long,
            value_name = "DIR",
            help = "override the descriptor cache directory (in-memory cache is always active; this dir is reserved for v0.2 persistence)"
        )]
        cache: Option<PathBuf>,
    },
}

pub(crate) fn run(action: PyarmorCmd) -> miette::Result<()> {
    match action {
        PyarmorCmd::Unpack {
            input,
            out,
            emit,
            allow_dynamic,
            dynamic_timeout,
            target,
            allow_bcc,
            mode,
            all_emits,
            strict,
            no_cextract,
            cextract_only,
            cache,
        } => unpack(
            input,
            out,
            emit,
            allow_dynamic,
            dynamic_timeout,
            target,
            allow_bcc,
            mode,
            all_emits,
            strict,
            no_cextract,
            cextract_only,
            cache,
        ),
    }
}

#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
fn unpack(
    input: PathBuf,
    out: Option<PathBuf>,
    emit: Vec<String>,
    allow_dynamic: bool,
    dynamic_timeout: Option<u64>,
    target: Option<String>,
    allow_bcc: bool,
    mode: String,
    all_emits: bool,
    strict: bool,
    no_cextract: bool,
    cextract_only: bool,
    cache: Option<PathBuf>,
) -> miette::Result<()> {
    let text: String = std::fs::read_to_string(&input).map_err(|e| {
        miette::miette!(
            "DR-CLI-0001: cannot read wrapper at {}: {e}",
            input.display()
        )
    })?;

    if globals::current().dry_run {
        println!("disrobe pyarmor unpack: DRY-RUN");
        println!("  input:        {}", input.display());
        println!("  would unpack: {} bytes", text.len());
        return Ok(());
    }

    let out_dir: PathBuf = out.unwrap_or_else(|| {
        let stem: &str = input
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("disrobe-out");
        PathBuf::from(format!("./out/{stem}-unpacked"))
    });
    let g: globals::Globals = globals::current();
    if out_dir.exists() && !g.force {
        let has_entries: bool = std::fs::read_dir(&out_dir).is_ok_and(|mut it| it.next().is_some());
        if has_entries {
            return Err(miette::miette!(
                "DR-CLI-0030: out dir {} already exists; pass --force to overwrite",
                out_dir.display()
            ));
        }
    }
    std::fs::create_dir_all(&out_dir).map_err(|e| {
        miette::miette!(
            "DR-CLI-0002: cannot create out dir {}: {e}",
            out_dir.display()
        )
    })?;

    let mode_override: disrobe_pass_pyarmor::ModeOverride =
        disrobe_pass_pyarmor::ModeOverride::parse(&mode)
            .ok_or_else(|| miette::miette!("DR-CLI-0020: invalid --mode value: {mode}"))?;
    let target_pyver: Option<disrobe_pass_pyarmor::TargetPyVersion> = match target.as_deref() {
        Some(raw) => Some(
            disrobe_pass_pyarmor::TargetPyVersion::parse(raw)
                .ok_or_else(|| miette::miette!("DR-CLI-0021: invalid --target value: {raw}"))?,
        ),
        None => None,
    };
    if let Some(ref cache_dir) = cache {
        std::fs::create_dir_all(cache_dir).map_err(|e| {
            miette::miette!(
                "DR-CLI-0022: cannot create cache dir {}: {e}",
                cache_dir.display()
            )
        })?;
    }
    let options: disrobe_pass_pyarmor::UnpackOptions = disrobe_pass_pyarmor::UnpackOptions {
        allow_dynamic,
        dynamic_out_dir: Some(out_dir.join("dynamic")),
        dynamic_timeout: dynamic_timeout.map(Duration::from_secs),
        descriptor_cache: None,
        descriptor_cache_dir: cache.clone(),
        emit_provenance: false,
        allow_bcc,
        mode_override,
        target_pyver,
        all_emits,
        strict,
        no_cextract,
        cextract_only,
    };

    let bar: progress_ui::ActiveProgress = progress_ui::make_progress("pyarmor unpack");
    bar.set_message("decrypting");
    let result: disrobe_pass_pyarmor::UnpackOutput =
        disrobe_pass_pyarmor::unpack_wrapper_text_with_options(&text, &input, &options)
            .map_err(|e| miette::miette!("{e}"))?;
    let stats_ref: Option<&disrobe_pass_pyarmor::DecryptionStats> =
        result.inner_cipher_stats.as_ref();
    if let Some(stats) = stats_ref {
        let total: u64 = u64::from(stats.objects_visited.max(1));
        bar.set_total(total);
        for i in 0..total {
            bar.set_pos(i + 1);
            bar.tick();
        }
    } else {
        bar.set_total(1);
        bar.tick();
    }
    bar.finish("done");

    let mut wrote: Vec<PathBuf> = Vec::new();

    let manifest_path: PathBuf = out_dir.join("manifest.json");
    let dynamic_summary_json: Option<serde_json::Value> = result.dynamic_hook.as_ref().map(|d| {
        serde_json::json!({
            "manifest_path": d.manifest_path.display().to_string(),
            "interpreter": d.interpreter.display().to_string(),
            "interpreter_version": format!(
                "{}.{}.{}",
                d.interpreter_version.0, d.interpreter_version.1, d.interpreter_version.2
            ),
            "exit_code": d.exit_code,
            "total_captures": d.total_captures,
            "stderr_excerpt": d.stderr_excerpt,
            "candidates": d.user_code_candidates.iter().map(|c| serde_json::json!({
                "pyc_path": c.pyc_path.display().to_string(),
                "source": format!("{:?}", c.source),
                "index": c.index,
                "size": c.size,
                "sha256": c.sha256,
                "has_armor_enter": c.has_armor_enter,
                "distinct_names": c.distinct_names,
                "names_sample": c.names_sample,
                "score": c.score,
            })).collect::<Vec<_>>(),
            "primary_pyc": d.primary_candidate.as_ref().map(|c| c.pyc_path.display().to_string()),
            "limitations": d.limitations.iter().map(|l| serde_json::json!({
                "id": l.id,
                "channel": l.channel,
                "severity": l.severity,
                "message": l.message,
            })).collect::<Vec<_>>(),
        })
    });
    let pass_path: &'static str = if result.dynamic_hook.is_some() {
        "dynamic-hook fallback"
    } else {
        "pure-static"
    };
    let limitations: Vec<String> = compute_limitations(&result);
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.pyarmor.manifest/v0",
        "input": input.display().to_string(),
        "runtime": result.runtime_path.display().to_string(),
        "version": format!("{:?}", result.detection.version),
        "protection": format!("{:?}", result.detection.protection),
        "confidence": format!("{:?}", result.detection.confidence),
        "diagnostics": result.detection.diagnostics,
        "pass_path": pass_path,
        "limitations": limitations,
        "serial": result.detection.serial,
        "python": result
            .py_version
            .map(|v| format!("{}.{}", v.major, v.minor)),
        "pyc_magic": result.detection.pyc_magic,
        "target_pyver_applied": target_pyver.map(|t| format!("{}.{}", t.major, t.minor)),
        "mode_override": mode_override.label(),
        "allow_bcc": allow_bcc,
        "strict": strict,
        "no_cextract": no_cextract,
        "cextract_only": cextract_only,
        "descriptor_cache_dir": cache.as_ref().map(|p| p.display().to_string()),
        "key_hex": result.key_hex,
        "iv_hex": result.iv_hex,
        "plaintext_size": result.plaintext.len(),
        "marshal_offset": result.marshal_offset,
        "marshal_error": result.marshal_error,
        "pyc_emitted": result.pyc.is_some(),
        "wrap_stripped": result.wrap_stripped,
        "fallback_reason": result.fallback_reason,
        "dynamic_hook": dynamic_summary_json,
        "inner_cipher_stats": result.inner_cipher_stats.as_ref().map(|s| serde_json::json!({
            "objects_visited": s.objects_visited,
            "objects_with_trailer": s.objects_with_trailer,
            "descriptors_applied": s.descriptors_applied,
            "bytes_decrypted": s.bytes_decrypted,
            "copy_prologue_applied": s.copy_prologue_applied,
            "trailer_parse_failures": s.trailer_parse_failures,
            "missing_consts_failures": s.missing_consts_failures,
            "first_trailer_hex": s.first_trailer_hex,
            "nine_pro_stage_2_segments_found": s.nine_pro_stage_2_segments_found,
            "nine_pro_stage_2_segments_unwrapped": s.nine_pro_stage_2_segments_unwrapped,
            "nine_pro_stage_2_bytes_unwrapped": s.nine_pro_stage_2_bytes_unwrapped,
            "nine_pro_stage_2_bind_required": s.nine_pro_stage_2_bind_required,
        })),
    });
    let manifest_bytes: Vec<u8> = serde_json::to_vec_pretty(&manifest)
        .map_err(|e: serde_json::Error| miette::miette!("DR-CLI-0003b: serialize manifest: {e}"))?;
    std::fs::write(&manifest_path, &manifest_bytes)
        .map_err(|e: std::io::Error| miette::miette!("DR-CLI-0003: cannot write manifest: {e}"))?;
    wrote.push(manifest_path);

    if !result.plaintext.is_empty()
        && (emit.is_empty() || emit.iter().any(|s| s == "ir" || s == "report"))
    {
        let plaintext_path: PathBuf = out_dir.join("payload.bin");
        std::fs::write(&plaintext_path, &result.plaintext)
            .map_err(|e| miette::miette!("DR-CLI-0004: cannot write plaintext: {e}"))?;
        wrote.push(plaintext_path);
    }

    if all_emits {
        let stubs: Vec<(&str, &str)> = vec![
            (
                "source",
                "pyarmor pass does not produce source; chain with disrobe py decompile",
            ),
            (
                "disasm",
                "pyarmor pass emits the unwrapped .pyc; chain with disrobe py disasm",
            ),
            (
                "ast",
                "pyarmor pass does not produce AST; chain with disrobe py decompile",
            ),
            ("cfg", "pyarmor pass does not produce CFG"),
            ("sourcemap", "pyarmor pass does not produce sourcemaps"),
            (
                "symbols",
                "pyarmor pass emits names through the .pyc; chain with disrobe py disasm",
            ),
            (
                "strings",
                "pyarmor pass emits constants through the .pyc; chain with disrobe py disasm",
            ),
            (
                "imports",
                "pyarmor pass emits imports through the .pyc; chain with disrobe py disasm",
            ),
            (
                "signatures",
                "pyarmor pass does not compute external signatures",
            ),
        ];
        for (kind, reason) in stubs {
            let stub_path: PathBuf = out_dir.join(format!("emit_{kind}.json"));
            let payload: serde_json::Value = serde_json::json!({
                "schema": "disrobe.emit.stub/v0",
                "pass": "pyarmor",
                "emit_kind": kind,
                "applicable": false,
                "error_code": "DR-IR-NotApplicable",
                "reason": reason,
            });
            let stub_bytes: Vec<u8> =
                serde_json::to_vec_pretty(&payload).map_err(|e: serde_json::Error| {
                    miette::miette!("DR-CLI-0023b: serialize emit stub {kind}: {e}")
                })?;
            std::fs::write(&stub_path, &stub_bytes).map_err(|e: std::io::Error| {
                miette::miette!("DR-CLI-0023: cannot write emit stub {kind}: {e}")
            })?;
            wrote.push(stub_path);
        }
        let report_path: PathBuf = out_dir.join("emit_report.json");
        let report: serde_json::Value = serde_json::json!({
            "schema": "disrobe.emit.report/v0",
            "pass": "pyarmor",
            "applicable": true,
            "pyc_emitted": result.pyc.is_some(),
            "wrap_stripped": result.wrap_stripped,
            "version": format!("{:?}", result.detection.version),
            "protection": format!("{:?}", result.detection.protection),
            "pass_path": pass_path,
        });
        let report_bytes: Vec<u8> =
            serde_json::to_vec_pretty(&report).map_err(|e: serde_json::Error| {
                miette::miette!("DR-CLI-0024b: serialize emit report: {e}")
            })?;
        std::fs::write(&report_path, &report_bytes).map_err(|e: std::io::Error| {
            miette::miette!("DR-CLI-0024: cannot write emit report: {e}")
        })?;
        wrote.push(report_path);
        let ir_path: PathBuf = out_dir.join("emit_ir.json");
        let ir: serde_json::Value = serde_json::json!({
            "schema": "disrobe.emit.ir/v0",
            "pass": "pyarmor",
            "applicable": result.pyc.is_some(),
            "rung": "P-bytecode",
            "carrier": "pyc",
            "size_bytes": result.pyc.as_ref().map_or(0, Vec::len),
        });
        let ir_bytes: Vec<u8> =
            serde_json::to_vec_pretty(&ir).map_err(|e: serde_json::Error| {
                miette::miette!("DR-CLI-0025b: serialize emit ir: {e}")
            })?;
        std::fs::write(&ir_path, &ir_bytes).map_err(|e: std::io::Error| {
            miette::miette!("DR-CLI-0025: cannot write emit ir: {e}")
        })?;
        wrote.push(ir_path);
    }

    if let Some(ref pyc_bytes) = result.pyc {
        let pyc_path: PathBuf = out_dir.join(format!(
            "{}.pyc",
            input
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("module")
        ));
        std::fs::write(&pyc_path, pyc_bytes)
            .map_err(|e| miette::miette!("DR-CLI-0005: cannot write pyc: {e}"))?;
        wrote.push(pyc_path);
    }

    println!("disrobe pyarmor unpack: OK");
    println!("  input:        {}", input.display());
    println!(
        "  detection:    {:?} ({:?})",
        result.detection.version, result.detection.protection
    );
    if let Some(ref s) = result.detection.serial {
        println!("  serial:       {s}");
    }
    if let (Some(maj), Some(min)) = (result.detection.python_major, result.detection.python_minor) {
        println!("  python:       {maj}.{min}");
    }
    println!("  runtime:      {}", result.runtime_path.display());
    if !result.key_hex.is_empty() {
        println!("  key:          {}", result.key_hex);
        println!("  iv:           {}", result.iv_hex);
    }
    println!("  plaintext:    {} bytes", result.plaintext.len());
    println!("  pyc emitted:  {}", result.pyc.is_some());
    println!("  wrap stripped: {}", result.wrap_stripped);
    println!("  marshal offset: {}", result.marshal_offset);
    if let Some(ref err) = result.marshal_error {
        println!("  marshal error: {err}");
    }
    if let Some(ref stats) = result.inner_cipher_stats {
        println!("  inner cipher:");
        println!("    objects visited:        {}", stats.objects_visited);
        println!("    objects with trailer:   {}", stats.objects_with_trailer);
        println!("    descriptors applied:    {}", stats.descriptors_applied);
        println!("    bytes decrypted:        {}", stats.bytes_decrypted);
        println!(
            "    copy-prologue applied:  {}",
            stats.copy_prologue_applied
        );
        println!(
            "    trailer parse failures: {}",
            stats.trailer_parse_failures
        );
    }
    if let Some(ref dh) = result.dynamic_hook {
        println!("  dynamic hook:");
        println!(
            "    interpreter:           {} ({}.{}.{})",
            dh.interpreter.display(),
            dh.interpreter_version.0,
            dh.interpreter_version.1,
            dh.interpreter_version.2
        );
        println!("    total captures:        {}", dh.total_captures);
        println!(
            "    user-code candidates:  {}",
            dh.user_code_candidates.len()
        );
        if let Some(ref primary) = dh.primary_candidate {
            println!("    primary candidate:     {}", primary.pyc_path.display());
            println!(
                "      score={} size={} distinct_names={} armor_enter={}",
                primary.score, primary.size, primary.distinct_names, primary.has_armor_enter
            );
        }
        println!("    manifest:              {}", dh.manifest_path.display());
        if let Some(code) = dh.exit_code {
            println!("    subprocess exit code:  {code}");
        }
    }
    if let Some(ref reason) = result.fallback_reason {
        println!("  fallback used: dynamic hook ({reason})");
    }
    println!("  out dir:      {}", out_dir.display());
    for path in &wrote {
        println!("    wrote: {}", path.display());
    }

    Ok(())
}

fn compute_limitations(result: &disrobe_pass_pyarmor::UnpackOutput) -> Vec<String> {
    let mut limits: Vec<String> = Vec::new();
    if matches!(
        result.detection.version,
        disrobe_pass_pyarmor::PyarmorVersion::V6 | disrobe_pass_pyarmor::PyarmorVersion::V7
    ) && result.dynamic_hook.is_some()
    {
        limits.push(
            "v6/v7 pure-static key extraction not yet implemented; used dynamic-hook fallback. See SPRINT.md.".to_owned(),
        );
    }
    if let Some(ref dh) = result.dynamic_hook {
        for limitation in &dh.limitations {
            limits.push(format!(
                "[{}/{}] {}",
                limitation.channel, limitation.id, limitation.message
            ));
        }
    }
    if matches!(
        result.detection.version,
        disrobe_pass_pyarmor::PyarmorVersion::V3
            | disrobe_pass_pyarmor::PyarmorVersion::V4
            | disrobe_pass_pyarmor::PyarmorVersion::V5
    ) {
        limits.push(
            "PyArmor v3/v4/v5 detection-only; no decryption implemented (no real-world sample corpus available)."
                .to_owned(),
        );
    }
    if matches!(
        result.detection.protection,
        disrobe_pass_pyarmor::ProtectionKind::Bcc
    ) {
        limits.push(
            "BCC native body lift requires --allow-bcc & ghidra-headless on PATH; not lifted here."
                .to_owned(),
        );
    }
    if let Some(stats) = result.inner_cipher_stats.as_ref()
        && stats.nine_pro_stage_2_bind_required > 0
    {
        limits.push(format!(
            "9-Pro stage-2 segments require runtime bind credentials; {} segment(s) left wrapped.",
            stats.nine_pro_stage_2_bind_required
        ));
    }
    limits
}
