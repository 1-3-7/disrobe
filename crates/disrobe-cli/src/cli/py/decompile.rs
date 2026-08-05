use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use disrobe_llm_metadata::{LlmMetadataEmitter, MetadataSelection};
use disrobe_pass_py_decompile::{
    NativeDecompile, RoundtripOutcome, RoundtripStatus, decompile_pyc, roundtrip_native,
    roundtrip_skipped,
};
use disrobe_pass_py_deob::{AutoDeobOutcome, RouteKind, auto_deobfuscate};

use super::super::llm::{self as llm_cli, LlmFlags};
use super::super::progress_ui::StageSpinner;
use super::deob::print_supported_obfuscators;
use super::{DecompileBackend, py_obj_label};

pub(super) fn decompile(
    input: Option<PathBuf>,
    out: Option<PathBuf>,
    backend: DecompileBackend,
    json: bool,
    no_roundtrip: bool,
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
            "DR-CLI-0066: py decompile needs an input .pyc (or `--list` to show supported obfuscators)"
        ));
    };
    let _: Option<MetadataSelection> = llm_flags.to_selection()?;
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0060: cannot read input: {e}"))?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("py-decompile")
        .to_owned();

    let route: AutoDeobOutcome = auto_deobfuscate(&bytes, None);
    match route.kind {
        RouteKind::Deobfuscated => {
            return write_deobfuscated_decompile(&input, out, &stem, json, &route, &emit_kinds);
        }
        RouteKind::Unidentified => {
            let guidance: String = route
                .guidance
                .unwrap_or_else(|| disrobe_pass_py_deob::unidentified_guidance(&bytes));
            eprintln!("{guidance}");
            return Err(miette::miette!(
                "DR-CLI-0067: could not decompile: input is neither a known obfuscator nor a decodable .pyc"
            ));
        }
        RouteKind::CleanPyc => {}
    }
    let out_dir: PathBuf = out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-decompile")));
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-CLI-0061: cannot create out dir: {e}"))?;

    let source_path: PathBuf = out_dir.join(format!("{stem}.py"));
    let manifest_path: PathBuf = out_dir.join("manifest.json");
    let pyc: disrobe_py_marshal::PycFile = disrobe_py_marshal::read_pyc(&bytes)
        .map_err(|e| miette::miette!("DR-CLI-0051: not a valid .pyc: {e}"))?;
    let code: disrobe_py_marshal::CodeObject = match &pyc.code {
        disrobe_py_marshal::Object::Code(c) => c.as_ref().clone(),
        _ => {
            return Err(miette::miette!(
                "DR-CLI-0052: .pyc body is not a code object"
            ));
        }
    };

    let spinner: StageSpinner = StageSpinner::start("py decompile", "lifting bytecode");
    let outcome: DecompileOutcome = run_native_backend(&bytes, no_roundtrip)?;
    spinner.finish(&format!("decompiled via {}", outcome.backend_label));

    std::fs::write(&source_path, outcome.source.as_bytes())
        .map_err(|e| miette::miette!("DR-CLI-0062: cannot write decompiled source: {e}"))?;

    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.py.decompile/v1",
        "input": input.display().to_string(),
        "python_version": format!("{}.{}", pyc.header.version.major, pyc.header.version.minor),
        "backend": outcome.backend_label,
        "backend_requested": backend.label(),
        "source_path": source_path.display().to_string(),
        "external_tool": outcome.external_tool.as_ref().map(|p| p.display().to_string()),
        "native_engine_ok": outcome.native_engine_ok,
        "native_fallback_reason": outcome.native_fallback_reason,
        "roundtrip": outcome.roundtrip.as_ref().map(roundtrip_to_json),
    });
    let manifest_bytes: Vec<u8> = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| miette::miette!("DR-CLI-0063: manifest serialize: {e}"))?;
    std::fs::write(&manifest_path, manifest_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0064: cannot write manifest: {e}"))?;

    super::super::emit::apply_not_applicable_stubs(
        &emit_kinds,
        &out_dir,
        &stem,
        "py-decompile",
        "not implemented for the py pass in this build",
    )?;

    let roundtrip_label: Option<String> = outcome
        .roundtrip
        .as_ref()
        .map(|rt: &RoundtripOutcome| rt.status.as_label().to_owned());
    let llm_out: Option<llm_cli::LlmOutputs> = maybe_emit_llm_decompile(
        llm_flags,
        &input,
        &bytes,
        &source_path,
        &outcome.source,
        &pyc,
        &code,
        outcome.backend_label,
        roundtrip_label.as_deref(),
    )?;

    println!("py decompile: OK");
    println!("  input:        {}", input.display());
    println!("  backend:      {}", outcome.backend_label);
    println!(
        "  python:       {}.{}",
        pyc.header.version.major, pyc.header.version.minor
    );
    println!("  source:       {}", source_path.display());
    println!("  manifest:     {}", manifest_path.display());
    if let Some(rt) = outcome.roundtrip.as_ref() {
        println!("  roundtrip:    {}", rt.status.as_label());
        if let Some(interp) = rt.interpreter_version.as_deref() {
            println!("  interpreter:  {interp}");
        }
        if let RoundtripStatus::CodeDiff { detail } = &rt.status {
            println!("  rt-detail:    {detail}");
        }
        if let RoundtripStatus::NoInterpreter { hint } = &rt.status {
            println!("  rt-hint:      {hint}");
        }
        if let RoundtripStatus::RecompileFailed { stderr } = &rt.status {
            let first_line: &str = stderr.lines().next().unwrap_or(stderr.as_str());
            println!("  rt-error:     {first_line}");
        }
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
    if json {
        let line: String = serde_json::to_string(&manifest).unwrap_or_else(|_| "{}".to_owned());
        println!("{line}");
    }
    Ok(())
}

fn write_deobfuscated_decompile(
    input: &Path,
    out: Option<PathBuf>,
    stem: &str,
    json: bool,
    route: &AutoDeobOutcome,
    emit_kinds: &[String],
) -> miette::Result<()> {
    let source: &str = route
        .source
        .as_deref()
        .ok_or_else(|| miette::miette!("DR-CLI-0068: deobfuscation produced no source"))?;
    let out_dir: PathBuf = out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-decompile")));
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-CLI-0061: cannot create out dir: {e}"))?;
    let source_path: PathBuf = out_dir.join(format!("{stem}.py"));
    let manifest_path: PathBuf = out_dir.join("manifest.json");
    std::fs::write(&source_path, source.as_bytes())
        .map_err(|e| miette::miette!("DR-CLI-0062: cannot write decompiled source: {e}"))?;

    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.py.decompile/v1",
        "input": input.display().to_string(),
        "backend": "auto-deob",
        "detected_family": format!("{:?}", route.detection.family),
        "deob_chain": route.chain,
        "peel": route.peel,
        "source_path": source_path.display().to_string(),
    });
    let manifest_bytes: Vec<u8> = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| miette::miette!("DR-CLI-0063: manifest serialize: {e}"))?;
    std::fs::write(&manifest_path, manifest_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0064: cannot write manifest: {e}"))?;

    super::super::emit::apply_not_applicable_stubs(
        emit_kinds,
        &out_dir,
        stem,
        "py-decompile",
        "not implemented for the py pass in this build",
    )?;

    println!("py decompile: OK (auto-deobfuscated)");
    println!("  input:        {}", input.display());
    println!("  chain:        {}", route.chain.join(" -> "));
    println!("  source:       {}", source_path.display());
    println!("  manifest:     {}", manifest_path.display());
    if json {
        let line: String = serde_json::to_string(&manifest).unwrap_or_else(|_| "{}".to_owned());
        println!("{line}");
    }
    Ok(())
}

#[derive(Debug)]
struct DecompileOutcome {
    source: String,
    backend_label: &'static str,
    external_tool: Option<PathBuf>,
    native_engine_ok: bool,
    native_fallback_reason: Option<String>,
    roundtrip: Option<RoundtripOutcome>,
}

fn run_native_backend(bytes: &[u8], no_roundtrip: bool) -> miette::Result<DecompileOutcome> {
    let native: NativeDecompile = decompile_pyc(bytes)
        .map_err(|e| miette::miette!("DR-CLI-0065: native decompile engine failed: {e}"))?;
    let rt: RoundtripOutcome = if no_roundtrip {
        roundtrip_skipped()
    } else if native.recovered_directly {
        roundtrip_native(
            &native.source,
            &native.code,
            &native.decompile_version,
            native.marshal_version,
        )
    } else {
        RoundtripOutcome {
            status: RoundtripStatus::RecompileFailed {
                stderr: "native engine produced disasm fallback; skipping roundtrip".to_owned(),
            },
            interpreter_path: None,
            interpreter_version: None,
        }
    };
    Ok(DecompileOutcome {
        source: native.source,
        backend_label: "native",
        external_tool: None,
        native_engine_ok: native.recovered_directly,
        native_fallback_reason: native.fallback_reason,
        roundtrip: Some(rt),
    })
}

fn roundtrip_to_json(rt: &RoundtripOutcome) -> serde_json::Value {
    let detail: Option<serde_json::Value> = match &rt.status {
        RoundtripStatus::CodeDiff { detail } => Some(serde_json::Value::String(detail.clone())),
        RoundtripStatus::NoInterpreter { hint } => Some(serde_json::Value::String(hint.clone())),
        RoundtripStatus::RecompileFailed { stderr } => {
            Some(serde_json::Value::String(stderr.clone()))
        }
        RoundtripStatus::Perfect | RoundtripStatus::Semantic | RoundtripStatus::Skipped => None,
    };
    serde_json::json!({
        "status": rt.status.as_label(),
        "interpreter_path": rt.interpreter_path.as_ref().map(|p| p.display().to_string()),
        "interpreter_version": rt.interpreter_version,
        "detail": detail,
    })
}

#[allow(clippy::too_many_arguments)]
fn maybe_emit_llm_decompile(
    llm_flags: &LlmFlags,
    input: &Path,
    bytes: &[u8],
    source_path: &Path,
    source: &str,
    pyc: &disrobe_py_marshal::PycFile,
    code: &disrobe_py_marshal::CodeObject,
    backend: &str,
    roundtrip_status: Option<&str>,
) -> miette::Result<Option<llm_cli::LlmOutputs>> {
    let Some(selection): Option<MetadataSelection> = llm_flags.to_selection()? else {
        return Ok(None);
    };
    let started: std::time::Instant = std::time::Instant::now();
    let ins: Vec<disrobe_pass_py_disasm::Instruction> =
        disrobe_pass_py_disasm::disassemble(code, pyc.header.version);
    let disasm_v: Vec<disrobe_pass_py_decompile::LlmDisasmIns> = ins
        .iter()
        .map(
            |i: &disrobe_pass_py_disasm::Instruction| disrobe_pass_py_decompile::LlmDisasmIns {
                offset: i.offset as u64,
                opname: i.opname.clone(),
                arg: i.arg,
                argrepr: i.argrepr.clone(),
                line: i.line,
            },
        )
        .collect();
    let names: Vec<String> = code.names.iter().map(py_obj_label).collect();
    let varnames: Vec<String> = code.varnames.iter().map(py_obj_label).collect();
    let consts: Vec<String> = code.consts.iter().map(py_obj_label).collect();
    let input_size_bytes: u64 = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let hash: String = llm_cli::blake3_hex(bytes);
    let duration_ms: f64 = started.elapsed().as_secs_f64() * 1000.0_f64;
    let emitter: disrobe_pass_py_decompile::PyDecompileLlmInput =
        disrobe_pass_py_decompile::PyDecompileLlmInput {
            module_path: input.display().to_string(),
            python_version: format!("{}.{}", pyc.header.version.major, pyc.header.version.minor),
            final_source: source.to_owned(),
            backend: backend.to_owned(),
            disasm: disasm_v,
            names,
            varnames,
            consts,
            input_size_bytes,
            input_hash_blake3: hash,
            roundtrip_status: roundtrip_status.map(str::to_owned),
            duration_ms,
        };
    let envelope_map: serde_json::Value = emitter.emit_metadata(&selection);
    let step: disrobe_llm_metadata::PipelineStep = llm_cli::make_step(
        "disrobe-pass-py-decompile",
        disrobe_pass_py_decompile::VERSION,
        "disasm",
        "surface",
        duration_ms,
    );
    let mut passes: Vec<(disrobe_llm_metadata::PipelineStep, serde_json::Value)> =
        vec![(step, envelope_map)];
    passes.extend(crate::cli::ir_metadata::pass_for_bytes(
        &selection, input, bytes,
    ));
    let outputs: llm_cli::LlmOutputs =
        llm_cli::write_llm_bundle(llm_flags, &selection, input, bytes, source_path, passes)?;
    Ok(Some(outputs))
}
