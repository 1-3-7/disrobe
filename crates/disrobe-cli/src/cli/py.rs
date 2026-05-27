#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::{Subcommand, ValueEnum};

use super::emit::EmitSpec;
use super::globals;
use super::llm::{self as llm_cli, LlmFlags};

use disrobe_llm_metadata::{LlmMetadataEmitter, MetadataSelection};
use disrobe_pass_py_decompile::{
    NativeDecompile, RoundtripOutcome, RoundtripStatus, decompile_pyc, roundtrip_native,
};

#[derive(Subcommand, Debug)]
pub(crate) enum PyCmd {
    #[command(
        about = "peel a Python obfuscator wrapper (hyperion, kramer, berserker, jawbreaker, blankobf, plusobf, wodx, oxyry, pyminifier, manglify, pyobfuscate.com, ...) and optionally clean up with a ruff-AST pass"
    )]
    Deob {
        #[arg(help = "obfuscated Python source file")]
        input: PathBuf,
        #[arg(short, long, help = "output path for the deobfuscated source")]
        out: Option<PathBuf>,
        #[arg(
            long,
            help = "run ruff-AST constant-fold + dead-branch elimination after peel"
        )]
        cleanup: bool,
        #[arg(
            long,
            value_delimiter = ',',
            help = "comma-separated emit kinds: source, disasm, ast, cfg, ir, manifest, sourcemap, symbols, strings, imports, signatures, report (non-applicable kinds are written as stubs)"
        )]
        emit: Vec<String>,
    },
    #[command(
        about = "decrypt a sourcedefender .pye envelope (filename-derived password + AES + msgpack)"
    )]
    Sourcedefender {
        #[arg(help = ".pye envelope to decrypt")]
        input: PathBuf,
        #[arg(short, long, help = "output path for the decrypted msgpack payload")]
        out: Option<PathBuf>,
    },
    #[command(
        about = "disassemble a .pyc into a per-instruction trace (CPython 1.0 .. 3.15 + PyPy + MicroPython + Jython + IronPython + Brython)"
    )]
    Disasm {
        #[arg(help = ".pyc input file")]
        input: PathBuf,
        #[arg(short, long, help = "output path for the disassembly text")]
        out: Option<PathBuf>,
        #[arg(
            long,
            value_delimiter = ',',
            help = "comma-separated emit kinds: source, disasm, ast, cfg, ir, manifest, sourcemap, symbols, strings, imports, signatures, report"
        )]
        emit: Vec<String>,
    },
    #[command(
        about = "decompile a .pyc back to readable Python source (default: in-tree native engine supporting CPython 1.0..3.15 with frame-tree + per-version opcode dispatch + round-trip verification)"
    )]
    Decompile {
        #[arg(help = ".pyc input file")]
        input: PathBuf,
        #[arg(short, long, help = "output directory")]
        out: Option<PathBuf>,
        #[arg(
            long,
            value_enum,
            default_value_t = DecompileBackend::Native,
            help = "decompiler backend: `native` (in-tree engine, deterministic, no external tools) | `pycdc` | `decompyle3` | `uncompyle6` (external subprocess; must be on PATH)"
        )]
        backend: DecompileBackend,
        #[arg(
            long,
            help = "emit a JSON manifest line on stdout after the summary (sidecar always written)"
        )]
        json: bool,
        #[arg(long, value_delimiter = ',', help = "comma-separated emit kinds")]
        emit: Vec<String>,
    },
    #[command(
        about = "extract a Python wheel, sdist, egg, .whl, .zip, or any other archive container"
    )]
    Extract {
        #[arg(help = "archive to extract")]
        input: PathBuf,
        #[arg(short, long, help = "output directory")]
        out: Option<PathBuf>,
    },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum DecompileBackend {
    Native,
    Pycdc,
    Decompyle3,
    Uncompyle6,
}

impl DecompileBackend {
    const fn label(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Pycdc => "pycdc",
            Self::Decompyle3 => "decompyle3",
            Self::Uncompyle6 => "uncompyle6",
        }
    }

    const fn external_tool_name(self) -> Option<&'static str> {
        match self {
            Self::Native => None,
            Self::Pycdc => Some("pycdc"),
            Self::Decompyle3 => Some("decompyle3"),
            Self::Uncompyle6 => Some("uncompyle6"),
        }
    }
}

pub(crate) fn run(action: PyCmd, llm_flags: &LlmFlags) -> miette::Result<()> {
    match action {
        PyCmd::Deob {
            input,
            out,
            cleanup,
            emit,
        } => deob(input, out, cleanup, emit, llm_flags),
        PyCmd::Sourcedefender { input, out } => sourcedefender(input, out),
        PyCmd::Disasm { input, out, emit } => disasm(input, out, emit, llm_flags),
        PyCmd::Decompile {
            input,
            out,
            backend,
            json,
            emit,
        } => decompile(input, out, backend, json, emit, llm_flags),
        PyCmd::Extract { input, out } => extract(input, out),
    }
}

fn decompile(
    input: PathBuf,
    out: Option<PathBuf>,
    backend: DecompileBackend,
    json: bool,
    emit_kinds: Vec<String>,
    llm_flags: &LlmFlags,
) -> miette::Result<()> {
    let _: Option<MetadataSelection> = llm_flags.to_selection()?;
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0060: cannot read input: {e}"))?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("py-decompile")
        .to_owned();
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

    let outcome: DecompileOutcome = match backend {
        DecompileBackend::Native => run_native_backend(&bytes)?,
        DecompileBackend::Pycdc | DecompileBackend::Decompyle3 | DecompileBackend::Uncompyle6 => {
            run_external_backend(backend, &input, &code, pyc.header.version)?
        }
    };

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

    apply_emit_stubs(&emit_kinds, &out_dir, &stem, "py-decompile")?;

    let roundtrip_label: Option<String> = outcome
        .roundtrip
        .as_ref()
        .map(|rt: &RoundtripOutcome| rt.status.as_label().to_owned());
    let llm_out: Option<PathBuf> = maybe_emit_llm_decompile(
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
    if let Some(p) = llm_out.as_ref() {
        println!("  llm bundle:   {}", p.display());
    }
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

fn run_native_backend(bytes: &[u8]) -> miette::Result<DecompileOutcome> {
    let native: NativeDecompile = decompile_pyc(bytes)
        .map_err(|e| miette::miette!("DR-CLI-0065: native decompile engine failed: {e}"))?;
    let rt: RoundtripOutcome = if native.recovered_directly {
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

fn run_external_backend(
    backend: DecompileBackend,
    input: &Path,
    code: &disrobe_py_marshal::CodeObject,
    version: disrobe_py_marshal::PyVersion,
) -> miette::Result<DecompileOutcome> {
    let tool_name: &'static str = backend.external_tool_name().ok_or_else(|| {
        miette::miette!("DR-CLI-0066: internal: external backend without tool name")
    })?;
    let Some(tool): Option<PathBuf> = which_on_path(tool_name) else {
        return Err(miette::miette!(
            "DR-CLI-0067: backend `{tool_name}` requested but not found on PATH; install it or use --backend native"
        ));
    };
    match Command::new(&tool).arg(input).output() {
        Ok(o) if o.status.success() => Ok(DecompileOutcome {
            source: String::from_utf8_lossy(&o.stdout).into_owned(),
            backend_label: backend.label(),
            external_tool: Some(tool),
            native_engine_ok: false,
            native_fallback_reason: None,
            roundtrip: None,
        }),
        Ok(o) => {
            let header: String = format!(
                "# decompile-error: {} exited with status {:?}\n# stderr_tail:\n# {}\n",
                tool.display(),
                o.status.code(),
                String::from_utf8_lossy(&o.stderr)
                    .lines()
                    .take(20)
                    .collect::<Vec<_>>()
                    .join("\n# ")
            );
            let dis_text: String = render_disasm(code, version);
            Ok(DecompileOutcome {
                source: format!("{header}\n{dis_text}"),
                backend_label: "disasm-fallback",
                external_tool: Some(tool),
                native_engine_ok: false,
                native_fallback_reason: Some(format!(
                    "external {} exit {:?}",
                    backend.label(),
                    o.status.code()
                )),
                roundtrip: None,
            })
        }
        Err(e) => {
            let header: String = format!(
                "# decompile-error: failed to spawn {}: {e}\n",
                tool.display()
            );
            let dis_text: String = render_disasm(code, version);
            Ok(DecompileOutcome {
                source: format!("{header}\n{dis_text}"),
                backend_label: "disasm-fallback",
                external_tool: Some(tool),
                native_engine_ok: false,
                native_fallback_reason: Some(format!("spawn-error: {e}")),
                roundtrip: None,
            })
        }
    }
}

fn roundtrip_to_json(rt: &RoundtripOutcome) -> serde_json::Value {
    let detail: Option<serde_json::Value> = match &rt.status {
        RoundtripStatus::CodeDiff { detail } => Some(serde_json::Value::String(detail.clone())),
        RoundtripStatus::NoInterpreter { hint } => Some(serde_json::Value::String(hint.clone())),
        RoundtripStatus::RecompileFailed { stderr } => {
            Some(serde_json::Value::String(stderr.clone()))
        }
        RoundtripStatus::Perfect | RoundtripStatus::Semantic => None,
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
) -> miette::Result<Option<PathBuf>> {
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
    let path: PathBuf = llm_cli::write_llm_bundle(
        llm_flags,
        &selection,
        input,
        bytes,
        source_path,
        vec![(step, envelope_map)],
    )?;
    Ok(Some(path))
}

fn py_obj_label(obj: &disrobe_py_marshal::Object) -> String {
    match obj {
        disrobe_py_marshal::Object::String { value, .. }
        | disrobe_py_marshal::Object::ShortAscii { value, .. } => value.clone(),
        other => format!("{other:?}"),
    }
}

fn extract(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0070: cannot read input: {e}"))?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("py-extract")
        .to_owned();
    let out_dir: PathBuf = out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-extracted")));
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-CLI-0071: cannot create out dir: {e}"))?;
    let kind: disrobe_binfmt::ContainerKind =
        disrobe_binfmt::detect_container_with_hint(&bytes, Some(&input)).ok_or_else(|| {
            miette::miette!(
                "DR-CLI-0072: input {} is not a recognized archive (.whl/.zip/.tar/.tar.gz/.7z/.asar/...)",
                input.display()
            )
        })?;
    let result: disrobe_binfmt::ExtractionResult =
        disrobe_binfmt::extract_to(kind, &bytes, &out_dir)
            .map_err(|e| miette::miette!("DR-CLI-0073: extract failed: {e}"))?;
    let manifest_path: PathBuf = out_dir.join("manifest.json");
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.py.extract/v0",
        "input": input.display().to_string(),
        "container": result.kind.label(),
        "entries_extracted": result.entries.len(),
        "bytes_uncompressed": result.quota.total_uncompressed_bytes,
        "bytes_compressed": result.quota.total_compressed_bytes,
        "entries": result.entries.iter().map(|e| serde_json::json!({
            "name": e.name,
            "uncompressed_size": e.uncompressed_size,
            "compressed_size": e.compressed_size,
            "disk_path": e.disk_path.as_ref().map(|p| p.display().to_string()),
            "executable": e.is_executable,
        })).collect::<Vec<_>>(),
    });
    let manifest_bytes: Vec<u8> = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| miette::miette!("DR-CLI-0074: manifest serialize: {e}"))?;
    std::fs::write(&manifest_path, manifest_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0075: cannot write manifest: {e}"))?;
    println!("py extract: OK");
    println!("  input:        {}", input.display());
    println!("  container:    {}", result.kind.label());
    println!("  entries:      {}", result.entries.len());
    println!(
        "  bytes:        {} uncompressed / {} compressed",
        result.quota.total_uncompressed_bytes, result.quota.total_compressed_bytes
    );
    println!("  out dir:      {}", out_dir.display());
    println!("  manifest:     {}", manifest_path.display());
    Ok(())
}

fn render_disasm(
    code: &disrobe_py_marshal::CodeObject,
    ver: disrobe_py_marshal::PyVersion,
) -> String {
    let ins: Vec<disrobe_pass_py_disasm::Instruction> =
        disrobe_pass_py_disasm::disassemble(code, ver);
    disrobe_pass_py_disasm::render_dis(&ins)
        .lines()
        .map(|l| format!("# {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn which_on_path(exe: &str) -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        for variant in [exe, &format!("{exe}.exe")] {
            let p: PathBuf = dir.join(variant);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

fn apply_emit_stubs(
    emit_kinds: &[String],
    out_dir: &Path,
    stem: &str,
    pass: &'static str,
) -> miette::Result<()> {
    let spec: EmitSpec = EmitSpec::parse(emit_kinds);
    if spec.is_empty() {
        return Ok(());
    }
    for kind in spec.iter() {
        let _: PathBuf = super::emit::write_not_applicable_stub(
            out_dir,
            stem,
            pass,
            kind,
            "not implemented for the py pass in this build",
        )?;
    }
    Ok(())
}

fn disasm(
    input: PathBuf,
    out: Option<PathBuf>,
    emit_kinds: Vec<String>,
    llm_flags: &LlmFlags,
) -> miette::Result<()> {
    let _: Option<MetadataSelection> = llm_flags.to_selection()?;
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0050: cannot read input: {e}"))?;
    let pyc: disrobe_py_marshal::PycFile = disrobe_py_marshal::read_pyc(&bytes)
        .map_err(|e| miette::miette!("DR-CLI-0051: not a valid .pyc: {e}"))?;
    let code_obj: disrobe_py_marshal::CodeObject = match &pyc.code {
        disrobe_py_marshal::Object::Code(co) => co.as_ref().clone(),
        _ => {
            return Err(miette::miette!(
                "DR-CLI-0052: .pyc body is not a code object"
            ));
        }
    };
    let instructions: Vec<disrobe_pass_py_disasm::Instruction> =
        disrobe_pass_py_disasm::disassemble(&code_obj, pyc.header.version);
    let rendered: String = disrobe_pass_py_disasm::render_dis(&instructions);

    let out_path: PathBuf = out.unwrap_or_else(|| {
        let stem: &str = input
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("disasm");
        PathBuf::from(format!("./out/{stem}.dis.txt"))
    });
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0053: cannot create dir: {e}"))?;
    }
    std::fs::write(&out_path, &rendered)
        .map_err(|e| miette::miette!("DR-CLI-0054: cannot write disasm: {e}"))?;
    let json_path: PathBuf = out_path.with_extension("dis.json");
    std::fs::write(
        &json_path,
        serde_json::to_vec_pretty(&instructions).unwrap_or_default(),
    )
    .map_err(|e| miette::miette!("DR-CLI-0055: cannot write disasm json: {e}"))?;

    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("py-disasm")
        .to_owned();
    let stub_dir: &Path = out_path.parent().unwrap_or_else(|| Path::new("."));
    apply_emit_stubs(&emit_kinds, stub_dir, &stem, "py-disasm")?;

    let llm_out: Option<PathBuf> = maybe_emit_llm_disasm(
        llm_flags,
        &input,
        &bytes,
        &out_path,
        &instructions,
        &code_obj,
        pyc.header.version,
    )?;

    println!("py disasm: OK");
    println!("  input:        {}", input.display());
    println!(
        "  python:       {}.{}",
        pyc.header.version.major, pyc.header.version.minor
    );
    println!(
        "  pyc magic:    0x{:04x} ({})",
        pyc.header.magic, pyc.header.magic
    );
    println!("  instructions: {}", instructions.len());
    println!("  wrote:        {}", out_path.display());
    println!("  json:         {}", json_path.display());
    if let Some(p) = llm_out.as_ref() {
        println!("  llm bundle:   {}", p.display());
    }
    Ok(())
}

fn maybe_emit_llm_disasm(
    llm_flags: &LlmFlags,
    input: &Path,
    bytes: &[u8],
    out_path: &Path,
    instructions: &[disrobe_pass_py_disasm::Instruction],
    code: &disrobe_py_marshal::CodeObject,
    version: disrobe_py_marshal::PyVersion,
) -> miette::Result<Option<PathBuf>> {
    let Some(selection): Option<MetadataSelection> = llm_flags.to_selection()? else {
        return Ok(None);
    };
    let started: std::time::Instant = std::time::Instant::now();
    let names: Vec<String> = code.names.iter().map(py_obj_label).collect();
    let varnames: Vec<String> = code.varnames.iter().map(py_obj_label).collect();
    let consts: Vec<String> = code.consts.iter().map(py_obj_label).collect();
    let duration_ms: f64 = started.elapsed().as_secs_f64() * 1000.0_f64;
    let emitter: disrobe_pass_py_disasm::PyDisasmLlmInput =
        disrobe_pass_py_disasm::PyDisasmLlmInput {
            bytecode_version: format!("python.{}.{}", version.major, version.minor),
            instructions: instructions.to_vec(),
            names,
            varnames,
            consts,
            duration_ms,
        };
    let envelope_map: serde_json::Value = emitter.emit_metadata(&selection);
    let step: disrobe_llm_metadata::PipelineStep = llm_cli::make_step(
        "disrobe-pass-py-disasm",
        disrobe_pass_py_disasm::VERSION,
        "raw",
        "disasm",
        duration_ms,
    );
    let path: PathBuf = llm_cli::write_llm_bundle(
        llm_flags,
        &selection,
        input,
        bytes,
        out_path,
        vec![(step, envelope_map)],
    )?;
    Ok(Some(path))
}

fn deob(
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
        apply_emit_stubs(&emit_kinds, stub_dir, &stem, "py-deob")?;
    }

    let llm_out: Option<PathBuf> =
        maybe_emit_llm_deob(llm_flags, &input, &bytes, &out_path, &result)?;

    println!("  wrote:        {}", out_path.display());
    if let Some(mp) = manifest_path.as_ref() {
        println!("  manifest:     {}", mp.display());
    }
    if let Some(p) = llm_out.as_ref() {
        println!("  llm bundle:   {}", p.display());
    }
    Ok(())
}

fn maybe_emit_llm_deob(
    llm_flags: &LlmFlags,
    input: &Path,
    bytes: &[u8],
    out_path: &Path,
    peel: &disrobe_pass_py_deob::PeelResult,
) -> miette::Result<Option<PathBuf>> {
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
    let path: PathBuf = llm_cli::write_llm_bundle(
        llm_flags,
        &selection,
        input,
        bytes,
        out_path,
        vec![(step, envelope_map)],
    )?;
    Ok(Some(path))
}

fn sourcedefender(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0034: cannot read input: {e}"))?;
    let filename: &str = input
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("module.pye");
    let result: disrobe_pass_sourcedefender::DecryptedPye =
        disrobe_pass_sourcedefender::decrypt_pye(&bytes, filename)
            .map_err(|e| miette::miette!("{e}"))?;
    let out_path: PathBuf = out.unwrap_or_else(|| {
        let stem: &str = input
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("sourcedefender");
        PathBuf::from(format!("./out/{stem}.decrypted.bin"))
    });
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0035: cannot create dir: {e}"))?;
    }
    std::fs::write(&out_path, &result.plaintext_msgpack)
        .map_err(|e| miette::miette!("DR-CLI-0036: cannot write output: {e}"))?;
    println!("sourcedefender decrypt: OK");
    println!("  filename:     {}", result.filename);
    println!("  key:          {}", result.key_hex);
    println!("  iv:           {}", result.iv_hex);
    println!(
        "  plaintext:    {} bytes (msgpack envelope)",
        result.plaintext_msgpack.len()
    );
    println!("  wrote:        {}", out_path.display());
    Ok(())
}
