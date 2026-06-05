#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]

use std::ffi::OsStr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Subcommand, ValueEnum};

use disrobe_pass_dotnet::{
    Backend, BackendInvocation, DecompiledAssembly, PassSummary, analyze as analyze_dotnet,
    backends::{invoke_decompile, probe},
    decompile_assembly_in,
};

use super::emit::EmitSpec;
use super::globals;

#[derive(Subcommand, Debug)]
pub(crate) enum DotnetCmd {
    #[command(about = "decompile a .NET PE (.dll / .exe) through ILSpy, dnSpy, dnSpyEx, or de4dot")]
    Decompile {
        #[arg(help = "input .NET PE file (.dll / .exe)")]
        input: PathBuf,
        #[arg(short, long, help = "output directory (default: ./out/<stem>-dotnet)")]
        out: Option<PathBuf>,
        #[arg(
            long,
            value_enum,
            default_value_t = DotnetBackendKind::Auto,
            help = "decompiler backend; defaults to the first available on PATH"
        )]
        backend: DotnetBackendKind,
        #[arg(long, default_value_t = 300, help = "per-backend timeout in seconds")]
        timeout_secs: u64,
        #[arg(
            long,
            value_delimiter = ',',
            help = "comma-separated emit kinds: source, disasm, ast, cfg, ir, manifest, sourcemap, symbols, strings, imports, signatures, report"
        )]
        emit: Vec<String>,
        #[arg(
            long,
            value_enum,
            default_value_t = DotnetLang::Csharp,
            help = "native pseudo-source language: csharp, fsharp, vbnet"
        )]
        language: DotnetLang,
    },
    #[command(
        about = "static analysis of a .NET PE: PE header, CLR metadata, protector detection, ReadyToRun + NativeAOT probe"
    )]
    Analyze {
        #[arg(help = "input .NET PE file")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output path for the analysis JSON (default: ./out/<stem>-dotnet-analyze.json)"
        )]
        out: Option<PathBuf>,
    },
    #[command(about = "report available .NET backends discovered on PATH")]
    Backends,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DotnetBackendKind {
    Auto,
    Ilspy,
    Dnspy,
    DnspyEx,
    De4dot,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) enum DotnetLang {
    #[default]
    Csharp,
    Fsharp,
    Vbnet,
}

impl DotnetLang {
    const fn to_target(self) -> disrobe_pass_dotnet::TargetLang {
        match self {
            Self::Csharp => disrobe_pass_dotnet::TargetLang::CSharp,
            Self::Fsharp => disrobe_pass_dotnet::TargetLang::FSharp,
            Self::Vbnet => disrobe_pass_dotnet::TargetLang::VbNet,
        }
    }

    const fn ext(self) -> &'static str {
        match self {
            Self::Csharp => "cs",
            Self::Fsharp => "fs",
            Self::Vbnet => "vb",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Csharp => "C#",
            Self::Fsharp => "F#",
            Self::Vbnet => "VB.NET",
        }
    }
}

pub(crate) fn run(action: DotnetCmd) -> miette::Result<()> {
    match action {
        DotnetCmd::Decompile {
            input,
            out,
            backend,
            timeout_secs,
            emit,
            language,
        } => decompile(input, out, backend, timeout_secs, emit, language),
        DotnetCmd::Analyze { input, out } => analyze(input, out),
        DotnetCmd::Backends => backends(),
    }
}

fn decompile(
    input: PathBuf,
    out: Option<PathBuf>,
    backend_choice: DotnetBackendKind,
    timeout_secs: u64,
    emit_kinds: Vec<String>,
    language: DotnetLang,
) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0430: cannot read input: {e}"))?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("dotnet-decompile")
        .to_owned();
    let out_dir: PathBuf = out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-dotnet")));
    let g: globals::Globals = globals::current();
    if g.dry_run {
        println!("dotnet decompile: DRY-RUN");
        println!("  input:        {}", input.display());
        println!("  backend:      {backend_choice:?}");
        return Ok(());
    }
    let summary: PassSummary =
        analyze_dotnet(&bytes).map_err(|e| miette::miette!("DR-CLI-0431: dotnet analyze: {e}"))?;
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-CLI-0432: cannot create out dir: {e}"))?;

    let backend: Option<Backend> = pick_backend(backend_choice);
    let invocation: Option<BackendInvocation> = match backend {
        Some(b) => Some(
            invoke_decompile(b, &input, &out_dir, Duration::from_secs(timeout_secs))
                .map_err(|e| miette::miette!("DR-CLI-0433: backend {b:?} failed: {e}"))?,
        ),
        None => None,
    };

    let manifest_path: PathBuf = out_dir.join("manifest.json");
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.dotnet.decompile/v0",
        "input": input.display().to_string(),
        "pe_bitness": summary.pe_bitness,
        "machine": summary.machine,
        "clr_runtime_version": summary.clr_runtime_version,
        "runtime_label": format!("{:?}", summary.runtime_label),
        "r2r_present": summary.r2r_present,
        "native_aot": summary.native_aot,
        "primary_protector": summary.primary_protector.as_ref().map(|p| format!("{p:?}")),
        "protectors_detected": summary.protectors_detected.iter().map(|p| format!("{p:?}")).collect::<Vec<_>>(),
        "stream_names": summary.stream_names,
        "backend_invoked": backend.map(|b| format!("{b:?}")),
        "backend_exit_code": invocation.as_ref().map(|i| i.status),
    });
    let manifest_bytes: Vec<u8> = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| miette::miette!("DR-CLI-0436: serialize manifest: {e}"))?;
    std::fs::write(&manifest_path, manifest_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0434: cannot write manifest: {e}"))?;

    let native: Option<DecompiledAssembly> =
        emit_native_decompilation(&bytes, &out_dir, &stem, language)?;

    apply_emit_stubs(&emit_kinds, &out_dir, &stem, "dotnet-decompile")?;

    println!("dotnet decompile: OK");
    println!("  input:        {}", input.display());
    println!("  bitness:      {}", summary.pe_bitness);
    println!(
        "  runtime:      {} ({})",
        summary.clr_runtime_version,
        format_runtime(&summary)
    );
    println!(
        "  r2r/aot:      r2r={} aot={}",
        summary.r2r_present, summary.native_aot
    );
    if let Some(p) = summary.primary_protector.as_ref() {
        println!("  protector:    {p:?}");
    }
    if let Some(b) = backend {
        println!(
            "  backend:      {b:?} (exit={})",
            invocation.as_ref().map_or(-1, |i| i.status)
        );
    } else {
        println!("  backend:      (none available; using native CIL->C# decompiler)");
    }
    if let Some(asm) = native.as_ref() {
        println!(
            "  native {}:    {} methods (bodyless={}, failed={}) -> {}.native.{}",
            language.label(),
            asm.methods_decompiled,
            asm.methods_bodyless,
            asm.methods_failed,
            stem,
            language.ext()
        );
    }
    println!("  out dir:      {}", out_dir.display());
    println!("  manifest:     {}", manifest_path.display());
    Ok(())
}

/// Emit the native CIL-to-pseudo-source decompilation as `<stem>.native.<ext>`, returning `None` when the image is not a parseable managed PE.
fn emit_native_decompilation(
    bytes: &[u8],
    out_dir: &std::path::Path,
    stem: &str,
    language: DotnetLang,
) -> miette::Result<Option<DecompiledAssembly>> {
    use std::fmt::Write as _;

    let Ok(asm): Result<DecompiledAssembly, _> = decompile_assembly_in(bytes, language.to_target())
    else {
        return Ok(None);
    };
    let cm: &str = if language == DotnetLang::Vbnet {
        "'"
    } else {
        "//"
    };
    let mut text: String = String::with_capacity(asm.methods.len() * 128);
    let _ = writeln!(
        text,
        "{cm} native disrobe CIL->{} decompilation (no runtime, no external tool)",
        language.label()
    );
    let _ = writeln!(text, "{cm} module: {}\n", asm.module_name);
    for m in &asm.methods {
        text.push_str(&m.body);
        text.push('\n');
    }
    let path: PathBuf = out_dir.join(format!("{stem}.native.{}", language.ext()));
    std::fs::write(&path, text)
        .map_err(|e| miette::miette!("DR-CLI-0435: cannot write native decompilation: {e}"))?;
    Ok(Some(asm))
}

fn analyze(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0440: cannot read input: {e}"))?;
    let summary: PassSummary =
        analyze_dotnet(&bytes).map_err(|e| miette::miette!("DR-CLI-0441: dotnet analyze: {e}"))?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("dotnet-analyze")
        .to_owned();
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-dotnet-analyze.json")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0442: cannot create dir: {e}"))?;
    }
    let bytes_out: Vec<u8> = serde_json::to_vec_pretty(&summary)
        .map_err(|e| miette::miette!("DR-CLI-0443: serialize: {e}"))?;
    std::fs::write(&out_path, bytes_out)
        .map_err(|e| miette::miette!("DR-CLI-0444: cannot write output: {e}"))?;
    println!("dotnet analyze: OK");
    println!("  input:        {}", input.display());
    println!("  bitness:      {}", summary.pe_bitness);
    println!(
        "  runtime:      {} ({})",
        summary.clr_runtime_version,
        format_runtime(&summary)
    );
    println!(
        "  cil opcodes:  {} ({}% spec coverage)",
        summary.opcode_table_size, summary.opcode_spec_coverage_pct
    );
    println!("  wrote:        {}", out_path.display());
    Ok(())
}

fn backends() -> miette::Result<()> {
    println!("dotnet backends:");
    for b in [
        Backend::Ilspy,
        Backend::Dnspy,
        Backend::DnspyEx,
        Backend::De4dot,
    ] {
        let present: bool = probe(b);
        let mark: &str = if present { "available" } else { "missing" };
        println!("  - {b:?}: {mark}");
    }
    Ok(())
}

fn pick_backend(choice: DotnetBackendKind) -> Option<Backend> {
    let want: Option<Backend> = match choice {
        DotnetBackendKind::Ilspy => Some(Backend::Ilspy),
        DotnetBackendKind::Dnspy => Some(Backend::Dnspy),
        DotnetBackendKind::DnspyEx => Some(Backend::DnspyEx),
        DotnetBackendKind::De4dot => Some(Backend::De4dot),
        DotnetBackendKind::Auto => None,
    };
    if let Some(b) = want
        && probe(b)
    {
        return Some(b);
    }
    [
        Backend::Ilspy,
        Backend::DnspyEx,
        Backend::Dnspy,
        Backend::De4dot,
    ]
    .into_iter()
    .find(|&b: &Backend| probe(b))
}

fn format_runtime(summary: &PassSummary) -> String {
    format!("{:?}", summary.runtime_label)
}

fn apply_emit_stubs(
    emit_kinds: &[String],
    out_dir: &std::path::Path,
    stem: &str,
    pass: &'static str,
) -> miette::Result<()> {
    let spec: EmitSpec = EmitSpec::parse(emit_kinds)?;
    if spec.is_empty() {
        return Ok(());
    }
    for kind in spec.iter() {
        let _: PathBuf = super::emit::write_not_applicable_stub(
            out_dir,
            stem,
            pass,
            kind,
            "not implemented for the dotnet pass in this build",
        )?;
    }
    Ok(())
}
