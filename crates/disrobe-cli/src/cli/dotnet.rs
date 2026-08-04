#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
use std::ffi::OsStr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Subcommand, ValueEnum};

use disrobe_pass_dotnet::{
    Backend, BackendInvocation, DecompiledAssembly, PassSummary, analyze as analyze_dotnet,
    backends::{invoke_decompile, probe},
    decompile_assembly_in,
    peel::confuserex_constants::peel_confuserex_constants,
    peel::static_decrypt::{DecodedValue, RecoveredConstant},
    peel::string_emu::RecoveredString as EmulatedString,
    peel::{PeelReport, RecoveredMethod, peel_by},
    protectors::{DetectionReport, Protector, detect_all},
};

use super::emit::EmitSpec;
use super::globals;

#[derive(Subcommand, Debug)]
pub(crate) enum DotnetCmd {
    #[command(about = "decompile a .NET PE (.dll / .exe) through ILSpy, dnSpy, dnSpyEx, or de4dot")]
    Decompile {
        #[arg(help = "input .NET PE file (.dll / .exe)")]
        input: Option<PathBuf>,
        #[arg(short, long, help = "output directory (default: ./out/<stem>-dotnet)")]
        out: Option<PathBuf>,
        #[arg(
            long,
            help = "list the obfuscators/protectors disrobe can detect for this pass, then exit"
        )]
        list: bool,
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
        #[arg(
            long,
            help = "surface the recovered iterator / async state-machine MoveNext bodies (yield/await reconstruction) instead of the full assembly dump"
        )]
        recover_iterators: bool,
        #[arg(
            long,
            help = "with --recover-iterators, emit the recovered MoveNext bodies as machine-clean JSON to stdout (no human-readable summary, no file output)"
        )]
        json: bool,
    },
    #[command(
        visible_alias = "peel",
        about = "detect the .NET obfuscator/protector and peel it: decrypt resources, recover constants/strings, classify renamable identifiers, strip watermarks, or honestly wall native-VM/runtime-key protections"
    )]
    Deobfuscate {
        #[arg(help = "input obfuscated .NET PE file (.dll / .exe)")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output directory (default: ./out/<stem>-dotnet-peel)"
        )]
        out: Option<PathBuf>,
        #[arg(
            long,
            help = "force a specific protector instead of auto-detection (kebab-case, e.g. confuser-ex2, obfuscar, themida-dotnet)"
        )]
        protector: Option<String>,
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
            list,
            backend,
            timeout_secs,
            emit,
            language,
            recover_iterators,
            json,
        } => {
            if recover_iterators {
                return recover_iterators_cmd(input, language, json);
            }
            decompile(input, out, list, backend, timeout_secs, emit, language)
        }
        DotnetCmd::Deobfuscate {
            input,
            out,
            protector,
        } => deobfuscate(input, out, protector),
        DotnetCmd::Analyze { input, out } => analyze(input, out),
        DotnetCmd::Backends => backends(),
    }
}

fn decompile(
    input: Option<PathBuf>,
    out: Option<PathBuf>,
    list: bool,
    backend_choice: DotnetBackendKind,
    timeout_secs: u64,
    emit_kinds: Vec<String>,
    language: DotnetLang,
) -> miette::Result<()> {
    if list {
        super::emit::print_obfuscator_catalog(
            &disrobe_pass_dotnet::chain_detector::DotnetDetector,
            "disrobe dotnet decompile <input.dll> --out <output-dir>",
        );
        return Ok(());
    }
    let Some(input): Option<PathBuf> = input else {
        return Err(miette::miette!(
            "DR-CLI-0430b: dotnet decompile needs an input file (or `--list` to show supported obfuscators)"
        ));
    };
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
    let (invocation, backend_error): (Option<BackendInvocation>, Option<String>) =
        backend.map_or((None, None), |b: Backend| {
            match invoke_decompile(b, &input, &out_dir, Duration::from_secs(timeout_secs)) {
                Ok(inv) => (Some(inv), None),
                Err(e) => (None, Some(e.to_string())),
            }
        });

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
        "backend_error": backend_error,
    });
    let manifest_bytes: Vec<u8> = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| miette::miette!("DR-CLI-0436: serialize manifest: {e}"))?;
    std::fs::write(&manifest_path, manifest_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0434: cannot write manifest: {e}"))?;

    let native: NativeDecompileOutcome =
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
    match (backend, &backend_error) {
        (Some(b), None) => println!(
            "  backend:      {b:?} (exit={})",
            invocation.as_ref().map_or(-1, |i| i.status)
        ),
        (Some(b), Some(err)) => {
            let first_line: &str = err.lines().next().unwrap_or(err.as_str());
            println!(
                "  backend:      {b:?} FAILED: {first_line} (falling back to native CIL decompiler)"
            );
        }
        (None, _) => {
            println!("  backend:      (none available; using native CIL->C# decompiler)");
        }
    }
    match &native {
        NativeDecompileOutcome::Decompiled(asm) => println!(
            "  native {}:    {} methods (bodyless={}, failed={}) -> {}.native.{}",
            language.label(),
            asm.methods_decompiled,
            asm.methods_bodyless,
            asm.methods_failed,
            stem,
            language.ext()
        ),
        NativeDecompileOutcome::Failed(reason) => println!(
            "  native {}:    decompile failed: {reason} (manifest written; see {}.native.{})",
            language.label(),
            stem,
            language.ext()
        ),
    }
    println!("  out dir:      {}", out_dir.display());
    println!("  manifest:     {}", manifest_path.display());
    Ok(())
}

fn is_move_next_signature(signature: &str) -> bool {
    signature.contains("MoveNext")
        && (signature.contains("state machine")
            || signature.contains("[iterator")
            || signature.contains("[async"))
}

fn recover_iterators_cmd(
    input: Option<PathBuf>,
    language: DotnetLang,
    json: bool,
) -> miette::Result<()> {
    let Some(input): Option<PathBuf> = input else {
        return Err(miette::miette!(
            "DR-CLI-0460: dotnet decompile --recover-iterators needs an input file"
        ));
    };
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0461: cannot read input: {e}"))?;
    let asm: DecompiledAssembly = decompile_assembly_in(&bytes, language.to_target())
        .map_err(|e| miette::miette!("DR-CLI-0462: dotnet decompile: {e}"))?;
    let recovered: Vec<&disrobe_pass_dotnet::StructuredMethod> = asm
        .methods
        .iter()
        .filter(|m: &&disrobe_pass_dotnet::StructuredMethod| is_move_next_signature(&m.signature))
        .collect();
    if json {
        let methods: Vec<serde_json::Value> = recovered
            .iter()
            .map(|m: &&disrobe_pass_dotnet::StructuredMethod| {
                serde_json::json!({
                    "signature": m.signature,
                    "body": m.body,
                    "statement_count": m.statement_count,
                    "recovered_locals": m.recovered_locals,
                    "recovered_branches": m.recovered_branches,
                })
            })
            .collect();
        let value: serde_json::Value = serde_json::json!({
            "schema": "disrobe.dotnet.iterators/v1",
            "input": input.display().to_string(),
            "module": asm.module_name,
            "move_next_bodies": methods,
        });
        let text: String = serde_json::to_string_pretty(&value)
            .map_err(|e| miette::miette!("DR-CLI-0463: iterator serialize: {e}"))?;
        println!("{text}");
        return Ok(());
    }
    println!("dotnet decompile --recover-iterators: OK");
    println!("  input:        {}", input.display());
    println!("  module:       {}", asm.module_name);
    println!(
        "  move-next:    {} state-machine body(ies) recovered",
        recovered.len()
    );
    for m in &recovered {
        println!("  ----");
        println!("{}", m.body);
    }
    Ok(())
}

fn parse_protector(name: &str) -> miette::Result<Protector> {
    let quoted: String = format!("\"{name}\"");
    serde_json::from_str::<Protector>(&quoted).map_err(|_| {
        miette::miette!(
            "DR-CLI-0450: unknown protector '{name}'; expected kebab-case (e.g. confuser-ex2, \
             obfuscar, smart-assembly, dotnet-reactor, themida-dotnet, ilprotector, max-to-code)"
        )
    })
}

fn deobfuscate(input: PathBuf, out: Option<PathBuf>, forced: Option<String>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0451: cannot read input: {e}"))?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("dotnet-deobfuscate")
        .to_owned();
    let out_dir: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-dotnet-peel")));
    let g: globals::Globals = globals::current();
    if g.dry_run {
        println!("dotnet deobfuscate: DRY-RUN");
        println!("  input:        {}", input.display());
        return Ok(());
    }

    let detection: DetectionReport = detect_all(&bytes);
    let chosen: Option<Protector> = match forced {
        Some(name) => Some(parse_protector(&name)?),
        None => detection.primary,
    };

    let Some(protector): Option<Protector> = chosen else {
        std::fs::create_dir_all(&out_dir)
            .map_err(|e| miette::miette!("DR-CLI-0452: cannot create out dir: {e}"))?;
        let report_path: PathBuf = out_dir.join("peel.json");
        let report_json: serde_json::Value = serde_json::json!({
            "schema": "disrobe.dotnet.peel/v0",
            "input": input.display().to_string(),
            "status": "no-obfuscator-detected",
            "detected": serde_json::Value::Null,
            "candidates_seen": detection
                .matches
                .keys()
                .map(|p: &Protector| p.label())
                .collect::<Vec<&str>>(),
        });
        write_json(&report_path, &report_json)?;
        println!("dotnet deobfuscate: no obfuscator detected");
        println!("  input:        {}", input.display());
        println!("  report:       {}", report_path.display());
        return Ok(());
    };

    let report: PeelReport = match peel_by(protector, &bytes) {
        Some(Ok(r)) => r,
        Some(Err(e)) => {
            return Err(miette::miette!(
                "DR-CLI-0453: peel of {} failed: {e}",
                protector.label()
            ));
        }
        None => {
            return Err(miette::miette!(
                "DR-CLI-0454: no peel routine registered for {}",
                protector.label()
            ));
        }
    };

    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-CLI-0455: cannot create out dir: {e}"))?;

    let walled: bool = report.strategy.is_walled();
    let strings_path: PathBuf = out_dir.join(format!("{stem}.recovered-strings.txt"));
    let strings_written: usize = write_recovered_strings(
        &strings_path,
        &report.recovered_constants,
        &report.recovered_strings,
        &bytes,
    )?;
    let cil_path: PathBuf = out_dir.join(format!("{stem}.recovered-cil.txt"));
    let cil_methods_written: usize = write_recovered_cil(&cil_path, &report.recovered_methods)?;
    let report_path: PathBuf = out_dir.join("peel.json");
    let report_json: serde_json::Value = serde_json::json!({
        "schema": "disrobe.dotnet.peel/v0",
        "input": input.display().to_string(),
        "detected": protector.label(),
        "protector": protector,
        "strategy": report.strategy,
        "walled": walled,
        "attributes_stripped": report.attributes_stripped,
        "strings_total": report.strings_total,
        "strings_obfuscated_count": report.strings_obfuscated_count,
        "us_strings_total": report.us_strings_total,
        "renamable_identifiers": report.renamable_identifiers,
        "unobfuscatable_identifiers": report.unobfuscatable_identifiers,
        "recovered_decoders": report.recovered_decoders,
        "recovered_constants": report.recovered_constants,
        "recovered_strings": report.recovered_strings,
        "recovered_strings_written": strings_written,
        "recovered_methods": report.recovered_methods,
        "recovered_methods_written": cil_methods_written,
        "bytes_in": report.bytes_in,
        "bytes_out": report.bytes_out,
        "notes": report.notes,
    });
    write_json(&report_path, &report_json)?;

    println!(
        "dotnet deobfuscate: {}",
        if walled { "DETECT + WALL" } else { "OK" }
    );
    println!("  input:        {}", input.display());
    println!("  detected:     {} ({:?})", protector.label(), protector);
    println!("  strategy:     {:?}", report.strategy);
    println!(
        "  identifiers:  {} renamable / {} human-readable",
        report.renamable_identifiers, report.unobfuscatable_identifiers
    );
    println!(
        "  strings:      {} total, {} obfuscated, {} #US literals",
        report.strings_total, report.strings_obfuscated_count, report.us_strings_total
    );
    println!(
        "  recovered:    {} static decoders, {} constants ({} string literals -> {})",
        report.recovered_decoders,
        report.recovered_constants.len(),
        strings_written,
        strings_path.display()
    );
    if cil_methods_written > 0 {
        println!(
            "  devirt CIL:   {cil_methods_written} method body(ies) lifted -> {}",
            cil_path.display()
        );
    }
    if !report.attributes_stripped.is_empty() {
        println!("  watermarks:   {}", report.attributes_stripped.join(", "));
    }
    if walled {
        println!("  WALL:         protected methods were detected but not emitted");
    }
    for note in &report.notes {
        println!("  note:         {note}");
    }
    println!("  report:       {}", report_path.display());
    Ok(())
}

fn write_json(path: &std::path::Path, value: &serde_json::Value) -> miette::Result<()> {
    let bytes: Vec<u8> = serde_json::to_vec_pretty(value)
        .map_err(|e| miette::miette!("DR-CLI-0456: serialize peel report: {e}"))?;
    std::fs::write(path, bytes)
        .map_err(|e| miette::miette!("DR-CLI-0457: cannot write peel report: {e}"))?;
    Ok(())
}

fn write_recovered_strings(
    path: &std::path::Path,
    constants: &[RecoveredConstant],
    emulated: &[EmulatedString],
    bytes: &[u8],
) -> miette::Result<usize> {
    use std::fmt::Write as _;
    let mut text: String = String::with_capacity(constants.len() * 48);
    let mut count: usize = 0;
    for c in constants {
        if let DecodedValue::Utf16(s) = &c.decoded {
            let _ = writeln!(
                text,
                "static-decoder\t0x{:08X}\t{}\t{s:?}",
                c.method_token, c.method_name
            );
            count += 1;
        }
    }
    for s in emulated {
        let _ = writeln!(
            text,
            "emulated-decryptor\t0x{:08X}\t{}\t{:?}",
            s.method_token, s.method_name, s.text
        );
        count += 1;
    }
    if let Ok(Some(recovery)) = peel_confuserex_constants(bytes) {
        for rs in &recovery.strings_recovered {
            let _ = writeln!(
                text,
                "confuserex-constants\tcall_site=0x{:08X}\tmut_off={}\t{:?}",
                rs.call_site_id, rs.mutated_offset, rs.text
            );
            count += 1;
        }
    }
    std::fs::write(path, text)
        .map_err(|e| miette::miette!("DR-CLI-0458: cannot write recovered strings: {e}"))?;
    Ok(count)
}

fn write_recovered_cil(
    path: &std::path::Path,
    methods: &[RecoveredMethod],
) -> miette::Result<usize> {
    use std::fmt::Write as _;
    let mut text: String = String::with_capacity(methods.len() * 128);
    for m in methods {
        let _ = writeln!(
            text,
            "method {} token=0x{:08X} args={} locals={}",
            m.method_name, m.metadata_token, m.arg_count, m.local_count
        );
        for line in &m.cil {
            let _ = writeln!(text, "  {line}");
        }
        let _ = writeln!(text, "end");
    }
    std::fs::write(path, text)
        .map_err(|e| miette::miette!("DR-CLI-0459: cannot write recovered CIL: {e}"))?;
    Ok(methods.len())
}

enum NativeDecompileOutcome {
    Decompiled(DecompiledAssembly),
    Failed(String),
}

fn emit_native_decompilation(
    bytes: &[u8],
    out_dir: &std::path::Path,
    stem: &str,
    language: DotnetLang,
) -> miette::Result<NativeDecompileOutcome> {
    use std::fmt::Write as _;

    let cm: &str = if language == DotnetLang::Vbnet {
        "'"
    } else {
        "//"
    };
    let asm: DecompiledAssembly = match decompile_assembly_in(bytes, language.to_target()) {
        Ok(asm) => asm,
        Err(e) => {
            let reason: String = e.to_string();
            let path: PathBuf = out_dir.join(format!("{stem}.native.{}", language.ext()));
            let text: String = format!(
                "{cm} native disrobe CIL->{} decompilation FAILED\n{cm} reason: {reason}\n",
                language.label()
            );
            std::fs::write(&path, text).map_err(|w| {
                miette::miette!("DR-CLI-0437: cannot write native decompile failure note: {w}")
            })?;
            return Ok(NativeDecompileOutcome::Failed(reason));
        }
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
    Ok(NativeDecompileOutcome::Decompiled(asm))
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
