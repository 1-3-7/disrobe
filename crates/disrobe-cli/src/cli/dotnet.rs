#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Subcommand, ValueEnum};

use disrobe_pass_dotnet::aot::{AotMethod, AotMethodBody, AotReport, detect as detect_native_aot};
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

const MAX_BUNDLE_ASSEMBLIES: usize = 512;
const NATIVE_AOT_INPUT_MAX_BYTES: u64 = 1 << 29;

struct DecompileMode {
    require_native_success: bool,
    logical_input: Option<String>,
    quiet: bool,
}

struct BundleStage {
    path: PathBuf,
    committed: bool,
}

impl BundleStage {
    fn create(output: &Path) -> miette::Result<Self> {
        let parent: &Path = output
            .parent()
            .filter(|path: &&Path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent).map_err(|error: std::io::Error| {
            miette::miette!("DR-CLI-0464: cannot create output parent: {error}")
        })?;
        let token: disrobe_core::scratch::ScratchDir = disrobe_core::scratch::ScratchDir::create(
            "disrobe-dotnet-bundle-stage",
        )
        .map_err(|error: std::io::Error| {
            miette::miette!("DR-CLI-0465: cannot allocate bundle stage: {error}")
        })?;
        let token_name: &OsStr = token
            .path()
            .file_name()
            .ok_or_else(|| miette::miette!("DR-CLI-0465: bundle stage has no file name"))?;
        let output_name: &OsStr = output
            .file_name()
            .ok_or_else(|| miette::miette!("DR-CLI-0466: bundle output must name a directory"))?;
        let path: PathBuf = parent.join(format!(
            ".{}.{}",
            output_name.to_string_lossy(),
            token_name.to_string_lossy()
        ));
        std::fs::create_dir(&path).map_err(|error: std::io::Error| {
            miette::miette!("DR-CLI-0465: cannot create bundle stage: {error}")
        })?;
        Ok(Self {
            path,
            committed: false,
        })
    }

    fn commit(mut self, output: &Path) -> miette::Result<()> {
        if output.exists() {
            let mut entries: std::fs::ReadDir =
                std::fs::read_dir(output).map_err(|error: std::io::Error| {
                    miette::miette!("DR-CLI-0467: cannot inspect bundle output: {error}")
                })?;
            if entries.next().is_some() {
                return Err(miette::miette!(
                    "DR-CLI-0468: bundle output directory is not empty: {}",
                    output.display()
                ));
            }
            std::fs::remove_dir(output).map_err(|error: std::io::Error| {
                miette::miette!("DR-CLI-0469: cannot replace empty bundle output: {error}")
            })?;
        }
        std::fs::rename(&self.path, output).map_err(|error: std::io::Error| {
            miette::miette!("DR-CLI-0470: cannot publish bundle output atomically: {error}")
        })?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for BundleStage {
    fn drop(&mut self) {
        if !self.committed
            && let Err(error) = std::fs::remove_dir_all(&self.path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(path = %self.path.display(), %error, "failed to remove .NET bundle stage");
        }
    }
}

#[derive(Subcommand, Debug)]
pub(crate) enum DotnetCmd {
    #[command(about = "decompile a .NET assembly or single-file bundle")]
    Decompile {
        #[arg(help = "input .NET assembly or PE, ELF, or Mach-O single-file bundle")]
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
    #[command(
        name = "native-aot",
        about = "recover NativeAOT names, types, method boundaries and managed signatures from an ahead-of-time compiled .NET image (PE, ELF or Mach-O)"
    )]
    NativeAot {
        #[arg(help = "input NativeAOT image (PE, ELF, or Mach-O)")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output path for the recovery JSON (default: ./out/<stem>-dotnet-native-aot.json)"
        )]
        out: Option<PathBuf>,
        #[arg(
            long,
            help = "emit the recovery JSON to stdout as machine-clean output (no summary, no file written)"
        )]
        json: bool,
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
            decompile(
                input,
                out,
                list,
                backend,
                timeout_secs,
                emit,
                language,
                DecompileMode {
                    require_native_success: false,
                    logical_input: None,
                    quiet: false,
                },
            )
        }
        DotnetCmd::Deobfuscate {
            input,
            out,
            protector,
        } => deobfuscate(input, out, protector),
        DotnetCmd::Analyze { input, out } => analyze(input, out),
        DotnetCmd::NativeAot { input, out, json } => native_aot(input, out, json),
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
    mode: DecompileMode,
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
    let input_label: String = mode
        .logical_input
        .unwrap_or_else(|| input.as_os_str().to_string_lossy().into_owned());
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
    if disrobe_binfmt::containers::dotnet_bundle::detect_dotnet_bundle(&bytes).is_some() {
        return decompile_bundle(
            &input,
            &bytes,
            &out_dir,
            backend_choice,
            timeout_secs,
            &emit_kinds,
            language,
        );
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
        "input": &input_label,
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

    if mode.require_native_success {
        ensure_native_decompile_complete(&native, &input_label)?;
    }

    apply_emit_stubs(&emit_kinds, &out_dir, &stem, "dotnet-decompile")?;

    if !mode.quiet {
        println!("dotnet decompile: OK");
        println!("  input:        {input_label}");
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
    }
    Ok(())
}

fn decompile_bundle(
    input: &Path,
    bytes: &[u8],
    out_dir: &Path,
    backend_choice: DotnetBackendKind,
    timeout_secs: u64,
    emit_kinds: &[String],
    language: DotnetLang,
) -> miette::Result<()> {
    let bundle: disrobe_binfmt::containers::dotnet_bundle::DotnetBundle =
        disrobe_binfmt::containers::dotnet_bundle::parse_dotnet_bundle(bytes).map_err(
            |error: disrobe_binfmt::Error| {
                miette::miette!("DR-CLI-0471: parse .NET bundle: {error}")
            },
        )?;
    let declared_assembly_count: usize = bundle
        .files
        .iter()
        .filter(|file: &&disrobe_binfmt::containers::DotnetBundleFile| {
            matches!(
                file.file_type,
                disrobe_binfmt::containers::BundleFileType::Assembly
            )
        })
        .count();
    enforce_bundle_assembly_limit(declared_assembly_count)?;
    let stage: BundleStage = BundleStage::create(out_dir)?;
    let members_dir: PathBuf = stage.path.join("members");
    let extraction: disrobe_binfmt::ExtractionResult = disrobe_binfmt::extract_to_with_quota(
        disrobe_binfmt::ContainerKind::DotnetSingleFile,
        bytes,
        &members_dir,
        disrobe_binfmt::ExtractionQuota::default_safe(),
    )
    .map_err(|error: disrobe_binfmt::Error| {
        miette::miette!("DR-CLI-0472: extract .NET bundle: {error}")
    })?;
    if !extraction.integrity_violations.is_empty() {
        return Err(miette::miette!(
            "DR-CLI-0473: .NET bundle extraction failed integrity checks: {}",
            extraction.integrity_violations.join("; ")
        ));
    }
    let mut file_types: BTreeMap<String, disrobe_binfmt::containers::BundleFileType> =
        BTreeMap::new();
    for file in &bundle.files {
        let safe_name: String = disrobe_binfmt::sanitize_entry_path(&file.relative_path).map_err(
            |error: disrobe_binfmt::Error| {
                miette::miette!("DR-CLI-0480: invalid .NET bundle member path: {error}")
            },
        )?;
        if file_types
            .insert(safe_name.clone(), file.file_type)
            .is_some()
        {
            return Err(miette::miette!(
                "DR-CLI-0481: .NET bundle member paths collide after sanitization: `{safe_name}`"
            ));
        }
    }
    let mut assemblies: Vec<(String, PathBuf)> = Vec::new();
    for entry in &extraction.entries {
        let file_type: disrobe_binfmt::containers::BundleFileType =
            *file_types.get(&entry.name).ok_or_else(|| {
                miette::miette!(
                    "DR-CLI-0482: extracted .NET bundle member is absent from the manifest: `{}`",
                    entry.name
                )
            })?;
        let declared_assembly: bool = matches!(
            file_type,
            disrobe_binfmt::containers::BundleFileType::Assembly
        );
        let content_detected: bool = bundle.major_version == 1
            && matches!(
                file_type,
                disrobe_binfmt::containers::BundleFileType::Unknown
            );
        if !declared_assembly && !content_detected {
            continue;
        }
        let Some(member_path): Option<&PathBuf> = entry.disk_path.as_ref() else {
            continue;
        };
        let member_bytes: Vec<u8> =
            std::fs::read(member_path).map_err(|error: std::io::Error| {
                miette::miette!(
                    "DR-CLI-0474: cannot read extracted member `{}`: {error}",
                    entry.name
                )
            })?;
        if let Err(error) = analyze_dotnet(&member_bytes) {
            if declared_assembly {
                return Err(miette::miette!(
                    "DR-CLI-0483: declared managed assembly `{}` is invalid or unsupported: {error}",
                    entry.name
                ));
            }
            continue;
        }
        assemblies.push((entry.name.clone(), member_path.clone()));
        enforce_bundle_assembly_limit(assemblies.len())?;
    }
    if assemblies.is_empty() {
        return Err(miette::miette!(
            "DR-CLI-0475: .NET bundle contains no managed assembly"
        ));
    }
    let assemblies_dir: PathBuf = stage.path.join("assemblies");
    for (relative_path, member_path) in &assemblies {
        let assembly_out: PathBuf = assemblies_dir.join(relative_path);
        decompile(
            Some(member_path.clone()),
            Some(assembly_out),
            false,
            backend_choice,
            timeout_secs,
            emit_kinds.to_vec(),
            language,
            DecompileMode {
                require_native_success: true,
                logical_input: Some(format!("members/{relative_path}")),
                quiet: true,
            },
        )?;
    }
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.dotnet.bundle-decompile/v1",
        "input": input.display().to_string(),
        "bundle_version": format!("{}.{}", bundle.major_version, bundle.minor_version),
        "bundle_id": bundle.bundle_id,
        "member_count": extraction.entries.len(),
        "managed_assembly_count": assemblies.len(),
        "managed_assemblies": assemblies.iter().map(|(name, _): &(String, PathBuf)| name).collect::<Vec<_>>(),
        "quota": extraction.quota,
    });
    let manifest_bytes: Vec<u8> =
        serde_json::to_vec_pretty(&manifest).map_err(|error: serde_json::Error| {
            miette::miette!("DR-CLI-0477: serialize bundle manifest: {error}")
        })?;
    std::fs::write(stage.path.join("bundle.manifest.json"), manifest_bytes).map_err(
        |error: std::io::Error| miette::miette!("DR-CLI-0478: write bundle manifest: {error}"),
    )?;
    let member_count: usize = extraction.entries.len();
    let assembly_count: usize = assemblies.len();
    stage.commit(out_dir)?;
    println!("dotnet bundle decompile: OK");
    println!("  input:        {}", input.display());
    println!(
        "  version:      {}.{}",
        bundle.major_version, bundle.minor_version
    );
    println!("  members:      {member_count}");
    println!("  assemblies:   {assembly_count}");
    println!("  out dir:      {}", out_dir.display());
    Ok(())
}

fn enforce_bundle_assembly_limit(count: usize) -> miette::Result<()> {
    if count > MAX_BUNDLE_ASSEMBLIES {
        return Err(miette::miette!(
            "DR-CLI-0476: .NET bundle contains {count} managed assemblies; limit is {MAX_BUNDLE_ASSEMBLIES}"
        ));
    }
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

fn ensure_native_decompile_complete(
    native: &NativeDecompileOutcome,
    input_label: &str,
) -> miette::Result<()> {
    match native {
        NativeDecompileOutcome::Decompiled(assembly) if assembly.methods_failed == 0 => Ok(()),
        NativeDecompileOutcome::Decompiled(assembly) => {
            let noun: &str = if assembly.methods_failed == 1 {
                "method body"
            } else {
                "method bodies"
            };
            Err(miette::miette!(
                "DR-CLI-0479: native CIL decompilation failed for `{input_label}`: {} {noun} failed",
                assembly.methods_failed
            ))
        }
        NativeDecompileOutcome::Failed(reason) => Err(miette::miette!(
            "DR-CLI-0479: native CIL decompilation failed for `{input_label}`: {reason}"
        )),
    }
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

struct SignatureSplit {
    managed: usize,
    registers: usize,
    refused: usize,
}

impl SignatureSplit {
    fn of(methods: &[AotMethod]) -> Self {
        let mut managed: usize = 0;
        let mut registers: usize = 0;
        let mut refused: usize = 0;
        for method in methods {
            match &method.body {
                Some(AotMethodBody::Recovered { signature, .. }) => {
                    if signature.is_managed() {
                        managed = managed.saturating_add(1);
                    } else {
                        registers = registers.saturating_add(1);
                    }
                }
                Some(AotMethodBody::Refused { .. }) => refused = refused.saturating_add(1),
                None => {}
            }
        }
        Self {
            managed,
            registers,
            refused,
        }
    }
}

fn native_aot(input: PathBuf, out: Option<PathBuf>, json: bool) -> miette::Result<()> {
    let meta: std::fs::Metadata = std::fs::metadata(&input)
        .map_err(|e| miette::miette!("DR-CLI-0484: cannot stat input: {e}"))?;
    if meta.len() > NATIVE_AOT_INPUT_MAX_BYTES {
        return Err(miette::miette!(
            "DR-CLI-0484: input is {} bytes, above the {NATIVE_AOT_INPUT_MAX_BYTES} byte cap for a NativeAOT image",
            meta.len()
        ));
    }
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0484: cannot read input: {e}"))?;
    let report: AotReport = detect_native_aot(&bytes);
    if json {
        let rendered: String = serde_json::to_string_pretty(&report)
            .map_err(|e| miette::miette!("DR-CLI-0486: serialize: {e}"))?;
        println!("{rendered}");
        return Ok(());
    }
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("dotnet-native-aot")
        .to_owned();
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-dotnet-native-aot.json")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0485: cannot create dir: {e}"))?;
    }
    let bytes_out: Vec<u8> = serde_json::to_vec_pretty(&report)
        .map_err(|e| miette::miette!("DR-CLI-0486: serialize: {e}"))?;
    std::fs::write(&out_path, bytes_out)
        .map_err(|e| miette::miette!("DR-CLI-0487: cannot write output: {e}"))?;

    println!("dotnet native-aot: OK");
    println!("  input:        {}", input.display());
    if !report.is_native_aot {
        println!("  native aot:   no (nothing recovered; the image is not NativeAOT)");
        println!(
            "  next:         this command does not probe ReadyToRun or managed metadata; run \
             `disrobe dotnet analyze` for those"
        );
        println!("  wrote:        {}", out_path.display());
        return Ok(());
    }
    let methods: &[AotMethod] = &report.metadata_attribution.methods;
    let split: SignatureSplit = SignatureSplit::of(methods);
    let with_range: usize = methods
        .iter()
        .filter(|method: &&AotMethod| method.code_range.is_some())
        .count();
    let with_entrypoint: usize = methods
        .iter()
        .filter(|method: &&AotMethod| method.entrypoint_rva.is_some())
        .count();
    println!("  native aot:   yes ({:?})", report.runtime_label);
    println!(
        "  names:        {} recovered, {} symbol(s)",
        report.recovered_names.len(),
        report.recovered_symbols.len()
    );
    println!(
        "  metadata:     {} type(s), {} method(s)",
        report.metadata_attribution.types.len(),
        methods.len()
    );
    println!("  boundaries:   {with_entrypoint} entrypoint(s), {with_range} code range(s)");
    println!(
        "  signatures:   {} managed, {} register-typed, {} refused",
        split.managed, split.registers, split.refused
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

#[cfg(test)]
mod tests {
    use super::{
        DecompiledAssembly, MAX_BUNDLE_ASSEMBLIES, NativeDecompileOutcome,
        enforce_bundle_assembly_limit, ensure_native_decompile_complete,
    };

    #[test]
    fn bundle_assembly_limit_accepts_boundary() {
        assert!(enforce_bundle_assembly_limit(MAX_BUNDLE_ASSEMBLIES).is_ok());
    }

    #[test]
    fn bundle_assembly_limit_refuses_first_excess() {
        let error: Option<miette::Report> =
            enforce_bundle_assembly_limit(MAX_BUNDLE_ASSEMBLIES + 1).err();
        assert!(error.is_some_and(|report: miette::Report| {
            report.to_string().contains("513 managed assemblies")
        }));
    }

    #[test]
    fn bundle_native_decompile_refuses_partial_method_failure() {
        let native: NativeDecompileOutcome =
            NativeDecompileOutcome::Decompiled(DecompiledAssembly {
                module_name: "probe".to_owned(),
                methods: Vec::new(),
                methods_decompiled: 1,
                methods_bodyless: 0,
                methods_failed: 1,
            });
        let error: Option<String> = ensure_native_decompile_complete(&native, "members/probe.dll")
            .err()
            .map(|report: miette::Report| report.to_string());

        assert_eq!(
            error.as_deref(),
            Some(
                "DR-CLI-0479: native CIL decompilation failed for `members/probe.dll`: 1 method body failed"
            )
        );
    }
}
