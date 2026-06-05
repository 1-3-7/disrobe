#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]

use std::ffi::OsStr;
use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};

use disrobe_pass_lua::decompile::decompile_luajit_bytes;
use disrobe_pass_lua::decompile::lua51::decompile as decompile_lua51;
use disrobe_pass_lua::{
    DecompiledChunk, DeobfOptions, DetectedFormat, LuaChunk, ObfuscatorDetection, PeelResult,
    detect as detect_lua, ironbrew2, moonsec_v1, moonsec_v2, moonsec_v3, prometheus, read_auto,
    wearedevs,
};

use super::globals;

#[derive(Subcommand, Debug)]
pub(crate) enum LuaCmd {
    #[command(
        about = "decompile a Lua 5.1 / 5.2 / 5.3 / 5.4 / LuaJIT / Luau / GLua chunk back to Lua source"
    )]
    Decompile {
        #[arg(help = "compiled Lua chunk (.luac / .lua bytecode / luajit / luau)")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output path for the decompiled source (default: ./out/<stem>.lua)"
        )]
        out: Option<PathBuf>,
        #[arg(
            long,
            value_delimiter = ',',
            help = "comma-separated emit kinds: source, disasm, ast, cfg, ir, manifest, sourcemap, symbols, strings, imports, signatures, report"
        )]
        emit: Vec<String>,
    },
    #[command(
        about = "peel a Lua obfuscator wrapper (Prometheus, MoonSec v1/v2/v3, Ironbrew2, ...)"
    )]
    Deobfuscate {
        #[arg(help = "obfuscated Lua source or bytecode file")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output path for the peeled source (default: ./out/<stem>.peeled.lua)"
        )]
        out: Option<PathBuf>,
        #[arg(
            long,
            value_enum,
            default_value_t = LuaFamilyChoice::Auto,
            help = "force a specific obfuscator family; default auto-detects"
        )]
        family: LuaFamilyChoice,
        #[arg(
            long,
            help = "acknowledge authorization for MoonSec v3 / Ironbrew2 (grey-zone)"
        )]
        i_have_authorization: bool,
    },
    #[command(about = "detect the Lua dialect & report header fields")]
    Detect {
        #[arg(help = "compiled Lua chunk")]
        input: PathBuf,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LuaFamilyChoice {
    Auto,
    Prometheus,
    MoonsecV1,
    MoonsecV2,
    MoonsecV3,
    Ironbrew2,
    Wearedevs,
}

pub(crate) fn run(action: LuaCmd) -> miette::Result<()> {
    match action {
        LuaCmd::Decompile { input, out, emit } => decompile(input, out, emit),
        LuaCmd::Deobfuscate {
            input,
            out,
            family,
            i_have_authorization,
        } => deobfuscate(input, out, family, i_have_authorization),
        LuaCmd::Detect { input } => detect(input),
    }
}

fn decompile(input: PathBuf, out: Option<PathBuf>, emit_kinds: Vec<String>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0520: cannot read input: {e}"))?;
    let format: DetectedFormat = detect_lua(&bytes);
    let chunk: LuaChunk =
        read_auto(&bytes).map_err(|e| miette::miette!("DR-CLI-0521: lua read: {e}"))?;
    let decompiled: DecompiledChunk = match format {
        DetectedFormat::Lua51
        | DetectedFormat::Lua52
        | DetectedFormat::Lua53
        | DetectedFormat::Lua54
        | DetectedFormat::Luau
        | DetectedFormat::GLua => decompile_lua51(&chunk)
            .map_err(|e| miette::miette!("DR-CLI-0522: lua51 decompile: {e}"))?,
        DetectedFormat::LuaJit => decompile_luajit_bytes(&bytes)
            .map_err(|e| miette::miette!("DR-CLI-0523: luajit decompile: {e}"))?,
        DetectedFormat::Unknown => {
            return Err(miette::miette!("DR-CLI-0524: lua dialect not recognized"));
        }
    };
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("lua-decompile")
        .to_owned();
    let out_path: PathBuf = out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}.lua")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0525: cannot create dir: {e}"))?;
    }
    std::fs::write(&out_path, decompiled.source.as_bytes())
        .map_err(|e| miette::miette!("DR-CLI-0526: cannot write output: {e}"))?;
    let manifest_path: PathBuf = out_path.with_extension("manifest.json");
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.lua.decompile/v0",
        "input": input.display().to_string(),
        "format": format!("{format:?}"),
        "fidelity": format!("{:?}", decompiled.fidelity),
        "warnings": decompiled.warnings,
    });
    let manifest_bytes: Vec<u8> = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| miette::miette!("DR-CLI-0528: serialize manifest: {e}"))?;
    std::fs::write(&manifest_path, manifest_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0527: cannot write manifest: {e}"))?;
    let stub_dir: &std::path::Path = out_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    super::emit::apply_not_applicable_stubs(
        &emit_kinds,
        stub_dir,
        &stem,
        "lua-decompile",
        "not implemented for the lua pass in this build",
    )?;
    println!("lua decompile: OK");
    println!("  input:        {}", input.display());
    println!("  format:       {format:?}");
    println!("  fidelity:     {:?}", decompiled.fidelity);
    println!("  warnings:     {}", decompiled.warnings.len());
    println!("  wrote:        {}", out_path.display());
    println!("  manifest:     {}", manifest_path.display());
    Ok(())
}

fn deobfuscate(
    input: PathBuf,
    out: Option<PathBuf>,
    family: LuaFamilyChoice,
    i_have_authorization: bool,
) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0530: cannot read input: {e}"))?;
    let g: globals::Globals = globals::current();
    let detection: Option<ObfuscatorDetection> = detect_family(&bytes, family);
    let opts: DeobfOptions = DeobfOptions {
        i_have_authorization,
        strict: false,
    };
    let result: PeelResult = match family {
        LuaFamilyChoice::Prometheus => prometheus::peel(&bytes, &opts),
        LuaFamilyChoice::MoonsecV1 => moonsec_v1::peel(&bytes, &opts),
        LuaFamilyChoice::MoonsecV2 => moonsec_v2::peel(&bytes, &opts),
        LuaFamilyChoice::MoonsecV3 => moonsec_v3::peel(&bytes, &opts),
        LuaFamilyChoice::Ironbrew2 => ironbrew2::peel(&bytes, &opts),
        LuaFamilyChoice::Wearedevs => wearedevs::peel(&bytes, &opts),
        LuaFamilyChoice::Auto => auto_peel(&bytes, &opts),
    }
    .map_err(|e| miette::miette!("DR-CLI-0531: lua deobfuscate: {e}"))?;

    if g.dry_run {
        println!("lua deobfuscate: DRY-RUN");
        println!("  input:        {}", input.display());
        println!("  family:       {family:?}");
        return Ok(());
    }
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("lua-deob")
        .to_owned();
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}.peeled.lua")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0532: cannot create dir: {e}"))?;
    }
    std::fs::write(&out_path, &result.deobfuscated)
        .map_err(|e| miette::miette!("DR-CLI-0533: cannot write output: {e}"))?;
    println!("lua deobfuscate: OK");
    println!("  input:        {}", input.display());
    println!("  family:       {family:?}");
    if let Some(d) = detection.as_ref() {
        println!(
            "  detected:     {} (confidence={})",
            d.kind.display_name(),
            d.confidence
        );
    }
    println!("  passes run:   {}", result.passes_run.len());
    for p in &result.passes_run {
        println!("    - {p}");
    }
    println!(
        "  recovered:    {} string(s)",
        result.recovered_strings.len()
    );
    println!("  fully peeled: {}", result.fully_recovered);
    println!("  residual:     {}", result.residual_markers.len());
    for r in &result.residual_markers {
        println!("    ! {r}");
    }
    println!("  wrote:        {}", out_path.display());
    Ok(())
}

fn detect(input: PathBuf) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0540: cannot read input: {e}"))?;
    let format: DetectedFormat = detect_lua(&bytes);
    println!("lua detect: OK");
    println!("  input:        {}", input.display());
    println!("  format:       {format:?}");
    if matches!(format, DetectedFormat::Unknown) {
        return Ok(());
    }
    match read_auto(&bytes) {
        Ok(chunk) => {
            println!("  dialect:      {:?}", chunk.dialect);
            println!("  proto depth:  computed from chunk root");
            println!("  constants:    {}", chunk.main.constants.len());
            println!("  protos:       {}", chunk.main.protos.len());
            println!("  code len:     {}", chunk.main.code.len());
        }
        Err(e) => {
            println!("  parse error:  {e}");
        }
    }
    Ok(())
}

fn detect_family(bytes: &[u8], family: LuaFamilyChoice) -> Option<ObfuscatorDetection> {
    match family {
        LuaFamilyChoice::Auto => prometheus::detect(bytes)
            .or_else(|| moonsec_v3::detect(bytes))
            .or_else(|| moonsec_v2::detect(bytes))
            .or_else(|| moonsec_v1::detect(bytes))
            .or_else(|| ironbrew2::detect(bytes))
            .or_else(|| wearedevs::detect(bytes)),
        LuaFamilyChoice::Prometheus => prometheus::detect(bytes),
        LuaFamilyChoice::MoonsecV1 => moonsec_v1::detect(bytes),
        LuaFamilyChoice::MoonsecV2 => moonsec_v2::detect(bytes),
        LuaFamilyChoice::MoonsecV3 => moonsec_v3::detect(bytes),
        LuaFamilyChoice::Ironbrew2 => ironbrew2::detect(bytes),
        LuaFamilyChoice::Wearedevs => wearedevs::detect(bytes),
    }
}

fn auto_peel(bytes: &[u8], opts: &DeobfOptions) -> disrobe_pass_lua::Result<PeelResult> {
    if prometheus::detect(bytes).is_some() {
        return prometheus::peel(bytes, opts);
    }
    if moonsec_v3::detect(bytes).is_some() {
        return moonsec_v3::peel(bytes, opts);
    }
    if moonsec_v2::detect(bytes).is_some() {
        return moonsec_v2::peel(bytes, opts);
    }
    if moonsec_v1::detect(bytes).is_some() {
        return moonsec_v1::peel(bytes, opts);
    }
    if ironbrew2::detect(bytes).is_some() {
        return ironbrew2::peel(bytes, opts);
    }
    if wearedevs::detect(bytes).is_some() {
        return wearedevs::peel(bytes, opts);
    }
    Err(disrobe_pass_lua::Error::NoObfuscatorSignature(
        "no known Lua obfuscator family matched",
    ))
}
