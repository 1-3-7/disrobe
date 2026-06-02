#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]

use std::ffi::OsStr;
use std::path::PathBuf;

use clap::Subcommand;

use disrobe_pass_swift_objc::{
    ContainerKind, FatArchEntry, MachoKind, ObjcClassDump, ParsedSlice, SliceReport,
    SwiftClassDump, SwiftObjcReport, analyze as analyze_macho, detect_magic, objc_class_dump,
    parse_slice, slice_bytes, swift_class_dump, walk_fat,
};

use super::emit::EmitSpec;
use super::globals;

#[derive(Subcommand, Debug)]
pub(crate) enum MachoCmd {
    #[command(
        about = "dump Mach-O / Fat-Mach-O / .ipa / .framework header, segments, sections, & encryption-info"
    )]
    Dump {
        #[arg(help = "input Mach-O binary, fat binary, framework binary, or .ipa")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output path for the dump JSON (default: ./out/<stem>-macho.json)"
        )]
        out: Option<PathBuf>,
    },
    #[command(about = "ObjC / Swift class-dump across every slice in a Mach-O / Fat-Mach-O / .ipa")]
    Classdump {
        #[arg(help = "input Mach-O / .ipa")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output directory (default: ./out/<stem>-macho-classdump)"
        )]
        out: Option<PathBuf>,
        #[arg(
            long,
            value_delimiter = ',',
            help = "comma-separated emit kinds: source, disasm, ast, cfg, ir, manifest, sourcemap, symbols, strings, imports, signatures, report"
        )]
        emit: Vec<String>,
    },
    #[command(about = "walk a Fat-Mach-O envelope & report each slice's CPU type, size, & offset")]
    Fat {
        #[arg(help = "input fat Mach-O binary")]
        input: PathBuf,
    },
}

pub(crate) fn run(action: MachoCmd) -> miette::Result<()> {
    match action {
        MachoCmd::Dump { input, out } => dump(input, out),
        MachoCmd::Classdump { input, out, emit } => classdump(input, out, emit),
        MachoCmd::Fat { input } => fat(input),
    }
}

fn dump(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0480: cannot read input: {e}"))?;
    let report: SwiftObjcReport =
        analyze_macho(&bytes).map_err(|e| miette::miette!("DR-CLI-0481: macho analyze: {e}"))?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("macho-dump")
        .to_owned();
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-macho.json")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0482: cannot create dir: {e}"))?;
    }
    let bytes_out: Vec<u8> = serde_json::to_vec_pretty(&report)
        .map_err(|e| miette::miette!("DR-CLI-0483: serialize: {e}"))?;
    std::fs::write(&out_path, bytes_out)
        .map_err(|e| miette::miette!("DR-CLI-0484: cannot write output: {e}"))?;
    println!("macho dump: OK");
    println!("  input:        {}", input.display());
    println!("  container:    {:?}", report.container);
    println!("  fat entries:  {}", report.fat_entries.len());
    println!("  slices:       {}", report.slices.len());
    for slice in &report.slices {
        println!(
            "    - {} ({}-bit): {} objc class(es), {} swift type(s), fairplay={:?}",
            slice.cpu_label,
            slice.bitness_bits,
            slice.objc.class_count,
            swift_type_count(&slice.swift),
            slice.fairplay,
        );
    }
    println!("  wrote:        {}", out_path.display());
    Ok(())
}

fn classdump(input: PathBuf, out: Option<PathBuf>, emit_kinds: Vec<String>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0490: cannot read input: {e}"))?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("macho-classdump")
        .to_owned();
    let out_dir: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-macho-classdump")));
    let g: globals::Globals = globals::current();
    if g.dry_run {
        println!("macho classdump: DRY-RUN");
        println!("  input:        {}", input.display());
        return Ok(());
    }
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-CLI-0491: cannot create out dir: {e}"))?;

    let slice_reports: Vec<DirectSliceReport> = classdump_all(&bytes)?;
    let manifest_path: PathBuf = out_dir.join("manifest.json");
    for (i, sr) in slice_reports.iter().enumerate() {
        let stem_slice: String = format!("{stem}.slice-{i:02}-{}", sr.cpu_label);
        let objc_path: PathBuf = out_dir.join(format!("{stem_slice}.objc.json"));
        let swift_path: PathBuf = out_dir.join(format!("{stem_slice}.swift.json"));
        std::fs::write(
            &objc_path,
            serde_json::to_vec_pretty(&sr.objc).unwrap_or_default(),
        )
        .map_err(|e| miette::miette!("DR-CLI-0492: cannot write objc dump: {e}"))?;
        std::fs::write(
            &swift_path,
            serde_json::to_vec_pretty(&sr.swift).unwrap_or_default(),
        )
        .map_err(|e| miette::miette!("DR-CLI-0493: cannot write swift dump: {e}"))?;
    }
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.macho.classdump/v0",
        "input": input.display().to_string(),
        "slice_count": slice_reports.len(),
        "slices": slice_reports.iter().map(|s| serde_json::json!({
            "cpu": s.cpu_label,
            "bits": s.bits,
            "objc_classes": s.objc.class_count,
            "swift_types": swift_type_count(&s.swift),
        })).collect::<Vec<_>>(),
    });
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap_or_default(),
    )
    .map_err(|e| miette::miette!("DR-CLI-0494: cannot write manifest: {e}"))?;

    apply_emit_stubs(&emit_kinds, &out_dir, &stem, "macho-classdump")?;

    println!("macho classdump: OK");
    println!("  input:        {}", input.display());
    println!("  slices:       {}", slice_reports.len());
    for sr in &slice_reports {
        println!(
            "    - {} ({}-bit): {} objc class(es), {} swift type(s)",
            sr.cpu_label,
            sr.bits,
            sr.objc.class_count,
            swift_type_count(&sr.swift)
        );
    }
    println!("  out dir:      {}", out_dir.display());
    println!("  manifest:     {}", manifest_path.display());
    Ok(())
}

fn fat(input: PathBuf) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0500: cannot read input: {e}"))?;
    let kind: MachoKind = detect_magic(&bytes)
        .ok_or_else(|| miette::miette!("DR-CLI-0501: input is not a Mach-O / fat Mach-O binary"))?;
    if !matches!(kind, MachoKind::Fat32 | MachoKind::Fat64) {
        return Err(miette::miette!(
            "DR-CLI-0502: input is a thin Mach-O ({kind:?}); use `disrobe macho dump` instead"
        ));
    }
    let entries: Vec<FatArchEntry> =
        walk_fat(&bytes).map_err(|e| miette::miette!("DR-CLI-0503: walk fat: {e}"))?;
    println!("macho fat: OK");
    println!("  input:        {}", input.display());
    println!("  envelope:     {kind:?}");
    println!("  slices:       {}", entries.len());
    for (i, entry) in entries.iter().enumerate() {
        println!(
            "    [{i}] cpu={} offset={} size={}",
            entry.cpu.label(),
            entry.offset,
            entry.size
        );
    }
    Ok(())
}

struct DirectSliceReport {
    cpu_label: String,
    bits: u32,
    objc: ObjcClassDump,
    swift: SwiftClassDump,
}

fn classdump_all(bytes: &[u8]) -> miette::Result<Vec<DirectSliceReport>> {
    let kind: MachoKind =
        detect_magic(bytes).ok_or_else(|| miette::miette!("DR-CLI-0510: not a Mach-O binary"))?;
    match kind {
        MachoKind::Fat32 | MachoKind::Fat64 => {
            let entries: Vec<FatArchEntry> =
                walk_fat(bytes).map_err(|e| miette::miette!("DR-CLI-0511: walk fat: {e}"))?;
            let mut out: Vec<DirectSliceReport> = Vec::with_capacity(entries.len());
            for entry in &entries {
                let Some(slice) = slice_bytes(bytes, entry) else {
                    continue;
                };
                if detect_magic(slice).is_none() {
                    continue;
                }
                let parsed: ParsedSlice = parse_slice(slice)
                    .map_err(|e| miette::miette!("DR-CLI-0512: parse slice: {e}"))?;
                let objc: ObjcClassDump = objc_class_dump(slice, &parsed);
                let swift: SwiftClassDump = swift_class_dump(slice, &parsed);
                let bits: u32 = bits_for(&parsed);
                out.push(DirectSliceReport {
                    cpu_label: entry.cpu.label().to_owned(),
                    bits,
                    objc,
                    swift,
                });
            }
            Ok(out)
        }
        _ => {
            let parsed: ParsedSlice =
                parse_slice(bytes).map_err(|e| miette::miette!("DR-CLI-0513: parse slice: {e}"))?;
            let objc: ObjcClassDump = objc_class_dump(bytes, &parsed);
            let swift: SwiftClassDump = swift_class_dump(bytes, &parsed);
            Ok(vec![DirectSliceReport {
                cpu_label: parsed.header.cpu.label().to_owned(),
                bits: bits_for(&parsed),
                objc,
                swift,
            }])
        }
    }
}

const fn bits_for(parsed: &ParsedSlice) -> u32 {
    match parsed.header.bitness {
        disrobe_pass_swift_objc::Bitness::Bits32 => 32,
        disrobe_pass_swift_objc::Bitness::Bits64 => 64,
    }
}

fn swift_type_count(swift: &SwiftClassDump) -> usize {
    swift.types_section.as_ref().map_or(0, |s| s.pointer_count)
}

#[allow(dead_code)]
const fn _unused_slice_report(_: &SliceReport, _: ContainerKind) {}

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
            "not implemented for the macho pass in this build",
        )?;
    }
    Ok(())
}
