#![allow(clippy::needless_pass_by_value)]

use std::ffi::OsStr;
use std::path::PathBuf;

use clap::Subcommand;

use disrobe_pass_mobile::{
    DartAotDecompile, DartSnapshotHeader, FlutterObfuscationMap, LibAppLayout, decompile_dart_aot,
    parse_dart_snapshot, parse_flutter_obfuscation_map, parse_libapp_so,
};

#[derive(Subcommand, Debug)]
pub(crate) enum FlutterCmd {
    #[command(
        about = "dump the Dart snapshot symbol layout from a Flutter libapp.so / libflutter.so"
    )]
    Dump {
        #[arg(help = "input Flutter libapp.so / libflutter.so")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output path for the layout JSON (default: ./out/<stem>-flutter.json)"
        )]
        out: Option<PathBuf>,
    },
    #[command(
        about = "best-effort decompile of a Dart AOT snapshot (header + class table estimate + readable strings)"
    )]
    Decompile {
        #[arg(help = "input Dart AOT snapshot blob")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output path for the decompile JSON (default: ./out/<stem>-dart-aot.json)"
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
        about = "parse a Flutter obfuscation_map.json into a typed lookup (original ↔ obfuscated)"
    )]
    Map {
        #[arg(help = "input obfuscation_map.json")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output path for the typed map JSON (default: ./out/<stem>-obfmap.json)"
        )]
        out: Option<PathBuf>,
    },
}

pub(crate) fn run(action: FlutterCmd) -> miette::Result<()> {
    match action {
        FlutterCmd::Dump { input, out } => dump(input, out),
        FlutterCmd::Decompile { input, out, emit } => decompile(input, out, emit),
        FlutterCmd::Map { input, out } => map(input, out),
    }
}

fn dump(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0750: cannot read input: {e}"))?;
    let layout: LibAppLayout =
        parse_libapp_so(&bytes).map_err(|e| miette::miette!("DR-CLI-0751: libapp parse: {e}"))?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("flutter-dump")
        .to_owned();
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-flutter.json")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0752: cannot create dir: {e}"))?;
    }
    let bytes_out: Vec<u8> = serde_json::to_vec_pretty(&layout)
        .map_err(|e| miette::miette!("DR-CLI-0753: serialize: {e}"))?;
    std::fs::write(&out_path, bytes_out)
        .map_err(|e| miette::miette!("DR-CLI-0754: cannot write output: {e}"))?;
    println!("flutter dump: OK");
    println!("  input:        {}", input.display());
    println!("  sections:     {}", layout.section_names.len());
    println!(
        "  vm data:      {}",
        layout
            .vm_snapshot_data
            .as_ref()
            .map_or("<missing>", |s: &disrobe_pass_mobile::SnapshotSection| s
                .symbol
                .as_str())
    );
    println!(
        "  vm instr:     {}",
        layout
            .vm_snapshot_instructions
            .as_ref()
            .map_or("<missing>", |s| s.symbol.as_str())
    );
    println!(
        "  isolate data: {}",
        layout
            .isolate_snapshot_data
            .as_ref()
            .map_or("<missing>", |s| s.symbol.as_str())
    );
    println!(
        "  isolate inst: {}",
        layout
            .isolate_snapshot_instructions
            .as_ref()
            .map_or("<missing>", |s| s.symbol.as_str())
    );
    println!("  wrote:        {}", out_path.display());
    Ok(())
}

fn decompile(input: PathBuf, out: Option<PathBuf>, emit: Vec<String>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0760: cannot read input: {e}"))?;
    let header: DartSnapshotHeader = parse_dart_snapshot(&bytes)
        .map_err(|e| miette::miette!("DR-CLI-0761: dart snapshot parse: {e}"))?;
    let dec: DartAotDecompile = decompile_dart_aot(&bytes)
        .map_err(|e| miette::miette!("DR-CLI-0762: dart aot decompile: {e}"))?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("dart-aot")
        .to_owned();
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-dart-aot.json")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0763: cannot create dir: {e}"))?;
    }
    let bytes_out: Vec<u8> = serde_json::to_vec_pretty(&dec)
        .map_err(|e| miette::miette!("DR-CLI-0764: serialize: {e}"))?;
    std::fs::write(&out_path, bytes_out)
        .map_err(|e| miette::miette!("DR-CLI-0765: cannot write output: {e}"))?;
    let stub_dir: &std::path::Path = out_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    crate::cli::emit::apply_not_applicable_stubs(
        &emit,
        stub_dir,
        &stem,
        "flutter-decompile",
        "not implemented for the flutter pass in this build",
    )?;
    println!("flutter decompile: OK");
    println!("  input:        {}", input.display());
    println!("  magic:        0x{:08x}", header.magic);
    println!("  length:       {}", header.length);
    println!("  features:     {}", header.features);
    println!(
        "  class table:  {} (estimate)",
        dec.class_table_entry_estimate
    );
    println!("  object pool:  {} (estimate)", dec.object_pool_estimate);
    println!("  readable str: {}", dec.readable_strings.len());
    println!("  wrote:        {}", out_path.display());
    Ok(())
}

fn map(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0770: cannot read input: {e}"))?;
    let parsed: FlutterObfuscationMap = parse_flutter_obfuscation_map(&bytes)
        .map_err(|e| miette::miette!("DR-CLI-0771: obfuscation map parse: {e}"))?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("flutter-obfmap")
        .to_owned();
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-obfmap.json")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0772: cannot create dir: {e}"))?;
    }
    let bytes_out: Vec<u8> = serde_json::to_vec_pretty(&parsed)
        .map_err(|e| miette::miette!("DR-CLI-0773: serialize: {e}"))?;
    std::fs::write(&out_path, bytes_out)
        .map_err(|e| miette::miette!("DR-CLI-0774: cannot write output: {e}"))?;
    println!("flutter map: OK");
    println!("  input:        {}", input.display());
    println!("  entries:      {}", parsed.entries);
    println!("  wrote:        {}", out_path.display());
    Ok(())
}
