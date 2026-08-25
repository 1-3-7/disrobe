#![allow(clippy::needless_pass_by_value)]
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use clap::{Subcommand, ValueEnum};

use disrobe_pass_mobile::flutter::has_dart_aot_snapshot;
use disrobe_pass_mobile::{
    AotLiftReport, Arm64Disassembly, DART_ISOLATE_DATA_SYMBOL, DART_ISOLATE_INSTR_SYMBOL,
    DART_VM_DATA_SYMBOL, DART_VM_INSTR_SYMBOL, DartAotDecompile, DartGraphObfuscationHint,
    DartGraphRecoveryOptions, DartGraphRecoveryReport, DartKernelDecompile, DartLiftedFunction,
    DartSnapshotHeader, FLUTTER_ENGINE_SYMBOL_MAP_FORMAT, FlutterEngineSymbolMap,
    FlutterObfuscationMap, LibAppLayout, ValidatedFlutterEngineSymbolMap, decompile_dart_aot,
    decompile_dart_kernel, disassemble_libapp_so, is_dart_kernel, lift_libapp_aot,
    parse_dart_snapshot, parse_flutter_engine_symbol_map_reader, parse_flutter_obfuscation_map,
    parse_libapp_so, recover_dart_pinned_elf, recover_dart_pinned_standalone,
    validate_flutter_engine_symbol_map_for_elf,
};
use disrobe_pass_native::{
    ExportFormat, RecoveredSymbol, SYMBOL_MAP_SCHEMA, SymbolClass, SymbolMap, SymbolMapProvenance,
    SymbolOrigin, render_ghidra_postscript, render_idapython, render_symbol_map_json,
};

#[cfg(feature = "chain")]
use super::backend_export::{BackendExportTarget, SupplementalOutput};
use super::emit::{EmitKind, EmitSpec};

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
        #[arg(
            long,
            value_enum,
            help = "also emit recovered function names for an analysis tool"
        )]
        format: Option<FlutterExportTarget>,
        #[arg(
            long,
            requires = "format",
            help = "validated disrobe.flutter.engine-symbol-map v1 file whose build identity must match the input"
        )]
        engine_symbol_map: Option<PathBuf>,
    },
    #[command(
        about = "recover pseudo-Dart from a Flutter libapp.so, or inspect metadata in a raw Dart AOT snapshot"
    )]
    Decompile {
        #[arg(help = "input Flutter libapp.so or raw Dart AOT snapshot blob")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output path for the recovery report JSON (default: ./out/<stem>-dart-aot.json)"
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
        about = "parse a Dart kernel (.dill / kernel_blob.bin) and recover classes, methods, fields, and byte-exact Dart source bodies"
    )]
    Kernel {
        #[arg(help = "input Dart kernel (.dill / kernel_blob.bin)")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output path for the kernel JSON (default: ./out/<stem>-dart-kernel.json)"
        )]
        out: Option<PathBuf>,
        #[arg(
            long,
            help = "accepted for compatibility; the recovered Dart source is always written next to the JSON as <stem>.recovered.dart"
        )]
        emit_source: bool,
    },
    #[command(
        about = "disassemble the ARM64 (AArch64) Dart AOT function bodies from a libapp.so into readable instructions with recovered control flow"
    )]
    Disasm {
        #[arg(help = "input Flutter libapp.so (ARM64 AOT)")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output path for the disassembly JSON (default: ./out/<stem>-arm64-disasm.json)"
        )]
        out: Option<PathBuf>,
        #[arg(long, help = "also write a flat text listing as <stem>.arm64.txt")]
        emit_listing: bool,
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
    #[command(
        about = "recover the full library/class/method/field declaration graph from a libapp.so on a pinned Dart snapshot version"
    )]
    Inventory {
        #[arg(help = "input Flutter libapp.so (pinned Dart AOT snapshot version)")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output path for the inventory JSON (default: ./out/<stem>-dart-inventory.json)"
        )]
        out: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = ObfuscationNames::Auto)]
        names: ObfuscationNames,
    },
    #[command(
        about = "recover the full declaration graph from four standalone Dart snapshot blobs, on a pinned snapshot version"
    )]
    InventoryStandalone {
        #[arg(value_name = "VM_DATA")]
        vm_data: PathBuf,
        #[arg(value_name = "VM_INSTRUCTIONS")]
        vm_instructions: PathBuf,
        #[arg(value_name = "ISOLATE_DATA")]
        isolate_data: PathBuf,
        #[arg(value_name = "ISOLATE_INSTRUCTIONS")]
        isolate_instructions: PathBuf,
        #[arg(
            short,
            long,
            help = "output path for the inventory JSON (default: ./out/<stem>-dart-inventory.json)"
        )]
        out: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = ObfuscationNames::Auto)]
        names: ObfuscationNames,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum ObfuscationNames {
    Auto,
    Source,
    Opaque,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum FlutterExportTarget {
    Ghidra,
    Ida,
    Json,
}

pub(crate) struct FlutterEngineSymbolInput {
    map: ValidatedFlutterEngineSymbolMap,
    source: String,
}

impl FlutterExportTarget {
    const fn into_pass(self) -> ExportFormat {
        match self {
            Self::Ghidra => ExportFormat::Ghidra,
            Self::Ida => ExportFormat::Ida,
            Self::Json => ExportFormat::Json,
        }
    }
}

impl ObfuscationNames {
    const fn hint(self) -> DartGraphObfuscationHint {
        match self {
            Self::Auto => DartGraphObfuscationHint::Auto,
            Self::Source => DartGraphObfuscationHint::SourceNames,
            Self::Opaque => DartGraphObfuscationHint::OpaqueNames,
        }
    }
}

pub(crate) fn run(action: FlutterCmd) -> miette::Result<()> {
    match action {
        FlutterCmd::Dump {
            input,
            out,
            format,
            engine_symbol_map,
        } => dump(input, out, format, engine_symbol_map),
        FlutterCmd::Decompile { input, out, emit } => decompile(input, out, emit),
        FlutterCmd::Kernel {
            input,
            out,
            emit_source,
        } => kernel(input, out, emit_source),
        FlutterCmd::Disasm {
            input,
            out,
            emit_listing,
        } => disasm(input, out, emit_listing),
        FlutterCmd::Map { input, out } => map(input, out),
        FlutterCmd::Inventory { input, out, names } => inventory(input, out, names),
        FlutterCmd::InventoryStandalone {
            vm_data,
            vm_instructions,
            isolate_data,
            isolate_instructions,
            out,
            names,
        } => inventory_standalone(
            vm_data,
            vm_instructions,
            isolate_data,
            isolate_instructions,
            out,
            names,
        ),
    }
}

fn kernel(input: PathBuf, out: Option<PathBuf>, _emit_source: bool) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0780: cannot read input: {e}"))?;
    if !is_dart_kernel(&bytes) {
        return Err(miette::miette!(
            "DR-CLI-0781: input is not a Dart kernel (expected magic 0x90abcdef)"
        ));
    }
    let dec: DartKernelDecompile = decompile_dart_kernel(&bytes)
        .map_err(|e| miette::miette!("DR-CLI-0782: dart kernel parse: {e}"))?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("dart-kernel")
        .to_owned();
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-dart-kernel.json")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0783: cannot create dir: {e}"))?;
    }
    let bytes_out: Vec<u8> = serde_json::to_vec_pretty(&dec.kernel)
        .map_err(|e| miette::miette!("DR-CLI-0784: serialize: {e}"))?;
    std::fs::write(&out_path, bytes_out)
        .map_err(|e| miette::miette!("DR-CLI-0785: cannot write output: {e}"))?;
    let src_path: PathBuf = out_path.with_extension("recovered.dart");
    std::fs::write(&src_path, dec.recovered_source.as_bytes())
        .map_err(|e| miette::miette!("DR-CLI-0786: cannot write source: {e}"))?;
    let classes: usize = dec.kernel.class_count;
    println!("flutter kernel: OK");
    println!("  input:        {}", input.display());
    println!("  format ver:   {}", dec.kernel.format_version);
    println!("  libraries:    {}", dec.kernel.libraries.len());
    println!("  classes:      {classes}");
    println!("  procedures:   {}", dec.kernel.procedure_count);
    println!("  fields:       {}", dec.kernel.field_count);
    println!(
        "  bodies:       {} recovered (byte-exact Dart source from the kernel source table)",
        dec.kernel.bodies_recovered
    );
    println!("  strings:      {}", dec.kernel.string_count);
    println!("  wrote:        {}", out_path.display());
    println!("  dart source:  {}", src_path.display());
    Ok(())
}

fn disasm(input: PathBuf, out: Option<PathBuf>, emit_listing: bool) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0790: cannot read input: {e}"))?;
    let disassembly: Arm64Disassembly = disassemble_libapp_so(&bytes)
        .map_err(|e| miette::miette!("DR-CLI-0791: arm64 disassemble: {e}"))?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("libapp")
        .to_owned();
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-arm64-disasm.json")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0792: cannot create dir: {e}"))?;
    }
    let bytes_out: Vec<u8> = serde_json::to_vec_pretty(&disassembly)
        .map_err(|e| miette::miette!("DR-CLI-0793: serialize: {e}"))?;
    std::fs::write(&out_path, bytes_out)
        .map_err(|e| miette::miette!("DR-CLI-0794: cannot write output: {e}"))?;
    if emit_listing {
        let listing_path: PathBuf = out_path.with_extension("arm64.txt");
        let mut listing: String = String::new();
        for func in &disassembly.functions {
            listing.push_str(&func.to_listing());
            listing.push('\n');
        }
        std::fs::write(&listing_path, listing.as_bytes())
            .map_err(|e| miette::miette!("DR-CLI-0795: cannot write listing: {e}"))?;
    }
    println!("flutter disasm: OK");
    println!("  input:        {}", input.display());
    println!("  functions:    {}", disassembly.function_count);
    println!("  instructions: {}", disassembly.total_instructions);
    println!(
        "  note:         exact Dart source is not byte-recoverable from optimized ARM64; use `flutter kernel` on a .dill for source bodies"
    );
    println!("  wrote:        {}", out_path.display());
    Ok(())
}

fn dump(
    input: PathBuf,
    out: Option<PathBuf>,
    export_target: Option<FlutterExportTarget>,
    engine_symbol_map_path: Option<PathBuf>,
) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0750: cannot read input: {e}"))?;
    let layout: LibAppLayout =
        parse_libapp_so(&bytes).map_err(|e| miette::miette!("DR-CLI-0751: libapp parse: {e}"))?;
    let engine_symbol_map: Option<FlutterEngineSymbolInput> = engine_symbol_map_path
        .as_deref()
        .map(|path: &Path| load_flutter_engine_symbol_map(path, &bytes))
        .transpose()?;
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
    let sidecar_path: Option<PathBuf> = export_target
        .map(|target: FlutterExportTarget| {
            write_flutter_symbol_export(
                &input,
                &out_path,
                &layout,
                engine_symbol_map.as_ref(),
                target,
            )
        })
        .transpose()?;
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
    if let Some(path) = sidecar_path {
        println!("  symbols:      {}", path.display());
    }
    Ok(())
}

fn write_flutter_symbol_export(
    input: &Path,
    out_path: &Path,
    layout: &LibAppLayout,
    engine_symbol_map: Option<&FlutterEngineSymbolInput>,
    target: FlutterExportTarget,
) -> miette::Result<PathBuf> {
    let format: ExportFormat = target.into_pass();
    let rendered: String =
        render_flutter_symbol_export_with_engine_map(input, layout, engine_symbol_map, format)?;
    let sidecar_path: PathBuf = out_path.with_extension(format.sidecar_extension());
    std::fs::write(&sidecar_path, rendered.as_bytes())
        .map_err(|error| miette::miette!("DR-CLI-0756: cannot write symbol export: {error}"))?;
    Ok(sidecar_path)
}

fn render_flutter_symbol_export_with_engine_map(
    input: &Path,
    layout: &LibAppLayout,
    engine_symbol_map: Option<&FlutterEngineSymbolInput>,
    format: ExportFormat,
) -> miette::Result<String> {
    let mut symbols: Vec<RecoveredSymbol> = layout
        .function_symbols
        .iter()
        .map(
            |symbol: &disrobe_pass_mobile::DartFunctionSymbol| RecoveredSymbol {
                address: symbol.address,
                name: symbol.name.clone(),
                demangled: None,
                class: SymbolClass::Function,
                origin: SymbolOrigin::SymbolTable,
                note: Some(format!(
                    "Flutter AOT function, file offset {}, size {}",
                    symbol.offset, symbol.size
                )),
            },
        )
        .collect();
    if let Some(map) = engine_symbol_map {
        let external_addresses: BTreeSet<u64> = map
            .map
            .symbols()
            .iter()
            .map(|symbol| symbol.address)
            .collect();
        symbols.retain(|symbol: &RecoveredSymbol| !external_addresses.contains(&symbol.address));
        for external in map.map.symbols() {
            symbols.push(RecoveredSymbol {
                address: external.address,
                name: external.name.clone(),
                demangled: None,
                class: SymbolClass::Function,
                origin: SymbolOrigin::CompilerRuntime,
                note: Some(format!(
                    "Flutter engine symbol from {:?} {}",
                    map.map.identity().kind,
                    map.map.identity().value
                )),
            });
        }
    }
    symbols.sort_unstable_by(|left: &RecoveredSymbol, right: &RecoveredSymbol| {
        left.address
            .cmp(&right.address)
            .then_with(|| left.name.cmp(&right.name))
    });
    symbols.dedup_by(|left: &mut RecoveredSymbol, right: &mut RecoveredSymbol| {
        left.address == right.address && left.name == right.name
    });
    let symbol_map: SymbolMap = SymbolMap {
        schema: SYMBOL_MAP_SCHEMA,
        source: input.display().to_string(),
        format: "elf-flutter-aot".to_owned(),
        image_base: 0,
        original_entry_point: None,
        symbol_count: symbols.len(),
        symbols,
        provenance: engine_symbol_map.map_or_else(Vec::new, |map| {
            vec![SymbolMapProvenance {
                source: map.source.clone(),
                kind: FLUTTER_ENGINE_SYMBOL_MAP_FORMAT.to_owned(),
                identity: Some(map.map.identity().value.clone()),
            }]
        }),
    };
    match format {
        ExportFormat::Ghidra => render_ghidra_postscript(&symbol_map)
            .map_err(|error| miette::miette!("DR-CLI-0755: symbol export: {error}")),
        ExportFormat::Ida => render_idapython(&symbol_map)
            .map_err(|error| miette::miette!("DR-CLI-0755: symbol export: {error}")),
        ExportFormat::Json => render_symbol_map_json(&symbol_map)
            .map_err(|error| miette::miette!("DR-CLI-0755: symbol export: {error}")),
    }
}

pub(crate) fn load_flutter_engine_symbol_map(
    path: &Path,
    input_bytes: &[u8],
) -> miette::Result<FlutterEngineSymbolInput> {
    let file: std::fs::File = std::fs::File::open(path).map_err(|error| {
        miette::miette!(
            "DR-CLI-0757: cannot open Flutter engine symbol map {}: {error}",
            path.display()
        )
    })?;
    let map: FlutterEngineSymbolMap = parse_flutter_engine_symbol_map_reader(file)
        .map_err(|error| miette::miette!("DR-CLI-0758: Flutter engine symbol map: {error}"))?;
    let validated: ValidatedFlutterEngineSymbolMap =
        validate_flutter_engine_symbol_map_for_elf(input_bytes, map)
            .map_err(|error| miette::miette!("DR-CLI-0759: Flutter engine symbol map: {error}"))?;
    Ok(FlutterEngineSymbolInput {
        map: validated,
        source: path.display().to_string(),
    })
}

#[cfg(feature = "chain")]
pub(crate) fn prepare_flutter_symbol_export(
    input: &Path,
    layout: &LibAppLayout,
    engine_symbol_map: Option<&FlutterEngineSymbolInput>,
    target: BackendExportTarget,
) -> miette::Result<SupplementalOutput> {
    let rendered: String = render_flutter_symbol_export_with_engine_map(
        input,
        layout,
        engine_symbol_map,
        target.format(),
    )?;
    SupplementalOutput::new(target.flutter_auto_path(), rendered.into_bytes())
}

fn decompile(input: PathBuf, out: Option<PathBuf>, emit: Vec<String>) -> miette::Result<()> {
    let spec: EmitSpec = EmitSpec::parse(&emit)?;
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0760: cannot read input: {e}"))?;
    let is_elf: bool = bytes.starts_with(b"\x7fELF");
    validate_decompile_emit(&spec, is_elf)?;
    if is_elf {
        return decompile_libapp_aot(input, bytes, out, &spec);
    }
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
    println!("  classes:      {}", dec.structure.classes.len());
    println!(
        "  methods:      {} attributed + {} unattributed",
        dec.structure
            .classes
            .iter()
            .map(|c: &disrobe_pass_mobile::DartClassEntry| c.methods.len())
            .sum::<usize>(),
        dec.structure.unattributed_methods.len()
    );
    println!("  functions:    {}", dec.structure.functions.len());
    println!("  libraries:    {}", dec.structure.library_uris.len());
    println!(
        "  clusters:     {} declared, version-keyed bodies not deserialised ({:?})",
        dec.structure.framing.num_clusters, dec.structure.framing.status
    );
    println!(
        "  fields/sigs:  not statically recoverable (version-keyed object clusters absent from artifact)"
    );
    if let Some(recovery) = dec.structure.libapp_recovery.as_ref() {
        println!(
            "  cid table:    {} (Dart {}, {:?})",
            recovery.cid_table.predefined_count,
            recovery.cid_table.dart_sdk,
            recovery.cid_table_match
        );
        println!(
            "  string pool:  {} strings ({} classes, {} get/set/init selectors, {} libraries)",
            recovery.string_pool.total_strings,
            recovery.string_pool.class_names.len(),
            recovery.recovered_selector_count,
            recovery.string_pool.library_uris.len()
        );
        println!(
            "  object pool:  {} slots over {} load sites, {} dispatch slots before blr",
            recovery.object_pool.distinct_slots,
            recovery.object_pool.total_load_sites,
            recovery.object_pool.distinct_dispatch_slots
        );
    }
    println!("  wrote:        {}", out_path.display());
    Ok(())
}

fn validate_decompile_emit(spec: &EmitSpec, is_elf: bool) -> miette::Result<()> {
    let allowed: &[EmitKind] = if is_elf {
        &[EmitKind::Source, EmitKind::Report]
    } else {
        &[EmitKind::Report]
    };
    let unsupported: Vec<&'static str> = spec
        .iter()
        .filter(|kind: &EmitKind| !allowed.contains(kind))
        .map(EmitKind::label)
        .collect();
    if unsupported.is_empty() {
        return Ok(());
    }
    let supported: Vec<&'static str> = allowed.iter().copied().map(EmitKind::label).collect();
    Err(miette::miette!(
        "DR-CLI-0766: unsupported Flutter decompile emit kind(s) {unsupported:?}; this input supports {supported:?}"
    ))
}

fn decompile_libapp_aot(
    input: PathBuf,
    bytes: Vec<u8>,
    out: Option<PathBuf>,
    spec: &EmitSpec,
) -> miette::Result<()> {
    validate_libapp_aot(&bytes)?;
    let report: AotLiftReport = lift_libapp_aot(&bytes)
        .map_err(|error| miette::miette!("DR-CLI-0767: Flutter AOT lift: {error}"))?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("libapp")
        .to_owned();
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-dart-aot.json")));
    let source_path: PathBuf = out_path.with_extension("recovered.dart");
    let want_report: bool = spec.is_empty() || spec.contains(EmitKind::Report);
    let want_source: bool = spec.is_empty() || spec.contains(EmitKind::Source);
    let report_bytes: Option<Vec<u8>> = want_report
        .then(|| serde_json::to_vec_pretty(&report))
        .transpose()
        .map_err(|error| miette::miette!("DR-CLI-0764: serialize: {error}"))?;
    let source: Option<String> = want_source.then(|| render_aot_source(&report));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| miette::miette!("DR-CLI-0763: cannot create dir: {error}"))?;
    }
    if let Some(report_bytes) = report_bytes {
        std::fs::write(&out_path, report_bytes)
            .map_err(|error| miette::miette!("DR-CLI-0765: cannot write output: {error}"))?;
    }
    if let Some(source) = source {
        std::fs::write(&source_path, source.as_bytes())
            .map_err(|error| miette::miette!("DR-CLI-0768: cannot write source: {error}"))?;
    }
    println!("flutter decompile: OK");
    println!("  input:        {}", input.display());
    println!("  functions:    {}", report.function_count);
    println!("  named:        {}", report.named_function_count);
    println!("  structured:   {}", report.structured_function_count);
    println!("  fallback:     {}", report.flat_fallback_count);
    println!(
        "  call args:    {} resolved",
        report.call_sites_with_arguments
    );
    if want_report {
        println!("  report:       {}", out_path.display());
    }
    if want_source {
        println!("  pseudo-Dart:  {}", source_path.display());
    }
    Ok(())
}

fn validate_libapp_aot(bytes: &[u8]) -> miette::Result<()> {
    if !has_dart_aot_snapshot(bytes) {
        return Err(miette::miette!(
            "DR-CLI-0767: ELF does not contain a parseable Dart AOT snapshot"
        ));
    }
    let layout: LibAppLayout = parse_libapp_so(bytes)
        .map_err(|error| miette::miette!("DR-CLI-0767: Flutter AOT layout: {error}"))?;
    let required: [(&'static str, bool); 4] = [
        (DART_VM_DATA_SYMBOL, layout.vm_snapshot_data.is_some()),
        (
            DART_VM_INSTR_SYMBOL,
            layout.vm_snapshot_instructions.is_some(),
        ),
        (
            DART_ISOLATE_DATA_SYMBOL,
            layout.isolate_snapshot_data.is_some(),
        ),
        (
            DART_ISOLATE_INSTR_SYMBOL,
            layout.isolate_snapshot_instructions.is_some(),
        ),
    ];
    if let Some((symbol, _)) = required
        .into_iter()
        .find(|(_, present): &(&str, bool)| !present)
    {
        return Err(miette::miette!(
            "DR-CLI-0767: Flutter AOT snapshot section {symbol} is missing"
        ));
    }
    Ok(())
}

fn render_aot_source(report: &AotLiftReport) -> String {
    let mut source: String = String::new();
    for function in &report.functions {
        let function: &DartLiftedFunction = function;
        if !source.is_empty() {
            source.push_str("\n\n");
        }
        source.push_str(&function.best_pseudo_dart());
    }
    source
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

fn inventory(input: PathBuf, out: Option<PathBuf>, names: ObfuscationNames) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0861: cannot read input: {e}"))?;
    let options: DartGraphRecoveryOptions = DartGraphRecoveryOptions {
        obfuscation_hint: names.hint(),
        ..DartGraphRecoveryOptions::default()
    };
    let report: DartGraphRecoveryReport = recover_dart_pinned_elf(&bytes, &options)
        .map_err(|e| miette::miette!("DR-CLI-0862: dart pinned graph recovery: {e}"))?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("dart-inventory")
        .to_owned();
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-dart-inventory.json")));
    write_inventory_report(&input, &out_path, &report)
}

#[allow(clippy::too_many_arguments)]
fn inventory_standalone(
    vm_data: PathBuf,
    vm_instructions: PathBuf,
    isolate_data: PathBuf,
    isolate_instructions: PathBuf,
    out: Option<PathBuf>,
    names: ObfuscationNames,
) -> miette::Result<()> {
    let vm_data_bytes: Vec<u8> = std::fs::read(&vm_data)
        .map_err(|e| miette::miette!("DR-CLI-0863: cannot read vm data blob: {e}"))?;
    let vm_instructions_bytes: Vec<u8> = std::fs::read(&vm_instructions)
        .map_err(|e| miette::miette!("DR-CLI-0864: cannot read vm instructions blob: {e}"))?;
    let isolate_data_bytes: Vec<u8> = std::fs::read(&isolate_data)
        .map_err(|e| miette::miette!("DR-CLI-0865: cannot read isolate data blob: {e}"))?;
    let isolate_instructions_bytes: Vec<u8> = std::fs::read(&isolate_instructions)
        .map_err(|e| miette::miette!("DR-CLI-0866: cannot read isolate instructions blob: {e}"))?;
    let options: DartGraphRecoveryOptions = DartGraphRecoveryOptions {
        obfuscation_hint: names.hint(),
        ..DartGraphRecoveryOptions::default()
    };
    let report: DartGraphRecoveryReport = recover_dart_pinned_standalone(
        &vm_data_bytes,
        &vm_instructions_bytes,
        &isolate_data_bytes,
        &isolate_instructions_bytes,
        &options,
    )
    .map_err(|e| miette::miette!("DR-CLI-0867: dart pinned graph recovery: {e}"))?;
    let stem: String = isolate_data
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("dart-inventory")
        .to_owned();
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-dart-inventory.json")));
    write_inventory_report(&isolate_data, &out_path, &report)
}

fn write_inventory_report(
    input: &std::path::Path,
    out_path: &std::path::Path,
    report: &DartGraphRecoveryReport,
) -> miette::Result<()> {
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0868: cannot create dir: {e}"))?;
    }
    let bytes_out: Vec<u8> = serde_json::to_vec_pretty(report)
        .map_err(|e| miette::miette!("DR-CLI-0869: serialize: {e}"))?;
    std::fs::write(out_path, bytes_out)
        .map_err(|e| miette::miette!("DR-CLI-0870: cannot write output: {e}"))?;
    println!("flutter inventory: OK");
    println!("  input:        {}", input.display());
    println!("  status:       {:?}", report.status);
    println!(
        "  name mode:    {:?} ({})",
        report.name_mode, report.name_mode_reason
    );
    println!("  hash:         {}", report.snapshot_compatibility_hash);
    println!(
        "  libraries:    {} ({} named)",
        report.inventory.counts.libraries, report.inventory.counts.named_classes
    );
    println!(
        "  classes:      {} ({} named)",
        report.inventory.counts.classes, report.inventory.counts.named_classes
    );
    println!(
        "  methods:      {} ({} named)",
        report.inventory.counts.methods, report.inventory.counts.named_methods
    );
    println!(
        "  fields:       {} ({} named)",
        report.inventory.counts.fields, report.inventory.counts.named_fields
    );
    for warning in &report.warnings {
        println!("  warning:      {warning}");
    }
    println!("  wrote:        {}", out_path.display());
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::panic,
    clippy::unwrap_used
)]
mod tests {
    use super::*;
    use disrobe_pass_mobile::parse_flutter_engine_symbol_map;

    fn flutter_aot_fixture() -> Vec<u8> {
        let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("mobile")
            .join("flutter")
            .join("disrobe_sample")
            .join("libapp_arm64.so");
        std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
    }

    #[test]
    fn matching_external_engine_map_reaches_the_flutter_export() {
        let input: Vec<u8> = flutter_aot_fixture();
        let native: disrobe_binfmt::NativeFile =
            disrobe_binfmt::parse_native(&input).expect("parse native image");
        let address: u64 = native
            .segments
            .iter()
            .find(|segment| segment.size != 0)
            .expect("bounded segment")
            .address;
        let map_json: String = format!(
            r#"{{"format":"disrobe.flutter.engine-symbol-map","version":1,"identity":{{"kind":"elf-build-id","value":"b71885094a73117bf90d3cfa05824129"}},"symbols":[{{"address":{address},"name":"FlutterEngineExternal"}}]}}"#
        );
        let map: FlutterEngineSymbolMap =
            parse_flutter_engine_symbol_map(map_json.as_bytes()).expect("parse matching map");
        let validated: ValidatedFlutterEngineSymbolMap =
            validate_flutter_engine_symbol_map_for_elf(&input, map).expect("matching map");
        let external: FlutterEngineSymbolInput = FlutterEngineSymbolInput {
            map: validated,
            source: "engine-symbols.json".to_owned(),
        };
        let layout: LibAppLayout = parse_libapp_so(&input).expect("parse Flutter layout");
        let rendered: String = render_flutter_symbol_export_with_engine_map(
            Path::new("libapp_arm64.so"),
            &layout,
            Some(&external),
            ExportFormat::Json,
        )
        .expect("render export");

        assert!(rendered.contains("FlutterEngineExternal"), "{rendered}");
        assert!(rendered.contains("compiler-runtime"), "{rendered}");
    }

    #[test]
    fn mismatched_external_engine_map_is_refused_before_export() {
        let input: Vec<u8> = flutter_aot_fixture();
        let map: FlutterEngineSymbolMap = parse_flutter_engine_symbol_map(
            br#"{"format":"disrobe.flutter.engine-symbol-map","version":1,"identity":{"kind":"elf-build-id","value":"00000000000000000000000000000000"},"symbols":[]}"#,
        )
        .expect("parse mismatched map");

        let error: disrobe_pass_mobile::Error =
            validate_flutter_engine_symbol_map_for_elf(&input, map).expect_err("identity mismatch");

        assert!(error.to_string().contains("does not match input build ID"));
    }

    fn encode_uint(value: u64) -> Vec<u8> {
        if value < 0x80 {
            vec![u8::try_from(value).unwrap_or(0)]
        } else if value < 0x4000 {
            vec![0x80 | ((value >> 8) as u8), (value & 0xff) as u8]
        } else {
            vec![
                0xc0 | ((value >> 24) as u8),
                ((value >> 16) & 0xff) as u8,
                ((value >> 8) & 0xff) as u8,
                (value & 0xff) as u8,
            ]
        }
    }

    fn byte_list(data: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = encode_uint(data.len() as u64);
        out.extend_from_slice(data);
        out
    }

    fn be_u32(value: u32) -> [u8; 4] {
        value.to_be_bytes()
    }

    fn build_minimal_dart_kernel(uri: &str, dart_src: &str) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&be_u32(0x90ab_cdef));
        buf.extend_from_slice(&be_u32(130));

        let source_table_offset: usize = buf.len();
        let mut source_table: Vec<u8> = Vec::new();
        source_table.extend_from_slice(&be_u32(1));
        source_table.extend_from_slice(&byte_list(uri.as_bytes()));
        source_table.extend_from_slice(&byte_list(dart_src.as_bytes()));
        source_table.extend_from_slice(&encode_uint(0));
        source_table.extend_from_slice(&byte_list(&[]));
        source_table.extend_from_slice(&encode_uint(0));
        buf.extend_from_slice(&source_table);

        let string_table_offset: usize = buf.len();
        buf.extend_from_slice(&encode_uint(0));

        let mut fixed: Vec<u8> = Vec::new();
        fixed.extend_from_slice(&be_u32(u32::try_from(source_table_offset).unwrap()));
        for _ in 1..6 {
            fixed.extend_from_slice(&be_u32(0));
        }
        fixed.extend_from_slice(&be_u32(u32::try_from(string_table_offset).unwrap()));
        fixed.extend_from_slice(&be_u32(0));
        buf.extend_from_slice(&fixed);

        buf.extend_from_slice(&be_u32(0));
        buf.extend_from_slice(&be_u32(0));
        buf.extend_from_slice(&be_u32(0));
        buf.extend_from_slice(&be_u32(u32::try_from(buf.len() + 4).unwrap()));
        buf
    }

    #[test]
    fn kernel_default_emits_byte_exact_dart_source() {
        let dart_src: &str = "class Greeter {\n  String hello() => 'hi';\n}\n";
        let kernel_bytes: Vec<u8> = build_minimal_dart_kernel("file:///lib/main.dart", dart_src);
        assert!(
            is_dart_kernel(&kernel_bytes),
            "fixture must parse as a kernel"
        );

        let scratch: PathBuf = std::env::current_dir()
            .expect("cwd")
            .join("tmp")
            .join("flutter-kernel-test");
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).expect("mk scratch");
        let in_path: PathBuf = scratch.join("kernel_blob.bin");
        std::fs::write(&in_path, &kernel_bytes).expect("write kernel");
        let out_path: PathBuf = scratch.join("out.json");

        kernel(in_path, Some(out_path.clone()), false).expect("kernel ok");

        let dart_path: PathBuf = out_path.with_extension("recovered.dart");
        assert!(
            dart_path.is_file(),
            "recovered .dart must be written by default without --emit-source"
        );
        let recovered: String = std::fs::read_to_string(&dart_path).expect("read dart");
        assert!(
            recovered.contains("class Greeter") && recovered.contains("String hello()"),
            "recovered dart must be the byte-exact source from the kernel source table: {recovered}"
        );
        let _ = std::fs::remove_dir_all(&scratch);
    }
}
