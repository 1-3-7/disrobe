use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use clap::Subcommand;
use disrobe_pass_swift_objc::asset_catalog::{
    AssetCatalog, CatalogFile, RenditionPayload, catalog_files, decode_asset_catalog,
};
use disrobe_pass_swift_objc::keyed_archive::{ArchivedValue, KeyedArchive, decode_keyed_archive};
use disrobe_pass_swift_objc::nib_archive::{NibArchive, decode_nib_archive};

use disrobe_pass_swift_objc::{
    ContainerKind, DyldCacheFamily, DyldSharedCache, FatArchEntry, MachoKind, ObjcClassDump,
    ParsedSlice, ReconstructBatch, ReconstructOptions, SliceReport, SwiftClassDump,
    SwiftObjcReport, analyze as analyze_macho, detect_magic, is_dyld_shared_cache, objc_class_dump,
    open_dyld_cache_family, parse_slice, reconstruct_dyld_cache_family, slice_bytes,
    swift_class_dump, walk_fat,
};

use super::emit::EmitSpec;
use super::globals;

#[derive(Subcommand, Debug)]
pub(crate) enum MachoCmd {
    #[command(
        about = "dump Mach-O / Fat-Mach-O / .ipa header, segments, sections, & encryption-info"
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
    #[command(about = "ObjC / Swift class-dump across every slice in a raw Mach-O / Fat-Mach-O")]
    Classdump {
        #[arg(help = "input raw Mach-O or Fat-Mach-O binary")]
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
    #[command(
        about = "decode an NSKeyedArchiver archive (binary or XML plist) into its object graph: arrays, sets, dictionaries, strings, data, dates, URLs, UUIDs and custom classes with their fields, with cycles shown as back-references"
    )]
    KeyedArchive {
        #[arg(
            help = "input keyed archive (.plist, .archive, NIB keyed data, NSUserDefaults blob)"
        )]
        input: PathBuf,
        #[arg(long, help = "print the decoded graph as JSON")]
        json: bool,
    },
    #[command(
        about = "decode a compiled NIB (NIBArchive, from a .nib file or a storyboardc bundle) into its object graph, with the outlet and action connections that tie the interface to code, the custom classes it instantiates and its strings"
    )]
    Nib {
        #[arg(help = "input compiled .nib file")]
        input: PathBuf,
        #[arg(long, help = "print the decoded graph as JSON")]
        json: bool,
    },
    #[command(
        about = "decode a compiled asset catalog (Assets.car): header, key format, appearances, facets and every rendition with its key attributes, pixel format, compression, colour components or data UTI and digests; --extract writes the data sets and decodable images"
    )]
    Car {
        #[arg(help = "input compiled Assets.car")]
        input: PathBuf,
        #[arg(long, help = "print the decoded catalog as JSON")]
        json: bool,
        #[arg(
            long,
            value_name = "DIR",
            help = "write every data set and decodable image here"
        )]
        extract: Option<PathBuf>,
    },
    #[command(about = "walk a Fat-Mach-O envelope & report each slice's CPU type, size, & offset")]
    Fat {
        #[arg(help = "input fat Mach-O binary")]
        input: PathBuf,
    },
    #[command(
        about = "recover the bundled dylibs from a dyld shared cache into standalone Mach-O images"
    )]
    Dyldcache {
        #[arg(
            help = "input dyld shared cache file; split caches read their .01, .02, ... and .symbols subcaches from the same directory"
        )]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output directory (default: ./out/<stem>-dyld-dylibs)"
        )]
        out: Option<PathBuf>,
        #[arg(
            long = "image",
            value_name = "INSTALL_NAME",
            help = "extract only the image with this install name (repeatable)"
        )]
        images: Vec<String>,
    },
}

pub(crate) fn run(action: MachoCmd) -> miette::Result<()> {
    match action {
        MachoCmd::Dump { input, out } => dump(input, out),
        MachoCmd::Classdump { input, out, emit } => classdump(input, out, emit),
        MachoCmd::KeyedArchive { input, json } => keyed_archive(&input, json),
        MachoCmd::Nib { input, json } => nib(&input, json),
        MachoCmd::Car {
            input,
            json,
            extract,
        } => car(&input, json, extract.as_deref()),
        MachoCmd::Fat { input } => fat(input),
        MachoCmd::Dyldcache { input, out, images } => dyldcache(input, out, images),
    }
}

const MAX_CAR_BYTES: u64 = 1024 * 1024 * 1024;

fn car(input: &Path, json: bool, extract: Option<&Path>) -> miette::Result<()> {
    let size: u64 = std::fs::metadata(input)
        .map_err(|e| miette::miette!("DR-CLI-0993: cannot read {}: {e}", input.display()))?
        .len();
    if size > MAX_CAR_BYTES {
        return Err(miette::miette!(
            "DR-CLI-0993: {} is {size} bytes, above the {MAX_CAR_BYTES}-byte limit",
            input.display()
        ));
    }
    let bytes: Vec<u8> = std::fs::read(input)
        .map_err(|e| miette::miette!("DR-CLI-0993: cannot read {}: {e}", input.display()))?;
    let catalog: AssetCatalog = decode_asset_catalog(&bytes)
        .map_err(|e| miette::miette!("DR-CLI-0993: {}: {e}", input.display()))?;
    if let Some(dir) = extract {
        let files: Vec<CatalogFile> = catalog_files(&bytes, &catalog)
            .map_err(|e| miette::miette!("DR-CLI-0993: {}: {e}", input.display()))?;
        for file in &files {
            let path: PathBuf = dir.join(&file.path);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    miette::miette!("DR-CLI-0993: cannot create {}: {e}", parent.display())
                })?;
            }
            std::fs::write(&path, &file.bytes).map_err(|e| {
                miette::miette!("DR-CLI-0993: cannot write {}: {e}", path.display())
            })?;
        }
        eprintln!("wrote {} file(s) to {}", files.len(), dir.display());
    }
    if json {
        let rendered: String = serde_json::to_string_pretty(&catalog)
            .map_err(|e| miette::miette!("DR-CLI-0993: serialize: {e}"))?;
        println!("{rendered}");
        return Ok(());
    }
    println!(
        "asset catalog: CoreUI {}, storage {}, schema {}, {} renditions, {} facets",
        catalog.header.core_ui_version,
        catalog.header.storage_version,
        catalog.header.schema_version,
        catalog.renditions.len(),
        catalog.facets.len()
    );
    println!("version: {}", catalog.header.version);
    if let Some(metadata) = &catalog.metadata {
        println!(
            "platform: {} {}; tool: {}",
            metadata.deployment_platform,
            metadata.deployment_platform_version,
            metadata.authoring_tool
        );
    }
    println!("key format: {}", catalog.key_format.join(", "));
    for rendition in &catalog.renditions {
        let detail: String = match &rendition.payload {
            RenditionPayload::Pixels {
                compression,
                length,
                ..
            } => format!(
                "{} {}x{} {compression} {length} bytes",
                rendition.pixel_format, rendition.width, rendition.height
            ),
            RenditionPayload::Color {
                color_space_id,
                components,
            } => format!("colour space {color_space_id} {components:?}"),
            RenditionPayload::Data { length, .. } => format!(
                "data {} {length} bytes",
                rendition.uti.as_deref().unwrap_or("?")
            ),
            RenditionPayload::MultisizeImageSet { sizes } => {
                format!("multisize set of {}", sizes.len())
            }
            RenditionPayload::Other { name, length, .. } => format!("{name} {length} bytes"),
            RenditionPayload::Empty => "empty".to_owned(),
        };
        println!(
            "{} / {} [{} {}x {}] {}",
            rendition.asset.as_deref().unwrap_or("?"),
            rendition.name,
            rendition.idiom.as_deref().unwrap_or("?"),
            rendition.scale.unwrap_or(0),
            rendition.appearance.as_deref().unwrap_or("any"),
            detail
        );
    }
    Ok(())
}

const MAX_NIB_BYTES: u64 = 256 * 1024 * 1024;

fn nib(input: &Path, json: bool) -> miette::Result<()> {
    let size: u64 = std::fs::metadata(input)
        .map_err(|e| miette::miette!("DR-CLI-0506: cannot read {}: {e}", input.display()))?
        .len();
    if size > MAX_NIB_BYTES {
        return Err(miette::miette!(
            "DR-CLI-0506: {} is {size} bytes, above the {MAX_NIB_BYTES}-byte limit",
            input.display()
        ));
    }
    let bytes: Vec<u8> = std::fs::read(input)
        .map_err(|e| miette::miette!("DR-CLI-0506: cannot read {}: {e}", input.display()))?;
    let archive: NibArchive = decode_nib_archive(&bytes)
        .map_err(|e| miette::miette!("DR-CLI-0506: {}: {e}", input.display()))?;
    if json {
        let rendered: String = serde_json::to_string_pretty(&archive)
            .map_err(|e| miette::miette!("DR-CLI-0506: serialize: {e}"))?;
        println!("{rendered}");
        return Ok(());
    }
    println!(
        "NIBArchive version {}, coder {}, {} objects of {} classes",
        archive.format_version,
        archive.coder_version,
        archive.objects.len(),
        archive.classes.len()
    );
    if !archive.custom_classes.is_empty() {
        println!("custom classes: {}", archive.custom_classes.join(", "));
    }
    for connection in &archive.connections {
        println!(
            "{} {} : {} -> {}",
            connection.kind,
            connection.label.as_deref().unwrap_or("?"),
            connection.source_class.as_deref().unwrap_or("?"),
            connection.destination_class.as_deref().unwrap_or("?")
        );
    }
    let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for object in &archive.objects {
        *counts.entry(object.class.as_str()).or_default() += 1;
    }
    for (class, count) in counts {
        println!("  {count:>4} {class}");
    }
    for text in &archive.strings {
        println!("string {text:?}");
    }
    if archive.trailing_bytes > 0 {
        println!("{} bytes follow the last table", archive.trailing_bytes);
    }
    Ok(())
}

const MAX_KEYED_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;

fn keyed_archive(input: &Path, json: bool) -> miette::Result<()> {
    let size: u64 = std::fs::metadata(input)
        .map_err(|e| miette::miette!("DR-CLI-0419: cannot read {}: {e}", input.display()))?
        .len();
    if size > MAX_KEYED_ARCHIVE_BYTES {
        return Err(miette::miette!(
            "DR-CLI-0419: {} is {size} bytes, above the {MAX_KEYED_ARCHIVE_BYTES}-byte limit",
            input.display()
        ));
    }
    let bytes: Vec<u8> = std::fs::read(input)
        .map_err(|e| miette::miette!("DR-CLI-0419: cannot read {}: {e}", input.display()))?;
    let archive: KeyedArchive = decode_keyed_archive(&bytes)
        .map_err(|e| miette::miette!("DR-CLI-0419: {}: {e}", input.display()))?;
    if json {
        let rendered: String = serde_json::to_string_pretty(&archive)
            .map_err(|e| miette::miette!("DR-CLI-0419: serialize: {e}"))?;
        println!("{rendered}");
        return Ok(());
    }
    println!(
        "{} archive, version {}, {} objects",
        archive.archiver,
        archive
            .version
            .map_or_else(|| "unknown".to_owned(), |version: i128| version.to_string()),
        archive.objects
    );
    for (key, value) in &archive.top {
        print_archived(key, value, 1);
    }
    for problem in &archive.problems {
        println!("problem: {problem}");
    }
    Ok(())
}

fn print_archived(label: &str, value: &ArchivedValue, depth: usize) {
    let indent: String = "  ".repeat(depth);
    let line = |text: String| println!("{indent}{label}: {text}");
    match value {
        ArchivedValue::Null => line("nil".to_owned()),
        ArchivedValue::Bool { value } => line(value.to_string()),
        ArchivedValue::Integer { value } => line(value.to_string()),
        ArchivedValue::Real { value } => line(value.to_string()),
        ArchivedValue::String { value } => line(format!("{value:?}")),
        ArchivedValue::Data { hex } => line(format!("<{} bytes> {hex}", hex.len() / 2)),
        ArchivedValue::Date {
            seconds_since_2001,
            unix,
        } => line(format!("date {seconds_since_2001} (unix {unix})")),
        ArchivedValue::Uuid { value } => line(format!("UUID {value}")),
        ArchivedValue::BackReference { uid } => line(format!("<back-reference to object {uid}>")),
        ArchivedValue::Dangling { uid } => line(format!("<missing object {uid}>")),
        ArchivedValue::Truncated => line("<truncated>".to_owned()),
        ArchivedValue::Url { base, relative } => {
            line("NSURL".to_owned());
            if let Some(base) = base {
                print_archived("base", base, depth + 1);
            }
            print_archived("relative", relative, depth + 1);
        }
        ArchivedValue::Array { class, items } | ArchivedValue::Set { class, items } => {
            line(format!("{class} ({} items)", items.len()));
            for (index, item) in items.iter().enumerate() {
                print_archived(&format!("[{index}]"), item, depth + 1);
            }
        }
        ArchivedValue::Dictionary { class, entries } => {
            line(format!("{class} ({} entries)", entries.len()));
            for (key, item) in entries {
                let name: String = match key {
                    ArchivedValue::String { value } => value.clone(),
                    other => format!("{other:?}"),
                };
                print_archived(&name, item, depth + 1);
            }
        }
        ArchivedValue::Value { class, fields } => {
            line(class.clone());
            for (name, item) in fields {
                print_archived(name, item, depth + 1);
            }
        }
        ArchivedValue::Object {
            class,
            superclasses,
            fields,
        } => {
            line(if superclasses.is_empty() {
                class.clone()
            } else {
                format!("{class} : {}", superclasses.join(" : "))
            });
            for (name, item) in fields {
                print_archived(name, item, depth + 1);
            }
        }
    }
}

fn sanitize_dylib_relpath(install_name: &str, index: usize) -> PathBuf {
    let mut rel: PathBuf = PathBuf::new();
    for component in install_name.split(['/', '\\']) {
        if component.is_empty() || component == "." || component == ".." {
            continue;
        }
        rel.push(component);
    }
    if rel.as_os_str().is_empty() {
        rel.push(format!("image-{index}.dylib"));
    }
    rel
}

fn dyldcache(input: PathBuf, out: Option<PathBuf>, images: Vec<String>) -> miette::Result<()> {
    let head: Vec<u8> = read_head(&input, 16)
        .map_err(|e| miette::miette!("DR-CLI-0495: cannot read input: {e}"))?;
    if !is_dyld_shared_cache(&head) {
        return Err(miette::miette!(
            "DR-CLI-0496: input is not a dyld shared cache (missing dyld_v1 magic)"
        ));
    }
    let (family, parsed): (DyldCacheFamily, DyldSharedCache) = open_dyld_cache_family(&input)
        .map_err(|e| miette::miette!("DR-CLI-0497: dyld cache parse: {e}"))?;
    let requested: BTreeSet<String> = images.into_iter().collect();
    let absent: Vec<&str> = requested
        .iter()
        .filter(|name: &&String| {
            !parsed
                .images
                .iter()
                .any(|image| image.install_name.as_str() == name.as_str())
        })
        .map(String::as_str)
        .collect();
    if !absent.is_empty() {
        return Err(miette::miette!(
            "DR-CLI-0502: the cache holds no image named {}",
            absent.join(", ")
        ));
    }
    let only: Option<&BTreeSet<String>> = (!requested.is_empty()).then_some(&requested);
    let batch: ReconstructBatch =
        reconstruct_dyld_cache_family(&family, &parsed, ReconstructOptions::COMPACT, only)
            .map_err(|e| miette::miette!("DR-CLI-0498: dyld image reconstruct: {e}"))?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("dyld-cache")
        .to_owned();
    let out_dir: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-dyld-dylibs")));
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-CLI-0499: cannot create out dir: {e}"))?;
    let mut written: usize = 0;
    for (index, dylib) in batch.dylibs.iter().enumerate() {
        let rel: PathBuf = sanitize_dylib_relpath(&dylib.install_name, index);
        let target: PathBuf = out_dir.join(&rel);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| miette::miette!("DR-CLI-0500: cannot create dir: {e}"))?;
        }
        std::fs::write(&target, &dylib.bytes)
            .map_err(|e| miette::miette!("DR-CLI-0501: cannot write dylib: {e}"))?;
        written += 1;
    }
    let complete: bool = batch.unresolved.is_empty() && batch.missing_sub_caches.is_empty();
    println!(
        "dyld shared cache: {}",
        if complete { "OK" } else { "partial" }
    );
    println!("  input:      {}", input.display());
    println!("  arch:       {}", parsed.arch);
    println!("  mappings:   {}", parsed.mappings.len());
    println!("  subcaches:  {}", parsed.sub_caches.len());
    println!("  images:     {}", parsed.images.len());
    println!("  recovered:  {written} standalone dylib(s)");
    for missing in &batch.missing_sub_caches {
        println!(
            "  missing subcache {}: {} (looked for {})",
            missing.index,
            missing.reason,
            missing.candidate_names.join(", ")
        );
    }
    if let Some(reason) = &batch.partial_reason {
        println!("  partial:    {reason}");
    }
    for unresolved in &batch.unresolved {
        println!(
            "  unresolved: {} at {:#x}: {}",
            unresolved.install_name, unresolved.image_address, unresolved.reason
        );
    }
    println!("  wrote:      {}", out_dir.display());
    Ok(())
}

fn read_head(path: &std::path::Path, len: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    let mut head: Vec<u8> = Vec::new();
    std::fs::File::open(path)?
        .take(len)
        .read_to_end(&mut head)?;
    Ok(head)
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
    let mut objc_header_files: usize = 0;
    let mut swift_declaration_files: usize = 0;
    for (i, sr) in slice_reports.iter().enumerate() {
        let stem_slice: String = format!("{stem}.slice-{i:02}-{}", sr.cpu_label);
        let objc_path: PathBuf = out_dir.join(format!("{stem_slice}.objc.json"));
        let swift_path: PathBuf = out_dir.join(format!("{stem_slice}.swift.json"));
        let objc_bytes: Vec<u8> = serde_json::to_vec_pretty(&sr.objc)
            .map_err(|e| miette::miette!("DR-CLI-0495: serialize objc dump: {e}"))?;
        std::fs::write(&objc_path, objc_bytes)
            .map_err(|e| miette::miette!("DR-CLI-0492: cannot write objc dump: {e}"))?;
        let swift_bytes: Vec<u8> = serde_json::to_vec_pretty(&sr.swift)
            .map_err(|e| miette::miette!("DR-CLI-0496: serialize swift dump: {e}"))?;
        std::fs::write(&swift_path, swift_bytes)
            .map_err(|e| miette::miette!("DR-CLI-0493: cannot write swift dump: {e}"))?;

        let objc_header: String = render_objc_header(&sr.objc);
        if !objc_header.is_empty() {
            let header_path: PathBuf = out_dir.join(format!("{stem_slice}.h"));
            std::fs::write(&header_path, objc_header.as_bytes())
                .map_err(|e| miette::miette!("DR-CLI-0498: cannot write objc header: {e}"))?;
            objc_header_files += 1;
        }
        let swift_declarations: String = render_swift_declarations(&sr.swift);
        if !swift_declarations.is_empty() {
            let declarations_path: PathBuf = out_dir.join(format!("{stem_slice}.swift"));
            std::fs::write(&declarations_path, swift_declarations.as_bytes()).map_err(|e| {
                miette::miette!("DR-CLI-0499: cannot write swift declarations: {e}")
            })?;
            swift_declaration_files += 1;
        }
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
    let manifest_bytes: Vec<u8> = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| miette::miette!("DR-CLI-0497: serialize manifest: {e}"))?;
    std::fs::write(&manifest_path, manifest_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0494: cannot write manifest: {e}"))?;

    apply_emit_stubs(&emit_kinds, &out_dir, &stem, "macho-classdump")?;

    println!("macho classdump: OK");
    println!("  input:        {}", input.display());
    println!("  slices:       {}", slice_reports.len());
    println!("  objc headers: {objc_header_files}");
    println!("  swift declarations: {swift_declaration_files}");
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
                let Some(slice): Option<&[u8]> = slice_bytes(bytes, entry) else {
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

fn render_objc_header(objc: &ObjcClassDump) -> String {
    if objc.interfaces.is_empty() {
        return String::new();
    }
    let mut out: String =
        String::from("// disrobe objc class-dump (recovered @interface declarations)\n\n");
    for interface in &objc.interfaces {
        out.push_str(&interface.render());
        out.push('\n');
    }
    out
}

fn render_swift_declarations(swift: &SwiftClassDump) -> String {
    if !swift.type_dump.is_empty() {
        let mut out: String =
            String::from("// disrobe swift class-dump (recovered reflection metadata)\n\n");
        out.push_str(&swift.type_dump.render());
        return out;
    }
    if swift.reflected_types.is_empty() {
        return String::new();
    }
    let mut out: String =
        String::from("// disrobe swift class-dump (recovered reflection metadata)\n\n");
    for ty in &swift.reflected_types {
        out.push_str(&ty.render());
        out.push('\n');
    }
    out
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_dylib_relpath_strips_leading_slash_and_traversal() {
        let rel: PathBuf = sanitize_dylib_relpath("/usr/lib/libSystem.B.dylib", 0);
        assert_eq!(
            rel,
            PathBuf::from("usr").join("lib").join("libSystem.B.dylib")
        );
        let escaped: PathBuf = sanitize_dylib_relpath("../../etc/passwd", 1);
        assert_eq!(escaped, PathBuf::from("etc").join("passwd"));
        let empty: PathBuf = sanitize_dylib_relpath("///", 3);
        assert_eq!(empty, PathBuf::from("image-3.dylib"));
    }

    #[test]
    fn dyldcache_rejects_non_cache_input() {
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("dr-dyld").expect("create scratch directory");
        let dir: PathBuf = scratch.path().to_path_buf();
        let bogus: PathBuf = dir.join("not-a-cache.bin");
        std::fs::write(&bogus, b"MZ\x00\x00 definitely not a dyld cache").expect("write");
        let err: miette::Report =
            dyldcache(bogus, Some(dir.join("out")), Vec::new()).expect_err("must reject");
        assert!(format!("{err}").contains("DR-CLI-0496"));
    }

    #[test]
    fn classdump_writes_real_objc_header_and_swift_declarations() {
        let input: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("mobile")
            .join("macho-mac")
            .join("SwiftHello.original");
        if !input.is_file() {
            return;
        }
        let out_dir_guard: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("macho-classdump-test")
                .expect("create scratch directory");
        let out_dir: PathBuf = out_dir_guard.path().join("macho-classdump-test");

        classdump(input, Some(out_dir.clone()), Vec::new()).expect("classdump ok");

        let entries: Vec<PathBuf> = std::fs::read_dir(&out_dir)
            .expect("read out dir")
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        let header: &PathBuf = entries
            .iter()
            .find(|p: &&PathBuf| p.extension().and_then(|e| e.to_str()) == Some("h"))
            .expect("a recovered .h must land");
        let header_text: String = std::fs::read_to_string(header).expect("read header");
        assert!(
            header_text.contains("@interface") && header_text.contains("@end"),
            "objc header must contain recovered @interface blocks: {header_text}"
        );
        let swift: &PathBuf = entries
            .iter()
            .find(|p: &&PathBuf| p.extension().and_then(|e| e.to_str()) == Some("swift"))
            .expect("a recovered .swift must land");
        let swift_text: String = std::fs::read_to_string(swift).expect("read swift declarations");
        assert!(
            swift_text.contains("class ")
                || swift_text.contains("struct ")
                || swift_text.contains("enum ")
                || swift_text.contains("protocol "),
            "swift declarations must contain recovered type declarations: {swift_text}"
        );
        let _ = std::fs::remove_dir_all(&out_dir);
    }
}
