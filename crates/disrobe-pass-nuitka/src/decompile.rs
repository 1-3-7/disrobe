use std::collections::BTreeSet;
use std::path::Path;

use disrobe_core::debug::DebugLog;
use serde::{Deserialize, Serialize};

use crate::blob_scan::BlobScan;
use crate::bytecode_table::{BytecodeTable, decode_bytecode_table};
use crate::c_module::{CModuleStructure, parse_c_module};
use crate::const_blob::{
    ConstantsUnparsedReason, ModuleConstants, NuitkaConstants, constants_unparsed_reason,
    parse_constants,
};
use crate::const_manifest::{ConstantManifest, parse_constant_manifest};
use crate::constants::{ConstantsPool, ConstantsTable, decode_const_file};
use crate::detect::{Detection, detect_in_bytes, find_python_version_strings};
use crate::error::{Error, Result};
use crate::frozen::{FrozenModules, recover_frozen_bytecode};
use crate::name_map::{NativeNameMap, map_names};
use crate::native_body::{NativeBodyRecovery, lift_native_bodies};
use crate::native_disasm::{NativeDisasm, disassemble_module_stats};
use crate::onefile::{OnefileEntry, OnefilePayload, extract_onefile};
use crate::skeleton::{NuitkaSkeleton, SkeletonModule, reconstruct};
use crate::surface::{SurfaceModule, build_surface, build_surface_names_only_with_skeleton};
use crate::symbols::{SymbolGraph, scan_symbols};
use crate::version_db::{NuitkaVersionReport, detect_nuitka_version};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryConstants {
    pub blob_offset: u64,
    pub blob_len: u64,
    pub strings: BTreeSet<String>,
    pub ints: BTreeSet<i64>,
    pub container_count: u32,
}

impl From<&BlobScan> for BinaryConstants {
    fn from(scan: &BlobScan) -> Self {
        Self {
            blob_offset: scan.blob_offset as u64,
            blob_len: scan.blob_len as u64,
            strings: scan.strings.clone(),
            ints: scan.ints.clone(),
            container_count: scan.container_count,
        }
    }
}

impl BinaryConstants {
    fn from_modules(constants: &NuitkaConstants) -> Self {
        let mut strings: BTreeSet<String> = BTreeSet::new();
        let mut ints: BTreeSet<i64> = BTreeSet::new();
        for module in &constants.modules {
            strings.extend(module.strings.iter().cloned());
            ints.extend(module.ints.iter().copied());
        }
        Self {
            blob_offset: constants.region_offset,
            blob_len: constants.region_len,
            strings,
            ints,
            container_count: u32::try_from(constants.modules.len()).unwrap_or(u32::MAX),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DataFileKind {
    NativeModule,
    SharedLibrary,
    DataFile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataFileEntry {
    pub filename: String,
    pub size: u64,
    pub kind: DataFileKind,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NuitkaDecompilation {
    pub schema: String,
    pub manifest: Option<ConstantManifest>,
    pub constants: ConstantsTable,
    pub binary_constants: Option<BinaryConstants>,
    pub module_constants: Option<NuitkaConstants>,
    pub skeleton: Option<NuitkaSkeleton>,
    pub frozen_modules: Option<FrozenModules>,
    pub native_disasm: Option<NativeDisasm>,
    pub native_bodies: Option<NativeBodyRecovery>,
    pub name_map: Option<NativeNameMap>,
    pub data_files: Vec<DataFileEntry>,
    pub bytecode: Option<BytecodeTable>,
    pub version: NuitkaVersionReport,
    pub source_kind: DecompSourceKind,
    pub surface: Option<SurfaceModule>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecompSourceKind {
    BuildDir,
    OnefilePayload,
    EmbeddedStandalone,
}

const SCHEMA: &str = "disrobe.nuitka.decompile/v0";
const BYTECODE_CONST: &str = "__bytecode.const";

pub fn decompile_build_dir(build_dir: &Path) -> Result<NuitkaDecompilation> {
    let mut notes: Vec<String> = Vec::new();

    let manifest: Option<ConstantManifest> = read_manifest(build_dir, &mut notes)?;

    let constants_c: Option<Vec<u8>> = read_optional(&build_dir.join("__constants.c"))?;
    if constants_c.is_none() {
        notes.push("__constants.c absent: exact version unavailable (Tier-A skipped)".to_owned());
    }

    let binary_bytes: Vec<u8> = locate_sibling_binary(build_dir)?.unwrap_or_default();
    let python_abi: Option<(u8, u8)> = python_abi_from_binary(&binary_bytes);
    if python_abi.is_none() {
        notes.push("python ABI not recoverable from sibling binary".to_owned());
    }

    let version: NuitkaVersionReport =
        detect_nuitka_version(&binary_bytes, constants_c.as_deref(), python_abi);

    let (const_files, bytecode_const): ConstFiles = list_const_files(build_dir)?;
    let python_abi: Option<(u8, u8)> = python_abi.or(version.python_abi);
    let bytecode: Option<BytecodeTable> =
        recover_bytecode_table(bytecode_const.as_deref(), python_abi, &mut notes);
    if const_files.is_empty() && bytecode.is_none() {
        return Err(Error::NoConstantsSource);
    }

    let mut constants: ConstantsTable = ConstantsTable::default();
    for (file_name, bytes) in &const_files {
        let blob_name: String = manifest
            .as_ref()
            .and_then(|m: &ConstantManifest| m.by_source_file(file_name))
            .map_or_else(
                || blob_name_from_filename(file_name),
                |e| e.blob_name.clone(),
            );
        let pool: ConstantsPool = decode_const_file(bytes, file_name, &blob_name)?;
        for s in &pool.strings {
            constants.all_strings.insert(s.clone());
        }
        for i in &pool.ints {
            constants.all_ints.insert(*i);
        }
        constants.pools.insert(file_name.clone(), pool);
    }

    let surface: Option<SurfaceModule> = build_dir_surface(build_dir, &constants, &mut notes)?;

    Ok(NuitkaDecompilation {
        schema: SCHEMA.to_owned(),
        manifest,
        constants,
        binary_constants: None,
        module_constants: None,
        skeleton: None,
        frozen_modules: None,
        native_disasm: None,
        native_bodies: None,
        name_map: None,
        data_files: Vec::new(),
        bytecode,
        version,
        source_kind: DecompSourceKind::BuildDir,
        surface,
        notes,
    })
}

fn recover_bytecode_table(
    bytecode_const: Option<&[u8]>,
    python_abi: Option<(u8, u8)>,
    notes: &mut Vec<String>,
) -> Option<BytecodeTable> {
    let bytes: &[u8] = bytecode_const?;
    if bytes.is_empty() {
        notes.push(format!(
            "{BYTECODE_CONST} present but empty: no frozen modules demoted"
        ));
        return None;
    }
    match decode_bytecode_table(bytes, python_abi) {
        Ok(table) => {
            notes.extend(table.notes.iter().cloned());
            if table.modules.is_empty() {
                return None;
            }
            let recovered: usize = table
                .modules
                .iter()
                .filter(|m| m.recovered_directly)
                .count();
            notes.push(format!(
                "{BYTECODE_CONST}: decoded {} frozen module(s) (python {}.{}); {recovered} recovered to source, {} disassembled",
                table.modules.len(),
                table.marshal_version.0,
                table.marshal_version.1,
                table.modules.len() - recovered,
            ));
            Some(table)
        }
        Err(e) => {
            notes.push(format!("{BYTECODE_CONST} decode failed: {e}"));
            None
        }
    }
}

fn build_dir_surface(
    build_dir: &Path,
    constants: &ConstantsTable,
    notes: &mut Vec<String>,
) -> Result<Option<SurfaceModule>> {
    let Some((const_file, primary_blob)): Option<(&String, String)> =
        primary_module_blob(constants)
    else {
        notes.push("no primary module .const pool: surface unavailable".to_owned());
        return Ok(None);
    };
    let c_path: std::path::PathBuf = build_dir.join(format!("module.{primary_blob}.c"));
    let Some(bytes): Option<Vec<u8>> = read_optional(&c_path)? else {
        notes.push(format!(
            "module.{primary_blob}.c absent: surface limited to names-only"
        ));
        return Ok(None);
    };
    let text: String = String::from_utf8_lossy(&bytes).into_owned();
    let cmod: CModuleStructure = parse_c_module(&text)?;
    let Some(pool): Option<&ConstantsPool> = constants.pools.get(const_file) else {
        notes.push("primary module pool vanished before surface build".to_owned());
        return Ok(None);
    };
    let surface: SurfaceModule = build_surface(&cmod, pool, Some(&text))?;
    notes.extend(surface.notes.iter().cloned());
    Ok(Some(surface))
}

fn primary_module_blob(constants: &ConstantsTable) -> Option<(&String, String)> {
    constants.pools.keys().find_map(|file_name: &String| {
        let blob: String = blob_name_from_filename(file_name);
        (!blob.is_empty()).then_some((file_name, blob))
    })
}

pub fn decompile_binary(path: &Path) -> Result<NuitkaDecompilation> {
    let bytes: Vec<u8> = std::fs::read(path)?;
    let detection: Detection = detect_in_bytes(&bytes)?;

    if let Some(offset) = detection.onefile_payload_offset
        && let Some(decomp) = try_decompile_onefile(&bytes, offset)
    {
        return Ok(decomp);
    }

    if let Some(build_dir) = sibling_build_dir(path) {
        return decompile_build_dir(&build_dir);
    }

    Ok(decompile_embedded_standalone(&bytes, &detection))
}

pub fn decompile_bytes(bytes: &[u8]) -> Result<NuitkaDecompilation> {
    let detection: Detection = detect_in_bytes(bytes)?;
    if let Some(offset) = detection.onefile_payload_offset
        && let Some(decomp) = try_decompile_onefile(bytes, offset)
    {
        return Ok(decomp);
    }
    Ok(decompile_embedded_standalone(bytes, &detection))
}

fn try_decompile_onefile(bytes: &[u8], offset: usize) -> Option<NuitkaDecompilation> {
    match decompile_onefile(bytes, offset) {
        Ok(decomp) => Some(decomp),
        Err(e) => {
            let dbg: DebugLog = DebugLog::for_scope("nuitka");
            dbg.line(|| {
                format!(
                    "onefile extraction at {offset:#x} failed ({e}); falling back to embedded-standalone"
                )
            });
            None
        }
    }
}

fn decompile_embedded_standalone(bytes: &[u8], detection: &Detection) -> NuitkaDecompilation {
    let python_abi: Option<(u8, u8)> = match (
        detection.version.python_major,
        detection.version.python_minor,
    ) {
        (Some(major), Some(minor)) => Some((major, minor)),
        _ => None,
    };
    let version: NuitkaVersionReport = detect_nuitka_version(bytes, None, python_abi);

    let mut notes: Vec<String> = Vec::new();
    let (module_constants, skeleton): (Option<NuitkaConstants>, Option<NuitkaSkeleton>) =
        recover_module_constants(bytes, &mut notes);
    notes.push(
        "embedded-standalone binary: bundled data files (if any) live as sibling files in the \
         .dist directory, not embedded in this PE; run on the onefile build to carve appended \
         files, or inspect the .dist directory directly"
            .to_owned(),
    );

    let binary_constants: Option<BinaryConstants> =
        module_constants.as_ref().map(|constants: &NuitkaConstants| {
            let summary: BinaryConstants = BinaryConstants::from_modules(constants);
            notes.push(format!(
                "embedded-standalone binary: aggregated {} string and {} int constants across {} module chunk(s)",
                summary.strings.len(),
                summary.ints.len(),
                constants.modules.len()
            ));
            summary
        });

    let frozen_modules: Option<FrozenModules> = recover_frozen(bytes, python_abi, &mut notes);
    let native_disasm: Option<NativeDisasm> = disassemble_module_stats("<standalone>", bytes);
    if native_disasm.is_none() {
        notes.push("native disassembly unavailable for this image format".to_owned());
    }
    let name_map: Option<NativeNameMap> =
        recover_name_map("<standalone>", bytes, module_constants.as_ref(), &mut notes);
    let native_bodies: Option<NativeBodyRecovery> = module_constants
        .as_ref()
        .and_then(|constants: &NuitkaConstants| lift_native_bodies(bytes, constants));
    if let Some(bodies) = native_bodies.as_ref() {
        notes.extend(bodies.notes.iter().cloned());
    }
    let mut surface: Option<SurfaceModule> = names_only_surface(
        bytes,
        module_constants.as_ref(),
        skeleton.as_ref(),
        &mut notes,
    );
    if let (Some(module), Some(bodies)) = (surface.as_mut(), native_bodies.as_ref()) {
        apply_native_bodies(module, bodies, &mut notes);
    }

    NuitkaDecompilation {
        schema: SCHEMA.to_owned(),
        manifest: None,
        constants: ConstantsTable::default(),
        binary_constants,
        module_constants,
        skeleton,
        frozen_modules,
        native_disasm,
        native_bodies,
        name_map,
        data_files: Vec::new(),
        bytecode: None,
        version,
        source_kind: DecompSourceKind::EmbeddedStandalone,
        surface,
        notes,
    }
}

fn apply_native_bodies(
    module: &mut SurfaceModule,
    bodies: &NativeBodyRecovery,
    notes: &mut Vec<String>,
) {
    let mut upgraded: usize = 0;
    for function in &mut module.functions {
        let Some(body) = bodies.body_for(&function.name) else {
            continue;
        };
        if body.recovered_stmts.is_empty() {
            continue;
        }
        function.body_stmts = body.recovered_stmts.clone();
        function.body_recovered = true;
        function.lift_fidelity = body.fidelity;
        upgraded += 1;
    }
    if upgraded > 0 {
        module.python_source = crate::surface::emit_python(module);
        notes.push(format!(
            "native body lift: upgraded {upgraded} surface function(s) from skeleton stub to a \
             body reconstructed from the compiled machine code"
        ));
    }
}

fn recover_frozen(
    image: &[u8],
    python_abi: Option<(u8, u8)>,
    notes: &mut Vec<String>,
) -> Option<FrozenModules> {
    let frozen: FrozenModules = recover_frozen_bytecode(image, python_abi)?;
    notes.extend(frozen.notes.iter().cloned());
    Some(frozen)
}

fn recover_name_map(
    module_name: &str,
    image: &[u8],
    module_constants: Option<&NuitkaConstants>,
    notes: &mut Vec<String>,
) -> Option<NativeNameMap> {
    let constants: &NuitkaConstants = module_constants?;
    let mut names: Vec<String> = Vec::new();
    for module in &constants.modules {
        names.extend(module.strings.iter().cloned());
    }
    names.sort_unstable();
    names.dedup();
    let map: NativeNameMap = map_names(module_name, image, &names)?;
    notes.push(format!(
        "native name map: {} recovered identifier(s) referenced from .text across {} attributable function(s)",
        map.entries.len(),
        map.mapped_functions
    ));
    Some(map)
}

fn recover_module_constants(
    image: &[u8],
    notes: &mut Vec<String>,
) -> (Option<NuitkaConstants>, Option<NuitkaSkeleton>) {
    let constants: NuitkaConstants = parse_constants(image);
    if constants.is_empty() {
        let note: &str = match constants_unparsed_reason(image) {
            ConstantsUnparsedReason::TableHeaderPresent => {
                "no plaintext Nuitka constants chunks parsed: table headers are present, but the payload did not validate under modern varint or legacy fixed-width grammars"
            }
            ConstantsUnparsedReason::LoaderMarkerPresent => {
                "no plaintext Nuitka constants chunks parsed: loader markers are present, but no self-validating plaintext table was found"
            }
            ConstantsUnparsedReason::WideScanSkipped => {
                "no plaintext Nuitka constants chunks parsed: PE data sections did not validate and the bounded full-image fallback was skipped"
            }
            ConstantsUnparsedReason::NoPlaintextTable => {
                "no plaintext Nuitka constants chunks parsed: no self-validating table was found in the scanned image"
            }
        };
        notes.push(note.to_owned());
        return (None, None);
    }
    let skeleton: NuitkaSkeleton = reconstruct(&constants);
    let total_co: usize = constants
        .modules
        .iter()
        .map(|m| m.code_objects.len())
        .sum::<usize>();
    notes.push(format!(
        "recovered {} module chunk(s) ({}) carrying {} function skeleton(s); {} embedded code objects",
        constants.modules.len(),
        constants
            .modules
            .iter()
            .map(|m| m.name.as_str())
            .collect::<Vec<&str>>()
            .join(", "),
        skeleton.function_count(),
        total_co,
    ));
    (Some(constants), Some(skeleton))
}

fn names_only_surface(
    image: &[u8],
    module_constants: Option<&NuitkaConstants>,
    skeleton: Option<&NuitkaSkeleton>,
    notes: &mut Vec<String>,
) -> Option<SurfaceModule> {
    let skeleton: &NuitkaSkeleton = skeleton?;
    let primary: &SkeletonModule = primary_skeleton_module(skeleton)?;
    let graph: SymbolGraph = scan_symbols(image).unwrap_or_default();
    let pool: ConstantsPool = pool_for_module(module_constants, &primary.name);
    let surface: SurfaceModule =
        build_surface_names_only_with_skeleton(&graph, &pool, Some(primary));
    notes.push(format!(
        "names-only surface built for module '{}' from reconstructed skeleton: {} signature(s) recovered, bodies compiled to native code (no module.<name>.c present)",
        surface.module_name,
        surface.functions.len(),
    ));
    Some(surface)
}

fn primary_skeleton_module(skeleton: &NuitkaSkeleton) -> Option<&SkeletonModule> {
    skeleton
        .modules
        .iter()
        .filter(|m: &&SkeletonModule| !m.functions.is_empty())
        .max_by(|a: &&SkeletonModule, b: &&SkeletonModule| {
            a.functions
                .len()
                .cmp(&b.functions.len())
                .then_with(|| b.name.cmp(&a.name))
        })
        .or_else(|| skeleton.modules.first())
}

fn pool_for_module(module_constants: Option<&NuitkaConstants>, module_name: &str) -> ConstantsPool {
    let mut pool: ConstantsPool = ConstantsPool::default();
    let Some(constants): Option<&NuitkaConstants> = module_constants else {
        return pool;
    };
    for module in &constants.modules {
        if module.name == module_name {
            pool.strings.extend(module.strings.iter().cloned());
            pool.ints.extend(module.ints.iter().copied());
        }
    }
    if pool.strings.iter().any(|s: &String| s == "__main__")
        || constants
            .modules
            .iter()
            .any(|m: &ModuleConstants| m.name == "__main__")
    {
        pool.strings.insert("__main__".to_owned());
    }
    pool
}

pub fn decompile_const_bytes(
    bytes: &[u8],
    source_file: &str,
    blob_name: &str,
) -> Result<ConstantsPool> {
    decode_const_file(bytes, source_file, blob_name)
}

fn decompile_onefile(bytes: &[u8], offset: usize) -> Result<NuitkaDecompilation> {
    let payload: OnefilePayload = extract_onefile(bytes, offset)?;

    let manifest: Option<ConstantManifest> = payload
        .entries
        .iter()
        .find(|e| e.filename.ends_with("__constant.txt"))
        .and_then(|e| parse_constant_manifest(&e.data).ok());

    let mut notes: Vec<String> = Vec::new();
    let mut constants: ConstantsTable = ConstantsTable::default();
    let mut bytecode_const: Option<Vec<u8>> = None;
    for entry in &payload.entries {
        if entry.filename.ends_with(BYTECODE_CONST) {
            bytecode_const = Some(entry.data.clone());
            continue;
        }
        if !is_const_filename(&entry.filename) {
            continue;
        }
        let file_name: String = entry.filename.clone();
        let blob_name: String = manifest
            .as_ref()
            .and_then(|m: &ConstantManifest| m.by_source_file(&file_name))
            .map_or_else(
                || blob_name_from_filename(&file_name),
                |e| e.blob_name.clone(),
            );
        let pool: ConstantsPool = decode_const_file(&entry.data, &file_name, &blob_name)?;
        for s in &pool.strings {
            constants.all_strings.insert(s.clone());
        }
        for i in &pool.ints {
            constants.all_ints.insert(*i);
        }
        constants.pools.insert(file_name, pool);
    }

    if constants.pools.is_empty() {
        notes.push("onefile payload carried no .const constant files".to_owned());
    }

    let (module_constants, skeleton): (Option<NuitkaConstants>, Option<NuitkaSkeleton>) =
        recover_onefile_module_constants(&payload.entries, &mut notes);
    let binary_constants: Option<BinaryConstants> =
        module_constants.as_ref().map(BinaryConstants::from_modules);
    let data_files: Vec<DataFileEntry> = data_files_from_entries(&payload.entries);
    let plain_data: usize = data_files
        .iter()
        .filter(|d: &&DataFileEntry| matches!(d.kind, DataFileKind::DataFile))
        .count();
    notes.push(format!(
        "onefile payload bundles {} file(s): {} native module(s), {} shared library(ies), {plain_data} data file(s)",
        data_files.len(),
        data_files
            .iter()
            .filter(|d: &&DataFileEntry| matches!(d.kind, DataFileKind::NativeModule))
            .count(),
        data_files
            .iter()
            .filter(|d: &&DataFileEntry| matches!(d.kind, DataFileKind::SharedLibrary))
            .count(),
    ));

    let python_abi: Option<(u8, u8)> = python_abi_from_binary(bytes);
    let version: NuitkaVersionReport = detect_nuitka_version(bytes, None, python_abi);
    let abi: Option<(u8, u8)> = python_abi.or(version.python_abi);
    let bytecode: Option<BytecodeTable> =
        recover_bytecode_table(bytecode_const.as_deref(), abi, &mut notes);
    let frozen_modules: Option<FrozenModules> =
        recover_onefile_frozen(&payload.entries, abi, &mut notes);
    let main_image: Option<(&str, &[u8])> = onefile_main_image(&payload.entries);
    let native_disasm: Option<NativeDisasm> =
        main_image.and_then(|(name, image): (&str, &[u8])| disassemble_module_stats(name, image));
    let name_map: Option<NativeNameMap> = main_image.and_then(|(name, image): (&str, &[u8])| {
        recover_name_map(name, image, module_constants.as_ref(), &mut notes)
    });
    let native_bodies: Option<NativeBodyRecovery> =
        main_image.and_then(|(_, image): (&str, &[u8])| {
            module_constants
                .as_ref()
                .and_then(|constants: &NuitkaConstants| lift_native_bodies(image, constants))
        });
    if let Some(bodies) = native_bodies.as_ref() {
        notes.extend(bodies.notes.iter().cloned());
    }
    let mut surface: Option<SurfaceModule> = main_image.and_then(|(_, image): (&str, &[u8])| {
        names_only_surface(
            image,
            module_constants.as_ref(),
            skeleton.as_ref(),
            &mut notes,
        )
    });
    if let (Some(module), Some(bodies)) = (surface.as_mut(), native_bodies.as_ref()) {
        apply_native_bodies(module, bodies, &mut notes);
    }

    Ok(NuitkaDecompilation {
        schema: SCHEMA.to_owned(),
        manifest,
        constants,
        binary_constants,
        module_constants,
        skeleton,
        frozen_modules,
        native_disasm,
        native_bodies,
        name_map,
        data_files,
        bytecode,
        version,
        source_kind: DecompSourceKind::OnefilePayload,
        surface,
        notes,
    })
}

fn onefile_main_image(entries: &[OnefileEntry]) -> Option<(&str, &[u8])> {
    entries
        .iter()
        .find(|e: &&OnefileEntry| {
            e.symlink_target.is_none()
                && !e.filename.contains('/')
                && !e.filename.contains('\\')
                && e.filename.to_ascii_lowercase().ends_with(".dll")
                && is_native_image(&e.data)
                && !is_runtime_dll(&e.filename)
        })
        .map(|e: &OnefileEntry| (e.filename.as_str(), e.data.as_slice()))
}

fn is_runtime_dll(filename: &str) -> bool {
    let lower: String = filename.to_ascii_lowercase();
    [
        "python",
        "vcruntime",
        "libcrypto",
        "libssl",
        "libffi",
        "api-ms",
    ]
    .iter()
    .any(|p: &&str| lower.starts_with(p))
}

fn recover_onefile_frozen(
    entries: &[OnefileEntry],
    python_abi: Option<(u8, u8)>,
    notes: &mut Vec<String>,
) -> Option<FrozenModules> {
    let mut best: Option<FrozenModules> = None;
    for entry in entries {
        if !is_native_image(&entry.data) {
            continue;
        }
        let Some(frozen): Option<FrozenModules> = recover_frozen_bytecode(&entry.data, python_abi)
        else {
            continue;
        };
        let better: bool = best
            .as_ref()
            .is_none_or(|b: &FrozenModules| frozen.modules.len() > b.modules.len());
        if better {
            best = Some(frozen);
        }
    }
    if let Some(frozen) = &best {
        notes.extend(frozen.notes.iter().cloned());
    }
    best
}

fn classify_data_file(filename: &str) -> DataFileKind {
    let lower: String = filename.to_ascii_lowercase();
    let ext: Option<&str> = Path::new(&lower).extension().and_then(|e| e.to_str());
    match ext {
        Some("pyd" | "so") => DataFileKind::NativeModule,
        Some("dll" | "dylib") => DataFileKind::SharedLibrary,
        _ if lower.contains(".so.") => DataFileKind::NativeModule,
        _ => DataFileKind::DataFile,
    }
}

fn data_files_from_entries(entries: &[OnefileEntry]) -> Vec<DataFileEntry> {
    entries
        .iter()
        .filter(|e: &&OnefileEntry| e.symlink_target.is_none())
        .map(|e: &OnefileEntry| DataFileEntry {
            filename: e.filename.clone(),
            size: e.size,
            kind: classify_data_file(&e.filename),
        })
        .collect()
}

fn recover_onefile_module_constants(
    entries: &[OnefileEntry],
    notes: &mut Vec<String>,
) -> (Option<NuitkaConstants>, Option<NuitkaSkeleton>) {
    let mut best: Option<NuitkaConstants> = None;
    for entry in entries {
        if !is_native_image(&entry.data) {
            continue;
        }
        let constants: NuitkaConstants = parse_constants(&entry.data);
        if constants.is_empty() {
            continue;
        }
        let better: bool = best
            .as_ref()
            .is_none_or(|b: &NuitkaConstants| constants.modules.len() > b.modules.len());
        if better {
            best = Some(constants);
        }
    }
    let Some(constants): Option<NuitkaConstants> = best else {
        notes.push(
            "onefile inner image: no plaintext Nuitka constants chunks parsed in any native entry"
                .to_owned(),
        );
        return (None, None);
    };
    let skeleton: NuitkaSkeleton = reconstruct(&constants);
    notes.push(format!(
        "onefile inner image: recovered {} module chunk(s) carrying {} function skeleton(s)",
        constants.modules.len(),
        skeleton.function_count(),
    ));
    (Some(constants), Some(skeleton))
}

#[inline]
fn is_native_image(data: &[u8]) -> bool {
    matches!(
        data.get(0..4),
        Some(
            [b'M', b'Z', _, _]
                | [0x7F, b'E', b'L', b'F']
                | [0xFE, 0xED, 0xFA, 0xCE | 0xCF]
                | [0xCE | 0xCF, 0xFA, 0xED, 0xFE]
        )
    )
}

fn read_manifest(build_dir: &Path, notes: &mut Vec<String>) -> Result<Option<ConstantManifest>> {
    let manifest_path: std::path::PathBuf = build_dir.join("blobs").join("__constant.txt");
    let Some(bytes): Option<Vec<u8>> = read_optional(&manifest_path)? else {
        notes.push("blobs/__constant.txt absent: blob_name fallback from filenames".to_owned());
        return Ok(None);
    };
    Ok(Some(parse_constant_manifest(&bytes)?))
}

fn is_const_filename(file_name: &str) -> bool {
    Path::new(file_name)
        .extension()
        .is_some_and(|ext: &std::ffi::OsStr| ext.eq_ignore_ascii_case("const"))
}

type ConstFiles = (Vec<(String, Vec<u8>)>, Option<Vec<u8>>);

fn list_const_files(build_dir: &Path) -> Result<ConstFiles> {
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    let mut bytecode: Option<Vec<u8>> = None;
    for entry in std::fs::read_dir(build_dir)? {
        let entry: std::fs::DirEntry = entry?;
        let file_name_os: std::ffi::OsString = entry.file_name();
        let Some(file_name): Option<&str> = file_name_os.to_str() else {
            continue;
        };
        if !is_const_filename(file_name) {
            continue;
        }
        let bytes: Vec<u8> = std::fs::read(entry.path())?;
        if file_name == BYTECODE_CONST {
            bytecode = Some(bytes);
            continue;
        }
        out.push((file_name.to_owned(), bytes));
    }
    out.sort_by(|a: &(String, Vec<u8>), b: &(String, Vec<u8>)| a.0.cmp(&b.0));
    Ok((out, bytecode))
}

fn locate_sibling_binary(build_dir: &Path) -> Result<Option<Vec<u8>>> {
    let stem: Option<&str> = build_dir
        .file_name()
        .and_then(|n: &std::ffi::OsStr| n.to_str())
        .and_then(|n: &str| n.strip_suffix(".build"));
    let Some(stem): Option<&str> = stem else {
        return Ok(None);
    };
    let parent: &Path = match build_dir.parent() {
        Some(p) => p,
        None => return Ok(None),
    };
    for extension in ["exe", "bin", "pyd", "so", "dylib", ""] {
        let candidate: std::path::PathBuf = if extension.is_empty() {
            parent.join(stem)
        } else {
            parent.join(format!("{stem}.{extension}"))
        };
        if candidate.is_file()
            && let Some(bytes) = read_optional(&candidate)?
        {
            return Ok(Some(bytes));
        }
    }
    Ok(None)
}

fn sibling_build_dir(binary: &Path) -> Option<std::path::PathBuf> {
    let stem: &str = binary
        .file_stem()
        .and_then(|s: &std::ffi::OsStr| s.to_str())?;
    let parent: &Path = binary.parent()?;
    let candidate: std::path::PathBuf = parent.join(format!("{stem}.build"));
    candidate.is_dir().then_some(candidate)
}

fn python_abi_from_binary(bytes: &[u8]) -> Option<(u8, u8)> {
    if bytes.is_empty() {
        return None;
    }
    if let Some(python_abi) = find_python_version_strings(bytes) {
        return Some(python_abi);
    }
    let detection: Detection = detect_in_bytes(bytes).ok()?;
    match (
        detection.version.python_major,
        detection.version.python_minor,
    ) {
        (Some(major), Some(minor)) => Some((major, minor)),
        _ => None,
    }
}

fn blob_name_from_filename(file_name: &str) -> String {
    let stem: &str = file_name.strip_suffix(".const").unwrap_or(file_name);
    if stem == "__constants" {
        return String::new();
    }
    stem.strip_prefix("module.").unwrap_or(stem).to_owned()
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::Io(e)),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::surface::SurfaceFunction;
    use crate::version_db::{ExactNuitkaVersion, VersionConfidence};

    fn fixture(rel: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus/python/nuitka")
            .join(rel)
    }

    fn corpus(rel: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus/python/nuitka/real")
            .join(rel)
    }

    fn assert_real_recovery(d: &NuitkaDecompilation) {
        let skeleton: &NuitkaSkeleton = d.skeleton.as_ref().expect("skeleton recovered");
        let names: Vec<&str> = skeleton
            .modules
            .iter()
            .map(|m: &crate::skeleton::SkeletonModule| m.name.as_str())
            .collect();
        for expected in [
            "sample_app",
            "sample_app.core",
            "sample_app.cli",
            "sample_app.models",
            "sample_app.utils",
        ] {
            assert!(
                names.contains(&expected),
                "module {expected} missing: {names:?}"
            );
        }
        let constants: &NuitkaConstants = d.module_constants.as_ref().expect("module constants");
        let all_strings: std::collections::BTreeSet<&str> = constants
            .modules
            .iter()
            .flat_map(|m| m.strings.iter().map(String::as_str))
            .collect();
        for func in [
            "compute_checksum",
            "transform_pipeline",
            "normalize_scores",
            "magic_sum",
            "deposit",
            "withdraw",
            "apply_interest",
            "clamp",
        ] {
            assert!(all_strings.contains(func), "function {func} not recovered");
        }
        let core: &crate::skeleton::SkeletonModule = skeleton
            .modules
            .iter()
            .find(|m| m.name == "sample_app.core")
            .expect("core");
        assert!(
            core.functions
                .iter()
                .any(|f| f.name == "compute_checksum"
                    && f.return_annotation.as_deref() == Some("int")),
            "compute_checksum signature not bound"
        );
    }

    fn any_annotated_param(funcs: &[SurfaceFunction]) -> bool {
        funcs.iter().any(|f: &SurfaceFunction| {
            f.params
                .iter()
                .any(|p: &crate::surface::SurfaceParam| p.annotation.is_some())
                || any_annotated_param(&f.nested)
        })
    }

    fn any_return_annotation(funcs: &[SurfaceFunction]) -> bool {
        funcs.iter().any(|f: &SurfaceFunction| {
            f.return_annotation.is_some() || any_return_annotation(&f.nested)
        })
    }

    #[test]
    fn skeleton_only_standalone_attaches_names_only_surface() {
        let path: std::path::PathBuf = corpus("sample_app-standalone.exe");
        if !path.is_file() {
            eprintln!("skipping: real standalone corpus absent");
            return;
        }
        let bytes: Vec<u8> = std::fs::read(&path).expect("read standalone");
        let d: NuitkaDecompilation = decompile_bytes(&bytes).expect("decompile standalone");
        assert_eq!(d.source_kind, DecompSourceKind::EmbeddedStandalone);
        assert!(
            d.skeleton.is_some(),
            "standalone corpus must reconstruct a skeleton"
        );
        let surface: &SurfaceModule = d
            .surface
            .as_ref()
            .expect("skeleton-only standalone must attach a names-only surface");
        assert_eq!(surface.fidelity, crate::surface::SurfaceFidelity::NamesOnly);
        assert!(
            !surface.module_name.is_empty(),
            "names-only surface must carry a module name"
        );
        assert!(
            !surface.functions.is_empty(),
            "names-only surface must carry recovered function signatures"
        );
        assert!(
            any_annotated_param(&surface.functions),
            "names-only surface must carry recovered parameter annotations"
        );
        assert!(
            any_return_annotation(&surface.functions),
            "names-only surface must carry recovered return annotations"
        );
        assert!(
            surface
                .functions
                .iter()
                .all(|f: &SurfaceFunction| !f.name.is_empty()),
            "names-only surface qualnames/names must be recovered, not blank"
        );
        assert!(
            surface.python_source.contains(" -> "),
            "names-only surface python must emit at least one return-annotated signature:\n{}",
            surface.python_source
        );
        assert!(
            d.notes
                .iter()
                .any(|n: &String| n.contains("names-only surface built for module")),
            "names-only surface wiring must record a provenance note"
        );
    }

    #[test]
    fn real_standalone_binary_recovers_modules_and_signatures() {
        let path: std::path::PathBuf = corpus("sample_app-standalone.exe");
        if !path.is_file() {
            eprintln!("skipping: real standalone corpus absent");
            return;
        }
        let bytes: Vec<u8> = std::fs::read(&path).expect("read standalone");
        let d: NuitkaDecompilation = decompile_bytes(&bytes).expect("decompile standalone");
        assert_real_recovery(&d);
    }

    #[test]
    fn real_onefile_binary_recovers_modules_and_signatures() {
        let path: std::path::PathBuf = corpus("sample_app-onefile.exe");
        if !path.is_file() {
            eprintln!("skipping: real onefile corpus absent");
            return;
        }
        let bytes: Vec<u8> = std::fs::read(&path).expect("read onefile");
        let d: NuitkaDecompilation = decompile_bytes(&bytes).expect("decompile onefile");
        assert_eq!(d.source_kind, DecompSourceKind::OnefilePayload);
        assert_real_recovery(&d);
        assert!(
            !d.data_files.is_empty(),
            "onefile must list bundled data files"
        );
        assert!(
            d.data_files
                .iter()
                .any(|f| f.filename.ends_with("sample_app.dll")),
            "onefile bundled files must include the app library: {:?}",
            d.data_files
                .iter()
                .map(|f| f.filename.as_str())
                .collect::<Vec<&str>>()
        );
        assert!(
            d.data_files
                .iter()
                .any(|f| matches!(f.kind, DataFileKind::NativeModule)),
            "onefile bundled files must classify native modules"
        );
    }

    #[test]
    fn build_dir_recovers_constants_and_exact_version() {
        let d: NuitkaDecompilation =
            decompile_build_dir(&fixture("module/hello.build")).expect("decompile");
        assert_eq!(d.schema, SCHEMA);
        assert_eq!(d.source_kind, DecompSourceKind::BuildDir);
        assert_eq!(d.version.confidence, VersionConfidence::Exact);
        let exact: &ExactNuitkaVersion = d.version.exact.as_ref().expect("exact");
        assert_eq!((exact.major, exact.minor, exact.micro), (4, 1, 1));
        let pool: &ConstantsPool = d
            .constants
            .pools
            .get("module.hello.const")
            .expect("hello pool");
        assert!(pool.strings.contains("greet"));
        assert!(pool.strings.contains("fib"));
        assert!(d.constants.all_strings.contains("disrobe"));
    }

    #[test]
    fn build_dir_without_bytecode_table_reports_none() {
        let d: NuitkaDecompilation =
            decompile_build_dir(&fixture("module/hello.build")).expect("decompile");
        assert!(d.bytecode.is_none());
    }

    #[test]
    fn build_dir_recovers_frozen_bytecode_module() {
        let d: NuitkaDecompilation =
            decompile_build_dir(&fixture("bytecode-module/app.build")).expect("decompile");
        let table: &crate::bytecode_table::BytecodeTable =
            d.bytecode.as_ref().expect("bytecode table recovered");
        assert_eq!(table.modules.len(), 1);
        let module: &crate::bytecode_table::BytecodeModule = &table.modules[0];
        assert_eq!(module.module_name, "packaging");
        assert!(module.instruction_count > 0);
        assert!(
            module.source.contains("describe") && module.source.contains("total"),
            "recovered source missing known defs:\n{}",
            module.source
        );
        assert!(
            d.notes
                .iter()
                .any(|n: &String| n.contains(BYTECODE_CONST) && n.contains("frozen module"))
        );
    }

    #[test]
    fn blob_name_from_filename_handles_module_and_global() {
        assert_eq!(blob_name_from_filename("module.hello.const"), "hello");
        assert_eq!(blob_name_from_filename("module.__main__.const"), "__main__");
        assert_eq!(blob_name_from_filename("__constants.const"), "");
    }

    #[test]
    fn python_abi_scan_reads_sibling_binary_import_name() {
        let bytes: Vec<u8> = b"MZ\x90\x00.imports\x00python314.dll\x00".to_vec();
        let result: Result<Detection> = detect_in_bytes(&bytes);
        assert!(matches!(result, Err(Error::NotNuitka)));
        assert_eq!(python_abi_from_binary(&bytes), Some((3, 14)));
    }

    #[test]
    fn python_abi_scan_prefers_runtime_import_over_doc_version_text() {
        let bytes: Vec<u8> =
            b"MZ\x90\x00Python 3.19.\0Python 3.15.\0.imports\x00python314.dll\x00".to_vec();
        assert_eq!(python_abi_from_binary(&bytes), Some((3, 14)));
    }

    #[test]
    fn python_abi_scan_rejects_conflicting_doc_version_text() {
        let bytes: Vec<u8> = b"MZ\x90\x00Python 3.19.\0Python 3.15.\0".to_vec();
        assert_eq!(python_abi_from_binary(&bytes), None);
    }

    #[test]
    fn python_abi_scan_reads_utf16_import_name() {
        let mut bytes: Vec<u8> = b"MZ\x90\x00.imports\x00".to_vec();
        for unit in "python312.dll".encode_utf16() {
            let unit: u16 = unit;
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(python_abi_from_binary(&bytes), Some((3, 12)));
    }

    #[test]
    fn python_abi_scan_reads_unix_and_framework_markers() {
        assert_eq!(
            python_abi_from_binary(b"\x7fELF\0libpython3.13.so.1.0\0"),
            Some((3, 13))
        );
        assert_eq!(
            python_abi_from_binary(b"Python.framework/Versions/3.11/Python"),
            Some((3, 11))
        );
    }
}
