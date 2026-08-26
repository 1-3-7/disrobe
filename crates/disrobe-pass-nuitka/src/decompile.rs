use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::blob_scan::BlobScan;
use crate::bytecode_table::{BytecodeTable, decode_bytecode_table};
use crate::c_module::{CModuleStructure, parse_c_module_with_optional_python_abi};
use crate::const_blob::{
    ConstantsUnparsedReason, ModuleConstants, NuitkaConstants, constants_unparsed_reason,
    parse_constants,
};
use crate::const_manifest::{
    ConstantManifest, MAX_CONSTANT_MANIFEST_BYTES, parse_constant_manifest,
};
use crate::constants::{
    ConstantInputBudget, ConstantsPool, ConstantsTable, MAX_BUILD_CONST_BYTES,
    MAX_BUILD_CONST_FILES, MAX_CONST_FILE_BYTES, decode_const_file,
};
use crate::detect::{Detection, detect_in_bytes, find_python_version_strings};
use crate::error::{Error, Result};
use crate::frozen::{FrozenModules, recover_frozen_bytecode};
use crate::limits::{MAX_BINARY_INPUT_BYTES, MAX_C_SOURCE_BYTES, validate_binary_input_size};
use crate::name_map::{NativeNameMap, map_names};
use crate::native_body::{NativeBodyRecovery, lift_native_bodies};
use crate::native_disasm::{NativeDisasm, disassemble_module_stats};
use crate::onefile::{OnefilePayload, StreamedEntry, extract_onefile};
use crate::reassembly::{ReassemblyPlan, plan_reassembly};
use crate::skeleton::{NuitkaSkeleton, SkeletonModule, reconstruct};
use crate::surface::{
    SurfaceModule, build_surface_names_only_with_skeleton, build_surface_with_optional_python_abi,
};
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
const MAX_SIBLING_BINARY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_BUILD_DIRECTORY_ENTRIES: usize = 65_536;
const MAX_BOUNDED_READ_PREALLOC_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
struct SiblingBinary {
    bytes: Vec<u8>,
    python_abi: Option<(u8, u8)>,
    skipped_bytes: Option<u64>,
}

#[derive(Debug)]
enum BoundedFileRead {
    Bytes(Vec<u8>),
    TooLarge { bytes: u64 },
}

pub fn decompile_build_dir(build_dir: &Path) -> Result<NuitkaDecompilation> {
    decompile_build_dir_with_binary(build_dir, None, None)
}

pub fn decompile_build_dir_with_python_abi(
    build_dir: &Path,
    python_abi: (u8, u8),
) -> Result<NuitkaDecompilation> {
    decompile_build_dir_with_binary(build_dir, None, Some(python_abi))
}

fn decompile_build_dir_with_binary(
    build_dir: &Path,
    supplied_binary: Option<&[u8]>,
    supplied_abi: Option<(u8, u8)>,
) -> Result<NuitkaDecompilation> {
    let mut notes: Vec<String> = Vec::new();

    let manifest: Option<ConstantManifest> = read_manifest(build_dir, &mut notes)?;

    let constants_c: Option<Vec<u8>> = read_c_source(&build_dir.join("__constants.c"))?;
    if constants_c.is_none() {
        notes.push("__constants.c absent: exact version unavailable (Tier-A skipped)".to_owned());
    }

    let sibling_binary: Option<SiblingBinary> = if supplied_binary.is_none() {
        locate_sibling_binary(build_dir)?
    } else {
        None
    };
    let sibling_abi: Option<(u8, u8)> = sibling_binary
        .as_ref()
        .and_then(|binary: &SiblingBinary| binary.python_abi);
    if let Some(bytes) = sibling_binary
        .as_ref()
        .and_then(|binary: &SiblingBinary| binary.skipped_bytes)
    {
        notes.push(format!(
            "sibling binary skipped after {bytes} bytes exceeded the {MAX_SIBLING_BINARY_BYTES}-byte cap"
        ));
    }
    let binary_view: &[u8] = match (supplied_binary, sibling_binary.as_ref()) {
        (Some(binary), _) => binary,
        (None, Some(binary)) => &binary.bytes,
        (None, None) => &[],
    };
    let python_abi: Option<(u8, u8)> = supplied_abi
        .or(sibling_abi)
        .or_else(|| python_abi_from_binary(binary_view));
    if python_abi.is_none() {
        notes.push("python ABI not recoverable from selected binary".to_owned());
    }

    let version: NuitkaVersionReport =
        detect_nuitka_version(binary_view, constants_c.as_deref(), python_abi);

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

    let surface: Option<SurfaceModule> =
        build_dir_surface(build_dir, &constants, python_abi, &mut notes)?;

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
    python_abi: Option<(u8, u8)>,
    notes: &mut Vec<String>,
) -> Result<Option<SurfaceModule>> {
    let Some((const_file, primary_blob)): Option<(&String, String)> =
        primary_module_blob(constants)
    else {
        notes.push("no primary module .const pool: surface unavailable".to_owned());
        return Ok(None);
    };
    let c_path: std::path::PathBuf = build_dir.join(format!("module.{primary_blob}.c"));
    let Some(bytes): Option<Vec<u8>> = read_c_source(&c_path)? else {
        notes.push(format!(
            "module.{primary_blob}.c absent: surface limited to names-only"
        ));
        return Ok(None);
    };
    let text: &str = std::str::from_utf8(&bytes).map_err(Error::CSourceInvalidUtf8)?;
    let cmod: CModuleStructure = parse_c_module_with_optional_python_abi(text, python_abi)?;
    let Some(pool): Option<&ConstantsPool> = constants.pools.get(const_file) else {
        notes.push("primary module pool vanished before surface build".to_owned());
        return Ok(None);
    };
    let surface: SurfaceModule =
        build_surface_with_optional_python_abi(&cmod, pool, Some(text), python_abi)?;
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
    let bytes: Vec<u8> = read_required_file_bounded(path, MAX_BINARY_INPUT_BYTES)?;
    let detection: Detection = detect_in_bytes(&bytes)?;

    if let Some(offset) = detection.onefile_payload_offset {
        return decompile_detected_onefile(&bytes, offset, &detection);
    }

    if let Some(build_dir) = sibling_build_dir(path) {
        let supplied_abi: Option<(u8, u8)> = python_abi_from_extension_path(path);
        return decompile_build_dir_with_binary(&build_dir, Some(&bytes), supplied_abi);
    }

    Ok(decompile_embedded_standalone(&bytes, &detection))
}

pub fn decompile_bytes(bytes: &[u8]) -> Result<NuitkaDecompilation> {
    validate_primary_binary_size(bytes.len())?;
    let detection: Detection = detect_in_bytes(bytes)?;
    if let Some(offset) = detection.onefile_payload_offset {
        return decompile_detected_onefile(bytes, offset, &detection);
    }
    Ok(decompile_embedded_standalone(bytes, &detection))
}

fn decompile_detected_onefile(
    bytes: &[u8],
    offset: usize,
    detection: &Detection,
) -> Result<NuitkaDecompilation> {
    match decompile_onefile(bytes, offset) {
        Ok(decompilation) => Ok(decompilation),
        Err(error) if onefile_transport_error(&error) => {
            Ok(decompile_embedded_standalone(bytes, detection))
        }
        Err(error) => Err(error),
    }
}

const fn onefile_transport_error(error: &Error) -> bool {
    matches!(
        error,
        Error::BadOnefileMagic(_) | Error::EmptyPayload | Error::EntryTruncated(_) | Error::Zstd(_)
    )
}

fn validate_primary_binary_size(bytes: usize) -> Result<()> {
    validate_binary_input_size("binary input", bytes)
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
    let native_bodies: Option<NativeBodyRecovery> =
        lift_native_bodies(bytes, module_constants.as_ref());
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
        function.body_stmts = body.recovered_stmts.clone();
        function.body_recovered = true;
        function.lift_fidelity = body.fidelity;
        upgraded += 1;
    }
    if upgraded > 0 {
        module.python_source = crate::surface::emit_python(module);
    }
    notes.push(format!(
        "native body lift: reconstructed {} body/bodies from the compiled machine code and \
         upgraded {upgraded} of them onto a named surface function; the rest carry an impl \
         address, a resolved CPython C-API call set and an operation trace only",
        bodies.reconstructed_bodies
    ));
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
    let python_abi: Option<(u8, u8)> = python_abi_from_binary(bytes);
    let version: NuitkaVersionReport = detect_nuitka_version(bytes, None, python_abi);
    let abi: Option<(u8, u8)> = python_abi.or(version.python_abi);
    let extracted: OnefilePayload = extract_onefile(bytes, offset)?;
    let reassembly: ReassemblyPlan = plan_reassembly(&extracted.entries)?;
    let mut payload: OnefileDecompilePayload = OnefileDecompilePayload::default();
    for entry in &extracted.entries {
        let streamed: StreamedEntry<'_> = StreamedEntry {
            filename: entry.filename.clone(),
            size: entry.size,
            permissions: entry.permissions,
            crc32: entry.crc32,
            symlink_target: entry.symlink_target.clone(),
            data: &entry.data,
        };
        payload.collect(&streamed, abi)?;
    }

    let mut notes: Vec<String> = Vec::new();
    let mut constants: ConstantsTable = ConstantsTable::default();
    for (file_name, bytes) in &payload.const_files {
        let blob_name: String = payload
            .manifest
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

    if constants.pools.is_empty() {
        notes.push("onefile payload carried no .const constant files".to_owned());
    }

    let (module_constants, skeleton): (Option<NuitkaConstants>, Option<NuitkaSkeleton>) =
        finalize_onefile_module_constants(payload.module_constants, &mut notes);
    let binary_constants: Option<BinaryConstants> =
        module_constants.as_ref().map(BinaryConstants::from_modules);
    let data_files: Vec<DataFileEntry> = payload.data_files;
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
    notes.push(format!(
        "onefile reassembly plan: {} entry/entries, {} byte(s), {} directory/directories",
        reassembly.tree.len(),
        reassembly.stats.total_bytes,
        reassembly.directories.len(),
    ));

    let bytecode: Option<BytecodeTable> =
        recover_bytecode_table(payload.bytecode_const.as_deref(), abi, &mut notes);
    let frozen_modules: Option<FrozenModules> = payload.frozen_modules;
    if let Some(frozen) = frozen_modules.as_ref() {
        notes.extend(frozen.notes.iter().cloned());
    }
    let main_image: Option<(&str, &[u8])> = payload
        .main_image
        .as_ref()
        .map(|(name, image): &(String, Vec<u8>)| (name.as_str(), image.as_slice()));
    let native_disasm: Option<NativeDisasm> =
        main_image.and_then(|(name, image): (&str, &[u8])| disassemble_module_stats(name, image));
    let name_map: Option<NativeNameMap> = main_image.and_then(|(name, image): (&str, &[u8])| {
        recover_name_map(name, image, module_constants.as_ref(), &mut notes)
    });
    let native_bodies: Option<NativeBodyRecovery> = main_image
        .and_then(|(_, image): (&str, &[u8])| lift_native_bodies(image, module_constants.as_ref()));
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
        manifest: payload.manifest,
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

#[derive(Debug, Default)]
struct OnefileDecompilePayload {
    manifest: Option<ConstantManifest>,
    const_files: Vec<(String, Vec<u8>)>,
    bytecode_const: Option<Vec<u8>>,
    data_files: Vec<DataFileEntry>,
    module_constants: Option<NuitkaConstants>,
    frozen_modules: Option<FrozenModules>,
    main_image: Option<(String, Vec<u8>)>,
    constant_budget: ConstantInputBudget,
}

impl OnefileDecompilePayload {
    fn collect(&mut self, entry: &StreamedEntry<'_>, python_abi: Option<(u8, u8)>) -> Result<()> {
        if entry.symlink_target.is_none() {
            self.data_files.push(DataFileEntry {
                filename: entry.filename.clone(),
                size: entry.size,
                kind: classify_data_file(&entry.filename),
            });
        }
        if self.manifest.is_none() && is_constant_manifest_filename(&entry.filename) {
            self.manifest = Some(parse_constant_manifest(entry.data)?);
        }
        if is_bytecode_const_filename(&entry.filename) || is_const_filename(&entry.filename) {
            self.constant_budget.add(entry.data.len())?;
            if is_bytecode_const_filename(&entry.filename) {
                self.bytecode_const = Some(entry.data.to_vec());
            } else {
                self.const_files
                    .push((entry.filename.clone(), entry.data.to_vec()));
            }
        }
        if !is_native_image(entry.data) {
            return Ok(());
        }
        consider_onefile_module_constants(&mut self.module_constants, entry.data);
        consider_onefile_frozen(&mut self.frozen_modules, entry.data, python_abi);
        if self.main_image.is_none() && is_onefile_main_image(entry) {
            self.main_image = Some((entry.filename.clone(), entry.data.to_vec()));
        }
        Ok(())
    }
}

fn is_onefile_main_image(entry: &StreamedEntry<'_>) -> bool {
    entry.symlink_target.is_none()
        && !entry.filename.contains('/')
        && !entry.filename.contains('\\')
        && entry.filename.to_ascii_lowercase().ends_with(".dll")
        && is_native_image(entry.data)
        && !is_runtime_dll(&entry.filename)
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

fn consider_onefile_frozen(
    best: &mut Option<FrozenModules>,
    data: &[u8],
    python_abi: Option<(u8, u8)>,
) {
    let Some(frozen): Option<FrozenModules> = recover_frozen_bytecode(data, python_abi) else {
        return;
    };
    let better: bool = best
        .as_ref()
        .is_none_or(|current: &FrozenModules| frozen.modules.len() > current.modules.len());
    if better {
        *best = Some(frozen);
    }
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

fn consider_onefile_module_constants(best: &mut Option<NuitkaConstants>, data: &[u8]) {
    let constants: NuitkaConstants = parse_constants(data);
    if constants.is_empty() {
        return;
    }
    let better: bool = best
        .as_ref()
        .is_none_or(|current: &NuitkaConstants| constants.modules.len() > current.modules.len());
    if better {
        *best = Some(constants);
    }
}

fn finalize_onefile_module_constants(
    best: Option<NuitkaConstants>,
    notes: &mut Vec<String>,
) -> (Option<NuitkaConstants>, Option<NuitkaSkeleton>) {
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
    let bytes: Vec<u8> = match read_file_bounded(&manifest_path, MAX_CONSTANT_MANIFEST_BYTES)? {
        None => {
            notes.push("blobs/__constant.txt absent: blob_name fallback from filenames".to_owned());
            return Ok(None);
        }
        Some(BoundedFileRead::Bytes(bytes)) => bytes,
        Some(BoundedFileRead::TooLarge { bytes }) => {
            return Err(Error::ArtifactTooLarge {
                path: manifest_path,
                bytes,
                max_bytes: MAX_CONSTANT_MANIFEST_BYTES,
            });
        }
    };
    Ok(Some(parse_constant_manifest(&bytes)?))
}

fn is_const_filename(file_name: &str) -> bool {
    Path::new(file_name)
        .extension()
        .is_some_and(|ext: &std::ffi::OsStr| ext.eq_ignore_ascii_case("const"))
}

fn is_bytecode_const_filename(file_name: &str) -> bool {
    file_name
        .rsplit(['/', '\\'])
        .next()
        .is_some_and(|name: &str| name.eq_ignore_ascii_case(BYTECODE_CONST))
}

fn is_constant_manifest_filename(file_name: &str) -> bool {
    file_name
        .rsplit(['/', '\\'])
        .next()
        .is_some_and(|name: &str| name.eq_ignore_ascii_case("__constant.txt"))
}

type ConstFiles = (Vec<(String, Vec<u8>)>, Option<Vec<u8>>);

fn list_const_files(build_dir: &Path) -> Result<ConstFiles> {
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    let mut bytecode: Option<Vec<u8>> = None;
    let mut paths: Vec<(String, std::path::PathBuf)> = Vec::new();
    let mut directory_entries: usize = 0usize;
    for entry in std::fs::read_dir(build_dir)? {
        directory_entries = next_directory_entry_count(directory_entries, build_dir)?;
        let entry: std::fs::DirEntry = entry?;
        let file_name_os: std::ffi::OsString = entry.file_name();
        let Some(file_name): Option<&str> = file_name_os.to_str() else {
            continue;
        };
        if !is_const_filename(file_name) {
            continue;
        }
        if paths.len() == MAX_BUILD_CONST_FILES {
            return Err(Error::TooManyConstFiles {
                count: paths.len().saturating_add(1usize),
                max_count: MAX_BUILD_CONST_FILES,
            });
        }
        paths.push((file_name.to_owned(), entry.path()));
    }
    paths.sort_by(
        |left: &(String, std::path::PathBuf), right: &(String, std::path::PathBuf)| {
            left.0.cmp(&right.0)
        },
    );
    let mut total_bytes: u64 = 0u64;
    for (file_name, path) in paths {
        let remaining: u64 = MAX_BUILD_CONST_BYTES.saturating_sub(total_bytes);
        let maximum: u64 = MAX_CONST_FILE_BYTES.min(remaining);
        let bytes: Vec<u8> = match read_file_bounded(&path, maximum)? {
            None => continue,
            Some(BoundedFileRead::Bytes(bytes)) => bytes,
            Some(BoundedFileRead::TooLarge { bytes }) if maximum == MAX_CONST_FILE_BYTES => {
                return Err(Error::ArtifactTooLarge {
                    path,
                    bytes,
                    max_bytes: MAX_CONST_FILE_BYTES,
                });
            }
            Some(BoundedFileRead::TooLarge { bytes }) => {
                return Err(Error::BuildConstantsTooLarge {
                    bytes: total_bytes.saturating_add(bytes),
                    max_bytes: MAX_BUILD_CONST_BYTES,
                });
            }
        };
        let bytes_len: u64 = u64::try_from(bytes.len()).map_or(u64::MAX, |value| value);
        total_bytes = total_bytes
            .checked_add(bytes_len)
            .ok_or(Error::BuildConstantsTooLarge {
                bytes: u64::MAX,
                max_bytes: MAX_BUILD_CONST_BYTES,
            })?;
        if is_bytecode_const_filename(&file_name) {
            bytecode = Some(bytes);
            continue;
        }
        out.push((file_name.clone(), bytes));
    }
    out.sort_by(|a: &(String, Vec<u8>), b: &(String, Vec<u8>)| a.0.cmp(&b.0));
    Ok((out, bytecode))
}

fn next_directory_entry_count(count: usize, directory: &Path) -> Result<usize> {
    if count == MAX_BUILD_DIRECTORY_ENTRIES {
        return Err(Error::TooManyDirectoryEntries {
            path: directory.to_path_buf(),
            max_count: MAX_BUILD_DIRECTORY_ENTRIES,
        });
    }
    Ok(count.saturating_add(1usize))
}

fn locate_sibling_binary(build_dir: &Path) -> Result<Option<SiblingBinary>> {
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
    let mut candidate: Option<std::path::PathBuf> = None;
    let Ok(entries): std::result::Result<std::fs::ReadDir, std::io::Error> =
        std::fs::read_dir(parent)
    else {
        return Ok(None);
    };
    for (directory_entries, entry) in entries.flatten().enumerate() {
        if directory_entries == MAX_BUILD_DIRECTORY_ENTRIES {
            return Ok(None);
        }
        let path: std::path::PathBuf = entry.path();
        if sibling_binary_path_matches(&path, stem) && candidate.replace(path).is_some() {
            return Ok(None);
        }
    }
    if let Some(candidate) = candidate {
        return read_sibling_binary(&candidate);
    }
    Ok(None)
}

fn sibling_binary_path_matches(path: &Path, stem: &str) -> bool {
    if !path.is_file() {
        return false;
    }
    let Some(file_name): Option<&str> = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if file_name == stem {
        return true;
    }
    let Some(extension): Option<&str> = path.extension().and_then(|value| value.to_str()) else {
        return false;
    };
    let Some(file_stem): Option<&str> = path.file_stem().and_then(|value| value.to_str()) else {
        return false;
    };
    if (extension.eq_ignore_ascii_case("exe") || extension.eq_ignore_ascii_case("bin"))
        && file_stem == stem
    {
        return true;
    }
    if !is_extension_module_extension(extension) {
        return false;
    }
    if file_stem == stem {
        return true;
    }
    let Some((candidate_stem, abi_suffix)): Option<(&str, &str)> = file_stem.rsplit_once('.')
    else {
        return false;
    };
    candidate_stem == stem && python_extension_abi_suffix(abi_suffix)
}

fn read_sibling_binary(path: &Path) -> Result<Option<SiblingBinary>> {
    read_sibling_binary_with_limit(path, MAX_SIBLING_BINARY_BYTES)
}

fn read_sibling_binary_with_limit(path: &Path, maximum: u64) -> Result<Option<SiblingBinary>> {
    let python_abi: Option<(u8, u8)> = python_abi_from_extension_path(path);
    let (bytes, skipped_bytes): (Vec<u8>, Option<u64>) = match read_file_bounded(path, maximum)? {
        None => return Ok(None),
        Some(BoundedFileRead::Bytes(bytes)) => (bytes, None),
        Some(BoundedFileRead::TooLarge { bytes }) => (Vec::new(), Some(bytes)),
    };
    Ok(Some(SiblingBinary {
        bytes,
        python_abi,
        skipped_bytes,
    }))
}

fn sibling_build_dir(binary: &Path) -> Option<std::path::PathBuf> {
    let file_stem: &str = binary
        .file_stem()
        .and_then(|s: &std::ffi::OsStr| s.to_str())?;
    let stem: &str = if is_extension_module_path(binary) {
        module_build_stem(file_stem)
    } else {
        file_stem
    };
    let parent: &Path = binary.parent()?;
    let candidate: std::path::PathBuf = parent.join(format!("{stem}.build"));
    candidate.is_dir().then_some(candidate)
}

fn module_build_stem(file_stem: &str) -> &str {
    let Some((stem, abi_suffix)): Option<(&str, &str)> = file_stem.rsplit_once('.') else {
        return file_stem;
    };
    if python_extension_abi_suffix(abi_suffix) {
        stem
    } else {
        file_stem
    }
}

fn python_extension_abi_suffix(suffix: &str) -> bool {
    python_abi_from_extension_suffix(suffix).is_some()
}

fn python_abi_from_extension_path(path: &Path) -> Option<(u8, u8)> {
    if !is_extension_module_path(path) {
        return None;
    }
    let stem: &str = path.file_stem()?.to_str()?;
    let (_, suffix): (&str, &str) = stem.rsplit_once('.')?;
    python_abi_from_extension_suffix(suffix)
}

fn is_extension_module_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension: &std::ffi::OsStr| extension.to_str())
        .is_some_and(is_extension_module_extension)
}

const fn is_extension_module_extension(extension: &str) -> bool {
    extension.eq_ignore_ascii_case("pyd")
        || extension.eq_ignore_ascii_case("so")
        || extension.eq_ignore_ascii_case("dylib")
}

fn python_abi_from_extension_suffix(suffix: &str) -> Option<(u8, u8)> {
    let digits: &str = python_extension_abi_digits(suffix)?;
    let (major, minor): (&str, &str) = digits.split_at(1usize);
    let major: u8 = major.parse().ok()?;
    let minor: u8 = minor.parse().ok()?;
    (major != 0u8).then_some((major, minor))
}

fn python_extension_abi_digits(suffix: &str) -> Option<&str> {
    let digits: &str = suffix
        .strip_prefix("cpython-")
        .or_else(|| suffix.strip_prefix("cp"))?;
    let digit_count: usize = digits
        .bytes()
        .take_while(|byte: &u8| byte.is_ascii_digit())
        .count();
    if digit_count < 2 {
        return None;
    }
    let flags_and_platform: &[u8] = &digits.as_bytes()[digit_count..];
    let mut flag_end: usize = 0usize;
    while flags_and_platform
        .get(flag_end)
        .is_some_and(|byte: &u8| matches!(*byte, b'd' | b'm' | b't' | b'u'))
    {
        flag_end += 1;
    }
    flags_and_platform
        .get(flag_end)
        .is_none_or(|byte: &u8| matches!(*byte, b'-' | b'_'))
        .then_some(&digits[..digit_count])
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
    let stem: &str = strip_const_suffix(file_name);
    if stem == "__constants" {
        return String::new();
    }
    stem.strip_prefix("module.").unwrap_or(stem).to_owned()
}

fn strip_const_suffix(file_name: &str) -> &str {
    let Some(stem_end): Option<usize> = file_name.len().checked_sub(".const".len()) else {
        return file_name;
    };
    let (Some(stem), Some(suffix)): (Option<&str>, Option<&str>) =
        (file_name.get(..stem_end), file_name.get(stem_end..))
    else {
        return file_name;
    };
    if suffix.eq_ignore_ascii_case(".const") {
        stem
    } else {
        file_name
    }
}

fn read_c_source(path: &Path) -> Result<Option<Vec<u8>>> {
    read_c_source_with_limit(path, MAX_C_SOURCE_BYTES as u64)
}

fn read_c_source_with_limit(path: &Path, maximum: u64) -> Result<Option<Vec<u8>>> {
    match read_file_bounded(path, maximum)? {
        None => Ok(None),
        Some(BoundedFileRead::Bytes(bytes)) => Ok(Some(bytes)),
        Some(BoundedFileRead::TooLarge { bytes }) => {
            let bytes: usize = usize::try_from(bytes).map_or(usize::MAX, |bytes| bytes);
            let max_bytes: usize = usize::try_from(maximum).map_or(usize::MAX, |bytes| bytes);
            Err(Error::CSourceTooLarge { bytes, max_bytes })
        }
    }
}

pub(crate) fn read_required_file_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    match read_file_bounded(path, maximum)? {
        Some(BoundedFileRead::Bytes(bytes)) => Ok(bytes),
        Some(BoundedFileRead::TooLarge { bytes }) => Err(Error::ArtifactTooLarge {
            path: path.to_path_buf(),
            bytes,
            max_bytes: maximum,
        }),
        None => Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{} was not found", path.display()),
        ))),
    }
}

fn read_file_bounded(path: &Path, maximum: u64) -> Result<Option<BoundedFileRead>> {
    let metadata: std::fs::Metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(Error::Io(error)),
    };
    if !metadata.is_file() {
        return Err(Error::NonRegularArtifact {
            path: path.to_path_buf(),
        });
    }
    let file: std::fs::File = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(Error::Io(error)),
    };
    let opened_metadata: std::fs::Metadata = file.metadata()?;
    if !opened_metadata.is_file() {
        return Err(Error::NonRegularArtifact {
            path: path.to_path_buf(),
        });
    }
    let declared: u64 = opened_metadata.len();
    if declared > maximum {
        return Ok(Some(BoundedFileRead::TooLarge { bytes: declared }));
    }
    let mut bytes: Vec<u8> = Vec::with_capacity(bounded_read_capacity(declared));
    let mut reader: std::io::Take<std::fs::File> = file.take(maximum.saturating_add(1u64));
    reader.read_to_end(&mut bytes)?;
    let actual: u64 = u64::try_from(bytes.len()).map_or(u64::MAX, |actual| actual);
    if actual > maximum {
        return Ok(Some(BoundedFileRead::TooLarge { bytes: actual }));
    }
    Ok(Some(BoundedFileRead::Bytes(bytes)))
}

fn bounded_read_capacity(declared: u64) -> usize {
    usize::try_from(declared).map_or(MAX_BOUNDED_READ_PREALLOC_BYTES, |bytes: usize| {
        bytes.min(MAX_BOUNDED_READ_PREALLOC_BYTES)
    })
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
    fn versioned_extension_stems_locate_the_normal_build_directory() {
        assert_eq!(module_build_stem("module.cp314-win_amd64"), "module");
        assert_eq!(
            module_build_stem("module.cpython-314-x86_64-linux-gnu"),
            "module"
        );
        assert_eq!(module_build_stem("module.custom"), "module.custom");
    }

    #[test]
    fn extension_abi_suffix_preserves_the_compiled_python_minor() {
        assert_eq!(
            python_abi_from_extension_suffix("cp314-win_amd64"),
            Some((3, 14))
        );
        assert_eq!(
            python_abi_from_extension_suffix("cpython-313-x86_64-linux-gnu"),
            Some((3, 13))
        );
        assert_eq!(python_abi_from_extension_suffix("cp3-win_amd64"), None);
    }

    #[test]
    fn extension_abi_requires_an_extension_module_filename() {
        assert_eq!(
            python_abi_from_extension_path(Path::new("module.cp314-win_amd64.pyd")),
            Some((3, 14))
        );
        assert_eq!(
            python_abi_from_extension_path(Path::new("module.cp314-win_amd64.PYD")),
            Some((3, 14))
        );
        assert_eq!(
            python_abi_from_extension_path(Path::new("module.cp314-win_amd64.exe")),
            None
        );
    }

    #[test]
    fn only_extension_modules_strip_abi_tags_for_build_directory_lookup() {
        let purpose: String = format!("disrobe-nuitka-extension-build-stem-{}", std::process::id());
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
        let dir: std::path::PathBuf = scratch.path().to_path_buf();
        let build_dir: std::path::PathBuf = dir.join("module.build");
        std::fs::create_dir_all(&build_dir).expect("create build directory");

        assert_eq!(
            sibling_build_dir(&dir.join("module.cp314-win_amd64.PYD")),
            Some(build_dir)
        );
        assert_eq!(
            sibling_build_dir(&dir.join("module.cp314-win_amd64.exe")),
            None
        );
    }

    #[test]
    fn sibling_discovery_accepts_case_insensitive_unversioned_extensions() {
        let purpose: String = format!(
            "disrobe-nuitka-upper-extension-sibling-{}",
            std::process::id()
        );
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
        let dir: std::path::PathBuf = scratch.path().to_path_buf();
        std::fs::create_dir_all(dir.join("module.build")).expect("create build directory");
        let binary_path: std::path::PathBuf = dir.join("module.PYD");
        std::fs::write(&binary_path, b"__compiled__").expect("write extension module");

        let sibling: SiblingBinary = locate_sibling_binary(&dir.join("module.build"))
            .expect("locate sibling")
            .expect("uppercase extension sibling");
        assert_eq!(sibling.python_abi, None);
        assert_eq!(sibling.bytes, b"__compiled__");
        assert_eq!(sibling.skipped_bytes, None);
    }

    #[test]
    fn oversized_versioned_sibling_preserves_filename_abi_without_payload() {
        let purpose: String = format!("disrobe-nuitka-oversized-sibling-{}", std::process::id());
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
        let dir: std::path::PathBuf = scratch.path().to_path_buf();
        std::fs::create_dir_all(dir.join("module.build")).expect("create build directory");
        let binary_path: std::path::PathBuf = dir.join("module.cp314-win_amd64.PYD");
        std::fs::write(&binary_path, b"four").expect("write binary");

        let sibling: SiblingBinary = read_sibling_binary_with_limit(&binary_path, 3u64)
            .expect("locate sibling")
            .expect("versioned sibling");

        assert_eq!(sibling.python_abi, Some((3, 14)));
        assert!(sibling.bytes.is_empty());
        assert_eq!(sibling.skipped_bytes, Some(4u64));
        assert!(matches!(
            read_c_source_with_limit(&binary_path, 3u64),
            Err(Error::CSourceTooLarge { bytes, max_bytes })
                if bytes == 4usize && max_bytes == 3usize
        ));
    }

    #[test]
    fn primary_binary_reader_rejects_before_reading_the_whole_artifact() {
        let purpose: String = format!("disrobe-nuitka-primary-cap-{}", std::process::id());
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
        let dir: std::path::PathBuf = scratch.path().to_path_buf();
        let binary_path: std::path::PathBuf = dir.join("oversized.exe");
        std::fs::write(&binary_path, b"four").expect("write binary");

        assert!(matches!(
            read_required_file_bounded(&binary_path, 3u64),
            Err(Error::ArtifactTooLarge {
                path,
                bytes,
                max_bytes,
            }) if path == binary_path && bytes == 4u64 && max_bytes == 3u64
        ));
    }

    #[test]
    fn raw_binary_and_directory_entry_caps_reject_before_work() {
        let bytes: usize =
            usize::try_from(MAX_BINARY_INPUT_BYTES + 1u64).expect("binary cap fits usize");
        assert!(matches!(
            validate_primary_binary_size(bytes),
            Err(Error::InputTooLarge { resource, bytes: actual, max_bytes })
                if resource == "binary input"
                    && actual == MAX_BINARY_INPUT_BYTES + 1u64
                    && max_bytes == MAX_BINARY_INPUT_BYTES
        ));
        let directory: &Path = Path::new("build");
        assert!(matches!(
            next_directory_entry_count(MAX_BUILD_DIRECTORY_ENTRIES, directory),
            Err(Error::TooManyDirectoryEntries { path, max_count })
                if path == directory && max_count == MAX_BUILD_DIRECTORY_ENTRIES
        ));
        assert_eq!(bounded_read_capacity(4096u64), 4096usize);
        assert_eq!(
            bounded_read_capacity(MAX_BINARY_INPUT_BYTES),
            MAX_BOUNDED_READ_PREALLOC_BYTES
        );
    }

    #[test]
    fn bounded_constant_manifest_reader_rejects_before_reading() {
        let purpose: String = format!("disrobe-nuitka-manifest-cap-{}", std::process::id());
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
        let dir: std::path::PathBuf = scratch.path().to_path_buf();
        let manifest_path: std::path::PathBuf = dir.join("__constant.txt");
        std::fs::write(&manifest_path, b"four").expect("write manifest");

        assert!(matches!(
            read_required_file_bounded(&manifest_path, 3u64),
            Err(Error::ArtifactTooLarge {
                path,
                bytes,
                max_bytes,
            }) if path == manifest_path && bytes == 4u64 && max_bytes == 3u64
        ));
    }

    #[test]
    fn bounded_constant_blob_reader_rejects_before_reading() {
        let purpose: String = format!("disrobe-nuitka-const-cap-{}", std::process::id());
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
        let dir: std::path::PathBuf = scratch.path().to_path_buf();
        let const_path: std::path::PathBuf = dir.join("module.oversized.const");
        std::fs::write(&const_path, b"four").expect("write const file");

        assert!(matches!(
            read_required_file_bounded(&const_path, 3u64),
            Err(Error::ArtifactTooLarge {
                path,
                bytes,
                max_bytes,
            }) if path == const_path && bytes == 4u64 && max_bytes == 3u64
        ));
    }

    #[test]
    fn direct_versioned_extension_passes_filename_abi_to_its_build_directory() {
        let purpose: String = format!("disrobe-nuitka-direct-extension-{}", std::process::id());
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
        let dir: std::path::PathBuf = scratch.path().to_path_buf();
        let build_dir: std::path::PathBuf = dir.join("hello.build");
        std::fs::create_dir_all(&build_dir).expect("create build directory");
        let fixture_dir: std::path::PathBuf = fixture("module/hello.build");
        for file_name in [
            "__constants.const",
            "__constants.c",
            "module.hello.const",
            "module.hello.c",
        ] {
            std::fs::copy(fixture_dir.join(file_name), build_dir.join(file_name))
                .expect("copy build artifact");
        }
        let binary_path: std::path::PathBuf = dir.join("hello.cp314-win_amd64.pyd");
        std::fs::write(&binary_path, b"__compiled__").expect("write nuitka marker");

        let decompilation: NuitkaDecompilation =
            decompile_binary(&binary_path).expect("decompile direct extension");

        assert_eq!(decompilation.source_kind, DecompSourceKind::BuildDir);
        assert_eq!(decompilation.version.python_abi, Some((3, 14)));
        assert!(decompilation.surface.is_some());
    }

    #[test]
    fn bounded_build_constants_source_is_rejected_before_reading() {
        let purpose: String = format!("disrobe-nuitka-oversized-constants-{}", std::process::id());
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
        let dir: std::path::PathBuf = scratch.path().to_path_buf();
        let c_path: std::path::PathBuf = dir.join("__constants.c");
        std::fs::write(&c_path, b"four").expect("write C source");

        assert!(matches!(
            read_c_source_with_limit(&c_path, 3u64),
            Err(Error::CSourceTooLarge { bytes, max_bytes })
                if bytes == 4usize && max_bytes == 3usize
        ));
    }

    #[test]
    fn nonregular_build_constants_source_is_rejected_before_opening() {
        let purpose: String = format!("disrobe-nuitka-nonregular-constants-{}", std::process::id());
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
        let dir: std::path::PathBuf = scratch.path().to_path_buf();
        let c_path: std::path::PathBuf = dir.join("__constants.c");
        std::fs::create_dir(&c_path).expect("create nonregular C source");

        assert!(matches!(
            decompile_build_dir(&dir),
            Err(Error::NonRegularArtifact { path }) if path == c_path
        ));
    }

    #[test]
    fn invalid_utf8_module_source_is_rejected_without_lossy_expansion() {
        let purpose: String = format!("disrobe-nuitka-invalid-utf8-{}", std::process::id());
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
        let dir: std::path::PathBuf = scratch.path().to_path_buf();
        std::fs::copy(
            fixture("module/hello.build/module.hello.const"),
            dir.join("module.hello.const"),
        )
        .expect("copy constants");
        std::fs::write(dir.join("module.hello.c"), [0xffu8]).expect("write invalid C source");

        assert!(matches!(
            decompile_build_dir(&dir),
            Err(Error::CSourceInvalidUtf8(_))
        ));
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
