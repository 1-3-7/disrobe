use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::str::FromStr as _;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use disrobe_binfmt::{
    Arch, NativeFile, NativeImage, NativeImageSection, ParsedNativeFormat as NativeFormat,
    parse_native, parse_native_image,
};
use disrobe_core::{ExtractedString, StringTagging as Tagging, StringsOptions, strings_report};
use disrobe_dataforensics::capture::{
    CaptureError, CaptureOptions, CaptureReport, inspect as inspect_capture,
};
use disrobe_dataforensics::sqlite::{
    InspectOptions, Limits as SqliteLimits, SqliteError, SqliteReport, inspect as inspect_sqlite,
};
use disrobe_ir::payload::DisasmPayload;
use disrobe_pass_native::{
    IdentityReport, ProgramFunction, PseudoAbi, RecoveredFunction, RecoveredProgram,
    build_disasm_payload, detect_identity, recover_program,
};
use disrobe_query::{Function, FunctionId, InsnClass, InsnView, Module, module_from_envelope};
use rmcp::ErrorData;
use rmcp::Json;
use rmcp::handler::server::wrapper::Parameters;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use super::navigation::decode_module;
use super::{DisrobeMcp, decode_inline_bytes, hex32, read_bounded_open_file};

pub(super) const ROOTS_ENV: &str = "DISROBE_MCP_ROOTS";
const MAX_TARGET_BYTES: u64 = 512 * 1024 * 1024;
const MAX_INLINE_TOOL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CACHED_TARGETS: usize = 8;
const MAX_CACHED_BYTES: usize = 1024 * 1024 * 1024;
const DEFAULT_FUNCTION_PAGE: usize = 100;
const MAX_FUNCTION_PAGE: usize = 500;
const MAX_SELECTOR_BYTES: usize = 512;
const DEFAULT_DISASM_INSTRUCTIONS: usize = 512;
const MAX_DISASM_INSTRUCTIONS: usize = 4096;
const DEFAULT_READ_BYTES: usize = 256;
const MAX_READ_BYTES: usize = 64 * 1024;
const DEFAULT_SEARCH_HITS: usize = 64;
const MAX_SEARCH_HITS: usize = 1024;
const MAX_PATTERN_TOKENS: usize = 256;
const DEFAULT_CALL_PATH_DEPTH: u8 = 12;
const MAX_CALL_PATH_DEPTH: u8 = 32;
const MAX_LAYOUT_ROWS: usize = 4096;
const MAX_DECOMPILE_CALLEES: usize = 256;
const DEFAULT_SQLITE_ROWS: usize = 20;
const MAX_SQLITE_ROWS: usize = 1000;
const MAX_DATA_REFS: usize = 2_000_000;
const MAX_POINTER_SLOTS: usize = 4_000_000;
const MAX_POINTER_SCAN_BYTES: usize = 128 * 1024 * 1024;
const MAX_REFERENCES: usize = 1024;
const DEFAULT_STRING_PAGE: usize = 100;
const MAX_STRING_PAGE: usize = 1000;
const MAX_REFS_PER_STRING: usize = 16;
const MAX_NEEDLE_BYTES: usize = 1024;

#[derive(Debug)]
pub(super) struct Workspace {
    roots: Vec<PathBuf>,
    cache: Mutex<TargetCache>,
}

#[derive(Debug, Default)]
struct TargetCache {
    order: VecDeque<[u8; 32]>,
    entries: BTreeMap<[u8; 32], Arc<Target>>,
    bytes: usize,
}

#[derive(Debug)]
pub(super) struct Target {
    id: [u8; 32],
    path: PathBuf,
    bytes: Vec<u8>,
    native: OnceLock<Result<NativeIndex, String>>,
}

#[derive(Debug)]
struct NativeIndex {
    file: NativeFile,
    module: Module,
    data_refs: BTreeMap<u64, Vec<u64>>,
    data_refs_truncated: bool,
    pointer_slots: BTreeMap<u64, Vec<u64>>,
    pointer_slots_truncated: bool,
}

impl Workspace {
    pub(super) fn discover(extra: &[PathBuf]) -> Result<Self, String> {
        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Ok(cwd) = std::env::current_dir() {
            candidates.push(cwd);
        }
        if let Some(value) = std::env::var_os(ROOTS_ENV) {
            candidates.extend(
                std::env::split_paths(&value).filter(|p: &PathBuf| !p.as_os_str().is_empty()),
            );
        }
        candidates.extend(extra.iter().cloned());
        let mut roots: Vec<PathBuf> = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            let canonical: PathBuf =
                candidate.canonicalize().map_err(|error: std::io::Error| {
                    format!(
                        "DR-MCP-0700: workspace root {} cannot be resolved: {error}",
                        candidate.display()
                    )
                })?;
            if !canonical.is_dir() {
                return Err(format!(
                    "DR-MCP-0700: workspace root {} is not a directory",
                    canonical.display()
                ));
            }
            if !roots.contains(&canonical) {
                roots.push(canonical);
            }
        }
        if roots.is_empty() {
            return Err(format!(
                "DR-MCP-0700: no workspace root: the working directory is unreadable and neither --root nor {ROOTS_ENV} names one"
            ));
        }
        Ok(Self {
            roots,
            cache: Mutex::new(TargetCache::default()),
        })
    }

    fn resolve(&self, raw: &str) -> Result<PathBuf, ErrorData> {
        if raw.trim().is_empty() {
            return Err(ErrorData::invalid_params(
                "DR-MCP-0701: `path` must name a file inside a workspace root",
                None,
            ));
        }
        let requested: &Path = Path::new(raw);
        let joined: PathBuf = match (requested.is_absolute(), self.roots.first()) {
            (true, _) | (false, None) => requested.to_path_buf(),
            (false, Some(root)) => root.join(requested),
        };
        let canonical: PathBuf = joined.canonicalize().map_err(|error: std::io::Error| {
            ErrorData::invalid_params(format!("DR-MCP-0702: cannot locate {raw}: {error}"), None)
        })?;
        if !self
            .roots
            .iter()
            .any(|root: &PathBuf| canonical.starts_with(root))
        {
            return Err(ErrorData::invalid_params(
                format!(
                    "DR-MCP-0703: {raw} resolves to {} outside every workspace root ({}); start the server with --root or {ROOTS_ENV} to admit another directory",
                    canonical.display(),
                    self.roots
                        .iter()
                        .map(|root: &PathBuf| root.display().to_string())
                        .collect::<Vec<String>>()
                        .join(", ")
                ),
                None,
            ));
        }
        if !canonical.is_file() {
            return Err(ErrorData::invalid_params(
                format!("DR-MCP-0704: {} is not a regular file", canonical.display()),
                None,
            ));
        }
        Ok(canonical)
    }

    pub(super) fn read_path(&self, raw: &str, limit: u64) -> Result<(PathBuf, Vec<u8>), ErrorData> {
        let path: PathBuf = self.resolve(raw)?;
        let file: std::fs::File = std::fs::File::open(&path).map_err(|error: std::io::Error| {
            ErrorData::invalid_params(
                format!("DR-MCP-0705: cannot open {}: {error}", path.display()),
                None,
            )
        })?;
        let bytes: Vec<u8> = read_bounded_open_file(&path, file, limit, "DR-MCP-0705")?;
        Ok((path, bytes))
    }

    fn lock(&self) -> MutexGuard<'_, TargetCache> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn open(&self, raw: &str) -> Result<Arc<Target>, ErrorData> {
        let (path, bytes): (PathBuf, Vec<u8>) = self.read_path(raw, MAX_TARGET_BYTES)?;
        let id: [u8; 32] = *blake3::hash(&bytes).as_bytes();
        let target: Arc<Target> = Arc::new(Target {
            id,
            path,
            bytes,
            native: OnceLock::new(),
        });
        let stored: Arc<Target> = self.lock().insert(target);
        Ok(stored)
    }

    fn get(&self, target_id: &str) -> Result<Arc<Target>, ErrorData> {
        let id: [u8; 32] = parse_target_id(target_id)?;
        self.lock().touch(&id).ok_or_else(|| {
            ErrorData::invalid_params(
                format!(
                    "DR-MCP-0707: target {target_id} is not open; call open_target again (the server keeps the {MAX_CACHED_TARGETS} most recently used targets)"
                ),
                None,
            )
        })
    }
}

impl TargetCache {
    fn touch(&mut self, id: &[u8; 32]) -> Option<Arc<Target>> {
        let found: Arc<Target> = self.entries.get(id).cloned()?;
        self.order.retain(|key: &[u8; 32]| key != id);
        self.order.push_back(*id);
        Some(found)
    }

    fn insert(&mut self, target: Arc<Target>) -> Arc<Target> {
        let id: [u8; 32] = target.id;
        if let Some(existing) = self.touch(&id) {
            return existing;
        }
        self.bytes = self.bytes.saturating_add(target.bytes.len());
        self.entries.insert(id, Arc::clone(&target));
        self.order.push_back(id);
        while self.order.len() > 1
            && (self.order.len() > MAX_CACHED_TARGETS || self.bytes > MAX_CACHED_BYTES)
        {
            let Some(evicted) = self.order.pop_front() else {
                break;
            };
            if let Some(old) = self.entries.remove(&evicted) {
                self.bytes = self.bytes.saturating_sub(old.bytes.len());
            }
        }
        target
    }
}

fn parse_target_id(value: &str) -> Result<[u8; 32], ErrorData> {
    let invalid = || {
        ErrorData::invalid_params(
            "DR-MCP-0706: `target_id` must be the 64-hex-digit id open_target returned",
            None,
        )
    };
    if value.len() != 64 {
        return Err(invalid());
    }
    let mut id: [u8; 32] = [0u8; 32];
    for (slot, pair) in id.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let text: &str = std::str::from_utf8(pair).map_err(|_| invalid())?;
        *slot = u8::from_str_radix(text, 16).map_err(|_| invalid())?;
    }
    Ok(id)
}

impl Target {
    fn native(&self) -> Result<&NativeIndex, ErrorData> {
        self.native
            .get_or_init(|| build_native_index(&self.bytes))
            .as_ref()
            .map_err(|reason: &String| {
                ErrorData::invalid_params(
                    format!(
                        "DR-MCP-0710: {} is not a disassemblable native image: {reason}",
                        self.path.display()
                    ),
                    None,
                )
            })
    }

    fn image(&self) -> Option<NativeImage<'_>> {
        parse_native_image(&self.bytes).ok()
    }
}

fn build_native_index(bytes: &[u8]) -> Result<NativeIndex, String> {
    let file: NativeFile = parse_native(bytes).map_err(|error| error.to_string())?;
    let payload: DisasmPayload = build_disasm_payload(bytes).map_err(|error| error.to_string())?;
    let mut data_refs: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    let mut recorded: usize = 0;
    let mut data_refs_truncated: bool = false;
    'instructions: for instruction in &payload.instructions {
        for operand in &instruction.mem_uses {
            let absolute: bool = matches!(operand.base.as_str(), "RIP" | "EIP")
                || (operand.base == "None" && operand.index == "None");
            if !absolute || operand.displacement == 0 {
                continue;
            }
            if recorded >= MAX_DATA_REFS {
                data_refs_truncated = true;
                break 'instructions;
            }
            data_refs
                .entry(operand.displacement)
                .or_default()
                .push(instruction.offset);
            recorded += 1;
        }
    }
    let (pointer_slots, pointer_slots_truncated): (BTreeMap<u64, Vec<u64>>, bool) =
        parse_native_image(bytes).map_or_else(
            |_| (BTreeMap::new(), false),
            |image| scan_pointer_slots(&image),
        );
    Ok(NativeIndex {
        file,
        module: Module::from_disasm(&payload),
        data_refs,
        data_refs_truncated,
        pointer_slots,
        pointer_slots_truncated,
    })
}

fn scan_pointer_slots(image: &NativeImage<'_>) -> (BTreeMap<u64, Vec<u64>>, bool) {
    let width: usize = usize::from(image.pointer_size());
    let mut slots: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    if width != 4 && width != 8 {
        return (slots, false);
    }
    let big_endian: bool = matches!(image.endian(), disrobe_binfmt::Endian::Big);
    let mut recorded: usize = 0;
    let mut scanned: usize = 0;
    for section in image.sections() {
        if section.executable {
            continue;
        }
        let Some(bytes) = image.bytes_at(section.address) else {
            continue;
        };
        let misalignment: usize = usize::try_from(section.address % width as u64).unwrap_or(0);
        let start: usize = (width - misalignment) % width;
        for (index, chunk) in bytes
            .get(start..)
            .unwrap_or_default()
            .chunks_exact(width)
            .enumerate()
        {
            scanned += width;
            if scanned > MAX_POINTER_SCAN_BYTES || recorded >= MAX_POINTER_SLOTS {
                return (slots, true);
            }
            let value: u64 = match (width, big_endian) {
                (8, false) => chunk.try_into().map_or(0, u64::from_le_bytes),
                (8, true) => chunk.try_into().map_or(0, u64::from_be_bytes),
                (_, false) => chunk
                    .try_into()
                    .map_or(0, |raw: [u8; 4]| u64::from(u32::from_le_bytes(raw))),
                (_, true) => chunk
                    .try_into()
                    .map_or(0, |raw: [u8; 4]| u64::from(u32::from_be_bytes(raw))),
            };
            if value == 0 || image.section_at(value).is_none() {
                continue;
            }
            let slot: u64 = section.address + (start + index * width) as u64;
            slots.entry(value).or_default().push(slot);
            recorded += 1;
        }
    }
    (slots, false)
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct OpenTargetParams {
    pub path: String,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct OpenTargetOut {
    pub target_id: String,
    pub path: String,
    pub size: usize,
    pub sha256: String,
    pub blake3: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native: Option<NativeIdentityOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_refusal: Option<String>,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct NativeIdentityOut {
    pub format: String,
    pub arch: String,
    pub bits: u32,
    pub big_endian: bool,
    pub sections: usize,
    pub symbols: usize,
    pub imports: usize,
    pub exports: usize,
    pub functions: usize,
    pub debug_info_present: bool,
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct TargetParams {
    pub target_id: String,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct LayoutOut {
    pub target_id: String,
    pub format: String,
    pub arch: String,
    pub sections: Vec<SectionOut>,
    pub imports: Vec<ImportOut>,
    pub imports_total: usize,
    pub exports: Vec<ExportOut>,
    pub exports_total: usize,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct SectionOut {
    pub name: String,
    pub address: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_offset: Option<u64>,
    pub file_size: u64,
    pub executable: bool,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct ImportOut {
    pub library: String,
    pub name: String,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct ExportOut {
    pub name: String,
    pub address: String,
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct ListFunctionsParams {
    pub target_id: String,
    #[serde(default)]
    pub name_contains: Option<String>,
    #[serde(default)]
    pub offset: Option<usize>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct ListFunctionsOut {
    pub target_id: String,
    pub total: usize,
    pub matched: usize,
    pub offset: usize,
    pub functions: Vec<FunctionRowOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
}

#[derive(Debug, Clone, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct FunctionRowOut {
    pub name: String,
    pub address: String,
    pub end: String,
    pub instructions: usize,
    pub export: bool,
    pub function_id: String,
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct FunctionParams {
    pub target_id: String,
    pub function: String,
    #[serde(default)]
    pub max_instructions: Option<usize>,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct DisassemblyOut {
    pub function: FunctionRowOut,
    pub instructions: Vec<InstructionOut>,
    pub total: usize,
    pub truncated: bool,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct InstructionOut {
    pub address: String,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_name: Option<String>,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct DecompileFunctionOut {
    pub function: FunctionRowOut,
    pub language: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
    pub resolved_calls: Vec<String>,
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct ReadBytesParams {
    pub target_id: String,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub offset: Option<u64>,
    #[serde(default)]
    pub length: Option<usize>,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct ReadBytesOut {
    pub offset: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    pub length: usize,
    pub hex: String,
    pub ascii: String,
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct SearchBytesParams {
    pub target_id: String,
    pub pattern: String,
    #[serde(default)]
    pub max_hits: Option<usize>,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct SearchBytesOut {
    pub pattern: String,
    pub hits: Vec<LocationOut>,
    pub truncated: bool,
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct LocateParams {
    pub target_id: String,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub offset: Option<u64>,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct LocationOut {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_address: Option<String>,
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct CallPathParams {
    pub target_id: String,
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub max_depth: Option<u8>,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct CallPathOut {
    pub found: bool,
    pub path: Vec<FunctionRowOut>,
    pub explored: usize,
    pub max_depth: u8,
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct ReferencesParams {
    pub target_id: String,
    pub address: String,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct ReferencesOut {
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    pub references: Vec<ReferenceOut>,
    pub total: usize,
    pub truncated: bool,
    pub data_index_truncated: bool,
}

#[derive(Debug, Clone, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct ReferenceOut {
    pub from: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_address: Option<String>,
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct FindStringsParams {
    pub target_id: String,
    #[serde(default)]
    pub contains: Option<String>,
    #[serde(default)]
    pub min_len: Option<usize>,
    #[serde(default)]
    pub referenced_only: Option<bool>,
    #[serde(default)]
    pub offset: Option<usize>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct FindStringsOut {
    pub total: usize,
    pub matched: usize,
    pub offset: usize,
    pub strings: Vec<StringRowOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    pub data_index_truncated: bool,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct StringRowOut {
    pub value: String,
    pub encoding: String,
    pub offset: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    pub references: Vec<ReferenceOut>,
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct CaptureParams {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub target_id: Option<String>,
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct SqliteParams {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub target_id: Option<String>,
    #[serde(default)]
    pub wal_path: Option<String>,
    #[serde(default)]
    pub table: Option<String>,
    #[serde(default)]
    pub rows: Option<usize>,
    #[serde(default)]
    pub recover: Option<bool>,
}

#[rmcp::tool_router(router = target_tool_router, vis = "pub(super)")]
impl DisrobeMcp {
    #[rmcp::tool(
        name = "open_target",
        description = "Open a file inside a workspace root by path (relative paths resolve against the server's working directory) and return its target_id, size, sha256 and blake3, plus format, architecture and function counts for native PE / ELF / Mach-O images. Reads only; never executes the file. Pass the target_id to the other target tools."
    )]
    fn open_target(
        &self,
        Parameters(p): Parameters<OpenTargetParams>,
    ) -> Result<Json<OpenTargetOut>, ErrorData> {
        let target: Arc<Target> = self.workspace()?.open(&p.path)?;
        let (native, native_refusal): (Option<NativeIdentityOut>, Option<String>) =
            match target.native() {
                Ok(index) => (Some(native_identity(index)), None),
                Err(error) => (None, Some(error.message.to_string())),
            };
        Ok(Json(OpenTargetOut {
            target_id: hex32(&target.id),
            path: target.path.display().to_string(),
            size: target.bytes.len(),
            sha256: hex_lower(&sha2::Sha256::digest(&target.bytes)),
            blake3: hex32(&target.id),
            native,
            native_refusal,
        }))
    }

    #[rmcp::tool(
        name = "target_layout",
        description = "Sections (virtual address, size, file offset, file size, executable flag), imports and exports of an opened native target."
    )]
    fn target_layout(
        &self,
        Parameters(p): Parameters<TargetParams>,
    ) -> Result<Json<LayoutOut>, ErrorData> {
        let target: Arc<Target> = self.workspace()?.get(&p.target_id)?;
        let index: &NativeIndex = target.native()?;
        let sections: Vec<SectionOut> = target
            .image()
            .map(|image: NativeImage<'_>| {
                image
                    .sections()
                    .iter()
                    .take(MAX_LAYOUT_ROWS)
                    .map(section_out)
                    .collect()
            })
            .unwrap_or_default();
        Ok(Json(LayoutOut {
            target_id: p.target_id,
            format: format_label(index.file.format),
            arch: arch_label(index.file.arch),
            sections,
            imports: index
                .file
                .imports
                .iter()
                .take(MAX_LAYOUT_ROWS)
                .map(|import| ImportOut {
                    library: import.library.clone(),
                    name: import.name.clone(),
                })
                .collect(),
            imports_total: index.file.imports.len(),
            exports: index
                .file
                .exports
                .iter()
                .take(MAX_LAYOUT_ROWS)
                .map(|export| ExportOut {
                    name: export.name.clone(),
                    address: hex_address(export.address),
                })
                .collect(),
            exports_total: index.file.exports.len(),
        }))
    }

    #[rmcp::tool(
        name = "list_functions",
        description = "Page through the functions discovered in an opened native target (recursive descent plus symbols): name, address, end, instruction count, export flag and the content-bound function_id the xrefs, function_summary and neighborhood tools accept. Filter with name_contains (case-insensitive)."
    )]
    fn list_functions(
        &self,
        Parameters(p): Parameters<ListFunctionsParams>,
    ) -> Result<Json<ListFunctionsOut>, ErrorData> {
        let target: Arc<Target> = self.workspace()?.get(&p.target_id)?;
        let index: &NativeIndex = target.native()?;
        let limit: usize = page_limit(p.limit)?;
        let offset: usize = p.offset.unwrap_or(0);
        let needle: Option<String> = p
            .name_contains
            .as_deref()
            .map(str::to_ascii_lowercase)
            .filter(|needle: &String| !needle.is_empty());
        let functions: &[Function] = index.module.functions();
        let matched: Vec<&Function> = functions
            .iter()
            .filter(|function: &&Function| {
                needle.as_ref().is_none_or(|needle: &String| {
                    function.name.to_ascii_lowercase().contains(needle.as_str())
                })
            })
            .collect();
        let page: Vec<FunctionRowOut> = matched
            .iter()
            .skip(offset)
            .take(limit)
            .map(|function: &&Function| function_row(&index.module, function))
            .collect();
        let next: usize = offset.saturating_add(page.len());
        Ok(Json(ListFunctionsOut {
            target_id: p.target_id,
            total: functions.len(),
            matched: matched.len(),
            offset,
            functions: page,
            next_offset: (next < matched.len()).then_some(next),
        }))
    }

    #[rmcp::tool(
        name = "disassemble_function",
        description = "Disassemble one function of an opened native target. `function` is a name, a 0x-prefixed address inside the function, or a function_id. Branch and call targets are resolved to function names where one is known."
    )]
    fn disassemble_function(
        &self,
        Parameters(p): Parameters<FunctionParams>,
    ) -> Result<Json<DisassemblyOut>, ErrorData> {
        let target: Arc<Target> = self.workspace()?.get(&p.target_id)?;
        let index: &NativeIndex = target.native()?;
        let function: &Function = select_function(&index.module, &p.function)?;
        let limit: usize = match p.max_instructions {
            None => DEFAULT_DISASM_INSTRUCTIONS,
            Some(value) if (1..=MAX_DISASM_INSTRUCTIONS).contains(&value) => value,
            Some(_) => {
                return Err(ErrorData::invalid_params(
                    format!(
                        "DR-MCP-0712: max_instructions must be in 1..={MAX_DISASM_INSTRUCTIONS}"
                    ),
                    None,
                ));
            }
        };
        let instructions: Vec<InstructionOut> = function
            .instructions
            .iter()
            .take(limit)
            .map(|insn: &InsnView| instruction_out(&index.module, insn))
            .collect();
        Ok(Json(DisassemblyOut {
            function: function_row(&index.module, function),
            total: function.instructions.len(),
            truncated: function.instructions.len() > limit,
            instructions,
        }))
    }

    #[rmcp::tool(
        name = "decompile_function",
        description = "Decompile one function of an opened x86-64 PE / ELF / Mach-O target to C with disrobe's in-tree decompiler; direct callees are lifted alongside so their arities and names resolve. A function the decompiler cannot prove sound is refused with the reason instead of approximated. Other architectures: use run_command with `native decompile`."
    )]
    fn decompile_function(
        &self,
        Parameters(p): Parameters<FunctionParams>,
    ) -> Result<Json<DecompileFunctionOut>, ErrorData> {
        let target: Arc<Target> = self.workspace()?.get(&p.target_id)?;
        let index: &NativeIndex = target.native()?;
        if !matches!(index.file.arch, Arch::X86_64) {
            return Err(ErrorData::invalid_params(
                format!(
                    "DR-MCP-0720: decompile_function lifts x86-64 only; this target is {}; run_command `native decompile` covers aarch64, arm32 and mips32",
                    arch_label(index.file.arch)
                ),
                None,
            ));
        }
        let function: &Function = select_function(&index.module, &p.function)?;
        let abi: PseudoAbi = if matches!(
            index.file.format,
            NativeFormat::Pe32 | NativeFormat::Pe64 | NativeFormat::Coff
        ) {
            PseudoAbi::MsX64
        } else {
            PseudoAbi::SysV
        };
        let image: NativeImage<'_> = target.image().ok_or_else(|| {
            ErrorData::invalid_params(
                "DR-MCP-0721: the image's section map could not be parsed",
                None,
            )
        })?;
        let mut members: Vec<&Function> = vec![function];
        let mut seen: BTreeSet<u64> = BTreeSet::from([function.address]);
        for insn in &function.instructions {
            if members.len() > MAX_DECOMPILE_CALLEES {
                break;
            }
            if insn.class != InsnClass::Call {
                continue;
            }
            let Some(callee) = insn
                .branch_target
                .and_then(|address: u64| index.module.function_containing(address))
            else {
                continue;
            };
            if callee.address == insn.branch_target.unwrap_or(u64::MAX)
                && seen.insert(callee.address)
            {
                members.push(callee);
            }
        }
        let program_functions: Vec<ProgramFunction> = members
            .iter()
            .filter_map(|member: &&Function| {
                function_code(&image, member).map(|code: Vec<u8>| ProgramFunction {
                    name: c_identifier(&member.name, member.address),
                    address: member.address,
                    code,
                })
            })
            .collect();
        if !program_functions
            .iter()
            .any(|member: &ProgramFunction| member.address == function.address)
        {
            return Ok(Json(DecompileFunctionOut {
                function: function_row(&index.module, function),
                language: "c".to_owned(),
                source: None,
                refusal: Some("no file-backed code bytes cover the function's range".to_owned()),
                resolved_calls: Vec::new(),
            }));
        }
        let program: RecoveredProgram = recover_program(&target.bytes, &program_functions, abi);
        let recovered: Option<&RecoveredFunction> = program
            .recovered
            .iter()
            .find(|candidate: &&RecoveredFunction| candidate.address == function.address);
        let refusal: Option<String> = match recovered {
            Some(_) => None,
            None => Some(
                program
                    .unrecovered
                    .iter()
                    .find(|candidate| candidate.address == function.address)
                    .map_or_else(
                        || "the decompiler returned no result for this function".to_owned(),
                        |candidate| candidate.reason.clone(),
                    ),
            ),
        };
        Ok(Json(DecompileFunctionOut {
            function: function_row(&index.module, function),
            language: "c".to_owned(),
            source: recovered.map(|rec: &RecoveredFunction| rec.source.clone()),
            refusal,
            resolved_calls: recovered
                .map(|rec: &RecoveredFunction| {
                    rec.resolved_calls
                        .iter()
                        .copied()
                        .map(hex_address)
                        .collect()
                })
                .unwrap_or_default(),
        }))
    }

    #[rmcp::tool(
        name = "read_bytes",
        description = "Read up to 65536 bytes of an opened target at a file `offset` or a 0x-prefixed virtual `address` (native images), returned as hex and printable ASCII with the containing section."
    )]
    fn read_bytes(
        &self,
        Parameters(p): Parameters<ReadBytesParams>,
    ) -> Result<Json<ReadBytesOut>, ErrorData> {
        let target: Arc<Target> = self.workspace()?.get(&p.target_id)?;
        let length: usize = match p.length {
            None => DEFAULT_READ_BYTES,
            Some(value) if (1..=MAX_READ_BYTES).contains(&value) => value,
            Some(_) => {
                return Err(ErrorData::invalid_params(
                    format!("DR-MCP-0713: length must be in 1..={MAX_READ_BYTES}"),
                    None,
                ));
            }
        };
        let location: LocationOut = locate(&target, p.address.as_deref(), p.offset)?;
        let offset: u64 = location.offset.ok_or_else(|| {
            ErrorData::invalid_params(
                format!(
                    "DR-MCP-0714: address {} has no file-backed bytes (uninitialized or runtime-only memory)",
                    location.address.as_deref().unwrap_or("?")
                ),
                None,
            )
        })?;
        let start: usize = usize::try_from(offset).unwrap_or(usize::MAX);
        let window: &[u8] = target.bytes.get(start..).unwrap_or_default();
        let bytes: &[u8] = window.get(..length.min(window.len())).unwrap_or_default();
        Ok(Json(ReadBytesOut {
            offset,
            address: location.address,
            section: location.section,
            length: bytes.len(),
            hex: hex_spaced(bytes),
            ascii: bytes
                .iter()
                .map(|byte: &u8| {
                    if byte.is_ascii_graphic() || *byte == b' ' {
                        char::from(*byte)
                    } else {
                        '.'
                    }
                })
                .collect(),
        }))
    }

    #[rmcp::tool(
        name = "search_bytes",
        description = "Search an opened target for a byte pattern such as `48 8B 05 ?? ?? ?? ??` (hex bytes, `??` wildcards, at most 256 tokens); hits carry file offset, virtual address, section and containing function."
    )]
    fn search_bytes(
        &self,
        Parameters(p): Parameters<SearchBytesParams>,
    ) -> Result<Json<SearchBytesOut>, ErrorData> {
        let target: Arc<Target> = self.workspace()?.get(&p.target_id)?;
        let pattern: Vec<Option<u8>> = parse_pattern(&p.pattern)?;
        let max_hits: usize = match p.max_hits {
            None => DEFAULT_SEARCH_HITS,
            Some(value) if (1..=MAX_SEARCH_HITS).contains(&value) => value,
            Some(_) => {
                return Err(ErrorData::invalid_params(
                    format!("DR-MCP-0716: max_hits must be in 1..={MAX_SEARCH_HITS}"),
                    None,
                ));
            }
        };
        let offsets: Vec<usize> = find_pattern(&target.bytes, &pattern, max_hits.saturating_add(1));
        let truncated: bool = offsets.len() > max_hits;
        let mut hits: Vec<LocationOut> = Vec::with_capacity(offsets.len().min(max_hits));
        for found in offsets.into_iter().take(max_hits) {
            hits.push(locate(&target, None, Some(found as u64))?);
        }
        Ok(Json(SearchBytesOut {
            pattern: pattern
                .iter()
                .map(|token: &Option<u8>| {
                    token.map_or_else(|| "??".to_owned(), |b: u8| format!("{b:02X}"))
                })
                .collect::<Vec<String>>()
                .join(" "),
            hits,
            truncated,
        }))
    }

    #[rmcp::tool(
        name = "locate",
        description = "Translate between a file `offset` and a 0x-prefixed virtual `address` in an opened native target and name the containing section and function."
    )]
    fn locate(
        &self,
        Parameters(p): Parameters<LocateParams>,
    ) -> Result<Json<LocationOut>, ErrorData> {
        let target: Arc<Target> = self.workspace()?.get(&p.target_id)?;
        locate(&target, p.address.as_deref(), p.offset).map(Json)
    }

    #[rmcp::tool(
        name = "inspect_capture",
        description = "Decode a pcap, pcapng, HAR or Fiddler SAZ capture inside a workspace root (`path`) or an opened target (`target_id`): protocol counts, endpoints, flows with reassembled TCP streams, DNS questions and answers, TLS client hellos (SNI, ALPN, supported versions, JA3 and its MD5) and HTTP exchanges (method, host, target, status, content type, body sizes). Nothing is replayed or sent."
    )]
    fn inspect_capture(
        &self,
        Parameters(p): Parameters<CaptureParams>,
    ) -> Result<Json<serde_json::Map<String, serde_json::Value>>, ErrorData> {
        let workspace: &Workspace = self.workspace()?;
        let bytes: Vec<u8> = match (p.path.as_deref(), p.target_id.as_deref()) {
            (Some(path), None) => workspace.read_path(path, MAX_TARGET_BYTES)?.1,
            (None, Some(target_id)) => workspace.get(target_id)?.bytes.clone(),
            _ => {
                return Err(ErrorData::invalid_params(
                    "DR-MCP-0709: pass exactly one of `path` and `target_id`",
                    None,
                ));
            }
        };
        let report: CaptureReport = inspect_capture(&bytes, &CaptureOptions::default()).map_err(
            |error: CaptureError| ErrorData::invalid_params(format!("DR-MCP-0725: {error}"), None),
        )?;
        match serde_json::to_value(&report) {
            Ok(serde_json::Value::Object(object)) => Ok(Json(object)),
            Ok(_) => Err(ErrorData::internal_error(
                "DR-MCP-0725: capture report serialized to a non-object value",
                None,
            )),
            Err(error) => Err(ErrorData::internal_error(
                format!("DR-MCP-0725: capture report serialize: {error}"),
                None,
            )),
        }
    }

    #[rmcp::tool(
        name = "inspect_sqlite",
        description = "Read a SQLite database inside a workspace root (`path`) or an opened target (`target_id`) without SQLite: header, schema (tables with columns, indexes, views, triggers), row counts and the first `rows` rows per table (default 20, at most 1000; `table` narrows to one table), a write-ahead log (`wal_path`, or `<path>-wal` when it exists) applied up to its last valid commit, the freelist, and with `recover` the deleted records carved from freelist pages, freeblocks and unallocated space."
    )]
    fn inspect_sqlite(
        &self,
        Parameters(p): Parameters<SqliteParams>,
    ) -> Result<Json<serde_json::Map<String, serde_json::Value>>, ErrorData> {
        let workspace: &Workspace = self.workspace()?;
        let (database, sibling): (Vec<u8>, Option<String>) =
            match (p.path.as_deref(), p.target_id.as_deref()) {
                (Some(path), None) => {
                    let (_, bytes): (PathBuf, Vec<u8>) =
                        workspace.read_path(path, MAX_TARGET_BYTES)?;
                    (bytes, Some(format!("{path}-wal")))
                }
                (None, Some(target_id)) => (workspace.get(target_id)?.bytes.clone(), None),
                _ => {
                    return Err(ErrorData::invalid_params(
                        "DR-MCP-0709: pass exactly one of `path` and `target_id`",
                        None,
                    ));
                }
            };
        let wal: Option<Vec<u8>> = match (p.wal_path.as_deref(), sibling) {
            (Some(wal_path), _) => Some(workspace.read_path(wal_path, MAX_TARGET_BYTES)?.1),
            (None, Some(candidate)) => workspace
                .read_path(&candidate, MAX_TARGET_BYTES)
                .ok()
                .map(|(_, bytes): (PathBuf, Vec<u8>)| bytes),
            (None, None) => None,
        };
        let rows: usize = match p.rows {
            None => DEFAULT_SQLITE_ROWS,
            Some(value) if value <= MAX_SQLITE_ROWS => value,
            Some(_) => {
                return Err(ErrorData::invalid_params(
                    format!("DR-MCP-0724: rows must be at most {MAX_SQLITE_ROWS}"),
                    None,
                ));
            }
        };
        let options: InspectOptions = InspectOptions {
            limits: SqliteLimits {
                rows_per_table: rows,
                ..SqliteLimits::default()
            },
            only_table: p.table,
            recover_deleted: p.recover.unwrap_or(false),
        };
        let report: SqliteReport =
            inspect_sqlite(&database, wal.as_deref(), &options).map_err(|error: SqliteError| {
                ErrorData::invalid_params(format!("DR-MCP-0724: {error}"), None)
            })?;
        match serde_json::to_value(&report) {
            Ok(serde_json::Value::Object(object)) => Ok(Json(object)),
            Ok(_) => Err(ErrorData::internal_error(
                "DR-MCP-0724: SQLite report serialized to a non-object value",
                None,
            )),
            Err(error) => Err(ErrorData::internal_error(
                format!("DR-MCP-0724: SQLite report serialize: {error}"),
                None,
            )),
        }
    }

    #[rmcp::tool(
        name = "identify_target",
        description = "Identify what built, packed, protected, installed or signed an opened target: format, each compiler, linker, packer, protector, installer, library and signature hit with its evidence and confidence, Authenticode details for PE images, and per hit the disrobe commands that handle it (run them with run_command)."
    )]
    fn identify_target(
        &self,
        Parameters(p): Parameters<TargetParams>,
    ) -> Result<Json<serde_json::Map<String, serde_json::Value>>, ErrorData> {
        let target: Arc<Target> = self.workspace()?.get(&p.target_id)?;
        let now: u64 = disrobe_core::time::now_secs().map_err(|error| {
            ErrorData::internal_error(format!("DR-MCP-0723: cannot read the clock: {error}"), None)
        })?;
        let report: IdentityReport = detect_identity(&target.bytes, now);
        let mut value: serde_json::Value =
            serde_json::to_value(&report).map_err(|error: serde_json::Error| {
                ErrorData::internal_error(format!("DR-MCP-0723: identify serialize: {error}"), None)
            })?;
        if let Some(hits) = value
            .get_mut("hits")
            .and_then(serde_json::Value::as_array_mut)
        {
            for (row, hit) in hits.iter_mut().zip(&report.hits) {
                if let Some(object) = row.as_object_mut() {
                    object.insert(
                        "commands".to_owned(),
                        serde_json::Value::from(hit.support.invocations().to_vec()),
                    );
                }
            }
        }
        match value {
            serde_json::Value::Object(object) => Ok(Json(object)),
            _ => Err(ErrorData::internal_error(
                "DR-MCP-0723: identify report serialized to a non-object value",
                None,
            )),
        }
    }

    #[rmcp::tool(
        name = "call_path",
        description = "Shortest chain of direct calls from one function to another in an opened native target (breadth-first, at most max_depth calls, default 12, maximum 32). `from` and `to` take a name, a 0x-prefixed address or a function_id. Indirect calls are not followed."
    )]
    fn call_path(
        &self,
        Parameters(p): Parameters<CallPathParams>,
    ) -> Result<Json<CallPathOut>, ErrorData> {
        let target: Arc<Target> = self.workspace()?.get(&p.target_id)?;
        let index: &NativeIndex = target.native()?;
        let max_depth: u8 = match p.max_depth {
            None => DEFAULT_CALL_PATH_DEPTH,
            Some(value) if (1..=MAX_CALL_PATH_DEPTH).contains(&value) => value,
            Some(_) => {
                return Err(ErrorData::invalid_params(
                    format!("DR-MCP-0717: max_depth must be in 1..={MAX_CALL_PATH_DEPTH}"),
                    None,
                ));
            }
        };
        let from: &Function = select_function(&index.module, &p.from)?;
        let to: &Function = select_function(&index.module, &p.to)?;
        let (path, explored): (Option<Vec<u64>>, usize) =
            shortest_call_path(&index.module, from.address, to.address, max_depth);
        let rows: Vec<FunctionRowOut> = path
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter_map(|address: &u64| {
                index
                    .module
                    .function_containing(*address)
                    .map(|function: &Function| function_row(&index.module, function))
            })
            .collect();
        Ok(Json(CallPathOut {
            found: path.is_some(),
            path: rows,
            explored,
            max_depth,
        }))
    }
}

#[rmcp::tool_router(router = reference_tool_router, vis = "pub(super)")]
impl DisrobeMcp {
    #[rmcp::tool(
        name = "references_to",
        description = "Every instruction in an opened native target that calls, jumps to or reads or writes a 0x-prefixed address or a named function (direct branches, switch targets, absolute and RIP-relative memory operands), with the containing function."
    )]
    fn references_to(
        &self,
        Parameters(p): Parameters<ReferencesParams>,
    ) -> Result<Json<ReferencesOut>, ErrorData> {
        let target: Arc<Target> = self.workspace()?.get(&p.target_id)?;
        let index: &NativeIndex = target.native()?;
        let address: u64 = match parse_address(&p.address) {
            Some(address) => address,
            None => select_function(&index.module, &p.address)?.address,
        };
        let all: Vec<ReferenceOut> = references(index, address);
        Ok(Json(ReferencesOut {
            address: hex_address(address),
            symbol: index.module.symbol_name(address).map(str::to_owned),
            total: all.len(),
            truncated: all.len() > MAX_REFERENCES,
            references: all.into_iter().take(MAX_REFERENCES).collect(),
            data_index_truncated: index.data_refs_truncated || index.pointer_slots_truncated,
        }))
    }

    #[rmcp::tool(
        name = "find_strings",
        description = "Page through the printable ASCII and UTF-16 strings of an opened target with file offset, virtual address, section and the instructions that reference each one. Filter with contains (case-insensitive) and referenced_only."
    )]
    fn find_strings(
        &self,
        Parameters(p): Parameters<FindStringsParams>,
    ) -> Result<Json<FindStringsOut>, ErrorData> {
        let target: Arc<Target> = self.workspace()?.get(&p.target_id)?;
        let limit: usize = match p.limit {
            None => DEFAULT_STRING_PAGE,
            Some(value) if (1..=MAX_STRING_PAGE).contains(&value) => value,
            Some(_) => {
                return Err(ErrorData::invalid_params(
                    format!("DR-MCP-0722: limit must be in 1..={MAX_STRING_PAGE}"),
                    None,
                ));
            }
        };
        let min_len: usize = p
            .min_len
            .unwrap_or_else(|| StringsOptions::default().min_len);
        if !(1..=MAX_NEEDLE_BYTES).contains(&min_len) {
            return Err(ErrorData::invalid_params(
                format!("DR-MCP-0722: min_len must be in 1..={MAX_NEEDLE_BYTES}"),
                None,
            ));
        }
        let needle: Option<String> = p
            .contains
            .as_deref()
            .filter(|needle: &&str| !needle.is_empty())
            .map(str::to_lowercase);
        if needle
            .as_ref()
            .is_some_and(|needle: &String| needle.len() > MAX_NEEDLE_BYTES)
        {
            return Err(ErrorData::invalid_params(
                format!("DR-MCP-0722: contains must be at most {MAX_NEEDLE_BYTES} bytes"),
                None,
            ));
        }
        let index: Option<&NativeIndex> = target.native().ok();
        let image: Option<NativeImage<'_>> = target.image();
        let found: Vec<ExtractedString> = strings_report(
            &target.bytes,
            None,
            StringsOptions {
                min_len,
                decode: false,
            },
        )
        .strings;
        let total: usize = found.len();
        let referenced_only: bool = p.referenced_only.unwrap_or(false);
        let offset: usize = p.offset.unwrap_or(0);
        let mut matched: usize = 0;
        let mut rows: Vec<StringRowOut> = Vec::new();
        for string in found {
            if needle.as_ref().is_some_and(|needle: &String| {
                !string.value.to_lowercase().contains(needle.as_str())
            }) {
                continue;
            }
            let mapped: Option<(&NativeImageSection, u64)> =
                image.as_ref().and_then(|image: &NativeImage<'_>| {
                    image.address_of_file_offset(string.offset as u64)
                });
            let refs: Vec<ReferenceOut> = match (index, mapped) {
                (Some(index), Some((_, address))) => data_references_within(
                    index,
                    address,
                    address.saturating_add(string_byte_len(&string)),
                ),
                _ => Vec::new(),
            };
            if referenced_only && refs.is_empty() {
                continue;
            }
            matched += 1;
            if matched <= offset || rows.len() >= limit {
                continue;
            }
            rows.push(StringRowOut {
                encoding: string.tagging.label(),
                offset: string.offset,
                address: mapped
                    .map(|(_, address): (&NativeImageSection, u64)| hex_address(address)),
                section: mapped
                    .map(|(section, _): (&NativeImageSection, u64)| section.name.clone()),
                references: refs.into_iter().take(MAX_REFS_PER_STRING).collect(),
                value: string.value,
            });
        }
        let next: usize = offset.saturating_add(rows.len());
        Ok(Json(FindStringsOut {
            total,
            matched,
            offset,
            strings: rows,
            next_offset: (next < matched).then_some(next),
            data_index_truncated: index.is_some_and(|index: &NativeIndex| {
                index.data_refs_truncated || index.pointer_slots_truncated
            }),
        }))
    }
}

#[derive(Debug)]
pub(super) enum ModuleSource {
    Owned(Module),
    Target(Arc<Target>),
}

impl ModuleSource {
    pub(super) fn module(&self) -> Result<&Module, ErrorData> {
        match self {
            Self::Owned(module) => Ok(module),
            Self::Target(target) => target.native().map(|index: &NativeIndex| &index.module),
        }
    }
}

impl DisrobeMcp {
    pub(super) fn input_bytes(
        &self,
        bytes_b64: &str,
        path: Option<&str>,
        target_id: Option<&str>,
    ) -> Result<Vec<u8>, ErrorData> {
        match one_input(bytes_b64, path, target_id)? {
            Input::Inline => decode_inline_bytes(bytes_b64),
            Input::Path(path) => self
                .workspace()?
                .read_path(path, MAX_INLINE_TOOL_BYTES)
                .map(|(_, bytes): (PathBuf, Vec<u8>)| bytes),
            Input::Target(target_id) => {
                let target: Arc<Target> = self.workspace()?.get(target_id)?;
                if target.bytes.len() as u64 > MAX_INLINE_TOOL_BYTES {
                    return Err(ErrorData::invalid_params(
                        format!(
                            "DR-MCP-0709: target {target_id} holds {} bytes; this tool reads at most {MAX_INLINE_TOOL_BYTES}",
                            target.bytes.len()
                        ),
                        None,
                    ));
                }
                Ok(target.bytes.clone())
            }
        }
    }

    pub(super) fn module_source(
        &self,
        bytes_b64: &str,
        path: Option<&str>,
        target_id: Option<&str>,
    ) -> Result<ModuleSource, ErrorData> {
        match one_input(bytes_b64, path, target_id)? {
            Input::Inline => decode_module(bytes_b64).map(ModuleSource::Owned),
            Input::Path(path) => {
                let (_, bytes): (PathBuf, Vec<u8>) =
                    self.workspace()?.read_path(path, MAX_TARGET_BYTES)?;
                if let Ok(envelope) = disrobe_ir::Envelope::decode(&bytes) {
                    return module_from_envelope(&envelope)
                        .map(ModuleSource::Owned)
                        .map_err(|error| {
                            ErrorData::invalid_params(
                                format!("DR-MCP-0650: {path} is a .dr envelope but not navigable: {error}"),
                                None,
                            )
                        });
                }
                let payload: DisasmPayload = build_disasm_payload(&bytes).map_err(|error| {
                    ErrorData::invalid_params(
                        format!("DR-MCP-0710: {path} is neither a navigable .dr envelope nor a disassemblable native image: {error}"),
                        None,
                    )
                })?;
                Ok(ModuleSource::Owned(Module::from_disasm(&payload)))
            }
            Input::Target(target_id) => {
                let target: Arc<Target> = self.workspace()?.get(target_id)?;
                target.native()?;
                Ok(ModuleSource::Target(target))
            }
        }
    }

    pub(super) fn known_target(&self, target_id: &str) -> Result<(), ErrorData> {
        self.workspace()?.get(target_id).map(|_| ())
    }

    fn workspace(&self) -> Result<&Workspace, ErrorData> {
        self.workspace.as_deref().ok_or_else(|| {
            ErrorData::invalid_params(
                "DR-MCP-0708: this server was started without a workspace root, so path and target tools are unavailable",
                None,
            )
        })
    }
}

enum Input<'a> {
    Inline,
    Path(&'a str),
    Target(&'a str),
}

fn one_input<'a>(
    bytes_b64: &str,
    path: Option<&'a str>,
    target_id: Option<&'a str>,
) -> Result<Input<'a>, ErrorData> {
    match (bytes_b64.is_empty(), path, target_id) {
        (_, None, None) => Ok(Input::Inline),
        (true, Some(path), None) => Ok(Input::Path(path)),
        (true, None, Some(target_id)) => Ok(Input::Target(target_id)),
        _ => Err(ErrorData::invalid_params(
            "DR-MCP-0709: pass exactly one of `bytes_b64`, `path` and `target_id`",
            None,
        )),
    }
}

fn native_identity(index: &NativeIndex) -> NativeIdentityOut {
    NativeIdentityOut {
        format: format_label(index.file.format),
        arch: arch_label(index.file.arch),
        bits: index.file.bits,
        big_endian: matches!(index.file.endian, disrobe_binfmt::Endian::Big),
        sections: index.file.sections.len(),
        symbols: index.file.symbols.len(),
        imports: index.file.imports.len(),
        exports: index.file.exports.len(),
        functions: index.module.functions().len(),
        debug_info_present: index.file.debug_info_present,
    }
}

fn format_label(format: NativeFormat) -> String {
    format.label().to_owned()
}

fn arch_label(arch: Arch) -> String {
    arch.label().to_owned()
}

fn section_out(section: &NativeImageSection) -> SectionOut {
    SectionOut {
        name: section.name.clone(),
        address: hex_address(section.address),
        size: section.size,
        file_offset: section.file_offset(),
        file_size: section.file_size(),
        executable: section.executable,
    }
}

fn page_limit(value: Option<usize>) -> Result<usize, ErrorData> {
    match value {
        None => Ok(DEFAULT_FUNCTION_PAGE),
        Some(limit) if (1..=MAX_FUNCTION_PAGE).contains(&limit) => Ok(limit),
        Some(_) => Err(ErrorData::invalid_params(
            format!("DR-MCP-0711: limit must be in 1..={MAX_FUNCTION_PAGE}"),
            None,
        )),
    }
}

fn function_row(module: &Module, function: &Function) -> FunctionRowOut {
    FunctionRowOut {
        name: function.name.clone(),
        address: hex_address(function.address),
        end: hex_address(function.end),
        instructions: function.instructions.len(),
        export: function.is_export,
        function_id: module.function_id(function).to_string(),
    }
}

fn instruction_out(module: &Module, insn: &InsnView) -> InstructionOut {
    let text: String = if insn.operands.is_empty() {
        insn.mnemonic.clone()
    } else {
        format!("{} {}", insn.mnemonic, insn.operands.join(", "))
    };
    InstructionOut {
        address: hex_address(insn.offset),
        text,
        target: insn.branch_target.map(hex_address),
        target_name: insn
            .branch_target
            .and_then(|address: u64| module.symbol_name(address))
            .map(str::to_owned),
    }
}

fn select_function<'m>(module: &'m Module, selector: &str) -> Result<&'m Function, ErrorData> {
    let selector: &str = selector.trim();
    if selector.is_empty() || selector.len() > MAX_SELECTOR_BYTES {
        return Err(ErrorData::invalid_params(
            format!(
                "DR-MCP-0715: `function` must be 1..={MAX_SELECTOR_BYTES} bytes: a name, a 0x-prefixed address or a function_id"
            ),
            None,
        ));
    }
    if let Ok(id) = FunctionId::from_str(selector) {
        return module.function_by_id(&id).map_err(|error| {
            ErrorData::invalid_params(format!("DR-MCP-0715: {selector}: {error}"), None)
        });
    }
    if let Some(digits) = selector
        .strip_prefix("0x")
        .or_else(|| selector.strip_prefix("0X"))
    {
        let address: u64 = u64::from_str_radix(digits, 16).map_err(|error| {
            ErrorData::invalid_params(
                format!("DR-MCP-0715: {selector} is not a hex address: {error}"),
                None,
            )
        })?;
        return module.function_containing(address).ok_or_else(|| {
            ErrorData::invalid_params(
                format!("DR-MCP-0715: no discovered function contains {selector}"),
                None,
            )
        });
    }
    module.function_by_name(selector).ok_or_else(|| {
        ErrorData::invalid_params(
            format!("DR-MCP-0715: no function is named {selector}; list_functions with name_contains finds candidates"),
            None,
        )
    })
}

fn function_code(image: &NativeImage<'_>, function: &Function) -> Option<Vec<u8>> {
    let len: usize = usize::try_from(function.end.checked_sub(function.address)?).ok()?;
    if len == 0 {
        return None;
    }
    let bytes: &[u8] = image.bytes_at(function.address)?;
    Some(bytes.get(..len.min(bytes.len()))?.to_vec())
}

fn c_identifier(name: &str, address: u64) -> String {
    let cleaned: String = name
        .chars()
        .map(|c: char| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    match cleaned.chars().next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => cleaned,
        _ => format!("sub_{address:x}"),
    }
}

fn locate(
    target: &Target,
    address: Option<&str>,
    offset: Option<u64>,
) -> Result<LocationOut, ErrorData> {
    let image: Option<NativeImage<'_>> = target.image();
    let module: Option<&Module> = target
        .native
        .get()
        .and_then(|built: &Result<NativeIndex, String>| built.as_ref().ok())
        .map(|index: &NativeIndex| &index.module);
    let (resolved_offset, resolved_address, section): (Option<u64>, Option<u64>, Option<String>) =
        match (address, offset) {
            (Some(raw), None) => {
                let digits: &str = raw
                    .trim()
                    .strip_prefix("0x")
                    .or_else(|| raw.trim().strip_prefix("0X"))
                    .ok_or_else(|| {
                        ErrorData::invalid_params(
                            "DR-MCP-0718: `address` must be 0x-prefixed hex",
                            None,
                        )
                    })?;
                let va: u64 = u64::from_str_radix(digits, 16).map_err(|error| {
                    ErrorData::invalid_params(format!("DR-MCP-0718: {raw}: {error}"), None)
                })?;
                let image: &NativeImage<'_> = image.as_ref().ok_or_else(|| {
                    ErrorData::invalid_params(
                        "DR-MCP-0718: virtual addresses need a native image; pass a file `offset` instead",
                        None,
                    )
                })?;
                let section: Option<String> = image
                    .section_at(va)
                    .map(|s: &NativeImageSection| s.name.clone());
                (image.file_offset(va), Some(va), section)
            }
            (None, Some(file_offset)) => {
                if usize::try_from(file_offset).map_or(true, |o: usize| o >= target.bytes.len()) {
                    return Err(ErrorData::invalid_params(
                        format!(
                            "DR-MCP-0719: offset {file_offset} is past the end of the {}-byte target",
                            target.bytes.len()
                        ),
                        None,
                    ));
                }
                let mapped: Option<(&NativeImageSection, u64)> = image
                    .as_ref()
                    .and_then(|image: &NativeImage<'_>| image.address_of_file_offset(file_offset));
                (
                    Some(file_offset),
                    mapped.map(|(_, va): (&NativeImageSection, u64)| va),
                    mapped.map(|(s, _): (&NativeImageSection, u64)| s.name.clone()),
                )
            }
            _ => {
                return Err(ErrorData::invalid_params(
                    "DR-MCP-0718: pass exactly one of `address` and `offset`",
                    None,
                ));
            }
        };
    let function: Option<&Function> = resolved_address
        .zip(module)
        .and_then(|(va, module): (u64, &Module)| module.function_containing(va));
    Ok(LocationOut {
        offset: resolved_offset,
        address: resolved_address.map(hex_address),
        section,
        function: function.map(|f: &Function| f.name.clone()),
        function_address: function.map(|f: &Function| hex_address(f.address)),
    })
}

fn parse_pattern(raw: &str) -> Result<Vec<Option<u8>>, ErrorData> {
    let invalid =
        |detail: String| ErrorData::invalid_params(format!("DR-MCP-0716: pattern {detail}"), None);
    let mut tokens: Vec<Option<u8>> = Vec::new();
    for word in raw.split_whitespace() {
        if word == "?" || word == "??" {
            tokens.push(None);
            continue;
        }
        if word.len() % 2 != 0 {
            return Err(invalid(format!("token `{word}` is not whole hex bytes")));
        }
        for pair in word.as_bytes().chunks_exact(2) {
            if pair == b"??" {
                tokens.push(None);
                continue;
            }
            let text: &str = std::str::from_utf8(pair)
                .map_err(|_| invalid(format!("token `{word}` is not hex")))?;
            let byte: u8 = u8::from_str_radix(text, 16)
                .map_err(|_| invalid(format!("token `{word}` is not hex")))?;
            tokens.push(Some(byte));
        }
        if tokens.len() > MAX_PATTERN_TOKENS {
            return Err(invalid(format!("exceeds {MAX_PATTERN_TOKENS} bytes")));
        }
    }
    if tokens.len() > MAX_PATTERN_TOKENS {
        return Err(invalid(format!("exceeds {MAX_PATTERN_TOKENS} bytes")));
    }
    if !tokens.iter().any(Option::is_some) {
        return Err(invalid("needs at least one concrete byte".to_owned()));
    }
    while tokens.last() == Some(&None) {
        tokens.pop();
    }
    while tokens.first() == Some(&None) {
        tokens.remove(0);
    }
    Ok(tokens)
}

fn find_pattern(haystack: &[u8], pattern: &[Option<u8>], cap: usize) -> Vec<usize> {
    let mut hits: Vec<usize> = Vec::new();
    let Some(Some(first)) = pattern.first().copied() else {
        return hits;
    };
    if pattern.len() > haystack.len() {
        return hits;
    }
    let last_start: usize = haystack.len() - pattern.len();
    let mut start: usize = 0;
    while start <= last_start && hits.len() < cap {
        let Some(relative) = haystack
            .get(start..=last_start)
            .and_then(|window: &[u8]| window.iter().position(|byte: &u8| *byte == first))
        else {
            break;
        };
        let candidate: usize = start + relative;
        let matches: bool = haystack
            .get(candidate..candidate + pattern.len())
            .is_some_and(|window: &[u8]| {
                window
                    .iter()
                    .zip(pattern)
                    .all(|(byte, token): (&u8, &Option<u8>)| {
                        token.is_none_or(|want: u8| want == *byte)
                    })
            });
        if matches {
            hits.push(candidate);
        }
        start = candidate + 1;
    }
    hits
}

fn shortest_call_path(
    module: &Module,
    from: u64,
    to: u64,
    max_depth: u8,
) -> (Option<Vec<u64>>, usize) {
    let mut callees: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for function in module.functions() {
        let edges: &mut BTreeSet<u64> = callees.entry(function.address).or_default();
        for insn in &function.instructions {
            if insn.class != InsnClass::Call {
                continue;
            }
            if let Some(callee) = insn
                .branch_target
                .and_then(|address: u64| module.function_containing(address))
            {
                edges.insert(callee.address);
            }
        }
    }
    let mut parent: BTreeMap<u64, u64> = BTreeMap::new();
    let mut frontier: VecDeque<(u64, u8)> = VecDeque::from([(from, 0)]);
    let mut visited: BTreeSet<u64> = BTreeSet::from([from]);
    while let Some((current, depth)) = frontier.pop_front() {
        if current == to {
            let mut path: Vec<u64> = vec![to];
            let mut cursor: u64 = to;
            while let Some(previous) = parent.get(&cursor).copied() {
                path.push(previous);
                cursor = previous;
            }
            path.reverse();
            return (Some(path), visited.len());
        }
        if depth >= max_depth {
            continue;
        }
        for next in callees.get(&current).into_iter().flatten().copied() {
            if visited.insert(next) {
                parent.insert(next, current);
                frontier.push_back((next, depth + 1));
            }
        }
    }
    (None, visited.len())
}

fn parse_address(raw: &str) -> Option<u64> {
    let trimmed: &str = raw.trim();
    let digits: &str = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))?;
    u64::from_str_radix(digits, 16).ok()
}

fn data_references_within(index: &NativeIndex, start: u64, end: u64) -> Vec<ReferenceOut> {
    let mut found: Vec<ReferenceOut> = Vec::new();
    for (to, sources) in index.data_refs.range(start..end) {
        for from in sources {
            let mut row: ReferenceOut = reference_out(index, *from, "data");
            row.to = Some(hex_address(*to));
            found.push(row);
        }
    }
    for (to, slots) in index.pointer_slots.range(start..end) {
        for slot in slots {
            let readers: &[u64] = index.data_refs.get(slot).map_or(&[], Vec::as_slice);
            if readers.is_empty() {
                let mut row: ReferenceOut = reference_out(index, *slot, "pointer-slot");
                row.to = Some(hex_address(*to));
                found.push(row);
            }
            for from in readers {
                let mut row: ReferenceOut = reference_out(index, *from, "via-pointer");
                row.to = Some(hex_address(*to));
                row.via = Some(hex_address(*slot));
                found.push(row);
            }
        }
    }
    found
}

fn string_byte_len(string: &ExtractedString) -> u64 {
    let chars: u64 = string.value.chars().count() as u64;
    match string.tagging {
        Tagging::Plain { wide: true } => chars.saturating_mul(2),
        _ => string.value.len() as u64,
    }
}

fn reference_out(index: &NativeIndex, from: u64, kind: &str) -> ReferenceOut {
    let function: Option<&Function> = index.module.function_containing(from);
    ReferenceOut {
        from: hex_address(from),
        kind: kind.to_owned(),
        to: None,
        via: None,
        function: function.map(|f: &Function| f.name.clone()),
        function_address: function.map(|f: &Function| hex_address(f.address)),
    }
}

fn references(index: &NativeIndex, address: u64) -> Vec<ReferenceOut> {
    let mut found: BTreeMap<u64, &'static str> = BTreeMap::new();
    for function in index.module.functions() {
        for insn in &function.instructions {
            if insn.branch_target == Some(address) || insn.switch_targets.contains(&address) {
                let kind: &'static str = if insn.class == InsnClass::Call {
                    "call"
                } else {
                    "jump"
                };
                found.entry(insn.offset).or_insert(kind);
            }
        }
    }
    for from in index.data_refs.get(&address).into_iter().flatten() {
        found.entry(*from).or_insert("data");
    }
    let mut rows: Vec<ReferenceOut> = found
        .into_iter()
        .map(|(from, kind): (u64, &'static str)| reference_out(index, from, kind))
        .collect();
    for slot in index.pointer_slots.get(&address).into_iter().flatten() {
        let readers: &[u64] = index.data_refs.get(slot).map_or(&[], Vec::as_slice);
        if readers.is_empty() {
            rows.push(reference_out(index, *slot, "pointer-slot"));
        }
        for from in readers {
            let mut row: ReferenceOut = reference_out(index, *from, "via-pointer");
            row.via = Some(hex_address(*slot));
            rows.push(row);
        }
    }
    rows
}

fn hex_address(address: u64) -> String {
    format!("{address:#x}")
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut out: String, byte: &u8| {
            let _ = write!(out, "{byte:02x}");
            out
        },
    )
}

fn hex_spaced(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte: &u8| format!("{byte:02X}"))
        .collect::<Vec<String>>()
        .join(" ")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn patterns_parse_wildcards_and_reject_bad_tokens() {
        assert_eq!(
            parse_pattern("?? 48 8B?? 05 ??").unwrap(),
            vec![Some(0x48), Some(0x8B), None, Some(0x05)]
        );
        assert!(parse_pattern("?? ??").is_err());
        assert!(parse_pattern("4").is_err());
        assert!(parse_pattern("zz").is_err());
        assert!(parse_pattern(&"00 ".repeat(MAX_PATTERN_TOKENS + 1)).is_err());
    }

    #[test]
    fn pattern_search_agrees_with_a_naive_scan() {
        let haystack: Vec<u8> = (0u32..4096)
            .map(|i: u32| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
            .collect();
        let pattern: Vec<Option<u8>> = vec![Some(haystack[100]), None, Some(haystack[102])];
        let naive: Vec<usize> = (0..=haystack.len() - 3)
            .filter(|&i: &usize| haystack[i] == haystack[100] && haystack[i + 2] == haystack[102])
            .collect();
        assert!(naive.contains(&100));
        assert_eq!(find_pattern(&haystack, &pattern, usize::MAX), naive);
        assert_eq!(find_pattern(&haystack, &pattern, 1), naive[..1].to_vec());
    }

    #[test]
    fn target_ids_round_trip_and_reject_malformed_text() {
        let id: [u8; 32] = *blake3::hash(b"disrobe").as_bytes();
        assert_eq!(parse_target_id(&hex32(&id)).unwrap(), id);
        assert!(parse_target_id("00").is_err());
        assert!(parse_target_id(&"g".repeat(64)).is_err());
    }
}
