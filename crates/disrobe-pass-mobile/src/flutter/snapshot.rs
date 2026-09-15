use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::DartFunctionSymbol;
use super::arm64_traversal::{Arm64TraversalReport, traverse};
use super::cluster::{DartSnapshotFraming, attach_cluster_schema, parse_snapshot_framing};
use super::demangler::{DartNameKind, DemangledName, demangle};
use super::libapp_parser::{DartLibAppRecovery, recover_libapp};
use crate::debug::{dbg_kv, dbg_section};

const IMAGE_HEADER_SIZE: usize = 64;

const ARM64_PUSH_FP_LR_DART_SP: u32 = 0xA9BF_79FD;

const ARM64_PUSH_FP_LR_SYS_SP: u32 = 0xA9BF_7BFD;

const ARM64_MOV_FP_DART_SP: u32 = 0xAA0F_03FD;

const ARM64_MOV_FP_SYS_SP: u32 = 0x9100_03FD;

const BARE_PAYLOAD_ALIGNMENT: usize = 4;

const MAX_FUNCTION_BOUNDARIES: usize = 1 << 20;

const MIN_IDENTIFIER_LEN: usize = 2;

const MAX_DART_IDENTIFIER_BYTES: usize = 1 << 14;

const MAX_DART_IDENTIFIER_COUNT: usize = 1 << 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageHeader {
    pub image_size: u64,
    pub instructions_section_offset: u64,
}

#[must_use]
pub fn parse_image_header(blob: &[u8]) -> Option<ImageHeader> {
    if blob.len() < IMAGE_HEADER_SIZE {
        return None;
    }
    let image_size: u64 = u64::from_le_bytes(read8(blob, 0)?);
    let instructions_section_offset: u64 = u64::from_le_bytes(read8(blob, 8)?);
    Some(ImageHeader {
        image_size,
        instructions_section_offset,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartFunctionBoundary {
    pub offset: usize,
    pub inferred_arg_registers: u8,
    pub has_frame: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DartStaticRecovery {
    pub function_boundary_count: usize,
    pub function_boundaries: Vec<DartFunctionBoundary>,
    pub class_names: Vec<String>,
    pub method_names: Vec<DemangledName>,
    pub library_uris: Vec<String>,
    pub recovered_name_count: usize,
}

#[must_use]
pub fn recover_dart_static(isolate_data: &[u8], isolate_instructions: &[u8]) -> DartStaticRecovery {
    let function_boundaries: Vec<DartFunctionBoundary> =
        scan_function_boundaries(isolate_instructions);
    let identifiers: Vec<String> = extract_dart_identifiers(isolate_data);

    let mut class_names: Vec<String> = Vec::new();
    let mut method_names: Vec<DemangledName> = Vec::new();
    let mut library_uris: Vec<String> = Vec::new();

    for ident in &identifiers {
        if is_library_uri(ident) {
            library_uris.push(ident.clone());
        } else if is_class_name(ident) {
            class_names.push(ident.clone());
        } else if is_method_name(ident) {
            method_names.push(demangle(ident));
        }
    }
    class_names.sort_unstable();
    class_names.dedup();
    library_uris.sort_unstable();
    library_uris.dedup();
    method_names.sort_by(|a: &DemangledName, b: &DemangledName| a.scrubbed.cmp(&b.scrubbed));
    method_names.dedup();

    let recovered_name_count: usize = class_names.len() + method_names.len() + library_uris.len();
    DartStaticRecovery {
        function_boundary_count: function_boundaries.len(),
        function_boundaries,
        class_names,
        method_names,
        library_uris,
        recovered_name_count,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartMethodEntry {
    pub name: String,
    pub signature: String,
    pub kind: DartNameKind,
    pub is_private: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartClassEntry {
    pub name: String,
    pub library_uri: Option<String>,
    pub fields: Vec<String>,
    pub fields_recoverable: bool,
    pub methods: Vec<DartMethodEntry>,
    pub code_object_backed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DartNameSource {
    CodeObjectCluster,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartRecoveredFunction {
    pub offset: usize,
    pub name: Option<String>,
    pub name_source: DartNameSource,
    pub arg_registers: u8,
    pub has_frame: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartSnapshotStructure {
    pub classes: Vec<DartClassEntry>,
    pub functions: Vec<DartRecoveredFunction>,
    pub named_function_count: usize,
    pub unresolved_function_count: usize,
    pub library_uris: Vec<String>,
    pub unattributed_methods: Vec<DartMethodEntry>,
    pub framing: DartSnapshotFraming,
    pub instruction_traversal: Option<Arm64TraversalReport>,
    pub libapp_recovery: Option<DartLibAppRecovery>,
    pub class_fields_recoverable: bool,
    pub method_signatures_recoverable: bool,
    pub function_names_recoverable: bool,
    pub code_object_attributed_class_count: usize,
    pub code_object_attributed_method_count: usize,
    pub recovery_notes: Vec<String>,
}

const SIGNATURE_UNRECOVERABLE: &str = "(...) -> ? signature types are version-keyed in the Function object cluster, absent from the AOT artifact";

const FIELDS_NOTE: &str = "Class and Field cluster tags identify where per-class field layouts live; object bodies are version-keyed and not decoded yet, so recovered fields stay empty rather than fabricated";

const SIGNATURE_NOTE: &str = "method parameter/return types are not statically recoverable; argument register count is the only honest arity proxy from the AOT machine code";

const FUNCTION_NAME_NOTE: &str = "function entry offsets come from ARM64 prologue scanning of the instruction section; exact Dart code-symbol offsets name those functions when present, and stripped images keep unresolved sub_<offset> labels rather than pairing boundaries with sorted string-pool names";

const METHOD_ATTRIBUTION_NOTE: &str = "each recovered code object carries its owning class as a qualified Class.member identity; those are decoded into per-class method lists. a fully stripped snapshot drops the code-object identity table, so this attribution needs the pinned SDK Function/Code cluster owner reference or the retained code symbol table";

#[must_use]
pub fn recover_dart_snapshot_structure(
    isolate_data: &[u8],
    isolate_instructions: &[u8],
) -> DartSnapshotStructure {
    recover_dart_snapshot_structure_with_symbols(isolate_data, isolate_instructions, &[])
}

#[must_use]
pub fn recover_dart_snapshot_structure_with_symbols(
    isolate_data: &[u8],
    isolate_instructions: &[u8],
    function_symbols: &[DartFunctionSymbol],
) -> DartSnapshotStructure {
    let recovery: DartStaticRecovery = recover_dart_static(isolate_data, isolate_instructions);
    let version_hash: String = super::parse_dart_snapshot(isolate_data)
        .map(|h: super::DartSnapshotHeader| h.version_hash)
        .unwrap_or_default();
    let mut framing: DartSnapshotFraming = parse_snapshot_framing(framing_input(isolate_data));
    if !version_hash.is_empty() {
        attach_cluster_schema(&mut framing, &version_hash);
    }

    let mut class_map: BTreeMap<String, DartClassEntry> = BTreeMap::new();
    let mut pending_members: Vec<(String, DartMethodEntry)> = Vec::new();
    for class_name in &recovery.class_names {
        match qualifying_class(class_name) {
            Some((class, member)) => {
                ensure_class(&mut class_map, class);
                pending_members.push((
                    class.to_owned(),
                    DartMethodEntry {
                        name: member.to_owned(),
                        signature: SIGNATURE_UNRECOVERABLE.to_owned(),
                        kind: DartNameKind::Method,
                        is_private: member.starts_with('_'),
                    },
                ));
            }
            None => ensure_class(&mut class_map, class_name),
        }
    }

    let mut unattributed_methods: Vec<DartMethodEntry> = Vec::new();
    for method in &recovery.method_names {
        let entry: DartMethodEntry = DartMethodEntry {
            name: method.scrubbed.clone(),
            signature: SIGNATURE_UNRECOVERABLE.to_owned(),
            kind: method.kind,
            is_private: method.is_private,
        };
        match qualifying_class(&method.scrubbed) {
            Some((class, member)) if class_map.contains_key(class) => {
                pending_members.push((
                    class.to_owned(),
                    DartMethodEntry {
                        name: member.to_owned(),
                        signature: SIGNATURE_UNRECOVERABLE.to_owned(),
                        kind: method.kind,
                        is_private: method.is_private,
                    },
                ));
            }
            _ => unattributed_methods.push(entry),
        }
    }

    for (class, member) in pending_members {
        if let Some(class_entry) = class_map.get_mut(&class) {
            class_entry.methods.push(member);
        }
    }

    let (code_object_attributed_class_count, code_object_attributed_method_count): (usize, usize) =
        attribute_code_object_methods(&mut class_map, function_symbols);

    for class_entry in class_map.values_mut() {
        class_entry.library_uri = best_library_for(&recovery.library_uris);
        class_entry
            .methods
            .sort_by(|a: &DartMethodEntry, b: &DartMethodEntry| a.name.cmp(&b.name));
        class_entry.methods.dedup();
    }
    unattributed_methods.sort_by(|a: &DartMethodEntry, b: &DartMethodEntry| a.name.cmp(&b.name));
    unattributed_methods.dedup();

    let names_by_offset: BTreeMap<usize, String> = function_symbols
        .iter()
        .map(|s: &DartFunctionSymbol| (s.offset, s.name.clone()))
        .collect();
    let mut functions: Vec<DartRecoveredFunction> =
        Vec::with_capacity(recovery.function_boundaries.len());
    for boundary in &recovery.function_boundaries {
        let name: Option<String> = names_by_offset.get(&boundary.offset).cloned();
        let name_source: DartNameSource = if name.is_some() {
            DartNameSource::CodeObjectCluster
        } else {
            DartNameSource::None
        };
        functions.push(DartRecoveredFunction {
            offset: boundary.offset,
            name,
            name_source,
            arg_registers: boundary.inferred_arg_registers,
            has_frame: boundary.has_frame,
        });
    }
    let named_function_count: usize = functions
        .iter()
        .filter(|f: &&DartRecoveredFunction| f.name.is_some())
        .count();
    let unresolved_function_count: usize = functions.len() - named_function_count;

    let instruction_traversal: Option<Arm64TraversalReport> = if isolate_instructions.is_empty() {
        None
    } else {
        let entries: Vec<u64> = recovery
            .function_boundaries
            .iter()
            .map(|b: &DartFunctionBoundary| b.offset as u64)
            .collect::<Vec<u64>>();
        Some(traverse(0, isolate_instructions, &entries))
    };

    let libapp_recovery: Option<DartLibAppRecovery> =
        if isolate_data.is_empty() && isolate_instructions.is_empty() {
            None
        } else {
            Some(recover_libapp(
                &version_hash,
                isolate_data,
                0,
                isolate_instructions,
                &recovery,
            ))
        };

    DartSnapshotStructure {
        classes: class_map.into_values().collect(),
        functions,
        named_function_count,
        unresolved_function_count,
        library_uris: recovery.library_uris,
        unattributed_methods,
        framing,
        instruction_traversal,
        libapp_recovery,
        class_fields_recoverable: false,
        method_signatures_recoverable: false,
        function_names_recoverable: named_function_count > 0,
        code_object_attributed_class_count,
        code_object_attributed_method_count,
        recovery_notes: vec![
            FIELDS_NOTE.to_owned(),
            SIGNATURE_NOTE.to_owned(),
            FUNCTION_NAME_NOTE.to_owned(),
            METHOD_ATTRIBUTION_NOTE.to_owned(),
        ],
    }
}

#[must_use]
fn framing_input(isolate_data: &[u8]) -> &[u8] {
    const MIN_HEADER_PLUS_FEATURES: usize = 20 + 32;
    if isolate_data.len() < MIN_HEADER_PLUS_FEATURES + 1 {
        return &[];
    }
    if u32::from_le_bytes([
        isolate_data[0],
        isolate_data[1],
        isolate_data[2],
        isolate_data[3],
    ]) != super::DART_SNAPSHOT_MAGIC
    {
        return &[];
    }
    let features_start: usize = MIN_HEADER_PLUS_FEATURES;
    let scan_end: usize = features_start.saturating_add(4096).min(isolate_data.len());
    let features_terminator: usize = isolate_data[features_start..scan_end]
        .iter()
        .position(|b: &u8| *b == 0)
        .map_or(scan_end, |p: usize| features_start + p + 1);
    isolate_data.get(features_terminator..).unwrap_or(&[])
}

fn ensure_class(class_map: &mut BTreeMap<String, DartClassEntry>, class: &str) {
    class_map
        .entry(class.to_owned())
        .or_insert_with(|| DartClassEntry {
            name: class.to_owned(),
            library_uri: None,
            fields: Vec::new(),
            fields_recoverable: false,
            methods: Vec::new(),
            code_object_backed: false,
        });
}

fn attribute_code_object_methods(
    class_map: &mut BTreeMap<String, DartClassEntry>,
    function_symbols: &[DartFunctionSymbol],
) -> (usize, usize) {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut attributed_classes: BTreeSet<String> = BTreeSet::new();
    let mut method_count: usize = 0;
    for symbol in function_symbols {
        let Some((class, member)): Option<(&str, &str)> = split_code_object_owner(&symbol.name)
        else {
            continue;
        };
        let dedup_key: String = format!("{class}\u{1}{member}");
        if !seen.insert(dedup_key) {
            continue;
        }
        let entry: &mut DartClassEntry =
            class_map
                .entry(class.to_owned())
                .or_insert_with(|| DartClassEntry {
                    name: class.to_owned(),
                    library_uri: None,
                    fields: Vec::new(),
                    fields_recoverable: false,
                    methods: Vec::new(),
                    code_object_backed: false,
                });
        entry.code_object_backed = true;
        let demangled: DemangledName = demangle(member);
        entry.methods.push(DartMethodEntry {
            name: demangled.scrubbed,
            signature: SIGNATURE_UNRECOVERABLE.to_owned(),
            kind: demangled.kind,
            is_private: demangled.is_private,
        });
        method_count += 1;
        attributed_classes.insert(class.to_owned());
    }
    (attributed_classes.len(), method_count)
}

#[must_use]
fn split_code_object_owner(symbol_name: &str) -> Option<(&str, &str)> {
    let (class, remainder): (&str, &str) = symbol_name.split_once('.')?;
    if !is_owner_class_token(class) {
        return None;
    }
    let member: &str = match remainder.find('.') {
        Some(dot) => &remainder[..dot],
        None => remainder,
    };
    if member.is_empty() || member == "<anonymous closure>" {
        return None;
    }
    if !member
        .chars()
        .all(|c: char| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    Some((class, member))
}

#[must_use]
fn is_owner_class_token(class: &str) -> bool {
    let first: char = match class.chars().next() {
        Some(c) => c,
        None => return false,
    };
    let leading: char = if first == '_' {
        match class.chars().nth(1) {
            Some(c) => c,
            None => return false,
        }
    } else {
        first
    };
    leading.is_ascii_uppercase()
        && class
            .chars()
            .all(|c: char| c.is_ascii_alphanumeric() || c == '_')
}

#[must_use]
fn qualifying_class(name: &str) -> Option<(&str, &str)> {
    let (class, member): (&str, &str) = name.split_once('.')?;
    if member.is_empty() || member.contains('.') {
        return None;
    }
    let first: char = class.chars().next()?;
    let leading: char = if first == '_' {
        class.chars().nth(1).unwrap_or(first)
    } else {
        first
    };
    if !leading.is_ascii_uppercase() {
        return None;
    }
    if !class
        .chars()
        .all(|c: char| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    Some((class, member))
}

#[must_use]
fn best_library_for(library_uris: &[String]) -> Option<String> {
    library_uris
        .iter()
        .find(|u: &&String| u.starts_with("package:"))
        .or_else(|| library_uris.first())
        .cloned()
}

#[must_use]
fn scan_function_boundaries(instructions: &[u8]) -> Vec<DartFunctionBoundary> {
    dbg_section("dart.arm64-prologue-scan");
    dbg_kv("instruction_bytes", || instructions.len().to_string());
    let body_start: usize = if instructions.len() >= IMAGE_HEADER_SIZE {
        IMAGE_HEADER_SIZE
    } else {
        0
    };
    dbg_kv("body_start", || body_start.to_string());
    let mut out: Vec<DartFunctionBoundary> = Vec::new();
    let mut i: usize = body_start;
    while i + 8 <= instructions.len() && out.len() < MAX_FUNCTION_BOUNDARIES {
        let w0: u32 = u32::from_le_bytes([
            instructions[i],
            instructions[i + 1],
            instructions[i + 2],
            instructions[i + 3],
        ]);
        if w0 == ARM64_PUSH_FP_LR_DART_SP || w0 == ARM64_PUSH_FP_LR_SYS_SP {
            let w1: u32 = u32::from_le_bytes([
                instructions[i + 4],
                instructions[i + 5],
                instructions[i + 6],
                instructions[i + 7],
            ]);
            let has_frame: bool = matches!(w1, ARM64_MOV_FP_DART_SP | ARM64_MOV_FP_SYS_SP);
            let inferred_arg_registers: u8 = infer_arg_registers(&instructions[i..], has_frame);
            out.push(DartFunctionBoundary {
                offset: i,
                inferred_arg_registers,
                has_frame,
            });
            i += BARE_PAYLOAD_ALIGNMENT.max(8);
        } else {
            i += BARE_PAYLOAD_ALIGNMENT;
        }
    }
    dbg_kv("function_boundaries", || out.len().to_string());
    out
}

#[must_use]
fn infer_arg_registers(func: &[u8], _has_frame: bool) -> u8 {
    const WINDOW_INSNS: usize = 32;
    let mut seen: u8 = 0;
    let limit: usize = (WINDOW_INSNS * 4).min(func.len());
    let mut i: usize = 0;
    while i + 4 <= limit {
        let w: u32 = u32::from_le_bytes([func[i], func[i + 1], func[i + 2], func[i + 3]]);
        if is_arm64_return(w) {
            break;
        }
        let rn: u8 = ((w >> 5) & 0x1f) as u8;
        let rm: u8 = ((w >> 16) & 0x1f) as u8;
        for reg in [rn, rm] {
            if reg < 8 {
                seen |= 1u8 << reg;
            }
        }
        i += 4;
    }
    seen.count_ones() as u8
}

#[must_use]
const fn is_arm64_return(w: u32) -> bool {
    w == 0xD65F_03C0
}

#[must_use]
fn extract_dart_identifiers(data: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    let mut current_overlong: bool = false;
    for byte in data {
        if out.len() >= MAX_DART_IDENTIFIER_COUNT {
            break;
        }
        if is_dart_ident_byte(*byte) {
            if current_overlong {
                continue;
            }
            if current.len() >= MAX_DART_IDENTIFIER_BYTES {
                current.clear();
                current_overlong = true;
            } else {
                current.push(*byte);
            }
        } else {
            flush_identifier(&mut current, current_overlong, &mut out);
            current_overlong = false;
        }
    }
    flush_identifier(&mut current, current_overlong, &mut out);
    out
}

fn flush_identifier(current: &mut Vec<u8>, current_overlong: bool, out: &mut Vec<String>) {
    if !current_overlong
        && out.len() < MAX_DART_IDENTIFIER_COUNT
        && current.len() >= MIN_IDENTIFIER_LEN
        && let Ok(s) = std::str::from_utf8(current)
        && looks_like_dart_name(s)
    {
        out.push(s.to_owned());
    }
    current.clear();
}

#[must_use]
const fn is_dart_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || b == b'_'
        || b == b'.'
        || b == b'@'
        || b == b':'
        || b == b'/'
        || b == b'<'
        || b == b'>'
}

#[must_use]
fn looks_like_dart_name(s: &str) -> bool {
    let first: char = match s.chars().next() {
        Some(c) => c,
        None => return false,
    };
    if !(first.is_ascii_alphabetic() || first == '_' || first == 'd' || first == 'p') {
        return false;
    }
    s.chars().any(|c: char| c.is_ascii_alphabetic())
}

#[must_use]
fn is_library_uri(s: &str) -> bool {
    s.starts_with("package:")
        || s.starts_with("dart:")
        || s.starts_with("file:")
        || (s.contains('/') && s.ends_with(".dart"))
}

#[must_use]
fn is_class_name(s: &str) -> bool {
    if s.contains(':') || s.contains('/') {
        return false;
    }
    let first: char = match s.chars().next() {
        Some(c) => c,
        None => return false,
    };
    let leading: char = if first == '_' {
        s.chars().nth(1).unwrap_or(first)
    } else {
        first
    };
    leading.is_ascii_uppercase() && !s.contains('@')
}

#[must_use]
fn is_method_name(s: &str) -> bool {
    s.starts_with("get:") || s.starts_with("set:") || s.contains('@') || {
        let first: char = match s.chars().next() {
            Some(c) => c,
            None => return false,
        };
        let leading: char = if first == '_' {
            s.chars().nth(1).unwrap_or(first)
        } else {
            first
        };
        leading.is_ascii_lowercase() && !s.contains('/') && !s.contains(':')
    }
}

#[must_use]
fn read8(blob: &[u8], at: usize) -> Option<[u8; 8]> {
    let end: usize = at.checked_add(8)?;
    if end > blob.len() {
        return None;
    }
    let mut out: [u8; 8] = [0u8; 8];
    out.copy_from_slice(&blob[at..end]);
    Some(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn arm64_func(arg_regs: &[u8], body_filler: usize) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&ARM64_PUSH_FP_LR_DART_SP.to_le_bytes());
        v.extend_from_slice(&ARM64_MOV_FP_DART_SP.to_le_bytes());
        for reg in arg_regs {
            let insn: u32 = 0x9100_0000 | ((*reg as u32) << 5);
            v.extend_from_slice(&insn.to_le_bytes());
        }
        for _ in 0..body_filler {
            v.extend_from_slice(&0x9100_03FFu32.to_le_bytes());
        }
        v.extend_from_slice(&0xD65F_03C0u32.to_le_bytes());
        v
    }

    fn image_with_funcs(funcs: &[Vec<u8>]) -> Vec<u8> {
        let mut v: Vec<u8> = vec![0u8; IMAGE_HEADER_SIZE];
        for f in funcs {
            v.extend_from_slice(f);
            while v.len() % 16 != 0 {
                v.push(0u8);
            }
        }
        v
    }

    fn encode_unsigned(mut value: u64) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        loop {
            let low: u8 = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(low | 0x80);
                return out;
            }
            out.push(low);
        }
    }

    fn isolate_snapshot_with_cluster_tags(cids: &[u64]) -> Vec<u8> {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&super::super::DART_SNAPSHOT_MAGIC.to_le_bytes());
        data.extend_from_slice(&1024u64.to_le_bytes());
        data.extend_from_slice(&3u64.to_le_bytes());
        data.extend_from_slice(super::super::cid_table::DART_3_12_VERSION_HASH.as_bytes());
        data.extend_from_slice(b"product");
        data.push(0);
        data.extend_from_slice(&encode_unsigned(107));
        data.extend_from_slice(&encode_unsigned(50_000));
        data.extend_from_slice(&encode_unsigned(cids.len() as u64));
        data.extend_from_slice(&encode_unsigned(0));
        for cid in cids {
            data.extend_from_slice(&encode_unsigned(*cid));
            data.push(0x00);
        }
        data
    }

    #[test]
    fn parses_image_header() {
        let mut blob: Vec<u8> = vec![0u8; IMAGE_HEADER_SIZE];
        blob[0..8].copy_from_slice(&4096u64.to_le_bytes());
        blob[8..16].copy_from_slice(&512u64.to_le_bytes());
        let header: ImageHeader = parse_image_header(&blob).expect("header");
        assert_eq!(header.image_size, 4096);
        assert_eq!(header.instructions_section_offset, 512);
    }

    #[test]
    fn scans_two_function_boundaries() {
        let funcs: Vec<Vec<u8>> = vec![arm64_func(&[0, 1], 2), arm64_func(&[0], 1)];
        let image: Vec<u8> = image_with_funcs(&funcs);
        let boundaries: Vec<DartFunctionBoundary> = scan_function_boundaries(&image);
        assert_eq!(boundaries.len(), 2);
        assert!(boundaries[0].has_frame);
        assert!(boundaries[0].inferred_arg_registers >= 2);
    }

    #[test]
    fn scans_system_sp_prologue_form() {
        let mut func: Vec<u8> = Vec::new();
        func.extend_from_slice(&ARM64_PUSH_FP_LR_SYS_SP.to_le_bytes());
        func.extend_from_slice(&ARM64_MOV_FP_SYS_SP.to_le_bytes());
        func.extend_from_slice(&0xD65F_03C0u32.to_le_bytes());
        let image: Vec<u8> = image_with_funcs(&[func]);
        let boundaries: Vec<DartFunctionBoundary> = scan_function_boundaries(&image);
        assert_eq!(boundaries.len(), 1);
        assert!(boundaries[0].has_frame);
    }

    #[test]
    fn classifies_dart_names() {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(b"\x00package:myapp/main.dart\x00");
        data.extend_from_slice(b"MyWidget\x00");
        data.extend_from_slice(b"build\x00");
        data.extend_from_slice(b"get:length@1a2b3c\x00");
        data.extend_from_slice(b"_PrivateState\x00");
        let recovery: DartStaticRecovery = recover_dart_static(&data, &[]);
        assert!(
            recovery
                .library_uris
                .iter()
                .any(|u: &String| u == "package:myapp/main.dart")
        );
        assert!(
            recovery
                .class_names
                .iter()
                .any(|c: &String| c == "MyWidget")
        );
        assert!(
            recovery
                .class_names
                .iter()
                .any(|c: &String| c == "_PrivateState")
        );
        assert!(
            recovery
                .method_names
                .iter()
                .any(|m: &DemangledName| m.scrubbed == "build")
        );
        assert!(
            recovery
                .method_names
                .iter()
                .any(|m: &DemangledName| m.scrubbed == "length")
        );
        assert!(recovery.recovered_name_count >= 4);
    }

    #[test]
    fn end_to_end_recovery_counts_functions_and_names() {
        let funcs: Vec<Vec<u8>> = vec![arm64_func(&[0], 1), arm64_func(&[0, 1, 2], 2)];
        let image: Vec<u8> = image_with_funcs(&funcs);
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(b"\x00package:app/x.dart\x00HomePage\x00createState\x00");
        let recovery: DartStaticRecovery = recover_dart_static(&data, &image);
        assert_eq!(recovery.function_boundary_count, 2);
        assert!(recovery.recovered_name_count >= 3);
    }

    #[test]
    fn empty_inputs_do_not_panic() {
        let recovery: DartStaticRecovery = recover_dart_static(&[], &[]);
        assert_eq!(recovery.function_boundary_count, 0);
        assert_eq!(recovery.recovered_name_count, 0);
    }

    #[test]
    fn identifier_scan_rejects_overlong_token() {
        let data: Vec<u8> = vec![b'A'; MAX_DART_IDENTIFIER_BYTES + 1];
        let identifiers: Vec<String> = extract_dart_identifiers(&data);
        assert!(identifiers.is_empty());
    }

    #[test]
    fn identifier_scan_caps_token_count() {
        let mut data: Vec<u8> = Vec::new();
        for index in 0..(MAX_DART_IDENTIFIER_COUNT + 8) {
            data.extend_from_slice(format!("Name{index}\0").as_bytes());
        }
        let identifiers: Vec<String> = extract_dart_identifiers(&data);
        assert_eq!(identifiers.len(), MAX_DART_IDENTIFIER_COUNT);
    }

    #[test]
    fn structure_attributes_qualified_method_to_its_class() {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(b"\x00package:app/main.dart\x00HomePage\x00HomePage.build\x00");
        let structure: DartSnapshotStructure = recover_dart_snapshot_structure(&data, &[]);
        let home: &DartClassEntry = structure
            .classes
            .iter()
            .find(|c: &&DartClassEntry| c.name == "HomePage")
            .expect("HomePage class recovered");
        assert!(
            home.methods
                .iter()
                .any(|m: &DartMethodEntry| m.name == "build"),
            "HomePage.build must attribute to HomePage, methods = {:?}",
            home.methods
        );
        assert_eq!(
            home.library_uri.as_deref(),
            Some("package:app/main.dart"),
            "class must carry its library uri"
        );
    }

    #[test]
    fn structure_never_fabricates_fields_or_signatures() {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(b"\x00package:app/m.dart\x00Widget\x00Widget.build\x00paint\x00");
        let structure: DartSnapshotStructure = recover_dart_snapshot_structure(&data, &[]);
        assert!(
            !structure.class_fields_recoverable,
            "fields are version-keyed; must be reported unrecoverable"
        );
        assert!(
            !structure.method_signatures_recoverable,
            "signatures are version-keyed; must be reported unrecoverable"
        );
        for class in &structure.classes {
            assert!(
                class.fields.is_empty() && !class.fields_recoverable,
                "no class may carry fabricated fields: {} has {:?}",
                class.name,
                class.fields
            );
            for method in &class.methods {
                assert!(
                    method.signature.contains("version-keyed"),
                    "every signature must honestly flag the wall, got {:?}",
                    method.signature
                );
            }
        }
        assert!(
            structure
                .recovery_notes
                .iter()
                .any(|n: &String| n.contains("Class and Field cluster tags")
                    && n.contains("object bodies are version-keyed")),
            "recovery notes must cite the precise field-layout wall"
        );
    }

    #[test]
    fn structure_attaches_versioned_signature_cluster_schema() {
        let function_type_cid: u64 = (0..super::super::cid_table::predefined_count())
            .find(|cid: &u16| {
                super::super::cid_table::predefined_name(*cid) == Some("FunctionType")
            })
            .map(u64::from)
            .expect("FunctionType cid exists");
        let type_cid: u64 = (0..super::super::cid_table::predefined_count())
            .find(|cid: &u16| super::super::cid_table::predefined_name(*cid) == Some("Type"))
            .map(u64::from)
            .expect("Type cid exists");
        let class_cid: u64 = (0..super::super::cid_table::predefined_count())
            .find(|cid: &u16| super::super::cid_table::predefined_name(*cid) == Some("Class"))
            .map(u64::from)
            .expect("Class cid exists");
        let code_cid: u64 = (0..super::super::cid_table::predefined_count())
            .find(|cid: &u16| super::super::cid_table::predefined_name(*cid) == Some("Code"))
            .map(u64::from)
            .expect("Code cid exists");
        let field_cid: u64 = (0..super::super::cid_table::predefined_count())
            .find(|cid: &u16| super::super::cid_table::predefined_name(*cid) == Some("Field"))
            .map(u64::from)
            .expect("Field cid exists");
        let function_cid: u64 = (0..super::super::cid_table::predefined_count())
            .find(|cid: &u16| super::super::cid_table::predefined_name(*cid) == Some("Function"))
            .map(u64::from)
            .expect("Function cid exists");
        let data: Vec<u8> = isolate_snapshot_with_cluster_tags(&[
            function_type_cid,
            type_cid,
            class_cid,
            code_cid,
            field_cid,
            function_cid,
        ]);
        let structure: DartSnapshotStructure = recover_dart_snapshot_structure(&data, &[]);
        let schema: &super::super::cluster::DartClusterSchemaReport = structure
            .framing
            .cluster_schema
            .as_ref()
            .expect("cluster schema");
        assert!(schema.version_matched);
        assert_eq!(schema.class_cluster_count, 1);
        assert_eq!(schema.code_cluster_count, 1);
        assert_eq!(schema.field_cluster_count, 1);
        assert_eq!(schema.function_cluster_count, 1);
        assert_eq!(schema.class_field_related_cluster_count, 2);
        assert_eq!(schema.function_type_cluster_count, 1);
        assert_eq!(schema.signature_related_cluster_count, 2);
        assert!(!structure.class_fields_recoverable);
        assert!(!structure.method_signatures_recoverable);
    }

    #[test]
    fn structure_bare_method_is_unattributed_not_invented_class() {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(b"\x00package:app/m.dart\x00main\x00helper\x00");
        let structure: DartSnapshotStructure = recover_dart_snapshot_structure(&data, &[]);
        assert!(
            structure
                .unattributed_methods
                .iter()
                .any(|m: &DartMethodEntry| m.name == "main"),
            "a bare method with no class qualifier must land in unattributed, not invent a class"
        );
    }

    #[test]
    fn splits_qualified_code_object_owner() {
        assert_eq!(
            split_code_object_owner("WarehouseLedger.mostValuable"),
            Some(("WarehouseLedger", "mostValuable"))
        );
        assert_eq!(
            split_code_object_owner("WarehouseLedger.countBackordered.<anonymous closure>"),
            Some(("WarehouseLedger", "countBackordered"))
        );
        assert_eq!(
            split_code_object_owner("_PrivateState.build"),
            Some(("_PrivateState", "build"))
        );
        assert_eq!(split_code_object_owner("fibonacciStep"), None);
        assert_eq!(split_code_object_owner("main"), None);
        assert_eq!(
            split_code_object_owner("WarehouseLedger.<anonymous closure>"),
            None
        );
        assert_eq!(
            split_code_object_owner("lowercaseOwner.member"),
            None,
            "an owner token must be a class-shaped UpperCamel identifier"
        );
    }

    #[test]
    fn structure_attributes_code_object_methods_to_owner_class() {
        let symbols: Vec<DartFunctionSymbol> = vec![
            DartFunctionSymbol {
                offset: 0x100,
                address: 0x100,
                size: 0x40,
                name: "WarehouseLedger.mostValuable".to_owned(),
            },
            DartFunctionSymbol {
                offset: 0x140,
                address: 0x140,
                size: 0x40,
                name: "WarehouseLedger.countBackordered".to_owned(),
            },
            DartFunctionSymbol {
                offset: 0x180,
                address: 0x180,
                size: 0x20,
                name: "WarehouseLedger.countBackordered.<anonymous closure>".to_owned(),
            },
            DartFunctionSymbol {
                offset: 0x1a0,
                address: 0x1a0,
                size: 0x20,
                name: "fibonacciStep".to_owned(),
            },
        ];
        let structure: DartSnapshotStructure =
            recover_dart_snapshot_structure_with_symbols(&[], &[], &symbols);
        let ledger: &DartClassEntry = structure
            .classes
            .iter()
            .find(|c: &&DartClassEntry| c.name == "WarehouseLedger")
            .expect("WarehouseLedger attributed from code-object identity");
        assert!(ledger.code_object_backed);
        assert!(
            ledger
                .methods
                .iter()
                .any(|m: &DartMethodEntry| m.name == "mostValuable"),
        );
        assert!(
            ledger
                .methods
                .iter()
                .any(|m: &DartMethodEntry| m.name == "countBackordered"),
        );
        assert_eq!(
            ledger.methods.len(),
            2,
            "the anonymous-closure duplicate must fold into countBackordered, not add a method"
        );
        assert_eq!(structure.code_object_attributed_class_count, 1);
        assert_eq!(
            structure.code_object_attributed_method_count, 2,
            "two distinct Class.member code objects were attributed"
        );
        assert!(
            !ledger.fields_recoverable && ledger.fields.is_empty(),
            "instance field names stay walled even when methods attribute"
        );
    }

    #[test]
    fn structure_traverses_instructions_when_present() {
        let funcs: Vec<Vec<u8>> = vec![arm64_func(&[0], 1)];
        let image: Vec<u8> = image_with_funcs(&funcs);
        let structure: DartSnapshotStructure = recover_dart_snapshot_structure(&[], &image);
        let traversal: &Arm64TraversalReport = structure
            .instruction_traversal
            .as_ref()
            .expect("traversal runs when instructions are present");
        assert!(
            traversal.reachable_instruction_count > 0,
            "traversal should decode at least the prologue from a boundary entry"
        );
    }
}
