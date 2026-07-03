use core::fmt::Write as _;
use std::collections::BTreeMap;

use object::{Object, ObjectSymbol, SymbolKind};
use serde::{Deserialize, Serialize};

use crate::cxx_recovery::{CxxDemangled, demangle_auto};
use crate::error::{Error, Result};
use crate::packers::pe_sections::{PeImage, PeSection, parse_pe_image};
use crate::packers::{Detection as PackerDetection, detect as detect_packers};
use crate::rust_recovery::{DemangledSymbol, demangle as demangle_rust};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExportFormat {
    Ghidra,
    Ida,
    Json,
}

impl ExportFormat {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ghidra => "ghidra",
            Self::Ida => "ida",
            Self::Json => "json",
        }
    }

    #[must_use]
    pub const fn sidecar_extension(self) -> &'static str {
        match self {
            Self::Ghidra => "ghidra.java",
            Self::Ida => "ida.py",
            Self::Json => "symbols.json",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SymbolOrigin {
    SymbolTable,
    DynamicSymbol,
    OriginalEntryPoint,
    PackerChain,
    CompilerRuntime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SymbolClass {
    Function,
    Data,
    Section,
    EntryPoint,
    Label,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredSymbol {
    pub address: u64,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub demangled: Option<String>,
    pub class: SymbolClass,
    pub origin: SymbolOrigin,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolMap {
    pub schema: &'static str,
    pub source: String,
    pub format: String,
    pub image_base: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_entry_point: Option<u64>,
    pub symbol_count: usize,
    pub symbols: Vec<RecoveredSymbol>,
}

pub const SYMBOL_MAP_SCHEMA: &str = "disrobe.native.symbol-map/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RebuildLayout {
    MemoryImageOverlay,
    BareBlockPlacement,
    StandaloneObject,
}

impl RebuildLayout {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::MemoryImageOverlay => "memory-image-overlay",
            Self::BareBlockPlacement => "bare-block-placement",
            Self::StandaloneObject => "standalone-object",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebuiltImage {
    pub bytes: Vec<u8>,
    pub layout: RebuildLayout,
    pub restored_entry_point_rva: Option<u32>,
    pub sections_overlaid: usize,
    pub bytes_placed: usize,
    pub iat_slots_rewritten: usize,
    pub note: String,
}

fn dos_pe_offset(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 0x40 || &bytes[..2] != b"MZ" {
        return None;
    }
    let e_lfanew: usize = u32::from_le_bytes([
        *bytes.get(0x3C)?,
        *bytes.get(0x3D)?,
        *bytes.get(0x3E)?,
        *bytes.get(0x3F)?,
    ]) as usize;
    if bytes.get(e_lfanew..e_lfanew + 4)? != b"PE\x00\x00" {
        return None;
    }
    Some(e_lfanew)
}

const fn optional_header_offset(pe_off: usize) -> usize {
    pe_off + 4 + 20
}

fn write_entry_point_rva(bytes: &mut [u8], pe_off: usize, oep_rva: u32) -> bool {
    let opt_off: usize = optional_header_offset(pe_off);
    let field: usize = opt_off + 16;
    if field + 4 > bytes.len() {
        return false;
    }
    bytes[field..field + 4].copy_from_slice(&oep_rva.to_le_bytes());
    true
}

fn is_rva_memory_image(img: &PeImage, recovered: &[u8]) -> bool {
    if recovered.len() < 2 || &recovered[..2] != b"MZ" {
        return false;
    }
    let span: usize = img.size_of_image as usize;
    let lo: usize = span.saturating_sub(span / 8);
    recovered.len() >= lo && recovered.len() >= 0x1000
}

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

fn lowest_executable_section_index(img: &PeImage) -> Option<usize> {
    img.sections
        .iter()
        .enumerate()
        .filter(|(_, s): &(usize, &PeSection)| s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
        .min_by_key(|(_, s): &(usize, &PeSection)| s.virtual_address)
        .map(|(i, _): (usize, &PeSection)| i)
}

fn section_table_offset(packed: &[u8], pe_off: usize) -> Option<usize> {
    let coff: usize = pe_off + 4;
    let opt_size: usize =
        u16::from_le_bytes([*packed.get(coff + 16)?, *packed.get(coff + 17)?]) as usize;
    Some(coff + 20 + opt_size)
}

fn overlay_memory_image(out: &mut [u8], img: &PeImage, recovered: &[u8]) -> usize {
    let mut sections_overlaid: usize = 0;
    for sec in &img.sections {
        let sec: &PeSection = sec;
        let va: usize = sec.virtual_address as usize;
        let vsz: usize = sec.virtual_size as usize;
        let raw_off: usize = sec.raw_pointer as usize;
        let raw_sz: usize = sec.raw_size as usize;
        if raw_sz == 0 || raw_off == 0 || va >= recovered.len() {
            continue;
        }
        let avail: usize = recovered.len().saturating_sub(va);
        let copy: usize = raw_sz.min(vsz.max(raw_sz)).min(avail);
        let copy_clamped: usize = copy.min(out.len().saturating_sub(raw_off));
        if copy_clamped == 0 {
            continue;
        }
        let src: &[u8] = &recovered[va..va + copy_clamped];
        if src == &out[raw_off..raw_off + copy_clamped] {
            continue;
        }
        out[raw_off..raw_off + copy_clamped].copy_from_slice(src);
        sections_overlaid += 1;
    }
    sections_overlaid
}

fn place_recovered_block_into_section(
    out: &mut Vec<u8>,
    sec_table: usize,
    idx: usize,
    target: &PeSection,
    recovered: &[u8],
) -> Result<usize> {
    if recovered.is_empty() {
        return Err(Error::Export {
            stage: "place-bare-block",
            detail: "recovered block is empty".to_owned(),
        });
    }
    let entry: usize = sec_table + idx * 40;
    if entry + 40 > out.len() {
        return Err(Error::Export {
            stage: "place-bare-block",
            detail: "section table entry out of range".to_owned(),
        });
    }
    let raw_sz: usize = target.raw_size as usize;
    let raw_off: usize = target.raw_pointer as usize;
    let fits_in_place: bool =
        raw_sz >= recovered.len() && raw_off != 0 && raw_off + recovered.len() <= out.len();
    let new_raw_size: u32 = u32::try_from(recovered.len()).map_err(|_| Error::Export {
        stage: "place-bare-block",
        detail: "recovered block exceeds a 32-bit section size".to_owned(),
    })?;
    if fits_in_place {
        out[raw_off..raw_off + recovered.len()].copy_from_slice(recovered);
    } else {
        let appended_off: usize = out.len();
        let new_raw_off: u32 = u32::try_from(appended_off).map_err(|_| Error::Export {
            stage: "place-bare-block",
            detail: "appended section offset exceeds a 32-bit file offset".to_owned(),
        })?;
        out.extend_from_slice(recovered);
        out[entry + 20..entry + 24].copy_from_slice(&new_raw_off.to_le_bytes());
    }
    out[entry + 16..entry + 20].copy_from_slice(&new_raw_size.to_le_bytes());
    let new_vsize: u32 = target.virtual_size.max(new_raw_size);
    out[entry + 8..entry + 12].copy_from_slice(&new_vsize.to_le_bytes());
    Ok(recovered.len())
}

pub fn rebuild_unpacked_pe(
    packed: &[u8],
    recovered_image: &[u8],
    restored_oep_va: Option<u64>,
) -> Result<RebuiltImage> {
    let img: PeImage = parse_pe_image(packed).map_err(|e| Error::Export {
        stage: "parse-packed-pe",
        detail: e.to_string(),
    })?;
    let pe_off: usize = dos_pe_offset(packed).ok_or_else(|| Error::Export {
        stage: "locate-pe-header",
        detail: "packed input has no resolvable MZ/PE header".to_owned(),
    })?;

    let mut out: Vec<u8> = packed.to_vec();

    let (layout, sections_overlaid, bytes_placed): (RebuildLayout, usize, usize) =
        if is_rva_memory_image(&img, recovered_image) {
            let overlaid: usize = overlay_memory_image(&mut out, &img, recovered_image);
            let placed: usize = recovered_image.len().min(out.len());
            (RebuildLayout::MemoryImageOverlay, overlaid, placed)
        } else {
            let idx: usize =
                lowest_executable_section_index(&img).ok_or_else(|| Error::Export {
                    stage: "locate-code-section",
                    detail:
                        "packed PE has no executable section to host the recovered original code \
                         block"
                            .to_owned(),
                })?;
            let sec_table: usize =
                section_table_offset(packed, pe_off).ok_or_else(|| Error::Export {
                    stage: "locate-section-table",
                    detail: "cannot resolve the PE section table".to_owned(),
                })?;
            let placed: usize = place_recovered_block_into_section(
                &mut out,
                sec_table,
                idx,
                &img.sections[idx],
                recovered_image,
            )?;
            (RebuildLayout::BareBlockPlacement, 1, placed)
        };

    let restored_entry_point_rva: Option<u32> = match restored_oep_va {
        Some(va) => {
            let rva: u64 = va.saturating_sub(img.image_base);
            let rva32: u32 = u32::try_from(rva).map_err(|_| Error::Export {
                stage: "oep-rva",
                detail: format!("recovered OEP VA {va:#x} not representable as a 32-bit RVA"),
            })?;
            if write_entry_point_rva(&mut out, pe_off, rva32) {
                Some(rva32)
            } else {
                None
            }
        }
        None => None,
    };

    if object::File::parse(out.as_slice()).is_err() {
        return Err(Error::Export {
            stage: "reparse-rebuilt-pe",
            detail: "rebuilt image no longer parses as a valid object file".to_owned(),
        });
    }

    let note: String = match layout {
        RebuildLayout::MemoryImageOverlay => format!(
            "memory-image overlay: the recovered image is an RVA-indexed process dump; overlaid \
             {sections_overlaid} section bod(ies) by virtual address into the file image, OEP {}",
            restored_entry_point_rva.map_or_else(
                || "unchanged".to_owned(),
                |rva: u32| format!("restored to RVA {rva:#x}")
            ),
        ),
        RebuildLayout::BareBlockPlacement => format!(
            "bare-block placement: the recovered image is the decompressed original code block \
             (not a process dump); repointed the lowest-VA executable section to {bytes_placed} \
             recovered byte(s) so a backend disassembles real instructions at that section's RVA \
             instead of the packer stub, OEP {}",
            restored_entry_point_rva.map_or_else(
                || "unchanged".to_owned(),
                |rva: u32| format!("restored to RVA {rva:#x}")
            ),
        ),
        RebuildLayout::StandaloneObject => "standalone object".to_owned(),
    };

    Ok(RebuiltImage {
        bytes: out,
        layout,
        restored_entry_point_rva,
        sections_overlaid,
        bytes_placed,
        iat_slots_rewritten: 0,
        note,
    })
}

pub fn rebuild_passthrough(recovered: &[u8]) -> Result<RebuiltImage> {
    if object::File::parse(recovered).is_err() {
        return Err(Error::Export {
            stage: "passthrough-parse",
            detail: "recovered bytes are not a standalone loadable object; supply the packed \
                     original so the file image can be reconstructed from its section table"
                .to_owned(),
        });
    }
    Ok(RebuiltImage {
        bytes: recovered.to_vec(),
        layout: RebuildLayout::StandaloneObject,
        restored_entry_point_rva: None,
        sections_overlaid: 0,
        bytes_placed: recovered.len(),
        iat_slots_rewritten: 0,
        note: format!(
            "recovered bytes are already a standalone loadable object ({} bytes); written through \
             unmodified",
            recovered.len()
        ),
    })
}

fn demangle_symbol(name: &str) -> Option<String> {
    if let Ok(rust) = demangle_rust(name) {
        let rust: DemangledSymbol = rust;
        if rust.demangled != name {
            return Some(rust.demangled);
        }
    }
    if let Ok(cxx) = demangle_auto(name) {
        let cxx: CxxDemangled = cxx;
        if cxx.demangled != name {
            return Some(cxx.demangled);
        }
    }
    None
}

const fn class_for(kind: SymbolKind) -> SymbolClass {
    match kind {
        SymbolKind::Text => SymbolClass::Function,
        SymbolKind::Data | SymbolKind::Tls => SymbolClass::Data,
        SymbolKind::Section => SymbolClass::Section,
        _ => SymbolClass::Label,
    }
}

pub fn collect_recovered_symbols(bytes: &[u8]) -> Result<SymbolMap> {
    collect_recovered_symbols_with_oep(bytes, None)
}

pub fn collect_recovered_symbols_with_oep(
    bytes: &[u8],
    recovered_oep_va: Option<u64>,
) -> Result<SymbolMap> {
    let file: object::File<'_> = object::File::parse(bytes).map_err(|e| Error::Export {
        stage: "symbol-parse",
        detail: e.to_string(),
    })?;
    let format: &'static str = match file.format() {
        object::BinaryFormat::Elf => "elf",
        object::BinaryFormat::Pe => "pe",
        object::BinaryFormat::Coff => "coff",
        object::BinaryFormat::MachO => "macho",
        object::BinaryFormat::Wasm => "wasm",
        object::BinaryFormat::Xcoff => "xcoff",
        _ => "unknown",
    };
    let image_base: u64 = file.relative_address_base();
    let entry: u64 = file.entry();

    let mut seen: BTreeMap<(u64, String), RecoveredSymbol> = BTreeMap::new();

    let mut ingest = |sym_name: &str, address: u64, kind: SymbolKind, origin: SymbolOrigin| {
        if sym_name.is_empty() || address == 0 {
            return;
        }
        let demangled: Option<String> = demangle_symbol(sym_name);
        let class: SymbolClass = class_for(kind);
        let name: String = sym_name.to_owned();
        let key: (u64, String) = (address, name.clone());
        seen.entry(key).or_insert_with(|| RecoveredSymbol {
            address,
            name,
            demangled,
            class,
            origin,
            note: None,
        });
    };

    for symbol in file.symbols() {
        let Ok(name): core::result::Result<&str, object::Error> = symbol.name() else {
            continue;
        };
        ingest(
            name,
            symbol.address(),
            symbol.kind(),
            SymbolOrigin::SymbolTable,
        );
    }
    for symbol in file.dynamic_symbols() {
        let Ok(name): core::result::Result<&str, object::Error> = symbol.name() else {
            continue;
        };
        ingest(
            name,
            symbol.address(),
            symbol.kind(),
            SymbolOrigin::DynamicSymbol,
        );
    }

    let mut symbols: Vec<RecoveredSymbol> = seen.into_values().collect();

    let oep_va: Option<u64> = recovered_oep_va;
    if let Some(oep) = oep_va {
        let oep: u64 = oep;
        symbols.push(RecoveredSymbol {
            address: oep,
            name: "disrobe_OEP".to_owned(),
            demangled: None,
            class: SymbolClass::EntryPoint,
            origin: SymbolOrigin::OriginalEntryPoint,
            note: Some("original entry point recovered by disrobe unpack".to_owned()),
        });
    } else if entry != 0 {
        symbols.push(RecoveredSymbol {
            address: entry,
            name: "disrobe_packed_entry".to_owned(),
            demangled: None,
            class: SymbolClass::Label,
            origin: SymbolOrigin::PackerChain,
            note: Some(
                "current image entry point (packer stub; original entry not recovered for this \
                 packer)"
                    .to_owned(),
            ),
        });
    }

    for det in detect_packers(bytes) {
        let det: PackerDetection = det;
        let Some(off): Option<u64> = det.matched_offset else {
            continue;
        };
        if off == 0 {
            continue;
        }
        symbols.push(RecoveredSymbol {
            address: image_base.saturating_add(off),
            name: format!("disrobe_chain_{}", sanitize_ident(det.packer.label())),
            demangled: None,
            class: SymbolClass::Label,
            origin: SymbolOrigin::PackerChain,
            note: Some(format!("{} stub marker: {}", det.packer.label(), det.note)),
        });
    }

    symbols.sort_by(|a: &RecoveredSymbol, b: &RecoveredSymbol| {
        a.address.cmp(&b.address).then_with(|| a.name.cmp(&b.name))
    });

    let symbol_count: usize = symbols.len();
    Ok(SymbolMap {
        schema: SYMBOL_MAP_SCHEMA,
        source: String::new(),
        format: format.to_owned(),
        image_base,
        original_entry_point: oep_va,
        symbol_count,
        symbols,
    })
}

fn sanitize_ident(raw: &str) -> String {
    let mut out: String = String::with_capacity(raw.len());
    for c in raw.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push('x');
    }
    out
}

fn java_string_escape(raw: &str) -> String {
    let mut out: String = String::with_capacity(raw.len() + 2);
    for c in raw.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

fn python_string_escape(raw: &str) -> String {
    java_string_escape(raw)
}

pub fn render_symbol_map_json(map: &SymbolMap) -> Result<String> {
    serde_json::to_string_pretty(map).map_err(|e| Error::Export {
        stage: "json-serialize",
        detail: e.to_string(),
    })
}

#[must_use]
pub fn render_ghidra_postscript(map: &SymbolMap) -> String {
    let mut body: String = String::with_capacity(map.symbols.len() * 96 + 1024);
    body.push_str(
        "import ghidra.app.script.GhidraScript;\n\
         import ghidra.program.model.address.Address;\n\
         import ghidra.program.model.symbol.SourceType;\n\
         import ghidra.program.model.listing.Function;\n\n\
         public class DisrobeApplySymbols extends GhidraScript {\n\
         \x20\x20\x20\x20@Override\n\
         \x20\x20\x20\x20public void run() throws Exception {\n\
         \x20\x20\x20\x20\x20\x20\x20\x20long base = currentProgram.getImageBase().getOffset();\n",
    );
    let _: core::fmt::Result = writeln!(
        body,
        "\x20\x20\x20\x20\x20\x20\x20\x20long disrobeBase = {disrobe_base}L;",
        disrobe_base = map.image_base
    );
    if let Some(oep) = map.original_entry_point {
        let oep: u64 = oep;
        let _: core::fmt::Result = writeln!(
            body,
            "\x20\x20\x20\x20\x20\x20\x20\x20applyEntry({oep}L, base, disrobeBase);"
        );
    }
    for sym in &map.symbols {
        let label: &str = sym.demangled.as_deref().unwrap_or(&sym.name);
        let is_func: bool = matches!(sym.class, SymbolClass::Function | SymbolClass::EntryPoint);
        let _: core::fmt::Result = writeln!(
            body,
            "\x20\x20\x20\x20\x20\x20\x20\x20applySymbol({addr}L, base, disrobeBase, \"{name}\", {func});",
            addr = sym.address,
            name = java_string_escape(label),
            func = is_func
        );
    }
    body.push_str(
        "\x20\x20\x20\x20}\n\n\
         \x20\x20\x20\x20private Address rebase(long disrobeAddr, long ghidraBase, long disrobeBase) {\n\
         \x20\x20\x20\x20\x20\x20\x20\x20long off = disrobeAddr - disrobeBase;\n\
         \x20\x20\x20\x20\x20\x20\x20\x20return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(ghidraBase + off);\n\
         \x20\x20\x20\x20}\n\n\
         \x20\x20\x20\x20private void applyEntry(long disrobeAddr, long ghidraBase, long disrobeBase) throws Exception {\n\
         \x20\x20\x20\x20\x20\x20\x20\x20Address a = rebase(disrobeAddr, ghidraBase, disrobeBase);\n\
         \x20\x20\x20\x20\x20\x20\x20\x20createFunction(a, \"disrobe_OEP\");\n\
         \x20\x20\x20\x20\x20\x20\x20\x20addEntryPoint(a);\n\
         \x20\x20\x20\x20}\n\n\
         \x20\x20\x20\x20private void applySymbol(long disrobeAddr, long ghidraBase, long disrobeBase, String name, boolean isFunc) throws Exception {\n\
         \x20\x20\x20\x20\x20\x20\x20\x20Address a = rebase(disrobeAddr, ghidraBase, disrobeBase);\n\
         \x20\x20\x20\x20\x20\x20\x20\x20if (isFunc) {\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20Function f = getFunctionAt(a);\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20if (f == null) { f = createFunction(a, name); }\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20if (f != null) { f.setName(name, SourceType.IMPORTED); }\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20else { createLabel(a, name, true, SourceType.IMPORTED); }\n\
         \x20\x20\x20\x20\x20\x20\x20\x20} else {\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20createLabel(a, name, true, SourceType.IMPORTED);\n\
         \x20\x20\x20\x20\x20\x20\x20\x20}\n\
         \x20\x20\x20\x20}\n\
         }\n",
    );
    body
}

#[must_use]
pub fn render_idapython(map: &SymbolMap) -> String {
    let mut body: String = String::with_capacity(map.symbols.len() * 80 + 512);
    body.push_str(
        "import idaapi\n\
         import idc\n\
         import ida_funcs\n\
         import ida_name\n\
         import ida_entry\n\n",
    );
    let _: core::fmt::Result = writeln!(body, "DISROBE_BASE = {base}", base = map.image_base);
    body.push_str("IDA_BASE = idaapi.get_imagebase()\n\n");
    body.push_str(
        "def _rebase(disrobe_addr):\n\
         \x20\x20\x20\x20return IDA_BASE + (disrobe_addr - DISROBE_BASE)\n\n\
         def _apply(disrobe_addr, name, is_func):\n\
         \x20\x20\x20\x20ea = _rebase(disrobe_addr)\n\
         \x20\x20\x20\x20if is_func and ida_funcs.get_func(ea) is None:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20ida_funcs.add_func(ea)\n\
         \x20\x20\x20\x20ida_name.set_name(ea, name, ida_name.SN_NOCHECK | ida_name.SN_FORCE)\n\n",
    );
    if let Some(oep) = map.original_entry_point {
        let oep: u64 = oep;
        let _: core::fmt::Result = writeln!(
            body,
            "ida_entry.add_entry(_rebase({oep}), _rebase({oep}), \"disrobe_OEP\", 1)"
        );
    }
    for sym in &map.symbols {
        let label: &str = sym.demangled.as_deref().unwrap_or(&sym.name);
        let is_func: bool = matches!(sym.class, SymbolClass::Function | SymbolClass::EntryPoint);
        let _: core::fmt::Result = writeln!(
            body,
            "_apply({addr}, \"{name}\", {func})",
            addr = sym.address,
            name = python_string_escape(label),
            func = if is_func { "True" } else { "False" }
        );
    }
    body.push_str("\nprint(\"disrobe: applied %d recovered symbols\" % ");
    let _: core::fmt::Result = write!(body, "{count})", count = map.symbols.len());
    body.push('\n');
    body
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use object::ObjectSection;

    use super::*;
    use crate::fixtures::minimal_pe32;

    const SECTION_ENTRY_SIZE: usize = 40;

    fn pe_with_named_sections(secs: &[(&[u8], u32, u32, &[u8])], ep_rva: u32) -> Vec<u8> {
        let opt_size: usize = 0xE0;
        let sec_off: usize = 0x80 + 4 + 20 + opt_size;
        let header_len: usize = sec_off + secs.len() * SECTION_ENTRY_SIZE;
        let mut buf: Vec<u8> = vec![0u8; header_len.max(0x200)];
        buf[0] = b'M';
        buf[1] = b'Z';
        let e_lfanew: u32 = 0x80;
        buf[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        let pe_off: usize = e_lfanew as usize;
        buf[pe_off..pe_off + 4].copy_from_slice(b"PE\x00\x00");
        let coff: usize = pe_off + 4;
        buf[coff..coff + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
        buf[coff + 2..coff + 4].copy_from_slice(&(secs.len() as u16).to_le_bytes());
        buf[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());
        let opt: usize = coff + 20;
        buf[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
        buf[opt + 16..opt + 20].copy_from_slice(&ep_rva.to_le_bytes());
        buf[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
        buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        buf[opt + 56..opt + 60].copy_from_slice(&0x4000u32.to_le_bytes());
        let mut bodies: Vec<(usize, Vec<u8>)> = Vec::new();
        let mut raw_cursor: usize = header_len.max(0x200);
        for (i, (name, va, raw_off, data)) in secs.iter().enumerate() {
            let base: usize = sec_off + i * SECTION_ENTRY_SIZE;
            buf[base..base + name.len().min(8)].copy_from_slice(&name[..name.len().min(8)]);
            buf[base + 8..base + 12].copy_from_slice(&(data.len() as u32).to_le_bytes());
            buf[base + 12..base + 16].copy_from_slice(&va.to_le_bytes());
            buf[base + 16..base + 20].copy_from_slice(&(data.len() as u32).to_le_bytes());
            buf[base + 20..base + 24].copy_from_slice(&raw_off.to_le_bytes());
            buf[base + 36..base + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
            bodies.push((*raw_off as usize, (*data).to_vec()));
            raw_cursor = raw_cursor.max(*raw_off as usize + data.len());
        }
        buf.resize(raw_cursor, 0);
        for (off, data) in bodies {
            buf[off..off + data.len()].copy_from_slice(&data);
        }
        buf
    }

    #[test]
    fn rebuild_overlays_memory_image_by_virtual_address() {
        let stub_text: [u8; 64] = [0x60; 64];
        let packed: Vec<u8> =
            pe_with_named_sections(&[(b".text", 0x1000, 0x400, &stub_text)], 0x1000);

        let mut loaded: Vec<u8> = vec![0u8; 0x4000];
        loaded[0] = b'M';
        loaded[1] = b'Z';
        let real_code: [u8; 64] = [0x90; 64];
        loaded[0x1000..0x1000 + real_code.len()].copy_from_slice(&real_code);

        let rebuilt: RebuiltImage =
            rebuild_unpacked_pe(&packed, &loaded, None).expect("rebuild ok");
        assert_eq!(rebuilt.layout, RebuildLayout::MemoryImageOverlay);
        assert_eq!(rebuilt.sections_overlaid, 1);
        assert_eq!(
            &rebuilt.bytes[0x400..0x400 + 64],
            &real_code,
            "memory-image .text content must land at the .text raw offset"
        );
        assert!(
            object::File::parse(rebuilt.bytes.as_slice()).is_ok(),
            "rebuilt PE must re-parse"
        );
    }

    #[test]
    fn rebuild_places_bare_code_block_in_place_when_it_fits() {
        let stub_text: [u8; 64] = [0x60; 64];
        let packed: Vec<u8> =
            pe_with_named_sections(&[(b".text", 0x1000, 0x400, &stub_text)], 0x1000);
        let real_code: Vec<u8> = vec![0x90u8; 32];
        let rebuilt: RebuiltImage =
            rebuild_unpacked_pe(&packed, &real_code, None).expect("rebuild ok");
        assert_eq!(rebuilt.layout, RebuildLayout::BareBlockPlacement);
        assert_eq!(rebuilt.bytes_placed, 32);
        assert_eq!(
            &rebuilt.bytes[0x400..0x400 + 32],
            real_code.as_slice(),
            "a recovered block that fits the section raw size must overwrite the stub in place"
        );
        assert_eq!(
            rebuilt.bytes.len(),
            packed.len(),
            "in-place placement must not grow the file"
        );
        assert!(object::File::parse(rebuilt.bytes.as_slice()).is_ok());
    }

    #[test]
    fn rebuild_appends_and_repoints_when_block_exceeds_section() {
        let stub_text: [u8; 32] = [0x60; 32];
        let packed: Vec<u8> =
            pe_with_named_sections(&[(b".text", 0x1000, 0x400, &stub_text)], 0x1000);
        let original_len: usize = packed.len();
        let real_code: Vec<u8> = (0..200u32).map(|i: u32| (i & 0xFF) as u8).collect();
        let rebuilt: RebuiltImage =
            rebuild_unpacked_pe(&packed, &real_code, None).expect("rebuild ok");
        assert_eq!(rebuilt.layout, RebuildLayout::BareBlockPlacement);
        assert_eq!(rebuilt.bytes_placed, 200);
        assert_eq!(
            &rebuilt.bytes[original_len..original_len + 200],
            real_code.as_slice(),
            "an oversized recovered block must be appended at the file end"
        );

        let parsed: object::File<'_> =
            object::File::parse(rebuilt.bytes.as_slice()).expect("rebuilt PE must re-parse");
        let text: object::Section<'_, '_> = parsed
            .sections()
            .find(|s: &object::Section<'_, '_>| s.name().ok() == Some(".text"))
            .expect(".text section");
        let data: &[u8] = text.data().expect(".text data");
        assert_eq!(
            &data[..200],
            real_code.as_slice(),
            "the repointed .text section must now resolve to the full recovered code block"
        );
    }

    #[test]
    fn rebuild_restores_oep_into_optional_header() {
        let stub_text: [u8; 32] = [0xCC; 32];
        let packed: Vec<u8> =
            pe_with_named_sections(&[(b".text", 0x1000, 0x400, &stub_text)], 0x1500);
        let loaded: Vec<u8> = vec![0u8; 0x2000];
        let oep_va: u64 = 0x0040_0000 + 0x1234;
        let rebuilt: RebuiltImage =
            rebuild_unpacked_pe(&packed, &loaded, Some(oep_va)).expect("rebuild ok");
        assert_eq!(rebuilt.restored_entry_point_rva, Some(0x1234));
        let parsed: object::File<'_> =
            object::File::parse(rebuilt.bytes.as_slice()).expect("reparse");
        assert_eq!(
            parsed.entry(),
            0x0040_0000 + 0x1234,
            "object reports PE entry as the absolute VA (image_base + restored RVA)"
        );
    }

    #[test]
    fn collect_symbols_marks_recovered_oep_only_when_supplied() {
        let text: [u8; 32] = [0x90; 32];
        let pe: Vec<u8> = pe_with_named_sections(&[(b".text", 0x1000, 0x400, &text)], 0x1000);
        let recovered_oep: u64 = 0x0040_1000;
        let map: SymbolMap =
            collect_recovered_symbols_with_oep(&pe, Some(recovered_oep)).expect("collect");
        assert_eq!(map.schema, SYMBOL_MAP_SCHEMA);
        assert_eq!(map.original_entry_point, Some(recovered_oep));
        assert!(
            map.symbols.iter().any(|s: &RecoveredSymbol| s.origin
                == SymbolOrigin::OriginalEntryPoint
                && s.name == "disrobe_OEP"),
            "recovered OEP marker must be emitted when a recovered OEP VA is supplied"
        );
    }

    #[test]
    fn collect_symbols_does_not_claim_oep_when_unrecovered() {
        let text: [u8; 32] = [0x90; 32];
        let pe: Vec<u8> = pe_with_named_sections(&[(b".text", 0x1000, 0x400, &text)], 0x1000);
        let map: SymbolMap = collect_recovered_symbols(&pe).expect("collect");
        assert_eq!(
            map.original_entry_point, None,
            "with no recovered OEP, the map must not claim an original entry point"
        );
        assert!(
            map.symbols
                .iter()
                .all(|s: &RecoveredSymbol| s.name != "disrobe_OEP"),
            "the packer-stub entry must never be mislabeled as the recovered OEP"
        );
        assert!(
            map.symbols
                .iter()
                .any(|s: &RecoveredSymbol| s.name == "disrobe_packed_entry"),
            "the current (stub) entry should be surfaced as a distinct labeled marker"
        );
    }

    #[test]
    fn collect_symbols_handles_minimal_pe_without_entry() {
        let pe: Vec<u8> = minimal_pe32();
        let map: SymbolMap = collect_recovered_symbols(&pe).expect("collect");
        assert_eq!(map.schema, SYMBOL_MAP_SCHEMA);
        assert_eq!(
            map.original_entry_point, None,
            "minimal PE has a zero entry RVA; no OEP marker should be fabricated"
        );
    }

    #[test]
    fn ghidra_script_is_well_formed_java() {
        let map: SymbolMap = SymbolMap {
            schema: SYMBOL_MAP_SCHEMA,
            source: "x".to_owned(),
            format: "pe".to_owned(),
            image_base: 0x0040_0000,
            original_entry_point: Some(0x0040_1234),
            symbol_count: 1,
            symbols: vec![RecoveredSymbol {
                address: 0x0040_2000,
                name: "_ZN4core3fmt5Write9write_fmt17habcdE".to_owned(),
                demangled: Some("core::fmt::Write::write_fmt".to_owned()),
                class: SymbolClass::Function,
                origin: SymbolOrigin::SymbolTable,
                note: None,
            }],
        };
        let java: String = render_ghidra_postscript(&map);
        assert!(java.contains("public class DisrobeApplySymbols extends GhidraScript"));
        assert!(java.contains("applyEntry(4198964L"));
        assert!(java.contains("core::fmt::Write::write_fmt"));
        assert_eq!(
            java.matches('{').count(),
            java.matches('}').count(),
            "java braces must balance"
        );
    }

    #[test]
    fn idapython_is_well_formed() {
        let map: SymbolMap = SymbolMap {
            schema: SYMBOL_MAP_SCHEMA,
            source: "x".to_owned(),
            format: "pe".to_owned(),
            image_base: 0x0040_0000,
            original_entry_point: Some(0x0040_1234),
            symbol_count: 1,
            symbols: vec![RecoveredSymbol {
                address: 0x0040_2000,
                name: "main".to_owned(),
                demangled: None,
                class: SymbolClass::Function,
                origin: SymbolOrigin::SymbolTable,
                note: None,
            }],
        };
        let py: String = render_idapython(&map);
        assert!(py.contains("DISROBE_BASE = 4194304"));
        assert!(py.contains("ida_entry.add_entry"));
        assert!(py.contains("_apply(4202496, \"main\", True)"));
    }

    #[test]
    fn passthrough_rejects_non_object_bytes() {
        let err: Error = rebuild_passthrough(b"not an object").expect_err("must reject");
        assert!(matches!(err, Error::Export { .. }));
    }

    #[test]
    fn rebuild_rejects_non_pe_packed() {
        let err: Error =
            rebuild_unpacked_pe(b"not a pe at all", &[0u8; 16], None).expect_err("reject");
        assert!(matches!(err, Error::Export { .. }));
    }
}
