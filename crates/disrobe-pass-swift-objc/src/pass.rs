use serde::{Deserialize, Serialize};

use crate::code_signature::{self, CodeSignature};
use crate::error::Error;
use crate::fairplay::{self, FairPlayStatus};
use crate::ipa::{self, EmbeddedImage, EmbeddedImageRole, IpaInventory};
use crate::macho::{self, FatArchEntry, MachoKind, ParsedSlice};
use crate::native_bodies::{self, NativeBodyReport};
use crate::objc::{self, ObjcClassDump};
use crate::objc_records;
use crate::swift::{self, SwiftClassDump};
use crate::swift_reflect::{self, SwiftTypeReflection};
use crate::swiftinterface::{self, ParsedInterface};
use crate::swiftmodule::{self, SwiftModuleDecls};
use crate::toolchain::{self, ToolchainReport};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftObjcReport {
    pub container: ContainerKind,
    pub ipa: Option<IpaInventory>,
    pub fat_entries: Vec<FatArchEntry>,
    pub slices: Vec<SliceReport>,
    pub embedded_images: Vec<EmbeddedImageReport>,
    pub unanalyzed_embedded_images: Vec<UnanalyzedEmbeddedImage>,
    pub swift_module: Option<SwiftModuleDecls>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedImageReport {
    pub path: String,
    pub role: EmbeddedImageRole,
    pub fat_entries: Vec<FatArchEntry>,
    pub slices: Vec<SliceReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnanalyzedEmbeddedImage {
    pub path: String,
    pub role: EmbeddedImageRole,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainerKind {
    Ipa,
    MachO,
    SwiftModule,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SliceReport {
    pub cpu_label: String,
    pub bitness_bits: u32,
    pub metadata_summary: MetadataSummary,
    pub swift: SwiftClassDump,
    pub objc: ObjcClassDump,
    pub fairplay: FairPlayStatus,
    pub code_signature: Option<CodeSignature>,
    pub toolchain: ToolchainReport,
    pub native_bodies: NativeBodyReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataSummary {
    pub objc_classes: usize,
    pub objc_interfaces_recovered: usize,
    pub objc_categories_recovered: usize,
    pub objc_protocols_recovered: usize,
    pub objc_methods_recovered: usize,
    pub objc_typed_methods: usize,
    pub objc_unique_selectors: usize,
    pub objc_unique_method_types: usize,
    pub objc_unique_class_names: usize,
    pub swift_reflected_types: usize,
    pub swift_named_types: usize,
    pub swift_nominal_types: usize,
    pub swift_protocols: usize,
    pub swift_conformances: usize,
    pub swift_associated_types: usize,
    pub swift_mangled_symbols: usize,
    pub swift_demangled_symbols: usize,
}

pub fn analyze(bytes: &[u8]) -> crate::error::Result<SwiftObjcReport> {
    crate::debug::dbg_section("swift-objc analyze");
    crate::debug::dbg_kv("input-len", || bytes.len().to_string());
    crate::debug::dbg_hex("input-magic", bytes, 8);
    if zip_like(bytes)
        && let Ok(inv) = ipa::inventory(bytes)
    {
        crate::debug::dbg_kv("classify", || {
            "ipa/zip (PK\\x03\\x04 local header)".to_owned()
        });
        crate::debug::dbg_kv("ipa-inventory", || {
            format!(
                "app_dir={} bundle_name={} entries={} frameworks={} plugins={} info_plist={:?}",
                inv.app_dir,
                inv.bundle_name,
                inv.entries.len(),
                inv.frameworks.len(),
                inv.plugins.len(),
                inv.info_plist_path
            )
        });
        let mut slices: Vec<SliceReport> = Vec::new();
        let mut fat_entries: Vec<FatArchEntry> = Vec::new();
        if let Some(path) = inv.main_binary_path.as_deref() {
            crate::debug::dbg_kv("ipa-main-binary", || path.to_owned());
            if let Some(bin) = read_zip_entry_bytes(bytes, path)? {
                crate::debug::dbg_kv("ipa-main-binary-len", || bin.len().to_string());
                let (e, s): (Vec<FatArchEntry>, Vec<SliceReport>) = analyze_macho(&bin)?;
                fat_entries = e;
                slices = s;
            } else {
                crate::debug::dbg_kv("ipa-main-binary", || {
                    format!("entry {path} not present in archive")
                });
            }
        } else {
            crate::debug::dbg_kv("ipa-main-binary", || {
                "no main binary path in Info.plist".to_owned()
            });
        }
        recover_interface_field_names(bytes, &inv, &mut slices);
        let (embedded_images, unanalyzed_embedded_images): (
            Vec<EmbeddedImageReport>,
            Vec<UnanalyzedEmbeddedImage>,
        ) = analyze_embedded_images(bytes, &inv);
        return Ok(SwiftObjcReport {
            container: ContainerKind::Ipa,
            ipa: Some(inv),
            fat_entries,
            slices,
            embedded_images,
            unanalyzed_embedded_images,
            swift_module: None,
        });
    }
    if let Some(kind) = macho::detect_magic(bytes) {
        crate::debug::dbg_kv("classify", || format!("mach-o ({kind:?})"));
        let (fat_entries, slices): (Vec<FatArchEntry>, Vec<SliceReport>) = analyze_macho(bytes)?;
        return Ok(SwiftObjcReport {
            container: ContainerKind::MachO,
            ipa: None,
            fat_entries,
            slices,
            embedded_images: Vec::new(),
            unanalyzed_embedded_images: Vec::new(),
            swift_module: None,
        });
    }
    if swiftmodule::is_swift_module(bytes) {
        crate::debug::dbg_kv("classify", || {
            "swift serialized module (signature E2 9C A8 0E)".to_owned()
        });
        let decls: SwiftModuleDecls = swiftmodule::read(bytes)?;
        return Ok(SwiftObjcReport {
            container: ContainerKind::SwiftModule,
            ipa: None,
            fat_entries: Vec::new(),
            slices: Vec::new(),
            embedded_images: Vec::new(),
            unanalyzed_embedded_images: Vec::new(),
            swift_module: Some(decls),
        });
    }
    crate::debug::dbg_kv("classify", || {
        "other (not zip/ipa, not mach-o magic, not swift module)".to_owned()
    });
    Ok(SwiftObjcReport {
        container: ContainerKind::Other,
        ipa: None,
        fat_entries: Vec::new(),
        slices: Vec::new(),
        embedded_images: Vec::new(),
        unanalyzed_embedded_images: Vec::new(),
        swift_module: None,
    })
}

const MAX_EMBEDDED_IMAGES: usize = 256;

fn analyze_embedded_images(
    image: &[u8],
    inv: &IpaInventory,
) -> (Vec<EmbeddedImageReport>, Vec<UnanalyzedEmbeddedImage>) {
    let mut reports: Vec<EmbeddedImageReport> = Vec::new();
    let mut unanalyzed: Vec<UnanalyzedEmbeddedImage> = Vec::new();
    let embedded: Vec<EmbeddedImage> = match ipa::embedded_images(image, inv) {
        Ok(found) => found,
        Err(error) => {
            crate::debug::dbg_kv("ipa-embedded-images", || {
                format!("enumeration failed: {error}")
            });
            return (reports, unanalyzed);
        }
    };
    crate::debug::dbg_kv("ipa-embedded-images", || {
        format!(
            "mach-o images under Frameworks/ and PlugIns/: {}",
            embedded.len()
        )
    });
    for entry in embedded.iter().take(MAX_EMBEDDED_IMAGES) {
        match read_zip_entry_bytes(image, &entry.path) {
            Ok(Some(bytes)) => match analyze_macho(&bytes) {
                Ok((fat_entries, slices)) => reports.push(EmbeddedImageReport {
                    path: entry.path.clone(),
                    role: entry.role,
                    fat_entries,
                    slices,
                }),
                Err(error) => unanalyzed.push(UnanalyzedEmbeddedImage {
                    path: entry.path.clone(),
                    role: entry.role,
                    reason: format!("the slice does not parse as Mach-O: {error}"),
                }),
            },
            Ok(None) => unanalyzed.push(UnanalyzedEmbeddedImage {
                path: entry.path.clone(),
                role: entry.role,
                reason: "the archive no longer lists this entry".to_owned(),
            }),
            Err(error) => unanalyzed.push(UnanalyzedEmbeddedImage {
                path: entry.path.clone(),
                role: entry.role,
                reason: format!("the entry could not be read out of the archive: {error}"),
            }),
        }
    }
    for entry in embedded.iter().skip(MAX_EMBEDDED_IMAGES) {
        unanalyzed.push(UnanalyzedEmbeddedImage {
            path: entry.path.clone(),
            role: entry.role,
            reason: format!(
                "the archive carries more than the {MAX_EMBEDDED_IMAGES} embedded images this pass \
                 analyzes in one run"
            ),
        });
    }
    (reports, unanalyzed)
}

fn analyze_macho(bytes: &[u8]) -> crate::error::Result<(Vec<FatArchEntry>, Vec<SliceReport>)> {
    let kind: MachoKind = macho::detect_magic(bytes).ok_or(Error::NotMachO)?;
    match kind {
        MachoKind::Fat32 | MachoKind::Fat64 => {
            let entries: Vec<FatArchEntry> = macho::walk_fat(bytes)?;
            crate::debug::dbg_kv("fat-arch-count", || entries.len().to_string());
            let mut reports: Vec<SliceReport> = Vec::with_capacity(entries.len());
            for (idx, entry) in entries.iter().enumerate() {
                crate::debug::dbg_kv("fat-arch", || {
                    format!(
                        "[{idx}] cpu={} offset={:#x} size={}",
                        entry.cpu.label(),
                        entry.offset,
                        entry.size
                    )
                });
                let Some(slice): Option<&[u8]> = macho::slice_bytes(bytes, entry) else {
                    crate::debug::dbg_line(|| {
                        format!("fat-arch [{idx}] bail: slice range out of image bounds")
                    });
                    continue;
                };
                if macho::detect_magic(slice).is_none() {
                    crate::debug::dbg_line(|| {
                        format!("fat-arch [{idx}] bail: slice has no mach-o magic")
                    });
                    continue;
                }
                let parsed: ParsedSlice = macho::parse_slice(slice)?;
                reports.push(build_slice_report(slice, &parsed));
            }
            Ok((entries, reports))
        }
        _ => {
            crate::debug::dbg_kv("thin-slice", || format!("kind={kind:?}"));
            let parsed: ParsedSlice = macho::parse_slice(bytes)?;
            let report: SliceReport = build_slice_report(bytes, &parsed);
            Ok((Vec::new(), vec![report]))
        }
    }
}

fn build_slice_report(slice: &[u8], parsed: &ParsedSlice) -> SliceReport {
    crate::debug::dbg_section("slice");
    crate::debug::dbg_kv("slice-header", || {
        format!(
            "cpu={} bitness={:?} endian={:?} filetype={:#x} ncmds={} segments={} symtab={}",
            parsed.header.cpu.label(),
            parsed.header.bitness,
            parsed.header.endian,
            parsed.header.filetype,
            parsed.header.ncmds,
            parsed.segments.len(),
            parsed.symtab.is_some()
        )
    });
    let swift_dump: SwiftClassDump = swift::class_dump(slice, parsed);
    crate::debug::dbg_kv("swift-sections", || {
        format!(
            "types={} protos={} proto_conf={} fieldmd={} assocty={} reflstr={}",
            section_present(swift_dump.types_section.is_some()),
            section_present(swift_dump.protos_section.is_some()),
            section_present(swift_dump.proto_conf_section.is_some()),
            section_present(swift_dump.fieldmd_section.is_some()),
            section_present(swift_dump.assocty_section.is_some()),
            section_present(swift_dump.reflection_strings.is_some())
        )
    });
    crate::debug::dbg_kv("swift-typedump", || {
        format!(
            "reflected_types={} nominal={} protocols={} conformances={} associated_types={}",
            swift_dump.reflected_types.len(),
            swift_dump.type_dump.nominal_types.len(),
            swift_dump.type_dump.protocols.len(),
            swift_dump.type_dump.conformances.len(),
            swift_dump.type_dump.associated_types.len()
        )
    });
    let mangled: usize = swift_dump.mangled_symbols.len();
    let demangled: usize = swift_dump.demangled.len();
    crate::debug::dbg_kv("swift-demangle", || {
        format!(
            "mangled_symbols={mangled} demangled_ok={demangled} demangle_failures={}",
            mangled.saturating_sub(demangled)
        )
    });
    if crate::debug::dbg_enabled() {
        for sym in &swift_dump.mangled_symbols {
            if !swift_dump.demangled.contains_key(sym) {
                crate::debug::dbg_line(|| format!("swift-demangle bail: {sym}"));
            }
        }
    }
    let objc_dump: ObjcClassDump = objc::class_dump(slice, parsed);
    crate::debug::dbg_kv("objc-metadata", || {
        format!(
            "classes={} categories={} protocols={} selrefs={} unique_selectors={} unique_method_types={} unique_class_names={}",
            objc_dump.class_count,
            objc_dump.category_count,
            objc_dump.protocol_count,
            objc_dump.selrefs_count,
            objc_dump.unique_selectors.len(),
            objc_dump.unique_method_types.len(),
            objc_dump.unique_class_names.len()
        )
    });
    let objc_methods: usize = objc_dump
        .interfaces
        .iter()
        .map(|i: &objc_records::ObjcInterface| i.instance_methods.len() + i.class_methods.len())
        .sum();
    let objc_ivars: usize = objc_dump
        .interfaces
        .iter()
        .map(|i: &objc_records::ObjcInterface| i.ivars.len())
        .sum();
    crate::debug::dbg_kv("objc-interfaces", || {
        format!(
            "recovered={} methods={objc_methods} ivars={objc_ivars} categories={} protocols={}",
            objc_dump.interfaces.len(),
            objc_dump.categories.len(),
            objc_dump.protocols.len()
        )
    });
    if let Some(notice) = objc_dump.encrypted_text.as_ref() {
        crate::debug::dbg_kv("encrypted-at-rest", || {
            format!(
                "cryptid={} range={}..{} withheld_sections={}",
                notice.crypt_id,
                notice.file_off,
                notice.file_end,
                notice.withheld_sections.len()
            )
        });
    }
    let fp: FairPlayStatus = fairplay::detect(parsed);
    crate::debug::dbg_kv("fairplay", || format!("{fp:?}"));
    let signature: Option<CodeSignature> = code_signature::parse(slice, parsed);
    crate::debug::dbg_kv("code-signature", || {
        signature.as_ref().map_or_else(
        || "absent or not an embedded signature superblob".to_owned(),
        |sig: &CodeSignature| format!(
            "slots={} identifier={:?} team={:?} adhoc={} cms={} entitlements={} covers_image={} pages={}",
            sig.slot_count,
            sig.code_directory
                .as_ref()
                .and_then(|d: &crate::code_signature::CodeDirectory| d.identifier.clone()),
            sig.code_directory
                .as_ref()
                .and_then(|d: &crate::code_signature::CodeDirectory| d.team_id.clone()),
            sig.is_adhoc_signed,
            sig.has_cms_signature,
            sig.entitlements_xml.is_some(),
            sig.coverage.covers_all_bytes_before_signature,
            sig.page_hashes.verdict.label(),
        ),
        )
    });
    let toolchain_report: ToolchainReport = toolchain::report(slice, parsed);
    crate::debug::dbg_kv("chained-fixups", || {
        toolchain_report
            .chained_pointer_formats
            .iter()
            .map(|format: &crate::objc_dispatch::ChainedPointerFormat| format.label())
            .collect::<Vec<&'static str>>()
            .join(",")
    });
    crate::debug::dbg_kv("toolchain", || {
        format!(
            "filetype={} platform={:?} minos={:?} sdk={:?} swift_runtime={} objc_runtime={} symbols={} dylibs={}",
            toolchain_report.file_type,
            toolchain_report.platform,
            toolchain_report.min_os_version,
            toolchain_report.sdk_version,
            toolchain_report.links_swift_runtime,
            toolchain_report.links_objc_runtime,
            toolchain_report.symbol_state.label(),
            toolchain_report.dylib_count,
        )
    });
    let bits: u32 = match parsed.header.bitness {
        macho::Bitness::Bits32 => 32,
        macho::Bitness::Bits64 => 64,
    };
    let metadata_summary: MetadataSummary = summarize(&swift_dump, &objc_dump);
    let native: NativeBodyReport = native_bodies::recover_native_bodies(slice, parsed);
    crate::debug::dbg_kv("native-bodies", || {
        format!(
            "dwarf={} grade={} recoverable={} types={} line-coverage={:.1}% disasm_arch={} functions={}",
            native.dwarf_present,
            native.grade.label(),
            native.source_recoverable,
            native.named_type_count,
            native.line_coverage_pct,
            native.disasm_arch_supported,
            native.functions.len(),
        )
    });
    SliceReport {
        cpu_label: parsed.header.cpu.label().to_owned(),
        bitness_bits: bits,
        metadata_summary,
        swift: swift_dump,
        objc: objc_dump,
        fairplay: fp,
        code_signature: signature,
        toolchain: toolchain_report,
        native_bodies: native,
    }
}

fn summarize(swift: &SwiftClassDump, objc: &ObjcClassDump) -> MetadataSummary {
    let objc_methods_recovered: usize = objc
        .interfaces
        .iter()
        .map(|i: &objc_records::ObjcInterface| i.instance_methods.len() + i.class_methods.len())
        .sum();
    let objc_typed_methods: usize = objc
        .interfaces
        .iter()
        .flat_map(|i: &objc_records::ObjcInterface| {
            i.instance_methods.iter().chain(i.class_methods.iter())
        })
        .filter(|m: &&objc_records::ObjcMethod| m.types.is_some())
        .count();
    let swift_named_types: usize = swift
        .reflected_types
        .iter()
        .filter(|t: &&swift_reflect::SwiftTypeReflection| {
            t.demangled_type_name.is_some() || t.mangled_type_name.is_some()
        })
        .count();
    MetadataSummary {
        objc_classes: objc.class_count,
        objc_interfaces_recovered: objc.interfaces.len(),
        objc_categories_recovered: objc.categories.len(),
        objc_protocols_recovered: objc.protocols.len(),
        objc_methods_recovered,
        objc_typed_methods,
        objc_unique_selectors: objc.unique_selectors.len(),
        objc_unique_method_types: objc.unique_method_types.len(),
        objc_unique_class_names: objc.unique_class_names.len(),
        swift_reflected_types: swift.reflected_types.len(),
        swift_named_types,
        swift_nominal_types: swift.type_dump.nominal_types.len(),
        swift_protocols: swift.type_dump.protocols.len(),
        swift_conformances: swift.type_dump.conformances.len(),
        swift_associated_types: swift.type_dump.associated_types.len(),
        swift_mangled_symbols: swift.mangled_symbols.len(),
        swift_demangled_symbols: swift.demangled.len(),
    }
}

const fn section_present(present: bool) -> &'static str {
    if present { "yes" } else { "absent" }
}

fn zip_like(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && &bytes[..4] == b"PK\x03\x04"
}

const SWIFTINTERFACE_SUFFIX: &str = ".swiftinterface";

fn recover_interface_field_names(image: &[u8], inv: &IpaInventory, slices: &mut [SliceReport]) {
    let interface_paths: Vec<&str> = inv
        .entries
        .iter()
        .filter(|e: &&crate::ipa::IpaEntry| e.name.ends_with(SWIFTINTERFACE_SUFFIX))
        .map(|e: &crate::ipa::IpaEntry| e.name.as_str())
        .collect();
    if interface_paths.is_empty() || slices.is_empty() {
        return;
    }
    let mut interfaces: Vec<ParsedInterface> = Vec::with_capacity(interface_paths.len());
    for path in interface_paths {
        let Ok(Some(raw)): crate::error::Result<Option<Vec<u8>>> =
            read_zip_entry_bytes(image, path)
        else {
            continue;
        };
        let Ok(text): core::result::Result<&str, _> = std::str::from_utf8(&raw) else {
            continue;
        };
        interfaces.push(swiftinterface::parse(text));
    }
    if interfaces.is_empty() {
        return;
    }
    let mut filled_total: usize = 0;
    for slice in slices.iter_mut() {
        for interface in &interfaces {
            let taken: Vec<SwiftTypeReflection> = std::mem::take(&mut slice.swift.reflected_types);
            let (merged, filled): (Vec<SwiftTypeReflection>, usize) =
                swiftinterface::merge_elided_field_names(taken, interface);
            slice.swift.reflected_types = merged;
            filled_total += filled;
        }
    }
    crate::debug::dbg_kv("ipa-interface-field-recovery", || {
        format!(
            "interfaces={} fields_recovered={filled_total}",
            interfaces.len()
        )
    });
}

const MAX_ZIP_ENTRY: u64 = 64 * 1024 * 1024;

fn read_zip_entry_bytes(image: &[u8], name: &str) -> crate::error::Result<Option<Vec<u8>>> {
    use std::io::Cursor;
    let mut archive: zip::ZipArchive<Cursor<&[u8]>> = zip::ZipArchive::new(Cursor::new(image))
        .map_err(|e: zip::result::ZipError| Error::Ipa(e.to_string()))?;
    match archive.by_name(name) {
        Ok(f) => {
            let uncompressed: u64 = f.size();
            let compressed: u64 = f.compressed_size();
            Ok(Some(ipa::read_zip_entry_limited(
                f,
                name,
                uncompressed,
                compressed,
                MAX_ZIP_ENTRY,
            )?))
        }
        Err(zip::result::ZipError::FileNotFound) => Ok(None),
        Err(e) => Err(Error::Ipa(e.to_string())),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn analyze_unknown_returns_other() {
        let report: SwiftObjcReport = analyze(b"hello world\0not a binary").expect("analyze ok");
        assert_eq!(report.container, ContainerKind::Other);
        assert!(report.slices.is_empty());
    }
}
