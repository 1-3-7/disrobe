use disrobe_core::{Artifact, Capability, LegacyPass, PassId, Result as CoreResult, Rung};
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::fairplay::{self, FairPlayStatus};
use crate::ipa::{self, IpaInventory};
use crate::macho::{self, FatArchEntry, MachoKind, ParsedSlice};
use crate::objc::{self, ObjcClassDump};
use crate::objc_records;
use crate::swift::{self, SwiftClassDump};
use crate::swift_reflect;

#[derive(Debug, Default)]
pub struct SwiftObjcPass;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftObjcReport {
    pub container: ContainerKind,
    pub ipa: Option<IpaInventory>,
    pub fat_entries: Vec<FatArchEntry>,
    pub slices: Vec<SliceReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainerKind {
    Ipa,
    MachO,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataSummary {
    pub objc_classes: usize,
    pub objc_interfaces_recovered: usize,
    pub objc_methods_recovered: usize,
    pub objc_typed_methods: usize,
    pub objc_unique_selectors: usize,
    pub objc_unique_method_types: usize,
    pub objc_unique_class_names: usize,
    pub swift_reflected_types: usize,
    pub swift_named_types: usize,
    pub swift_mangled_symbols: usize,
    pub swift_demangled_symbols: usize,
}

pub const PASS_ID: PassId = "ios.swift_objc";

impl LegacyPass for SwiftObjcPass {
    const CONSUMES: &'static [Rung] = &[Rung::Raw];
    const EMITS: &'static [Rung] = &[Rung::Disasm];
    const REQUIRES: &'static [fn() -> Capability] = &[];
    const PRODUCES: &'static [fn() -> Capability] =
        &[|| Capability::produces("ios.swift_objc.dump", 1)];

    fn id(&self) -> PassId {
        PASS_ID
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let report: SwiftObjcReport = analyze(&artifact.envelope)
            .map_err(|e: Error| disrobe_core::CoreError::PassFailure(e.to_string()))?;
        let envelope: Vec<u8> = serde_json::to_vec(&report)
            .map_err(|e: serde_json::Error| disrobe_core::CoreError::PassFailure(e.to_string()))?;
        let mut next: Artifact = Artifact::new(Rung::Disasm, envelope, artifact.root_hash);
        for emitter in <Self as LegacyPass>::PRODUCES {
            next.add_capability(emitter());
        }
        Ok(next)
    }
}

pub fn analyze(bytes: &[u8]) -> crate::error::Result<SwiftObjcReport> {
    if zip_like(bytes)
        && let Ok(inv) = ipa::inventory(bytes)
    {
        let mut slices: Vec<SliceReport> = Vec::new();
        let mut fat_entries: Vec<FatArchEntry> = Vec::new();
        if let Some(path) = inv.main_binary_path.as_deref()
            && let Some(bin) = read_zip_entry_bytes(bytes, path)?
        {
            let (e, s): (Vec<FatArchEntry>, Vec<SliceReport>) = analyze_macho(&bin)?;
            fat_entries = e;
            slices = s;
        }
        return Ok(SwiftObjcReport {
            container: ContainerKind::Ipa,
            ipa: Some(inv),
            fat_entries,
            slices,
        });
    }
    if let Some(kind) = macho::detect_magic(bytes) {
        let _ = kind;
        let (fat_entries, slices): (Vec<FatArchEntry>, Vec<SliceReport>) = analyze_macho(bytes)?;
        return Ok(SwiftObjcReport {
            container: ContainerKind::MachO,
            ipa: None,
            fat_entries,
            slices,
        });
    }
    Ok(SwiftObjcReport {
        container: ContainerKind::Other,
        ipa: None,
        fat_entries: Vec::new(),
        slices: Vec::new(),
    })
}

fn analyze_macho(bytes: &[u8]) -> crate::error::Result<(Vec<FatArchEntry>, Vec<SliceReport>)> {
    let kind: MachoKind = macho::detect_magic(bytes).ok_or(Error::NotMachO)?;
    match kind {
        MachoKind::Fat32 | MachoKind::Fat64 => {
            let entries: Vec<FatArchEntry> = macho::walk_fat(bytes)?;
            let mut reports: Vec<SliceReport> = Vec::with_capacity(entries.len());
            for entry in &entries {
                if let Some(slice) = macho::slice_bytes(bytes, entry)
                    && macho::detect_magic(slice).is_some()
                {
                    let parsed: ParsedSlice = macho::parse_slice(slice)?;
                    reports.push(build_slice_report(slice, &parsed));
                }
            }
            Ok((entries, reports))
        }
        _ => {
            let parsed: ParsedSlice = macho::parse_slice(bytes)?;
            let report: SliceReport = build_slice_report(bytes, &parsed);
            Ok((Vec::new(), vec![report]))
        }
    }
}

fn build_slice_report(slice: &[u8], parsed: &ParsedSlice) -> SliceReport {
    let swift_dump: SwiftClassDump = swift::class_dump(slice, parsed);
    let objc_dump: ObjcClassDump = objc::class_dump(slice, parsed);
    let fp: FairPlayStatus = fairplay::detect(parsed);
    let bits: u32 = match parsed.header.bitness {
        macho::Bitness::Bits32 => 32,
        macho::Bitness::Bits64 => 64,
    };
    let metadata_summary: MetadataSummary = summarize(&swift_dump, &objc_dump);
    SliceReport {
        cpu_label: parsed.header.cpu.label().to_owned(),
        bitness_bits: bits,
        metadata_summary,
        swift: swift_dump,
        objc: objc_dump,
        fairplay: fp,
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
        objc_methods_recovered,
        objc_typed_methods,
        objc_unique_selectors: objc.unique_selectors.len(),
        objc_unique_method_types: objc.unique_method_types.len(),
        objc_unique_class_names: objc.unique_class_names.len(),
        swift_reflected_types: swift.reflected_types.len(),
        swift_named_types,
        swift_mangled_symbols: swift.mangled_symbols.len(),
        swift_demangled_symbols: swift.demangled.len(),
    }
}

fn zip_like(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && &bytes[..4] == b"PK\x03\x04"
}

fn read_zip_entry_bytes(image: &[u8], name: &str) -> crate::error::Result<Option<Vec<u8>>> {
    use std::io::{Cursor, Read};
    let mut archive: zip::ZipArchive<Cursor<&[u8]>> = zip::ZipArchive::new(Cursor::new(image))
        .map_err(|e: zip::result::ZipError| Error::Ipa(e.to_string()))?;
    match archive.by_name(name) {
        Ok(mut f) => {
            let cap: usize = usize::try_from(f.size()).unwrap_or(0);
            let mut buf: Vec<u8> = Vec::with_capacity(cap);
            f.read_to_end(&mut buf)?;
            Ok(Some(buf))
        }
        Err(zip::result::ZipError::FileNotFound) => Ok(None),
        Err(e) => Err(Error::Ipa(e.to_string())),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use disrobe_core::PassMetadata;

    #[test]
    fn pass_metadata_advertises_capability() {
        let p: SwiftObjcPass = SwiftObjcPass;
        assert_eq!(PassMetadata::id(&p), PASS_ID);
        assert_eq!(p.produced_capabilities().len(), 1);
    }

    #[test]
    fn analyze_unknown_returns_other() {
        let report: SwiftObjcReport = analyze(b"hello world\0not a binary").expect("analyze ok");
        assert_eq!(report.container, ContainerKind::Other);
        assert!(report.slices.is_empty());
    }
}
