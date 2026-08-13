#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]
use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::{
    CatalogEntry, DetectContext, DetectVerdict, Detector, DetectorOutput, FAMILY_NATIVE_FORMAT,
    ObfuscatorCatalog, OutputKind, Pass, SupportQuality,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;
use disrobe_core::provenance::Language;

use crate::macho::{
    DylibReference, FatArchEntry, MachoKind, ParsedSlice, Section, Segment, detect_magic,
    parse_slice, slice_bytes, walk_fat,
};
use crate::pass::{SwiftObjcReport, analyze as analyze_swift_objc};

pub const PASS_ID: PassId = "swift-objc.classify";

const TAG_MACHO_SLICE32: &str = "macho-slice-32";
const TAG_MACHO_SLICE64: &str = "macho-slice-64";
const TAG_MACHO_FAT32: &str = "macho-fat-32";
const TAG_MACHO_FAT64: &str = "macho-fat-64";

#[derive(Debug)]
pub struct SwiftObjcDetector;

impl Detector for SwiftObjcDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let kind: MachoKind = detect_magic(ctx.bytes)?;
        let marker: &'static str = semantic_marker(ctx.bytes, kind)?;
        Some(verdict_for(kind, marker))
    }
}

#[derive(Debug)]
pub struct SwiftObjcPassAdapter;

impl Pass for SwiftObjcPassAdapter {
    #[inline]
    fn meta(&self) -> disrobe_core::chain::PassMeta {
        META
    }
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &SwiftObjcDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Source {
            language: Language::Swift,
            formatted: true,
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        if detect_magic(bytes).is_none() {
            return Err(CoreError::PassFailure(
                "DR-SWOBJ-0902: swift-objc.classify: input is not a recognized Mach-O magic"
                    .to_string(),
            ));
        }
        let report: SwiftObjcReport =
            analyze_swift_objc(bytes).map_err(|e: crate::error::Error| {
                CoreError::PassFailure(format!("DR-SWOBJ-0903: swift-objc analyze: {e}"))
            })?;
        if let Some(source) = render_class_dump(&report) {
            return Ok(Artifact::new(
                Rung::Surface,
                source.into_bytes(),
                artifact.root_hash,
            ));
        }
        let payload: Vec<u8> =
            serde_json::to_vec_pretty(&report).map_err(|e: serde_json::Error| {
                CoreError::PassFailure(format!("DR-SWOBJ-0904: serialize report: {e}"))
            })?;
        Ok(Artifact::new(Rung::Disasm, payload, artifact.root_hash))
    }
}

pub const META: disrobe_core::chain::PassMeta = disrobe_core::chain::PassMeta::new(
    PASS_ID,
    disrobe_core::chain::Ecosystem::Swift,
    disrobe_core::chain::SupportQuality::Full,
    disrobe_core::chain::Determinism::Deterministic,
    disrobe_core::chain::SafetyClass::Static,
);

pub static SWIFT_OBJC_PASS: SwiftObjcPassAdapter = SwiftObjcPassAdapter;

fn render_class_dump(report: &SwiftObjcReport) -> Option<String> {
    let mut out: String =
        String::from("// disrobe swift/objc class-dump (recovered reflection metadata)\n\n");
    let mut emitted: usize = 0;
    for slice in &report.slices {
        for ty in &slice.swift.reflected_types {
            out.push_str(&ty.render());
            out.push('\n');
            emitted += 1;
        }
        for iface in &slice.objc.interfaces {
            out.push_str(&iface.render());
            out.push('\n');
            emitted += 1;
        }
    }
    if emitted == 0 { None } else { Some(out) }
}

fn semantic_marker(bytes: &[u8], kind: MachoKind) -> Option<&'static str> {
    match kind {
        MachoKind::Fat32 | MachoKind::Fat64 => walk_fat(bytes)
            .ok()?
            .iter()
            .filter_map(|entry: &FatArchEntry| slice_bytes(bytes, entry))
            .filter_map(|slice: &[u8]| parse_slice(slice).ok())
            .find_map(|parsed: ParsedSlice| parsed_semantic_marker(&parsed)),
        MachoKind::Slice32Le
        | MachoKind::Slice32Be
        | MachoKind::Slice64Le
        | MachoKind::Slice64Be => {
            let parsed: ParsedSlice = parse_slice(bytes).ok()?;
            parsed_semantic_marker(&parsed)
        }
    }
}

fn parsed_semantic_marker(parsed: &ParsedSlice) -> Option<&'static str> {
    let has_swift_section: bool = parsed
        .segments
        .iter()
        .flat_map(|segment: &Segment| segment.sections.iter())
        .any(|section: &Section| section.name.starts_with("__swift5_"));
    if has_swift_section {
        return Some("swift-metadata-section");
    }
    let has_objc_section: bool = parsed
        .segments
        .iter()
        .flat_map(|segment: &Segment| segment.sections.iter())
        .any(|section: &Section| section.name.starts_with("__objc_"));
    if has_objc_section {
        return Some("objc-metadata-section");
    }
    let has_swift_runtime: bool = parsed
        .dylibs
        .iter()
        .any(|dylib: &DylibReference| dylib.name.starts_with("/usr/lib/swift/libswift"));
    if has_swift_runtime {
        return Some("swift-runtime-link");
    }
    parsed
        .dylibs
        .iter()
        .any(|dylib: &DylibReference| dylib.name == "/usr/lib/libobjc.A.dylib")
        .then_some("objc-runtime-link")
}

fn verdict_for(kind: MachoKind, marker: &'static str) -> DetectVerdict {
    let tag: &'static str = match kind {
        MachoKind::Fat32 => TAG_MACHO_FAT32,
        MachoKind::Fat64 => TAG_MACHO_FAT64,
        MachoKind::Slice32Le | MachoKind::Slice32Be => TAG_MACHO_SLICE32,
        MachoKind::Slice64Le | MachoKind::Slice64Be => TAG_MACHO_SLICE64,
    };
    DetectVerdict::new(
        PASS_ID,
        tag,
        FAMILY_NATIVE_FORMAT,
        0.95,
        40,
        vec![marker],
        format!("macho kind={tag}"),
    )
}

#[derive(Debug)]
pub struct SwiftObjcCatalogEntry {
    id: &'static str,
    display_name: &'static str,
    aliases: &'static [&'static str],
    quality: SupportQuality,
}

impl CatalogEntry for SwiftObjcCatalogEntry {
    #[inline]
    fn id(&self) -> &'static str {
        self.id
    }
    #[inline]
    fn display_name(&self) -> &'static str {
        self.display_name
    }
    #[inline]
    fn aliases(&self) -> &'static [&'static str] {
        self.aliases
    }
    #[inline]
    fn support_quality(&self) -> SupportQuality {
        self.quality
    }
}

const CATALOG_COUNT: usize = 2;

static CATALOG: [SwiftObjcCatalogEntry; CATALOG_COUNT] = [
    SwiftObjcCatalogEntry {
        id: "swift-macho",
        display_name: "Mach-O Swift / Objective-C metadata",
        aliases: &["macho", "swift", "objc", "objective-c"],
        quality: SupportQuality::Full,
    },
    SwiftObjcCatalogEntry {
        id: "swift-macho-fat",
        display_name: "Mach-O fat (universal) binary",
        aliases: &["fat", "universal", "lipo"],
        quality: SupportQuality::Full,
    },
];

fn catalog_id_for_tag(tag: &str) -> Option<&'static str> {
    match tag {
        TAG_MACHO_SLICE32 | TAG_MACHO_SLICE64 => Some("swift-macho"),
        TAG_MACHO_FAT32 | TAG_MACHO_FAT64 => Some("swift-macho-fat"),
        _ => None,
    }
}

impl ObfuscatorCatalog for SwiftObjcDetector {
    #[inline]
    fn pass_id(&self) -> PassId {
        PASS_ID
    }

    fn catalog(&self) -> Vec<&'static dyn CatalogEntry> {
        CATALOG
            .iter()
            .map(|e: &'static SwiftObjcCatalogEntry| e as &'static dyn CatalogEntry)
            .collect()
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectorOutput> {
        let verdict: DetectVerdict = Detector::detect(self, ctx)?;
        let entry_id: &'static str = catalog_id_for_tag(verdict.format_tag)?;
        let markers: Vec<String> = verdict
            .markers
            .iter()
            .map(|m: &&str| (*m).to_owned())
            .collect();
        Some(DetectorOutput::new(entry_id, verdict.confidence, markers))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use disrobe_core::Rung;

    fn ctx(bytes: &[u8]) -> DetectContext<'_> {
        DetectContext {
            bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        }
    }

    #[test]
    fn detector_id_is_stable() {
        assert_eq!(SwiftObjcDetector.id(), PASS_ID);
    }

    #[test]
    fn magic_without_swift_or_objc_evidence_is_not_claimed() {
        let bytes: Vec<u8> = vec![0xCF, 0xFA, 0xED, 0xFE, 0u8, 0u8, 0u8, 0u8];
        assert!(Detector::detect(&SwiftObjcDetector, &ctx(&bytes)).is_none());
    }

    #[test]
    fn detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0u8; 8];
        assert!(Detector::detect(&SwiftObjcDetector, &ctx(&bytes)).is_none());
    }

    #[test]
    fn pass_output_kind_is_swift_source() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        match SWIFT_OBJC_PASS.output_kind(&a) {
            OutputKind::Source {
                language,
                formatted,
            } => {
                assert_eq!(language, Language::Swift);
                assert!(formatted);
            }
            _ => panic!("expected Source"),
        }
    }

    #[test]
    fn pass_run_rejects_synthetic_macho_without_load_commands() {
        let bytes: Vec<u8> = vec![0xCF, 0xFA, 0xED, 0xFE, 0u8, 0u8, 0u8, 0u8];
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let err: CoreError = SWIFT_OBJC_PASS
            .run(&a)
            .expect_err("synthetic mach-o has no load commands");
        let msg: String = format!("{err}");
        assert!(msg.contains("DR-SWOBJ-0903") || msg.contains("DR-SWOBJ-0904"));
    }

    #[test]
    fn pass_run_rejects_unknown_bytes() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 16], [0u8; 32]);
        let err: CoreError = SWIFT_OBJC_PASS.run(&a).expect_err("must reject");
        assert!(format!("{err}").contains("DR-SWOBJ-0902"));
    }

    #[test]
    fn catalog_lists_macho_targets() {
        let entries: Vec<&'static dyn CatalogEntry> =
            ObfuscatorCatalog::catalog(&SwiftObjcDetector);
        assert_eq!(entries.len(), CATALOG_COUNT);
        let ids: Vec<&'static str> = entries.iter().map(|e| e.id()).collect();
        assert!(ids.contains(&"swift-macho"), "got {ids:?}");
        assert!(ids.contains(&"swift-macho-fat"), "got {ids:?}");
    }

    #[test]
    fn catalog_detect_maps_objc_macho_slice() {
        let bytes: &[u8] =
            include_bytes!("../tests/fixtures/objc_dispatch/dispatch_sends_x86_64.macho");
        let out: DetectorOutput = ObfuscatorCatalog::detect(&SwiftObjcDetector, &ctx(bytes))
            .expect("macho catalog detect");
        assert_eq!(out.entry_id, "swift-macho");
        assert_eq!(out.markers, vec!["objc-metadata-section"]);
    }

    #[test]
    fn catalog_detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0u8; 8];
        assert!(ObfuscatorCatalog::detect(&SwiftObjcDetector, &ctx(&bytes)).is_none());
    }
}
