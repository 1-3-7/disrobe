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

use crate::detect::{LangFingerprint, NativeLang, fingerprint};
use crate::image::NativeImage;
use crate::pass::{NativeLangPassReport, build_report};
use crate::{NativeLangAnalysis, analyze};

pub const PASS_ID: PassId = "nativelang.classify";

const NATIVELANG_REPORT_TAG: &str = "nativelang.report";

const MIN_FINGERPRINT_HITS: u32 = 2;
const MIN_FINGERPRINT_CONFIDENCE: f32 = 0.60;

const SPECIFICITY: u16 = 30;

#[derive(Debug)]
pub struct NativeLangDetector;

impl Detector for NativeLangDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let image: NativeImage<'_> = NativeImage::parse(ctx.bytes).ok()?;
        let fp: LangFingerprint = fingerprint(&image)?;
        verdict_for(&fp)
    }
}

#[derive(Debug)]
pub struct NativeLangPassAdapter;

impl Pass for NativeLangPassAdapter {
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
        &NativeLangDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Report {
            format_tag: NATIVELANG_REPORT_TAG,
            family: FAMILY_NATIVE_FORMAT,
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        self.run_with_path(artifact, None)
    }

    fn run_with_path(&self, artifact: &Artifact, path_hint: Option<&str>) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let analysis: NativeLangAnalysis = analyze(bytes).map_err(|e| {
            CoreError::PassFailure(format!("DR-NLANG-0901: nativelang.classify: {e}"))
        })?;
        let source_path: String = path_hint.unwrap_or("<artifact>").to_owned();
        let report: NativeLangPassReport = build_report(source_path, analysis);
        let payload: Vec<u8> = serde_json::to_vec(&report).map_err(|e| {
            CoreError::PassFailure(format!(
                "DR-NLANG-0902: nativelang.classify: serialize report: {e}"
            ))
        })?;
        Ok(Artifact::new(Rung::Surface, payload, artifact.root_hash))
    }
}

pub const META: disrobe_core::chain::PassMeta = disrobe_core::chain::PassMeta::new(
    PASS_ID,
    disrobe_core::chain::Ecosystem::Native,
    disrobe_core::chain::SupportQuality::Partial,
    disrobe_core::chain::Determinism::Deterministic,
    disrobe_core::chain::SafetyClass::Static,
);

pub static NATIVELANG_PASS: NativeLangPassAdapter = NativeLangPassAdapter;

fn verdict_for(fp: &LangFingerprint) -> Option<DetectVerdict> {
    let hits: u32 = u32::try_from(fp.markers.len()).unwrap_or(u32::MAX);
    if hits < MIN_FINGERPRINT_HITS || fp.confidence < MIN_FINGERPRINT_CONFIDENCE {
        return None;
    }
    Some(DetectVerdict::new(
        PASS_ID,
        fp.lang.label(),
        FAMILY_NATIVE_FORMAT,
        fp.confidence,
        SPECIFICITY,
        vec![fp.lang.label()],
        format!(
            "nativelang lang={} hits={hits} markers={}",
            fp.lang.label(),
            fp.markers.join(",")
        ),
    ))
}

#[derive(Debug)]
pub struct NativeLangCatalogEntry {
    id: &'static str,
    display_name: &'static str,
    aliases: &'static [&'static str],
}

impl CatalogEntry for NativeLangCatalogEntry {
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
        SupportQuality::Partial
    }
}

const CATALOG_COUNT: usize = 4;

static CATALOG: [NativeLangCatalogEntry; CATALOG_COUNT] = [
    NativeLangCatalogEntry {
        id: "nim",
        display_name: "Nim",
        aliases: &["nimlang"],
    },
    NativeLangCatalogEntry {
        id: "zig",
        display_name: "Zig",
        aliases: &["ziglang"],
    },
    NativeLangCatalogEntry {
        id: "crystal",
        display_name: "Crystal",
        aliases: &["crystal-lang"],
    },
    NativeLangCatalogEntry {
        id: "d",
        display_name: "D",
        aliases: &["dlang", "d-lang"],
    },
];

const fn catalog_id_for(lang: NativeLang) -> &'static str {
    match lang {
        NativeLang::Nim => "nim",
        NativeLang::Zig => "zig",
        NativeLang::Crystal => "crystal",
        NativeLang::D => "d",
    }
}

impl ObfuscatorCatalog for NativeLangDetector {
    #[inline]
    fn pass_id(&self) -> PassId {
        PASS_ID
    }

    fn catalog(&self) -> Vec<&'static dyn CatalogEntry> {
        CATALOG
            .iter()
            .map(|e: &'static NativeLangCatalogEntry| e as &'static dyn CatalogEntry)
            .collect()
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectorOutput> {
        let image: NativeImage<'_> = NativeImage::parse(ctx.bytes).ok()?;
        let fp: LangFingerprint = fingerprint(&image)?;
        let hits: u32 = u32::try_from(fp.markers.len()).unwrap_or(u32::MAX);
        if hits < MIN_FINGERPRINT_HITS || fp.confidence < MIN_FINGERPRINT_CONFIDENCE {
            return None;
        }
        Some(DetectorOutput::new(
            catalog_id_for(fp.lang),
            fp.confidence,
            fp.markers,
        ))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;

    fn ctx(bytes: &[u8]) -> DetectContext<'_> {
        DetectContext {
            bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        }
    }

    fn corpus_path(relative: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("native")
            .join(relative)
    }

    fn read_fixture(relative: &str) -> Vec<u8> {
        let path: std::path::PathBuf = corpus_path(relative);
        std::fs::read(&path).unwrap_or_else(|error: std::io::Error| {
            panic!(
                "committed fixture {} is the graded reference for this test and could not be \
                 read ({error}); restore it from git rather than skipping the measurement",
                path.display()
            )
        })
    }

    #[test]
    fn detector_id_is_stable() {
        assert_eq!(NativeLangDetector.id(), PASS_ID);
    }

    fn assert_fingerprint_matches(bytes: &[u8], expected_hits: usize, expected_confidence: f32) {
        let image: NativeImage<'_> = NativeImage::parse(bytes).expect("image must parse");
        let fp: LangFingerprint = fingerprint(&image).expect("fingerprint must resolve");
        assert_eq!(
            fp.markers.len(),
            expected_hits,
            "marker-hit count regressed: {:?}",
            fp.markers
        );
        assert!(
            (fp.confidence - expected_confidence).abs() < 0.0001,
            "confidence regressed: got {} want {expected_confidence}",
            fp.confidence
        );
    }

    #[test]
    fn detect_real_nim_elf_matches_nim_above_floor() {
        let bytes: Vec<u8> = read_fixture("nim/hello.nim.elf");
        let v: DetectVerdict =
            Detector::detect(&NativeLangDetector, &ctx(&bytes)).expect("nim must be detected");
        assert_eq!(v.format_tag, "nim");
        assert_fingerprint_matches(&bytes, 7, 0.9000);
    }

    #[test]
    fn detect_real_zig_elf_matches_zig_above_floor() {
        let bytes: Vec<u8> = read_fixture("zig/hello.zig.elf");
        let v: DetectVerdict =
            Detector::detect(&NativeLangDetector, &ctx(&bytes)).expect("zig must be detected");
        assert_eq!(v.format_tag, "zig");
        assert_fingerprint_matches(&bytes, 6, 0.9500);
    }

    #[test]
    fn detect_real_crystal_exe_matches_crystal_above_floor() {
        let bytes: Vec<u8> = read_fixture("crystal/hello.cr.exe");
        let v: DetectVerdict =
            Detector::detect(&NativeLangDetector, &ctx(&bytes)).expect("crystal must be detected");
        assert_eq!(v.format_tag, "crystal");
        assert_fingerprint_matches(&bytes, 4, 0.7500);
    }

    #[test]
    fn detect_real_d_exe_matches_d_above_floor() {
        let bytes: Vec<u8> = read_fixture("d/hello.d.exe");
        let v: DetectVerdict =
            Detector::detect(&NativeLangDetector, &ctx(&bytes)).expect("d must be detected");
        assert_eq!(v.format_tag, "d");
        assert_fingerprint_matches(&bytes, 9, 0.8071);
    }

    #[test]
    fn detect_abstains_on_real_unrelated_native_binary() {
        let bytes: Vec<u8> = read_fixture("packers/aspack/AccessEnum.original.exe");
        assert!(
            Detector::detect(&NativeLangDetector, &ctx(&bytes)).is_none(),
            "an unrelated real compiled binary must not be claimed by the nativelang floor"
        );
    }

    #[test]
    fn detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0u8; 128];
        assert!(Detector::detect(&NativeLangDetector, &ctx(&bytes)).is_none());
    }

    #[test]
    fn floor_rejects_a_single_marker_hit_even_at_nominal_confidence() {
        let fp: LangFingerprint = LangFingerprint {
            lang: NativeLang::D,
            confidence: 0.58,
            markers: vec!["_Dmain".to_owned()],
        };
        assert!(
            verdict_for(&fp).is_none(),
            "a single marker hit must abstain regardless of the confidence formula"
        );
    }

    #[test]
    fn floor_accepts_two_marker_hits_above_confidence_floor() {
        let fp: LangFingerprint = LangFingerprint {
            lang: NativeLang::Zig,
            confidence: 0.6833,
            markers: vec!["start.callMain".to_owned(), "panicUnwrap".to_owned()],
        };
        let v: DetectVerdict = verdict_for(&fp).expect("two hits above floor must emit a verdict");
        assert_eq!(v.format_tag, "zig");
    }

    #[test]
    fn pass_output_kind_is_a_report_not_a_new_sample() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        match NATIVELANG_PASS.output_kind(&a) {
            OutputKind::Report { format_tag, family } => {
                assert_eq!(format_tag, NATIVELANG_REPORT_TAG);
                assert_eq!(family, FAMILY_NATIVE_FORMAT);
            }
            other => {
                panic!("the analysis json describes the input; expected Report, got {other:?}")
            }
        }
    }

    #[test]
    fn pass_run_rejects_unrecognized_bytes() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 128], [0u8; 32]);
        let err: CoreError = NATIVELANG_PASS.run(&a).expect_err("must reject");
        assert!(format!("{err}").contains("DR-NLANG-0901"));
    }

    #[test]
    fn pass_run_produces_a_real_nonempty_report_for_nim() {
        let bytes: Vec<u8> = read_fixture("nim/hello.nim.elf");
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let out: Artifact = NATIVELANG_PASS.run(&a).expect("nim run must succeed");
        assert_eq!(out.rung, Rung::Surface);
        let report: NativeLangPassReport =
            serde_json::from_slice(&out.envelope).expect("report must be valid json");
        assert_eq!(report.lang, "nim");
        assert!(report.confidence > 0.0);
        assert!(!report.disasm_arch_supported || report.disassembled_function_count > 0);
    }

    #[test]
    fn pass_run_with_path_records_the_hint() {
        let bytes: Vec<u8> = read_fixture("zig/hello.zig.elf");
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let out: Artifact = NATIVELANG_PASS
            .run_with_path(&a, Some("hello.zig.elf"))
            .expect("zig run must succeed");
        let report: NativeLangPassReport =
            serde_json::from_slice(&out.envelope).expect("report must be valid json");
        assert_eq!(report.source_path, "hello.zig.elf");
    }

    #[test]
    fn pass_run_surfaces_structural_d_rtti_names() {
        let bytes: Vec<u8> = read_fixture("d/hello.d.exe");
        let artifact: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let output: Artifact = NATIVELANG_PASS.run(&artifact).expect("d run must succeed");
        let report: serde_json::Value =
            serde_json::from_slice(&output.envelope).expect("report must be valid json");
        let symbols: &[serde_json::Value] = report["demangled_symbols"]
            .as_array()
            .map(Vec::as_slice)
            .expect("report must expose recovered symbol records");
        assert!(symbols.iter().any(|symbol: &serde_json::Value| {
            symbol["demangled"].as_str() == Some("hello.Greeter")
        }));
    }

    #[test]
    fn pass_run_surfaces_recovered_pseudo_c_and_pseudo_rust_bodies() {
        let bytes: Vec<u8> = read_fixture("zig/hello.zig.elf");
        let artifact: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let output: Artifact = NATIVELANG_PASS
            .run(&artifact)
            .expect("zig run must succeed");
        let report: serde_json::Value =
            serde_json::from_slice(&output.envelope).expect("report must be valid json");
        assert_eq!(report["body_arch_supported"].as_bool(), Some(true));
        let recovered: u64 = report["recovered_body_count"]
            .as_u64()
            .expect("the report must count recovered bodies");
        let rust: u64 = report["rust_body_count"]
            .as_u64()
            .expect("the report must count emitted pseudo-Rust bodies");
        assert!(recovered >= 312, "recovered {recovered} bodies");
        assert!(rust >= 309, "emitted {rust} pseudo-Rust bodies");
        let bodies: &[serde_json::Value] = report["bodies"]["bodies"]
            .as_array()
            .map(Vec::as_slice)
            .expect("the report must carry one record per carved function");
        let function_count: u64 = report["recovered_function_count"]
            .as_u64()
            .expect("carved function count");
        assert_eq!(bodies.len() as u64, function_count);
        let sum: u64 = recovered
            + report["elided_body_count"].as_u64().unwrap_or_default()
            + report["rejected_body_count"].as_u64().unwrap_or_default()
            + report["not_attempted_body_count"]
                .as_u64()
                .unwrap_or_default();
        assert_eq!(sum, function_count);
        let sample: &serde_json::Value = bodies
            .iter()
            .find(|body: &&serde_json::Value| body["status"]["state"].as_str() == Some("recovered"))
            .expect("at least one carved zig function must carry a body");
        let source: &str = sample["status"]["pseudo_c"]
            .as_str()
            .expect("a recovered body carries pseudo-C");
        let emitted: &str = sample["emitted_name"]
            .as_str()
            .expect("a recovered body names its emitted identifier");
        assert!(source.contains("#include <stdint.h>"), "{source}");
        assert!(source.contains(emitted), "{emitted} missing from {source}");
    }

    #[test]
    fn catalog_lists_all_four_languages_with_partial_quality() {
        let entries: Vec<&'static dyn CatalogEntry> =
            ObfuscatorCatalog::catalog(&NativeLangDetector);
        assert_eq!(entries.len(), CATALOG_COUNT);
        let ids: Vec<&'static str> = entries.iter().map(|e| e.id()).collect();
        for expected in ["nim", "zig", "crystal", "d"] {
            assert!(ids.contains(&expected), "got {ids:?}");
        }
        for e in &entries {
            assert_eq!(e.support_quality(), SupportQuality::Partial);
        }
    }

    #[test]
    fn catalog_detect_maps_real_d_fixture() {
        let bytes: Vec<u8> = read_fixture("d/hello.d.exe");
        let out: DetectorOutput =
            ObfuscatorCatalog::detect(&NativeLangDetector, &ctx(&bytes)).expect("d catalog detect");
        assert_eq!(out.entry_id, "d");
    }

    #[test]
    fn catalog_detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0u8; 64];
        assert!(ObfuscatorCatalog::detect(&NativeLangDetector, &ctx(&bytes)).is_none());
    }
}
