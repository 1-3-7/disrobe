#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]
use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::detection::{ChildArtifact, ChildHandle, TERMINAL_HINT};
use disrobe_core::chain::{
    CatalogEntry, DetectContext, DetectVerdict, Detector, DetectorOutput,
    FAMILY_OBFUSCATOR_WRAPPER, ObfuscatorCatalog, OutputKind, Pass, SupportQuality,
};
use disrobe_core::debug::DebugLog;
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;
use disrobe_core::provenance::Language;

use crate::detect::{PhpConfidence, PhpDetection, PhpKind, detect as detect_php};
use crate::peel::{PeelOptions, PeelReport, PeelTrace, peel as peel_php};
use crate::phar::{PharArchive, PharEntry, extract_entry, parse as parse_phar};
use crate::protectors::{ProtectorFamily, ioncube, sourceguardian, zend_guard};

pub const PASS_ID: PassId = "php.peel";

const PEEL_MANIFEST_CHILD: &str = "php-peel-manifest.json";
const PEEL_MANIFEST_SCHEMA: &str = "disrobe.php.peel-manifest/v0";

const TAG_PHP_SOURCE: &str = "php-source";
const TAG_PHAR_STUB: &str = "php-phar-stub";
const TAG_PHAR_ARCHIVE: &str = "php-phar-archive";
const TAG_BCG: &str = "php-bcg";

const PHAR_MANIFEST_BANNER: &str = "php.phar archive";

#[derive(Debug)]
pub struct PhpDetectorImpl;

impl Detector for PhpDetectorImpl {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let detection: PhpDetection = detect_php(ctx.bytes);
        verdict_for(&detection)
    }
}

#[derive(Debug)]
pub struct PhpPass;

impl Pass for PhpPass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &PhpDetectorImpl
    }

    fn output_kind(&self, output: &Artifact) -> OutputKind {
        if output.envelope.starts_with(PHAR_MANIFEST_BANNER.as_bytes()) {
            OutputKind::Mixed {
                children: Vec::new(),
            }
        } else {
            OutputKind::Source {
                language: Language::Php,
                formatted: true,
            }
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let dbg: DebugLog = DebugLog::for_scope("php");
        dbg.section("php.peel");
        let bytes: &[u8] = artifact.envelope.as_slice();
        dbg.kv("input_len", || bytes.len().to_string());
        let detection: PhpDetection = detect_php(bytes);
        dbg.kv("detected_kind", || format!("{:?}", detection.kind));
        dbg.kv("confidence", || format!("{:?}", detection.confidence));
        let verdict: DetectVerdict = verdict_for(&detection).ok_or_else(|| {
            dbg.line(|| "no verdict: input is not a recognized php source or archive".to_owned());
            CoreError::PassFailure(
                "DR-PHP-0902: php.peel: input is not a recognized php source or archive"
                    .to_string(),
            )
        })?;
        dbg.kv("format_tag", || verdict.format_tag.to_owned());
        match verdict.format_tag {
            TAG_PHAR_STUB | TAG_PHAR_ARCHIVE => {
                let archive: PharArchive =
                    parse_phar(bytes).map_err(|e: crate::error::Error| {
                        dbg.line(|| format!("phar parse failed: {e}"));
                        CoreError::PassFailure(format!("DR-PHP-0904: parse phar: {e}"))
                    })?;
                dbg.kv("phar_entries", || archive.entries.len().to_string());
                let manifest: String = render_phar_manifest(&archive);
                Ok(Artifact::new(
                    Rung::Disasm,
                    manifest.into_bytes(),
                    artifact.root_hash,
                ))
            }
            _ => {
                let source: Vec<u8> = recovered_source(bytes);
                dbg.kv("recovered_source_len", || source.len().to_string());
                Ok(Artifact::new(Rung::Surface, source, artifact.root_hash))
            }
        }
    }

    fn extract_children(&self, input: &Artifact) -> CoreResult<Vec<ChildArtifact>> {
        let bytes: &[u8] = input.envelope.as_slice();
        let detection: PhpDetection = detect_php(bytes);
        if !matches!(detection.kind, PhpKind::PharStub | PhpKind::PharArchive) {
            return Ok(peel_manifest_child(bytes).into_iter().collect());
        }
        let archive: PharArchive = parse_phar(bytes).map_err(|e: crate::error::Error| {
            CoreError::PassFailure(format!("DR-PHP-0905: parse phar children: {e}"))
        })?;
        let mut children: Vec<ChildArtifact> = Vec::with_capacity(archive.entries.len());
        for (index, (name, _entry)) in archive.entries.iter().enumerate() {
            let extracted: crate::error::Result<Vec<u8>> = extract_entry(&archive, bytes, name);
            let Ok(data): crate::error::Result<Vec<u8>> = extracted else {
                continue;
            };
            if data.is_empty() {
                continue;
            }
            children.push(ChildArtifact {
                handle: ChildHandle {
                    artifact_index: u32::try_from(index).unwrap_or(u32::MAX),
                    relative_path: name.clone(),
                    hint: Some("php-phar-entry".to_string()),
                },
                bytes: data,
            });
        }
        Ok(children)
    }
}

fn peel_manifest_child(bytes: &[u8]) -> Option<ChildArtifact> {
    let manifest: serde_json::Value = build_peel_manifest(bytes)?;
    let json: Vec<u8> = serde_json::to_vec_pretty(&manifest).ok()?;
    Some(ChildArtifact {
        handle: ChildHandle {
            artifact_index: u32::MAX,
            relative_path: PEEL_MANIFEST_CHILD.to_string(),
            hint: Some(TERMINAL_HINT.to_string()),
        },
        bytes: json,
    })
}

fn build_peel_manifest(bytes: &[u8]) -> Option<serde_json::Value> {
    let protector: Option<(ProtectorFamily, f32, Vec<String>)> = detect_protector(bytes);
    let report: Option<PeelReport> = peel_php(bytes, PeelOptions::default()).ok();
    if report.is_none() && protector.is_none() {
        return None;
    }
    let steps: Vec<serde_json::Value> = report.as_ref().map_or_else(Vec::new, |r: &PeelReport| {
        r.layers
            .iter()
            .map(|t: &PeelTrace| {
                serde_json::json!({
                    "family": format!("{:?}", t.layer),
                    "before_len": t.before_len,
                    "after_len": t.after_len,
                })
            })
            .collect()
    });
    let families: std::collections::BTreeMap<String, u32> =
        report
            .as_ref()
            .map_or_else(Default::default, |r: &PeelReport| {
                r.layer_counts
                    .iter()
                    .map(|(layer, count): (&crate::peel::PeelLayer, &u32)| {
                        (format!("{layer:?}"), *count)
                    })
                    .collect()
            });
    let residual_eval: bool = report
        .as_ref()
        .is_some_and(|r: &PeelReport| r.residual_eval);
    let mut walls: Vec<serde_json::Value> = Vec::new();
    if residual_eval {
        walls.push(serde_json::json!({
            "kind": "residual-eval",
            "note": "peeled residue still contains an eval()/assert() call that resolves at runtime",
        }));
    }
    if let Some((family, confidence, markers)) = protector.as_ref() {
        walls.push(serde_json::json!({
            "kind": "commercial-encoder",
            "family": family.name(),
            "confidence": confidence,
            "markers": markers,
            "note": family.wall_reason(),
        }));
    }
    Some(serde_json::json!({
        "schema": PEEL_MANIFEST_SCHEMA,
        "steps": steps,
        "families": families,
        "residual_eval": residual_eval,
        "walls": walls,
    }))
}

pub static PHP_PASS: PhpPass = PhpPass;

const TAG_IONCUBE: &str = "php-ioncube";
const TAG_SOURCEGUARDIAN: &str = "php-sourceguardian";
const TAG_ZENDGUARD: &str = "php-zendguard";

#[derive(Debug)]
pub struct PhpCatalogEntry {
    family: ProtectorFamily,
    id: &'static str,
    display_name: &'static str,
    aliases: &'static [&'static str],
    quality: SupportQuality,
}

impl CatalogEntry for PhpCatalogEntry {
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

const CATALOG_COUNT: usize = 3;

static CATALOG: [PhpCatalogEntry; CATALOG_COUNT] = [
    PhpCatalogEntry {
        family: ProtectorFamily::IonCube,
        id: TAG_IONCUBE,
        display_name: "ionCube",
        aliases: &["ioncube"],
        quality: SupportQuality::DetectOnly,
    },
    PhpCatalogEntry {
        family: ProtectorFamily::SourceGuardian,
        id: TAG_SOURCEGUARDIAN,
        display_name: "SourceGuardian",
        aliases: &["sourceguardian", "sg"],
        quality: SupportQuality::DetectOnly,
    },
    PhpCatalogEntry {
        family: ProtectorFamily::ZendGuard,
        id: TAG_ZENDGUARD,
        display_name: "Zend Guard",
        aliases: &["zendguard", "zend-guard", "zend"],
        quality: SupportQuality::DetectOnly,
    },
];

fn catalog_id_for(family: ProtectorFamily) -> Option<&'static str> {
    CATALOG
        .iter()
        .find(|e: &&PhpCatalogEntry| e.family == family)
        .map(|e: &PhpCatalogEntry| e.id)
}

fn detect_protector(bytes: &[u8]) -> Option<(ProtectorFamily, f32, Vec<String>)> {
    if let Some((era, _off)) = ioncube::detect(bytes) {
        return Some((
            ProtectorFamily::IonCube,
            0.96,
            vec![format!("ioncube-{label}", label = era.label())],
        ));
    }
    if let Some((era, _off)) = sourceguardian::detect(bytes) {
        return Some((
            ProtectorFamily::SourceGuardian,
            0.96,
            vec![format!("sourceguardian-{label}", label = era.label())],
        ));
    }
    if let Some((era, _off, _len)) = zend_guard::detect(bytes) {
        return Some((
            ProtectorFamily::ZendGuard,
            0.96,
            vec![format!("zendguard-{label}", label = era.label())],
        ));
    }
    if let Some(_off) = ioncube::detect_loader_only(bytes) {
        return Some((
            ProtectorFamily::IonCube,
            0.6,
            vec!["ioncube-loader-call".to_owned()],
        ));
    }
    if let Some(_off) = zend_guard::detect_loader_only(bytes) {
        return Some((
            ProtectorFamily::ZendGuard,
            0.6,
            vec!["zendguard-loader-banner".to_owned()],
        ));
    }
    None
}

impl ObfuscatorCatalog for PhpDetectorImpl {
    #[inline]
    fn pass_id(&self) -> PassId {
        PASS_ID
    }

    fn catalog(&self) -> Vec<&'static dyn CatalogEntry> {
        CATALOG
            .iter()
            .map(|e: &'static PhpCatalogEntry| e as &'static dyn CatalogEntry)
            .collect()
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectorOutput> {
        let (family, confidence, markers): (ProtectorFamily, f32, Vec<String>) =
            detect_protector(ctx.bytes)?;
        let entry_id: &'static str = catalog_id_for(family)?;
        Some(DetectorOutput::new(entry_id, confidence, markers))
    }
}

fn recovered_source(bytes: &[u8]) -> Vec<u8> {
    let peeled: crate::error::Result<PeelReport> = peel_php(bytes, PeelOptions::default());
    match peeled {
        Ok(report) => report.final_source,
        Err(_) => bytes.to_vec(),
    }
}

fn render_phar_manifest(archive: &PharArchive) -> String {
    let mut out: String = String::with_capacity(64 + 48 * archive.entries.len());
    push_line(
        &mut out,
        &format!(
            "{PHAR_MANIFEST_BANNER} api={:#06x} entries={}",
            archive.api_version,
            archive.entries.len(),
        ),
    );
    for entry in archive.entries.values() {
        let entry: &PharEntry = entry;
        push_line(
            &mut out,
            &format!(
                "{} bytes={} stored={} compression={:?}",
                entry.name, entry.uncompressed_size, entry.stored_size, entry.compression,
            ),
        );
    }
    out
}

fn push_line(out: &mut String, line: &str) {
    out.push_str(line);
    out.push('\n');
}

fn verdict_for(d: &PhpDetection) -> Option<DetectVerdict> {
    let confidence: f32 = confidence_to_float(d.confidence);
    if confidence < 0.5 {
        return None;
    }
    let (tag, marker): (&'static str, &'static str) = match d.kind {
        PhpKind::Source => (TAG_PHP_SOURCE, "<?php-tag"),
        PhpKind::PharStub => (TAG_PHAR_STUB, "__HALT_COMPILER"),
        PhpKind::PharArchive => (TAG_PHAR_ARCHIVE, "phar-GBMB"),
        PhpKind::Bcg => (TAG_BCG, "bcg-magic"),
        PhpKind::Unknown => return None,
    };
    Some(DetectVerdict::new(
        PASS_ID,
        tag,
        FAMILY_OBFUSCATOR_WRAPPER,
        confidence,
        30,
        vec![marker],
        format!("php kind={tag} halt={halt}", halt = d.has_halt_compiler),
    ))
}

#[inline]
const fn confidence_to_float(c: PhpConfidence) -> f32 {
    match c {
        PhpConfidence::Definite => 0.96,
        PhpConfidence::High => 0.86,
        PhpConfidence::Medium => 0.72,
        PhpConfidence::Low => 0.40,
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
        assert_eq!(PhpDetectorImpl.id(), PASS_ID);
    }

    #[test]
    fn detect_open_tag_source() {
        let bytes: &[u8] = b"<?php echo 'hi';";
        let v: DetectVerdict =
            Detector::detect(&PhpDetectorImpl, &ctx(bytes)).expect("must detect");
        assert_eq!(v.format_tag, TAG_PHP_SOURCE);
        assert!(v.confidence > 0.9);
    }

    #[test]
    fn detect_bcg_magic() {
        let bytes: &[u8] = b"BCG\x00rest";
        let v: DetectVerdict =
            Detector::detect(&PhpDetectorImpl, &ctx(bytes)).expect("must detect");
        assert_eq!(v.format_tag, TAG_BCG);
    }

    #[test]
    fn detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0u8; 32];
        assert!(Detector::detect(&PhpDetectorImpl, &ctx(&bytes)).is_none());
    }

    #[test]
    fn pass_output_kind_is_php_source_for_source_output() {
        let a: Artifact = Artifact::new(Rung::Raw, b"<?php echo 1;".to_vec(), [0u8; 32]);
        match PHP_PASS.output_kind(&a) {
            OutputKind::Source {
                language,
                formatted,
            } => {
                assert_eq!(language, Language::Php);
                assert!(formatted);
            }
            other => panic!("expected Source, got {other:?}"),
        }
    }

    #[test]
    fn pass_run_returns_recovered_source_not_json() {
        let bytes: Vec<u8> = b"<?php echo 'hi';".to_vec();
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let out: Artifact = PHP_PASS.run(&a).expect("classify must succeed");
        assert_eq!(out.rung, Rung::Surface);
        let s: &str = std::str::from_utf8(&out.envelope).expect("utf8 source");
        assert!(
            !s.trim_start().starts_with('{'),
            "must not emit json: {s:?}"
        );
        assert!(!s.contains("\"source_text\""), "must not leak extract json");
        assert!(s.contains("echo 'hi'"), "must contain the real php: {s:?}");
        match PHP_PASS.output_kind(&out) {
            OutputKind::Source { .. } => {}
            other => panic!("expected Source output_kind, got {other:?}"),
        }
    }

    #[test]
    fn pass_run_peels_eval_chain_to_final_source() {
        let inner: &str = "<?php echo 'recovered';";
        let b64: String = {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(inner.as_bytes())
        };
        let wrapper: String = format!("<?php eval(base64_decode('{b64}'));");
        let a: Artifact = Artifact::new(Rung::Raw, wrapper.into_bytes(), [0u8; 32]);
        let out: Artifact = PHP_PASS.run(&a).expect("peel must succeed");
        let s: &str = std::str::from_utf8(&out.envelope).expect("utf8 source");
        assert!(
            s.contains("echo 'recovered'"),
            "eval-chain must be peeled to its inner php source; got {s:?}",
        );
        assert!(
            !s.contains("base64_decode"),
            "recovered output must not still be the wrapper",
        );
    }

    #[test]
    fn pass_run_renders_phar_manifest_and_extracts_members() {
        let fixture: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("php")
            .join("phar")
            .join("hello.phar");
        let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&fixture) else {
            eprintln!("SKIP: phar fixture missing at {}", fixture.display());
            return;
        };
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let out: Artifact = PHP_PASS.run(&a).expect("phar run must succeed");
        let manifest: &str = std::str::from_utf8(&out.envelope).expect("utf8 manifest");
        assert!(
            manifest.starts_with(PHAR_MANIFEST_BANNER),
            "phar run must emit the readable manifest, got {manifest:?}",
        );
        assert!(matches!(
            PHP_PASS.output_kind(&out),
            OutputKind::Mixed { .. }
        ));
        let children: Vec<ChildArtifact> = PHP_PASS
            .extract_children(&a)
            .expect("phar children must carve");
        assert!(
            !children.is_empty(),
            "phar must surface at least one member as a real child",
        );
        let any_php: bool = children
            .iter()
            .any(|c: &ChildArtifact| c.bytes.windows(2).any(|w: &[u8]| w == b"<?"));
        assert!(any_php, "at least one phar member must be real php bytes");
    }

    #[test]
    fn extract_children_emits_peel_manifest_for_eval_chain() {
        let inner: &str = "<?php echo 'recovered';";
        let b64: String = {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(inner.as_bytes())
        };
        let wrapper: String = format!("<?php eval(base64_decode('{b64}'));");
        let a: Artifact = Artifact::new(Rung::Raw, wrapper.into_bytes(), [0u8; 32]);
        let children: Vec<ChildArtifact> = PHP_PASS
            .extract_children(&a)
            .expect("manifest child must emit");
        let manifest: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == PEEL_MANIFEST_CHILD)
            .expect("peel manifest sidecar must appear in chain extract_children");
        assert!(
            manifest.handle.is_terminal(),
            "manifest is a terminal sidecar"
        );
        let parsed: serde_json::Value =
            serde_json::from_slice(&manifest.bytes).expect("manifest is json");
        assert_eq!(parsed["schema"], PEEL_MANIFEST_SCHEMA);
        assert!(
            parsed["steps"]
                .as_array()
                .is_some_and(|s: &Vec<serde_json::Value>| !s.is_empty()),
            "manifest must record the peel chain steps: {parsed}",
        );
        assert!(
            parsed["families"]
                .as_object()
                .is_some_and(|m| !m.is_empty()),
            "manifest must record the decoder families applied: {parsed}",
        );
        assert_eq!(parsed["residual_eval"], false);
    }

    #[test]
    fn extract_children_manifest_records_commercial_wall() {
        let mut blob: Vec<u8> = b"<?php //004F\n".to_vec();
        blob.extend_from_slice(
            b"encrypted Zend opcode payload that cannot be decrypted statically",
        );
        let a: Artifact = Artifact::new(Rung::Raw, blob, [0u8; 32]);
        let children: Vec<ChildArtifact> = PHP_PASS
            .extract_children(&a)
            .expect("manifest child must emit");
        let manifest: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == PEEL_MANIFEST_CHILD)
            .expect("peel manifest sidecar must appear for commercial encoder");
        let parsed: serde_json::Value =
            serde_json::from_slice(&manifest.bytes).expect("manifest is json");
        let walls: &Vec<serde_json::Value> =
            parsed["walls"].as_array().expect("walls array present");
        assert!(
            walls
                .iter()
                .any(|w: &serde_json::Value| w["kind"] == "commercial-encoder"),
            "ionCube/SourceGuardian/ZendGuard wall must be recorded: {parsed}",
        );
    }

    #[test]
    fn pass_run_rejects_unknown_bytes() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 32], [0u8; 32]);
        let err: CoreError = PHP_PASS.run(&a).expect_err("must reject");
        assert!(format!("{err}").contains("DR-PHP-0902"));
    }

    #[test]
    fn catalog_lists_three_detect_only_protectors() {
        let entries: Vec<&'static dyn CatalogEntry> = PhpDetectorImpl.catalog();
        assert_eq!(entries.len(), CATALOG_COUNT);
        for e in &entries {
            assert!(!e.id().is_empty());
            assert!(!e.display_name().is_empty());
            assert_eq!(
                e.support_quality(),
                SupportQuality::DetectOnly,
                "php commercial loaders are native-key-walled; recovery is detect-only",
            );
        }
        let ioncube: &&dyn CatalogEntry = entries
            .iter()
            .find(|e: &&&dyn CatalogEntry| e.id() == TAG_IONCUBE)
            .expect("ioncube entry present");
        assert_eq!(ioncube.display_name(), "ionCube");
    }

    #[test]
    fn catalog_detect_fires_on_ioncube_era_marker() {
        let mut blob: Vec<u8> = b"<?php //004F\n".to_vec();
        blob.extend_from_slice(
            b"encrypted Zend opcode payload that cannot be decrypted statically",
        );
        let out: DetectorOutput = ObfuscatorCatalog::detect(&PhpDetectorImpl, &ctx(&blob))
            .expect("catalog detect must fire on ionCube era marker");
        assert_eq!(out.entry_id, TAG_IONCUBE);
        assert!(out.confidence >= 0.9);
    }

    #[test]
    fn catalog_detect_misses_plain_source() {
        let bytes: &[u8] = b"<?php echo 'clear text';";
        assert!(ObfuscatorCatalog::detect(&PhpDetectorImpl, &ctx(bytes)).is_none());
    }
}
