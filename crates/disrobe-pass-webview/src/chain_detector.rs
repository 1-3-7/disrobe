#![cfg(feature = "chain")]

use disrobe_core::chain::{
    ChildArtifact, ChildHandle, DetectContext, DetectVerdict, Detector, Determinism, Ecosystem,
    FAMILY_PACKER_ARCHIVE, OutputKind, Pass, PassMeta, SafetyClass, SupportQuality,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;
use disrobe_core::{Artifact, Capability, Rung};
use serde::Serialize;

use crate::detect::{FamilyEvidence, classify};
use crate::error::Error;
use crate::model::{CarveReport, RecoveredAsset, SymlinkEntry, WebviewFamily};
use crate::{CarveConfig, carve_with_config};

pub const PASS_ID: PassId = "webview.carve";

const TAG_ELECTRON: &str = "electron-asar";
const TAG_TAURI: &str = "tauri-embedded";
const TAG_WAILS: &str = "wails-embedded";

const ARCHIVE_SPECIFICITY: u16 = 30;
const MARKER_SPECIFICITY: u16 = 12;

const SUMMARY_SCHEMA: &str = "disrobe.webview.chain/v1";

pub const META: PassMeta = PassMeta::new(
    PASS_ID,
    Ecosystem::Container,
    SupportQuality::Partial,
    Determinism::Deterministic,
    SafetyClass::Static,
);

#[derive(Debug)]
pub struct WebviewDetector;

impl Detector for WebviewDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let evidence: FamilyEvidence = classify(ctx.bytes)?;
        let tag: &'static str = tag_for(evidence.family);
        let specificity: u16 = if evidence.archive_verified {
            ARCHIVE_SPECIFICITY
        } else {
            MARKER_SPECIFICITY
        };
        let recovery: &str = if evidence.archive_verified {
            "archive header parsed"
        } else {
            "markers only, table not yet located"
        };
        Some(DetectVerdict::new(
            PASS_ID,
            tag,
            FAMILY_PACKER_ARCHIVE,
            evidence.confidence,
            specificity,
            evidence.markers.clone(),
            format!(
                "webview family={family} evidence={recovery} markers={markers}",
                family = evidence.family.label(),
                markers = evidence.markers.join(",")
            ),
        ))
    }
}

#[derive(Debug)]
pub struct WebviewPassAdapter;

impl Pass for WebviewPassAdapter {
    #[inline]
    fn meta(&self) -> PassMeta {
        META
    }

    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &WebviewDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Mixed {
            children: Vec::new(),
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let Some(evidence): Option<FamilyEvidence> = classify(bytes) else {
            return Err(CoreError::PassFailure(format!(
                "DR-WEBVIEW-0060: {PASS_ID}: input carries no webview-desktop evidence"
            )));
        };
        let summary: Summary = summarize(&evidence, bytes);
        let encoded: Vec<u8> = serde_json::to_vec(&summary).map_err(|e: serde_json::Error| {
            CoreError::PassFailure(format!(
                "DR-WEBVIEW-0061: {PASS_ID}: serialize summary: {e}"
            ))
        })?;
        let mut next: Artifact = Artifact::new(Rung::Disasm, encoded, artifact.root_hash);
        next.add_capability(Capability::produces("webview.detection.json", 1));
        if summary.recovered > 0 {
            next.add_capability(Capability::produces("webview.frontend.extracted", 1));
        }
        Ok(next)
    }

    fn extract_children(&self, input: &Artifact) -> CoreResult<Vec<ChildArtifact>> {
        let bytes: &[u8] = input.envelope.as_slice();
        if classify(bytes).is_none() {
            return Ok(Vec::new());
        }
        match carve_with_config(bytes, &CarveConfig::default()) {
            Ok(report) => Ok(to_children(&report.assets)),
            Err(
                Error::NotDetected
                | Error::FamilyNotExtractable { .. }
                | Error::NoEmbeddedTable(_)
                | Error::NativeParse(_),
            ) => Ok(Vec::new()),
            Err(other) => Err(CoreError::PassFailure(format!(
                "DR-WEBVIEW-0062: {PASS_ID}: carve: {other}"
            ))),
        }
    }
}

pub static WEBVIEW_PASS: WebviewPassAdapter = WebviewPassAdapter;

#[derive(Debug, Serialize)]
struct SummaryAsset {
    path: String,
    bytes: usize,
    compression: &'static str,
    integrity: &'static str,
    executable: bool,
}

#[derive(Debug, Serialize)]
struct Summary {
    schema: &'static str,
    family: &'static str,
    confidence: f32,
    archive_verified: bool,
    markers: Vec<&'static str>,
    extractable: bool,
    abstain_reason: Option<String>,
    declared: usize,
    recovered: usize,
    coverage: f64,
    directories: Vec<String>,
    symlinks: Vec<SymlinkEntry>,
    external_unpacked: Vec<String>,
    assets: Vec<SummaryAsset>,
}

fn summarize(evidence: &FamilyEvidence, bytes: &[u8]) -> Summary {
    let base: Summary = Summary {
        schema: SUMMARY_SCHEMA,
        family: evidence.family.label(),
        confidence: evidence.confidence,
        archive_verified: evidence.archive_verified,
        markers: evidence.markers.clone(),
        extractable: false,
        abstain_reason: None,
        declared: 0,
        recovered: 0,
        coverage: 0.0,
        directories: Vec::new(),
        symlinks: Vec::new(),
        external_unpacked: Vec::new(),
        assets: Vec::new(),
    };
    match carve_with_config(bytes, &CarveConfig::default()) {
        Ok(report) => merge_report(base, &report),
        Err(reason) => Summary {
            abstain_reason: Some(reason.to_string()),
            ..base
        },
    }
}

fn merge_report(base: Summary, report: &CarveReport) -> Summary {
    Summary {
        family: report.family.label(),
        extractable: true,
        declared: report.declared,
        recovered: report.recovered,
        coverage: report.coverage(),
        directories: report.directories.clone(),
        symlinks: report.symlinks.clone(),
        external_unpacked: report.external_unpacked.clone(),
        assets: report
            .assets
            .iter()
            .map(|asset: &RecoveredAsset| SummaryAsset {
                path: asset.path.clone(),
                bytes: asset.bytes.len(),
                compression: asset.compression.label(),
                integrity: asset.integrity.label(),
                executable: asset.executable,
            })
            .collect(),
        ..base
    }
}

fn to_children(assets: &[RecoveredAsset]) -> Vec<ChildArtifact> {
    assets
        .iter()
        .enumerate()
        .map(|(index, asset): (usize, &RecoveredAsset)| ChildArtifact {
            handle: ChildHandle {
                artifact_index: u32::try_from(index).unwrap_or(u32::MAX),
                relative_path: asset.path.clone(),
                hint: Some(hint_for(&asset.path).to_owned()),
            },
            bytes: asset.bytes.clone(),
        })
        .collect()
}

fn hint_for(path: &str) -> &'static str {
    let lowered: String = path.to_ascii_lowercase();
    let extension: &str = lowered.rsplit_once('.').map_or("", |(_, ext)| ext);
    match extension {
        "js" | "mjs" | "cjs" | "jsx" | "ts" | "tsx" => "javascript",
        "wasm" => "wasm",
        "asar" => "asar",
        "map" => "source-map",
        "node" | "dll" | "so" | "dylib" => "native",
        "zip" | "gz" | "tgz" | "tar" | "br" | "zst" => "archive",
        "json" => "json",
        "html" | "htm" => "html",
        "css" => "css",
        _ => "webview-asset",
    }
}

const fn tag_for(family: WebviewFamily) -> &'static str {
    match family {
        WebviewFamily::Electron => TAG_ELECTRON,
        WebviewFamily::Tauri => TAG_TAURI,
        WebviewFamily::Wails => TAG_WAILS,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use disrobe_bytes::align_up_u32;

    fn ctx(bytes: &[u8]) -> DetectContext<'_> {
        DetectContext {
            bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        }
    }

    fn asar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut data: Vec<u8> = Vec::new();
        let mut entries: Vec<String> = Vec::new();
        for (name, body) in files {
            let offset: usize = data.len();
            data.extend_from_slice(body);
            entries.push(format!(
                "\"{name}\":{{\"size\":{size},\"offset\":\"{offset}\"}}",
                size = body.len()
            ));
        }
        let json: String = format!("{{\"files\":{{{}}}}}", entries.join(","));
        let json_len: u32 = u32::try_from(json.len()).expect("json len fits");
        let aligned: u32 = align_up_u32(json_len, 4);
        let payload_size: u32 = aligned + 4;
        let header_buf_len: u32 = payload_size + 4;
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&4u32.to_le_bytes());
        out.extend_from_slice(&header_buf_len.to_le_bytes());
        out.extend_from_slice(&payload_size.to_le_bytes());
        out.extend_from_slice(&json_len.to_le_bytes());
        out.extend_from_slice(json.as_bytes());
        out.extend(std::iter::repeat_n(0u8, (aligned - json_len) as usize));
        out.extend_from_slice(&data);
        out
    }

    fn artifact(bytes: Vec<u8>) -> Artifact {
        Artifact::new(Rung::Raw, bytes, [0u8; 32])
    }

    #[test]
    fn detector_id_matches_the_pass_and_its_meta() {
        assert_eq!(WebviewDetector.id(), PASS_ID);
        assert_eq!(WEBVIEW_PASS.id(), PASS_ID);
        assert_eq!(WEBVIEW_PASS.meta().id, PASS_ID);
        assert_ne!(
            WEBVIEW_PASS.meta().ecosystem,
            Ecosystem::Other,
            "a pass reporting the other ecosystem is refused by the registry coherence check"
        );
    }

    #[test]
    fn a_parsed_archive_outranks_a_marker_only_hit() {
        let archive: Vec<u8> = asar(&[("index.html", b"<html>hi</html>")]);
        let strong: DetectVerdict = WebviewDetector
            .detect(&ctx(&archive))
            .expect("archive detect");
        let weak: DetectVerdict = WebviewDetector
            .detect(&ctx(b"__TAURI_INTERNALS__ marker with no table"))
            .expect("marker detect");
        assert_eq!(strong.format_tag, TAG_ELECTRON);
        assert_eq!(weak.format_tag, TAG_TAURI);
        assert!(
            strong.confidence > weak.confidence,
            "registration order must not decide precedence, evidence must"
        );
        assert!(strong.specificity > weak.specificity);
    }

    #[test]
    fn detect_abstains_without_evidence() {
        assert!(WebviewDetector.detect(&ctx(&[0u8; 256])).is_none());
        assert!(WebviewDetector.detect(&ctx(b"")).is_none());
    }

    #[test]
    fn every_recovered_asset_becomes_a_chain_child() {
        let files: [(&str, &[u8]); 3] = [
            ("index.html", b"<html>hi</html>"),
            ("assets/app.js", b"console.log(1)"),
            ("assets/inner.zip", b"PK\x03\x04payload"),
        ];
        let archive: Vec<u8> = asar(&files);
        let children: Vec<ChildArtifact> = WEBVIEW_PASS
            .extract_children(&artifact(archive))
            .expect("children");
        assert_eq!(children.len(), files.len());
        let paths: Vec<String> = children
            .iter()
            .map(|child: &ChildArtifact| child.handle.relative_path.clone())
            .collect();
        assert_eq!(
            paths,
            vec!["assets/app.js", "assets/inner.zip", "index.html"]
        );
        for (child, expected) in children.iter().zip([
            b"console.log(1)".as_slice(),
            b"PK\x03\x04payload".as_slice(),
            b"<html>hi</html>".as_slice(),
        ]) {
            assert_eq!(
                child.bytes, expected,
                "a child handed to a downstream pass must carry the exact recovered bytes"
            );
        }
        assert_eq!(children[0].handle.hint.as_deref(), Some("javascript"));
        assert_eq!(children[1].handle.hint.as_deref(), Some("archive"));
        assert_eq!(children[2].handle.hint.as_deref(), Some("html"));
    }

    #[test]
    fn a_marker_only_input_reports_detection_without_claiming_recovery() {
        let input: Vec<u8> = b"__TAURI_INTERNALS__ and tauri://localhost, no asset table".to_vec();
        let out: Artifact = WEBVIEW_PASS.run(&artifact(input.clone())).expect("run");
        let summary: serde_json::Value =
            serde_json::from_slice(out.envelope.as_slice()).expect("summary json");
        assert_eq!(summary["family"], "tauri");
        assert_eq!(summary["extractable"], false);
        assert_eq!(summary["recovered"], 0);
        assert!(
            summary["abstain_reason"].is_string(),
            "an abstain must carry the concrete reason, not an empty success"
        );
        assert!(
            WEBVIEW_PASS
                .extract_children(&artifact(input))
                .expect("children")
                .is_empty(),
            "detection alone must not manufacture children"
        );
    }

    #[test]
    fn run_refuses_input_with_no_evidence() {
        let err: CoreError = WEBVIEW_PASS
            .run(&artifact(vec![0u8; 64]))
            .expect_err("must refuse");
        assert!(format!("{err}").contains("DR-WEBVIEW-0060"));
    }

    #[test]
    fn run_reports_the_recovered_tree_for_a_parsed_archive() {
        let archive: Vec<u8> = asar(&[("index.html", b"<html>hi</html>"), ("app.js", b"var a=1")]);
        let out: Artifact = WEBVIEW_PASS.run(&artifact(archive)).expect("run");
        let summary: serde_json::Value =
            serde_json::from_slice(out.envelope.as_slice()).expect("summary json");
        assert_eq!(summary["family"], "electron");
        assert_eq!(summary["extractable"], true);
        assert_eq!(summary["recovered"], 2);
        assert_eq!(summary["declared"], 2);
        assert_eq!(summary["assets"][0]["path"], "app.js");
        assert_eq!(summary["assets"][0]["bytes"], 7);
    }
}
