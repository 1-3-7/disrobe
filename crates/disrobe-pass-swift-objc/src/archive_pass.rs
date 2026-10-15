use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::{
    DetectContext, DetectVerdict, Detector, Ecosystem, FAMILY_INTERPRETER_BYTECODE, OutputKind,
    Pass, PassMeta, SafetyClass, SupportQuality,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;

use crate::asset_catalog::{AssetCatalog, decode_asset_catalog, is_asset_catalog};
use crate::keyed_archive::{KeyedArchive, decode_keyed_archive};
use crate::nib_archive::{NibArchive, decode_nib_archive, is_nib_archive};

pub const PASS_ID: PassId = "swift-objc.archive";

const TAG_NIB: &str = "apple-nib-archive";
const TAG_KEYED_ARCHIVE: &str = "nskeyedarchiver";
const TAG_ASSET_CATALOG: &str = "apple-asset-catalog";
const TAG_REPORT: &str = "apple-archive-report";
const KEYED_ARCHIVE_MARKER: &[u8] = b"NSKeyedArchiver";
const MARKER_WINDOW: usize = 64 * 1024;

#[derive(Debug)]
pub struct AppleArchiveDetector;

fn is_keyed_archive_candidate(bytes: &[u8]) -> bool {
    let plist: bool = bytes.starts_with(b"bplist00")
        || bytes.starts_with(b"<?xml")
        || bytes.starts_with(b"<plist");
    if !plist {
        return false;
    }
    let window: &[u8] = if bytes.starts_with(b"bplist00") {
        bytes
    } else {
        &bytes[..bytes.len().min(MARKER_WINDOW)]
    };
    window
        .windows(KEYED_ARCHIVE_MARKER.len())
        .any(|candidate: &[u8]| candidate == KEYED_ARCHIVE_MARKER)
}

impl Detector for AppleArchiveDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let bytes: &[u8] = ctx.bytes;
        if is_nib_archive(bytes) {
            let archive: NibArchive = decode_nib_archive(bytes).ok()?;
            return Some(verdict(
                TAG_NIB,
                0.99,
                45,
                "NIBArchive magic and consistent tables",
                format!(
                    "compiled NIB: {} objects, {} connections",
                    archive.objects.len(),
                    archive.connections.len()
                ),
            ));
        }
        if is_asset_catalog(bytes) {
            let catalog: AssetCatalog = decode_asset_catalog(bytes).ok()?;
            return Some(verdict(
                TAG_ASSET_CATALOG,
                0.99,
                45,
                "BOMStore with a CARHEADER and consistent trees",
                format!(
                    "compiled asset catalog: {} renditions of {} assets",
                    catalog.renditions.len(),
                    catalog.facets.len()
                ),
            ));
        }
        if is_keyed_archive_candidate(bytes) {
            let archive: KeyedArchive = decode_keyed_archive(bytes).ok()?;
            return Some(verdict(
                TAG_KEYED_ARCHIVE,
                0.95,
                40,
                "plist with an $archiver and $objects table",
                format!("{} archive: {} objects", archive.archiver, archive.objects),
            ));
        }
        None
    }
}

fn verdict(
    tag: &'static str,
    confidence: f32,
    specificity: u16,
    marker: &'static str,
    note: String,
) -> DetectVerdict {
    DetectVerdict::new(
        PASS_ID,
        tag,
        FAMILY_INTERPRETER_BYTECODE,
        confidence,
        specificity,
        vec![marker],
        note,
    )
}

#[derive(Debug)]
pub struct AppleArchivePass;

impl Pass for AppleArchivePass {
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
        &AppleArchiveDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Report {
            format_tag: TAG_REPORT,
            family: FAMILY_INTERPRETER_BYTECODE,
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let rendered: Result<Vec<u8>, serde_json::Error> = if is_nib_archive(bytes) {
            let archive: NibArchive =
                decode_nib_archive(bytes).map_err(|error: crate::error::Error| {
                    CoreError::PassFailure(format!("DR-IOS-0023: swift-objc.archive: {error}"))
                })?;
            serde_json::to_vec_pretty(&archive)
        } else if is_asset_catalog(bytes) {
            let catalog: AssetCatalog =
                decode_asset_catalog(bytes).map_err(|error: crate::error::Error| {
                    CoreError::PassFailure(format!("DR-IOS-0023: swift-objc.archive: {error}"))
                })?;
            serde_json::to_vec_pretty(&catalog)
        } else if is_keyed_archive_candidate(bytes) {
            let archive: KeyedArchive =
                decode_keyed_archive(bytes).map_err(|error: crate::error::Error| {
                    CoreError::PassFailure(format!("DR-IOS-0023: swift-objc.archive: {error}"))
                })?;
            serde_json::to_vec_pretty(&archive)
        } else {
            return Err(CoreError::PassFailure(
                "DR-IOS-0023: swift-objc.archive: input is not a compiled NIB, asset catalog or keyed archive"
                    .to_owned(),
            ));
        };
        let payload: Vec<u8> = rendered.map_err(|error: serde_json::Error| {
            CoreError::PassFailure(format!(
                "DR-IOS-0023: swift-objc.archive: report serialization: {error}"
            ))
        })?;
        Ok(Artifact::new(Rung::Surface, payload, artifact.root_hash))
    }
}

pub const META: PassMeta = PassMeta::new(
    PASS_ID,
    Ecosystem::Swift,
    SupportQuality::Full,
    disrobe_core::chain::Determinism::Deterministic,
    SafetyClass::Static,
);

pub static APPLE_ARCHIVE_PASS: AppleArchivePass = AppleArchivePass;

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn ctx(bytes: &[u8]) -> DetectContext<'_> {
        DetectContext {
            bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        }
    }

    #[test]
    fn plain_property_lists_and_random_bytes_are_not_claimed() {
        assert!(AppleArchiveDetector.detect(&ctx(b"bplist00\x08")).is_none());
        assert!(
            AppleArchiveDetector
                .detect(&ctx(b"<?xml version=\"1.0\"?><plist><dict/></plist>"))
                .is_none()
        );
        assert!(
            AppleArchiveDetector
                .detect(&ctx(&[0x4e, 0x49, 0x42, 0x00]))
                .is_none()
        );
        assert!(AppleArchiveDetector.detect(&ctx(b"NIBArchive")).is_none());
    }

    #[test]
    fn the_pass_refuses_what_the_detector_does_not_claim() {
        let artifact: Artifact = Artifact::new(Rung::Raw, b"not an archive".to_vec(), [0u8; 32]);
        let error: String = APPLE_ARCHIVE_PASS.run(&artifact).unwrap_err().to_string();
        assert!(error.contains("DR-IOS-0023"), "{error}");
    }
}
