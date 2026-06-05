#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::{
    DetectContext, DetectVerdict, Detector, FAMILY_NATIVE_FORMAT, OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;
use disrobe_core::provenance::Language;

use crate::GoAnalysis;
use crate::pclntab::{MAGIC_GO12, MAGIC_GO116, MAGIC_GO118, MAGIC_GO120};

pub const PASS_ID: PassId = "go.classify";

const TAG_GO12: &str = "go-pclntab-1.2";
const TAG_GO116: &str = "go-pclntab-1.16";
const TAG_GO118: &str = "go-pclntab-1.18";
const TAG_GO120: &str = "go-pclntab-1.20+";
const TAG_GO_SYMBOL: &str = "go-runtime-symbol";

const FIRSTMODULEDATA_MARKER: &[u8] = b"runtime.firstmoduledata";
const PCLNTAB_SECTION_MARKER: &[u8] = b"runtime.pclntab";
const SCAN_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub struct GoDetector;

impl Detector for GoDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let bytes: &[u8] = ctx.bytes;
        if bytes.len() < 64 {
            return None;
        }
        let scan: &[u8] = if bytes.len() > SCAN_LIMIT {
            &bytes[..SCAN_LIMIT]
        } else {
            bytes
        };
        if let Some(magic) = first_pclntab_magic(scan) {
            return Some(verdict_for_magic(magic));
        }
        if window_contains(scan, FIRSTMODULEDATA_MARKER)
            || window_contains(scan, PCLNTAB_SECTION_MARKER)
        {
            return Some(verdict_runtime_symbol());
        }
        None
    }
}

#[derive(Debug)]
pub struct GoPass;

impl Pass for GoPass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &GoDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Source {
            language: Language::Go,
            formatted: true,
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let ctx: DetectContext<'_> = DetectContext {
            bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        if GoDetector.detect(&ctx).is_none() {
            return Err(CoreError::PassFailure(
                "DR-GO-0902: go.classify: input has no pclntab/runtime markers".to_string(),
            ));
        }
        let analysis: GoAnalysis = crate::analyze(bytes).map_err(|e: crate::error::Error| {
            CoreError::PassFailure(format!("DR-GO-0903: go analyze: {e}"))
        })?;
        let payload: Vec<u8> =
            serde_json::to_vec_pretty(&analysis).map_err(|e: serde_json::Error| {
                CoreError::PassFailure(format!("DR-GO-0904: serialize analysis: {e}"))
            })?;
        Ok(Artifact::new(Rung::Disasm, payload, artifact.root_hash))
    }
}

pub static GO_PASS: GoPass = GoPass;

fn first_pclntab_magic(bytes: &[u8]) -> Option<u32> {
    let known: [u32; 4] = [MAGIC_GO12, MAGIC_GO116, MAGIC_GO118, MAGIC_GO120];
    for chunk in bytes.windows(4) {
        let m_le: u32 = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        if known.contains(&m_le) {
            return Some(m_le);
        }
    }
    None
}

fn verdict_for_magic(magic: u32) -> DetectVerdict {
    let tag: &'static str = match magic {
        MAGIC_GO12 => TAG_GO12,
        MAGIC_GO116 => TAG_GO116,
        MAGIC_GO118 => TAG_GO118,
        MAGIC_GO120 => TAG_GO120,
        _ => TAG_GO_SYMBOL,
    };
    DetectVerdict::new(
        PASS_ID,
        tag,
        FAMILY_NATIVE_FORMAT,
        0.92,
        35,
        vec!["pclntab-magic"],
        format!("go pclntab magic={magic:#010x}"),
    )
}

fn verdict_runtime_symbol() -> DetectVerdict {
    DetectVerdict::new(
        PASS_ID,
        TAG_GO_SYMBOL,
        FAMILY_NATIVE_FORMAT,
        0.78,
        38,
        vec!["runtime.firstmoduledata"],
        "go runtime symbol marker".to_string(),
    )
}

#[inline]
fn window_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
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
        assert_eq!(GoDetector.id(), PASS_ID);
    }

    #[test]
    fn detect_pclntab_go118_magic() {
        let mut bytes: Vec<u8> = vec![0u8; 128];
        bytes[64..68].copy_from_slice(&MAGIC_GO118.to_le_bytes());
        let v: DetectVerdict = GoDetector.detect(&ctx(&bytes)).expect("must detect");
        assert_eq!(v.format_tag, TAG_GO118);
    }

    #[test]
    fn detect_runtime_symbol_marker() {
        let mut bytes: Vec<u8> = vec![0u8; 64];
        bytes.extend_from_slice(FIRSTMODULEDATA_MARKER);
        bytes.extend(std::iter::repeat_n(0u8, 32));
        let v: DetectVerdict = GoDetector.detect(&ctx(&bytes)).expect("must detect");
        assert_eq!(v.format_tag, TAG_GO_SYMBOL);
    }

    #[test]
    fn detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0u8; 128];
        assert!(GoDetector.detect(&ctx(&bytes)).is_none());
    }

    #[test]
    fn pass_output_kind_is_go_source() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        match GO_PASS.output_kind(&a) {
            OutputKind::Source {
                language,
                formatted,
            } => {
                assert_eq!(language, Language::Go);
                assert!(formatted);
            }
            _ => panic!("expected Source"),
        }
    }

    #[test]
    fn pass_run_rejects_synthetic_pclntab_without_image() {
        let mut bytes: Vec<u8> = vec![0u8; 128];
        bytes[64..68].copy_from_slice(&MAGIC_GO118.to_le_bytes());
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let err: CoreError = GO_PASS
            .run(&a)
            .expect_err("must reject without valid image");
        assert!(format!("{err}").contains("DR-GO-0903"));
    }

    #[test]
    fn pass_run_rejects_unknown_bytes() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 128], [0u8; 32]);
        let err: CoreError = GO_PASS.run(&a).expect_err("must reject");
        assert!(format!("{err}").contains("DR-GO-0902"));
    }
}
