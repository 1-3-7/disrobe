#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]

use serde::Serialize;

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::{
    DetectContext, DetectVerdict, Detector, FAMILY_INTERPRETER_BYTECODE, OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;
use disrobe_core::provenance::Language;

use crate::abc::{AbcFile, parse as parse_abc};
use crate::decompile::render_program;
use crate::swf::{
    SwfCompression, TagCode, detect as detect_swf, parse as parse_swf, parse_do_abc,
    parse_do_abc_legacy,
};

pub const PASS_ID: PassId = "as3.classify";

const TAG_SWF_FWS: &str = "swf-uncompressed";
const TAG_SWF_CWS: &str = "swf-zlib";
const TAG_SWF_ZWS: &str = "swf-lzma";
const TAG_ABC: &str = "abc-bytecode";

const ABC_VERSION_MINOR: u16 = 16;
const ABC_VERSION_MAJOR: u16 = 46;

#[derive(Debug)]
pub struct As3Detector;

impl Detector for As3Detector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let bytes: &[u8] = ctx.bytes;
        if let Some(comp) = detect_swf(bytes) {
            return Some(verdict_swf(comp));
        }
        if looks_like_abc(bytes) {
            return Some(verdict_abc());
        }
        None
    }
}

#[derive(Debug)]
pub struct As3Pass;

impl Pass for As3Pass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &As3Detector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Source {
            language: Language::ActionScript3,
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
        let verdict: DetectVerdict = As3Detector.detect(&ctx).ok_or_else(|| {
            CoreError::PassFailure(
                "DR-AS3-0902: as3.classify: input is neither SWF nor raw ABC".to_string(),
            )
        })?;
        let extract: As3Extract = match verdict.format_tag {
            TAG_ABC => extract_raw_abc(bytes)?,
            _ => extract_swf(bytes)?,
        };
        let payload: Vec<u8> =
            serde_json::to_vec_pretty(&extract).map_err(|e: serde_json::Error| {
                CoreError::PassFailure(format!("DR-AS3-0904: serialize extract: {e}"))
            })?;
        Ok(Artifact::new(Rung::Surface, payload, artifact.root_hash))
    }
}

pub static AS3_PASS: As3Pass = As3Pass;

#[derive(Debug, Clone, Serialize)]
pub struct As3Extract {
    pub kind: &'static str,
    pub abc_payload_count: usize,
    pub class_skeleton_source: String,
}

fn extract_raw_abc(bytes: &[u8]) -> CoreResult<As3Extract> {
    let abc: AbcFile = parse_abc(bytes).map_err(|e: crate::error::Error| {
        CoreError::PassFailure(format!("DR-AS3-0905: abc parse: {e}"))
    })?;
    let source: String = render_program(&abc).map_err(|e: crate::error::Error| {
        CoreError::PassFailure(format!("DR-AS3-0906: abc render: {e}"))
    })?;
    Ok(As3Extract {
        kind: "abc",
        abc_payload_count: 1,
        class_skeleton_source: source,
    })
}

fn extract_swf(bytes: &[u8]) -> CoreResult<As3Extract> {
    let swf: crate::swf::Swf = parse_swf(bytes).map_err(|e: crate::error::Error| {
        CoreError::PassFailure(format!("DR-AS3-0907: swf parse: {e}"))
    })?;
    let mut source: String = String::new();
    let mut abc_count: usize = 0usize;
    for tag in &swf.tags {
        let parsed: Option<crate::swf::DoAbc> = if tag.code == TagCode::DO_ABC {
            parse_do_abc(tag).ok()
        } else if tag.code == TagCode::DO_ABC_DEFINE {
            parse_do_abc_legacy(tag).ok()
        } else {
            None
        };
        let Some(doabc): Option<crate::swf::DoAbc> = parsed else {
            continue;
        };
        abc_count += 1;
        let Ok(abc): crate::error::Result<AbcFile> = parse_abc(&doabc.abc_bytes) else {
            continue;
        };
        let rendered: String = render_program(&abc).unwrap_or_default();
        source.push_str(&rendered);
        source.push('\n');
    }
    Ok(As3Extract {
        kind: "swf",
        abc_payload_count: abc_count,
        class_skeleton_source: source,
    })
}

fn verdict_swf(comp: SwfCompression) -> DetectVerdict {
    let (tag, marker): (&'static str, &'static str) = match comp {
        SwfCompression::None => (TAG_SWF_FWS, "FWS-magic"),
        SwfCompression::Zlib => (TAG_SWF_CWS, "CWS-magic"),
        SwfCompression::Lzma => (TAG_SWF_ZWS, "ZWS-magic"),
    };
    DetectVerdict::new(
        PASS_ID,
        tag,
        FAMILY_INTERPRETER_BYTECODE,
        0.96,
        30,
        vec![marker],
        format!("swf compression={comp:?}"),
    )
}

fn verdict_abc() -> DetectVerdict {
    DetectVerdict::new(
        PASS_ID,
        TAG_ABC,
        FAMILY_INTERPRETER_BYTECODE,
        0.85,
        30,
        vec!["abc-version"],
        "raw abc bytecode (version minor=16 major=46)".to_string(),
    )
}

fn looks_like_abc(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    let minor: u16 = u16::from_le_bytes([bytes[0], bytes[1]]);
    let major: u16 = u16::from_le_bytes([bytes[2], bytes[3]]);
    minor == ABC_VERSION_MINOR && major == ABC_VERSION_MAJOR
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
        assert_eq!(As3Detector.id(), PASS_ID);
    }

    #[test]
    fn detect_fws() {
        let v: DetectVerdict = As3Detector
            .detect(&ctx(b"FWS\x0a\x00\x00\x00\x00"))
            .expect("must detect");
        assert_eq!(v.format_tag, TAG_SWF_FWS);
    }

    #[test]
    fn detect_cws() {
        let v: DetectVerdict = As3Detector
            .detect(&ctx(b"CWS\x0a\x00\x00\x00\x00"))
            .expect("must detect");
        assert_eq!(v.format_tag, TAG_SWF_CWS);
    }

    #[test]
    fn detect_abc_version_46_16() {
        let mut bytes: Vec<u8> = Vec::with_capacity(8);
        bytes.extend_from_slice(&ABC_VERSION_MINOR.to_le_bytes());
        bytes.extend_from_slice(&ABC_VERSION_MAJOR.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 4]);
        let v: DetectVerdict = As3Detector.detect(&ctx(&bytes)).expect("must detect");
        assert_eq!(v.format_tag, TAG_ABC);
    }

    #[test]
    fn detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0u8; 32];
        assert!(As3Detector.detect(&ctx(&bytes)).is_none());
    }

    #[test]
    fn pass_output_kind_is_as3_source() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        match AS3_PASS.output_kind(&a) {
            OutputKind::Source {
                language,
                formatted,
            } => {
                assert_eq!(language, Language::ActionScript3);
                assert!(formatted);
            }
            _ => panic!("expected Source"),
        }
    }

    #[test]
    fn pass_run_rejects_synthetic_fws_without_real_body() {
        let bytes: Vec<u8> = b"FWS\x0a\x00\x00\x00\x00".to_vec();
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let err: CoreError = AS3_PASS
            .run(&a)
            .expect_err("synthetic FWS lacks rect+frame data");
        assert!(format!("{err}").contains("DR-AS3-0907"));
    }

    #[test]
    fn pass_run_rejects_unknown_bytes() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 32], [0u8; 32]);
        let err: CoreError = AS3_PASS.run(&a).expect_err("must reject");
        assert!(format!("{err}").contains("DR-AS3-0902"));
    }
}
