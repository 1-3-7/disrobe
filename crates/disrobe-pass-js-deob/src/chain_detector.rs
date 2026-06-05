#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::{
    DetectContext, DetectVerdict, Detector, FAMILY_OBFUSCATOR_WRAPPER, OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;
use disrobe_core::provenance::Language;

use crate::detect::{Detection, JsObfuscator, detect as detect_obfuscator};
use crate::esoteric::{
    EsotericClassification, EsotericFamily, classify as classify_esoteric, decode_aaencode,
    decode_jjencode, decode_jsfuck,
};
use crate::obfuscator_io::{
    Output as ObfuscatorIoOutput, Preset as ObfPreset, deobfuscate_preset as obfuscator_io_deob,
};
use crate::protectors::{
    ProtectorDetection, ProtectorFamily, ProtectorOptions, ProtectorOutput,
    arxan::{deobfuscate as arxan_deobfuscate, detect as detect_arxan},
    jsdefender::{deobfuscate as jsdefender_deobfuscate, detect as detect_jsdefender},
    pace::{detect as detect_pace, detect_only_report as pace_detect_only_report},
};

pub const PASS_ID: PassId = "js.deob";

const TAG_JAVASCRIPT_OBF: &str = "js-javascript-obfuscator";
const TAG_JSCRAMBLER: &str = "js-jscrambler";
const TAG_JSFUCK: &str = "js-jsfuck";
const TAG_AAENCODE: &str = "js-aaencode";
const TAG_JJENCODE: &str = "js-jjencode";
const TAG_WEBPACK: &str = "js-webpack-bundle";
const TAG_GENERIC: &str = "js-obfuscated";
const TAG_JSDEFENDER: &str = "js-jsdefender";
const TAG_ARXAN: &str = "js-arxan";
const TAG_PACE: &str = "js-pace";
const TAG_NODE_SEA: &str = "js-node-sea";
const TAG_BYTENODE: &str = "js-bytenode-jsc";
const PROTECTOR_SPECIFICITY: u16 = 20;
const SEA_SPECIFICITY: u16 = 40;

#[derive(Debug)]
pub struct JsObfDetector;

impl Detector for JsObfDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let bytes: &[u8] = ctx.bytes;
        if let Some(loc) = crate::v8::sea::detect_node_sea_blob(bytes) {
            return Some(DetectVerdict::new(
                PASS_ID,
                TAG_NODE_SEA,
                FAMILY_OBFUSCATOR_WRAPPER,
                0.95,
                SEA_SPECIFICITY,
                vec!["node-sea-blob"],
                format!(
                    "node SEA blob at offset {off} flags 0x{flags:08x}",
                    off = loc.blob_offset,
                    flags = loc.flags
                ),
            ));
        }
        if crate::v8::bytenode::looks_like_bytenode(bytes) {
            return Some(DetectVerdict::new(
                PASS_ID,
                TAG_BYTENODE,
                FAMILY_OBFUSCATOR_WRAPPER,
                0.90,
                SEA_SPECIFICITY,
                vec!["v8-cached-data-magic"],
                "bytenode .jsc V8 cached-data blob".to_string(),
            ));
        }
        if let Ok(text) = std::str::from_utf8(bytes) {
            if let Some(v) = verdict_from_protector(text) {
                return Some(v);
            }
            let eso: EsotericClassification = classify_esoteric(text);
            if let Some(v) = verdict_from_esoteric(&eso) {
                return Some(v);
            }
        }
        let det: Detection = detect_obfuscator(bytes);
        verdict_from_obfuscator(&det)
    }
}

#[derive(Debug)]
pub struct JsObfPass;

impl Pass for JsObfPass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &JsObfDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Source {
            language: Language::JavaScript,
            formatted: true,
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        if let Some(loc) = crate::v8::sea::detect_node_sea_blob(bytes) {
            let body: Vec<u8> = serde_json::to_vec_pretty(&loc).map_err(|e| {
                CoreError::PassFailure(format!("DR-JS-0913: sea report serialize: {e}"))
            })?;
            return Ok(Artifact::new(Rung::Surface, body, artifact.root_hash));
        }
        if let Ok(header) = crate::v8::bytenode::parse_bytenode_header(bytes) {
            let body: Vec<u8> = serde_json::to_vec_pretty(&header).map_err(|e| {
                CoreError::PassFailure(format!("DR-JS-0914: bytenode report serialize: {e}"))
            })?;
            return Ok(Artifact::new(Rung::Surface, body, artifact.root_hash));
        }
        if let Ok(text) = std::str::from_utf8(bytes) {
            if let Some(out) = run_protector(text, artifact)? {
                return Ok(out);
            }
            let eso: EsotericClassification = classify_esoteric(text);
            if let Some(source) = run_esoteric(&eso, bytes) {
                return Ok(Artifact::new(
                    Rung::Surface,
                    source.into_bytes(),
                    artifact.root_hash,
                ));
            }
        }
        let det: Detection = detect_obfuscator(bytes);
        match det.family {
            JsObfuscator::ObfuscatorIo => run_javascript_obfuscator(bytes, artifact),
            JsObfuscator::Webpack | JsObfuscator::Minified | JsObfuscator::Vite => {
                Ok(run_passthrough_format(bytes, artifact))
            }
            other => Err(CoreError::PassFailure(format!(
                "DR-JS-0901: js.deob: family {other:?} not yet wired through chain runner",
            ))),
        }
    }
}

pub static JS_OBF_PASS: JsObfPass = JsObfPass;

fn verdict_from_esoteric(eso: &EsotericClassification) -> Option<DetectVerdict> {
    match eso.family {
        EsotericFamily::JsFuck => Some(DetectVerdict::new(
            PASS_ID,
            TAG_JSFUCK,
            FAMILY_OBFUSCATOR_WRAPPER,
            0.95,
            30,
            vec!["jsfuck-charset"],
            "jsfuck source".to_string(),
        )),
        EsotericFamily::AaEncode => Some(DetectVerdict::new(
            PASS_ID,
            TAG_AAENCODE,
            FAMILY_OBFUSCATOR_WRAPPER,
            0.95,
            30,
            vec!["aaencode-charset"],
            "aaencode source".to_string(),
        )),
        EsotericFamily::JjEncode => Some(DetectVerdict::new(
            PASS_ID,
            TAG_JJENCODE,
            FAMILY_OBFUSCATOR_WRAPPER,
            0.95,
            30,
            vec!["jjencode-charset"],
            "jjencode source".to_string(),
        )),
        _ => None,
    }
}

fn verdict_from_obfuscator(det: &Detection) -> Option<DetectVerdict> {
    if det.confidence < 0.5 {
        return None;
    }
    let (format_tag, specificity): (&'static str, u16) = match det.family {
        JsObfuscator::ObfuscatorIo => (TAG_JAVASCRIPT_OBF, 30),
        JsObfuscator::Jscrambler => (TAG_JSCRAMBLER, 30),
        JsObfuscator::Webpack => (TAG_WEBPACK, 35),
        JsObfuscator::Vite
        | JsObfuscator::Rollup
        | JsObfuscator::Esbuild
        | JsObfuscator::Turbopack
        | JsObfuscator::Bun => (TAG_WEBPACK, 36),
        JsObfuscator::JsObfu | JsObfuscator::Minified | JsObfuscator::Unknown => (TAG_GENERIC, 50),
    };
    Some(DetectVerdict::new(
        PASS_ID,
        format_tag,
        FAMILY_OBFUSCATOR_WRAPPER,
        det.confidence,
        specificity,
        vec!["js-obf-marker"],
        format!("js detector family={family:?}", family = det.family),
    ))
}

fn verdict_from_protector(text: &str) -> Option<DetectVerdict> {
    let pace_det: Option<ProtectorDetection> = detect_pace(text);
    if let Some(d) = pace_det {
        return Some(DetectVerdict::new(
            PASS_ID,
            TAG_PACE,
            FAMILY_OBFUSCATOR_WRAPPER,
            d.confidence,
            PROTECTOR_SPECIFICITY,
            vec!["js-pace-marker"],
            format!(
                "pace js (detect-only, stance={stance}) markers={n}",
                stance = d.stance_doc,
                n = d.markers.len(),
            ),
        ));
    }
    let jsd_det: Option<ProtectorDetection> = detect_jsdefender(text);
    if let Some(d) = jsd_det {
        return Some(DetectVerdict::new(
            PASS_ID,
            TAG_JSDEFENDER,
            FAMILY_OBFUSCATOR_WRAPPER,
            d.confidence,
            PROTECTOR_SPECIFICITY,
            vec!["js-jsdefender-marker"],
            format!(
                "jsdefender (stance={stance}) markers={n}",
                stance = d.stance_doc,
                n = d.markers.len(),
            ),
        ));
    }
    let arx_det: Option<ProtectorDetection> = detect_arxan(text);
    if let Some(d) = arx_det {
        return Some(DetectVerdict::new(
            PASS_ID,
            TAG_ARXAN,
            FAMILY_OBFUSCATOR_WRAPPER,
            d.confidence,
            PROTECTOR_SPECIFICITY,
            vec!["js-arxan-marker"],
            format!(
                "arxan (stance={stance}) markers={n}",
                stance = d.stance_doc,
                n = d.markers.len(),
            ),
        ));
    }
    None
}

fn run_protector(text: &str, artifact: &Artifact) -> CoreResult<Option<Artifact>> {
    if detect_pace(text).is_some() {
        let report: ProtectorOutput = pace_detect_only_report(text);
        let body: Vec<u8> = serde_json::to_vec_pretty(&report).map_err(|e| {
            CoreError::PassFailure(format!("DR-JS-0910: pace detect-only serialize: {e}"))
        })?;
        return Ok(Some(Artifact::new(Rung::Surface, body, artifact.root_hash)));
    }
    if detect_jsdefender(text).is_some() {
        let opts: ProtectorOptions = ProtectorOptions {
            i_have_authorization: true,
        };
        let out: ProtectorOutput = jsdefender_deobfuscate(text, &opts)
            .map_err(|e| CoreError::PassFailure(format!("DR-JS-0911: jsdefender deob: {e}")))?;
        debug_assert!(matches!(out.family, ProtectorFamily::JsDefender));
        return Ok(Some(Artifact::new(
            Rung::Surface,
            out.source.into_bytes(),
            artifact.root_hash,
        )));
    }
    if detect_arxan(text).is_some() {
        let opts: ProtectorOptions = ProtectorOptions {
            i_have_authorization: true,
        };
        let out: ProtectorOutput = arxan_deobfuscate(text, &opts)
            .map_err(|e| CoreError::PassFailure(format!("DR-JS-0912: arxan deob: {e}")))?;
        debug_assert!(matches!(out.family, ProtectorFamily::Arxan));
        return Ok(Some(Artifact::new(
            Rung::Surface,
            out.source.into_bytes(),
            artifact.root_hash,
        )));
    }
    Ok(None)
}

fn run_esoteric(eso: &EsotericClassification, bytes: &[u8]) -> Option<String> {
    let text: &str = std::str::from_utf8(bytes).ok()?;
    match eso.family {
        EsotericFamily::JsFuck => decode_jsfuck(text).recovered,
        EsotericFamily::AaEncode => decode_aaencode(text).recovered,
        EsotericFamily::JjEncode => decode_jjencode(text).recovered,
        _ => None,
    }
}

fn run_javascript_obfuscator(bytes: &[u8], artifact: &Artifact) -> CoreResult<Artifact> {
    let text: &str = std::str::from_utf8(bytes)
        .map_err(|e| CoreError::PassFailure(format!("DR-JS-0902: input not utf-8: {e}")))?;
    let out: ObfuscatorIoOutput = obfuscator_io_deob(text, ObfPreset::High)
        .map_err(|e| CoreError::PassFailure(format!("DR-JS-0903: obfuscator.io deob: {e}")))?;
    let serialized: Vec<u8> = serde_json::to_vec_pretty(&out).unwrap_or_else(|_| Vec::new());
    let body: Vec<u8> = if serialized.is_empty() {
        bytes.to_vec()
    } else {
        serialized
    };
    Ok(Artifact::new(Rung::Surface, body, artifact.root_hash))
}

fn run_passthrough_format(bytes: &[u8], artifact: &Artifact) -> Artifact {
    Artifact::new(Rung::Surface, bytes.to_vec(), artifact.root_hash)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detector_id_is_stable() {
        assert_eq!(JsObfDetector.id(), PASS_ID);
    }

    #[test]
    fn detect_javascript_obfuscator_banner() {
        let src: &[u8] = b"// obfuscator.io output\nvar _0xabcd = function(){};";
        let ctx: DetectContext<'_> = DetectContext {
            bytes: src,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        let v: DetectVerdict = JsObfDetector.detect(&ctx).expect("must detect");
        assert_eq!(v.format_tag, TAG_JAVASCRIPT_OBF);
    }

    #[test]
    fn detect_jsfuck_charset() {
        let src: &[u8] = b"[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]";
        let ctx: DetectContext<'_> = DetectContext {
            bytes: src,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        let v: Option<DetectVerdict> = JsObfDetector.detect(&ctx);
        if let Some(verdict) = v {
            assert!(
                verdict.format_tag == TAG_JSFUCK || verdict.format_tag.starts_with("js-"),
                "got {tag}",
                tag = verdict.format_tag,
            );
        }
    }

    #[test]
    fn pass_output_kind_is_javascript_source() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        let k: OutputKind = JS_OBF_PASS.output_kind(&a);
        match k {
            OutputKind::Source {
                language,
                formatted,
            } => {
                assert_eq!(language, Language::JavaScript);
                assert!(formatted);
            }
            _ => panic!("expected Source"),
        }
    }

    #[test]
    fn detect_node_sea_blob_yields_sea_tag() {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&crate::v8::sea::SEA_MAGIC.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.push(0u8);
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        let ctx: DetectContext<'_> = DetectContext {
            bytes: &bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        let v: DetectVerdict = JsObfDetector.detect(&ctx).expect("sea detect");
        assert_eq!(v.format_tag, TAG_NODE_SEA);
    }

    #[test]
    fn detect_misses_clean_source() {
        let src: &[u8] = b"const x = 1;\nfunction foo() { return x + 1; }";
        let ctx: DetectContext<'_> = DetectContext {
            bytes: src,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        assert!(JsObfDetector.detect(&ctx).is_none());
    }
}
