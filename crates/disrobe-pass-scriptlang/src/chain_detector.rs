#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::{
    DetectContext, DetectVerdict, Detector, FAMILY_CONTAINER, FAMILY_INTERPRETER_BYTECODE,
    FAMILY_SOURCE, OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;
use disrobe_core::provenance::Language;

use serde::Deserialize;

use crate::lang::{ScriptArtifact, ScriptLang, analyze, classify, haxe::HaxeTarget};

pub const PASS_ID: PassId = "scriptlang.classify";

const TAG_PERL: &str = "perl-concise";
const TAG_R: &str = "r-rds";
const TAG_TCL: &str = "tcl-starkit";
const TAG_HAXE_JS: &str = "haxe-js";
const TAG_HAXE_SWF: &str = "haxe-swf";
const TAG_HAXE_HL: &str = "haxe-hl";

#[derive(Debug)]
pub struct ScriptLangDetector;

impl Detector for ScriptLangDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let bytes: &[u8] = ctx.bytes;
        let lang: ScriptLang = classify(bytes)?;
        Some(verdict_for(bytes, lang))
    }
}

#[derive(Debug)]
pub struct ScriptLangPass;

impl Pass for ScriptLangPass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &ScriptLangDetector
    }

    fn output_kind(&self, output: &Artifact) -> OutputKind {
        #[derive(Deserialize)]
        struct LangTag {
            lang: String,
        }
        let language: Option<Language> = serde_json::from_slice::<LangTag>(&output.envelope)
            .ok()
            .and_then(|tag: LangTag| match tag.lang.as_str() {
                "perl" => Some(Language::Perl),
                "r" => Some(Language::R),
                "tcl" => Some(Language::Tcl),
                "haxe" => Some(Language::Haxe),
                _ => None,
            });
        match language {
            Some(language) => OutputKind::Source {
                language,
                formatted: false,
            },
            None => OutputKind::Bytes {
                format_tag: "scriptlang-report",
                family: FAMILY_SOURCE,
            },
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
        if ScriptLangDetector.detect(&ctx).is_none() {
            return Err(CoreError::PassFailure(
                "DR-SCRIPT-0902: scriptlang.classify: input is not a perl/r/tcl/haxe artifact"
                    .to_string(),
            ));
        }
        let art: ScriptArtifact = analyze(bytes).map_err(|e: crate::error::Error| {
            CoreError::PassFailure(format!("DR-SCRIPT-0903: scriptlang analyze: {e}"))
        })?;
        let payload: Vec<u8> =
            serde_json::to_vec_pretty(&art).map_err(|e: serde_json::Error| {
                CoreError::PassFailure(format!(
                    "DR-SCRIPT-0904: serialize scriptlang artifact: {e}"
                ))
            })?;
        Ok(Artifact::new(Rung::Surface, payload, artifact.root_hash))
    }
}

pub static SCRIPTLANG_PASS: ScriptLangPass = ScriptLangPass;

fn verdict_for(bytes: &[u8], lang: ScriptLang) -> DetectVerdict {
    let (tag, family, confidence, specificity, marker, explain): (
        &'static str,
        &'static str,
        f32,
        u16,
        &'static str,
        String,
    ) = match lang {
        ScriptLang::Perl => (
            TAG_PERL,
            FAMILY_INTERPRETER_BYTECODE,
            0.90,
            30,
            "b-concise-optree",
            "perl B::Concise op-tree dump".to_string(),
        ),
        ScriptLang::R => (
            TAG_R,
            FAMILY_INTERPRETER_BYTECODE,
            0.94,
            32,
            "rds-xdr-magic",
            "r RDS (saveRDS) serialized object".to_string(),
        ),
        ScriptLang::Tcl => (
            TAG_TCL,
            FAMILY_CONTAINER,
            0.93,
            35,
            "starkit-header",
            "tcl starkit / tclkit container".to_string(),
        ),
        ScriptLang::Haxe => haxe_meta(bytes),
    };
    DetectVerdict::new(
        PASS_ID,
        tag,
        family,
        confidence,
        specificity,
        vec![marker],
        explain,
    )
}

fn haxe_meta(bytes: &[u8]) -> (&'static str, &'static str, f32, u16, &'static str, String) {
    let tag: &'static str = match crate::lang::haxe::detect(bytes).map(|fp| fp.target) {
        Some(HaxeTarget::JavaScript) => TAG_HAXE_JS,
        Some(HaxeTarget::SwfFlash) => TAG_HAXE_SWF,
        Some(HaxeTarget::HashLink) => TAG_HAXE_HL,
        None => TAG_HAXE_JS,
    };
    (
        tag,
        FAMILY_SOURCE,
        0.88,
        28,
        "haxe-emitted-target",
        "haxe cross-target output (routes to matching target pass)".to_string(),
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
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
    fn detector_id_is_stable() {
        assert_eq!(ScriptLangDetector.id(), PASS_ID);
    }

    #[test]
    fn detect_haxe_js() {
        let js: &[u8] = b"// Generated by Haxe 4.3.6\n();\n";
        let v: DetectVerdict = ScriptLangDetector.detect(&ctx(js)).expect("detect");
        assert_eq!(v.format_tag, TAG_HAXE_JS);
    }

    #[test]
    fn detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0x33u8; 64];
        assert!(ScriptLangDetector.detect(&ctx(&bytes)).is_none());
    }

    #[test]
    fn pass_run_rejects_unknown() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0x33u8; 64], [0u8; 32]);
        let err: CoreError = SCRIPTLANG_PASS.run(&a).expect_err("must reject");
        assert!(format!("{err}").contains("DR-SCRIPT-0902"));
    }

    #[test]
    fn pass_run_classifies_haxe() {
        let js: &[u8] = b"// Generated by Haxe 4.3.6\n();\n";
        let a: Artifact = Artifact::new(Rung::Raw, js.to_vec(), [0u8; 32]);
        let out: Artifact = SCRIPTLANG_PASS.run(&a).expect("classify");
        assert_eq!(out.rung, Rung::Surface);
        match SCRIPTLANG_PASS.output_kind(&out) {
            OutputKind::Source { language, .. } => assert_eq!(language, Language::Haxe),
            other => panic!("expected Source, got {other:?}"),
        }
    }
}
