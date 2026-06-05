#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::{
    DetectContext, DetectVerdict, Detector, FAMILY_INTERPRETER_BYTECODE, OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;
use disrobe_core::provenance::Language;

use crate::detect::Flavor;
use crate::pass::{RubyAnalysis, analyze_bytes};

pub const PASS_ID: PassId = "ruby.classify";

const YARV_MAGIC: &[u8; 4] = b"YARB";
const RITE_MAGIC: &[u8; 4] = b"RITE";
const JVM_CLASS_MAGIC: &[u8; 4] = b"\xCA\xFE\xBA\xBE";
const TRUFFLE_AOT_MARKER: &[u8] = b"TruffleRuby-NativeImage";
const RUBY2EXE_MARKER: &[u8] = b"Ruby2Exe";
const OCRA_MARKER: &[u8] = b"OcraStub";

const TAG_MRI: &str = "ruby-mri-source";
const TAG_YARV: &str = "ruby-yarv";
const TAG_MRUBY: &str = "ruby-mruby-rite";
const TAG_JRUBY: &str = "ruby-jruby-class";
const TAG_TRUFFLE: &str = "ruby-truffleruby-aot";
const TAG_RUBY2EXE: &str = "ruby-ruby2exe";
const TAG_OCRA: &str = "ruby-ocra";

#[derive(Debug)]
pub struct RubyDetector;

impl Detector for RubyDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let bytes: &[u8] = ctx.bytes;
        if bytes.len() >= 4 {
            let head: &[u8] = &bytes[..4];
            if head == YARV_MAGIC.as_slice() {
                return Some(verdict_for(Flavor::YarvBinary));
            }
            if head == RITE_MAGIC.as_slice() {
                return Some(verdict_for(Flavor::MrubyBinary));
            }
            if head == JVM_CLASS_MAGIC.as_slice() {
                return Some(verdict_for(Flavor::JrubyClass));
            }
        }
        if window_contains(bytes, TRUFFLE_AOT_MARKER) {
            return Some(verdict_for(Flavor::TruffleRubyAot));
        }
        if window_contains(bytes, RUBY2EXE_MARKER) {
            return Some(verdict_for(Flavor::Ruby2Exe));
        }
        if window_contains(bytes, OCRA_MARKER) {
            return Some(verdict_for(Flavor::Ocra));
        }
        if looks_like_ruby_source(bytes) {
            return Some(verdict_for(Flavor::MriSource));
        }
        None
    }
}

#[derive(Debug)]
pub struct RubyPass;

impl Pass for RubyPass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &RubyDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Source {
            language: Language::Ruby,
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
        let verdict: DetectVerdict = RubyDetector.detect(&ctx).ok_or_else(|| {
            CoreError::PassFailure(
                "DR-RUBY-0902: ruby.classify: input is not a recognized ruby flavor".to_string(),
            )
        })?;
        let analysis: RubyAnalysis =
            analyze_bytes(bytes, "<chain-input>").map_err(|e: crate::error::RubyError| {
                CoreError::PassFailure(format!("DR-RUBY-0903: ruby analyze: {e}"))
            })?;
        let payload: Vec<u8> =
            serde_json::to_vec_pretty(&analysis).map_err(|e: serde_json::Error| {
                CoreError::PassFailure(format!("DR-RUBY-0904: serialize ruby analysis: {e}"))
            })?;
        let next_rung: Rung = if verdict.format_tag == TAG_MRI {
            Rung::Surface
        } else {
            Rung::Disasm
        };
        Ok(Artifact::new(next_rung, payload, artifact.root_hash))
    }
}

pub static RUBY_PASS: RubyPass = RubyPass;

fn verdict_for(flavor: Flavor) -> DetectVerdict {
    let (tag, confidence, marker): (&'static str, f32, &'static str) = match flavor {
        Flavor::MriSource => (TAG_MRI, 0.72, "ruby-source-heuristic"),
        Flavor::YarvBinary => (TAG_YARV, 0.95, "YARB-magic"),
        Flavor::MrubyBinary => (TAG_MRUBY, 0.95, "RITE-magic"),
        Flavor::JrubyClass => (TAG_JRUBY, 0.85, "CAFEBABE+jruby-hint"),
        Flavor::TruffleRubyAot => (TAG_TRUFFLE, 0.88, "TruffleRuby-NativeImage"),
        Flavor::Ruby2Exe => (TAG_RUBY2EXE, 0.86, "Ruby2Exe-marker"),
        Flavor::Ocra => (TAG_OCRA, 0.86, "OcraStub-marker"),
    };
    DetectVerdict::new(
        PASS_ID,
        tag,
        FAMILY_INTERPRETER_BYTECODE,
        confidence,
        30,
        vec![marker],
        format!("ruby flavor={tag}"),
    )
}

fn looks_like_ruby_source(bytes: &[u8]) -> bool {
    let head: &[u8] = if bytes.len() > 4096 {
        &bytes[..4096]
    } else {
        bytes
    };
    let Ok(text): Result<&str, _> = std::str::from_utf8(head) else {
        return false;
    };
    let has_shebang: bool =
        text.starts_with("#!/usr/bin/env ruby") || text.starts_with("#!/usr/bin/ruby");
    let has_require: bool = text.contains("require '") || text.contains("require \"");
    let has_def_end: bool = text.contains("def ") && text.contains("\nend");
    let has_module_class: bool = text.contains("module ") || text.contains("class ");
    has_shebang || (has_require && (has_def_end || has_module_class))
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
        assert_eq!(RubyDetector.id(), PASS_ID);
    }

    #[test]
    fn detect_yarv_magic() {
        let v: DetectVerdict = RubyDetector
            .detect(&ctx(b"YARB\x00\x00\x00\x00"))
            .expect("yarv");
        assert_eq!(v.format_tag, TAG_YARV);
    }

    #[test]
    fn detect_mruby_magic() {
        let v: DetectVerdict = RubyDetector
            .detect(&ctx(b"RITE\x00\x00\x00\x00"))
            .expect("mruby");
        assert_eq!(v.format_tag, TAG_MRUBY);
    }

    #[test]
    fn detect_mri_source_heuristic() {
        let src: &[u8] = b"#!/usr/bin/env ruby\nrequire 'json'\ndef foo\nend\n";
        let v: DetectVerdict = RubyDetector.detect(&ctx(src)).expect("mri");
        assert_eq!(v.format_tag, TAG_MRI);
    }

    #[test]
    fn detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0u8; 32];
        assert!(RubyDetector.detect(&ctx(&bytes)).is_none());
    }

    #[test]
    fn pass_output_kind_is_ruby_source() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        match RUBY_PASS.output_kind(&a) {
            OutputKind::Source {
                language,
                formatted,
            } => {
                assert_eq!(language, Language::Ruby);
                assert!(formatted);
            }
            _ => panic!("expected Source"),
        }
    }

    #[test]
    fn pass_run_extracts_mri_source_as_surface_json() {
        let src: &[u8] = b"#!/usr/bin/env ruby\nrequire 'json'\ndef foo\nend\n";
        let a: Artifact = Artifact::new(Rung::Raw, src.to_vec(), [0u8; 32]);
        let out: Artifact = RUBY_PASS.run(&a).expect("classify must succeed");
        assert_eq!(out.rung, Rung::Surface);
        let s: &str = std::str::from_utf8(&out.envelope).expect("utf8 json");
        assert!(s.contains("\"flavor\""));
        assert!(s.contains("mri-source"));
    }

    #[test]
    fn pass_run_rejects_unknown_bytes() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 32], [0u8; 32]);
        let err: CoreError = RUBY_PASS.run(&a).expect_err("must reject");
        assert!(format!("{err}").contains("DR-RUBY-0902"));
    }
}
