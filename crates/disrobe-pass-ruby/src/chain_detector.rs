#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]
use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::byte_search::contains;
use disrobe_core::chain::{
    CatalogEntry, DetectContext, DetectVerdict, Detector, DetectorOutput,
    FAMILY_INTERPRETER_BYTECODE, ObfuscatorCatalog, OutputKind, Pass, SupportQuality,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;
use disrobe_core::provenance::Language;

use crate::detect::{Flavor, RUBYSCRIPT2EXE_MARKER, has_ocra_signature};
use crate::pass::{RubyAnalysis, analyze_bytes};
use crate::wrappers::looks_like_ocra_opcode_stream;

pub const PASS_ID: PassId = "ruby.classify";

const YARV_MAGIC: &[u8; 4] = b"YARB";
const RITE_MAGIC: &[u8; 4] = b"RITE";
const JVM_CLASS_MAGIC: &[u8; 4] = b"\xCA\xFE\xBA\xBE";
const TRUFFLE_AOT_MARKER: &[u8] = b"TruffleRuby-NativeImage";

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
        if contains(bytes, TRUFFLE_AOT_MARKER) {
            return Some(verdict_for(Flavor::TruffleRubyAot));
        }
        if has_ocra_signature(bytes) || looks_like_ocra_opcode_stream(bytes) {
            return Some(verdict_for(Flavor::Ocra));
        }
        if contains(bytes, RUBYSCRIPT2EXE_MARKER) {
            return Some(verdict_for(Flavor::Ruby2Exe));
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
        let verdict: DetectVerdict = Detector::detect(&RubyDetector, &ctx).ok_or_else(|| {
            CoreError::PassFailure(
                "DR-RUBY-0902: ruby.classify: input is not a recognized ruby flavor".to_string(),
            )
        })?;
        if verdict.format_tag == TAG_MRI {
            return Ok(Artifact::new(
                Rung::Surface,
                bytes.to_vec(),
                artifact.root_hash,
            ));
        }
        let analysis: RubyAnalysis =
            analyze_bytes(bytes, "<chain-input>").map_err(|e: crate::error::RubyError| {
                CoreError::PassFailure(format!("DR-RUBY-0903: ruby analyze: {e}"))
            })?;
        if let Some(source) = render_recovered_ruby(&analysis) {
            return Ok(Artifact::new(
                Rung::Surface,
                source.into_bytes(),
                artifact.root_hash,
            ));
        }
        let payload: Vec<u8> =
            serde_json::to_vec_pretty(&analysis).map_err(|e: serde_json::Error| {
                CoreError::PassFailure(format!("DR-RUBY-0904: serialize ruby analysis: {e}"))
            })?;
        Ok(Artifact::new(Rung::Disasm, payload, artifact.root_hash))
    }
}

pub static RUBY_PASS: RubyPass = RubyPass;

fn render_recovered_ruby(analysis: &RubyAnalysis) -> Option<String> {
    if let Some(yarv) = analysis.yarv.as_ref() {
        if yarv.decompiled.source.trim().is_empty() {
            return None;
        }
        let mut out: String = String::new();
        out.push_str("# disrobe ruby yarv decompile (in-house IBF/ISeq recovery)\n");
        out.push_str("# statements: ");
        out.push_str(&yarv.decompiled.statement_count.to_string());
        out.push_str("\n\n");
        out.push_str(&yarv.decompiled.source);
        return Some(out);
    }
    if let Some(mruby) = analysis.mruby.as_ref() {
        if !mruby.decompiled.has_body {
            return None;
        }
        return Some(mruby.decompiled.source.clone());
    }
    None
}

fn verdict_for(flavor: Flavor) -> DetectVerdict {
    let (tag, confidence, marker): (&'static str, f32, &'static str) = match flavor {
        Flavor::MriSource => (TAG_MRI, 0.72, "ruby-source-heuristic"),
        Flavor::YarvBinary => (TAG_YARV, 0.95, "YARB-magic"),
        Flavor::MrubyBinary => (TAG_MRUBY, 0.95, "RITE-magic"),
        Flavor::JrubyClass => (TAG_JRUBY, 0.85, "CAFEBABE+jruby-hint"),
        Flavor::TruffleRubyAot => (TAG_TRUFFLE, 0.88, "TruffleRuby-NativeImage"),
        Flavor::Ruby2Exe => (TAG_RUBY2EXE, 0.86, "rubyscript2exe-marker"),
        Flavor::Ocra => (TAG_OCRA, 0.9, "ocra-signature-0x41b6ba4e"),
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

#[derive(Debug)]
pub struct RubyCatalogEntry {
    tag: &'static str,
    id: &'static str,
    display_name: &'static str,
    aliases: &'static [&'static str],
    quality: SupportQuality,
}

impl CatalogEntry for RubyCatalogEntry {
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

const CATALOG_COUNT: usize = 6;

static CATALOG: [RubyCatalogEntry; CATALOG_COUNT] = [
    RubyCatalogEntry {
        tag: TAG_YARV,
        id: "ruby-yarv",
        display_name: "YARV InstructionSequence (compiled .rb)",
        aliases: &["yarv", "iseq", "rubyvm"],
        quality: SupportQuality::Full,
    },
    RubyCatalogEntry {
        tag: TAG_MRUBY,
        id: "ruby-mruby",
        display_name: "mruby RITE bytecode",
        aliases: &["mruby", "rite"],
        quality: SupportQuality::Full,
    },
    RubyCatalogEntry {
        tag: TAG_OCRA,
        id: "ruby-ocra",
        display_name: "OCRA self-extracting executable",
        aliases: &["ocra"],
        quality: SupportQuality::Partial,
    },
    RubyCatalogEntry {
        tag: TAG_RUBY2EXE,
        id: "ruby-ruby2exe",
        display_name: "RubyScript2Exe package",
        aliases: &["ruby2exe", "rubyscript2exe"],
        quality: SupportQuality::Partial,
    },
    RubyCatalogEntry {
        tag: TAG_JRUBY,
        id: "ruby-jruby",
        display_name: "JRuby compiled class",
        aliases: &["jruby"],
        quality: SupportQuality::DetectOnly,
    },
    RubyCatalogEntry {
        tag: TAG_TRUFFLE,
        id: "ruby-truffleruby",
        display_name: "TruffleRuby native image",
        aliases: &["truffleruby", "graalvm"],
        quality: SupportQuality::DetectOnly,
    },
];

fn catalog_id_for_tag(tag: &str) -> Option<&'static str> {
    CATALOG
        .iter()
        .find(|e: &&RubyCatalogEntry| e.tag == tag)
        .map(|e: &RubyCatalogEntry| e.id)
}

impl ObfuscatorCatalog for RubyDetector {
    #[inline]
    fn pass_id(&self) -> PassId {
        PASS_ID
    }

    fn catalog(&self) -> Vec<&'static dyn CatalogEntry> {
        CATALOG
            .iter()
            .map(|e: &'static RubyCatalogEntry| e as &'static dyn CatalogEntry)
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
        assert_eq!(RubyDetector.id(), PASS_ID);
    }

    #[test]
    fn catalog_lists_yarv_and_mruby() {
        let entries: Vec<&'static dyn CatalogEntry> = ObfuscatorCatalog::catalog(&RubyDetector);
        assert_eq!(entries.len(), CATALOG_COUNT);
        let ids: Vec<&'static str> = entries.iter().map(|e| e.id()).collect();
        assert!(ids.contains(&"ruby-yarv"), "got {ids:?}");
        assert!(ids.contains(&"ruby-mruby"), "got {ids:?}");
        assert!(ids.contains(&"ruby-ocra"), "got {ids:?}");
    }

    #[test]
    fn catalog_detect_maps_yarv_magic() {
        let out: DetectorOutput =
            ObfuscatorCatalog::detect(&RubyDetector, &ctx(b"YARB\x00\x00\x00\x00"))
                .expect("yarv catalog detect");
        assert_eq!(out.entry_id, "ruby-yarv");
    }

    #[test]
    fn catalog_detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0u8; 32];
        assert!(ObfuscatorCatalog::detect(&RubyDetector, &ctx(&bytes)).is_none());
    }

    #[test]
    fn detect_yarv_magic() {
        let v: DetectVerdict =
            Detector::detect(&RubyDetector, &ctx(b"YARB\x00\x00\x00\x00")).expect("yarv");
        assert_eq!(v.format_tag, TAG_YARV);
    }

    #[test]
    fn detect_mruby_magic() {
        let v: DetectVerdict =
            Detector::detect(&RubyDetector, &ctx(b"RITE\x00\x00\x00\x00")).expect("mruby");
        assert_eq!(v.format_tag, TAG_MRUBY);
    }

    #[test]
    fn detect_mri_source_heuristic() {
        let src: &[u8] = b"#!/usr/bin/env ruby\nrequire 'json'\ndef foo\nend\n";
        let v: DetectVerdict = Detector::detect(&RubyDetector, &ctx(src)).expect("mri");
        assert_eq!(v.format_tag, TAG_MRI);
    }

    #[test]
    fn detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0u8; 32];
        assert!(Detector::detect(&RubyDetector, &ctx(&bytes)).is_none());
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
    fn pass_run_passes_through_mri_source() {
        let src: &[u8] = b"#!/usr/bin/env ruby\nrequire 'json'\ndef foo\nend\n";
        let a: Artifact = Artifact::new(Rung::Raw, src.to_vec(), [0u8; 32]);
        let out: Artifact = RUBY_PASS.run(&a).expect("classify must succeed");
        assert_eq!(out.rung, Rung::Surface);
        assert_eq!(out.envelope, src, "mri source must pass through verbatim");
        let s: &str = std::str::from_utf8(&out.envelope).expect("utf8 source");
        assert!(s.contains("def foo"));
        assert!(
            !s.contains("\"flavor\""),
            "must be ruby source, not analysis json"
        );
    }

    #[test]
    fn pass_withholds_incomplete_mruby_source() {
        let path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("ruby")
            .join("mruby")
            .join("breadth")
            .join("exceptions.mrb");
        let bytes: Vec<u8> = std::fs::read(&path)
            .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", path.display()));
        let artifact: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let output: Artifact = RUBY_PASS.run(&artifact).expect("classify must succeed");
        assert_eq!(output.rung, Rung::Disasm);
        let text: &str = std::str::from_utf8(&output.envelope).expect("analysis JSON utf8");
        assert!(text.contains("\"has_body\": false"), "got: {text}");
        assert!(
            !text.contains("def safe_div"),
            "a partial reconstruction must not enter the chain surface: {text}"
        );
    }

    #[test]
    fn pass_run_rejects_unknown_bytes() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 32], [0u8; 32]);
        let err: CoreError = RUBY_PASS.run(&a).expect_err("must reject");
        assert!(format!("{err}").contains("DR-RUBY-0902"));
    }
}
