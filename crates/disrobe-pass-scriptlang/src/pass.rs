use std::fmt::Arguments;

use disrobe_core::debug::DebugLog;
use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};
use disrobe_ir::{Envelope, decode_raw};
use serde::{Deserialize, Serialize};

use crate::lang::rcpp::RcppFingerprint;
use crate::lang::{ScriptArtifact, ScriptLang, analyze, analyze_rcpp, classify};

pub const PASS_INPUT_PATH_CAP: &str = "raw.scriptlang";

macro_rules! push_text {
    ($output:expr, $($arg:tt)*) => {
        push_format(&mut $output, format_args!($($arg)*))
    };
}

fn push_format(output: &mut String, args: Arguments<'_>) {
    match std::fmt::write(output, args) {
        Ok(()) => {}
        Err(error) => unreachable!("string formatting failed: {error:?}"),
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ScriptLangPass;

impl LegacyPass for ScriptLangPass {
    const CONSUMES: &'static [Rung] = &[Rung::Raw];
    const EMITS: &'static [Rung] = &[Rung::Surface];
    const REQUIRES: &'static [fn() -> Capability] =
        &[|| Capability::requires(PASS_INPUT_PATH_CAP, 1)];
    const PRODUCES: &'static [fn() -> Capability] =
        &[|| Capability::produces("scriptlang.classified", 1)];

    fn id(&self) -> PassId {
        "disrobe-pass-scriptlang"
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let dbg: DebugLog = DebugLog::for_scope("scriptlang");
        dbg.section("scriptlang.pass");
        let input: PassInput = decode_pass_input(&artifact.envelope);
        dbg.kv("input_len", || input.bytes.len().to_string());
        let Some(lang): Option<ScriptLang> = classify(&input.bytes) else {
            dbg.line(|| "not a recognized perl/r/tcl/haxe artifact".to_owned());
            return Err(CoreError::PassFailure(
                "DR-SCRIPT-PASS: input is not a recognized perl/r/tcl/haxe artifact".to_owned(),
            ));
        };
        dbg.kv("lang", || format!("{lang:?}"));
        let artifact_data: ScriptArtifact =
            analyze(&input.bytes).map_err(|e: crate::error::Error| {
                dbg.line(|| format!("analyze failed: {e}"));
                CoreError::PassFailure(format!("DR-SCRIPT-PASS: {e}"))
            })?;
        let rcpp: Option<RcppFingerprint> = if lang == ScriptLang::R {
            analyze_rcpp(&input.bytes)
                .ok()
                .filter(RcppFingerprint::is_rcpp)
        } else {
            None
        };
        let report: ScriptLangReport =
            build_report(input.source_path, lang, &artifact_data, rcpp.as_ref());
        let payload: Vec<u8> = serde_json::to_vec(&report).map_err(|e: serde_json::Error| {
            CoreError::PassFailure(format!("DR-SCRIPT-PASS encode: {e}"))
        })?;
        let mut next: Artifact = Artifact::new(Rung::Surface, payload, artifact.root_hash);
        for producer in <Self as LegacyPass>::PRODUCES {
            next.add_capability(producer());
        }
        Ok(next)
    }
}

#[derive(Debug, Clone)]
pub struct PassInput {
    pub source_path: String,
    pub bytes: Vec<u8>,
}

#[must_use]
pub fn decode_pass_input(envelope_bytes: &[u8]) -> PassInput {
    if let Ok(envelope) = Envelope::decode(envelope_bytes)
        && let Ok(raw) = decode_raw(&envelope.hot)
    {
        return PassInput {
            source_path: raw.source_path,
            bytes: raw.source_bytes,
        };
    }
    if let Ok(raw) = decode_raw(envelope_bytes) {
        return PassInput {
            source_path: raw.source_path,
            bytes: raw.source_bytes,
        };
    }
    PassInput {
        source_path: "<artifact>".to_owned(),
        bytes: envelope_bytes.to_vec(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScriptLangReport {
    pub source_path: String,
    pub language: String,
    pub format_tag: String,
    pub symbol_count: usize,
    pub recovered_names: Vec<String>,
    pub detail: String,
}

fn build_report(
    source_path: String,
    lang: ScriptLang,
    artifact: &ScriptArtifact,
    rcpp: Option<&RcppFingerprint>,
) -> ScriptLangReport {
    let (symbol_count, recovered_names, detail): (usize, Vec<String>, String) = match artifact {
        ScriptArtifact::Perl(tree) => {
            let mut names: Vec<String> = tree.subs.iter().map(|s| s.name.clone()).collect();
            names.sort();
            let detail: String = format!("op-tree subs={} ops={}", tree.subs.len(), tree.op_count);
            (names.len(), names, detail)
        }
        ScriptArtifact::R(obj) => {
            let mut names: Vec<String> = obj.names.clone();
            names.extend(obj.symbols.iter().cloned());
            names.sort();
            names.dedup();
            let mut detail: String = format!(
                "rds v{} root={} len={:?} class={:?} closures={} raw_vectors={} complex_vectors={} s4_objects={} environments={} altrep={} extptr={} weakref={}",
                obj.header.version,
                obj.root_type,
                obj.root_length,
                obj.class,
                obj.closures.len(),
                obj.raw_vectors.len(),
                obj.complex_vectors.len(),
                obj.s4_objects.len(),
                obj.environments.len(),
                obj.altrep_objects.len(),
                obj.external_pointers.len(),
                obj.weak_references.len()
            );
            for closure in &obj.closures {
                names.push(closure.rendered.clone());
            }
            for s4 in &obj.s4_objects {
                if let Some(class_name) = s4.class.as_deref() {
                    names.push(format!("s4:{class_name}"));
                }
            }
            for env in &obj.environments {
                names.extend(env.bindings.iter().map(|b: &String| format!("env:{b}")));
            }
            for alt in &obj.altrep_objects {
                if let (Some(class_name), Some(materialized)) =
                    (alt.class.as_deref(), alt.materialized.as_deref())
                {
                    names.push(format!("altrep:{class_name}={materialized}"));
                }
            }
            if let Some(fp) = rcpp {
                detail.push_str(" rcpp=1 markers=");
                push_debug_string_list(&mut detail, &fp.class_markers);
                detail.push_str(" native_images=");
                detail.push_str(&fp.embedded_images.len().to_string());
                detail.push_str(" route=");
                detail.push_str(crate::lang::rcpp::NATIVE_ROUTE_PASS_ID);
                let mut img_names: Vec<String> = fp
                    .embedded_images
                    .iter()
                    .map(|img| format!("rcpp-native:{}@{}", img.format.label(), img.offset))
                    .collect();
                names.append(&mut img_names);
            }
            (names.len(), names, detail)
        }
        ScriptArtifact::Tcl(container) => {
            let names: Vec<String> = container.entries.iter().map(|e| e.path.clone()).collect();
            let detail: String = format!(
                "starkit format={:?} entries={} tcl_files={} obfuscated={} obf_hits=(indirect={},dynproc={},subst={}) completeness={:.2}",
                container.format,
                container.entries.len(),
                container.tcl_source_files.len(),
                container.obfuscation.obfuscated,
                container.obfuscation.indirect_call_hits,
                container.obfuscation.dynamic_proc_hits,
                container.obfuscation.subst_hits,
                container.completeness.ratio()
            );
            (names.len(), names, detail)
        }
        ScriptArtifact::Haxe(fp) => {
            let mut names: Vec<String> = fp.recovered.classes.clone();
            names.extend(fp.recovered.methods.iter().cloned());
            names.sort();
            names.dedup();
            let mut detail: String = format!(
                "haxe target={} route={} version={:?} confirmed={} recovered=(classes={},methods={},source_files={},std_modules={},strings={})",
                fp.target.target_label(),
                fp.route_pass_id,
                fp.compiler_version,
                fp.haxe_confirmed,
                fp.recovered.classes.len(),
                fp.recovered.methods.len(),
                fp.recovered.source_files.len(),
                fp.recovered.std_modules.len(),
                fp.recovered.string_literals.len()
            );
            if let Some(hl) = fp.hashlink.as_ref() {
                push_text!(
                    detail,
                    " hashlink=(v{},types={},globals={},natives={},functions={},opcodes={},constants={},fully_parsed={})",
                    hl.version,
                    hl.num_types,
                    hl.num_globals,
                    hl.num_natives,
                    hl.num_functions,
                    hl.num_opcodes,
                    hl.num_constants,
                    hl.fully_parsed
                );
            }
            (names.len(), names, detail)
        }
        ScriptArtifact::WinScript(recovery) => {
            let mut names: Vec<String> = recovery
                .techniques
                .iter()
                .map(|t: &crate::lang::winscript::WinTechnique| t.tag().to_owned())
                .collect();
            if !recovery.recovered_text.is_empty() {
                names.push(recovery.recovered_text.clone());
            }
            let walls: String = recovery
                .walls
                .iter()
                .map(|w: &crate::lang::winscript::WinWall| {
                    format!("{}:{}", w.technique.tag(), w.reason.tag())
                })
                .collect::<Vec<String>>()
                .join(",");
            let detail: String = format!(
                "win-script lang={} layers={} techniques={} walls=[{}] obfuscated={}",
                recovery.language.tag(),
                recovery.layers.len(),
                recovery.techniques.len(),
                walls,
                recovery.is_obfuscated()
            );
            (names.len(), names, detail)
        }
    };
    ScriptLangReport {
        source_path,
        language: lang.tag().to_owned(),
        format_tag: lang.tag().to_owned(),
        symbol_count,
        recovered_names,
        detail,
    }
}

fn push_debug_string_list(out: &mut String, values: &[String]) {
    out.push('[');
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            out.push_str(", ");
        }
        out.push('"');
        for ch in value.escape_debug() {
            out.push(ch);
        }
        out.push('"');
    }
    out.push(']');
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use disrobe_core::PassMetadata;
    use disrobe_ir::{Envelope, RawPayload, encode_raw};

    use super::*;

    fn synth_envelope(source_path: &str, body: &[u8]) -> Vec<u8> {
        let raw: RawPayload = RawPayload {
            source_path: source_path.to_owned(),
            source_bytes: body.to_vec(),
            source_hash: [0u8; 32],
            detected_format: None,
        };
        let hot: Vec<u8> = encode_raw(&raw).expect("encode raw");
        Envelope::new(Rung::Raw, hot, vec![])
            .encode()
            .expect("encode envelope")
    }

    #[test]
    fn pass_metadata_advertises_capabilities() {
        let p: ScriptLangPass = ScriptLangPass;
        assert_eq!(PassMetadata::id(&p), "disrobe-pass-scriptlang");
        assert_eq!(p.consumes(), &[Rung::Raw]);
        assert_eq!(p.emits(), &[Rung::Surface]);
        assert_eq!(p.required_capabilities().len(), 1);
        assert_eq!(p.produced_capabilities().len(), 1);
    }

    #[test]
    fn pass_run_classifies_haxe_js() {
        let body: &[u8] = b"// Generated by Haxe 4.3.6\n(function(){})();\n";
        let bytes: Vec<u8> = synth_envelope("main.js", body);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [9u8; 32],
        );
        let out: Artifact = ScriptLangPass.run(&input).expect("run");
        assert_eq!(out.rung, Rung::Surface);
        let report: ScriptLangReport =
            serde_json::from_slice(&out.envelope).expect("decode report");
        assert_eq!(report.language, "haxe-target");
        assert!(report.detail.contains("js.deob"));
    }

    fn rcpp_module_rds() -> Vec<u8> {
        const NILVALUE_SXP: u32 = 254u32;
        const SYMSXP: u32 = 1u32;
        const LISTSXP: u32 = 2u32;
        const CHARSXP: u32 = 9u32;
        const STRSXP: u32 = 16u32;
        const RAWSXP: u32 = 24u32;
        const VECSXP: u32 = 19u32;
        const HAS_ATTR_BIT: u32 = 1u32 << 9;
        const HAS_TAG_BIT: u32 = 1u32 << 10;
        let char_sxp = |out: &mut Vec<u8>, s: &str| {
            out.extend_from_slice(&CHARSXP.to_be_bytes());
            out.extend_from_slice(&(s.len() as i32).to_be_bytes());
            out.extend_from_slice(s.as_bytes());
        };
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(b"X\n");
        out.extend_from_slice(&3i32.to_be_bytes());
        out.extend_from_slice(&0x04_05_00i32.to_be_bytes());
        out.extend_from_slice(&0x03_05_00i32.to_be_bytes());
        out.extend_from_slice(&5i32.to_be_bytes());
        out.extend_from_slice(b"UTF-8");
        out.extend_from_slice(&(VECSXP | HAS_ATTR_BIT).to_be_bytes());
        out.extend_from_slice(&2i32.to_be_bytes());
        out.extend_from_slice(&STRSXP.to_be_bytes());
        out.extend_from_slice(&1i32.to_be_bytes());
        char_sxp(&mut out, "RcppExports");
        let mut so: Vec<u8> = vec![0x7f, b'E', b'L', b'F', 0x02, 0x01, 0x01, 0x00];
        so.extend_from_slice(&[0u8; 56]);
        out.extend_from_slice(&RAWSXP.to_be_bytes());
        out.extend_from_slice(&(so.len() as i32).to_be_bytes());
        out.extend_from_slice(&so);
        out.extend_from_slice(&(LISTSXP | HAS_TAG_BIT).to_be_bytes());
        out.extend_from_slice(&SYMSXP.to_be_bytes());
        char_sxp(&mut out, "names");
        out.extend_from_slice(&STRSXP.to_be_bytes());
        out.extend_from_slice(&2i32.to_be_bytes());
        char_sxp(&mut out, "exports");
        char_sxp(&mut out, "dll");
        out.extend_from_slice(&NILVALUE_SXP.to_be_bytes());
        out
    }

    #[test]
    fn pass_run_surfaces_rcpp_routing() {
        let body: Vec<u8> = rcpp_module_rds();
        let bytes: Vec<u8> = synth_envelope("module.rds", &body);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [9u8; 32],
        );
        let out: Artifact = ScriptLangPass.run(&input).expect("run");
        let report: ScriptLangReport =
            serde_json::from_slice(&out.envelope).expect("decode report");
        assert_eq!(report.language, "r-rds");
        assert!(report.detail.contains("rcpp=1"), "detail={}", report.detail);
        assert!(report.detail.contains("native_images=1"));
        assert!(report.detail.contains("disrobe-pass-native"));
        assert!(
            report
                .recovered_names
                .iter()
                .any(|n: &String| n.starts_with("rcpp-native:elf@")),
            "carved native image must appear in recovered names: {:?}",
            report.recovered_names
        );
    }

    #[test]
    fn pass_run_rejects_unrecognized() {
        let bytes: Vec<u8> = synth_envelope("junk.bin", &[0x42u8; 64]);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [9u8; 32],
        );
        let err: CoreError = ScriptLangPass.run(&input).expect_err("must reject");
        assert!(format!("{err}").contains("DR-SCRIPT-PASS"));
    }
}
