use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};
use disrobe_ir::{Envelope, decode_raw};
use serde::{Deserialize, Serialize};

use crate::lang::{ScriptArtifact, ScriptLang, analyze, classify};

pub const PASS_INPUT_PATH_CAP: &str = "raw.scriptlang";

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
        let input: PassInput = decode_pass_input(&artifact.envelope);
        let Some(lang): Option<ScriptLang> = classify(&input.bytes) else {
            return Err(CoreError::PassFailure(
                "DR-SCRIPT-PASS: input is not a recognized perl/r/tcl/haxe artifact".to_owned(),
            ));
        };
        let artifact_data: ScriptArtifact =
            analyze(&input.bytes).map_err(|e: crate::error::Error| {
                CoreError::PassFailure(format!("DR-SCRIPT-PASS: {e}"))
            })?;
        let report: ScriptLangReport = build_report(input.source_path, lang, &artifact_data);
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
            let detail: String = format!(
                "rds v{} root={} len={:?} class={:?}",
                obj.header.version, obj.root_type, obj.root_length, obj.class
            );
            (names.len(), names, detail)
        }
        ScriptArtifact::Tcl(container) => {
            let names: Vec<String> = container.entries.iter().map(|e| e.path.clone()).collect();
            let detail: String = format!(
                "starkit format={:?} entries={} tcl_files={}",
                container.format,
                container.entries.len(),
                container.tcl_source_files.len()
            );
            (names.len(), names, detail)
        }
        ScriptArtifact::Haxe(fp) => {
            let detail: String = format!(
                "haxe target={} route={} version={:?} confirmed={}",
                fp.target.target_label(),
                fp.route_pass_id,
                fp.compiler_version,
                fp.haxe_confirmed
            );
            (0usize, Vec::new(), detail)
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
