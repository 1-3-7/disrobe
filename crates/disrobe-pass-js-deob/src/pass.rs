use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};
use disrobe_ir::{Envelope, decode_raw};
use serde::{Deserialize, Serialize};

use crate::{DeobOptions, DeobOutput, Detection, JsObfuscator, deobfuscate_all, detect};

pub const PASS_INPUT_PATH_CAP: &str = "raw.js";

#[derive(Debug, Default, Clone, Copy)]
pub struct JsPass;

impl LegacyPass for JsPass {
    const CONSUMES: &'static [Rung] = &[Rung::Raw];
    const EMITS: &'static [Rung] = &[Rung::Surface];
    const REQUIRES: &'static [fn() -> Capability] =
        &[|| Capability::requires(PASS_INPUT_PATH_CAP, 1)];
    const PRODUCES: &'static [fn() -> Capability] =
        &[|| Capability::produces("js.obfuscator-detected", 1)];

    fn id(&self) -> PassId {
        "disrobe-pass-js-deob"
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let input: PassInput = decode_pass_input(&artifact.envelope);
        crate::debug::dbg_section("js-deob pass run");
        crate::debug::dbg_kv("source-path", || input.source_path.clone());
        let detection: Detection = detect(&input.bytes);
        if matches!(detection.family, JsObfuscator::Unknown) {
            crate::debug::dbg_line(|| "bail: no obfuscator/bundler family recognized".to_owned());
            return Err(CoreError::PassFailure(
                "DR-JS-PASS: no obfuscator/bundler family recognized".to_owned(),
            ));
        }
        let recovery: Option<JsRecovery> = recover_jsconfuser(detection.family, &input.bytes);
        let report: JsPassReport = JsPassReport {
            source_path: input.source_path,
            family: format!("{:?}", detection.family),
            confidence: detection.confidence,
            markers: detection.markers,
            recovery,
        };
        let payload: Vec<u8> = serde_json::to_vec(&report).map_err(|e: serde_json::Error| {
            CoreError::PassFailure(format!("DR-JS-PASS: serialize: {e}"))
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsPassReport {
    pub source_path: String,
    pub family: String,
    pub confidence: f32,
    pub markers: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<JsRecovery>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JsRecovery {
    pub recovered_source: String,
    pub state_sum_machines_linearized: usize,
    pub state_sum_blocks_recovered: usize,
    pub rgf_eval_wrappers_inlined: usize,
    pub rgf_eval_runtime_walls: usize,
    pub string_conceal_call_sites_decoded: usize,
    pub string_conceal_runtime_keyed: bool,
    pub string_literals_decoded: usize,
    pub string_compression_blocks_reversed: usize,
    pub flatten_dispatches_collapsed: usize,
}

fn recover_jsconfuser(family: JsObfuscator, bytes: &[u8]) -> Option<JsRecovery> {
    if !matches!(family, JsObfuscator::JsConfuser) {
        return None;
    }
    let source: &str = std::str::from_utf8(bytes).ok()?;
    let opts: DeobOptions = DeobOptions::all();
    let out: DeobOutput = deobfuscate_all(source, &opts);
    Some(JsRecovery {
        recovered_source: out.source,
        state_sum_machines_linearized: out.state_sum_machines_linearized,
        state_sum_blocks_recovered: out.state_sum_blocks_recovered,
        rgf_eval_wrappers_inlined: out.rgf_eval_wrappers_inlined,
        rgf_eval_runtime_walls: out.rgf_eval_runtime_walls,
        string_conceal_call_sites_decoded: out.string_conceal_call_sites_decoded,
        string_conceal_runtime_keyed: out.string_conceal_runtime_keyed,
        string_literals_decoded: out.string_literals_decoded,
        string_compression_blocks_reversed: out.string_compression_blocks_reversed,
        flatten_dispatches_collapsed: out.flatten_dispatches_collapsed,
    })
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
    fn js_pass_metadata_advertises_capabilities() {
        let p: JsPass = JsPass;
        assert_eq!(PassMetadata::id(&p), "disrobe-pass-js-deob");
        assert_eq!(p.consumes(), &[Rung::Raw]);
        assert_eq!(p.emits(), &[Rung::Surface]);
        assert_eq!(p.required_capabilities().len(), 1);
        assert_eq!(p.produced_capabilities().len(), 1);
    }

    #[test]
    fn pass_run_envelope_roundtrip() {
        let body: &[u8] = b"// obfuscator.io output\nvar _0xabcd = function(){};";
        let bytes: Vec<u8> = synth_envelope("raw.js", body);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let out: Artifact = JsPass.run(&input).expect("run");
        assert_eq!(out.rung, Rung::Surface);
        assert_eq!(out.root_hash, [7u8; 32]);
        let report: JsPassReport = serde_json::from_slice(&out.envelope).expect("decode report");
        assert_eq!(report.source_path, "raw.js");
        assert_eq!(report.family, "ObfuscatorIo");
        assert!(report.confidence > 0.9);
    }

    #[test]
    fn js_pass_run_rejects_unrecognized_input() {
        let body: &[u8] = b"const x = 1;\nfunction foo(){ return x+1; }";
        let bytes: Vec<u8> = synth_envelope("clean.js", body);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let err: CoreError = JsPass.run(&input).expect_err("must reject");
        assert!(format!("{err}").contains("DR-JS-PASS"));
    }
}
