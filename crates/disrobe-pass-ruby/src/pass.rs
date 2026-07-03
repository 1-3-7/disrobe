use disrobe_core::debug::DebugLog;
use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};
use disrobe_ir::{Envelope, decode_raw};
use serde::{Deserialize, Serialize};

use crate::detect::{Flavor, sniff};
use crate::error::RubyError;
use crate::jruby::{JrubyDelegation, delegate as jruby_delegate};
use crate::mri::{MriAst, parse_mri};
use crate::mruby::{MrubyAnalysis, analyze as mruby_analyze};
use crate::truffleruby::{TruffleRubyAot, walk as truffle_walk};
use crate::wrappers::{WrapperExtract, extract as wrapper_extract};
use crate::yarv::{YarvAnalysis, analyze as yarv_analyze};

pub const PASS_INPUT_PATH_CAP: &str = "raw.ruby";

#[derive(Debug, Default, Clone, Copy)]
pub struct RubyPass;

impl LegacyPass for RubyPass {
    const CONSUMES: &'static [Rung] = &[Rung::Raw];
    const EMITS: &'static [Rung] = &[Rung::Disasm];
    const REQUIRES: &'static [fn() -> Capability] =
        &[|| Capability::requires(PASS_INPUT_PATH_CAP, 1)];
    const PRODUCES: &'static [fn() -> Capability] = &[
        || Capability::produces("disasm.ruby", 1),
        || Capability::produces("ruby.flavor.detected", 1),
    ];

    fn id(&self) -> PassId {
        "disrobe-pass-ruby"
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let input: PassInput = decode_pass_input(&artifact.envelope);
        let analysis: RubyAnalysis = analyze_bytes(&input.wrapper_bytes, &input.source_path)
            .map_err(|e: RubyError| CoreError::PassFailure(format!("{e}")))?;
        let payload: Vec<u8> = serde_json::to_vec(&analysis).map_err(|e: serde_json::Error| {
            CoreError::PassFailure(format!("DR-RUBY-PASS: serialize: {e}"))
        })?;
        let mut next: Artifact = Artifact::new(Rung::Disasm, payload, artifact.root_hash);
        for producer in <Self as LegacyPass>::PRODUCES {
            next.add_capability(producer());
        }
        Ok(next)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PassInput {
    pub source_path: String,
    pub wrapper_bytes: Vec<u8>,
}

#[must_use]
pub fn decode_pass_input(envelope_bytes: &[u8]) -> PassInput {
    if let Ok(envelope) = Envelope::decode(envelope_bytes)
        && let Ok(raw) = decode_raw(&envelope.hot)
    {
        return PassInput {
            source_path: raw.source_path,
            wrapper_bytes: raw.source_bytes,
        };
    }
    if let Ok(raw) = decode_raw(envelope_bytes) {
        return PassInput {
            source_path: raw.source_path,
            wrapper_bytes: raw.source_bytes,
        };
    }
    PassInput {
        source_path: "<artifact>".to_owned(),
        wrapper_bytes: envelope_bytes.to_vec(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RubyAnalysis {
    pub flavor: Flavor,
    pub source_path: String,
    pub input_len: u32,
    pub input_hash: [u8; 32],
    pub mri: Option<MriAst>,
    pub yarv: Option<YarvAnalysis>,
    pub mruby: Option<MrubyAnalysis>,
    pub jruby: Option<JrubyDelegation>,
    pub truffleruby: Option<TruffleRubyAot>,
    pub wrapper: Option<WrapperExtract>,
}

pub fn analyze_bytes(bytes: &[u8], source_path: &str) -> crate::error::Result<RubyAnalysis> {
    let dbg: DebugLog = DebugLog::for_scope("ruby");
    dbg.section("ruby.analyze");
    dbg.kv("input_len", || bytes.len().to_string());
    let flavor: Flavor = sniff(bytes, source_path)?;
    dbg.kv("flavor", || format!("{flavor:?}"));
    let mut analysis: RubyAnalysis = RubyAnalysis {
        flavor,
        source_path: source_path.to_owned(),
        input_len: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
        input_hash: blake3::hash(bytes).into(),
        mri: None,
        yarv: None,
        mruby: None,
        jruby: None,
        truffleruby: None,
        wrapper: None,
    };
    match flavor {
        Flavor::MriSource => analysis.mri = Some(parse_mri(bytes, source_path)?),
        Flavor::YarvBinary => analysis.yarv = Some(yarv_analyze(bytes)?),
        Flavor::MrubyBinary => analysis.mruby = Some(mruby_analyze(bytes)?),
        Flavor::JrubyClass => analysis.jruby = Some(jruby_delegate(bytes)?),
        Flavor::TruffleRubyAot => analysis.truffleruby = Some(truffle_walk(bytes)?),
        Flavor::Ruby2Exe | Flavor::Ocra => analysis.wrapper = Some(wrapper_extract(bytes)?),
    }
    dbg.line(|| format!("recovered via {flavor:?} branch"));
    Ok(analysis)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use disrobe_core::PassMetadata;
    use disrobe_ir::{Envelope, RawPayload, encode_raw};

    use super::*;

    fn wrap_envelope(source_path: &str, bytes: &[u8]) -> Vec<u8> {
        let raw: RawPayload = RawPayload {
            source_path: source_path.to_owned(),
            source_bytes: bytes.to_vec(),
            source_hash: blake3::hash(bytes).into(),
            detected_format: None,
        };
        let hot: Vec<u8> = encode_raw(&raw).expect("encode raw");
        let env: Envelope = Envelope::new(Rung::Raw, hot, vec![]);
        env.encode().expect("encode envelope")
    }

    #[test]
    fn metadata_advertises_capabilities() {
        let p: RubyPass = RubyPass;
        assert_eq!(PassMetadata::id(&p), "disrobe-pass-ruby");
        assert_eq!(p.consumes(), &[Rung::Raw]);
        assert_eq!(p.emits(), &[Rung::Disasm]);
        assert_eq!(p.required_capabilities().len(), 1);
        assert_eq!(p.produced_capabilities().len(), 2);
    }

    #[test]
    fn run_on_mri_source_emits_disasm_with_mri() {
        let bytes: Vec<u8> = wrap_envelope("hello.rb", b"puts 'hello world'\n");
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [9u8; 32],
        );
        let out: Artifact = RubyPass.run(&input).expect("run");
        assert_eq!(out.rung, Rung::Disasm);
        let json: RubyAnalysis = serde_json::from_slice(&out.envelope).expect("parse json");
        assert_eq!(json.flavor, Flavor::MriSource);
        assert!(json.mri.is_some());
    }
}
