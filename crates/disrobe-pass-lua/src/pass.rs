use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};
use disrobe_ir::{Envelope, decode_raw};
use serde::{Deserialize, Serialize};

use crate::debug::{dbg_kv, dbg_line, dbg_section};

use crate::obfuscator::{
    LuaObfuscatorKind, ObfuscatorDetection, aztup_brew, boronide, darksec, hercules, ironbrew2,
    luaobfuscator_com, luraph, moonsec_v1, moonsec_v2, moonsec_v3, prometheus, psu, slua,
    wearedevs,
};
use crate::reader::{DetectedFormat, LuaChunk, LuaProto, detect, read_auto};

pub const PASS_INPUT_PATH_CAP: &str = "raw.lua";

#[derive(Debug, Default, Clone, Copy)]
pub struct LuaPass;

impl LegacyPass for LuaPass {
    const CONSUMES: &'static [Rung] = &[Rung::Raw];
    const EMITS: &'static [Rung] = &[Rung::Surface];
    const REQUIRES: &'static [fn() -> Capability] =
        &[|| Capability::requires(PASS_INPUT_PATH_CAP, 1)];
    const PRODUCES: &'static [fn() -> Capability] =
        &[|| Capability::produces("lua.format-detected", 1)];

    fn id(&self) -> PassId {
        "disrobe-pass-lua"
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        dbg_section("lua.pass");
        let input: PassInput = decode_pass_input(&artifact.envelope);
        dbg_kv("input_len", || input.bytes.len().to_string());
        dbg_kv("source_path", || input.source_path.clone());
        let obfuscation: Option<ObfuscatorDetection> = max_obfuscator(&input.bytes);
        let format: DetectedFormat = detect(&input.bytes);
        dbg_kv("obfuscator", || {
            obfuscation.as_ref().map_or_else(
                || "none".to_owned(),
                |d: &ObfuscatorDetection| format!("{:?} (conf {})", d.kind, d.confidence),
            )
        });
        dbg_kv("format", || format!("{format:?}"));
        if obfuscation.is_none() && matches!(format, DetectedFormat::Unknown) {
            dbg_line(|| "no obfuscator and unknown format: not recoverable lua".to_owned());
            return Err(CoreError::PassFailure(
                "DR-LUA-PASS: input is neither known lua bytecode nor an obfuscated lua wrapper"
                    .to_owned(),
            ));
        }
        let (function_count, constant_count): (Option<usize>, Option<usize>) =
            if obfuscation.is_none() {
                match read_auto(&input.bytes) {
                    Ok(chunk) => (Some(count_protos(&chunk)), Some(count_constants(&chunk))),
                    Err(e) => {
                        dbg_line(|| format!("read_auto failed, metadata-only fallback: {e}"));
                        (None, None)
                    }
                }
            } else {
                dbg_line(|| "obfuscated wrapper detected: metadata-only classification".to_owned());
                (None, None)
            };
        dbg_kv("function_count", || format!("{function_count:?}"));
        dbg_kv("constant_count", || format!("{constant_count:?}"));
        let report: LuaPassReport = LuaPassReport {
            source_path: input.source_path,
            format: format_label(format),
            obfuscator_kind: obfuscation.map(|d: ObfuscatorDetection| kind_label(d.kind)),
            function_count,
            constant_count,
        };
        let payload: Vec<u8> = serde_json::to_vec(&report)
            .map_err(|e| CoreError::PassFailure(format!("DR-LUA-PASS encode: {e}")))?;
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
pub struct LuaPassReport {
    pub source_path: String,
    pub format: String,
    pub obfuscator_kind: Option<String>,
    pub function_count: Option<usize>,
    pub constant_count: Option<usize>,
}

fn max_obfuscator(bytes: &[u8]) -> Option<ObfuscatorDetection> {
    let candidates: [Option<ObfuscatorDetection>; 14] = [
        prometheus::detect(bytes),
        moonsec_v1::detect(bytes),
        moonsec_v2::detect(bytes),
        moonsec_v3::detect(bytes),
        ironbrew2::detect(bytes),
        aztup_brew::detect(bytes),
        darksec::detect(bytes),
        boronide::detect(bytes),
        psu::detect(bytes),
        wearedevs::detect(bytes),
        luaobfuscator_com::detect(bytes),
        slua::detect(bytes),
        hercules::detect(bytes),
        luraph::detect(bytes),
    ];
    candidates
        .into_iter()
        .flatten()
        .max_by_key(|d: &ObfuscatorDetection| d.confidence)
}

fn format_label(fmt: DetectedFormat) -> String {
    match fmt {
        DetectedFormat::Lua51 => "lua-5.1",
        DetectedFormat::Lua52 => "lua-5.2",
        DetectedFormat::Lua53 => "lua-5.3",
        DetectedFormat::Lua54 => "lua-5.4",
        DetectedFormat::LuaJit => "luajit",
        DetectedFormat::Luau => "luau",
        DetectedFormat::GLua => "glua",
        DetectedFormat::Unknown => "unknown",
    }
    .to_owned()
}

fn kind_label(k: LuaObfuscatorKind) -> String {
    match k {
        LuaObfuscatorKind::Prometheus => "prometheus",
        LuaObfuscatorKind::MoonSecV1 => "moonsec-v1",
        LuaObfuscatorKind::MoonSecV2 => "moonsec-v2",
        LuaObfuscatorKind::MoonSecV3 => "moonsec-v3",
        LuaObfuscatorKind::Ironbrew2 => "ironbrew2",
        LuaObfuscatorKind::AztupBrew => "aztup-brew",
        LuaObfuscatorKind::DarkSec => "darksec",
        LuaObfuscatorKind::Boronide => "boronide",
        LuaObfuscatorKind::Psu => "psu",
        LuaObfuscatorKind::WeAreDevs => "wearedevs",
        LuaObfuscatorKind::LuaObfuscatorCom => "luaobfuscator-com",
        LuaObfuscatorKind::Slua => "slua",
        LuaObfuscatorKind::Hercules => "hercules",
        LuaObfuscatorKind::Luraph => "luraph",
    }
    .to_owned()
}

fn count_protos(chunk: &LuaChunk) -> usize {
    fn walk(p: &LuaProto, acc: &mut usize) {
        *acc += 1;
        for sub in &p.protos {
            walk(sub, acc);
        }
    }
    let mut acc: usize = 0usize;
    walk(&chunk.main, &mut acc);
    acc
}

fn count_constants(chunk: &LuaChunk) -> usize {
    fn walk(p: &LuaProto, acc: &mut usize) {
        *acc += p.constants.len();
        for sub in &p.protos {
            walk(sub, acc);
        }
    }
    let mut acc: usize = 0usize;
    walk(&chunk.main, &mut acc);
    acc
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
    fn lua_pass_metadata_advertises_capabilities() {
        let p: LuaPass = LuaPass;
        assert_eq!(PassMetadata::id(&p), "disrobe-pass-lua");
        assert_eq!(p.consumes(), &[Rung::Raw]);
        assert_eq!(p.emits(), &[Rung::Surface]);
        assert_eq!(p.required_capabilities().len(), 1);
        assert_eq!(p.produced_capabilities().len(), 1);
    }

    #[test]
    fn pass_run_envelope_roundtrip() {
        let body: &[u8] = &[0x1b, b'L', b'u', b'a', 0x51, 0, 0, 0];
        let bytes: Vec<u8> = synth_envelope("chunk.luac", body);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let out: Artifact = LuaPass.run(&input).expect("run");
        assert_eq!(out.rung, Rung::Surface);
        assert_eq!(out.root_hash, [7u8; 32]);
        let report: LuaPassReport = serde_json::from_slice(&out.envelope).expect("decode report");
        assert_eq!(report.source_path, "chunk.luac");
        assert_eq!(report.format, "lua-5.1");
    }

    #[test]
    fn lua_pass_run_rejects_unrecognized_input() {
        let bytes: Vec<u8> = synth_envelope("junk.bin", &[0xffu8; 32]);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let err: CoreError = LuaPass.run(&input).expect_err("must reject");
        assert!(format!("{err}").contains("DR-LUA-PASS"));
    }
}
