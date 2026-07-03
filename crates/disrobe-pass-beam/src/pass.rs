use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};
use disrobe_ir::{Envelope, decode_raw};
use serde::{Deserialize, Serialize};

use crate::debug::{dbg_hex, dbg_kv, dbg_line, dbg_section};
use crate::surface::{self, ErlangSurface};
use crate::{BeamFile, disassemble};

pub const PASS_INPUT_PATH_CAP: &str = "raw.beam";

#[derive(Debug, Default, Clone, Copy)]
pub struct BeamPass;

impl LegacyPass for BeamPass {
    const CONSUMES: &'static [Rung] = &[Rung::Raw];
    const EMITS: &'static [Rung] = &[Rung::Disasm];
    const REQUIRES: &'static [fn() -> Capability] =
        &[|| Capability::requires(PASS_INPUT_PATH_CAP, 1)];
    const PRODUCES: &'static [fn() -> Capability] = &[
        || Capability::produces("disasm.beam", 1),
        || Capability::produces("beam.flavor-detected", 1),
    ];

    fn id(&self) -> PassId {
        "disrobe-pass-beam"
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        dbg_section("beam analyze");
        let input: PassInput = decode_pass_input(&artifact.envelope);
        dbg_kv("source_path", || input.source_path.clone());
        dbg_kv("input_len", || input.bytes.len().to_string());
        dbg_hex("input_magic", &input.bytes, 12);
        dbg_kv("classify", || match input.bytes.first_chunk::<4>() {
            Some(b"FOR1") => "beam (FOR1/BEAM IFF container)".to_owned(),
            Some(other) => format!("unrecognized magic {other:02x?}"),
            None => "truncated: fewer than 4 bytes".to_owned(),
        });
        let beam: BeamFile = BeamFile::parse(&input.bytes).map_err(|e| {
            dbg_line(|| format!("beam parse failed: {e}"));
            CoreError::PassFailure(format!("DR-BEAM-PASS: {e}"))
        })?;
        dbg_kv("chunks", || {
            format!(
                "atoms={} exports={} imports={} locals={} funs={} code={} dbgi={} docs={} attrs={} literals={} line={}",
                beam.chunks.atoms.atoms.len(),
                beam.chunks.exports.len(),
                beam.chunks.imports.len(),
                beam.chunks.locals.len(),
                beam.chunks.funs.len(),
                beam.chunks.code.is_some(),
                beam.chunks.dbgi.is_some(),
                beam.chunks.docs.is_some(),
                beam.chunks.attributes.is_some(),
                beam.chunks.literals.is_some(),
                beam.chunks.line.is_some(),
            )
        });
        let instruction_count: u32 = beam
            .chunks
            .code
            .as_ref()
            .map(|c| {
                disassemble(c).map(|d| u32::try_from(d.instructions.len()).unwrap_or(u32::MAX))
            })
            .transpose()
            .map_err(|e| {
                dbg_line(|| format!("beam disassemble failed: {e}"));
                CoreError::PassFailure(format!("DR-BEAM-PASS: {e}"))
            })?
            .unwrap_or(0);
        dbg_kv("instruction_count", || instruction_count.to_string());
        let symbolic_disasm: Option<String> = beam.chunks.code.as_ref().and_then(|_| {
            crate::symbolic::symbolic_disassemble(&beam)
                .map(|m| crate::symbolic::render_symbolic(&m))
                .ok()
        });
        dbg_kv("symbolic_disasm", || match &symbolic_disasm {
            Some(s) => format!("bytes={}", s.len()),
            None => "none".to_owned(),
        });
        let recovery: Option<ErlangSurface> = surface::recover(&beam).ok();
        dbg_kv("recovered", || match &recovery {
            Some(s) => format!(
                "module={} from={:?} source_bytes={}",
                s.module,
                s.recovered_from,
                s.source.len()
            ),
            None => "none".to_owned(),
        });
        let (module, recovered_from, recovered_source): (
            Option<String>,
            Option<String>,
            Option<String>,
        ) = match recovery {
            Some(surface) => (
                Some(surface.module),
                Some(format!("{:?}", surface.recovered_from)),
                Some(surface.source),
            ),
            None => (None, None, None),
        };
        let report: BeamPassReport = BeamPassReport {
            source_path: input.source_path,
            form_length: beam.form_length,
            atom_count: u32::try_from(beam.chunks.atoms.atoms.len()).unwrap_or(u32::MAX),
            export_count: u32::try_from(beam.chunks.exports.len()).unwrap_or(u32::MAX),
            import_count: u32::try_from(beam.chunks.imports.len()).unwrap_or(u32::MAX),
            has_code: beam.chunks.code.is_some(),
            has_dbgi: beam.chunks.dbgi.is_some(),
            instruction_count,
            module,
            recovered_from,
            recovered_source,
            symbolic_disasm,
        };
        let payload: Vec<u8> = serde_json::to_vec(&report)
            .map_err(|e| CoreError::PassFailure(format!("DR-BEAM-PASS: serialize: {e}")))?;
        let mut next: Artifact = Artifact::new(Rung::Disasm, payload, artifact.root_hash);
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
pub struct BeamPassReport {
    pub source_path: String,
    pub form_length: u32,
    pub atom_count: u32,
    pub export_count: u32,
    pub import_count: u32,
    pub has_code: bool,
    pub has_dbgi: bool,
    pub instruction_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovered_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovered_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbolic_disasm: Option<String>,
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

    fn minimal_beam() -> (Vec<u8>, u32) {
        let mut atu8: Vec<u8> = Vec::new();
        atu8.extend_from_slice(&1i32.to_be_bytes());
        atu8.push(5u8);
        atu8.extend_from_slice(b"hello");
        let mut form_body: Vec<u8> = Vec::new();
        form_body.extend_from_slice(b"BEAM");
        form_body.extend_from_slice(b"AtU8");
        form_body.extend_from_slice(&u32::try_from(atu8.len()).unwrap().to_be_bytes());
        form_body.extend_from_slice(&atu8);
        let pad: usize = (4 - atu8.len() % 4) % 4;
        form_body.extend(std::iter::repeat_n(0u8, pad));
        let form_length: u32 = u32::try_from(form_body.len()).unwrap();
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(b"FOR1");
        out.extend_from_slice(&form_length.to_be_bytes());
        out.extend_from_slice(&form_body);
        (out, form_length)
    }

    #[test]
    fn beam_pass_metadata_advertises_capabilities() {
        let p: BeamPass = BeamPass;
        assert_eq!(PassMetadata::id(&p), "disrobe-pass-beam");
        assert_eq!(p.consumes(), &[Rung::Raw]);
        assert_eq!(p.emits(), &[Rung::Disasm]);
        assert_eq!(p.required_capabilities().len(), 1);
        assert_eq!(p.produced_capabilities().len(), 2);
    }

    #[test]
    fn pass_run_envelope_roundtrip() {
        let (body, form_length): (Vec<u8>, u32) = minimal_beam();
        let bytes: Vec<u8> = synth_envelope("raw.beam", &body);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let out: Artifact = BeamPass.run(&input).expect("run");
        assert_eq!(out.rung, Rung::Disasm);
        assert_eq!(out.root_hash, [7u8; 32]);
        let report: BeamPassReport = serde_json::from_slice(&out.envelope).expect("decode report");
        assert_eq!(report.form_length, form_length);
        assert_eq!(report.atom_count, 1);
        assert!(!report.has_code);
    }

    #[test]
    fn beam_pass_run_rejects_unrecognized_input() {
        let bytes: Vec<u8> = synth_envelope("junk.bin", &[0xffu8; 32]);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let err: CoreError = BeamPass.run(&input).expect_err("must reject");
        assert!(format!("{err}").contains("DR-BEAM-PASS"));
    }

    const HELLO_BEAM: &[u8] = include_bytes!("../../../corpus/beam/erlang/hello.beam");

    #[test]
    fn pass_run_surfaces_recovered_erlang_source() {
        let bytes: Vec<u8> = synth_envelope("hello.beam", HELLO_BEAM);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [9u8; 32],
        );
        let out: Artifact = BeamPass.run(&input).expect("run");
        let report: BeamPassReport = serde_json::from_slice(&out.envelope).expect("decode report");
        assert_eq!(report.module.as_deref(), Some("hello"));
        let source: String = report
            .recovered_source
            .expect("surface recovery must reach the pass output, not just a counts summary");
        assert!(
            source.contains("-module"),
            "expected recovered erlang module in pass output, got: {source}"
        );
        assert!(
            report.recovered_from.is_some(),
            "recovered_from provenance must be attached"
        );
    }

    #[test]
    fn pass_run_surfaces_symbolic_disassembly() {
        let bytes: Vec<u8> = synth_envelope("hello.beam", HELLO_BEAM);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [9u8; 32],
        );
        let out: Artifact = BeamPass.run(&input).expect("run");
        let report: BeamPassReport = serde_json::from_slice(&out.envelope).expect("decode report");
        let disasm: String = report
            .symbolic_disasm
            .expect("symbolic disassembly must reach the pass output");
        assert!(
            disasm.contains("{func_info,{atom,hello},{atom,main},0}"),
            "expected beam_disasm-shaped func_info in symbolic output, got: {disasm}"
        );
        assert!(
            disasm.contains("{label,") && disasm.contains("function, main, 0"),
            "expected per-function resolved instruction blocks, got: {disasm}"
        );
    }
}
