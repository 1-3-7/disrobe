#![deny(unsafe_code)]
#![deny(unreachable_pub)]

use std::fmt;

use disrobe_core::Rung;
use disrobe_ir::payload::{
    DisasmPayload, RawPayload, decode_disasm, decode_raw, encode_disasm, encode_raw,
};
use disrobe_ir::{ENVELOPE_FORMAT_VERSION, Envelope};

pub const TRANSCODED_FORMAT_VERSION: u16 = ENVELOPE_FORMAT_VERSION;

#[derive(Debug)]
pub enum TranscodeError {
    Envelope(disrobe_ir::EnvelopeError),
    UnsupportedRung(Rung),
    VerifyHotPayloadMismatch,
    VerifyRungMismatch,
    VerifyColdMutated,
    VerifySourceVersionMismatch,
    VerifyTargetVersionMismatch,
    VerifyLengthMismatch,
}

impl fmt::Display for TranscodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Envelope(e) => write!(f, "envelope codec: {e}"),
            Self::UnsupportedRung(r) => {
                write!(f, "rung {r:?} has no canonical hot-segment codec")
            }
            Self::VerifyHotPayloadMismatch => {
                write!(
                    f,
                    "verify: transcoded hot payload does not owned-value-equal the source payload"
                )
            }
            Self::VerifyRungMismatch => write!(f, "verify: transcoded rung changed"),
            Self::VerifyColdMutated => write!(f, "verify: cold sidecar segment was mutated"),
            Self::VerifySourceVersionMismatch => {
                write!(f, "verify: transcoded source version metadata changed")
            }
            Self::VerifyTargetVersionMismatch => {
                write!(f, "verify: transcoded target version metadata changed")
            }
            Self::VerifyLengthMismatch => {
                write!(
                    f,
                    "verify: transcoded length metadata does not match envelope bytes"
                )
            }
        }
    }
}

impl std::error::Error for TranscodeError {}

impl From<disrobe_ir::EnvelopeError> for TranscodeError {
    fn from(e: disrobe_ir::EnvelopeError) -> Self {
        Self::Envelope(e)
    }
}

pub type Result<T> = std::result::Result<T, TranscodeError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HotPayload {
    Raw(RawPayload),
    Disasm(DisasmPayload),
}

fn decode_hot(rung: Rung, hot: &[u8]) -> Result<HotPayload> {
    match rung {
        Rung::Raw => Ok(HotPayload::Raw(decode_raw(hot)?)),
        Rung::Disasm => Ok(HotPayload::Disasm(decode_disasm(hot)?)),
        other => Err(TranscodeError::UnsupportedRung(other)),
    }
}

fn encode_hot(payload: &HotPayload) -> Result<Vec<u8>> {
    match payload {
        HotPayload::Raw(raw) => Ok(encode_raw(raw)?),
        HotPayload::Disasm(disasm) => Ok(encode_disasm(disasm)?),
    }
}

#[derive(Debug, Clone)]
pub struct Transcoded {
    pub bytes: Vec<u8>,
    pub source_version: u16,
    pub target_version: u16,
    pub rung: Rung,
    pub old_hot_len: usize,
    pub new_hot_len: usize,
    pub cold_len: usize,
}

pub fn transcode_envelope(env: &Envelope) -> Result<Transcoded> {
    let source_version: u16 = env.version;
    let rung: Rung = env.rung;
    let old_hot_len: usize = env.hot.len();
    let cold_len: usize = env.cold.len();

    let payload: HotPayload = decode_hot(rung, &env.hot)?;
    let new_hot: Vec<u8> = encode_hot(&payload)?;
    let new_hot_len: usize = new_hot.len();

    let mut out_env: Envelope = Envelope::new(rung, new_hot, env.cold.clone());
    out_env.flags = env.flags;
    let bytes: Vec<u8> = out_env.encode()?;

    Ok(Transcoded {
        bytes,
        source_version,
        target_version: ENVELOPE_FORMAT_VERSION,
        rung,
        old_hot_len,
        new_hot_len,
        cold_len,
    })
}

pub fn transcode_bytes(input: &[u8]) -> Result<Transcoded> {
    let env: Envelope = Envelope::decode(input)?;
    transcode_envelope(&env)
}

pub fn verify_transcode_envelope(original_env: &Envelope, transcoded: &Transcoded) -> Result<()> {
    let original_payload: HotPayload = decode_hot(original_env.rung, &original_env.hot)?;
    let output_env: Envelope = Envelope::decode(&transcoded.bytes)?;

    if transcoded.source_version != original_env.version {
        return Err(TranscodeError::VerifySourceVersionMismatch);
    }
    if transcoded.target_version != output_env.version
        || output_env.version != TRANSCODED_FORMAT_VERSION
    {
        return Err(TranscodeError::VerifyTargetVersionMismatch);
    }
    if output_env.rung != original_env.rung || output_env.rung != transcoded.rung {
        return Err(TranscodeError::VerifyRungMismatch);
    }
    if transcoded.old_hot_len != original_env.hot.len()
        || transcoded.new_hot_len != output_env.hot.len()
        || transcoded.cold_len != output_env.cold.len()
    {
        return Err(TranscodeError::VerifyLengthMismatch);
    }

    let output_payload: HotPayload = decode_hot(output_env.rung, &output_env.hot)?;
    if output_payload != original_payload {
        return Err(TranscodeError::VerifyHotPayloadMismatch);
    }

    if output_env.cold != original_env.cold {
        return Err(TranscodeError::VerifyColdMutated);
    }

    Ok(())
}

pub fn verify_transcode(original_input: &[u8], transcoded: &Transcoded) -> Result<()> {
    let original_env: Envelope = Envelope::decode(original_input)?;
    verify_transcode_envelope(&original_env, transcoded)
}
