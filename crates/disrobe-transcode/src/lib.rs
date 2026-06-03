#![deny(unsafe_code)]

pub mod mirror;

use std::fmt;

use disrobe_core::Rung;
use disrobe_ir::payload::{
    ArchivedDisasmPayload, ArchivedRawPayload, DisasmInstruction, DisasmPayload, DisasmSymbol,
    DisasmSymbolKind, RawPayload,
};
use disrobe_ir::{ENVELOPE_FORMAT_VERSION, Envelope, compute_root_hash};
use rkyv::rancor::Error as RkyvError;

use crate::mirror::{
    ArchivedDisasmPayloadMirror, ArchivedRawPayloadMirror, DisasmInstructionMirror,
    DisasmPayloadMirror, DisasmSymbolKindMirror, DisasmSymbolMirror, RawPayloadMirror,
};

pub const TRANSCODED_FORMAT_VERSION: u16 = ENVELOPE_FORMAT_VERSION + 1;

#[derive(Debug)]
pub enum TranscodeError {
    Envelope(disrobe_ir::EnvelopeError),
    RkyvAccess(String),
    RkyvDeser(String),
    RkyvSer(String),
    UnsupportedRung(Rung),
    VerifyHotPayloadMismatch,
    VerifyRootMismatch,
    VerifyColdMutated,
}

impl fmt::Display for TranscodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Envelope(e) => write!(f, "envelope codec: {e}"),
            Self::RkyvAccess(e) => write!(f, "rkyv access (source 0.8): {e}"),
            Self::RkyvDeser(e) => write!(f, "rkyv deserialize (source 0.8): {e}"),
            Self::RkyvSer(e) => write!(f, "rkyv serialize (target): {e}"),
            Self::UnsupportedRung(r) => {
                write!(f, "rung {r:?} has no rkyv hot-segment codec to transcode")
            }
            Self::VerifyHotPayloadMismatch => {
                write!(
                    f,
                    "verify: transcoded hot payload does not owned-value-equal the source payload"
                )
            }
            Self::VerifyRootMismatch => {
                write!(
                    f,
                    "verify: recomputed BLAKE3 root does not match rewritten header"
                )
            }
            Self::VerifyColdMutated => write!(f, "verify: cold sidecar segment was mutated"),
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

fn raw_to_mirror(p: RawPayload) -> RawPayloadMirror {
    let RawPayload {
        source_path,
        source_bytes,
        source_hash,
        detected_format,
    }: RawPayload = p;
    RawPayloadMirror {
        source_path,
        source_bytes,
        source_hash,
        detected_format,
    }
}

const fn symbol_kind_to_mirror(k: DisasmSymbolKind) -> DisasmSymbolKindMirror {
    match k {
        DisasmSymbolKind::Function => DisasmSymbolKindMirror::Function,
        DisasmSymbolKind::Data => DisasmSymbolKindMirror::Data,
        DisasmSymbolKind::Label => DisasmSymbolKindMirror::Label,
        DisasmSymbolKind::Export => DisasmSymbolKindMirror::Export,
        DisasmSymbolKind::Import => DisasmSymbolKindMirror::Import,
    }
}

fn instruction_to_mirror(i: DisasmInstruction) -> DisasmInstructionMirror {
    let DisasmInstruction {
        offset,
        bytes,
        mnemonic,
        operands,
    }: DisasmInstruction = i;
    DisasmInstructionMirror {
        offset,
        bytes,
        mnemonic,
        operands,
    }
}

fn symbol_to_mirror(s: DisasmSymbol) -> DisasmSymbolMirror {
    let DisasmSymbol {
        address,
        name,
        kind,
    }: DisasmSymbol = s;
    DisasmSymbolMirror {
        address,
        name,
        kind: symbol_kind_to_mirror(kind),
    }
}

fn disasm_to_mirror(p: DisasmPayload) -> DisasmPayloadMirror {
    let DisasmPayload {
        source_hash,
        instructions,
        symbol_table,
    }: DisasmPayload = p;
    DisasmPayloadMirror {
        source_hash,
        instructions: instructions
            .into_iter()
            .map(instruction_to_mirror)
            .collect(),
        symbol_table: symbol_table.into_iter().map(symbol_to_mirror).collect(),
    }
}

fn decode_hot(rung: Rung, hot: &[u8]) -> Result<HotPayload> {
    match rung {
        Rung::Raw => {
            let archived: &ArchivedRawPayload = rkyv::access::<ArchivedRawPayload, RkyvError>(hot)
                .map_err(|e| TranscodeError::RkyvAccess(e.to_string()))?;
            let owned: RawPayload = rkyv::deserialize::<RawPayload, RkyvError>(archived)
                .map_err(|e| TranscodeError::RkyvDeser(e.to_string()))?;
            Ok(HotPayload::Raw(owned))
        }
        Rung::Disasm => {
            let archived: &ArchivedDisasmPayload =
                rkyv::access::<ArchivedDisasmPayload, RkyvError>(hot)
                    .map_err(|e| TranscodeError::RkyvAccess(e.to_string()))?;
            let owned: DisasmPayload = rkyv::deserialize::<DisasmPayload, RkyvError>(archived)
                .map_err(|e| TranscodeError::RkyvDeser(e.to_string()))?;
            Ok(HotPayload::Disasm(owned))
        }
        other => Err(TranscodeError::UnsupportedRung(other)),
    }
}

fn reencode_hot(payload: HotPayload) -> Result<Vec<u8>> {
    match payload {
        HotPayload::Raw(raw) => {
            let mirror: RawPayloadMirror = raw_to_mirror(raw);
            rkyv::to_bytes::<RkyvError>(&mirror)
                .map(|b| b.to_vec())
                .map_err(|e| TranscodeError::RkyvSer(e.to_string()))
        }
        HotPayload::Disasm(disasm) => {
            let mirror: DisasmPayloadMirror = disasm_to_mirror(disasm);
            rkyv::to_bytes::<RkyvError>(&mirror)
                .map(|b| b.to_vec())
                .map_err(|e| TranscodeError::RkyvSer(e.to_string()))
        }
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

pub fn transcode_bytes(input: &[u8]) -> Result<Transcoded> {
    let env: Envelope = Envelope::decode(input)?;
    let source_version: u16 = env.version;
    let rung: Rung = env.rung;
    let old_hot_len: usize = env.hot.len();
    let cold_len: usize = env.cold.len();

    let payload: HotPayload = decode_hot(rung, &env.hot)?;
    let new_hot: Vec<u8> = reencode_hot(payload)?;
    let new_hot_len: usize = new_hot.len();

    let new_root: [u8; 32] = compute_root_hash(&new_hot, &env.cold);
    let out_env: Envelope = Envelope {
        version: TRANSCODED_FORMAT_VERSION,
        rung,
        flags: env.flags,
        hot: new_hot,
        cold: env.cold,
        root_hash: new_root,
    };
    let bytes: Vec<u8> = out_env.encode()?;

    Ok(Transcoded {
        bytes,
        source_version,
        target_version: TRANSCODED_FORMAT_VERSION,
        rung,
        old_hot_len,
        new_hot_len,
        cold_len,
    })
}

pub fn verify_transcode(original_input: &[u8], transcoded: &Transcoded) -> Result<()> {
    let original_env: Envelope = Envelope::decode(original_input)?;
    let original_payload: HotPayload = decode_hot(original_env.rung, &original_env.hot)?;

    let (out_hot, out_cold): (Vec<u8>, Vec<u8>) = split_segments(&transcoded.bytes)?;

    let transcoded_payload: HotPayload = decode_hot_target(transcoded.rung, &out_hot)?;
    if transcoded_payload != original_payload {
        return Err(TranscodeError::VerifyHotPayloadMismatch);
    }

    let recomputed: [u8; 32] = compute_root_hash(&out_hot, &out_cold);
    let header_root: [u8; 32] = header_root_hash(&transcoded.bytes)?;
    if recomputed != header_root {
        return Err(TranscodeError::VerifyRootMismatch);
    }

    if out_cold != original_env.cold {
        return Err(TranscodeError::VerifyColdMutated);
    }

    Ok(())
}

fn decode_hot_target(rung: Rung, hot: &[u8]) -> Result<HotPayload> {
    match rung {
        Rung::Raw => {
            let archived: &ArchivedRawPayloadMirror =
                rkyv::access::<ArchivedRawPayloadMirror, RkyvError>(hot)
                    .map_err(|e| TranscodeError::RkyvAccess(e.to_string()))?;
            let owned: RawPayloadMirror =
                rkyv::deserialize::<RawPayloadMirror, RkyvError>(archived)
                    .map_err(|e| TranscodeError::RkyvDeser(e.to_string()))?;
            Ok(HotPayload::Raw(mirror_to_raw(owned)))
        }
        Rung::Disasm => {
            let archived: &ArchivedDisasmPayloadMirror =
                rkyv::access::<ArchivedDisasmPayloadMirror, RkyvError>(hot)
                    .map_err(|e| TranscodeError::RkyvAccess(e.to_string()))?;
            let owned: DisasmPayloadMirror =
                rkyv::deserialize::<DisasmPayloadMirror, RkyvError>(archived)
                    .map_err(|e| TranscodeError::RkyvDeser(e.to_string()))?;
            Ok(HotPayload::Disasm(mirror_to_disasm(owned)))
        }
        other => Err(TranscodeError::UnsupportedRung(other)),
    }
}

fn mirror_to_raw(m: RawPayloadMirror) -> RawPayload {
    let RawPayloadMirror {
        source_path,
        source_bytes,
        source_hash,
        detected_format,
    }: RawPayloadMirror = m;
    RawPayload {
        source_path,
        source_bytes,
        source_hash,
        detected_format,
    }
}

const fn mirror_kind_to_kind(k: DisasmSymbolKindMirror) -> DisasmSymbolKind {
    match k {
        DisasmSymbolKindMirror::Function => DisasmSymbolKind::Function,
        DisasmSymbolKindMirror::Data => DisasmSymbolKind::Data,
        DisasmSymbolKindMirror::Label => DisasmSymbolKind::Label,
        DisasmSymbolKindMirror::Export => DisasmSymbolKind::Export,
        DisasmSymbolKindMirror::Import => DisasmSymbolKind::Import,
    }
}

fn mirror_to_disasm(m: DisasmPayloadMirror) -> DisasmPayload {
    let DisasmPayloadMirror {
        source_hash,
        instructions,
        symbol_table,
    }: DisasmPayloadMirror = m;
    DisasmPayload {
        source_hash,
        instructions: instructions
            .into_iter()
            .map(|i: DisasmInstructionMirror| {
                let DisasmInstructionMirror {
                    offset,
                    bytes,
                    mnemonic,
                    operands,
                }: DisasmInstructionMirror = i;
                DisasmInstruction {
                    offset,
                    bytes,
                    mnemonic,
                    operands,
                }
            })
            .collect(),
        symbol_table: symbol_table
            .into_iter()
            .map(|s: DisasmSymbolMirror| {
                let DisasmSymbolMirror {
                    address,
                    name,
                    kind,
                }: DisasmSymbolMirror = s;
                DisasmSymbol {
                    address,
                    name,
                    kind: mirror_kind_to_kind(kind),
                }
            })
            .collect(),
    }
}

const HEADER_SIZE: usize = disrobe_ir::HEADER_SIZE;
const HOT_LEN_OFFSET: usize = 12;
const COLD_LEN_OFFSET: usize = 16;
const ROOT_HASH_OFFSET: usize = 20;

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<usize> {
    let slice: &[u8] = bytes
        .get(offset..offset + 4)
        .ok_or(TranscodeError::Envelope(
            disrobe_ir::EnvelopeError::Truncated {
                expected: offset + 4,
                got: bytes.len(),
            },
        ))?;
    let arr: [u8; 4] = slice.try_into().map_err(|_| {
        TranscodeError::Envelope(disrobe_ir::EnvelopeError::Truncated {
            expected: offset + 4,
            got: bytes.len(),
        })
    })?;
    Ok(u32::from_le_bytes(arr) as usize)
}

fn split_segments(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if bytes.len() < HEADER_SIZE {
        return Err(TranscodeError::Envelope(
            disrobe_ir::EnvelopeError::Truncated {
                expected: HEADER_SIZE,
                got: bytes.len(),
            },
        ));
    }
    let hot_len: usize = read_u32_le(bytes, HOT_LEN_OFFSET)?;
    let cold_len: usize = read_u32_le(bytes, COLD_LEN_OFFSET)?;
    let hot_end: usize = HEADER_SIZE + hot_len;
    let cold_end: usize = hot_end + cold_len;
    let hot: &[u8] = bytes
        .get(HEADER_SIZE..hot_end)
        .ok_or(TranscodeError::Envelope(
            disrobe_ir::EnvelopeError::Truncated {
                expected: hot_end,
                got: bytes.len(),
            },
        ))?;
    let cold: &[u8] = bytes
        .get(hot_end..cold_end)
        .ok_or(TranscodeError::Envelope(
            disrobe_ir::EnvelopeError::Truncated {
                expected: cold_end,
                got: bytes.len(),
            },
        ))?;
    Ok((hot.to_vec(), cold.to_vec()))
}

fn header_root_hash(bytes: &[u8]) -> Result<[u8; 32]> {
    let slice: &[u8] =
        bytes
            .get(ROOT_HASH_OFFSET..ROOT_HASH_OFFSET + 32)
            .ok_or(TranscodeError::Envelope(
                disrobe_ir::EnvelopeError::Truncated {
                    expected: ROOT_HASH_OFFSET + 32,
                    got: bytes.len(),
                },
            ))?;
    let arr: [u8; 32] = slice.try_into().map_err(|_| {
        TranscodeError::Envelope(disrobe_ir::EnvelopeError::Truncated {
            expected: ROOT_HASH_OFFSET + 32,
            got: bytes.len(),
        })
    })?;
    Ok(arr)
}
