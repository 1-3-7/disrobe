use std::collections::BTreeSet;
use std::io::{Error as IoError, ErrorKind, Write};

use crc32fast::Hasher;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Capability, Rung};

pub const ARTIFACT_LEDGER_FORMAT_VERSION: u16 = 1;
pub const MAX_ARTIFACT_LEDGER_RECORD_BYTES: usize = 4 * 1024 * 1024;

const FRAME_MAGIC: [u8; 4] = *b"DLGR";
const FRAME_HEADER_BYTES: usize = 18;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ArtifactNodeId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactNodeKind {
    Input,
    Intermediate,
    Child,
    Final,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassIdentity {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WallClockDuration {
    pub milliseconds: u64,
}

impl WallClockDuration {
    #[must_use]
    pub const fn from_millis(milliseconds: u64) -> Self {
        Self { milliseconds }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Platform {
    pub operating_system: String,
    pub architecture: String,
    pub endianness: Endianness,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfigurationArgument {
    Flag { name: String, enabled: bool },
    Signed { name: String, value: i64 },
    Unsigned { name: String, value: u64 },
    Text { name: String, value: String },
    Bytes { name: String, value: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunStartRecord {
    pub tool_version: String,
    pub configuration: Vec<ConfigurationArgument>,
    pub input_hash: [u8; 32],
    pub platform: Platform,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactNodeRecord {
    pub id: ArtifactNodeId,
    pub kind: ArtifactNodeKind,
    pub root_hash: [u8; 32],
    pub rung: Rung,
    pub capabilities: BTreeSet<Capability>,
    pub producing_pass: Option<PassIdentity>,
    pub wall_clock: WallClockDuration,
    pub byte_len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandInvocation {
    pub program: String,
    pub arguments: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassInvocation {
    pub pass: PassIdentity,
    pub configuration: Vec<ConfigurationArgument>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeInvocation {
    Command(CommandInvocation),
    Pass(PassInvocation),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactEdgeKind {
    PassApplied,
    ContainerMemberExtracted {
        member_name: String,
    },
    ChainBranch,
    ChainJoin,
    Refusal {
        pass: PassIdentity,
        reason: String,
    },
    Wall {
        pass: Option<PassIdentity>,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactEdgeRecord {
    pub id: u64,
    pub inputs: Vec<ArtifactNodeId>,
    pub outputs: Vec<ArtifactNodeId>,
    pub invocation: Option<EdgeInvocation>,
    pub kind: ArtifactEdgeKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactLedgerRecord {
    RunStart(RunStartRecord),
    Node(ArtifactNodeRecord),
    Edge(ArtifactEdgeRecord),
}

#[derive(Debug, Error)]
pub enum ArtifactLedgerError {
    #[error("artifact ledger record serialization failed: {0}")]
    Serialize(#[source] serde_json::Error),
    #[error("artifact ledger write failed: {0}")]
    Write(#[source] std::io::Error),
    #[error("artifact ledger frame could not reserve {requested} bytes")]
    AllocationFailed { requested: usize },
    #[error(
        "artifact ledger record {record_index:?} is {length} bytes, exceeding the {maximum}-byte limit"
    )]
    RecordTooLarge {
        record_index: Option<usize>,
        length: usize,
        maximum: usize,
        buffered: usize,
    },
    #[error("artifact ledger record {record_index} has an invalid frame marker")]
    InvalidMagic { record_index: usize },
    #[error("artifact ledger record {record_index} uses unknown version {version}")]
    UnknownVersion { record_index: usize, version: u16 },
    #[error("artifact ledger record {record_index} failed its header checksum")]
    HeaderChecksumMismatch { record_index: usize },
    #[error("artifact ledger record {record_index} failed its checksum")]
    ChecksumMismatch { record_index: usize },
    #[error("artifact ledger record {record_index} is invalid: {source}")]
    InvalidRecord {
        record_index: usize,
        #[source]
        source: serde_json::Error,
    },
}

pub fn append_record(
    writer: &mut impl Write,
    record: &ArtifactLedgerRecord,
) -> Result<(), ArtifactLedgerError> {
    let mut frame: BoundedFrame = BoundedFrame::new()?;
    if let Err(source) = serde_json::to_writer(&mut frame, record) {
        if let Some(length) = frame.overflow_length {
            return Err(ArtifactLedgerError::RecordTooLarge {
                record_index: None,
                length,
                maximum: MAX_ARTIFACT_LEDGER_RECORD_BYTES,
                buffered: frame.payload_len(),
            });
        }
        if let Some(requested) = frame.allocation_length {
            return Err(ArtifactLedgerError::AllocationFailed { requested });
        }
        return Err(ArtifactLedgerError::Serialize(source));
    }
    frame.finalize();
    writer
        .write_all(&frame.bytes)
        .map_err(ArtifactLedgerError::Write)
}

pub fn parse_ledger(bytes: &[u8]) -> Result<Vec<ArtifactLedgerRecord>, ArtifactLedgerError> {
    let mut records: Vec<ArtifactLedgerRecord> = Vec::new();
    let mut offset: usize = 0;
    let mut record_index: usize = 0;
    while offset < bytes.len() {
        let remaining: &[u8] = &bytes[offset..];
        if remaining.len() < FRAME_HEADER_BYTES {
            break;
        }
        if remaining[..FRAME_MAGIC.len()] != FRAME_MAGIC {
            return Err(ArtifactLedgerError::InvalidMagic { record_index });
        }
        let version: u16 = u16::from_le_bytes([remaining[4], remaining[5]]);
        if version != ARTIFACT_LEDGER_FORMAT_VERSION {
            return Err(ArtifactLedgerError::UnknownVersion {
                record_index,
                version,
            });
        }
        let expected_header_checksum: u32 =
            u32::from_le_bytes([remaining[10], remaining[11], remaining[12], remaining[13]]);
        let actual_header_checksum: u32 = crc32fast::hash(&remaining[..10]);
        if actual_header_checksum != expected_header_checksum {
            return Err(ArtifactLedgerError::HeaderChecksumMismatch { record_index });
        }
        let payload_len_u32: u32 =
            u32::from_le_bytes([remaining[6], remaining[7], remaining[8], remaining[9]]);
        let payload_len: usize = payload_len_u32 as usize;
        if payload_len > MAX_ARTIFACT_LEDGER_RECORD_BYTES {
            return Err(ArtifactLedgerError::RecordTooLarge {
                record_index: Some(record_index),
                length: payload_len,
                maximum: MAX_ARTIFACT_LEDGER_RECORD_BYTES,
                buffered: 0,
            });
        }
        let frame_len: usize = FRAME_HEADER_BYTES + payload_len;
        if remaining.len() < frame_len {
            break;
        }
        let expected_checksum: u32 =
            u32::from_le_bytes([remaining[14], remaining[15], remaining[16], remaining[17]]);
        let payload: &[u8] = &remaining[FRAME_HEADER_BYTES..frame_len];
        let mut hasher: Hasher = Hasher::new();
        hasher.update(payload);
        let actual_checksum: u32 = hasher.finalize();
        if actual_checksum != expected_checksum {
            return Err(ArtifactLedgerError::ChecksumMismatch { record_index });
        }
        let record: ArtifactLedgerRecord =
            serde_json::from_slice(payload).map_err(|source: serde_json::Error| {
                ArtifactLedgerError::InvalidRecord {
                    record_index,
                    source,
                }
            })?;
        records.push(record);
        offset += frame_len;
        record_index += 1;
    }
    Ok(records)
}

struct BoundedFrame {
    bytes: Vec<u8>,
    overflow_length: Option<usize>,
    allocation_length: Option<usize>,
}

impl BoundedFrame {
    fn new() -> Result<Self, ArtifactLedgerError> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.try_reserve_exact(FRAME_HEADER_BYTES).map_err(|_| {
            ArtifactLedgerError::AllocationFailed {
                requested: FRAME_HEADER_BYTES,
            }
        })?;
        bytes.resize(FRAME_HEADER_BYTES, 0);
        Ok(Self {
            bytes,
            overflow_length: None,
            allocation_length: None,
        })
    }

    const fn payload_len(&self) -> usize {
        self.bytes.len() - FRAME_HEADER_BYTES
    }

    fn finalize(&mut self) {
        let payload_len: usize = self.payload_len();
        let payload_len_u32: u32 = payload_len as u32;
        self.bytes[..4].copy_from_slice(&FRAME_MAGIC);
        self.bytes[4..6].copy_from_slice(&ARTIFACT_LEDGER_FORMAT_VERSION.to_le_bytes());
        self.bytes[6..10].copy_from_slice(&payload_len_u32.to_le_bytes());
        let header_checksum: u32 = crc32fast::hash(&self.bytes[..10]);
        self.bytes[10..14].copy_from_slice(&header_checksum.to_le_bytes());
        let payload_checksum: u32 = crc32fast::hash(&self.bytes[FRAME_HEADER_BYTES..]);
        self.bytes[14..18].copy_from_slice(&payload_checksum.to_le_bytes());
    }
}

impl Write for BoundedFrame {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let buffered: usize = self.payload_len();
        let attempted: usize = buffered.saturating_add(buffer.len());
        if attempted > MAX_ARTIFACT_LEDGER_RECORD_BYTES {
            self.overflow_length = Some(attempted);
            return Err(IoError::new(
                ErrorKind::FileTooLarge,
                "artifact ledger record exceeds size limit",
            ));
        }
        if self.bytes.try_reserve_exact(buffer.len()).is_err() {
            self.allocation_length = Some(FRAME_HEADER_BYTES + attempted);
            return Err(IoError::new(
                ErrorKind::OutOfMemory,
                "artifact ledger frame allocation failed",
            ));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiny_record_does_not_reserve_the_record_limit() -> Result<(), ArtifactLedgerError> {
        let mut frame: BoundedFrame = BoundedFrame::new()?;
        frame.write_all(b"{}").map_err(ArtifactLedgerError::Write)?;

        assert!(frame.bytes.capacity() < MAX_ARTIFACT_LEDGER_RECORD_BYTES);
        Ok(())
    }
}
