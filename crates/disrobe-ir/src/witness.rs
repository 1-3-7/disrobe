use disrobe_core::recovery::ConfidenceTier;

const MAGIC: &[u8; 8] = b"DRWITNS\0";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 14;
const RECORD_BYTES: usize = 68;
const MAX_RECORDS: usize = 1 << 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransformKind {
    Transcode = 0,
}

impl TransformKind {
    const fn from_byte(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Transcode),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WitnessKind {
    ByteIdentity = 0,
}

impl WitnessKind {
    const fn from_byte(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::ByteIdentity),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WitnessRecord {
    pub transform: TransformKind,
    pub claim_tier: ConfidenceTier,
    pub witness: WitnessKind,
    pub input_root: [u8; 32],
    pub output_root: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessSidecar {
    records: Vec<WitnessRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessVerification {
    Reproduced,
    NotReproduced,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WitnessError {
    #[error("witness sidecar is truncated: expected at least {expected} bytes, got {actual}")]
    Truncated { expected: usize, actual: usize },
    #[error("witness sidecar magic is invalid")]
    BadMagic,
    #[error("witness sidecar version {0} is unsupported")]
    BadVersion(u16),
    #[error("witness sidecar record count {actual} exceeds the {max}-record cap")]
    RecordLimit { actual: usize, max: usize },
    #[error("witness sidecar size calculation overflows")]
    SizeOverflow,
    #[error("witness sidecar length is {actual}, expected exactly {expected}")]
    LengthMismatch { expected: usize, actual: usize },
    #[error("witness sidecar transform kind {0} is unsupported")]
    BadTransform(u8),
    #[error("witness sidecar confidence tier {0} is unsupported")]
    BadClaimTier(u8),
    #[error("witness sidecar witness kind {0} is unsupported")]
    BadWitness(u8),
    #[error("witness sidecar reserved byte is nonzero")]
    BadReserved,
    #[error("byte-identity witness input and output differ")]
    NotByteIdentical,
    #[error("witness sidecar has no records")]
    Empty,
}

impl WitnessSidecar {
    pub fn exact_transcode(input: &[u8], output: &[u8]) -> Result<Self, WitnessError> {
        if input != output {
            return Err(WitnessError::NotByteIdentical);
        }
        let input_root: [u8; 32] = *blake3::hash(input).as_bytes();
        let output_root: [u8; 32] = *blake3::hash(output).as_bytes();
        Ok(Self {
            records: vec![WitnessRecord {
                transform: TransformKind::Transcode,
                claim_tier: ConfidenceTier::Exact,
                witness: WitnessKind::ByteIdentity,
                input_root,
                output_root,
            }],
        })
    }

    #[must_use]
    pub fn records(&self) -> &[WitnessRecord] {
        &self.records
    }

    pub fn encode(&self) -> Result<Vec<u8>, WitnessError> {
        if self.records.len() > MAX_RECORDS {
            return Err(WitnessError::RecordLimit {
                actual: self.records.len(),
                max: MAX_RECORDS,
            });
        }
        let payload_bytes: usize = self
            .records
            .len()
            .checked_mul(RECORD_BYTES)
            .ok_or(WitnessError::SizeOverflow)?;
        let total_bytes: usize = HEADER_BYTES
            .checked_add(payload_bytes)
            .ok_or(WitnessError::SizeOverflow)?;
        let count: u32 =
            u32::try_from(self.records.len()).map_err(|_| WitnessError::RecordLimit {
                actual: self.records.len(),
                max: MAX_RECORDS,
            })?;
        let mut encoded: Vec<u8> = Vec::with_capacity(total_bytes);
        encoded.extend_from_slice(MAGIC);
        encoded.extend_from_slice(&VERSION.to_le_bytes());
        encoded.extend_from_slice(&count.to_le_bytes());
        for record in &self.records {
            encoded.push(record.transform as u8);
            encoded.push(record.claim_tier.rank());
            encoded.push(record.witness as u8);
            encoded.push(0);
            encoded.extend_from_slice(&record.input_root);
            encoded.extend_from_slice(&record.output_root);
        }
        Ok(encoded)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WitnessError> {
        if bytes.len() < HEADER_BYTES {
            return Err(WitnessError::Truncated {
                expected: HEADER_BYTES,
                actual: bytes.len(),
            });
        }
        if bytes.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
            return Err(WitnessError::BadMagic);
        }
        let version: u16 = read_u16(bytes, 8)?;
        if version != VERSION {
            return Err(WitnessError::BadVersion(version));
        }
        let count: usize =
            usize::try_from(read_u32(bytes, 10)?).map_err(|_| WitnessError::RecordLimit {
                actual: usize::MAX,
                max: MAX_RECORDS,
            })?;
        if count > MAX_RECORDS {
            return Err(WitnessError::RecordLimit {
                actual: count,
                max: MAX_RECORDS,
            });
        }
        if count == 0 {
            return Err(WitnessError::Empty);
        }
        let expected: usize = HEADER_BYTES
            .checked_add(
                count
                    .checked_mul(RECORD_BYTES)
                    .ok_or(WitnessError::SizeOverflow)?,
            )
            .ok_or(WitnessError::SizeOverflow)?;
        if bytes.len() != expected {
            return Err(WitnessError::LengthMismatch {
                expected,
                actual: bytes.len(),
            });
        }
        let mut records: Vec<WitnessRecord> = Vec::with_capacity(count);
        for index in 0..count {
            let at: usize = HEADER_BYTES + index * RECORD_BYTES;
            let transform_byte: u8 = bytes[at];
            let claim_byte: u8 = bytes[at + 1];
            let witness_byte: u8 = bytes[at + 2];
            if bytes[at + 3] != 0 {
                return Err(WitnessError::BadReserved);
            }
            let transform: TransformKind = TransformKind::from_byte(transform_byte)
                .ok_or(WitnessError::BadTransform(transform_byte))?;
            let claim_tier: ConfidenceTier = ConfidenceTier::from_rank(claim_byte)
                .ok_or(WitnessError::BadClaimTier(claim_byte))?;
            let witness: WitnessKind = WitnessKind::from_byte(witness_byte)
                .ok_or(WitnessError::BadWitness(witness_byte))?;
            let input_root: [u8; 32] = read_root(bytes, at + 4)?;
            let output_root: [u8; 32] = read_root(bytes, at + 36)?;
            records.push(WitnessRecord {
                transform,
                claim_tier,
                witness,
                input_root,
                output_root,
            });
        }
        Ok(Self { records })
    }

    pub fn verify(&self, input: &[u8], output: &[u8]) -> Result<WitnessVerification, WitnessError> {
        if self.records.is_empty() {
            return Err(WitnessError::Empty);
        }
        let input_root: [u8; 32] = *blake3::hash(input).as_bytes();
        let output_root: [u8; 32] = *blake3::hash(output).as_bytes();
        let reproduced: bool = self.records.iter().all(|record: &WitnessRecord| {
            record.transform == TransformKind::Transcode
                && record.claim_tier == ConfidenceTier::Exact
                && record.witness == WitnessKind::ByteIdentity
                && record.input_root == input_root
                && record.output_root == output_root
                && input_root == output_root
        });
        Ok(if reproduced {
            WitnessVerification::Reproduced
        } else {
            WitnessVerification::NotReproduced
        })
    }
}

fn read_u16(bytes: &[u8], at: usize) -> Result<u16, WitnessError> {
    let end: usize = at.checked_add(2).ok_or(WitnessError::SizeOverflow)?;
    let field: &[u8] = bytes.get(at..end).ok_or(WitnessError::Truncated {
        expected: end,
        actual: bytes.len(),
    })?;
    let array: [u8; 2] = field.try_into().map_err(|_| WitnessError::Truncated {
        expected: end,
        actual: bytes.len(),
    })?;
    Ok(u16::from_le_bytes(array))
}

fn read_u32(bytes: &[u8], at: usize) -> Result<u32, WitnessError> {
    let end: usize = at.checked_add(4).ok_or(WitnessError::SizeOverflow)?;
    let field: &[u8] = bytes.get(at..end).ok_or(WitnessError::Truncated {
        expected: end,
        actual: bytes.len(),
    })?;
    let array: [u8; 4] = field.try_into().map_err(|_| WitnessError::Truncated {
        expected: end,
        actual: bytes.len(),
    })?;
    Ok(u32::from_le_bytes(array))
}

fn read_root(bytes: &[u8], at: usize) -> Result<[u8; 32], WitnessError> {
    let end: usize = at.checked_add(32).ok_or(WitnessError::SizeOverflow)?;
    let field: &[u8] = bytes.get(at..end).ok_or(WitnessError::Truncated {
        expected: end,
        actual: bytes.len(),
    })?;
    field.try_into().map_err(|_| WitnessError::Truncated {
        expected: end,
        actual: bytes.len(),
    })
}
