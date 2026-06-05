use rkyv::{Archive, Deserialize, Serialize, rancor::Error as RkyvError};

use crate::error::{EnvelopeError, Result};

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(derive(Debug))]
pub struct RawPayload {
    pub source_path: String,
    pub source_bytes: Vec<u8>,
    pub source_hash: [u8; 32],
    pub detected_format: Option<String>,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(derive(Debug))]
pub struct DisasmPayload {
    pub source_hash: [u8; 32],
    pub instructions: Vec<DisasmInstruction>,
    pub symbol_table: Vec<DisasmSymbol>,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(derive(Debug))]
pub struct DisasmInstruction {
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: Vec<String>,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(derive(Debug))]
pub struct DisasmSymbol {
    pub address: u64,
    pub name: String,
    pub kind: DisasmSymbolKind,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[rkyv(derive(Debug))]
pub enum DisasmSymbolKind {
    Function,
    Data,
    Label,
    Export,
    Import,
}

#[inline]
pub fn encode_raw(payload: &RawPayload) -> Result<Vec<u8>> {
    rkyv::to_bytes::<RkyvError>(payload)
        .map(|bytes| bytes.to_vec())
        .map_err(|e| EnvelopeError::RkyvSer(e.to_string()))
}

#[inline]
pub fn decode_raw(bytes: &[u8]) -> Result<RawPayload> {
    let archived: &ArchivedRawPayload = rkyv::access::<ArchivedRawPayload, RkyvError>(bytes)
        .map_err(|e| EnvelopeError::RkyvAccess(e.to_string()))?;
    rkyv::deserialize::<RawPayload, RkyvError>(archived)
        .map_err(|e| EnvelopeError::RkyvDeser(e.to_string()))
}

#[inline]
pub fn encode_disasm(payload: &DisasmPayload) -> Result<Vec<u8>> {
    rkyv::to_bytes::<RkyvError>(payload)
        .map(|bytes| bytes.to_vec())
        .map_err(|e| EnvelopeError::RkyvSer(e.to_string()))
}

#[inline]
pub fn decode_disasm(bytes: &[u8]) -> Result<DisasmPayload> {
    let archived: &ArchivedDisasmPayload = rkyv::access::<ArchivedDisasmPayload, RkyvError>(bytes)
        .map_err(|e| EnvelopeError::RkyvAccess(e.to_string()))?;
    rkyv::deserialize::<DisasmPayload, RkyvError>(archived)
        .map_err(|e| EnvelopeError::RkyvDeser(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_raw_payload() {
        let p: RawPayload = RawPayload {
            source_path: "hello.wasm".to_owned(),
            source_bytes: vec![0, 1, 2, 3, 4, 5, 6, 7],
            source_hash: [0xAA; 32],
            detected_format: Some("wasm".to_owned()),
        };
        let bytes: Vec<u8> = encode_raw(&p).expect("encode");
        let decoded: RawPayload = decode_raw(&bytes).expect("decode");
        assert_eq!(p, decoded);
    }

    #[test]
    fn round_trip_raw_payload_no_format() {
        let p: RawPayload = RawPayload {
            source_path: "/tmp/blob".to_owned(),
            source_bytes: vec![],
            source_hash: [0; 32],
            detected_format: None,
        };
        let bytes: Vec<u8> = encode_raw(&p).expect("encode");
        let decoded: RawPayload = decode_raw(&bytes).expect("decode");
        assert_eq!(p, decoded);
        assert!(decoded.detected_format.is_none());
    }

    #[test]
    fn round_trip_disasm_payload() {
        let p: DisasmPayload = DisasmPayload {
            source_hash: [0xBB; 32],
            instructions: vec![
                DisasmInstruction {
                    offset: 0x1000,
                    bytes: vec![0x55, 0x48, 0x89, 0xE5],
                    mnemonic: "push".to_owned(),
                    operands: vec!["rbp".to_owned()],
                },
                DisasmInstruction {
                    offset: 0x1004,
                    bytes: vec![0xC3],
                    mnemonic: "ret".to_owned(),
                    operands: vec![],
                },
            ],
            symbol_table: vec![DisasmSymbol {
                address: 0x1000,
                name: "main".to_owned(),
                kind: DisasmSymbolKind::Function,
            }],
        };
        let bytes: Vec<u8> = encode_disasm(&p).expect("encode");
        let decoded: DisasmPayload = decode_disasm(&bytes).expect("decode");
        assert_eq!(p, decoded);
    }

    #[test]
    fn rkyv_zero_copy_access_does_not_deserialize() {
        let p: RawPayload = RawPayload {
            source_path: "a.bin".to_owned(),
            source_bytes: vec![9, 8, 7],
            source_hash: [1; 32],
            detected_format: None,
        };
        let bytes: Vec<u8> = encode_raw(&p).expect("encode");
        let archived: &ArchivedRawPayload =
            rkyv::access::<ArchivedRawPayload, RkyvError>(&bytes).expect("access");
        assert_eq!(archived.source_path.as_str(), "a.bin");
        assert_eq!(archived.source_bytes.as_slice(), &[9u8, 8, 7]);
        assert_eq!(archived.source_hash, [1u8; 32]);
        assert!(archived.detected_format.is_none());
    }
}
