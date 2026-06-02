use crate::Rung;
use crate::error::{EnvelopeError, Result};
use crate::{ENVELOPE_FORMAT_VERSION, ENVELOPE_MAGIC};

pub const HEADER_SIZE: usize = 8 + 2 + 1 + 1 + 4 + 4 + 32;

const MAGIC_OFFSET: usize = 0;
const VERSION_OFFSET: usize = 8;
const RUNG_OFFSET: usize = 10;
const FLAGS_OFFSET: usize = 11;
const HOT_LEN_OFFSET: usize = 12;
const COLD_LEN_OFFSET: usize = 16;
const ROOT_HASH_OFFSET: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub version: u16,
    pub rung: Rung,
    pub flags: u8,
    pub hot: Vec<u8>,
    pub cold: Vec<u8>,
    pub root_hash: [u8; 32],
}

impl Envelope {
    #[inline]
    #[must_use]
    pub fn new(rung: Rung, hot: Vec<u8>, cold: Vec<u8>) -> Self {
        let root_hash: [u8; 32] = compute_root_hash(&hot, &cold);
        Self {
            version: ENVELOPE_FORMAT_VERSION,
            rung,
            flags: 0,
            hot,
            cold,
            root_hash,
        }
    }

    pub fn header_bytes(&self) -> Result<[u8; HEADER_SIZE]> {
        let hot_len: u32 =
            u32::try_from(self.hot.len()).map_err(|_| EnvelopeError::PayloadTooLarge {
                actual: self.hot.len(),
                max: u32::MAX,
            })?;
        let cold_len: u32 =
            u32::try_from(self.cold.len()).map_err(|_| EnvelopeError::PayloadTooLarge {
                actual: self.cold.len(),
                max: u32::MAX,
            })?;
        let mut h: [u8; HEADER_SIZE] = [0u8; HEADER_SIZE];
        h[MAGIC_OFFSET..MAGIC_OFFSET + 8].copy_from_slice(ENVELOPE_MAGIC);
        h[VERSION_OFFSET..VERSION_OFFSET + 2].copy_from_slice(&self.version.to_le_bytes());
        h[RUNG_OFFSET] = self.rung as u8;
        h[FLAGS_OFFSET] = self.flags;
        h[HOT_LEN_OFFSET..HOT_LEN_OFFSET + 4].copy_from_slice(&hot_len.to_le_bytes());
        h[COLD_LEN_OFFSET..COLD_LEN_OFFSET + 4].copy_from_slice(&cold_len.to_le_bytes());
        h[ROOT_HASH_OFFSET..ROOT_HASH_OFFSET + 32].copy_from_slice(&self.root_hash);
        Ok(h)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let header: [u8; HEADER_SIZE] = self.header_bytes()?;
        let total: usize = HEADER_SIZE + self.hot.len() + self.cold.len();
        let mut out: Vec<u8> = Vec::with_capacity(total);
        out.extend_from_slice(&header);
        out.extend_from_slice(&self.hot);
        out.extend_from_slice(&self.cold);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_SIZE {
            return Err(EnvelopeError::Truncated {
                expected: HEADER_SIZE,
                got: bytes.len(),
            });
        }
        let Some(header_slice) = bytes.get(..HEADER_SIZE) else {
            return Err(EnvelopeError::Truncated {
                expected: HEADER_SIZE,
                got: bytes.len(),
            });
        };
        let header: &[u8; HEADER_SIZE] = match header_slice.try_into() {
            Ok(arr) => arr,
            Err(_) => {
                return Err(EnvelopeError::Truncated {
                    expected: HEADER_SIZE,
                    got: bytes.len(),
                });
            }
        };
        let magic: [u8; 8] = read_array::<8>(header, MAGIC_OFFSET);
        if &magic != ENVELOPE_MAGIC {
            return Err(EnvelopeError::BadMagic {
                expected: *ENVELOPE_MAGIC,
                got: magic,
            });
        }
        let version: u16 = u16::from_le_bytes(read_array::<2>(header, VERSION_OFFSET));
        if version != ENVELOPE_FORMAT_VERSION {
            return Err(EnvelopeError::BadVersion(version));
        }
        let rung: Rung = decode_rung(header[RUNG_OFFSET])?;
        let flags: u8 = header[FLAGS_OFFSET];
        let hot_len: usize = u32::from_le_bytes(read_array::<4>(header, HOT_LEN_OFFSET)) as usize;
        let cold_len: usize = u32::from_le_bytes(read_array::<4>(header, COLD_LEN_OFFSET)) as usize;
        let root_hash: [u8; 32] = read_array::<32>(header, ROOT_HASH_OFFSET);

        let expected_total: usize = HEADER_SIZE + hot_len + cold_len;
        if bytes.len() < expected_total {
            return Err(EnvelopeError::Truncated {
                expected: expected_total,
                got: bytes.len(),
            });
        }

        let hot_end: usize = HEADER_SIZE + hot_len;
        let cold_end: usize = hot_end + cold_len;
        let hot: Vec<u8> = bytes[HEADER_SIZE..hot_end].to_vec();
        let cold: Vec<u8> = bytes[hot_end..cold_end].to_vec();

        let computed: [u8; 32] = compute_root_hash(&hot, &cold);
        if computed != root_hash {
            return Err(EnvelopeError::RootHashMismatch {
                header: root_hash,
                computed,
            });
        }

        Ok(Self {
            version,
            rung,
            flags,
            hot,
            cold,
            root_hash,
        })
    }
}

#[inline]
#[must_use]
pub fn compute_root_hash(hot: &[u8], cold: &[u8]) -> [u8; 32] {
    let mut hasher: blake3::Hasher = blake3::Hasher::new();
    hasher.update(hot);
    hasher.update(cold);
    *hasher.finalize().as_bytes()
}

#[inline]
fn read_array<const N: usize>(src: &[u8; HEADER_SIZE], offset: usize) -> [u8; N] {
    let mut out: [u8; N] = [0u8; N];
    let end: usize = offset + N;
    out.copy_from_slice(&src[offset..end]);
    out
}

#[inline]
const fn decode_rung(b: u8) -> Result<Rung> {
    match b {
        0 => Ok(Rung::Raw),
        1 => Ok(Rung::Disasm),
        2 => Ok(Rung::Mir),
        3 => Ok(Rung::Hir),
        4 => Ok(Rung::Surface),
        other => Err(EnvelopeError::BadRung(other)),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::payload::{RawPayload, encode_raw};
    use crate::sidecar::Sidecar;
    use disrobe_core::Capability;
    use std::collections::BTreeMap;

    fn sample_sidecar() -> Sidecar {
        Sidecar {
            produced_by: "test-pass".to_owned(),
            produced_by_version: "0.1.0".to_owned(),
            capabilities: vec![Capability::produces("test-cap", 1)],
            provenance: BTreeMap::default(),
        }
    }

    fn sample_raw_payload() -> RawPayload {
        RawPayload {
            source_path: "x.wasm".to_owned(),
            source_bytes: vec![0, 1, 2, 3],
            source_hash: [0x11; 32],
            detected_format: Some("wasm".to_owned()),
        }
    }

    #[test]
    fn round_trip_empty_envelope() {
        let env: Envelope = Envelope::new(Rung::Raw, vec![], vec![]);
        let bytes: Vec<u8> = env.encode().expect("encode");
        assert_eq!(bytes.len(), HEADER_SIZE);
        let decoded: Envelope = Envelope::decode(&bytes).expect("decode");
        assert_eq!(env, decoded);
    }

    #[test]
    fn round_trip_with_payloads() {
        let hot: Vec<u8> = encode_raw(&sample_raw_payload()).expect("encode raw");
        let cold: Vec<u8> = sample_sidecar().encode().expect("encode sidecar");
        let env: Envelope = Envelope::new(Rung::Raw, hot, cold);
        let bytes: Vec<u8> = env.encode().expect("encode");
        let decoded: Envelope = Envelope::decode(&bytes).expect("decode");
        assert_eq!(env, decoded);
        assert_eq!(decoded.rung, Rung::Raw);
    }

    #[test]
    fn truncated_header_rejected() {
        let env: Envelope = Envelope::new(Rung::Raw, vec![], vec![]);
        let mut bytes: Vec<u8> = env.encode().expect("encode");
        bytes.truncate(HEADER_SIZE - 1);
        let err: EnvelopeError = Envelope::decode(&bytes).expect_err("should fail");
        assert!(matches!(err, EnvelopeError::Truncated { .. }));
    }

    #[test]
    fn bad_magic_rejected() {
        let env: Envelope = Envelope::new(Rung::Raw, vec![1, 2, 3], vec![4, 5]);
        let mut bytes: Vec<u8> = env.encode().expect("encode");
        bytes[0] = b'X';
        let err: EnvelopeError = Envelope::decode(&bytes).expect_err("should fail");
        assert!(matches!(err, EnvelopeError::BadMagic { .. }));
    }

    #[test]
    fn bad_version_rejected() {
        let env: Envelope = Envelope::new(Rung::Raw, vec![], vec![]);
        let mut bytes: Vec<u8> = env.encode().expect("encode");
        bytes[VERSION_OFFSET] = 0xFF;
        bytes[VERSION_OFFSET + 1] = 0xFF;
        let err: EnvelopeError = Envelope::decode(&bytes).expect_err("should fail");
        assert!(matches!(err, EnvelopeError::BadVersion(_)));
    }

    #[test]
    fn unknown_rung_rejected() {
        let env: Envelope = Envelope::new(Rung::Raw, vec![], vec![]);
        let mut bytes: Vec<u8> = env.encode().expect("encode");
        bytes[RUNG_OFFSET] = 0xEE;
        let err: EnvelopeError = Envelope::decode(&bytes).expect_err("should fail");
        assert!(matches!(err, EnvelopeError::BadRung(0xEE)));
    }

    #[test]
    fn tampered_hot_payload_caught_by_root_hash() {
        let hot: Vec<u8> = vec![10, 20, 30, 40];
        let cold: Vec<u8> = vec![50, 60];
        let env: Envelope = Envelope::new(Rung::Raw, hot, cold);
        let mut bytes: Vec<u8> = env.encode().expect("encode");
        bytes[HEADER_SIZE] ^= 0x01;
        let err: EnvelopeError = Envelope::decode(&bytes).expect_err("should fail");
        assert!(matches!(err, EnvelopeError::RootHashMismatch { .. }));
    }

    #[test]
    fn tampered_cold_sidecar_caught_by_root_hash() {
        let hot: Vec<u8> = vec![10, 20, 30, 40];
        let cold: Vec<u8> = vec![50, 60, 70];
        let env: Envelope = Envelope::new(Rung::Raw, hot, cold);
        let mut bytes: Vec<u8> = env.encode().expect("encode");
        bytes[HEADER_SIZE + 4] ^= 0x01;
        let err: EnvelopeError = Envelope::decode(&bytes).expect_err("should fail");
        assert!(matches!(err, EnvelopeError::RootHashMismatch { .. }));
    }

    #[test]
    fn rung_round_trips_across_all_variants() {
        for rung in [Rung::Raw, Rung::Disasm, Rung::Mir, Rung::Hir, Rung::Surface] {
            let env: Envelope = Envelope::new(rung, vec![1, 2], vec![3]);
            let bytes: Vec<u8> = env.encode().expect("encode");
            let decoded: Envelope = Envelope::decode(&bytes).expect("decode");
            assert_eq!(decoded.rung, rung);
        }
    }

    #[test]
    fn root_hash_is_deterministic() {
        let h1: [u8; 32] = compute_root_hash(&[1, 2, 3], &[4, 5]);
        let h2: [u8; 32] = compute_root_hash(&[1, 2, 3], &[4, 5]);
        assert_eq!(h1, h2);
        let h3: [u8; 32] = compute_root_hash(&[1, 2, 3], &[4, 6]);
        assert_ne!(h1, h3);
    }

    #[test]
    fn header_bytes_matches_encoded_prefix() {
        let env: Envelope = Envelope::new(Rung::Disasm, vec![1, 2, 3], vec![4, 5]);
        let bytes: Vec<u8> = env.encode().expect("encode");
        let header: [u8; HEADER_SIZE] = env.header_bytes().expect("header");
        assert_eq!(&bytes[..HEADER_SIZE], &header[..]);
    }
}
