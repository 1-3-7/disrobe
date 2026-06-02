use std::collections::BTreeMap;

use disrobe_core::Capability;
use serde::{Deserialize, Serialize};

use crate::error::Result;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Sidecar {
    pub produced_by: String,
    pub produced_by_version: String,
    pub capabilities: Vec<Capability>,
    pub provenance: BTreeMap<String, String>,
}

impl Sidecar {
    #[inline]
    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(postcard::to_stdvec(self)?)
    }

    #[inline]
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Ok(postcard::from_bytes(bytes)?)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_empty_sidecar() {
        let s: Sidecar = Sidecar::default();
        let bytes: Vec<u8> = s.encode().expect("encode");
        let decoded: Sidecar = Sidecar::decode(&bytes).expect("decode");
        assert_eq!(s, decoded);
    }

    #[test]
    fn round_trip_full_sidecar() {
        let mut provenance: BTreeMap<String, String> = BTreeMap::new();
        provenance.insert("source_hash".to_owned(), "abc123".to_owned());
        provenance.insert("input_size".to_owned(), "2048".to_owned());
        let s: Sidecar = Sidecar {
            produced_by: "disrobe-pass-wasm-deob".to_owned(),
            produced_by_version: "0.1.0".to_owned(),
            capabilities: vec![
                Capability::requires("wasm-raw", 1),
                Capability::produces("wasm-cfg", 1),
                Capability::produces("wasm-ssa", 1),
            ],
            provenance,
        };
        let bytes: Vec<u8> = s.encode().expect("encode");
        let decoded: Sidecar = Sidecar::decode(&bytes).expect("decode");
        assert_eq!(s, decoded);
        assert_eq!(decoded.capabilities.len(), 3);
        assert_eq!(
            decoded.provenance.get("input_size"),
            Some(&"2048".to_owned())
        );
    }

    #[test]
    fn capability_kinds_distinguish() {
        let r: Capability = Capability::requires("x", 1);
        let p: Capability = Capability::produces("x", 1);
        assert_ne!(r, p);
    }
}
