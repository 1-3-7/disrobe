pub mod ioncube;
pub mod sourceguardian;
pub mod zend_guard;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationToken(());

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EncoderFamily {
    IonCube,
    SourceGuardian,
    ZendGuard,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncoderDetection {
    pub family: EncoderFamily,
    pub version_label: String,
    pub marker_offset: usize,
    pub confident: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncoderHeader {
    pub family: EncoderFamily,
    pub version_label: String,
    pub flags: u32,
    pub payload_offset: usize,
    pub payload_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecodeOutcome {
    StructuralOnly {
        header: EncoderHeader,
        ciphertext: Vec<u8>,
    },
    PartialPlaintext {
        header: EncoderHeader,
        recovered: Vec<u8>,
        residual_ciphertext: Vec<u8>,
    },
}

impl AuthorizationToken {
    #[must_use]
    pub fn user_attested() -> Self {
        Self(())
    }
}
