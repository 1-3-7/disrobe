use serde::{Deserialize, Serialize};

use crate::detect::JVM_CLASS_MAGIC;
use crate::error::{Result, RubyError};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JrubyDelegation {
    pub magic: [u8; 4],
    pub minor: u16,
    pub major: u16,
    pub delegate_pass: String,
    pub delegate_reason: String,
}

pub(crate) fn delegate(bytes: &[u8]) -> Result<JrubyDelegation> {
    if bytes.len() < 8 {
        return Err(RubyError::Truncated {
            got: bytes.len(),
            need: 8,
        });
    }
    let magic: [u8; 4] = bytes[0..4]
        .try_into()
        .map_err(|_| RubyError::Truncated { got: 0, need: 4 })?;
    if &magic != JVM_CLASS_MAGIC {
        return Err(RubyError::JrubyDelegationRequired);
    }
    let minor: u16 = u16::from_be_bytes([bytes[4], bytes[5]]);
    let major: u16 = u16::from_be_bytes([bytes[6], bytes[7]]);
    Ok(JrubyDelegation {
        magic,
        minor,
        major,
        delegate_pass: "disrobe-pass-jvm".to_owned(),
        delegate_reason: "JRuby compiles Ruby to JVM .class; analysis path is JVM bytecode"
            .to_owned(),
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn delegates_to_jvm_pass() {
        let bytes: Vec<u8> = b"\xCA\xFE\xBA\xBE\x00\x00\x00\x34".to_vec();
        let d: JrubyDelegation = delegate(&bytes).expect("delegate");
        assert_eq!(d.delegate_pass, "disrobe-pass-jvm");
        assert_eq!(d.major, 0x34);
    }

    #[test]
    fn rejects_non_class() {
        let bytes: Vec<u8> = b"\xDE\xAD\xBE\xEF\x00\x00\x00\x00".to_vec();
        let err: RubyError = delegate(&bytes).expect_err("not a class");
        assert!(matches!(err, RubyError::JrubyDelegationRequired));
    }
}
