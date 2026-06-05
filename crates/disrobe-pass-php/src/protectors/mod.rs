#![allow(
    clippy::needless_range_loop,
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::must_use_candidate
)]

use serde::{Deserialize, Serialize};

pub mod ioncube;
pub mod sourceguardian;
pub mod zend_guard;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProtectorFamily {
    IonCube,
    SourceGuardian,
    ZendGuard,
}

impl ProtectorFamily {
    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::IonCube => "ionCube",
            Self::SourceGuardian => "SourceGuardian",
            Self::ZendGuard => "ZendGuard",
        }
    }

    #[inline]
    #[must_use]
    pub const fn wall_reason(self) -> &'static str {
        match self {
            Self::IonCube => {
                "ionCube ships encrypted Zend opcode arrays; the decryption key lives inside the licensed native loader (.so/.dll) and is not present in the PHP envelope, so source cannot be recovered without that runtime key"
            }
            Self::SourceGuardian => {
                "SourceGuardian ships encrypted Zend opcodes behind the ixed.* native loader; the key is held by the loader binary, not the PHP file, so source is not recoverable from the envelope alone"
            }
            Self::ZendGuard => {
                "Zend Guard ships encrypted Zend opcode streams behind the Zend Optimizer/Guard Loader; the key is embedded in the loader, not the PHP file, so source cannot be recovered from the envelope alone"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectorDetection {
    pub family: ProtectorFamily,
    pub version_label: String,
    pub marker_offset: usize,
    pub confident: bool,
    pub payload_offset: Option<usize>,
    pub payload_len: usize,
    pub recovered_strings: Vec<String>,
    pub wall_reason: &'static str,
}

impl ProtectorDetection {
    #[inline]
    #[must_use]
    pub fn new(
        family: ProtectorFamily,
        version_label: String,
        marker_offset: usize,
        confident: bool,
    ) -> Self {
        Self {
            family,
            version_label,
            marker_offset,
            confident,
            payload_offset: None,
            payload_len: 0,
            recovered_strings: Vec::new(),
            wall_reason: family.wall_reason(),
        }
    }
}

pub fn extract_envelope_strings(plaintext: &[u8], min_len: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut buf: Vec<u8> = Vec::with_capacity(64);
    let flush = |buf: &mut Vec<u8>, out: &mut Vec<String>| {
        if buf.len() >= min_len
            && let Ok(s) = std::str::from_utf8(buf)
        {
            out.push(s.to_string());
        }
        buf.clear();
    };
    for &b in plaintext {
        if (0x20..0x7F).contains(&b) || b == b'\n' || b == b'\t' {
            buf.push(b);
        } else {
            flush(&mut buf, &mut out);
        }
    }
    flush(&mut buf, &mut out);
    out
}
