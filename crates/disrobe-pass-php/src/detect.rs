use memchr::memmem;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PhpKind {
    Source,
    PharStub,
    PharArchive,
    Bcg,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PhpConfidence {
    Definite,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhpDetection {
    pub kind: PhpKind,
    pub confidence: PhpConfidence,
    pub open_tag_offset: Option<usize>,
    pub has_halt_compiler: bool,
}

const PHP_OPEN: &[u8] = b"<?php";
const SHORT_OPEN: &[u8] = b"<?";
const HALT: &[u8] = b"__HALT_COMPILER();";
const PHAR_SIG_HEAD: &[u8] = b"GBMB";
const BCG_MAGIC_A: &[u8; 3] = b"BCG";
const BCG_MAGIC_B: &[u8; 3] = b"BC\x01";

#[must_use]
pub fn detect(bytes: &[u8]) -> PhpDetection {
    let open_php: Option<usize> = memmem::find(bytes, PHP_OPEN);
    let open_short: Option<usize> = memmem::find(bytes, SHORT_OPEN);
    let halt: Option<usize> = memmem::find(bytes, HALT);
    let has_halt: bool = halt.is_some();

    if bytes.len() >= 3
        && (&bytes[..3] == BCG_MAGIC_A.as_slice() || &bytes[..3] == BCG_MAGIC_B.as_slice())
    {
        return PhpDetection {
            kind: PhpKind::Bcg,
            confidence: PhpConfidence::Definite,
            open_tag_offset: None,
            has_halt_compiler: false,
        };
    }

    if has_halt && memmem::find(bytes, PHAR_SIG_HEAD).is_some() {
        return PhpDetection {
            kind: PhpKind::PharArchive,
            confidence: PhpConfidence::High,
            open_tag_offset: open_php.or(open_short),
            has_halt_compiler: true,
        };
    }

    if has_halt {
        return PhpDetection {
            kind: PhpKind::PharStub,
            confidence: PhpConfidence::Medium,
            open_tag_offset: open_php.or(open_short),
            has_halt_compiler: true,
        };
    }

    if let Some(offset) = open_php {
        return PhpDetection {
            kind: PhpKind::Source,
            confidence: PhpConfidence::Definite,
            open_tag_offset: Some(offset),
            has_halt_compiler: false,
        };
    }

    if let Some(offset) = open_short {
        let context_ok: bool = bytes
            .get(offset + 2)
            .copied()
            .is_some_and(|b: u8| b == b'=' || b.is_ascii_whitespace());
        if context_ok {
            return PhpDetection {
                kind: PhpKind::Source,
                confidence: PhpConfidence::Medium,
                open_tag_offset: Some(offset),
                has_halt_compiler: false,
            };
        }
    }

    PhpDetection {
        kind: PhpKind::Unknown,
        confidence: PhpConfidence::Low,
        open_tag_offset: None,
        has_halt_compiler: false,
    }
}
