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
const ECHO_OPEN: &[u8] = b"<?=";
const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";
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
        let confidence: PhpConfidence = if opens_file(bytes, offset) {
            PhpConfidence::Definite
        } else {
            PhpConfidence::Medium
        };
        return PhpDetection {
            kind: PhpKind::Source,
            confidence,
            open_tag_offset: Some(offset),
            has_halt_compiler: false,
        };
    }

    let leading_short: Option<usize> = open_short.filter(|offset: &usize| {
        opens_file(bytes, *offset)
            && bytes
                .get(offset + 2)
                .is_some_and(|b: &u8| b.is_ascii_whitespace())
    });
    if let Some(offset) = leading_short.or_else(|| memmem::find(bytes, ECHO_OPEN)) {
        return PhpDetection {
            kind: PhpKind::Source,
            confidence: PhpConfidence::Medium,
            open_tag_offset: Some(offset),
            has_halt_compiler: false,
        };
    }

    PhpDetection {
        kind: PhpKind::Unknown,
        confidence: PhpConfidence::Low,
        open_tag_offset: None,
        has_halt_compiler: false,
    }
}

fn opens_file(bytes: &[u8], offset: usize) -> bool {
    let mut rest: &[u8] = bytes.strip_prefix(UTF8_BOM).unwrap_or(bytes);
    if rest.starts_with(b"#!") {
        rest = memchr::memchr(b'\n', rest)
            .and_then(|newline: usize| rest.get(newline + 1..))
            .unwrap_or_default();
    }
    let blank: usize = rest
        .iter()
        .take_while(|b: &&u8| b.is_ascii_whitespace())
        .count();
    bytes.len() - rest.len() + blank == offset
}
