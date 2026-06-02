#![allow(
    clippy::needless_range_loop,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::manual_is_multiple_of,
    clippy::manual_range_contains,
    clippy::map_unwrap_or,
    clippy::unreadable_literal,
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::single_match_else,
    clippy::option_if_let_else,
    clippy::redundant_closure_for_method_calls
)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub mod allatori;
pub mod dasho;
pub mod dexguard;
pub mod stringer;
pub mod zelix;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProtectorFamily {
    ZelixKlassMaster,
    Allatori,
    Stringer,
    DashO,
    DexGuard,
}

impl ProtectorFamily {
    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ZelixKlassMaster => "Zelix KlassMaster",
            Self::Allatori => "Allatori",
            Self::Stringer => "Stringer",
            Self::DashO => "DashO",
            Self::DexGuard => "DexGuard",
        }
    }
}

/// Honest disclosure of how much a `peel` actually accomplished.
///
/// The proprietary per-vendor string ciphers (`ZelixKlassMaster`, `Allatori`,
/// `DashO`, `Stringer`) are opaque without the embedded decrypt stub the
/// protector ships inside the class. Recovery is only principled when that stub
/// is found and emulated; otherwise the pass can detect and structurally
/// characterise the protection but cannot honestly claim to have decrypted
/// strings. This mirrors `disrobe-pass-pyarmor`'s `DecryptStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PeelStatus {
    /// Strings were decrypted by emulating the class's own embedded decrypt stub.
    StubRecovered,
    /// The protector was detected and structurally characterised (CFF blocks,
    /// watermarks, markers, residual encrypted-string count) but no embedded
    /// decrypt stub was found, so no string plaintext is claimed.
    #[default]
    DetectOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectorPeelReport {
    pub family: ProtectorFamily,
    pub status: PeelStatus,
    pub strings_recovered: BTreeMap<u16, String>,
    pub strings_residual: usize,
    pub cff_methods_unflattened: u32,
    pub cff_branches_recovered: u32,
    pub watermarks_stripped: Vec<String>,
    pub notes: Vec<String>,
}

impl ProtectorPeelReport {
    #[inline]
    #[must_use]
    pub const fn new(family: ProtectorFamily) -> Self {
        Self {
            family,
            status: PeelStatus::DetectOnly,
            strings_recovered: BTreeMap::new(),
            strings_residual: 0,
            cff_methods_unflattened: 0,
            cff_branches_recovered: 0,
            watermarks_stripped: Vec::new(),
            notes: Vec::new(),
        }
    }
}

/// Recover obfuscated string constants by emulating the class's own decrypt stub.
///
/// Locates the embedded `char[]`-to-`char[]` (or to-`String`) decrypt routine and
/// runs it over every constant-pool UTF-8 entry. This is the principled,
/// vendor-agnostic reversal: it executes the protector's actual shipped decrypt
/// logic rather than guessing a cipher. Returns the count of constants recovered
/// and inserts the plaintext into `report.strings_recovered`. When no embedded
/// stub is present (native, reflective, or split across classes) it returns 0 and
/// the caller should fall back to a labeled heuristic or the JVM backend.
pub fn recover_via_embedded_stub(
    cf: &crate::classfile::ClassFile,
    report: &mut ProtectorPeelReport,
) -> usize {
    use crate::stub_emulator::{DecryptStub, decrypt_constant, find_char_array_decrypt};
    let Some(stub): Option<DecryptStub> = find_char_array_decrypt(cf) else {
        return 0;
    };
    let mut recovered: usize = 0;
    for (idx, original) in cf.collect_strings() {
        if let Some(plain) = decrypt_constant(&stub, &original)
            && plain != original
            && is_readable(&plain)
        {
            report.strings_recovered.insert(idx, plain);
            recovered += 1;
        }
    }
    if recovered > 0 {
        report.status = PeelStatus::StubRecovered;
        report.notes.push(format!(
            "recovered {recovered} strings via embedded decrypt-stub emulation"
        ));
    }
    recovered
}

fn is_readable(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let printable: usize = s
        .chars()
        .filter(|c: &char| c.is_ascii_graphic() || *c == ' ' || *c == '\t' || *c == '\n')
        .count();
    (printable as f64 / s.chars().count() as f64) > 0.85
}
