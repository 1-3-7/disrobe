use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::abc::AbcFile;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub enum ObfuscationSignal {
    StringEncryption,
    NameMangling,
    ControlFlowFlattening,
    DeadCodeInsertion,
    NumericLiteralBloat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConfidenceScore(pub u8);

impl ConfidenceScore {
    pub const LOW: Self = Self(25);
    pub const MEDIUM: Self = Self(60);
    pub const HIGH: Self = Self(85);
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObfuscationReport {
    pub signals: BTreeMap<ObfuscationSignal, ConfidenceScore>,
    pub printable_string_ratio_percent: u8,
    pub identifier_mangle_ratio_percent: u8,
    pub control_flow_jump_density_percent: u8,
}

fn printable_string_ratio(abc: &AbcFile) -> u8 {
    let total: usize = abc.cpool.strings.iter().filter(|s| !s.is_empty()).count();
    if total == 0 {
        return 100;
    }
    let printable: usize = abc
        .cpool
        .strings
        .iter()
        .filter(|s: &&String| !s.is_empty())
        .filter(|s: &&String| {
            s.chars()
                .all(|c: char| c.is_ascii_graphic() || c == ' ' || c == '\t')
        })
        .count();
    let pct: u64 = (printable as u64 * 100) / total as u64;
    pct.min(100) as u8
}

fn identifier_mangle_ratio(abc: &AbcFile) -> u8 {
    let mut total: usize = 0;
    let mut mangled: usize = 0;
    for inst in &abc.instances {
        if let Ok(rendered) = abc.cpool.render_multiname(inst.name_index) {
            total += 1;
            if is_mangled_identifier(&rendered) {
                mangled += 1;
            }
        }
    }
    for tr in abc.instances.iter().flat_map(|i| &i.traits) {
        if let Ok(name) = abc.cpool.string_at(tr.name_index) {
            total += 1;
            if is_mangled_identifier(name) {
                mangled += 1;
            }
        }
    }
    if total == 0 {
        return 0;
    }
    ((mangled as u64 * 100) / total as u64).min(100) as u8
}

fn is_mangled_identifier(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    if name.len() <= 2 && name.chars().all(|c: char| c.is_ascii_alphabetic()) {
        return true;
    }
    let non_ascii: usize = name.chars().filter(|c: &char| !c.is_ascii()).count();
    if non_ascii > 0 && (non_ascii * 100 / name.chars().count()) > 30 {
        return true;
    }
    let suspicious_prefix: bool = name
        .chars()
        .next()
        .is_some_and(|c: char| matches!(c, '_' | '$' | '\u{200B}' | '\u{200C}' | '\u{200D}'));
    if suspicious_prefix && name.len() > 6 {
        return true;
    }
    let hex_run: usize = name
        .chars()
        .filter(|c: &char| c.is_ascii_hexdigit())
        .count();
    if name.len() >= 8 && hex_run == name.len() {
        return true;
    }
    false
}

const JUMP_OPCODES: &[u8] = &[
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x0C, 0x0D, 0x0E, 0x0F, 0x1B,
];

fn control_flow_jump_density(abc: &AbcFile) -> u8 {
    let mut total: u64 = 0;
    let mut jumps: u64 = 0;
    for body in &abc.method_bodies {
        total += body.code.len() as u64;
        jumps += body
            .code
            .iter()
            .filter(|b: &&u8| JUMP_OPCODES.contains(*b))
            .count() as u64;
    }
    if total == 0 {
        return 0;
    }
    ((jumps * 1000) / total).min(100) as u8
}

#[must_use]
pub fn analyze(abc: &AbcFile) -> ObfuscationReport {
    let printable_pct: u8 = printable_string_ratio(abc);
    let mangle_pct: u8 = identifier_mangle_ratio(abc);
    let jump_density: u8 = control_flow_jump_density(abc);

    let mut signals: BTreeMap<ObfuscationSignal, ConfidenceScore> = BTreeMap::new();
    if printable_pct < 40 {
        signals.insert(ObfuscationSignal::StringEncryption, ConfidenceScore::HIGH);
    } else if printable_pct < 70 {
        signals.insert(ObfuscationSignal::StringEncryption, ConfidenceScore::MEDIUM);
    }
    if mangle_pct >= 60 {
        signals.insert(ObfuscationSignal::NameMangling, ConfidenceScore::HIGH);
    } else if mangle_pct >= 30 {
        signals.insert(ObfuscationSignal::NameMangling, ConfidenceScore::MEDIUM);
    }
    if jump_density >= 15 {
        signals.insert(
            ObfuscationSignal::ControlFlowFlattening,
            ConfidenceScore::HIGH,
        );
    } else if jump_density >= 8 {
        signals.insert(
            ObfuscationSignal::ControlFlowFlattening,
            ConfidenceScore::MEDIUM,
        );
    }
    ObfuscationReport {
        signals,
        printable_string_ratio_percent: printable_pct,
        identifier_mangle_ratio_percent: mangle_pct,
        control_flow_jump_density_percent: jump_density,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn detects_short_identifier_as_mangled() {
        assert!(is_mangled_identifier("a"));
        assert!(is_mangled_identifier("ab"));
        assert!(!is_mangled_identifier("init"));
    }

    #[test]
    fn detects_hex_identifier_as_mangled() {
        assert!(is_mangled_identifier("abcdef01"));
        assert!(!is_mangled_identifier("notHex_"));
    }
}
