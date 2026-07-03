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
pub mod name_keyed;
pub mod stringer;
pub mod unflatten;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PeelStatus {
    StubRecovered,
    CipherRecovered,

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

pub fn recover_via_embedded_stub(
    cf: &crate::classfile::ClassFile,
    report: &mut ProtectorPeelReport,
) -> usize {
    use crate::stub_emulator::{decrypt_constant, find_char_array_decrypt};
    let mut recovered: usize = 0;

    let caller_report: crate::bytecode_eval::CallerKeyedReport =
        crate::bytecode_eval::recover_caller_keyed_strings(cf);
    let mut via_caller: usize = 0;
    for (idx, plain) in caller_report.recovered {
        if is_readable(&plain) && !report.strings_recovered.contains_key(&idx) {
            report.strings_recovered.insert(idx, plain);
            via_caller += 1;
        }
    }
    if via_caller > 0 {
        recovered += via_caller;
        report.notes.push(format!(
            "recovered {via_caller} strings via call-site bytecode evaluation (the class's own \
             decrypt method is executed end to end, with <clinit> run first to populate any \
             per-class static key and the static call site's class+method identity supplied as a \
             synthetic stack frame for caller-keyed shapes)"
        ));
    } else if caller_report.runtime_key_wall
        && let Some(reason) = caller_report.runtime_key_wall_reason
    {
        report.notes.push(reason);
    }

    if let Some(stub) = find_char_array_decrypt(cf) {
        let mut via_stub: usize = 0;
        for (idx, original) in cf.collect_strings() {
            if report.strings_recovered.contains_key(&idx) {
                continue;
            }
            if let Some(plain) = decrypt_constant(&stub, &original)
                && plain != original
                && is_readable(&plain)
            {
                report.strings_recovered.insert(idx, plain);
                via_stub += 1;
            }
        }
        if via_stub > 0 {
            recovered += via_stub;
            report.notes.push(format!(
                "recovered {via_stub} additional strings via char-array decrypt-stub emulation"
            ));
        }
    }

    let string_report: crate::string_recovery::StringRecoveryReport =
        crate::string_recovery::recover_strings(cf);
    let mut via_method: usize = 0;
    for (idx, plain) in string_report.recovered {
        if is_readable(&plain) && !report.strings_recovered.contains_key(&idx) {
            report.strings_recovered.insert(idx, plain);
            via_method += 1;
        }
    }
    if via_method > 0 {
        recovered += via_method;
        report.notes.push(format!(
            "recovered {via_method} additional strings via injected decrypt-method emulation"
        ));
    } else if via_caller == 0 && string_report.runtime_key_wall {
        report.notes.push(
            "injected decrypt method reads a runtime/environment key; static emulation cannot \
             reproduce the plaintext"
                .to_owned(),
        );
    }

    if recovered > 0 {
        report.status = PeelStatus::StubRecovered;
    }
    recovered
}

pub fn recover_via_name_keyed_fallback(
    cf: &crate::classfile::ClassFile,
    report: &mut ProtectorPeelReport,
    cipher_kind: name_keyed::NameKeyedCipher,
) -> usize {
    let recovery: name_keyed::NameKeyedRecovery = name_keyed::recover_name_keyed(cf, cipher_kind);
    let mut added: usize = 0;
    for (idx, plain) in recovery.recovered {
        if is_readable(&plain) && !report.strings_recovered.contains_key(&idx) {
            report.strings_recovered.insert(idx, plain);
            added += 1;
        }
    }
    if added > 0 {
        report.status = PeelStatus::CipherRecovered;
        report.notes.push(format!(
            "recovered {added} string(s) via the per-class-name key derivation: the shared \
             decryptor lives in another class, but the key is a deterministic function of this \
             class's own retained this_class name, so the documented per-class cipher is rebuilt \
             statically and applied to each ciphertext handed to an external String->String \
             decrypt call site"
        ));
    }
    added
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeeledClass {
    pub report: ProtectorPeelReport,
    pub source: String,
}

#[must_use]
const fn family_of(protector: crate::obfuscators::Protector) -> Option<ProtectorFamily> {
    match protector {
        crate::obfuscators::Protector::ZelixKlassMaster => Some(ProtectorFamily::ZelixKlassMaster),
        crate::obfuscators::Protector::Allatori => Some(ProtectorFamily::Allatori),
        crate::obfuscators::Protector::Stringer => Some(ProtectorFamily::Stringer),
        crate::obfuscators::Protector::DashO => Some(ProtectorFamily::DashO),
        crate::obfuscators::Protector::DexGuard => Some(ProtectorFamily::DexGuard),
        crate::obfuscators::Protector::ProguardR8
        | crate::obfuscators::Protector::YGuard
        | crate::obfuscators::Protector::SkidSuite2
        | crate::obfuscators::Protector::Jbco => None,
    }
}

pub fn detect_family(cf: &crate::classfile::ClassFile) -> Option<ProtectorFamily> {
    let detections: Vec<crate::obfuscators::Detection> = crate::obfuscators::detect_all(cf);
    if crate::debug::dbg_enabled() {
        for d in &detections {
            crate::debug::dbg_kv("protector-candidate", || {
                format!(
                    "{:?} confidence={} evidence={}",
                    d.protector,
                    d.confidence,
                    d.evidence.join("; ")
                )
            });
        }
    }
    let best: Option<&crate::obfuscators::Detection> = detections
        .iter()
        .filter(|d: &&crate::obfuscators::Detection| {
            !matches!(d.protector, crate::obfuscators::Protector::ProguardR8)
        })
        .max_by_key(|d: &&crate::obfuscators::Detection| d.confidence);
    if let Some(family) = best.and_then(|d: &crate::obfuscators::Detection| family_of(d.protector))
    {
        crate::debug::dbg_kv("protector-family", || {
            format!("{} (highest-confidence detection)", family.name())
        });
        return Some(family);
    }
    if stringer::has_runtime_key_signature(cf) {
        crate::debug::dbg_kv("protector-family", || {
            "Stringer (runtime-key signature fallback)".to_owned()
        });
        return Some(ProtectorFamily::Stringer);
    }
    crate::debug::dbg_line(|| "no protector family detected".to_owned());
    None
}

#[must_use]
pub fn peel_for_family(
    cf: &crate::classfile::ClassFile,
    family: ProtectorFamily,
) -> ProtectorPeelReport {
    let owner: String = cf
        .this_class_name()
        .map_or_else(|_| String::new(), str::to_owned);
    match family {
        ProtectorFamily::ZelixKlassMaster | ProtectorFamily::DexGuard => zelix::peel(cf),
        ProtectorFamily::Allatori => allatori::peel(cf, &owner, "decrypt"),
        ProtectorFamily::Stringer => stringer::peel(cf, &owner, "decrypt"),
        ProtectorFamily::DashO => dasho::peel(cf, &owner),
    }
}

#[must_use]
pub fn peel_classfile(cf: &crate::classfile::ClassFile) -> Option<ProtectorPeelReport> {
    let family: ProtectorFamily = detect_family(cf)?;
    Some(peel_for_family(cf, family))
}

#[must_use]
pub fn substitute_recovered_strings(
    cf: &crate::classfile::ClassFile,
    recovered: &BTreeMap<u16, String>,
) -> crate::classfile::ClassFile {
    let mut out: crate::classfile::ClassFile = cf.clone();
    for (utf8_idx, plain) in recovered {
        if let Some(entry) = out.constant_pool.get_mut(usize::from(*utf8_idx))
            && matches!(entry, crate::classfile::ConstantPoolEntry::Utf8(_))
        {
            *entry = crate::classfile::ConstantPoolEntry::Utf8(plain.clone());
        }
    }
    out
}

#[must_use]
pub fn peel_and_decompile(cf: &crate::classfile::ClassFile) -> Option<PeeledClass> {
    let report: ProtectorPeelReport = peel_classfile(cf)?;
    let substituted: crate::classfile::ClassFile =
        substitute_recovered_strings(cf, &report.strings_recovered);
    let decompiled: crate::decompile::DecompiledClass =
        crate::decompile::decompile_class(&substituted);
    Some(PeeledClass {
        report,
        source: decompiled.source,
    })
}
