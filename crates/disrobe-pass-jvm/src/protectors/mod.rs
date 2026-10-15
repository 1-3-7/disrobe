#![allow(
    clippy::needless_range_loop,
    clippy::manual_is_multiple_of,
    clippy::manual_range_contains,
    clippy::map_unwrap_or,
    clippy::unreadable_literal,
    clippy::missing_panics_doc,
    clippy::single_match_else,
    clippy::option_if_let_else,
    clippy::redundant_closure_for_method_calls
)]

use std::collections::{BTreeMap, BTreeSet};

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
    use crate::stub_emulator::{decrypt_constant, locate_char_array_decrypt};
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

    if let Some(located) = locate_char_array_decrypt(cf) {
        let mut via_stub: usize = 0;
        let call_site_operands: BTreeSet<u16> = stub_call_site_operands(cf, &located);
        let string_operands: BTreeMap<u16, BTreeSet<u16>> = string_operands_by_utf8(cf);
        for (idx, original) in cf.collect_strings() {
            let Some(operands): Option<&BTreeSet<u16>> = string_operands.get(&idx) else {
                continue;
            };
            if report.strings_recovered.contains_key(&idx)
                || operands.is_empty()
                || !operands.is_subset(&call_site_operands)
            {
                continue;
            }
            if let Some(plain) = decrypt_constant(&located.stub, &original)
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

fn stub_call_site_operands(
    cf: &crate::classfile::ClassFile,
    located: &crate::stub_emulator::LocatedDecryptStub,
) -> BTreeSet<u16> {
    let mut operands: BTreeSet<u16> = BTreeSet::new();
    let Ok(owner): Result<&str, crate::error::Error> = cf.this_class_name() else {
        return operands;
    };
    let stub_ref: String = format!("{owner}.{}:{}", located.name, located.descriptor);
    for method in &cf.methods {
        for attr in &method.attributes {
            if cf.utf8_at(attr.name_index).ok() != Some("Code") {
                continue;
            }
            let Ok(code): Result<crate::bytecode::CodeAttribute, crate::error::Error> =
                crate::bytecode::parse_code_attribute(&attr.info)
            else {
                continue;
            };
            let Ok(insns): Result<Vec<crate::bytecode::Instruction>, crate::error::Error> =
                crate::bytecode::disassemble(&code.code)
            else {
                continue;
            };
            let mut pending: Option<(u16, bool)> = None;
            for insn in &insns {
                let pool_index: Option<u16> = match insn.operands {
                    crate::bytecode::Operands::ConstPool(cp) => Some(cp),
                    _ => None,
                };
                let calls = |expected: &str| -> bool {
                    pool_index
                        .and_then(|cp: u16| crate::bytecode::resolve_ref(cf, cp))
                        .is_some_and(|target: String| target == expected)
                };
                pending = match (insn.opcode, pending) {
                    (0x12 | 0x13, _) => pool_index
                        .filter(|cp: &u16| {
                            matches!(
                                cf.constant_pool.get(usize::from(*cp)),
                                Some(crate::classfile::ConstantPoolEntry::String { .. })
                            )
                        })
                        .map(|cp: u16| (cp, false)),
                    (0xB6, Some((string_index, false)))
                        if calls("java/lang/String.toCharArray:()[C") =>
                    {
                        Some((string_index, true))
                    }
                    (0xB8, Some((string_index, true))) if calls(&stub_ref) => {
                        operands.insert(string_index);
                        None
                    }
                    _ => None,
                };
            }
        }
    }
    operands
}

fn string_operands_by_utf8(cf: &crate::classfile::ClassFile) -> BTreeMap<u16, BTreeSet<u16>> {
    let mut operands: BTreeMap<u16, BTreeSet<u16>> = BTreeMap::new();
    for (index, entry) in cf.constant_pool.iter().enumerate() {
        let crate::classfile::ConstantPoolEntry::String { utf8_index } = entry else {
            continue;
        };
        let Ok(index): Result<u16, _> = u16::try_from(index) else {
            continue;
        };
        operands.entry(*utf8_index).or_default().insert(index);
    }
    operands
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
    pub fully_lifted_methods: usize,
    pub fallback_methods: usize,
    pub decode_error_count: usize,
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
        let Ok(fresh): Result<u16, _> = u16::try_from(out.constant_pool.len()) else {
            break;
        };
        if fresh == u16::MAX {
            break;
        }
        let mut repointed: bool = false;
        for entry in &mut out.constant_pool {
            if let crate::classfile::ConstantPoolEntry::String { utf8_index } = entry
                && *utf8_index == *utf8_idx
            {
                *utf8_index = fresh;
                repointed = true;
            }
        }
        if repointed {
            out.constant_pool
                .push(crate::classfile::ConstantPoolEntry::Utf8(plain.clone()));
        }
    }
    out
}

const CODE_ATTRIBUTE: &str = "Code";
const CODE_HEADER_BYTES: usize = 8;
const NOP: u8 = 0x00;
const LDC: u8 = 0x12;
const LDC_W: u8 = 0x13;
const GETSTATIC: u8 = 0xB2;
const INVOKEVIRTUAL: u8 = 0xB6;
const INVOKESTATIC: u8 = 0xB8;
const STRING_TO_STRING: &str = "(Ljava/lang/String;)Ljava/lang/String;";
const PRINTLN_STRING: &str = "(Ljava/lang/String;)V";
const DEMO_BANNER_MARKER: &str = "allatori";

#[derive(Debug, Clone, Copy, Default)]
struct InlineCounts {
    call_sites_inlined: usize,
    banners_removed: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlinedStrings {
    pub class: crate::classfile::ClassFile,
    pub call_sites_inlined: usize,
    pub banners_removed: usize,
}

fn string_constant_utf8(cf: &crate::classfile::ClassFile, index: u16) -> Option<u16> {
    match cf.constant_pool.get(usize::from(index))? {
        crate::classfile::ConstantPoolEntry::String { utf8_index } => Some(*utf8_index),
        _ => None,
    }
}

fn is_own_string_decryptor(cf: &crate::classfile::ClassFile, methodref: u16) -> bool {
    let Some((owner, name, descriptor)) = owner_name_descriptor(cf, methodref) else {
        return false;
    };
    descriptor == STRING_TO_STRING
        && cf.this_class_name().ok() == Some(owner)
        && cf
            .methods
            .iter()
            .any(|method: &crate::classfile::MethodInfo| {
                cf.utf8_at(method.name_index).ok() == Some(name)
                    && cf.utf8_at(method.descriptor_index).ok() == Some(descriptor)
                    && method.access_flags & crate::decompile::ACC_STATIC != 0
            })
}

fn owner_name_descriptor(
    cf: &crate::classfile::ClassFile,
    index: u16,
) -> Option<(&str, &str, &str)> {
    let (class_index, name_and_type_index): (u16, u16) =
        match cf.constant_pool.get(usize::from(index))? {
            crate::classfile::ConstantPoolEntry::Methodref {
                class_index,
                name_and_type_index,
            }
            | crate::classfile::ConstantPoolEntry::Fieldref {
                class_index,
                name_and_type_index,
            } => (*class_index, *name_and_type_index),
            _ => return None,
        };
    let owner: &str = cf.class_name(class_index).ok()?;
    let crate::classfile::ConstantPoolEntry::NameAndType {
        name_index,
        descriptor_index,
    } = cf.constant_pool.get(usize::from(name_and_type_index))?
    else {
        return None;
    };
    Some((
        owner,
        cf.utf8_at(*name_index).ok()?,
        cf.utf8_at(*descriptor_index).ok()?,
    ))
}

fn is_system_out(cf: &crate::classfile::ClassFile, fieldref: u16) -> bool {
    owner_name_descriptor(cf, fieldref).is_some_and(
        |(owner, name, descriptor): (&str, &str, &str)| {
            owner == "java/lang/System" && name == "out" && descriptor == "Ljava/io/PrintStream;"
        },
    )
}

fn is_println_string(cf: &crate::classfile::ClassFile, methodref: u16) -> bool {
    owner_name_descriptor(cf, methodref).is_some_and(
        |(owner, name, descriptor): (&str, &str, &str)| {
            owner == "java/io/PrintStream" && name == "println" && descriptor == PRINTLN_STRING
        },
    )
}

const fn pool_operand(insn: &crate::bytecode::Instruction) -> Option<u16> {
    match insn.operands {
        crate::bytecode::Operands::ConstPool(index) => Some(index),
        _ => None,
    }
}

fn blank(code: &mut [u8], start: u32, end: u32) {
    let (Ok(start), Ok(end)): (Result<usize, _>, Result<usize, _>) =
        (usize::try_from(start), usize::try_from(end))
    else {
        return;
    };
    if let Some(slice) = code.get_mut(start..end) {
        slice.fill(NOP);
    }
}

fn inline_code(
    cf: &crate::classfile::ClassFile,
    recovered: &BTreeMap<u16, String>,
    code: &mut [u8],
    counts: &mut InlineCounts,
) {
    let Ok(insns): Result<Vec<crate::bytecode::Instruction>, _> =
        crate::bytecode::disassemble(code)
    else {
        return;
    };
    let code_end: u32 = u32::try_from(code.len()).unwrap_or(u32::MAX);
    let end_of = |index: usize| -> u32 {
        insns
            .get(index + 1)
            .map_or(code_end, |next: &crate::bytecode::Instruction| next.pc)
    };
    let mut index: usize = 0;
    while index < insns.len() {
        let insn: &crate::bytecode::Instruction = &insns[index];
        let is_recovered_load: bool = matches!(insn.opcode, LDC | LDC_W)
            && pool_operand(insn)
                .and_then(|operand: u16| string_constant_utf8(cf, operand))
                .is_some_and(|utf8: u16| recovered.contains_key(&utf8));
        if !is_recovered_load {
            index += 1;
            continue;
        }
        let Some(call) = insns.get(index + 1) else {
            break;
        };
        let decrypts: bool = call.opcode == INVOKESTATIC
            && pool_operand(call).is_some_and(|operand: u16| is_own_string_decryptor(cf, operand));
        if !decrypts {
            index += 1;
            continue;
        }
        let plaintext: &str = pool_operand(insn)
            .and_then(|operand: u16| string_constant_utf8(cf, operand))
            .and_then(|utf8: u16| recovered.get(&utf8))
            .map_or("", String::as_str);
        let banner: bool = plaintext.to_ascii_lowercase().contains(DEMO_BANNER_MARKER)
            && index >= 1
            && insns[index - 1].opcode == GETSTATIC
            && pool_operand(&insns[index - 1])
                .is_some_and(|operand: u16| is_system_out(cf, operand))
            && insns
                .get(index + 2)
                .is_some_and(|print: &crate::bytecode::Instruction| {
                    print.opcode == INVOKEVIRTUAL
                        && pool_operand(print)
                            .is_some_and(|operand: u16| is_println_string(cf, operand))
                });
        if banner {
            blank(code, insns[index - 1].pc, end_of(index + 2));
            counts.banners_removed += 1;
            index += 3;
            continue;
        }
        blank(code, call.pc, end_of(index + 1));
        counts.call_sites_inlined += 1;
        index += 2;
    }
}

#[must_use]
pub fn inline_recovered_strings(
    cf: &crate::classfile::ClassFile,
    recovered: &BTreeMap<u16, String>,
) -> InlinedStrings {
    let mut class: crate::classfile::ClassFile = substitute_recovered_strings(cf, recovered);
    let mut counts: InlineCounts = InlineCounts::default();
    for method in &mut class.methods {
        for attribute in &mut method.attributes {
            if cf.utf8_at(attribute.name_index).ok() != Some(CODE_ATTRIBUTE) {
                continue;
            }
            let Some(length_bytes): Option<&[u8]> = attribute.info.get(4..CODE_HEADER_BYTES) else {
                continue;
            };
            let code_length: usize = usize::try_from(u32::from_be_bytes([
                length_bytes[0],
                length_bytes[1],
                length_bytes[2],
                length_bytes[3],
            ]))
            .unwrap_or(usize::MAX);
            let Some(end): Option<usize> = CODE_HEADER_BYTES.checked_add(code_length) else {
                continue;
            };
            let Some(code): Option<&mut [u8]> = attribute.info.get_mut(CODE_HEADER_BYTES..end)
            else {
                continue;
            };
            inline_code(cf, recovered, code, &mut counts);
        }
    }
    InlinedStrings {
        class,
        call_sites_inlined: counts.call_sites_inlined,
        banners_removed: counts.banners_removed,
    }
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
        fully_lifted_methods: decompiled.fully_lifted_methods,
        fallback_methods: decompiled.fallback_methods,
        decode_error_count: decompiled.decode_error_count,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::classfile::{Attribute, ClassFile, ConstantPoolEntry, MethodInfo};

    fn code_attr(name_index: u16, max_stack: u16, max_locals: u16, code: &[u8]) -> Attribute {
        let mut info: Vec<u8> = Vec::new();
        info.extend_from_slice(&max_stack.to_be_bytes());
        info.extend_from_slice(&max_locals.to_be_bytes());
        info.extend_from_slice(&(code.len() as u32).to_be_bytes());
        info.extend_from_slice(code);
        info.extend_from_slice(&0_u16.to_be_bytes());
        info.extend_from_slice(&0_u16.to_be_bytes());
        Attribute { name_index, info }
    }

    fn shared_string_stub_class() -> ClassFile {
        let decrypt_code: [u8; 2] = [0x2A, 0xB0];
        let caller_code: [u8; 12] = [
            0x13, 0x00, 0x07, 0xB6, 0x00, 0x0E, 0xB8, 0x00, 0x12, 0x57, 0x00, 0xB1,
        ];
        ClassFile {
            minor_version: 0,
            major_version: 52,
            constant_pool: vec![
                ConstantPoolEntry::Placeholder,
                ConstantPoolEntry::Utf8("App".to_owned()),
                ConstantPoolEntry::Class { name_index: 1 },
                ConstantPoolEntry::Utf8("Code".to_owned()),
                ConstantPoolEntry::Utf8("run".to_owned()),
                ConstantPoolEntry::Utf8("()V".to_owned()),
                ConstantPoolEntry::Utf8("shared".to_owned()),
                ConstantPoolEntry::String { utf8_index: 6 },
                ConstantPoolEntry::String { utf8_index: 6 },
                ConstantPoolEntry::Utf8("java/lang/String".to_owned()),
                ConstantPoolEntry::Class { name_index: 9 },
                ConstantPoolEntry::Utf8("toCharArray".to_owned()),
                ConstantPoolEntry::Utf8("()[C".to_owned()),
                ConstantPoolEntry::NameAndType {
                    name_index: 11,
                    descriptor_index: 12,
                },
                ConstantPoolEntry::Methodref {
                    class_index: 10,
                    name_and_type_index: 13,
                },
                ConstantPoolEntry::Utf8("decrypt".to_owned()),
                ConstantPoolEntry::Utf8("([C)[C".to_owned()),
                ConstantPoolEntry::NameAndType {
                    name_index: 15,
                    descriptor_index: 16,
                },
                ConstantPoolEntry::Methodref {
                    class_index: 2,
                    name_and_type_index: 17,
                },
            ],
            access_flags: 0,
            this_class: 2,
            super_class: 0,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: vec![
                MethodInfo {
                    access_flags: 0x0008,
                    name_index: 15,
                    descriptor_index: 16,
                    attributes: vec![code_attr(3, 1, 1, &decrypt_code)],
                },
                MethodInfo {
                    access_flags: 0x0008,
                    name_index: 4,
                    descriptor_index: 5,
                    attributes: vec![code_attr(3, 1, 0, &caller_code)],
                },
            ],
            attributes: Vec::new(),
        }
    }

    #[test]
    fn stub_calls_track_string_constant_operands_not_shared_utf8() {
        let cf: ClassFile = shared_string_stub_class();
        let located: crate::stub_emulator::LocatedDecryptStub =
            crate::stub_emulator::locate_char_array_decrypt(&cf).expect("decrypt stub");
        assert_eq!(stub_call_site_operands(&cf, &located), BTreeSet::from([7]));
        assert_eq!(
            string_operands_by_utf8(&cf).get(&6),
            Some(&BTreeSet::from([7, 8]))
        );
    }

    #[test]
    fn a_recovered_string_never_rewrites_a_shared_utf8() {
        let cf: ClassFile = ClassFile {
            minor_version: 0,
            major_version: 52,
            constant_pool: vec![
                ConstantPoolEntry::Placeholder,
                ConstantPoolEntry::Utf8("Code".to_owned()),
                ConstantPoolEntry::String { utf8_index: 1 },
            ],
            access_flags: 0,
            this_class: 0,
            super_class: 0,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            attributes: Vec::new(),
        };
        let recovered: BTreeMap<u16, String> = BTreeMap::from([(1, "plain text".to_owned())]);
        let out: ClassFile = substitute_recovered_strings(&cf, &recovered);
        assert_eq!(
            out.constant_pool[1],
            ConstantPoolEntry::Utf8("Code".to_owned()),
            "the Code attribute name must survive"
        );
        assert_eq!(
            out.constant_pool[2],
            ConstantPoolEntry::String { utf8_index: 3 }
        );
        assert_eq!(
            out.constant_pool[3],
            ConstantPoolEntry::Utf8("plain text".to_owned())
        );
    }
}
