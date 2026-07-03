use std::collections::{BTreeMap, BTreeSet};

use crate::bytecode::{self, Instruction, Operands};
use crate::classfile::{ClassFile, ConstantPoolEntry, MethodInfo};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameKeyedCipher {
    Allatori,
    DashO,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameKeyedRecovery {
    pub recovered: BTreeMap<u16, String>,
    pub call_sites: usize,
}

#[must_use]
fn allatori_class_key(owner_internal: &str) -> i32 {
    let mut key: i32 = 0;
    for unit in owner_internal.encode_utf16() {
        key = key.wrapping_mul(31).wrapping_add(i32::from(unit));
    }
    key & 0x7F
}

#[must_use]
fn allatori_decrypt(owner_internal: &str, cipher: &str) -> String {
    let key: i32 = allatori_class_key(owner_internal);
    let units: Vec<u16> = cipher
        .encode_utf16()
        .enumerate()
        .map(|(i, u): (usize, u16)| {
            let pos: i32 = i32::try_from(i % 0x80).unwrap_or(0);
            let mask: i32 = (key + pos) & 0x7F;
            (i32::from(u) ^ mask) as u16
        })
        .collect();
    String::from_utf16_lossy(&units)
}

#[must_use]
fn dasho_class_key(owner_internal: &str) -> [u16; 8] {
    let mut a: i64 = 0x5A5A_5A5A;
    for unit in owner_internal.encode_utf16() {
        a = (a.wrapping_mul(31).wrapping_add(i64::from(unit))) & 0x7FFF_FFFF;
    }
    let mut k: [u16; 8] = [0u16; 8];
    for slot in &mut k {
        a = (a.wrapping_mul(1_103_515_245).wrapping_add(12345)) & 0x7FFF_FFFF;
        *slot = u16::try_from(0x21 + (a % 0x5E)).unwrap_or(0x21);
    }
    k
}

#[must_use]
fn dasho_decrypt(owner_internal: &str, cipher: &str) -> String {
    let k: [u16; 8] = dasho_class_key(owner_internal);
    let units: Vec<u16> = cipher
        .encode_utf16()
        .enumerate()
        .map(|(i, u): (usize, u16)| {
            let kb: i32 = i32::from(k[i % 8]) & 0x3F;
            let ib: i32 = i32::try_from(i).unwrap_or(0) & 0x1F;
            (i32::from(u) ^ kb ^ ib) as u16
        })
        .collect();
    String::from_utf16_lossy(&units)
}

#[must_use]
fn decrypt_with(cipher_kind: NameKeyedCipher, owner_internal: &str, cipher: &str) -> String {
    match cipher_kind {
        NameKeyedCipher::Allatori => allatori_decrypt(owner_internal, cipher),
        NameKeyedCipher::DashO => dasho_decrypt(owner_internal, cipher),
    }
}

#[must_use]
pub fn recover_name_keyed(cf: &ClassFile, cipher_kind: NameKeyedCipher) -> NameKeyedRecovery {
    let mut out: NameKeyedRecovery = NameKeyedRecovery {
        recovered: BTreeMap::new(),
        call_sites: 0,
    };
    let Ok(owner): Result<&str, crate::error::Error> = cf.this_class_name() else {
        return out;
    };
    if owner.is_empty() {
        return out;
    }

    let string_const_to_utf8: BTreeMap<u16, u16> = string_pool_entries(cf);
    let strings: BTreeMap<u16, String> = cf.collect_strings();
    let external_targets: BTreeSet<u16> = external_string_decrypt_refs(cf);

    let mut site_literals: BTreeSet<u16> = BTreeSet::new();
    for method in &cf.methods {
        let Some(code): Option<bytecode::CodeAttribute> = method_code(cf, method) else {
            continue;
        };
        let Ok(insns): Result<Vec<Instruction>, crate::error::Error> =
            bytecode::disassemble(&code.code)
        else {
            continue;
        };
        scan_external_call_sites(
            &insns,
            &external_targets,
            &string_const_to_utf8,
            &mut site_literals,
        );
    }
    out.call_sites = site_literals.len();

    for utf8_idx in site_literals {
        let Some(cipher): Option<&String> = strings.get(&utf8_idx) else {
            continue;
        };
        if cipher.is_empty() {
            continue;
        }
        let plain: String = decrypt_with(cipher_kind, owner, cipher);
        if plain != *cipher && is_plausible_plaintext(&plain) {
            out.recovered.insert(utf8_idx, plain);
        }
    }
    out
}

fn external_string_decrypt_refs(cf: &ClassFile) -> BTreeSet<u16> {
    let this_name: &str = match cf.this_class_name() {
        Ok(name) if !name.is_empty() => name,
        _ => "\0",
    };
    let mut refs: BTreeSet<u16> = BTreeSet::new();
    for (i, entry) in cf.constant_pool.iter().enumerate() {
        let is_callable: bool = matches!(
            entry,
            ConstantPoolEntry::Methodref { .. } | ConstantPoolEntry::InterfaceMethodref { .. }
        );
        if !is_callable {
            continue;
        }
        let Ok(cp_idx): Result<u16, _> = u16::try_from(i) else {
            continue;
        };
        let Some(sig): Option<String> = bytecode::resolve_ref(cf, cp_idx) else {
            continue;
        };
        let Some((owner, rest)): Option<(&str, &str)> = sig.split_once('.') else {
            continue;
        };
        let Some((_name, desc)): Option<(&str, &str)> = rest.split_once(':') else {
            continue;
        };
        if owner == this_name {
            continue;
        }
        if desc == "(Ljava/lang/String;)Ljava/lang/String;"
            || desc == "(Ljava/lang/Object;)Ljava/lang/String;"
        {
            refs.insert(cp_idx);
        }
    }
    refs
}

fn scan_external_call_sites(
    insns: &[Instruction],
    external_targets: &BTreeSet<u16>,
    string_const_to_utf8: &BTreeMap<u16, u16>,
    out: &mut BTreeSet<u16>,
) {
    let mut pending_literal: Option<u16> = None;
    for insn in insns {
        match insn.opcode {
            0x12 | 0x13 => {
                if let Operands::ConstPool(cp) = insn.operands {
                    pending_literal = string_const_to_utf8.get(&cp).copied();
                }
            }
            0xB6 | 0xB8 | 0xB9 => {
                if let Some(utf8_idx) = pending_literal
                    && let Operands::ConstPool(cp) | Operands::InvokeInterface { index: cp, .. } =
                        insn.operands
                    && external_targets.contains(&cp)
                {
                    out.insert(utf8_idx);
                }
                pending_literal = None;
            }
            _ => pending_literal = None,
        }
    }
}

fn method_code(cf: &ClassFile, method: &MethodInfo) -> Option<bytecode::CodeAttribute> {
    for attr in &method.attributes {
        let Ok(name): Result<&str, crate::error::Error> = cf.utf8_at(attr.name_index) else {
            continue;
        };
        if name == "Code"
            && let Ok(code) = bytecode::parse_code_attribute(&attr.info)
        {
            return Some(code);
        }
    }
    None
}

fn string_pool_entries(cf: &ClassFile) -> BTreeMap<u16, u16> {
    let mut map: BTreeMap<u16, u16> = BTreeMap::new();
    for (i, entry) in cf.constant_pool.iter().enumerate() {
        if let ConstantPoolEntry::String { utf8_index } = entry
            && let Ok(cp_idx) = u16::try_from(i)
        {
            map.insert(cp_idx, *utf8_index);
        }
    }
    map
}

fn is_plausible_plaintext(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let printable: usize = s
        .chars()
        .filter(|c: &char| c.is_ascii_graphic() || c.is_whitespace() || (*c as u32) >= 0xA0)
        .count();
    let total: usize = s.chars().count();
    printable * 100 >= total * 85
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn allatori_key_is_class_name_seeded_and_static() {
        let a: i32 = allatori_class_key("com/disrobe/bench/AllatoriNameKeyed");
        let b: i32 = allatori_class_key("com/disrobe/bench/Other");
        assert_ne!(a, b, "the per-class key must depend on the class name");
        assert!((0..=0x7F).contains(&a));
    }

    #[test]
    fn allatori_forward_then_inverse_round_trips() {
        let owner: &str = "com/disrobe/bench/AllatoriNameKeyed";
        let plain: &str = "jdbc:mariadb://10.2.0.7:3306/ledger";
        let key: i32 = allatori_class_key(owner);
        let cipher: String = String::from_utf16_lossy(
            &plain
                .encode_utf16()
                .enumerate()
                .map(|(i, u): (usize, u16)| {
                    let mask: i32 = (key + i32::try_from(i & 0x7F).unwrap_or(0)) & 0x7F;
                    (i32::from(u) ^ mask) as u16
                })
                .collect::<Vec<u16>>(),
        );
        assert_eq!(allatori_decrypt(owner, &cipher), plain);
    }

    #[test]
    fn dasho_forward_then_inverse_round_trips() {
        let owner: &str = "com/disrobe/bench/DashONameKeyed";
        let plain: &str = "https://settlement.internal/api/post";
        let k: [u16; 8] = dasho_class_key(owner);
        let cipher: String = String::from_utf16_lossy(
            &plain
                .encode_utf16()
                .enumerate()
                .map(|(i, u): (usize, u16)| {
                    let kb: i32 = i32::from(k[i % 8]) & 0x3F;
                    let ib: i32 = i32::try_from(i).unwrap_or(0) & 0x1F;
                    (i32::from(u) ^ kb ^ ib) as u16
                })
                .collect::<Vec<u16>>(),
        );
        assert_eq!(dasho_decrypt(owner, &cipher), plain);
    }

    #[test]
    fn wrong_class_name_does_not_decrypt() {
        let owner: &str = "com/disrobe/bench/DashONameKeyed";
        let plain: &str = "/opt/app/conf/keystore.p12";
        let k: [u16; 8] = dasho_class_key(owner);
        let cipher: String = String::from_utf16_lossy(
            &plain
                .encode_utf16()
                .enumerate()
                .map(|(i, u): (usize, u16)| {
                    let kb: i32 = i32::from(k[i % 8]) & 0x3F;
                    let ib: i32 = i32::try_from(i).unwrap_or(0) & 0x1F;
                    (i32::from(u) ^ kb ^ ib) as u16
                })
                .collect::<Vec<u16>>(),
        );
        let wrong: String = dasho_decrypt("com/disrobe/bench/WrongName", &cipher);
        assert_ne!(
            wrong, plain,
            "a wrong class-name seed must not reproduce the plaintext"
        );
    }
}
