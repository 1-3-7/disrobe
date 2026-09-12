use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::dalvik::{DalvikInsn, SwitchPayload};

const OP_CONST_STRING: u8 = 0x1A;
const OP_CONST_STRING_JUMBO: u8 = 0x1B;
const OP_INVOKE_VIRTUAL: u8 = 0x6E;
const OP_INVOKE_VIRTUAL_RANGE: u8 = 0x74;
const OP_PACKED_SWITCH: u8 = 0x2B;
const OP_SPARSE_SWITCH: u8 = 0x2C;
const MIN_DISPATCH_KEYS: usize = 3;
const MIN_MASK_EVIDENCE: usize = 2;
const MAX_MASK_SEARCH_PAIRS: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlackObfReport {
    pub flattened: bool,
    pub dispatcher_count: usize,
    pub dispatch_cases: usize,
    pub hashcode_keyed: bool,
    pub const_string_blocks: usize,
    pub note: String,
}

impl BlackObfReport {
    fn clean() -> Self {
        Self {
            flattened: false,
            dispatcher_count: 0,
            dispatch_cases: 0,
            hashcode_keyed: false,
            const_string_blocks: 0,
            note: "no BlackObfuscator hashCode-dispatcher control-flow flattening detected"
                .to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlackObfDeflatten {
    pub linear_block_pcs: Vec<u32>,
    pub resolved_cases: usize,
    pub unresolved_cases: usize,
    pub dispatch_mask: i32,
}

#[must_use]
pub fn java_string_hashcode(s: &str) -> i32 {
    let mut h: i32 = 0;
    for unit in s.encode_utf16() {
        h = h.wrapping_mul(31).wrapping_add(i32::from(unit));
    }
    h
}

fn payload_for<'a>(
    insn: &DalvikInsn,
    switches: &'a [(u32, SwitchPayload)],
) -> Option<&'a SwitchPayload> {
    switches
        .iter()
        .find(|(pc, _): &&(u32, SwitchPayload)| *pc == insn.pc)
        .map(|(_, payload): &(u32, SwitchPayload)| payload)
}

fn block_name_hashes(insns: &[DalvikInsn], strings: &[String]) -> Vec<i32> {
    insns
        .iter()
        .filter(|i: &&DalvikInsn| i.op == OP_CONST_STRING || i.op == OP_CONST_STRING_JUMBO)
        .filter_map(|i: &DalvikInsn| i.index)
        .filter_map(|index: u32| strings.get(index as usize))
        .map(|label: &String| java_string_hashcode(label))
        .collect()
}

fn recover_dispatch_mask(hashes: &[i32], keys: &[i32]) -> i32 {
    if hashes.is_empty() || keys.is_empty() {
        return 0;
    }
    if hashes.len().saturating_mul(keys.len()) > MAX_MASK_SEARCH_PAIRS {
        return 0;
    }
    let key_set: BTreeSet<i32> = keys.iter().copied().collect();
    let mut candidates: BTreeSet<i32> = BTreeSet::from([0]);
    for hash in hashes {
        for key in keys {
            candidates.insert(hash ^ key);
        }
    }
    let mut best: (usize, i32) = (0, 0);
    for candidate in candidates {
        let hits: usize = hashes
            .iter()
            .filter(|hash: &&i32| key_set.contains(&(*hash ^ candidate)))
            .count();
        if hits > best.0 {
            best = (hits, candidate);
        }
    }
    if best.0 < MIN_MASK_EVIDENCE {
        0
    } else {
        best.1
    }
}

#[must_use]
pub fn deflatten_blackobfuscator(
    insns: &[DalvikInsn],
    switches: &[(u32, SwitchPayload)],
    strings: &[String],
) -> Option<BlackObfDeflatten> {
    let report: BlackObfReport = detect_blackobfuscator(insns, switches);
    if !report.flattened {
        return None;
    }
    let hashes: Vec<i32> = block_name_hashes(insns, strings);
    let dispatchers: Vec<&SwitchPayload> = insns
        .iter()
        .filter(|i: &&DalvikInsn| i.op == OP_SPARSE_SWITCH || i.op == OP_PACKED_SWITCH)
        .filter_map(|i: &DalvikInsn| payload_for(i, switches))
        .filter(|payload: &&SwitchPayload| keys_look_like_hashcodes(&payload.keys))
        .collect();
    let first: &SwitchPayload = dispatchers.first().copied()?;
    let dispatch_mask: i32 = recover_dispatch_mask(&hashes, &first.keys);

    let mut linear_block_pcs: Vec<u32> = Vec::new();
    let mut resolved_cases: usize = 0;
    let mut unresolved_cases: usize = 0;
    let mut emitted: BTreeSet<u32> = BTreeSet::new();
    for payload in dispatchers {
        let mask: i32 = recover_dispatch_mask(&hashes, &payload.keys);
        let mut key_to_target: BTreeMap<i32, u32> = BTreeMap::new();
        for (key, target) in payload.keys.iter().zip(payload.targets.iter()) {
            key_to_target.insert(*key, *target);
        }
        let mut matched: BTreeSet<i32> = BTreeSet::new();
        for hash in &hashes {
            let key: i32 = hash ^ mask;
            let Some(&target): Option<&u32> = key_to_target.get(&key) else {
                continue;
            };
            matched.insert(key);
            if emitted.insert(target) {
                linear_block_pcs.push(target);
            }
        }
        resolved_cases += matched.len();
        unresolved_cases += key_to_target.len().saturating_sub(matched.len());
    }

    Some(BlackObfDeflatten {
        linear_block_pcs,
        resolved_cases,
        unresolved_cases,
        dispatch_mask,
    })
}

#[must_use]
pub fn detect_blackobfuscator(
    insns: &[DalvikInsn],
    switches: &[(u32, SwitchPayload)],
) -> BlackObfReport {
    let const_string_blocks: usize = insns
        .iter()
        .filter(|i: &&DalvikInsn| i.op == OP_CONST_STRING || i.op == OP_CONST_STRING_JUMBO)
        .count();

    let has_hashcode_invoke: bool = insns.iter().any(|i: &DalvikInsn| {
        (i.op == OP_INVOKE_VIRTUAL || i.op == OP_INVOKE_VIRTUAL_RANGE) && i.index.is_some()
    });

    let mut dispatcher_count: usize = 0;
    let mut dispatch_cases: usize = 0;
    let mut hashcode_keyed: bool = false;
    for insn in insns {
        if insn.op != OP_SPARSE_SWITCH && insn.op != OP_PACKED_SWITCH {
            continue;
        }
        let Some(payload): Option<&SwitchPayload> = payload_for(insn, switches) else {
            continue;
        };
        if payload.keys.len() < MIN_DISPATCH_KEYS {
            continue;
        }
        if keys_look_like_hashcodes(&payload.keys) {
            dispatcher_count += 1;
            dispatch_cases += payload.keys.len();
            hashcode_keyed = true;
        }
    }

    let flattened: bool = dispatcher_count > 0
        && has_hashcode_invoke
        && const_string_blocks >= dispatch_cases.min(MIN_DISPATCH_KEYS);

    if !flattened {
        return BlackObfReport::clean();
    }
    BlackObfReport {
        flattened,
        dispatcher_count,
        dispatch_cases,
        hashcode_keyed,
        const_string_blocks,
        note: format!(
            "BlackObfuscator-style control-flow flattening: {dispatcher_count} hashCode-keyed dispatcher(s) over {dispatch_cases} case(s); each real block is gated behind String.hashCode() of a literal block-name, and each case key is that hashCode xor a per-method constant. Static deflattening recovers that constant from the block-name set and maps every case back to its block."
        ),
    }
}

fn keys_look_like_hashcodes(keys: &[i32]) -> bool {
    if keys.len() < MIN_DISPATCH_KEYS {
        return false;
    }
    let sequential: bool = keys
        .windows(2)
        .all(|w: &[i32]| w[1].wrapping_sub(w[0]) == 1);
    if sequential {
        return false;
    }
    let large_spread: bool = keys.iter().any(|&k: &i32| k.unsigned_abs() > 0x1_0000);
    let distinct: bool = {
        let mut sorted: Vec<i32> = keys.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        sorted.len() == keys.len()
    };
    large_spread && distinct
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::dalvik::{InsnFormat, decode_method};

    fn java_hashcode(s: &str) -> i32 {
        let mut h: i32 = 0;
        for c in s.chars() {
            h = h.wrapping_mul(31).wrapping_add(c as i32);
        }
        h
    }

    fn insn(op: u8, pc: u32, index: Option<u32>, payload_off: Option<u32>) -> DalvikInsn {
        DalvikInsn {
            pc,
            op,
            mnemonic: "x",
            width: 2,
            format: InsnFormat::Fmt10x,
            regs: Vec::new(),
            literal: None,
            index,
            branch: None,
            payload_off,
        }
    }

    #[test]
    fn detects_hashcode_dispatcher_flattening() {
        let keys: Vec<i32> = ["block_a", "block_b", "block_c", "block_entry"]
            .iter()
            .map(|s: &&str| java_hashcode(s))
            .collect();
        let payload: SwitchPayload = SwitchPayload {
            keys,
            targets: vec![10, 20, 30, 40],
        };
        let insns: Vec<DalvikInsn> = vec![
            insn(OP_CONST_STRING, 0, Some(1), None),
            insn(OP_INVOKE_VIRTUAL, 2, Some(7), None),
            insn(OP_SPARSE_SWITCH, 6, None, Some(0x100)),
            insn(OP_CONST_STRING, 10, Some(2), None),
            insn(OP_CONST_STRING, 14, Some(3), None),
            insn(OP_CONST_STRING, 18, Some(4), None),
        ];
        let report: BlackObfReport = detect_blackobfuscator(&insns, &[(6, payload)]);
        assert!(report.flattened, "must flag flattening: {report:?}");
        assert_eq!(report.dispatcher_count, 1);
        assert_eq!(report.dispatch_cases, 4);
        assert!(report.hashcode_keyed);
    }

    #[test]
    fn deflattens_to_linear_block_order() {
        let names: [&str; 4] = ["block_a", "block_b", "block_c", "block_entry"];
        let keys: Vec<i32> = names.iter().map(|s: &&str| java_hashcode(s)).collect();
        let payload: SwitchPayload = SwitchPayload {
            keys,
            targets: vec![100, 200, 300, 400],
        };
        let strings: Vec<String> = vec![
            "unused0".to_owned(),
            "block_entry".to_owned(),
            "block_a".to_owned(),
            "block_b".to_owned(),
            "block_c".to_owned(),
        ];
        let insns: Vec<DalvikInsn> = vec![
            insn(OP_INVOKE_VIRTUAL, 0, Some(7), None),
            insn(OP_SPARSE_SWITCH, 4, None, Some(0x100)),
            insn(OP_CONST_STRING, 8, Some(1), None),
            insn(OP_CONST_STRING, 12, Some(2), None),
            insn(OP_CONST_STRING, 16, Some(3), None),
            insn(OP_CONST_STRING, 20, Some(4), None),
        ];
        let de: BlackObfDeflatten =
            deflatten_blackobfuscator(&insns, &[(4, payload)], &strings).expect("deflatten");
        assert_eq!(de.resolved_cases, 4);
        assert_eq!(de.unresolved_cases, 0);
        assert_eq!(de.dispatch_mask, 0);
        assert_eq!(de.linear_block_pcs, vec![400, 100, 200, 300]);
    }

    #[test]
    fn deflattens_a_mask_keyed_dispatcher() {
        let names: [&str; 4] = ["k_alpha", "k_beta", "k_gamma", "k_entry"];
        let mask: i32 = -1_918_291_217;
        let keys: Vec<i32> = names
            .iter()
            .map(|s: &&str| java_hashcode(s) ^ mask)
            .collect();
        let payload: SwitchPayload = SwitchPayload {
            keys,
            targets: vec![100, 200, 300, 400],
        };
        let strings: Vec<String> = vec![
            "unused0".to_owned(),
            "k_entry".to_owned(),
            "k_alpha".to_owned(),
            "k_beta".to_owned(),
            "k_gamma".to_owned(),
        ];
        let insns: Vec<DalvikInsn> = vec![
            insn(OP_INVOKE_VIRTUAL, 0, Some(7), None),
            insn(OP_SPARSE_SWITCH, 4, None, Some(0x100)),
            insn(OP_CONST_STRING, 8, Some(1), None),
            insn(OP_CONST_STRING, 12, Some(2), None),
            insn(OP_CONST_STRING, 16, Some(3), None),
            insn(OP_CONST_STRING, 20, Some(4), None),
        ];
        let de: BlackObfDeflatten =
            deflatten_blackobfuscator(&insns, &[(4, payload)], &strings).expect("deflatten");
        assert_eq!(de.dispatch_mask, mask);
        assert_eq!(de.resolved_cases, 4);
        assert_eq!(de.unresolved_cases, 0);
        assert_eq!(de.linear_block_pcs, vec![400, 100, 200, 300]);
    }

    #[test]
    fn java_string_hashcode_matches_jdk() {
        assert_eq!(java_string_hashcode("hello"), 99_162_322);
        assert_eq!(java_string_hashcode(""), 0);
        assert_eq!(java_string_hashcode("a"), 97);
    }

    #[test]
    fn ignores_ordinary_packed_switch() {
        let payload: SwitchPayload = SwitchPayload {
            keys: vec![0, 1, 2, 3],
            targets: vec![10, 20, 30, 40],
        };
        let insns: Vec<DalvikInsn> = vec![insn(OP_PACKED_SWITCH, 0, None, Some(0x100))];
        let report: BlackObfReport = detect_blackobfuscator(&insns, &[(0, payload)]);
        assert!(
            !report.flattened,
            "sequential keys are a real switch, not flattening"
        );
    }

    #[test]
    fn clean_method_reports_not_flattened() {
        let insns: Vec<DalvikInsn> = decode_method(&[0x000Eu16]);
        let report: BlackObfReport = detect_blackobfuscator(&insns, &[]);
        assert!(!report.flattened);
        assert_eq!(report.dispatcher_count, 0);
    }
}
