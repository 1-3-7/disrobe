use serde::{Deserialize, Serialize};

use crate::dalvik::{DalvikInsn, SwitchPayload};

const OP_CONST_STRING: u8 = 0x1A;
const OP_CONST_STRING_JUMBO: u8 = 0x1B;
const OP_INVOKE_VIRTUAL: u8 = 0x6E;
const OP_PACKED_SWITCH: u8 = 0x2B;
const OP_SPARSE_SWITCH: u8 = 0x2C;
const MIN_DISPATCH_KEYS: usize = 3;

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
}

#[must_use]
pub fn java_string_hashcode(s: &str) -> i32 {
    let mut h: i32 = 0;
    for unit in s.encode_utf16() {
        h = h.wrapping_mul(31).wrapping_add(i32::from(unit));
    }
    h
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
    let (_, payload): &(u32, SwitchPayload) = insns
        .iter()
        .filter(|i: &&DalvikInsn| i.op == OP_SPARSE_SWITCH || i.op == OP_PACKED_SWITCH)
        .find_map(|i: &DalvikInsn| {
            i.payload_off.and_then(|off: u32| {
                switches
                    .iter()
                    .find(|(o, _): &&(u32, SwitchPayload)| *o == off)
            })
        })?;

    let mut hashcode_to_target: std::collections::BTreeMap<i32, u32> =
        std::collections::BTreeMap::new();
    for (key, target) in payload.keys.iter().zip(payload.targets.iter()) {
        hashcode_to_target.insert(*key, *target);
    }

    let mut linear_block_pcs: Vec<u32> = Vec::new();
    let mut resolved_cases: usize = 0;
    let mut unresolved_cases: usize = 0;
    let mut seen: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    for insn in insns {
        if insn.op != OP_CONST_STRING && insn.op != OP_CONST_STRING_JUMBO {
            continue;
        }
        let Some(idx): Option<u32> = insn.index else {
            continue;
        };
        let Some(label): Option<&String> = strings.get(idx as usize) else {
            unresolved_cases += 1;
            continue;
        };
        let hash: i32 = java_string_hashcode(label);
        match hashcode_to_target.get(&hash) {
            Some(&target) if seen.insert(target) => {
                linear_block_pcs.push(target);
                resolved_cases += 1;
            }
            Some(_) => {}
            None => unresolved_cases += 1,
        }
    }

    Some(BlackObfDeflatten {
        linear_block_pcs,
        resolved_cases,
        unresolved_cases,
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

    let has_hashcode_invoke: bool = insns
        .iter()
        .any(|i: &DalvikInsn| (i.op == OP_INVOKE_VIRTUAL || i.op == 0x74) && i.index.is_some());

    let mut dispatcher_count: usize = 0;
    let mut dispatch_cases: usize = 0;
    let mut hashcode_keyed: bool = false;
    for insn in insns {
        if insn.op != OP_SPARSE_SWITCH && insn.op != OP_PACKED_SWITCH {
            continue;
        }
        let Some(off): Option<u32> = insn.payload_off else {
            continue;
        };
        let Some((_, payload)): Option<&(u32, SwitchPayload)> = switches
            .iter()
            .find(|(o, _): &&(u32, SwitchPayload)| *o == off)
        else {
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
            "BlackObfuscator-style control-flow flattening: {dispatcher_count} hashCode-keyed dispatcher(s) over {dispatch_cases} case(s); each real block is gated behind String.hashCode() of a literal block-name. Static deflattening recovers the linear order by matching each block's const-string hashCode to its switch case."
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
        let report: BlackObfReport = detect_blackobfuscator(&insns, &[(0x100, payload)]);
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
            deflatten_blackobfuscator(&insns, &[(0x100, payload)], &strings).expect("deflatten");
        assert_eq!(de.resolved_cases, 4);
        assert_eq!(de.unresolved_cases, 0);
        assert_eq!(de.linear_block_pcs, vec![400, 100, 200, 300]);
    }

    #[test]
    fn java_string_hashcode_matches_jdk() {
        assert_eq!(java_string_hashcode("hello"), 99162322);
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
        let report: BlackObfReport = detect_blackobfuscator(&insns, &[(0x100, payload)]);
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
