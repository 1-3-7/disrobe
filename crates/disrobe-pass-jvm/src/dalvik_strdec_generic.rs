use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::dalvik::{self, DalvikInsn};
use crate::dalvik_interp::{self, Interp, RegSlot};
use crate::dex::{CodeItem, DexFile, MethodId};

const SIG_WEIGHT_HIGH: u32 = 40;
const SIG_WEIGHT_LOW: u32 = 20;
const BODY_WEIGHT_XOR: u32 = 15;
const BODY_WEIGHT_BYTE_ACCESS: u32 = 15;
const BODY_WEIGHT_ARRAY_LEN: u32 = 5;
const BODY_WEIGHT_NEW_ARRAY: u32 = 5;
const BODY_WEIGHT_ARRAY_LITERAL: u32 = 10;
const BODY_WEIGHT_TERMINAL: u32 = 15;
const BODY_WEIGHT_TIGHT_LOOP: u32 = 25;
const CONFIDENCE_THRESHOLD: u32 = 50;
const MAX_CANDIDATE_PARAMS: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SkipReason {
    BudgetExhausted,
    UnsupportedOpcode(u8),
    UnsupportedCall(String),
    Unsound,
    DivByZero,
    OutputTooLarge,
}

impl std::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BudgetExhausted => write!(f, "budget exhausted"),
            Self::UnsupportedOpcode(op) => write!(f, "unsupported opcode 0x{op:02X}"),
            Self::UnsupportedCall(m) => write!(f, "unsupported call {m}"),
            Self::Unsound => write!(f, "unsound register or heap access"),
            Self::DivByZero => write!(f, "division by zero"),
            Self::OutputTooLarge => write!(f, "output exceeded the size bound"),
        }
    }
}

impl From<dalvik_interp::SkipReason> for SkipReason {
    fn from(value: dalvik_interp::SkipReason) -> Self {
        match value {
            dalvik_interp::SkipReason::BudgetExhausted => Self::BudgetExhausted,
            dalvik_interp::SkipReason::UnsupportedOpcode(op) => Self::UnsupportedOpcode(op),
            dalvik_interp::SkipReason::UnsupportedCall(m) => Self::UnsupportedCall(m),
            dalvik_interp::SkipReason::Unsound => Self::Unsound,
            dalvik_interp::SkipReason::DivByZero => Self::DivByZero,
            dalvik_interp::SkipReason::OutputTooLarge => Self::OutputTooLarge,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallSiteOutcome {
    Recovered(String),
    Skipped(SkipReason),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallSiteRecovery {
    pub caller_class: String,
    pub caller_method: String,
    pub caller_descriptor: String,
    pub pc: u32,
    pub decrypt_class: String,
    pub decrypt_method: String,
    pub decrypt_descriptor: String,
    pub outcome: CallSiteOutcome,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenericStringRecovery {
    pub candidates_found: usize,
    pub call_sites: Vec<CallSiteRecovery>,
}

impl GenericStringRecovery {
    #[must_use]
    pub fn recovered_count(&self) -> usize {
        self.call_sites
            .iter()
            .filter(|c: &&CallSiteRecovery| matches!(c.outcome, CallSiteOutcome::Recovered(_)))
            .count()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConstVal {
    Int(i64),
    Str(String),
    Bytes(Vec<u8>),
    Chars(Vec<u16>),
    Ints(Vec<i32>),
}

struct CandidateInfo {
    code_index: usize,
}

#[must_use]
pub fn recover(dex: &DexFile, dex_bytes: &[u8]) -> GenericStringRecovery {
    let code_items: Vec<CodeItem> = crate::dex::parse_code_items(dex, dex_bytes);
    let method_by_sig: BTreeMap<(String, String, String), &MethodId> = dex
        .method_ids
        .iter()
        .map(|m: &MethodId| {
            (
                (
                    m.class.clone(),
                    m.name.clone(),
                    dalvik_interp::method_descriptor(m),
                ),
                m,
            )
        })
        .collect();

    let candidates: Vec<CandidateInfo> = find_candidates(dex, &code_items, &method_by_sig);
    let candidates_found: usize = candidates.len();
    let candidates_by_key: BTreeMap<(String, String, String), usize> = candidates
        .iter()
        .map(|c: &CandidateInfo| {
            let code: &CodeItem = &code_items[c.code_index];
            (
                (
                    code.class.clone(),
                    code.method_name.clone(),
                    code.method_descriptor.clone(),
                ),
                c.code_index,
            )
        })
        .collect();

    let mut class_interps: BTreeMap<String, Result<Interp<'_>, dalvik_interp::SkipReason>> =
        BTreeMap::new();
    let mut result_cache: BTreeMap<(String, String), Result<String, dalvik_interp::SkipReason>> =
        BTreeMap::new();
    let mut call_sites: Vec<CallSiteRecovery> = Vec::new();

    for caller_code in &code_items {
        scan_caller(
            dex,
            &code_items,
            caller_code,
            &candidates_by_key,
            &mut class_interps,
            &mut result_cache,
            &mut call_sites,
        );
    }

    crate::debug::dbg_kv("dex-strdec-generic", || {
        format!(
            "candidates={candidates_found} call_sites={} recovered={}",
            call_sites.len(),
            call_sites
                .iter()
                .filter(|c: &&CallSiteRecovery| matches!(c.outcome, CallSiteOutcome::Recovered(_)))
                .count()
        )
    });

    GenericStringRecovery {
        candidates_found,
        call_sites,
    }
}

fn find_candidates(
    dex: &DexFile,
    code_items: &[CodeItem],
    method_by_sig: &BTreeMap<(String, String, String), &MethodId>,
) -> Vec<CandidateInfo> {
    let mut out: Vec<CandidateInfo> = Vec::new();
    for (i, code) in code_items.iter().enumerate() {
        if code.method_name == "<clinit>" || code.method_name == "<init>" {
            continue;
        }
        let key: (String, String, String) = (
            code.class.clone(),
            code.method_name.clone(),
            code.method_descriptor.clone(),
        );
        let Some(method): Option<&&MethodId> = method_by_sig.get(&key) else {
            continue;
        };
        let Some(sig_score): Option<u32> =
            signature_weight(&method.proto.return_type, &method.proto.parameters)
        else {
            continue;
        };
        let insns: Vec<DalvikInsn> = dalvik::decode_method(&code.insns);
        if !self_contained(dex, &insns) {
            continue;
        }
        let body_score: u32 = body_signal_score(dex, &insns);
        if body_score == 0 {
            continue;
        }
        if sig_score + body_score >= CONFIDENCE_THRESHOLD {
            out.push(CandidateInfo { code_index: i });
        }
    }
    out
}

fn signature_weight(return_type: &str, params: &[String]) -> Option<u32> {
    if return_type != "Ljava/lang/String;" {
        return None;
    }
    if params.is_empty() || params.len() > MAX_CANDIDATE_PARAMS {
        return None;
    }
    if !params.iter().all(|p: &String| {
        matches!(
            p.as_str(),
            "[B" | "[C" | "[I" | "Ljava/lang/String;" | "I" | "J"
        )
    }) {
        return None;
    }
    let sig: Vec<&str> = params.iter().map(String::as_str).collect();
    let highest: bool = matches!(
        sig.as_slice(),
        ["[B" | "Ljava/lang/String;"] | ["Ljava/lang/String;" | "[B", "I"]
    );
    Some(if highest {
        SIG_WEIGHT_HIGH
    } else {
        SIG_WEIGHT_LOW
    })
}

fn is_disallowed_external(owner: &str) -> bool {
    if owner == "Landroid/util/Base64;" {
        return false;
    }
    owner.starts_with("Landroid/")
        || owner.starts_with("Ljava/io/")
        || owner.starts_with("Ljava/net/")
        || owner.starts_with("Ljavax/net/")
        || owner.starts_with("Ljava/nio/file/")
        || owner.starts_with("Ljava/nio/channels/")
        || owner.starts_with("Ljava/lang/reflect/")
        || owner.starts_with("Ljava/lang/Thread")
        || owner == "Ljava/lang/ClassLoader;"
        || owner.starts_with("Ldalvik/system/")
        || owner.contains("Socket")
}

fn self_contained(dex: &DexFile, insns: &[DalvikInsn]) -> bool {
    for ins in insns {
        match ins.op {
            0x1D | 0x1E => return false,
            0x52..=0x5F | 0xE3 | 0xE4 | 0xE7..=0xE9 | 0xF2..=0xF7 => return false,
            0xFA..=0xFD => return false,
            0x6E..=0x72 | 0x74..=0x78 => {
                let Some(m): Option<&MethodId> =
                    ins.index.and_then(|i: u32| dex.method_ids.get(i as usize))
                else {
                    continue;
                };
                if is_disallowed_external(&m.class) {
                    return false;
                }
                if m.class == "Ljava/lang/Class;"
                    && matches!(
                        m.name.as_str(),
                        "forName"
                            | "getDeclaredMethod"
                            | "getMethod"
                            | "getDeclaredMethods"
                            | "getMethods"
                    )
                {
                    return false;
                }
            }
            0x1C | 0x1F | 0x22 => {
                let Some(idx): Option<u32> = ins.index else {
                    continue;
                };
                let Some(descriptor): Option<&String> = dex.type_names.get(idx as usize) else {
                    continue;
                };
                if is_disallowed_external(descriptor) {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

fn body_signal_score(dex: &DexFile, insns: &[DalvikInsn]) -> u32 {
    let mut score: u32 = 0;
    if insns
        .iter()
        .any(|i: &DalvikInsn| matches!(i.op, 0x97 | 0xB7 | 0xD7 | 0xDF))
    {
        score += BODY_WEIGHT_XOR;
    }
    if insns
        .iter()
        .any(|i: &DalvikInsn| matches!(i.op, 0x48 | 0x4F))
    {
        score += BODY_WEIGHT_BYTE_ACCESS;
    }
    if insns.iter().any(|i: &DalvikInsn| i.op == 0x21) {
        score += BODY_WEIGHT_ARRAY_LEN;
    }
    if insns.iter().any(|i: &DalvikInsn| i.op == 0x23) {
        score += BODY_WEIGHT_NEW_ARRAY;
    }
    if insns
        .iter()
        .any(|i: &DalvikInsn| matches!(i.op, 0x24..=0x26))
    {
        score += BODY_WEIGHT_ARRAY_LITERAL;
    }
    if has_string_ctor_or_base64(dex, insns) {
        score += BODY_WEIGHT_TERMINAL;
    }
    if tight_backward_loop_signal(insns) {
        score += BODY_WEIGHT_TIGHT_LOOP;
    }
    score
}

fn has_string_ctor_or_base64(dex: &DexFile, insns: &[DalvikInsn]) -> bool {
    insns.iter().any(|ins: &DalvikInsn| {
        if !matches!(ins.op, 0x6E..=0x72 | 0x74..=0x78) {
            return false;
        }
        let Some(m): Option<&MethodId> =
            ins.index.and_then(|i: u32| dex.method_ids.get(i as usize))
        else {
            return false;
        };
        (m.class == "Ljava/lang/String;"
            && m.name == "<init>"
            && m.proto
                .parameters
                .first()
                .is_some_and(|p: &String| p == "[B"))
            || (m.class == "Landroid/util/Base64;" && m.name == "decode")
    })
}

fn tight_backward_loop_signal(insns: &[DalvikInsn]) -> bool {
    let pc_to_index: BTreeMap<u32, usize> = insns
        .iter()
        .enumerate()
        .map(|(i, ins): (usize, &DalvikInsn)| (ins.pc, i))
        .collect();
    for (idx, ins) in insns.iter().enumerate() {
        let Some(target): Option<u32> = ins.branch_target_pc() else {
            continue;
        };
        if target > ins.pc {
            continue;
        }
        let Some(&start): Option<&usize> = pc_to_index.get(&target) else {
            continue;
        };
        if start > idx {
            continue;
        }
        let body: &[DalvikInsn] = &insns[start..=idx];
        let has_aget: bool = body
            .iter()
            .any(|i: &DalvikInsn| matches!(i.op, 0x44..=0x4A));
        let has_bitop: bool = body.iter().any(
            |i: &DalvikInsn| matches!(i.op, 0x95..=0x97 | 0xB5..=0xB7 | 0xD5..=0xD7 | 0xDD..=0xDF),
        );
        let has_aput: bool = body
            .iter()
            .any(|i: &DalvikInsn| matches!(i.op, 0x4B..=0x51));
        if has_aget && has_bitop && has_aput {
            return true;
        }
    }
    false
}

fn compute_join_points(code: &CodeItem, insns: &[DalvikInsn]) -> BTreeSet<u32> {
    let mut out: BTreeSet<u32> = BTreeSet::new();
    for ins in insns {
        if let Some(t) = ins.branch_target_pc() {
            out.insert(t);
        }
        if matches!(ins.op, 0x2B | 0x2C)
            && let Some(payload_off) = ins.payload_off
        {
            let switch: Option<dalvik::SwitchPayload> = if ins.op == 0x2B {
                dalvik::parse_packed_switch(&code.insns, ins.pc, payload_off)
            } else {
                dalvik::parse_sparse_switch(&code.insns, ins.pc, payload_off)
            };
            if let Some(sw) = switch {
                out.extend(sw.targets);
            }
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn scan_caller<'a>(
    dex: &'a DexFile,
    code_items: &'a [CodeItem],
    caller_code: &'a CodeItem,
    candidates_by_key: &BTreeMap<(String, String, String), usize>,
    class_interps: &mut BTreeMap<String, Result<Interp<'a>, dalvik_interp::SkipReason>>,
    result_cache: &mut BTreeMap<(String, String), Result<String, dalvik_interp::SkipReason>>,
    out: &mut Vec<CallSiteRecovery>,
) {
    let insns: Vec<DalvikInsn> = dalvik::decode_method(&caller_code.insns);
    let joins: BTreeSet<u32> = compute_join_points(caller_code, &insns);
    let mut regs: BTreeMap<u16, ConstVal> = BTreeMap::new();
    let mut pending: Option<ConstVal> = None;

    for ins in &insns {
        if joins.contains(&ins.pc) {
            regs.clear();
        }
        match ins.op {
            0x01..=0x09 => {
                if let (Some(&dst), Some(&src)) = (ins.regs.first(), ins.regs.get(1)) {
                    match regs.get(&src).cloned() {
                        Some(v) => {
                            regs.insert(dst, v);
                        }
                        None => {
                            regs.remove(&dst);
                        }
                    }
                }
            }
            0x0A | 0x0C => {
                if let Some(&dst) = ins.regs.first() {
                    match pending.take() {
                        Some(v) => {
                            regs.insert(dst, v);
                        }
                        None => {
                            regs.remove(&dst);
                        }
                    }
                }
            }
            0x0B => {
                if let Some(&dst) = ins.regs.first() {
                    regs.remove(&dst);
                }
                pending = None;
            }
            0x12..=0x15 => {
                if let (Some(&dst), Some(lit)) = (ins.regs.first(), ins.literal) {
                    let v: i64 = if ins.op == 0x15 { lit << 16 } else { lit };
                    regs.insert(dst, ConstVal::Int(v));
                }
            }
            0x16..=0x19 => {
                if let (Some(&dst), Some(lit)) = (ins.regs.first(), ins.literal) {
                    let v: i64 = if ins.op == 0x19 { lit << 48 } else { lit };
                    regs.insert(dst, ConstVal::Int(v));
                }
            }
            0x1A | 0x1B => {
                if let (Some(&dst), Some(idx)) = (ins.regs.first(), ins.index) {
                    match dex.strings.get(idx as usize) {
                        Some(s) => {
                            regs.insert(dst, ConstVal::Str(s.clone()));
                        }
                        None => {
                            regs.remove(&dst);
                        }
                    }
                }
            }
            0x23 => {
                if let (Some(&dst), Some(&size_reg), Some(type_idx)) =
                    (ins.regs.first(), ins.regs.get(1), ins.index)
                {
                    let descriptor: Option<&str> =
                        dex.type_names.get(type_idx as usize).map(String::as_str);
                    let len: Option<usize> = match regs.get(&size_reg) {
                        Some(ConstVal::Int(n)) => usize::try_from(*n).ok(),
                        _ => None,
                    };
                    match (descriptor, len) {
                        (Some("[B"), Some(n)) if n <= dalvik_interp::MAX_ARRAY_LEN => {
                            regs.insert(dst, ConstVal::Bytes(vec![0u8; n]));
                        }
                        (Some("[C"), Some(n)) if n <= dalvik_interp::MAX_ARRAY_LEN => {
                            regs.insert(dst, ConstVal::Chars(vec![0u16; n]));
                        }
                        (Some("[I"), Some(n)) if n <= dalvik_interp::MAX_ARRAY_LEN => {
                            regs.insert(dst, ConstVal::Ints(vec![0i32; n]));
                        }
                        _ => {
                            regs.remove(&dst);
                        }
                    }
                }
            }
            0x24 | 0x25 => {
                pending = ins.index.and_then(|type_idx: u32| {
                    let descriptor: &str = dex.type_names.get(type_idx as usize)?.as_str();
                    let vals: Vec<i64> = ins
                        .regs
                        .iter()
                        .map(|r: &u16| match regs.get(r) {
                            Some(ConstVal::Int(n)) => Some(*n),
                            _ => None,
                        })
                        .collect::<Option<Vec<i64>>>()?;
                    match descriptor {
                        "[B" => Some(ConstVal::Bytes(
                            vals.iter().map(|&v: &i64| v as u8).collect(),
                        )),
                        "[C" => Some(ConstVal::Chars(
                            vals.iter().map(|&v: &i64| v as u16).collect(),
                        )),
                        "[I" => Some(ConstVal::Ints(
                            vals.iter().map(|&v: &i64| v as i32).collect(),
                        )),
                        _ => None,
                    }
                });
            }
            0x26 => {
                if let (Some(&dst), Some(payload_off)) = (ins.regs.first(), ins.payload_off) {
                    apply_fill_array_data(&mut regs, &caller_code.insns, dst, payload_off);
                }
            }
            0x4B => update_array_put(&mut regs, ins, ArrayKind::Ints),
            0x4F => update_array_put(&mut regs, ins, ArrayKind::Bytes),
            0x50 => update_array_put(&mut regs, ins, ArrayKind::Chars),
            0x6E..=0x72 | 0x74..=0x78 => {
                pending = None;
                let Some(method_idx): Option<u32> = ins.index else {
                    continue;
                };
                let Some(method): Option<&MethodId> = dex.method_ids.get(method_idx as usize)
                else {
                    continue;
                };
                let key: (String, String, String) = (
                    method.class.clone(),
                    method.name.clone(),
                    dalvik_interp::method_descriptor(method),
                );
                let Some(&code_index): Option<&usize> = candidates_by_key.get(&key) else {
                    continue;
                };
                let Some(args): Option<Vec<ConstVal>> =
                    collect_args(&regs, &ins.regs, &method.proto.parameters)
                else {
                    continue;
                };
                let candidate_code: &CodeItem = &code_items[code_index];
                let method_id: String = format!("{}->{}{}", key.0, key.1, key.2);
                let cache_key: (String, String) = (method_id, canonical_key(&args));
                let outcome: Result<String, dalvik_interp::SkipReason> = result_cache
                    .entry(cache_key)
                    .or_insert_with(|| {
                        evaluate_candidate(
                            dex,
                            code_items,
                            class_interps,
                            candidate_code,
                            &method.proto.parameters,
                            &args,
                        )
                    })
                    .clone();
                out.push(CallSiteRecovery {
                    caller_class: caller_code.class.clone(),
                    caller_method: caller_code.method_name.clone(),
                    caller_descriptor: caller_code.method_descriptor.clone(),
                    pc: ins.pc,
                    decrypt_class: method.class.clone(),
                    decrypt_method: method.name.clone(),
                    decrypt_descriptor: dalvik_interp::method_descriptor(method),
                    outcome: match &outcome {
                        Ok(plain) => CallSiteOutcome::Recovered(plain.clone()),
                        Err(e) => CallSiteOutcome::Skipped(e.clone().into()),
                    },
                });
                if let Ok(plain) = outcome {
                    pending = Some(ConstVal::Str(plain));
                }
            }
            _ => {}
        }
    }
}

enum ArrayKind {
    Bytes,
    Chars,
    Ints,
}

fn update_array_put(regs: &mut BTreeMap<u16, ConstVal>, ins: &DalvikInsn, kind: ArrayKind) {
    let (Some(&src), Some(&arr), Some(&idx)) = (ins.regs.first(), ins.regs.get(1), ins.regs.get(2))
    else {
        return;
    };
    let src_val: Option<i64> = match regs.get(&src) {
        Some(ConstVal::Int(v)) => Some(*v),
        _ => None,
    };
    let idx_val: Option<usize> = match regs.get(&idx) {
        Some(ConstVal::Int(v)) => usize::try_from(*v).ok(),
        _ => None,
    };
    let Some(i): Option<usize> = idx_val else {
        regs.remove(&arr);
        return;
    };
    let Some(v): Option<i64> = src_val else {
        regs.remove(&arr);
        return;
    };
    let ok: bool = match (kind, regs.get_mut(&arr)) {
        (ArrayKind::Bytes, Some(ConstVal::Bytes(a))) if i < a.len() => {
            a[i] = v as u8;
            true
        }
        (ArrayKind::Chars, Some(ConstVal::Chars(a))) if i < a.len() => {
            a[i] = v as u16;
            true
        }
        (ArrayKind::Ints, Some(ConstVal::Ints(a))) if i < a.len() => {
            a[i] = v as i32;
            true
        }
        _ => false,
    };
    if !ok {
        regs.remove(&arr);
    }
}

fn apply_fill_array_data(
    regs: &mut BTreeMap<u16, ConstVal>,
    code_units: &[u16],
    dst: u16,
    payload_off: u32,
) {
    let Some(payload): Option<dalvik::ArrayDataPayload> =
        dalvik::parse_fill_array_data(code_units, payload_off)
    else {
        regs.remove(&dst);
        return;
    };
    let replacement: Option<ConstVal> = match (regs.get(&dst), payload.element_width) {
        (Some(ConstVal::Bytes(v)), 1) if v.len() == payload.data.len() => {
            Some(ConstVal::Bytes(payload.data))
        }
        (Some(ConstVal::Chars(v)), 2) if v.len() * 2 == payload.data.len() => {
            Some(ConstVal::Chars(
                payload
                    .data
                    .chunks_exact(2)
                    .map(|c: &[u8]| u16::from_le_bytes([c[0], c[1]]))
                    .collect(),
            ))
        }
        (Some(ConstVal::Ints(v)), 4) if v.len() * 4 == payload.data.len() => Some(ConstVal::Ints(
            payload
                .data
                .chunks_exact(4)
                .map(|c: &[u8]| i32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                .collect(),
        )),
        _ => None,
    };
    match replacement {
        Some(v) => {
            regs.insert(dst, v);
        }
        None => {
            regs.remove(&dst);
        }
    }
}

fn collect_args(
    regs: &BTreeMap<u16, ConstVal>,
    arg_regs: &[u16],
    params: &[String],
) -> Option<Vec<ConstVal>> {
    let mut out: Vec<ConstVal> = Vec::with_capacity(params.len());
    let mut ci: usize = 0;
    for p in params {
        let reg: u16 = *arg_regs.get(ci)?;
        let val: ConstVal = regs.get(&reg)?.clone();
        match (p.as_str(), &val) {
            ("I", ConstVal::Int(_))
            | ("Ljava/lang/String;", ConstVal::Str(_))
            | ("[B", ConstVal::Bytes(_))
            | ("[C", ConstVal::Chars(_))
            | ("[I", ConstVal::Ints(_)) => {
                out.push(val);
                ci += 1;
            }
            ("J", ConstVal::Int(_)) => {
                out.push(val);
                ci += 2;
            }
            _ => return None,
        }
    }
    Some(out)
}

fn canonical_key(args: &[ConstVal]) -> String {
    let mut out: String = String::new();
    for a in args {
        match a {
            ConstVal::Int(v) => {
                let _ = write!(out, "I:{v}");
            }
            ConstVal::Str(s) => {
                out.push_str("S:");
                out.push_str(s);
            }
            ConstVal::Bytes(b) => {
                out.push_str("B:");
                for byte in b {
                    let _ = write!(out, "{byte:02x}");
                }
            }
            ConstVal::Chars(c) => {
                out.push_str("C:");
                for ch in c {
                    let _ = write!(out, "{ch:04x}");
                }
            }
            ConstVal::Ints(v) => {
                out.push_str("N:");
                for n in v {
                    let _ = write!(out, "{n:08x},");
                }
            }
        }
        out.push('|');
    }
    out
}

fn expected_slots(params: &[String]) -> usize {
    params
        .iter()
        .map(|p: &String| if p == "J" { 2 } else { 1 })
        .sum()
}

fn is_static_call(code: &CodeItem, params: &[String]) -> Option<bool> {
    let expected: usize = expected_slots(params);
    let ins: usize = usize::from(code.ins_size);
    if ins == expected {
        Some(true)
    } else if ins == expected + 1 {
        Some(false)
    } else {
        None
    }
}

fn build_arg_regs(
    interp: &mut Interp<'_>,
    code: &CodeItem,
    params: &[String],
    args: &[ConstVal],
) -> Result<Vec<RegSlot>, dalvik_interp::SkipReason> {
    let is_static: bool = is_static_call(code, params).ok_or(dalvik_interp::SkipReason::Unsound)?;
    let mut regs: Vec<RegSlot> = vec![RegSlot::Undefined; usize::from(code.registers_size).max(1)];
    let in_count: usize = usize::from(code.ins_size);
    let base: usize = regs.len().saturating_sub(in_count);
    let mut cursor: usize = if is_static { base } else { base + 1 };
    for (param, arg) in params.iter().zip(args) {
        if cursor >= regs.len() {
            return Err(dalvik_interp::SkipReason::Unsound);
        }
        match (param.as_str(), arg) {
            ("I", ConstVal::Int(v)) => {
                regs[cursor] = RegSlot::I32(*v as u32);
                cursor += 1;
            }
            ("J", ConstVal::Int(v)) => {
                if cursor + 1 >= regs.len() {
                    return Err(dalvik_interp::SkipReason::Unsound);
                }
                regs[cursor] = RegSlot::WideLow(*v as u64);
                regs[cursor + 1] = RegSlot::WideHigh;
                cursor += 2;
            }
            ("Ljava/lang/String;", ConstVal::Str(s)) => {
                let units: Vec<u16> = s.encode_utf16().collect();
                regs[cursor] = interp.alloc_text(units)?;
                cursor += 1;
            }
            ("[B", ConstVal::Bytes(b)) => {
                regs[cursor] = interp.alloc_byte_array(b.clone())?;
                cursor += 1;
            }
            ("[C", ConstVal::Chars(c)) => {
                regs[cursor] = interp.alloc_char_array(c.clone())?;
                cursor += 1;
            }
            ("[I", ConstVal::Ints(v)) => {
                regs[cursor] = interp.alloc_int_array(v.clone())?;
                cursor += 1;
            }
            _ => return Err(dalvik_interp::SkipReason::Unsound),
        }
    }
    Ok(regs)
}

fn evaluate_candidate<'a>(
    dex: &'a DexFile,
    code_items: &'a [CodeItem],
    class_interps: &mut BTreeMap<String, Result<Interp<'a>, dalvik_interp::SkipReason>>,
    candidate_code: &'a CodeItem,
    params: &[String],
    args: &[ConstVal],
) -> Result<String, dalvik_interp::SkipReason> {
    let entry: &mut Result<Interp<'a>, dalvik_interp::SkipReason> = class_interps
        .entry(candidate_code.class.clone())
        .or_insert_with(|| {
            let mut interp: Interp<'a> = Interp::new(dex, &candidate_code.class, code_items);
            match interp.run_clinit() {
                Ok(()) => Ok(interp),
                Err(e) => Err(e),
            }
        });
    let interp: &mut Interp<'a> = match entry {
        Ok(i) => i,
        Err(e) => return Err(e.clone()),
    };
    let regs: Vec<RegSlot> = build_arg_regs(interp, candidate_code, params, args)?;
    match interp.execute(candidate_code, regs) {
        Ok(Some(slot)) => interp.finish_text(slot),
        Ok(None) => Err(dalvik_interp::SkipReason::Unsound),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests;
