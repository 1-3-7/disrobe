use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use yaxpeax_arch::Decoder as _;
use yaxpeax_arm::armv8::a64::{InstDecoder, Instruction, Opcode, Operand};

use super::cluster::DartReadStream;
use super::string_pool::recover_string_pool;

const ARM64_INSN_LEN: usize = 4;

const DART_POOL_POINTER_REG: u16 = 27;

const DART_POOL_ENTRY_BYTES: u64 = 8;

const DISPATCH_LOOKBACK_INSNS: usize = 4;

const POOL_DECODE_BUDGET: usize = 1 << 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PoolSlotUse {
    pub slot_index: u64,
    pub byte_offset: u64,
    pub load_sites: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DispatchSite {
    pub call_address: u64,
    pub pool_slot_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectPoolReferenceMap {
    pub distinct_slots: usize,
    pub total_load_sites: usize,
    pub highest_slot_index: u64,
    pub estimated_pool_entries: u64,
    pub slots: Vec<PoolSlotUse>,
    pub direct_call_count: usize,
    pub indirect_call_count: usize,
    pub dispatch_sites: Vec<DispatchSite>,
    pub distinct_dispatch_slots: usize,
}

#[must_use]
pub fn recover_object_pool_references(base: u64, instructions: &[u8]) -> ObjectPoolReferenceMap {
    let decoder: InstDecoder = InstDecoder::default();
    let word_count: usize = instructions.len() / ARM64_INSN_LEN;
    let scanned: usize = word_count.min(POOL_DECODE_BUDGET);

    let mut slot_load_sites: BTreeMap<u64, u32> = BTreeMap::new();
    let mut last_pool_slot: Option<(u64, u64)> = None;
    let mut dispatch_sites: Vec<DispatchSite> = Vec::new();
    let mut direct_calls: usize = 0;
    let mut indirect_calls: usize = 0;
    let mut highest_slot: u64 = 0;

    for i in 0..scanned {
        let offset: usize = i * ARM64_INSN_LEN;
        let window: &[u8] = &instructions[offset..offset + ARM64_INSN_LEN];
        let address: u64 = base + offset as u64;
        let mut reader: yaxpeax_arch::U8Reader<'_> = yaxpeax_arch::U8Reader::new(window);
        let Ok(insn): Result<Instruction, _> = decoder.decode(&mut reader) else {
            last_pool_slot = None;
            continue;
        };

        if let Some(slot) = pool_load_slot(&insn) {
            *slot_load_sites.entry(slot).or_insert(0) += 1;
            highest_slot = highest_slot.max(slot);
            last_pool_slot = Some((address, slot));
            continue;
        }

        match insn.opcode {
            Opcode::BL => {
                direct_calls += 1;
                last_pool_slot = None;
            }
            Opcode::BLR => {
                indirect_calls += 1;
                if let Some((load_addr, slot)) = last_pool_slot
                    && address.saturating_sub(load_addr)
                        <= (DISPATCH_LOOKBACK_INSNS as u64) * ARM64_INSN_LEN as u64
                {
                    dispatch_sites.push(DispatchSite {
                        call_address: address,
                        pool_slot_index: slot,
                    });
                }
                last_pool_slot = None;
            }
            _ => {}
        }
    }

    let total_load_sites: usize = slot_load_sites.values().map(|c: &u32| *c as usize).sum();
    let slots: Vec<PoolSlotUse> = slot_load_sites
        .iter()
        .map(|(slot, count): (&u64, &u32)| PoolSlotUse {
            slot_index: *slot,
            byte_offset: slot * DART_POOL_ENTRY_BYTES,
            load_sites: *count,
        })
        .collect::<Vec<PoolSlotUse>>();
    let distinct_slots: usize = slots.len();
    let estimated_pool_entries: u64 = if distinct_slots == 0 {
        0
    } else {
        highest_slot + 1
    };

    dispatch_sites.sort_unstable();
    let mut dispatch_slot_set: Vec<u64> = dispatch_sites
        .iter()
        .map(|d: &DispatchSite| d.pool_slot_index)
        .collect::<Vec<u64>>();
    dispatch_slot_set.sort_unstable();
    dispatch_slot_set.dedup();

    ObjectPoolReferenceMap {
        distinct_slots,
        total_load_sites,
        highest_slot_index: highest_slot,
        estimated_pool_entries,
        slots,
        direct_call_count: direct_calls,
        indirect_call_count: indirect_calls,
        dispatch_sites,
        distinct_dispatch_slots: dispatch_slot_set.len(),
    }
}

const POOL_ENTRY_IMMEDIATE: u8 = 0x10;

const POOL_ENTRY_IMMEDIATE_PATCHABLE: u8 = 0x30;

const POOL_ENTRY_TAGGED: u8 = 0x11;

const POOL_ENTRY_TAGGED_PATCHABLE: u8 = 0x31;

const MIN_POOL_RUN: usize = 4;

const MAX_RUN_PROBE: usize = 64;

const MIN_DOUBLE_VARINT_BYTES: usize = 9;

const MAX_POOL_LITERALS: usize = 1 << 16;

const DOUBLE_MIN_MAGNITUDE: f64 = 1e-4;

const DOUBLE_MAX_MAGNITUDE: f64 = 1e12;

const DOUBLE_EXPONENT_MASK: u64 = 0x7ff;

const DOUBLE_EXPONENT_SHIFT: u32 = 52;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum DartPoolLiteral {
    Str(String),
    Double(u64),
}

impl DartPoolLiteral {
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(text) => Some(text.as_str()),
            Self::Double(_) => None,
        }
    }

    #[must_use]
    pub fn as_double(&self) -> Option<f64> {
        match self {
            Self::Double(bits) => Some(f64::from_bits(*bits)),
            Self::Str(_) => None,
        }
    }
}

#[must_use]
pub fn resolve_pool_literals(isolate_data: &[u8]) -> Vec<DartPoolLiteral> {
    let mut literals: Vec<DartPoolLiteral> = Vec::new();
    for text in recover_string_pool(isolate_data).literals {
        if literals.len() >= MAX_POOL_LITERALS {
            break;
        }
        literals.push(DartPoolLiteral::Str(text));
    }
    let mut doubles: BTreeSet<u64> = BTreeSet::new();
    let mut cursor: usize = 0;
    while cursor + 1 < isolate_data.len() && doubles.len() < MAX_POOL_LITERALS {
        if is_immediate_entry(isolate_data[cursor])
            && let Some((bits, _)) = read_double_immediate(isolate_data, cursor + 1)
            && pool_run_length(isolate_data, cursor) >= MIN_POOL_RUN
        {
            doubles.insert(bits);
        }
        cursor += 1;
    }
    for bits in doubles {
        literals.push(DartPoolLiteral::Double(bits));
    }
    literals
}

#[must_use]
const fn is_immediate_entry(bits: u8) -> bool {
    matches!(bits, POOL_ENTRY_IMMEDIATE | POOL_ENTRY_IMMEDIATE_PATCHABLE)
}

#[must_use]
const fn is_tagged_entry(bits: u8) -> bool {
    matches!(bits, POOL_ENTRY_TAGGED | POOL_ENTRY_TAGGED_PATCHABLE)
}

#[must_use]
fn read_double_immediate(data: &[u8], at: usize) -> Option<(u64, usize)> {
    let tail: &[u8] = data.get(at..)?;
    let mut stream: DartReadStream<'_> = DartReadStream::new(tail);
    let value: i64 = stream.read_signed()?;
    let consumed: usize = stream.position();
    if consumed < MIN_DOUBLE_VARINT_BYTES {
        return None;
    }
    let bits: u64 = value as u64;
    plausible_double_bits(bits).then_some((bits, consumed))
}

#[must_use]
fn plausible_double_bits(bits: u64) -> bool {
    let exponent: u64 = (bits >> DOUBLE_EXPONENT_SHIFT) & DOUBLE_EXPONENT_MASK;
    if exponent == 0 || exponent == DOUBLE_EXPONENT_MASK {
        return false;
    }
    let magnitude: f64 = f64::from_bits(bits).abs();
    (DOUBLE_MIN_MAGNITUDE..=DOUBLE_MAX_MAGNITUDE).contains(&magnitude)
}

#[must_use]
fn pool_run_length(data: &[u8], at: usize) -> usize {
    let mut position: usize = at;
    let mut entries: usize = 0;
    while entries < MAX_RUN_PROBE {
        let Some(span): Option<usize> = entry_span(data, position) else {
            break;
        };
        position += span;
        entries += 1;
        if position >= data.len() {
            break;
        }
    }
    entries
}

#[must_use]
fn entry_span(data: &[u8], at: usize) -> Option<usize> {
    let bits: u8 = *data.get(at)?;
    let tail: &[u8] = data.get(at + 1..)?;
    let mut stream: DartReadStream<'_> = DartReadStream::new(tail);
    if is_immediate_entry(bits) {
        stream.read_signed()?;
        Some(1 + stream.position())
    } else if is_tagged_entry(bits) {
        stream.read_unsigned()?;
        Some(1 + stream.position())
    } else {
        None
    }
}

#[must_use]
fn pool_load_slot(insn: &Instruction) -> Option<u64> {
    if insn.opcode != Opcode::LDR {
        return None;
    }
    let Operand::Register(_, dst): Operand = insn.operands[0] else {
        return None;
    };
    if dst == 31 {
        return None;
    }
    match insn.operands[1] {
        Operand::RegPreIndex(DART_POOL_POINTER_REG, offset, false) if offset >= 0 => {
            let byte_offset: u64 = offset as u64;
            if byte_offset % DART_POOL_ENTRY_BYTES != 0 {
                return None;
            }
            Some(byte_offset / DART_POOL_ENTRY_BYTES)
        }
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn ldr_pool(dst: u32, byte_offset: u32) -> u32 {
        let imm12: u32 = byte_offset / 8;
        0xF940_0000 | (imm12 << 10) | (DART_POOL_POINTER_REG as u32) << 5 | dst
    }

    fn blr(reg: u32) -> u32 {
        0xD63F_0000 | (reg << 5)
    }

    fn bl(from: u64, to: u64) -> u32 {
        let imm: i64 = ((to as i64) - (from as i64)) >> 2;
        0x9400_0000 | ((imm as u32) & 0x03ff_ffff)
    }

    fn nop() -> u32 {
        0xD503_201F
    }

    fn assemble(words: &[u32]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(words.len() * 4);
        for w in words {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out
    }

    #[test]
    fn decodes_pool_load_slot_index() {
        let bytes: Vec<u8> = assemble(&[ldr_pool(0, 16), ldr_pool(1, 24), ldr_pool(0, 16)]);
        let map: ObjectPoolReferenceMap = recover_object_pool_references(0, &bytes);
        assert_eq!(map.distinct_slots, 2, "slots 2 and 3 are distinct");
        assert_eq!(map.total_load_sites, 3, "three ldr sites total");
        let slot2: &PoolSlotUse = map
            .slots
            .iter()
            .find(|s: &&PoolSlotUse| s.slot_index == 2)
            .expect("slot 2 present");
        assert_eq!(slot2.byte_offset, 16);
        assert_eq!(slot2.load_sites, 2, "slot 2 loaded twice");
    }

    #[test]
    fn estimates_pool_entries_from_highest_slot() {
        let bytes: Vec<u8> = assemble(&[ldr_pool(0, 16), ldr_pool(1, 800)]);
        let map: ObjectPoolReferenceMap = recover_object_pool_references(0, &bytes);
        assert_eq!(map.highest_slot_index, 100, "800/8 = slot 100");
        assert_eq!(map.estimated_pool_entries, 101);
    }

    #[test]
    fn pairs_pool_load_with_following_dispatch_call() {
        let bytes: Vec<u8> = assemble(&[ldr_pool(2, 64), nop(), blr(2)]);
        let map: ObjectPoolReferenceMap = recover_object_pool_references(0x1000, &bytes);
        assert_eq!(map.indirect_call_count, 1);
        assert_eq!(
            map.dispatch_sites.len(),
            1,
            "the blr after a pool load is a dispatch"
        );
        assert_eq!(map.dispatch_sites[0].pool_slot_index, 8, "64/8 = slot 8");
        assert_eq!(map.distinct_dispatch_slots, 1);
    }

    #[test]
    fn direct_call_breaks_dispatch_pairing() {
        let bytes: Vec<u8> = assemble(&[ldr_pool(2, 64), bl(0x1004, 0x2000), blr(2)]);
        let map: ObjectPoolReferenceMap = recover_object_pool_references(0x1000, &bytes);
        assert_eq!(map.direct_call_count, 1);
        assert_eq!(map.indirect_call_count, 1);
        assert!(
            map.dispatch_sites.is_empty(),
            "an intervening bl clears the last-pool-slot, so the blr is not slot-attributed"
        );
    }

    #[test]
    fn ignores_non_pool_ldr() {
        let ldr_from_obj: u32 = 0xF940_0000;
        let bytes: Vec<u8> = assemble(&[ldr_from_obj]);
        let map: ObjectPoolReferenceMap = recover_object_pool_references(0, &bytes);
        assert_eq!(
            map.distinct_slots, 0,
            "ldr x0,[x0,#0] is a field load, not a pool load"
        );
    }

    #[test]
    fn empty_instructions_yield_empty_map() {
        let map: ObjectPoolReferenceMap = recover_object_pool_references(0, &[]);
        assert_eq!(map.distinct_slots, 0);
        assert_eq!(map.estimated_pool_entries, 0);
        assert_eq!(map.indirect_call_count, 0);
    }

    fn encode_unsigned(mut value: u64) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        loop {
            let low: u8 = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(low | 0x80);
                return out;
            }
            out.push(low);
        }
    }

    fn encode_signed(mut value: i64) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        loop {
            let low: u8 = (value as u8) & 0x7f;
            value >>= 7;
            let sign_bit: bool = low & 0x40 != 0;
            if (value == 0 && !sign_bit) || (value == -1 && sign_bit) {
                out.push(low | 0x80);
                return out;
            }
            out.push(low);
        }
    }

    fn immediate_entry(bits: u64) -> Vec<u8> {
        let mut entry: Vec<u8> = vec![POOL_ENTRY_IMMEDIATE];
        entry.extend_from_slice(&encode_signed(bits as i64));
        entry
    }

    fn tagged_entry(reference: u64) -> Vec<u8> {
        let mut entry: Vec<u8> = vec![POOL_ENTRY_TAGGED];
        entry.extend_from_slice(&encode_unsigned(reference));
        entry
    }

    fn smi_len(char_count: usize) -> Vec<u8> {
        encode_unsigned((char_count as u64) << 1)
    }

    #[test]
    fn resolves_double_immediate_inside_a_pool_run() {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&immediate_entry(19.95f64.to_bits()));
        data.extend_from_slice(&tagged_entry(4886));
        data.extend_from_slice(&immediate_entry(149.5f64.to_bits()));
        data.extend_from_slice(&tagged_entry(4391));
        data.extend_from_slice(&immediate_entry(2400.0f64.to_bits()));
        data.extend_from_slice(&tagged_entry(13069));
        data.extend_from_slice(&tagged_entry(2495));
        data.extend_from_slice(&tagged_entry(8077));
        data.extend_from_slice(&tagged_entry(9114));
        let literals: Vec<DartPoolLiteral> = resolve_pool_literals(&data);
        let doubles: Vec<u64> = literals
            .iter()
            .filter_map(|l: &DartPoolLiteral| l.as_double().map(f64::to_bits))
            .collect::<Vec<u64>>();
        for expected in [19.95f64, 149.5, 2400.0] {
            assert!(
                doubles.contains(&expected.to_bits()),
                "the pool immediate {expected} must resolve byte-exact, got {doubles:?}"
            );
        }
    }

    #[test]
    fn isolated_double_immediate_outside_a_run_is_not_resolved() {
        let mut data: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        data.extend_from_slice(&immediate_entry(19.95f64.to_bits()));
        data.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        let literals: Vec<DartPoolLiteral> = resolve_pool_literals(&data);
        assert!(
            literals
                .iter()
                .all(|l: &DartPoolLiteral| l.as_double().is_none()),
            "a lone immediate with no surrounding entry run must not be typed as a pool double"
        );
    }

    #[test]
    fn corrupted_double_varint_fails_the_match() {
        let mut good: Vec<u8> = Vec::new();
        good.extend_from_slice(&immediate_entry(19.95f64.to_bits()));
        good.extend_from_slice(&tagged_entry(1));
        good.extend_from_slice(&tagged_entry(2));
        good.extend_from_slice(&immediate_entry(149.5f64.to_bits()));
        assert!(
            resolve_pool_literals(&good)
                .iter()
                .filter_map(|l: &DartPoolLiteral| l.as_double().map(f64::to_bits))
                .any(|bits: u64| bits == 19.95f64.to_bits()),
            "the intact pool run must resolve 19.95 byte-exact"
        );

        let mut corrupted: Vec<u8> = Vec::new();
        corrupted.extend_from_slice(&immediate_entry(f64::INFINITY.to_bits()));
        corrupted.extend_from_slice(&tagged_entry(1));
        corrupted.extend_from_slice(&tagged_entry(2));
        corrupted.extend_from_slice(&immediate_entry(f64::NAN.to_bits()));
        let corrupted_doubles: Vec<u64> = resolve_pool_literals(&corrupted)
            .iter()
            .filter_map(|l: &DartPoolLiteral| l.as_double().map(f64::to_bits))
            .collect::<Vec<u64>>();
        assert!(
            corrupted_doubles.is_empty(),
            "non-finite immediates are not plausible pool doubles, got {corrupted_doubles:?}"
        );
    }

    #[test]
    fn resolves_one_byte_string_literal_from_the_pool() {
        let mut data: Vec<u8> = vec![0x00];
        data.extend_from_slice(&smi_len("widget-alpha".len()));
        data.extend_from_slice(b"widget-alpha");
        data.push(0x00);
        let literals: Vec<DartPoolLiteral> = resolve_pool_literals(&data);
        assert!(
            literals
                .iter()
                .any(|l: &DartPoolLiteral| l.as_str() == Some("widget-alpha")),
            "a one-byte string literal must resolve to a typed Str, got {literals:?}"
        );
    }
}
