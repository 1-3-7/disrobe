use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use yaxpeax_arch::Decoder as _;
use yaxpeax_arm::armv8::a64::{InstDecoder, Instruction, Opcode, Operand};

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
}
