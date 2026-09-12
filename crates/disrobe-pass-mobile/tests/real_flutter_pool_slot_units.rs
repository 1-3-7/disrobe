#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::uninlined_format_args
)]

use std::path::{Path, PathBuf};

use disrobe_pass_mobile::flutter::pool_table::{pool_offset_of_slot, pool_slot_of_offset};
use disrobe_pass_mobile::{
    AotLiftReport, DART_POOL_ELEMENT_BASE_BYTES, DartPoolRef, ObjectPoolReferenceMap, PoolSlotUse,
    dart_isolate_instruction_bytes, lift_libapp_aot, recover_object_pool_references,
};

const COMMITTED_SAMPLES: [&str; 4] = [
    "disrobe_sample/libapp_arm64.so",
    "pinned_graph_fixture/receipt_validator_arm64.so",
    "pinned_graph_fixture/receipt_validator_obfuscated_arm64.so",
    "pinned_graph_fixture/voucher_validator_arm64.so",
];

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("mobile")
        .join("flutter")
}

fn read_sample(relative: &str) -> Vec<u8> {
    let mut path: PathBuf = corpus();
    for part in relative.split('/') {
        path = path.join(part);
    }
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("sample {} must be committed: {e}", path.display()))
}

#[test]
fn every_reported_pool_slot_index_is_an_entry_index_not_a_byte_offset() {
    let mut checked: usize = 0;
    for sample in COMMITTED_SAMPLES {
        let instructions: Vec<u8> = dart_isolate_instruction_bytes(&read_sample(sample))
            .expect("the committed sample carries isolate instructions");
        let map: ObjectPoolReferenceMap = recover_object_pool_references(0, &instructions);
        for slot in &map.slots {
            let PoolSlotUse {
                slot_index,
                byte_offset,
                ..
            } = *slot;
            assert_eq!(
                pool_offset_of_slot(slot_index),
                byte_offset,
                "{sample} reports slot {slot_index} at byte offset {byte_offset}; the two must be \
                 the same location expressed in entries and in bytes"
            );
            assert_eq!(
                pool_slot_of_offset(byte_offset),
                Some(slot_index),
                "{sample} byte offset {byte_offset} must convert back to entry index {slot_index}"
            );
            assert!(
                byte_offset >= DART_POOL_ELEMENT_BASE_BYTES,
                "{sample} reports byte offset {byte_offset} inside the pool header, which is not a \
                 slot"
            );
            checked += 1;
        }
        for dispatch in &map.dispatch_sites {
            assert!(
                dispatch.pool_slot_index <= map.highest_slot_index,
                "{sample} dispatch site at {:#x} names entry {} above the highest observed entry \
                 {}; a byte offset stored in an entry-index field would land here",
                dispatch.call_address,
                dispatch.pool_slot_index,
                map.highest_slot_index
            );
        }
    }
    eprintln!("pool slot uses whose entry index and byte offset agree: {checked}");
    assert!(
        checked > 0,
        "the committed corpus must report pool slot uses for this unit check to mean anything"
    );
}

#[test]
fn every_lifted_pool_reference_names_an_entry_index_within_the_table() {
    let mut checked: usize = 0;
    let mut resolved: usize = 0;
    for sample in COMMITTED_SAMPLES {
        let report: AotLiftReport =
            lift_libapp_aot(&read_sample(sample)).expect("lift committed Dart sample");
        let slots: usize = report.pool_slots.as_ref().map_or(0, |stats| stats.slots);
        if slots == 0 {
            continue;
        }
        for function in &report.functions {
            for pool_ref in &function.pool_refs {
                let DartPoolRef {
                    slot_index,
                    resolved_content,
                    ..
                } = pool_ref;
                assert!(
                    usize::try_from(*slot_index).is_ok_and(|index: usize| index < slots),
                    "{sample} reports pool entry {slot_index} but the table holds {slots} entries; \
                     a byte offset stored in an entry-index field would exceed the table"
                );
                if resolved_content.is_some() {
                    resolved += 1;
                }
                checked += 1;
            }
        }
    }
    eprintln!(
        "lifted pool references whose entry index lies inside the table: {checked}, of which \
         {resolved} carry resolved content"
    );
    assert!(checked > 0, "the corpus must expose pool references");
    assert!(resolved > 0, "the corpus must resolve pool content");
}

#[test]
fn the_entry_index_and_byte_offset_conversions_are_inverses() {
    for slot in [0_u64, 1, 2, 6, 98, 100, 512, 4095] {
        let offset: u64 = pool_offset_of_slot(slot);
        assert_eq!(
            pool_slot_of_offset(offset),
            Some(slot),
            "entry {slot} must survive a round trip through its byte offset {offset}"
        );
    }
    assert_eq!(
        pool_slot_of_offset(DART_POOL_ELEMENT_BASE_BYTES),
        Some(0),
        "the first entry sits at the element base, so its index is zero and not the base in bytes"
    );
    assert_eq!(
        pool_slot_of_offset(0),
        None,
        "the pool header is not an entry"
    );
    assert_eq!(
        pool_slot_of_offset(DART_POOL_ELEMENT_BASE_BYTES + 4),
        None,
        "an offset that is not a whole number of entries is not an entry"
    );
}
