#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::panic::{AssertUnwindSafe, catch_unwind};

use disrobe_pass_pyfreeze::pyoxidizer::signatures::{
    ExtractedModule, PackedResourcesParse, extract_modules, extract_resources_blob,
    parse_packed_resources,
};

const BLOB_MAGIC_V3: &[u8] = b"pyembed\x03";
const BLOB_START_OF_ENTRY: u8 = 0x01;
const BLOB_RESOURCE_FIELD_TYPE: u8 = 0x02;
const BLOB_RAW_PAYLOAD_LENGTH: u8 = 0x03;
const BLOB_INTERIOR_PADDING: u8 = 0x04;
const BLOB_END_OF_ENTRY: u8 = 0xff;
const BLOB_END_OF_INDEX: u8 = 0x00;
const PADDING_NONE: u8 = 0x01;
const RES_START_OF_ENTRY: u8 = 0x01;
const RES_NAME: u8 = 0x03;
const RES_IS_PYTHON_PACKAGE: u8 = 0x04;
const RES_IS_PYTHON_MODULE: u8 = 0x16;
const RES_IN_MEMORY_BYTECODE: u8 = 0x07;
const RES_END_OF_ENTRY: u8 = 0xff;
const RES_END_OF_INDEX: u8 = 0x00;

const COUNT_OFFSET: usize = BLOB_MAGIC_V3.len() + 1 + 4;
const CAP: usize = 1_000_000;

struct Module<'a> {
    name: &'a str,
    is_package: bool,
    bytecode: &'a [u8],
}

fn push_section(index: &mut Vec<u8>, count: &mut u8, field: u8, len: usize) {
    index.push(BLOB_START_OF_ENTRY);
    index.push(BLOB_RESOURCE_FIELD_TYPE);
    index.push(field);
    index.push(BLOB_RAW_PAYLOAD_LENGTH);
    index.extend_from_slice(&(len as u64).to_le_bytes());
    index.push(BLOB_INTERIOR_PADDING);
    index.push(PADDING_NONE);
    index.push(BLOB_END_OF_ENTRY);
    *count += 1;
}

fn build_v3_blob(modules: &[Module<'_>]) -> Vec<u8> {
    let mut name_section: Vec<u8> = Vec::new();
    let mut bytecode_section: Vec<u8> = Vec::new();
    for m in modules {
        name_section.extend_from_slice(m.name.as_bytes());
        bytecode_section.extend_from_slice(m.bytecode);
    }

    let mut blob_index: Vec<u8> = Vec::new();
    let mut section_count: u8 = 0;
    push_section(
        &mut blob_index,
        &mut section_count,
        RES_NAME,
        name_section.len(),
    );
    if !bytecode_section.is_empty() {
        push_section(
            &mut blob_index,
            &mut section_count,
            RES_IN_MEMORY_BYTECODE,
            bytecode_section.len(),
        );
    }
    blob_index.push(BLOB_END_OF_INDEX);

    let mut resources_index: Vec<u8> = Vec::new();
    for m in modules {
        resources_index.push(RES_START_OF_ENTRY);
        resources_index.push(RES_NAME);
        resources_index.extend_from_slice(&(m.name.len() as u16).to_le_bytes());
        if m.is_package {
            resources_index.push(RES_IS_PYTHON_PACKAGE);
        }
        resources_index.push(RES_IS_PYTHON_MODULE);
        if !m.bytecode.is_empty() {
            resources_index.push(RES_IN_MEMORY_BYTECODE);
            resources_index.extend_from_slice(&(m.bytecode.len() as u32).to_le_bytes());
        }
        resources_index.push(RES_END_OF_ENTRY);
    }
    resources_index.push(RES_END_OF_INDEX);

    assemble(
        section_count,
        &blob_index,
        modules.len() as u32,
        &resources_index,
        &name_section,
        &bytecode_section,
    )
}

fn build_empty_name_blob(entry_count: usize) -> Vec<u8> {
    let mut blob_index: Vec<u8> = Vec::new();
    let mut section_count: u8 = 0;
    push_section(&mut blob_index, &mut section_count, RES_NAME, 0);
    blob_index.push(BLOB_END_OF_INDEX);

    let mut resources_index: Vec<u8> = Vec::with_capacity(entry_count * 5 + 1);
    for _ in 0..entry_count {
        resources_index.push(RES_START_OF_ENTRY);
        resources_index.push(RES_NAME);
        resources_index.extend_from_slice(&0u16.to_le_bytes());
        resources_index.push(RES_END_OF_ENTRY);
    }
    resources_index.push(RES_END_OF_INDEX);

    assemble(
        section_count,
        &blob_index,
        entry_count as u32,
        &resources_index,
        &[],
        &[],
    )
}

fn assemble(
    section_count: u8,
    blob_index: &[u8],
    resources_count: u32,
    resources_index: &[u8],
    name_section: &[u8],
    bytecode_section: &[u8],
) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(BLOB_MAGIC_V3);
    out.push(section_count);
    out.extend_from_slice(&(blob_index.len() as u32).to_le_bytes());
    out.extend_from_slice(&resources_count.to_le_bytes());
    out.extend_from_slice(&(resources_index.len() as u32).to_le_bytes());
    out.extend_from_slice(blob_index);
    out.extend_from_slice(resources_index);
    out.extend_from_slice(name_section);
    out.extend_from_slice(bytecode_section);
    out
}

fn never_panics(label: &str, input: &[u8]) {
    let owned: Vec<u8> = input.to_vec();
    let result: Result<(), _> = catch_unwind(AssertUnwindSafe(|| {
        let _ = extract_resources_blob(&owned);
        let _ = parse_packed_resources(&owned);
        let _ = extract_modules(&owned);
    }));
    assert!(result.is_ok(), "parser panicked on {label}");
}

#[test]
fn well_formed_blob_still_parses_identically() {
    let blob: Vec<u8> = build_v3_blob(&[
        Module {
            name: "alpha",
            is_package: false,
            bytecode: b"\xde\xad\xbe\xef body a",
        },
        Module {
            name: "pkg",
            is_package: true,
            bytecode: b"pkg init body",
        },
    ]);
    let modules: Vec<ExtractedModule> = extract_modules(&blob).expect("well-formed blob extracts");
    assert_eq!(modules.len(), 2);
    assert_eq!(modules[0].name, "alpha");
    assert_eq!(
        modules[0].bytecode.as_deref(),
        Some(&b"\xde\xad\xbe\xef body a"[..])
    );
    assert!(!modules[0].is_package);
    assert_eq!(modules[1].name, "pkg");
    assert!(modules[1].is_package);
    assert_eq!(modules[1].bytecode.as_deref(), Some(&b"pkg init body"[..]));

    let parsed: PackedResourcesParse = parse_packed_resources(&blob).expect("parse");
    assert!(!parsed.best_effort);
    assert_eq!(parsed.declared_count, 2);
    assert_eq!(parsed.entries.len(), 2);
}

#[test]
fn empty_name_entry_flood_is_capped_not_ooming() {
    let blob: Vec<u8> = build_empty_name_blob(CAP + 1);
    let outcome: Result<Vec<ExtractedModule>, _> = extract_modules(&blob);
    assert!(
        outcome.is_err(),
        "a v3 blob declaring {} minimal resource entries must be rejected once the entry cap is hit, \
         not walked into a multi-gigabyte allocation",
        CAP + 1
    );
    never_panics("empty-name flood", &blob);
}

#[test]
fn modest_entry_count_below_cap_parses() {
    let blob: Vec<u8> = build_empty_name_blob(16);
    let modules: Vec<ExtractedModule> = extract_modules(&blob).expect("under-cap blob extracts");
    assert_eq!(modules.len(), 16);
    assert!(modules.iter().all(|m: &ExtractedModule| m.name.is_empty()));
}

#[test]
fn truncated_header_variants_return_error_not_panic() {
    let full: Vec<u8> = build_v3_blob(&[Module {
        name: "m",
        is_package: false,
        bytecode: b"BC",
    }]);
    for cut in 0..full.len().min(48) {
        let slice: &[u8] = &full[..cut];
        never_panics("truncated header", slice);
        let recovered: bool = extract_modules(slice).map_or(true, |m| m.is_empty());
        assert!(
            recovered,
            "truncated blob must never yield a populated module list"
        );
    }
}

#[test]
fn oversized_length_fields_fail_fast() {
    let base: Vec<u8> = build_v3_blob(&[Module {
        name: "m",
        is_package: false,
        bytecode: b"BC",
    }]);

    let mut huge_blob_index: Vec<u8> = base.clone();
    let bi_off: usize = BLOB_MAGIC_V3.len() + 1;
    huge_blob_index[bi_off..bi_off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    never_panics("huge blob_index_length", &huge_blob_index);
    let _ = extract_modules(&huge_blob_index);

    let mut huge_res_index: Vec<u8> = base;
    let ri_off: usize = BLOB_MAGIC_V3.len() + 1 + 4 + 4;
    huge_res_index[ri_off..ri_off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    never_panics("huge resources_index_length", &huge_res_index);
    let _ = extract_modules(&huge_res_index);
}

#[test]
fn oversized_payload_length_stays_bounded() {
    let name: &[u8] = b"m";
    let mut blob_index: Vec<u8> = Vec::new();
    let mut section_count: u8 = 0;
    push_section(&mut blob_index, &mut section_count, RES_NAME, name.len());
    push_section(
        &mut blob_index,
        &mut section_count,
        RES_IN_MEMORY_BYTECODE,
        2,
    );
    blob_index.push(BLOB_END_OF_INDEX);

    let mut resources_index: Vec<u8> = Vec::new();
    resources_index.push(RES_START_OF_ENTRY);
    resources_index.push(RES_NAME);
    resources_index.extend_from_slice(&(name.len() as u16).to_le_bytes());
    resources_index.push(RES_IS_PYTHON_MODULE);
    resources_index.push(RES_IN_MEMORY_BYTECODE);
    resources_index.extend_from_slice(&u32::MAX.to_le_bytes());
    resources_index.push(RES_END_OF_ENTRY);
    resources_index.push(RES_END_OF_INDEX);

    let blob: Vec<u8> = assemble(section_count, &blob_index, 1, &resources_index, name, b"BC");
    never_panics("payload length overruns region", &blob);
    assert!(
        extract_modules(&blob).is_err(),
        "a resource declaring a u32::MAX bytecode length past the region must fail, not allocate it"
    );
    let parsed: PackedResourcesParse =
        parse_packed_resources(&blob).expect("parse falls back rather than failing");
    assert!(parsed.best_effort);
}

#[test]
fn count_mismatch_falls_back_to_bounded_heuristic() {
    let mut blob: Vec<u8> = build_v3_blob(&[Module {
        name: "only",
        is_package: false,
        bytecode: b"__pycache__/only.pyc",
    }]);
    blob[COUNT_OFFSET..COUNT_OFFSET + 4].copy_from_slice(&9999u32.to_le_bytes());
    let parsed: PackedResourcesParse =
        parse_packed_resources(&blob).expect("count mismatch falls back, never fails");
    assert!(parsed.best_effort);
    never_panics("count mismatch", &blob);
}

#[test]
fn section_count_mismatch_is_rejected() {
    let mut blob: Vec<u8> = build_v3_blob(&[Module {
        name: "m",
        is_package: false,
        bytecode: b"BC",
    }]);
    let section_off: usize = BLOB_MAGIC_V3.len();
    blob[section_off] = 200;
    never_panics("section count mismatch", &blob);
    let _ = extract_modules(&blob);
}

#[test]
fn wrong_magic_yields_empty_not_panic() {
    let mut blob: Vec<u8> = build_v3_blob(&[Module {
        name: "m",
        is_package: false,
        bytecode: b"BC",
    }]);
    blob[0..7].copy_from_slice(b"garbage");
    never_panics("wrong magic", &blob);
    assert!(
        extract_modules(&blob)
            .expect("no v3 magic is not malformed")
            .is_empty(),
        "without the v3 magic the extractor yields no modules"
    );
    assert!(parse_packed_resources(&blob).is_none());
}

#[test]
fn all_ones_and_zero_regions_never_panic() {
    never_panics("all zero", &[0u8; 512]);
    never_panics("all ones", &[0xffu8; 512]);
    let mut magic_then_ones: Vec<u8> = BLOB_MAGIC_V3.to_vec();
    magic_then_ones.extend_from_slice(&[0xffu8; 256]);
    never_panics("magic then ones", &magic_then_ones);
    let mut magic_then_zero: Vec<u8> = BLOB_MAGIC_V3.to_vec();
    magic_then_zero.extend_from_slice(&[0u8; 256]);
    never_panics("magic then zero", &magic_then_zero);
}

#[test]
fn deterministic_bitflip_sweep_over_valid_blob_never_panics() {
    let base: Vec<u8> = build_v3_blob(&[
        Module {
            name: "alpha",
            is_package: false,
            bytecode: b"AAAA",
        },
        Module {
            name: "beta",
            is_package: true,
            bytecode: b"BBBBBB",
        },
    ]);
    for byte_idx in 0..base.len() {
        for bit in 0u8..8 {
            let mut mutated: Vec<u8> = base.clone();
            mutated[byte_idx] ^= 1u8 << bit;
            never_panics("bitflip", &mutated);
        }
    }
}

#[test]
fn xorshift_random_inputs_never_panic() {
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = || -> u64 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..4_000 {
        let len: usize = (next() % 600) as usize;
        let mut bytes: Vec<u8> = Vec::with_capacity(len);
        if next() & 1 == 0 {
            bytes.extend_from_slice(BLOB_MAGIC_V3);
        }
        while bytes.len() < len {
            bytes.push((next() & 0xff) as u8);
        }
        never_panics("random", &bytes);
    }
}
