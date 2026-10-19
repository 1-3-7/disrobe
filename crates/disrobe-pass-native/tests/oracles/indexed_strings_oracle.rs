#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::missing_docs_in_private_items
)]

use std::collections::BTreeMap;

use disrobe_pass_native::{IndexedStringRecovery, recover_indexed_strings};
use object::{Object as _, ObjectSection as _};

const SOURCE: &str = include_str!("../../../../corpus/native/string-accessor/string_accessor.c");
const MSVC_V1: &[u8] =
    include_bytes!("../../../../corpus/native/string-accessor/string-accessor-msvc-v1.dll");
const MSVC_V2: &[u8] =
    include_bytes!("../../../../corpus/native/string-accessor/string-accessor-msvc-v2.dll");
const CLANG_V1: &[u8] =
    include_bytes!("../../../../corpus/native/string-accessor/string-accessor-clang-v1.dll");
const CLANG_V2: &[u8] =
    include_bytes!("../../../../corpus/native/string-accessor/string-accessor-clang-v2.dll");

fn reference_plaintext() -> Vec<String> {
    let (_, array): (&str, &str) = SOURCE
        .split_once("static const char *const reference_plaintext[] = {")
        .expect("reference plaintext array");
    let (array, _): (&str, &str) = array.split_once("};").expect("reference array terminator");
    array
        .lines()
        .filter_map(|line: &str| {
            let trimmed: &str = line.trim().trim_end_matches(',');
            trimmed
                .strip_prefix('"')
                .and_then(|text: &str| text.strip_suffix('"'))
                .map(str::to_owned)
        })
        .collect()
}

fn annotation_map(recovery: &IndexedStringRecovery) -> BTreeMap<u32, String> {
    recovery
        .annotations
        .iter()
        .map(|annotation| (annotation.index, annotation.literal.clone()))
        .collect()
}

fn assert_fixture_matches_reference(
    name: &str,
    fixture: &[u8],
    expected: &[String],
) -> IndexedStringRecovery {
    let recovery: IndexedStringRecovery = recover_indexed_strings(fixture)
        .unwrap_or_else(|error| panic!("{name} indexed-string recovery failed: {error}"));
    assert!(
        recovery.refusals.is_empty(),
        "{name} must emulate every detected site, got {:?}",
        recovery.refusals
    );
    assert_eq!(
        recovery.annotations.len(),
        expected.len(),
        "{name} must recover one literal per exported wrapper"
    );
    let actual: BTreeMap<u32, String> = annotation_map(&recovery);
    let reference: BTreeMap<u32, String> = expected
        .iter()
        .enumerate()
        .map(|(index, literal): (usize, &String)| (index as u32, literal.clone()))
        .collect();
    assert_eq!(
        actual, reference,
        "{name} recovered literals must match C source"
    );
    recovery
}

fn first_ciphertext_prefix() -> Vec<u8> {
    let (_, blob): (&str, &str) = SOURCE
        .split_once("static const u8 encrypted_blob[] = {")
        .expect("first encrypted blob");
    let (blob, _): (&str, &str) = blob.split_once("};").expect("encrypted blob terminator");
    blob.split(',')
        .filter_map(|field: &str| {
            let value: &str = field.trim().strip_prefix("0x")?;
            u8::from_str_radix(value, 16).ok()
        })
        .take(12)
        .collect()
}

fn mutate_accessor_return(fixture: &[u8], accessor: u64) -> Vec<u8> {
    let file: object::File<'_> = object::File::parse(fixture).expect("fixture object");
    let mut mutated: Vec<u8> = fixture.to_vec();
    for section in file.sections() {
        let Some((file_offset, file_size)): Option<(u64, u64)> = section.file_range() else {
            continue;
        };
        let section_end: u64 = section.address().saturating_add(section.size());
        if accessor < section.address() || accessor >= section_end {
            continue;
        }
        let relative: usize =
            usize::try_from(accessor - section.address()).expect("fixture relative address");
        let start: usize = usize::try_from(file_offset).expect("fixture file offset") + relative;
        let end: usize = (usize::try_from(file_offset + file_size).expect("fixture file end"))
            .min(start.saturating_add(2048));
        let ret: usize = (start..end)
            .find(|offset: &usize| mutated[*offset] == 0xC3)
            .expect("accessor return instruction");
        mutated[ret] = 0xF4;
        return mutated;
    }
    panic!("accessor address must map to a fixture section");
}

#[test]
fn indexed_accessors_recover_source_plaintext_for_every_compiler_and_variant() {
    let expected: Vec<String> = reference_plaintext();
    assert_eq!(
        expected.len(),
        64,
        "source reference must cover every accessor index"
    );
    for (name, fixture) in [
        ("msvc-v1", MSVC_V1),
        ("msvc-v2", MSVC_V2),
        ("clang-v1", CLANG_V1),
        ("clang-v2", CLANG_V2),
    ] {
        let _recovery: IndexedStringRecovery =
            assert_fixture_matches_reference(name, fixture, &expected);
    }
}

#[test]
fn ciphertext_mutation_cannot_preserve_the_source_plaintext_oracle() {
    let expected: Vec<String> = reference_plaintext();
    let prefix: Vec<u8> = first_ciphertext_prefix();
    assert_eq!(prefix.len(), 12, "source ciphertext prefix");
    let mut mutated: Vec<u8> = MSVC_V1.to_vec();
    let offset: usize = mutated
        .windows(prefix.len())
        .position(|window: &[u8]| window == prefix)
        .expect("fixture contains source ciphertext");
    mutated[offset] ^= 0x80;
    if let Ok(recovery) = recover_indexed_strings(&mutated) {
        let reference: BTreeMap<u32, String> = expected
            .iter()
            .enumerate()
            .map(|(index, literal): (usize, &String)| (index as u32, literal.clone()))
            .collect();
        assert!(
            !recovery.refusals.is_empty() || annotation_map(&recovery) != reference,
            "ciphertext mutation must make the independent plaintext oracle fail or differ"
        );
    }
}

#[test]
fn invalid_accessor_return_is_refused_with_a_named_diagnostic() {
    let original: IndexedStringRecovery =
        recover_indexed_strings(MSVC_V1).expect("original recovery");
    let accessor: u64 = original
        .annotations
        .first()
        .expect("fixture annotation")
        .accessor;
    let mutated: Vec<u8> = mutate_accessor_return(MSVC_V1, accessor);
    let recovery: IndexedStringRecovery =
        recover_indexed_strings(&mutated).expect("mutated recovery");
    assert!(
        recovery.refusals.iter().any(|refusal| {
            refusal.accessor == accessor && refusal.reason.starts_with("DR-NATIVE-")
        }),
        "invalid accessor output must become a named per-site refusal, got {:?}",
        recovery.refusals
    );
}

#[test]
fn malformed_inputs_are_refused_without_recovery() {
    for malformed in [b"MZ".as_slice(), &MSVC_V1[..1024]] {
        if let Ok(recovery) = recover_indexed_strings(malformed) {
            assert!(
                recovery.annotations.is_empty(),
                "malformed input must not produce literal annotations: {recovery:?}"
            );
        }
    }
}
