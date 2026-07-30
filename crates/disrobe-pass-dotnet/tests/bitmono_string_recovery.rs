#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_pass_dotnet::metadata::{
    MetadataRoot, StreamHeader, metadata_slice, parse_metadata_root, read_us_heap_strings,
};
use disrobe_pass_dotnet::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use disrobe_pass_dotnet::peel::bitmono_strings::{
    BitMonoRecoveredString, BitMonoStringRecovery, recover_bitmono_strings,
};
use disrobe_pass_dotnet::peel::{PeelReport, PeelStrategy, peel_by};
use disrobe_pass_dotnet::protectors::Protector;
use disrobe_pass_dotnet::tables::{FieldRvaRow, Tables, parse_tables};

const BITMONO_REL: &str =
    "../../corpus/dotnet/obfuscators/bitmono/gauntlet/GauntletBitMono.bitmono.dll";
const CLEAN_REL: &str =
    "../../corpus/dotnet/obfuscators/bitmono/gauntlet/GauntletBitMono.clean.dll";
const CLEAN_SOURCE: &str =
    include_str!("../../../corpus/dotnet/obfuscators/bitmono/gauntlet/clean_original.cs");

const PICK_ARM_ORDER: [&str; 4] = ["zero", "one", "two", "many"];

fn load(rel: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    std::fs::read(&path)
        .unwrap_or_else(|e: std::io::Error| panic!("fixture missing at {}: {e}", path.display()))
}

fn user_strings(image: &[u8]) -> BTreeSet<String> {
    let pe: PeImage = parse(image).expect("PE parse");
    let clr: ClrHeader = parse_clr_header(image, &pe).expect("CLR header");
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr).expect("metadata root");
    let metadata: &[u8] = metadata_slice(image, &pe, &clr, &root).expect("metadata slice");
    let Some(header): Option<&StreamHeader> = root.streams.get("#US") else {
        return BTreeSet::new();
    };
    read_us_heap_strings(metadata, *header)
        .into_iter()
        .collect()
}

fn tables_of(image: &[u8]) -> (PeImage, Tables) {
    let pe: PeImage = parse(image).expect("PE parse");
    let clr: ClrHeader = parse_clr_header(image, &pe).expect("CLR header");
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr).expect("metadata root");
    let metadata: &[u8] = metadata_slice(image, &pe, &clr, &root).expect("metadata slice");
    let header: StreamHeader = *root
        .streams
        .get("#~")
        .or_else(|| root.streams.get("#-"))
        .expect("table stream present");
    let tables: Tables = parse_tables(metadata, header).expect("tables");
    (pe, tables)
}

fn recovery_of(image: &[u8]) -> BitMonoStringRecovery {
    recover_bitmono_strings(image).expect("BitMono string recovery must run on the real sample")
}

fn recovered_texts(recovery: &BitMonoStringRecovery) -> Vec<String> {
    recovery
        .recovered
        .iter()
        .map(|value: &BitMonoRecoveredString| value.text.clone())
        .collect()
}

fn appears_as_standalone_literal(image: &[u8], needle: &[u8]) -> bool {
    let mut wide: Vec<u8> = Vec::with_capacity(needle.len() * 2);
    for byte in needle {
        wide.push(*byte);
        wide.push(0);
    }
    if image.windows(wide.len()).any(|w: &[u8]| w == wide) {
        return true;
    }
    image
        .windows(needle.len())
        .enumerate()
        .filter(|(_, window): &(usize, &[u8])| *window == needle)
        .any(|(at, _): (usize, &[u8])| {
            let before: bool = at
                .checked_sub(1)
                .and_then(|i: usize| image.get(i))
                .is_some_and(|b: &u8| b.is_ascii_alphanumeric());
            let after: bool = image
                .get(at + needle.len())
                .is_some_and(|b: &u8| b.is_ascii_alphanumeric());
            !before && !after
        })
}

#[test]
fn clean_original_carries_the_literals_this_test_grades_against() {
    let clean: Vec<u8> = load(CLEAN_REL);
    let literals: BTreeSet<String> = user_strings(&clean);
    for expected in PICK_ARM_ORDER {
        assert!(
            literals.contains(expected),
            "oracle sanity: the clean pre-obfuscation assembly must carry {expected:?} as a #US \
             literal; found {literals:?}"
        );
        assert!(
            CLEAN_SOURCE.contains(&format!("\"{expected}\"")),
            "oracle sanity: {expected:?} must be a source literal in clean_original.cs, which is \
             the pre-obfuscation ground truth this recovery is graded against"
        );
    }
    assert!(
        literals.contains(","),
        "oracle sanity: the clean assembly must carry the concat separator literal"
    );
}

#[test]
fn bitmono_removed_every_literal_from_the_string_heap() {
    let bitmono: Vec<u8> = load(BITMONO_REL);
    let pe: PeImage = parse(&bitmono).expect("PE parse");
    let clr: ClrHeader = parse_clr_header(&bitmono, &pe).expect("CLR header");
    let root: MetadataRoot = parse_metadata_root(&bitmono, &pe, &clr).expect("metadata root");
    assert!(
        !root.streams.contains_key("#US"),
        "BitMono StringsEncryption must leave the assembly with no user-string heap at all; \
         streams present: {:?}",
        root.streams.keys().collect::<Vec<&String>>()
    );
    for expected in PICK_ARM_ORDER {
        assert!(
            !appears_as_standalone_literal(&bitmono, expected.as_bytes()),
            "{expected:?} must not survive in the protected image as a UTF-16 literal or as a \
             standalone ASCII token; if it did, a substring scan could pass this suite without \
             decrypting anything. The only ASCII hits allowed are inside longer identifiers such \
             as TryRemoveComponent and the manifest's standalone attribute, which are not the \
             literal"
        );
    }
}

#[test]
fn recovered_plaintext_matches_the_clean_assembly_literal_set() {
    let bitmono: Vec<u8> = load(BITMONO_REL);
    let clean: Vec<u8> = load(CLEAN_REL);
    let recovery: BitMonoStringRecovery = recovery_of(&bitmono);
    let recovered: BTreeSet<String> = recovered_texts(&recovery).into_iter().collect();
    let expected: BTreeSet<String> = user_strings(&clean);
    assert_eq!(
        recovered, expected,
        "every literal BitMono encrypted must come back byte-for-byte equal to the clean \
         pre-obfuscation assembly's #US heap"
    );
}

#[test]
fn every_call_site_resolves_with_no_residual() {
    let bitmono: Vec<u8> = load(BITMONO_REL);
    let recovery: BitMonoStringRecovery = recovery_of(&bitmono);
    assert_eq!(
        recovery.call_sites_total, 6,
        "clean_original.cs has six string literal sites: four switch arms in Pick and two concat \
         separators in Main"
    );
    assert_eq!(
        recovery.call_sites_unresolved, 0,
        "no decrypt call site may be left unresolved; unresolved sites were {:?}",
        recovery.call_sites_unresolved
    );
    assert_eq!(recovery.recovered.len(), 6);
}

#[test]
fn switch_arms_recover_in_source_order() {
    let bitmono: Vec<u8> = load(BITMONO_REL);
    let recovery: BitMonoStringRecovery = recovery_of(&bitmono);
    let mut arms: Vec<&BitMonoRecoveredString> = recovery
        .recovered
        .iter()
        .filter(|value: &&BitMonoRecoveredString| value.text != ",")
        .collect();
    arms.sort_by_key(|value: &&BitMonoRecoveredString| (value.caller_token, value.call_offset));
    let texts: Vec<&str> = arms
        .iter()
        .map(|value: &&BitMonoRecoveredString| value.text.as_str())
        .collect();
    assert_eq!(
        texts,
        PICK_ARM_ORDER.to_vec(),
        "the four Pick arms must decrypt back in the order the switch emits them, which is the \
         order the literals appear in clean_original.cs; a set-equal but mis-paired recovery \
         would fail here"
    );
    assert_eq!(
        arms.iter()
            .map(|value: &&BitMonoRecoveredString| value.caller_token)
            .collect::<BTreeSet<u32>>()
            .len(),
        1,
        "all four arms belong to one recovered method"
    );
}

#[test]
fn decryptor_parameters_are_read_from_the_assembly_not_assumed() {
    let bitmono: Vec<u8> = load(BITMONO_REL);
    let recovery: BitMonoStringRecovery = recovery_of(&bitmono);
    assert_eq!(
        recovery.shape.key_size_bits, 256,
        "the AES key size must come from the set_KeySize immediate in the decryptor body"
    );
    assert_eq!(recovery.shape.block_size_bits, 128);
    assert_eq!(
        recovery.shape.iterations, 1000,
        "the PBKDF2 iteration count must come from the Rfc2898DeriveBytes constructor immediate"
    );
    assert_eq!(
        (
            recovery.shape.data_arg,
            recovery.shape.salt_arg,
            recovery.shape.password_arg
        ),
        (0, 1, 2),
        "the argument roles must be derived from the ldarg order feeding Rfc2898DeriveBytes"
    );
}

#[test]
fn recovery_reads_every_carrier_and_not_a_baked_in_table() {
    let bitmono: Vec<u8> = load(BITMONO_REL);
    let baseline: Vec<String> = recovered_texts(&recovery_of(&bitmono));
    let (pe, tables): (PeImage, Tables) = tables_of(&bitmono);
    let mut checked: usize = 0;
    for row in &tables.field_rvas {
        let row: FieldRvaRow = *row;
        let Some(offset): Option<usize> = pe.rva_to_offset(row.rva) else {
            continue;
        };
        let mut mutated: Vec<u8> = bitmono.clone();
        mutated[offset] ^= 0xFF;
        let after: Vec<String> = recover_bitmono_strings(&mutated)
            .map(|recovery: BitMonoStringRecovery| recovered_texts(&recovery))
            .unwrap_or_default();
        assert_ne!(
            after, baseline,
            "flipping one byte of the FieldRVA carrier at rva {:#x} must change what the recovery \
             reports; an unchanged result would mean the plaintext comes from a table baked into \
             disrobe instead of from the assembly",
            row.rva
        );
        checked += 1;
    }
    assert!(
        checked >= 6,
        "the sample carries one FieldRVA blob per encrypted literal plus the key material; only \
         {checked} were reachable"
    );
}

#[test]
fn clean_baseline_yields_no_recovery() {
    let clean: Vec<u8> = load(CLEAN_REL);
    assert!(
        recover_bitmono_strings(&clean).is_none(),
        "the unobfuscated baseline has no BitMono string decryptor, so the recovery must decline \
         rather than invent literals"
    );
}

#[test]
fn peel_surfaces_the_recovered_literals() {
    let bitmono: Vec<u8> = load(BITMONO_REL);
    let report: PeelReport = peel_by(Protector::BitMono, &bitmono)
        .expect("BitMono has a peel route")
        .expect("peel must succeed on the real managed PE");
    assert_eq!(report.protector, Protector::BitMono);
    assert_eq!(
        report.strategy,
        PeelStrategy::StaticStringRecovery,
        "recovering the literals must promote the peel strategy off report-only"
    );
    let texts: BTreeSet<String> = report
        .recovered_strings
        .iter()
        .map(|value: &disrobe_pass_dotnet::peel::string_emu::RecoveredString| value.text.clone())
        .collect();
    assert_eq!(texts, user_strings(&load(CLEAN_REL)));
    assert!(
        report
            .notes
            .iter()
            .any(|note: &String| note.contains("6/6")),
        "the peel report must state the recovered/total call-site count: {:?}",
        report.notes
    );
}
