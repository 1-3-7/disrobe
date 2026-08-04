#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use disrobe_pass_dotnet::metadata::{
    MetadataRoot, parse_metadata_root, read_strings_heap, read_us_heap_strings,
};
use disrobe_pass_dotnet::pass::{PassSummary, analyze};
use disrobe_pass_dotnet::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use disrobe_pass_dotnet::peel::obfuscar::{
    ObfuscarEvidence, classify_obfuscar_naming, detect_obfuscar, peel_obfuscar,
};
use disrobe_pass_dotnet::peel::{NameClassification, PeelReport, PeelStrategy, classify_names};
use disrobe_pass_dotnet::protectors::Protector;
use disrobe_pass_dotnet::tables::{FieldRvaRow, Tables, parse_tables};

const CLEAN_REL: &str =
    "../../corpus/dotnet/obfuscators/obfuscar/gauntlet/GauntletSample.clean.dll";
const OBFUSCATED_REL: &str =
    "../../corpus/dotnet/obfuscators/obfuscar/gauntlet/GauntletSample.obfuscar.dll";
const PUBLISHED_HIDDEN_STRINGS_BAR: &str = "Obfuscar hidden strings";

const ORIGINAL_IDENTIFIERS: &[&str] = &[
    "InventoryLedger",
    "StockSnapshot",
    "PriceCalculator",
    "SkuValidator",
    "AuditTrail",
    "WarehouseRouter",
    "ReorderPolicy",
    "GauntletEntry",
    "ComputeWeightedTotal",
    "ComputeSkuWeight",
    "BuildReport",
    "ApplyTax",
    "BulkDiscount",
    "IsWellFormed",
    "RouteFor",
    "RecommendedQuantity",
    "DisrobeObfuscarGauntlet",
];

const HIDDEN_STRING_LITERALS: &[&[u8]] = &[
    b"north", b"south", b"central", b"ledger=", b"audits=", b"record",
];

const HIDDEN_ACCESSORS: &str = include_str!("fixtures/obfuscar_accessor_map/expected.tsv");

const INLINED_CONST_BANNER: &[u8] = b"DISROBE_OBFUSCAR_LICENSE_BANNER_2026";

fn load(rel: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    std::fs::read(&path)
        .unwrap_or_else(|e: std::io::Error| panic!("fixture missing at {}: {e}", path.display()))
}

fn published_ratio(label: &str) -> (f64, u64, u64) {
    let path: PathBuf = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("xtask")
        .join("data")
        .join("recovery.json");
    let raw: String = std::fs::read_to_string(&path).expect("xtask/data/recovery.json is readable");
    let doc: serde_json::Value =
        serde_json::from_str(&raw).expect("xtask/data/recovery.json parses as JSON");
    let mut found: Vec<serde_json::Value> = Vec::new();
    for group in doc["groups"].as_array().expect("groups array") {
        for bar in group["bars"].as_array().unwrap_or(&Vec::new()) {
            if bar["label"].as_str() == Some(label) {
                found.push(bar.clone());
            }
        }
    }
    assert_eq!(
        found.len(),
        1,
        "xtask/data/recovery.json must carry exactly one bar labelled `{label}`, found {}",
        found.len()
    );
    let bar: serde_json::Value = found.remove(0);
    let value: f64 = bar["value"]
        .as_f64()
        .expect("the published ratio bar must carry a percentage value");
    let num: u64 = bar["num"]
        .as_u64()
        .expect("the published ratio bar must carry a numerator");
    let den: u64 = bar["den"]
        .as_u64()
        .expect("the published ratio bar must carry a denominator");
    (value, num, den)
}

fn strings_heap(image: &[u8]) -> BTreeMap<u32, String> {
    let pe: PeImage = parse(image).expect("PE parse");
    let clr: ClrHeader = parse_clr_header(image, &pe).expect("CLR header");
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr).expect("metadata root");
    let md: &[u8] = pe
        .slice_at_rva(image, clr.metadata.rva, clr.metadata.size as usize)
        .expect("metadata slice");
    let header: &disrobe_pass_dotnet::metadata::StreamHeader =
        root.streams.get("#Strings").expect("#Strings heap present");
    read_strings_heap(md, *header)
}

fn user_strings(image: &[u8]) -> BTreeSet<String> {
    let pe: PeImage = parse(image).expect("PE parse");
    let clr: ClrHeader = parse_clr_header(image, &pe).expect("CLR header");
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr).expect("metadata root");
    let md: &[u8] = pe
        .slice_at_rva(image, clr.metadata.rva, clr.metadata.size as usize)
        .expect("metadata slice");
    let Some(header): Option<&disrobe_pass_dotnet::metadata::StreamHeader> =
        root.streams.get("#US")
    else {
        return BTreeSet::new();
    };
    read_us_heap_strings(md, *header).into_iter().collect()
}

fn hidden_accessors() -> BTreeMap<u32, Vec<u8>> {
    HIDDEN_ACCESSORS
        .lines()
        .map(|line: &str| {
            let (token, bytes): (&str, &str) = line.split_once('\t').expect("token and bytes");
            let token: u32 =
                u32::from_str_radix(token.strip_prefix("0x").expect("token prefix"), 16)
                    .expect("token hex");
            assert!(bytes.len().is_multiple_of(2));
            let bytes: Vec<u8> = bytes
                .as_bytes()
                .chunks_exact(2)
                .map(|pair: &[u8]| {
                    u8::from_str_radix(std::str::from_utf8(pair).expect("UTF-8 hex"), 16)
                        .expect("byte hex")
                })
                .collect();
            (token, bytes)
        })
        .collect()
}

fn appears_utf8_or_utf16(image: &[u8], needle: &[u8]) -> bool {
    if image.windows(needle.len()).any(|w: &[u8]| w == needle) {
        return true;
    }
    let mut wide: Vec<u8> = Vec::with_capacity(needle.len() * 2);
    for b in needle {
        wide.push(*b);
        wide.push(0);
    }
    image.windows(wide.len()).any(|w: &[u8]| w == wide)
}

#[test]
fn clean_original_carries_the_source_identifiers() {
    let clean: Vec<u8> = load(CLEAN_REL);
    let heap: BTreeMap<u32, String> = strings_heap(&clean);
    let present: usize = ORIGINAL_IDENTIFIERS
        .iter()
        .filter(|name: &&&str| heap.values().any(|v: &String| v == **name))
        .count();
    assert_eq!(
        present,
        ORIGINAL_IDENTIFIERS.len(),
        "oracle sanity: every source identifier must live in the clean (pre-obfuscation) \
         #Strings heap; found {present}/{}",
        ORIGINAL_IDENTIFIERS.len()
    );
}

#[test]
fn obfuscar_renamed_every_source_identifier_away() {
    let obf: Vec<u8> = load(OBFUSCATED_REL);
    let heap: BTreeMap<u32, String> = strings_heap(&obf);
    let surviving: Vec<&str> = ORIGINAL_IDENTIFIERS
        .iter()
        .copied()
        .filter(|name: &&str| heap.values().any(|v: &String| v == *name))
        .collect();
    assert!(
        surviving.is_empty(),
        "real Obfuscar 2.2.50 rename must erase all {} source identifiers from the #Strings heap; \
         these survived: {surviving:?}",
        ORIGINAL_IDENTIFIERS.len()
    );
}

#[test]
fn obfuscated_identifiers_are_base52_odometer_names() {
    let obf: Vec<u8> = load(OBFUSCATED_REL);
    let heap: BTreeMap<u32, String> = strings_heap(&obf);
    let evidence: ObfuscarEvidence = classify_obfuscar_naming(&heap);
    assert!(
        evidence.is_obfuscar,
        "Obfuscar NameMaker emits a base-52 odometer block (A, a, B, b, C, ...); the obfuscated \
         heap must classify as Obfuscar: {evidence:?}"
    );
    assert!(
        evidence.odometer_members >= 8,
        "the rename of 8 types plus their members must leave at least 8 distinct odometer slots; \
         got {}",
        evidence.odometer_members
    );
}

#[test]
fn disrobe_detects_obfuscar_on_obfuscated_not_on_clean() {
    let obf: Vec<u8> = load(OBFUSCATED_REL);
    let clean: Vec<u8> = load(CLEAN_REL);
    assert!(
        detect_obfuscar(&obf),
        "disrobe must fingerprint Obfuscar from the odometer naming in the obfuscated assembly"
    );
    assert!(
        !detect_obfuscar(&clean),
        "the clean pre-obfuscation assembly must NOT be misread as Obfuscar (no false positive)"
    );
    let summary: PassSummary = analyze(&obf).expect("analyze obfuscated managed PE");
    assert!(
        summary.protectors_detected.contains(&Protector::Obfuscar),
        "the dotnet pass must report Obfuscar among detected protectors; got {:?}",
        summary.protectors_detected
    );
    assert_eq!(
        summary.primary_protector,
        Some(Protector::Obfuscar),
        "Obfuscar must be the primary protector for an Obfuscar-only sample; got {:?}",
        summary.primary_protector
    );
    let clean_summary: PassSummary = analyze(&clean).expect("analyze clean managed PE");
    assert!(
        !clean_summary
            .protectors_detected
            .contains(&Protector::Obfuscar),
        "the clean assembly must report no protector; got {:?}",
        clean_summary.protectors_detected
    );
}

#[test]
fn rename_raises_obfuscated_identifier_count_over_clean() {
    let obf: Vec<u8> = load(OBFUSCATED_REL);
    let clean: Vec<u8> = load(CLEAN_REL);
    let obf_class: NameClassification = classify_names(&strings_heap(&obf));
    let clean_class: NameClassification = classify_names(&strings_heap(&clean));
    assert!(
        obf_class.renamable > clean_class.renamable,
        "Obfuscar rename must increase the obfuscated-identifier count vs the clean original; \
         clean renamable={} obf renamable={}",
        clean_class.renamable,
        obf_class.renamable
    );
    assert!(
        obf_class.human < clean_class.human,
        "renaming source members to odometer slots must shrink the human-readable identifier \
         count; clean human={} obf human={}",
        clean_class.human,
        obf_class.human
    );
}

#[test]
fn peel_reports_obfuscar_and_states_the_honest_residual() {
    let obf: Vec<u8> = load(OBFUSCATED_REL);
    let report: PeelReport = peel_obfuscar(&obf).expect("peel must succeed on real managed PE");
    assert_eq!(report.protector, Protector::Obfuscar);
    assert!(
        report.renamable_identifiers >= 6,
        "peel must classify the renamed odometer slots; got {}",
        report.renamable_identifiers
    );
    let note: &String = report
        .notes
        .first()
        .expect("peel must emit a residual note");
    assert!(
        note.contains("not") && note.contains("statically recoverable"),
        "the honest residual must be stated: Obfuscar embeds no in-PE name map, so original \
         identifiers are not statically recoverable; got note: {note:?}"
    );
}

#[test]
fn string_hiding_moved_literals_out_of_plaintext() {
    let clean: Vec<u8> = load(CLEAN_REL);
    let obf: Vec<u8> = load(OBFUSCATED_REL);
    let mut clean_visible: usize = 0;
    let mut obf_visible: usize = 0;
    for literal in HIDDEN_STRING_LITERALS {
        if appears_utf8_or_utf16(&clean, literal) {
            clean_visible += 1;
        }
        if appears_utf8_or_utf16(&obf, literal) {
            obf_visible += 1;
        }
    }
    assert_eq!(
        clean_visible,
        HIDDEN_STRING_LITERALS.len(),
        "oracle sanity: every literal must be plaintext in the clean assembly; got {clean_visible}/{}",
        HIDDEN_STRING_LITERALS.len()
    );
    assert_eq!(
        obf_visible,
        0,
        "Obfuscar HideStrings must move these {} ldstr literals out of plaintext; {obf_visible} \
         still appear verbatim in the obfuscated assembly",
        HIDDEN_STRING_LITERALS.len()
    );
}

fn obfuscar_hidden_string_grade() -> (u64, u64) {
    let clean: Vec<u8> = load(CLEAN_REL);
    let obf: Vec<u8> = load(OBFUSCATED_REL);
    let clean_literals: BTreeSet<String> = user_strings(&clean);
    let obfuscated_literals: BTreeSet<String> = user_strings(&obf);
    let expected_literals: BTreeSet<Vec<u8>> = clean_literals
        .difference(&obfuscated_literals)
        .map(|value: &String| value.as_bytes().to_vec())
        .collect();
    assert_eq!(
        expected_literals.len(),
        15,
        "ground-truth clean assembly must expose 15 unique ldstr values removed by Obfuscar"
    );
    let expected_accessors: BTreeMap<u32, Vec<u8>> = hidden_accessors();
    let mapped_literals: BTreeSet<Vec<u8>> = expected_accessors.values().cloned().collect();
    assert_eq!(mapped_literals, expected_literals);

    let report: PeelReport = peel_obfuscar(&obf).expect("peel real Obfuscar assembly");
    let recovered: BTreeMap<u32, Vec<u8>> = report
        .recovered_strings
        .iter()
        .map(|value| (value.method_token, value.text.as_bytes().to_vec()))
        .collect();
    assert_eq!(
        recovered, expected_accessors,
        "the protected FieldRVA carrier must recover the runtime-verified accessor-token map byte-for-byte"
    );
    let recovered_literals: BTreeSet<Vec<u8>> = recovered.values().cloned().collect();
    assert_eq!(recovered_literals, expected_literals);
    let recovered_count: u64 =
        u64::try_from(recovered_literals.len()).expect("recovered string count fits u64");
    let expected_count: u64 =
        u64::try_from(expected_literals.len()).expect("expected string count fits u64");
    assert_eq!(report.strategy, PeelStrategy::StaticStringRecovery);
    assert!(
        report
            .notes
            .iter()
            .any(|note: &String| note.contains("15/15")),
        "the peel report must expose the complete recovered/accessor count: {:?}",
        report.notes
    );
    (recovered_count, expected_count)
}

#[test]
fn peel_recovers_every_hidden_string_from_real_obfuscar_field_rva_carrier() {
    let _: (u64, u64) = obfuscar_hidden_string_grade();
}

#[test]
fn published_obfuscar_hidden_strings_bar_matches_real_grader() {
    let measured: (u64, u64) = obfuscar_hidden_string_grade();
    let (published_value, published_num, published_den): (f64, u64, u64) =
        published_ratio(PUBLISHED_HIDDEN_STRINGS_BAR);
    assert_eq!(
        (published_num, published_den),
        measured,
        "the `Obfuscar hidden strings` recovery bar must publish the recovered and expected counts derived from the real gauntlet fixture"
    );
    assert_ne!(measured.1, 0, "the measured denominator must be nonzero");
    let measured_num: f64 =
        f64::from(u32::try_from(measured.0).expect("measured numerator fits u32"));
    let measured_den: f64 =
        f64::from(u32::try_from(measured.1).expect("measured denominator fits u32"));
    let measured_value: f64 = measured_num * 100.0 / measured_den;
    assert_eq!(
        published_value.to_bits(),
        measured_value.to_bits(),
        "the `Obfuscar hidden strings` recovery bar percentage must equal its real measured ratio"
    );
}

fn flip_first_field_rva_byte(image: &mut [u8]) -> u32 {
    let pe: PeImage = parse(image).expect("PE parse");
    let clr: ClrHeader = parse_clr_header(image, &pe).expect("CLR header");
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr).expect("metadata root");
    let md: &[u8] = pe
        .slice_at_rva(image, clr.metadata.rva, clr.metadata.size as usize)
        .expect("metadata slice");
    let header: disrobe_pass_dotnet::metadata::StreamHeader = *root
        .streams
        .get("#~")
        .or_else(|| root.streams.get("#-"))
        .expect("table stream present");
    let tables: Tables = parse_tables(md, header).expect("tables");
    let row: &FieldRvaRow = tables
        .field_rvas
        .first()
        .expect("Obfuscar HideStrings must place the hidden literals in a FieldRVA carrier");
    let offset: usize = pe
        .rva_to_offset(row.rva)
        .expect("FieldRVA data must map into the file");
    image[offset] ^= 0xFF;
    row.rva
}

#[test]
fn recovery_reads_the_carrier_and_not_a_baked_in_table() {
    let mut mutated: Vec<u8> = load(OBFUSCATED_REL);
    let rva: u32 = flip_first_field_rva_byte(&mut mutated);
    let expected_accessors: BTreeMap<u32, Vec<u8>> = hidden_accessors();
    let recovered: BTreeMap<u32, Vec<u8>> = peel_obfuscar(&mutated)
        .expect("peel mutated Obfuscar assembly")
        .recovered_strings
        .iter()
        .map(|value| (value.method_token, value.text.as_bytes().to_vec()))
        .collect();
    assert_ne!(
        recovered, expected_accessors,
        "flipping one byte of the FieldRVA carrier at rva {rva:#x} must change what the peeler \
         reports; an unchanged 15/15 map would mean the recovery is reading a baked-in table \
         instead of the assembly"
    );
}

#[test]
fn inlined_const_string_is_an_honest_residual() {
    let clean: Vec<u8> = load(CLEAN_REL);
    let obf: Vec<u8> = load(OBFUSCATED_REL);
    assert!(
        appears_utf8_or_utf16(&clean, INLINED_CONST_BANNER),
        "oracle sanity: the const banner must be plaintext in the clean assembly"
    );
    assert!(
        appears_utf8_or_utf16(&obf, INLINED_CONST_BANNER),
        "honest residual: a `public const string` is a compile-time constant baked into metadata, \
         so Obfuscar HideStrings cannot remove it; the banner is expected to survive in the \
         obfuscated assembly. If a future Obfuscar version hides it, this assertion documents the \
         behavior change."
    );
}

#[test]
fn obfuscated_assembly_still_parses_as_managed_pe() {
    use disrobe_pass_dotnet::metadata::METADATA_SIGNATURE;

    let obf: Vec<u8> = load(OBFUSCATED_REL);
    let pe: PeImage = parse(&obf).expect("PE parse must survive Obfuscar");
    let clr: ClrHeader = parse_clr_header(&obf, &pe).expect("CLR header survives Obfuscar");
    let root: MetadataRoot =
        parse_metadata_root(&obf, &pe, &clr).expect("metadata root survives Obfuscar");
    assert_eq!(
        root.signature, METADATA_SIGNATURE,
        "BSJB signature must be intact after Obfuscar"
    );
    assert!(
        !root.streams.is_empty(),
        "metadata streams must be present in the obfuscated PE"
    );
}
