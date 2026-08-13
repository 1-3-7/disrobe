#![allow(clippy::expect_used, clippy::panic, clippy::print_stdout)]

use std::collections::{BTreeMap, BTreeSet};

use disrobe_ir::payload::{DisasmPayload, DisasmSymbol, DisasmSymbolKind};
use disrobe_pass_native::build_disasm_payload;
use object::{Object as _, ObjectSection as _, ObjectSymbol as _, SymbolKind as ObjSymbolKind};

const STATIC_STRIPPED: &[u8] =
    include_bytes!("../../../corpus/native/discovery/disc_aarch64.stripped.elf");

const STATIC_REFERENCE: &[u8] =
    include_bytes!("../../../corpus/native/discovery/disc_aarch64.unstripped.elf");

const SHARED_STRIPPED: &[u8] =
    include_bytes!("../../../corpus/native/discovery/disc_aarch64_shared.stripped.elf");

const SHARED_REFERENCE: &[u8] =
    include_bytes!("../../../corpus/native/discovery/disc_aarch64_shared.unstripped.elf");

const PLAIN_STRIPPED: &[u8] =
    include_bytes!("../../../corpus/native/discovery/disc_aarch64_nounwind.stripped.elf");

const PLAIN_REFERENCE: &[u8] =
    include_bytes!("../../../corpus/native/discovery/disc_aarch64_nounwind.unstripped.elf");

const UNWOUND_RECALL_FLOOR_PERMILLE: u64 = 1000;

const PLAIN_RECALL_FLOOR_PERMILLE: u64 = 962;

const PRECISION_FLOOR_PERMILLE: u64 = 1000;

const STATIC_REFERENCE_STARTS: usize = 27;

const SHARED_REFERENCE_STARTS: usize = 25;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Tally {
    truth: usize,
    recovered: usize,
    hits: usize,
    strays: usize,
}

impl Tally {
    const fn recall_permille(self) -> u64 {
        if self.truth == 0 {
            return 0;
        }
        (self.hits as u64).saturating_mul(1000) / self.truth as u64
    }

    const fn precision_permille(self) -> u64 {
        if self.recovered == 0 {
            return 0;
        }
        ((self.recovered - self.strays) as u64).saturating_mul(1000) / self.recovered as u64
    }
}

fn reference_starts(unstripped: &[u8]) -> BTreeMap<u64, String> {
    let file: object::File<'_> =
        object::File::parse(unstripped).expect("the reference twin must parse");
    let text_sections: BTreeSet<usize> = file
        .sections()
        .filter(|section: &object::Section<'_, '_>| {
            matches!(section.kind(), object::SectionKind::Text)
        })
        .map(|section: object::Section<'_, '_>| section.index().0)
        .collect();
    assert!(
        !text_sections.is_empty(),
        "the reference twin must carry an executable section"
    );
    let mut starts: BTreeMap<u64, String> = BTreeMap::new();
    for symbol in file.symbols() {
        if !matches!(symbol.kind(), ObjSymbolKind::Text) {
            continue;
        }
        let object::SymbolSection::Section(index) = symbol.section() else {
            continue;
        };
        if !text_sections.contains(&index.0) {
            continue;
        }
        let name: String = symbol.name().unwrap_or("<unnamed>").to_owned();
        starts.entry(symbol.address()).or_insert(name);
    }
    starts
}

fn recovered_starts(stripped: &[u8]) -> BTreeSet<u64> {
    let payload: DisasmPayload =
        build_disasm_payload(stripped).expect("the stripped image must disassemble");
    payload
        .symbol_table
        .iter()
        .filter(|symbol: &&DisasmSymbol| {
            matches!(
                symbol.kind,
                DisasmSymbolKind::Function | DisasmSymbolKind::Export
            )
        })
        .map(|symbol: &DisasmSymbol| symbol.address)
        .collect()
}

fn grade(
    label: &str,
    stripped: &[u8],
    unstripped: &[u8],
    expected_starts: usize,
    recall_floor: u64,
) -> Tally {
    let truth: BTreeMap<u64, String> = reference_starts(unstripped);
    assert_eq!(
        truth.len(),
        expected_starts,
        "{label}: the committed reference twin changed shape"
    );
    let recovered: BTreeSet<u64> = recovered_starts(stripped);
    let hits: usize = truth
        .keys()
        .filter(|address: &&u64| recovered.contains(address))
        .count();
    let strays: usize = recovered
        .iter()
        .filter(|address: &&u64| !truth.contains_key(address))
        .count();
    let tally: Tally = Tally {
        truth: truth.len(),
        recovered: recovered.len(),
        hits,
        strays,
    };
    let missed: Vec<&str> = truth
        .iter()
        .filter(|(address, _): &(&u64, &String)| !recovered.contains(address))
        .map(|(_, name): (&u64, &String)| name.as_str())
        .collect();
    println!(
        "{label}: recall {}/{} at {} permille, precision {}/{} at {} permille, missed {missed:?}",
        tally.hits,
        tally.truth,
        tally.recall_permille(),
        tally.recovered - tally.strays,
        tally.recovered,
        tally.precision_permille()
    );
    assert!(
        tally.recall_permille() >= recall_floor,
        "{label}: recall {}/{} is below the floor, missed {missed:?}",
        tally.hits,
        tally.truth
    );
    assert!(
        tally.precision_permille() >= PRECISION_FLOOR_PERMILLE,
        "{label}: {} of {} recovered starts are absent from the reference twin",
        tally.strays,
        tally.recovered
    );
    tally
}

fn recovered_names(stripped: &[u8], unstripped: &[u8]) -> BTreeSet<String> {
    let truth: BTreeMap<u64, String> = reference_starts(unstripped);
    let recovered: BTreeSet<u64> = recovered_starts(stripped);
    truth
        .into_iter()
        .filter(|(address, _): &(u64, String)| recovered.contains(address))
        .map(|(_, name): (u64, String)| name)
        .collect()
}

#[test]
fn a_stripped_static_image_recovers_every_reference_start() {
    let tally: Tally = grade(
        "static",
        STATIC_STRIPPED,
        STATIC_REFERENCE,
        STATIC_REFERENCE_STARTS,
        UNWOUND_RECALL_FLOOR_PERMILLE,
    );
    assert_eq!(tally.strays, 0, "no start outside the reference twin");
}

#[test]
fn a_stripped_shared_object_recovers_every_reference_start() {
    let tally: Tally = grade(
        "shared",
        SHARED_STRIPPED,
        SHARED_REFERENCE,
        SHARED_REFERENCE_STARTS,
        UNWOUND_RECALL_FLOOR_PERMILLE,
    );
    assert_eq!(tally.strays, 0, "no start outside the reference twin");
}

#[test]
fn an_image_without_unwind_tables_recovers_all_but_its_tail_called_start() {
    let tally: Tally = grade(
        "no-unwind",
        PLAIN_STRIPPED,
        PLAIN_REFERENCE,
        STATIC_REFERENCE_STARTS,
        PLAIN_RECALL_FLOOR_PERMILLE,
    );
    assert_eq!(tally.strays, 0, "no start outside the reference twin");
    let names: BTreeSet<String> = recovered_names(PLAIN_STRIPPED, PLAIN_REFERENCE);
    assert!(
        !names.contains("clamp_high"),
        "a tail-called start with no unwind entry is the recorded residual, not a pass"
    );
}

#[test]
fn starts_with_no_incoming_call_are_recovered_from_their_evidence() {
    for (label, stripped, unstripped) in [
        ("static", STATIC_STRIPPED, STATIC_REFERENCE),
        ("shared", SHARED_STRIPPED, SHARED_REFERENCE),
        ("no-unwind", PLAIN_STRIPPED, PLAIN_REFERENCE),
    ] {
        let names: BTreeSet<String> = recovered_names(stripped, unstripped);
        for required in [
            "only_from_data",
            "also_only_from_data",
            "discovery_ctor",
            "discovery_dtor",
        ] {
            assert!(
                names.contains(required),
                "{label}: {required} has no incoming call and must come from its own evidence, recovered {names:?}"
            );
        }
    }
    for (label, stripped, unstripped) in [
        ("static", STATIC_STRIPPED, STATIC_REFERENCE),
        ("shared", SHARED_STRIPPED, SHARED_REFERENCE),
    ] {
        let names: BTreeSet<String> = recovered_names(stripped, unstripped);
        assert!(
            names.contains("clamp_high"),
            "{label}: a tail-called start comes from the unwind table, recovered {names:?}"
        );
    }
}

#[test]
fn discovery_repeats_byte_for_byte() {
    for stripped in [STATIC_STRIPPED, SHARED_STRIPPED, PLAIN_STRIPPED] {
        let first: BTreeSet<u64> = recovered_starts(stripped);
        let second: BTreeSet<u64> = recovered_starts(stripped);
        assert_eq!(first, second, "discovery must repeat exactly");
    }
}
