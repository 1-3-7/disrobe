#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::missing_panics_doc
)]

#[path = "support/xlm_reference.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod xlm_reference;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use disrobe_core::scratch::ScratchDir;
use serde::Deserialize;

use disrobe_pass_shell::xlm::ftab::{cetab_name, ftab_name};
use xlm_reference::{
    FunctionTables, TABLE_REFERENCE, TABLE_REFERENCE_VERSION, TABLE_SYMBOL, golden_dir, parse_id,
    read_function_tables, require_interpreter,
};

#[derive(Debug, Deserialize)]
struct Snapshot {
    reference: String,
    version: String,
    symbol: String,
    ftab: BTreeMap<String, String>,
    cetab: BTreeMap<String, String>,
}

const DELIBERATE_FTAB_DIVERGENCES: [(u16, &str, &str); 1] =
    [(0x00FF, "USERFUNCTION", "UserDefinedFunction")];

fn snapshot() -> Snapshot {
    let path: PathBuf = golden_dir().join("pyxlsb2_function_names.json");
    let text: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("missing function-name snapshot {}: {err}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|err| panic!("malformed function-name snapshot {}: {err}", path.display()))
}

fn live_tables() -> FunctionTables {
    let python: PathBuf = require_interpreter();
    let guard: ScratchDir =
        ScratchDir::create("xlm-function-tables").expect("create scratch directory");
    let path: &Path = guard.path();
    read_function_tables(&python, path)
}

fn divergence(id: u16) -> Option<(&'static str, &'static str)> {
    DELIBERATE_FTAB_DIVERGENCES
        .iter()
        .find(|(known, _ours, _theirs): &&(u16, &str, &str)| *known == id)
        .map(|(_known, ours, theirs): &(u16, &'static str, &'static str)| (*ours, *theirs))
}

fn compare(
    kind: &str,
    theirs: &BTreeMap<String, String>,
    ours: &dyn Fn(u16) -> Option<&'static str>,
    exempt: bool,
    faults: &mut Vec<String>,
) -> usize {
    let mut shared: usize = 0;
    for (raw, reference_name) in theirs {
        let id: u16 = parse_id(raw);
        let Some(our_name): Option<&'static str> = ours(id) else {
            faults.push(format!("{kind} {raw}: {TABLE_REFERENCE} names it {reference_name} and the recovery names nothing"));
            continue;
        };
        shared += 1;
        match exempt.then(|| divergence(id)).flatten() {
            Some((expected_ours, expected_theirs)) => {
                if our_name != expected_ours || reference_name != expected_theirs {
                    faults.push(format!(
                        "{kind} {raw}: recorded divergence is {expected_ours} against \
                         {expected_theirs}, now {our_name} against {reference_name}"
                    ));
                }
            }
            None if our_name != reference_name => {
                faults.push(format!(
                    "{kind} {raw}: ours {our_name}, {TABLE_REFERENCE} {reference_name}"
                ));
            }
            None => {}
        }
    }
    shared
}

#[test]
fn function_tables_agree_with_the_reference_read_at_test_time() {
    let tables: FunctionTables = live_tables();
    let mut faults: Vec<String> = Vec::new();
    let shared_ftab: usize = compare("ftab", &tables.ftab, &ftab_name, true, &mut faults);
    let shared_cetab: usize = compare("cetab", &tables.cetab, &cetab_name, false, &mut faults);
    assert!(
        faults.is_empty(),
        "{} function-name disagreement(s) with {TABLE_REFERENCE} {}:\n{}",
        faults.len(),
        tables.pyxlsb2,
        faults.join("\n")
    );
    assert_eq!(shared_ftab, 476, "shared ftab coverage shrank");
    assert_eq!(shared_cetab, 396, "shared cetab coverage shrank");
    for (id, _ours, _theirs) in DELIBERATE_FTAB_DIVERGENCES {
        assert!(
            tables.ftab.contains_key(&format!("0x{id:04X}")),
            "recorded divergence 0x{id:04X} left the reference table"
        );
    }
    println!(
        "\nGRADED: {shared_ftab} ftab and {shared_cetab} cetab names against {TABLE_REFERENCE} {} \
         read from {TABLE_SYMBOL} at test time\n",
        tables.pyxlsb2
    );
}

#[test]
fn the_committed_snapshot_still_records_what_the_reference_carries() {
    let tables: FunctionTables = live_tables();
    let snapshot: Snapshot = snapshot();
    assert_eq!(snapshot.reference, TABLE_REFERENCE);
    assert_eq!(snapshot.version, TABLE_REFERENCE_VERSION);
    assert_eq!(snapshot.symbol, TABLE_SYMBOL);
    assert_eq!(
        snapshot.ftab, tables.ftab,
        "the committed ftab snapshot no longer matches {TABLE_REFERENCE} {}, so regenerate it \
         rather than widening the comparison",
        tables.pyxlsb2
    );
    assert_eq!(
        snapshot.cetab, tables.cetab,
        "the committed cetab snapshot no longer matches {TABLE_REFERENCE} {}, so regenerate it \
         rather than widening the comparison",
        tables.pyxlsb2
    );
}

#[test]
fn function_tables_define_every_reference_id() {
    let tables: FunctionTables = live_tables();
    let missing_ftab: Vec<&String> = tables
        .ftab
        .keys()
        .filter(|raw: &&String| ftab_name(parse_id(raw)).is_none())
        .collect();
    let missing_cetab: Vec<&String> = tables
        .cetab
        .keys()
        .filter(|raw: &&String| cetab_name(parse_id(raw)).is_none())
        .collect();
    assert!(
        missing_ftab.is_empty(),
        "{TABLE_REFERENCE} names ftab ids we do not: {missing_ftab:?}"
    );
    assert!(
        missing_cetab.is_empty(),
        "{TABLE_REFERENCE} names cetab ids we do not: {missing_cetab:?}"
    );
}
