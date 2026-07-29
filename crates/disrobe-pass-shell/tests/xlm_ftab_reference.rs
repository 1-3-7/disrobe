#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use disrobe_pass_shell::xlm::ftab::{cetab_name, ftab_name};

#[derive(Debug, Deserialize)]
struct Snapshot {
    reference: String,
    symbol: String,
    ftab: BTreeMap<String, String>,
    cetab: BTreeMap<String, String>,
}

const DELIBERATE_FTAB_DIVERGENCES: [(u16, &str, &str); 1] =
    [(0x00FF, "USERFUNCTION", "UserDefinedFunction")];

fn snapshot() -> Snapshot {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join("xlm")
        .join("pyxlsb2_function_names.json");
    let text: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("missing function-name snapshot {}: {err}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|err| panic!("malformed function-name snapshot {}: {err}", path.display()))
}

fn parse_id(raw: &str) -> u16 {
    let digits: &str = raw
        .strip_prefix("0x")
        .unwrap_or_else(|| panic!("snapshot ids must be hexadecimal with an 0x prefix, got {raw}"));
    u16::from_str_radix(digits, 16)
        .unwrap_or_else(|err| panic!("unparsable snapshot id {raw}: {err}"))
}

fn divergence(id: u16) -> Option<(&'static str, &'static str)> {
    DELIBERATE_FTAB_DIVERGENCES
        .iter()
        .find(|(known, _ours, _theirs): &&(u16, &str, &str)| *known == id)
        .map(|(_known, ours, theirs): &(u16, &'static str, &'static str)| (*ours, *theirs))
}

#[test]
fn function_tables_agree_with_the_snapshot_on_every_shared_id() {
    let snapshot: Snapshot = snapshot();
    assert_eq!(snapshot.reference, "pyxlsb2");
    assert_eq!(snapshot.symbol, "pyxlsb2.ptgs.function_names");
    let mut faults: Vec<String> = Vec::new();
    let mut shared_ftab: usize = 0;
    for (raw, theirs) in &snapshot.ftab {
        let id: u16 = parse_id(raw);
        let Some(ours): Option<&'static str> = ftab_name(id) else {
            continue;
        };
        shared_ftab += 1;
        match divergence(id) {
            Some((expected_ours, expected_theirs)) => {
                if ours != expected_ours || theirs != expected_theirs {
                    faults.push(format!(
                        "ftab {raw}: recorded divergence is {expected_ours} against {expected_theirs}, now {ours} against {theirs}"
                    ));
                }
            }
            None if ours != theirs => {
                faults.push(format!("ftab {raw}: ours {ours}, snapshot {theirs}"));
            }
            None => {}
        }
    }
    let mut shared_cetab: usize = 0;
    for (raw, theirs) in &snapshot.cetab {
        let id: u16 = parse_id(raw);
        let Some(ours): Option<&'static str> = cetab_name(id) else {
            continue;
        };
        shared_cetab += 1;
        if ours != theirs {
            faults.push(format!("cetab {raw}: ours {ours}, snapshot {theirs}"));
        }
    }
    assert!(
        faults.is_empty(),
        "{} function-name disagreements:\n{}",
        faults.len(),
        faults.join("\n")
    );
    assert_eq!(shared_ftab, 476, "shared ftab coverage shrank");
    assert_eq!(shared_cetab, 396, "shared cetab coverage shrank");
    for (id, _ours, _theirs) in DELIBERATE_FTAB_DIVERGENCES {
        assert!(
            snapshot.ftab.contains_key(&format!("0x{id:04X}")),
            "recorded divergence 0x{id:04X} left the snapshot"
        );
    }
}

#[test]
fn function_tables_define_every_snapshot_id() {
    let snapshot: Snapshot = snapshot();
    let missing_ftab: Vec<&String> = snapshot
        .ftab
        .keys()
        .filter(|raw: &&String| ftab_name(parse_id(raw)).is_none())
        .collect();
    let missing_cetab: Vec<&String> = snapshot
        .cetab
        .keys()
        .filter(|raw: &&String| cetab_name(parse_id(raw)).is_none())
        .collect();
    assert!(
        missing_ftab.is_empty(),
        "the snapshot names ftab ids we do not: {missing_ftab:?}"
    );
    assert!(
        missing_cetab.is_empty(),
        "the snapshot names cetab ids we do not: {missing_cetab:?}"
    );
}
