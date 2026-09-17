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

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::Path;

use disrobe_pass_shell::xlm::biff::read_u16;
use disrobe_pass_shell::xlm::container::{XlmSource, open_source};
use xlm_reference::{Fixture, Manifest, manifest, pinned_fixture_bytes};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Coverage {
    CommittedWorkbook,
    ConstructedWorkbook(&'static str),
    Uncovered(&'static str),
}

#[derive(Debug, Clone, Copy)]
struct RecordEntry {
    rt: u16,
    name: &'static str,
    coverage: Coverage,
}

const RECORD_SPACE: [RecordEntry; 12] = [
    RecordEntry {
        rt: 0x0085,
        name: "BOUNDSHEET",
        coverage: Coverage::CommittedWorkbook,
    },
    RecordEntry {
        rt: 0x0006,
        name: "FORMULA",
        coverage: Coverage::CommittedWorkbook,
    },
    RecordEntry {
        rt: 0x0018,
        name: "NAME",
        coverage: Coverage::CommittedWorkbook,
    },
    RecordEntry {
        rt: 0x0017,
        name: "EXTERNSHEET",
        coverage: Coverage::CommittedWorkbook,
    },
    RecordEntry {
        rt: 0x01AE,
        name: "SUPBOOK",
        coverage: Coverage::CommittedWorkbook,
    },
    RecordEntry {
        rt: 0x0221,
        name: "ARRAY",
        coverage: Coverage::CommittedWorkbook,
    },
    RecordEntry {
        rt: 0x04BC,
        name: "SHRFMLA",
        coverage: Coverage::ConstructedWorkbook(
            "xlm_fixtures.rs builds a shared formula whose host cell carries tExp, because Excel \
             only writes SHRFMLA when a formula is filled across a range and the committed sheets \
             carry no such fill",
        ),
    },
    RecordEntry {
        rt: 0x0204,
        name: "LABEL",
        coverage: Coverage::Uncovered(
            "BIFF8 Excel writes a cell string as LABELSST against the shared string table, so a \
             workbook Excel produces carries no LABEL record",
        ),
    },
    RecordEntry {
        rt: 0x00D6,
        name: "RSTRING",
        coverage: Coverage::Uncovered(
            "RSTRING is the BIFF5 rich string and BIFF8 replaced it with LABELSST, so a workbook \
             Excel 16 produces cannot carry one",
        ),
    },
    RecordEntry {
        rt: 0x0236,
        name: "TABLE",
        coverage: Coverage::Uncovered(
            "TABLE records a what-if data table, which no committed sheet declares",
        ),
    },
    RecordEntry {
        rt: 0x003C,
        name: "CONTINUE",
        coverage: Coverage::Uncovered(
            "Excel writes CONTINUE only when a record body passes 8224 bytes, and the largest body \
             in the committed corpus stays far below that",
        ),
    },
    RecordEntry {
        rt: 0x002F,
        name: "FILEPASS",
        coverage: Coverage::Uncovered(
            "FILEPASS marks an encrypted workbook and the corpus commits none, because a committed \
             encrypted sample would be a credential-shaped artifact in the tree",
        ),
    },
];

fn workbook_stream(data: &[u8]) -> Option<Vec<u8>> {
    match open_source(data)? {
        XlmSource::Biff8 { workbook } => Some(workbook),
        XlmSource::Biff12 { .. } => None,
    }
}

fn record_counts(stream: &[u8]) -> BTreeMap<u16, usize> {
    let mut counts: BTreeMap<u16, usize> = BTreeMap::new();
    let mut offset: usize = 0;
    while let (Some(rt), Some(cb)) = (read_u16(stream, offset), read_u16(stream, offset + 2)) {
        let Some(end): Option<usize> = offset.checked_add(4 + usize::from(cb)) else {
            break;
        };
        if end > stream.len() {
            break;
        }
        *counts.entry(rt).or_default() += 1;
        offset = end;
    }
    counts
}

fn biff8_record_counts(data: &[u8]) -> BTreeMap<u16, usize> {
    workbook_stream(data).map_or_else(BTreeMap::new, |stream: Vec<u8>| record_counts(&stream))
}

#[test]
fn every_declared_biff8_record_is_covered_by_a_workbook_or_states_why_it_is_not() {
    let catalog: Manifest = manifest();
    let mut carried: BTreeMap<u16, BTreeSet<String>> = BTreeMap::new();
    let mut biff8_fixtures: usize = 0;
    for fixture in &catalog.fixtures {
        let data: Vec<u8> = pinned_fixture_bytes(&catalog, &fixture.file);
        let counts: BTreeMap<u16, usize> = biff8_record_counts(&data);
        if counts.is_empty() {
            continue;
        }
        biff8_fixtures += 1;
        for rt in counts.into_keys() {
            carried.entry(rt).or_default().insert(fixture.file.clone());
        }
    }
    assert_eq!(
        biff8_fixtures,
        catalog
            .fixtures
            .iter()
            .filter(|f: &&Fixture| {
                Path::new(&f.file)
                    .extension()
                    .is_some_and(|ext: &OsStr| ext.eq_ignore_ascii_case("xls"))
            })
            .count(),
        "every committed .xls fixture must walk as BIFF8"
    );

    let mut faults: Vec<String> = Vec::new();
    let mut covered: usize = 0;
    for entry in RECORD_SPACE {
        let holders: Option<&BTreeSet<String>> = carried.get(&entry.rt);
        match entry.coverage {
            Coverage::CommittedWorkbook => match holders {
                Some(files) => {
                    covered += 1;
                    println!(
                        "  {} (0x{:04X}) is carried by {}",
                        entry.name,
                        entry.rt,
                        files.iter().cloned().collect::<Vec<String>>().join(", ")
                    );
                }
                None => faults.push(format!(
                    "{} (0x{:04X}) is recorded as carried by a committed workbook and no committed \
                     workbook carries it",
                    entry.name, entry.rt
                )),
            },
            Coverage::ConstructedWorkbook(reason) | Coverage::Uncovered(reason) => {
                if let Some(files) = holders {
                    faults.push(format!(
                        "{} (0x{:04X}) is recorded as absent from the committed workbooks because \
                         {reason}, and {} now carries it, so promote the roster entry",
                        entry.name,
                        entry.rt,
                        files.iter().cloned().collect::<Vec<String>>().join(", ")
                    ));
                }
            }
        }
    }
    assert!(
        faults.is_empty(),
        "{} record-space roster disagreement(s):\n{}",
        faults.len(),
        faults.join("\n")
    );
    assert_eq!(
        covered,
        RECORD_SPACE
            .iter()
            .filter(|entry: &&RecordEntry| entry.coverage == Coverage::CommittedWorkbook)
            .count()
    );
    println!(
        "\nRECORD SPACE: {covered} of {} declared BIFF8 records are carried by a committed \
         workbook, and each of the remaining {} states why it is not\n",
        RECORD_SPACE.len(),
        RECORD_SPACE.len() - covered
    );
}

const DIMENSIONS: u16 = 0x0200;
const TABLE: u16 = 0x0236;

#[test]
fn the_record_walk_reports_a_record_the_roster_calls_absent_once_one_is_planted() {
    let catalog: Manifest = manifest();
    let data: Vec<u8> = pinned_fixture_bytes(&catalog, "real_xlm_excel16.xls");
    let mut stream: Vec<u8> =
        workbook_stream(&data).expect("the committed workbook opens as BIFF8");
    let before: BTreeMap<u16, usize> = record_counts(&stream);
    assert!(
        !before.contains_key(&TABLE),
        "the control must start without a TABLE record"
    );
    assert_eq!(
        before.get(&DIMENSIONS),
        Some(&2),
        "the control must carry one DIMENSIONS record per sheet substream"
    );

    let mut offset: usize = 0;
    let mut planted: bool = false;
    while let (Some(rt), Some(cb)) = (read_u16(&stream, offset), read_u16(&stream, offset + 2)) {
        if rt == DIMENSIONS {
            stream[offset] = (TABLE & 0x00FF) as u8;
            stream[offset + 1] = (TABLE >> 8) as u8;
            planted = true;
            break;
        }
        offset += 4 + usize::from(cb);
    }
    assert!(planted, "the control must carry a record to relabel");

    let after: BTreeMap<u16, usize> = record_counts(&stream);
    assert_eq!(
        after.get(&TABLE),
        Some(&1),
        "a planted record type must reach the roster walk, or the walk grades nothing"
    );
    assert_eq!(
        after.get(&DIMENSIONS),
        Some(&1),
        "relabelling one record must not disturb the rest of the walk"
    );
}
