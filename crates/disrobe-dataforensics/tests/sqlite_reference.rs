#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_dataforensics::sqlite::{
    InspectOptions, Limits, RecoveredRecord, SqliteReport, TableReport, inspect,
};
use disrobe_tool_process::{CommandSpec, Completion, Execution};
use serde_json::Value;

const PYTHON_OVERRIDE: &str = "DISROBE_PYTHON";
const BASIC: [&str; 6] = [
    "basic.db",
    "page1k.db",
    "page64k.db",
    "utf16le.db",
    "utf16be.db",
    "autovacuum.db",
];

struct Generated {
    dir: ScratchDir,
    reference: Value,
}

fn exited_cleanly(execution: &Execution) -> bool {
    matches!(execution.completion, Completion::Exited(status) if status.success())
}

fn python() -> String {
    let probe = |candidate: &str| -> bool {
        CommandSpec::new(candidate, Duration::from_secs(30))
            .args(["-c", "import sqlite3"])
            .run()
            .is_ok_and(|execution: Execution| exited_cleanly(&execution))
    };
    if let Ok(explicit) = std::env::var(PYTHON_OVERRIDE)
        && probe(&explicit)
    {
        return explicit;
    }
    let found: Option<&str> = ["python", "python3", "py"]
        .into_iter()
        .find(|candidate: &&str| probe(candidate));
    found.map_or_else(
        || {
            panic!(
                "the SQLite grader needs CPython 3 with its sqlite3 module as the reference reader; none is usable here, so this run would compare the parser against nothing. Install CPython 3 or point {PYTHON_OVERRIDE} at one."
            )
        },
        str::to_owned,
    )
}

fn generated() -> &'static Generated {
    static GENERATED: OnceLock<Generated> = OnceLock::new();
    GENERATED.get_or_init(|| {
        let dir: ScratchDir = ScratchDir::create("sqlite-reference").expect("scratch");
        let script: PathBuf =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/make_sqlite.py");
        let execution = CommandSpec::new(python(), Duration::from_mins(10))
            .arg(script.as_os_str())
            .arg(dir.path().as_os_str())
            .run()
            .expect("run the reference generator");
        assert!(
            exited_cleanly(&execution),
            "generator failed: {execution:?}"
        );
        let reference: Value = serde_json::from_slice(
            &std::fs::read(dir.path().join("reference.json")).expect("reference.json"),
        )
        .expect("reference JSON");
        Generated { dir, reference }
    })
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(generated().dir.path().join(name)).expect("generated database")
}

fn options(recover_deleted: bool) -> InspectOptions {
    InspectOptions {
        limits: Limits {
            rows_per_table: 1_000_000,
            ..Limits::default()
        },
        only_table: None,
        recover_deleted,
    }
}

fn rows_of(table: &TableReport) -> Vec<Value> {
    table
        .rows
        .iter()
        .map(|row| {
            serde_json::json!([
                row.rowid,
                serde_json::to_value(&row.values).expect("values")
            ])
        })
        .collect()
}

fn mismatches(report: &SqliteReport, expected: &Value) -> Vec<String> {
    let mut problems: Vec<String> = Vec::new();
    let tables: &serde_json::Map<String, Value> = expected["tables"].as_object().expect("tables");
    for (name, want) in tables {
        let Some(table) = report
            .tables
            .iter()
            .find(|t: &&TableReport| &t.name == name)
        else {
            problems.push(format!("table {name} missing"));
            continue;
        };
        let got: Vec<Value> = rows_of(table);
        let want_rows: &Vec<Value> = want["rows"].as_array().expect("rows");
        if &got != want_rows {
            let first: Option<usize> = got
                .iter()
                .zip(want_rows)
                .position(|(a, b): (&Value, &Value)| a != b);
            problems.push(format!(
                "table {name}: {} rows against {} expected; first difference at {:?}: {:?} vs {:?}",
                got.len(),
                want_rows.len(),
                first,
                first.and_then(|i: usize| got.get(i)),
                first.and_then(|i: usize| want_rows.get(i))
            ));
        }
        if table.row_count != want_rows.len() as u64 {
            problems.push(format!("table {name}: row_count {}", table.row_count));
        }
    }
    let user_tables: usize = report
        .tables
        .iter()
        .filter(|t: &&TableReport| !t.name.starts_with("sqlite_"))
        .count();
    if user_tables != tables.len() {
        problems.push(format!(
            "{user_tables} tables reported, {} expected",
            tables.len()
        ));
    }
    for (name, entries) in expected["indexes"].as_object().expect("indexes") {
        match report.indexes.iter().find(|index| &index.name == name) {
            Some(index) if Some(index.entries) == entries.as_u64() => {}
            other => problems.push(format!("index {name}: {:?}", other.map(|i| i.entries))),
        }
    }
    let views: Vec<String> = report.views.iter().map(|v| v.name.clone()).collect();
    let triggers: Vec<String> = report.triggers.iter().map(|t| t.name.clone()).collect();
    if serde_json::to_value(&views).expect("views") != expected["views"] {
        problems.push(format!("views {views:?}"));
    }
    if serde_json::to_value(&triggers).expect("triggers") != expected["triggers"] {
        problems.push(format!("triggers {triggers:?}"));
    }
    problems
}

#[test]
fn every_live_row_index_view_and_trigger_matches_cpython_sqlite3() {
    let databases: &Value = &generated().reference["databases"];
    for name in BASIC {
        let report: SqliteReport = inspect(&read(name), None, &options(false)).expect(name);
        assert!(report.problems.is_empty(), "{name}: {:?}", report.problems);
        let found: Vec<String> = mismatches(&report, &databases[name]);
        assert!(found.is_empty(), "{name}: {found:?}");
    }
}

#[test]
fn committed_wal_frames_are_applied_and_the_bare_file_shows_the_checkpointed_state() {
    let expected: &Value = &generated().reference["databases"]["wal.db"];
    let db: Vec<u8> = read("wal.db.copy");
    let wal: Vec<u8> = read("wal.db.copy-wal");
    let with_wal: SqliteReport = inspect(&db, Some(&wal), &options(false)).expect("with wal");
    let report = with_wal.wal.as_ref().expect("wal report");
    assert!(report.commits >= 3, "{report:?}");
    assert_eq!(report.valid_frames, report.frames, "{report:?}");
    let found: Vec<String> = mismatches(&with_wal, &expected["with_wal"]);
    assert!(found.is_empty(), "with wal: {found:?}");
    let bare: SqliteReport = inspect(&db, None, &options(false)).expect("without wal");
    let found: Vec<String> = mismatches(&bare, &expected["without_wal"]);
    assert!(found.is_empty(), "without wal: {found:?}");
}

#[test]
fn deleted_rows_are_recovered_without_inventing_any() {
    let expected: &Value = &generated().reference["databases"]["deleted.db"];
    let report: SqliteReport =
        inspect(&read("deleted.db"), None, &options(true)).expect("deleted.db");
    assert!(mismatches(&report, expected).is_empty());
    let ever: BTreeSet<String> = expected["ever"]["notes"]
        .as_array()
        .expect("ever")
        .iter()
        .map(Value::to_string)
        .collect();
    let deleted: Vec<Value> = expected["deleted"]["notes"]
        .as_array()
        .expect("deleted")
        .iter()
        .map(|row: &Value| row[1].clone())
        .collect();
    assert!(
        deleted.len() >= 90,
        "the fixture deletes {} rows",
        deleted.len()
    );
    let notes: Vec<&RecoveredRecord> = report
        .recovered
        .iter()
        .filter(|record: &&RecoveredRecord| record.table.as_deref() == Some("notes"))
        .collect();
    let mut invented: Vec<String> = Vec::new();
    for record in &notes {
        let mut values: Value = serde_json::to_value(&record.values).expect("values");
        if values[0] == serde_json::json!({ "type": "null" }) {
            continue;
        }
        if !ever.contains(&values.to_string()) {
            values[0] = Value::Null;
            invented.push(values.to_string());
        }
    }
    assert!(
        invented.is_empty(),
        "recovered rows never written: {invented:?}"
    );
    let tail = |values: &Value| -> String {
        values
            .as_array()
            .map(|cells: &Vec<Value>| {
                Value::Array(cells.iter().skip(1).cloned().collect()).to_string()
            })
            .unwrap_or_default()
    };
    let with_id: BTreeSet<String> = notes
        .iter()
        .map(|record| {
            serde_json::to_value(&record.values)
                .expect("values")
                .to_string()
        })
        .collect();
    let content: BTreeSet<String> = notes
        .iter()
        .map(|record| tail(&serde_json::to_value(&record.values).expect("values")))
        .collect();
    let exact: usize = deleted
        .iter()
        .filter(|row: &&Value| with_id.contains(&row.to_string()))
        .count();
    let recovered: usize = deleted
        .iter()
        .filter(|row: &&Value| with_id.contains(&row.to_string()) || content.contains(&tail(row)))
        .count();
    println!(
        "deleted rows: {} written, {recovered} recovered ({exact} with their rowid); notes records carved: {}",
        deleted.len(),
        notes.len()
    );
    assert!(
        recovered * 100 >= deleted.len() * 80,
        "only {recovered} of {} deleted rows recovered",
        deleted.len()
    );
}

#[test]
fn a_corrupted_record_header_breaks_agreement_with_the_reference() {
    let mut bytes: Vec<u8> = read("basic.db");
    let needle: &[u8] = b"row 00042 ";
    let at: usize = bytes
        .windows(needle.len())
        .position(|window: &[u8]| window == needle)
        .expect("the row text is stored inline");
    bytes[at - 1] ^= 0x55;
    bytes[at + 4] = b'X';
    let report: SqliteReport = inspect(&bytes, None, &options(false)).expect("still a database");
    let expected: &Value = &generated().reference["databases"]["basic.db"];
    assert!(
        !mismatches(&report, expected).is_empty() || !report.problems.is_empty(),
        "a corrupted record must not pass the grader"
    );
}

#[test]
fn hostile_inputs_are_typed_errors_or_bounded_reports() {
    let base: Vec<u8> = read("basic.db");
    let mut seed: u64 = 0x5eed_1234_abcd_0001;
    for round in 0..400 {
        let mut bytes: Vec<u8> = base[..base.len().min(64 * 1024)].to_vec();
        for _ in 0..8 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let at: usize = (seed as usize) % bytes.len();
            bytes[at] = (seed >> 32) as u8;
        }
        if round % 5 == 0 {
            bytes.truncate((seed as usize) % bytes.len());
        }
        let _ = inspect(&bytes, None, &options(true));
    }
    assert!(inspect(b"not a database at all", None, &options(false)).is_err());
}
