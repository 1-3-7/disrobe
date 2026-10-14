#![cfg(feature = "data")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use common::{cli_binary, run_disrobe, temp_dir};

fn reference_python() -> String {
    let found: Option<&str> = ["python", "python3", "py"]
        .into_iter()
        .find(|candidate: &&str| {
            std::process::Command::new(candidate)
                .args(["-c", "import sqlite3"])
                .status()
                .is_ok_and(|status: std::process::ExitStatus| status.success())
        });
    found.map_or_else(
        || panic!("the sqlite caller case needs CPython 3 with sqlite3 as its reference writer"),
        str::to_owned,
    )
}

#[test]
fn disrobe_sqlite_reports_live_rows_and_recovers_a_deleted_one() {
    assert!(
        cli_binary().exists(),
        "cargo builds the disrobe binary before this test binary runs"
    );
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("sqlite-cli");
    let db: PathBuf = scratch.path().join("app.db");
    let script: String = format!(
        "import sqlite3\nc = sqlite3.connect(r'{}', isolation_level=None)\nc.execute('PRAGMA secure_delete = OFF')\nc.execute('CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT, body TEXT)')\nfor i in range(40):\n    c.execute('INSERT INTO notes (title, body) VALUES (?, ?)', (f'title {{i:03d}}', 'body ' * 40))\nc.execute('DELETE FROM notes WHERE id = 7')\nc.close()\n",
        db.display()
    );
    let status: std::process::ExitStatus = std::process::Command::new(reference_python())
        .args(["-c", &script])
        .status()
        .expect("run the reference writer");
    assert!(status.success());

    let run: common::Run = run_disrobe(&[
        "--json",
        "sqlite",
        db.to_str().expect("utf8 path"),
        "--recover",
        "--rows",
        "100",
    ]);
    assert_eq!(run.code, 0, "disrobe sqlite failed: {}", run.stderr);
    let report: serde_json::Value = serde_json::from_str(&run.stdout).expect("JSON report");
    let table: &serde_json::Value = &report["tables"][0];
    assert_eq!(table["name"], "notes");
    assert_eq!(table["row_count"], 39);
    let titles: Vec<&str> = table["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|row: &serde_json::Value| row["values"][1]["value"].as_str().expect("title"))
        .collect();
    assert!(
        !titles.contains(&"title 006"),
        "the deleted row is not live"
    );
    let recovered: bool = report["recovered"]
        .as_array()
        .expect("recovered")
        .iter()
        .any(|record: &serde_json::Value| record["values"][1]["value"] == "title 006");
    assert!(
        recovered,
        "the deleted row comes back with --recover: {}",
        report["recovered"]
    );
}

#[test]
fn disrobe_capture_reports_the_tls_name_and_writes_decoded_http_bodies() {
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("capture-cli");
    let script: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../disrobe-dataforensics/tests/support/make_captures.py");
    let status: std::process::ExitStatus = std::process::Command::new(reference_python())
        .arg(&script)
        .arg(scratch.path())
        .status()
        .expect("run the capture writer");
    assert!(status.success());
    let bodies: PathBuf = scratch.path().join("bodies");
    let run: common::Run = run_disrobe(&[
        "--json",
        "capture",
        scratch
            .path()
            .join("capture.pcapng")
            .to_str()
            .expect("utf8 path"),
        "--extract",
        bodies.to_str().expect("utf8 path"),
    ]);
    assert_eq!(run.code, 0, "disrobe capture failed: {}", run.stderr);
    let report: serde_json::Value = serde_json::from_str(&run.stdout).expect("JSON report");
    assert_eq!(report["tls"][0]["hello"]["sni"], "secure.example.org");
    assert_eq!(report["http"].as_array().expect("http").len(), 2);
    let html: String =
        std::fs::read_to_string(bodies.join("exchange-00000.html")).expect("first body");
    assert_eq!(
        html,
        "<html><body>hello from the reference capture</body></html>"
    );
}
