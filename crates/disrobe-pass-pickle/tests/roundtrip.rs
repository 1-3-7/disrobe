#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_pickle::{PickleValue, Session, disassemble, reconstruct};
use serde_json::{Map, Value, json};

const MIN_SUPPORTED: usize = 120;
const FLOOR_PERCENT: usize = 100;

fn probe(exe: &str) -> bool {
    Command::new(exe)
        .arg("--version")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
}

fn find_python() -> Option<String> {
    if let Ok(explicit) = std::env::var("DISROBE_PYTHON")
        && probe(&explicit)
    {
        return Some(explicit);
    }
    ["python", "python3", "py"]
        .into_iter()
        .find(|cand: &&str| probe(cand))
        .map(str::to_owned)
}

fn harness_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("roundtrip_harness.py")
}

fn reconstruct_source(bytes: &[u8]) -> Value {
    let dis = match disassemble(bytes) {
        Ok(dis) => dis,
        Err(e) => {
            return json!({"program": Value::Null, "reexecutable": false, "reason": format!("disasm: {e}")});
        }
    };
    let mut session: Session = Session::new();
    let result: PickleValue = match session.run(&dis) {
        Ok(result) => result,
        Err(e) => {
            return json!({"program": Value::Null, "reexecutable": false, "reason": format!("vm: {e}")});
        }
    };
    let recon = reconstruct(&result, session.memo());
    json!({
        "program": recon.program,
        "reexecutable": recon.reexecutable,
        "reason": recon.unsupported.join("; "),
    })
}

#[test]
fn cpython_roundtrip_differential_oracle() {
    let Some(python): Option<String> = find_python() else {
        eprintln!(
            "roundtrip oracle SKIPPED: no CPython interpreter found (set DISROBE_PYTHON); the re-execution floor is not enforced on this host"
        );
        return;
    };

    let workdir: PathBuf =
        std::env::temp_dir().join(format!("disrobe-pkl-rt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&workdir);
    std::fs::create_dir_all(&workdir).expect("create workdir");
    let harness: PathBuf = harness_path();

    let emit_status: std::process::ExitStatus = Command::new(&python)
        .arg(&harness)
        .arg("emit")
        .arg(&workdir)
        .status()
        .expect("run emit phase");
    assert!(emit_status.success(), "emit phase failed");

    let cases_text: String =
        std::fs::read_to_string(workdir.join("cases.json")).expect("read cases.json");
    let cases: Vec<Value> = serde_json::from_str(&cases_text).expect("parse cases.json");
    assert!(
        cases.len() >= MIN_SUPPORTED,
        "corpus too small: {} cases",
        cases.len()
    );

    let mut sources: Map<String, Value> = Map::new();
    for case in &cases {
        let file: &str = case["file"].as_str().expect("case file");
        let bytes: Vec<u8> = std::fs::read(workdir.join(file)).expect("read fixture");
        sources.insert(file.to_owned(), reconstruct_source(&bytes));
    }
    let sources_path: PathBuf = workdir.join("sources.json");
    std::fs::write(
        &sources_path,
        serde_json::to_string(&Value::Object(sources)).expect("encode sources"),
    )
    .expect("write sources.json");

    let grade_status: std::process::ExitStatus = Command::new(&python)
        .arg(&harness)
        .arg("grade")
        .arg(&workdir)
        .arg(&sources_path)
        .status()
        .expect("run grade phase");
    assert!(grade_status.success(), "grade phase failed");

    let results_text: String =
        std::fs::read_to_string(workdir.join("results.json")).expect("read results.json");
    let results: BTreeMap<String, Value> =
        serde_json::from_str(&results_text).expect("parse results.json");

    let mut ok: usize = 0;
    let mut mismatch: Vec<String> = Vec::new();
    let mut errored: Vec<String> = Vec::new();
    let mut excluded: BTreeMap<String, usize> = BTreeMap::new();
    for (file, outcome) in &results {
        let status: &str = outcome["status"].as_str().unwrap_or("?");
        let detail: &str = outcome["detail"].as_str().unwrap_or("");
        match status {
            "ok" => ok += 1,
            "mismatch" => mismatch.push(format!("{file}: {detail}")),
            "error" => errored.push(format!("{file}: {detail}")),
            "excluded" => *excluded.entry(detail.to_owned()).or_default() += 1,
            other => errored.push(format!("{file}: unknown status {other}")),
        }
    }
    let supported: usize = ok + mismatch.len() + errored.len();
    let pct: usize = ok.saturating_mul(100).checked_div(supported).unwrap_or(0);

    let mut summary: String = format!(
        "\n=== pickle re-execution differential oracle ===\ncases={} supported(reexecutable)={} ok={} mismatch={} error={} excluded={}\nre-exec-equivalence = {ok}/{supported} = {pct}%\n",
        results.len(),
        supported,
        ok,
        mismatch.len(),
        errored.len(),
        excluded.values().sum::<usize>(),
    );
    summary.push_str("excluded (walled, by reason):\n");
    for (reason, count) in &excluded {
        summary.push_str("  [");
        summary.push_str(&count.to_string());
        summary.push_str("] ");
        summary.push_str(reason);
        summary.push('\n');
    }
    if !mismatch.is_empty() {
        summary.push_str("mismatches:\n");
        for m in &mismatch {
            summary.push_str("  ");
            summary.push_str(m);
            summary.push('\n');
        }
    }
    if !errored.is_empty() {
        summary.push_str("errors:\n");
        for e in &errored {
            summary.push_str("  ");
            summary.push_str(e);
            summary.push('\n');
        }
    }
    eprintln!("{summary}");

    let _ = std::fs::remove_dir_all(&workdir);

    assert!(
        supported >= MIN_SUPPORTED,
        "too few re-executable cases: {supported} < {MIN_SUPPORTED}{summary}"
    );
    assert!(
        pct >= FLOOR_PERCENT,
        "re-exec-equivalence {pct}% below floor {FLOOR_PERCENT}%{summary}"
    );
}
