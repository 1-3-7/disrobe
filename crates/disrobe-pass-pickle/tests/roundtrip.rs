#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::Write as _;
use std::path::PathBuf;
use std::process::Command;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_pickle::{PickleValue, Session, disassemble, execute_full, reconstruct};
use serde_json::{Map, Value, json};

const MIN_SUPPORTED: usize = 120;
const FLOOR_PERCENT: usize = 100;
const PINNED_FIXTURES: usize = 470;
const PINNED_REEXECUTED: usize = 470;
const REQUIRE_PYTHON_VAR: &str = "DISROBE_REQUIRE_PYTHON";
const GRADED: &str = "the pickle reconstruction roundtrip";
const CPYTHON_SHARED_TUPLE_PROTOCOL2: &[u8] =
    b"\x80\x02]q\x00(K\x07]q\x01K\x08a\x86q\x02h\x02}q\x03X\x05\x00\x00\x00tupleq\x04h\x02se.";
const CPYTHON_SHARED_TUPLE_PROTOCOL2_OPCODES: &[&str] = &[
    "PROTO",
    "EMPTY_LIST",
    "BINPUT",
    "MARK",
    "BININT1",
    "EMPTY_LIST",
    "BINPUT",
    "BININT1",
    "APPEND",
    "TUPLE2",
    "BINPUT",
    "BINGET",
    "EMPTY_DICT",
    "BINPUT",
    "BINUNICODE",
    "BINPUT",
    "BINGET",
    "SETITEM",
    "APPENDS",
    "STOP",
];
const DUP_SHARED_LIST: &[u8] = b"\x80\x02(]q\x002l.";
const DUP_SHARED_LIST_OPCODES: &[&str] = &[
    "PROTO",
    "MARK",
    "EMPTY_LIST",
    "BINPUT",
    "DUP",
    "LIST",
    "STOP",
];
const MEMO_OVERWRITE_TUPLE: &[u8] = b"\x80\x02]q\x00(K\x07]q\x01K\x08a\x86q\x02h\x02Kcq\x020e.";
const MEMO_OVERWRITE_TUPLE_OPCODES: &[&str] = &[
    "PROTO",
    "EMPTY_LIST",
    "BINPUT",
    "MARK",
    "BININT1",
    "EMPTY_LIST",
    "BINPUT",
    "BININT1",
    "APPEND",
    "TUPLE2",
    "BINPUT",
    "BINGET",
    "BININT1",
    "BINPUT",
    "POP",
    "APPENDS",
    "STOP",
];

const GENUINE_CEILINGS: &[&str] = &[
    "resolves only via the runtime copyreg registry",
    "out-of-band buffer",
    "persistent id requires a runtime",
    "has no importable module",
];

fn is_genuine_ceiling(reason: &str) -> bool {
    GENUINE_CEILINGS
        .iter()
        .any(|needle: &&str| reason.contains(needle))
}

fn probe(exe: &str) -> bool {
    Command::new(exe)
        .arg("--version")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InterpreterRequirement {
    Optional,
    Mandatory,
}

fn requirement_from_value(value: Option<&OsStr>) -> InterpreterRequirement {
    let Some(raw): Option<&OsStr> = value else {
        return InterpreterRequirement::Optional;
    };
    let text: String = raw.to_string_lossy().trim().to_ascii_lowercase();
    match text.as_str() {
        "" | "0" | "false" | "no" | "off" | "optional" => InterpreterRequirement::Optional,
        _ => InterpreterRequirement::Mandatory,
    }
}

fn requirement() -> InterpreterRequirement {
    let raw: Option<OsString> = std::env::var_os(REQUIRE_PYTHON_VAR);
    requirement_from_value(raw.as_deref())
}

fn announce_unmeasured() {
    let line: String = format!(
        "\nNOT MEASURED: {GRADED} was compared against nothing and graded nothing, because no \
         CPython interpreter is usable here. The published {PINNED_REEXECUTED}-fixture figure is \
         not enforced on this host. Set DISROBE_PYTHON to a real interpreter, or set \
         {REQUIRE_PYTHON_VAR}=1 to fail instead of skipping when CPython cannot be run.\n"
    );
    let mut sink: std::io::StdoutLock<'static> = std::io::stdout().lock();
    drop(sink.write_all(line.as_bytes()));
    drop(sink.flush());
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

fn enforce_requirement(requirement: InterpreterRequirement) {
    assert!(
        requirement == InterpreterRequirement::Optional,
        "{REQUIRE_PYTHON_VAR} makes a real CPython interpreter mandatory for this run, so {GRADED} \
         cannot be measured and this case must not report success. Install CPython 3 and put it on \
         PATH, or point DISROBE_PYTHON at one; to permit a run that measures nothing here, clear \
         {REQUIRE_PYTHON_VAR}."
    );
    announce_unmeasured();
}

fn require_python() -> Option<String> {
    let found: Option<String> = find_python();
    if found.is_some() {
        return found;
    }
    enforce_requirement(requirement());
    None
}

#[test]
fn the_python_requirement_reads_its_environment_variable() {
    assert_eq!(
        requirement_from_value(None),
        InterpreterRequirement::Optional,
        "an unset {REQUIRE_PYTHON_VAR} leaves the interpreter optional"
    );
    for off in ["", "0", "false", "no", "off", "optional", "  OFF  "] {
        assert_eq!(
            requirement_from_value(Some(OsStr::new(off))),
            InterpreterRequirement::Optional,
            "{off:?} must read as optional"
        );
    }
    for on in ["1", "true", "yes", "required", "on"] {
        assert_eq!(
            requirement_from_value(Some(OsStr::new(on))),
            InterpreterRequirement::Mandatory,
            "{on:?} must read as mandatory"
        );
    }
}

#[test]
#[should_panic(expected = "makes a real CPython interpreter mandatory")]
fn a_mandatory_python_requirement_fails_rather_than_skipping() {
    enforce_requirement(InterpreterRequirement::Mandatory);
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
    let recon = reconstruct(&result, session.memo(), session.root_memo_key());
    json!({
        "program": recon.program,
        "reexecutable": recon.reexecutable,
        "reason": recon.unsupported.join("; "),
    })
}

#[test]
fn overwritten_memo_keeps_the_prior_cpython_tuple_binding() {
    let dis = disassemble(MEMO_OVERWRITE_TUPLE).expect("disassemble CPython fixture");
    let opcodes: Vec<&str> = dis
        .instructions
        .iter()
        .map(|insn| insn.name.as_str())
        .collect();
    assert_eq!(opcodes, MEMO_OVERWRITE_TUPLE_OPCODES);

    let (trace, memo) = execute_full(&dis).expect("execute CPython fixture");
    assert_eq!(
        trace.result,
        PickleValue::List(vec![
            PickleValue::MemoRef { key: 2 },
            PickleValue::MemoRef { key: 2 },
        ])
    );
    assert_eq!(
        memo.get(&2),
        Some(&PickleValue::Tuple(vec![
            PickleValue::Int(7),
            PickleValue::List(vec![PickleValue::Int(8)]),
        ]))
    );

    let reconstruction = reconstruct(&trace.result, &memo, trace.root_memo_key);
    assert!(reconstruction.reexecutable);
    assert!(reconstruction.program.contains("_m[2] = (7, [8])"));
    assert!(reconstruction.program.contains("result = [_m[2], _m[2]]"));
}

#[test]
fn cpython_pickle_protocol2_shared_tuple_keeps_aliases() {
    let dis = disassemble(CPYTHON_SHARED_TUPLE_PROTOCOL2).expect("disassemble CPython fixture");
    let opcodes: Vec<&str> = dis
        .instructions
        .iter()
        .map(|insn| insn.name.as_str())
        .collect();
    assert_eq!(opcodes, CPYTHON_SHARED_TUPLE_PROTOCOL2_OPCODES);

    let (trace, memo) = execute_full(&dis).expect("execute CPython fixture");
    assert_eq!(
        trace.result,
        PickleValue::List(vec![
            PickleValue::MemoRef { key: 2 },
            PickleValue::MemoRef { key: 2 },
            PickleValue::Dict(vec![(
                PickleValue::Str("tuple".into()),
                PickleValue::MemoRef { key: 2 },
            )]),
        ])
    );
    assert_eq!(
        memo.get(&2),
        Some(&PickleValue::Tuple(vec![
            PickleValue::Int(7),
            PickleValue::List(vec![PickleValue::Int(8)]),
        ]))
    );

    let reconstruction = reconstruct(&trace.result, &memo, trace.root_memo_key);
    assert!(reconstruction.reexecutable);
    assert!(reconstruction.program.contains("_m[2] = (7, [8])"));
}

#[test]
fn dup_keeps_the_cpython_memoized_list_alias() {
    let dis = disassemble(DUP_SHARED_LIST).expect("disassemble CPython fixture");
    let opcodes: Vec<&str> = dis
        .instructions
        .iter()
        .map(|insn| insn.name.as_str())
        .collect();
    assert_eq!(opcodes, DUP_SHARED_LIST_OPCODES);

    let (trace, memo) = execute_full(&dis).expect("execute CPython fixture");
    assert_eq!(
        trace.result,
        PickleValue::List(vec![
            PickleValue::MemoRef { key: 0 },
            PickleValue::MemoRef { key: 0 },
        ])
    );

    let reconstruction = reconstruct(&trace.result, &memo, trace.root_memo_key);
    assert!(reconstruction.reexecutable);
    assert!(reconstruction.program.contains("result = [_m[0], _m[0]]"));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RoundtripTally {
    population: usize,
    recoverable: usize,
    reexecuted: usize,
}

fn roundtrip_defects(tally: RoundtripTally) -> Vec<String> {
    let mut defects: Vec<String> = Vec::new();
    if tally.population != PINNED_FIXTURES {
        defects.push(format!(
            "the CPython harness emits a fixed fixture set and the published figure names it: \
             {PINNED_FIXTURES} pickles across protocols 0 to 5. This run emitted {}. A run that \
             grades fewer fixtures must score worse, never shrink what it is measured against",
            tally.population
        ));
    }
    if tally.recoverable < PINNED_REEXECUTED {
        defects.push(format!(
            "the published figure is graded over {PINNED_REEXECUTED} recoverable fixtures, but this \
             run left only {} in the denominator. Excluding a case as a ceiling removes it from the \
             population the figure is cut from, so it cannot be absorbed as an unchanged ratio",
            tally.recoverable
        ));
    }
    if tally.reexecuted < PINNED_REEXECUTED {
        defects.push(format!(
            "the published figure is {PINNED_REEXECUTED} fixtures reconstructing to source that \
             re-executes to an equal object under CPython; this run reconstructed {}. Raise the \
             recovery or correct the published figure, never the reverse",
            tally.reexecuted
        ));
    }
    defects
}

#[test]
fn the_pinned_roundtrip_check_rejects_a_dropped_fixture_and_a_shrunken_denominator() {
    let measured: RoundtripTally = RoundtripTally {
        population: PINNED_FIXTURES,
        recoverable: PINNED_REEXECUTED,
        reexecuted: PINNED_REEXECUTED,
    };
    assert!(
        roundtrip_defects(measured).is_empty(),
        "the check must accept the published measurement unchanged"
    );

    let dropped: Vec<String> = roundtrip_defects(RoundtripTally {
        reexecuted: measured.reexecuted - 1,
        ..measured
    });
    assert!(
        dropped
            .iter()
            .any(|defect: &String| defect.contains("this run reconstructed")),
        "losing one reconstructed fixture must be reported as a shortfall against the published \
         numerator, got {dropped:?}"
    );

    let shrunk: Vec<String> = roundtrip_defects(RoundtripTally {
        population: measured.population - 1,
        recoverable: measured.recoverable - 1,
        reexecuted: measured.reexecuted - 1,
    });
    assert!(
        shrunk
            .iter()
            .any(|defect: &String| defect.contains("never shrink what it is measured against")),
        "dropping a fixture from the emitted corpus must be rejected on the denominator rather than \
         absorbed as an unchanged percentage, got {shrunk:?}"
    );

    let relabeled: Vec<String> = roundtrip_defects(RoundtripTally {
        recoverable: measured.recoverable - 1,
        reexecuted: measured.reexecuted - 1,
        ..measured
    });
    assert!(
        relabeled
            .iter()
            .any(|defect: &String| defect.contains("left only")),
        "relabeling one fixture as a ceiling removes it from the denominator and must be rejected, \
         got {relabeled:?}"
    );
}

#[test]
fn cpython_roundtrip_differential_oracle() {
    let Some(python): Option<String> = require_python() else {
        return;
    };

    let scratch: ScratchDir =
        ScratchDir::create("disrobe-pkl-rt").expect("create scratch directory");
    let workdir: PathBuf = scratch.path().to_path_buf();
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

    let shared_tuple_cases: Vec<&Value> = cases
        .iter()
        .filter(|case: &&Value| {
            matches!(
                case["name"].as_str(),
                Some("shared_tuple" | "shared_tuple1" | "shared_tuple3")
            )
        })
        .collect();
    assert_eq!(
        shared_tuple_cases.len(),
        18,
        "CPython must emit every shared tuple fixture for each supported protocol"
    );
    for case in shared_tuple_cases {
        let name: &str = case["name"].as_str().expect("fixture name");
        let protocol: u64 = case["proto"].as_u64().expect("fixture protocol");
        let opcodes: &Vec<Value> = case["opcodes"].as_array().expect("pickletools opcodes");
        let pickletools_dis: &str = case["pickletools_dis"]
            .as_str()
            .expect("pickletools disassembly");
        let expected_tuple: &str = if protocol < 2 {
            "TUPLE"
        } else {
            match name {
                "shared_tuple1" => "TUPLE1",
                "shared_tuple" => "TUPLE2",
                "shared_tuple3" => "TUPLE3",
                _ => unreachable!("filtered shared tuple fixture name"),
            }
        };
        let has_tuple: bool = opcodes
            .iter()
            .any(|opcode: &Value| opcode.as_str() == Some(expected_tuple));
        let has_memo_store: bool = opcodes.iter().any(|opcode: &Value| {
            matches!(
                opcode.as_str(),
                Some("PUT" | "BINPUT" | "LONG_BINPUT" | "MEMOIZE")
            )
        });
        let has_memo_get: bool = opcodes.iter().any(|opcode: &Value| {
            matches!(opcode.as_str(), Some("GET" | "BINGET" | "LONG_BINGET"))
        });
        assert!(
            has_tuple && has_memo_store && has_memo_get && pickletools_dis.contains(expected_tuple),
            "pickletools must show {expected_tuple} and memo reuse for {name} protocol {protocol}: {opcodes:?}"
        );
    }

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
    let mut genuine: BTreeMap<String, usize> = BTreeMap::new();
    let mut modelable: Vec<String> = Vec::new();
    for (file, outcome) in &results {
        let status: &str = outcome["status"].as_str().unwrap_or("?");
        let detail: &str = outcome["detail"].as_str().unwrap_or("");
        match status {
            "ok" => ok += 1,
            "mismatch" => mismatch.push(format!("{file}: {detail}")),
            "error" => errored.push(format!("{file}: {detail}")),
            "excluded" if is_genuine_ceiling(detail) => {
                *genuine.entry(detail.to_owned()).or_default() += 1;
            }
            "excluded" => modelable.push(format!("{file}: {detail}")),
            other => errored.push(format!("{file}: unknown status {other}")),
        }
    }
    let total: usize = results.len();
    let genuine_total: usize = genuine.values().sum();
    let recoverable: usize = total.saturating_sub(genuine_total);
    let pct: usize = ok.saturating_mul(100).checked_div(recoverable).unwrap_or(0);

    let mut summary: String = format!(
        "\n=== pickle re-execution differential oracle ===\ncases={total} ok={ok} mismatch={} error={} genuine-ceiling(excluded)={genuine_total} modelable-walled={}\nrecoverable={recoverable} (all cases minus proven info-theoretic ceilings)\nre-exec-equivalence = {ok}/{recoverable} = {pct}%  (full-corpus ok/total = {ok}/{total})\n",
        mismatch.len(),
        errored.len(),
        modelable.len(),
    );
    summary.push_str("genuine info-theoretic ceilings (correctly excluded, by reason):\n");
    for (reason, count) in &genuine {
        summary.push_str("  [");
        summary.push_str(&count.to_string());
        summary.push_str("] ");
        summary.push_str(reason);
        summary.push('\n');
    }
    if !modelable.is_empty() {
        summary.push_str("MODELABLE cases walled (denominator-inflation guard tripped):\n");
        for m in &modelable {
            summary.push_str("  ");
            summary.push_str(m);
            summary.push('\n');
        }
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

    assert!(
        total >= MIN_SUPPORTED,
        "corpus too small: {total} < {MIN_SUPPORTED}{summary}"
    );
    let defects: Vec<String> = roundtrip_defects(RoundtripTally {
        population: total,
        recoverable,
        reexecuted: ok,
    });
    assert!(
        defects.is_empty(),
        "the published pickle roundtrip figure is {PINNED_REEXECUTED} of {PINNED_FIXTURES}, and \
         that figure is this emitted fixture set rather than a bare percentage:\n{}\n{summary}",
        defects.join("\n")
    );
    assert!(
        modelable.is_empty(),
        "modelable cases walled instead of reconstructed (a wall here would inflate the denominator and fake the score){summary}"
    );
    assert!(mismatch.is_empty(), "reconstruction mismatches{summary}");
    assert!(errored.is_empty(), "reconstruction runtime errors{summary}");
    assert_eq!(
        ok, recoverable,
        "every case except a proven info-theoretic ceiling must re-execute equivalently{summary}"
    );
    assert!(
        pct >= FLOOR_PERCENT,
        "re-exec-equivalence {pct}% below floor {FLOOR_PERCENT}%{summary}"
    );
}
