#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_py_deob::ast_eval::{EvalReport, evaluate_source};
use disrobe_testkit::{CommandSpec, ToolOutput, tool_output};

const PYTHON_TIMEOUT: Duration = Duration::from_secs(30);
const PYTHON_CAPTURE_BYTES: usize = 1024;

const AUTHORED: &str = r"
print(7 // -2)
print(pow(2, 3, -5))
";

fn python_output(python: &Path, source: &str, label: &str) -> String {
    let scratch: ScratchDir = ScratchDir::create("disrobe_pyint_reference").expect("scratch dir");
    let source_path: PathBuf = scratch.path().join("arithmetic.py");
    std::fs::write(&source_path, source).expect("write authored or recovered Python source");
    let output: ToolOutput = tool_output(
        CommandSpec::new(python, PYTHON_TIMEOUT)
            .arg("-I")
            .arg("-X")
            .arg("utf8")
            .arg(&source_path)
            .current_dir(scratch.path().to_path_buf())
            .env("PYTHONHASHSEED", "0")
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .capture_limits(PYTHON_CAPTURE_BYTES, PYTHON_CAPTURE_BYTES)
            .reap_descendants_on_exit(),
    )
    .unwrap_or_else(|error| panic!("{label}: CPython launch failed: {error}"));
    assert!(
        output.success,
        "{label}: CPython rejected source; stdout={} stderr={}",
        output.stdout_text(),
        output.stderr_text()
    );
    output.stdout_text().replace("\r\n", "\n")
}

#[test]
fn public_arithmetic_recovery_matches_cpython_and_rejects_a_mutation() {
    let python: PathBuf = common::require_python_312();
    let expected: String = python_output(&python, AUTHORED, "authored reference");
    assert_eq!(expected, "-4\n-2\n");

    let (recovered, report): (String, EvalReport) =
        evaluate_source(AUTHORED).expect("public arithmetic recovery must parse authored source");
    assert!(report.exprs_folded >= 2, "{report:?}\n{recovered}");
    assert_ne!(recovered, AUTHORED, "recovery must not hand back its input");
    assert!(
        !recovered.contains("// -2") && !recovered.contains("pow(2, 3, -5)"),
        "both repaired arithmetic forms must be evaluated:\n{recovered}"
    );
    assert_eq!(
        python_output(&python, &recovered, "recovered source"),
        expected
    );

    let mutated: String = recovered.replacen("-4", "-3", 1);
    assert_ne!(
        mutated, recovered,
        "recovered floor-division result must be present"
    );
    assert_ne!(
        python_output(&python, &mutated, "arithmetic mutation"),
        expected,
        "the independent CPython oracle must reject a changed recovered result"
    );
}
