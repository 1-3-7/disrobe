#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::missing_panics_doc
)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use flate2::read::GzDecoder;
use serde::Deserialize;

use disrobe_pass_shell::{XlmRecovery, recover_xlm};

const REFERENCE_TOOL: &str = "XLMMacroDeobfuscator";
const REFERENCE_VERSION: &str = "0.2.7";
const REQUIRE_VAR: &str = "DISROBE_REQUIRE_XLM_REFERENCE";
const PYTHON_VAR: &str = "DISROBE_PYTHON_BIN";
const CALL_TIMEOUT: Duration = Duration::from_secs(200);
const MAX_CAPTURE: usize = 4 * 1024 * 1024;
const EXPECTED_GRADED_CELLS: usize = 44;
const GRADED: &str = "the recovered XLM formula text compared against what XLMMacroDeobfuscator reads from the same \
     workbook";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeclaredRefusal {
    fixture: &'static str,
    marker: &'static str,
    reason: &'static str,
}

const DECLARED_REFUSALS: [DeclaredRefusal; 2] = [
    DeclaredRefusal {
        fixture: "real_xlm_ptgspread.xls",
        marker: "unknown FuncID:87",
        reason: "the reference stops at a ptgFuncVar function id it does not carry, so it cannot \
                 grade this sheet; disrobe recovers it and is unrefereed here",
    },
    DeclaredRefusal {
        fixture: "ftab_probe.xls",
        marker: "Unexpected token 0xff",
        reason: "the probe sheet deliberately carries ftab index 0x00FF, the one entry the name \
                 tables already declare as divergent, and the reference refuses the record",
    },
];

#[derive(Debug, Deserialize)]
struct Manifest {
    fixtures: Vec<Fixture>,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    file: String,
    expected_from: String,
}

#[derive(Debug, Deserialize)]
struct ReferenceDump {
    records: Vec<ReferenceRecord>,
}

#[derive(Debug, Deserialize)]
struct ReferenceRecord {
    sheet: String,
    cell_add: String,
    formula: Option<String>,
}

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join("xlm")
}

fn manifest() -> Manifest {
    let path: PathBuf = golden_dir().join("excel_authored.json");
    let text: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("missing reference manifest {}: {err}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|err| panic!("malformed reference manifest {}: {err}", path.display()))
}

fn fixture_bytes(name: &str) -> Vec<u8> {
    let path: PathBuf = golden_dir().join(format!("{name}.gz.b64"));
    let armored: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("missing reference fixture {}: {err}", path.display()));
    let packed: Vec<u8> = base64::engine::general_purpose::STANDARD
        .decode(armored.replace(['\r', '\n'], ""))
        .unwrap_or_else(|err| panic!("undecodable reference fixture {name}: {err}"));
    let mut raw: Vec<u8> = Vec::new();
    GzDecoder::new(packed.as_slice())
        .read_to_end(&mut raw)
        .unwrap_or_else(|err| panic!("uninflatable reference fixture {name}: {err}"));
    raw
}

fn mandatory() -> bool {
    let Some(raw): Option<OsString> = std::env::var_os(REQUIRE_VAR) else {
        return false;
    };
    !matches!(
        raw.to_string_lossy().trim().to_ascii_lowercase().as_str(),
        "" | "0" | "false" | "no" | "off" | "optional"
    )
}

fn refuse_or_announce(defect: &str) {
    assert!(
        !mandatory(),
        "{REQUIRE_VAR} makes {REFERENCE_TOOL} mandatory for this run, so {GRADED} cannot be \
         measured and this case must not report success: {defect}. To fix it, install \
         {REFERENCE_TOOL}=={REFERENCE_VERSION} for the interpreter on PATH, or point {PYTHON_VAR} \
         at one that has it; to permit a run that measures nothing here, clear {REQUIRE_VAR}."
    );
    println!(
        "\nNOT MEASURED: {GRADED} compared nothing and graded nothing, because {defect}. Set \
         {REQUIRE_VAR}=1 to fail instead of skipping when {REFERENCE_TOOL} cannot be run.\n"
    );
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path_var: OsString = std::env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) { &["", ".exe"] } else { &[""] };
    for dir in std::env::split_paths(&path_var) {
        for ext in exts {
            let candidate: PathBuf = dir.join(format!("{name}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn interpreter() -> Option<PathBuf> {
    if let Some(raw) = std::env::var_os(PYTHON_VAR) {
        let candidate: PathBuf = PathBuf::from(raw);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    find_on_path("python").or_else(|| find_on_path("python3"))
}

fn run(python: &Path, args: &[&str]) -> Option<CapturedOutput> {
    run_captured(python, args, CALL_TIMEOUT, MAX_CAPTURE)
        .ok()
        .flatten()
}

fn reference_version(python: &Path) -> Result<String, String> {
    let probe: &str = "import importlib.metadata as m; print(m.version('XLMMacroDeobfuscator'))";
    let Some(out): Option<CapturedOutput> = run(python, &["-c", probe]) else {
        return Err(format!(
            "`{}` did not answer a version query within {CALL_TIMEOUT:?}",
            python.display()
        ));
    };
    let text: String = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if out.exit_code == Some(0) && !text.is_empty() {
        return Ok(text);
    }
    Err(format!(
        "`{}` cannot import {REFERENCE_TOOL} (stdout {:?}, stderr {:?}), so the reference is not \
         installed for this interpreter",
        python.display(),
        text,
        String::from_utf8_lossy(&out.stderr).trim()
    ))
}

fn normalize(formula: &str) -> String {
    let mut out: String = String::with_capacity(formula.len());
    let mut in_string: bool = false;
    let mut chars: std::iter::Peekable<std::str::Chars<'_>> = formula.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '"' {
            in_string = !in_string;
            out.push(ch);
            continue;
        }
        if in_string {
            out.push(ch);
            continue;
        }
        match ch {
            '\'' => {}
            ',' => {
                out.push(',');
                while chars.peek() == Some(&' ') {
                    let _: Option<char> = chars.next();
                }
            }
            '.' if chars.peek() == Some(&'0') && out.ends_with(|c: char| c.is_ascii_digit()) => {
                let mut lookahead: std::iter::Peekable<std::str::Chars<'_>> = chars.clone();
                let _: Option<char> = lookahead.next();
                if lookahead.peek().is_none_or(|c: &char| !c.is_ascii_digit()) {
                    let _: Option<char> = chars.next();
                } else {
                    out.push('.');
                }
            }
            other => out.push(other),
        }
    }
    out
}

fn recovered_cells(report: &XlmRecovery) -> BTreeMap<(String, String), String> {
    let mut out: BTreeMap<(String, String), String> = BTreeMap::new();
    for sheet in &report.sheets {
        for cell in &sheet.cells {
            out.insert(
                (sheet.name.clone(), cell.cell.clone()),
                cell.formula.clone(),
            );
        }
    }
    out
}

fn reference_cells(dump: &ReferenceDump) -> BTreeMap<(String, String), String> {
    let mut out: BTreeMap<(String, String), String> = BTreeMap::new();
    for record in &dump.records {
        let Some(formula): Option<&String> = record.formula.as_ref() else {
            continue;
        };
        if formula.is_empty() || formula == "None" {
            continue;
        }
        out.insert(
            (record.sheet.clone(), record.cell_add.clone()),
            formula.clone(),
        );
    }
    out
}

fn declared_refusal(fixture: &str) -> Option<&'static DeclaredRefusal> {
    DECLARED_REFUSALS
        .iter()
        .find(|entry: &&DeclaredRefusal| entry.fixture == fixture)
}

struct Graded {
    cells: usize,
    faults: Vec<String>,
}

fn grade_fixture(
    python: &Path,
    scratch: &Path,
    fixture: &Fixture,
    faults: &mut Vec<String>,
) -> Graded {
    let data: Vec<u8> = fixture_bytes(&fixture.file);
    let workbook: PathBuf = scratch.join(&fixture.file);
    std::fs::write(&workbook, &data)
        .unwrap_or_else(|err| panic!("cannot stage {}: {err}", workbook.display()));
    let dump_path: PathBuf = scratch.join(format!("{}.reference.json", fixture.file));

    let workbook_arg: String = workbook.to_string_lossy().into_owned();
    let dump_arg: String = dump_path.to_string_lossy().into_owned();
    let out: Option<CapturedOutput> = run(
        python,
        &[
            "-m",
            "XLMMacroDeobfuscator.deobfuscator",
            "--file",
            &workbook_arg,
            "--extract-only",
            "--no-indent",
            "--export-json",
            &dump_arg,
        ],
    );
    let Some(captured): Option<CapturedOutput> = out else {
        faults.push(format!(
            "{}: the reference did not finish within {CALL_TIMEOUT:?}",
            fixture.file
        ));
        return Graded {
            cells: 0,
            faults: Vec::new(),
        };
    };
    let transcript: String = format!(
        "{}{}",
        String::from_utf8_lossy(&captured.stdout),
        String::from_utf8_lossy(&captured.stderr)
    );

    if !dump_path.is_file() {
        match declared_refusal(&fixture.file) {
            Some(refusal) if transcript.contains(refusal.marker) => {
                println!(
                    "  reference refuses {} at {:?}: {}",
                    fixture.file, refusal.marker, refusal.reason
                );
            }
            Some(refusal) => faults.push(format!(
                "{}: the reference still fails but no longer at {:?}. Transcript tail: {}",
                fixture.file,
                refusal.marker,
                transcript
                    .lines()
                    .rev()
                    .take(3)
                    .collect::<Vec<&str>>()
                    .join(" | ")
            )),
            None => faults.push(format!(
                "{}: the reference produced no dump and this fixture is not a declared refusal. \
                 Transcript tail: {}",
                fixture.file,
                transcript
                    .lines()
                    .rev()
                    .take(3)
                    .collect::<Vec<&str>>()
                    .join(" | ")
            )),
        }
        return Graded {
            cells: 0,
            faults: Vec::new(),
        };
    }

    if let Some(refusal) = declared_refusal(&fixture.file) {
        faults.push(format!(
            "{}: this fixture is declared unrefereeable at {:?} but the reference parsed it. \
             Remove the declared refusal rather than leaving a stale exemption.",
            fixture.file, refusal.marker
        ));
    }

    let text: String = std::fs::read_to_string(&dump_path)
        .unwrap_or_else(|err| panic!("unreadable reference dump for {}: {err}", fixture.file));
    let dump: ReferenceDump = serde_json::from_str(&text)
        .unwrap_or_else(|err| panic!("malformed reference dump for {}: {err}", fixture.file));

    let Some(report): Option<XlmRecovery> = recover_xlm(&data) else {
        faults.push(format!(
            "{}: the reference read this workbook but disrobe recovered no XLM at all",
            fixture.file
        ));
        return Graded {
            cells: 0,
            faults: Vec::new(),
        };
    };

    let theirs: BTreeMap<(String, String), String> = reference_cells(&dump);
    let ours: BTreeMap<(String, String), String> = recovered_cells(&report);
    let mut graded: usize = 0;
    for ((sheet, cell), reference_formula) in &theirs {
        let Some(our_formula): Option<&String> = ours.get(&(sheet.clone(), cell.clone())) else {
            faults.push(format!(
                "{}: {sheet}!{cell} is a formula to the reference ({reference_formula}) and absent \
                 from disrobe's recovery",
                fixture.file
            ));
            continue;
        };
        graded += 1;
        if normalize(reference_formula) != normalize(our_formula) {
            faults.push(format!(
                "{}: {sheet}!{cell} reference {reference_formula:?}, disrobe {our_formula:?}",
                fixture.file
            ));
        }
    }
    println!(
        "  {} ({}): {graded} cells graded against the reference",
        fixture.file, fixture.expected_from
    );
    Graded {
        cells: graded,
        faults: Vec::new(),
    }
}

#[test]
fn recovered_formulas_match_an_independent_deobfuscator() {
    let Some(python): Option<PathBuf> = interpreter() else {
        refuse_or_announce(
            "no python interpreter is on PATH and DISROBE_PYTHON_BIN does not name a file",
        );
        return;
    };
    let version: String = match reference_version(&python) {
        Ok(found) => found,
        Err(defect) => {
            refuse_or_announce(&defect);
            return;
        }
    };
    if version != REFERENCE_VERSION {
        refuse_or_announce(&format!(
            "the interpreter carries {REFERENCE_TOOL} {version}, and this grader is pinned to \
             {REFERENCE_VERSION}, so a comparison would grade a different tool"
        ));
        return;
    }

    let guard: ScratchDir =
        ScratchDir::create("xlm-independent-reference").expect("create scratch directory");
    let manifest: Manifest = manifest();
    let mut faults: Vec<String> = Vec::new();
    let mut graded_cells: usize = 0;
    let mut graded_fixtures: usize = 0;

    println!(
        "\nreference: {REFERENCE_TOOL} {version} via {}",
        python.display()
    );
    for fixture in &manifest.fixtures {
        let outcome: Graded = grade_fixture(&python, guard.path(), fixture, &mut faults);
        if outcome.cells > 0 {
            graded_fixtures += 1;
        }
        graded_cells += outcome.cells;
        faults.extend(outcome.faults);
    }

    assert!(
        faults.is_empty(),
        "{} disagreement(s) between disrobe and {REFERENCE_TOOL} {version}:\n{}",
        faults.len(),
        faults.join("\n")
    );
    assert!(
        graded_cells > 0 && graded_fixtures > 0,
        "the reference graded {graded_cells} cell(s) across {graded_fixtures} fixture(s); a run \
         that compares nothing must not report success"
    );
    assert_eq!(
        graded_cells, EXPECTED_GRADED_CELLS,
        "docs/src/languages/shell.md publishes {EXPECTED_GRADED_CELLS} independently graded cells, \
         so a change to the corpus moves the figure in the same commit"
    );
    assert!(
        graded_fixtures + DECLARED_REFUSALS.len() == manifest.fixtures.len(),
        "{graded_fixtures} fixture(s) graded and {} declared unrefereeable, which does not account \
         for all {} committed fixtures",
        DECLARED_REFUSALS.len(),
        manifest.fixtures.len()
    );
    println!(
        "\nGRADED: {graded_cells} XLM formula cells across {graded_fixtures} workbooks against \
         {REFERENCE_TOOL} {version}, with {} fixture(s) the reference cannot read\n",
        DECLARED_REFUSALS.len()
    );
}

#[test]
fn the_normalizer_folds_formatting_without_folding_a_wrong_function_name() {
    assert_eq!(normalize("=SUM(1.0,2.0)"), normalize("=SUM(1,2)"));
    assert_eq!(normalize("=MID(D1, 2, 3)"), normalize("=MID(D1,2,3)"));
    assert_eq!(normalize("='Sheet1'!A1"), normalize("=Sheet1!A1"));
    assert_ne!(normalize("=SUM(1,2)"), normalize("=PRODUCT(1,2)"));
    assert_ne!(normalize("=CALL(D4,D5)"), normalize("=EXEC(D4,D5)"));
    assert_ne!(
        normalize("=ROUND(3.14159,2)"),
        normalize("=ROUND(3.14158,2)")
    );
    assert_ne!(normalize("=A2+1"), normalize("=A2+1.5"));
    assert_ne!(normalize("=A1"), normalize("=A2"));
    assert_eq!(normalize("=\"a, b\""), "=\"a, b\"");
    assert_eq!(
        normalize("=CONCATENATE(\"x'y\",1.0)"),
        "=CONCATENATE(\"x'y\",1)"
    );
}
