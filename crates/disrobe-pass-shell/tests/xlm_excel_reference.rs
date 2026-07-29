#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use flate2::read::GzDecoder;
use serde::Deserialize;

use disrobe_pass_shell::{XlmRecovery, XlmSheet, recover_xlm};

#[derive(Debug, Deserialize)]
struct Manifest {
    producer: String,
    fixtures: Vec<Fixture>,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    file: String,
    sha256: String,
    bytes: usize,
    expected_from: String,
    cells: Vec<ExpectedCell>,
}

#[derive(Debug, Deserialize)]
struct ExpectedCell {
    sheet: String,
    cell: String,
    formula: String,
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

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest as _;
    use std::fmt::Write as _;
    let mut hasher: sha2::Sha256 = sha2::Sha256::new();
    hasher.update(data);
    hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut out: String, b: &u8| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

fn decoded_cells(report: &XlmRecovery) -> BTreeMap<(String, String), String> {
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

fn grade(fixture: &Fixture, data: &[u8]) -> Vec<String> {
    let mut faults: Vec<String> = Vec::new();
    let Some(report): Option<XlmRecovery> = recover_xlm(data) else {
        return vec![format!("{}: no XLM recovery at all", fixture.file)];
    };
    let actual: BTreeMap<(String, String), String> = decoded_cells(&report);
    let expected: BTreeMap<(String, String), String> = fixture
        .cells
        .iter()
        .map(|c: &ExpectedCell| ((c.sheet.clone(), c.cell.clone()), c.formula.clone()))
        .collect();
    for ((sheet, cell), want) in &expected {
        match actual.get(&(sheet.clone(), cell.clone())) {
            None => faults.push(format!(
                "{}: {sheet}!{cell} missing, want {want}",
                fixture.file
            )),
            Some(got) if got != want => faults.push(format!(
                "{}: {sheet}!{cell} want {want} got {got}",
                fixture.file
            )),
            Some(_) => {}
        }
    }
    for (sheet, cell) in actual.keys() {
        if !expected.contains_key(&(sheet.clone(), cell.clone())) {
            faults.push(format!(
                "{}: {sheet}!{cell} decoded but absent from the reference",
                fixture.file
            ));
        }
    }
    faults
}

#[test]
fn excel_authored_workbooks_decode_to_the_authored_formulas() {
    let manifest: Manifest = manifest();
    assert!(
        manifest.producer.contains("Microsoft Excel"),
        "the reference producer must be Excel itself, got {}",
        manifest.producer
    );
    assert_eq!(manifest.fixtures.len(), 4, "reference corpus size changed");
    let mut faults: Vec<String> = Vec::new();
    let mut graded: usize = 0;
    for fixture in &manifest.fixtures {
        let data: Vec<u8> = fixture_bytes(&fixture.file);
        assert_eq!(
            data.len(),
            fixture.bytes,
            "{} length drifted from the recorded original",
            fixture.file
        );
        assert_eq!(
            sha256_hex(&data),
            fixture.sha256,
            "{} content drifted from the recorded original",
            fixture.file
        );
        assert!(
            matches!(
                fixture.expected_from.as_str(),
                "excel-readback" | "authored"
            ),
            "{} has an unrecognised expectation source {}",
            fixture.file,
            fixture.expected_from
        );
        graded += fixture.cells.len();
        faults.extend(grade(fixture, &data));
    }
    assert!(
        faults.is_empty(),
        "{} of {graded} reference cells disagree:\n{}",
        faults.len(),
        faults.join("\n")
    );
    assert_eq!(graded, 99, "reference cell count changed");
}

const SUM_OF_1_AND_2: [u8; 10] = [0x1E, 0x01, 0x00, 0x1E, 0x02, 0x00, 0x42, 0x02, 0x04, 0x00];

#[test]
fn excel_authored_grader_rejects_a_corrupted_ptg_stream() {
    let manifest: Manifest = manifest();
    let fixture: &Fixture = manifest
        .fixtures
        .iter()
        .find(|f: &&Fixture| f.file == "real_xlm_excel16.xls")
        .expect("mutation target present in the reference corpus");
    let mut data: Vec<u8> = fixture_bytes(&fixture.file);
    assert!(grade(fixture, &data).is_empty(), "control must start clean");
    let at: usize = data
        .windows(SUM_OF_1_AND_2.len())
        .position(|w: &[u8]| w == SUM_OF_1_AND_2)
        .expect("the =SUM(1,2) ptg stream is present in the fixture");
    data[at + 1] = 0x07;
    let faults: Vec<String> = grade(fixture, &data);
    assert!(
        faults.iter().any(|f: &String| f.contains("=SUM(1,2)")),
        "a corrupted ptg stream must be reported, got {faults:?}"
    );
}

#[test]
fn excel_authored_xlsb_names_tabs_and_skips_index_parts() {
    let data: Vec<u8> = fixture_bytes("bench_biff12.xlsb");
    let report: XlmRecovery = recover_xlm(&data).expect("xlsb workbook recovers");
    let named: Vec<(String, String)> = report
        .sheets
        .iter()
        .map(|s: &XlmSheet| (s.name.clone(), s.kind.clone()))
        .collect();
    assert_eq!(
        named,
        vec![("Macro1".to_owned(), "macro".to_owned())],
        "xlsb sheets must carry their workbook tab names and exclude index parts"
    );
}

#[test]
fn excel_authored_macro_sheets_are_classified_and_named() {
    let data: Vec<u8> = fixture_bytes("real_xlm_ptgspread.xls");
    let report: XlmRecovery = recover_xlm(&data).expect("ptgspread workbook recovers");
    let macro_sheets: Vec<&XlmSheet> = report
        .sheets
        .iter()
        .filter(|s: &&XlmSheet| s.kind == "macro")
        .collect();
    assert_eq!(macro_sheets.len(), 1);
    assert_eq!(macro_sheets[0].name, "Macro2");
    let entry: &disrobe_pass_shell::XlmEntryPoint = report
        .entry_points
        .iter()
        .find(|e: &&disrobe_pass_shell::XlmEntryPoint| e.name == "Auto_Open")
        .expect("built-in Auto_Open name recovered");
    assert_eq!(entry.target, "Macro2!$A$2");
}
