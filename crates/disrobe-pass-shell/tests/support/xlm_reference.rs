use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use flate2::read::GzDecoder;
use serde::Deserialize;

pub(crate) const FORMULA_REFERENCE: &str = "XLMMacroDeobfuscator";
pub(crate) const FORMULA_REFERENCE_VERSION: &str = "0.2.7";
pub(crate) const TABLE_REFERENCE: &str = "pyxlsb2";
pub(crate) const TABLE_REFERENCE_VERSION: &str = "0.0.9";
pub(crate) const TABLE_SYMBOL: &str = "pyxlsb2.ptgs.function_names";
pub(crate) const PYTHON_VAR: &str = "DISROBE_PYTHON_BIN";

const DRIVER_TIMEOUT: Duration = Duration::from_mins(15);
const MAX_CAPTURE: usize = 4 * 1024 * 1024;

pub(crate) fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join("xlm")
}

pub(crate) fn driver_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("xlm_reference_driver.py")
}

pub(crate) fn fixture_bytes(name: &str) -> Vec<u8> {
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

pub(crate) fn sha256_hex(data: &[u8]) -> String {
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

pub(crate) fn normalize(formula: &str) -> String {
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

#[derive(Debug, Deserialize)]
pub(crate) struct Manifest {
    pub(crate) producer: String,
    pub(crate) fixtures: Vec<Fixture>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Fixture {
    pub(crate) file: String,
    pub(crate) producer: String,
    pub(crate) producer_version: String,
    pub(crate) sha256: String,
    pub(crate) bytes: usize,
    pub(crate) expected_from: String,
    pub(crate) cells: Vec<ExpectedCell>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ExpectedCell {
    pub(crate) sheet: String,
    pub(crate) cell: String,
    pub(crate) formula: String,
}

pub(crate) fn manifest() -> Manifest {
    let path: PathBuf = golden_dir().join("excel_authored.json");
    let text: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("missing reference manifest {}: {err}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|err| panic!("malformed reference manifest {}: {err}", path.display()))
}

pub(crate) fn pinned_fixture_bytes(manifest: &Manifest, name: &str) -> Vec<u8> {
    let fixture: &Fixture = manifest
        .fixtures
        .iter()
        .find(|f: &&Fixture| f.file == name)
        .unwrap_or_else(|| panic!("{name} is absent from the reference manifest"));
    let data: Vec<u8> = fixture_bytes(name);
    assert_eq!(
        data.len(),
        fixture.bytes,
        "{name} length drifted from the recorded original"
    );
    assert_eq!(
        sha256_hex(&data),
        fixture.sha256,
        "{name} content drifted from the recorded original"
    );
    data
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

pub(crate) fn find_interpreter() -> Option<PathBuf> {
    if let Some(raw) = std::env::var_os(PYTHON_VAR) {
        let candidate: PathBuf = PathBuf::from(raw);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    find_on_path("python").or_else(|| find_on_path("python3"))
}

pub(crate) fn install_hint() -> String {
    format!(
        "install {FORMULA_REFERENCE}=={FORMULA_REFERENCE_VERSION}, which pulls \
         {TABLE_REFERENCE}=={TABLE_REFERENCE_VERSION}, for the interpreter on PATH, or point \
         {PYTHON_VAR} at one that carries both. On an interpreter past 3.11, \
         {FORMULA_REFERENCE}.deobfuscator imports the removed stdlib distutils module, so also \
         install setuptools, which reinstates it as an importable shim"
    )
}

pub(crate) fn require_interpreter() -> PathBuf {
    find_interpreter().unwrap_or_else(|| {
        panic!(
            "no python interpreter is on PATH and {PYTHON_VAR} does not name a file, so the XLM \
             function tables would be graded against nothing. {}",
            install_hint()
        )
    })
}

pub(crate) fn run_driver(python: &Path, args: &[&str]) -> CapturedOutput {
    match run_captured(python, args, DRIVER_TIMEOUT, MAX_CAPTURE) {
        Ok(Some(captured)) => captured,
        Ok(None) => panic!(
            "`{}` did not finish the reference driver within {DRIVER_TIMEOUT:?}",
            python.display()
        ),
        Err(err) => panic!("cannot run `{}`: {err}", python.display()),
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct FunctionTables {
    pub(crate) pyxlsb2: String,
    pub(crate) xlmmacrodeobfuscator: String,
    pub(crate) xlrd2: String,
    pub(crate) symbol: String,
    pub(crate) ftab: BTreeMap<String, String>,
    pub(crate) cetab: BTreeMap<String, String>,
    pub(crate) parser_ids: Vec<String>,
}

pub(crate) fn parse_id(raw: &str) -> u16 {
    let digits: &str = raw
        .strip_prefix("0x")
        .unwrap_or_else(|| panic!("function ids must be hexadecimal with an 0x prefix, got {raw}"));
    u16::from_str_radix(digits, 16)
        .unwrap_or_else(|err| panic!("unparsable function id {raw}: {err}"))
}

pub(crate) fn read_function_tables(python: &Path, scratch: &Path) -> FunctionTables {
    let driver: PathBuf = driver_path();
    let out_path: PathBuf = scratch.join("function_tables.json");
    let driver_arg: String = driver.to_string_lossy().into_owned();
    let out_arg: String = out_path.to_string_lossy().into_owned();
    let captured: CapturedOutput = run_driver(python, &[&driver_arg, "tables", &out_arg]);
    assert_eq!(
        captured.exit_code,
        Some(0),
        "`{}` cannot read {TABLE_SYMBOL} (stdout {:?}, stderr {:?}), so the function tables would \
         be graded against nothing. {}",
        python.display(),
        String::from_utf8_lossy(&captured.stdout).trim(),
        String::from_utf8_lossy(&captured.stderr).trim(),
        install_hint()
    );
    let text: String = std::fs::read_to_string(&out_path)
        .unwrap_or_else(|err| panic!("unreadable function-table dump: {err}"));
    let tables: FunctionTables = serde_json::from_str(&text)
        .unwrap_or_else(|err| panic!("malformed function-table dump: {err}"));
    assert_eq!(
        tables.pyxlsb2, TABLE_REFERENCE_VERSION,
        "the interpreter carries {TABLE_REFERENCE} {}, and this grader is pinned to {TABLE_REFERENCE_VERSION}, \
         so a comparison would grade a different table",
        tables.pyxlsb2
    );
    assert_eq!(
        tables.xlmmacrodeobfuscator, FORMULA_REFERENCE_VERSION,
        "the interpreter carries {FORMULA_REFERENCE} {}, and this grader is pinned to \
         {FORMULA_REFERENCE_VERSION}, so a comparison would grade a different tool",
        tables.xlmmacrodeobfuscator
    );
    assert_eq!(tables.symbol, TABLE_SYMBOL);
    tables
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct CellJob {
    pub(crate) key: String,
    pub(crate) file: String,
    pub(crate) sheet: String,
    pub(crate) cell: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct CellAnswer {
    pub(crate) status: String,
    pub(crate) formula: String,
    pub(crate) detail: String,
}

pub(crate) fn read_cells(
    python: &Path,
    scratch: &Path,
    round: usize,
    jobs: &[CellJob],
) -> BTreeMap<String, CellAnswer> {
    if jobs.is_empty() {
        return BTreeMap::new();
    }
    let driver: PathBuf = driver_path();
    let job_path: PathBuf = scratch.join(format!("jobs_{round}.json"));
    let out_path: PathBuf = scratch.join(format!("answers_{round}.json"));
    let encoded: String = serde_json::to_string(jobs)
        .unwrap_or_else(|err| panic!("cannot encode driver jobs: {err}"));
    std::fs::write(&job_path, encoded)
        .unwrap_or_else(|err| panic!("cannot stage {}: {err}", job_path.display()));
    let driver_arg: String = driver.to_string_lossy().into_owned();
    let job_arg: String = job_path.to_string_lossy().into_owned();
    let out_arg: String = out_path.to_string_lossy().into_owned();
    let captured: CapturedOutput = run_driver(python, &[&driver_arg, "cells", &job_arg, &out_arg]);
    assert_eq!(
        captured.exit_code,
        Some(0),
        "the reference driver failed on round {round} (stdout {:?}, stderr {:?})",
        String::from_utf8_lossy(&captured.stdout).trim(),
        String::from_utf8_lossy(&captured.stderr).trim()
    );
    let text: String = std::fs::read_to_string(&out_path)
        .unwrap_or_else(|err| panic!("unreadable driver answers for round {round}: {err}"));
    serde_json::from_str(&text)
        .unwrap_or_else(|err| panic!("malformed driver answers for round {round}: {err}"))
}
