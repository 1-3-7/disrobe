#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::fmt::Write as _;
use std::fs::File;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchFile;
use disrobe_pass_shell::{JsFinding, PdfReport, analyze_pdf};
use serde_json::Value;

const QPDF_VAR: &str = "DISROBE_QPDF";
const LIVE_JS: &str = "app.alert('live');";
const PAGE_TREE: [(u32, &[u8]); 3] = [
    (
        1,
        b"1 0 obj <</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>> endobj\n",
    ),
    (2, b"2 0 obj <</Type/Pages/Kids [3 0 R]/Count 1>> endobj\n"),
    (
        3,
        b"3 0 obj <</Type/Page/Parent 2 0 R/Resources <<>>/MediaBox [0 0 612 792]>> endobj\n",
    ),
];

fn qpdf() -> PathBuf {
    if let Some(configured) = std::env::var_os(QPDF_VAR) {
        let path: PathBuf = PathBuf::from(configured);
        assert!(
            path.is_file(),
            "required tool missing: {QPDF_VAR} names {}, which is not a file; qpdf is the \
             independent PDF reader these object resolutions are graded against",
            path.display()
        );
        return path;
    }
    match Command::new("qpdf").arg("--version").output() {
        Ok(out) if out.status.success() => PathBuf::from("qpdf"),
        Ok(out) => panic!(
            "required tool missing: `qpdf --version` exited with {}; set {QPDF_VAR} to a working \
             qpdf, the independent PDF reader these object resolutions are graded against",
            out.status
        ),
        Err(error) => panic!(
            "required tool missing: qpdf is not on PATH and {QPDF_VAR} is unset ({error}); qpdf \
             is the independent PDF reader these object resolutions are graded against"
        ),
    }
}

fn run_qpdf(qpdf: &PathBuf, args: &[&str], pdf: &ScratchFile) -> Output {
    Command::new(qpdf)
        .args(args)
        .arg(pdf.path())
        .output()
        .unwrap_or_else(|error| panic!("spawn {} {args:?}: {error}", qpdf.display()))
}

fn qpdf_javascript(pdf_bytes: &[u8], number: u32) -> String {
    let qpdf: PathBuf = qpdf();
    let (scratch, mut handle): (ScratchFile, File) =
        ScratchFile::create("pdf-xref-qpdf", "pdf").expect("create a scratch PDF");
    handle.write_all(pdf_bytes).expect("write the scratch PDF");
    drop(handle);
    let check: Output = run_qpdf(&qpdf, &["--check"], &scratch);
    assert_eq!(
        check.status.code(),
        Some(0),
        "qpdf --check must accept the built PDF without warnings or repair\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
    let object_arg: String = format!("--json-object={number}");
    let shown: Output = run_qpdf(
        &qpdf,
        &["--json=2", "--json-key=qpdf", &object_arg],
        &scratch,
    );
    assert_eq!(
        shown.status.code(),
        Some(0),
        "qpdf --json-object={number} failed\nstderr: {}",
        String::from_utf8_lossy(&shown.stderr)
    );
    let json: Value = serde_json::from_slice(&shown.stdout).expect("qpdf prints JSON");
    let key: String = format!("obj:{number} 0 R");
    let js: &str = json["qpdf"][1][&key]["value"]["/JS"]
        .as_str()
        .unwrap_or_else(|| panic!("qpdf shows no string /JS in {key}: {json}"));
    js.strip_prefix("u:")
        .unwrap_or_else(|| panic!("qpdf encodes /JS of {key} as a non-text string: {js}"))
        .to_owned()
}

fn disrobe_javascript(pdf_bytes: &[u8]) -> String {
    let report: PdfReport = analyze_pdf(pdf_bytes).expect("the built bytes are a PDF");
    let open_action: Vec<&JsFinding> = report
        .javascript
        .iter()
        .filter(|finding: &&JsFinding| finding.origin == "OpenAction")
        .collect();
    assert_eq!(
        open_action.len(),
        1,
        "exactly one OpenAction script: {:?}",
        report.javascript
    );
    open_action[0].script.clone()
}

fn without_xref(pdf_bytes: &[u8]) -> Vec<u8> {
    let mut mutated: Vec<u8> = pdf_bytes.to_vec();
    let mut index: usize = 0;
    while index + 9 <= mutated.len() {
        if &mutated[index..index + 9] == b"startxref" {
            mutated[index + 7] = b'X';
            index += 9;
        } else {
            index += 1;
        }
    }
    mutated
}

fn page_tree(pdf: &mut Vec<u8>) -> Vec<(u32, usize)> {
    let mut offsets: Vec<(u32, usize)> = Vec::new();
    for (number, body) in PAGE_TREE {
        offsets.push((number, pdf.len()));
        pdf.extend_from_slice(body);
    }
    offsets
}

fn xref_table(offsets: &[(u32, usize)], size: u32) -> String {
    let mut table: String = format!("xref\n0 {size}\n0000000000 65535 f \n");
    for number in 1..size {
        match offsets.iter().find(|(n, _): &&(u32, usize)| *n == number) {
            Some((_, offset)) => {
                writeln!(table, "{offset:010} 00000 n ").expect("write to a String");
            }
            None => table.push_str("0000000000 00000 f \n"),
        }
    }
    table
}

fn with_appended_decoy() -> Vec<u8> {
    let mut pdf: Vec<u8> = b"%PDF-1.4\n".to_vec();
    let mut offsets: Vec<(u32, usize)> = page_tree(&mut pdf);
    offsets.push((5, pdf.len()));
    pdf.extend_from_slice(b"5 0 obj <</S/JavaScript/JS (app.alert\\('live'\\);)>> endobj\n");
    let xref: usize = pdf.len();
    pdf.extend_from_slice(xref_table(&offsets, 6).as_bytes());
    pdf.extend_from_slice(
        format!("trailer <</Size 6/Root 1 0 R>>\nstartxref\n{xref}\n%%EOF\n").as_bytes(),
    );
    pdf.extend_from_slice(b"5 0 obj <</S/JavaScript/JS (app.alert\\('decoy'\\);)>> endobj\n");
    pdf
}

fn with_update_into_object_stream() -> Vec<u8> {
    let mut pdf: Vec<u8> = b"%PDF-1.5\n".to_vec();
    let mut offsets: Vec<(u32, usize)> = page_tree(&mut pdf);
    offsets.push((5, pdf.len()));
    pdf.extend_from_slice(b"5 0 obj <</S/JavaScript/JS (app.alert\\('stale'\\);)>> endobj\n");
    let first_xref: usize = pdf.len();
    pdf.extend_from_slice(xref_table(&offsets, 6).as_bytes());
    pdf.extend_from_slice(
        format!("trailer <</Size 6/Root 1 0 R>>\nstartxref\n{first_xref}\n%%EOF\n").as_bytes(),
    );
    let members: &[u8] = b"5 0 <</S/JavaScript/JS (app.alert\\('live'\\);)>>";
    let object_stream: usize = pdf.len();
    pdf.extend_from_slice(
        format!(
            "7 0 obj <</Type/ObjStm/N 1/First 4/Length {}>> stream\n",
            members.len()
        )
        .as_bytes(),
    );
    pdf.extend_from_slice(members);
    pdf.extend_from_slice(b"\nendstream endobj\n");
    let xref_stream: usize = pdf.len();
    let object_stream_at: [u8; 2] = u16::try_from(object_stream).expect("small").to_be_bytes();
    let xref_stream_at: [u8; 2] = u16::try_from(xref_stream).expect("small").to_be_bytes();
    let rows: [u8; 12] = [
        2,
        0,
        7,
        0,
        1,
        object_stream_at[0],
        object_stream_at[1],
        0,
        1,
        xref_stream_at[0],
        xref_stream_at[1],
        0,
    ];
    pdf.extend_from_slice(
        format!(
            "8 0 obj <</Type/XRef/W [1 2 1]/Index [5 1 7 2]/Size 9/Prev {first_xref}/Root 1 0 R/Length {}>> stream\n",
            rows.len()
        )
        .as_bytes(),
    );
    pdf.extend_from_slice(&rows);
    pdf.extend_from_slice(
        format!("\nendstream endobj\nstartxref\n{xref_stream}\n%%EOF\n").as_bytes(),
    );
    pdf
}

fn grade(label: &str, pdf: &[u8], superseded: &str) {
    let reference: String = qpdf_javascript(pdf, 5);
    assert_eq!(
        reference, LIVE_JS,
        "[{label}] qpdf must resolve the object the xref chain names"
    );
    let recovered: String = disrobe_javascript(pdf);
    assert_eq!(
        recovered, reference,
        "[{label}] disrobe must report the JavaScript of the object qpdf resolves"
    );
    let scanned: String = disrobe_javascript(&without_xref(pdf));
    assert_ne!(
        scanned, reference,
        "[{label}] mutation control: resolving by the brute-force scan alone must disagree with qpdf"
    );
    assert_eq!(
        scanned, superseded,
        "[{label}] mutation control reads the superseded copy"
    );
    eprintln!("[{label}] qpdf={reference:?} disrobe={recovered:?} scan-only={scanned:?}");
}

#[test]
fn an_appended_decoy_resolves_to_the_object_qpdf_shows() {
    grade(
        "appended decoy",
        &with_appended_decoy(),
        "app.alert('decoy');",
    );
}

#[test]
fn an_update_into_an_object_stream_resolves_to_the_object_qpdf_shows() {
    grade(
        "update into object stream",
        &with_update_into_object_stream(),
        "app.alert('stale');",
    );
}
