#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use disrobe_pass_native::delphi::{DelphiForm, decode_dfm};

const CASES: [&str; 5] = ["binary", "collection", "deep", "nested", "scalars"];

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/delphi_dfm")
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e: std::io::Error| {
        panic!(
            "fixture {} is required and could not be read: {e}",
            path.display()
        )
    })
}

fn normalize_newlines(text: &str) -> String {
    text.replace("\r\n", "\n")
}

#[test]
fn every_case_has_both_a_binary_form_and_a_reference_rendering() {
    let dir: PathBuf = fixture_dir();
    for case in CASES {
        let binary: PathBuf = dir.join(format!("{case}.dfm"));
        let reference: PathBuf = dir.join(format!("{case}.ref.txt"));
        let source: PathBuf = dir.join(format!("{case}.src.txt"));
        for path in [&binary, &reference, &source] {
            assert!(
                path.exists(),
                "{} is missing, so case {case} would go ungraded",
                path.display()
            );
        }
    }
    assert!(
        dir.join("dfmconv.pas").exists(),
        "the converter source must ship so the reference rendering can be regenerated"
    );
}

#[test]
fn decoded_form_text_matches_the_external_reference_rendering() {
    let dir: PathBuf = fixture_dir();
    let mut compared: usize = 0;
    for case in CASES {
        let binary: Vec<u8> = read(&dir.join(format!("{case}.dfm")));
        let reference_bytes: Vec<u8> = read(&dir.join(format!("{case}.ref.txt")));
        let reference: String = normalize_newlines(&String::from_utf8_lossy(&reference_bytes));

        let form: DelphiForm = decode_dfm(&binary)
            .unwrap_or_else(|| panic!("case {case} was not recognized as a form stream"));
        assert!(
            !form.truncated,
            "case {case} decoded partially: {:?}",
            form.notes
        );
        assert_eq!(
            form.text, reference,
            "case {case} does not match the reference rendering, newlines normalized to line feeds on both sides"
        );
        compared += 1;
    }
    assert_eq!(
        compared,
        CASES.len(),
        "every case must be compared, none skipped"
    );
}

#[test]
fn reference_rendering_round_trips_through_the_recovered_root_class() {
    let dir: PathBuf = fixture_dir();
    for case in CASES {
        let binary: Vec<u8> = read(&dir.join(format!("{case}.dfm")));
        let form: DelphiForm = decode_dfm(&binary)
            .unwrap_or_else(|| panic!("case {case} was not recognized as a form stream"));
        let first_line: &str = form
            .text
            .lines()
            .next()
            .unwrap_or_else(|| panic!("case {case} produced no output"));
        assert!(
            first_line.ends_with(&form.root_class),
            "case {case} reported root class {} but rendered {first_line}",
            form.root_class
        );
    }
}

#[test]
fn a_stream_without_the_form_signature_is_refused() {
    assert!(decode_dfm(b"not a form at all").is_none());
    assert!(decode_dfm(&[]).is_none());
}
