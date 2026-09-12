#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use disrobe_pass_shell::detect::{Dialect, detect};
use disrobe_pass_shell::{PdfReport, analyze_pdf};

const OPENACTION_TABLE: &[u8] = include_bytes!("../../../corpus/shell/pdf/openaction_table.pdf");
const NAMES_XREFSTREAM: &[u8] = include_bytes!("../../../corpus/shell/pdf/names_xrefstream.pdf");
const LAUNCH_ACTION: &[u8] = include_bytes!("../../../corpus/shell/pdf/launch_action.pdf");
const EMBEDDED_FILE: &[u8] = include_bytes!("../../../corpus/shell/pdf/embedded_file.pdf");
const ENCRYPTED_RC4: &[u8] = include_bytes!("../../../corpus/shell/pdf/encrypted_rc4.pdf");
const ENCRYPTED_AESV2: &[u8] = include_bytes!("../../../corpus/shell/pdf/encrypted_aesv2.pdf");
const HEXNAME: &[u8] = include_bytes!("../../../corpus/shell/pdf/hexname_javascript.pdf");
const SPLIT_STRING: &[u8] = include_bytes!("../../../corpus/shell/pdf/split_string_javascript.pdf");
const CHAINED_FILTER: &[u8] =
    include_bytes!("../../../corpus/shell/pdf/chained_filter_javascript.pdf");
const LZW_JS: &[u8] = include_bytes!("../../../corpus/shell/pdf/lzw_javascript.pdf");

fn scripts_contain(report: &PdfReport, needle: &str) -> bool {
    report
        .javascript
        .iter()
        .any(|finding| finding.script.contains(needle))
}

#[test]
fn every_fixture_detects_as_pdf() {
    for fixture in [
        OPENACTION_TABLE,
        NAMES_XREFSTREAM,
        LAUNCH_ACTION,
        EMBEDDED_FILE,
        ENCRYPTED_RC4,
        ENCRYPTED_AESV2,
        HEXNAME,
        SPLIT_STRING,
        CHAINED_FILTER,
        LZW_JS,
    ] {
        assert_eq!(detect(fixture).dialect, Dialect::Pdf);
    }
}

#[test]
fn lzw_javascript_stream_is_decoded() {
    let report: PdfReport = analyze_pdf(LZW_JS).expect("pdf report");
    assert!(
        scripts_contain(&report, "LZW_STREAM_MARKER"),
        "LZWDecode-compressed JavaScript stream must be recovered"
    );
}

#[test]
fn openaction_table_recovers_catalog_javascript() {
    let report: PdfReport = analyze_pdf(OPENACTION_TABLE).expect("pdf report");
    assert!(report.xref_table, "classic xref table must be recognized");
    assert!(report.open_action, "OpenAction present");
    assert!(scripts_contain(&report, "OPENACTION_TABLE_MARKER"));
}

#[test]
fn names_xrefstream_recovers_objstm_hidden_javascript() {
    let report: PdfReport = analyze_pdf(NAMES_XREFSTREAM).expect("pdf report");
    assert!(report.xref_stream, "xref stream must be recognized");
    assert!(
        scripts_contain(&report, "NAMES_TREE_MARKER"),
        "name-tree JavaScript inside an object stream must be recovered"
    );
    assert!(
        scripts_contain(&report, "PAGE_AA_OPEN_MARKER"),
        "page additional-action JavaScript must be recovered"
    );
}

#[test]
fn launch_action_is_surfaced_with_target() {
    let report: PdfReport = analyze_pdf(LAUNCH_ACTION).expect("pdf report");
    let launch = report
        .actions
        .iter()
        .find(|action| action.kind == "Launch")
        .expect("launch action present");
    assert!(
        launch.target.contains("cmd.exe"),
        "target={}",
        launch.target
    );
}

#[test]
fn embedded_file_is_carved_with_content() {
    let report: PdfReport = analyze_pdf(EMBEDDED_FILE).expect("pdf report");
    let file = report
        .embedded_files
        .iter()
        .find(|entry| entry.name == "payload.bin")
        .expect("embedded file present");
    let preview: &str = file.preview.as_deref().unwrap_or_default();
    assert!(
        preview.contains("EMBEDDED_FILE_MARKER"),
        "preview={preview}"
    );
    assert_eq!(file.sha256.len(), 64);
}

#[test]
fn encrypted_rc4_empty_password_reveals_javascript() {
    let report: PdfReport = analyze_pdf(ENCRYPTED_RC4).expect("pdf report");
    let encryption = report.encryption.as_ref().expect("encryption detected");
    assert!(
        encryption.handler.contains("rc4"),
        "handler={}",
        encryption.handler
    );
    assert!(
        encryption.decrypted,
        "empty-password decrypt should succeed"
    );
    assert!(scripts_contain(&report, "ENCRYPTED_RC4_MARKER"));
}

#[test]
fn encrypted_aesv2_empty_password_reveals_javascript() {
    let report: PdfReport = analyze_pdf(ENCRYPTED_AESV2).expect("pdf report");
    let encryption = report.encryption.as_ref().expect("encryption detected");
    assert!(
        encryption.handler.contains("aesv2"),
        "handler={}",
        encryption.handler
    );
    assert!(
        encryption.decrypted,
        "empty-password decrypt should succeed"
    );
    assert!(scripts_contain(&report, "ENCRYPTED_AESV2_MARKER"));
}

#[test]
fn hex_escaped_javascript_name_is_normalized_and_recovered() {
    let report: PdfReport = analyze_pdf(HEXNAME).expect("pdf report");
    assert!(
        scripts_contain(&report, "HEX_NAME_MARKER"),
        "hex-escaped /J#61vaScript action must still be recognized"
    );
    assert!(
        report
            .name_obfuscation
            .iter()
            .any(|entry| entry.decoded == "/JavaScript"),
        "name obfuscation surface must report the decoded name: {:?}",
        report.name_obfuscation
    );
}

#[test]
fn split_strings_are_concatenated() {
    let report: PdfReport = analyze_pdf(SPLIT_STRING).expect("pdf report");
    let finding = report
        .javascript
        .iter()
        .find(|entry| entry.script.contains("SPLIT_STRING_MARKER"))
        .expect("split-string javascript present");
    assert_eq!(finding.script, "app.alert('SPLIT_STRING_MARKER');");
    assert!(
        finding
            .deobfuscation
            .iter()
            .any(|technique| technique == "concatenated-strings"),
        "deobfuscation={:?}",
        finding.deobfuscation
    );
}

#[test]
fn chained_ascii85_flate_javascript_stream_is_decoded() {
    let report: PdfReport = analyze_pdf(CHAINED_FILTER).expect("pdf report");
    let finding = report
        .javascript
        .iter()
        .find(|entry| entry.script.contains("CHAINED_FILTER_MARKER"))
        .expect("chained-filter javascript present");
    assert!(
        finding
            .deobfuscation
            .iter()
            .any(|technique| technique == "filter-decoded"),
        "deobfuscation={:?}",
        finding.deobfuscation
    );
}

#[test]
fn mutated_pdf_never_panics() {
    use std::panic::{self, AssertUnwindSafe};

    panic::set_hook(Box::new(|_info: &panic::PanicHookInfo<'_>| {}));
    let base: &[u8] = NAMES_XREFSTREAM;
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    let mut next = |bound: usize| -> usize {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        if bound == 0 {
            0
        } else {
            (state % bound as u64) as usize
        }
    };
    for _ in 0..8_000 {
        let mut buf: Vec<u8> = base.to_vec();
        let flips: usize = next(32) + 1;
        for _ in 0..flips {
            if buf.is_empty() {
                break;
            }
            let index: usize = next(buf.len());
            buf[index] = next(256) as u8;
        }
        if next(4) == 0 {
            buf.truncate(next(buf.len() + 1));
        }
        let result: Result<(), Box<dyn std::any::Any + Send>> =
            panic::catch_unwind(AssertUnwindSafe(|| {
                let _ = analyze_pdf(&buf);
                let _ = detect(&buf);
            }));
        assert!(result.is_ok(), "analyze_pdf panicked on a mutated pdf");
    }
}
