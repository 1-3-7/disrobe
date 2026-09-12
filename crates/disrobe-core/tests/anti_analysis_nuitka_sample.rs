#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;

use disrobe_core::anti_analysis::{AntiAnalysisFinding, AntiAnalysisReport, Technique, scan};

fn sample_path() -> Option<PathBuf> {
    let candidate: PathBuf = std::env::var_os("DISROBE_NUITKA_SAMPLE").map(PathBuf::from)?;
    candidate.is_file().then_some(candidate)
}

#[test]
#[ignore = "reads a 582MB local Nuitka sample; run with --ignored when the artifact is present"]
fn benign_nuitka_bundle_has_no_anti_debug_verdict() {
    let Some(path): Option<PathBuf> = sample_path() else {
        eprintln!("SKIP: set DISROBE_NUITKA_SAMPLE to a local Nuitka onefile to run this");
        return;
    };
    let bytes: Vec<u8> = std::fs::read(&path).expect("read nuitka sample");
    let report: AntiAnalysisReport = scan(&bytes, Some("dist_windows.exe"));

    let anti_debug: Option<&AntiAnalysisFinding> = report
        .findings
        .iter()
        .find(|f: &&AntiAnalysisFinding| f.technique == Technique::AntiDebug);

    eprintln!(
        "anti-debug finding on benign Nuitka bundle: {anti_debug:?}\nall detected verdicts: {:?}",
        report
            .findings
            .iter()
            .filter(|f: &&AntiAnalysisFinding| f.detected)
            .map(|f: &AntiAnalysisFinding| f.technique)
            .collect::<Vec<Technique>>()
    );

    assert!(
        anti_debug.is_none_or(|f: &AntiAnalysisFinding| !f.detected),
        "instruction-boundary decode must clear the coincidental anti-debug verdict on the \
         benign 582MB Nuitka app; got {anti_debug:?}"
    );
}
