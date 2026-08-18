#![cfg(feature = "chain")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::panic,
    clippy::unnecessary_debug_formatting
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_core::anti_analysis::{AntiAnalysisReport, DefeatStatus, Mechanism, Technique, scan};

fn workspace_root() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn corpus_path(rel: &str) -> PathBuf {
    workspace_root().join("corpus").join(rel)
}

fn cargo_bin() -> PathBuf {
    let exe: PathBuf = std::env::current_exe().expect("current exe");
    let mut dir: PathBuf = exe.parent().expect("exe dir").to_path_buf();
    while dir
        .file_name()
        .and_then(|part: &std::ffi::OsStr| part.to_str())
        != Some("debug")
        && dir
            .file_name()
            .and_then(|part: &std::ffi::OsStr| part.to_str())
            != Some("release")
    {
        if !dir.pop() {
            break;
        }
    }
    dir.push(if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    });
    dir
}

#[allow(clippy::disallowed_methods)]
fn tmp_out(name: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-anti-{name}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
}

fn run_auto(input: &Path, out: &Path) -> std::process::Output {
    let bin: PathBuf = cargo_bin();
    assert!(
        bin.exists(),
        "disrobe binary missing at {bin:?}; run `cargo build -p disrobe-cli` first"
    );
    Command::new(&bin)
        .arg("auto")
        .arg(input)
        .arg("--out")
        .arg(out)
        .output()
        .unwrap_or_else(|e: std::io::Error| panic!("failed to spawn disrobe: {e}"))
}

fn read_anti(out_dir: &Path) -> AntiAnalysisReport {
    let p: PathBuf = out_dir.join("anti-analysis.json");
    let raw: String = std::fs::read_to_string(&p)
        .unwrap_or_else(|e: std::io::Error| panic!("cannot read anti-analysis.json at {p:?}: {e}"));
    serde_json::from_str(&raw)
        .unwrap_or_else(|e: serde_json::Error| panic!("anti-analysis.json malformed: {e}"))
}

fn technique(
    report: &AntiAnalysisReport,
    t: Technique,
) -> Option<&disrobe_core::anti_analysis::AntiAnalysisFinding> {
    report.findings.iter().find(|f| f.technique == t)
}

#[test]
fn auto_emits_anti_analysis_report_and_packing_overcome_on_real_upx() {
    let packed: PathBuf = corpus_path("native/packers/upx/hello.packed.nrv2b.exe");
    assert!(
        packed.exists(),
        "{} is tracked in git and this case grades nothing without it, so its \
         absence is a damaged checkout rather than an optional dependency",
        packed.display()
    );
    let out_scratch: disrobe_core::scratch::ScratchDir = tmp_out("upx");
    let out: PathBuf = out_scratch.path().to_path_buf();
    let proc: std::process::Output = run_auto(&packed, &out);
    let stdout: String = String::from_utf8_lossy(&proc.stdout).into_owned();

    assert!(
        stdout.contains("anti-analysis.json written"),
        "auto text output must announce the anti-analysis report; got: {stdout}"
    );
    assert!(
        stdout.contains("anti-analysis: packing -> overcome via packer-unpack"),
        "auto text output must surface the packing defeat line; got: {stdout}"
    );

    let report: AntiAnalysisReport = read_anti(&out);
    assert_eq!(report.target_family.label(), "pe");
    let packing = technique(&report, Technique::Packing).expect("packing technique present");
    assert!(packing.detected);
    match &packing.defeated_by {
        DefeatStatus::OvercomeBy { mechanism } => {
            assert_eq!(
                *mechanism,
                Mechanism::PackerUnpack,
                "packing must be overcome via the real packer-unpack mechanism that actually ran in \
                 this chain, not a static claim"
            );
        }
        walled @ DefeatStatus::DetectedNotDefeated { .. } => {
            panic!("expected packer-unpack mechanism on a real UPX chain, got {walled:?}")
        }
    }

    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn clean_compiled_binary_does_not_invent_string_encryption() {
    let original: PathBuf = corpus_path("native/packers/upx/hello.original.exe");
    assert!(
        original.exists(),
        "{} is tracked in git and this case grades nothing without it, so its \
         absence is a damaged checkout rather than an optional dependency",
        original.display()
    );
    let bytes: Vec<u8> =
        std::fs::read(&original).unwrap_or_else(|e: std::io::Error| panic!("read original: {e}"));
    let report: AntiAnalysisReport = scan(&bytes, None);
    assert!(
        technique(&report, Technique::StringEncryption).is_none(),
        "an ordinary unpacked compiled binary must not be flagged as string-encrypted; the xor \
         heuristic outlier gate keeps compression / plaintext noise from inflating the matrix: {:?}",
        report.findings
    );
    assert!(
        technique(&report, Technique::Packing).is_none(),
        "the unpacked original carries no packer section magic: {:?}",
        report.findings
    );
}
