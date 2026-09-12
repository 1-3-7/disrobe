#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;

use disrobe_pass_shell::{
    ContainerKind, ExtractedProject, VbsReport, deobfuscate_vbs, extract_from_bytes,
};

fn corpus_path(relative: &str) -> PathBuf {
    let manifest_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root: &std::path::Path = manifest_dir
        .parent()
        .and_then(|p: &std::path::Path| p.parent())
        .expect("workspace root");
    workspace_root.join("corpus").join("shell").join(relative)
}

#[test]
fn fixture_real_docm_extracts_module_with_msgbox() -> disrobe_pass_shell::Result<()> {
    let p: PathBuf = corpus_path("vba/hello.docm");
    let bytes: Vec<u8> = std::fs::read(&p)
        .unwrap_or_else(|e: std::io::Error| panic!("read {} failed: {e}", p.display()));
    let project: ExtractedProject = extract_from_bytes(&bytes)?;
    assert_eq!(project.container_kind, ContainerKind::OoxmlZip);
    assert!(
        !project.modules.is_empty(),
        "no modules extracted from real docm"
    );
    Ok(())
}

#[test]
fn fixture_real_vba_project_bin_is_ole_compound_file() -> disrobe_pass_shell::Result<()> {
    let p: PathBuf = corpus_path("vba/vbaProject.bin");
    let bytes: Vec<u8> = std::fs::read(&p)
        .unwrap_or_else(|e: std::io::Error| panic!("read {} failed: {e}", p.display()));
    let project: ExtractedProject = extract_from_bytes(&bytes)?;
    assert_eq!(project.container_kind, ContainerKind::OleCompoundFile);
    assert!(
        !project.modules.is_empty(),
        "no modules extracted from real vbaProject.bin"
    );
    Ok(())
}

#[test]
fn fixture_vbs_chr_chain_deobfuscates_to_wscript_echo() {
    let p: PathBuf = corpus_path("vbs/chr_chain/hello.vbs");
    let src: String = std::fs::read_to_string(&p)
        .unwrap_or_else(|e: std::io::Error| panic!("read {} failed: {e}", p.display()));
    let r: VbsReport = deobfuscate_vbs(&src);
    assert!(r.chr_substitutions >= 8, "report: {r:?}");
    let lowered: String = r.output.to_ascii_lowercase();
    assert!(
        lowered.contains("wscript.echo") || lowered.contains("wscript"),
        "deobfuscated output did not surface WScript.Echo: {}",
        r.output
    );
}

#[test]
fn fixture_vbs_baseline_plain_text_round_trips() {
    let p: PathBuf = corpus_path("vbs/hello.vbs");
    let src: String = std::fs::read_to_string(&p)
        .unwrap_or_else(|e: std::io::Error| panic!("read {} failed: {e}", p.display()));
    let r: VbsReport = deobfuscate_vbs(&src);
    assert_eq!(r.chr_substitutions, 0);
    assert!(r.output.contains("WScript.Echo"));
}
