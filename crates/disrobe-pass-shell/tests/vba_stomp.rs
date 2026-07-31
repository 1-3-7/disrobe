#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;

use disrobe_pass_shell::{
    ExtractedProject, ModuleStompReport, RealPCodeReport, StompReport, StompVerdict, analyze_stomp,
    analyze_stomp_parts, disassemble_pcode_real, extract_from_bytes,
};

fn corpus_path(relative: &str) -> PathBuf {
    let manifest_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root: &std::path::Path = manifest_dir
        .parent()
        .and_then(|p: &std::path::Path| p.parent())
        .expect("workspace root");
    workspace_root.join("corpus").join("shell").join(relative)
}

fn read_corpus(relative: &str) -> Vec<u8> {
    let p: PathBuf = corpus_path(relative);
    std::fs::read(&p).unwrap_or_else(|e: std::io::Error| panic!("read {} failed: {e}", p.display()))
}

#[test]
fn real_vbaproject_module1_source_and_pcode_agree() -> disrobe_pass_shell::Result<()> {
    let raw: Vec<u8> = read_corpus("vba/vbaProject.bin");
    let report: StompReport = analyze_stomp(&raw)?;
    let module1: &ModuleStompReport = report
        .modules
        .iter()
        .find(|m: &&ModuleStompReport| m.module == "Module1")
        .expect("Module1 in stomp report");
    assert_eq!(
        module1.verdict,
        StompVerdict::Consistent,
        "independent OVBA source and p-code lift must agree on a non-stomped module; report={module1:?}"
    );
    assert!(
        module1.pcode_strings.contains(&"hello world".to_owned()),
        "p-code side must recover the literal; strings={:?}",
        module1.pcode_strings
    );
    assert!(
        module1
            .source_strings
            .iter()
            .any(|s: &String| s.contains("hello world")),
        "source side must recover the literal independently; strings={:?}",
        module1.source_strings
    );
    assert!(
        module1.pcode_calls.contains(&"MsgBox".to_owned()),
        "p-code side must recover the MsgBox call; calls={:?}",
        module1.pcode_calls
    );
    assert!(
        module1.source_calls.contains(&"MsgBox".to_owned()),
        "source side must recover the MsgBox call independently; calls={:?}",
        module1.source_calls
    );
    assert!(
        module1.pcode_only_strings.is_empty() && module1.pcode_only_calls.is_empty(),
        "non-stomped module must have no p-code-exclusive behavior; report={module1:?}"
    );
    assert!(!report.any_stomped, "clean fixture must not flag a stomp");
    Ok(())
}

#[test]
fn synthetic_stomp_flags_stripped_source_but_recovers_pcode() -> disrobe_pass_shell::Result<()> {
    let raw: Vec<u8> = read_corpus("vba/vbaProject.bin");
    let pcode: RealPCodeReport = disassemble_pcode_real(&raw)?;
    let mut project: ExtractedProject = extract_from_bytes(&raw)?;
    for module in &mut project.modules {
        if module.name.eq_ignore_ascii_case("Module1") {
            module.recovered_source = "Attribute VB_Name = \"Module1\"\n".to_owned();
        }
    }
    let report: StompReport = analyze_stomp_parts(&project, &pcode);
    let module1: &ModuleStompReport = report
        .modules
        .iter()
        .find(|m: &&ModuleStompReport| m.module == "Module1")
        .expect("Module1 in stomp report");
    assert_eq!(
        module1.verdict,
        StompVerdict::Stomped,
        "stripped source with intact p-code must be flagged stomped; report={module1:?}"
    );
    assert!(
        report.any_stomped,
        "report must propagate the stomp flag at project level"
    );
    assert!(
        module1
            .pcode_only_strings
            .contains(&"hello world".to_owned()),
        "stomp report must surface the behavior the attacker stripped; report={module1:?}"
    );
    assert!(
        module1.recovered_source.contains("MsgBox \"hello world\""),
        "recovered p-code source must be readable despite the stomp; got:\n{}",
        module1.recovered_source
    );
    assert!(
        !module1.evidence.is_empty(),
        "a stomp verdict must carry evidence; report={module1:?}"
    );
    Ok(())
}

#[test]
fn real_docm_stomp_analysis_is_consistent() -> disrobe_pass_shell::Result<()> {
    let raw: Vec<u8> = read_corpus("vba/hello.docm");
    let report: StompReport = analyze_stomp(&raw)?;
    assert!(
        !report.modules.is_empty(),
        "docm must yield at least one analyzed module"
    );
    assert!(
        !report.any_stomped,
        "clean docm must not be flagged as stomped; report={:?}",
        report
            .modules
            .iter()
            .map(|m: &ModuleStompReport| (&m.module, m.verdict))
            .collect::<Vec<_>>()
    );
    Ok(())
}
