#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::io::Read;
use std::path::PathBuf;

use disrobe_pass_shell::{
    RealModuleDisasm, RealPCodeReport, SemanticLift, disassemble_pcode_real, semantic_lift,
};

fn corpus_path(relative: &str) -> PathBuf {
    let manifest_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root: &std::path::Path = manifest_dir
        .parent()
        .and_then(|p: &std::path::Path| p.parent())
        .expect("workspace root");
    workspace_root.join("corpus").join("shell").join(relative)
}

fn vbaproject_from_docm(relative: &str) -> Vec<u8> {
    let bytes: Vec<u8> = std::fs::read(corpus_path(relative))
        .unwrap_or_else(|e: std::io::Error| panic!("read {relative}: {e}"));
    let cursor: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(bytes);
    let mut zip: zip::ZipArchive<std::io::Cursor<Vec<u8>>> =
        zip::ZipArchive::new(cursor).expect("open docm zip");
    for i in 0..zip.len() {
        let mut f: zip::read::ZipFile<'_> = zip.by_index(i).expect("zip index");
        if f.name().to_ascii_lowercase().ends_with("vbaproject.bin") {
            let mut out: Vec<u8> = Vec::new();
            f.read_to_end(&mut out).expect("read vbaProject.bin");
            return out;
        }
    }
    panic!("no vbaProject.bin inside {relative}");
}

#[test]
fn real_vbaproject_bin_lifts_msgbox_hello_world() -> disrobe_pass_shell::Result<()> {
    let bin: Vec<u8> = std::fs::read(corpus_path("vba/vbaProject.bin"))
        .unwrap_or_else(|e: std::io::Error| panic!("read vbaProject.bin: {e}"));
    let report: RealPCodeReport = disassemble_pcode_real(&bin)?;
    let module: &RealModuleDisasm = report
        .modules
        .iter()
        .find(|m: &&RealModuleDisasm| m.name == "Module1")
        .expect("Module1 present in real fixture");
    let lift: SemanticLift = semantic_lift(module);
    assert!(
        lift.pseudocode.contains("MsgBox \"hello world\""),
        "lift must recover the MsgBox call from real p-code; got:\n{}",
        lift.pseudocode
    );
    assert!(
        lift.pseudocode.contains("End Sub"),
        "lift must close the procedure; got:\n{}",
        lift.pseudocode
    );
    assert_eq!(
        lift.unlifted_lines, 0,
        "every real p-code line must lift; pseudocode:\n{}",
        lift.pseudocode
    );
    assert!(
        lift.walls.is_empty(),
        "no synthetic block closures expected on well-formed module; walls={:?}",
        lift.walls
    );
    Ok(())
}

#[test]
fn real_docm_lifts_msgbox_hello_world() -> disrobe_pass_shell::Result<()> {
    let bin: Vec<u8> = vbaproject_from_docm("vba/hello.docm");
    let report: RealPCodeReport = disassemble_pcode_real(&bin)?;
    let lifted_any: bool = report.modules.iter().any(|m: &RealModuleDisasm| {
        semantic_lift(m)
            .pseudocode
            .contains("MsgBox \"hello world\"")
    });
    assert!(
        lifted_any,
        "semantic lift over real docm p-code must surface MsgBox \"hello world\""
    );
    Ok(())
}

#[test]
fn lift_never_fabricates_against_empty_module() -> disrobe_pass_shell::Result<()> {
    let bin: Vec<u8> = std::fs::read(corpus_path("vba/vbaProject.bin"))
        .unwrap_or_else(|e: std::io::Error| panic!("read vbaProject.bin: {e}"));
    let report: RealPCodeReport = disassemble_pcode_real(&bin)?;
    if let Some(empty) = report
        .modules
        .iter()
        .find(|m: &&RealModuleDisasm| m.num_lines == 0)
    {
        let lift: SemanticLift = semantic_lift(empty);
        assert!(
            lift.pseudocode.is_empty() || !lift.pseudocode.contains("MsgBox"),
            "empty module must not fabricate statements; got:\n{}",
            lift.pseudocode
        );
        assert_eq!(lift.lifted_lines, 0);
    }
    Ok(())
}
