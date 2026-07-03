#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;

use disrobe_pass_shell::{ContainerKind, ExtractedModule, ExtractedProject, extract_from_bytes};

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

fn read_corpus_text(relative: &str) -> String {
    let p: PathBuf = corpus_path(relative);
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e: std::io::Error| panic!("read {} failed: {e}", p.display()))
}

fn normalize(text: &str) -> String {
    text.replace("\r\n", "\n")
        .replace('\r', "\n")
        .trim_end_matches('\n')
        .to_owned()
}

fn module_named<'a>(project: &'a ExtractedProject, name: &str) -> &'a ExtractedModule {
    project
        .modules
        .iter()
        .find(|m: &&ExtractedModule| m.name.eq_ignore_ascii_case(name))
        .unwrap_or_else(|| {
            panic!(
                "module {name} not recovered; got {:?}",
                project
                    .modules
                    .iter()
                    .map(|m: &ExtractedModule| &m.name)
                    .collect::<Vec<_>>()
            )
        })
}

#[test]
fn docm_recovers_module_source_byte_exact() {
    let container: Vec<u8> = read_corpus("vba/sourceprobe.docm");
    let authored: String = read_corpus_text("vba/sourceprobe/SourceProbe.bas");
    let project: ExtractedProject = extract_from_bytes(&container).expect("extract docm");
    assert_eq!(project.container_kind, ContainerKind::OoxmlZip);
    let module: &ExtractedModule = module_named(&project, "SourceProbe");
    assert!(
        module.text_offset.is_some(),
        "module must carry a dir-stream TextOffset"
    );
    assert_eq!(
        normalize(&module.recovered_source),
        normalize(&authored),
        "recovered source must equal the authored .bas (real ground truth)"
    );
}

#[test]
fn xlsm_recovers_module_source_byte_exact() {
    let container: Vec<u8> = read_corpus("vba/sourceprobe.xlsm");
    let authored: String = read_corpus_text("vba/sourceprobe/SourceProbe.bas");
    let project: ExtractedProject = extract_from_bytes(&container).expect("extract xlsm");
    assert_eq!(project.container_kind, ContainerKind::OoxmlZip);
    let module: &ExtractedModule = module_named(&project, "SourceProbe");
    assert_eq!(
        normalize(&module.recovered_source),
        normalize(&authored),
        "recovered source must equal the authored .bas across the xlsm container too"
    );
}

#[test]
fn recovered_source_contains_specific_constructs() {
    let container: Vec<u8> = read_corpus("vba/sourceprobe.docm");
    let project: ExtractedProject = extract_from_bytes(&container).expect("extract docm");
    let module: &ExtractedModule = module_named(&project, "SourceProbe");
    let src: &str = &module.recovered_source;
    for needle in [
        "Attribute VB_Name = \"SourceProbe\"",
        "Public Function Accumulate(ByVal upTo As Long) As Long",
        "Public Function FactorialRec(ByVal n As Long) As Currency",
        "MsgBox \"total=\" & total, vbInformation, APP_NAME",
        "Select Case score",
    ] {
        assert!(
            src.contains(needle),
            "recovered source missing {needle:?}; got:\n{src}"
        );
    }
}

#[test]
fn dir_text_offset_is_used_not_stream_start() {
    let container: Vec<u8> = read_corpus("vba/sourceprobe.docm");
    let project: ExtractedProject = extract_from_bytes(&container).expect("extract docm");
    let module: &ExtractedModule = module_named(&project, "SourceProbe");
    let offset: usize = module.text_offset.expect("text offset present");
    assert!(
        offset > 0,
        "the CompressedSourceCode begins after the p-code PerformanceCache, so TextOffset must be non-zero (got {offset})"
    );
    assert!(
        !module.recovered_source.contains('\u{fffd}'),
        "decompressing from TextOffset must yield clean text, not p-code bytes"
    );
}

#[test]
fn megafile_multi_module_class_and_standard_recover() {
    let container: Vec<u8> = read_corpus("vba/megafile.docm");
    let project: ExtractedProject = extract_from_bytes(&container).expect("extract megafile docm");
    let edge: &ExtractedModule = module_named(&project, "EdgeCases");
    let greet: &ExtractedModule = module_named(&project, "GreetingTemplate");

    let edge_authored: String = read_corpus_text("vba/megafile/EdgeCases.bas");
    assert_source_matches_modulo_case(&edge_authored, &edge.recovered_source, "EdgeCases");

    for needle in [
        "Public Function Render() As String",
        "Public Property Let Mood",
        "RaiseEvent MoodChanged",
    ] {
        assert!(
            greet
                .recovered_source
                .to_ascii_lowercase()
                .contains(&needle.to_ascii_lowercase()),
            "class module missing {needle:?}; got:\n{}",
            greet.recovered_source
        );
    }
}

fn assert_source_matches_modulo_case(authored: &str, recovered: &str, label: &str) {
    let strip_comments = |text: &str| -> Vec<String> {
        text.lines()
            .map(|l: &str| l.trim_end().to_ascii_lowercase())
            .filter(|l: &String| !l.trim_start().starts_with('\''))
            .filter(|l: &String| !l.trim().is_empty())
            .collect::<Vec<String>>()
    };
    let a: Vec<String> = strip_comments(authored);
    let r: Vec<String> = strip_comments(recovered);
    let recovered_set: std::collections::BTreeSet<&String> = r.iter().collect();
    let mut missing: Vec<&String> = a
        .iter()
        .filter(|line: &&String| !recovered_set.contains(*line))
        .collect();
    missing.dedup();
    assert!(
        missing.len() <= 2,
        "{label}: authored lines not present in recovered source (modulo case/comments): {missing:?}"
    );
}
