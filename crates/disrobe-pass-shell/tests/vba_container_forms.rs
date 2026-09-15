#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

#[path = "support/vba_source_grade.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod vba_source_grade;

#[path = "support/vba_stomp_harness.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod vba_stomp_harness;

use disrobe_pass_shell::{
    ContainerKind, Error, ExtractedProject, ModuleStompReport, PCodeWall, PCodeWallDetail,
    RealPCodeReport, StompReport, StompVerdict, analyze_stomp, disassemble_pcode_real,
    extract_from_bytes,
};

use vba_source_grade::read_corpus;
use vba_stomp_harness::{
    SECOND_PROJECT_STORAGE, legacy_doc_container, legacy_xls_container, module_text_offset,
    pptm_container, repack_ooxml_with_vba_project, stomp_by_truncating_at_source,
    stomp_to_empty_source, stomp_with_decoy_source, stomp_with_junk_source, two_project_container,
};

const HELLO_MODULE: &str = "Module1";
const BENIGN_DECOY: &str = "Attribute VB_Name = \"Module1\"\nSub Harmless()\n    Debug.Print \"nothing to see\"\nEnd Sub\n";
const RECOVERED_BEHAVIOR: &str = "MsgBox \"hello world\"";
const RECOVERED_STRING: &str = "hello world";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form {
    RawVbaProject,
    Docm,
    Xlsm,
    Pptm,
    LegacyDoc,
    LegacyXls,
}

impl Form {
    const fn label(self) -> &'static str {
        match self {
            Self::RawVbaProject => "bare vbaProject.bin",
            Self::Docm => "docm",
            Self::Xlsm => "xlsm",
            Self::Pptm => "pptm",
            Self::LegacyDoc => "legacy .doc OLE (Macros storage)",
            Self::LegacyXls => "legacy .xls OLE (_VBA_PROJECT_CUR storage)",
        }
    }

    const fn expected_kind(self) -> ContainerKind {
        match self {
            Self::Docm | Self::Xlsm | Self::Pptm => ContainerKind::OoxmlZip,
            Self::RawVbaProject | Self::LegacyDoc | Self::LegacyXls => {
                ContainerKind::OleCompoundFile
            }
        }
    }
}

const EVERY_FORM: [Form; 6] = [
    Form::RawVbaProject,
    Form::Docm,
    Form::Xlsm,
    Form::Pptm,
    Form::LegacyDoc,
    Form::LegacyXls,
];

fn hello_project() -> Vec<u8> {
    read_corpus("vba/vbaProject.bin")
}

fn wrap(form: Form, project: &[u8]) -> Vec<u8> {
    match form {
        Form::RawVbaProject => project.to_vec(),
        Form::Docm => repack_ooxml_with_vba_project(&read_corpus("vba/hello.docm"), project),
        Form::Xlsm => repack_ooxml_with_vba_project(&read_corpus("vba/sourceprobe.xlsm"), project),
        Form::Pptm => pptm_container(project),
        Form::LegacyDoc => legacy_doc_container(project),
        Form::LegacyXls => legacy_xls_container(project),
    }
}

fn module_report<'a>(report: &'a StompReport, module: &str) -> &'a ModuleStompReport {
    report
        .modules
        .iter()
        .find(|m: &&ModuleStompReport| m.module.eq_ignore_ascii_case(module))
        .unwrap_or_else(|| {
            panic!(
                "module {module} missing from the report; present={:?}",
                report
                    .modules
                    .iter()
                    .map(|m: &ModuleStompReport| m.module.as_str())
                    .collect::<Vec<&str>>()
            )
        })
}

#[test]
fn every_declared_container_form_reaches_the_same_module_set() {
    let project: Vec<u8> = hello_project();
    let baseline: Vec<String> = extract_from_bytes(&project)
        .expect("extract the bare project")
        .modules
        .iter()
        .map(|m: &disrobe_pass_shell::ExtractedModule| m.name.to_ascii_lowercase())
        .collect();
    assert!(
        baseline.len() >= 2,
        "the corpus project must carry more than one module for this to mean anything; got \
         {baseline:?}"
    );
    for form in EVERY_FORM {
        let container: Vec<u8> = wrap(form, &project);
        let extracted: ExtractedProject = extract_from_bytes(&container)
            .unwrap_or_else(|e: Error| panic!("{}: extraction refused: {e}", form.label()));
        assert_eq!(
            extracted.container_kind,
            form.expected_kind(),
            "{}: container kind misread",
            form.label()
        );
        let names: Vec<String> = extracted
            .modules
            .iter()
            .map(|m: &disrobe_pass_shell::ExtractedModule| m.name.to_ascii_lowercase())
            .collect();
        assert_eq!(
            names,
            baseline,
            "{}: the container form must not change which modules are found",
            form.label()
        );
    }
}

#[test]
fn every_declared_container_form_disassembles_the_same_pcode() {
    let project: Vec<u8> = hello_project();
    let baseline: String = module_report(
        &analyze_stomp(&project).expect("analyze the bare project"),
        HELLO_MODULE,
    )
    .recovered_source
    .clone();
    assert!(
        baseline.contains(RECOVERED_BEHAVIOR),
        "the baseline recovery must carry the behavior under test; got:\n{baseline}"
    );
    for form in EVERY_FORM {
        let container: Vec<u8> = wrap(form, &project);
        let report: StompReport = analyze_stomp(&container)
            .unwrap_or_else(|e: Error| panic!("{}: analyze_stomp refused: {e}", form.label()));
        assert_eq!(
            module_report(&report, HELLO_MODULE).recovered_source,
            baseline,
            "{}: p-code recovery must not depend on the container that carries the project",
            form.label()
        );
    }
}

fn stomping_variants(project: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let offset: usize = module_text_offset(project, HELLO_MODULE);
    vec![
        (
            "benign decoy",
            stomp_with_decoy_source(project, HELLO_MODULE, offset, BENIGN_DECOY),
        ),
        (
            "empty module",
            stomp_to_empty_source(project, HELLO_MODULE, offset),
        ),
        (
            "junk overwrite",
            stomp_with_junk_source(project, HELLO_MODULE, offset),
        ),
        (
            "truncated at TextOffset",
            stomp_by_truncating_at_source(project, HELLO_MODULE, offset),
        ),
    ]
}

#[test]
fn every_stomping_variant_is_recovered_in_every_container_form() {
    let project: Vec<u8> = hello_project();
    let mut graded: usize = 0;
    for (variant, stomped_project) in stomping_variants(&project) {
        for form in EVERY_FORM {
            let container: Vec<u8> = wrap(form, &stomped_project);
            let tag: String = format!("{} / {variant}", form.label());
            let report: StompReport = analyze_stomp(&container)
                .unwrap_or_else(|e: Error| panic!("{tag}: analyze_stomp refused: {e}"));
            let module: &ModuleStompReport = module_report(&report, HELLO_MODULE);
            assert_eq!(
                module.verdict,
                StompVerdict::Stomped,
                "{tag}: a stomped module must be reported as stomped; report={module:?}"
            );
            assert!(
                report.any_stomped,
                "{tag}: the project-level stomp flag must be raised"
            );
            assert!(
                module.recovered_source.contains(RECOVERED_BEHAVIOR),
                "{tag}: p-code must still carry the behavior the stomp removed; got:\n{}",
                module.recovered_source
            );
            assert!(
                module
                    .pcode_only_strings
                    .contains(&RECOVERED_STRING.to_owned()),
                "{tag}: the string the stomp removed must be listed as p-code-only; got {:?}",
                module.pcode_only_strings
            );
            graded += 1;
        }
    }
    assert_eq!(
        graded,
        4 * EVERY_FORM.len(),
        "every stomping variant must be graded in every container form; the product is pinned so \
         a dropped form cannot shrink the matrix"
    );
}

#[cfg(feature = "chain")]
#[test]
fn the_registered_shell_pass_recovers_a_stomped_legacy_container() {
    use disrobe_core::chain::Pass as _;
    use disrobe_core::{Artifact, Rung};
    use disrobe_pass_shell::chain_detector::SHELL_PASS;

    let project: Vec<u8> = hello_project();
    let offset: usize = module_text_offset(&project, HELLO_MODULE);
    let stomped_project: Vec<u8> = stomp_with_junk_source(&project, HELLO_MODULE, offset);
    for form in [Form::LegacyDoc, Form::LegacyXls, Form::Pptm] {
        let container: Vec<u8> = wrap(form, &stomped_project);
        let input: Artifact = Artifact::new(Rung::Raw, container, [0_u8; 32]);
        let output: Artifact = SHELL_PASS
            .run(&input)
            .unwrap_or_else(|e| panic!("{}: the registered pass refused: {e}", form.label()));
        let text: String = String::from_utf8_lossy(output.envelope.as_slice()).into_owned();
        assert!(
            text.contains(RECOVERED_BEHAVIOR),
            "{}: the pass that disrobe auto runs must surface the p-code-only recovery, not only \
             the library entry point; got:\n{text}",
            form.label()
        );
    }
}

#[test]
fn a_container_holding_two_vba_projects_names_the_one_it_left_unread() {
    let project: Vec<u8> = hello_project();
    let single: Vec<u8> = legacy_doc_container(&project);
    let both: Vec<u8> = two_project_container(&project);
    let one: RealPCodeReport =
        disassemble_pcode_real(&single).expect("disassemble the single-project container");
    assert!(
        one.walls
            .iter()
            .all(|w: &PCodeWallDetail| w.kind != PCodeWall::MultipleVbaProjects),
        "one project must not raise the several-projects wall; walls={:?}",
        one.walls
    );
    let two: RealPCodeReport =
        disassemble_pcode_real(&both).expect("disassemble the two-project container");
    let flagged: Vec<&PCodeWallDetail> = two
        .walls
        .iter()
        .filter(|w: &&PCodeWallDetail| w.kind == PCodeWall::MultipleVbaProjects)
        .collect();
    assert_eq!(
        flagged.len(),
        1,
        "a container with two VBA projects must raise exactly one wall; walls={:?}",
        two.walls
    );
    assert!(
        flagged[0].reason.contains(SECOND_PROJECT_STORAGE),
        "the wall must name the storage recovery did not read; got {:?}",
        flagged[0].reason
    );
    assert_eq!(
        two.modules.len(),
        one.modules.len(),
        "the project that was read must still be disassembled in full"
    );
}

#[test]
fn a_legacy_container_without_a_vba_storage_names_what_it_could_not_find() {
    let project: Vec<u8> = hello_project();
    let mut mangled: Vec<u8> = legacy_doc_container(&project);
    let marker: &[u8] = b"_\0V\0B\0A\0_\0P\0R\0O\0J\0E\0C\0T\0";
    let at: usize = mangled
        .windows(marker.len())
        .position(|w: &[u8]| w == marker)
        .expect("the legacy container must name its _VBA_PROJECT stream in the directory");
    mangled[at] = b'X';
    let refusal: Error = disrobe_pass_shell::disassemble_pcode_real(&mangled)
        .expect_err("a container with no _VBA_PROJECT stream must be refused, not guessed at");
    let text: String = refusal.to_string();
    assert!(
        text.contains("_VBA_PROJECT"),
        "the refusal must name the stream it needed; got {text:?}"
    );
}
