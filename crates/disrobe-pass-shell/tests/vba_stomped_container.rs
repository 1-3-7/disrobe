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

use std::fmt::Write as _;

use disrobe_pass_shell::{
    Error, ExtractedModule, ExtractedProject, ModuleStompReport, StompReport, StompVerdict,
    analyze_stomp, extract_from_bytes,
};

use vba_source_grade::{Grade, assert_line_match, grade, read_authored, read_corpus};
use vba_stomp_harness::{
    dir_stream_declaring, module_text_offset, ovba_compress, repack_ooxml_with_vba_project,
    replace_dir_stream, stomp_by_truncating_at_source, stomp_to_empty_source,
    stomp_with_decoy_source, stomp_with_junk_source, vba_project_of,
};

const HELLO_MODULE: &str = "Module1";
const EDGECASES_MODULE: &str = "EdgeCases";
const SOURCEPROBE_MODULE: &str = "SourceProbe";

const EDGECASES_AUTHORED_LINES: usize = 552;
const SOURCEPROBE_AUTHORED_LINES: usize = 71;
const PCODE_ONLY_FLOOR_PCT: f64 = 100.0;

const SHORT_DECOY: &str = "Attribute VB_Name = \"Module1\"\nSub Harmless()\nEnd Sub\n";
const BENIGN_DECOY: &str = "Attribute VB_Name = \"Module1\"\nSub Harmless()\n    Debug.Print \"nothing to see\"\nEnd Sub\n";

fn long_decoy(module: &str, at_least: usize) -> String {
    let mut text: String = format!("Attribute VB_Name = \"{module}\"\nSub Harmless()\n");
    let mut filler: usize = 0;
    while text.len() < at_least {
        writeln!(text, "    ' decoy padding line {filler}").expect("write to a String");
        filler += 1;
    }
    text.push_str("End Sub\n");
    text
}

fn module_report<'a>(report: &'a StompReport, module: &str) -> &'a ModuleStompReport {
    report
        .modules
        .iter()
        .find(|m: &&ModuleStompReport| m.module.eq_ignore_ascii_case(module))
        .unwrap_or_else(|| {
            panic!(
                "module {module} missing from the stomp report; present={:?}",
                report
                    .modules
                    .iter()
                    .map(|m: &ModuleStompReport| m.module.as_str())
                    .collect::<Vec<&str>>()
            )
        })
}

fn extracted<'a>(project: &'a ExtractedProject, module: &str) -> &'a ExtractedModule {
    project
        .modules
        .iter()
        .find(|m: &&ExtractedModule| m.name.eq_ignore_ascii_case(module))
        .unwrap_or_else(|| panic!("module {module} missing from the extracted project"))
}

fn hello_variants() -> Vec<(&'static str, Vec<u8>)> {
    let raw: Vec<u8> = read_corpus("vba/vbaProject.bin");
    let offset: usize = module_text_offset(&raw, HELLO_MODULE);
    vec![
        (
            "decoy shorter than the original",
            stomp_with_decoy_source(&raw, HELLO_MODULE, offset, SHORT_DECOY),
        ),
        (
            "decoy longer than the original",
            stomp_with_decoy_source(
                &raw,
                HELLO_MODULE,
                offset,
                &long_decoy(HELLO_MODULE, raw.len()),
            ),
        ),
        (
            "source replaced with an empty module",
            stomp_to_empty_source(&raw, HELLO_MODULE, offset),
        ),
        (
            "source replaced with a benign decoy",
            stomp_with_decoy_source(&raw, HELLO_MODULE, offset, BENIGN_DECOY),
        ),
        (
            "source overwritten with bytes that are not a compressed container",
            stomp_with_junk_source(&raw, HELLO_MODULE, offset),
        ),
        (
            "module stream truncated so TextOffset runs past its end",
            stomp_by_truncating_at_source(&raw, HELLO_MODULE, offset),
        ),
    ]
}

#[test]
fn every_stomping_variant_recovers_the_behavior_from_pcode() {
    for (label, stomped) in hello_variants() {
        let report: StompReport = analyze_stomp(&stomped)
            .unwrap_or_else(|e: Error| panic!("{label}: analyze_stomp refused the document: {e}"));
        let module: &ModuleStompReport = module_report(&report, HELLO_MODULE);
        assert_eq!(
            module.verdict,
            StompVerdict::Stomped,
            "{label}: a stomped module must be reported as stomped; report={module:?}"
        );
        assert!(
            report.any_stomped,
            "{label}: the project-level stomp flag must be raised"
        );
        assert!(
            module.recovered_source.contains("MsgBox \"hello world\""),
            "{label}: p-code must still carry the behavior the stomp removed; got:\n{}",
            module.recovered_source
        );
        assert!(
            module
                .pcode_only_strings
                .contains(&"hello world".to_owned()),
            "{label}: the string the stomp removed must be listed as p-code-only; got {:?}",
            module.pcode_only_strings
        );
    }
}

#[test]
fn a_decoy_that_keeps_the_real_procedure_name_is_still_flagged() {
    let raw: Vec<u8> = read_corpus("vba/vbaProject.bin");
    let clean: StompReport = analyze_stomp(&raw).expect("analyze the clean project");
    let procedures: Vec<String> = module_report(&clean, HELLO_MODULE).pcode_procedures.clone();
    assert!(
        !procedures.is_empty(),
        "the corpus module must declare at least one procedure to impersonate"
    );
    let mut decoy: String = format!("Attribute VB_Name = \"{HELLO_MODULE}\"\n");
    for name in &procedures {
        write!(
            decoy,
            "Sub {name}()\n    MsgBox \"nothing to see\"\nEnd Sub\n"
        )
        .expect("write to a String");
    }
    let offset: usize = module_text_offset(&raw, HELLO_MODULE);
    let stomped: Vec<u8> = stomp_with_decoy_source(&raw, HELLO_MODULE, offset, &decoy);
    let report: StompReport = analyze_stomp(&stomped).expect("analyze the impersonating decoy");
    let module: &ModuleStompReport = module_report(&report, HELLO_MODULE);
    assert!(
        module.pcode_only_procedures.is_empty(),
        "the decoy keeps every procedure name, so the procedure channel must not be what fires"
    );
    assert_eq!(
        module.verdict,
        StompVerdict::Stomped,
        "a decoy that keeps the entry-point name but changes the body must still be flagged; \
         report={module:?}"
    );
    assert!(
        module
            .pcode_only_strings
            .contains(&"hello world".to_owned()),
        "the behavior the decoy hid must be listed; got {:?}",
        module.pcode_only_strings
    );
}

#[test]
fn an_undecodable_source_stream_names_its_reason_instead_of_failing_the_project() {
    let raw: Vec<u8> = read_corpus("vba/vbaProject.bin");
    let offset: usize = module_text_offset(&raw, HELLO_MODULE);
    for (label, stomped, needle) in [
        (
            "junk overwrite",
            stomp_with_junk_source(&raw, HELLO_MODULE, offset),
            "signature byte",
        ),
        (
            "truncated module stream",
            stomp_by_truncating_at_source(&raw, HELLO_MODULE, offset),
            "TextOffset",
        ),
    ] {
        let project: ExtractedProject = extract_from_bytes(&stomped).unwrap_or_else(|e: Error| {
            panic!("{label}: one damaged module must not fail extraction: {e}")
        });
        let module: &ExtractedModule = extracted(&project, HELLO_MODULE);
        let reason: &str = module
            .source_error
            .as_deref()
            .unwrap_or_else(|| panic!("{label}: the damaged module must record why it failed"));
        assert!(
            reason.contains(needle),
            "{label}: the recorded reason must name the failure; got {reason:?}"
        );
        assert!(
            module.recovered_source.is_empty(),
            "{label}: a module whose source did not decode must not report source text"
        );
        let report: StompReport = analyze_stomp(&stomped).expect("analyze the stomped project");
        let stomp: &ModuleStompReport = module_report(&report, HELLO_MODULE);
        assert!(
            stomp.evidence.iter().any(|e: &String| e.contains(needle)),
            "{label}: the stomp evidence must repeat the decode failure; evidence={:?}",
            stomp.evidence
        );
    }
}

#[test]
fn stomping_one_module_leaves_its_siblings_readable() {
    let raw: Vec<u8> = read_corpus("vba/vbaProject.bin");
    let clean: ExtractedProject = extract_from_bytes(&raw).expect("extract the clean project");
    let sibling_before: String = extracted(&clean, "ThisDocument").recovered_source.clone();
    assert!(
        !sibling_before.trim().is_empty(),
        "the corpus sibling module must carry source before the stomp"
    );
    let offset: usize = module_text_offset(&raw, HELLO_MODULE);
    let stomped: Vec<u8> = stomp_with_junk_source(&raw, HELLO_MODULE, offset);
    let after: ExtractedProject =
        extract_from_bytes(&stomped).expect("extract the partially stomped project");
    let sibling_after: &ExtractedModule = extracted(&after, "ThisDocument");
    assert_eq!(
        sibling_after.recovered_source, sibling_before,
        "a damaged sibling must not take the rest of the project down with it"
    );
    assert!(
        sibling_after.source_error.is_none(),
        "an intact module must not carry a source error"
    );
}

fn stomped_docm(relative: &str, module: &str) -> Vec<u8> {
    let container: Vec<u8> = read_corpus(relative);
    let offset: usize = module_text_offset(&container, module);
    let project_bin: Vec<u8> = vba_project_of(&container);
    let stomped_bin: Vec<u8> = stomp_with_junk_source(&project_bin, module, offset);
    repack_ooxml_with_vba_project(&container, &stomped_bin)
}

#[test]
fn a_stomped_docm_recovers_every_authored_line_of_the_module_from_pcode() {
    let stomped: Vec<u8> = stomped_docm("vba/megafile.docm", EDGECASES_MODULE);
    let report: StompReport = analyze_stomp(&stomped).expect("analyze the stomped docm");
    let module: &ModuleStompReport = module_report(&report, EDGECASES_MODULE);
    assert_eq!(module.verdict, StompVerdict::Stomped);
    let authored: String = read_authored("vba/megafile/EdgeCases.bas");
    let g: Grade = grade(&module.recovered_source, &authored);
    assert_line_match(
        "EdgeCases under a stomped docm",
        &g,
        PCODE_ONLY_FLOOR_PCT,
        EDGECASES_AUTHORED_LINES,
    );
    let sibling: &ModuleStompReport = module_report(&report, "GreetingTemplate");
    assert_eq!(
        sibling.verdict,
        StompVerdict::Consistent,
        "the untouched class module must stay consistent; report={sibling:?}"
    );
}

#[test]
fn a_clean_multi_module_document_flags_nothing() {
    let clean: Vec<u8> = read_corpus("vba/megafile.docm");
    let report: StompReport = analyze_stomp(&clean).expect("analyze the clean docm");
    let flagged: Vec<(&str, StompVerdict)> = report
        .modules
        .iter()
        .filter(|m: &&ModuleStompReport| m.verdict != StompVerdict::Consistent)
        .map(|m: &ModuleStompReport| (m.module.as_str(), m.verdict))
        .collect();
    assert!(
        flagged.is_empty(),
        "an unstomped document must not raise a stomp verdict; flagged={flagged:?}"
    );
}

#[test]
fn a_stomped_xlsm_recovers_every_authored_line_of_the_module_from_pcode() {
    let stomped: Vec<u8> = stomped_docm("vba/sourceprobe.xlsm", SOURCEPROBE_MODULE);
    let report: StompReport = analyze_stomp(&stomped).expect("analyze the stomped xlsm");
    let module: &ModuleStompReport = module_report(&report, SOURCEPROBE_MODULE);
    assert_eq!(module.verdict, StompVerdict::Stomped);
    let authored: String = read_authored("vba/sourceprobe/SourceProbe.bas");
    let g: Grade = grade(&module.recovered_source, &authored);
    assert_line_match(
        "SourceProbe under a stomped xlsm",
        &g,
        PCODE_ONLY_FLOOR_PCT,
        SOURCEPROBE_AUTHORED_LINES,
    );
}

#[test]
fn recovered_source_is_identical_across_every_stomping_variant() {
    let raw: Vec<u8> = read_corpus("vba/vbaProject.bin");
    let clean: StompReport = analyze_stomp(&raw).expect("analyze the clean project");
    let expected: &str = module_report(&clean, HELLO_MODULE)
        .recovered_source
        .as_str();
    for (label, stomped) in hello_variants() {
        let report: StompReport =
            analyze_stomp(&stomped).unwrap_or_else(|e: Error| panic!("{label}: {e}"));
        assert_eq!(
            module_report(&report, HELLO_MODULE).recovered_source,
            expected,
            "{label}: p-code recovery must not depend on what the stomp wrote over the source"
        );
    }
}

#[test]
fn analyzing_the_same_stomped_document_twice_gives_the_same_report() {
    let raw: Vec<u8> = read_corpus("vba/vbaProject.bin");
    let offset: usize = module_text_offset(&raw, HELLO_MODULE);
    let stomped: Vec<u8> = stomp_with_junk_source(&raw, HELLO_MODULE, offset);
    let first: String = serde_json::to_string(&analyze_stomp(&stomped).expect("first pass"))
        .expect("serialize first report");
    let second: String = serde_json::to_string(&analyze_stomp(&stomped).expect("second pass"))
        .expect("serialize second report");
    assert_eq!(first, second, "stomp analysis must be deterministic");
}

#[test]
fn a_decoy_written_by_the_harness_reads_back_through_the_product_decompressor() {
    let raw: Vec<u8> = read_corpus("vba/vbaProject.bin");
    let offset: usize = module_text_offset(&raw, HELLO_MODULE);
    for decoy in [
        String::new(),
        "A".to_owned(),
        SHORT_DECOY.to_owned(),
        "B".repeat(3639),
        "C".repeat(3640),
        "D".repeat(3641),
        long_decoy(HELLO_MODULE, 20_000),
    ] {
        let stomped: Vec<u8> = stomp_with_decoy_source(&raw, HELLO_MODULE, offset, &decoy);
        let project: ExtractedProject =
            extract_from_bytes(&stomped).expect("extract the decoy project");
        let module: &ExtractedModule = extracted(&project, HELLO_MODULE);
        assert_eq!(
            module.source_error, None,
            "a decoy written as a valid compressed container must decode"
        );
        assert_eq!(
            module.recovered_source,
            decoy,
            "decoy of {} bytes did not round-trip through the product decompressor",
            decoy.len()
        );
    }
}

#[test]
fn a_destroyed_module_table_reports_nothing_rather_than_raw_stream_bytes() {
    let raw: Vec<u8> = read_corpus("vba/vbaProject.bin");
    let no_table: Vec<u8> = replace_dir_stream(&raw, b"no module table here");
    let project: ExtractedProject =
        extract_from_bytes(&no_table).expect("a damaged dir stream must not fail extraction");
    let module: &ExtractedModule = extracted(&project, HELLO_MODULE);
    assert!(
        module.source_error.is_some(),
        "a module stream that is not a compressed container must record why it did not decode"
    );
    assert!(
        module.recovered_source.is_empty(),
        "raw p-code bytes must never be presented as recovered VBA source; got {:?}",
        module.recovered_source
    );
    let report: StompReport = analyze_stomp(&no_table).expect("analyze the damaged project");
    assert!(
        report.modules.is_empty(),
        "module enumeration reads the dir stream, so destroying it costs the p-code side too; \
         this pins that limitation rather than hiding it behind a partial answer, present={:?}",
        report
            .modules
            .iter()
            .map(|m: &ModuleStompReport| m.module.as_str())
            .collect::<Vec<&str>>()
    );
}

const MAX_MODULE_REFS: usize = 512;

#[test]
fn a_dir_stream_declaring_more_modules_than_the_cap_is_refused() {
    let raw: Vec<u8> = read_corpus("vba/vbaProject.bin");
    let at_cap: Vec<u8> = replace_dir_stream(&raw, &dir_stream_declaring(MAX_MODULE_REFS));
    let accepted: ExtractedProject =
        extract_from_bytes(&at_cap).expect("a project exactly at the cap must still be read");
    assert_eq!(accepted.modules.len(), MAX_MODULE_REFS);
    assert!(
        accepted
            .modules
            .iter()
            .all(|m: &ExtractedModule| m.source_error.is_some()),
        "every declared module points at a stream that does not exist, so each must record why"
    );
    let over_cap: Vec<u8> = replace_dir_stream(&raw, &dir_stream_declaring(MAX_MODULE_REFS + 1));
    let refusal: Error = extract_from_bytes(&over_cap)
        .expect_err("a project above the cap must be refused, not walked");
    let text: String = refusal.to_string();
    assert!(
        text.contains(&MAX_MODULE_REFS.to_string()),
        "the refusal must name the cap it enforced; got {text:?}"
    );
}

#[test]
fn the_harness_compressor_emits_the_documented_chunk_header() {
    assert_eq!(ovba_compress(b""), vec![0x01_u8]);
    let one: Vec<u8> = ovba_compress(b"A");
    assert_eq!(one, vec![0x01, 0x01, 0xB0, 0x00, b'A']);
    let nine: Vec<u8> = ovba_compress(b"ABCDEFGHI");
    assert_eq!(nine.len(), 1 + 2 + 2 + 9);
    assert_eq!(u16::from_le_bytes([nine[1], nine[2]]), 0xB000 | 0x000A);
}
