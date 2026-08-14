#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use disrobe_pass_scriptlang::lang::tcl::{
    StarkitContainer, StarkitEntry, StarkitFormat, extract, has_starkit_header, is_starkit,
};
use disrobe_pass_scriptlang::lang::{ScriptArtifact, ScriptLang, analyze, classify};

const HELLO_KIT: &[u8] = include_bytes!("fixtures/hello.kit");
const MAIN_TCL_BODY: &[u8] = include_bytes!("fixtures/starkit_src_main.tcl");
const UTIL_TCL_BODY: &[u8] = include_bytes!("fixtures/starkit_src_util.tcl");
const SDX_KIT: &[u8] = include_bytes!("fixtures/sdx.kit");

fn entry<'a>(c: &'a StarkitContainer, path: &str) -> &'a StarkitEntry {
    c.entries
        .iter()
        .find(|e: &&StarkitEntry| e.path == path)
        .unwrap_or_else(|| {
            panic!(
                "entry '{path}' must be present; got {:?}",
                c.entries.iter().map(|e| &e.path).collect::<Vec<_>>()
            )
        })
}

#[test]
fn real_starkit_is_detected() {
    assert!(is_starkit(HELLO_KIT));
    assert!(has_starkit_header(HELLO_KIT));
    assert_eq!(classify(HELLO_KIT), Some(ScriptLang::Tcl));
}

#[test]
fn real_starkit_is_zip_vfs() {
    let c: StarkitContainer = extract(HELLO_KIT).expect("extract");
    assert_eq!(c.format, StarkitFormat::ZipVfs);
    assert!(c.has_starkit_header);
}

#[test]
fn real_starkit_extract_byte_identical_oracle() {
    let c: StarkitContainer = extract(HELLO_KIT).expect("extract");
    let main: &StarkitEntry = entry(&c, "app/main.tcl");
    assert_eq!(
        main.contents, MAIN_TCL_BODY,
        "extracted app/main.tcl must be byte-identical to the wrapped source"
    );
    let util: &StarkitEntry = entry(&c, "app/lib/util.tcl");
    assert_eq!(
        util.contents, UTIL_TCL_BODY,
        "extracted app/lib/util.tcl must be byte-identical to the wrapped source"
    );
}

#[test]
fn real_starkit_lists_tcl_sources() {
    let c: StarkitContainer = extract(HELLO_KIT).expect("extract");
    assert!(
        c.tcl_source_files
            .iter()
            .any(|p: &String| p == "app/main.tcl")
    );
    assert!(
        c.tcl_source_files
            .iter()
            .any(|p: &String| p == "app/lib/util.tcl")
    );
    assert_eq!(c.tcl_source_files.len(), 2);
}

#[test]
fn real_metakit_sdx_kit_is_detected() {
    assert!(is_starkit(SDX_KIT));
    assert!(has_starkit_header(SDX_KIT));
    assert_eq!(classify(SDX_KIT), Some(ScriptLang::Tcl));
}

#[test]
fn real_metakit_sdx_kit_recovers_tcl_members_under_their_directories() {
    let c: StarkitContainer = extract(SDX_KIT).expect("extract sdx.kit");
    assert_eq!(c.format, StarkitFormat::Metakit);
    for expected in [
        "lib/sdx/sdx.tcl",
        "lib/base64/base64.tcl",
        "lib/ftpd/ftpd.tcl",
        "lib/app-sdx/httpd.tcl",
        "lib/wikit/gui.tcl",
    ] {
        assert!(
            c.tcl_source_files.iter().any(|p: &String| p == expected),
            "real starkit member '{expected}' must be recovered from the Metakit directory; got {} files",
            c.tcl_source_files.len()
        );
    }
    assert!(
        c.tcl_source_files.len() >= 40,
        "sdx.kit ships dozens of .tcl modules; recovered {}",
        c.tcl_source_files.len()
    );
}

#[test]
fn real_starkit_analyze_returns_tcl_artifact() {
    let art: ScriptArtifact = analyze(HELLO_KIT).expect("analyze");
    match art {
        ScriptArtifact::Tcl(c) => assert_eq!(c.entries.len(), 2),
        other => panic!("expected Tcl artifact, got {other:?}"),
    }
}

#[test]
fn real_clean_starkit_is_not_flagged_obfuscated() {
    let c: StarkitContainer = extract(HELLO_KIT).expect("extract");
    assert!(
        !c.obfuscation.obfuscated,
        "the hello.kit demo source is ordinary tcl and must not be flagged: {:?}",
        c.obfuscation
    );
}

#[test]
fn real_zip_starkit_extraction_is_byte_complete() {
    let c: StarkitContainer = extract(HELLO_KIT).expect("extract");
    assert_eq!(c.completeness.declared_entries, 2);
    assert_eq!(
        c.completeness.recovered_with_contents, 2,
        "every zipvfs member's bytes are recovered in full"
    );
    assert!((c.completeness.ratio() - 1.0).abs() < f64::EPSILON);
}

#[test]
fn real_metakit_extraction_is_byte_complete() {
    let c: StarkitContainer = extract(SDX_KIT).expect("extract sdx.kit");
    assert_eq!(c.format, StarkitFormat::Metakit);
    assert!(
        c.completeness.declared_entries >= 40,
        "the metakit directory lists dozens of members; got {}",
        c.completeness.declared_entries
    );
    assert_eq!(
        c.completeness.recovered_with_contents, c.completeness.declared_entries,
        "every member the metakit directory lists must come back with its bytes"
    );
    assert!((c.completeness.ratio() - 1.0).abs() < f64::EPSILON);
    let main: &StarkitEntry = entry(&c, "main.tcl");
    assert!(
        main.contents.starts_with(b"package require starkit"),
        "the recovered entry point must be the real starkit main script"
    );
}
