#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use disrobe_pass_nativelang::{NativeLang, NativeLangAnalysis, analyze};

struct ModeSpec {
    flag: &'static str,
    present: &'static [&'static str],
    absent: &'static [&'static str],
    surfaced: &'static [&'static str],
}

const MODES: &[ModeSpec] = &[
    ModeSpec {
        flag: "orc",
        present: &[
            "nimNewObj",
            "nimRawDispose",
            "collectCyclesBacon",
            "rememberCycle",
        ],
        absent: &[],
        surfaced: &["nimNewObj", "collectCyclesBacon"],
    },
    ModeSpec {
        flag: "arc",
        present: &["nimNewObj", "nimRawDispose", "nimDestroyAndDispose"],
        absent: &["collectCyclesBacon", "rememberCycle"],
        surfaced: &["nimNewObj"],
    },
    ModeSpec {
        flag: "refc",
        present: &["nimGCunref", "newObjRC1", "nimGCvisit"],
        absent: &["nimNewObj"],
        surfaced: &["nimGCunref", "newObjRC1"],
    },
    ModeSpec {
        flag: "markAndSweep",
        present: &["nimGCunref", "markGlobals"],
        absent: &["newObjRC1", "nimNewObj"],
        surfaced: &["nimGCunref"],
    },
    ModeSpec {
        flag: "none",
        present: &[],
        absent: &[
            "nimGCunref",
            "nimNewObj",
            "boehmgc",
            "nimGC_setStackBottom",
            "nimGCvisit",
        ],
        surfaced: &[],
    },
    ModeSpec {
        flag: "boehm",
        present: &["boehmgc"],
        absent: &["nimGCunref", "nimNewObj"],
        surfaced: &["boehmgc"],
    },
    ModeSpec {
        flag: "go",
        present: &["newObjRC1", "nimGC_setStackBottom", "nimGCvisit"],
        absent: &["nimGCunref", "nimNewObj", "boehmgc"],
        surfaced: &["newObjRC1", "nimGC_setStackBottom"],
    },
];

fn fixture_bytes(flag: &str) -> Vec<u8> {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p.push("nim_mm");
    p.push(format!("mm_{flag}.exe"));
    std::fs::read(&p).unwrap_or_else(|e: std::io::Error| {
        panic!("missing committed fixture {}: {e}", p.display())
    })
}

fn raw_has(bytes: &[u8], token: &str) -> bool {
    let needle: &[u8] = token.as_bytes();
    !needle.is_empty() && bytes.windows(needle.len()).any(|w: &[u8]| w == needle)
}

#[test]
fn nim_mm_modes_classify_to_the_build_flag() {
    let mut recovered: Vec<(&'static str, String)> = Vec::new();
    for spec in MODES {
        let bytes: Vec<u8> = fixture_bytes(spec.flag);
        assert_eq!(
            &bytes[..2],
            b"MZ",
            "mm_{}.exe must be a real PE built by the nim compiler",
            spec.flag
        );

        for token in spec.present {
            assert!(
                raw_has(&bytes, token),
                "mm_{}.exe: distinguishing symbol {token} must exist in the real nim binary \
                 (the classification keys on it)",
                spec.flag
            );
        }
        for token in spec.absent {
            assert!(
                !raw_has(&bytes, token),
                "mm_{}.exe: symbol {token} must be genuinely absent; its absence is what \
                 separates {} from a sibling mode",
                spec.flag,
                spec.flag
            );
        }

        let analysis: NativeLangAnalysis = analyze(&bytes).expect("analyze nim mm fixture");
        assert_eq!(
            analysis.fingerprint.lang,
            NativeLang::Nim,
            "mm_{}.exe must fingerprint as nim",
            spec.flag
        );

        let kind: &str = analysis.recovery.gc.gc_kind.as_deref().unwrap_or("<none>");
        assert_eq!(
            kind, spec.flag,
            "mm_{}.exe recovered gc_kind {kind} must equal the --mm:{} build flag",
            spec.flag, spec.flag
        );

        for token in spec.surfaced {
            assert!(
                analysis
                    .recovery
                    .gc
                    .runtime_symbols
                    .iter()
                    .any(|s: &String| s == token),
                "mm_{}.exe: classifier must surface distinguishing symbol {token}; got {:?}",
                spec.flag,
                analysis.recovery.gc.runtime_symbols
            );
        }

        recovered.push((spec.flag, kind.to_owned()));
    }

    for (flag, kind) in &recovered {
        assert_eq!(
            flag, kind,
            "build flag {flag} did not round-trip to gc_kind {kind}"
        );
    }
    let mut distinct: Vec<String> = recovered
        .iter()
        .map(|(_, k): &(_, String)| k.clone())
        .collect();
    distinct.sort();
    distinct.dedup();
    assert_eq!(
        distinct.len(),
        MODES.len(),
        "each --mm mode must recover a distinct gc_kind (no mode collapses onto another); got {recovered:?}"
    );
}

#[test]
fn nim_arc_is_distinguished_from_orc_by_absent_cycle_collector() {
    let arc: Vec<u8> = fixture_bytes("arc");
    let orc: Vec<u8> = fixture_bytes("orc");

    assert!(raw_has(&arc, "nimNewObj") && raw_has(&orc, "nimNewObj"));
    assert!(
        !raw_has(&arc, "collectCyclesBacon") && !raw_has(&arc, "rememberCycle"),
        "arc must not link the orc cycle collector"
    );
    assert!(
        raw_has(&orc, "collectCyclesBacon") && raw_has(&orc, "rememberCycle"),
        "orc must link the cycle collector"
    );

    let arc_kind: Option<String> = analyze(&arc).expect("analyze arc").recovery.gc.gc_kind;
    let orc_kind: Option<String> = analyze(&orc).expect("analyze orc").recovery.gc.gc_kind;
    assert_eq!(arc_kind.as_deref(), Some("arc"));
    assert_eq!(orc_kind.as_deref(), Some("orc"));
}

#[test]
fn nim_go_that_also_links_the_unref_slot_stays_go_not_refc() {
    let go: Vec<u8> = fixture_bytes("go_unref");
    assert_eq!(
        &go[..2],
        b"MZ",
        "mm_go_unref.exe must be a real nim-built PE"
    );

    assert!(
        raw_has(&go, "nimGCunref") && raw_has(&go, "newObjRC1"),
        "this go build links both nimGCunref and newObjRC1; that overlap is what a refc-keyed \
         classifier trips on"
    );
    assert!(
        !raw_has(&go, "collectCycles") && !raw_has(&go, "nimNewObj"),
        "the go collector links neither the refc cycle collector nor the arc allocator; their \
         absence is what keeps it separable from refc and arc"
    );

    let analysis: NativeLangAnalysis = analyze(&go).expect("analyze go_unref fixture");
    assert_eq!(analysis.fingerprint.lang, NativeLang::Nim);
    assert_eq!(
        analysis.recovery.gc.gc_kind.as_deref(),
        Some("go"),
        "a go binary that also links nimGCunref must recover as go, not refc; got {:?}",
        analysis.recovery.gc.gc_kind
    );
    assert!(
        analysis
            .recovery
            .gc
            .runtime_symbols
            .iter()
            .any(|s: &String| s == "newObjRC1"),
        "classifier must surface the go allocator marker newObjRC1; got {:?}",
        analysis.recovery.gc.runtime_symbols
    );
}
