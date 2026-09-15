#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;

use disrobe_pass_jvm::{
    DecompiledDex, DexFile, DexVersion, decompile_dex, parse_dex, parse_dex_header,
};

const CLEAN_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/obfuscators/r8/Widget-clean.dex");
const OBF_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/obfuscators/r8/Widget-r8.dex");
const R8_MAPPING: &str = include_str!("../../../corpus/jvm/dex/obfuscators/r8/mapping.txt");

const BANNER_FRAGMENT: &str = "R8_GAUNTLET_BANNER v5";

fn user_strings(dex: &DexFile) -> BTreeSet<String> {
    dex.strings
        .iter()
        .filter(|s: &&String| {
            s.contains("R8_GAUNTLET") || s.contains("tier:") || s.contains("Ledger")
        })
        .cloned()
        .collect()
}

#[test]
fn obf_dex_is_real_d8_dalvik_container() {
    assert_eq!(
        &OBF_DEX[..4],
        b"dex\n",
        "obf fixture must be a real DEX file"
    );
    assert_eq!(&OBF_DEX[4..7], b"035", "R8 min-api 21 emits dex 035");
    let header = parse_dex_header(OBF_DEX).expect("parse obf dex header");
    assert!(
        matches!(header.version, DexVersion::V035),
        "obf dex must report version 035"
    );
}

#[test]
fn mapping_carries_r8_compiler_signature_and_renames() {
    assert!(
        R8_MAPPING.contains("compiler: R8"),
        "mapping must carry the R8 compiler banner"
    );
    assert!(
        R8_MAPPING.contains("compiler_version: 9."),
        "mapping must record an R8 9.x compiler version"
    );
    assert!(
        R8_MAPPING.contains("com.example.app.Widget$Ledger -> a:"),
        "R8 must rename the inner Ledger class to a single letter, recorded in the mapping"
    );
    assert!(
        R8_MAPPING.contains("int entries -> a"),
        "R8 must minify the inner-class field, recorded in the mapping"
    );
}

#[test]
fn obf_dex_method_bodies_fully_lift_through_r8_minification() {
    let dex: DexFile = parse_dex(OBF_DEX).expect("parse obf dex");
    let dc: DecompiledDex = decompile_dex(&dex, OBF_DEX);
    assert!(
        dc.method_count >= 2,
        "the kept ctor + main must survive R8 tree-shaking and inlining, got {}",
        dc.method_count
    );
    assert_eq!(
        dc.fallback_methods, 0,
        "disrobe must fully lift every R8-minified method with zero fallbacks, got {}",
        dc.fallback_methods
    );
    assert_eq!(
        dc.fully_lifted_methods, dc.method_count,
        "every method body must lift cleanly: {} lifted of {} methods",
        dc.fully_lifted_methods, dc.method_count
    );
    assert!(
        !dc.source.is_empty(),
        "decompiled R8 source must not be empty"
    );
}

#[test]
fn obf_dex_inlined_accumulate_logic_recovered_in_source() {
    let dex: DexFile = parse_dex(OBF_DEX).expect("parse obf dex");
    let dc: DecompiledDex = decompile_dex(&dex, OBF_DEX);
    let src: &str = &dc.source;
    assert!(
        src.contains("while") || src.contains("if"),
        "R8 inlined accumulate into main; disrobe must recover the loop/branch structure, source head: {}",
        src.chars().take(400).collect::<String>()
    );
    assert!(
        src.contains("& 1"),
        "the inlined parity test (i & 1) must survive the lift, source head: {}",
        src.chars().take(400).collect::<String>()
    );
    assert!(
        src.contains("* 3"),
        "the inlined even-branch multiply (i * 3) must survive the lift, source head: {}",
        src.chars().take(400).collect::<String>()
    );
}

#[test]
fn obf_dex_string_literals_recovered_verbatim() {
    let dex: DexFile = parse_dex(OBF_DEX).expect("parse obf dex");
    assert!(
        dex.strings
            .iter()
            .any(|s: &String| s.contains(BANNER_FRAGMENT)),
        "the banner literal must survive R8 verbatim (R8 does not encrypt strings)"
    );
    for tier in ["tier:large:", "tier:medium:", "tier:small:"] {
        assert!(
            dex.strings.iter().any(|s: &String| s.contains(tier)),
            "classify tier fragment {tier:?} must be recovered verbatim from the R8 dex"
        );
    }
}

#[test]
fn obf_dex_renamed_inner_class_recovered_originals_discarded() {
    let dex: DexFile = parse_dex(OBF_DEX).expect("parse obf dex");
    let descriptors: BTreeSet<String> = dex.class_descriptors.iter().cloned().collect();
    assert!(
        descriptors.contains("Lcom/example/app/Widget;"),
        "the kept entrypoint class survives with its name"
    );
    assert!(
        descriptors.contains("La;"),
        "R8 repackages the inner Ledger to the single-letter class La;, got {descriptors:?}"
    );
    assert!(
        !descriptors.contains("Lcom/example/app/Widget$Ledger;"),
        "the original inner-class name must be discarded by R8 in the artifact"
    );
    for original in ["banner", "accumulate", "classify", "report", "record"] {
        assert!(
            !dex.strings.iter().any(|s: &String| s == original),
            "R8 discards the original method name {original:?}; recovery canonicalizes, it does not restore"
        );
    }
}

#[test]
fn clean_dex_baseline_recovers_full_named_structure() {
    let dex: DexFile = parse_dex(CLEAN_DEX).expect("parse clean dex");
    let dc: DecompiledDex = decompile_dex(&dex, CLEAN_DEX);
    assert_eq!(dc.class_count, 2, "clean dex holds Widget + Widget$Ledger");
    assert!(
        dc.method_count >= 10,
        "clean dex retains every method un-inlined, got {}",
        dc.method_count
    );
    assert_eq!(
        dc.fallback_methods, 0,
        "clean baseline must also lift with zero fallbacks"
    );
    let strings: BTreeSet<String> = user_strings(&dex);
    for original in ["banner", "accumulate", "classify", "report", "record"] {
        assert!(
            dex.strings.iter().any(|s: &String| s == original),
            "clean baseline must carry the original method name {original:?}"
        );
    }
    assert!(
        strings.iter().any(|s: &String| s == BANNER_FRAGMENT),
        "clean dex carries the un-merged banner literal"
    );
    let descriptors: BTreeSet<String> = dex.class_descriptors.iter().cloned().collect();
    assert!(
        descriptors.contains("Lcom/example/app/Widget$Ledger;"),
        "clean dex carries the original inner-class descriptor"
    );
}
