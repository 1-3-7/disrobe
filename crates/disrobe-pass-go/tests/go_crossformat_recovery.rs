#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::BTreeSet;

use disrobe_pass_go::{GoAnalysis, GoFunc, GoItab, GoTypeRef, analyze};

fn recovered_type_names(analysis: &GoAnalysis) -> BTreeSet<String> {
    analysis
        .typemeta
        .types
        .iter()
        .filter_map(|t: &GoTypeRef| t.name.as_deref())
        .map(common::normalize_type_name)
        .collect()
}

fn recovered_itab_pairs(analysis: &GoAnalysis) -> BTreeSet<(String, String)> {
    analysis
        .typemeta
        .itabs
        .iter()
        .filter_map(|i: &GoItab| {
            Some((
                common::normalize_type_name(i.concrete_name.as_deref()?),
                common::normalize_type_name(i.interface_name.as_deref()?),
            ))
        })
        .collect()
}

const RECOVERY_FLOOR: common::FunctionRecoveryFloor = common::FunctionRecoveryFloor::new(99, 100);
const TYPE_EQ_RECOVERY_FLOOR: f64 = 1.0;
const ITAB_RECOVERY_FLOOR: f64 = 1.0;

fn assert_nm_recovery(bin: &str, nm: &str, expect_kind: &str, expect_ptr: u8) {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(bin) else {
        return;
    };
    let Some(nm_bytes): Option<Vec<u8>> = common::fixture_or_skip(nm) else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).unwrap_or_else(|e| panic!("analyze {bin}: {e}"));
    assert_eq!(
        analysis.image_kind, expect_kind,
        "{bin} must parse as {expect_kind}"
    );
    assert_eq!(
        analysis.ptr_size, expect_ptr,
        "{bin} must report a {expect_ptr}-byte pointer size"
    );

    let truth: BTreeSet<String> =
        common::parse_nm_text_symbols(&String::from_utf8_lossy(&nm_bytes));
    assert!(
        truth.len() > 1000,
        "{bin}: `go tool nm` ground truth is implausibly small ({} text symbols); \
         regenerate via crates/disrobe-pass-go/tests/fixtures/regen.ps1",
        truth.len()
    );
    let grade: common::FunctionRecoveryGrade =
        common::grade_analyzed_function_names(&analysis, &truth);
    eprintln!(
        "{bin} ({expect_kind} normal): function-name recovery {}/{} = {}; missing={:?}",
        grade.hit,
        grade.total,
        grade.percentage_display(),
        grade.missing
    );
    assert!(
        grade.meets_floor(RECOVERY_FLOOR),
        "{bin} ({expect_kind}): function-name recovery against `go tool nm` ground truth \
         fell below 99%: {}/{} = {}; missing={:?}",
        grade.hit,
        grade.total,
        grade.percentage_display(),
        grade.missing
    );
    assert!(
        grade.missing.is_empty(),
        "{bin} ({expect_kind} normal): non-anchor `go tool nm` names must all recover; \
         missing={:?}",
        grade.missing
    );
}

fn assert_type_eq_recovery(bin: &str, nm_eq: &str, expect_kind: &str) {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(bin) else {
        return;
    };
    let Some(eq_bytes): Option<Vec<u8>> = common::fixture_or_skip(nm_eq) else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).unwrap_or_else(|e| panic!("analyze {bin}: {e}"));
    assert_eq!(
        analysis.image_kind, expect_kind,
        "{bin} must parse as {expect_kind}"
    );

    let truth: BTreeSet<String> = common::parse_eq_type_names(&String::from_utf8_lossy(&eq_bytes));
    assert!(
        truth.len() > 40,
        "{bin}: `go tool nm` type:.eq.* ground truth is implausibly small ({} names); \
         regenerate via crates/disrobe-pass-go/tests/fixtures/regen.ps1",
        truth.len()
    );
    let recovered: BTreeSet<String> = recovered_type_names(&analysis);
    let hit: usize = truth.iter().filter(|n| recovered.contains(*n)).count();
    let total: usize = truth.len();
    #[allow(clippy::cast_precision_loss)]
    let ratio: f64 = hit as f64 / total.max(1) as f64;
    let missing: Vec<&String> = truth.iter().filter(|n| !recovered.contains(*n)).collect();
    eprintln!(
        "{bin} ({expect_kind}): type-eq recovery {hit}/{total} = {ratio:.4}; missing={missing:?}"
    );
    assert!(
        ratio >= TYPE_EQ_RECOVERY_FLOOR,
        "{bin} ({expect_kind}): type-name recovery against the independent `go tool nm` \
         type:.eq oracle fell below {TYPE_EQ_RECOVERY_FLOOR}: {hit}/{total} = {ratio:.4}; \
         missing {missing:?}"
    );
    assert!(
        recovered.contains("main.Box"),
        "{bin} ({expect_kind}): the user generic base type main.Box (from the main.Box[int]/ \
         main.Box[string] instantiations, bracket-normalized) must be recovered; recovered {} \
         type names",
        recovered.len()
    );
}

fn assert_itab_recovery(bin: &str, nm_itab: &str, expect_kind: &str) {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(bin) else {
        return;
    };
    let Some(itab_bytes): Option<Vec<u8>> = common::fixture_or_skip(nm_itab) else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).unwrap_or_else(|e| panic!("analyze {bin}: {e}"));
    assert_eq!(
        analysis.image_kind, expect_kind,
        "{bin} must parse as {expect_kind}"
    );

    let truth: BTreeSet<(String, String)> =
        common::parse_itab_pairs(&String::from_utf8_lossy(&itab_bytes));
    assert!(
        truth.len() > 15,
        "{bin}: `go tool nm` go:itab.* ground truth is implausibly small ({} pairs); \
         regenerate via crates/disrobe-pass-go/tests/fixtures/regen.ps1",
        truth.len()
    );
    let recovered: BTreeSet<(String, String)> = recovered_itab_pairs(&analysis);
    let hit: usize = truth.iter().filter(|p| recovered.contains(*p)).count();
    let total: usize = truth.len();
    #[allow(clippy::cast_precision_loss)]
    let ratio: f64 = hit as f64 / total.max(1) as f64;
    let missing: Vec<&(String, String)> =
        truth.iter().filter(|p| !recovered.contains(*p)).collect();
    eprintln!(
        "{bin} ({expect_kind}): itab recovery {hit}/{total} = {ratio:.4}; missing={missing:?}"
    );
    assert!(
        ratio >= ITAB_RECOVERY_FLOOR,
        "{bin} ({expect_kind}): itab (concrete,interface) recovery against the independent \
         `go tool nm` go:itab oracle fell below {ITAB_RECOVERY_FLOOR}: {hit}/{total} = {ratio:.4}; \
         missing {missing:?}"
    );
    assert!(
        recovered.contains(&("main.Box".to_owned(), "main.Stringer".to_owned())),
        "{bin} ({expect_kind}): the user itab (main.Box[...], main.Stringer, bracket-normalized) \
         must be recovered; got {recovered:?}"
    );
}

#[test]
fn linux_amd64_elf_function_names_match_go_tool_nm() {
    assert_nm_recovery(
        common::BENCH_LINUX_AMD64,
        common::BENCH_LINUX_AMD64_NM,
        "elf",
        8,
    );
}

#[test]
fn linux_arm64_elf_function_names_match_go_tool_nm() {
    assert_nm_recovery(
        common::BENCH_LINUX_ARM64,
        common::BENCH_LINUX_ARM64_NM,
        "elf",
        8,
    );
}

#[test]
fn darwin_amd64_macho_function_names_match_go_tool_nm() {
    assert_nm_recovery(
        common::BENCH_DARWIN_AMD64,
        common::BENCH_DARWIN_AMD64_NM,
        "macho",
        8,
    );
}

#[test]
fn darwin_arm64_macho_function_names_match_go_tool_nm() {
    assert_nm_recovery(
        common::BENCH_DARWIN_ARM64,
        common::BENCH_DARWIN_ARM64_NM,
        "macho",
        8,
    );
}

#[test]
fn linux_amd64_elf_type_eq_names_match_go_tool_nm() {
    assert_type_eq_recovery(
        common::BENCH_LINUX_AMD64,
        common::BENCH_LINUX_AMD64_NM_EQ,
        "elf",
    );
}

#[test]
fn linux_arm64_elf_type_eq_names_match_go_tool_nm() {
    assert_type_eq_recovery(
        common::BENCH_LINUX_ARM64,
        common::BENCH_LINUX_ARM64_NM_EQ,
        "elf",
    );
}

#[test]
fn darwin_amd64_macho_type_eq_names_match_go_tool_nm() {
    assert_type_eq_recovery(
        common::BENCH_DARWIN_AMD64,
        common::BENCH_DARWIN_AMD64_NM_EQ,
        "macho",
    );
}

#[test]
fn darwin_arm64_macho_type_eq_names_match_go_tool_nm() {
    assert_type_eq_recovery(
        common::BENCH_DARWIN_ARM64,
        common::BENCH_DARWIN_ARM64_NM_EQ,
        "macho",
    );
}

#[test]
fn linux_amd64_elf_itab_pairs_match_go_tool_nm() {
    assert_itab_recovery(
        common::BENCH_LINUX_AMD64,
        common::BENCH_LINUX_AMD64_NM_ITAB,
        "elf",
    );
}

#[test]
fn linux_arm64_elf_itab_pairs_match_go_tool_nm() {
    assert_itab_recovery(
        common::BENCH_LINUX_ARM64,
        common::BENCH_LINUX_ARM64_NM_ITAB,
        "elf",
    );
}

#[test]
fn darwin_amd64_macho_itab_pairs_match_go_tool_nm() {
    assert_itab_recovery(
        common::BENCH_DARWIN_AMD64,
        common::BENCH_DARWIN_AMD64_NM_ITAB,
        "macho",
    );
}

#[test]
fn darwin_arm64_macho_itab_pairs_match_go_tool_nm() {
    assert_itab_recovery(
        common::BENCH_DARWIN_ARM64,
        common::BENCH_DARWIN_ARM64_NM_ITAB,
        "macho",
    );
}

#[test]
fn macho_asm_symbols_carry_their_underscore_linker_symbol() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::BENCH_DARWIN_ARM64) else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze darwin arm64");
    let aeshash: &GoFunc = analysis
        .symbols
        .funcs
        .iter()
        .find(|f: &&GoFunc| f.name == "aeshashbody")
        .expect("aeshashbody must be recovered from the pclntab");
    assert_eq!(
        aeshash.linker_symbol.as_deref(),
        Some("_aeshashbody"),
        "a Mach-O pure-assembly symbol keeps its leading underscore in the symbol table; \
         disrobe must surface it exactly as `go tool nm` prints it"
    );

    let abi0_count: usize = analysis
        .symbols
        .funcs
        .iter()
        .filter(|f: &&GoFunc| f.abi0)
        .count();
    assert!(
        abi0_count >= 50,
        "a real arm64 Mach-O go binary carries dozens of .abi0 assembly entries; the pclntab \
         <-> symbol-table cross-reference must recover them, got {abi0_count}"
    );

    let morestack: &GoFunc = analysis
        .symbols
        .funcs
        .iter()
        .find(|f: &&GoFunc| f.name == "runtime.morestack")
        .expect("runtime.morestack must be recovered");
    assert_eq!(
        morestack.linker_symbol.as_deref(),
        Some("runtime.morestack.abi0")
    );
    assert!(morestack.abi0);
}

#[test]
fn real_pe_elf_and_macho_truncations_are_rejected() {
    let targets: [(&str, &str); 3] = [
        (common::BENCH_GENERICS, "pe"),
        (common::BENCH_LINUX_AMD64, "elf"),
        (common::BENCH_DARWIN_AMD64, "macho"),
    ];
    for (bin, kind) in targets {
        let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(bin) else {
            return;
        };
        let Some(pclntab_offset): Option<usize> = common::find_pclntab_offset(&bytes) else {
            panic!("{bin} ({kind}) must contain a pclntab header");
        };
        let truncation_end: usize = pclntab_offset
            .checked_add(16)
            .expect("pclntab offset plus header prefix fits usize");
        assert!(
            truncation_end < bytes.len(),
            "{bin} ({kind}) must have pclntab data after its header prefix"
        );
        assert!(
            analyze(&bytes[..truncation_end]).is_err(),
            "{bin} ({kind}) truncated inside the pclntab header must be refused"
        );

        let mut malformed: Vec<u8> = bytes;
        let count_end: usize = pclntab_offset
            .checked_add(16)
            .expect("pclntab function count range fits usize");
        malformed[pclntab_offset + 8..count_end].copy_from_slice(&u64::MAX.to_le_bytes());
        let malformed_analysis: GoAnalysis = analyze(&malformed)
            .expect("oversized pclntab function count must degrade without panicking");
        assert!(
            malformed_analysis.symbols.funcs.is_empty(),
            "{bin} ({kind}) with an out-of-range pclntab function count must not recover functions"
        );
    }
}
