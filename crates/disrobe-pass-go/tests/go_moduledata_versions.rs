#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::BTreeSet;

use disrobe_pass_go::{GoAnalysis, GoItab, GoMethod, GoTypeRef, analyze};

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

#[test]
fn go124_moduledata_recovers_typelinks_without_epclntab_word() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::GO124_WINDOWS_AMD64) else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze go1.24 fixture");

    assert_eq!(
        analysis.buildversion.as_deref(),
        Some("go1.24.0"),
        "the go1.24 fixture must report its build version"
    );

    assert_ne!(
        analysis.moduledata.typelinks_va, 0,
        "go1.20..go1.25 moduledata places typelinks one word earlier than go1.26 (no epclntab \
         field); reading the go1.26 offset yields a rejected slice and zero types"
    );
    assert!(
        analysis.moduledata.typelinks_len > 100,
        "expected the full typelinks slice length on a real go1.24 binary, got {}",
        analysis.moduledata.typelinks_len
    );

    let total: usize = analysis.typemeta.types.len();
    let named: usize = analysis
        .typemeta
        .types
        .iter()
        .filter(|t: &&GoTypeRef| t.name.is_some())
        .count();
    assert!(
        total > 100,
        "go1.24 typelinks walk should expose hundreds of types (got {total})"
    );
    #[allow(clippy::cast_precision_loss)]
    let ratio: f64 = named as f64 / total.max(1) as f64;
    assert!(
        ratio >= 0.85,
        "expected >= 85% type-name recovery on the go1.24 fixture (got {named}/{total} = {ratio:.3})"
    );

    let names: Vec<&str> = analysis
        .typemeta
        .types
        .iter()
        .filter_map(|t: &GoTypeRef| t.name.as_deref())
        .collect();
    let canonical_runtime: &[&str] = &[
        "*runtime.g",
        "*runtime.m",
        "*runtime.p",
        "*runtime.mheap",
        "*runtime._type",
        "*runtime.itab",
    ];
    let canonical_hits: usize = canonical_runtime
        .iter()
        .filter(|needle: &&&str| names.iter().any(|n: &&str| n.contains(*needle)))
        .count();
    assert!(
        canonical_hits >= 3,
        "expected >= 3 canonical runtime types from {canonical_runtime:?} (matched {canonical_hits})"
    );
}

#[test]
fn go124_moduledata_recovers_itablinks_and_methods() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::GO124_WINDOWS_AMD64) else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze go1.24 fixture");

    assert_ne!(
        analysis.moduledata.itablinks_va, 0,
        "itablinks follows typelinks by three words in every layout; recovering typelinks at the \
         go1.24 offset must also land itablinks"
    );
    let fully_resolved: usize = analysis
        .typemeta
        .itabs
        .iter()
        .filter(|i: &&GoItab| i.interface_name.is_some() && i.concrete_name.is_some())
        .count();
    assert!(
        fully_resolved > 0,
        "expected at least one fully-resolved itab (interface + concrete) on the go1.24 fixture"
    );
    let pairs: BTreeSet<(String, String)> = recovered_itab_pairs(&analysis);
    assert!(
        pairs.contains(&("fs.PathError".to_owned(), "error".to_owned())),
        "the *fs.PathError itab bound to error must be recovered on go1.24; got {pairs:?}"
    );

    let total_methods: usize = analysis
        .typemeta
        .types
        .iter()
        .map(|t: &GoTypeRef| t.methods.len())
        .sum();
    assert!(
        total_methods >= 400,
        "abi.UncommonType method sets are version-independent once types resolve; expected \
         hundreds of methods on go1.24 (got {total_methods})"
    );
    let mismatches: usize = analysis
        .typemeta
        .types
        .iter()
        .flat_map(|t: &GoTypeRef| t.methods.iter())
        .filter_map(|m: &GoMethod| Some((m.name.as_deref()?, m.linker_name.as_deref()?)))
        .filter(|(name, link): &(&str, &str)| !link.ends_with(&format!(".{name}")))
        .count();
    assert_eq!(
        mismatches, 0,
        "every linked go1.24 method name must be the exact tail of its pclntab function"
    );
}

#[test]
fn go124_type_names_match_go_tool_nm_eq_oracle() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::GO124_WINDOWS_AMD64) else {
        return;
    };
    let Some(eq_bytes): Option<Vec<u8>> =
        common::fixture_or_skip(common::GO124_WINDOWS_AMD64_NM_EQ)
    else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze go1.24 fixture");

    let truth: BTreeSet<String> = common::parse_eq_type_names(&String::from_utf8_lossy(&eq_bytes))
        .into_iter()
        .filter(|n: &String| n.contains('.'))
        .collect();
    assert!(
        truth.len() > 40,
        "the go1.24 fixture emits dozens of named type equality routines; got {}",
        truth.len()
    );

    let recovered: BTreeSet<String> = recovered_type_names(&analysis);
    let missing: Vec<&String> = truth.iter().filter(|n| !recovered.contains(*n)).collect();
    let hit: usize = truth.len() - missing.len();
    let total: usize = truth.len();
    #[allow(clippy::cast_precision_loss)]
    let oracle_ratio: f64 = hit as f64 / total.max(1) as f64;
    eprintln!("go1.24 windows/amd64 (pe): type-eq recovery {hit}/{total} = {oracle_ratio:.4}");
    assert!(
        oracle_ratio >= 1.0,
        "named-type recovery on the go1.24 fixture vs the independent `go tool nm` type:.eq oracle \
         must be 100% (the pre-epclntab moduledata offset is now correct): {hit}/{total} = \
         {oracle_ratio:.4}; missing {missing:?}"
    );
    assert!(
        recovered.contains("main.Widget") && recovered.contains("fs.PathError"),
        "the user struct main.Widget and referenced io/fs.PathError must both be recovered on \
         go1.24; recovered {} names",
        recovered.len()
    );
}

#[test]
fn go124_itab_pairs_match_go_tool_nm_itab_oracle() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::GO124_WINDOWS_AMD64) else {
        return;
    };
    let Some(itab_bytes): Option<Vec<u8>> =
        common::fixture_or_skip(common::GO124_WINDOWS_AMD64_NM_ITAB)
    else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze go1.24 fixture");

    let truth: BTreeSet<(String, String)> =
        common::parse_itab_pairs(&String::from_utf8_lossy(&itab_bytes));
    assert!(
        !truth.is_empty(),
        "the go1.24 fixture stores interface values, so it emits go:itab.* symbols"
    );

    let recovered: BTreeSet<(String, String)> = recovered_itab_pairs(&analysis);
    let missing: Vec<&(String, String)> =
        truth.iter().filter(|p| !recovered.contains(*p)).collect();
    let hit: usize = truth.len() - missing.len();
    let total: usize = truth.len();
    #[allow(clippy::cast_precision_loss)]
    let oracle_ratio: f64 = hit as f64 / total.max(1) as f64;
    eprintln!("go1.24 windows/amd64 (pe): itab recovery {hit}/{total} = {oracle_ratio:.4}");
    assert!(
        oracle_ratio >= 1.0,
        "itab (concrete,interface) recovery on the go1.24 fixture vs the independent `go tool nm` \
         go:itab oracle must be 100%: {hit}/{total} = {oracle_ratio:.4}; missing {missing:?}"
    );
}
