#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use disrobe_pass_go::{GoAnalysis, GoItab, GoTypeRef, analyze};

#[test]
fn typemeta_emits_some_types_for_normal_binary() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::HELLO_NORMAL) else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze");
    let total_types: usize = analysis.typemeta.types.len();
    let total_itabs: usize = analysis.typemeta.itabs.len();
    assert!(
        total_types > 0,
        "expected typelinks walk to recover types on go1.26.3 binary"
    );
    assert!(
        total_itabs > 0,
        "expected itablinks walk to recover itabs on go1.26.3 binary"
    );
}

#[test]
fn typemeta_recovers_real_type_names_on_go126() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::HELLO_NORMAL) else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze");
    let total: usize = analysis.typemeta.types.len();
    let named: usize = analysis
        .typemeta
        .types
        .iter()
        .filter(|t: &&GoTypeRef| t.name.is_some())
        .count();
    assert!(
        total > 100,
        "go1.26.3 fixture should expose hundreds of types via typelinks (got {total})"
    );
    let ratio: f64 = (named as f64) / (total.max(1) as f64);
    assert!(
        ratio >= 0.85,
        "expected >= 85% type-name recovery on go1.26.3 fixture (got {named}/{total} = {ratio:.3})"
    );

    let names: Vec<&str> = analysis
        .typemeta
        .types
        .iter()
        .filter_map(|t: &GoTypeRef| t.name.as_deref())
        .collect();

    let pkg_categories: &[&str] = &["runtime.", "sync.", "embed.", "reflect.", "internal/"];
    for pkg in pkg_categories {
        let hits: usize = names.iter().filter(|n: &&&str| n.contains(pkg)).count();
        assert!(
            hits > 0,
            "expected at least one recovered type name containing '{pkg}' (got {hits})"
        );
    }

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
        "expected at least 3 canonical runtime types from {:?} (matched {canonical_hits}); recovered {} names",
        canonical_runtime,
        names.len()
    );
}

#[test]
fn typemeta_recovers_itab_concrete_names_on_go126() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::HELLO_NORMAL) else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze");
    let total: usize = analysis.typemeta.itabs.len();
    assert!(total > 0, "expected itabs > 0");

    let fully_resolved: usize = analysis
        .typemeta
        .itabs
        .iter()
        .filter(|i: &&GoItab| i.interface_name.is_some() && i.concrete_name.is_some())
        .count();
    assert!(
        fully_resolved * 2 >= total,
        "expected at least half of itabs to surface BOTH interface+concrete names \
         (got {fully_resolved}/{total})"
    );

    let pairs: Vec<(&str, &str)> = analysis
        .typemeta
        .itabs
        .iter()
        .filter_map(|i: &GoItab| Some((i.interface_name.as_deref()?, i.concrete_name.as_deref()?)))
        .collect();
    let expected_concretes: &[&str] = &["*os.File", "*embed.FS", "*fs.PathError"];
    for concrete in expected_concretes {
        assert!(
            pairs
                .iter()
                .any(|(_, c): &(&str, &str)| c.contains(concrete)),
            "expected itab concrete name containing '{concrete}'; pairs recovered: {pairs:?}"
        );
    }
}

#[test]
fn typemeta_does_not_panic_on_stripped() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::HELLO_STRIPPED) else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze stripped");
    let total: usize = analysis.typemeta.types.len();
    let named: usize = analysis
        .typemeta
        .types
        .iter()
        .filter(|t: &&GoTypeRef| t.name.is_some())
        .count();
    assert!(
        total > 0,
        "stripped go1.26.3 binary still preserves typelinks/types"
    );
    assert!(
        named > 0,
        "stripped binary still has typelinks/names section -- expected >0 name recoveries"
    );
}
