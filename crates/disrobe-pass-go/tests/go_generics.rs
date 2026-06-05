#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use disrobe_pass_go::{GoAnalysis, GoGenericInstantiation, analyze};

/// Asserts structured recovery surfaces the fixture's generic instantiations with correct base and type-args.
#[test]
fn generics_recovers_user_instantiations() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::HELLO_GENERICS) else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze generics");
    let generics: &[GoGenericInstantiation] = &analysis.typemeta.generics;
    assert!(
        generics.len() >= 5,
        "expected structured generic instantiations, got {}",
        generics.len()
    );

    let has = |base: &str, args: &[&str]| -> bool {
        generics.iter().any(|g: &GoGenericInstantiation| {
            g.base == base
                && g.type_args
                    .iter()
                    .map(String::as_str)
                    .eq(args.iter().copied())
        })
    };

    assert!(has("main.Sum", &["go.shape.int"]), "missing Sum[int]");
    assert!(
        has("main.Sum", &["go.shape.float64"]),
        "missing Sum[float64]"
    );
    assert!(
        has("main.MapKeys", &["go.shape.string", "go.shape.int"]),
        "missing MapKeys[string,int]"
    );
    assert!(
        has("main.Box", &["go.shape.int"]) && has("main.Box", &["go.shape.string"]),
        "missing Box[int]/Box[string] from the generic method receiver"
    );

    for g in generics.iter().filter(|g| g.base.starts_with("main.")) {
        assert!(
            g.shape_args,
            "monomorphized user generics expose go.shape.* args: {g:?}"
        );
        assert!(g.from_function, "main generics come from funcname table");
    }
}

/// Generic recovery must not invent instantiations on a non-generic binary.
#[test]
fn generics_empty_or_stdlib_only_on_plain_binary() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::HELLO_NORMAL) else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze normal");
    assert!(
        analysis
            .typemeta
            .generics
            .iter()
            .all(|g: &GoGenericInstantiation| !g.base.starts_with("main.")),
        "plain binary must not surface main.* generic instantiations"
    );
}

/// Stripped generics binary still carries the pclntab funcname table, so user
/// instantiation recovery survives `-ldflags=-s -w`.
#[test]
fn generics_survive_stripping() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::HELLO_GENERICS_STRIPPED)
    else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze stripped generics");
    assert!(
        analysis
            .typemeta
            .generics
            .iter()
            .any(|g: &GoGenericInstantiation| g.base == "main.Sum"),
        "stripped generics binary must still recover main.Sum instantiations"
    );
}
