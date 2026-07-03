#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_go::{GoAnalysis, GoGenericInstantiation, analyze};

#[test]
fn generics_recovers_user_instantiations() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_GENERICS);
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

    for g in generics
        .iter()
        .filter(|g| g.base.starts_with("main.") && g.from_function)
    {
        assert!(
            g.shape_args,
            "function-table user generics expose go.shape.* args: {g:?}"
        );
    }

    assert!(
        generics
            .iter()
            .all(|g: &GoGenericInstantiation| !g.base.starts_with('*')
                && !g.base.starts_with('[')
                && !g.base.contains("func(")),
        "the generic base must be the bare pkg.Name, never a pointer/slice/array/func \
         type-constructor wrapper: {:?}",
        generics
            .iter()
            .filter(|g| g.base.starts_with('*')
                || g.base.starts_with('[')
                || g.base.contains("func("))
            .collect::<Vec<_>>()
    );
}

#[test]
fn generics_empty_or_stdlib_only_on_plain_binary() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_NORMAL);
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

#[test]
fn generics_survive_stripping() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_GENERICS_STRIPPED);
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

#[test]
fn shape_bodies_recover_concrete_args_from_sibling_symbols_on_real_binary() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::BENCH_GENERICS) else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze bench_generics");
    let generics: &[GoGenericInstantiation] = &analysis.typemeta.generics;

    let concrete_for = |base: &str| -> Vec<&GoGenericInstantiation> {
        generics
            .iter()
            .filter(|g: &&GoGenericInstantiation| g.base == base && !g.shape_args)
            .collect()
    };

    let registry: Vec<&GoGenericInstantiation> = concrete_for("main.Registry");
    assert!(
        registry
            .iter()
            .any(|g: &&GoGenericInstantiation| g.type_args
                == ["string".to_owned(), "int".to_owned()]),
        "main.Registry's go.shape.string,go.shape.int body must recover [string,int] from its \
         concrete sibling symbols with shape_args=false; got {registry:?}"
    );
    assert!(
        registry.iter().all(|g: &&GoGenericInstantiation| !g
            .type_args
            .iter()
            .any(|a: &String| a.starts_with("go.shape."))),
        "no recovered Registry arg may remain a go.shape stencil: {registry:?}"
    );

    let tree: Vec<&GoGenericInstantiation> = concrete_for("main.Tree");
    assert!(
        tree.iter()
            .any(|g: &&GoGenericInstantiation| g.type_args == ["int".to_owned()]),
        "main.Tree's go.shape.int body must recover [int] with shape_args=false; got {tree:?}"
    );

    assert!(
        generics.iter().all(|g: &GoGenericInstantiation| {
            !g.shape_args
                || g.type_args
                    .iter()
                    .any(|a: &String| a.starts_with("go.shape."))
        }),
        "any instantiation flagged shape_args=false must carry only concrete (non go.shape) args"
    );
}

#[test]
fn shape_only_generics_with_no_sibling_stay_an_honest_wall_on_real_binary() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::BENCH_GENERICS) else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze bench_generics");
    let generics: &[GoGenericInstantiation] = &analysis.typemeta.generics;

    let wall: Option<&GoGenericInstantiation> = generics
        .iter()
        .find(|g: &&GoGenericInstantiation| g.base == "slices.pdqsortOrdered");
    let wall: &GoGenericInstantiation = wall.expect("the sorted free generic function is present");
    assert!(
        wall.shape_args,
        "a free generic function reachable only through a go.shape body with no concrete sibling \
         is a genuine static wall and must stay shape_args=true: {wall:?}"
    );
    assert_eq!(wall.type_args, vec!["go.shape.string".to_owned()]);
    assert!(
        wall.concrete_candidates.is_empty(),
        "the genuine wall has no mined concrete candidates"
    );
}

#[test]
fn merged_shape_body_surfaces_full_concrete_candidate_set_on_real_binary() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::BENCH_GENERICS) else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze bench_generics");
    let generics: &[GoGenericInstantiation] = &analysis.typemeta.generics;

    let merged: Option<&GoGenericInstantiation> =
        generics.iter().find(|g: &&GoGenericInstantiation| {
            g.base == "atomic.Pointer" && g.shape_args && !g.concrete_candidates.is_empty()
        });
    let merged: &GoGenericInstantiation = merged
        .expect("atomic.Pointer's single shape body fans out to many concrete instantiations");
    assert!(
        merged.concrete_candidates.len() >= 2,
        "Go merges distinct concretes onto one shape body; we surface the full candidate set \
         instead of inventing a single pick: {merged:?}"
    );
    assert!(
        merged
            .concrete_candidates
            .iter()
            .any(|c: &Vec<String>| c == &vec!["os.dirInfo".to_owned()]),
        "the candidate set must include the verbatim concretes mined from the binary's tables: \
         {:?}",
        merged.concrete_candidates
    );
}
