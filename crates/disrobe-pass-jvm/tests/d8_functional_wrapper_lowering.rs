#![allow(clippy::expect_used)]

use disrobe_pass_jvm::{AndroidDecompileOutput, BackendPreference, android_decompile_dex};

const EDGECASES_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCases.dex");

fn recovered_edgecases_source() -> String {
    let recovered: AndroidDecompileOutput =
        android_decompile_dex(EDGECASES_DEX, BackendPreference::PreferInHouse)
            .expect("recover EdgeCases.dex through the production Android route");
    recovered
        .sources
        .into_iter()
        .find_map(|(path, source): (String, String)| {
            path.replace('\\', "/")
                .ends_with("EdgeCases.java")
                .then_some(source)
        })
        .expect("recovered EdgeCases.java")
}

#[test]
fn d8_functional_wrappers_bind_captures_once_and_call_emitted_helpers() {
    let source: String = recovered_edgecases_source();
    assert!(
        !source.contains("this.f$"),
        "D8 functional wrappers still read constructor capture fields instead of ordered outer bindings:\n{source}"
    );
    assert!(
        !source.contains("EdgeCases.lambda$"),
        "D8 functional wrappers still call a helper name that the same source unit emits as synthLambda$:\n{source}"
    );
    assert_eq!(
        source.matches("final int disrobeCapture$").count(),
        4,
        "the four emitted primitive captures must each be evaluated into one typed final binding:\n{source}"
    );
    assert_eq!(
        source
            .matches("final java.util.concurrent.CompletableFuture disrobeCapture$")
            .count(),
        1,
        "the future capture must be evaluated once"
    );
    assert_eq!(
        source
            .matches("final java.util.function.Supplier disrobeCapture$")
            .count(),
        1,
        "the supplier capture must be evaluated once"
    );
    assert_eq!(
        source
            .matches("final java.util.List disrobeCapture$")
            .count(),
        1,
        "the list capture must be evaluated once"
    );
    assert_eq!(
        source.matches("final Object disrobeCapture$").count(),
        1,
        "the generic repeat capture must be evaluated once"
    );
    assert_eq!(
        source.matches("final Integer disrobeCapture$").count(),
        1,
        "the boxed chain capture must be evaluated once"
    );
    assert_eq!(
        source.matches("disrobeCapture$").count(),
        18,
        "each of the nine bindings must have one declaration and one wrapper use"
    );
}
