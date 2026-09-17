#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
const SAMPLE: &str = include_str!("../../../corpus/src/javascript/full-pipeline.js");

fn main() {
    divan::main();
}

#[divan::bench]
fn full_pipeline(bencher: divan::Bencher<'_, '_>) {
    bencher.bench_local(|| {
        let recovery: disrobe_pass_js_deob::Result<
            Option<disrobe_pass_js_deob::StringArrayRecovery>,
        > = divan::black_box(disrobe_pass_js_deob::recover_string_array(SAMPLE));
        let mid: String = recovery
            .ok()
            .flatten()
            .map_or_else(|| SAMPLE.to_owned(), |r| r.rewritten_source);
        let (after_unminify, _): (String, disrobe_pass_js_deob::UnminifyStats) =
            disrobe_pass_js_deob::unminify(&mid);
        let (after_rename, _): (String, disrobe_pass_js_deob::RenameStats) =
            disrobe_pass_js_deob::rename_hex_idents(&after_unminify);
        let (final_source, _): (String, disrobe_pass_js_deob::ScopeAwareStats) =
            disrobe_pass_js_deob::rename_scope_aware(&after_rename).unwrap_or_else(|_| {
                (
                    after_rename.clone(),
                    disrobe_pass_js_deob::ScopeAwareStats::default(),
                )
            });
        divan::black_box(final_source);
    });
}
