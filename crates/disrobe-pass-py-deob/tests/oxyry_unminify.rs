#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::oxyry::{OxyryPass, bake};

/// Self-consistency smoke test: `bake()` is THIS crate's synthetic re-implementation of the Oxyry
/// minify transform, so this round-trip proves only that `peel()` inverts `bake()`. It is NOT
/// evidence of real-tool recovery accuracy; Oxyry has NO independent in-repo fixture (the service
/// is client-side-only `JS` with no public API), so this family's recovery is model-validated only.
/// See `oxyry_real_corpus_sourcing_blocked` and the ignored real test in `oxyry_real.rs`.
#[test]
fn oxyry_model_self_consistency_unminify_via_hints() {
    let original: &str =
        "def compute(value):\n    return value * 3\n\ndef triple(x):\n    return compute(x)\n";
    let obf: String = bake(original);
    assert!(OxyryPass.detect(obf.as_bytes()).matched);
    let out = OxyryPass.peel(obf.as_bytes()).expect("peel");
    assert!(out.recovered_source.contains("def compute"));
    assert!(out.recovered_source.contains("def triple"));
}

/// Self-consistency smoke test over the shared synthetic edge-case corpus. Validates the
/// `bake()` -> `peel()` model round-trip only, NOT real-tool recovery (Oxyry corpus is
/// sourcing-blocked; see `oxyry_real_corpus_sourcing_blocked`).
#[test]
fn oxyry_model_self_consistency_edge_cases() {
    let count: usize = common::run_edge_cases(bake, |obf: &[u8]| {
        OxyryPass
            .peel(obf)
            .is_ok_and(|o| !o.recovered_source.is_empty())
    });
    assert!(count >= 5);
}

/// Honest marker: no independent real-tool Oxyry corpus is committed in-repo. Oxyry
/// (`oxyry.com` / Online Python Obfuscator) is a client-side-only `JS` service with no public API, so
/// capturing genuine tool output requires a manual browser session (see
/// `corpus/python/obfuscators/oxyry/CAPTURE-MANUAL.md`). Until that lands, the Oxyry family's
/// recovery is validated ONLY by the synthetic `bake()` -> `peel()` model round-trip above and
/// must NOT back any real-recovery headline. This test fails loudly if a real fixture is added
/// without wiring up the gating real test in `oxyry_real.rs`.
#[test]
fn oxyry_real_corpus_sourcing_blocked() {
    let real_fixture: Option<Vec<u8>> = common::load_real_fixture("oxyry", "hello");
    assert!(
        real_fixture.is_none(),
        "an independent Oxyry real fixture now exists; remove this sourcing-blocked marker and un-ignore the gating real test in oxyry_real.rs"
    );
}
