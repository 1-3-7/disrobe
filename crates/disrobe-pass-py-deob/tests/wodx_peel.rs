#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::wodx::{WodxPass, bake};

/// Self-consistency smoke test: `bake()` is THIS crate's synthetic re-implementation of the `WodX`
/// transform, so this round-trip proves only that `peel()` inverts `bake()`. It is NOT evidence
/// of real-tool recovery accuracy; `WodX` has NO independent in-repo fixture (upstream is dead, see
/// below), so this family's recovery is model-validated only. See
/// `wodx_real_corpus_sourcing_blocked` and the ignored real test in `wodx_real.rs`.
#[test]
fn wodx_model_self_consistency_recovers_source() {
    let original: &str = "async def main():\n    return 1\n";
    let obf: String = bake(original);
    assert!(WodxPass.detect(obf.as_bytes()).matched);
    let out = WodxPass.peel(obf.as_bytes()).expect("peel");
    assert_eq!(out.recovered_source, original);
}

/// Self-consistency smoke test over the shared synthetic edge-case corpus. Validates the
/// `bake()` -> `peel()` model round-trip only, NOT real-tool recovery (`WodX` corpus is
/// sourcing-blocked; see `wodx_real_corpus_sourcing_blocked`).
#[test]
fn wodx_model_self_consistency_edge_cases() {
    let count: usize = common::run_edge_cases(bake, |obf: &[u8]| {
        WodxPass
            .peel(obf)
            .is_ok_and(|o| !o.recovered_source.is_empty())
    });
    assert!(count >= 5);
}

/// Honest marker: no independent real-tool `WodX` corpus is committed in-repo. The upstream `WodX`
/// obfuscator (`github.com/Hattori-A1S/WodX-Obfuscator`) is dead as of 2026-05 (HTTP 404), so no
/// genuine tool output can be captured. Until upstream revives, the `WodX` family's recovery is
/// validated ONLY by the synthetic `bake()` -> `peel()` model round-trip above and must NOT back
/// any real-recovery headline. This test fails loudly if a real fixture is added without wiring up
/// the gating real test in `wodx_real.rs`.
#[test]
fn wodx_real_corpus_sourcing_blocked() {
    let real_fixture: Option<Vec<u8>> = common::load_real_fixture("wodx", "hello");
    assert!(
        real_fixture.is_none(),
        "an independent WodX real fixture now exists; remove this sourcing-blocked marker and un-ignore the gating real test in wodx_real.rs"
    );
}
