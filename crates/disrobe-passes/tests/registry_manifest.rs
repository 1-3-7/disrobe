#![allow(
    clippy::expect_used,
    reason = "gate tests assert invariants and must panic loudly on a broken registry"
)]

use std::collections::BTreeSet;

use disrobe_core::chain::{Determinism, Ecosystem, PassRegistry, SafetyClass, ecosystem_for};
use disrobe_core::pass::PassId;
use disrobe_passes::{
    assert_meta_coherent, build_registry, expected_pass_ids, registered_pass_ids,
};

#[test]
fn registry_ids_match_the_cfg_composed_expectation() {
    let registered: Vec<PassId> = registered_pass_ids();
    let expected: Vec<PassId> = expected_pass_ids();
    assert_eq!(
        registered, expected,
        "build_registry() pass ids diverged from the cfg-composed expected_pass_ids(); a register \
         call and the expected list must be edited together under the same feature gate"
    );
}

#[test]
fn registry_has_no_duplicate_ids() {
    let registered: Vec<PassId> = registered_pass_ids();
    let unique: BTreeSet<PassId> = registered.iter().copied().collect();
    assert_eq!(
        registered.len(),
        unique.len(),
        "a pass id was registered more than once"
    );
}

#[test]
fn every_registered_pass_has_coherent_meta() {
    let r: PassRegistry = build_registry();
    assert_meta_coherent(&r).expect("meta coherence");
    for pass in r.iter_passes() {
        let id: PassId = pass.id();
        let eco: Ecosystem = pass.meta().ecosystem;
        assert_ne!(eco, Ecosystem::Other, "pass {id} classified as other");
        assert_eq!(eco, ecosystem_for(id), "pass {id} ecosystem disagreement");
    }
}

#[test]
fn every_registered_pass_is_deterministic() {
    let r: PassRegistry = build_registry();
    for pass in r.iter_passes() {
        assert_eq!(
            pass.meta().determinism,
            Determinism::Deterministic,
            "pass {id} is not deterministic; the chain cache keys by input hash and is only sound \
             for deterministic passes",
            id = pass.id()
        );
    }
}

#[test]
fn only_js_deob_carries_a_gated_dynamic_mode() {
    let r: PassRegistry = build_registry();
    for pass in r.iter_passes() {
        let id: PassId = pass.id();
        let safety: SafetyClass = pass.meta().safety;
        if id == "js.deob" {
            assert_eq!(
                safety,
                SafetyClass::GatedDynamic,
                "js.deob gates a static-marker strip behind operator authorization"
            );
        } else {
            assert_eq!(
                safety,
                SafetyClass::Static,
                "pass {id} declared a gated-dynamic mode it does not have"
            );
        }
    }
}
