#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/swift_toolchain.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod swift_toolchain;

use disrobe_pass_swift_objc::demangle;

use swift_toolchain::{
    ReferenceDemangler, provenance_note, reference_demangle, resolve_reference_demangler,
};

const GRADED: &str =
    "byte-exact agreement with swift-demangle on the FEAT-023 named-arm fixture corpus";

#[derive(Debug, Clone, Copy)]
struct ArmFixture {
    arm: &'static str,
    mangled: &'static str,
    expected: &'static str,
}

const ARM_FIXTURES: &[ArmFixture] = &[
    ArmFixture {
        arm: "opaque_return_type",
        mangled: "$s4Arms11makeGreeterQryF",
        expected: "Arms.makeGreeter() -> some",
    },
    ArmFixture {
        arm: "opaque_type_descriptor",
        mangled: "$s4Arms11makeGreeterQryFQOMQ",
        expected: "opaque type descriptor for <<opaque return type of Arms.makeGreeter() -> some>>",
    },
    ArmFixture {
        arm: "async_function",
        mangled: "$s4Arms10asyncGreetSSyYaF",
        expected: "Arms.asyncGreet() async -> Swift.String",
    },
    ArmFixture {
        arm: "async_function_pointer",
        mangled: "$s4Arms10asyncGreetSSyYaFTu",
        expected: "async function pointer to Arms.asyncGreet() async -> Swift.String",
    },
    ArmFixture {
        arm: "async_resume_partial",
        mangled: "$s4Arms10asyncGreetSSyYaFTQ0_",
        expected: "(1) await resume partial function for Arms.asyncGreet() async -> Swift.String",
    },
    ArmFixture {
        arm: "actor_entity",
        mangled: "$s4Arms7CounterC9incrementSiyF",
        expected: "Arms.Counter.increment() -> Swift.Int",
    },
    ArmFixture {
        arm: "distributed_actor_entity",
        mangled: "$s5Arms36WorkerC11Distributed0C5ActorAAMc",
        expected: "protocol conformance descriptor for Arms3.Worker : Distributed.DistributedActor in Arms3",
    },
    ArmFixture {
        arm: "distributed_thunk",
        mangled: "$s5Arms36WorkerC4pingSiyYaKFTE",
        expected: "distributed thunk Arms3.Worker.ping() async throws -> Swift.Int",
    },
    ArmFixture {
        arm: "distributed_accessor",
        mangled: "$s5Arms36WorkerC4pingSiyYaKFTETF",
        expected: "distributed accessor for distributed thunk Arms3.Worker.ping() async throws -> Swift.Int",
    },
    ArmFixture {
        arm: "global_actor_annotation",
        mangled: "$s4Arms7MyActorVs06GlobalC0AAMcMK",
        expected: "metadata instantiation cache for protocol conformance descriptor for Arms.MyActor : Swift.GlobalActor in Arms",
    },
    ArmFixture {
        arm: "isolated_parameter",
        mangled: "$s7IsoTest5touchySiAA5StoreCYiF",
        expected: "IsoTest.touch(isolated IsoTest.Store) -> Swift.Int",
    },
    ArmFixture {
        arm: "task_local_accessor",
        mangled: "$s5Arms39RequestIDO8$currents9TaskLocalCySiSgGvau",
        expected: "Arms3.RequestID.$current.unsafeMutableAddressor : Swift.TaskLocal<Swift.Int?>",
    },
    ArmFixture {
        arm: "sendable_closure",
        mangled: "$s4Arms15sendableClosureyyyyYbXEF",
        expected: "Arms.sendableClosure(@Sendable () -> ()) -> ()",
    },
    ArmFixture {
        arm: "attached_macro_expansion",
        mangled: "$s4Arms7CounterC9increment3FoofMm0_",
        expected: "member macro @Foo expansion #2 of increment in Arms.Counter",
    },
    ArmFixture {
        arm: "partial_apply_forwarder",
        mangled: "$s5Arms215genericIdentityyxxlFTA",
        expected: "partial apply forwarder for Arms2.genericIdentity<A>(A) -> A",
    },
    ArmFixture {
        arm: "protocol_witness_thunk",
        mangled: "$s4Arms14EnglishGreeterVAA0C0A2aDP5greetSSyFTW",
        expected: "protocol witness for Arms.Greeter.greet() -> Swift.String in conformance Arms.EnglishGreeter : Arms.Greeter in Arms",
    },
    ArmFixture {
        arm: "objc_bridging_thunk",
        mangled: "$s4Arms7CounterC9incrementSiyFTo",
        expected: "@objc Arms.Counter.increment() -> Swift.Int",
    },
    ArmFixture {
        arm: "method_descriptor",
        mangled: "$s4Arms7CounterCACycfCTq",
        expected: "method descriptor for Arms.Counter.__allocating_init() -> Arms.Counter",
    },
    ArmFixture {
        arm: "dispatch_thunk",
        mangled: "$sSQ2eeoiySbx_xtFZTj",
        expected: "dispatch thunk of static Swift.Equatable.== infix(A, A) -> Swift.Bool",
    },
    ArmFixture {
        arm: "keypath_getter_thunk",
        mangled: "$s5Arms27WrapperV8computedSivpACTK",
        expected: "key path getter for Arms2.Wrapper.computed : Swift.Int : Arms2.Wrapper",
    },
    ArmFixture {
        arm: "keypath_setter_thunk",
        mangled: "$s5Arms27WrapperV8computedSivpACTk",
        expected: "key path setter for Arms2.Wrapper.computed : Swift.Int : Arms2.Wrapper",
    },
    ArmFixture {
        arm: "generic_signature_with_requirements",
        mangled: "$s4Arms10GenericBoxV6isLess4thanSbx_tqd__RszlF",
        expected: "Arms.GenericBox.isLess<A where A == A1>(than: A) -> Swift.Bool",
    },
    ArmFixture {
        arm: "associated_type_descriptor",
        mangled: "$s7Element4Arms8HasAssocPTl",
        expected: "associated type descriptor for Arms.HasAssoc.Element",
    },
    ArmFixture {
        arm: "protocol_conformance_descriptor",
        mangled: "$sSi8OtherMod0A5Proto4ArmsMc",
        expected: "protocol conformance descriptor for Swift.Int : OtherMod.OtherProto in Arms",
    },
    ArmFixture {
        arm: "protocol_witness_table",
        mangled: "$sSi8OtherMod0A5Proto4ArmsWP",
        expected: "protocol witness table for Swift.Int : OtherMod.OtherProto in Arms",
    },
    ArmFixture {
        arm: "lazy_witness_table_accessor",
        mangled: "$s9MacroTest8Counter2CAC11Observation10ObservableAAWl",
        expected: "lazy protocol witness table accessor for type MacroTest.Counter2 and conformance MacroTest.Counter2 : Observation.Observable in MacroTest",
    },
];

const OPEN_ARMS: &[&str] = &[
    "reabstraction_thunk",
    "freestanding_macro_expansion",
    "autodiff_thunk",
];

fn closed_arm_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = ARM_FIXTURES.iter().map(|f: &ArmFixture| f.arm).collect();
    names.sort_unstable();
    names.dedup();
    names
}

#[test]
fn arm_fixture_mangled_names_are_unique() {
    let mut mangled: Vec<&'static str> = ARM_FIXTURES
        .iter()
        .map(|f: &ArmFixture| f.mangled)
        .collect();
    let before: usize = mangled.len();
    mangled.sort_unstable();
    mangled.dedup();
    assert_eq!(
        mangled.len(),
        before,
        "the fixture corpus must not grade the same mangled symbol under two arm names"
    );
}

#[test]
fn arm_fixtures_demangle_to_pinned_text() {
    for fixture in ARM_FIXTURES {
        let rendered: String = demangle::demangle(fixture.mangled).unwrap_or_else(|e| {
            panic!(
                "arm {} ({}) must demangle, got {e:?}",
                fixture.arm, fixture.mangled
            )
        });
        assert_eq!(
            rendered, fixture.expected,
            "arm {} regressed for {}",
            fixture.arm, fixture.mangled
        );
    }
}

#[test]
fn arm_fixtures_match_live_swift_demangle() {
    let Some(demangler): Option<ReferenceDemangler> = resolve_reference_demangler(GRADED) else {
        return;
    };
    let symbols: Vec<&str> = ARM_FIXTURES
        .iter()
        .map(|f: &ArmFixture| f.mangled)
        .collect();
    let live: Vec<String> = reference_demangle(&demangler, &symbols);
    for (fixture, actual) in ARM_FIXTURES.iter().zip(live.iter()) {
        assert_eq!(
            fixture.expected,
            actual,
            "the pinned text for arm {} drifted from what {} produces for {}. {}",
            fixture.arm,
            demangler.tool.display(),
            fixture.mangled,
            provenance_note(&demangler.identity)
        );
    }
}

#[test]
fn named_arm_coverage_is_measured_by_the_gate() {
    let closed: Vec<&'static str> = closed_arm_names();
    for arm in &closed {
        assert!(
            !OPEN_ARMS.contains(arm),
            "{arm} is listed as both closed (has a fixture) and open (documented gap)"
        );
    }
    let total: usize = closed.len() + OPEN_ARMS.len();
    let ratio: f64 = closed.len() as f64 / total as f64;
    eprintln!(
        "FEAT-023 named-arm coverage: {}/{} = {:.1}% closed with a real-compiler-graded fixture. \
         still open: {OPEN_ARMS:?}",
        closed.len(),
        total,
        ratio * 100.0
    );
    assert!(
        ratio > 0.75,
        "named-arm coverage must exceed the recorded 0.75 baseline, measured {}/{} = {:.3}",
        closed.len(),
        total,
        ratio
    );
}

const CROSS_CUTTING_FORMS: &[(&str, &str)] = &[
    (
        "generic_signature_with_requirements",
        "generic_signature_with_requirements",
    ),
    ("associated_types", "associated_type_descriptor"),
    ("substitution_back_references", "protocol_witness_thunk"),
    (
        "protocol_conformance_descriptors",
        "protocol_conformance_descriptor",
    ),
    ("compressed_identifiers", "protocol_witness_thunk"),
];

#[test]
fn every_cross_cutting_form_is_exercised_inside_a_closed_arm() {
    let closed: Vec<&'static str> = closed_arm_names();
    for (form, arm) in CROSS_CUTTING_FORMS {
        assert!(
            closed.contains(arm),
            "cross-cutting form {form} is claimed to be exercised inside arm {arm}, but that \
             arm has no closed, real-compiler-graded fixture"
        );
    }
}

#[test]
fn mangling_prefixes_across_swift_releases_are_all_accepted() {
    let body: &str = "4Arms7GreeterP";
    let expected: &str = "Arms.Greeter (protocol)";
    for prefix in ["_$s", "$s", "_$S", "$S", "_T0", "T0"] {
        let symbol: String = format!("{prefix}{body}");
        let rendered: String = demangle::demangle(&symbol)
            .unwrap_or_else(|e| panic!("prefix {prefix} must be accepted, got {e:?}"));
        assert_eq!(rendered, expected, "prefix {prefix} rendered differently");
    }
    assert!(
        demangle::demangle("_$t4Arms7GreeterP").is_err(),
        "an unrecognized prefix must abstain rather than guess"
    );
}

#[test]
fn a_symbolic_reference_that_cannot_resolve_abstains() {
    assert!(
        demangle::demangle_type("\u{1}").is_none(),
        "a control byte standing in for an unresolved symbolic reference must abstain, not guess"
    );
    assert!(
        demangle::demangle("$s\u{1}").is_err(),
        "a symbol carrying a raw symbolic-reference byte must abstain rather than echo it back"
    );
}

#[test]
fn a_substitution_index_beyond_the_table_abstains() {
    assert!(
        demangle::demangle("$sAB").is_err(),
        "the first substitution reference in a symbol has nothing to resolve against and must \
         abstain, not panic or guess"
    );
}

#[test]
fn a_punycode_identifier_that_fails_to_decode_abstains() {
    assert!(
        demangle::demangle("$s004fooP").is_err(),
        "a malformed punycode-prefixed identifier must abstain rather than emit garbage text"
    );
}

#[test]
fn a_mangled_name_over_the_length_bound_is_rejected() {
    let oversized: String = format!("$s4Arms{}P", "A".repeat(1 << 17));
    assert!(
        demangle::demangle(&oversized).is_err(),
        "a mangled name far past any real symbol's length must be capped and rejected"
    );
}

#[test]
fn a_truncated_mangled_name_yields_a_typed_error_not_a_panic() {
    let full: &str = ARM_FIXTURES[0].mangled;
    for end in 1..full.len() {
        let _: Result<String, _> = demangle::demangle(&full[..end]);
    }
}
