#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/swift_toolchain.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod swift_toolchain;

use disrobe_pass_swift_objc::demangle;

use swift_toolchain::{
    ReferenceDemangler, provenance_note, reference_demangle, resolve_reference_demangler,
};

const GRADED: &str = "byte-exact agreement with swift-demangle on closure-parameter signatures a real swiftc emitted";

#[derive(Debug, Clone, Copy)]
struct ClosureFixture {
    shape: &'static str,
    mangled: &'static str,
    reference: &'static str,
    exact: bool,
}

const CLOSURE_FIXTURES: &[ClosureFixture] = &[
    ClosureFixture {
        shape: "non_sendable_closure",
        mangled: "$s4Arms18nonSendableClosureyyyyXEF",
        reference: "Arms.nonSendableClosure(() -> ()) -> ()",
        exact: true,
    },
    ClosureFixture {
        shape: "sendable_closure",
        mangled: "$s4Arms15sendableClosureyyyyYbXEF",
        reference: "Arms.sendableClosure(@Sendable () -> ()) -> ()",
        exact: true,
    },
    ClosureFixture {
        shape: "escaping_closure",
        mangled: "$s4Arms15escapingClosureyyyycF",
        reference: "Arms.escapingClosure(() -> ()) -> ()",
        exact: true,
    },
    ClosureFixture {
        shape: "closure_first_of_two_parameters",
        mangled: "$s4Arms12closureFirstyyyyXE_SitF",
        reference: "Arms.closureFirst(() -> (), Swift.Int) -> ()",
        exact: true,
    },
    ClosureFixture {
        shape: "closure_last_of_two_parameters",
        mangled: "$s4Arms11closureLastyySi_yyXEtF",
        reference: "Arms.closureLast(Swift.Int, () -> ()) -> ()",
        exact: true,
    },
    ClosureFixture {
        shape: "closure_between_two_parameters",
        mangled: "$s4Arms13closureMiddleyySi_yyXESStF",
        reference: "Arms.closureMiddle(Swift.Int, () -> (), Swift.String) -> ()",
        exact: true,
    },
    ClosureFixture {
        shape: "two_closure_parameters",
        mangled: "$s4Arms11twoClosuresyyyyXE_yyXEtF",
        reference: "Arms.twoClosures(() -> (), () -> ()) -> ()",
        exact: true,
    },
    ClosureFixture {
        shape: "closure_nested_one_level",
        mangled: "$s4Arms13nestedClosureyyyyyXEXEF",
        reference: "Arms.nestedClosure((() -> ()) -> ()) -> ()",
        exact: true,
    },
    ClosureFixture {
        shape: "closure_nested_two_levels",
        mangled: "$s4Arms19doubleNestedClosureyyyyyyXEXEXEF",
        reference: "Arms.doubleNestedClosure(((() -> ()) -> ()) -> ()) -> ()",
        exact: true,
    },
    ClosureFixture {
        shape: "closure_with_labels",
        mangled: "$s4Arms14labeledClosure7handler5countyyyXE_SitF",
        reference: "Arms.labeledClosure(handler: () -> (), count: Swift.Int) -> ()",
        exact: true,
    },
    ClosureFixture {
        shape: "closure_over_any_object",
        mangled: "$s4Arms16anyObjectClosureyyyyXlXEF",
        reference: "Arms.anyObjectClosure((Swift.AnyObject) -> ()) -> ()",
        exact: true,
    },
    ClosureFixture {
        shape: "any_object_parameter",
        mangled: "$s4Arms14anyObjectParamyyyXlF",
        reference: "Arms.anyObjectParam(Swift.AnyObject) -> ()",
        exact: true,
    },
    ClosureFixture {
        shape: "closure_taking_a_value",
        mangled: "$s4Arms16closureTakingIntyyySiXEF",
        reference: "Arms.closureTakingInt((Swift.Int) -> ()) -> ()",
        exact: true,
    },
    ClosureFixture {
        shape: "closure_returning_a_value",
        mangled: "$s4Arms19closureReturningIntyySiyXEF",
        reference: "Arms.closureReturningInt(() -> Swift.Int) -> ()",
        exact: true,
    },
    ClosureFixture {
        shape: "closure_returning_a_closure",
        mangled: "$s4Arms21closureReturnsClosureyyyycyXEF",
        reference: "Arms.closureReturnsClosure(() -> () -> ()) -> ()",
        exact: true,
    },
    ClosureFixture {
        shape: "closure_as_the_result",
        mangled: "$s4Arms13closureResultyycyF",
        reference: "Arms.closureResult() -> () -> ()",
        exact: true,
    },
    ClosureFixture {
        shape: "throwing_closure",
        mangled: "$s4Arms15throwingClosureyyyyKXEKF",
        reference: "Arms.throwingClosure(() throws -> ()) throws -> ()",
        exact: true,
    },
    ClosureFixture {
        shape: "autoclosure",
        mangled: "$s4Arms16autoclosureParamyySiyXKF",
        reference: "Arms.autoclosureParam(@autoclosure () -> Swift.Int) -> ()",
        exact: true,
    },
    ClosureFixture {
        shape: "async_closure",
        mangled: "$s4Arms12asyncClosureyyyyYaXEYaF",
        reference: "Arms.asyncClosure(() async -> ()) async -> ()",
        exact: true,
    },
    ClosureFixture {
        shape: "async_closure_function_pointer",
        mangled: "$s4Arms12asyncClosureyyyyYaXEYaFTu",
        reference: "async function pointer to Arms.asyncClosure(() async -> ()) async -> ()",
        exact: true,
    },
    ClosureFixture {
        shape: "generic_closure",
        mangled: "$s4Arms14genericClosureyyxxXElF",
        reference: "Arms.genericClosure<A>((A) -> A) -> ()",
        exact: true,
    },
    ClosureFixture {
        shape: "closure_entity_inside_a_function",
        mangled: "$s4Arms13closureResultyycyFyycfU_",
        reference: "closure #1 () -> () in Arms.closureResult() -> () -> ()",
        exact: false,
    },
];

#[test]
fn no_closure_fixture_renders_text_the_compiler_did_not_emit() {
    let mut wrong: Vec<String> = Vec::new();
    for fixture in CLOSURE_FIXTURES {
        let Ok(rendered): Result<String, _> = demangle::demangle(fixture.mangled) else {
            continue;
        };
        if rendered != fixture.reference {
            wrong.push(format!(
                "{} ({})\n    swiftc/swift-demangle: {}\n    disrobe:               {rendered}",
                fixture.shape, fixture.mangled, fixture.reference
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "a demangled signature that is neither the compiler's own signature nor an abstention \
         silently rewrites the program the analyst is reading:\n{}",
        wrong.join("\n")
    );
}

#[test]
fn every_declared_closure_shape_keeps_its_closure_parameter() {
    let mut lost: Vec<String> = Vec::new();
    for fixture in CLOSURE_FIXTURES
        .iter()
        .filter(|f: &&ClosureFixture| f.exact)
    {
        match demangle::demangle(fixture.mangled) {
            Ok(rendered) if rendered == fixture.reference => {}
            Ok(rendered) => lost.push(format!(
                "{} ({}): rendered {rendered}, expected {}",
                fixture.shape, fixture.mangled, fixture.reference
            )),
            Err(error) => lost.push(format!(
                "{} ({}): abstained with {error:?}, expected {}",
                fixture.shape, fixture.mangled, fixture.reference
            )),
        }
    }
    let total: usize = CLOSURE_FIXTURES
        .iter()
        .filter(|f: &&ClosureFixture| f.exact)
        .count();
    eprintln!(
        "closure-parameter recovery: {} of {total} compiler-emitted closure shapes render to the \
         reference signature",
        total - lost.len()
    );
    assert!(
        lost.is_empty(),
        "these compiler-emitted closure signatures do not round-trip to the text the real \
         toolchain prints:\n{}",
        lost.join("\n")
    );
}

#[test]
fn the_repro_symbol_keeps_its_non_sendable_closure_parameter() {
    let rendered: String = demangle::demangle("$s4Arms18nonSendableClosureyyyyXEF")
        .expect("the non-sendable closure repro must demangle");
    assert_eq!(
        rendered, "Arms.nonSendableClosure(() -> ()) -> ()",
        "the non-sendable closure parameter must survive; dropping it reports a signature the \
         compiler never emitted"
    );
}

#[test]
fn closure_fixtures_match_live_swift_demangle() {
    let Some(demangler): Option<ReferenceDemangler> = resolve_reference_demangler(GRADED) else {
        return;
    };
    let symbols: Vec<&str> = CLOSURE_FIXTURES
        .iter()
        .map(|f: &ClosureFixture| f.mangled)
        .collect();
    let live: Vec<String> = reference_demangle(&demangler, &symbols);
    for (fixture, actual) in CLOSURE_FIXTURES.iter().zip(live.iter()) {
        assert_eq!(
            fixture.reference,
            actual,
            "the pinned reference signature for shape {} drifted from what {} produces for {}. {}",
            fixture.shape,
            demangler.tool.display(),
            fixture.mangled,
            provenance_note(&demangler.identity)
        );
    }
}

#[test]
fn closure_fixture_mangled_names_are_unique() {
    let mut mangled: Vec<&'static str> = CLOSURE_FIXTURES
        .iter()
        .map(|f: &ClosureFixture| f.mangled)
        .collect();
    let before: usize = mangled.len();
    mangled.sort_unstable();
    mangled.dedup();
    assert_eq!(
        mangled.len(),
        before,
        "the closure corpus must not grade the same mangled symbol under two shape names"
    );
}
