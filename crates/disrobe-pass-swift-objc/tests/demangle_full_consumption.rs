#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/swift_toolchain.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod swift_toolchain;

use disrobe_pass_swift_objc::demangle;
use disrobe_pass_swift_objc::error::Error;

use swift_toolchain::{
    ReferenceDemangler, provenance_note, reference_demangle, resolve_reference_demangler,
};

const RESIDUE_GRADED: &str =
    "abstention on a valid Swift mangling followed by bytes the real swift-demangle refuses";
const SPECIALIZATION_GRADED: &str =
    "byte-exact agreement with swift-demangle on function signature specialization manglings";

#[derive(Debug, Clone, Copy)]
struct ResidueCase {
    base: &'static str,
    residue: &'static str,
}

const PROTOCOL_BASE: &str = "$s4Arms7GreeterP";
const CLASS_BASE: &str = "$s10SwiftHello19LoginViewControllerC";
const METHOD_BASE: &str = "$s10SwiftHello19LoginViewControllerC15greetWithBannerSSyF";
const STATIC_BASE: &str = "$s10SwiftHello0B11RunnerEntryV4mainyyFZ";
const ANYOBJECT_BASE: &str = "$s4Arms14anyObjectParamyyyXlF";

const RESIDUE_CASES: &[ResidueCase] = &[
    ResidueCase {
        base: PROTOCOL_BASE,
        residue: "QQQQ",
    },
    ResidueCase {
        base: PROTOCOL_BASE,
        residue: "999",
    },
    ResidueCase {
        base: PROTOCOL_BASE,
        residue: "Ym",
    },
    ResidueCase {
        base: PROTOCOL_BASE,
        residue: "XX",
    },
    ResidueCase {
        base: PROTOCOL_BASE,
        residue: "Sq9",
    },
    ResidueCase {
        base: PROTOCOL_BASE,
        residue: "Tz",
    },
    ResidueCase {
        base: PROTOCOL_BASE,
        residue: "Tv",
    },
    ResidueCase {
        base: PROTOCOL_BASE,
        residue: "Tb",
    },
    ResidueCase {
        base: CLASS_BASE,
        residue: "QQQQ",
    },
    ResidueCase {
        base: CLASS_BASE,
        residue: "Ym",
    },
    ResidueCase {
        base: CLASS_BASE,
        residue: "XX",
    },
    ResidueCase {
        base: CLASS_BASE,
        residue: "Sq9",
    },
    ResidueCase {
        base: CLASS_BASE,
        residue: "Rz",
    },
    ResidueCase {
        base: METHOD_BASE,
        residue: "T",
    },
    ResidueCase {
        base: STATIC_BASE,
        residue: "Tf4d_",
    },
    ResidueCase {
        base: STATIC_BASE,
        residue: "Tf4d_gn",
    },
    ResidueCase {
        base: ANYOBJECT_BASE,
        residue: "QQQQ",
    },
    ResidueCase {
        base: ANYOBJECT_BASE,
        residue: "zzz",
    },
    ResidueCase {
        base: ANYOBJECT_BASE,
        residue: "_t",
    },
    ResidueCase {
        base: ANYOBJECT_BASE,
        residue: "Rz",
    },
];

fn glued(case: ResidueCase) -> String {
    format!("{}{}", case.base, case.residue)
}

#[test]
fn every_residue_case_starts_from_a_base_the_demangler_recovers() {
    for case in RESIDUE_CASES {
        assert!(
            demangle::demangle(case.base).is_ok(),
            "the residue corpus grades a valid prefix followed by refused bytes, so the bare \
             prefix {} must itself demangle; a base that abstains grades nothing",
            case.base
        );
    }
}

#[test]
fn a_valid_prefix_with_trailing_bytes_never_returns_the_prefix_reading() {
    for case in RESIDUE_CASES {
        let prefix_reading: String = demangle::demangle(case.base)
            .unwrap_or_else(|e| panic!("base {} must demangle, got {e:?}", case.base));
        let full: String = glued(*case);
        let rendered: Option<String> = demangle::demangle(&full).ok();
        assert_ne!(
            rendered.as_deref(),
            Some(prefix_reading.as_str()),
            "{full} carries bytes past a valid parse of {}, so returning the prefix's own reading \
             claims the whole symbol was understood when it was not",
            case.base
        );
    }
}

#[test]
fn a_valid_prefix_with_unconsumed_trailing_bytes_abstains() {
    for case in RESIDUE_CASES {
        let full: String = glued(*case);
        let rendered: Result<String, Error> = demangle::demangle(&full);
        assert!(
            rendered.is_err(),
            "{full} must abstain rather than render {:?}; a reading that ignores unconsumed bytes \
             is not a proven-complete reading of the symbol",
            rendered.ok()
        );
    }
}

#[test]
fn an_unconsumed_suffix_is_a_distinct_outcome_from_a_symbol_that_is_not_swift() {
    let case: ResidueCase = RESIDUE_CASES[0];
    let residue_error: Error = demangle::demangle(&glued(case))
        .expect_err("a symbol with unconsumed trailing bytes must abstain");
    assert!(
        matches!(residue_error, Error::DemangleResidue { .. }),
        "abstention on unconsumed input must be its own typed outcome, got {residue_error:?}"
    );
    let foreign_error: Error =
        demangle::demangle("_Z3foov").expect_err("a non-Swift symbol must abstain");
    assert!(
        matches!(foreign_error, Error::Demangle(_)),
        "a symbol that is not Swift-mangled at all must stay distinguishable from one that parsed \
         and left bytes behind, got {foreign_error:?}"
    );
}

#[test]
fn an_empty_and_a_prefix_only_symbol_abstain() {
    for symbol in ["", "$s", "_$s", "$S", "_T0"] {
        assert!(
            demangle::demangle(symbol).is_err(),
            "{symbol:?} carries no entity and must abstain"
        );
    }
}

#[test]
fn a_symbol_valid_up_to_its_last_byte_abstains_on_that_byte() {
    let off_by_one: &str = "$s4Arms7GreeterPQ";
    assert!(
        demangle::demangle(off_by_one).is_err(),
        "a single unconsumed byte past a valid parse must abstain exactly like a longer residue"
    );
}

#[test]
fn the_residue_corpus_is_refused_by_live_swift_demangle() {
    let Some(demangler): Option<ReferenceDemangler> = resolve_reference_demangler(RESIDUE_GRADED)
    else {
        return;
    };
    let glued_symbols: Vec<String> = RESIDUE_CASES
        .iter()
        .map(|c: &ResidueCase| glued(*c))
        .collect();
    let borrowed: Vec<&str> = glued_symbols.iter().map(String::as_str).collect();
    let live: Vec<String> = reference_demangle(&demangler, &borrowed);
    for (symbol, answer) in borrowed.iter().zip(live.iter()) {
        assert_eq!(
            answer,
            symbol,
            "the residue corpus claims {symbol} is not a readable Swift symbol, but {} read it as \
             {answer}. {}",
            demangler.tool.display(),
            provenance_note(&demangler.identity)
        );
    }
}

#[derive(Debug, Clone, Copy)]
struct SpecializationFixture {
    mangled: &'static str,
    expected: &'static str,
}

const SPECIALIZATION_FIXTURES: &[SpecializationFixture] = &[
    SpecializationFixture {
        mangled: "$s10SwiftHello0B11RunnerEntryV4mainyyFZTf4d_n",
        expected: "function signature specialization <Arg[0] = Dead> of static SwiftHello.HelloRunnerEntry.main() -> ()",
    },
    SpecializationFixture {
        mangled: "$s10SwiftHello0B11RunnerEntryV4mainyyFZTf4dn_n",
        expected: "function signature specialization <Arg[0] = Dead> of static SwiftHello.HelloRunnerEntry.main() -> ()",
    },
    SpecializationFixture {
        mangled: "$s10SwiftHello0B11RunnerEntryV4mainyyFZTf4nd_n",
        expected: "function signature specialization <Arg[1] = Dead> of static SwiftHello.HelloRunnerEntry.main() -> ()",
    },
    SpecializationFixture {
        mangled: "$s10SwiftHello0B11RunnerEntryV4mainyyFZTf4n_n",
        expected: "function signature specialization <> of static SwiftHello.HelloRunnerEntry.main() -> ()",
    },
    SpecializationFixture {
        mangled: "$s10SwiftHello0B11RunnerEntryV4mainyyFZTf4d_d",
        expected: "function signature specialization <Arg[0] = Dead, Return = Dead> of static SwiftHello.HelloRunnerEntry.main() -> ()",
    },
    SpecializationFixture {
        mangled: "$s10SwiftHello0B11RunnerEntryV4mainyyFZTf4dG_n",
        expected: "function signature specialization <Arg[0] = Dead and Owned To Guaranteed> of static SwiftHello.HelloRunnerEntry.main() -> ()",
    },
    SpecializationFixture {
        mangled: "$s10SwiftHello0B11RunnerEntryV4mainyyFZTf4dX_n",
        expected: "function signature specialization <Arg[0] = Dead and Exploded> of static SwiftHello.HelloRunnerEntry.main() -> ()",
    },
    SpecializationFixture {
        mangled: "$s10SwiftHello0B11RunnerEntryV4mainyyFZTf4gX_n",
        expected: "function signature specialization <Arg[0] = Owned To Guaranteed and Exploded> of static SwiftHello.HelloRunnerEntry.main() -> ()",
    },
    SpecializationFixture {
        mangled: "$s10SwiftHello0B11RunnerEntryV4mainyyFZTf4o_n",
        expected: "function signature specialization <Arg[0] = Guaranteed To Owned> of static SwiftHello.HelloRunnerEntry.main() -> ()",
    },
    SpecializationFixture {
        mangled: "$s10SwiftHello0B11RunnerEntryV4mainyyFZTf4x_n",
        expected: "function signature specialization <Arg[0] = Exploded> of static SwiftHello.HelloRunnerEntry.main() -> ()",
    },
    SpecializationFixture {
        mangled: "$s10SwiftHello0B11RunnerEntryV4mainyyFZTf4i_n",
        expected: "function signature specialization <Arg[0] = Value Promoted from Box> of static SwiftHello.HelloRunnerEntry.main() -> ()",
    },
    SpecializationFixture {
        mangled: "$s10SwiftHello0B11RunnerEntryV4mainyyFZTf4s_n",
        expected: "function signature specialization <Arg[0] = Stack Promoted from Box> of static SwiftHello.HelloRunnerEntry.main() -> ()",
    },
    SpecializationFixture {
        mangled: "$s10SwiftHello0B11RunnerEntryV4mainyyFZTf4r_n",
        expected: "function signature specialization <Arg[0] = InOut Converted to Out> of static SwiftHello.HelloRunnerEntry.main() -> ()",
    },
    SpecializationFixture {
        mangled: "$s10SwiftHello0B11RunnerEntryV4mainyyFZTfq4d_n",
        expected: "function signature specialization <serialized, Arg[0] = Dead> of static SwiftHello.HelloRunnerEntry.main() -> ()",
    },
    SpecializationFixture {
        mangled: "$s10SwiftHello0B11RunnerEntryV4mainyyFZTf4ddd_n",
        expected: "function signature specialization <Arg[0] = Dead, Arg[1] = Dead, Arg[2] = Dead> of static SwiftHello.HelloRunnerEntry.main() -> ()",
    },
    SpecializationFixture {
        mangled: "$s4Spec7deadArgyS2i_SitFTf4dn_n",
        expected: "function signature specialization <Arg[0] = Dead> of Spec.deadArg(Swift.Int, Swift.Int) -> Swift.Int",
    },
    SpecializationFixture {
        mangled: "$s4Spec8manyArgsyS2i_S2iSStFTf4nnnd_n",
        expected: "function signature specialization <Arg[3] = Dead> of Spec.manyArgs(Swift.Int, Swift.Int, Swift.Int, Swift.String) -> Swift.Int",
    },
];

const SPECIALIZATION_REFUSALS: &[&str] = &[
    "$s10SwiftHello0B11RunnerEntryV4mainyyFZTf4gG_n",
    "$s10SwiftHello0B11RunnerEntryV4mainyyFZTf4dXG_n",
    "$s10SwiftHello0B11RunnerEntryV4mainyyFZTf4c_n",
    "$s10SwiftHello0B11RunnerEntryV4mainyyFZTf10d_n",
];

#[test]
fn function_signature_specializations_demangle_to_pinned_text() {
    for fixture in SPECIALIZATION_FIXTURES {
        let rendered: String = demangle::demangle(fixture.mangled).unwrap_or_else(|e| {
            panic!(
                "function signature specialization {} must demangle, got {e:?}",
                fixture.mangled
            )
        });
        assert_eq!(
            rendered, fixture.expected,
            "function signature specialization regressed for {}",
            fixture.mangled
        );
    }
}

#[test]
fn a_specialization_shape_outside_the_recovered_grammar_abstains() {
    for mangled in SPECIALIZATION_REFUSALS {
        assert!(
            demangle::demangle(mangled).is_err(),
            "{mangled} is not a shape this demangler reads, so it must abstain rather than drop \
             the specialization and report the base symbol"
        );
    }
}

#[test]
fn specialization_fixtures_match_live_swift_demangle() {
    let Some(demangler): Option<ReferenceDemangler> =
        resolve_reference_demangler(SPECIALIZATION_GRADED)
    else {
        return;
    };
    let symbols: Vec<&str> = SPECIALIZATION_FIXTURES
        .iter()
        .map(|f: &SpecializationFixture| f.mangled)
        .collect();
    let live: Vec<String> = reference_demangle(&demangler, &symbols);
    for (fixture, actual) in SPECIALIZATION_FIXTURES.iter().zip(live.iter()) {
        assert_eq!(
            fixture.expected,
            actual,
            "the pinned text for {} drifted from what {} produces. {}",
            fixture.mangled,
            demangler.tool.display(),
            provenance_note(&demangler.identity)
        );
    }
    let refusals: Vec<&str> = SPECIALIZATION_REFUSALS.to_vec();
    let refused: Vec<String> = reference_demangle(&demangler, &refusals);
    for (symbol, answer) in refusals.iter().zip(refused.iter()) {
        assert_eq!(
            answer,
            symbol,
            "{symbol} is pinned as a shape outside the readable grammar, but {} read it as \
             {answer}. {}",
            demangler.tool.display(),
            provenance_note(&demangler.identity)
        );
    }
}
