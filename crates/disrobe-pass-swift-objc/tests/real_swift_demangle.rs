#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/macho_corpus.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod macho_corpus;

#[path = "support/swift_toolchain.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod swift_toolchain;

use disrobe_pass_swift_objc::demangle;
use disrobe_pass_swift_objc::macho::{self, CpuKind, ParsedSlice};

use macho_corpus::{
    CorpusFixture, SWIFT_DRIVER, SWIFT_HELLO_OBFUSCATED, SWIFT_HELLO_ORIGINAL, first_slice,
    read_host_sourced, read_tracked, slice_preferring,
};
use swift_toolchain::{
    ReferenceDemangler, provenance_note, reference_demangle, resolve_reference_demangler,
};

fn swift_mangled_symbols(slice: &[u8], parsed: &ParsedSlice) -> Vec<String> {
    let mut out: Vec<String> = macho::symbol_names(slice, parsed)
        .into_iter()
        .filter(|s: &String| demangle::looks_like_swift_mangled(s))
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

fn tracked_slice(fixture: CorpusFixture) -> (Vec<u8>, ParsedSlice) {
    let bytes: Vec<u8> = read_tracked(fixture);
    first_slice(fixture, &bytes)
}

const UNREADABLE_BY_REFERENCE: [&str; 2] = [
    "_$ss23_ContiguousArrayStorageCyypGMR",
    "_$ss23_ContiguousArrayStorageCyypGMd",
];

const READABILITY_GRADED: &str =
    "the set of committed-fixture symbols the real swift-demangle itself refuses to read";

fn readable_population(fixture_name: &str, symbols: &[String]) -> usize {
    for unreadable in UNREADABLE_BY_REFERENCE {
        assert!(
            symbols.iter().any(|s: &String| s == unreadable),
            "{unreadable} is excluded from {fixture_name}'s recovery denominator because the \
             reference demangler cannot read it, so it must still be present in that symbol \
             table; a stale exclusion silently shrinks what the recovery rate is measured against"
        );
    }
    symbols.len() - UNREADABLE_BY_REFERENCE.len()
}

fn assert_recovery_rate(fixture_name: &str, symbols: &[String]) {
    let population: usize = readable_population(fixture_name, symbols);
    let demangled: usize = symbols
        .iter()
        .filter(|s: &&String| !UNREADABLE_BY_REFERENCE.contains(&s.as_str()))
        .filter(|s: &&String| demangle::demangle(s).is_ok())
        .count();
    let ratio: f64 = demangled as f64 / population as f64;
    assert!(
        ratio >= 0.95,
        "demangler must recover >=95% of {fixture_name}'s readable symbols, got {demangled}/{population} = {:.1}%",
        ratio * 100.0
    );
}

#[test]
fn swift_hello_symbol_table_demangles_above_threshold() {
    let (slice, parsed): (Vec<u8>, ParsedSlice) = tracked_slice(SWIFT_HELLO_ORIGINAL);
    let symbols: Vec<String> = swift_mangled_symbols(&slice, &parsed);

    assert!(
        symbols.len() >= 30,
        "SwiftHello.original LC_SYMTAB must expose 30+ Swift-mangled symbols, got {}",
        symbols.len()
    );

    assert_recovery_rate("SwiftHello.original", &symbols);
}

#[test]
fn the_unreadable_exclusion_list_is_exactly_what_the_reference_refuses() {
    let Some(demangler): Option<ReferenceDemangler> =
        resolve_reference_demangler(READABILITY_GRADED)
    else {
        return;
    };
    for fixture in [SWIFT_HELLO_ORIGINAL, SWIFT_HELLO_OBFUSCATED] {
        let (slice, parsed): (Vec<u8>, ParsedSlice) = tracked_slice(fixture);
        let symbols: Vec<String> = swift_mangled_symbols(&slice, &parsed);
        let borrowed: Vec<&str> = symbols.iter().map(String::as_str).collect();
        let live: Vec<String> = reference_demangle(&demangler, &borrowed);
        let refused: Vec<&str> = borrowed
            .iter()
            .zip(live.iter())
            .filter(|(symbol, answer): &(&&str, &String)| *answer == **symbol)
            .map(|(symbol, _): (&&str, &String)| *symbol)
            .collect();
        assert_eq!(
            refused,
            UNREADABLE_BY_REFERENCE.to_vec(),
            "the recovery denominator excludes exactly the symbols {} cannot read in {}; an \
             exclusion the reference actually reads would hide a real recovery gap. {}",
            demangler.tool.display(),
            fixture.name,
            provenance_note(&demangler.identity)
        );
    }
}

#[test]
fn swift_hello_demangle_recovers_ground_truth_class_names() {
    let (slice, parsed): (Vec<u8>, ParsedSlice) = tracked_slice(SWIFT_HELLO_ORIGINAL);
    let symbols: Vec<String> = swift_mangled_symbols(&slice, &parsed);

    let rendered: Vec<String> = symbols
        .iter()
        .filter_map(|s: &String| demangle::demangle(s).ok())
        .collect();
    let joined: String = rendered.join("\n");

    for expected in [
        "SwiftHello.LoginViewController",
        "SwiftHello.AuthenticationService",
    ] {
        assert!(
            joined.contains(expected),
            "demangled symbol table must contain ground-truth class {expected}"
        );
    }
}

#[test]
fn swift_hello_demangle_recovers_entity_kinds_and_descriptors() {
    let (slice, parsed): (Vec<u8>, ParsedSlice) = tracked_slice(SWIFT_HELLO_ORIGINAL);
    let symbols: Vec<String> = swift_mangled_symbols(&slice, &parsed);
    let rendered: String = symbols
        .iter()
        .filter_map(|s: &String| demangle::demangle(s).ok())
        .collect::<Vec<String>>()
        .join("\n");

    assert!(
        rendered.contains("nominal type descriptor for SwiftHello."),
        "expected a recovered nominal type descriptor entity"
    );
    assert!(
        rendered.contains("type metadata for SwiftHello."),
        "expected a recovered type-metadata entity"
    );
    assert!(
        rendered.contains("field offset for SwiftHello."),
        "expected a recovered field-offset entity carrying a real property name"
    );
    assert!(
        rendered.contains(".__deallocating_deinit"),
        "expected a recovered deallocating destructor entity"
    );
    assert!(
        rendered.contains("function signature specialization <Arg[0] = Dead> of static "),
        "expected an optimizer-specialized entity read all the way through its Tf suffix rather \
         than reported as the unspecialized function it wraps"
    );
}

fn driver_arm64_slice() -> Option<(Vec<u8>, ParsedSlice)> {
    let bytes: Vec<u8> = read_host_sourced(SWIFT_DRIVER)?;
    Some(slice_preferring(SWIFT_DRIVER, &bytes, CpuKind::Arm64))
}

fn tuple_shaped(mangled: &str) -> bool {
    mangled.ends_with('t') && mangled.contains('_') && mangled.is_ascii()
}

#[test]
fn swift_driver_enum_payload_tuples_demangle_above_threshold() {
    use disrobe_pass_swift_objc::swift::{self, SwiftClassDump};
    use disrobe_pass_swift_objc::swift_typedump::{NominalKind, SwiftNominalType};

    let Some((slice, parsed)): Option<(Vec<u8>, ParsedSlice)> = driver_arm64_slice() else {
        return;
    };
    let dump: SwiftClassDump = swift::class_dump(&slice, &parsed);

    let payloads: Vec<String> = dump
        .type_dump
        .nominal_types
        .iter()
        .filter(|t: &&SwiftNominalType| matches!(t.kind, NominalKind::Enum))
        .flat_map(|t: &SwiftNominalType| t.fields.iter())
        .filter_map(|f| f.mangled_type.clone())
        .filter(|m: &String| tuple_shaped(m))
        .collect();

    assert!(
        payloads.len() >= 15,
        "swift-driver's own __swift5_fieldmd must expose 15+ tuple-shaped enum payloads, got {}",
        payloads.len()
    );

    let demangled: usize = payloads
        .iter()
        .filter(|m: &&String| {
            demangle::demangle_type(m)
                .is_some_and(|d: String| d.starts_with('(') && d.ends_with(')'))
        })
        .count();
    let ratio: f64 = demangled as f64 / payloads.len() as f64;
    assert!(
        ratio >= 0.85,
        "labeled-tuple payload demangling must clear 85% of the binary's own tuple payloads, \
         got {demangled}/{} = {:.1}%",
        payloads.len(),
        ratio * 100.0
    );

    let labeled: bool = payloads
        .iter()
        .any(|m: &String| demangle::demangle_type(m).is_some_and(|d: String| d.contains(": ")));
    assert!(
        labeled,
        "at least one recovered enum payload must carry a Swift tuple element label"
    );
}

#[test]
fn swift_driver_field_types_demangle_at_ceiling() {
    use disrobe_pass_swift_objc::swift::{self, SwiftClassDump};
    use disrobe_pass_swift_objc::swift_typedump::SwiftNominalType;

    let Some((slice, parsed)): Option<(Vec<u8>, ParsedSlice)> = driver_arm64_slice() else {
        return;
    };
    let dump: SwiftClassDump = swift::class_dump(&slice, &parsed);

    let field_types: Vec<String> = dump
        .type_dump
        .nominal_types
        .iter()
        .flat_map(|t: &SwiftNominalType| t.fields.iter())
        .filter_map(|f| f.mangled_type.clone())
        .filter(|m: &String| m.is_ascii())
        .collect();
    assert!(
        field_types.len() >= 400,
        "binary-context symbolic-ref resolution must surface 400+ ascii field-type mangled \
         names, got {}",
        field_types.len()
    );

    let demangled: usize = field_types
        .iter()
        .filter(|m: &&String| demangle::demangle_type(m).is_some())
        .count();
    let ratio: f64 = demangled as f64 / field_types.len() as f64;
    assert!(
        ratio >= 0.98,
        "field-type demangling must hold the recovered ceiling, got {demangled}/{} = {:.1}%",
        field_types.len(),
        ratio * 100.0
    );

    let objc: bool = field_types
        .iter()
        .filter_map(|m: &String| demangle::demangle_type(m))
        .any(|d: String| d.contains("__C."));
    assert!(
        objc,
        "objc-imported field types must resolve to the __C clang-importer module"
    );

    let symbolic_resolved: bool = field_types
        .iter()
        .filter_map(|m: &String| demangle::demangle_type(m))
        .any(|d: String| d.contains("swiftscan_") || d.contains("SwiftDriver"));
    assert!(
        symbolic_resolved,
        "a symbolic-referenced field type must resolve to its descriptor name via binary context"
    );

    let c_function: bool = field_types
        .iter()
        .filter_map(|m: &String| demangle::demangle_type(m))
        .any(|d: String| d.contains("@convention(c)"));
    assert!(
        c_function,
        "a C-convention function-pointer field type must demangle to its signature"
    );
}

const DRIVER_PARITY_GRADED: &str =
    "byte-exact agreement with swift-demangle across swift-driver's own symbol table";
const CURATED_PARITY_GRADED: &str =
    "byte-exact agreement with swift-demangle on the curated Swift 6 feature symbols";
const VARIADIC_PARITY_GRADED: &str =
    "byte-exact agreement with swift-demangle on the committed variadic-generic manglings";

#[test]
fn swift_driver_symbols_match_reference_demangler_exactly() {
    let Some(demangler): Option<ReferenceDemangler> =
        resolve_reference_demangler(DRIVER_PARITY_GRADED)
    else {
        return;
    };
    let Some((slice, parsed)): Option<(Vec<u8>, ParsedSlice)> = driver_arm64_slice() else {
        return;
    };
    let symbols: Vec<String> = swift_mangled_symbols(&slice, &parsed);
    assert!(
        symbols.len() >= 400,
        "swift-driver must expose 400+ Swift-mangled symbols for the reference comparison, got {}",
        symbols.len()
    );
    let borrowed: Vec<&str> = symbols.iter().map(String::as_str).collect();
    let reference: Vec<String> = reference_demangle(&demangler, &borrowed);

    let ours: Vec<String> = symbols
        .iter()
        .map(|s: &String| demangle::demangle(s).unwrap_or_else(|_| s.clone()))
        .collect();
    let matched: usize = reference
        .iter()
        .zip(ours.iter())
        .filter(|(r, o): &(&String, &String)| r == o)
        .count();
    let ratio: f64 = matched as f64 / symbols.len() as f64;
    if ratio < 0.95 {
        let mut mismatches: Vec<(&String, &String, &String)> = reference
            .iter()
            .zip(ours.iter())
            .zip(symbols.iter())
            .filter(|((r, o), _)| r != o)
            .map(|((r, o), s)| (s, r, o))
            .collect();
        mismatches.sort_by_key(|(s, _, _): &(&String, &String, &String)| s.len());
        for (sym, r, o) in &mismatches {
            eprintln!("mismatch sym={sym}\n  ref={r}\n  our={o}");
        }
    }
    assert!(
        ratio >= 0.95,
        "demangler must byte-match the real swift-demangle on >=95% of the binary's own \
         symbols (swift 6.x generic specialization, concurrency, opaque return type, and \
         substitution-table coverage), got {matched}/{} = {:.2}%. {}",
        symbols.len(),
        ratio * 100.0,
        provenance_note(&demangler.identity)
    );
}

#[test]
fn swift_driver_swift6_feature_symbols_match_reference_exactly() {
    let Some(demangler): Option<ReferenceDemangler> =
        resolve_reference_demangler(CURATED_PARITY_GRADED)
    else {
        return;
    };
    let Some((slice, parsed)): Option<(Vec<u8>, ParsedSlice)> = driver_arm64_slice() else {
        return;
    };
    let all_symbols: Vec<String> = swift_mangled_symbols(&slice, &parsed);
    let curated: [&str; 7] = [
        "_$sSa034_makeUniqueAndReserveCapacityIfNotB0yyFyXl_Ts5",
        "_$ss31withCheckedThrowingContinuation9isolation8function_xScA_pSgYi_SSyScCyxs5Error_pGXEtYaKlFTu",
        "_$ss12IdentifiableP2IDAB_SHTn",
        "_$ss5SliceVyxGSlsMc",
        "_$ss9CodingKeyP8intValuexSgSi_tcfCTq",
        "_$ss6HasherV5_hash4seed5bytes5countS2i_s6UInt64VSitFZ",
        "_$ss5ErrorWS",
    ];
    let symbols: Vec<&str> = curated
        .into_iter()
        .filter(|s: &&str| all_symbols.iter().any(|sym: &String| sym == s))
        .collect();
    assert_eq!(
        symbols.len(),
        curated.len(),
        "all curated swift 6 feature symbols must actually be present in swift-driver's own \
         symbol table, found {}/{}",
        symbols.len(),
        curated.len()
    );

    let reference: Vec<String> = reference_demangle(&demangler, &symbols);
    let ours: Vec<String> = symbols
        .iter()
        .map(|s: &&str| demangle::demangle(s).unwrap_or_else(|_| (*s).to_owned()))
        .collect();
    for ((sym, ref_text), our_text) in symbols.iter().zip(reference.iter()).zip(ours.iter()) {
        assert_eq!(
            ref_text,
            our_text,
            "mismatch for curated swift 6 symbol {sym}. {}",
            provenance_note(&demangler.identity)
        );
    }
}

const VARIADIC_GENERIC_FIXTURES: [(&str, &str); 7] = [
    (
        "$s5probe11forEachPackyyxxQpRvzlF",
        "probe.forEachPack<each A>(repeat A) -> ()",
    ),
    (
        "$s5probe4PackV7storagexxQp_tvg",
        "probe.Pack.storage.getter : (repeat A)",
    ),
    (
        "$s5probe4PackV7storagexxQp_tvs",
        "probe.Pack.storage.setter : (repeat A)",
    ),
    (
        "$s5probe4PackV7storagexxQp_tvM",
        "probe.Pack.storage.modify : (repeat A)",
    ),
    (
        "$s5probe4PackVyACyxxQp_QPGxxQpcfC",
        "probe.Pack.init(repeat A) -> probe.Pack<Pack{repeat A}>",
    ),
    (
        "$s5probe5ShapeTL",
        "protocol requirements base descriptor for probe.Shape",
    ),
    (
        "$s10SwiftHello0B9GreetableTL",
        "protocol requirements base descriptor for SwiftHello.HelloGreetable",
    ),
];

#[test]
fn variadic_generic_manglings_demangle_to_committed_fixtures() {
    for (mangled, expected) in VARIADIC_GENERIC_FIXTURES {
        let ours: String = demangle::demangle(mangled)
            .unwrap_or_else(|_| panic!("demangler must recover {mangled}"));
        assert_eq!(
            ours, expected,
            "variadic-generic / bare-nominal-descriptor demangling regressed for {mangled}"
        );
    }
}

#[test]
fn variadic_generic_manglings_match_reference_demangler_exactly() {
    let Some(demangler): Option<ReferenceDemangler> =
        resolve_reference_demangler(VARIADIC_PARITY_GRADED)
    else {
        return;
    };
    let symbols: Vec<&str> = VARIADIC_GENERIC_FIXTURES
        .iter()
        .map(|(m, _): &(&str, &str)| *m)
        .collect();
    let reference: Vec<String> = reference_demangle(&demangler, &symbols);
    for (fixture, refd) in VARIADIC_GENERIC_FIXTURES.iter().zip(reference.iter()) {
        let (mangled, expected): (&str, &str) = *fixture;
        assert_eq!(
            expected,
            refd,
            "committed fixture drifted from the live swift-demangle for {mangled}. {}",
            provenance_note(&demangler.identity)
        );
        let ours: String = demangle::demangle(mangled)
            .unwrap_or_else(|_| panic!("demangler must recover {mangled}"));
        assert_eq!(
            &ours, refd,
            "disrobe must byte-match swift-demangle for {mangled}"
        );
    }
}

#[test]
fn swift_hello_obfuscated_symbol_table_still_demangles_structurally() {
    let (slice, parsed): (Vec<u8>, ParsedSlice) = tracked_slice(SWIFT_HELLO_OBFUSCATED);
    let symbols: Vec<String> = swift_mangled_symbols(&slice, &parsed);
    assert!(
        symbols.len() >= 30,
        "obfuscated binary still carries 30+ mangled symbols, got {}",
        symbols.len()
    );
    assert_recovery_rate("SwiftHello.obfuscated", &symbols);
}
