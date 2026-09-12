#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/macho_corpus.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod macho_corpus;

#[path = "support/swift_toolchain.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod swift_toolchain;

use std::fs;
use std::path::PathBuf;

use disrobe_pass_swift_objc::demangle;
use disrobe_pass_swift_objc::macho::{self, ParsedSlice};

use macho_corpus::{SWIFT_HELLO_ORIGINAL, first_slice, read_tracked};
use swift_toolchain::{
    ReferenceDemangler, provenance_note, reference_demangle, resolve_reference_demangler,
};

const FIXTURE_NAME: &str = SWIFT_HELLO_ORIGINAL.name;
const REFERENCE_COLUMN_GRADED: &str =
    "the pinned reference column, byte for byte against the real swift-demangle";

const PUBLISHED_HEADING: &str = "Swift symbol rendering on the committed SwiftHello Mach-O";
const PUBLISHED_SYMBOL_BAR: &str = "pinned symbol renderings";
const PUBLISHED_VALUE_TOLERANCE: f64 = 0.05;

#[derive(Debug, Clone, Copy)]
struct PinnedSymbol {
    mangled: &'static str,
    reference: &'static str,
    ours: &'static str,
}

const PINNED: [PinnedSymbol; 37] = [
    PinnedSymbol {
        mangled: "_$s10SwiftHello0B11RunnerEntryV4mainyyFZTf4d_n",
        reference: "function signature specialization <Arg[0] = Dead> of static SwiftHello.HelloRunnerEntry.main() -> ()",
        ours: "function signature specialization <Arg[0] = Dead> of static SwiftHello.HelloRunnerEntry.main() -> ()",
    },
    PinnedSymbol {
        mangled: "_$s10SwiftHello0B9GreetableMp",
        reference: "protocol descriptor for SwiftHello.HelloGreetable",
        ours: "protocol descriptor for SwiftHello.HelloGreetable",
    },
    PinnedSymbol {
        mangled: "_$s10SwiftHello0B9GreetableTL",
        reference: "protocol requirements base descriptor for SwiftHello.HelloGreetable",
        ours: "protocol requirements base descriptor for SwiftHello.HelloGreetable",
    },
    PinnedSymbol {
        mangled: "_$s10SwiftHello0B9Greetable_pMF",
        reference: "reflection metadata field descriptor SwiftHello.HelloGreetable",
        ours: "reflection metadata field descriptor SwiftHello.HelloGreetable",
    },
    PinnedSymbol {
        mangled: "_$s10SwiftHello19LoginViewControllerC15greetWithBannerSSyFTq",
        reference: "method descriptor for SwiftHello.LoginViewController.greetWithBanner() -> Swift.String",
        ours: "method descriptor for SwiftHello.LoginViewController.greetWithBanner() -> Swift.String",
    },
    PinnedSymbol {
        mangled: "_$s10SwiftHello19LoginViewControllerC17displayedUserNameACSS_tcfCTq",
        reference: "method descriptor for SwiftHello.LoginViewController.__allocating_init(displayedUserName: Swift.String) -> SwiftHello.LoginViewController",
        ours: "method descriptor for SwiftHello.LoginViewController.__allocating_init(displayedUserName: Swift.String) -> SwiftHello.LoginViewController",
    },
    PinnedSymbol {
        mangled: "_$s10SwiftHello19LoginViewControllerC17displayedUserNameSSvpWvd",
        reference: "direct field offset for SwiftHello.LoginViewController.displayedUserName : Swift.String",
        ours: "direct field offset for SwiftHello.LoginViewController.displayedUserName : Swift.String",
    },
    PinnedSymbol {
        mangled: "_$s10SwiftHello19LoginViewControllerCAA0B9GreetableAAMc",
        reference: "protocol conformance descriptor for SwiftHello.LoginViewController : SwiftHello.HelloGreetable in SwiftHello",
        ours: "protocol conformance descriptor for SwiftHello.LoginViewController : SwiftHello.HelloGreetable in SwiftHello",
    },
    PinnedSymbol {
        mangled: "_$s10SwiftHello19LoginViewControllerCAA0B9GreetableAAWP",
        reference: "protocol witness table for SwiftHello.LoginViewController : SwiftHello.HelloGreetable in SwiftHello",
        ours: "protocol witness table for SwiftHello.LoginViewController : SwiftHello.HelloGreetable in SwiftHello",
    },
    PinnedSymbol {
        mangled: "_$s10SwiftHello19LoginViewControllerCMF",
        reference: "reflection metadata field descriptor SwiftHello.LoginViewController",
        ours: "reflection metadata field descriptor SwiftHello.LoginViewController",
    },
    PinnedSymbol {
        mangled: "_$s10SwiftHello19LoginViewControllerCMa",
        reference: "type metadata accessor for SwiftHello.LoginViewController",
        ours: "type metadata accessor for SwiftHello.LoginViewController",
    },
    PinnedSymbol {
        mangled: "_$s10SwiftHello19LoginViewControllerCMf",
        reference: "full type metadata for SwiftHello.LoginViewController",
        ours: "full type metadata for SwiftHello.LoginViewController",
    },
    PinnedSymbol {
        mangled: "_$s10SwiftHello19LoginViewControllerCMm",
        reference: "metaclass for SwiftHello.LoginViewController",
        ours: "metaclass for SwiftHello.LoginViewController",
    },
    PinnedSymbol {
        mangled: "_$s10SwiftHello19LoginViewControllerCMn",
        reference: "nominal type descriptor for SwiftHello.LoginViewController",
        ours: "nominal type descriptor for SwiftHello.LoginViewController",
    },
    PinnedSymbol {
        mangled: "_$s10SwiftHello19LoginViewControllerCN",
        reference: "type metadata for SwiftHello.LoginViewController",
        ours: "type metadata for SwiftHello.LoginViewController",
    },
    PinnedSymbol {
        mangled: "_$s10SwiftHello19LoginViewControllerCfD",
        reference: "SwiftHello.LoginViewController.__deallocating_deinit",
        ours: "SwiftHello.LoginViewController.__deallocating_deinit",
    },
    PinnedSymbol {
        mangled: "_$s10SwiftHello21AuthenticationServiceC15greetWithBannerSSyFTq",
        reference: "method descriptor for SwiftHello.AuthenticationService.greetWithBanner() -> Swift.String",
        ours: "method descriptor for SwiftHello.AuthenticationService.greetWithBanner() -> Swift.String",
    },
    PinnedSymbol {
        mangled: "_$s10SwiftHello21AuthenticationServiceC22configuredEndpointPathACSS_tcfCTq",
        reference: "method descriptor for SwiftHello.AuthenticationService.__allocating_init(configuredEndpointPath: Swift.String) -> SwiftHello.AuthenticationService",
        ours: "method descriptor for SwiftHello.AuthenticationService.__allocating_init(configuredEndpointPath: Swift.String) -> SwiftHello.AuthenticationService",
    },
    PinnedSymbol {
        mangled: "_$s10SwiftHello21AuthenticationServiceC22configuredEndpointPathSSvpWvd",
        reference: "direct field offset for SwiftHello.AuthenticationService.configuredEndpointPath : Swift.String",
        ours: "direct field offset for SwiftHello.AuthenticationService.configuredEndpointPath : Swift.String",
    },
    PinnedSymbol {
        mangled: "_$s10SwiftHello21AuthenticationServiceCAA0B9GreetableAAMc",
        reference: "protocol conformance descriptor for SwiftHello.AuthenticationService : SwiftHello.HelloGreetable in SwiftHello",
        ours: "protocol conformance descriptor for SwiftHello.AuthenticationService : SwiftHello.HelloGreetable in SwiftHello",
    },
    PinnedSymbol {
        mangled: "_$s10SwiftHello21AuthenticationServiceCAA0B9GreetableAAWP",
        reference: "protocol witness table for SwiftHello.AuthenticationService : SwiftHello.HelloGreetable in SwiftHello",
        ours: "protocol witness table for SwiftHello.AuthenticationService : SwiftHello.HelloGreetable in SwiftHello",
    },
    PinnedSymbol {
        mangled: "_$s10SwiftHello21AuthenticationServiceCMF",
        reference: "reflection metadata field descriptor SwiftHello.AuthenticationService",
        ours: "reflection metadata field descriptor SwiftHello.AuthenticationService",
    },
    PinnedSymbol {
        mangled: "_$s10SwiftHello21AuthenticationServiceCMa",
        reference: "type metadata accessor for SwiftHello.AuthenticationService",
        ours: "type metadata accessor for SwiftHello.AuthenticationService",
    },
    PinnedSymbol {
        mangled: "_$s10SwiftHello21AuthenticationServiceCMf",
        reference: "full type metadata for SwiftHello.AuthenticationService",
        ours: "full type metadata for SwiftHello.AuthenticationService",
    },
    PinnedSymbol {
        mangled: "_$s10SwiftHello21AuthenticationServiceCMm",
        reference: "metaclass for SwiftHello.AuthenticationService",
        ours: "metaclass for SwiftHello.AuthenticationService",
    },
    PinnedSymbol {
        mangled: "_$s10SwiftHello21AuthenticationServiceCMn",
        reference: "nominal type descriptor for SwiftHello.AuthenticationService",
        ours: "nominal type descriptor for SwiftHello.AuthenticationService",
    },
    PinnedSymbol {
        mangled: "_$s10SwiftHello21AuthenticationServiceCN",
        reference: "type metadata for SwiftHello.AuthenticationService",
        ours: "type metadata for SwiftHello.AuthenticationService",
    },
    PinnedSymbol {
        mangled: "_$s10SwiftHello21AuthenticationServiceCfD",
        reference: "SwiftHello.AuthenticationService.__deallocating_deinit",
        ours: "SwiftHello.AuthenticationService.__deallocating_deinit",
    },
    PinnedSymbol {
        mangled: "_$s10SwiftHelloMXM",
        reference: "module descriptor SwiftHello",
        ours: "module descriptor SwiftHello",
    },
    PinnedSymbol {
        mangled: "_$sBoWV",
        reference: "value witness table for Builtin.NativeObject",
        ours: "value witness table for Builtin.NativeObject",
    },
    PinnedSymbol {
        mangled: "_$sSS6appendyySSF",
        reference: "Swift.String.append(Swift.String) -> ()",
        ours: "Swift.String.append(Swift.String) -> ()",
    },
    PinnedSymbol {
        mangled: "_$sSSN",
        reference: "type metadata for Swift.String",
        ours: "type metadata for Swift.String",
    },
    PinnedSymbol {
        mangled: "_$ss11_StringGutsV4growyySiF",
        reference: "Swift._StringGuts.grow(Swift.Int) -> ()",
        ours: "Swift._StringGuts.grow(Swift.Int) -> ()",
    },
    PinnedSymbol {
        mangled: "_$ss23_ContiguousArrayStorageCMn",
        reference: "nominal type descriptor for Swift._ContiguousArrayStorage",
        ours: "nominal type descriptor for Swift._ContiguousArrayStorage",
    },
    PinnedSymbol {
        mangled: "_$ss23_ContiguousArrayStorageCyypGMR",
        reference: "_$ss23_ContiguousArrayStorageCyypGMR",
        ours: "_$ss23_ContiguousArrayStorageCyypGMR",
    },
    PinnedSymbol {
        mangled: "_$ss23_ContiguousArrayStorageCyypGMd",
        reference: "_$ss23_ContiguousArrayStorageCyypGMd",
        ours: "_$ss23_ContiguousArrayStorageCyypGMd",
    },
    PinnedSymbol {
        mangled: "_$ss5print_9separator10terminatoryypd_S2StF",
        reference: "Swift.print(_: Any..., separator: Swift.String, terminator: Swift.String) -> ()",
        ours: "Swift.print(_: Any..., separator: Swift.String, terminator: Swift.String) -> ()",
    },
];

const REFERENCE_DIVERGENCES: [&str; 0] = [];

const REFERENCE_AGREEMENT_FLOOR: usize = PINNED.len() - REFERENCE_DIVERGENCES.len();

fn pinned_slice() -> (Vec<u8>, ParsedSlice) {
    let bytes: Vec<u8> = read_tracked(SWIFT_HELLO_ORIGINAL);
    first_slice(SWIFT_HELLO_ORIGINAL, &bytes)
}

fn extract_swift_symbols(slice: &[u8], parsed: &ParsedSlice) -> Vec<String> {
    let mut out: Vec<String> = macho::symbol_names(slice, parsed)
        .into_iter()
        .filter(|s: &String| demangle::looks_like_swift_mangled(s))
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

fn pinned_mangled() -> Vec<&'static str> {
    PINNED.iter().map(|p: &PinnedSymbol| p.mangled).collect()
}

fn symbol_set_defects(observed: &[String]) -> Vec<String> {
    let expected: Vec<&'static str> = pinned_mangled();
    let mut defects: Vec<String> = Vec::new();
    if observed.len() != expected.len() {
        defects.push(format!(
            "the denominator is this fixture's own Swift-mangled symbol count, so it must stay {} \
             symbols; a run that inspects fewer must score worse, never shrink what it is measured \
             against. Observed {}",
            expected.len(),
            observed.len()
        ));
    }
    for want in &expected {
        if !observed.iter().any(|s: &String| s == want) {
            defects.push(format!(
                "pinned symbol is no longer recovered from the fixture symbol table: {want}"
            ));
        }
    }
    for got in observed {
        if !expected.iter().any(|w: &&'static str| w == got) {
            defects.push(format!(
                "fixture carries a Swift-mangled symbol that no pinned row accounts for: {got}"
            ));
        }
    }
    defects
}

fn rendered(mangled: &str) -> String {
    demangle::demangle(mangled).unwrap_or_else(|_| mangled.to_owned())
}

#[test]
fn swift_hello_symbol_set_matches_pinned_membership_and_denominator() {
    let (slice, parsed): (Vec<u8>, ParsedSlice) = pinned_slice();
    let observed: Vec<String> = extract_swift_symbols(&slice, &parsed);
    let defects: Vec<String> = symbol_set_defects(&observed);
    assert!(
        defects.is_empty(),
        "the published Swift symbol figure is {} of {} against {FIXTURE_NAME}, and that figure is \
         this set of names, not a bare count:\n{}",
        PINNED.len(),
        PINNED.len(),
        defects.join("\n")
    );
}

#[test]
fn swift_hello_demangler_output_matches_pinned_text() {
    let (slice, parsed): (Vec<u8>, ParsedSlice) = pinned_slice();
    let observed: Vec<String> = extract_swift_symbols(&slice, &parsed);
    assert!(
        symbol_set_defects(&observed).is_empty(),
        "pin the symbol set before grading its rendering"
    );
    for entry in &PINNED {
        assert_eq!(
            rendered(entry.mangled),
            entry.ours,
            "recovered text changed for {}; re-measure the reference agreement and re-pin both \
             columns in the same change",
            entry.mangled
        );
    }
}

#[test]
fn swift_hello_reference_agreement_is_pinned_at_measured_floor() {
    let agreeing: Vec<&'static str> = PINNED
        .iter()
        .filter(|p: &&PinnedSymbol| p.ours == p.reference)
        .map(|p: &PinnedSymbol| p.mangled)
        .collect();
    let diverging: Vec<&'static str> = PINNED
        .iter()
        .filter(|p: &&PinnedSymbol| p.ours != p.reference)
        .map(|p: &PinnedSymbol| p.mangled)
        .collect();
    assert!(
        agreeing.len() >= REFERENCE_AGREEMENT_FLOOR,
        "exact agreement with the reference demangler must hold at or above the measured {} of \
         {}; got {}",
        REFERENCE_AGREEMENT_FLOOR,
        PINNED.len(),
        agreeing.len()
    );
    assert_eq!(
        diverging, REFERENCE_DIVERGENCES,
        "the set of symbols where the recovered text differs from the reference demangler is \
         pinned, so neither a new divergence nor a fixed one may land without updating this list \
         and the pinned reference column together"
    );
}

#[test]
fn pinned_reference_column_matches_live_swift_demangle() {
    let Some(demangler): Option<ReferenceDemangler> =
        resolve_reference_demangler(REFERENCE_COLUMN_GRADED)
    else {
        return;
    };
    let symbols: Vec<&'static str> = pinned_mangled();
    let live: Vec<String> = reference_demangle(&demangler, &symbols);
    for (entry, actual) in PINNED.iter().zip(live.iter()) {
        assert_eq!(
            actual,
            entry.reference,
            "the pinned reference text for {} does not match what {} produced here. {}",
            entry.mangled,
            demangler.tool.display(),
            provenance_note(&demangler.identity)
        );
    }
}

#[derive(Debug, Clone, Copy)]
struct PinnedBar {
    num: u64,
    den: u64,
    value: f64,
}

fn published_bar(heading_needle: &str, label: &str) -> serde_json::Value {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("xtask")
        .join("data")
        .join("recovery.json");
    let raw: String = fs::read_to_string(&path)
        .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", path.display()));
    let doc: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e: serde_json::Error| panic!("parse {}: {e}", path.display()));
    let mut found: Vec<serde_json::Value> = Vec::new();
    for group in doc["groups"].as_array().expect("groups array") {
        let heading_matches: bool = group["heading"]
            .as_str()
            .is_some_and(|h: &str| h.contains(heading_needle));
        if !heading_matches {
            continue;
        }
        for bar in group["bars"].as_array().unwrap_or(&Vec::new()) {
            if bar["label"].as_str() == Some(label) {
                found.push(bar.clone());
            }
        }
    }
    assert_eq!(
        found.len(),
        1,
        "xtask/data/recovery.json must carry exactly one bar labeled `{label}` under a heading \
         containing `{heading_needle}`, found {}",
        found.len()
    );
    found.remove(0)
}

fn pinned_bar(label: &str) -> PinnedBar {
    let bar: serde_json::Value = published_bar(PUBLISHED_HEADING, label);
    let num: u64 = bar["num"]
        .as_u64()
        .unwrap_or_else(|| panic!("the `{label}` bar must publish a numerator"));
    let den: u64 = bar["den"]
        .as_u64()
        .unwrap_or_else(|| panic!("the `{label}` bar must publish a denominator"));
    let value: f64 = bar["value"]
        .as_f64()
        .unwrap_or_else(|| panic!("the `{label}` bar must publish the percentage it plots"));
    PinnedBar { num, den, value }
}

fn bar_defects(label: &str, hit: usize, total: usize, bar: PinnedBar) -> Vec<String> {
    let mut defects: Vec<String> = Vec::new();
    let measured_total: u64 = u64::try_from(total).expect("the graded population fits u64");
    let measured_hit: u64 = u64::try_from(hit).expect("the measured count fits u64");
    if measured_total != bar.den {
        defects.push(format!(
            "{label}: xtask/data/recovery.json publishes a denominator of {} and every document \
             renders that number, but this run measured {measured_total}. A run that inspects fewer \
             symbols must score worse, never shrink what it is measured against",
            bar.den
        ));
    }
    if measured_hit != bar.num {
        defects.push(format!(
            "{label}: recovery.json publishes {} of {}; this run measured {measured_hit}. Raise the \
             recovery or correct the published figure, never merely floor the measured recovery",
            bar.num, bar.den
        ));
    }
    let derived: f64 = 100.0 * bar.num as f64 / bar.den as f64;
    if (derived - bar.value).abs() >= PUBLISHED_VALUE_TOLERANCE {
        defects.push(format!(
            "{label}: the plotted value {} must equal its own {}/{} = {derived:.4}",
            bar.value, bar.num, bar.den
        ));
    }
    defects
}

#[test]
fn published_swift_symbol_rendering_is_pinned_to_the_measured_membership() {
    let symbol_bar: PinnedBar = pinned_bar(PUBLISHED_SYMBOL_BAR);

    let (slice, parsed): (Vec<u8>, ParsedSlice) = pinned_slice();
    let observed: Vec<String> = extract_swift_symbols(&slice, &parsed);
    let defects: Vec<String> = symbol_rendering_defects(&observed, symbol_bar);
    let recovered: usize = PINNED
        .iter()
        .filter(|entry: &&PinnedSymbol| {
            let present: bool = observed.iter().any(|s: &String| s == entry.mangled);
            present && rendered(entry.mangled) == entry.ours
        })
        .count();

    eprintln!(
        "{FIXTURE_NAME}: {recovered} of {} Swift-mangled symbols render to pinned text (published \
         {}/{} = {})",
        observed.len(),
        symbol_bar.num,
        symbol_bar.den,
        symbol_bar.value
    );
    assert!(
        defects.is_empty(),
        "the published Swift symbol rendering figure names this set of symbols rather than a bare \
         count:\n{}",
        defects.join("\n")
    );
}

fn symbol_rendering_defects(observed: &[String], symbol_bar: PinnedBar) -> Vec<String> {
    let mut defects: Vec<String> = symbol_set_defects(observed);
    let recovered: usize = PINNED
        .iter()
        .filter(|entry: &&PinnedSymbol| {
            let present: bool = observed
                .iter()
                .any(|symbol: &String| symbol == entry.mangled);
            present && rendered(entry.mangled) == entry.ours
        })
        .count();
    defects.extend(bar_defects(
        PUBLISHED_SYMBOL_BAR,
        recovered,
        observed.len(),
        symbol_bar,
    ));
    defects
}

#[test]
fn the_pinned_symbol_rendering_check_rejects_a_dropped_symbol() {
    let bar: PinnedBar = pinned_bar(PUBLISHED_SYMBOL_BAR);
    let (slice, parsed): (Vec<u8>, ParsedSlice) = pinned_slice();
    let observed: Vec<String> = extract_swift_symbols(&slice, &parsed);
    let dropped: &str = PINNED[0].mangled;
    let corrupted: Vec<String> = observed
        .iter()
        .filter(|symbol: &&String| symbol.as_str() != dropped)
        .cloned()
        .collect();
    let defects: Vec<String> = symbol_rendering_defects(&corrupted, bar);
    assert!(
        defects
            .iter()
            .any(|defect: &String| defect.contains(dropped)),
        "dropping {dropped} must be reported by name, got {defects:?}"
    );
    assert!(
        defects
            .iter()
            .any(|defect: &String| defect.contains("this run measured")),
        "losing one recovered symbol must be reported as a shortfall against the published \
         numerator, got {defects:?}"
    );
    assert!(
        defects
            .iter()
            .any(|defect: &String| defect.contains("never shrink what it is measured against")),
        "dropping a symbol from the graded population must be rejected on the denominator rather \
         than absorbed as a better ratio, got {defects:?}"
    );
}
