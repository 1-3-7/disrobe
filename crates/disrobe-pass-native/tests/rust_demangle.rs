#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{DemangleScheme, DemangledSymbol, demangle_rust};

#[test]
fn legacy_scheme_demangled() {
    let d: DemangledSymbol = demangle_rust("_ZN3foo3barE").expect("legacy");
    assert_eq!(d.scheme, DemangleScheme::RustLegacy);
}

#[test]
fn v0_scheme_demangled() {
    let d: DemangledSymbol = demangle_rust("_RNvCs9ltgdHTiPiY_3foo3bar").expect("v0");
    assert_eq!(d.scheme, DemangleScheme::RustV0);
}
