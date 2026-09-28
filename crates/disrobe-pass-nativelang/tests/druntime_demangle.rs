#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/druntime_demangle_vectors.rs"]
mod vectors;

use disrobe_pass_nativelang::{DemangledSymbol, demangle_d};

#[test]
fn d_symbols_demangle_as_druntime_core_demangle_does() {
    let mismatches: Vec<String> = vectors::DRUNTIME_DEMANGLE_VECTORS
        .iter()
        .filter_map(|&(mangled, expected): &(&str, &str)| {
            let got: String = demangle_d(mangled).map_or_else(
                || mangled.to_owned(),
                |symbol: DemangledSymbol| symbol.demangled,
            );
            (got != expected)
                .then(|| format!("{mangled}\n    druntime: {expected}\n    disrobe:  {got}"))
        })
        .collect();
    assert!(
        mismatches.is_empty(),
        "{} of {} druntime vectors differ:\n{}",
        mismatches.len(),
        vectors::DRUNTIME_DEMANGLE_VECTORS.len(),
        mismatches.join("\n")
    );
}
