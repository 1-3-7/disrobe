use crate::signature::ModuleSignatures;
#[cfg(feature = "dwarf")]
use crate::signature::dwarf_local_names;
use crate::sourcemap::SourceMap;

/// Outcome of attaching debug-info names to a module's signatures.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NameRecoveryStats {
    pub functions_with_names: usize,
    pub defined_function_count: usize,
}

impl NameRecoveryStats {
    /// Fraction of defined functions that received at least one real local name.
    /// Honestly debug-info gated: zero without DWARF or a source map.
    #[inline]
    #[must_use]
    pub fn name_recovery_ratio(&self) -> f64 {
        if self.defined_function_count == 0 {
            return 0.0;
        }
        self.functions_with_names as f64 / self.defined_function_count as f64
    }
}

/// Attaches real parameter/local names recovered from DWARF to a module's signatures.
///
/// `function_names` maps a defined-function index to its ordered
/// `(parameter_names, variable_names)` as recovered from the DWARF subprogram DIE.
/// Param names land on the leading wasm locals (source order) and variable names on
/// the trailing declared locals, matching the WASM lowering convention.
#[cfg(feature = "dwarf")]
#[must_use]
pub fn attach_dwarf_names<F>(
    sigs: &mut ModuleSignatures,
    mut function_names: F,
) -> NameRecoveryStats
where
    F: FnMut(u32) -> Option<(Vec<Option<String>>, Vec<Option<String>>)>,
{
    let defined_function_count: usize = sigs.defined().len();
    let attached: usize = sigs.attach_local_names(|defined_index: u32| {
        function_names(defined_index)
            .map_or_else(Vec::new, |(params, vars)| dwarf_local_names(&params, &vars))
    });
    NameRecoveryStats {
        functions_with_names: attached,
        defined_function_count,
    }
}

/// Attaches names recovered from a source map, keyed by each defined function's body
/// byte range in the binary.
///
/// `function_byte_ranges` maps a defined-function index to the half-open
/// `[start, end)` byte range of its body; every source-map segment whose generated
/// column falls in that range contributes its name to a positional slot. The slot is
/// the local index inferred from segment order within the range (params and locals
/// are emitted in increasing local index by toolchains that target the WASM profile).
#[must_use]
pub fn attach_sourcemap_names<F>(
    sigs: &mut ModuleSignatures,
    map: &SourceMap,
    mut function_byte_ranges: F,
) -> NameRecoveryStats
where
    F: FnMut(u32) -> Option<(u32, u32)>,
{
    let defined_function_count: usize = sigs.defined().len();
    let attached: usize = sigs.attach_local_names(|defined_index: u32| {
        let Some((start, end)): Option<(u32, u32)> = function_byte_ranges(defined_index) else {
            return Vec::new();
        };
        names_in_range(map, start, end)
    });
    NameRecoveryStats {
        functions_with_names: attached,
        defined_function_count,
    }
}

fn names_in_range(map: &SourceMap, start: u32, end: u32) -> Vec<Option<String>> {
    let mut out: Vec<Option<String>> = Vec::new();
    for segment in &map.segments {
        if segment.gen_column < start || segment.gen_column >= end {
            continue;
        }
        let Some(name_index): Option<u32> = segment.name_index else {
            continue;
        };
        let Some(name): Option<&String> = map.names.get(name_index as usize) else {
            continue;
        };
        out.push(Some(name.clone()));
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::signature::extract_signatures;
    use crate::sourcemap::parse_source_map;

    const ARITH4: &[u8] = include_bytes!("../tests/fixtures/arith4.wasm");

    #[test]
    fn no_provider_yields_zero_recovery() {
        let mut sigs: ModuleSignatures = extract_signatures(ARITH4).unwrap();
        let stats: NameRecoveryStats =
            attach_sourcemap_names(&mut sigs, &SourceMap::default(), |_| None);
        assert_eq!(stats.functions_with_names, 0);
        assert!(stats.defined_function_count > 0);
        assert!(stats.name_recovery_ratio().abs() < f64::EPSILON);
    }

    #[cfg(feature = "dwarf")]
    #[test]
    fn dwarf_names_land_on_params_then_locals() {
        let mut sigs: ModuleSignatures = extract_signatures(ARITH4).unwrap();
        let stats: NameRecoveryStats = attach_dwarf_names(&mut sigs, |defined_index: u32| {
            if defined_index == 0 {
                Some((
                    vec![Some("lhs".to_owned()), Some("rhs".to_owned())],
                    vec![Some("acc".to_owned())],
                ))
            } else {
                None
            }
        });
        assert_eq!(stats.functions_with_names, 1);
        let add: &crate::signature::FunctionSig = sigs.defined_sig(0).unwrap();
        assert_eq!(add.local_name(0), Some("lhs"));
        assert_eq!(add.local_name(1), Some("rhs"));
        assert_eq!(add.local_name(2), Some("acc"));
        assert_eq!(add.local_name(3), None);
    }

    #[test]
    fn sourcemap_names_attach_within_byte_range() {
        let mut sigs: ModuleSignatures = extract_signatures(ARITH4).unwrap();
        let json: &str = r#"{
            "version": 3,
            "sources": ["arith.rs"],
            "names": ["a", "b"],
            "mappings": "AAAAA,IAACC"
        }"#;
        let map: SourceMap = parse_source_map(json.as_bytes()).unwrap();
        let stats: NameRecoveryStats =
            attach_sourcemap_names(&mut sigs, &map, |defined_index: u32| {
                if defined_index == 0 {
                    Some((0, 100))
                } else {
                    None
                }
            });
        assert_eq!(stats.functions_with_names, 1);
        let add: &crate::signature::FunctionSig = sigs.defined_sig(0).unwrap();
        assert_eq!(add.local_name(0), Some("a"));
        assert_eq!(add.local_name(1), Some("b"));
    }
}
