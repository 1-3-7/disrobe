use std::collections::BTreeMap;

use object::{Object, ObjectSection, ObjectSymbol};
use serde::Serialize;

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImpFunction {
    pub identifier: String,
    pub module: Option<String>,
    pub bare_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModuleInit {
    pub raw_symbol: String,
    pub module_name: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SymbolGraph {
    pub impl_functions: Vec<ImpFunction>,
    pub module_inits: Vec<ModuleInit>,
    pub make_function_count: usize,
    pub strings: BTreeMap<String, u32>,
}

pub fn scan_symbols(image: &[u8]) -> Result<SymbolGraph> {
    let mut graph: SymbolGraph = SymbolGraph::default();
    let parsed: object::File<'_> =
        object::File::parse(image).map_err(|e| Error::ObjectParse(format!("{e}")))?;
    for symbol in parsed.symbols() {
        let Ok(raw): core::result::Result<&str, object::Error> = symbol.name() else {
            continue;
        };
        if raw.is_empty() {
            continue;
        }
        classify_symbol(raw, &mut graph);
    }

    for section in parsed.sections() {
        if let Ok(data) = section.data() {
            extract_printable_strings(data, &mut graph.strings);
        }
    }
    Ok(graph)
}

fn classify_symbol(raw: &str, graph: &mut SymbolGraph) {
    if let Some(rest) = raw.strip_prefix("impl_") {
        let (module, bare): (Option<String>, Option<String>) = split_function_identifier(rest);
        graph.impl_functions.push(ImpFunction {
            identifier: rest.to_owned(),
            module,
            bare_name: bare,
        });
    } else if let Some(module) = raw
        .strip_prefix("PyInit_")
        .or_else(|| raw.strip_prefix("PyInitU_"))
    {
        graph.module_inits.push(ModuleInit {
            raw_symbol: raw.to_owned(),
            module_name: module.to_owned(),
        });
    } else if raw.starts_with("MAKE_FUNCTION_") {
        graph.make_function_count += 1;
    }
}

fn split_function_identifier(rest: &str) -> (Option<String>, Option<String>) {
    if let Some((module, bare)) = rest.split_once("$$") {
        return (Some(module.to_owned()), Some(bare.to_owned()));
    }
    if let Some((module, bare)) = rest.split_once("__") {
        return (Some(module.to_owned()), Some(bare.to_owned()));
    }
    (None, Some(rest.to_owned()))
}

const MIN_INTERESTING_STRING_LEN: usize = 6;

fn extract_printable_strings(data: &[u8], dst: &mut BTreeMap<String, u32>) {
    let mut current: Vec<u8> = Vec::with_capacity(64);
    for &byte in data {
        if (0x20..=0x7E).contains(&byte) {
            current.push(byte);
            continue;
        }
        flush_candidate(&current, dst);
        current.clear();
    }
    flush_candidate(&current, dst);
}

#[inline]
fn flush_candidate(current: &[u8], dst: &mut BTreeMap<String, u32>) {
    if current.len() < MIN_INTERESTING_STRING_LEN {
        return;
    }
    let Ok(s): core::result::Result<&str, core::str::Utf8Error> = core::str::from_utf8(current)
    else {
        return;
    };
    if !is_interesting(s) {
        return;
    }
    *dst.entry(s.to_owned()).or_insert(0) += 1;
}

#[inline]
fn is_interesting(s: &str) -> bool {
    s.starts_with("Nuitka_")
        || s.starts_with("loadConstantsBlob")
        || s.starts_with("PyInit_")
        || s.starts_with("impl_")
        || s.starts_with("MAKE_FUNCTION_")
        || s.starts_with("NUITKA_")
        || s.starts_with("__nuitka_")
        || s.contains("python3")
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn split_identifier_with_dollar() {
        let (m, b): (Option<String>, Option<String>) = split_function_identifier("mod$$func");
        assert_eq!(m.as_deref(), Some("mod"));
        assert_eq!(b.as_deref(), Some("func"));
    }

    #[test]
    fn split_identifier_with_underscore() {
        let (m, b): (Option<String>, Option<String>) = split_function_identifier("mod__func");
        assert_eq!(m.as_deref(), Some("mod"));
        assert_eq!(b.as_deref(), Some("func"));
    }

    #[test]
    fn interesting_string_filter() {
        assert!(is_interesting("Nuitka_FunctionObject"));
        assert!(is_interesting("loadConstantsBlob"));
        assert!(is_interesting("PyInit___main__"));
        assert!(!is_interesting("regular_string"));
    }

    #[test]
    fn classify_symbol_routes_to_make_function() {
        let mut graph: SymbolGraph = SymbolGraph::default();
        classify_symbol("MAKE_FUNCTION_foo", &mut graph);
        classify_symbol("MAKE_FUNCTION_bar", &mut graph);
        assert_eq!(graph.make_function_count, 2);
        assert!(graph.impl_functions.is_empty());
        assert!(graph.module_inits.is_empty());
    }

    #[test]
    fn classify_symbol_routes_module_init() {
        let mut graph: SymbolGraph = SymbolGraph::default();
        classify_symbol("PyInit___main__", &mut graph);
        classify_symbol("PyInitU_pkg", &mut graph);
        assert_eq!(graph.module_inits.len(), 2);
        assert_eq!(graph.module_inits[0].module_name, "__main__");
        assert_eq!(graph.module_inits[1].module_name, "pkg");
    }

    #[test]
    fn extract_printable_strings_captures_interesting_only() {
        let raw: &[u8] = b"\x00\x00Nuitka_FunctionObject\x00garbage\x00\x00MAKE_FUNCTION_foo\x00";
        let mut dst: BTreeMap<String, u32> = BTreeMap::new();
        extract_printable_strings(raw, &mut dst);
        assert_eq!(dst.get("Nuitka_FunctionObject"), Some(&1));
        assert_eq!(dst.get("MAKE_FUNCTION_foo"), Some(&1));
        assert!(!dst.contains_key("garbage"));
    }

    #[test]
    fn extract_printable_strings_handles_trailing_run() {
        let raw: &[u8] = b"\x00Nuitka_TrailingTag";
        let mut dst: BTreeMap<String, u32> = BTreeMap::new();
        extract_printable_strings(raw, &mut dst);
        assert_eq!(dst.get("Nuitka_TrailingTag"), Some(&1));
    }
}
