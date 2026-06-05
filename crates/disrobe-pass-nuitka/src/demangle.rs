use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NuitkaSymbolKind {
    Function,
    Class,
    Lambda,
    Genexpr,
    Listcontr,
    Setcontr,
    Dictcontr,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemangledFunction {
    pub module_path: String,
    pub function_name: String,
    pub source_index: u32,
    pub kind: NuitkaSymbolKind,
    pub kind_raw: String,
    pub raw_symbol: String,
}

#[inline]
fn classify_kind(kind_raw: &str) -> NuitkaSymbolKind {
    match kind_raw {
        "function" => NuitkaSymbolKind::Function,
        "class" => NuitkaSymbolKind::Class,
        "lambda" => NuitkaSymbolKind::Lambda,
        "genexpr" => NuitkaSymbolKind::Genexpr,
        "listcontr" => NuitkaSymbolKind::Listcontr,
        "setcontr" => NuitkaSymbolKind::Setcontr,
        "dictcontr" => NuitkaSymbolKind::Dictcontr,
        _ => NuitkaSymbolKind::Other,
    }
}

/// Demangle a Nuitka `impl_`/`MAKE_FUNCTION_` symbol.
///
/// Accepts the symbol WITH or WITHOUT a leading `impl_` / `MAKE_FUNCTION_` prefix.
/// Returns `None` for any symbol lacking the `$$$<kind>__<idx>_<name>` infix
/// (rejects `impl_code`, `MAKE_FUNCTION_FRAME`, typedef tokens, etc).
#[must_use]
pub fn demangle_function(symbol: &str) -> Option<DemangledFunction> {
    let body: &str = symbol
        .strip_prefix("impl_")
        .or_else(|| symbol.strip_prefix("MAKE_FUNCTION_"))
        .unwrap_or(symbol);

    let (module_path, tail): (&str, &str) = body.split_once("$$$")?;
    let (kind_raw, rest): (&str, &str) = tail.split_once("__")?;
    let (idx_str, function_name): (&str, &str) = rest.split_once('_')?;
    let source_index: u32 = idx_str.parse().ok()?;

    if module_path.is_empty() || function_name.is_empty() {
        return None;
    }

    Some(DemangledFunction {
        module_path: module_path.to_owned(),
        function_name: function_name.to_owned(),
        source_index,
        kind: classify_kind(kind_raw),
        kind_raw: kind_raw.to_owned(),
        raw_symbol: symbol.to_owned(),
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn demangle_impl_greet() {
        let d: DemangledFunction =
            demangle_function("impl_hello$$$function__1_greet").expect("demangle");
        assert_eq!(d.module_path, "hello");
        assert_eq!(d.function_name, "greet");
        assert_eq!(d.source_index, 1);
        assert_eq!(d.kind, NuitkaSymbolKind::Function);
    }

    #[test]
    fn demangle_impl_dunder_main_module() {
        let d: DemangledFunction =
            demangle_function("impl___main__$$$function__2_fib").expect("demangle");
        assert_eq!(d.module_path, "__main__");
        assert_eq!(d.function_name, "fib");
        assert_eq!(d.source_index, 2);
        assert_eq!(d.kind, NuitkaSymbolKind::Function);
    }

    #[test]
    fn demangle_make_function_prefix() {
        let d: DemangledFunction =
            demangle_function("MAKE_FUNCTION_hello$$$function__3_main").expect("demangle");
        assert_eq!(d.module_path, "hello");
        assert_eq!(d.function_name, "main");
        assert_eq!(d.source_index, 3);
    }

    #[test]
    fn demangle_rejects_impl_code() {
        assert!(demangle_function("impl_code").is_none());
    }

    #[test]
    fn demangle_class_kind() {
        let d: DemangledFunction =
            demangle_function("impl_hello$$$class__1_Foo").expect("demangle");
        assert_eq!(d.kind, NuitkaSymbolKind::Class);
        assert_eq!(d.function_name, "Foo");
    }

    #[test]
    fn demangle_keeps_underscores_in_name() {
        let d: DemangledFunction =
            demangle_function("impl_pkg$$$function__1_a_b_c").expect("demangle");
        assert_eq!(d.function_name, "a_b_c");
        assert_eq!(d.module_path, "pkg");
    }

    #[test]
    fn demangle_rejects_non_numeric_index() {
        assert!(demangle_function("impl_hello$$$function__x_greet").is_none());
    }

    #[test]
    fn demangle_rejects_missing_infix() {
        assert!(demangle_function("MAKE_FUNCTION_FRAME").is_none());
        assert!(demangle_function("some_random_token").is_none());
    }
}
