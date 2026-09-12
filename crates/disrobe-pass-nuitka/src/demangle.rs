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
    pub parent_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScopeSegment {
    kind_raw: String,
    source_index: u32,
    name: String,
}

fn parse_scope_segment(segment: &str) -> Option<ScopeSegment> {
    let (kind_raw, rest): (&str, &str) = segment.split_once("__")?;
    let (idx_str, name): (&str, &str) = rest.split_once('_')?;
    let source_index: u32 = idx_str.parse().ok()?;
    if name.is_empty() {
        return None;
    }
    Some(ScopeSegment {
        kind_raw: kind_raw.to_owned(),
        source_index,
        name: name.to_owned(),
    })
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

#[must_use]
pub fn demangle_function(symbol: &str) -> Option<DemangledFunction> {
    let body: &str = symbol
        .strip_prefix("impl_")
        .or_else(|| symbol.strip_prefix("MAKE_FUNCTION_"))
        .unwrap_or(symbol);

    let (module_path, tail): (&str, &str) = body.split_once("$$$")?;
    if module_path.is_empty() {
        return None;
    }

    let mut segments: Vec<ScopeSegment> = Vec::new();
    for raw_segment in tail.split("$$$") {
        segments.push(parse_scope_segment(raw_segment)?);
    }
    let leaf: ScopeSegment = segments.pop()?;
    let parent_names: Vec<String> = segments
        .into_iter()
        .map(|seg: ScopeSegment| seg.name)
        .collect();

    Some(DemangledFunction {
        module_path: module_path.to_owned(),
        function_name: leaf.name,
        source_index: leaf.source_index,
        kind: classify_kind(&leaf.kind_raw),
        kind_raw: leaf.kind_raw,
        raw_symbol: symbol.to_owned(),
        parent_names,
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

    #[test]
    fn demangle_nested_function_carries_parent_chain() {
        let d: DemangledFunction =
            demangle_function("impl_advanced$$$function__5_closure$$$function__1_inner")
                .expect("demangle nested");
        assert_eq!(d.module_path, "advanced");
        assert_eq!(d.function_name, "inner");
        assert_eq!(d.source_index, 1);
        assert_eq!(d.parent_names, vec!["closure".to_owned()]);
        assert_eq!(d.kind, NuitkaSymbolKind::Function);
    }

    #[test]
    fn demangle_top_level_has_empty_parent_chain() {
        let d: DemangledFunction =
            demangle_function("impl_hello$$$function__1_greet").expect("demangle");
        assert!(d.parent_names.is_empty());
    }

    #[test]
    fn demangle_double_nested_function() {
        let d: DemangledFunction =
            demangle_function("impl_m$$$function__1_a$$$function__2_b$$$function__3_c")
                .expect("demangle deep");
        assert_eq!(d.function_name, "c");
        assert_eq!(d.source_index, 3);
        assert_eq!(d.parent_names, vec!["a".to_owned(), "b".to_owned()]);
    }
}
