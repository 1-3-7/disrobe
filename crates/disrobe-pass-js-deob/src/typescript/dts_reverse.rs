use std::collections::BTreeMap;

use regex::Regex;
use serde::Serialize;

use super::TypeScriptEmitStats;

#[derive(Debug, Clone, Serialize)]
pub struct DtsReverseResult {
    pub emitted_ts: String,
    pub stats: TypeScriptEmitStats,
    pub declared_symbols: BTreeMap<String, String>,
    pub mapped_symbols: BTreeMap<String, String>,
}

#[must_use]
pub fn reverse_declarations(dts: &str, js: &str) -> DtsReverseResult {
    let declared: BTreeMap<String, String> = parse_dts_symbols(dts);
    let js_symbols: BTreeMap<String, JsSymbolKind> = scan_js_symbols(js);
    let mut mapped: BTreeMap<String, String> = BTreeMap::new();
    let mut stats: TypeScriptEmitStats = TypeScriptEmitStats::default();
    for (name, signature) in &declared {
        if js_symbols.contains_key(name) {
            mapped.insert(name.clone(), signature.clone());
            stats.symbols_matched_via_corpus += 1;
        } else {
            stats.unknown_symbols += 1;
        }
    }
    let emitted: String = emit_ts(dts, js, &mapped, &js_symbols);
    stats.annotations_emitted = mapped.len();
    DtsReverseResult {
        emitted_ts: emitted,
        stats,
        declared_symbols: declared,
        mapped_symbols: mapped,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JsSymbolKind {
    Function,
    Class,
    Var,
}

fn parse_dts_symbols(dts: &str) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let func_re: Regex = match Regex::new(
        r"(?m)^\s*(?:export\s+)?declare\s+function\s+([A-Za-z_$][\w$]*)\s*(\([^)]*\)(?:\s*:\s*[^;]+)?)\s*;",
    ) {
        Ok(re) => re,
        Err(_) => return out,
    };
    let const_re: Regex = match Regex::new(
        r"(?m)^\s*(?:export\s+)?declare\s+(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*:\s*([^;]+);",
    ) {
        Ok(re) => re,
        Err(_) => return out,
    };
    let class_re: Regex =
        match Regex::new(r"(?m)^\s*(?:export\s+)?declare\s+class\s+([A-Za-z_$][\w$]*)") {
            Ok(re) => re,
            Err(_) => return out,
        };
    for cap in func_re.captures_iter(dts) {
        if let (Some(name), Some(sig)) = (cap.get(1), cap.get(2)) {
            out.insert(name.as_str().to_owned(), sig.as_str().trim().to_owned());
        }
    }
    for cap in const_re.captures_iter(dts) {
        if let (Some(name), Some(sig)) = (cap.get(1), cap.get(2)) {
            out.insert(name.as_str().to_owned(), sig.as_str().trim().to_owned());
        }
    }
    for cap in class_re.captures_iter(dts) {
        if let Some(name) = cap.get(1) {
            out.entry(name.as_str().to_owned())
                .or_insert_with(|| "class".to_owned());
        }
    }
    out
}

fn scan_js_symbols(js: &str) -> BTreeMap<String, JsSymbolKind> {
    let mut out: BTreeMap<String, JsSymbolKind> = BTreeMap::new();
    let func_re: Regex = match Regex::new(r"(?m)\bfunction\s+([A-Za-z_$][\w$]*)\s*\(") {
        Ok(re) => re,
        Err(_) => return out,
    };
    let class_re: Regex = match Regex::new(r"(?m)\bclass\s+([A-Za-z_$][\w$]*)") {
        Ok(re) => re,
        Err(_) => return out,
    };
    let var_re: Regex = match Regex::new(r"(?m)\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=") {
        Ok(re) => re,
        Err(_) => return out,
    };
    for cap in func_re.captures_iter(js) {
        if let Some(n) = cap.get(1) {
            out.insert(n.as_str().to_owned(), JsSymbolKind::Function);
        }
    }
    for cap in class_re.captures_iter(js) {
        if let Some(n) = cap.get(1) {
            out.insert(n.as_str().to_owned(), JsSymbolKind::Class);
        }
    }
    for cap in var_re.captures_iter(js) {
        if let Some(n) = cap.get(1) {
            out.entry(n.as_str().to_owned())
                .or_insert(JsSymbolKind::Var);
        }
    }
    out
}

fn emit_ts(
    dts: &str,
    js: &str,
    mapped: &BTreeMap<String, String>,
    js_symbols: &BTreeMap<String, JsSymbolKind>,
) -> String {
    fn push_format(out: &mut String, args: std::fmt::Arguments<'_>) {
        let result: std::result::Result<(), std::fmt::Error> = std::fmt::write(out, args);
        if let Err(error) = result {
            unreachable!("string formatting failed: {error}");
        }
    }

    let mut out: String = String::with_capacity(js.len() + dts.len() + 512);
    out.push_str("// reconstructed .ts via .d.ts reverse mapping\n");
    out.push_str("// fields without source in .js are emitted as ambient declarations\n");
    for (name, signature) in mapped {
        match js_symbols.get(name) {
            Some(JsSymbolKind::Function) if signature.starts_with('(') => {
                push_format(
                    &mut out,
                    format_args!("// FUNCTION {name} matched: {signature}\n"),
                );
            }
            Some(JsSymbolKind::Class) => {
                push_format(
                    &mut out,
                    format_args!("// CLASS {name} matched declaration\n"),
                );
            }
            Some(JsSymbolKind::Var) => {
                push_format(&mut out, format_args!("// VAR {name}: {signature}\n"));
            }
            _ => {}
        }
    }
    out.push('\n');
    out.push_str(js);
    out
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn maps_function_from_dts() {
        let dts: &str = "declare function greet(name: string): string;";
        let js: &str = "function greet(name) { return 'hi ' + name; }";
        let res: DtsReverseResult = reverse_declarations(dts, js);
        assert!(res.declared_symbols.contains_key("greet"));
        assert!(res.mapped_symbols.contains_key("greet"));
        assert_eq!(res.stats.symbols_matched_via_corpus, 1);
        assert!(res.emitted_ts.contains("FUNCTION greet"));
    }

    #[test]
    fn maps_var_from_dts() {
        let dts: &str = "declare const API_URL: string;";
        let js: &str = "const API_URL = 'https://example.com';";
        let res: DtsReverseResult = reverse_declarations(dts, js);
        assert!(res.mapped_symbols.contains_key("API_URL"));
    }

    #[test]
    fn declared_but_missing_in_js_counts_unknown() {
        let dts: &str = "declare function missing(): void;";
        let js: &str = "function present() {}";
        let res: DtsReverseResult = reverse_declarations(dts, js);
        assert_eq!(res.stats.unknown_symbols, 1);
        assert!(!res.mapped_symbols.contains_key("missing"));
    }
}
