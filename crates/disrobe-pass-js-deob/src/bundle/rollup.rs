use regex::Regex;

use super::{BundlerDetection, BundlerKind, ExtractedModule};

pub fn detect(source: &str) -> BundlerDetection {
    let head: &str = &source[..source.len().min(256 * 1024)];
    let mut markers: Vec<String> = Vec::new();
    let mut score: f32 = 0.0;

    let has_es_module_flag: bool = head.contains("Object.defineProperty(exports, '__esModule'")
        || head.contains("Object.defineProperty(exports, \"__esModule\"");
    let has_universal_iife: bool =
        head.contains("(function (global, factory)") || head.contains("(function(global, factory)");
    let has_rollup_banner: bool = head.contains("Rollup") || head.contains("rollup");
    let has_named_exports: bool = head.contains("export {") || head.contains("export const ");
    let has_module_define: bool =
        head.contains("define(['exports'") || head.contains("define([\"exports\"");
    let has_pure_comment: bool = head.contains("/*#__PURE__*/") || head.contains("/* @__PURE__ */");
    let has_proto_freeze: bool = head.contains("Object.freeze({\n  __proto__: null")
        || head.contains("Object.freeze({__proto__:null")
        || head.contains("Object.freeze({ __proto__: null");
    let has_dynamic_import_shim: bool = head
        .contains("Promise.resolve().then(function () { return ")
        || head.contains("Promise.resolve().then(() => ");

    if has_es_module_flag {
        markers.push("__esModule-defineProperty".to_owned());
        score += 0.3;
    }
    if has_universal_iife {
        markers.push("rollup-umd-iife".to_owned());
        score += 0.25;
    }
    if has_rollup_banner {
        markers.push("rollup-banner".to_owned());
        score += 0.15;
    }
    if has_named_exports {
        markers.push("es-named-exports".to_owned());
        score += 0.15;
    }
    if has_module_define {
        markers.push("amd-define-exports".to_owned());
        score += 0.15;
    }
    if has_pure_comment {
        markers.push("rollup-pure-annotation".to_owned());
        score += 0.2;
    }
    if has_proto_freeze {
        markers.push("rollup-proto-null-freeze".to_owned());
        score += 0.3;
    }
    if has_dynamic_import_shim {
        markers.push("rollup-dynamic-import-shim".to_owned());
        score += 0.2;
    }

    if head.contains("__webpack_require__") {
        score -= 0.3;
    }
    if head.contains("__vitePreload") {
        score -= 0.3;
    }
    if head.contains("@bun") || head.contains("__bun_register") {
        score -= 0.3;
    }

    let matched: bool = score >= 0.45;
    BundlerDetection {
        kind: BundlerKind::Rollup,
        matched,
        confidence: score.clamp(0.0, 0.93),
        markers,
    }
}

pub(super) fn extract(source: &str) -> Vec<ExtractedModule> {
    let mut modules: Vec<ExtractedModule> = Vec::new();
    extract_export_const(source, &mut modules);
    extract_export_functions(source, &mut modules);
    extract_export_classes(source, &mut modules);
    modules
}

fn extract_export_const(source: &str, modules: &mut Vec<ExtractedModule>) {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r"export\s+(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=")
    else {
        return;
    };
    for caps in re.captures_iter(source) {
        let Some(name): Option<&str> = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(full): Option<regex::Match<'_>> = caps.get(0) else {
            continue;
        };
        let bytes: &[u8] = source.as_bytes();
        let mut end: usize = full.end();
        while end < bytes.len() && bytes[end] != b';' && bytes[end] != b'\n' {
            end += 1;
        }
        let snippet: &str = &source[full.start()..end.min(bytes.len())];
        modules.push(ExtractedModule {
            id: name.to_owned(),
            chunk_id: None,
            source: snippet.trim().to_owned(),
        });
    }
}

fn extract_export_functions(source: &str, modules: &mut Vec<ExtractedModule>) {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r"export\s+(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(")
    else {
        return;
    };
    let bytes: &[u8] = source.as_bytes();
    for caps in re.captures_iter(source) {
        let Some(name): Option<&str> = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(full): Option<regex::Match<'_>> = caps.get(0) else {
            continue;
        };
        let paren_open: usize = full.end() - 1;
        let Some(paren_close): Option<usize> = super::scan::find_paren_close(bytes, paren_open + 1)
        else {
            continue;
        };
        let mut body_open: usize = paren_close + 1;
        while body_open < bytes.len() && matches!(bytes[body_open], b' ' | b'\t' | b'\r' | b'\n') {
            body_open += 1;
        }
        if bytes.get(body_open) != Some(&b'{') {
            continue;
        }
        let Some(body_close): Option<usize> = super::scan::find_brace_close(bytes, body_open + 1)
        else {
            continue;
        };
        modules.push(ExtractedModule {
            id: name.to_owned(),
            chunk_id: None,
            source: source[full.start()..=body_close].trim().to_owned(),
        });
    }
}

fn extract_export_classes(source: &str, modules: &mut Vec<ExtractedModule>) {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r"export\s+class\s+([A-Za-z_$][A-Za-z0-9_$]*)")
    else {
        return;
    };
    let bytes: &[u8] = source.as_bytes();
    for caps in re.captures_iter(source) {
        let Some(name): Option<&str> = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(full): Option<regex::Match<'_>> = caps.get(0) else {
            continue;
        };
        let mut body_open: usize = full.end();
        while body_open < bytes.len() && bytes[body_open] != b'{' {
            body_open += 1;
        }
        let Some(body_close): Option<usize> = super::scan::find_brace_close(bytes, body_open + 1)
        else {
            continue;
        };
        modules.push(ExtractedModule {
            id: name.to_owned(),
            chunk_id: None,
            source: source[full.start()..=body_close].trim().to_owned(),
        });
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_rollup_umd_iife() {
        let src: &str = "(function (global, factory) { factory(global.MyLib = {}); }(this, function (exports) { Object.defineProperty(exports, '__esModule', { value: true }); export const foo = 1; }));";
        let det: BundlerDetection = detect(src);
        assert!(det.matched);
    }

    #[test]
    fn extracts_named_exports() {
        let src: &str = "export const A = 1;\nexport function helper() { return 2; }\nexport class Widget { constructor() {} }";
        let mods: Vec<ExtractedModule> = extract(src);
        assert!(mods.iter().any(|m| m.id == "A"));
        assert!(mods.iter().any(|m| m.id == "helper"));
        assert!(mods.iter().any(|m| m.id == "Widget"));
    }
}
