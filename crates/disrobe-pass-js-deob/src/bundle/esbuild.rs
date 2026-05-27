use regex::Regex;

use super::{BundlerDetection, BundlerKind, ExtractedModule};

pub fn detect(source: &str) -> BundlerDetection {
    let head: &str = &source[..source.len().min(256 * 1024)];
    let mut markers: Vec<String> = Vec::new();
    let mut score: f32 = 0.0;

    let has_commonjs_helper: bool =
        head.contains("var __commonJS = ") || head.contains("var __commonJS=(");
    let has_to_module: bool = head.contains("var __toModule") || head.contains("__toCommonJS");
    let has_export_helper: bool =
        head.contains("var __export = ") || head.contains("var __export=(");
    let has_create_re_export: bool =
        head.contains("var __reExport") || head.contains("__copyProps");
    let has_define_prop_for: bool =
        head.contains("var __defProp = Object.defineProperty") || head.contains("__defNormalProp");
    let has_esm_helper: bool =
        head.contains("var __esm = (fn, res)") || head.contains("var __esm=(fn,res)");
    let has_get_own_prop_names: bool = head
        .contains("var __getOwnPropNames = Object.getOwnPropertyNames")
        || head.contains("var __getOwnPropNames=Object.getOwnPropertyNames");
    let has_path_comments: bool =
        head.contains("// src/") || head.contains("// ./src/") || head.contains("// node_modules/");

    if has_commonjs_helper {
        markers.push("esbuild-__commonJS".to_owned());
        score += 0.35;
    }
    if has_to_module {
        markers.push("esbuild-__toModule".to_owned());
        score += 0.25;
    }
    if has_export_helper {
        markers.push("esbuild-__export".to_owned());
        score += 0.2;
    }
    if has_create_re_export {
        markers.push("esbuild-__reExport".to_owned());
        score += 0.15;
    }
    if has_define_prop_for {
        markers.push("esbuild-__defProp".to_owned());
        score += 0.2;
    }
    if has_esm_helper {
        markers.push("esbuild-__esm".to_owned());
        score += 0.3;
    }
    if has_get_own_prop_names {
        markers.push("esbuild-__getOwnPropNames".to_owned());
        score += 0.15;
    }
    if has_path_comments {
        markers.push("esbuild-path-comments".to_owned());
        score += 0.1;
    }

    if head.contains("__webpack_require__") {
        score -= 0.3;
    }
    if head.contains("@bun") || head.contains("__bun_register") {
        score -= 0.3;
    }

    let matched: bool = score >= 0.45;
    BundlerDetection {
        kind: BundlerKind::Esbuild,
        matched,
        confidence: score.clamp(0.0, 0.95),
        markers,
    }
}

pub(super) fn extract(source: &str) -> Vec<ExtractedModule> {
    let mut modules: Vec<ExtractedModule> = Vec::new();
    extract_commonjs_modules(source, &mut modules);
    extract_es_exports(source, &mut modules);
    modules
}

fn extract_commonjs_modules(source: &str, modules: &mut Vec<ExtractedModule>) {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(
        r#"var\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*__commonJS\s*\(\s*\{\s*["']([^"']+)["']\s*:\s*\(\s*\w+\s*,\s*\w+\s*\)\s*=>\s*\{"#,
    ) else {
        return;
    };
    let bytes: &[u8] = source.as_bytes();
    for caps in re.captures_iter(source) {
        let Some(var_name): Option<&str> = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(path): Option<&str> = caps.get(2).map(|m| m.as_str()) else {
            continue;
        };
        let Some(full): Option<regex::Match<'_>> = caps.get(0) else {
            continue;
        };
        let body_open: usize = full.end() - 1;
        let Some(body_close): Option<usize> = super::scan::find_brace_close(bytes, body_open + 1)
        else {
            continue;
        };
        let body_text: &str = &source[body_open + 1..body_close];
        modules.push(ExtractedModule {
            id: path.to_owned(),
            chunk_id: Some(var_name.to_owned()),
            source: body_text.trim().to_owned(),
        });
    }
}

fn extract_es_exports(source: &str, modules: &mut Vec<ExtractedModule>) {
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_esbuild_runtime_helpers() {
        let src: &str = "var __defProp = Object.defineProperty; var __export = (target, all) => {}; var __commonJS = (cb, mod) => function(){ return mod || (cb((mod={exports:{}}).exports, mod), mod), mod.exports; };";
        let det: BundlerDetection = detect(src);
        assert!(det.matched);
    }

    #[test]
    fn extracts_commonjs_module_blocks() {
        let src: &str = "var require_a = __commonJS({ \"./src/a.js\": (exports, module) => { module.exports = 'first'; } });\nvar require_b = __commonJS({ \"./src/b.js\": (exports, module) => { module.exports = 'second'; } });";
        let mods: Vec<ExtractedModule> = extract(src);
        assert_eq!(mods.len(), 2);
        assert!(mods.iter().any(|m| m.id == "./src/a.js"));
        assert!(mods.iter().any(|m| m.id == "./src/b.js"));
    }
}
