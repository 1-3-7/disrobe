use std::collections::BTreeMap;

use regex::Regex;

use super::ExtractedModule;

pub fn build_id_to_path_map(modules: &[ExtractedModule]) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for m in modules {
        if !m.id.is_empty() {
            out.insert(m.id.clone(), to_relative(&m.id));
        }
    }
    out
}

pub fn rewrite_requires(source: &str, map: &BTreeMap<String, String>) -> String {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r#"(__webpack_require__|require)\s*\(\s*(?:(\d+)|["']([^"']+)["'])\s*\)"#)
    else {
        return source.to_owned();
    };
    let result: String = re
        .replace_all(source, |caps: &regex::Captures<'_>| {
            let fn_name: &str = caps
                .get(1)
                .map_or("require", |m: regex::Match<'_>| m.as_str());
            let raw_id: String = caps.get(2).map_or_else(
                || {
                    caps.get(3)
                        .map_or_else(String::new, |m: regex::Match<'_>| m.as_str().to_owned())
                },
                |m: regex::Match<'_>| m.as_str().to_owned(),
            );
            map.get(&raw_id).map_or_else(
                || format!("{fn_name}(\"{raw_id}\")"),
                |resolved: &String| format!("{fn_name}(\"{resolved}\")"),
            )
        })
        .into_owned();
    result
}

fn to_relative(id: &str) -> String {
    if id.starts_with("./") || id.starts_with("../") {
        id.to_owned()
    } else if id.starts_with('/') {
        format!(".{id}")
    } else if id.chars().all(|c: char| c.is_ascii_digit()) {
        format!("./module-{id}.js")
    } else if id.contains('/') {
        format!("./{id}")
    } else {
        format!("./{id}.js")
    }
}

pub fn rewrite_modules(modules: &mut [ExtractedModule]) {
    let map: BTreeMap<String, String> = build_id_to_path_map(modules);
    for m in modules.iter_mut() {
        m.source = rewrite_requires(&m.source, &map);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_numeric_require_to_relative_path() {
        let mods: Vec<ExtractedModule> = vec![
            ExtractedModule {
                id: "0".to_owned(),
                chunk_id: None,
                source: "var x = __webpack_require__(1);".to_owned(),
            },
            ExtractedModule {
                id: "1".to_owned(),
                chunk_id: None,
                source: "module.exports = 'one';".to_owned(),
            },
        ];
        let map: BTreeMap<String, String> = build_id_to_path_map(&mods);
        let rewritten: String = rewrite_requires(&mods[0].source, &map);
        assert!(rewritten.contains("./module-1.js"), "got: {rewritten}");
    }

    #[test]
    fn rewrites_string_id_require() {
        let mods: Vec<ExtractedModule> = vec![
            ExtractedModule {
                id: "./src/a.js".to_owned(),
                chunk_id: None,
                source: "var b = require(\"./src/b.js\");".to_owned(),
            },
            ExtractedModule {
                id: "./src/b.js".to_owned(),
                chunk_id: None,
                source: "module.exports = 'b';".to_owned(),
            },
        ];
        let map: BTreeMap<String, String> = build_id_to_path_map(&mods);
        let rewritten: String = rewrite_requires(&mods[0].source, &map);
        assert!(rewritten.contains("./src/b.js"));
    }
}
