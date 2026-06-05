use std::collections::BTreeMap;

use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize)]
pub struct PresetEnvUndoResult {
    pub rewritten: String,
    pub helpers_removed: BTreeMap<String, usize>,
    pub spreads_restored: usize,
    pub classes_restored: usize,
    pub async_restored: usize,
    pub optional_chains_restored: usize,
    pub nullish_coalesce_restored: usize,
}

fn try_replace(text: &str, pattern: &str, replacement: &str) -> (String, usize) {
    let re: Regex = match Regex::new(pattern) {
        Ok(r) => r,
        Err(_) => return (text.to_owned(), 0),
    };
    let count: usize = re.find_iter(text).count();
    if count == 0 {
        return (text.to_owned(), 0);
    }
    (re.replace_all(text, replacement).into_owned(), count)
}

fn collapse_optional_chains(text: &str) -> (String, usize) {
    let outer: Regex = match Regex::new(
        r"\(\s*([A-Za-z_$][\w$]*)\s*===?\s*null\s*\|\|\s*([A-Za-z_$][\w$]*)\s*===?\s*void 0\s*\)\s*\?\s*void 0\s*:\s*([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)",
    ) {
        Ok(r) => r,
        Err(_) => return (text.to_owned(), 0),
    };
    let mut count: usize = 0;
    let result: std::borrow::Cow<'_, str> =
        outer.replace_all(text, |caps: &regex::Captures<'_>| {
            let a: &str = caps.get(1).map_or("", |m| m.as_str());
            let b: &str = caps.get(2).map_or("", |m| m.as_str());
            let c: &str = caps.get(3).map_or("", |m| m.as_str());
            let field: &str = caps.get(4).map_or("", |m| m.as_str());
            if a == b && b == c {
                count = count.saturating_add(1);
                return format!("{a}?.{field}");
            }
            caps.get(0).map_or(String::new(), |m| m.as_str().to_owned())
        });
    (result.into_owned(), count)
}

fn collapse_nullish_coalesce(text: &str) -> (String, usize) {
    let outer: Regex = match Regex::new(
        r"([A-Za-z_$][\w$]*)\s*!==?\s*null\s*&&\s*([A-Za-z_$][\w$]*)\s*!==?\s*void 0\s*\?\s*([A-Za-z_$][\w$]*)\s*:\s*([A-Za-z_$][\w$]*)",
    ) {
        Ok(r) => r,
        Err(_) => return (text.to_owned(), 0),
    };
    let mut count: usize = 0;
    let result: std::borrow::Cow<'_, str> =
        outer.replace_all(text, |caps: &regex::Captures<'_>| {
            let a: &str = caps.get(1).map_or("", |m| m.as_str());
            let b: &str = caps.get(2).map_or("", |m| m.as_str());
            let c: &str = caps.get(3).map_or("", |m| m.as_str());
            let fallback: &str = caps.get(4).map_or("", |m| m.as_str());
            if a == b && b == c {
                count = count.saturating_add(1);
                return format!("{a} ?? {fallback}");
            }
            caps.get(0).map_or(String::new(), |m| m.as_str().to_owned())
        });
    (result.into_owned(), count)
}

#[must_use]
pub fn undo_preset_env(source: &str) -> PresetEnvUndoResult {
    let mut out: String = source.to_owned();
    let mut helpers_removed: BTreeMap<String, usize> = BTreeMap::new();

    let helpers: &[&str] = &[
        "_toConsumableArray",
        "_classCallCheck",
        "_createClass",
        "_inherits",
        "_possibleConstructorReturn",
        "_getPrototypeOf",
        "_defineProperty",
        "_objectSpread",
        "_objectWithoutProperties",
        "_asyncToGenerator",
        "_regeneratorRuntime",
        "_typeof",
        "_slicedToArray",
        "_toArray",
        "_iterableToArray",
        "_arrayLikeToArray",
        "_assertThisInitialized",
        "_setPrototypeOf",
        "_construct",
        "_wrapNativeSuper",
    ];
    for helper in helpers {
        let pattern: String = format!(
            r"(?ms)function\s+{}\s*\([^)]*\)\s*\{{(?:[^{{}}]|\{{[^{{}}]*\}})*?\}}\s*",
            regex::escape(helper)
        );
        let (next, count): (String, usize) = try_replace(&out, &pattern, "");
        out = next;
        if count > 0 {
            helpers_removed.insert((*helper).to_owned(), count);
        }
    }

    let (next, spreads_restored): (String, usize) = try_replace(
        &out,
        r"_toConsumableArray\s*\(\s*([A-Za-z_$][\w$]*)\s*\)",
        "...$1",
    );
    out = next;
    let (next, classes_restored): (String, usize) = try_replace(
        &out,
        r"_classCallCheck\s*\(\s*this\s*,\s*[A-Za-z_$][\w$]*\s*\)\s*;\s*",
        "",
    );
    out = next;
    let (next, async_restored): (String, usize) = try_replace(
        &out,
        r"_asyncToGenerator\s*\(\s*function\s*\*\s*\(\s*\)",
        "async function()",
    );
    out = next;
    let (next, optional_chains_restored): (String, usize) = collapse_optional_chains(&out);
    out = next;
    let (next, nullish_coalesce_restored): (String, usize) = collapse_nullish_coalesce(&out);
    out = next;

    PresetEnvUndoResult {
        rewritten: out,
        helpers_removed,
        spreads_restored,
        classes_restored,
        async_restored,
        optional_chains_restored,
        nullish_coalesce_restored,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn restores_array_spread() {
        let src: &str = "var b = [].concat(_toConsumableArray(a), [1]);";
        let r: PresetEnvUndoResult = undo_preset_env(src);
        assert!(r.spreads_restored >= 1);
        assert!(r.rewritten.contains("...a"));
    }

    #[test]
    fn removes_class_call_check() {
        let src: &str = "function Foo() { _classCallCheck(this, Foo); this.x = 1; }";
        let r: PresetEnvUndoResult = undo_preset_env(src);
        assert!(r.classes_restored >= 1);
        assert!(!r.rewritten.contains("_classCallCheck"));
    }

    #[test]
    fn detects_async_to_generator() {
        let src: &str = "var f = _asyncToGenerator(function* () { yield 1; });";
        let r: PresetEnvUndoResult = undo_preset_env(src);
        assert!(r.async_restored >= 1);
        assert!(r.rewritten.contains("async function()"));
    }

    #[test]
    fn restores_optional_chain() {
        let src: &str = "var v = (obj === null || obj === void 0) ? void 0 : obj.field;";
        let r: PresetEnvUndoResult = undo_preset_env(src);
        assert!(r.optional_chains_restored >= 1);
        assert!(r.rewritten.contains("obj?.field"));
    }

    #[test]
    fn restores_nullish_coalesce() {
        let src: &str = "var x = (val !== null && val !== void 0 ? val : fallback);";
        let r: PresetEnvUndoResult = undo_preset_env(src);
        assert!(r.nullish_coalesce_restored >= 1);
        assert!(r.rewritten.contains("val ?? fallback"));
    }

    #[test]
    fn strips_helper_definitions() {
        let src: &str = "function _classCallCheck(a, b) { if (!(a instanceof b)) throw new TypeError('x'); } function Foo() {}";
        let r: PresetEnvUndoResult = undo_preset_env(src);
        assert_eq!(r.helpers_removed.get("_classCallCheck"), Some(&1));
        assert!(!r.rewritten.contains("function _classCallCheck"));
    }
}
