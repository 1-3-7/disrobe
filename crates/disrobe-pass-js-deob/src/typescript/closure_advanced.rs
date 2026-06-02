use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;

use regex::Regex;
use serde::Serialize;

use crate::mangled_names::{
    Context, ContextNameSource, CorpusNameSource, HeuristicNameSource, NameRegistry, RestoreStats,
    ScopeKey, SymbolRole,
};

#[derive(Debug, Clone, Default, Serialize)]
pub struct ClosureAdvancedReport {
    pub detected: bool,
    pub property_renames: BTreeMap<String, String>,
    pub dead_code_stripped_bytes: usize,
    pub restore_stats: RestoreStats,
    pub rewritten: String,
}

#[must_use]
pub fn undo_closure_advanced(source: &str) -> ClosureAdvancedReport {
    let detected: bool = looks_like_closure_advanced(source);
    let mangled: BTreeSet<String> = collect_mangled_properties(source);
    let mut registry: NameRegistry = NameRegistry::new()
        .with_source(Arc::new(CorpusNameSource::well_known_minified()))
        .with_source(Arc::new(ContextNameSource::new()))
        .with_source(Arc::new(HeuristicNameSource::new()));

    let mut contexts: BTreeMap<String, Context> = BTreeMap::new();
    for ident in &mangled {
        let mut ctx: Context = Context::new(ident.clone(), SymbolRole::Property, ScopeKey(0));
        for hint in nearby_string_hints(source, ident) {
            ctx.nearby_strings.insert(hint);
        }
        for member in nearby_member_accesses(source, ident) {
            ctx.member_accesses.insert(member);
        }
        contexts.insert(ident.clone(), ctx);
    }
    let (plan, restore_stats): (BTreeMap<String, String>, RestoreStats) =
        registry.restore(&contexts);

    let mut rewritten: String = source.to_owned();
    for (original, restored) in &plan {
        let pattern: String = format!(r"\.{}(?P<tail>\b)", regex::escape(original));
        let Ok(re): Result<Regex, regex::Error> = Regex::new(&pattern) else {
            continue;
        };
        rewritten = re
            .replace_all(&rewritten, format!(".{restored}$tail").as_str())
            .into_owned();
    }
    let before: usize = rewritten.len();
    rewritten = strip_advanced_dead_code(&rewritten);
    let after: usize = rewritten.len();

    ClosureAdvancedReport {
        detected,
        property_renames: plan,
        dead_code_stripped_bytes: before.saturating_sub(after),
        restore_stats,
        rewritten,
    }
}

fn looks_like_closure_advanced(source: &str) -> bool {
    let single_letter_props: usize = Regex::new(r"\.(?:[a-zA-Z]_\b|[a-z]{1,2}\b)")
        .map_or(0, |re: Regex| re.find_iter(source).count());
    let var_underscore: usize =
        Regex::new(r"\b[a-zA-Z]+\$\$module\$").map_or(0, |re: Regex| re.find_iter(source).count());
    single_letter_props >= 4 || var_underscore >= 1
}

fn collect_mangled_properties(source: &str) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    let Ok(re) = Regex::new(r"\.([a-zA-Z][a-zA-Z0-9]?)(_?)") else {
        return out;
    };
    for cap in re.captures_iter(source) {
        if let Some(m) = cap.get(1) {
            let s: &str = m.as_str();
            if s.len() <= 3 && !is_common_short_method(s) {
                out.insert(s.to_owned());
            }
        }
    }
    out
}

fn is_common_short_method(s: &str) -> bool {
    matches!(
        s,
        "of" | "is"
            | "in"
            | "do"
            | "if"
            | "or"
            | "to"
            | "id"
            | "on"
            | "at"
            | "by"
            | "all"
            | "any"
            | "log"
            | "map"
            | "get"
            | "set"
            | "add"
            | "has"
            | "key"
            | "for"
            | "use"
            | "new"
            | "now"
    )
}

fn nearby_string_hints(source: &str, ident: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let Ok(re): Result<Regex, regex::Error> = Regex::new(&format!(
        r#"\.{}\s*[=:]\s*["']([^"']{{2,40}})["']"#,
        regex::escape(ident)
    )) else {
        return out;
    };
    for cap in re.captures_iter(source) {
        if let Some(m) = cap.get(1) {
            out.push(m.as_str().to_owned());
        }
    }
    out
}

fn nearby_member_accesses(source: &str, ident: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(&format!(r"\.{}\.([A-Za-z_$][\w$]*)", regex::escape(ident)))
    else {
        return out;
    };
    for cap in re.captures_iter(source) {
        if let Some(m) = cap.get(1) {
            out.push(m.as_str().to_owned());
        }
    }
    out
}

fn strip_advanced_dead_code(source: &str) -> String {
    let mut out: String = source.to_owned();
    if let Ok(re) = Regex::new(r"(?m)^\s*/\*[!]?goog\..*?\*/\s*$") {
        out = re.replace_all(&out, "").into_owned();
    }
    if let Ok(re) = Regex::new(r"goog\.DEBUG\s*&&[^;]+;") {
        out = re.replace_all(&out, "").into_owned();
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn detects_mangled_property_pattern() {
        let src: &str = "obj.a_=1; obj.b_=2; obj.c_=3; obj.d_=4; obj.e=5;";
        assert!(looks_like_closure_advanced(src));
    }

    #[test]
    fn collects_short_property_names() {
        let src: &str = "obj.a_ = 1; obj.b = 2; obj.length = 3;";
        let props: BTreeSet<String> = collect_mangled_properties(src);
        assert!(props.contains("a"));
        assert!(props.contains("b"));
    }

    #[test]
    fn undoer_returns_rewritten_source_with_plan() {
        let src: &str = "obj.a=1; obj.b=2; obj.c=3; obj.d=4;";
        let r: ClosureAdvancedReport = undo_closure_advanced(src);
        assert!(r.detected);
        assert!(!r.property_renames.is_empty());
        assert!(!r.rewritten.is_empty());
    }
}
