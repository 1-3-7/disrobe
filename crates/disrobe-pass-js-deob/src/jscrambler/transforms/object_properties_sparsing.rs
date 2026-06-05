use core::ops::Range;
use std::collections::BTreeMap;

use regex::Regex;

use super::{TransformOpts, TransformOutput, TransformStats};
use crate::error::{Error, Result};
use crate::jscrambler::scanner::{apply_splice_edits, is_valid_js_ident};

pub(in crate::jscrambler) fn detect(source: &str) -> usize {
    let groups: BTreeMap<String, ObjectGroup> = collect_object_groups(source);
    groups
        .values()
        .filter(|g: &&ObjectGroup| g.props.len() >= 2)
        .count()
}

pub(in crate::jscrambler) fn reverse(source: &str, _opts: &TransformOpts) -> TransformOutput {
    let groups: BTreeMap<String, ObjectGroup> = collect_object_groups(source);
    let mut stats: TransformStats = TransformStats::default();
    if groups.is_empty() {
        return TransformOutput::noop(source);
    }
    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    for group in groups.values() {
        if group.props.len() < 2 {
            continue;
        }
        stats.matched += 1;
        let mut lit: String = String::from("{ ");
        for (i, p) in group.props.iter().enumerate() {
            if i > 0 {
                lit.push_str(", ");
            }
            if is_valid_js_ident(&p.key) {
                lit.push_str(&p.key);
            } else {
                lit.push('"');
                lit.push_str(&p.key);
                lit.push('"');
            }
            lit.push_str(": ");
            lit.push_str(&p.value);
        }
        lit.push_str(" }");
        edits.push((group.init_range.clone(), Some(lit)));
        for p in &group.props {
            edits.push((p.statement_range.clone(), Some(String::new())));
        }
    }
    if edits.is_empty() {
        return TransformOutput {
            source: source.to_owned(),
            stats,
        };
    }
    let (rewritten, applied): (String, usize) = apply_splice_edits(source, &mut edits);
    stats.reversed = applied.min(stats.matched);
    TransformOutput {
        source: rewritten,
        stats,
    }
}

pub(in crate::jscrambler) fn reverse_strict(
    source: &str,
    opts: &TransformOpts,
) -> Result<TransformOutput> {
    let out: TransformOutput = reverse(source, opts);
    if out.stats.matched == 0 {
        return Err(Error::TransformNotYetImplemented {
            transform: "objectPropertiesSparsing",
        });
    }
    Ok(out)
}

#[derive(Debug, Clone)]
struct ObjectGroup {
    init_range: Range<usize>,
    props: Vec<PropAssign>,
}

#[derive(Debug, Clone)]
struct PropAssign {
    key: String,
    value: String,
    statement_range: Range<usize>,
}

fn collect_object_groups(source: &str) -> BTreeMap<String, ObjectGroup> {
    let Ok(decl_re): core::result::Result<Regex, regex::Error> =
        Regex::new(r"(?m)(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*\{\s*\}\s*;")
    else {
        return BTreeMap::new();
    };
    let Ok(assign_re): core::result::Result<Regex, regex::Error> =
        Regex::new(r"(?m)([A-Za-z_$][\w$]*)\s*\.\s*([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+);")
    else {
        return BTreeMap::new();
    };
    let mut groups: BTreeMap<String, ObjectGroup> = BTreeMap::new();
    for cap in decl_re.captures_iter(source) {
        let Some(whole): Option<regex::Match<'_>> = cap.get(0) else {
            continue;
        };
        let Some(name): Option<regex::Match<'_>> = cap.get(1) else {
            continue;
        };
        groups.insert(
            name.as_str().to_owned(),
            ObjectGroup {
                init_range: whole.range(),
                props: Vec::new(),
            },
        );
    }
    for cap in assign_re.captures_iter(source) {
        let Some(whole): Option<regex::Match<'_>> = cap.get(0) else {
            continue;
        };
        let Some(obj): Option<regex::Match<'_>> = cap.get(1) else {
            continue;
        };
        let Some(key): Option<regex::Match<'_>> = cap.get(2) else {
            continue;
        };
        let Some(value): Option<regex::Match<'_>> = cap.get(3) else {
            continue;
        };
        if let Some(group) = groups.get_mut(obj.as_str()) {
            if whole.start() <= group.init_range.end {
                continue;
            }
            group.props.push(PropAssign {
                key: key.as_str().to_owned(),
                value: value.as_str().trim().to_owned(),
                statement_range: whole.range(),
            });
        }
    }
    groups
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detect_finds_sparsed_object() {
        let src: &str = "var o = {}; o.a = 1; o.b = 2;";
        assert!(detect(src) >= 1);
    }

    #[test]
    fn collapses_two_props_into_literal() {
        let src: &str = "var o = {};\no.a = 1;\no.b = 2;\n";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert!(out.stats.reversed >= 1);
        assert!(out.source.contains("a: 1"));
        assert!(out.source.contains("b: 2"));
        assert!(!out.source.contains("o.a"));
    }

    #[test]
    fn skips_single_prop_object() {
        let src: &str = "var o = {}; o.a = 1;";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.stats.reversed, 0);
    }

    #[test]
    fn returns_typed_error_in_strict_mode_when_nothing_matches() {
        let res: Result<TransformOutput> = reverse_strict("var x = 1;", &TransformOpts::default());
        assert!(res.is_err());
    }
}
