//! Removal of Roslyn cached-delegate caching boilerplate.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Fold cached-delegate boilerplate in a rendered C# method body.
#[must_use]
pub fn fold_cached_delegates(body: &str) -> (String, u32) {
    let lines: Vec<&str> = body.lines().collect();
    let (mapping, guard_lines): (BTreeMap<String, String>, Vec<usize>) = collect_guards(&lines);
    if mapping.is_empty() {
        return (body.to_owned(), 0);
    }
    let folded: u32 = u32::try_from(mapping.len()).unwrap_or(u32::MAX);
    let mut out: String = String::with_capacity(body.len());
    let mut idx: usize = 0;
    while idx < lines.len() {
        if guard_lines.contains(&idx) {
            idx += 1;
            continue;
        }
        let rewritten: String = rewrite_references(lines[idx], &mapping);
        let _ = writeln!(out, "{rewritten}");
        idx += 1;
    }
    (out, folded)
}

/// Scan for cached-delegate guards, returning a `field -> lambda-name` map and guard line indices.
fn collect_guards(lines: &[&str]) -> (BTreeMap<String, String>, Vec<usize>) {
    let mut mapping: BTreeMap<String, String> = BTreeMap::new();
    let mut guard_lines: Vec<usize> = Vec::new();
    let mut i: usize = 0;
    while i < lines.len() {
        if let Some((field, lambda, span)) = match_guard(&lines[i..]) {
            mapping.insert(field, lambda);
            for off in 0..span {
                guard_lines.push(i + off);
            }
            i += span;
            continue;
        }
        i += 1;
    }
    (mapping, guard_lines)
}

/// Match the guard shape across consecutive lines:
/// ```text
/// if (!(<>9__N_M))
/// {
///     <>9__N_M = new <...>(<>9, <Method>b__N_M);
/// }
/// ```
/// Returns the cached field, the lambda method name, and the number of lines consumed.
fn match_guard(lines: &[&str]) -> Option<(String, String, usize)> {
    let head: &str = lines.first()?.trim();
    let field: &str = head
        .strip_prefix("if (!(")
        .and_then(|s: &str| s.strip_suffix("))"))?;
    if !is_cached_delegate_field(field) {
        return None;
    }
    let mut idx: usize = 1;
    if lines.get(idx).map(|l: &&str| l.trim()) == Some("{") {
        idx += 1;
    }
    let assign: &str = lines.get(idx)?.trim();
    idx += 1;
    let lambda: String = extract_lambda_name(assign, field)?;
    if lines.get(idx).map(|l: &&str| l.trim()) == Some("}") {
        idx += 1;
    }
    Some((field.to_owned(), lambda, idx))
}

/// Whether `name` is a Roslyn cached-delegate field (`<>9__N_M` or `<>9`).
fn is_cached_delegate_field(name: &str) -> bool {
    name == "<>9" || (name.starts_with("<>9__") && name.len() > 5)
}

/// Extract the lambda method name from a cached-delegate assignment.
fn extract_lambda_name(assign: &str, field: &str) -> Option<String> {
    let rhs: &str = assign.strip_prefix(&format!("{field} = "))?;
    let inner: &str = rhs.trim_start_matches("new ");
    let args_start: usize = inner.find('(')?;
    let args: &str = inner[args_start + 1..]
        .trim_end_matches(';')
        .trim_end_matches(')');
    let last: &str = args.rsplit(',').next()?.trim();
    if last.contains("b__") {
        Some(last.to_owned())
    } else {
        None
    }
}

/// Replace each cached-delegate field reference with its lambda method name.
fn rewrite_references(line: &str, mapping: &BTreeMap<String, String>) -> String {
    let mut out: String = line.to_owned();
    for (field, lambda) in mapping {
        if field == "<>9" {
            continue;
        }
        out = out.replace(field, lambda);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_single_cached_delegate() {
        let body: &str = concat!(
            "    if (!(<>9__0_0))\n",
            "    {\n",
            "        <>9__0_0 = new Func(<>9, <CountWith>b__0_0);\n",
            "    }\n",
            "    return xs.Where(<>9__0_0);\n"
        );
        let (out, folded): (String, u32) = fold_cached_delegates(body);
        assert_eq!(folded, 1);
        assert!(!out.contains("<>9__0_0"), "field removed:\n{out}");
        assert!(!out.contains("if (!("), "guard removed:\n{out}");
        assert!(
            out.contains("xs.Where(<CountWith>b__0_0)"),
            "reference rewritten:\n{out}"
        );
    }

    #[test]
    fn folds_multiple_cached_delegates() {
        let body: &str = concat!(
            "    if (!(<>9__1_1))\n",
            "    {\n",
            "        <>9__1_1 = new (<>9, <CrossJoin>b__1_1);\n",
            "    }\n",
            "    if (!(<>9__1_2))\n",
            "    {\n",
            "        <>9__1_2 = new (<>9, <CrossJoin>b__1_2);\n",
            "    }\n",
            "    return Select(<>9__1_1, <>9__1_2);\n"
        );
        let (out, folded): (String, u32) = fold_cached_delegates(body);
        assert_eq!(folded, 2);
        assert!(
            out.contains("Select(<CrossJoin>b__1_1, <CrossJoin>b__1_2)"),
            "both refs rewritten:\n{out}"
        );
    }

    #[test]
    fn non_cached_method_unchanged() {
        let body: &str = "    if (!(local0))\n    {\n        return 0;\n    }\n";
        let (out, folded): (String, u32) = fold_cached_delegates(body);
        assert_eq!(folded, 0);
        assert_eq!(out, body);
    }
}
