use std::collections::BTreeMap;

fn push_format(out: &mut String, args: std::fmt::Arguments<'_>) {
    let result: std::result::Result<(), std::fmt::Error> = std::fmt::write(out, args);
    if let Err(error) = result {
        unreachable!("string formatting failed: {error}");
    }
}

#[must_use]
pub fn fold_cached_delegates(body: &str) -> (String, u32) {
    let lines: Vec<&str> = body.lines().collect();
    let (mapping, guard_lines): (BTreeMap<String, String>, Vec<usize>) = collect_guards(&lines);
    let mut folded: u32 = u32::try_from(mapping.len()).unwrap_or(u32::MAX);
    let mut out: String = String::with_capacity(body.len());
    let mut idx: usize = 0;
    while idx < lines.len() {
        if guard_lines.contains(&idx) {
            idx += 1;
            continue;
        }
        if is_singleton_plumbing(lines[idx]) {
            idx += 1;
            continue;
        }
        let rewritten: String = rewrite_references(lines[idx], &mapping);
        let (collapsed, hits): (String, u32) = collapse_method_group_delegates(&rewritten);
        folded = folded.saturating_add(hits);
        push_format(&mut out, format_args!("{collapsed}\n"));
        idx += 1;
    }
    (out, folded)
}

fn is_singleton_plumbing(line: &str) -> bool {
    let t: &str = line.trim();
    matches!(t, "<>9 = new <>c();" | "this.ctor();") || t.starts_with("<>9 = new <>c__")
}

fn collapse_method_group_delegates(line: &str) -> (String, u32) {
    let mut out: String = String::with_capacity(line.len());
    let mut rest: &str = line;
    let mut hits: u32 = 0;
    while let Some(pos) = rest.find("new ") {
        let head_end: usize = pos + "new ".len();
        let after: &str = &rest[head_end..];
        if let Some((replacement, consumed)) = match_method_group_ctor(after) {
            out.push_str(&rest[..pos]);
            out.push_str(&replacement);
            rest = &after[consumed..];
            hits += 1;
        } else {
            out.push_str(&rest[..head_end]);
            rest = after;
        }
    }
    out.push_str(rest);
    (out, hits)
}

fn match_method_group_ctor(s: &str) -> Option<(String, usize)> {
    let open: usize = s.find('(')?;
    let depth_end: usize = matching_paren(&s[open..])? + open;
    let inner: &str = &s[open + 1..depth_end];
    let mut parts: std::str::Split<'_, char> = inner.split(',');
    let receiver: &str = parts.next()?.trim();
    let method: &str = parts.next()?.trim();
    if parts.next().is_some() {
        return None;
    }
    if !matches!(receiver, "<>9" | "this") || !method.contains("b__") {
        return None;
    }
    Some((method.to_owned(), depth_end + 1))
}

fn matching_paren(s: &str) -> Option<usize> {
    let bytes: &[u8] = s.as_bytes();
    if bytes.first() != Some(&b'(') {
        return None;
    }
    let mut depth: u32 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

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

fn is_cached_delegate_field(name: &str) -> bool {
    name == "<>9" || (name.starts_with("<>9__") && name.len() > 5)
}

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

    #[test]
    fn collapses_singleton_method_group_delegate() {
        let body: &str =
            "    return source.Select(new Func<int, int>(<>9, <Doubled>b__1_0)).ToList();\n";
        let (out, folded): (String, u32) = fold_cached_delegates(body);
        assert!(
            out.contains("source.Select(<Doubled>b__1_0).ToList();"),
            "method group recovered, synthetic <>9 receiver and delegate ctor dropped:\n{out}"
        );
        assert!(!out.contains("new Func"), "delegate ctor removed:\n{out}");
        assert!(!out.contains("<>9"), "singleton receiver removed:\n{out}");
        assert_eq!(folded, 1);
    }

    #[test]
    fn strips_singleton_cctor_plumbing() {
        let body: &str = "    <>9 = new <>c();\n    return;\n";
        let (out, _folded): (String, u32) = fold_cached_delegates(body);
        assert!(!out.contains("<>9"), "singleton init line removed:\n{out}");
        assert!(out.contains("return;"), "real statement preserved:\n{out}");
    }

    #[test]
    fn keeps_real_two_arg_ctor() {
        let body: &str = "    local0 = new Point(this, other);\n";
        let (out, folded): (String, u32) = fold_cached_delegates(body);
        assert_eq!(out, body, "non-delegate ctor untouched:\n{out}");
        assert_eq!(folded, 0);
    }

    #[test]
    fn collapses_instance_method_group() {
        let body: &str = "    return new Action(this, <Run>b__2_0);\n";
        let (out, _folded): (String, u32) = fold_cached_delegates(body);
        assert!(
            out.contains("return <Run>b__2_0;"),
            "instance method group recovered:\n{out}"
        );
    }
}
