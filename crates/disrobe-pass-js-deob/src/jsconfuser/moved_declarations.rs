use std::ops::Range;

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    BindingPatternKind, Program, Statement, VariableDeclaration, VariableDeclarationKind,
};
use oxc_parser::Parser;
use oxc_span::SourceType;
use regex::Regex;
use serde::Serialize;

use super::scanner::{apply_splice_edits, skip_string_literal};

#[derive(Debug, Clone, Serialize)]
pub struct MovedDeclReversalResult {
    pub decls_normalized: usize,
    pub rewritten_source: String,
}

#[must_use]
pub fn reverse_moved_declarations(source: &str) -> MovedDeclReversalResult {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("moved.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if parsed.panicked {
        return passthrough(source);
    }
    let unassigned: Vec<String> = collect_top_level_unassigned_var_names(&parsed.program);
    if unassigned.is_empty() {
        return passthrough(source);
    }
    let movable: Vec<String> = unassigned
        .into_iter()
        .filter(|name: &String| first_assignment_can_move(source, name))
        .collect();
    if movable.is_empty() {
        return passthrough(source);
    }
    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    let bytes: &[u8] = source.as_bytes();
    let list_re: Regex = match Regex::new(r"(?m)\bvar\s+([A-Za-z_$][\w$, \t]*)\s*;") {
        Ok(re) => re,
        Err(_) => return passthrough(source),
    };
    for mat in list_re.find_iter(source) {
        let captured: &str = mat.as_str();
        let names_in_decl: Vec<String> = captured
            .trim_start_matches("var")
            .trim_end_matches(';')
            .split(',')
            .map(|s: &str| s.trim().to_owned())
            .filter(|s: &String| !s.is_empty() && !s.contains('='))
            .collect();
        if names_in_decl.is_empty() {
            continue;
        }
        let all_match: bool = names_in_decl
            .iter()
            .all(|n: &String| movable.iter().any(|u: &String| u == n));
        if !all_match {
            continue;
        }
        let mut tail: usize = mat.end();
        while tail < bytes.len() && matches!(bytes[tail], b'\n' | b'\r' | b' ' | b'\t') {
            tail += 1;
        }
        edits.push((mat.start()..tail, Some(String::new())));
    }
    if edits.is_empty() {
        return passthrough(source);
    }
    let removed: usize = edits.len();
    let (rewritten, _): (String, usize) = apply_splice_edits(source, &mut edits);
    let final_source: String = rewrite_first_assignments(&rewritten, &movable);
    MovedDeclReversalResult {
        decls_normalized: removed,
        rewritten_source: final_source,
    }
}

fn passthrough(source: &str) -> MovedDeclReversalResult {
    MovedDeclReversalResult {
        decls_normalized: 0,
        rewritten_source: source.to_owned(),
    }
}

fn collect_top_level_unassigned_var_names(program: &Program<'_>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for stmt in &program.body {
        if let Statement::VariableDeclaration(decl) = stmt {
            walk_decl(decl, &mut out);
        }
    }
    out
}

fn walk_decl(decl: &VariableDeclaration<'_>, out: &mut Vec<String>) {
    if !matches!(decl.kind, VariableDeclarationKind::Var) {
        return;
    }
    for declarator in &decl.declarations {
        if declarator.init.is_some() {
            continue;
        }
        if let BindingPatternKind::BindingIdentifier(b) = &declarator.id.kind
            && looks_hoisted(b.name.as_str())
        {
            out.push(b.name.as_str().to_owned());
        }
    }
}

fn looks_hoisted(name: &str) -> bool {
    let bytes: &[u8] = name.as_bytes();
    bytes.len() >= 2
        && (matches!(bytes[0], b'_' | b'$') || name.starts_with("tmp") || name.starts_with("var_"))
}

fn first_assignment_can_move(source: &str, name: &str) -> bool {
    let Some(range): Option<Range<usize>> = first_assignment_range(source, name) else {
        return false;
    };
    let name_pos: usize = source[range.clone()]
        .find(name)
        .map_or(range.start, |offset: usize| range.start + offset);
    let Some(scope_end): Option<usize> = containing_brace_end(source, name_pos) else {
        return true;
    };
    !identifier_occurs_after(source, name, scope_end)
}

fn first_assignment_range(source: &str, name: &str) -> Option<Range<usize>> {
    let escaped: String = regex::escape(name);
    let pattern: String = format!(r"(^|[\s;{{}}])({escaped})\s*=\s*");
    let re: Regex = Regex::new(&pattern).ok()?;
    let mat: regex::Match<'_> = re.find(source)?;
    Some(mat.start()..mat.end())
}

fn containing_brace_end(source: &str, pos: usize) -> Option<usize> {
    let bytes: &[u8] = source.as_bytes();
    let mut stack: Vec<usize> = Vec::new();
    let mut i: usize = 0;
    while i < pos && i < bytes.len() {
        match bytes[i] {
            b'\'' | b'"' | b'`' => {
                i = skip_string_literal(bytes, i, bytes[i])?;
                continue;
            }
            b'{' => stack.push(i),
            b'}' => {
                stack.pop()?;
            }
            _ => {}
        }
        i += 1;
    }
    let open: usize = *stack.last()?;
    let mut depth: usize = 1;
    i = open + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' | b'"' | b'`' => {
                i = skip_string_literal(bytes, i, bytes[i])?;
                continue;
            }
            b'{' => depth = depth.saturating_add(1),
            b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn identifier_occurs_after(source: &str, name: &str, start: usize) -> bool {
    let escaped: String = regex::escape(name);
    let pattern: String = format!(r"(^|[^A-Za-z0-9_$]){escaped}([^A-Za-z0-9_$]|$)");
    Regex::new(&pattern)
        .ok()
        .is_some_and(|re: Regex| re.is_match(&source[start..]))
}

fn rewrite_first_assignments(source: &str, names: &[String]) -> String {
    let mut current: String = source.to_owned();
    for name in names {
        if let Some(range) = first_assignment_range(&current, name) {
            let whole: &str = &current[range.clone()];
            let prefix: &str = whole.split_once(name.as_str()).map_or("", |(l, _)| l);
            let replacement: String = format!("{prefix}var {name} = ");
            let new_source: String = format!(
                "{}{}{}",
                &current[..range.start],
                replacement,
                &current[range.end..]
            );
            current = new_source;
        }
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_top_hoisted_var_to_first_use() {
        let src: &str = "var _tmp1, _tmp2;\nfunction main(){\n  _tmp1 = compute();\n  _tmp2 = _tmp1 + 1;\n  return _tmp2;\n}";
        let r: MovedDeclReversalResult = reverse_moved_declarations(src);
        assert!(r.decls_normalized >= 1);
        assert!(!r.rewritten_source.starts_with("var _tmp1, _tmp2;"));
        assert!(r.rewritten_source.contains("var _tmp1 = compute()"));
    }

    #[test]
    fn leaves_unrelated_decls_alone() {
        let src: &str = "var data = compute();\nuse(data);";
        let r: MovedDeclReversalResult = reverse_moved_declarations(src);
        assert_eq!(r.decls_normalized, 0);
        assert_eq!(r.rewritten_source, src);
    }
}
