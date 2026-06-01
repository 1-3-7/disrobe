use std::ops::Range;

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    BindingPatternKind, Program, Statement, VariableDeclaration, VariableDeclarationKind,
};
use oxc_parser::Parser;
use oxc_span::SourceType;
use regex::Regex;
use serde::Serialize;

use super::scanner::apply_splice_edits;

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
            .all(|n: &String| unassigned.iter().any(|u: &String| u == n));
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
    let final_source: String = rewrite_first_assignments(&rewritten, &unassigned);
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

fn rewrite_first_assignments(source: &str, names: &[String]) -> String {
    let mut current: String = source.to_owned();
    for name in names {
        let escaped: String = regex::escape(name);
        let pattern: String = format!(r"(^|[\s;{{}}])({escaped})\s*=\s*");
        let Ok(re): Result<Regex, regex::Error> = Regex::new(&pattern) else {
            continue;
        };
        if let Some(mat) = re.find(&current) {
            let start: usize = mat.start();
            let end: usize = mat.end();
            let whole: &str = &current[start..end];
            let prefix: &str = whole.split_once(name.as_str()).map_or("", |(l, _)| l);
            let replacement: String = format!("{prefix}var {name} = ");
            let new_source: String =
                format!("{}{}{}", &current[..start], replacement, &current[end..]);
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
