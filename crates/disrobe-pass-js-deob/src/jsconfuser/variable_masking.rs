use std::collections::BTreeMap;
use std::ops::Range;

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    BindingPatternKind, Expression, Program, Statement, VariableDeclaration,
    VariableDeclarationKind, VariableDeclarator,
};
use oxc_parser::Parser;
use oxc_span::SourceType;
use regex::Regex;
use serde::Serialize;

use super::scanner::apply_splice_edits;

#[derive(Debug, Clone, Serialize)]
pub struct VariableMaskingResult {
    pub proxies_eliminated: usize,
    pub rewritten_source: String,
}

#[must_use]
pub fn reverse_variable_masking(source: &str) -> VariableMaskingResult {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("masking.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if parsed.panicked {
        return passthrough(source);
    }
    let aliases: BTreeMap<String, String> = collect_proxy_aliases(&parsed.program);
    if aliases.is_empty() {
        return passthrough(source);
    }
    let resolved: BTreeMap<String, String> = resolve_alias_chains(&aliases);
    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    let bytes: &[u8] = source.as_bytes();
    for alias in resolved.keys() {
        let pattern: String = format!(
            r"(?:var|let|const)\s+{}\s*=\s*[A-Za-z_$][\w$]*\s*;",
            regex::escape(alias)
        );
        let Ok(re): Result<Regex, regex::Error> = Regex::new(&pattern) else {
            continue;
        };
        for mat in re.find_iter(source) {
            edits.push((mat.start()..mat.end(), Some(String::new())));
        }
    }
    let identifier_re: Regex = match Regex::new(r"[A-Za-z_$][\w$]*") {
        Ok(re) => re,
        Err(_) => return passthrough(source),
    };
    for mat in identifier_re.find_iter(source) {
        let name: &str = mat.as_str();
        if let Some(target) = resolved.get(name) {
            let before: u8 = if mat.start() == 0 {
                b' '
            } else {
                bytes[mat.start() - 1]
            };
            if matches!(before, b'.' | b'$' | b'_') || before.is_ascii_alphanumeric() {
                continue;
            }
            if is_object_property_key(bytes, mat.end()) {
                continue;
            }
            edits.push((mat.start()..mat.end(), Some(target.clone())));
        }
    }
    if edits.is_empty() {
        return passthrough(source);
    }
    let (rewritten, eliminated): (String, usize) = apply_splice_edits(source, &mut edits);
    VariableMaskingResult {
        proxies_eliminated: eliminated,
        rewritten_source: rewritten,
    }
}

fn passthrough(source: &str) -> VariableMaskingResult {
    VariableMaskingResult {
        proxies_eliminated: 0,
        rewritten_source: source.to_owned(),
    }
}

fn collect_proxy_aliases(program: &Program<'_>) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for stmt in &program.body {
        let Statement::VariableDeclaration(decl) = stmt else {
            continue;
        };
        scan_var_decl(decl, &mut out);
    }
    for stmt in &program.body {
        if let Statement::FunctionDeclaration(func) = stmt
            && let Some(body) = func.body.as_ref()
        {
            for inner in &body.statements {
                if let Statement::VariableDeclaration(decl) = inner {
                    scan_var_decl(decl, &mut out);
                }
            }
        }
    }
    out
}

fn scan_var_decl(decl: &VariableDeclaration<'_>, out: &mut BTreeMap<String, String>) {
    if !matches!(
        decl.kind,
        VariableDeclarationKind::Var
            | VariableDeclarationKind::Let
            | VariableDeclarationKind::Const
    ) {
        return;
    }
    for declarator in &decl.declarations {
        if let Some((alias, target)) = single_identifier_proxy(declarator)
            && looks_like_proxy_identifier(&alias)
        {
            out.insert(alias, target);
        }
    }
}

fn single_identifier_proxy(declarator: &VariableDeclarator<'_>) -> Option<(String, String)> {
    let alias: String = match &declarator.id.kind {
        BindingPatternKind::BindingIdentifier(b) => b.name.as_str().to_owned(),
        _ => return None,
    };
    let init: &Expression<'_> = declarator.init.as_ref()?;
    let Expression::Identifier(ident) = init else {
        return None;
    };
    let target: String = ident.name.as_str().to_owned();
    if target == alias {
        return None;
    }
    Some((alias, target))
}

fn is_object_property_key(bytes: &[u8], end: usize) -> bool {
    let mut i: usize = end;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b':' {
        return false;
    }
    if bytes.get(i + 1) == Some(&b':') {
        return false;
    }
    true
}

fn looks_like_proxy_identifier(name: &str) -> bool {
    let bytes: &[u8] = name.as_bytes();
    if bytes.len() < 3 {
        return false;
    }
    let mut dollar_or_underscore: usize = 0;
    for &b in bytes {
        if matches!(b, b'_' | b'$') {
            dollar_or_underscore += 1;
        }
    }
    dollar_or_underscore * 2 >= bytes.len() && dollar_or_underscore >= 2
}

fn resolve_alias_chains(aliases: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for alias in aliases.keys() {
        let mut current: String = alias.clone();
        let mut steps: usize = 0;
        while let Some(next) = aliases.get(&current) {
            if next == &current || steps > 32 {
                break;
            }
            current.clone_from(next);
            steps += 1;
        }
        if &current != alias {
            out.insert(alias.clone(), current);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eliminates_two_level_proxy_chain() {
        let src: &str = "var _$_$ = console;\nvar _$$_ = _$_$;\nfunction main(){ _$$_.log('x'); }";
        let r: VariableMaskingResult = reverse_variable_masking(src);
        assert!(r.proxies_eliminated >= 1);
        assert!(r.rewritten_source.contains("console.log('x')"));
        assert!(!r.rewritten_source.contains("_$$_"));
    }

    #[test]
    fn preserves_normal_identifiers() {
        let src: &str = "var data = 1;\nvar copy = data;\nuse(copy);";
        let r: VariableMaskingResult = reverse_variable_masking(src);
        assert_eq!(r.proxies_eliminated, 0);
        assert_eq!(r.rewritten_source, src);
    }

    #[test]
    fn skips_member_access_with_same_name() {
        let src: &str = "var _$$_ = console;\nvar obj = { _$$_: 1 };";
        let r: VariableMaskingResult = reverse_variable_masking(src);
        assert!(r.rewritten_source.contains("_$$_: 1"));
    }
}
