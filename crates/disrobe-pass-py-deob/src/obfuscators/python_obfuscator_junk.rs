use std::collections::BTreeSet;

use ruff_python_ast::token::{Token, TokenKind};
use ruff_python_ast::visitor::{Visitor, walk_expr, walk_stmt};
use ruff_python_ast::{
    AtomicNodeIndex, ExceptHandler, Expr, ExprContext, ExprName, ModModule, Number, Stmt,
    StmtAssign, StmtPass,
};
use ruff_python_codegen::{Generator, Stylist};
use ruff_python_parser::{Mode, ParseOptions, Parsed, parse_module, parse_unchecked};
use ruff_text_size::{Ranged, TextRange};

use super::render_str_literal;
use crate::error::{Error, Result};

const JUNK_LETTERS: usize = 79;
const JUNK_INT_LIMIT: u64 = 1_000;
const MAX_SWEEPS: usize = 4_096;
const INTROSPECTION: [&str; 6] = ["globals", "locals", "vars", "dir", "eval", "exec"];

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JunkStats {
    pub(crate) hex_constants_folded: usize,
    pub(crate) unreachable_removed: usize,
    pub(crate) junk_assignments_removed: usize,
    pub(crate) introspection_blocked: bool,
}

pub(crate) fn clean_inner_source(source: &str) -> Result<(String, JunkStats)> {
    let mut stats: JunkStats = JunkStats::default();
    let (folded, hex_folded): (String, usize) = fold_fromhex_constants(source);
    stats.hex_constants_folded = hex_folded;
    let parsed: Parsed<ModModule> = parse_module(&folded)
        .map_err(|e| Error::AstCleanup(format!("python-obfuscator inner source: {e}")))?;
    let stylist: Stylist<'_> = Stylist::from_tokens(parsed.tokens(), &folded);
    let mut module: ModModule = parsed.into_syntax();

    stats.unreachable_removed = drop_unreachable(&mut module.body);
    stats.introspection_blocked = uses_introspection(&module);
    if !stats.introspection_blocked {
        for _ in 0..MAX_SWEEPS {
            let used: BTreeSet<String> = used_names(&module);
            let removed: usize = drop_junk_assignments(&mut module.body, &used);
            if removed == 0 {
                break;
            }
            stats.junk_assignments_removed += removed;
        }
    }

    let mut out: String = String::with_capacity(folded.len());
    for stmt in &module.body {
        out.push_str(&Generator::from(&stylist).stmt(stmt));
        out.push('\n');
    }
    Ok((out, stats))
}

fn fold_fromhex_constants(source: &str) -> (String, usize) {
    let parsed: Parsed<ruff_python_ast::Mod> =
        parse_unchecked(source, ParseOptions::from(Mode::Module));
    let tokens: &[Token] = parsed.tokens();
    let mut replacements: Vec<(TextRange, String)> = Vec::new();
    let mut index: usize = 0;
    while index < tokens.len() {
        match fromhex_call_at(source, tokens.get(index..).unwrap_or_default()) {
            Some((range, literal, consumed)) => {
                replacements.push((range, literal));
                index += consumed;
            }
            None => index += 1,
        }
    }
    let count: usize = replacements.len();
    let mut out: String = String::with_capacity(source.len());
    let mut cursor: usize = 0;
    for (range, literal) in replacements {
        let start: usize = range.start().to_usize();
        out.push_str(source.get(cursor..start).unwrap_or_default());
        out.push_str(&literal);
        cursor = range.end().to_usize();
    }
    out.push_str(source.get(cursor..).unwrap_or_default());
    (out, count)
}

fn fromhex_call_at(source: &str, tokens: &[Token]) -> Option<(TextRange, String, usize)> {
    const SHAPE: [TokenKind; 11] = [
        TokenKind::Name,
        TokenKind::Dot,
        TokenKind::Name,
        TokenKind::Lpar,
        TokenKind::String,
        TokenKind::Rpar,
        TokenKind::Dot,
        TokenKind::Name,
        TokenKind::Lpar,
        TokenKind::String,
        TokenKind::Rpar,
    ];
    let window: &[Token] = tokens.get(..SHAPE.len())?;
    if window
        .iter()
        .zip(SHAPE)
        .any(|(token, kind): (&Token, TokenKind)| token.kind() != kind)
    {
        return None;
    }
    let text = |at: usize| -> Option<&str> {
        let range: TextRange = window.get(at)?.range();
        source.get(range.start().to_usize()..range.end().to_usize())
    };
    if text(0)? != "bytes" || text(2)? != "fromhex" || text(7)? != "decode" {
        return None;
    }
    let encoding: &str = plain_quoted(text(9)?)?;
    if !matches!(encoding, "utf-8" | "utf8" | "UTF-8") {
        return None;
    }
    let hex: &str = plain_quoted(text(4)?)?;
    if !hex.len().is_multiple_of(2) || !hex.bytes().all(|b: u8| b.is_ascii_hexdigit()) {
        return None;
    }
    let bytes: Vec<u8> = hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair: &[u8]| {
            let digits: &str = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(digits, 16).ok()
        })
        .collect::<Option<Vec<u8>>>()?;
    let decoded: String = String::from_utf8(bytes).ok()?;
    let range: TextRange = TextRange::new(window[0].start(), window[SHAPE.len() - 1].end());
    Some((range, render_str_literal(&decoded), SHAPE.len()))
}

fn plain_quoted(token: &str) -> Option<&str> {
    let quote: char = token.chars().next()?;
    if !matches!(quote, '\'' | '"') || token.len() < 2 || !token.ends_with(quote) {
        return None;
    }
    let body: &str = token.get(1..token.len() - 1)?;
    (!body.contains(['\\', quote])).then_some(body)
}

const fn is_terminal(stmt: &Stmt) -> bool {
    matches!(
        stmt,
        Stmt::Return(_) | Stmt::Raise(_) | Stmt::Continue(_) | Stmt::Break(_)
    )
}

fn drop_unreachable(body: &mut Vec<Stmt>) -> usize {
    let mut removed: usize = 0;
    if let Some(stop) = body.iter().position(is_terminal) {
        removed += body.len() - stop - 1;
        body.truncate(stop + 1);
    }
    for stmt in body.iter_mut() {
        for_each_block(stmt, &mut |block: &mut Vec<Stmt>| {
            removed += drop_unreachable(block);
        });
    }
    removed
}

fn for_each_block(stmt: &mut Stmt, visit: &mut dyn FnMut(&mut Vec<Stmt>)) {
    match stmt {
        Stmt::FunctionDef(def) => visit(&mut def.body),
        Stmt::ClassDef(class) => visit(&mut class.body),
        Stmt::If(branch) => {
            visit(&mut branch.body);
            for clause in &mut branch.elif_else_clauses {
                visit(&mut clause.body);
            }
        }
        Stmt::For(looped) => {
            visit(&mut looped.body);
            visit(&mut looped.orelse);
        }
        Stmt::While(looped) => {
            visit(&mut looped.body);
            visit(&mut looped.orelse);
        }
        Stmt::With(with) => visit(&mut with.body),
        Stmt::Try(attempt) => {
            visit(&mut attempt.body);
            for handler in &mut attempt.handlers {
                let ExceptHandler::ExceptHandler(handler) = handler;
                visit(&mut handler.body);
            }
            visit(&mut attempt.orelse);
            visit(&mut attempt.finalbody);
        }
        Stmt::Match(matched) => {
            for case in &mut matched.cases {
                visit(&mut case.body);
            }
        }
        _ => {}
    }
}

fn junk_target(stmt: &Stmt, used: &BTreeSet<String>) -> bool {
    let Stmt::Assign(StmtAssign { targets, value, .. }) = stmt else {
        return false;
    };
    let [Expr::Name(target)] = targets.as_slice() else {
        return false;
    };
    if used.contains(target.id.as_str()) || target.id.starts_with("__") {
        return false;
    }
    match value.as_ref() {
        Expr::Name(_) => true,
        Expr::NumberLiteral(number) => {
            matches!(&number.value, Number::Int(int) if int.as_u64().is_some_and(|v: u64| v < JUNK_INT_LIMIT))
        }
        Expr::StringLiteral(text) => {
            let value: &str = text.value.to_str();
            value.len() == JUNK_LETTERS && value.bytes().all(|b: u8| b.is_ascii_alphabetic())
        }
        _ => false,
    }
}

fn drop_junk_assignments(body: &mut Vec<Stmt>, used: &BTreeSet<String>) -> usize {
    let before: usize = body.len();
    body.retain(|stmt: &Stmt| !junk_target(stmt, used));
    let mut removed: usize = before - body.len();
    if body.is_empty() && before > 0 {
        body.push(Stmt::Pass(StmtPass {
            range: TextRange::default(),
            node_index: AtomicNodeIndex::default(),
        }));
    }
    for stmt in body.iter_mut() {
        for_each_block(stmt, &mut |block: &mut Vec<Stmt>| {
            removed += drop_junk_assignments(block, used);
        });
    }
    removed
}

#[derive(Default)]
struct NameUses {
    used: BTreeSet<String>,
}

impl<'a> Visitor<'a> for NameUses {
    fn visit_stmt(&mut self, stmt: &'a Stmt) {
        match stmt {
            Stmt::Global(global) => {
                self.used
                    .extend(global.names.iter().map(|name| name.as_str().to_owned()));
            }
            Stmt::Nonlocal(nonlocal) => {
                self.used
                    .extend(nonlocal.names.iter().map(|name| name.as_str().to_owned()));
            }
            _ => {}
        }
        walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &'a Expr) {
        match expr {
            Expr::Name(ExprName { id, ctx, .. }) if *ctx != ExprContext::Store => {
                self.used.insert(id.as_str().to_owned());
            }
            Expr::StringLiteral(text) => {
                self.used.insert(text.value.to_str().to_owned());
            }
            Expr::Attribute(access) => {
                self.used.insert(access.attr.as_str().to_owned());
            }
            _ => {}
        }
        walk_expr(self, expr);
    }
}

fn used_names(module: &ModModule) -> BTreeSet<String> {
    let mut uses: NameUses = NameUses::default();
    for stmt in &module.body {
        uses.visit_stmt(stmt);
    }
    uses.used
}

fn uses_introspection(module: &ModModule) -> bool {
    let used: BTreeSet<String> = used_names(module);
    INTROSPECTION.iter().any(|name: &&str| used.contains(*name))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn clean(source: &str) -> (String, JunkStats) {
        clean_inner_source(source).expect("cleans")
    }

    #[test]
    fn folds_hex_constants_inside_match_patterns() {
        let source: &str = "def f(s):\n    match s:\n        case [bytes.fromhex('636972636c65').decode('utf-8'), r]:\n            return r\n        case _:\n            return 0\n";
        let (out, stats): (String, JunkStats) = clean(source);
        assert_eq!(stats.hex_constants_folded, 1);
        assert!(out.contains("case ['circle', r]:"), "{out}");
    }

    #[test]
    fn removes_dead_junk_chains_and_unreachable_tails() {
        let source: &str = "I = 573\nLL = I\nW = 'NzIiwNsZARHpuHPjvojGzySGhcSgZCaQkemDuVahBSQiQLCvjRrLWZURqDqpNMEXUEjqICWvDiGmHuB'\ndef f(n):\n    j = 541\n    if n <= 1:\n        return 1\n        z = j\n    return n * f(n - 1)\n    q = 'x'\nprint(f(4))\n";
        let (out, stats): (String, JunkStats) = clean(source);
        assert_eq!(
            out,
            "def f(n):\n    if n <= 1:\n        return 1\n    return n * f(n - 1)\nprint(f(4))\n"
        );
        assert_eq!(stats.unreachable_removed, 2);
        assert_eq!(stats.junk_assignments_removed, 4);
    }

    #[test]
    fn keeps_assignments_that_are_read_or_shaped_like_program_data() {
        let source: &str = "limit = 5\ncount = 4000\nlabel = 'short'\nprint(limit)\n";
        let (out, _): (String, JunkStats) = clean(source);
        assert_eq!(
            out,
            "limit = 5\ncount = 4000\nlabel = 'short'\nprint(limit)\n"
        );
    }

    #[test]
    fn namespace_introspection_keeps_every_assignment() {
        let source: &str = "a = 1\nprint(globals()['a'])\n";
        let (out, stats): (String, JunkStats) = clean(source);
        assert!(stats.introspection_blocked);
        assert_eq!(out, source);
    }

    #[test]
    fn class_attributes_read_through_self_stay() {
        let source: &str = "class C:\n    limit = 5\n    def f(self):\n        return self.limit\nprint(C().f())\n";
        let (out, _): (String, JunkStats) = clean(source);
        assert!(out.contains("limit = 5"), "{out}");
    }

    #[test]
    fn a_block_of_only_junk_keeps_a_pass() {
        let source: &str = "def f():\n    a = 3\n    b = a\nf()\n";
        let (out, _): (String, JunkStats) = clean(source);
        assert_eq!(out, "def f():\n    pass\nf()\n");
    }
}
