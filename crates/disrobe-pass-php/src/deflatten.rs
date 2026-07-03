use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::token::{Lexer, TokKind, Token};

const MAX_LINEARIZE_STEPS: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeflattenReport {
    pub source: Vec<u8>,
    pub labels_dropped: usize,
    pub gotos_followed: usize,
    pub strings_decoded: usize,
}

pub fn deflatten(source: &[u8]) -> Result<DeflattenReport> {
    let tokens: Vec<Token<'_>> = Lexer::new(source).tokens().map_err(|_| Error::Deflatten {
        reason: "lexing failed".to_owned(),
    })?;
    let significant: Vec<Token<'_>> = tokens
        .into_iter()
        .filter(|t| {
            !matches!(
                t.kind,
                TokKind::Whitespace
                    | TokKind::LineComment
                    | TokKind::BlockComment
                    | TokKind::DocComment
            )
        })
        .collect();

    let mut state: EmitState = EmitState {
        labels_dropped: 0,
        gotos_followed: 0,
        strings_decoded: 0,
        steps: 0,
    };
    let mut out: Vec<u8> = Vec::with_capacity(source.len());

    let mut idx: usize = 0;
    while idx < significant.len() {
        let tok: &Token<'_> = &significant[idx];
        match tok.kind {
            TokKind::OpenTag | TokKind::ShortOpenTag => {
                out.extend_from_slice(b"<?php\n");
                idx += 1;
                let region_end: usize = significant.len();
                let body: &[Token<'_>] = &significant[idx..region_end];
                state.linearize_region(body, &mut out, 0)?;
                idx = region_end;
            }
            TokKind::OpenTagWithEcho => {
                out.extend_from_slice(b"<?php echo ");
                idx += 1;
            }
            TokKind::CloseTag => {
                out.extend_from_slice(b"?>\n");
                idx += 1;
            }
            TokKind::InlineHtml => {
                out.extend_from_slice(tok.lexeme);
                idx += 1;
            }
            _ => {
                let body: &[Token<'_>] = &significant[idx..];
                state.linearize_region(body, &mut out, 0)?;
                break;
            }
        }
    }

    Ok(DeflattenReport {
        source: out,
        labels_dropped: state.labels_dropped,
        gotos_followed: state.gotos_followed,
        strings_decoded: state.strings_decoded,
    })
}

#[derive(Debug, Default)]
struct EmitState {
    labels_dropped: usize,
    gotos_followed: usize,
    strings_decoded: usize,
    steps: usize,
}

#[derive(Debug, Clone)]
enum Item {
    Label(Vec<u8>),
    Goto(Vec<u8>),
    Stmt { lo: usize, hi: usize },
}

impl EmitState {
    fn linearize_region(
        &mut self,
        toks: &[Token<'_>],
        out: &mut Vec<u8>,
        depth: usize,
    ) -> Result<()> {
        let items: Vec<Item> = parse_items(toks);
        let has_chain: bool = items.iter().any(|i| matches!(i, Item::Label(_)));
        if !has_chain {
            for item in &items {
                if let Item::Stmt { lo, hi } = item {
                    self.emit_stmt(toks, *lo, *hi, out, depth);
                }
            }
            return Ok(());
        }

        let entry: Vec<u8> =
            leading_goto(&items).unwrap_or_else(|| first_label(&items).unwrap_or_default());
        let chain: Chain = build_chain(&items);
        let order: Vec<Vec<u8>> = self.reachable_order(&entry, &chain)?;
        let emitted: BTreeSet<Vec<u8>> = order.iter().cloned().collect();

        let mut surviving_goto_targets: BTreeSet<Vec<u8>> =
            nested_goto_targets(toks, &chain.label_set);
        for (pos, label) in order.iter().enumerate() {
            if let Some(block) = chain.blocks.get(label)
                && let Some(target) = &block.goto
            {
                let falls_through: bool = order.get(pos + 1) == Some(target);
                let dropped: bool = falls_through && emitted.contains(target);
                if !dropped {
                    surviving_goto_targets.insert(target.clone());
                }
            }
        }

        for (pos, label) in order.iter().enumerate() {
            let Some(block): Option<&LabelBlock> = chain.blocks.get(label) else {
                continue;
            };
            if surviving_goto_targets.contains(label) {
                emit_label(out, label, depth);
            } else {
                self.labels_dropped += 1;
            }
            for &(lo, hi) in &block.stmts {
                self.emit_stmt(toks, lo, hi, out, depth);
            }
            if let Some(target) = &block.goto {
                let falls_through: bool = order.get(pos + 1) == Some(target);
                let dropped: bool = falls_through && emitted.contains(target);
                if dropped {
                    self.gotos_followed += 1;
                } else {
                    emit_goto(out, target, depth);
                }
            }
        }
        Ok(())
    }

    fn reachable_order(&mut self, entry: &[u8], chain: &Chain) -> Result<Vec<Vec<u8>>> {
        let mut order: Vec<Vec<u8>> = Vec::new();
        let mut seen: BTreeSet<Vec<u8>> = BTreeSet::new();
        let mut current: Option<Vec<u8>> = Some(entry.to_vec());

        while let Some(label) = current.take() {
            self.steps += 1;
            if self.steps > MAX_LINEARIZE_STEPS {
                return Err(Error::Deflatten {
                    reason: "goto chain did not terminate".to_owned(),
                });
            }
            if !seen.insert(label.clone()) {
                break;
            }
            order.push(label.clone());
            if let Some(block) = chain.blocks.get(&label)
                && let Some(target) = &block.goto
                && !seen.contains(target)
            {
                current = Some(target.clone());
            }
        }
        for label in &chain.order {
            if seen.insert(label.clone()) {
                order.push(label.clone());
            }
        }
        Ok(order)
    }

    fn emit_stmt(
        &mut self,
        toks: &[Token<'_>],
        lo: usize,
        hi: usize,
        out: &mut Vec<u8>,
        depth: usize,
    ) {
        if lo >= hi {
            return;
        }
        let indent: Vec<u8> = vec![b' '; depth * 4];
        if self.try_emit_braced(toks, lo, hi, out, depth) {
            return;
        }
        out.extend_from_slice(&indent);
        for ti in lo..hi {
            let tok: &Token<'_> = &toks[ti];
            let rendered: Vec<u8> = self.render_token(tok);
            out.extend_from_slice(&rendered);
            if needs_trailing_space(toks, ti, hi) {
                out.push(b' ');
            }
        }
        out.push(b'\n');
    }

    fn try_emit_braced(
        &mut self,
        toks: &[Token<'_>],
        lo: usize,
        hi: usize,
        out: &mut Vec<u8>,
        depth: usize,
    ) -> bool {
        let Some(open_rel): Option<usize> = (lo..hi).find(|&i| is_punct(&toks[i], b"{")) else {
            return false;
        };
        if !is_punct(&toks[hi - 1], b"}") {
            return false;
        }
        let is_decl: bool = (lo..open_rel).any(|i| {
            matches!(toks[i].kind, TokKind::Ident)
                && matches!(
                    toks[i].lexeme.to_ascii_lowercase().as_slice(),
                    b"function" | b"class" | b"trait" | b"interface" | b"namespace"
                )
        });
        if !is_decl {
            return false;
        }

        let indent: Vec<u8> = vec![b' '; depth * 4];
        out.extend_from_slice(&indent);
        for ti in lo..open_rel {
            let rendered: Vec<u8> = self.render_token(&toks[ti]);
            out.extend_from_slice(&rendered);
            if needs_trailing_space(toks, ti, open_rel) {
                out.push(b' ');
            }
        }
        out.extend_from_slice(b" {\n");
        let inner: &[Token<'_>] = &toks[open_rel + 1..hi - 1];
        let _ = self.linearize_region(inner, out, depth + 1);
        out.extend_from_slice(&indent);
        out.extend_from_slice(b"}\n");
        true
    }

    fn render_token(&mut self, tok: &Token<'_>) -> Vec<u8> {
        if matches!(tok.kind, TokKind::StringDouble)
            && let Some(decoded) = decode_double_quoted(tok.lexeme)
        {
            self.strings_decoded += 1;
            return decoded;
        }
        tok.lexeme.to_vec()
    }
}

fn parse_items(toks: &[Token<'_>]) -> Vec<Item> {
    let mut items: Vec<Item> = Vec::new();
    let mut i: usize = 0;
    let n: usize = toks.len();
    while i < n {
        if is_label_at(toks, i) {
            items.push(Item::Label(toks[i].lexeme.to_vec()));
            i += 2;
            continue;
        }
        if let Some((target, advance)) = goto_at(toks, i) {
            items.push(Item::Goto(target));
            i += advance;
            continue;
        }
        let (lo, hi): (usize, usize) = statement_span(toks, i);
        if hi > lo {
            items.push(Item::Stmt { lo, hi });
            i = hi;
        } else {
            i += 1;
        }
    }
    items
}

fn is_label_at(toks: &[Token<'_>], i: usize) -> bool {
    matches!(toks.get(i).map(|t| t.kind), Some(TokKind::Ident))
        && !is_reserved_label_word(toks[i].lexeme)
        && toks.get(i + 1).is_some_and(|t| is_punct(t, b":"))
}

fn goto_at(toks: &[Token<'_>], i: usize) -> Option<(Vec<u8>, usize)> {
    let kw: &Token<'_> = toks.get(i)?;
    if !(matches!(kw.kind, TokKind::Ident) && kw.lexeme.eq_ignore_ascii_case(b"goto")) {
        return None;
    }
    let target: &Token<'_> = toks.get(i + 1)?;
    if !matches!(target.kind, TokKind::Ident) {
        return None;
    }
    let semi: &Token<'_> = toks.get(i + 2)?;
    if !is_punct(semi, b";") {
        return None;
    }
    Some((target.lexeme.to_vec(), 3))
}

fn statement_span(toks: &[Token<'_>], start: usize) -> (usize, usize) {
    let mut depth: i32 = 0;
    let mut i: usize = start;
    let n: usize = toks.len();
    while i < n {
        let tok: &Token<'_> = &toks[i];
        if is_punct(tok, b"{") || is_punct(tok, b"(") || is_punct(tok, b"[") {
            depth += 1;
        } else if is_punct(tok, b"}") || is_punct(tok, b")") || is_punct(tok, b"]") {
            depth -= 1;
            if depth == 0 && is_punct(tok, b"}") {
                return (start, i + 1);
            }
            if depth < 0 {
                return (start, i);
            }
        } else if depth == 0 && is_punct(tok, b";") {
            return (start, i + 1);
        }
        i += 1;
    }
    (start, n)
}

#[derive(Debug, Default)]
struct LabelBlock {
    stmts: Vec<(usize, usize)>,
    goto: Option<Vec<u8>>,
}

#[derive(Debug, Default)]
struct Chain {
    blocks: BTreeMap<Vec<u8>, LabelBlock>,
    order: Vec<Vec<u8>>,
    label_set: BTreeSet<Vec<u8>>,
}

fn leading_goto(items: &[Item]) -> Option<Vec<u8>> {
    match items.first() {
        Some(Item::Goto(target)) => Some(target.clone()),
        _ => None,
    }
}

fn first_label(items: &[Item]) -> Option<Vec<u8>> {
    items.iter().find_map(|i| match i {
        Item::Label(name) => Some(name.clone()),
        _ => None,
    })
}

fn build_chain(items: &[Item]) -> Chain {
    let mut chain: Chain = Chain::default();
    let mut active: Vec<Vec<u8>> = Vec::new();
    for item in items {
        match item {
            Item::Label(name) => {
                if !chain.blocks.contains_key(name) {
                    chain.blocks.insert(name.clone(), LabelBlock::default());
                    chain.order.push(name.clone());
                }
                chain.label_set.insert(name.clone());
                active.push(name.clone());
            }
            Item::Stmt { lo, hi } => {
                for label in &active {
                    if let Some(block) = chain.blocks.get_mut(label) {
                        block.stmts.push((*lo, *hi));
                    }
                }
            }
            Item::Goto(target) => {
                for label in &active {
                    if let Some(block) = chain.blocks.get_mut(label)
                        && block.goto.is_none()
                    {
                        block.goto = Some(target.clone());
                    }
                }
                active.clear();
            }
        }
    }
    chain
}

fn nested_goto_targets(toks: &[Token<'_>], label_set: &BTreeSet<Vec<u8>>) -> BTreeSet<Vec<u8>> {
    let mut targets: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut depth: i32 = 0;
    let mut i: usize = 0;
    while i < toks.len() {
        let tok: &Token<'_> = &toks[i];
        if is_punct(tok, b"{") || is_punct(tok, b"(") || is_punct(tok, b"[") {
            depth += 1;
        } else if is_punct(tok, b"}") || is_punct(tok, b")") || is_punct(tok, b"]") {
            depth -= 1;
        } else if depth > 0
            && let Some((target, _)) = goto_at(toks, i)
            && label_set.contains(&target)
        {
            targets.insert(target);
        }
        i += 1;
    }
    targets
}

fn emit_label(out: &mut Vec<u8>, label: &[u8], depth: usize) {
    out.extend_from_slice(&vec![b' '; depth * 4]);
    out.extend_from_slice(label);
    out.extend_from_slice(b":\n");
}

fn emit_goto(out: &mut Vec<u8>, target: &[u8], depth: usize) {
    out.extend_from_slice(&vec![b' '; depth * 4]);
    out.extend_from_slice(b"goto ");
    out.extend_from_slice(target);
    out.extend_from_slice(b";\n");
}

fn is_reserved_label_word(lexeme: &[u8]) -> bool {
    matches!(
        lexeme.to_ascii_lowercase().as_slice(),
        b"default" | b"case" | b"else" | b"goto"
    )
}

fn is_punct(tok: &Token<'_>, lit: &[u8]) -> bool {
    matches!(tok.kind, TokKind::Punct) && tok.lexeme == lit
}

fn needs_trailing_space(toks: &[Token<'_>], i: usize, hi: usize) -> bool {
    if i + 1 >= hi {
        return false;
    }
    let cur: &Token<'_> = &toks[i];
    let next: &Token<'_> = &toks[i + 1];
    if cur.end == next.start {
        return false;
    }
    if matches!(cur.kind, TokKind::Ident) && matches!(next.kind, TokKind::Ident) {
        return true;
    }
    if matches!(cur.kind, TokKind::Ident)
        && matches!(
            next.kind,
            TokKind::Variable | TokKind::StringDouble | TokKind::StringSingle
        )
    {
        return true;
    }
    let glue_after: bool = matches!(
        cur.kind,
        TokKind::ObjectOp | TokKind::NullsafeOp | TokKind::ScopeRes | TokKind::NamespaceSep
    ) || is_punct(cur, b"(")
        || is_punct(cur, b"[")
        || is_punct(cur, b"{");
    let glue_before: bool = matches!(
        next.kind,
        TokKind::ObjectOp | TokKind::NullsafeOp | TokKind::ScopeRes | TokKind::NamespaceSep
    ) || is_punct(next, b";")
        || is_punct(next, b",")
        || is_punct(next, b")")
        || is_punct(next, b"]")
        || is_punct(next, b"(")
        || is_punct(next, b"{");
    !glue_after && !glue_before
}

fn decode_double_quoted(lexeme: &[u8]) -> Option<Vec<u8>> {
    if lexeme.len() < 2 || lexeme[0] != b'"' || lexeme[lexeme.len() - 1] != b'"' {
        return None;
    }
    let inner: &[u8] = &lexeme[1..lexeme.len() - 1];
    let mut decoded: Vec<u8> = Vec::with_capacity(inner.len());
    let mut changed: bool = false;
    let mut i: usize = 0;
    while i < inner.len() {
        if inner[i] == b'\\' && i + 1 < inner.len() {
            let c: u8 = inner[i + 1];
            if c == b'x' {
                let mut j: usize = i + 2;
                let mut val: u32 = 0;
                let mut count: usize = 0;
                while j < inner.len() && count < 2 && inner[j].is_ascii_hexdigit() {
                    val = val * 16 + u32::from(hex_val(inner[j]));
                    j += 1;
                    count += 1;
                }
                if count > 0 {
                    push_byte_escaped(&mut decoded, val as u8);
                    changed = true;
                    i = j;
                    continue;
                }
            } else if (b'0'..=b'7').contains(&c) {
                let mut j: usize = i + 1;
                let mut val: u32 = 0;
                let mut count: usize = 0;
                while j < inner.len() && count < 3 && (b'0'..=b'7').contains(&inner[j]) {
                    val = val * 8 + u32::from(inner[j] - b'0');
                    j += 1;
                    count += 1;
                }
                push_byte_escaped(&mut decoded, val as u8);
                changed = true;
                i = j;
                continue;
            }
            decoded.push(inner[i]);
            decoded.push(inner[i + 1]);
            i += 2;
            continue;
        }
        decoded.push(inner[i]);
        i += 1;
    }
    if !changed {
        return None;
    }
    let mut out: Vec<u8> = Vec::with_capacity(decoded.len() + 2);
    out.push(b'"');
    out.extend_from_slice(&decoded);
    out.push(b'"');
    Some(out)
}

fn push_byte_escaped(out: &mut Vec<u8>, b: u8) {
    match b {
        b'"' => out.extend_from_slice(b"\\\""),
        b'\\' => out.extend_from_slice(b"\\\\"),
        b'$' => out.extend_from_slice(b"\\$"),
        0x20..=0x7e => out.push(b),
        b'\n' => out.extend_from_slice(b"\\n"),
        b'\r' => out.extend_from_slice(b"\\r"),
        b'\t' => out.extend_from_slice(b"\\t"),
        _ => {
            out.extend_from_slice(b"\\x");
            out.push(hex_digit(b >> 4));
            out.push(hex_digit(b & 0x0f));
        }
    }
}

const fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

const fn hex_digit(v: u8) -> u8 {
    if v < 10 { b'0' + v } else { b'a' + (v - 10) }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn rendered(src: &[u8]) -> String {
        let report: DeflattenReport = deflatten(src).expect("deflatten");
        String::from_utf8(report.source).expect("utf8")
    }

    #[test]
    fn linear_goto_chain_recovers_statement_order_and_drops_gotos() {
        let src: &[u8] = b"<?php goto a3; a1: $x = 2; goto a2; a3: $x = 1; goto a1; a2: echo $x;";
        let out: String = rendered(src);
        assert!(!out.to_ascii_lowercase().contains("goto "), "out:\n{out}");
        let p1: usize = out.find("$x = 1").expect("first assign");
        let p2: usize = out.find("$x = 2").expect("second assign");
        let p3: usize = out.find("echo $x").expect("echo");
        assert!(p1 < p2 && p2 < p3, "execution order not recovered:\n{out}");
    }

    #[test]
    fn double_quoted_octal_and_hex_escapes_decode() {
        let src: &[u8] = b"<?php echo \"\\167\\x6f\\162\\x6c\\144\";";
        let out: String = rendered(src);
        assert!(out.contains("\"world\""), "escape decode failed:\n{out}");
    }

    #[test]
    fn branch_goto_inside_if_is_preserved_with_its_label() {
        let src: &[u8] =
            b"<?php goto s; s: if ($n > 1) { goto big; } echo \"small\"; goto end; big: echo \"big\"; goto end; end: echo \"!\";";
        let out: String = rendered(src);
        assert!(out.contains("goto big"), "branch goto dropped:\n{out}");
        assert!(out.contains("big:"), "branch target label dropped:\n{out}");
    }

    #[test]
    fn plain_php_without_goto_chain_is_unchanged_in_behavior() {
        let src: &[u8] = b"<?php $a = 1; echo $a;";
        let out: String = rendered(src);
        assert!(out.contains("$a = 1"), "out:\n{out}");
        assert!(out.contains("echo $a"), "out:\n{out}");
    }
}
