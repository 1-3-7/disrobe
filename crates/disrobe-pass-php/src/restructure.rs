use serde::{Deserialize, Serialize};

use crate::deflatten::deflatten;
use crate::error::{Error, Result};
use crate::token::{Lexer, TokKind, Token};

const MAX_RESTRUCTURE_DEPTH: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestructureReport {
    pub source: Vec<u8>,
    pub whiles_recovered: usize,
    pub ifs_recovered: usize,
    pub gotos_remaining: usize,
}

pub fn restructure(source: &[u8]) -> Result<RestructureReport> {
    let deflattened: Vec<u8> = deflatten(source)?.source;
    let tokens: Vec<Token<'_>> =
        Lexer::new(&deflattened)
            .tokens()
            .map_err(|_| Error::Deflatten {
                reason: "restructure lexing failed".to_owned(),
            })?;
    let significant: Vec<Token<'_>> = tokens
        .iter()
        .filter(|t| {
            !matches!(
                t.kind,
                TokKind::Whitespace
                    | TokKind::LineComment
                    | TokKind::BlockComment
                    | TokKind::DocComment
            )
        })
        .cloned()
        .collect();

    let mut state: State = State {
        src: &deflattened,
        whiles: 0,
        ifs: 0,
    };
    let mut out: Vec<u8> = Vec::with_capacity(deflattened.len());

    let mut idx: usize = 0;
    while idx < significant.len() {
        let tok: &Token<'_> = &significant[idx];
        match tok.kind {
            TokKind::OpenTag | TokKind::ShortOpenTag => {
                out.extend_from_slice(b"<?php\n");
                idx += 1;
                let body: &[Token<'_>] = &significant[idx..];
                state.structure_region(body, &mut out, 0);
                break;
            }
            TokKind::InlineHtml => {
                out.extend_from_slice(tok.lexeme);
                idx += 1;
            }
            TokKind::CloseTag => {
                out.extend_from_slice(b"?>\n");
                idx += 1;
            }
            _ => {
                let body: &[Token<'_>] = &significant[idx..];
                state.structure_region(body, &mut out, 0);
                break;
            }
        }
    }

    let gotos_remaining: usize = count_gotos(&out);
    Ok(RestructureReport {
        source: out,
        whiles_recovered: state.whiles,
        ifs_recovered: state.ifs,
        gotos_remaining,
    })
}

#[derive(Debug)]
struct State<'s> {
    src: &'s [u8],
    whiles: usize,
    ifs: usize,
}

#[derive(Debug, Clone)]
enum Unit {
    Label(Vec<u8>),
    Goto(Vec<u8>),
    Stmt {
        lo: usize,
        hi: usize,
    },
    Braced {
        header_lo: usize,
        open: usize,
        close: usize,
    },
}

impl State<'_> {
    fn structure_region(&mut self, toks: &[Token<'_>], out: &mut Vec<u8>, depth: usize) {
        let units: Vec<Unit> = drop_unreachable_gotos(parse_units(toks), toks, self.src);
        if depth >= MAX_RESTRUCTURE_DEPTH {
            for unit in &units {
                self.emit_unit(unit, toks, out, depth);
            }
            return;
        }
        let mut i: usize = 0;
        while i < units.len() {
            if let Some(consumed) = self.try_while(&units, i, toks, out, depth) {
                i = consumed;
                continue;
            }
            if let Some(consumed) = self.try_if_else(&units, i, toks, out, depth) {
                i = consumed;
                continue;
            }
            self.emit_unit(&units[i], toks, out, depth);
            i += 1;
        }
    }

    fn try_while(
        &mut self,
        units: &[Unit],
        start: usize,
        toks: &[Token<'_>],
        out: &mut Vec<u8>,
        depth: usize,
    ) -> Option<usize> {
        let Unit::Label(header): &Unit = &units[start] else {
            return None;
        };
        let guard_idx: usize = start + 1;
        let guard: &Unit = units.get(guard_idx)?;
        let (cond_negated, exit_label): (String, Vec<u8>) = guard_goto_if(guard, toks)?;
        let mut body_units: Vec<Unit> = Vec::new();
        let mut j: usize = guard_idx + 1;
        let mut found_backedge: bool = false;
        while j < units.len() {
            match &units[j] {
                Unit::Goto(target) if target == header => {
                    found_backedge = true;
                    j += 1;
                    break;
                }
                Unit::Label(l) if l == header => return None,
                other => body_units.push(other.clone()),
            }
            j += 1;
        }
        if !found_backedge {
            return None;
        }
        if !label_exists_ahead(units, j, &exit_label) {
            return None;
        }
        if references_label(&body_units, header) || references_label(&body_units, &exit_label) {
            return None;
        }
        let pad: String = indent_string(depth);
        let _ = self.src;
        out.extend_from_slice(pad.as_bytes());
        out.extend_from_slice(b"while (");
        out.extend_from_slice(cond_negated.as_bytes());
        out.extend_from_slice(b") {\n");
        let mut body_out: Vec<u8> = Vec::new();
        self.emit_units(&body_units, toks, &mut body_out, depth + 1);
        out.extend_from_slice(&body_out);
        out.extend_from_slice(pad.as_bytes());
        out.extend_from_slice(b"}\n");
        self.whiles += 1;
        Some(j)
    }

    fn try_if_else(
        &mut self,
        units: &[Unit],
        start: usize,
        toks: &[Token<'_>],
        out: &mut Vec<u8>,
        depth: usize,
    ) -> Option<usize> {
        let (cond_pos, raw_then): (String, Vec<u8>) = guard_goto_if(&units[start], toks)?;
        let then_label: Vec<u8> = resolve_forward(units, &raw_then);
        let then_pos: usize = label_index(units, &then_label)?;
        let mut else_units: Vec<Unit> = Vec::new();
        let mut j: usize = start + 1;
        let mut else_terminated: bool = false;
        while j < then_pos {
            match &units[j] {
                Unit::Label(_) => {}
                Unit::Goto(_) => {
                    else_terminated = true;
                    break;
                }
                Unit::Stmt { lo, hi } => {
                    else_units.push(units[j].clone());
                    if stmt_is_terminator(slice_src(self.src, toks, *lo, *hi)) {
                        else_terminated = true;
                        break;
                    }
                }
                Unit::Braced { .. } => else_units.push(units[j].clone()),
            }
            j += 1;
        }
        if !else_terminated {
            return None;
        }
        let then_start: usize = then_pos + 1;
        let mut then_units: Vec<Unit> = Vec::new();
        let mut k: usize = then_start;
        while k < units.len() {
            match &units[k] {
                Unit::Label(_) => {}
                Unit::Stmt { lo, hi } => {
                    then_units.push(units[k].clone());
                    if stmt_is_terminator(slice_src(self.src, toks, *lo, *hi)) {
                        k += 1;
                        break;
                    }
                }
                Unit::Goto(_) | Unit::Braced { .. } => then_units.push(units[k].clone()),
            }
            k += 1;
        }
        if then_units.is_empty()
            || references_label(&else_units, &then_label)
            || references_label(&then_units, &then_label)
        {
            return None;
        }
        let pad: String = indent_string(depth);
        out.extend_from_slice(pad.as_bytes());
        out.extend_from_slice(b"if (");
        out.extend_from_slice(cond_pos.as_bytes());
        out.extend_from_slice(b") {\n");
        let mut then_out: Vec<u8> = Vec::new();
        self.emit_units(&then_units, toks, &mut then_out, depth + 1);
        out.extend_from_slice(&then_out);
        out.extend_from_slice(pad.as_bytes());
        out.extend_from_slice(b"} else {\n");
        let mut else_out: Vec<u8> = Vec::new();
        self.emit_units(&else_units, toks, &mut else_out, depth + 1);
        out.extend_from_slice(&else_out);
        out.extend_from_slice(pad.as_bytes());
        out.extend_from_slice(b"}\n");
        self.ifs += 1;
        Some(k)
    }

    fn emit_units(&mut self, units: &[Unit], toks: &[Token<'_>], out: &mut Vec<u8>, depth: usize) {
        if depth >= MAX_RESTRUCTURE_DEPTH {
            for unit in units {
                self.emit_unit(unit, toks, out, depth);
            }
            return;
        }
        let mut i: usize = 0;
        while i < units.len() {
            if let Some(consumed) = self.try_while(units, i, toks, out, depth) {
                i = consumed;
                continue;
            }
            if let Some(consumed) = self.try_if_else(units, i, toks, out, depth) {
                i = consumed;
                continue;
            }
            self.emit_unit(&units[i], toks, out, depth);
            i += 1;
        }
    }

    fn emit_unit(&mut self, unit: &Unit, toks: &[Token<'_>], out: &mut Vec<u8>, depth: usize) {
        let pad: String = indent_string(depth);
        match unit {
            Unit::Label(name) => {
                out.extend_from_slice(pad.as_bytes());
                out.extend_from_slice(name);
                out.extend_from_slice(b":\n");
            }
            Unit::Goto(target) => {
                out.extend_from_slice(pad.as_bytes());
                out.extend_from_slice(b"goto ");
                out.extend_from_slice(target);
                out.extend_from_slice(b";\n");
            }
            Unit::Stmt { lo, hi } => {
                out.extend_from_slice(pad.as_bytes());
                out.extend_from_slice(slice_src(self.src, toks, *lo, *hi).trim_ascii());
                out.push(b'\n');
            }
            Unit::Braced {
                header_lo,
                open,
                close,
            } => {
                out.extend_from_slice(pad.as_bytes());
                let header: &[u8] = slice_src(self.src, toks, *header_lo, *open).trim_ascii();
                out.extend_from_slice(header);
                out.extend_from_slice(b" {\n");
                if depth + 1 >= MAX_RESTRUCTURE_DEPTH {
                    let raw: &[u8] = slice_src(self.src, toks, *open + 1, *close).trim_ascii();
                    if !raw.is_empty() {
                        out.extend_from_slice(raw);
                        out.push(b'\n');
                    }
                } else {
                    let inner: &[Token<'_>] = &toks[*open + 1..*close];
                    self.structure_region(inner, out, depth + 1);
                }
                out.extend_from_slice(pad.as_bytes());
                out.extend_from_slice(b"}\n");
            }
        }
    }
}

fn guard_goto_if(unit: &Unit, toks: &[Token<'_>]) -> Option<(String, Vec<u8>)> {
    let Unit::Stmt { lo, hi } = unit else {
        return None;
    };
    parse_if_goto(&toks[*lo..*hi])
}

fn parse_if_goto(stmt: &[Token<'_>]) -> Option<(String, Vec<u8>)> {
    if !(matches!(stmt.first().map(|t| t.kind), Some(TokKind::Ident))
        && stmt[0].lexeme.eq_ignore_ascii_case(b"if"))
    {
        return None;
    }
    let open: usize = stmt.iter().position(|t| punct(t, b"("))?;
    let close: usize = matching_paren(stmt, open)?;
    let body: &[Token<'_>] = &stmt[close + 1..];
    let brace_open: usize = body.iter().position(|t| punct(t, b"{"))?;
    let inner: &[Token<'_>] = &body[brace_open + 1..];
    let goto_target: Vec<u8> = lone_goto(inner)?;
    let cond_negated: bool = is_negated_cond(&stmt[open..=close]);
    let cond_text: String = render_condition(&stmt[open + 1..close], cond_negated);
    let _ = cond_negated;
    Some((cond_text, goto_target))
}

fn is_negated_cond(paren: &[Token<'_>]) -> bool {
    paren.len() >= 2 && punct(&paren[0], b"(") && punct(&paren[1], b"!")
}

fn render_condition(inner: &[Token<'_>], negated: bool) -> String {
    if negated && inner.len() >= 2 && punct(&inner[0], b"!") && punct(&inner[1], b"(") {
        let close: usize = matching_paren(inner, 1).unwrap_or(inner.len() - 1);
        return inner
            .get(2..close)
            .map_or_else(|| tokens_to_string(inner), tokens_to_string);
    }
    tokens_to_string(inner)
}

fn lone_goto(inner: &[Token<'_>]) -> Option<Vec<u8>> {
    let sig: Vec<&Token<'_>> = inner.iter().collect();
    if sig.len() >= 3
        && matches!(sig[0].kind, TokKind::Ident)
        && sig[0].lexeme.eq_ignore_ascii_case(b"goto")
        && matches!(sig[1].kind, TokKind::Ident)
        && punct(sig[2], b";")
    {
        return Some(sig[1].lexeme.to_vec());
    }
    None
}

fn matching_paren(toks: &[Token<'_>], open: usize) -> Option<usize> {
    let mut depth: i32 = 0;
    for (i, t) in toks.iter().enumerate().skip(open) {
        if punct(t, b"(") {
            depth += 1;
        } else if punct(t, b")") {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
    }
    None
}

fn drop_unreachable_gotos(units: Vec<Unit>, toks: &[Token<'_>], src: &[u8]) -> Vec<Unit> {
    let mut out: Vec<Unit> = Vec::with_capacity(units.len());
    let mut prev_terminates: bool = false;
    for unit in units {
        match &unit {
            Unit::Goto(_) if prev_terminates => {}
            Unit::Label(_) | Unit::Braced { .. } => {
                prev_terminates = false;
                out.push(unit);
            }
            Unit::Goto(_) => {
                out.push(unit);
                prev_terminates = true;
            }
            Unit::Stmt { lo, hi } => {
                prev_terminates = stmt_is_terminator(slice_src(src, toks, *lo, *hi));
                out.push(unit);
            }
        }
    }
    out
}

fn stmt_is_terminator(stmt_src: &[u8]) -> bool {
    let t: &[u8] = stmt_src.trim_ascii_start();
    starts_with_word(t, b"return")
        || starts_with_word(t, b"throw")
        || starts_with_word(t, b"exit")
        || starts_with_word(t, b"die")
}

fn starts_with_word(haystack: &[u8], word: &[u8]) -> bool {
    haystack.len() >= word.len()
        && haystack[..word.len()].eq_ignore_ascii_case(word)
        && haystack
            .get(word.len())
            .is_none_or(|b| !b.is_ascii_alphanumeric() && *b != b'_')
}

fn label_exists_ahead(units: &[Unit], from: usize, label: &[u8]) -> bool {
    units[from..]
        .iter()
        .any(|u| matches!(u, Unit::Label(l) if l == label))
}

fn label_index(units: &[Unit], label: &[u8]) -> Option<usize> {
    units
        .iter()
        .position(|u| matches!(u, Unit::Label(l) if l == label))
}

fn resolve_forward(units: &[Unit], label: &[u8]) -> Vec<u8> {
    let mut current: Vec<u8> = label.to_vec();
    let mut steps: usize = 0;
    loop {
        steps += 1;
        if steps > units.len() + 1 {
            return current;
        }
        let Some(pos): Option<usize> = label_index(units, &current) else {
            return current;
        };
        match units.get(pos + 1) {
            Some(Unit::Goto(next)) => current.clone_from(next),
            _ => return current,
        }
    }
}

fn references_label(units: &[Unit], label: &[u8]) -> bool {
    units.iter().any(|u| match u {
        Unit::Goto(t) => t == label,
        Unit::Label(l) => l == label,
        _ => false,
    })
}

fn parse_units(toks: &[Token<'_>]) -> Vec<Unit> {
    let mut units: Vec<Unit> = Vec::new();
    let mut i: usize = 0;
    let n: usize = toks.len();
    while i < n {
        if is_label_at(toks, i) {
            units.push(Unit::Label(toks[i].lexeme.to_vec()));
            i += 2;
            continue;
        }
        if let Some((target, adv)) = goto_unit(toks, i) {
            units.push(Unit::Goto(target));
            i += adv;
            continue;
        }
        let (lo, hi): (usize, usize) = stmt_span(toks, i);
        if hi <= lo {
            i += 1;
            continue;
        }
        if let Some(open) = brace_decl(toks, lo, hi) {
            units.push(Unit::Braced {
                header_lo: lo,
                open,
                close: hi - 1,
            });
        } else {
            units.push(Unit::Stmt { lo, hi });
        }
        i = hi;
    }
    units
}

fn brace_decl(toks: &[Token<'_>], lo: usize, hi: usize) -> Option<usize> {
    if !punct(&toks[hi - 1], b"}") {
        return None;
    }
    let open: usize = (lo..hi).find(|&i| punct(&toks[i], b"{"))?;
    let is_decl: bool = (lo..open).any(|i| {
        matches!(toks[i].kind, TokKind::Ident)
            && matches!(
                toks[i].lexeme.to_ascii_lowercase().as_slice(),
                b"function" | b"class" | b"trait" | b"interface" | b"namespace"
            )
    });
    if is_decl { Some(open) } else { None }
}

fn is_label_at(toks: &[Token<'_>], i: usize) -> bool {
    matches!(toks.get(i).map(|t| t.kind), Some(TokKind::Ident))
        && !toks[i].lexeme.eq_ignore_ascii_case(b"goto")
        && !toks[i].lexeme.eq_ignore_ascii_case(b"default")
        && !toks[i].lexeme.eq_ignore_ascii_case(b"case")
        && toks.get(i + 1).is_some_and(|t| punct(t, b":"))
}

fn goto_unit(toks: &[Token<'_>], i: usize) -> Option<(Vec<u8>, usize)> {
    let kw: &Token<'_> = toks.get(i)?;
    if !(matches!(kw.kind, TokKind::Ident) && kw.lexeme.eq_ignore_ascii_case(b"goto")) {
        return None;
    }
    let target: &Token<'_> = toks.get(i + 1)?;
    if !matches!(target.kind, TokKind::Ident) {
        return None;
    }
    if !toks.get(i + 2).is_some_and(|t| punct(t, b";")) {
        return None;
    }
    Some((target.lexeme.to_vec(), 3))
}

fn stmt_span(toks: &[Token<'_>], start: usize) -> (usize, usize) {
    let mut depth: i32 = 0;
    let n: usize = toks.len();
    let mut i: usize = start;
    while i < n {
        let t: &Token<'_> = &toks[i];
        if punct(t, b"{") || punct(t, b"(") || punct(t, b"[") {
            depth += 1;
        } else if punct(t, b"}") || punct(t, b")") || punct(t, b"]") {
            depth -= 1;
            if depth == 0 && punct(t, b"}") {
                return (start, i + 1);
            }
            if depth < 0 {
                return (start, i);
            }
        } else if depth == 0 && punct(t, b";") {
            return (start, i + 1);
        }
        i += 1;
    }
    (start, n)
}

fn slice_src<'s>(src: &'s [u8], toks: &[Token<'_>], lo: usize, hi: usize) -> &'s [u8] {
    if lo >= hi || hi > toks.len() {
        return &[];
    }
    let start: usize = toks[lo].start;
    let end: usize = toks[hi - 1].end;
    src.get(start..end).unwrap_or(&[])
}

fn tokens_to_string(toks: &[Token<'_>]) -> String {
    let mut out: Vec<u8> = Vec::new();
    for (i, t) in toks.iter().enumerate() {
        out.extend_from_slice(t.lexeme);
        if i + 1 < toks.len() && t.end != toks[i + 1].start {
            out.push(b' ');
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn punct(tok: &Token<'_>, lit: &[u8]) -> bool {
    matches!(tok.kind, TokKind::Punct) && tok.lexeme == lit
}

fn count_gotos(src: &[u8]) -> usize {
    let lower: Vec<u8> = src.to_ascii_lowercase();
    let needle: &[u8] = b"goto ";
    lower.windows(needle.len()).filter(|w| *w == needle).count()
}

fn indent_string(depth: usize) -> String {
    "    ".repeat(depth)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn rendered(src: &[u8]) -> (String, RestructureReport) {
        let report: RestructureReport = restructure(src).expect("restructure");
        (
            String::from_utf8(report.source.clone()).expect("utf8"),
            report,
        )
    }

    #[test]
    fn negated_guard_back_edge_recovers_a_while_loop() {
        let src: &[u8] =
            b"<?php $i = 0; goto h; h: if (!($i < 3)) { goto done; } $i++; goto h; done: echo $i;";
        let (out, report): (String, RestructureReport) = rendered(src);
        assert!(report.whiles_recovered >= 1, "no while recovered:\n{out}");
        assert!(out.contains("while ($i < 3)"), "while header wrong:\n{out}");
        assert!(
            !out.contains("goto h"),
            "back-edge goto not removed:\n{out}"
        );
    }

    #[test]
    fn guard_goto_then_with_terminating_arms_recovers_if_else() {
        let src: &[u8] = b"<?php function f($n) { goto g; g: if ($n > 1) { goto big; } return \"small\"; big: return \"big\"; }";
        let (out, report): (String, RestructureReport) = rendered(src);
        assert!(report.ifs_recovered >= 1, "no if/else recovered:\n{out}");
        assert!(out.contains("if ($n > 1)"), "if header wrong:\n{out}");
        assert!(out.contains("} else {"), "else arm missing:\n{out}");
        assert!(out.contains("return \"big\""), "then-body missing:\n{out}");
        assert!(
            out.contains("return \"small\""),
            "else-body missing:\n{out}"
        );
    }

    #[test]
    fn plain_php_without_control_flow_idioms_is_left_intact() {
        let src: &[u8] = b"<?php $a = 1; echo $a;";
        let (out, report): (String, RestructureReport) = rendered(src);
        assert_eq!(report.whiles_recovered, 0);
        assert_eq!(report.ifs_recovered, 0);
        assert!(out.contains("$a = 1"), "out:\n{out}");
        assert!(out.contains("echo $a"), "out:\n{out}");
    }

    #[test]
    fn deeply_nested_brace_declarations_do_not_overflow() {
        const NESTING: usize = MAX_RESTRUCTURE_DEPTH * 20;
        let mut src: Vec<u8> = Vec::with_capacity(NESTING * 14 + 16);
        src.extend_from_slice(b"<?php ");
        for _ in 0..NESTING {
            src.extend_from_slice(b"function f(){ ");
        }
        src.extend_from_slice(b"$x=1;");
        src.extend(std::iter::repeat_n(b'}', NESTING));
        let report: RestructureReport = restructure(&src).expect("restructure");
        assert!(
            report.source.windows(4).any(|w| w == b"$x=1"),
            "innermost statement lost"
        );
    }
}
