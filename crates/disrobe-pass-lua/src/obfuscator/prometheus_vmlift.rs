use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq)]
enum Num {
    Int(i64),
    Float(f64),
}

impl Num {
    #[inline]
    fn as_f64(self) -> f64 {
        match self {
            Self::Int(i) => i as f64,
            Self::Float(f) => f,
        }
    }

    #[inline]
    fn render(self) -> String {
        match self {
            Self::Int(i) => i.to_string(),
            Self::Float(f) => render_lua_float(f),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tok {
    Num,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Caret,
    LParen,
    RParen,
}

#[derive(Debug, Clone, Copy)]
struct Span {
    tok: Tok,
    start: usize,
    end: usize,
    value: Num,
}

struct Lexer<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    #[inline]
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn next_token(&mut self) -> Option<Span> {
        while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
        let start: usize = self.pos;
        let byte: u8 = *self.bytes.get(self.pos)?;
        let single = |this: &mut Self, tok: Tok| -> Option<Span> {
            this.pos += 1;
            Some(Span {
                tok,
                start,
                end: this.pos,
                value: Num::Int(0),
            })
        };
        match byte {
            b'+' => single(self, Tok::Plus),
            b'-' => single(self, Tok::Minus),
            b'*' => single(self, Tok::Star),
            b'/' => single(self, Tok::Slash),
            b'%' => single(self, Tok::Percent),
            b'^' => single(self, Tok::Caret),
            b'(' => single(self, Tok::LParen),
            b')' => single(self, Tok::RParen),
            b'0'..=b'9' => self.lex_number(start),
            b'.' if self.bytes.get(self.pos + 1).is_some_and(u8::is_ascii_digit) => {
                self.lex_number(start)
            }
            _ => None,
        }
    }

    fn lex_number(&mut self, start: usize) -> Option<Span> {
        if self.bytes.get(self.pos) == Some(&b'0')
            && matches!(self.bytes.get(self.pos + 1), Some(b'x' | b'X'))
        {
            self.pos += 2;
            let hex_start: usize = self.pos;
            while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_hexdigit() {
                self.pos += 1;
            }
            if self.pos == hex_start {
                return None;
            }
            let text: &str = std::str::from_utf8(&self.bytes[hex_start..self.pos]).ok()?;
            let value: i64 = i64::from_str_radix(text, 16).ok()?;
            return Some(Span {
                tok: Tok::Num,
                start,
                end: self.pos,
                value: Num::Int(value),
            });
        }
        let mut is_float: bool = false;
        while self.pos < self.bytes.len() {
            match self.bytes[self.pos] {
                b'0'..=b'9' => self.pos += 1,
                b'.' => {
                    is_float = true;
                    self.pos += 1;
                }
                b'e' | b'E' => {
                    is_float = true;
                    self.pos += 1;
                    if matches!(self.bytes.get(self.pos), Some(b'+' | b'-')) {
                        self.pos += 1;
                    }
                }
                _ => break,
            }
        }
        let text: &str = std::str::from_utf8(&self.bytes[start..self.pos]).ok()?;
        let value: Num = if is_float {
            Num::Float(text.parse::<f64>().ok()?)
        } else {
            match text.parse::<i64>() {
                Ok(i) => Num::Int(i),
                Err(_) => Num::Float(text.parse::<f64>().ok()?),
            }
        };
        Some(Span {
            tok: Tok::Num,
            start,
            end: self.pos,
            value,
        })
    }
}

struct Parser {
    spans: Vec<Span>,
    idx: usize,
}

impl Parser {
    #[inline]
    fn new(spans: Vec<Span>) -> Self {
        Self { spans, idx: 0 }
    }

    #[inline]
    fn peek(&self) -> Option<Tok> {
        self.spans.get(self.idx).map(|s: &Span| s.tok)
    }

    fn eval(&mut self) -> Option<Num> {
        let value: Num = self.add_sub()?;
        if self.idx == self.spans.len() {
            Some(value)
        } else {
            None
        }
    }

    fn add_sub(&mut self) -> Option<Num> {
        let mut acc: Num = self.mul_div_mod()?;
        while let Some(op) = self.peek() {
            match op {
                Tok::Plus => {
                    self.idx += 1;
                    let rhs: Num = self.mul_div_mod()?;
                    acc = num_add(acc, rhs);
                }
                Tok::Minus => {
                    self.idx += 1;
                    let rhs: Num = self.mul_div_mod()?;
                    acc = num_sub(acc, rhs);
                }
                _ => break,
            }
        }
        Some(acc)
    }

    fn mul_div_mod(&mut self) -> Option<Num> {
        let mut acc: Num = self.unary()?;
        while let Some(op) = self.peek() {
            match op {
                Tok::Star => {
                    self.idx += 1;
                    let rhs: Num = self.unary()?;
                    acc = num_mul(acc, rhs);
                }
                Tok::Slash => {
                    self.idx += 1;
                    let rhs: Num = self.unary()?;
                    acc = Num::Float(acc.as_f64() / rhs.as_f64());
                }
                Tok::Percent => {
                    self.idx += 1;
                    let rhs: Num = self.unary()?;
                    acc = num_mod(acc, rhs)?;
                }
                _ => break,
            }
        }
        Some(acc)
    }

    fn unary(&mut self) -> Option<Num> {
        match self.peek()? {
            Tok::Minus => {
                self.idx += 1;
                let operand: Num = self.unary()?;
                Some(num_neg(operand))
            }
            _ => self.power(),
        }
    }

    fn power(&mut self) -> Option<Num> {
        let base: Num = self.atom()?;
        if self.peek() == Some(Tok::Caret) {
            self.idx += 1;
            let exp: Num = self.unary()?;
            return Some(Num::Float(base.as_f64().powf(exp.as_f64())));
        }
        Some(base)
    }

    fn atom(&mut self) -> Option<Num> {
        match self.peek()? {
            Tok::Num => {
                let value: Num = self.spans[self.idx].value;
                self.idx += 1;
                Some(value)
            }
            Tok::LParen => {
                self.idx += 1;
                let inner: Num = self.add_sub()?;
                if self.peek() != Some(Tok::RParen) {
                    return None;
                }
                self.idx += 1;
                Some(inner)
            }
            _ => None,
        }
    }
}

#[inline]
fn num_add(lhs: Num, rhs: Num) -> Num {
    match (lhs, rhs) {
        (Num::Int(li), Num::Int(ri)) => match li.checked_add(ri) {
            Some(value) => Num::Int(value),
            None => Num::Float(li as f64 + ri as f64),
        },
        _ => Num::Float(lhs.as_f64() + rhs.as_f64()),
    }
}

#[inline]
fn num_sub(lhs: Num, rhs: Num) -> Num {
    match (lhs, rhs) {
        (Num::Int(li), Num::Int(ri)) => match li.checked_sub(ri) {
            Some(value) => Num::Int(value),
            None => Num::Float(li as f64 - ri as f64),
        },
        _ => Num::Float(lhs.as_f64() - rhs.as_f64()),
    }
}

#[inline]
fn num_mul(lhs: Num, rhs: Num) -> Num {
    match (lhs, rhs) {
        (Num::Int(li), Num::Int(ri)) => match li.checked_mul(ri) {
            Some(value) => Num::Int(value),
            None => Num::Float(li as f64 * ri as f64),
        },
        _ => Num::Float(lhs.as_f64() * rhs.as_f64()),
    }
}

#[inline]
fn num_neg(operand: Num) -> Num {
    match operand {
        Num::Int(value) => value
            .checked_neg()
            .map_or_else(|| Num::Float(-(value as f64)), Num::Int),
        Num::Float(value) => Num::Float(-value),
    }
}

fn num_mod(lhs: Num, rhs: Num) -> Option<Num> {
    match (lhs, rhs) {
        (Num::Int(li), Num::Int(ri)) => {
            if ri == 0 {
                return None;
            }
            let rem: i64 = li.wrapping_rem(ri);
            let adjusted: i64 = if rem != 0 && (rem < 0) != (ri < 0) {
                rem.wrapping_add(ri)
            } else {
                rem
            };
            Some(Num::Int(adjusted))
        }
        _ => {
            let lf: f64 = lhs.as_f64();
            let rf: f64 = rhs.as_f64();
            if rf == 0.0 {
                return None;
            }
            Some(Num::Float((-(lf / rf).floor()).mul_add(rf, lf)))
        }
    }
}

#[must_use]
fn render_lua_float(value: f64) -> String {
    if value.fract() == 0.0 && value.abs() < 1e15 {
        format!("{}.0", value as i64)
    } else {
        format!("{value}")
    }
}

const MAX_FOLD_TOKENS: usize = 4096;

const NUMERIC_EXPR_BUDGET: usize = 1 << 24;

/// Fold Prometheus `NumbersToExpressions` arithmetic wrappers back to plain numeric literals.
#[derive(Debug, Clone)]
struct FoldedSpan {
    start: usize,
    end: usize,
    value: String,
}

fn collect_folds(src: &str) -> Vec<FoldedSpan> {
    let bytes: &[u8] = src.as_bytes();
    let mut folds: Vec<FoldedSpan> = Vec::new();
    let mut pos: usize = 0;
    while pos < bytes.len() {
        let byte: u8 = bytes[pos];
        if is_string_open(byte) {
            pos = skip_string_literal(bytes, pos);
            continue;
        }
        if byte == b'-' && bytes.get(pos + 1) == Some(&b'-') {
            pos = skip_comment(bytes, pos);
            continue;
        }
        if let Some(span_start) = expr_anchor(bytes, pos, folds.last())
            && let Some((folded, next)) = try_fold_span(bytes, span_start)
        {
            folds.push(FoldedSpan {
                start: span_start,
                end: next,
                value: folded,
            });
            pos = next;
            continue;
        }
        pos += 1;
    }
    folds
}

#[inline]
fn expr_anchor(bytes: &[u8], pos: usize, prev_fold: Option<&FoldedSpan>) -> Option<usize> {
    let byte: u8 = *bytes.get(pos)?;
    let prev: u8 = prev_significant(bytes, pos);
    let at_boundary: bool = !is_ident_byte(prev) && !matches!(prev, b'.' | b']' | b')');
    if byte == b'(' {
        if at_boundary && opens_arithmetic_group(bytes, pos) {
            return Some(pos);
        }
        return None;
    }
    if byte.is_ascii_digit() {
        if matches!(prev, b'*' | b'/' | b'%' | b'^') {
            return None;
        }
        if matches!(prev, b'+' | b'-') && !sign_is_unary(bytes, pos) {
            return None;
        }
        if !at_boundary && !matches!(prev, b'+' | b'-') {
            return None;
        }
        return Some(unary_prefixed_start(bytes, pos, prev_fold));
    }
    None
}

#[inline]
fn sign_is_unary(bytes: &[u8], digit_pos: usize) -> bool {
    let mut i: usize = digit_pos;
    while i > 0 && bytes[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    if i == 0 || !matches!(bytes[i - 1], b'+' | b'-') {
        return false;
    }
    let before: u8 = prev_significant(bytes, i - 1);
    !is_ident_byte(before) && !matches!(before, b'.' | b']' | b')')
}

fn opens_arithmetic_group(bytes: &[u8], lparen: usize) -> bool {
    let mut depth: i32 = 0;
    let mut i: usize = lparen;
    let mut saw_operator: bool = false;
    let mut saw_number: bool = false;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return saw_operator && saw_number;
                }
            }
            b'0'..=b'9' | b'.' => saw_number = true,
            b'+' | b'-' | b'*' | b'/' | b'%' | b'^' => saw_operator = true,
            b' ' | b'\t' | b'\n' | b'\r' => {}
            _ => return false,
        }
        i += 1;
    }
    false
}

#[must_use]
pub fn fold_numeric_expressions(src: &str) -> String {
    if src.len() > NUMERIC_EXPR_BUDGET {
        return src.to_owned();
    }
    let folds: Vec<FoldedSpan> = collect_folds(src);
    let mut out: String = String::with_capacity(src.len());
    let mut cursor: usize = 0;
    for fold in &folds {
        out.push_str(&src[cursor..fold.start]);
        push_guarded(&mut out, &fold.value);
        cursor = fold.end;
    }
    out.push_str(&src[cursor..]);
    out
}

#[inline]
fn unary_prefixed_start(bytes: &[u8], digit_pos: usize, prev_fold: Option<&FoldedSpan>) -> usize {
    let floor: usize = prev_fold.map_or(0, |f: &FoldedSpan| f.end);
    let mut start: usize = digit_pos;
    loop {
        let mut i: usize = start;
        while i > floor && bytes[i - 1].is_ascii_whitespace() {
            i -= 1;
        }
        if i <= floor {
            return start;
        }
        let sign: u8 = bytes[i - 1];
        if sign != b'-' && sign != b'+' {
            return start;
        }
        let before_sign: u8 = prev_significant(bytes, i - 1);
        if is_ident_byte(before_sign) || matches!(before_sign, b'.' | b']' | b')') {
            return start;
        }
        start = i - 1;
    }
}

fn push_guarded(out: &mut String, folded: &str) {
    if let (Some(prev), Some(first)) = (out.chars().last(), folded.chars().next()) {
        let merge_comment: bool = prev == '-' && first == '-';
        let merge_concat: bool = prev == '.' && first == '.';
        let digit_glue: bool = (prev.is_ascii_alphanumeric() || prev == '_')
            && (first.is_ascii_digit() || first == '-');
        if merge_comment || merge_concat || digit_glue {
            out.push(' ');
        }
    }
    out.push_str(folded);
}

#[inline]
fn prev_significant(bytes: &[u8], pos: usize) -> u8 {
    let mut i: usize = pos;
    while i > 0 {
        i -= 1;
        let b: u8 = bytes[i];
        if !b.is_ascii_whitespace() {
            return b;
        }
    }
    0
}

#[inline]
fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn try_fold_span(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    let mut lex: Lexer<'_> = Lexer::new(&bytes[start..]);
    let mut spans: Vec<Span> = Vec::new();
    let mut depth: i32 = 0;
    let mut saw_operator: bool = false;
    let mut last_balanced_end: Option<usize> = None;
    while let Some(mut tok) = lex.next_token() {
        match tok.tok {
            Tok::LParen => depth += 1,
            Tok::RParen => {
                if depth == 0 {
                    break;
                }
                depth -= 1;
            }
            Tok::Plus | Tok::Minus | Tok::Star | Tok::Slash | Tok::Percent | Tok::Caret => {
                saw_operator = true;
            }
            Tok::Num => {}
        }
        tok.start += start;
        tok.end += start;
        spans.push(tok);
        if spans.len() > MAX_FOLD_TOKENS {
            return None;
        }
        if depth == 0
            && matches!(tok.tok, Tok::Num | Tok::RParen)
            && (saw_operator || matches!(tok.tok, Tok::RParen))
        {
            last_balanced_end = Some(spans.len());
        }
    }
    let keep: usize = last_balanced_end?;
    spans.truncate(keep);
    if spans.is_empty() {
        return None;
    }
    let trailing_unbalanced: bool = spans
        .iter()
        .filter(|s: &&Span| s.tok == Tok::LParen)
        .count()
        != spans
            .iter()
            .filter(|s: &&Span| s.tok == Tok::RParen)
            .count();
    if trailing_unbalanced {
        return None;
    }
    let num_terms: usize = spans.iter().filter(|s: &&Span| s.tok == Tok::Num).count();
    let has_paren: bool = spans.iter().any(|s: &Span| s.tok == Tok::LParen);
    if num_terms < 2 && !has_paren {
        return None;
    }
    let span_end: usize = spans.last()?.end;
    if follows_ident_after(bytes, span_end) {
        return None;
    }
    let mut parser: Parser = Parser::new(spans);
    let value: Num = parser.eval()?;
    Some((value.render(), span_end))
}

#[inline]
fn follows_ident_after(bytes: &[u8], pos: usize) -> bool {
    let mut i: usize = pos;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    bytes.get(i).copied().is_some_and(is_ident_byte)
}

#[inline]
fn is_string_open(byte: u8) -> bool {
    byte == b'"' || byte == b'\''
}

fn skip_string_literal(bytes: &[u8], start: usize) -> usize {
    let quote: u8 = bytes[start];
    let mut pos: usize = start + 1;
    while pos < bytes.len() {
        match bytes[pos] {
            b'\\' => pos += 2,
            b if b == quote => return pos + 1,
            _ => pos += 1,
        }
    }
    bytes.len()
}

fn skip_comment(bytes: &[u8], start: usize) -> usize {
    let mut pos: usize = start + 2;
    if bytes.get(pos) == Some(&b'[') {
        let mut eq: usize = 0;
        let mut probe: usize = pos + 1;
        while bytes.get(probe) == Some(&b'=') {
            eq += 1;
            probe += 1;
        }
        if bytes.get(probe) == Some(&b'[') {
            let close: Vec<u8> = {
                let mut v: Vec<u8> = vec![b']'];
                v.extend(std::iter::repeat_n(b'=', eq));
                v.push(b']');
                v
            };
            let mut scan: usize = probe + 1;
            while scan + close.len() <= bytes.len() {
                if &bytes[scan..scan + close.len()] == close.as_slice() {
                    return scan + close.len();
                }
                scan += 1;
            }
            return bytes.len();
        }
    }
    while pos < bytes.len() && bytes[pos] != b'\n' {
        pos += 1;
    }
    pos
}

#[must_use]
pub fn folded_span_pairs(src: &str) -> Vec<(String, String)> {
    collect_folds(src)
        .into_iter()
        .map(|f: FoldedSpan| (src[f.start..f.end].to_owned(), f.value))
        .collect()
}

#[must_use]
pub fn folded_span_offsets(src: &str) -> Vec<(usize, usize, String)> {
    collect_folds(src)
        .into_iter()
        .map(|f: FoldedSpan| (f.start, f.end, f.value))
        .collect()
}

#[must_use]
pub fn count_numeric_expressions(src: &str) -> usize {
    collect_folds(src).len()
}

#[must_use]
pub fn count_arithmetic_operators(src: &str) -> usize {
    let bytes: &[u8] = src.as_bytes();
    let mut count: usize = 0;
    let mut pos: usize = 0;
    while pos < bytes.len() {
        let byte: u8 = bytes[pos];
        if is_string_open(byte) {
            pos = skip_string_literal(bytes, pos);
            continue;
        }
        if byte == b'-' && bytes.get(pos + 1) == Some(&b'-') {
            pos = skip_comment(bytes, pos);
            continue;
        }
        if matches!(byte, b'+' | b'*' | b'/' | b'%' | b'^')
            || (byte == b'-' && bytes.get(pos + 1) != Some(&b'-'))
        {
            let prev: u8 = prev_significant(bytes, pos);
            let next: u8 = next_significant(bytes, pos + 1);
            let between_numbers: bool =
                (prev.is_ascii_digit() || prev == b')') && (next.is_ascii_digit() || next == b'(');
            if between_numbers {
                count += 1;
            }
        }
        pos += 1;
    }
    count
}

#[inline]
fn next_significant(bytes: &[u8], pos: usize) -> u8 {
    let mut i: usize = pos;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    bytes.get(i).copied().unwrap_or(0)
}

#[must_use]
pub fn fold_one_expression(expr: &str) -> Option<String> {
    let bytes: &[u8] = expr.as_bytes();
    let mut start: usize = 0;
    while start < bytes.len() && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    let lex_input: &str = &expr[start..];
    let mut lex: Lexer<'_> = Lexer::new(lex_input.as_bytes());
    let mut spans: Vec<Span> = Vec::new();
    while let Some(tok) = lex.next_token() {
        spans.push(tok);
        if spans.len() > MAX_FOLD_TOKENS {
            return None;
        }
    }
    if lex.pos != lex_input.len() {
        return None;
    }
    let mut parser: Parser = Parser::new(spans);
    parser.eval().map(Num::render)
}

pub fn fold_checked(src: &str) -> Result<String> {
    if src.len() > NUMERIC_EXPR_BUDGET {
        return Err(Error::DecompileUnsupported(
            "prometheus source exceeds numeric-fold budget",
        ));
    }
    Ok(fold_numeric_expressions(src))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchReport {
    pub state_variable: char,
    pub comparison_count: usize,
    pub leaf_states: Vec<i64>,
    pub successor_edges: usize,
    pub conditional_blocks: usize,
}

impl DispatchReport {
    #[inline]
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.leaf_states.len()
    }
}

const DISPATCH_SCAN_LIMIT: usize = 1 << 24;

#[must_use]
pub fn analyze_dispatch(folded_src: &str) -> Option<DispatchReport> {
    if folded_src.len() > DISPATCH_SCAN_LIMIT {
        return None;
    }
    let bytes: &[u8] = folded_src.as_bytes();
    let (state_variable, loop_body_start): (char, usize) = find_state_loop(folded_src)?;
    let sv: u8 = state_variable as u8;

    let comparison_count: usize = count_state_comparisons(bytes, loop_body_start, sv);
    if comparison_count == 0 {
        return None;
    }

    let mut leaf_states: Vec<i64> = Vec::new();
    let mut successor_edges: usize = 0;
    let mut conditional_blocks: usize = 0;
    let mut pos: usize = loop_body_start;
    while pos < bytes.len() {
        if let Some((assign_end, targets, conditional)) =
            match_state_assignment(folded_src, bytes, pos, sv)
        {
            successor_edges += targets.len();
            if conditional {
                conditional_blocks += 1;
            }
            for t in targets {
                if !leaf_states.contains(&t) {
                    leaf_states.push(t);
                }
            }
            pos = assign_end;
            continue;
        }
        pos += 1;
    }
    if successor_edges == 0 {
        return None;
    }
    leaf_states.sort_unstable();
    Some(DispatchReport {
        state_variable,
        comparison_count,
        leaf_states,
        successor_edges,
        conditional_blocks,
    })
}

fn find_state_loop(src: &str) -> Option<(char, usize)> {
    let bytes: &[u8] = src.as_bytes();
    let needle: &[u8] = b"while ";
    let mut pos: usize = 0;
    while let Some(rel) = find_subslice(&bytes[pos..], needle) {
        let kw: usize = pos + rel;
        let mut i: usize = kw + needle.len();
        while i < bytes.len() && bytes[i] == b' ' {
            i += 1;
        }
        let var_pos: usize = i;
        if bytes
            .get(var_pos)
            .is_some_and(|b: &u8| b.is_ascii_alphabetic())
        {
            let var: u8 = bytes[var_pos];
            let mut j: usize = var_pos + 1;
            while j < bytes.len() && bytes[j] == b' ' {
                j += 1;
            }
            if bytes.get(j) == Some(&b'd') && bytes.get(j + 1) == Some(&b'o') {
                let after_ident: bool = !is_ident_byte(*bytes.get(var_pos + 1).unwrap_or(&b' '));
                if after_ident {
                    return Some((var as char, j + 2));
                }
            }
        }
        pos = kw + needle.len();
    }
    None
}

fn count_state_comparisons(bytes: &[u8], from: usize, sv: u8) -> usize {
    let mut count: usize = 0;
    let mut i: usize = from;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b == sv && is_lone_state_var(bytes, i) {
            let next: u8 = next_significant(bytes, i + 1);
            if matches!(next, b'<' | b'>') {
                count += 1;
            }
        } else if matches!(b, b'<' | b'>') && bytes.get(i + 1) != Some(&b'=') {
            let after_pos: usize = next_significant_pos(bytes, i + 1);
            if bytes.get(after_pos) == Some(&sv) && is_lone_state_var(bytes, after_pos) {
                count += 1;
            }
        }
        i += 1;
    }
    count
}

#[inline]
fn is_lone_state_var(bytes: &[u8], pos: usize) -> bool {
    if bytes.get(pos + 1).copied().is_some_and(is_ident_byte) {
        return false;
    }
    !preceded_by_identifier(bytes, pos)
}

fn preceded_by_identifier(bytes: &[u8], pos: usize) -> bool {
    let mut i: usize = pos;
    while i > 0 && bytes[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    if i == 0 {
        return false;
    }
    let prev: u8 = bytes[i - 1];
    if matches!(prev, b'.' | b']' | b')') {
        return true;
    }
    if !is_ident_byte(prev) {
        return false;
    }
    let word_end: usize = i;
    let mut word_start: usize = i;
    while word_start > 0 && is_ident_byte(bytes[word_start - 1]) {
        word_start -= 1;
    }
    let word: &[u8] = &bytes[word_start..word_end];
    !is_lua_keyword(word)
}

#[inline]
fn is_lua_keyword(word: &[u8]) -> bool {
    matches!(
        word,
        b"and"
            | b"or"
            | b"not"
            | b"if"
            | b"elseif"
            | b"then"
            | b"else"
            | b"end"
            | b"do"
            | b"while"
            | b"for"
            | b"in"
            | b"return"
            | b"local"
            | b"function"
            | b"repeat"
            | b"until"
            | b"break"
            | b"nil"
            | b"true"
            | b"false"
    )
}

#[inline]
fn next_significant_pos(bytes: &[u8], pos: usize) -> usize {
    let mut i: usize = pos;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

fn match_state_assignment(
    src: &str,
    bytes: &[u8],
    pos: usize,
    sv: u8,
) -> Option<(usize, Vec<i64>, bool)> {
    if bytes[pos] != sv {
        return None;
    }
    if pos > 0 && is_ident_byte(bytes[pos - 1]) {
        return None;
    }
    if bytes.get(pos + 1).copied().is_some_and(is_ident_byte) {
        return None;
    }
    let target_index: usize = lhs_target_index(bytes, pos)?;
    let mut i: usize = pos + 1;
    skip_target_list(bytes, &mut i)?;
    while i < bytes.len() && bytes[i] == b' ' {
        i += 1;
    }
    if bytes.get(i) != Some(&b'=') || bytes.get(i + 1) == Some(&b'=') {
        return None;
    }
    if i > 0 && matches!(bytes[i - 1], b'<' | b'>' | b'~' | b'=') {
        return None;
    }
    i += 1;
    while i < bytes.len() && bytes[i] == b' ' {
        i += 1;
    }
    let value_start: usize = i;
    let mut depth: i32 = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\n' | b';' if depth == 0 => break,
            b'(' | b'{' | b'[' => depth += 1,
            b')' | b'}' | b']' => depth -= 1,
            _ if depth == 0 && rhs_statement_break(bytes, i) => break,
            _ => {}
        }
        i += 1;
    }
    let rhs: &str = src.get(value_start..i)?;
    let segment: Option<&str> = nth_top_level_segment(rhs, target_index);
    let (targets, conditional): (Vec<i64>, bool) = segment.map_or_else(
        || (Vec::new(), false),
        |seg: &str| {
            let cond: bool = seg.contains(" and ") || seg.contains(" or ");
            (constant_literals(seg), cond)
        },
    );
    if targets.is_empty() {
        return None;
    }
    Some((i, targets, conditional))
}

const RHS_BREAK_KEYWORDS: &[&[u8]] = &[
    b"else", b"elseif", b"end", b"while", b"then", b"do", b"return", b"local", b"for", b"if",
];

fn rhs_statement_break(bytes: &[u8], pos: usize) -> bool {
    if pos == 0 || !bytes[pos - 1].is_ascii_whitespace() {
        return false;
    }
    for kw in RHS_BREAK_KEYWORDS {
        let end: usize = pos + kw.len();
        if bytes.get(pos..end) == Some(*kw) && !bytes.get(end).copied().is_some_and(is_ident_byte) {
            return true;
        }
    }
    false
}

fn lhs_target_index(bytes: &[u8], state_pos: usize) -> Option<usize> {
    let mut idx: usize = 0;
    let mut i: usize = state_pos;
    while i > 0 {
        let b: u8 = bytes[i - 1];
        if b == b',' {
            idx += 1;
            i -= 1;
            continue;
        }
        if is_ident_byte(b) {
            i -= 1;
            continue;
        }
        break;
    }
    Some(idx)
}

fn skip_target_list(bytes: &[u8], i: &mut usize) -> Option<()> {
    while *i < bytes.len() {
        match bytes[*i] {
            b'=' => return Some(()),
            b'\n' | b';' => return None,
            b' ' => {
                let word_start: usize = next_significant_pos(bytes, *i);
                if word_at_is_keyword(bytes, word_start) {
                    return None;
                }
                *i += 1;
            }
            b if is_ident_byte(b) || matches!(b, b',' | b'[' | b']' | b'.') => *i += 1,
            _ => return None,
        }
    }
    None
}

fn word_at_is_keyword(bytes: &[u8], start: usize) -> bool {
    let mut end: usize = start;
    while end < bytes.len() && is_ident_byte(bytes[end]) {
        end += 1;
    }
    is_lua_keyword(&bytes[start..end])
}

fn nth_top_level_segment(rhs: &str, n: usize) -> Option<&str> {
    let bytes: &[u8] = rhs.as_bytes();
    let mut depth: i32 = 0;
    let mut seg_start: usize = 0;
    let mut idx: usize = 0;
    let mut i: usize = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'(' | b'{' | b'[' => depth += 1,
            b')' | b'}' | b']' => depth -= 1,
            b',' if depth == 0 => {
                if idx == n {
                    return Some(rhs[seg_start..i].trim());
                }
                idx += 1;
                seg_start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if idx == n {
        Some(rhs[seg_start..].trim())
    } else {
        None
    }
}

fn constant_literals(seg: &str) -> Vec<i64> {
    let bytes: &[u8] = seg.as_bytes();
    let mut targets: Vec<i64> = Vec::new();
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        let prev_glued: bool = i > 0 && is_ident_byte(bytes[i - 1]);
        if b.is_ascii_digit() && !prev_glued {
            let start: usize = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            if !bytes.get(i).copied().is_some_and(is_ident_byte)
                && bytes.get(i) != Some(&b'.')
                && let Ok(v) = seg[start..i].parse::<i64>()
            {
                targets.push(v);
            }
            continue;
        }
        i += 1;
    }
    targets
}

#[inline]
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w: &[u8]| w == needle)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn folds_lua_integer_arithmetic_with_floor_modulo() {
        assert_eq!(
            fold_one_expression("971750703%4206713").as_deref(),
            Some("0")
        );
        assert_eq!(fold_one_expression("-812166+812212").as_deref(), Some("46"));
        assert_eq!(
            fold_one_expression("(-833342-(-833343))").as_deref(),
            Some("1")
        );
        assert_eq!(fold_one_expression("339591+-339590").as_deref(), Some("1"));
    }

    #[test]
    fn lua_negative_floor_modulo_matches_reference() {
        assert_eq!(fold_one_expression("-5%3").as_deref(), Some("1"));
        assert_eq!(fold_one_expression("5%-3").as_deref(), Some("-1"));
        assert_eq!(fold_one_expression("-5%-3").as_deref(), Some("-2"));
    }

    #[test]
    fn division_and_power_yield_lua_floats() {
        assert_eq!(fold_one_expression("10/4").as_deref(), Some("2.5"));
        assert_eq!(fold_one_expression("2^10").as_deref(), Some("1024.0"));
        assert_eq!(fold_one_expression("100/4").as_deref(), Some("25.0"));
    }

    #[test]
    fn precedence_is_respected() {
        assert_eq!(fold_one_expression("2+3*4").as_deref(), Some("14"));
        assert_eq!(fold_one_expression("10%4-1").as_deref(), Some("1"));
        assert_eq!(fold_one_expression("(2+3)*4").as_deref(), Some("20"));
    }

    #[test]
    fn fold_leaves_identifiers_and_strings_untouched() {
        let src: &str = "local x = y[1+2] print(\"3+4 stays\") z = a%b";
        let out: String = fold_numeric_expressions(src);
        assert!(out.contains("y[3]"), "index folded: {out}");
        assert!(
            out.contains("\"3+4 stays\""),
            "string literal preserved: {out}"
        );
        assert!(out.contains("z = a%b"), "variable modulo preserved: {out}");
    }

    #[test]
    fn fold_never_creates_a_comment_via_negative_literal() {
        let out: String = fold_numeric_expressions("local t={5-(-833343)}");
        assert!(
            !out.contains("--"),
            "must not coalesce into a comment: {out}"
        );
    }

    #[test]
    fn fold_does_not_break_modulo_precedence_against_following_subtraction() {
        let out: String = fold_numeric_expressions("v=x%1425918-(-453186)");
        assert!(
            out.contains("%1425918") || out.contains("% 1425918"),
            "modulo operand must not be merged across precedence: {out}"
        );
    }

    #[test]
    fn dispatch_detects_flattened_state_machine() {
        let src: &str = "while m do if m<100 then a={} m=200 elseif m<300 then a={} m=400 else a={} m=500 end end";
        let report: DispatchReport = analyze_dispatch(src).unwrap();
        assert_eq!(report.state_variable, 'm');
        assert!(report.comparison_count >= 2);
        assert!(report.leaf_states.contains(&200));
        assert!(report.leaf_states.contains(&400));
        assert!(report.leaf_states.contains(&500));
    }

    #[test]
    fn dispatch_recovers_multi_assign_successor() {
        let src: &str = "while m do if m<10 then G,m=e,777 else b,m={},888 end end";
        let report: DispatchReport = analyze_dispatch(src).unwrap();
        assert!(report.leaf_states.contains(&777));
        assert!(report.leaf_states.contains(&888));
    }

    #[test]
    fn dispatch_counts_conditional_branches() {
        let src: &str = "while m do if m<10 then m=l and 111 or 222 else x={} m=333 end end";
        let report: DispatchReport = analyze_dispatch(src).unwrap();
        assert!(report.conditional_blocks >= 1);
        assert!(report.leaf_states.contains(&111));
        assert!(report.leaf_states.contains(&222));
        assert!(report.leaf_states.contains(&333));
    }

    #[test]
    fn non_vm_source_has_no_dispatch() {
        assert!(analyze_dispatch("local x = 1 print(x) return x").is_none());
    }

    #[test]
    fn arithmetic_operator_count_ignores_strings_and_comments() {
        let src: &str = "a=1+2 --[[ 9*9 ]] b=\"3-3\" c=4%5";
        assert_eq!(count_arithmetic_operators(src), 2);
    }
}
