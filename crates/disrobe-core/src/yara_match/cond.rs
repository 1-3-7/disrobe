use std::collections::BTreeSet;

#[derive(Debug)]
pub(super) struct CondError {
    pub(super) reason: String,
}

impl CondError {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum CmpOp {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
}

#[derive(Debug, Clone, Copy)]
enum ArithOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
}

#[derive(Debug)]
enum IntExpr {
    Lit(i64),
    Filesize,
    Count(usize),
    Neg(Box<Self>),
    Bin(ArithOp, Box<Self>, Box<Self>),
    FromBool(Box<Cond>),
}

#[derive(Debug)]
enum Quant {
    Count(IntExpr),
    Any,
    All,
    None,
}

#[derive(Debug)]
enum Cond {
    Bool(bool),
    StringMatch(usize),
    StringAt(usize, IntExpr),
    StringIn(usize, IntExpr, IntExpr),
    Of(Quant, Vec<usize>),
    Not(Box<Self>),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    Compare(IntExpr, CmpOp, IntExpr),
}

#[derive(Debug, Clone)]
enum Tok {
    LParen,
    RParen,
    DotDot,
    Comma,
    Str(String),
    StrWild(String),
    Anon,
    Count(String),
    Offset,
    Length,
    Num(i64),
    Ident(String),
    Cmp(CmpOp),
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
}

pub(super) struct MatchView<'a> {
    pub(super) offsets: &'a [Vec<u64>],
    pub(super) filesize: i64,
}

#[derive(Debug, Default, Clone)]
struct RefStats {
    total: usize,
    const_at: usize,
    anchor: i64,
}

#[derive(Debug)]
pub(super) struct CompiledCond {
    root: Cond,
    refs: Vec<RefStats>,
}

impl CompiledCond {
    pub(super) fn compile(condition: &str, ids: &[String]) -> Result<Self, CondError> {
        let toks: Vec<Tok> = tokenize(condition)?;
        let resolver: Resolver<'_> = Resolver { ids };
        let mut parser: Parser<'_> = Parser {
            toks: &toks,
            pos: 0,
            resolver,
        };
        let root: Cond = parser.parse_expr()?;
        if parser.pos != toks.len() {
            return Err(CondError::new("trailing tokens in condition"));
        }
        let mut refs: Vec<RefStats> = vec![RefStats::default(); ids.len()];
        collect_cond(&root, &mut refs);
        Ok(Self { root, refs })
    }

    pub(super) fn evaluate(&self, view: &MatchView<'_>) -> bool {
        eval_cond(&self.root, view)
    }

    pub(super) fn reported_offsets(&self, idx: usize, matches: &[u64]) -> Vec<u64> {
        let Some(stats): Option<&RefStats> = self.refs.get(idx) else {
            return matches.to_vec();
        };
        if stats.total == 1 && stats.const_at == 1 {
            let anchor: i64 = stats.anchor;
            return matches
                .iter()
                .copied()
                .filter(|&m: &u64| i64::try_from(m).is_ok_and(|v: i64| v == anchor))
                .collect();
        }
        matches.to_vec()
    }
}

struct Resolver<'a> {
    ids: &'a [String],
}

impl Resolver<'_> {
    fn single(&self, name: &str) -> Option<usize> {
        self.ids.iter().position(|id: &String| id == name)
    }

    fn wildcard(&self, prefix: &str) -> Vec<usize> {
        self.ids
            .iter()
            .enumerate()
            .filter(|(_, id): &(usize, &String)| {
                id.get(1..).is_some_and(|n: &str| n.starts_with(prefix))
            })
            .map(|(i, _): (usize, &String)| i)
            .collect()
    }

    fn all(&self) -> Vec<usize> {
        (0..self.ids.len()).collect()
    }
}

struct Parser<'a> {
    toks: &'a [Tok],
    pos: usize,
    resolver: Resolver<'a>,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn bump(&mut self) -> Option<&Tok> {
        let tok: Option<&Tok> = self.toks.get(self.pos);
        if tok.is_some() {
            self.pos += 1;
        }
        tok
    }

    fn eat_ident(&mut self, keyword: &str) -> bool {
        if matches!(self.peek(), Some(Tok::Ident(word)) if word == keyword) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, tok: &Tok) -> Result<(), CondError> {
        match self.peek() {
            Some(found) if tok_eq(found, tok) => {
                self.pos += 1;
                Ok(())
            }
            other => Err(CondError::new(format!("expected {tok:?}, found {other:?}"))),
        }
    }

    fn parse_expr(&mut self) -> Result<Cond, CondError> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<Cond, CondError> {
        let mut left: Cond = self.parse_and()?;
        while self.eat_ident("or") {
            let right: Cond = self.parse_and()?;
            left = Cond::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Cond, CondError> {
        let mut left: Cond = self.parse_not()?;
        while self.eat_ident("and") {
            let right: Cond = self.parse_not()?;
            left = Cond::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Cond, CondError> {
        if self.eat_ident("not") {
            let inner: Cond = self.parse_not()?;
            return Ok(Cond::Not(Box::new(inner)));
        }
        self.parse_cmp()
    }

    fn parse_cmp(&mut self) -> Result<Cond, CondError> {
        let left: Node = self.parse_add()?;
        if let Some(&Tok::Cmp(op)) = self.peek() {
            self.pos += 1;
            let right: Node = self.parse_add()?;
            return Ok(Cond::Compare(as_int(left), op, as_int(right)));
        }
        Ok(as_cond(left))
    }

    fn parse_add(&mut self) -> Result<Node, CondError> {
        let mut left: Node = self.parse_mul()?;
        loop {
            let op: ArithOp = match self.peek() {
                Some(Tok::Plus) => ArithOp::Add,
                Some(Tok::Minus) => ArithOp::Sub,
                _ => break,
            };
            self.pos += 1;
            let right: Node = self.parse_mul()?;
            left = Node::Int(IntExpr::Bin(
                op,
                Box::new(as_int(left)),
                Box::new(as_int(right)),
            ));
        }
        Ok(left)
    }

    fn parse_mul(&mut self) -> Result<Node, CondError> {
        let mut left: Node = self.parse_unary()?;
        loop {
            let op: ArithOp = match self.peek() {
                Some(Tok::Star) => ArithOp::Mul,
                Some(Tok::Slash) => ArithOp::Div,
                Some(Tok::Percent) => ArithOp::Rem,
                _ => break,
            };
            self.pos += 1;
            let right: Node = self.parse_unary()?;
            left = Node::Int(IntExpr::Bin(
                op,
                Box::new(as_int(left)),
                Box::new(as_int(right)),
            ));
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Node, CondError> {
        if matches!(self.peek(), Some(Tok::Minus)) {
            self.pos += 1;
            let inner: Node = self.parse_unary()?;
            return Ok(Node::Int(IntExpr::Neg(Box::new(as_int(inner)))));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Node, CondError> {
        let tok: Tok = self
            .bump()
            .cloned()
            .ok_or_else(|| CondError::new("unexpected end of condition"))?;
        match tok {
            Tok::LParen => {
                let inner: Cond = self.parse_expr()?;
                self.expect(&Tok::RParen)?;
                Ok(Node::Cond(inner))
            }
            Tok::Num(value) => {
                if self.eat_ident("of") {
                    let set: Vec<usize> = self.parse_set()?;
                    Ok(Node::Cond(Cond::Of(Quant::Count(IntExpr::Lit(value)), set)))
                } else {
                    Ok(Node::Int(IntExpr::Lit(value)))
                }
            }
            Tok::Str(name) => self.parse_string_primary(&name),
            Tok::Count(name) => {
                let idx: usize = self
                    .resolver
                    .single(&format!("${name}"))
                    .filter(|_: &usize| !name.is_empty())
                    .ok_or_else(|| CondError::new(format!("unknown count reference #{name}")))?;
                Ok(Node::Int(IntExpr::Count(idx)))
            }
            Tok::Ident(word) => self.parse_ident_primary(&word),
            other => Err(CondError::new(format!("unsupported token {other:?}"))),
        }
    }

    fn parse_string_primary(&mut self, name: &str) -> Result<Node, CondError> {
        let idx: usize = self
            .resolver
            .single(name)
            .ok_or_else(|| CondError::new(format!("unknown string {name}")))?;
        if self.eat_ident("at") {
            let offset: Node = self.parse_add()?;
            return Ok(Node::Cond(Cond::StringAt(idx, as_int(offset))));
        }
        if self.eat_ident("in") {
            self.expect(&Tok::LParen)?;
            let lo: Node = self.parse_add()?;
            self.expect(&Tok::DotDot)?;
            let hi: Node = self.parse_add()?;
            self.expect(&Tok::RParen)?;
            return Ok(Node::Cond(Cond::StringIn(idx, as_int(lo), as_int(hi))));
        }
        Ok(Node::Cond(Cond::StringMatch(idx)))
    }

    fn parse_ident_primary(&mut self, word: &str) -> Result<Node, CondError> {
        match word {
            "true" => Ok(Node::Cond(Cond::Bool(true))),
            "false" => Ok(Node::Cond(Cond::Bool(false))),
            "filesize" => Ok(Node::Int(IntExpr::Filesize)),
            "all" | "any" | "none" => {
                if !self.eat_ident("of") {
                    return Err(CondError::new(format!("expected 'of' after {word}")));
                }
                let set: Vec<usize> = self.parse_set()?;
                let quant: Quant = match word {
                    "all" => Quant::All,
                    "any" => Quant::Any,
                    _ => Quant::None,
                };
                Ok(Node::Cond(Cond::Of(quant, set)))
            }
            other => Err(CondError::new(format!("unsupported identifier {other:?}"))),
        }
    }

    fn parse_set(&mut self) -> Result<Vec<usize>, CondError> {
        if self.eat_ident("them") {
            return Ok(self.resolver.all());
        }
        self.expect(&Tok::LParen)?;
        let mut out: BTreeSet<usize> = BTreeSet::new();
        loop {
            let tok: Tok = self
                .bump()
                .cloned()
                .ok_or_else(|| CondError::new("unterminated string set"))?;
            match tok {
                Tok::Str(name) => {
                    let idx: usize = self
                        .resolver
                        .single(&name)
                        .ok_or_else(|| CondError::new(format!("unknown string {name}")))?;
                    out.insert(idx);
                }
                Tok::StrWild(prefix) => {
                    for idx in self.resolver.wildcard(&prefix) {
                        out.insert(idx);
                    }
                }
                other => {
                    return Err(CondError::new(format!("unsupported set entry {other:?}")));
                }
            }
            match self.peek() {
                Some(Tok::Comma) => {
                    self.pos += 1;
                }
                Some(Tok::RParen) => {
                    self.pos += 1;
                    break;
                }
                other => {
                    return Err(CondError::new(format!(
                        "malformed string set near {other:?}"
                    )));
                }
            }
        }
        Ok(out.into_iter().collect())
    }
}

enum Node {
    Cond(Cond),
    Int(IntExpr),
}

fn as_cond(node: Node) -> Cond {
    match node {
        Node::Cond(cond) => cond,
        Node::Int(expr) => Cond::Compare(expr, CmpOp::Ne, IntExpr::Lit(0)),
    }
}

fn as_int(node: Node) -> IntExpr {
    match node {
        Node::Int(expr) => expr,
        Node::Cond(cond) => IntExpr::FromBool(Box::new(cond)),
    }
}

const fn tok_eq(a: &Tok, b: &Tok) -> bool {
    matches!(
        (a, b),
        (Tok::LParen, Tok::LParen)
            | (Tok::RParen, Tok::RParen)
            | (Tok::DotDot, Tok::DotDot)
            | (Tok::Comma, Tok::Comma)
    )
}

fn tokenize(input: &str) -> Result<Vec<Tok>, CondError> {
    let bytes: &[u8] = input.as_bytes();
    let mut i: usize = 0;
    let mut out: Vec<Tok> = Vec::new();
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b'(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            b')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            b',' => {
                out.push(Tok::Comma);
                i += 1;
            }
            b'+' => {
                out.push(Tok::Plus);
                i += 1;
            }
            b'-' => {
                out.push(Tok::Minus);
                i += 1;
            }
            b'*' => {
                out.push(Tok::Star);
                i += 1;
            }
            b'%' => {
                out.push(Tok::Percent);
                i += 1;
            }
            b'\\' => {
                out.push(Tok::Slash);
                i += 1;
            }
            b'.' => {
                if bytes.get(i + 1) == Some(&b'.') {
                    out.push(Tok::DotDot);
                    i += 2;
                } else {
                    return Err(CondError::new("member access is unsupported"));
                }
            }
            b'<' => {
                if bytes.get(i + 1) == Some(&b'=') {
                    out.push(Tok::Cmp(CmpOp::Le));
                    i += 2;
                } else {
                    out.push(Tok::Cmp(CmpOp::Lt));
                    i += 1;
                }
            }
            b'>' => {
                if bytes.get(i + 1) == Some(&b'=') {
                    out.push(Tok::Cmp(CmpOp::Ge));
                    i += 2;
                } else {
                    out.push(Tok::Cmp(CmpOp::Gt));
                    i += 1;
                }
            }
            b'=' => {
                if bytes.get(i + 1) == Some(&b'=') {
                    out.push(Tok::Cmp(CmpOp::Eq));
                    i += 2;
                } else {
                    return Err(CondError::new("bare '=' is unsupported"));
                }
            }
            b'!' => {
                if bytes.get(i + 1) == Some(&b'=') {
                    out.push(Tok::Cmp(CmpOp::Ne));
                    i += 2;
                } else {
                    let (_name, next): (String, usize) = read_ident(bytes, i + 1);
                    out.push(Tok::Length);
                    i = next;
                }
            }
            b'@' => {
                let (_name, next): (String, usize) = read_ident(bytes, i + 1);
                out.push(Tok::Offset);
                i = next;
            }
            b'$' => {
                let (name, next): (String, usize) = read_ident(bytes, i + 1);
                if bytes.get(next) == Some(&b'*') {
                    out.push(Tok::StrWild(name));
                    i = next + 1;
                } else if name.is_empty() {
                    out.push(Tok::Anon);
                    i = next;
                } else {
                    out.push(Tok::Str(format!("${name}")));
                    i = next;
                }
            }
            b'#' => {
                let (name, next): (String, usize) = read_ident(bytes, i + 1);
                out.push(Tok::Count(name));
                i = next;
            }
            c if c.is_ascii_digit() => {
                let (value, next): (i64, usize) = read_number(bytes, i)?;
                out.push(Tok::Num(value));
                i = next;
            }
            c if c.is_ascii_alphabetic() || c == b'_' => {
                let (name, next): (String, usize) = read_ident(bytes, i);
                out.push(Tok::Ident(name));
                i = next;
            }
            other => {
                return Err(CondError::new(format!(
                    "unsupported condition character {:?}",
                    other as char
                )));
            }
        }
    }
    Ok(out)
}

fn read_ident(bytes: &[u8], start: usize) -> (String, usize) {
    let mut i: usize = start;
    while let Some(&c) = bytes.get(i) {
        if c.is_ascii_alphanumeric() || c == b'_' {
            i += 1;
        } else {
            break;
        }
    }
    (String::from_utf8_lossy(&bytes[start..i]).into_owned(), i)
}

fn read_number(bytes: &[u8], start: usize) -> Result<(i64, usize), CondError> {
    let mut i: usize = start;
    let is_hex: bool = bytes.get(i) == Some(&b'0') && matches!(bytes.get(i + 1), Some(b'x' | b'X'));
    let radix: u32 = if is_hex { 16 } else { 10 };
    if is_hex {
        i += 2;
    }
    let digit_start: usize = i;
    while let Some(&c) = bytes.get(i) {
        let is_digit: bool = if is_hex {
            c.is_ascii_hexdigit()
        } else {
            c.is_ascii_digit()
        };
        if is_digit {
            i += 1;
        } else {
            break;
        }
    }
    let text: &str = core::str::from_utf8(&bytes[digit_start..i])
        .map_err(|_e: core::str::Utf8Error| CondError::new("number encoding"))?;
    let mut value: i64 = i64::from_str_radix(text, radix)
        .map_err(|_e: core::num::ParseIntError| CondError::new("invalid number"))?;
    if let Some((multiplier, next)) = read_size_suffix(bytes, i) {
        value = value.saturating_mul(multiplier);
        i = next;
    }
    Ok((value, i))
}

fn read_size_suffix(bytes: &[u8], start: usize) -> Option<(i64, usize)> {
    let unit: u8 = bytes.get(start).copied()?;
    let second: u8 = bytes.get(start + 1).copied()?;
    if !second.eq_ignore_ascii_case(&b'b') {
        return None;
    }
    let boundary_ok: bool = bytes
        .get(start + 2)
        .is_none_or(|&c: &u8| !(c.is_ascii_alphanumeric() || c == b'_'));
    if !boundary_ok {
        return None;
    }
    match unit.to_ascii_lowercase() {
        b'k' => Some((1024, start + 2)),
        b'm' => Some((1024 * 1024, start + 2)),
        _ => None,
    }
}

fn collect_cond(cond: &Cond, refs: &mut [RefStats]) {
    match cond {
        Cond::Bool(_) => {}
        Cond::StringMatch(idx) => add_ref(refs, *idx),
        Cond::StringAt(idx, expr) => {
            if let Some(value) = const_eval(expr) {
                add_const_at(refs, *idx, value);
            } else {
                add_ref(refs, *idx);
            }
            collect_int(expr, refs);
        }
        Cond::StringIn(idx, lo, hi) => {
            add_ref(refs, *idx);
            collect_int(lo, refs);
            collect_int(hi, refs);
        }
        Cond::Of(quant, set) => {
            for &idx in set {
                add_ref(refs, idx);
            }
            if let Quant::Count(expr) = quant {
                collect_int(expr, refs);
            }
        }
        Cond::Not(inner) => collect_cond(inner, refs),
        Cond::And(a, b) | Cond::Or(a, b) => {
            collect_cond(a, refs);
            collect_cond(b, refs);
        }
        Cond::Compare(a, _, b) => {
            collect_int(a, refs);
            collect_int(b, refs);
        }
    }
}

fn collect_int(expr: &IntExpr, refs: &mut [RefStats]) {
    match expr {
        IntExpr::Lit(_) | IntExpr::Filesize => {}
        IntExpr::Count(idx) => add_ref(refs, *idx),
        IntExpr::Neg(inner) => collect_int(inner, refs),
        IntExpr::Bin(_, a, b) => {
            collect_int(a, refs);
            collect_int(b, refs);
        }
        IntExpr::FromBool(cond) => collect_cond(cond, refs),
    }
}

fn add_ref(refs: &mut [RefStats], idx: usize) {
    if let Some(slot) = refs.get_mut(idx) {
        slot.total += 1;
    }
}

fn add_const_at(refs: &mut [RefStats], idx: usize, anchor: i64) {
    if let Some(slot) = refs.get_mut(idx) {
        slot.total += 1;
        slot.const_at += 1;
        slot.anchor = anchor;
    }
}

fn const_eval(expr: &IntExpr) -> Option<i64> {
    match expr {
        IntExpr::Lit(value) => Some(*value),
        IntExpr::Neg(inner) => const_eval(inner).map(i64::saturating_neg),
        IntExpr::Bin(op, a, b) => {
            let lhs: i64 = const_eval(a)?;
            let rhs: i64 = const_eval(b)?;
            apply_arith(*op, lhs, rhs)
        }
        IntExpr::Filesize | IntExpr::Count(_) | IntExpr::FromBool(_) => None,
    }
}

fn apply_arith(op: ArithOp, lhs: i64, rhs: i64) -> Option<i64> {
    match op {
        ArithOp::Add => Some(lhs.saturating_add(rhs)),
        ArithOp::Sub => Some(lhs.saturating_sub(rhs)),
        ArithOp::Mul => Some(lhs.saturating_mul(rhs)),
        ArithOp::Div => (rhs != 0).then(|| lhs.wrapping_div(rhs)),
        ArithOp::Rem => (rhs != 0).then(|| lhs.wrapping_rem(rhs)),
    }
}

fn eval_cond(cond: &Cond, view: &MatchView<'_>) -> bool {
    match cond {
        Cond::Bool(value) => *value,
        Cond::StringMatch(idx) => view
            .offsets
            .get(*idx)
            .is_some_and(|o: &Vec<u64>| !o.is_empty()),
        Cond::StringAt(idx, expr) => {
            let target: i64 = eval_int(expr, view);
            u64::try_from(target).is_ok_and(|want: u64| {
                view.offsets
                    .get(*idx)
                    .is_some_and(|o: &Vec<u64>| o.binary_search(&want).is_ok())
            })
        }
        Cond::StringIn(idx, lo, hi) => {
            let low: i64 = eval_int(lo, view);
            let high: i64 = eval_int(hi, view);
            view.offsets.get(*idx).is_some_and(|o: &Vec<u64>| {
                o.iter()
                    .any(|&off: &u64| i64::try_from(off).is_ok_and(|v: i64| v >= low && v <= high))
            })
        }
        Cond::Of(quant, set) => {
            let matched: usize = set
                .iter()
                .filter(|&&idx: &&usize| {
                    view.offsets
                        .get(idx)
                        .is_some_and(|o: &Vec<u64>| !o.is_empty())
                })
                .count();
            let threshold: i64 = match quant {
                Quant::Count(expr) => eval_int(expr, view),
                Quant::Any => 1,
                Quant::All => set.len() as i64,
                Quant::None => return matched == 0,
            };
            (matched as i64) >= threshold
        }
        Cond::Not(inner) => !eval_cond(inner, view),
        Cond::And(a, b) => eval_cond(a, view) && eval_cond(b, view),
        Cond::Or(a, b) => eval_cond(a, view) || eval_cond(b, view),
        Cond::Compare(a, op, b) => {
            let lhs: i64 = eval_int(a, view);
            let rhs: i64 = eval_int(b, view);
            apply_cmp(*op, lhs, rhs)
        }
    }
}

fn eval_int(expr: &IntExpr, view: &MatchView<'_>) -> i64 {
    match expr {
        IntExpr::Lit(value) => *value,
        IntExpr::Filesize => view.filesize,
        IntExpr::Count(idx) => view
            .offsets
            .get(*idx)
            .map_or(0, |o: &Vec<u64>| o.len() as i64),
        IntExpr::Neg(inner) => eval_int(inner, view).saturating_neg(),
        IntExpr::Bin(op, a, b) => {
            let lhs: i64 = eval_int(a, view);
            let rhs: i64 = eval_int(b, view);
            apply_arith(*op, lhs, rhs).unwrap_or(0)
        }
        IntExpr::FromBool(cond) => i64::from(eval_cond(cond, view)),
    }
}

const fn apply_cmp(op: CmpOp, lhs: i64, rhs: i64) -> bool {
    match op {
        CmpOp::Lt => lhs < rhs,
        CmpOp::Le => lhs <= rhs,
        CmpOp::Gt => lhs > rhs,
        CmpOp::Ge => lhs >= rhs,
        CmpOp::Eq => lhs == rhs,
        CmpOp::Ne => lhs != rhs,
    }
}
