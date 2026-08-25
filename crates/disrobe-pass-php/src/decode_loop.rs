use crate::loader::{
    bin2hex, bzdecompress_bounded, decode_hex_stream_skip_ws, gunzip, html_entity_decode,
    inflate_raw, inflate_zlib, rot13_byte, str_repeat, str_replace_bytes, strtr_bytes, substr,
    uudecode,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64_STD;
use disrobe_core::codec::{CbcPadding, aes_cbc_decrypt, md5_digest, sha1_digest};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    pub steps: u64,
    pub output_bytes: usize,
    pub heap_bytes: usize,
    pub expr_depth: u32,
    pub frame_depth: u32,
    pub rounds: u32,
    pub wall: Duration,
}

pub const DEFAULT_MAX_STEPS: u64 = 4_000_000;
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_HEAP_BYTES: usize = 64 * 1024 * 1024;
pub const DEFAULT_MAX_EXPR_DEPTH: u32 = 64;
pub const DEFAULT_MAX_FRAME_DEPTH: u32 = 64;
pub const DEFAULT_MAX_ROUNDS: u32 = 64;
pub const DEFAULT_MAX_WALL: Duration = Duration::from_secs(2);

impl Default for Budget {
    fn default() -> Self {
        Self {
            steps: DEFAULT_MAX_STEPS,
            output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            heap_bytes: DEFAULT_MAX_HEAP_BYTES,
            expr_depth: DEFAULT_MAX_EXPR_DEPTH,
            frame_depth: DEFAULT_MAX_FRAME_DEPTH,
            rounds: DEFAULT_MAX_ROUNDS,
            wall: DEFAULT_MAX_WALL,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Abstain {
    StepBudget,
    WallBudget,
    OutputBudget,
    HeapBudget,
    DepthBudget,
    FrameBudget,
    RoundBudget,
    UndefinedRead,
    RefusedCall,
    Unsupported,
    TypeMismatch,
    OutOfRange,
}

type Eval<T> = Result<T, Abstain>;

#[derive(Debug, Clone, PartialEq)]
enum Val {
    Int(i64),
    Float(f64),
    Str(Vec<u8>),
    Arr(BTreeMap<i64, Self>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Concat,
    BitXor,
    BitAnd,
    BitOr,
    Shl,
    Shr,
    Eq,
    Ne,
    Identical,
    NotIdentical,
    Lt,
    Gt,
    Le,
    Ge,
    LogicAnd,
    LogicOr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnOp {
    Neg,
    Plus,
    Not,
    BitNot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AssignOp {
    Set,
    Concat,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    BitXor,
    BitAnd,
    BitOr,
    Shl,
    Shr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LExpr {
    Int(i64),
    Str(Vec<u8>),
    Var(Vec<u8>),
    Const(Vec<u8>),
    Index {
        base: Box<Self>,
        idx: Box<Self>,
    },
    Unary {
        op: UnOp,
        operand: Box<Self>,
    },
    Bin {
        op: BinOp,
        lhs: Box<Self>,
        rhs: Box<Self>,
    },
    Ternary {
        cond: Box<Self>,
        then: Box<Self>,
        other: Box<Self>,
    },
    Assign {
        target: Box<LValue>,
        value: Box<Self>,
    },
    Call {
        name: Vec<u8>,
        args: Vec<Self>,
    },
    DynCall {
        callee: Box<Self>,
        args: Vec<Self>,
    },
    ArrayLit(Vec<Self>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LValue {
    Var(Vec<u8>),
    Index { name: Vec<u8>, idx: Option<LExpr> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LStmt {
    Const {
        name: Vec<u8>,
        value: LExpr,
    },
    Assign {
        target: LValue,
        op: AssignOp,
        value: LExpr,
    },
    Destructure {
        targets: Vec<LValue>,
        value: LExpr,
    },
    IncDec {
        target: LValue,
        delta: i64,
    },
    Block(Vec<Self>),
    If {
        cond: LExpr,
        then: Box<Self>,
        other: Option<Box<Self>>,
    },
    For {
        init: Vec<Self>,
        cond: Option<LExpr>,
        step: Vec<Self>,
        body: Box<Self>,
    },
    While {
        cond: LExpr,
        body: Box<Self>,
    },
    DoWhile {
        body: Box<Self>,
        cond: LExpr,
    },
    Foreach {
        subject: LExpr,
        key: Option<Vec<u8>>,
        value: Vec<u8>,
        body: Box<Self>,
    },
    Break(u32),
    Continue(u32),
    Expr(LExpr),
    Nop,
    Return(Option<LExpr>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FnDef {
    params: Vec<(Vec<u8>, Option<LExpr>)>,
    body: Vec<LStmt>,
}

#[derive(Debug, Clone, PartialEq)]
enum Flow {
    Normal,
    Break(u32),
    Continue(u32),
    Return(Val),
}

const I64_RANGE_AS_F64: std::ops::Range<f64> =
    -9_223_372_036_854_775_808.0..9_223_372_036_854_775_808.0;

const MAX_PARSE_DEPTH: u32 = 128;
const MAX_STATEMENTS: usize = 4096;

struct LoopParser<'a> {
    buf: &'a [u8],
    pos: usize,
    depth: u32,
}

const fn is_ident_byte(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphanumeric()
}

const fn is_ident_start(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphabetic()
}

impl<'a> LoopParser<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            depth: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<u8> {
        self.buf.get(self.pos + offset).copied()
    }

    fn eof(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn skip_trivia(&mut self) {
        loop {
            let before: usize = self.pos;
            while self.pos < self.buf.len() && self.buf[self.pos].is_ascii_whitespace() {
                self.pos += 1;
            }
            let rest: &[u8] = &self.buf[self.pos..];
            if rest.starts_with(b"//") || (rest.starts_with(b"#") && !rest.starts_with(b"#[")) {
                while self.pos < self.buf.len() && self.buf[self.pos] != b'\n' {
                    self.pos += 1;
                }
            } else if rest.starts_with(b"/*") {
                self.pos += 2;
                while self.pos < self.buf.len() && !self.buf[self.pos..].starts_with(b"*/") {
                    self.pos += 1;
                }
                self.pos = (self.pos + 2).min(self.buf.len());
            }
            if self.pos == before {
                return;
            }
        }
    }

    fn eat(&mut self, tok: &[u8]) -> bool {
        self.skip_trivia();
        if self.buf[self.pos.min(self.buf.len())..].starts_with(tok) {
            self.pos += tok.len();
            return true;
        }
        false
    }

    fn eat_keyword(&mut self, kw: &[u8]) -> bool {
        self.skip_trivia();
        let end: usize = self.pos + kw.len();
        let Some(slice): Option<&[u8]> = self.buf.get(self.pos..end) else {
            return false;
        };
        if !slice.eq_ignore_ascii_case(kw) {
            return false;
        }
        if self.buf.get(end).copied().is_some_and(is_ident_byte) {
            return false;
        }
        self.pos = end;
        true
    }

    fn enter(&mut self) -> Option<()> {
        self.depth += 1;
        (self.depth <= MAX_PARSE_DEPTH).then_some(())
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn parse_program(&mut self) -> Option<Vec<LStmt>> {
        let mut out: Vec<LStmt> = Vec::new();
        loop {
            self.skip_trivia();
            if self.eof() {
                return Some(out);
            }
            if out.len() >= MAX_STATEMENTS {
                return None;
            }
            out.push(self.parse_stmt()?);
        }
    }

    fn parse_block_body(&mut self) -> Option<Vec<LStmt>> {
        let mut out: Vec<LStmt> = Vec::new();
        loop {
            self.skip_trivia();
            if self.eof() {
                return None;
            }
            if self.peek() == Some(b'}') {
                self.pos += 1;
                return Some(out);
            }
            if out.len() >= MAX_STATEMENTS {
                return None;
            }
            out.push(self.parse_stmt()?);
        }
    }

    fn parse_stmt(&mut self) -> Option<LStmt> {
        self.enter()?;
        let stmt: Option<LStmt> = self.parse_stmt_inner();
        self.leave();
        stmt
    }

    fn parse_stmt_inner(&mut self) -> Option<LStmt> {
        self.skip_trivia();
        if self.peek() == Some(b';') {
            self.pos += 1;
            return Some(LStmt::Nop);
        }
        if self.peek() == Some(b'{') {
            self.pos += 1;
            return Some(LStmt::Block(self.parse_block_body()?));
        }
        if self.eat_keyword(b"const") {
            self.skip_trivia();
            let name: Vec<u8> = self.parse_ident()?;
            if is_reserved_word(&name) || !self.eat(b"=") {
                return None;
            }
            let value: LExpr = self.parse_expr()?;
            self.expect_semicolon();
            return Some(LStmt::Const { name, value });
        }
        if self.eat_keyword(b"if") {
            return self.parse_if();
        }
        if self.eat_keyword(b"foreach") {
            return self.parse_foreach();
        }
        if self.eat_keyword(b"for") {
            return self.parse_for();
        }
        if self.eat_keyword(b"while") {
            return self.parse_while();
        }
        if self.eat_keyword(b"do") {
            return self.parse_do_while();
        }
        if self.eat_keyword(b"return") {
            self.skip_trivia();
            if self.peek() == Some(b';') {
                self.pos += 1;
                return Some(LStmt::Return(None));
            }
            let value: LExpr = self.parse_expr()?;
            self.expect_semicolon();
            return Some(LStmt::Return(Some(value)));
        }
        if self.eat_keyword(b"break") {
            let levels: u32 = self.parse_optional_level();
            self.expect_semicolon();
            return Some(LStmt::Break(levels));
        }
        if self.eat_keyword(b"continue") {
            let levels: u32 = self.parse_optional_level();
            self.expect_semicolon();
            return Some(LStmt::Continue(levels));
        }
        let stmt: LStmt = self.parse_simple_stmt()?;
        self.expect_semicolon();
        Some(stmt)
    }

    fn parse_optional_level(&mut self) -> u32 {
        self.skip_trivia();
        let start: usize = self.pos;
        while self.pos < self.buf.len() && self.buf[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        if self.pos == start {
            return 1;
        }
        std::str::from_utf8(&self.buf[start..self.pos])
            .ok()
            .and_then(|t: &str| t.parse::<u32>().ok())
            .unwrap_or(1)
            .max(1)
    }

    fn expect_semicolon(&mut self) {
        self.skip_trivia();
        if self.peek() == Some(b';') {
            self.pos += 1;
        }
    }

    fn parse_if(&mut self) -> Option<LStmt> {
        if !self.eat(b"(") {
            return None;
        }
        let cond: LExpr = self.parse_expr()?;
        if !self.eat(b")") {
            return None;
        }
        let then: LStmt = self.parse_stmt()?;
        let save: usize = self.pos;
        if self.eat_keyword(b"elseif") {
            let other: LStmt = self.parse_if()?;
            return Some(LStmt::If {
                cond,
                then: Box::new(then),
                other: Some(Box::new(other)),
            });
        }
        if self.eat_keyword(b"else") {
            self.skip_trivia();
            if self.eat_keyword(b"if") {
                let other: LStmt = self.parse_if()?;
                return Some(LStmt::If {
                    cond,
                    then: Box::new(then),
                    other: Some(Box::new(other)),
                });
            }
            let other: LStmt = self.parse_stmt()?;
            return Some(LStmt::If {
                cond,
                then: Box::new(then),
                other: Some(Box::new(other)),
            });
        }
        self.pos = save;
        Some(LStmt::If {
            cond,
            then: Box::new(then),
            other: None,
        })
    }

    fn parse_for(&mut self) -> Option<LStmt> {
        if !self.eat(b"(") {
            return None;
        }
        let init: Vec<LStmt> = self.parse_simple_stmt_list(b';')?;
        if !self.eat(b";") {
            return None;
        }
        self.skip_trivia();
        let cond: Option<LExpr> = if self.peek() == Some(b';') {
            None
        } else {
            Some(self.parse_expr()?)
        };
        if !self.eat(b";") {
            return None;
        }
        let step: Vec<LStmt> = self.parse_simple_stmt_list(b')')?;
        if !self.eat(b")") {
            return None;
        }
        let body: LStmt = self.parse_stmt()?;
        Some(LStmt::For {
            init,
            cond,
            step,
            body: Box::new(body),
        })
    }

    fn parse_simple_stmt_list(&mut self, terminator: u8) -> Option<Vec<LStmt>> {
        let mut out: Vec<LStmt> = Vec::new();
        self.skip_trivia();
        if self.peek() == Some(terminator) {
            return Some(out);
        }
        loop {
            out.push(self.parse_simple_stmt()?);
            self.skip_trivia();
            if self.peek() == Some(b',') {
                self.pos += 1;
                continue;
            }
            return Some(out);
        }
    }

    fn parse_while(&mut self) -> Option<LStmt> {
        if !self.eat(b"(") {
            return None;
        }
        let cond: LExpr = self.parse_expr()?;
        if !self.eat(b")") {
            return None;
        }
        let body: LStmt = self.parse_stmt()?;
        Some(LStmt::While {
            cond,
            body: Box::new(body),
        })
    }

    fn parse_do_while(&mut self) -> Option<LStmt> {
        let body: LStmt = self.parse_stmt()?;
        if !self.eat_keyword(b"while") {
            return None;
        }
        if !self.eat(b"(") {
            return None;
        }
        let cond: LExpr = self.parse_expr()?;
        if !self.eat(b")") {
            return None;
        }
        self.expect_semicolon();
        Some(LStmt::DoWhile {
            body: Box::new(body),
            cond,
        })
    }

    fn parse_foreach(&mut self) -> Option<LStmt> {
        if !self.eat(b"(") {
            return None;
        }
        let subject: LExpr = self.parse_expr()?;
        if !self.eat_keyword(b"as") {
            return None;
        }
        let first: Vec<u8> = self.parse_plain_var_name()?;
        self.skip_trivia();
        let (key, value): (Option<Vec<u8>>, Vec<u8>) = if self.eat(b"=>") {
            let second: Vec<u8> = self.parse_plain_var_name()?;
            (Some(first), second)
        } else {
            (None, first)
        };
        if !self.eat(b")") {
            return None;
        }
        let body: LStmt = self.parse_stmt()?;
        Some(LStmt::Foreach {
            subject,
            key,
            value,
            body: Box::new(body),
        })
    }

    fn parse_function_decl(&mut self) -> Option<(Vec<u8>, FnDef)> {
        self.skip_trivia();
        if !self.eat_keyword(b"function") {
            return None;
        }
        self.skip_trivia();
        if self.peek() == Some(b'&') {
            return None;
        }
        let name: Vec<u8> = self.parse_ident()?;
        if !self.eat(b"(") {
            return None;
        }
        let params: Vec<(Vec<u8>, Option<LExpr>)> = self.parse_param_list()?;
        self.skip_trivia();
        if self.peek() == Some(b':') {
            self.pos += 1;
            self.skip_trivia();
            while self.peek().is_some_and(|b: u8| b != b'{') {
                self.pos += 1;
            }
        }
        if !self.eat(b"{") {
            return None;
        }
        let body: Vec<LStmt> = self.parse_block_body()?;
        Some((name.to_ascii_lowercase(), FnDef { params, body }))
    }

    fn parse_param_list(&mut self) -> Option<Vec<(Vec<u8>, Option<LExpr>)>> {
        let mut out: Vec<(Vec<u8>, Option<LExpr>)> = Vec::new();
        self.skip_trivia();
        if self.peek() == Some(b')') {
            self.pos += 1;
            return Some(out);
        }
        loop {
            self.skip_trivia();
            if matches!(self.peek(), Some(b'&')) || self.buf[self.pos..].starts_with(b"...") {
                return None;
            }
            if self.peek() != Some(b'$') {
                self.skip_param_type()?;
            }
            let name: Vec<u8> = self.parse_plain_var_name()?;
            self.skip_trivia();
            let default: Option<LExpr> = if self.peek() == Some(b'=') {
                self.pos += 1;
                Some(self.parse_expr()?)
            } else {
                None
            };
            out.push((name, default));
            self.skip_trivia();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b')') => {
                    self.pos += 1;
                    return Some(out);
                }
                _ => return None,
            }
        }
    }

    fn skip_param_type(&mut self) -> Option<()> {
        self.skip_trivia();
        if self.peek() == Some(b'?') {
            self.pos += 1;
        }
        loop {
            self.skip_trivia();
            self.parse_ident()?;
            self.skip_trivia();
            if matches!(self.peek(), Some(b'|' | b'&')) && self.peek_at(1) != Some(b'$') {
                self.pos += 1;
                continue;
            }
            return Some(());
        }
    }

    fn parse_plain_var_name(&mut self) -> Option<Vec<u8>> {
        self.skip_trivia();
        if self.peek() != Some(b'$') {
            return None;
        }
        self.pos += 1;
        self.parse_ident()
    }

    fn parse_ident(&mut self) -> Option<Vec<u8>> {
        let start: usize = self.pos;
        if !self.peek().is_some_and(is_ident_start) {
            return None;
        }
        while self.peek().is_some_and(is_ident_byte) {
            self.pos += 1;
        }
        Some(self.buf[start..self.pos].to_vec())
    }

    fn parse_simple_stmt(&mut self) -> Option<LStmt> {
        self.enter()?;
        let stmt: Option<LStmt> = self.parse_simple_stmt_inner();
        self.leave();
        stmt
    }

    fn parse_simple_stmt_inner(&mut self) -> Option<LStmt> {
        self.skip_trivia();
        if self.eat(b"++") {
            let target: LValue = self.parse_lvalue()?;
            return Some(LStmt::IncDec { target, delta: 1 });
        }
        if self.eat(b"--") {
            let target: LValue = self.parse_lvalue()?;
            return Some(LStmt::IncDec { target, delta: -1 });
        }
        let destructure_start: usize = self.pos;
        if let Some(stmt) = self.parse_destructure() {
            return Some(stmt);
        }
        self.pos = destructure_start;
        let save: usize = self.pos;
        self.skip_trivia();
        if self.peek() == Some(b'$') && self.peek_at(1).is_some_and(is_ident_start) {
            if let Some(target) = self.parse_lvalue() {
                self.skip_trivia();
                if self.eat(b"++") {
                    return Some(LStmt::IncDec { target, delta: 1 });
                }
                if self.eat(b"--") {
                    return Some(LStmt::IncDec { target, delta: -1 });
                }
                if let Some(op) = self.match_assign_op() {
                    let value: LExpr = self.parse_expr()?;
                    return Some(LStmt::Assign { target, op, value });
                }
            }
            self.pos = save;
        }
        Some(LStmt::Expr(self.parse_expr()?))
    }

    fn parse_destructure(&mut self) -> Option<LStmt> {
        self.skip_trivia();
        let close: u8 = if self.peek() == Some(b'[') {
            self.pos += 1;
            b']'
        } else if self.eat_keyword(b"list") && self.eat(b"(") {
            b')'
        } else {
            return None;
        };
        let mut targets: Vec<LValue> = Vec::new();
        loop {
            if targets.len() >= MAX_STATEMENTS {
                return None;
            }
            let target: LValue = self.parse_lvalue()?;
            if matches!(target, LValue::Index { idx: None, .. }) {
                return None;
            }
            targets.push(target);
            self.skip_trivia();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(candidate) if candidate == close => {
                    self.pos += 1;
                    break;
                }
                _ => return None,
            }
        }
        if !self.eat(b"=") || self.peek() == Some(b'=') {
            return None;
        }
        let value: LExpr = self.parse_expr()?;
        Some(LStmt::Destructure { targets, value })
    }

    fn match_assign_op(&mut self) -> Option<AssignOp> {
        self.skip_trivia();
        for (tok, op) in ASSIGN_OPS {
            if self.buf[self.pos.min(self.buf.len())..].starts_with(tok) {
                self.pos += tok.len();
                return Some(*op);
            }
        }
        if self.peek() == Some(b'=') && !matches!(self.peek_at(1), Some(b'=' | b'>' | b'<')) {
            self.pos += 1;
            return Some(AssignOp::Set);
        }
        None
    }

    fn parse_lvalue(&mut self) -> Option<LValue> {
        self.skip_trivia();
        if self.peek() != Some(b'$') {
            return None;
        }
        self.pos += 1;
        let name: Vec<u8> = self.parse_ident()?;
        self.skip_trivia();
        if self.peek() != Some(b'[') {
            return Some(LValue::Var(name));
        }
        self.pos += 1;
        self.skip_trivia();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Some(LValue::Index { name, idx: None });
        }
        let idx: LExpr = self.parse_expr()?;
        if !self.eat(b"]") {
            return None;
        }
        self.skip_trivia();
        if self.peek() == Some(b'[') {
            return None;
        }
        Some(LValue::Index {
            name,
            idx: Some(idx),
        })
    }

    fn parse_expr(&mut self) -> Option<LExpr> {
        self.enter()?;
        let expr: Option<LExpr> = self.parse_assignment();
        self.leave();
        expr
    }

    fn parse_assignment(&mut self) -> Option<LExpr> {
        self.enter()?;
        let expr: Option<LExpr> = self.parse_assignment_inner();
        self.leave();
        expr
    }

    fn parse_assignment_inner(&mut self) -> Option<LExpr> {
        let save: usize = self.pos;
        if let Some(target) = self.parse_lvalue() {
            self.skip_trivia();
            if self.peek() == Some(b'=') && !matches!(self.peek_at(1), Some(b'=' | b'>' | b'<')) {
                self.pos += 1;
                let value: LExpr = self.parse_assignment()?;
                return Some(LExpr::Assign {
                    target: Box::new(target),
                    value: Box::new(value),
                });
            }
        }
        self.pos = save;
        self.parse_ternary()
    }

    fn parse_ternary(&mut self) -> Option<LExpr> {
        let cond: LExpr = self.parse_binary(0)?;
        self.skip_trivia();
        if self.peek() != Some(b'?') || self.peek_at(1) == Some(b'?') {
            return Some(cond);
        }
        self.pos += 1;
        let then: LExpr = self.parse_expr()?;
        if !self.eat(b":") {
            return None;
        }
        let other: LExpr = self.parse_expr()?;
        Some(LExpr::Ternary {
            cond: Box::new(cond),
            then: Box::new(then),
            other: Box::new(other),
        })
    }

    fn parse_binary(&mut self, level: usize) -> Option<LExpr> {
        const LEVELS: &[&[(&[u8], BinOp)]] = &[
            &[(b"||", BinOp::LogicOr)],
            &[(b"&&", BinOp::LogicAnd)],
            &[(b"|", BinOp::BitOr)],
            &[(b"^", BinOp::BitXor)],
            &[(b"&", BinOp::BitAnd)],
            &[
                (b"===", BinOp::Identical),
                (b"!==", BinOp::NotIdentical),
                (b"==", BinOp::Eq),
                (b"!=", BinOp::Ne),
                (b"<>", BinOp::Ne),
            ],
            &[
                (b"<=", BinOp::Le),
                (b">=", BinOp::Ge),
                (b"<", BinOp::Lt),
                (b">", BinOp::Gt),
            ],
            &[(b"<<", BinOp::Shl), (b">>", BinOp::Shr)],
            &[(b".", BinOp::Concat)],
            &[(b"+", BinOp::Add), (b"-", BinOp::Sub)],
            &[(b"*", BinOp::Mul), (b"/", BinOp::Div), (b"%", BinOp::Mod)],
        ];
        let Some(ops): Option<&&[(&[u8], BinOp)]> = LEVELS.get(level) else {
            return self.parse_unary();
        };
        self.enter()?;
        let parsed: Option<LExpr> = self.parse_binary_at(level, ops);
        self.leave();
        parsed
    }

    fn parse_binary_at(&mut self, level: usize, ops: &[(&[u8], BinOp)]) -> Option<LExpr> {
        let mut lhs: LExpr = self.parse_binary(level + 1)?;
        loop {
            self.skip_trivia();
            let mut matched: Option<BinOp> = None;
            for (tok, op) in ops {
                if !self.buf[self.pos.min(self.buf.len())..].starts_with(tok) {
                    continue;
                }
                if self.is_ambiguous_operator(tok) {
                    continue;
                }
                self.pos += tok.len();
                matched = Some(*op);
                break;
            }
            let Some(op): Option<BinOp> = matched else {
                return Some(lhs);
            };
            let rhs: LExpr = self.parse_binary(level + 1)?;
            lhs = LExpr::Bin {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
    }

    fn is_ambiguous_operator(&self, tok: &[u8]) -> bool {
        let next: Option<u8> = self.peek_at(tok.len());
        match tok {
            b"." => next.is_some_and(|b: u8| b == b'=' || b.is_ascii_digit()),
            b"|" | b"^" | b"&" | b"+" | b"-" | b"*" | b"/" | b"%" => next == Some(b'='),
            b"<" => matches!(next, Some(b'<' | b'=' | b'>')),
            b">" => matches!(next, Some(b'>' | b'=')),
            _ => false,
        }
    }

    fn parse_unary(&mut self) -> Option<LExpr> {
        self.skip_trivia();
        for (tok, op) in UNARY_OPS {
            if self.peek() != Some(*tok) {
                continue;
            }
            if *tok == b'!' && self.peek_at(1) == Some(b'=') {
                break;
            }
            if matches!(*tok, b'-' | b'+') && matches!(self.peek_at(1), Some(b'-' | b'+')) {
                break;
            }
            self.pos += 1;
            self.enter()?;
            let operand: Option<LExpr> = self.parse_unary();
            self.leave();
            return Some(LExpr::Unary {
                op: *op,
                operand: Box::new(operand?),
            });
        }
        self.parse_postfix()
    }

    fn parse_postfix(&mut self) -> Option<LExpr> {
        let mut base: LExpr = self.parse_primary()?;
        loop {
            self.skip_trivia();
            match self.peek() {
                Some(b'[') => {
                    self.pos += 1;
                    let idx: LExpr = self.parse_expr()?;
                    if !self.eat(b"]") {
                        return None;
                    }
                    base = LExpr::Index {
                        base: Box::new(base),
                        idx: Box::new(idx),
                    };
                }
                Some(b'(') if matches!(base, LExpr::Var(_) | LExpr::Index { .. }) => {
                    self.pos += 1;
                    let args: Vec<LExpr> = self.parse_arg_list(b')')?;
                    base = LExpr::DynCall {
                        callee: Box::new(base),
                        args,
                    };
                }
                _ => return Some(base),
            }
        }
    }

    fn parse_primary(&mut self) -> Option<LExpr> {
        self.skip_trivia();
        let c: u8 = self.peek()?;
        if c == b'(' {
            self.pos += 1;
            let inner: LExpr = self.parse_expr()?;
            if !self.eat(b")") {
                return None;
            }
            return Some(inner);
        }
        if c == b'$' {
            self.pos += 1;
            let name: Vec<u8> = self.parse_ident()?;
            return Some(LExpr::Var(name));
        }
        if c == b'\'' || c == b'"' {
            return self.parse_string(c);
        }
        if c == b'[' {
            self.pos += 1;
            let args: Vec<LExpr> = self.parse_arg_list(b']')?;
            return Some(LExpr::ArrayLit(args));
        }
        if c.is_ascii_digit() {
            return self.parse_number();
        }
        if is_ident_start(c) {
            let name: Vec<u8> = self.parse_ident()?;
            self.skip_trivia();
            if self.peek() != Some(b'(') {
                return literal_keyword(&name)
                    .or_else(|| (!is_reserved_word(&name)).then(|| LExpr::Const(name.clone())));
            }
            self.pos += 1;
            let args: Vec<LExpr> = self.parse_arg_list(b')')?;
            if name.eq_ignore_ascii_case(b"array") {
                return Some(LExpr::ArrayLit(args));
            }
            return Some(LExpr::Call {
                name: name.to_ascii_lowercase(),
                args,
            });
        }
        None
    }

    fn parse_arg_list(&mut self, close: u8) -> Option<Vec<LExpr>> {
        let mut args: Vec<LExpr> = Vec::new();
        self.skip_trivia();
        if self.peek() == Some(close) {
            self.pos += 1;
            return Some(args);
        }
        loop {
            args.push(self.parse_expr()?);
            self.skip_trivia();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                    self.skip_trivia();
                    if self.peek() == Some(close) {
                        self.pos += 1;
                        return Some(args);
                    }
                }
                Some(b) if b == close => {
                    self.pos += 1;
                    return Some(args);
                }
                _ => return None,
            }
        }
    }

    fn parse_number(&mut self) -> Option<LExpr> {
        let rest: &[u8] = self.buf.get(self.pos..)?;
        for (prefix, radix) in [
            (b"0x".as_slice(), 16u32),
            (b"0X".as_slice(), 16),
            (b"0b".as_slice(), 2),
            (b"0B".as_slice(), 2),
            (b"0o".as_slice(), 8),
            (b"0O".as_slice(), 8),
        ] {
            if rest.starts_with(prefix) {
                return self.parse_radix_digits(prefix.len(), radix);
            }
        }
        let start: usize = self.pos;
        while self
            .peek()
            .is_some_and(|b: u8| b.is_ascii_digit() || b == b'_')
        {
            self.pos += 1;
        }
        if self.peek() == Some(b'.') && self.peek_at(1).is_some_and(|b: u8| b.is_ascii_digit()) {
            return None;
        }
        if self.peek().is_some_and(|b: u8| b == b'e' || b == b'E') {
            return None;
        }
        let text: String = self.digits_between(start, self.pos)?;
        if text.len() > 1 && text.starts_with('0') {
            return i64::from_str_radix(&text, 8).ok().map(LExpr::Int);
        }
        text.parse::<i64>().ok().map(LExpr::Int)
    }

    fn parse_radix_digits(&mut self, prefix: usize, radix: u32) -> Option<LExpr> {
        self.pos += prefix;
        let start: usize = self.pos;
        while self
            .peek()
            .is_some_and(|b: u8| b.is_ascii_alphanumeric() || b == b'_')
        {
            self.pos += 1;
        }
        let text: String = self.digits_between(start, self.pos)?;
        i64::from_str_radix(&text, radix).ok().map(LExpr::Int)
    }

    fn digits_between(&self, start: usize, end: usize) -> Option<String> {
        Some(
            self.buf
                .get(start..end)?
                .iter()
                .filter(|b: &&u8| **b != b'_')
                .map(|b: &u8| char::from(*b))
                .collect(),
        )
    }

    fn parse_string(&mut self, quote: u8) -> Option<LExpr> {
        self.pos += 1;
        let mut out: Vec<u8> = Vec::new();
        while let Some(c) = self.peek() {
            if c == b'\\' {
                let next: u8 = self.peek_at(1)?;
                if quote == b'\'' {
                    if next == b'\\' || next == b'\'' {
                        out.push(next);
                        self.pos += 2;
                    } else {
                        out.push(c);
                        self.pos += 1;
                    }
                } else {
                    self.pos += self.push_double_escape(next, &mut out);
                }
            } else if c == quote {
                self.pos += 1;
                if quote == b'"' && out.contains(&b'$') {
                    return None;
                }
                return Some(LExpr::Str(out));
            } else {
                out.push(c);
                self.pos += 1;
            }
        }
        None
    }

    fn push_double_escape(&self, next: u8, out: &mut Vec<u8>) -> usize {
        match next {
            b'x' | b'X' => {
                let mut value: u32 = 0;
                let mut digits: usize = 0;
                while digits < 2 {
                    let Some(d): Option<u8> = self.peek_at(2 + digits) else {
                        break;
                    };
                    let Some(nib): Option<u8> = disrobe_core::codec::hex::nibble(d) else {
                        break;
                    };
                    value = value * 16 + u32::from(nib);
                    digits += 1;
                }
                if digits == 0 {
                    out.push(b'\\');
                    out.push(next);
                    return 2;
                }
                out.push(value as u8);
                2 + digits
            }
            b'0'..=b'7' => {
                let mut value: u32 = 0;
                let mut digits: usize = 0;
                while digits < 3 {
                    let Some(d): Option<u8> = self.peek_at(1 + digits) else {
                        break;
                    };
                    if !(b'0'..=b'7').contains(&d) {
                        break;
                    }
                    value = value * 8 + u32::from(d - b'0');
                    digits += 1;
                }
                out.push(value as u8);
                1 + digits
            }
            b'n' => {
                out.push(b'\n');
                2
            }
            b'r' => {
                out.push(b'\r');
                2
            }
            b't' => {
                out.push(b'\t');
                2
            }
            b'v' => {
                out.push(0x0b);
                2
            }
            b'f' => {
                out.push(0x0c);
                2
            }
            b'e' => {
                out.push(0x1b);
                2
            }
            other => {
                out.push(other);
                2
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct Interp {
    scope: BTreeMap<Vec<u8>, Val>,
    budget: Budget,
    steps: u64,
    rounds: u32,
    live_bytes: usize,
    frames_deep: u32,
    functions: BTreeMap<Vec<u8>, FnDef>,
    constants: BTreeMap<Vec<u8>, Val>,
    refused_names: std::collections::BTreeSet<Vec<u8>>,
    started: Instant,
}

impl Interp {
    pub(crate) fn new(budget: Budget) -> Self {
        let constants: BTreeMap<Vec<u8>, Val> = PREDEFINED_CONSTANTS
            .iter()
            .map(|(name, value): &(&[u8], i64)| ((*name).to_vec(), Val::Int(*value)))
            .collect();
        Self {
            scope: BTreeMap::new(),
            budget,
            steps: 0,
            rounds: 0,
            live_bytes: 0,
            frames_deep: 0,
            functions: BTreeMap::new(),
            constants,
            refused_names: std::collections::BTreeSet::new(),
            started: Instant::now(),
        }
    }

    pub(crate) fn observe_scalar(&mut self, name: &[u8], value: &[u8]) {
        self.bind_unchecked(name.to_vec(), Val::Str(value.to_vec()));
    }

    fn bind_unchecked(&mut self, name: Vec<u8>, value: Val) {
        let added: usize = val_size(&value);
        let removed: usize = self.scope.get(&name).map_or(0, val_size);
        self.live_bytes = self
            .live_bytes
            .saturating_sub(removed)
            .saturating_add(added);
        self.scope.insert(name, value);
    }

    fn bind(&mut self, name: Vec<u8>, value: Val) -> Eval<()> {
        self.bind_unchecked(name, value);
        self.check_heap()
    }

    fn check_heap(&self) -> Eval<()> {
        if self.live_bytes > self.budget.heap_bytes {
            return Err(Abstain::HeapBudget);
        }
        Ok(())
    }

    fn bind_constant(&mut self, name: Vec<u8>, value: Val) -> Eval<()> {
        if name.is_empty() || self.constants.contains_key(&name) {
            return Err(Abstain::Unsupported);
        }
        let added: usize = val_size(&value);
        if self.live_bytes.saturating_add(added) > self.budget.heap_bytes {
            return Err(Abstain::HeapBudget);
        }
        self.live_bytes += added;
        self.constants.insert(name, value);
        Ok(())
    }

    pub(crate) fn observe_array(&mut self, name: &[u8], elements: &[Vec<u8>]) {
        let map: BTreeMap<i64, Val> = elements
            .iter()
            .enumerate()
            .filter_map(|(i, item): (usize, &Vec<u8>)| {
                i64::try_from(i)
                    .ok()
                    .map(|k: i64| (k, Val::Str(item.clone())))
            })
            .collect();
        self.bind_unchecked(name.to_vec(), Val::Arr(map));
    }

    pub(crate) fn declare_function(&mut self, raw: &[u8]) {
        let mut parser: LoopParser<'_> = LoopParser::new(raw);
        let Some((name, def)): Option<(Vec<u8>, FnDef)> = parser.parse_function_decl() else {
            return;
        };
        if PURE_BUILTINS.contains(&name.as_slice()) || self.functions.contains_key(&name) {
            self.functions.remove(&name);
            self.refused_names.insert(name);
            return;
        }
        self.functions.insert(name, def);
    }

    fn call_function(&mut self, name: &[u8], args: &[Val]) -> Eval<Val> {
        let def: FnDef = self
            .functions
            .get(name)
            .cloned()
            .ok_or(Abstain::RefusedCall)?;
        let mut frame: BTreeMap<Vec<u8>, Val> = BTreeMap::new();
        for (index, (param, default)) in def.params.iter().enumerate() {
            let value: Val = if let Some(supplied) = args.get(index) {
                supplied.clone()
            } else {
                let Some(expr): Option<&LExpr> = default.as_ref() else {
                    return Err(Abstain::Unsupported);
                };
                self.eval(expr, 0)?
            };
            frame.insert(param.clone(), value);
        }
        if self.frames_deep >= self.budget.frame_depth {
            return Err(Abstain::FrameBudget);
        }
        self.frames_deep += 1;
        let entering: usize = scope_size(&frame);
        let caller: BTreeMap<Vec<u8>, Val> = std::mem::replace(&mut self.scope, frame);
        self.live_bytes = self.live_bytes.saturating_add(entering);
        let outcome: Eval<Flow> = self.exec_all(&def.body);
        let leaving: usize = scope_size(&self.scope);
        self.scope = caller;
        self.live_bytes = self.live_bytes.saturating_sub(leaving);
        self.frames_deep -= 1;
        match outcome? {
            Flow::Return(value) => Ok(value),
            Flow::Normal | Flow::Break(_) | Flow::Continue(_) => Ok(Val::Str(Vec::new())),
        }
    }

    pub(crate) fn declare_constant(&mut self, raw: &[u8]) -> bool {
        if self.check_heap().is_err() {
            return false;
        }
        let mut parser: LoopParser<'_> = LoopParser::new(raw);
        let Some(program): Option<Vec<LStmt>> = parser.parse_program() else {
            return false;
        };
        match program.as_slice() {
            [LStmt::Expr(LExpr::Call { name, args })] if name.as_slice() == b"define" => {
                self.dispatch_call(name, args, 0).is_ok()
            }
            [LStmt::Const { name, value }] if is_constant_expr(value) => {
                let Ok(evaluated): Eval<Val> = self.eval(value, 0) else {
                    return false;
                };
                self.bind_constant(name.clone(), evaluated).is_ok()
            }
            _ => false,
        }
    }

    pub(crate) fn run_sink_statement(&mut self, raw: &[u8]) -> Option<Vec<u8>> {
        self.check_heap().ok()?;
        let mut parser: LoopParser<'_> = LoopParser::new(raw);
        let program: Vec<LStmt> = parser.parse_program()?;
        let [LStmt::Expr(LExpr::Call { name, args })] = program.as_slice() else {
            return None;
        };
        if name.as_slice() != b"eval" && name.as_slice() != b"assert" {
            return None;
        }
        let [argument] = args.as_slice() else {
            return None;
        };
        let before: BTreeMap<Vec<u8>, Val> = self.scope.clone();
        let live_before: usize = self.live_bytes;
        let evaluated: Eval<Val> = self.eval(argument, 0);
        self.scope = before;
        self.live_bytes = live_before;
        to_bytes(&evaluated.ok()?).ok()
    }

    pub(crate) fn run_block(&mut self, raw: &[u8]) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
        self.check_heap().ok()?;
        let mut parser: LoopParser<'_> = LoopParser::new(raw);
        let program: Vec<LStmt> = parser.parse_program()?;
        if program.is_empty() {
            return None;
        }
        let before: BTreeMap<Vec<u8>, Val> = self.scope.clone();
        let live_before: usize = self.live_bytes;
        if self.exec_all(&program).is_err() {
            self.scope = before;
            self.live_bytes = live_before;
            return None;
        }
        let mut produced: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for (name, value) in &self.scope {
            let Val::Str(bytes) = value else {
                continue;
            };
            if before.get(name) == Some(value) {
                continue;
            }
            produced.push((name.clone(), bytes.clone()));
        }
        (!produced.is_empty()).then_some(produced)
    }

    fn tick(&mut self) -> Eval<()> {
        self.steps += 1;
        if self.steps > self.budget.steps {
            return Err(Abstain::StepBudget);
        }
        if self.steps.is_multiple_of(1024) && self.started.elapsed() > self.budget.wall {
            return Err(Abstain::WallBudget);
        }
        Ok(())
    }

    fn enter_loop(&mut self) -> Eval<()> {
        self.rounds += 1;
        if self.rounds > self.budget.rounds {
            return Err(Abstain::RoundBudget);
        }
        Ok(())
    }

    fn check_size(&self, len: usize) -> Eval<()> {
        if len > self.budget.output_bytes {
            return Err(Abstain::OutputBudget);
        }
        Ok(())
    }

    fn exec_all(&mut self, stmts: &[LStmt]) -> Eval<Flow> {
        for stmt in stmts {
            match self.exec(stmt)? {
                Flow::Normal => {}
                flow => return Ok(flow),
            }
        }
        Ok(Flow::Normal)
    }

    fn exec(&mut self, stmt: &LStmt) -> Eval<Flow> {
        self.tick()?;
        match stmt {
            LStmt::Nop => Ok(Flow::Normal),
            LStmt::Const { .. } => Err(Abstain::Unsupported),
            LStmt::Expr(expr) => {
                self.eval(expr, 0)?;
                Ok(Flow::Normal)
            }
            LStmt::Assign { target, op, value } => {
                let rhs: Val = self.eval(value, 0)?;
                self.assign(target, *op, rhs)?;
                Ok(Flow::Normal)
            }
            LStmt::Destructure { targets, value } => {
                let rhs: Val = self.eval(value, 0)?;
                let Val::Arr(mut values) = rhs else {
                    return Err(Abstain::TypeMismatch);
                };
                if values.len() != targets.len() {
                    return Err(Abstain::Unsupported);
                }
                let mut snapshot: Vec<Val> = Vec::with_capacity(targets.len());
                for index in 0..targets.len() {
                    let key: i64 = i64::try_from(index).map_err(|_| Abstain::OutOfRange)?;
                    snapshot.push(values.remove(&key).ok_or(Abstain::Unsupported)?);
                }
                for (target, assigned) in targets.iter().zip(snapshot) {
                    self.tick()?;
                    self.assign(target, AssignOp::Set, assigned)?;
                }
                Ok(Flow::Normal)
            }
            LStmt::IncDec { target, delta } => {
                let current: Val = self.read_lvalue(target)?;
                let n: i64 = to_int(&current)?;
                let next: i64 = n.checked_add(*delta).ok_or(Abstain::OutOfRange)?;
                self.assign(target, AssignOp::Set, Val::Int(next))?;
                Ok(Flow::Normal)
            }
            LStmt::Block(body) => self.exec_all(body),
            LStmt::If { cond, then, other } => {
                if to_bool(&self.eval(cond, 0)?) {
                    return self.exec(then);
                }
                other
                    .as_deref()
                    .map_or(Ok(Flow::Normal), |branch: &LStmt| self.exec(branch))
            }
            LStmt::For {
                init,
                cond,
                step,
                body,
            } => self.exec_for(init, cond.as_ref(), step, body),
            LStmt::While { cond, body } => self.exec_while(cond, body),
            LStmt::DoWhile { body, cond } => self.exec_do_while(body, cond),
            LStmt::Foreach {
                subject,
                key,
                value,
                body,
            } => self.exec_foreach(subject, key.as_deref(), value, body),
            LStmt::Break(levels) => Ok(Flow::Break(*levels)),
            LStmt::Continue(levels) => Ok(Flow::Continue(*levels)),
            LStmt::Return(value) => match value {
                Some(expr) => {
                    let evaluated: Val = self.eval(expr, 0)?;
                    Ok(Flow::Return(evaluated))
                }
                None => Ok(Flow::Return(Val::Str(Vec::new()))),
            },
        }
    }

    fn exec_for(
        &mut self,
        init: &[LStmt],
        cond: Option<&LExpr>,
        step: &[LStmt],
        body: &LStmt,
    ) -> Eval<Flow> {
        self.enter_loop()?;
        self.exec_all(init)?;
        loop {
            self.tick()?;
            if let Some(test) = cond
                && !to_bool(&self.eval(test, 0)?)
            {
                return Ok(Flow::Normal);
            }
            match self.exec(body)? {
                Flow::Normal | Flow::Continue(1) => {}
                Flow::Break(1) => return Ok(Flow::Normal),
                Flow::Break(n) => return Ok(Flow::Break(n - 1)),
                Flow::Continue(n) => return Ok(Flow::Continue(n - 1)),
                Flow::Return(value) => return Ok(Flow::Return(value)),
            }
            self.exec_all(step)?;
        }
    }

    fn exec_while(&mut self, cond: &LExpr, body: &LStmt) -> Eval<Flow> {
        self.enter_loop()?;
        loop {
            self.tick()?;
            if !to_bool(&self.eval(cond, 0)?) {
                return Ok(Flow::Normal);
            }
            match self.exec(body)? {
                Flow::Normal | Flow::Continue(1) => {}
                Flow::Break(1) => return Ok(Flow::Normal),
                Flow::Break(n) => return Ok(Flow::Break(n - 1)),
                Flow::Continue(n) => return Ok(Flow::Continue(n - 1)),
                Flow::Return(value) => return Ok(Flow::Return(value)),
            }
        }
    }

    fn exec_do_while(&mut self, body: &LStmt, cond: &LExpr) -> Eval<Flow> {
        self.enter_loop()?;
        loop {
            self.tick()?;
            match self.exec(body)? {
                Flow::Normal | Flow::Continue(1) => {}
                Flow::Break(1) => return Ok(Flow::Normal),
                Flow::Break(n) => return Ok(Flow::Break(n - 1)),
                Flow::Continue(n) => return Ok(Flow::Continue(n - 1)),
                Flow::Return(value) => return Ok(Flow::Return(value)),
            }
            if !to_bool(&self.eval(cond, 0)?) {
                return Ok(Flow::Normal);
            }
        }
    }

    fn exec_foreach(
        &mut self,
        subject: &LExpr,
        key: Option<&[u8]>,
        value: &[u8],
        body: &LStmt,
    ) -> Eval<Flow> {
        self.enter_loop()?;
        let items: Vec<(i64, Val)> = match self.eval(subject, 0)? {
            Val::Arr(map) => map.into_iter().collect(),
            Val::Str(_) | Val::Int(_) | Val::Float(_) => return Err(Abstain::TypeMismatch),
        };
        for (k, v) in items {
            self.tick()?;
            if let Some(key_name) = key {
                self.bind(key_name.to_vec(), Val::Int(k))?;
            }
            self.bind(value.to_vec(), v)?;
            match self.exec(body)? {
                Flow::Normal | Flow::Continue(1) => {}
                Flow::Break(1) => return Ok(Flow::Normal),
                Flow::Break(n) => return Ok(Flow::Break(n - 1)),
                Flow::Continue(n) => return Ok(Flow::Continue(n - 1)),
                Flow::Return(value) => return Ok(Flow::Return(value)),
            }
        }
        Ok(Flow::Normal)
    }

    fn read_lvalue(&mut self, target: &LValue) -> Eval<Val> {
        match target {
            LValue::Var(name) => self.scope.get(name).cloned().ok_or(Abstain::UndefinedRead),
            LValue::Index { name, idx } => {
                let Some(index_expr): Option<&LExpr> = idx.as_ref() else {
                    return Err(Abstain::Unsupported);
                };
                let key: i64 = to_int(&self.eval(index_expr, 0)?)?;
                let container: &Val = self.scope.get(name).ok_or(Abstain::UndefinedRead)?;
                index_value(container, key)
            }
        }
    }

    fn assign(&mut self, target: &LValue, op: AssignOp, rhs: Val) -> Eval<()> {
        let value: Val = if matches!(op, AssignOp::Set) {
            rhs
        } else {
            let current: Val = self.read_lvalue(target)?;
            apply_binary(assign_op_to_binary(op), &current, &rhs)?
        };
        if let Val::Str(bytes) = &value {
            self.check_size(bytes.len())?;
        }
        match target {
            LValue::Var(name) => self.bind(name.clone(), value),
            LValue::Index { name, idx } => {
                let key: Option<i64> = match idx {
                    Some(expr) => Some(to_int(&self.eval(expr, 0)?)?),
                    None => None,
                };
                let slot: &mut Val = self
                    .scope
                    .entry(name.clone())
                    .or_insert_with(|| Val::Arr(BTreeMap::new()));
                let Val::Arr(map) = slot else {
                    return Err(Abstain::TypeMismatch);
                };
                let key: i64 = key.unwrap_or_else(|| {
                    map.keys()
                        .next_back()
                        .map_or(0, |k: &i64| k.saturating_add(1))
                });
                let added: usize = val_size(&value).saturating_add(ARRAY_SLOT_OVERHEAD);
                let removed: usize = map.insert(key, value).map_or(0, |old: Val| {
                    val_size(&old).saturating_add(ARRAY_SLOT_OVERHEAD)
                });
                self.live_bytes = self
                    .live_bytes
                    .saturating_sub(removed)
                    .saturating_add(added);
                self.check_heap()
            }
        }
    }

    fn eval(&mut self, expr: &LExpr, depth: u32) -> Eval<Val> {
        self.tick()?;
        if depth > self.budget.expr_depth {
            return Err(Abstain::DepthBudget);
        }
        match expr {
            LExpr::Int(n) => Ok(Val::Int(*n)),
            LExpr::Str(s) => Ok(Val::Str(s.clone())),
            LExpr::Var(name) => self.scope.get(name).cloned().ok_or(Abstain::UndefinedRead),
            LExpr::Const(name) => self
                .constants
                .get(name)
                .cloned()
                .ok_or(Abstain::UndefinedRead),
            LExpr::Index { base, idx } => {
                let container: Val = self.eval(base, depth + 1)?;
                let key: i64 = to_int(&self.eval(idx, depth + 1)?)?;
                index_value(&container, key)
            }
            LExpr::Unary { op, operand } => {
                let value: Val = self.eval(operand, depth + 1)?;
                apply_unary(*op, &value)
            }
            LExpr::Bin { op, lhs, rhs } => {
                if matches!(op, BinOp::LogicAnd | BinOp::LogicOr) {
                    let left: bool = to_bool(&self.eval(lhs, depth + 1)?);
                    let short_circuit: bool = matches!(op, BinOp::LogicOr);
                    if left == short_circuit {
                        return Ok(Val::Int(i64::from(left)));
                    }
                    let right: bool = to_bool(&self.eval(rhs, depth + 1)?);
                    return Ok(Val::Int(i64::from(right)));
                }
                let left: Val = self.eval(lhs, depth + 1)?;
                let right: Val = self.eval(rhs, depth + 1)?;
                let out: Val = apply_binary(*op, &left, &right)?;
                if let Val::Str(bytes) = &out {
                    self.check_size(bytes.len())?;
                }
                Ok(out)
            }
            LExpr::Ternary { cond, then, other } => {
                if to_bool(&self.eval(cond, depth + 1)?) {
                    self.eval(then, depth + 1)
                } else {
                    self.eval(other, depth + 1)
                }
            }
            LExpr::Assign { target, value } => {
                let evaluated: Val = self.eval(value, depth + 1)?;
                self.assign(target, AssignOp::Set, evaluated.clone())?;
                Ok(evaluated)
            }
            LExpr::ArrayLit(items) => {
                let mut map: BTreeMap<i64, Val> = BTreeMap::new();
                for (i, item) in items.iter().enumerate() {
                    let value: Val = self.eval(item, depth + 1)?;
                    map.insert(i64::try_from(i).map_err(|_| Abstain::OutOfRange)?, value);
                }
                Ok(Val::Arr(map))
            }
            LExpr::Call { name, args } => self.dispatch_call(name, args, depth),
            LExpr::DynCall { callee, args } => {
                let name: Vec<u8> = to_bytes(&self.eval(callee, depth + 1)?)?.to_ascii_lowercase();
                self.dispatch_call(&name, args, depth)
            }
        }
    }

    fn dispatch_call(&mut self, name: &[u8], args: &[LExpr], depth: u32) -> Eval<Val> {
        if self.refused_names.contains(name) {
            return Err(Abstain::RefusedCall);
        }
        let user_defined: bool = self.functions.contains_key(name);
        if !user_defined && !PURE_BUILTINS.contains(&name) {
            return Err(Abstain::RefusedCall);
        }
        let mut values: Vec<Val> = Vec::with_capacity(args.len());
        for arg in args {
            values.push(self.eval(arg, depth + 1)?);
        }
        let out: Val = if user_defined {
            self.call_function(name, &values)?
        } else {
            self.call_builtin(name, &values)?
        };
        if let Val::Str(bytes) = &out {
            self.check_size(bytes.len())?;
        }
        Ok(out)
    }

    fn pack_values(&mut self, code: PackCode, repeat: PackRepeat, args: &[Val]) -> Eval<Val> {
        let first: Eval<&Val> = args.first().ok_or(Abstain::Unsupported);
        if matches!(code, PackCode::HexHigh | PackCode::HexLow) {
            if repeat != PackRepeat::All {
                return Err(Abstain::Unsupported);
            }
            let digits: Vec<u8> = to_bytes(first?)?;
            let packed: Vec<u8> =
                pack_hex(&digits, code == PackCode::HexLow).ok_or(Abstain::TypeMismatch)?;
            self.check_size(packed.len())?;
            return Ok(Val::Str(packed));
        }
        if matches!(code, PackCode::StringNull | PackCode::StringSpace) {
            if repeat != PackRepeat::All {
                return Err(Abstain::Unsupported);
            }
            return Ok(Val::Str(to_bytes(first?)?));
        }
        let width: usize = numeric_width(code);
        let wanted: usize = match repeat {
            PackRepeat::All => args.len(),
            PackRepeat::Count(n) => n,
        };
        if args.len() != wanted {
            return Err(Abstain::Unsupported);
        }
        let mut out: Vec<u8> = Vec::with_capacity(wanted.saturating_mul(width));
        for value in args {
            self.tick()?;
            let n: i64 = to_int(value)?;
            let wrapped: u32 = (n as u64 & u64::from(u32::MAX)) as u32;
            match code {
                PackCode::ByteUnsigned | PackCode::ByteSigned => out.push(wrapped as u8),
                PackCode::U16Be => out.extend_from_slice(&(wrapped as u16).to_be_bytes()),
                PackCode::U16Le => out.extend_from_slice(&(wrapped as u16).to_le_bytes()),
                PackCode::U32Be => out.extend_from_slice(&wrapped.to_be_bytes()),
                PackCode::U32Le => out.extend_from_slice(&wrapped.to_le_bytes()),
                PackCode::HexHigh
                | PackCode::HexLow
                | PackCode::StringNull
                | PackCode::StringSpace => return Err(Abstain::Unsupported),
            }
            self.check_size(out.len())?;
        }
        Ok(Val::Str(out))
    }

    fn unpack_values(&mut self, code: PackCode, repeat: PackRepeat, body: &[u8]) -> Eval<Val> {
        let mut map: BTreeMap<i64, Val> = BTreeMap::new();
        match code {
            PackCode::HexHigh | PackCode::HexLow => {
                if repeat != PackRepeat::All {
                    return Err(Abstain::Unsupported);
                }
                let hex: Vec<u8> = unpack_hex(body, code == PackCode::HexLow);
                self.check_size(hex.len())?;
                map.insert(1, Val::Str(hex));
            }
            PackCode::StringNull => {
                if repeat != PackRepeat::All {
                    return Err(Abstain::Unsupported);
                }
                map.insert(1, Val::Str(body.to_vec()));
            }
            PackCode::StringSpace => {
                if repeat != PackRepeat::All {
                    return Err(Abstain::Unsupported);
                }
                let trimmed: &[u8] = trim_end_pad(body);
                map.insert(1, Val::Str(trimmed.to_vec()));
            }
            PackCode::ByteUnsigned
            | PackCode::ByteSigned
            | PackCode::U16Be
            | PackCode::U16Le
            | PackCode::U32Be
            | PackCode::U32Le => {
                let width: usize = numeric_width(code);
                let available: usize = body.len() / width;
                let wanted: usize = match repeat {
                    PackRepeat::All => available,
                    PackRepeat::Count(n) => n,
                };
                if wanted > available {
                    return Err(Abstain::OutOfRange);
                }
                for index in 0..wanted {
                    self.tick()?;
                    let at: usize = index.checked_mul(width).ok_or(Abstain::OutOfRange)?;
                    let slot: &[u8] = body.get(at..at + width).ok_or(Abstain::OutOfRange)?;
                    map.insert(
                        i64::try_from(index).map_err(|_| Abstain::OutOfRange)? + 1,
                        Val::Int(read_numeric(code, slot)?),
                    );
                }
            }
        }
        self.check_heap()?;
        Ok(Val::Arr(map))
    }

    fn openssl_decrypt(&mut self, args: &[Val]) -> Eval<Val> {
        if args.len() > OPENSSL_MAX_ARGS {
            return Err(Abstain::Unsupported);
        }
        let data: Vec<u8> = to_bytes(args.first().ok_or(Abstain::Unsupported)?)?;
        let algorithm: Vec<u8> = to_bytes(args.get(1).ok_or(Abstain::Unsupported)?)?;
        let passphrase: Vec<u8> = to_bytes(args.get(2).ok_or(Abstain::Unsupported)?)?;
        let options: i64 = match args.get(3) {
            Some(value) => to_int(value)?,
            None => 0,
        };
        let vector: Vec<u8> = match args.get(4) {
            Some(value) => to_bytes(value)?,
            None => Vec::new(),
        };
        let (key_len, mode): (usize, AesMode) =
            aes_algorithm(&algorithm).ok_or(Abstain::Unsupported)?;
        let ciphertext: Vec<u8> = if options & OPENSSL_RAW_DATA == 0 {
            let clean: Vec<u8> = data
                .into_iter()
                .filter(|b: &u8| !b.is_ascii_whitespace())
                .collect();
            B64_STD.decode(&clean).map_err(|_| Abstain::TypeMismatch)?
        } else {
            data
        };
        self.check_size(ciphertext.len())?;
        if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(AES_BLOCK_LEN) {
            return Err(Abstain::OutOfRange);
        }
        let key: Vec<u8> = zero_extended(&passphrase, key_len);
        let padding: CbcPadding = if options & OPENSSL_ZERO_PADDING == 0 {
            CbcPadding::Pkcs7
        } else {
            CbcPadding::NoPadding
        };
        let plain: Vec<u8> = match mode {
            AesMode::Cbc => {
                let iv: Vec<u8> = zero_extended(&vector, AES_BLOCK_LEN);
                aes_cbc_decrypt(&key, &iv, &ciphertext, padding)
                    .map_err(|_| Abstain::TypeMismatch)?
            }
            AesMode::Ecb => {
                let blocks: usize = ciphertext.len() / AES_BLOCK_LEN;
                let mut out: Vec<u8> = Vec::with_capacity(ciphertext.len());
                for (index, block) in ciphertext.chunks(AES_BLOCK_LEN).enumerate() {
                    self.tick()?;
                    let step: CbcPadding = if index + 1 == blocks {
                        padding
                    } else {
                        CbcPadding::NoPadding
                    };
                    let decrypted: Vec<u8> = aes_cbc_decrypt(&key, &ECB_VECTOR, block, step)
                        .map_err(|_| Abstain::TypeMismatch)?;
                    out.extend_from_slice(&decrypted);
                }
                out
            }
        };
        self.check_size(plain.len())?;
        Ok(Val::Str(plain))
    }

    fn call_builtin(&mut self, name: &[u8], args: &[Val]) -> Eval<Val> {
        let arg0: Eval<&Val> = args.first().ok_or(Abstain::Unsupported);
        match name {
            b"strlen" => {
                let s: Vec<u8> = to_bytes(arg0?)?;
                Ok(Val::Int(
                    i64::try_from(s.len()).map_err(|_| Abstain::OutOfRange)?,
                ))
            }
            b"count" | b"sizeof" => match arg0? {
                Val::Arr(map) => Ok(Val::Int(
                    i64::try_from(map.len()).map_err(|_| Abstain::OutOfRange)?,
                )),
                Val::Str(_) | Val::Int(_) | Val::Float(_) => Err(Abstain::TypeMismatch),
            },
            b"ord" => {
                let s: Vec<u8> = to_bytes(arg0?)?;
                Ok(Val::Int(i64::from(s.first().copied().unwrap_or(0))))
            }
            b"chr" => {
                let n: i64 = to_int(arg0?)?;
                let byte: u8 = u8::try_from(n.rem_euclid(256)).map_err(|_| Abstain::OutOfRange)?;
                Ok(Val::Str(vec![byte]))
            }
            b"abs" => Ok(Val::Int(
                to_int(arg0?)?.checked_abs().ok_or(Abstain::OutOfRange)?,
            )),
            b"intval" => Ok(Val::Int(to_int(arg0?)?)),
            b"min" | b"max" => {
                let mut best: i64 = to_int(arg0?)?;
                for value in args.iter().skip(1) {
                    let n: i64 = to_int(value)?;
                    best = if name == b"min" {
                        best.min(n)
                    } else {
                        best.max(n)
                    };
                }
                Ok(Val::Int(best))
            }
            b"dechex" => Ok(Val::Str(format!("{:x}", to_int(arg0?)?).into_bytes())),
            b"hexdec" => {
                let s: Vec<u8> = to_bytes(arg0?)?;
                let text: &str = std::str::from_utf8(&s).map_err(|_| Abstain::TypeMismatch)?;
                i64::from_str_radix(text.trim(), 16)
                    .map(Val::Int)
                    .map_err(|_| Abstain::TypeMismatch)
            }
            b"base64_decode" => {
                let s: Vec<u8> = to_bytes(arg0?)?;
                let clean: Vec<u8> = s
                    .into_iter()
                    .filter(|b: &u8| !b.is_ascii_whitespace())
                    .collect();
                B64_STD
                    .decode(&clean)
                    .map(Val::Str)
                    .map_err(|_| Abstain::TypeMismatch)
            }
            b"base64_encode" => Ok(Val::Str(B64_STD.encode(to_bytes(arg0?)?).into_bytes())),
            b"gzinflate" => inflate_raw(&to_bytes(arg0?)?)
                .map(Val::Str)
                .ok_or(Abstain::TypeMismatch),
            b"gzuncompress" => inflate_zlib(&to_bytes(arg0?)?)
                .map(Val::Str)
                .ok_or(Abstain::TypeMismatch),
            b"gzdecode" => gunzip(&to_bytes(arg0?)?)
                .map(Val::Str)
                .ok_or(Abstain::TypeMismatch),
            b"bzdecompress" => bzdecompress_bounded(&to_bytes(arg0?)?)
                .map(Val::Str)
                .ok_or(Abstain::TypeMismatch),
            b"str_rot13" => Ok(Val::Str(
                to_bytes(arg0?)?.into_iter().map(rot13_byte).collect(),
            )),
            b"strrev" => Ok(Val::Str(to_bytes(arg0?)?.into_iter().rev().collect())),
            b"strtolower" => Ok(Val::Str(to_bytes(arg0?)?.to_ascii_lowercase())),
            b"strtoupper" => Ok(Val::Str(to_bytes(arg0?)?.to_ascii_uppercase())),
            b"trim" | b"ltrim" | b"rtrim" => {
                let s: Vec<u8> = to_bytes(arg0?)?;
                let trimmed: &[u8] = match name {
                    b"ltrim" => s.trim_ascii_start(),
                    b"rtrim" => s.trim_ascii_end(),
                    _ => s.trim_ascii(),
                };
                Ok(Val::Str(trimmed.to_vec()))
            }
            b"convert_uudecode" => Ok(Val::Str(uudecode(&to_bytes(arg0?)?))),
            b"urldecode" => Ok(Val::Str(
                disrobe_core::codec::web_escape::percent_decode_lenient(
                    &to_bytes(arg0?)?,
                    disrobe_core::codec::web_escape::PlusPolicy::Space,
                ),
            )),
            b"rawurldecode" => Ok(Val::Str(
                disrobe_core::codec::web_escape::percent_decode_lenient(
                    &to_bytes(arg0?)?,
                    disrobe_core::codec::web_escape::PlusPolicy::Literal,
                ),
            )),
            b"hex2bin" => decode_hex_stream_skip_ws(&to_bytes(arg0?)?)
                .map(Val::Str)
                .ok_or(Abstain::TypeMismatch),
            b"bin2hex" => Ok(Val::Str(bin2hex(&to_bytes(arg0?)?))),
            b"md5" | b"sha1" => {
                if !(1..=2).contains(&args.len()) {
                    return Err(Abstain::Unsupported);
                }
                let input: Vec<u8> = to_bytes(arg0?)?;
                let raw_output: bool = match args.get(1) {
                    Some(Val::Arr(_)) => return Err(Abstain::TypeMismatch),
                    Some(value) => to_bool(value),
                    None => false,
                };
                let digest: Vec<u8> = match name {
                    b"md5" => md5_digest(&input).to_vec(),
                    b"sha1" => sha1_digest(&input).to_vec(),
                    _ => return Err(Abstain::RefusedCall),
                };
                let output: Vec<u8> = if raw_output { digest } else { bin2hex(&digest) };
                self.check_size(output.len())?;
                Ok(Val::Str(output))
            }
            b"html_entity_decode" | b"htmlspecialchars_decode" => {
                Ok(Val::Str(html_entity_decode(&to_bytes(arg0?)?)))
            }
            b"pack" => {
                let (code, repeat): (PackCode, PackRepeat) =
                    parse_pack_format(&to_bytes(arg0?)?).ok_or(Abstain::Unsupported)?;
                self.pack_values(code, repeat, args.get(1..).unwrap_or_default())
            }
            b"unpack" => {
                let (code, repeat): (PackCode, PackRepeat) =
                    parse_pack_format(&to_bytes(arg0?)?).ok_or(Abstain::Unsupported)?;
                let body: Vec<u8> = to_bytes(args.get(1).ok_or(Abstain::Unsupported)?)?;
                self.unpack_values(code, repeat, &body)
            }
            b"substr" => {
                let s: Vec<u8> = to_bytes(arg0?)?;
                let start: i64 = to_int(args.get(1).ok_or(Abstain::Unsupported)?)?;
                let len: Option<i64> = match args.get(2) {
                    Some(value) => Some(to_int(value)?),
                    None => None,
                };
                Ok(Val::Str(substr(&s, start, len)))
            }
            b"str_repeat" => {
                let s: Vec<u8> = to_bytes(arg0?)?;
                let times: i64 = to_int(args.get(1).ok_or(Abstain::Unsupported)?)?;
                str_repeat(&s, times)
                    .map(Val::Str)
                    .ok_or(Abstain::OutputBudget)
            }
            b"str_replace" => {
                let from: Vec<u8> = to_bytes(arg0?)?;
                let to: Vec<u8> = to_bytes(args.get(1).ok_or(Abstain::Unsupported)?)?;
                let subject: Vec<u8> = to_bytes(args.get(2).ok_or(Abstain::Unsupported)?)?;
                str_replace_bytes(&subject, &from, &to)
                    .map(Val::Str)
                    .ok_or(Abstain::OutputBudget)
            }
            b"strtr" => {
                let subject: Vec<u8> = to_bytes(arg0?)?;
                let from: Vec<u8> = to_bytes(args.get(1).ok_or(Abstain::Unsupported)?)?;
                let to: Vec<u8> = to_bytes(args.get(2).ok_or(Abstain::Unsupported)?)?;
                Ok(Val::Str(strtr_bytes(&subject, &from, &to)))
            }
            b"str_split" => {
                let s: Vec<u8> = to_bytes(arg0?)?;
                let size: i64 = match args.get(1) {
                    Some(value) => to_int(value)?,
                    None => 1,
                };
                let width: usize = usize::try_from(size).map_err(|_| Abstain::OutOfRange)?;
                if width == 0 {
                    return Err(Abstain::OutOfRange);
                }
                let mut map: BTreeMap<i64, Val> = BTreeMap::new();
                for (i, chunk) in s.chunks(width).enumerate() {
                    map.insert(
                        i64::try_from(i).map_err(|_| Abstain::OutOfRange)?,
                        Val::Str(chunk.to_vec()),
                    );
                }
                Ok(Val::Arr(map))
            }
            b"implode" | b"join" => {
                let (glue, list): (Vec<u8>, &Val) = match (args.first(), args.get(1)) {
                    (Some(Val::Arr(_)), None) => (Vec::new(), arg0?),
                    (Some(sep), Some(list)) => (to_bytes(sep)?, list),
                    _ => return Err(Abstain::Unsupported),
                };
                let Val::Arr(map) = list else {
                    return Err(Abstain::TypeMismatch);
                };
                let mut out: Vec<u8> = Vec::new();
                for (i, value) in map.values().enumerate() {
                    if i > 0 {
                        out.extend_from_slice(&glue);
                    }
                    out.extend_from_slice(&to_bytes(value)?);
                    self.check_size(out.len())?;
                }
                Ok(Val::Str(out))
            }
            b"define" => {
                let key: Vec<u8> = to_bytes(arg0?)?;
                let value: Val = args.get(1).ok_or(Abstain::Unsupported)?.clone();
                self.bind_constant(key, value)?;
                Ok(Val::Int(1))
            }
            b"defined" => {
                let key: Vec<u8> = to_bytes(arg0?)?;
                Ok(Val::Int(i64::from(self.constants.contains_key(&key))))
            }
            b"constant" => {
                let key: Vec<u8> = to_bytes(arg0?)?;
                self.constants
                    .get(&key)
                    .cloned()
                    .ok_or(Abstain::UndefinedRead)
            }
            b"openssl_decrypt" => self.openssl_decrypt(args),
            b"range" => {
                let from: i64 = to_int(arg0?)?;
                let to: i64 = to_int(args.get(1).ok_or(Abstain::Unsupported)?)?;
                let span: u64 = from.abs_diff(to);
                if span >= u64::try_from(self.budget.output_bytes).unwrap_or(u64::MAX) {
                    return Err(Abstain::OutputBudget);
                }
                let step: i64 = if to >= from { 1 } else { -1 };
                let mut map: BTreeMap<i64, Val> = BTreeMap::new();
                let mut current: i64 = from;
                let mut index: i64 = 0;
                loop {
                    self.tick()?;
                    map.insert(index, Val::Int(current));
                    if current == to {
                        break;
                    }
                    current = current.checked_add(step).ok_or(Abstain::OutOfRange)?;
                    index = index.checked_add(1).ok_or(Abstain::OutOfRange)?;
                }
                Ok(Val::Arr(map))
            }
            _ => Err(Abstain::RefusedCall),
        }
    }
}

const ARRAY_SLOT_OVERHEAD: usize = 16;

fn scope_size(scope: &BTreeMap<Vec<u8>, Val>) -> usize {
    scope.values().fold(0usize, |acc: usize, item: &Val| {
        acc.saturating_add(val_size(item))
    })
}

fn val_size(value: &Val) -> usize {
    match value {
        Val::Int(_) => size_of::<i64>(),
        Val::Float(_) => size_of::<f64>(),
        Val::Str(bytes) => bytes.len(),
        Val::Arr(map) => map.values().fold(0usize, |acc: usize, item: &Val| {
            acc.saturating_add(val_size(item))
                .saturating_add(ARRAY_SLOT_OVERHEAD)
        }),
    }
}

const ASSIGN_OPS: &[(&[u8], AssignOp)] = &[
    (b"<<=", AssignOp::Shl),
    (b">>=", AssignOp::Shr),
    (b".=", AssignOp::Concat),
    (b"+=", AssignOp::Add),
    (b"-=", AssignOp::Sub),
    (b"*=", AssignOp::Mul),
    (b"/=", AssignOp::Div),
    (b"%=", AssignOp::Mod),
    (b"^=", AssignOp::BitXor),
    (b"&=", AssignOp::BitAnd),
    (b"|=", AssignOp::BitOr),
];

const UNARY_OPS: &[(u8, UnOp)] = &[
    (b'!', UnOp::Not),
    (b'~', UnOp::BitNot),
    (b'-', UnOp::Neg),
    (b'+', UnOp::Plus),
];

const PURE_BUILTINS: &[&[u8]] = &[
    b"abs",
    b"base64_decode",
    b"base64_encode",
    b"bin2hex",
    b"bzdecompress",
    b"chr",
    b"constant",
    b"convert_uudecode",
    b"count",
    b"dechex",
    b"define",
    b"defined",
    b"gzdecode",
    b"gzinflate",
    b"gzuncompress",
    b"hex2bin",
    b"hexdec",
    b"html_entity_decode",
    b"htmlspecialchars_decode",
    b"implode",
    b"intval",
    b"join",
    b"ltrim",
    b"max",
    b"md5",
    b"min",
    b"openssl_decrypt",
    b"ord",
    b"pack",
    b"range",
    b"rawurldecode",
    b"rtrim",
    b"sha1",
    b"sizeof",
    b"str_repeat",
    b"str_replace",
    b"str_rot13",
    b"str_split",
    b"strlen",
    b"strrev",
    b"strtolower",
    b"strtoupper",
    b"strtr",
    b"substr",
    b"trim",
    b"unpack",
    b"urldecode",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackCode {
    HexHigh,
    HexLow,
    ByteUnsigned,
    ByteSigned,
    StringNull,
    StringSpace,
    U16Be,
    U16Le,
    U32Be,
    U32Le,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackRepeat {
    All,
    Count(usize),
}

fn parse_pack_format(fmt: &[u8]) -> Option<(PackCode, PackRepeat)> {
    let (head, rest): (&u8, &[u8]) = fmt.trim_ascii().split_first()?;
    let code: PackCode = match head {
        b'H' => PackCode::HexHigh,
        b'h' => PackCode::HexLow,
        b'C' => PackCode::ByteUnsigned,
        b'c' => PackCode::ByteSigned,
        b'a' => PackCode::StringNull,
        b'A' => PackCode::StringSpace,
        b'n' => PackCode::U16Be,
        b'v' => PackCode::U16Le,
        b'N' => PackCode::U32Be,
        b'V' => PackCode::U32Le,
        _ => return None,
    };
    let repeat: PackRepeat = match rest {
        [] => PackRepeat::Count(1),
        [b'*'] => PackRepeat::All,
        digits if digits.iter().all(u8::is_ascii_digit) => PackRepeat::Count(
            std::str::from_utf8(digits)
                .ok()
                .and_then(|text: &str| text.parse::<usize>().ok())?,
        ),
        _ => return None,
    };
    Some((code, repeat))
}

const fn numeric_width(code: PackCode) -> usize {
    match code {
        PackCode::U32Be | PackCode::U32Le => 4,
        PackCode::U16Be | PackCode::U16Le => 2,
        PackCode::ByteUnsigned
        | PackCode::ByteSigned
        | PackCode::HexHigh
        | PackCode::HexLow
        | PackCode::StringNull
        | PackCode::StringSpace => 1,
    }
}

fn read_numeric(code: PackCode, slot: &[u8]) -> Eval<i64> {
    let head: u8 = slot.first().copied().ok_or(Abstain::OutOfRange)?;
    match code {
        PackCode::ByteUnsigned => Ok(i64::from(head)),
        PackCode::ByteSigned => Ok(i64::from(head as i8)),
        PackCode::U16Be | PackCode::U16Le => {
            let pair: [u8; 2] = slot.try_into().map_err(|_| Abstain::OutOfRange)?;
            let value: u16 = if code == PackCode::U16Be {
                u16::from_be_bytes(pair)
            } else {
                u16::from_le_bytes(pair)
            };
            Ok(i64::from(value))
        }
        PackCode::U32Be | PackCode::U32Le => {
            let quad: [u8; 4] = slot.try_into().map_err(|_| Abstain::OutOfRange)?;
            let value: u32 = if code == PackCode::U32Be {
                u32::from_be_bytes(quad)
            } else {
                u32::from_le_bytes(quad)
            };
            Ok(i64::from(value))
        }
        PackCode::HexHigh | PackCode::HexLow | PackCode::StringNull | PackCode::StringSpace => {
            Err(Abstain::Unsupported)
        }
    }
}

fn pack_hex(digits: &[u8], swapped: bool) -> Option<Vec<u8>> {
    if !swapped {
        return decode_hex_stream_skip_ws(digits);
    }
    let plain: Vec<u8> = decode_hex_stream_skip_ws(digits)?;
    Some(
        plain
            .into_iter()
            .map(|b: u8| b.rotate_left(4))
            .collect::<Vec<u8>>(),
    )
}

fn unpack_hex(body: &[u8], swapped: bool) -> Vec<u8> {
    if swapped {
        let flipped: Vec<u8> = body.iter().map(|b: &u8| b.rotate_left(4)).collect();
        return bin2hex(&flipped);
    }
    bin2hex(body)
}

fn trim_end_pad(body: &[u8]) -> &[u8] {
    let mut end: usize = body.len();
    while end > 0
        && body
            .get(end - 1)
            .is_some_and(|b: &u8| *b == 0 || b.is_ascii_whitespace())
    {
        end -= 1;
    }
    body.get(..end).unwrap_or(body)
}

const OPENSSL_RAW_DATA: i64 = 1;
const OPENSSL_ZERO_PADDING: i64 = 2;
const OPENSSL_MAX_ARGS: usize = 5;
const AES_BLOCK_LEN: usize = 16;
const ECB_VECTOR: [u8; AES_BLOCK_LEN] = [0u8; AES_BLOCK_LEN];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AesMode {
    Cbc,
    Ecb,
}

fn aes_algorithm(name: &[u8]) -> Option<(usize, AesMode)> {
    match name.to_ascii_lowercase().as_slice() {
        b"aes-128-cbc" => Some((16, AesMode::Cbc)),
        b"aes-192-cbc" => Some((24, AesMode::Cbc)),
        b"aes-256-cbc" => Some((32, AesMode::Cbc)),
        b"aes-128-ecb" => Some((16, AesMode::Ecb)),
        b"aes-192-ecb" => Some((24, AesMode::Ecb)),
        b"aes-256-ecb" => Some((32, AesMode::Ecb)),
        _ => None,
    }
}

fn zero_extended(source: &[u8], width: usize) -> Vec<u8> {
    let mut out: Vec<u8> = vec![0u8; width];
    let take: usize = source.len().min(width);
    out[..take].copy_from_slice(&source[..take]);
    out
}

const RESERVED_WORDS: &[&[u8]] = &[
    b"abstract",
    b"and",
    b"array",
    b"as",
    b"break",
    b"callable",
    b"case",
    b"catch",
    b"class",
    b"clone",
    b"const",
    b"continue",
    b"declare",
    b"default",
    b"die",
    b"do",
    b"echo",
    b"else",
    b"elseif",
    b"empty",
    b"enddeclare",
    b"endfor",
    b"endforeach",
    b"endif",
    b"endswitch",
    b"endwhile",
    b"enum",
    b"eval",
    b"exit",
    b"extends",
    b"final",
    b"finally",
    b"fn",
    b"for",
    b"foreach",
    b"function",
    b"global",
    b"goto",
    b"if",
    b"implements",
    b"include",
    b"include_once",
    b"instanceof",
    b"insteadof",
    b"interface",
    b"isset",
    b"list",
    b"match",
    b"namespace",
    b"new",
    b"or",
    b"print",
    b"private",
    b"protected",
    b"public",
    b"readonly",
    b"require",
    b"require_once",
    b"return",
    b"static",
    b"switch",
    b"throw",
    b"trait",
    b"try",
    b"unset",
    b"use",
    b"var",
    b"while",
    b"xor",
    b"yield",
];

const PREDEFINED_CONSTANTS: &[(&[u8], i64)] = &[
    (b"OPENSSL_RAW_DATA", OPENSSL_RAW_DATA),
    (b"OPENSSL_ZERO_PADDING", OPENSSL_ZERO_PADDING),
    (
        b"OPENSSL_NO_PADDING",
        OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
    ),
];

fn literal_keyword(name: &[u8]) -> Option<LExpr> {
    if name.eq_ignore_ascii_case(b"true") {
        return Some(LExpr::Int(1));
    }
    if name.eq_ignore_ascii_case(b"false") || name.eq_ignore_ascii_case(b"null") {
        return Some(LExpr::Str(Vec::new()));
    }
    None
}

fn is_constant_expr(expr: &LExpr) -> bool {
    match expr {
        LExpr::Int(_) | LExpr::Str(_) | LExpr::Const(_) => true,
        LExpr::Index { base, idx }
        | LExpr::Bin {
            lhs: base,
            rhs: idx,
            ..
        } => is_constant_expr(base) && is_constant_expr(idx),
        LExpr::Unary { operand, .. } => is_constant_expr(operand),
        LExpr::Ternary { cond, then, other } => {
            is_constant_expr(cond) && is_constant_expr(then) && is_constant_expr(other)
        }
        LExpr::ArrayLit(elements) => elements.iter().all(is_constant_expr),
        LExpr::Var(_) | LExpr::Assign { .. } | LExpr::Call { .. } | LExpr::DynCall { .. } => false,
    }
}

fn is_reserved_word(name: &[u8]) -> bool {
    let lowered: Vec<u8> = name.to_ascii_lowercase();
    RESERVED_WORDS.contains(&lowered.as_slice())
}

fn index_value(container: &Val, key: i64) -> Eval<Val> {
    match container {
        Val::Arr(map) => map.get(&key).cloned().ok_or(Abstain::UndefinedRead),
        Val::Str(s) => {
            let len: i64 = i64::try_from(s.len()).map_err(|_| Abstain::OutOfRange)?;
            let offset: i64 = if key < 0 { len + key } else { key };
            if offset < 0 || offset >= len {
                return Err(Abstain::OutOfRange);
            }
            let at: usize = usize::try_from(offset).map_err(|_| Abstain::OutOfRange)?;
            s.get(at)
                .map(|b: &u8| Val::Str(vec![*b]))
                .ok_or(Abstain::OutOfRange)
        }
        Val::Int(_) | Val::Float(_) => Err(Abstain::TypeMismatch),
    }
}

const fn assign_op_to_binary(op: AssignOp) -> BinOp {
    match op {
        AssignOp::Set | AssignOp::Concat => BinOp::Concat,
        AssignOp::Add => BinOp::Add,
        AssignOp::Sub => BinOp::Sub,
        AssignOp::Mul => BinOp::Mul,
        AssignOp::Div => BinOp::Div,
        AssignOp::Mod => BinOp::Mod,
        AssignOp::BitXor => BinOp::BitXor,
        AssignOp::BitAnd => BinOp::BitAnd,
        AssignOp::BitOr => BinOp::BitOr,
        AssignOp::Shl => BinOp::Shl,
        AssignOp::Shr => BinOp::Shr,
    }
}

fn to_int(value: &Val) -> Eval<i64> {
    match value {
        Val::Int(n) => Ok(*n),
        Val::Float(f) => {
            let truncated: f64 = f.trunc();
            if !truncated.is_finite() || !I64_RANGE_AS_F64.contains(&truncated) {
                return Err(Abstain::OutOfRange);
            }
            Ok(truncated as i64)
        }
        Val::Str(s) => {
            let text: &str = std::str::from_utf8(s).map_err(|_| Abstain::TypeMismatch)?;
            let trimmed: &str = text.trim();
            if trimmed.is_empty() {
                return Ok(0);
            }
            trimmed.parse::<i64>().map_err(|_| Abstain::TypeMismatch)
        }
        Val::Arr(_) => Err(Abstain::TypeMismatch),
    }
}

const fn either_is_float(lhs: &Val, rhs: &Val) -> bool {
    matches!(lhs, Val::Float(_)) || matches!(rhs, Val::Float(_))
}

fn to_float(value: &Val) -> Eval<f64> {
    match value {
        Val::Float(f) => Ok(*f),
        Val::Int(n) => Ok(*n as f64),
        Val::Str(_) => to_int(value).map(|n: i64| n as f64),
        Val::Arr(_) => Err(Abstain::TypeMismatch),
    }
}

fn to_bytes(value: &Val) -> Eval<Vec<u8>> {
    match value {
        Val::Int(n) => Ok(n.to_string().into_bytes()),
        Val::Str(s) => Ok(s.clone()),
        Val::Float(_) | Val::Arr(_) => Err(Abstain::TypeMismatch),
    }
}

fn to_bool(value: &Val) -> bool {
    match value {
        Val::Int(n) => *n != 0,
        Val::Float(f) => *f != 0.0,
        Val::Str(s) => !s.is_empty() && s.as_slice() != b"0",
        Val::Arr(map) => !map.is_empty(),
    }
}

fn is_numeric(value: &Val) -> bool {
    match value {
        Val::Int(_) | Val::Float(_) => true,
        Val::Str(s) => std::str::from_utf8(s)
            .is_ok_and(|t: &str| !t.trim().is_empty() && t.trim().parse::<i64>().is_ok()),
        Val::Arr(_) => false,
    }
}

fn apply_unary(op: UnOp, value: &Val) -> Eval<Val> {
    match op {
        UnOp::Not => Ok(Val::Int(i64::from(!to_bool(value)))),
        UnOp::Neg => match value {
            Val::Float(f) => Ok(Val::Float(-*f)),
            _ => Ok(Val::Int(
                to_int(value)?.checked_neg().ok_or(Abstain::OutOfRange)?,
            )),
        },
        UnOp::Plus => match value {
            Val::Float(f) => Ok(Val::Float(*f)),
            _ => Ok(Val::Int(to_int(value)?)),
        },
        UnOp::BitNot => match value {
            Val::Str(s) => Ok(Val::Str(s.iter().map(|b: &u8| !*b).collect())),
            Val::Int(_) | Val::Float(_) => Ok(Val::Int(!to_int(value)?)),
            Val::Arr(_) => Err(Abstain::TypeMismatch),
        },
    }
}

fn apply_binary(op: BinOp, lhs: &Val, rhs: &Val) -> Eval<Val> {
    match op {
        BinOp::Concat => {
            let mut out: Vec<u8> = to_bytes(lhs)?;
            out.extend_from_slice(&to_bytes(rhs)?);
            Ok(Val::Str(out))
        }
        BinOp::BitXor | BinOp::BitAnd | BinOp::BitOr => bitwise(op, lhs, rhs),
        BinOp::Shl | BinOp::Shr => {
            let a: i64 = to_int(lhs)?;
            let b: i64 = to_int(rhs)?;
            if b.is_negative() {
                return Err(Abstain::OutOfRange);
            }
            if b >= 64 {
                let saturated: i64 =
                    i64::from(matches!(op, BinOp::Shr) && a.is_negative()).wrapping_neg();
                return Ok(Val::Int(saturated));
            }
            let b: u32 = u32::try_from(b).map_err(|_| Abstain::OutOfRange)?;
            let shifted: i64 = if matches!(op, BinOp::Shl) {
                a.wrapping_shl(b)
            } else {
                a.wrapping_shr(b)
            };
            Ok(Val::Int(shifted))
        }
        BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Mod => {
            let a: i64 = to_int(lhs)?;
            let b: i64 = to_int(rhs)?;
            let out: i64 = match op {
                BinOp::Add => a.checked_add(b).ok_or(Abstain::OutOfRange)?,
                BinOp::Sub => a.checked_sub(b).ok_or(Abstain::OutOfRange)?,
                BinOp::Mul => a.checked_mul(b).ok_or(Abstain::OutOfRange)?,
                BinOp::Div => {
                    if b == 0 {
                        return Err(Abstain::TypeMismatch);
                    }
                    if a % b != 0 {
                        return Ok(Val::Float(a as f64 / b as f64));
                    }
                    a.checked_div(b).ok_or(Abstain::OutOfRange)?
                }
                _ => {
                    if b == 0 {
                        return Err(Abstain::TypeMismatch);
                    }
                    a.checked_rem(b).ok_or(Abstain::OutOfRange)?
                }
            };
            Ok(Val::Int(out))
        }
        BinOp::Eq | BinOp::Ne | BinOp::Identical | BinOp::NotIdentical => {
            let equal: bool = match op {
                BinOp::Identical | BinOp::NotIdentical => lhs == rhs,
                _ if either_is_float(lhs, rhs) => {
                    to_float(lhs)?.partial_cmp(&to_float(rhs)?) == Some(std::cmp::Ordering::Equal)
                }
                _ if is_numeric(lhs) && is_numeric(rhs) => to_int(lhs)? == to_int(rhs)?,
                _ => to_bytes(lhs)? == to_bytes(rhs)?,
            };
            let negate: bool = matches!(op, BinOp::Ne | BinOp::NotIdentical);
            Ok(Val::Int(i64::from(equal != negate)))
        }
        BinOp::Lt | BinOp::Gt | BinOp::Le | BinOp::Ge => {
            let ordering: std::cmp::Ordering = if either_is_float(lhs, rhs) {
                to_float(lhs)?
                    .partial_cmp(&to_float(rhs)?)
                    .ok_or(Abstain::TypeMismatch)?
            } else if is_numeric(lhs) && is_numeric(rhs) {
                to_int(lhs)?.cmp(&to_int(rhs)?)
            } else {
                to_bytes(lhs)?.cmp(&to_bytes(rhs)?)
            };
            let holds: bool = match op {
                BinOp::Lt => ordering.is_lt(),
                BinOp::Gt => ordering.is_gt(),
                BinOp::Le => ordering.is_le(),
                _ => ordering.is_ge(),
            };
            Ok(Val::Int(i64::from(holds)))
        }
        BinOp::LogicAnd => Ok(Val::Int(i64::from(to_bool(lhs) && to_bool(rhs)))),
        BinOp::LogicOr => Ok(Val::Int(i64::from(to_bool(lhs) || to_bool(rhs)))),
    }
}

fn bitwise(op: BinOp, lhs: &Val, rhs: &Val) -> Eval<Val> {
    if let (Val::Str(a), Val::Str(b)) = (lhs, rhs) {
        let out: Vec<u8> = match op {
            BinOp::BitOr => {
                let width: usize = a.len().max(b.len());
                (0..width)
                    .map(|i: usize| a.get(i).copied().unwrap_or(0) | b.get(i).copied().unwrap_or(0))
                    .collect()
            }
            BinOp::BitAnd => a
                .iter()
                .zip(b.iter())
                .map(|(x, y): (&u8, &u8)| x & y)
                .collect(),
            _ => a
                .iter()
                .zip(b.iter())
                .map(|(x, y): (&u8, &u8)| x ^ y)
                .collect(),
        };
        return Ok(Val::Str(out));
    }
    let a: i64 = to_int(lhs)?;
    let b: i64 = to_int(rhs)?;
    let out: i64 = match op {
        BinOp::BitOr => a | b,
        BinOp::BitAnd => a & b,
        _ => a ^ b,
    };
    Ok(Val::Int(out))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn seeded(budget: Budget, seed: &[(&str, &[u8])]) -> Interp {
        let mut interp: Interp = Interp::new(budget);
        for (name, value) in seed {
            interp.observe_scalar(name.as_bytes(), value);
        }
        interp
    }

    fn run(src: &str, seed: &[(&str, &[u8])]) -> Option<BTreeMap<Vec<u8>, Vec<u8>>> {
        let mut parser: LoopParser<'_> = LoopParser::new(src.as_bytes());
        let program: Vec<LStmt> = parser.parse_program()?;
        let mut interp: Interp = seeded(Budget::default(), seed);
        interp.exec_all(&program).ok()?;
        Some(
            interp
                .scope
                .iter()
                .filter_map(|(k, v): (&Vec<u8>, &Val)| match v {
                    Val::Str(s) => Some((k.clone(), s.clone())),
                    Val::Int(_) | Val::Float(_) | Val::Arr(_) => None,
                })
                .collect(),
        )
    }

    fn abstain_of(src: &str, seed: &[(&str, &[u8])]) -> Option<Abstain> {
        let mut parser: LoopParser<'_> = LoopParser::new(src.as_bytes());
        let program: Vec<LStmt> = parser.parse_program()?;
        let mut interp: Interp = seeded(Budget::default(), seed);
        interp.exec_all(&program).err()
    }

    fn abstain_under(budget: Budget, src: &str) -> Option<Abstain> {
        let mut parser: LoopParser<'_> = LoopParser::new(src.as_bytes());
        let program: Vec<LStmt> = parser.parse_program()?;
        let mut interp: Interp = Interp::new(budget);
        interp.exec_all(&program).err()
    }

    fn out_of(src: &str, seed: &[(&str, &[u8])]) -> Vec<u8> {
        run(src, seed)
            .expect("program runs")
            .get(b"o".as_slice())
            .cloned()
            .expect("accumulator bound")
    }

    #[test]
    fn inexact_division_truncates_to_the_value_php_produces() {
        assert_eq!(
            out_of(
                "$o = chr(65 + intval(strlen($d) / 3));",
                &[("d", b"abcdefghij")]
            ),
            b"D".to_vec(),
            "php 8.4.24 evaluates chr(65 + intval(strlen($d) / 3)) to D for a ten byte subject"
        );
    }

    #[test]
    fn division_truncates_toward_zero_rather_than_flooring() {
        assert_eq!(
            out_of("$o = chr(70 + intval(-7 / 2));", &[]),
            b"C".to_vec(),
            "php truncates -3.5 toward zero to -3, so flooring to -4 would render B"
        );
    }

    #[test]
    fn exact_division_stays_an_integer() {
        assert_eq!(
            out_of("$o = chr(65 + 6 / 3);", &[]),
            b"C".to_vec(),
            "php returns int(2) rather than float(2.0) when the division is exact"
        );
    }

    #[test]
    fn bitwise_not_of_a_quotient_truncates_before_inverting() {
        assert_eq!(
            out_of("$o = chr(70 + ~(10 / 3));", &[]),
            b"B".to_vec(),
            "php truncates 3.3333333333333335 to 3 before inverting, giving -4"
        );
    }

    #[test]
    fn a_quotient_drives_a_per_byte_decode_loop() {
        assert_eq!(
            out_of(
                "$o=''; for($i=0;$i<strlen($d);$i++){ $o .= chr(intval(ord($d[$i]) / 2)); }",
                &[("d", b"abcdefghij")]
            ),
            hex_literal(b"30313132323333343435"),
            "each byte halves and truncates exactly as php does"
        );
    }

    #[test]
    fn a_quotient_compares_as_a_fraction_rather_than_as_its_truncation() {
        assert_eq!(
            out_of("$o = chr(65 + ((10 / 3) > 3));", &[]),
            b"B".to_vec(),
            "php holds 3.3333333333333335 > 3, so a quotient truncated to 3 before comparing would \
             render A"
        );
        assert_eq!(
            out_of("$o = chr(65 + ((10 / 3) == 3));", &[]),
            b"A".to_vec(),
            "php holds 3.3333333333333335 != 3, so a truncating comparison would render B"
        );
        assert_eq!(
            out_of("$o = chr(65 + ((7 / 2) < 4));", &[]),
            b"B".to_vec(),
            "php holds 3.5 < 4"
        );
    }

    #[test]
    fn rendering_a_quotient_as_text_abstains_rather_than_guessing_php_precision() {
        assert_eq!(
            abstain_of("$o = '' . (10 / 3);", &[]),
            Some(Abstain::TypeMismatch),
            "php prints 3.3333333333333 at its default precision of fourteen significant digits; \
             emitting a different rendering would put a wrong byte into recovered source, so the \
             evaluator refuses instead"
        );
    }

    #[test]
    fn division_by_zero_still_abstains() {
        assert_eq!(
            abstain_of("$o = chr(65 + intval(7 / 0));", &[]),
            Some(Abstain::TypeMismatch),
            "php raises DivisionByZeroError, so there is no value to recover"
        );
    }

    fn hex_literal(hex: &[u8]) -> Vec<u8> {
        hex.chunks_exact(2)
            .filter_map(|pair: &[u8]| {
                let text: &str = std::str::from_utf8(pair).ok()?;
                u8::from_str_radix(text, 16).ok()
            })
            .collect()
    }

    #[test]
    fn for_loop_with_modulo_key_index_xors() {
        let out: Vec<u8> = out_of(
            "$o=''; for($i=0;$i<strlen($d);$i++){ $o .= $d[$i] ^ $k[$i % strlen($k)]; }",
            &[("d", b"\x0a\x0d\x08"), ("k", b"ko")],
        );
        assert_eq!(out, b"abc");
    }

    #[test]
    fn while_loop_with_manual_index_decodes() {
        let out: Vec<u8> = out_of(
            "$o=''; $i=0; while($i<strlen($d)){ $o .= chr(ord($d[$i]) ^ 32); $i++; }",
            &[("d", b"ABC")],
        );
        assert_eq!(out, b"abc");
    }

    #[test]
    fn foreach_over_str_split_decodes() {
        let out: Vec<u8> = out_of(
            "$o=''; foreach(str_split($d) as $c){ $o .= chr(ord($c) - 1); }",
            &[("d", b"bcd")],
        );
        assert_eq!(out, b"abc");
    }

    #[test]
    fn do_while_loop_decodes() {
        let out: Vec<u8> = out_of(
            "$o=''; $i=0; do { $o .= chr(ord($d[$i]) ^ 1); $i++; } while($i<strlen($d));",
            &[("d", b"`cb")],
        );
        assert_eq!(out, b"abc");
    }

    #[test]
    fn reversed_index_reads_from_the_end() {
        let out: Vec<u8> = out_of(
            "$o=''; for($i=0;$i<strlen($d);$i++){ $o .= $d[strlen($d)-1-$i]; }",
            &[("d", b"cba")],
        );
        assert_eq!(out, b"abc");
    }

    #[test]
    fn stride_index_skips_padding_bytes() {
        let out: Vec<u8> = out_of(
            "$o=''; for($i=0;$i<strlen($d);$i+=2){ $o .= $d[$i]; }",
            &[("d", b"aXbXcX")],
        );
        assert_eq!(out, b"abc");
    }

    #[test]
    fn rotating_index_advances_its_own_counter() {
        let out: Vec<u8> = out_of(
            "$o=''; $j=0; for($i=0;$i<strlen($d);$i++){ $o .= $d[$i] ^ $k[$j]; $j=($j+1)%strlen($k); }",
            &[("d", b"\x0a\x0d\x08"), ("k", b"ko")],
        );
        assert_eq!(out, b"abc");
    }

    #[test]
    fn nested_inner_loop_walks_two_dimensions() {
        let out: Vec<u8> = out_of(
            "$o=''; for($i=0;$i<2;$i++){ for($j=0;$j<2;$j++){ $o .= $d[$i*2+$j]; } }",
            &[("d", b"abcd")],
        );
        assert_eq!(out, b"abcd");
    }

    #[test]
    fn addition_wraps_around_the_byte_range() {
        let out: Vec<u8> = out_of(
            "$o=''; for($i=0;$i<strlen($d);$i++){ $o .= chr((ord($d[$i]) + 200) % 256); }",
            &[("d", &[0x99, 0x9a, 0x9b])],
        );
        assert_eq!(out, b"abc");
    }

    #[test]
    fn subtraction_wraps_around_the_byte_range() {
        let out: Vec<u8> = out_of(
            "$o=''; for($i=0;$i<strlen($d);$i++){ $o .= chr((ord($d[$i]) - 200 + 256) % 256); }",
            &[("d", &[0x29, 0x2a, 0x2b])],
        );
        assert_eq!(out, b"abc");
    }

    #[test]
    fn byte_rotation_recombines_both_halves() {
        let out: Vec<u8> = out_of(
            "$o=''; for($i=0;$i<strlen($d);$i++){ $o .= chr(((ord($d[$i]) << 3) | (ord($d[$i]) >> 5)) & 255); }",
            &[("d", &[0x2c, 0x4c, 0x6c])],
        );
        assert_eq!(out, b"abc");
    }

    #[test]
    fn oversized_integer_shifts_match_php_sign_extension() {
        let cases: [(BinOp, i64, i64, i64); 6] = [
            (BinOp::Shr, -9, 64, -1),
            (BinOp::Shr, -1, i64::MAX, -1),
            (BinOp::Shr, 9, 64, 0),
            (BinOp::Shr, 0, i64::MAX, 0),
            (BinOp::Shl, -9, 64, 0),
            (BinOp::Shl, 9, i64::MAX, 0),
        ];
        for (operation, lhs, rhs, expected) in cases {
            assert_eq!(
                apply_binary(operation, &Val::Int(lhs), &Val::Int(rhs)),
                Ok(Val::Int(expected))
            );
        }
        assert_eq!(
            apply_binary(BinOp::Shr, &Val::Int(-1), &Val::Int(-1)),
            Err(Abstain::OutOfRange)
        );
    }

    #[test]
    fn negation_recovers_the_complement() {
        let out: Vec<u8> = out_of(
            "$o=''; for($i=0;$i<strlen($d);$i++){ $o .= chr(~ord($d[$i]) & 255); }",
            &[("d", &[0x9e, 0x9d, 0x9c])],
        );
        assert_eq!(out, b"abc");
    }

    #[test]
    fn table_substitution_reads_the_array() {
        let out: Vec<u8> = out_of(
            "$o=''; $t=array(98,99,100); for($i=0;$i<3;$i++){ $o .= chr($t[$i] - 1); }",
            &[],
        );
        assert_eq!(out, b"abc");
    }

    #[test]
    fn parity_selected_operation_switches_per_index() {
        let out: Vec<u8> = out_of(
            "$o=''; for($i=0;$i<strlen($d);$i++){ if($i % 2 == 0){ $o .= chr(ord($d[$i]) - 1); } else { $o .= chr(ord($d[$i]) + 1); } }",
            &[("d", b"bad")],
        );
        assert_eq!(out, b"abc");
    }

    #[test]
    fn undefined_variable_read_abstains_instead_of_guessing() {
        assert_eq!(
            abstain_of(
                "$o=''; for($i=0;$i<strlen($d);$i++){ $o .= $d[$i] ^ $k[$i % strlen($k)]; }",
                &[("d", b"\x0b\x1e\x1c")],
            ),
            Some(Abstain::UndefinedRead),
            "a key absent from the file must abstain, never resolve to an invented value"
        );
    }

    #[test]
    fn an_impure_call_is_refused_by_the_allowlist() {
        for call in [
            "system('id')",
            "exec('id')",
            "shell_exec('id')",
            "file_get_contents('/etc/passwd')",
            "fopen('x','r')",
            "curl_exec($h)",
            "include('x.php')",
            "passthru('id')",
            "proc_open('id',$a,$b)",
        ] {
            let src: String = format!("$o=''; for($i=0;$i<1;$i++){{ $o .= {call}; }}");
            assert_eq!(
                abstain_of(&src, &[]),
                Some(Abstain::RefusedCall),
                "{call} must be refused by the pure-function allowlist"
            );
        }
    }

    #[test]
    fn every_allowlisted_name_is_dispatched_and_is_sorted() {
        let mut sorted: Vec<&[u8]> = PURE_BUILTINS.to_vec();
        sorted.sort_unstable();
        assert_eq!(
            sorted, PURE_BUILTINS,
            "the allowlist must stay sorted so a duplicate or a stray entry is visible"
        );
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            PURE_BUILTINS.len(),
            "duplicate allowlist entry"
        );
        let mut interp: Interp = Interp::new(Budget::default());
        for name in PURE_BUILTINS {
            assert_ne!(
                interp.call_builtin(name, &[]),
                Err(Abstain::RefusedCall),
                "{} is allowlisted but reaches no dispatch arm, so the allowlist over-promises",
                String::from_utf8_lossy(name)
            );
        }
    }

    #[test]
    fn digest_builtins_refuse_excluded_argument_shapes() {
        let mut interp: Interp = Interp::new(Budget::default());
        for name in [b"md5".as_slice(), b"sha1".as_slice()] {
            assert_eq!(interp.call_builtin(name, &[]), Err(Abstain::Unsupported));
            assert_eq!(
                interp.call_builtin(
                    name,
                    &[Val::Str(b"seed".to_vec()), Val::Int(0), Val::Int(0)],
                ),
                Err(Abstain::Unsupported)
            );
            assert_eq!(
                interp.call_builtin(
                    name,
                    &[
                        Val::Str(b"seed".to_vec()),
                        Val::Arr(BTreeMap::from([(0, Val::Int(1))])),
                    ],
                ),
                Err(Abstain::TypeMismatch)
            );
        }
    }

    #[test]
    fn digest_builtins_match_php_output_modes() {
        let mut interp: Interp = Interp::new(Budget::default());
        let seed: Val = Val::Str(b"seed".to_vec());
        assert_eq!(
            interp.call_builtin(b"md5", std::slice::from_ref(&seed)),
            Ok(Val::Str(b"fe4c0f30aa359c41d9f9a5f69c8c4192".to_vec()))
        );
        assert_eq!(
            interp.call_builtin(b"md5", &[seed.clone(), Val::Int(1)]),
            Ok(Val::Str(vec![
                0xfe, 0x4c, 0x0f, 0x30, 0xaa, 0x35, 0x9c, 0x41, 0xd9, 0xf9, 0xa5, 0xf6, 0x9c, 0x8c,
                0x41, 0x92,
            ]))
        );
        assert_eq!(
            interp.call_builtin(b"sha1", std::slice::from_ref(&seed)),
            Ok(Val::Str(
                b"92713d4709377111cf31f2a71986c411bd6cb5b0".to_vec()
            ))
        );
        assert_eq!(
            interp.call_builtin(b"sha1", &[seed, Val::Int(1)]),
            Ok(Val::Str(vec![
                0x92, 0x71, 0x3d, 0x47, 0x09, 0x37, 0x71, 0x11, 0xcf, 0x31, 0xf2, 0xa7, 0x19, 0x86,
                0xc4, 0x11, 0xbd, 0x6c, 0xb5, 0xb0,
            ]))
        );
    }

    #[test]
    fn an_argument_that_cannot_resolve_never_softens_a_refusal() {
        assert_eq!(
            abstain_of("$o = system($undefined_variable);", &[]),
            Some(Abstain::RefusedCall),
            "a refused call must be refused on its name alone, never on whether its arguments \
             happen to resolve first"
        );
    }

    fn with_helper(decl: &str, budget: Budget) -> Interp {
        let mut interp: Interp = Interp::new(budget);
        interp.declare_function(decl.as_bytes());
        interp
    }

    #[test]
    fn a_helper_body_cannot_see_the_caller_scope() {
        let mut interp: Interp =
            with_helper("function dd($s){ return $s . $outer; }", Budget::default());
        interp.observe_scalar(b"outer", b"VISIBLE");
        interp.observe_scalar(b"c", b"seed");
        assert!(
            interp.run_block(b"$o = dd($c);").is_none(),
            "php gives a function its own scope, so a helper reading a caller variable it was \
             never passed must abstain rather than resolve it"
        );
    }

    #[test]
    fn a_declaration_colliding_with_a_builtin_is_refused_not_silently_preferred() {
        let mut interp: Interp = with_helper(
            "function strrev($s){ return 'HIJACKED'; }",
            Budget::default(),
        );
        interp.observe_scalar(b"c", b"abc");
        assert!(
            interp.run_block(b"$o = strrev($c);").is_none(),
            "php fatals on redeclaring a builtin, so the call must abstain rather than silently \
             pick either the builtin or the declaration"
        );
    }

    #[test]
    fn a_duplicate_declaration_is_refused() {
        let mut interp: Interp =
            with_helper("function dd($s){ return 'first'; }", Budget::default());
        interp.declare_function(b"function dd($s){ return 'second'; }");
        interp.observe_scalar(b"c", b"abc");
        assert!(
            interp.run_block(b"$o = dd($c);").is_none(),
            "php fatals on redeclaring a function, so a second declaration must abstain rather \
             than pick a winner"
        );
    }

    #[test]
    fn frame_depth_budget_stops_unbounded_recursion() {
        let budget: Budget = Budget {
            frame_depth: 8,
            ..Budget::default()
        };
        let mut interp: Interp = with_helper("function dd($s){ return dd($s . 'x'); }", budget);
        interp.observe_scalar(b"c", b"seed");
        let mut parser: LoopParser<'_> = LoopParser::new(b"$o = dd($c);");
        let program: Vec<LStmt> = parser.parse_program().expect("parses");
        assert_eq!(
            interp.exec_all(&program).err(),
            Some(Abstain::FrameBudget),
            "a helper that never returns must hit the frame cap, not overflow the rust stack"
        );
    }

    #[test]
    fn an_abstaining_call_restores_the_caller_scope_and_its_accounting() {
        let mut interp: Interp = with_helper(
            "function dd($s){ return $s . $never_bound; }",
            Budget::default(),
        );
        interp.observe_scalar(b"c", b"seed");
        let live_before: usize = interp.live_bytes;
        let frames_before: u32 = interp.frames_deep;
        assert!(interp.run_block(b"$o = dd($c);").is_none());
        assert_eq!(
            interp.live_bytes, live_before,
            "a call that abstained must not leave its frame charged to the heap accounting"
        );
        assert_eq!(
            interp.frames_deep, frames_before,
            "a call that abstained must pop its frame"
        );
        assert_eq!(
            interp.scope.get(b"c".as_slice()),
            Some(&Val::Str(b"seed".to_vec())),
            "the caller scope must survive an abstaining call"
        );
    }

    #[test]
    fn eval_is_not_reachable_as_an_expression_builtin() {
        assert!(
            !PURE_BUILTINS.contains(&b"eval".as_slice())
                && !PURE_BUILTINS.contains(&b"assert".as_slice()),
            "eval and assert are sink statements, never expression builtins; allowing either here \
             would let a nested sink silently become a string-valued call"
        );
        let mut interp: Interp = Interp::new(Budget::default());
        interp.observe_scalar(b"c", b"echo 1;");
        assert_eq!(
            abstain_of("$o = eval($c);", &[("c", b"echo 1;")]),
            Some(Abstain::RefusedCall),
            "an eval in expression position must be refused"
        );
    }

    #[test]
    fn a_helper_returning_nothing_yields_the_empty_string() {
        let mut interp: Interp = with_helper("function dd($s){ $x = $s; }", Budget::default());
        interp.observe_scalar(b"c", b"seed");
        let produced: Vec<(Vec<u8>, Vec<u8>)> = interp.run_block(b"$o = dd($c);").expect("runs");
        assert!(
            produced
                .iter()
                .any(|(name, value): &(Vec<u8>, Vec<u8>)| name == b"o" && value.is_empty()),
            "a php function with no return statement yields null, which concatenates as empty"
        );
    }

    #[test]
    fn step_budget_stops_a_huge_trip_count() {
        let budget: Budget = Budget {
            steps: 5_000,
            ..Budget::default()
        };
        let src: &str = "$o=''; for($i=0;$i<100000000;$i++){ $o .= 'a'; }";
        let mut parser: LoopParser<'_> = LoopParser::new(src.as_bytes());
        let program: Vec<LStmt> = parser.parse_program().expect("parses");
        let mut interp: Interp = Interp::new(budget);
        assert_eq!(interp.exec_all(&program).err(), Some(Abstain::StepBudget));
        assert!(
            interp.steps <= budget.steps + 1,
            "the step counter must stop at the cap, ran {} steps",
            interp.steps
        );
    }

    #[test]
    fn wall_clock_budget_stops_a_long_run() {
        let budget: Budget = Budget {
            wall: Duration::from_millis(1),
            steps: u64::MAX,
            ..Budget::default()
        };
        let src: &str = "$o=0; for($i=0;$i<1000000000;$i++){ $o = $o + 1; }";
        let started: Instant = Instant::now();
        assert_eq!(abstain_under(budget, src), Some(Abstain::WallBudget));
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the wall-clock budget must end the run promptly"
        );
    }

    #[test]
    fn output_budget_stops_an_expanding_accumulator() {
        let budget: Budget = Budget {
            output_bytes: 64,
            ..Budget::default()
        };
        let src: &str = "$o=''; for($i=0;$i<1000;$i++){ $o .= 'aaaaaaaa'; }";
        assert_eq!(abstain_under(budget, src), Some(Abstain::OutputBudget));
    }

    #[test]
    fn heap_budget_stops_many_large_array_slots() {
        let budget: Budget = Budget {
            heap_bytes: 1024,
            ..Budget::default()
        };
        let src: &str = "for($i=0;$i<1000;$i++){ $a[$i] = str_repeat('x', 4096); }";
        assert_eq!(
            abstain_under(budget, src),
            Some(Abstain::HeapBudget),
            "each slot is under the single-value output cap, so only a total-heap budget can stop \
             a loop that fills many of them"
        );
    }

    #[test]
    fn heap_accounting_releases_bytes_when_a_slot_is_overwritten() {
        let budget: Budget = Budget {
            heap_bytes: 64 * 1024,
            ..Budget::default()
        };
        let src: &str = "for($i=0;$i<1000;$i++){ $a[0] = str_repeat('x', 4096); }";
        assert_eq!(
            abstain_under(budget, src),
            None,
            "rewriting one slot a thousand times holds one slot of bytes, so the accounting must \
             subtract the value it replaced instead of only ever adding"
        );
    }

    #[test]
    fn a_failed_block_restores_the_heap_accounting() {
        let mut interp: Interp = Interp::new(Budget::default());
        interp.observe_scalar(b"d", b"abc");
        let live_before: usize = interp.live_bytes;
        assert!(
            interp
                .run_block(b"$o=''; for($i=0;$i<3;$i++){ $o .= $missing[$i]; }")
                .is_none(),
            "an undefined read must abstain"
        );
        assert_eq!(
            interp.live_bytes, live_before,
            "a block that abstained rolled its scope back, so its byte accounting must roll back \
             too or a later block inherits a phantom charge"
        );
    }

    #[test]
    fn expression_depth_budget_stops_deep_nesting() {
        let budget: Budget = Budget {
            expr_depth: 4,
            ..Budget::default()
        };
        let src: &str = "$o = ((((((((1+1)+1)+1)+1)+1)+1)+1)+1);";
        assert_eq!(abstain_under(budget, src), Some(Abstain::DepthBudget));
    }

    #[test]
    fn round_budget_stops_too_many_loop_constructs() {
        let budget: Budget = Budget {
            rounds: 2,
            ..Budget::default()
        };
        let src: &str = "$o=''; for($i=0;$i<1;$i++){} for($i=0;$i<1;$i++){} for($i=0;$i<1;$i++){}";
        assert_eq!(abstain_under(budget, src), Some(Abstain::RoundBudget));
    }

    #[test]
    fn a_zero_length_key_never_divides_by_zero() {
        assert_eq!(
            abstain_of(
                "$o=''; for($i=0;$i<strlen($d);$i++){ $o .= $d[$i] ^ $k[$i % strlen($k)]; }",
                &[("d", b"abc"), ("k", b"")],
            ),
            Some(Abstain::TypeMismatch),
            "a modulo by an empty key length must abstain rather than panic"
        );
    }

    #[test]
    fn an_out_of_range_string_offset_abstains() {
        assert_eq!(
            abstain_of("$o=''; $o .= $d[99];", &[("d", b"abc")]),
            Some(Abstain::OutOfRange)
        );
    }

    #[test]
    fn integer_overflow_in_an_index_expression_abstains() {
        assert_eq!(
            abstain_of(
                "$o=''; $i=9223372036854775807; $o .= $d[$i + 1];",
                &[("d", b"abc")]
            ),
            Some(Abstain::OutOfRange)
        );
    }

    #[test]
    fn break_and_continue_control_the_loop() {
        let out: Vec<u8> = out_of(
            "$o=''; for($i=0;$i<10;$i++){ if($i==1){ continue; } if($i==4){ break; } $o .= chr(97+$i); }",
            &[],
        );
        assert_eq!(out, b"acd");
    }

    #[test]
    fn php_string_xor_truncates_to_the_shorter_operand() {
        let out: Vec<u8> = out_of("$o = $a ^ $b;", &[("a", b"abcdef"), ("b", b"\x00\x00")]);
        assert_eq!(out, b"ab");
    }

    #[test]
    fn php_string_or_pads_to_the_longer_operand() {
        let out: Vec<u8> = out_of("$o = $a | $b;", &[("a", b"\x00\x00\x63"), ("b", b"ab")]);
        assert_eq!(out, b"abc");
    }

    #[test]
    fn malformed_loop_sources_never_panic() {
        let cases: &[&str] = &[
            "",
            "for(",
            "for(;;)",
            "for(;;){",
            "while()",
            "foreach( as $x)",
            "do",
            "$o .= ;",
            "$o = 'unterminated",
            "if(",
            "$a[",
            "for($i=0;$i<1;$i++) $o .= $d[$i",
        ];
        for case in cases {
            let _: Option<Vec<(Vec<u8>, Vec<u8>)>> =
                Interp::new(Budget::default()).run_block(case.as_bytes());
        }
    }

    #[test]
    fn deeply_nested_parens_never_stack_overflow_the_loop_parser() {
        const NESTING: usize = 50_000;
        let mut src: Vec<u8> = b"$a = ".to_vec();
        src.extend(std::iter::repeat_n(b'(', NESTING));
        src.push(b'1');
        src.extend(std::iter::repeat_n(b')', NESTING));
        src.push(b';');
        let _: Option<Vec<(Vec<u8>, Vec<u8>)>> = Interp::new(Budget::default()).run_block(&src);
    }

    #[test]
    fn deeply_chained_assignments_stop_at_the_loop_parser_depth_budget() {
        let nesting: usize = usize::try_from(MAX_PARSE_DEPTH).unwrap_or(usize::MAX) + 1;
        let mut src: Vec<u8> = b"$a = ".repeat(nesting);
        src.extend_from_slice(b"0;");

        assert!(LoopParser::new(&src).parse_program().is_none());
    }

    #[test]
    fn deeply_nested_blocks_never_stack_overflow_the_loop_parser() {
        const NESTING: usize = 50_000;
        let mut src: Vec<u8> = Vec::new();
        src.extend(std::iter::repeat_n(b'{', NESTING));
        src.extend(std::iter::repeat_n(b'}', NESTING));
        let _: Option<Vec<(Vec<u8>, Vec<u8>)>> = Interp::new(Budget::default()).run_block(&src);
    }

    fn raw_zero_padded_call(cipher: &[u8], algorithm: &str) -> Vec<Val> {
        vec![
            Val::Str(cipher.to_vec()),
            Val::Str(algorithm.as_bytes().to_vec()),
            Val::Str(b"budget-key-00016".to_vec()),
            Val::Int(OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING),
            Val::Str(b"budget-ivec-0016".to_vec()),
        ]
    }

    #[test]
    fn an_aes_ecb_block_walk_respects_the_step_budget() {
        let cipher: Vec<u8> = vec![b'x'; 4096];
        let args: Vec<Val> = raw_zero_padded_call(&cipher, "aes-128-ecb");
        let unbounded: Eval<Val> = Interp::new(Budget::default()).openssl_decrypt(&args);
        assert_eq!(
            unbounded.map(|value: Val| to_bytes(&value).map(|b: Vec<u8>| b.len())),
            Ok(Ok(cipher.len())),
            "with room to run, every block of this ciphertext decrypts, so the bounded run below \
             is stopped by the budget and not by the input"
        );
        let bounded: Eval<Val> = Interp::new(Budget {
            steps: 8,
            ..Budget::default()
        })
        .openssl_decrypt(&args);
        assert_eq!(
            bounded.err(),
            Some(Abstain::StepBudget),
            "the per-block ecb walk must charge a step per block"
        );
    }

    #[test]
    fn an_openssl_plaintext_over_the_output_budget_abstains() {
        let cipher: Vec<u8> = vec![b'y'; 4096];
        let args: Vec<Val> = raw_zero_padded_call(&cipher, "aes-128-cbc");
        let unbounded: Eval<Val> = Interp::new(Budget::default()).openssl_decrypt(&args);
        assert_eq!(
            unbounded.map(|value: Val| to_bytes(&value).map(|b: Vec<u8>| b.len())),
            Ok(Ok(cipher.len())),
            "this ciphertext decrypts to a full-length plaintext when the caps allow it"
        );
        let bounded: Eval<Val> = Interp::new(Budget {
            output_bytes: 64,
            ..Budget::default()
        })
        .openssl_decrypt(&args);
        assert_eq!(
            bounded.err(),
            Some(Abstain::OutputBudget),
            "a ciphertext whose plaintext exceeds the output cap must abstain instead of \
             materialising it"
        );
    }

    #[test]
    fn an_unpack_walk_respects_the_step_budget() {
        let mut interp: Interp = Interp::new(Budget {
            steps: 16,
            ..Budget::default()
        });
        interp.observe_scalar(b"d", &vec![b'z'; 65_536]);
        assert!(
            interp.run_block(b"$a = unpack('C*', $d);").is_none(),
            "unpack must charge a step per produced element, so a large blob has to hit the cap"
        );
    }

    #[test]
    fn a_pack_run_respects_the_output_budget() {
        let budget: Budget = Budget {
            output_bytes: 32,
            ..Budget::default()
        };
        let src: &str = "$o = ''; for($i=0;$i<64;$i++){ $o .= pack('N*', 1, 2, 3, 4); }";
        assert_eq!(abstain_under(budget, src), Some(Abstain::OutputBudget));
    }

    #[test]
    fn a_constant_table_respects_the_heap_budget() {
        let budget: Budget = Budget {
            heap_bytes: 512,
            ..Budget::default()
        };
        let src: &str = "define('BIG', str_repeat('x', 4096));";
        assert_eq!(
            abstain_under(budget, src),
            Some(Abstain::HeapBudget),
            "a constant holds bytes for the rest of the run, so the constant table has to be \
             charged against the same heap budget as the scope"
        );
    }

    #[test]
    fn a_redefined_constant_is_refused_rather_than_resolved_either_way() {
        let mut interp: Interp = Interp::new(Budget::default());
        assert!(interp.declare_constant(b"define('K', 'first');"));
        assert!(
            !interp.declare_constant(b"define('K', 'second');"),
            "php emits a warning and keeps the first value for a duplicate define, so a second \
             binding must never silently replace the first"
        );
        assert_eq!(
            interp.constants.get(b"K".as_slice()),
            Some(&Val::Str(b"first".to_vec()))
        );
    }

    #[test]
    fn a_predefined_openssl_flag_cannot_be_overwritten_by_the_file() {
        let mut interp: Interp = Interp::new(Budget::default());
        assert!(
            !interp.declare_constant(b"define('OPENSSL_RAW_DATA', 999);"),
            "php refuses to redefine a constant the engine already provides, so a file must not \
             be able to reinterpret the option flags the evaluator reads"
        );
        assert_eq!(
            interp.constants.get(b"OPENSSL_RAW_DATA".as_slice()),
            Some(&Val::Int(OPENSSL_RAW_DATA))
        );
    }

    #[test]
    fn a_file_scope_const_refuses_a_runtime_expression() {
        let mut interp: Interp = Interp::new(Budget::default());
        interp.observe_scalar(b"seed", b"runtime");
        assert!(
            !interp.declare_constant(b"const K = $seed;"),
            "a file-scope const expression cannot depend on a runtime variable"
        );
        assert!(
            !interp.declare_constant(b"const K = str_repeat('x', 4);"),
            "a file-scope const expression cannot call a runtime function"
        );
        assert!(
            !interp.declare_constant(b"const K = \"$seed\";"),
            "a file-scope const expression cannot interpolate a runtime variable"
        );
    }

    #[test]
    fn an_undefined_constant_abstains_rather_than_reading_zero() {
        assert_eq!(
            abstain_of("$o = NOT_DEFINED_ANYWHERE;", &[]),
            Some(Abstain::UndefinedRead)
        );
    }

    #[test]
    fn a_reserved_word_is_never_read_as_a_constant() {
        let mut parser: LoopParser<'_> = LoopParser::new(b"$o = echo;");
        assert!(
            parser.parse_program().is_none(),
            "a php keyword is not a constant, so treating one as a name would invent a value the \
             interpreter never saw"
        );
    }

    #[test]
    fn an_unsupported_openssl_algorithm_names_no_key_length() {
        assert_eq!(aes_algorithm(b"aes-128-gcm"), None);
        assert_eq!(aes_algorithm(b"aes-128-ctr"), None);
        assert_eq!(aes_algorithm(b"rc4"), None);
        assert_eq!(aes_algorithm(b"aes-128-cbc"), Some((16, AesMode::Cbc)));
        assert_eq!(aes_algorithm(b"AES-256-ECB"), Some((32, AesMode::Ecb)));
    }

    #[test]
    fn a_ciphertext_that_is_not_a_block_multiple_abstains() {
        let mut interp: Interp = Interp::new(Budget::default());
        interp.observe_scalar(b"c", &[0u8; 17]);
        assert!(
            interp
                .run_sink_statement(
                    b"eval(openssl_decrypt($c, 'aes-128-cbc', 'k', 1, '0123456789abcdef'));"
                )
                .is_none(),
            "a truncated ciphertext must abstain rather than decrypt the blocks that happen to fit"
        );
    }

    #[test]
    fn an_empty_ciphertext_abstains() {
        let mut interp: Interp = Interp::new(Budget::default());
        interp.observe_scalar(b"c", b"");
        assert!(
            interp
                .run_sink_statement(
                    b"eval(openssl_decrypt($c, 'aes-128-cbc', 'k', 1, '0123456789abcdef'));"
                )
                .is_none(),
            "a zero-length ciphertext has no plaintext, so an empty success would be a fabricated \
             recovery"
        );
    }

    #[test]
    fn a_leading_zero_literal_is_read_as_octal_the_way_php_reads_it() {
        let out: Vec<u8> = out_of("$o = chr(0145) . chr(0143) . chr(0150);", &[]);
        assert_eq!(
            out, b"ech",
            "php reads a leading-zero integer as octal, so reading it as decimal would decode a \
             different byte than the file runs"
        );
    }

    #[test]
    fn an_invalid_octal_literal_is_refused_rather_than_read_as_decimal() {
        let mut parser: LoopParser<'_> = LoopParser::new(b"$o = chr(08);");
        assert!(
            parser.parse_program().is_none(),
            "php fatals on 08 because 8 is not an octal digit, so a file carrying one runs \
             nothing and no plaintext may be produced from it"
        );
    }

    #[test]
    fn binary_and_explicit_octal_literals_match_php() {
        let out: Vec<u8> = out_of("$o = chr(0b1100001) . chr(0o142) . chr(0x63);", &[]);
        assert_eq!(out, b"abc");
    }

    #[test]
    fn a_repeater_larger_than_the_data_abstains_before_allocating() {
        let mut interp: Interp = Interp::new(Budget::default());
        interp.observe_scalar(b"d", b"abcd");
        assert!(
            interp
                .run_block(b"$a = unpack('N4294967295', $d);")
                .is_none(),
            "a repeater the data cannot satisfy must abstain rather than size an allocation from a \
             file-controlled count"
        );
        assert!(
            interp.run_block(b"$a = pack('N4294967295', 1);").is_none(),
            "a pack repeater that does not match the supplied argument count must abstain"
        );
    }

    #[test]
    fn unpack_produces_the_one_based_array_php_produces() {
        let mut interp: Interp = Interp::new(Budget::default());
        interp.observe_scalar(b"d", b"abc");
        let produced: Option<Vec<(Vec<u8>, Vec<u8>)>> =
            interp.run_block(b"$h = unpack('H*', $d); $o = $h[1];");
        let bound: Vec<(Vec<u8>, Vec<u8>)> = produced.expect("unpack binds");
        assert!(
            bound.contains(&(b"o".to_vec(), b"616263".to_vec())),
            "php returns unpack('H*') as an array keyed from 1, so reading [1] must yield the \
             whole hex string, not one character of it; got {bound:?}"
        );
    }
}
