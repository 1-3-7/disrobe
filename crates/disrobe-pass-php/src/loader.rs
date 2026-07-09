use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64_STD;
use flate2::read::DeflateDecoder;
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read as _;
use std::sync::OnceLock;

pub const DEFAULT_LOADER_DEPTH: u32 = 64;

const EXPR_INFLATE_CAP: usize = 256 * 1024 * 1024;

const EXPR_INITIAL_CAP: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LoaderSink {
    Eval,
    Assert,
    PregReplaceEval,
    VariableFunction,
    CreateFunction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoaderReport {
    pub sink: LoaderSink,
    pub recovered: Vec<u8>,
    pub bound_variable_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Str(Vec<u8>),
}

#[derive(Debug, Default)]
struct Env {
    vars: BTreeMap<Vec<u8>, Value>,
    code_vars: std::collections::BTreeSet<Vec<u8>>,
    arr_vars: BTreeMap<Vec<u8>, Vec<Vec<u8>>>,
}

impl Env {
    fn get(&self, name: &[u8]) -> Option<&Value> {
        self.vars.get(name)
    }

    fn set(&mut self, name: Vec<u8>, value: Value) {
        self.code_vars.remove(&name);
        self.arr_vars.remove(&name);
        self.vars.insert(name, value);
    }

    fn set_code(&mut self, name: Vec<u8>, value: Value) {
        self.arr_vars.remove(&name);
        self.code_vars.insert(name.clone());
        self.vars.insert(name, value);
    }

    fn set_array(&mut self, name: Vec<u8>, elements: Vec<Vec<u8>>) {
        self.code_vars.remove(&name);
        self.vars.remove(&name);
        self.arr_vars.insert(name, elements);
    }

    fn is_code(&self, name: &[u8]) -> bool {
        self.code_vars.contains(name)
    }

    fn get_array(&self, name: &[u8]) -> Option<&Vec<Vec<u8>>> {
        self.arr_vars.get(name)
    }

    fn array_element(&self, name: &[u8], idx: i64) -> Option<Vec<u8>> {
        let elements: &Vec<Vec<u8>> = self.arr_vars.get(name)?;
        let index: usize = usize::try_from(idx).ok()?;
        elements.get(index).cloned()
    }
}

const MAX_PARSE_DEPTH: usize = 256;

struct Parser<'a> {
    buf: &'a [u8],
    pos: usize,
    depth: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Expr {
    StrLit(Vec<u8>),
    IntLit(i64),
    Var(Vec<u8>),
    DynVar(Box<Self>),
    Index {
        name: Vec<u8>,
        idx: i64,
    },
    Concat(Vec<Self>),
    Arith {
        op: ArithOp,
        lhs: Box<Self>,
        rhs: Box<Self>,
    },
    Call {
        name: CallName,
        args: Vec<Self>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArithOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CallName {
    Ident(Vec<u8>),
    DynVar(Vec<u8>),
    DynIndex { name: Vec<u8>, idx: i64 },
    DynExpr(Box<Expr>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AssignTarget {
    Name(Vec<u8>),
    Dynamic(Box<Expr>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Stmt {
    Assign { target: AssignTarget, value: Expr },
    Expression(Expr),
    ControlBlock { raw: Vec<u8> },
}

#[derive(Debug)]
enum VarRef {
    Name(Vec<u8>),
    Dynamic(Expr),
}

fn var_ref_to_expr(var_ref: VarRef) -> Expr {
    match var_ref {
        VarRef::Name(name) => Expr::Var(name),
        VarRef::Dynamic(name_expr) => Expr::DynVar(Box::new(name_expr)),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlKw {
    Loop,
    Do,
}

const fn is_ident_byte(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphanumeric()
}

impl<'a> Parser<'a> {
    fn new(buf: &'a [u8]) -> Self {
        let start: usize = open_tag_offset(buf);
        Self {
            buf,
            pos: start,
            depth: 0,
        }
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
            } else if self.buf[self.pos..].starts_with(b"/*") {
                self.pos += 2;
                while self.pos + 1 < self.buf.len() && !self.buf[self.pos..].starts_with(b"*/") {
                    self.pos += 1;
                }
                self.pos = (self.pos + 2).min(self.buf.len());
            } else if self.buf[self.pos..].starts_with(b"@") {
                self.pos += 1;
            }
            if self.pos == before {
                break;
            }
        }
    }

    fn eof(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    fn parse_statements(&mut self, cap: usize) -> Vec<Stmt> {
        let mut out: Vec<Stmt> = Vec::new();
        while out.len() < cap {
            self.skip_trivia();
            if self.eof() || self.buf[self.pos..].starts_with(b"?>") {
                break;
            }
            let Some(stmt): Option<Stmt> = self.parse_statement() else {
                if !self.recover_to_semicolon() {
                    break;
                }
                continue;
            };
            out.push(stmt);
        }
        out
    }

    fn recover_to_semicolon(&mut self) -> bool {
        let start: usize = self.pos;
        while self.pos < self.buf.len() && self.buf[self.pos] != b';' {
            self.pos += 1;
        }
        if self.pos < self.buf.len() {
            self.pos += 1;
        }
        self.pos > start && self.pos <= self.buf.len()
    }

    fn capture_control_block(&mut self) -> Option<Vec<u8>> {
        let start: usize = self.pos;
        let captured: Option<Vec<u8>> = self.try_capture_control_block();
        if captured.is_none() {
            self.pos = start;
        }
        captured
    }

    fn try_capture_control_block(&mut self) -> Option<Vec<u8>> {
        let start: usize = self.pos;
        let kw: ControlKw = self.match_control_keyword()?;
        self.skip_trivia();
        if matches!(kw, ControlKw::Do) {
            self.consume_block_or_stmt()?;
            self.skip_trivia();
            if self.match_keyword(b"while") {
                self.skip_trivia();
                self.consume_balanced(b'(', b')')?;
                self.expect_semicolon();
            }
            return Some(self.buf[start..self.pos].to_vec());
        }
        if self.peek() != Some(b'(') {
            return None;
        }
        self.consume_balanced(b'(', b')')?;
        self.consume_block_or_stmt()?;
        Some(self.buf[start..self.pos].to_vec())
    }

    fn match_control_keyword(&mut self) -> Option<ControlKw> {
        if self.match_keyword(b"foreach")
            || self.match_keyword(b"for")
            || self.match_keyword(b"while")
        {
            return Some(ControlKw::Loop);
        }
        if self.match_keyword(b"do") {
            return Some(ControlKw::Do);
        }
        None
    }

    fn match_keyword(&mut self, kw: &[u8]) -> bool {
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

    fn consume_block_or_stmt(&mut self) -> Option<()> {
        self.skip_trivia();
        if self.peek() == Some(b'{') {
            self.consume_balanced(b'{', b'}')
        } else {
            self.consume_to_semicolon()
        }
    }

    fn consume_balanced(&mut self, open: u8, close: u8) -> Option<()> {
        if self.peek() != Some(open) {
            return None;
        }
        let mut depth: i32 = 0;
        let mut quote: Option<u8> = None;
        while let Some(b) = self.peek() {
            match quote {
                Some(q) => {
                    if b == b'\\' {
                        self.pos += 1;
                    } else if b == q {
                        quote = None;
                    }
                }
                None if b == b'\'' || b == b'"' => quote = Some(b),
                None if b == open => depth += 1,
                None if b == close => {
                    depth -= 1;
                    if depth == 0 {
                        self.pos += 1;
                        return Some(());
                    }
                }
                None => {}
            }
            self.pos += 1;
        }
        None
    }

    fn consume_to_semicolon(&mut self) -> Option<()> {
        let mut nesting: i32 = 0;
        let mut quote: Option<u8> = None;
        while let Some(b) = self.peek() {
            match quote {
                Some(q) => {
                    if b == b'\\' {
                        self.pos += 1;
                    } else if b == q {
                        quote = None;
                    }
                }
                None if b == b'\'' || b == b'"' => quote = Some(b),
                None if matches!(b, b'(' | b'[' | b'{') => nesting += 1,
                None if matches!(b, b')' | b']' | b'}') => nesting -= 1,
                None if b == b';' && nesting == 0 => {
                    self.pos += 1;
                    return Some(());
                }
                None => {}
            }
            self.pos += 1;
        }
        None
    }

    fn parse_statement(&mut self) -> Option<Stmt> {
        self.skip_trivia();
        if let Some(raw) = self.capture_control_block() {
            return Some(Stmt::ControlBlock { raw });
        }
        if self.peek() == Some(b'$') {
            let save: usize = self.pos;
            if let Some(var_ref) = self.parse_var_ref() {
                self.skip_trivia();
                if self.peek() == Some(b'=') && self.buf.get(self.pos + 1) != Some(&b'=') {
                    self.pos += 1;
                    let value: Expr = self.parse_expr()?;
                    self.expect_semicolon();
                    let target: AssignTarget = match var_ref {
                        VarRef::Name(name) => AssignTarget::Name(name),
                        VarRef::Dynamic(name_expr) => AssignTarget::Dynamic(Box::new(name_expr)),
                    };
                    return Some(Stmt::Assign { target, value });
                }
            }
            self.pos = save;
        }
        let expr: Expr = self.parse_expr()?;
        self.expect_semicolon();
        Some(Stmt::Expression(expr))
    }

    fn expect_semicolon(&mut self) {
        self.skip_trivia();
        if self.peek() == Some(b';') {
            self.pos += 1;
        }
    }

    fn parse_var_ref(&mut self) -> Option<VarRef> {
        if self.depth >= MAX_PARSE_DEPTH {
            return None;
        }
        if self.peek() != Some(b'$') {
            return None;
        }
        self.pos += 1;
        if self.peek() == Some(b'$') {
            self.depth += 1;
            let inner: Option<VarRef> = self.parse_var_ref();
            self.depth -= 1;
            return Some(VarRef::Dynamic(var_ref_to_expr(inner?)));
        }
        if self.peek() == Some(b'{') {
            return self.parse_curly_var_ref();
        }
        let start: usize = self.pos;
        while let Some(c) = self.peek() {
            if c == b'_' || c.is_ascii_alphanumeric() {
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == start {
            return None;
        }
        let base: &[u8] = &self.buf[start..self.pos];
        if base == b"GLOBALS"
            && let Some(key) = self.parse_globals_subscript()
        {
            return Some(VarRef::Name(key));
        }
        Some(VarRef::Name(base.to_vec()))
    }

    fn parse_curly_var_ref(&mut self) -> Option<VarRef> {
        let save: usize = self.pos;
        self.pos += 1;
        self.skip_trivia();
        let Some(inner): Option<Expr> = self.parse_expr() else {
            self.pos = save;
            return None;
        };
        self.skip_trivia();
        if self.peek() != Some(b'}') {
            self.pos = save;
            return None;
        }
        self.pos += 1;
        if let Expr::StrLit(name) = inner {
            if name == b"GLOBALS"
                && let Some(key) = self.parse_globals_subscript()
            {
                return Some(VarRef::Name(key));
            }
            return Some(VarRef::Name(name));
        }
        Some(VarRef::Dynamic(inner))
    }

    fn parse_globals_subscript(&mut self) -> Option<Vec<u8>> {
        let save: usize = self.pos;
        self.skip_trivia();
        if self.peek() != Some(b'[') {
            self.pos = save;
            return None;
        }
        self.pos += 1;
        self.skip_trivia();
        if let Some(Expr::StrLit(key)) = self.parse_string_literal() {
            self.skip_trivia();
            if self.peek() == Some(b']') {
                self.pos += 1;
                return Some(key);
            }
        }
        self.pos = save;
        None
    }

    fn parse_expr(&mut self) -> Option<Expr> {
        if self.depth >= MAX_PARSE_DEPTH {
            return None;
        }
        self.depth += 1;
        let result: Option<Expr> = self.parse_expr_inner();
        self.depth -= 1;
        result
    }

    fn parse_expr_inner(&mut self) -> Option<Expr> {
        let first: Expr = self.parse_additive()?;
        let mut parts: Vec<Expr> = vec![first];
        loop {
            self.skip_trivia();
            if self.peek() == Some(b'.') && self.buf.get(self.pos + 1) != Some(&b'=') {
                self.pos += 1;
                let next: Expr = self.parse_additive()?;
                parts.push(next);
            } else {
                break;
            }
        }
        if parts.len() == 1 {
            parts.pop()
        } else {
            Some(Expr::Concat(parts))
        }
    }

    fn parse_additive(&mut self) -> Option<Expr> {
        let mut lhs: Expr = self.parse_multiplicative()?;
        loop {
            self.skip_trivia();
            let op: ArithOp = match self.peek() {
                Some(b'+') if self.buf.get(self.pos + 1) != Some(&b'+') => ArithOp::Add,
                Some(b'-') if self.buf.get(self.pos + 1) != Some(&b'-') => ArithOp::Sub,
                _ => break,
            };
            if self.buf.get(self.pos + 1) == Some(&b'=') {
                break;
            }
            self.pos += 1;
            let rhs: Expr = self.parse_multiplicative()?;
            lhs = Expr::Arith {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Some(lhs)
    }

    fn parse_multiplicative(&mut self) -> Option<Expr> {
        let mut lhs: Expr = self.parse_primary()?;
        loop {
            self.skip_trivia();
            let op: ArithOp = match self.peek() {
                Some(b'*') if self.buf.get(self.pos + 1) != Some(&b'*') => ArithOp::Mul,
                Some(b'/') if self.buf.get(self.pos + 1) != Some(&b'/') => ArithOp::Div,
                Some(b'%') => ArithOp::Mod,
                _ => break,
            };
            if self.buf.get(self.pos + 1) == Some(&b'=') {
                break;
            }
            self.pos += 1;
            let rhs: Expr = self.parse_primary()?;
            lhs = Expr::Arith {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Some(lhs)
    }

    fn parse_primary(&mut self) -> Option<Expr> {
        self.skip_trivia();
        match self.peek()? {
            b'\'' | b'"' => self.parse_string_literal(),
            b'(' => {
                self.pos += 1;
                let inner: Expr = self.parse_expr()?;
                self.skip_trivia();
                if self.peek() == Some(b')') {
                    self.pos += 1;
                }
                Some(inner)
            }
            b'$' => self.parse_var_or_dyn_call(),
            c if c.is_ascii_digit() => self.parse_int_literal(),
            c if c == b'_' || c.is_ascii_alphabetic() || c == b'\\' => self.parse_ident_call(),
            _ => None,
        }
    }

    fn parse_int_literal(&mut self) -> Option<Expr> {
        if self.peek() == Some(b'0')
            && let Some(radix_marker) = self.buf.get(self.pos + 1)
            && matches!(radix_marker, b'x' | b'X' | b'o' | b'O' | b'b' | b'B')
        {
            let radix: u32 = match radix_marker {
                b'x' | b'X' => 16,
                b'o' | b'O' => 8,
                _ => 2,
            };
            self.pos += 2;
            let start: usize = self.pos;
            while self
                .peek()
                .is_some_and(|b: u8| (b as char).is_digit(radix) || b == b'_')
            {
                self.pos += 1;
            }
            let digits: String = std::str::from_utf8(&self.buf[start..self.pos])
                .ok()?
                .replace('_', "");
            let value: i64 = i64::from_str_radix(&digits, radix).ok()?;
            return Some(Expr::IntLit(value));
        }
        let start: usize = self.pos;
        while self
            .peek()
            .is_some_and(|b: u8| b.is_ascii_digit() || b == b'_')
        {
            self.pos += 1;
        }
        let text: String = std::str::from_utf8(&self.buf[start..self.pos])
            .ok()?
            .replace('_', "");
        let value: i64 = text.parse::<i64>().ok()?;
        Some(Expr::IntLit(value))
    }

    fn parse_var_or_dyn_call(&mut self) -> Option<Expr> {
        match self.parse_var_ref()? {
            VarRef::Name(name) => self.finish_static_var_call(name),
            VarRef::Dynamic(name_expr) => self.finish_dynamic_var_call(name_expr),
        }
    }

    fn finish_static_var_call(&mut self, name: Vec<u8>) -> Option<Expr> {
        self.skip_trivia();
        if self.peek() == Some(b'[')
            && let Some(idx) = self.parse_int_subscript()
        {
            self.skip_trivia();
            if self.peek() == Some(b'(') {
                let args: Vec<Expr> = self.parse_arg_list()?;
                return Some(Expr::Call {
                    name: CallName::DynIndex { name, idx },
                    args,
                });
            }
            return Some(Expr::Index { name, idx });
        }
        if self.peek() == Some(b'(') {
            let args: Vec<Expr> = self.parse_arg_list()?;
            return Some(Expr::Call {
                name: CallName::DynVar(name),
                args,
            });
        }
        Some(Expr::Var(name))
    }

    fn finish_dynamic_var_call(&mut self, name_expr: Expr) -> Option<Expr> {
        self.skip_trivia();
        let read: Expr = Expr::DynVar(Box::new(name_expr));
        if self.peek() == Some(b'(') {
            let args: Vec<Expr> = self.parse_arg_list()?;
            return Some(Expr::Call {
                name: CallName::DynExpr(Box::new(read)),
                args,
            });
        }
        Some(read)
    }

    fn parse_int_subscript(&mut self) -> Option<i64> {
        let save: usize = self.pos;
        if self.peek() != Some(b'[') {
            return None;
        }
        self.pos += 1;
        self.skip_trivia();
        let idx_expr: Expr = self.parse_expr()?;
        self.skip_trivia();
        if self.peek() != Some(b']') {
            self.pos = save;
            return None;
        }
        self.pos += 1;
        if let Expr::IntLit(n) = idx_expr {
            Some(n)
        } else {
            self.pos = save;
            None
        }
    }

    fn parse_ident_call(&mut self) -> Option<Expr> {
        let start: usize = self.pos;
        if self.peek() == Some(b'\\') {
            self.pos += 1;
        }
        while let Some(c) = self.peek() {
            if c == b'_' || c.is_ascii_alphanumeric() || c == b'\\' {
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == start {
            return None;
        }
        let ident: Vec<u8> = self.buf[start..self.pos]
            .iter()
            .copied()
            .filter(|b: &u8| *b != b'\\')
            .collect();
        self.skip_trivia();
        if self.peek() == Some(b'(') {
            let args: Vec<Expr> = self.parse_arg_list()?;
            return Some(Expr::Call {
                name: CallName::Ident(ident),
                args,
            });
        }
        Some(Expr::StrLit(ident))
    }

    fn parse_arg_list(&mut self) -> Option<Vec<Expr>> {
        if self.peek() != Some(b'(') {
            return None;
        }
        self.pos += 1;
        let mut args: Vec<Expr> = Vec::new();
        loop {
            self.skip_trivia();
            if self.peek() == Some(b')') {
                self.pos += 1;
                break;
            }
            let arg: Expr = self.parse_expr()?;
            args.push(arg);
            self.skip_trivia();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b')') => {
                    self.pos += 1;
                    break;
                }
                _ => return None,
            }
        }
        Some(args)
    }

    fn parse_string_literal(&mut self) -> Option<Expr> {
        let quote: u8 = self.peek()?;
        if quote != b'\'' && quote != b'"' {
            return None;
        }
        self.pos += 1;
        let mut out: Vec<u8> = Vec::new();
        while let Some(c) = self.peek() {
            if c == b'\\' {
                let next: u8 = self.buf.get(self.pos + 1).copied()?;
                if quote == b'\'' {
                    match next {
                        b'\'' => out.push(b'\''),
                        b'\\' => out.push(b'\\'),
                        _ => {
                            out.push(b'\\');
                            out.push(next);
                        }
                    }
                    self.pos += 2;
                } else {
                    let consumed: usize = self.push_double_escape(next, &mut out);
                    self.pos += consumed;
                }
            } else if c == quote {
                self.pos += 1;
                return Some(Expr::StrLit(out));
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
                    let Some(d): Option<u8> = self.buf.get(self.pos + 2 + digits).copied() else {
                        break;
                    };
                    let Some(nib): Option<u8> = hex_nibble(d) else {
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
                    let Some(d): Option<u8> = self.buf.get(self.pos + 1 + digits).copied() else {
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
            other => {
                out.push(decode_double_escape(other));
                2
            }
        }
    }
}

const fn decode_double_escape(next: u8) -> u8 {
    match next {
        b'n' => b'\n',
        b'r' => b'\r',
        b't' => b'\t',
        b'"' => b'"',
        b'\\' => b'\\',
        b'$' => b'$',
        other => other,
    }
}

fn open_tag_offset(buf: &[u8]) -> usize {
    memchr::memmem::find(buf, b"<?php")
        .map(|p: usize| p + 5)
        .or_else(|| memchr::memmem::find(buf, b"<?").map(|p: usize| p + 2))
        .unwrap_or(0)
}

#[must_use]
pub fn peel_loader(buf: &[u8], depth: u32) -> Option<LoaderReport> {
    let mut parser: Parser<'_> = Parser::new(buf);
    let stmts: Vec<Stmt> = parser.parse_statements(4096);
    if stmts.is_empty() {
        return None;
    }
    if stmts.len() == 1 && !is_loader_owned_single(&stmts[0]) {
        return None;
    }
    let mut env: Env = Env::default();
    let mut bound: usize = 0;
    let mut sink_result: Option<LoaderReport> = None;
    let mut loop_src: Vec<u8> = Vec::new();
    for stmt in &stmts {
        match stmt {
            Stmt::Assign { target, value } => {
                let Some(name): Option<Vec<u8>> = resolve_assign_target(target, &env, depth) else {
                    continue;
                };
                if let Some(body) = create_function_body(value, &env, depth) {
                    env.set_code(name, Value::Str(body));
                    bound += 1;
                } else if let Some(elements) = inline_array_elements(value, &env, depth) {
                    env.set_array(name, elements);
                    bound += 1;
                } else if let Some(v) = eval_expr(value, &env, depth) {
                    env.set(name, v);
                    bound += 1;
                }
            }
            Stmt::ControlBlock { raw } => {
                loop_src.extend_from_slice(raw);
                loop_src.push(b'\n');
                if let Some((name, plaintext)) = eval_rc4_loop(&loop_src, &env) {
                    env.set(name, Value::Str(plaintext));
                    bound += 1;
                } else if let Some((name, plaintext)) = eval_xor_keystream_loop(raw, &env) {
                    env.set(name, Value::Str(plaintext));
                    bound += 1;
                }
            }
            Stmt::Expression(expr) => {
                if let Some((sink, recovered)) = eval_sink(expr, &env, depth) {
                    sink_result = Some(LoaderReport {
                        sink,
                        recovered,
                        bound_variable_count: bound,
                    });
                }
            }
        }
    }
    sink_result
}

fn resolve_assign_target(target: &AssignTarget, env: &Env, depth: u32) -> Option<Vec<u8>> {
    match target {
        AssignTarget::Name(name) => Some(name.clone()),
        AssignTarget::Dynamic(name_expr) => {
            let Value::Str(name): Value = eval_expr(name_expr, env, depth)?;
            (!name.is_empty()).then_some(name)
        }
    }
}

fn create_function_body(value: &Expr, env: &Env, depth: u32) -> Option<Vec<u8>> {
    let Expr::Call { name, args } = value else {
        return None;
    };
    let CallName::Ident(ident) = name else {
        return None;
    };
    if !ident.eq_ignore_ascii_case(b"create_function") {
        return None;
    }
    let body_arg: &Expr = args.get(1)?;
    let params: Vec<u8> = string_arg(args.first()?, env, depth)?;
    if !params.trim_ascii().is_empty() {
        return None;
    }
    string_arg(body_arg, env, depth)
}

fn is_loader_owned_single(stmt: &Stmt) -> bool {
    let Stmt::Expression(Expr::Call { name, args }) = stmt else {
        return false;
    };
    match name {
        CallName::DynVar(_) | CallName::DynIndex { .. } | CallName::DynExpr(_) => true,
        CallName::Ident(ident) => {
            if (ident.eq_ignore_ascii_case(b"eval") || ident.eq_ignore_ascii_case(b"assert"))
                && args.first().is_some_and(arg_needs_loader)
            {
                return true;
            }
            ident.eq_ignore_ascii_case(b"preg_replace") && preg_first_arg_is_e(args)
        }
    }
}

fn arg_needs_loader(arg: &Expr) -> bool {
    match arg {
        Expr::Arith { .. } => true,
        Expr::Concat(parts) => parts.iter().any(expr_has_decode_call),
        _ => false,
    }
}

fn expr_has_decode_call(expr: &Expr) -> bool {
    match expr {
        Expr::Call {
            name: CallName::Ident(ident),
            args,
        } => !ident.eq_ignore_ascii_case(b"chr") || args.iter().any(expr_has_decode_call),
        Expr::Call {
            name: CallName::DynVar(_) | CallName::DynIndex { .. } | CallName::DynExpr(_),
            ..
        } => true,
        Expr::Concat(parts) => parts.iter().any(expr_has_decode_call),
        Expr::Arith { lhs, rhs, .. } => expr_has_decode_call(lhs) || expr_has_decode_call(rhs),
        _ => false,
    }
}

fn preg_first_arg_is_e(args: &[Expr]) -> bool {
    let Some(Expr::StrLit(pat)): Option<&Expr> = args.first() else {
        return false;
    };
    pattern_has_e_modifier(pat)
}

fn eval_sink(expr: &Expr, env: &Env, depth: u32) -> Option<(LoaderSink, Vec<u8>)> {
    let Expr::Call { name, args } = expr else {
        return None;
    };
    match name {
        CallName::Ident(ident) => eval_ident_sink(ident, args, env, depth),
        CallName::DynVar(var) => eval_dynvar_sink(var, args, env, depth),
        CallName::DynIndex { name, idx } => {
            let callee: Vec<u8> = env.array_element(name, *idx)?;
            eval_indirect_sink(&callee, args, env, depth)
        }
        CallName::DynExpr(expr) => {
            let Value::Str(callee): Value = eval_expr(expr, env, depth)?;
            eval_indirect_sink(&callee, args, env, depth)
        }
    }
}

fn eval_ident_sink(
    ident: &[u8],
    args: &[Expr],
    env: &Env,
    depth: u32,
) -> Option<(LoaderSink, Vec<u8>)> {
    let lower: Vec<u8> = ident.to_ascii_lowercase();
    match lower.as_slice() {
        b"eval" => {
            let arg: &Expr = args.first()?;
            let Value::Str(s): Value = eval_expr(arg, env, depth)?;
            Some((LoaderSink::Eval, s))
        }
        b"assert" => {
            let arg: &Expr = args.first()?;
            let Value::Str(s): Value = eval_expr(arg, env, depth)?;
            Some((LoaderSink::Assert, s))
        }
        b"preg_replace" => eval_preg_replace_sink(args, env, depth),
        _ => None,
    }
}

fn eval_dynvar_sink(
    var: &[u8],
    args: &[Expr],
    env: &Env,
    depth: u32,
) -> Option<(LoaderSink, Vec<u8>)> {
    let Value::Str(callee): Value = env.get(var)?.clone();
    if env.is_code(var) {
        return Some((LoaderSink::CreateFunction, callee));
    }
    eval_indirect_sink(&callee, args, env, depth)
}

fn eval_indirect_sink(
    callee: &[u8],
    args: &[Expr],
    env: &Env,
    depth: u32,
) -> Option<(LoaderSink, Vec<u8>)> {
    let lower: Vec<u8> = callee.to_ascii_lowercase();
    if lower == b"eval" || lower == b"assert" {
        let arg: &Expr = args.first()?;
        let Value::Str(s): Value = eval_expr(arg, env, depth)?;
        return Some((LoaderSink::VariableFunction, s));
    }
    None
}

fn eval_preg_replace_sink(args: &[Expr], env: &Env, depth: u32) -> Option<(LoaderSink, Vec<u8>)> {
    let pattern: &Expr = args.first()?;
    let replacement: &Expr = args.get(1)?;
    let Value::Str(pat): Value = eval_expr(pattern, env, depth)?;
    if !pattern_has_e_modifier(&pat) {
        return None;
    }
    let Value::Str(rep): Value = eval_expr(replacement, env, depth)?;
    Some((LoaderSink::PregReplaceEval, rep))
}

fn pattern_has_e_modifier(pat: &[u8]) -> bool {
    let trimmed: &[u8] = pat.trim_ascii();
    let Some(&delim): Option<&u8> = trimmed.first() else {
        return false;
    };
    let close: u8 = match delim {
        b'(' => b')',
        b'{' => b'}',
        b'[' => b']',
        b'<' => b'>',
        other => other,
    };
    let Some(end): Option<usize> = trimmed.iter().rposition(|b: &u8| *b == close) else {
        return false;
    };
    if end == 0 {
        return false;
    }
    trimmed[end + 1..].contains(&b'e')
}

fn eval_expr(expr: &Expr, env: &Env, depth: u32) -> Option<Value> {
    if depth == 0 {
        return None;
    }
    match expr {
        Expr::StrLit(s) => Some(Value::Str(s.clone())),
        Expr::IntLit(n) => Some(Value::Str(n.to_string().into_bytes())),
        Expr::Var(name) => env.get(name).cloned(),
        Expr::DynVar(inner) => {
            let Value::Str(name): Value = eval_expr(inner, env, depth - 1)?;
            env.get(&name).cloned()
        }
        Expr::Index { name, idx } => env.array_element(name, *idx).map(Value::Str),
        Expr::Concat(parts) => {
            let mut out: Vec<u8> = Vec::new();
            for part in parts {
                let Value::Str(s): Value = eval_expr(part, env, depth - 1)?;
                out.extend_from_slice(&s);
            }
            Some(Value::Str(out))
        }
        Expr::Arith { op, lhs, rhs } => {
            let n: i64 = eval_arith(*op, lhs, rhs, env, depth - 1)?;
            Some(Value::Str(n.to_string().into_bytes()))
        }
        Expr::Call { name, args } => eval_call(name, args, env, depth - 1),
    }
}

fn eval_arith(op: ArithOp, lhs: &Expr, rhs: &Expr, env: &Env, depth: u32) -> Option<i64> {
    if depth == 0 {
        return None;
    }
    let a: i64 = eval_int(lhs, env, depth)?;
    let b: i64 = eval_int(rhs, env, depth)?;
    match op {
        ArithOp::Add => a.checked_add(b),
        ArithOp::Sub => a.checked_sub(b),
        ArithOp::Mul => a.checked_mul(b),
        ArithOp::Div => (b != 0).then(|| a.wrapping_div(b)),
        ArithOp::Mod => (b != 0).then(|| a.wrapping_rem(b)),
    }
}

fn eval_call(name: &CallName, args: &[Expr], env: &Env, depth: u32) -> Option<Value> {
    let resolved: Vec<u8> = match name {
        CallName::Ident(ident) => ident.clone(),
        CallName::DynVar(var) => {
            let Value::Str(callee): Value = env.get(var)?.clone();
            callee
        }
        CallName::DynIndex { name, idx } => env.array_element(name, *idx)?,
        CallName::DynExpr(expr) => {
            let Value::Str(callee): Value = eval_expr(expr, env, depth)?;
            callee
        }
    };
    let lower: Vec<u8> = resolved.to_ascii_lowercase();
    if lower == b"chr" {
        let code: i64 = eval_int(args.first()?, env, depth)?;
        let byte: u8 = u8::try_from(code.rem_euclid(256)).ok()?;
        return Some(Value::Str(vec![byte]));
    }
    apply_string_fn(&lower, args, env, depth)
}

fn eval_int(expr: &Expr, env: &Env, depth: u32) -> Option<i64> {
    if depth == 0 {
        return None;
    }
    match expr {
        Expr::IntLit(n) => Some(*n),
        Expr::Arith { op, lhs, rhs } => eval_arith(*op, lhs, rhs, env, depth - 1),
        Expr::Var(name) => match env.get(name)? {
            Value::Str(s) => std::str::from_utf8(s).ok()?.trim().parse::<i64>().ok(),
        },
        _ => {
            let Value::Str(s): Value = eval_expr(expr, env, depth - 1)?;
            std::str::from_utf8(&s).ok()?.trim().parse::<i64>().ok()
        }
    }
}

fn apply_string_fn(fname: &[u8], args: &[Expr], env: &Env, depth: u32) -> Option<Value> {
    let first: Option<Vec<u8>> = match args.first() {
        Some(arg) => {
            let Value::Str(s): Value = eval_expr(arg, env, depth)?;
            Some(s)
        }
        None => None,
    };
    match fname {
        b"base64_decode" => {
            let body: Vec<u8> = first?;
            let clean: Vec<u8> = body
                .iter()
                .copied()
                .filter(|b: &u8| !b.is_ascii_whitespace())
                .collect();
            B64_STD.decode(&clean).ok().map(Value::Str)
        }
        b"gzinflate" => inflate_raw(&first?).map(Value::Str),
        b"gzuncompress" => inflate_zlib(&first?).map(Value::Str),
        b"gzdecode" => gunzip(&first?).map(Value::Str),
        b"str_rot13" => Some(Value::Str(first?.iter().copied().map(rot13_byte).collect())),
        b"strrev" => Some(Value::Str(first?.iter().copied().rev().collect())),
        b"convert_uudecode" => Some(Value::Str(uudecode(&first?))),
        b"urldecode" => Some(Value::Str(url_decode(&first?, true))),
        b"rawurldecode" => Some(Value::Str(url_decode(&first?, false))),
        b"hex2bin" => decode_hex_stream(&first?).map(Value::Str),
        b"bin2hex" => Some(Value::Str(bin2hex(&first?))),
        b"strtolower" => Some(Value::Str(first?.to_ascii_lowercase())),
        b"strtoupper" => Some(Value::Str(first?.to_ascii_uppercase())),
        b"trim" | b"rtrim" | b"ltrim" | b"stripslashes" => Some(Value::Str(first?)),
        b"htmlspecialchars_decode" | b"html_entity_decode" => {
            Some(Value::Str(html_entity_decode(&first?)))
        }
        b"str_repeat" => {
            let s: Vec<u8> = first?;
            let n: i64 = eval_int(args.get(1)?, env, depth)?;
            str_repeat(&s, n).map(Value::Str)
        }
        b"substr" => {
            let s: Vec<u8> = first?;
            let start: i64 = eval_int(args.get(1)?, env, depth)?;
            let len: Option<i64> = match args.get(2) {
                Some(arg) => Some(eval_int(arg, env, depth)?),
                None => None,
            };
            Some(Value::Str(substr(&s, start, len)))
        }
        b"ord" => {
            let s: Vec<u8> = first?;
            let code: i64 = i64::from(s.first().copied().unwrap_or(0));
            Some(Value::Str(code.to_string().into_bytes()))
        }
        b"implode" | b"join" => apply_implode(args, env, depth),
        b"dechex" => Some(Value::Str(
            format!("{:x}", eval_int(args.first()?, env, depth)?).into_bytes(),
        )),
        b"hexdec" => {
            let s: Vec<u8> = first?;
            let txt: &str = std::str::from_utf8(&s).ok()?;
            let n: i64 = i64::from_str_radix(txt.trim(), 16).ok()?;
            Some(Value::Str(n.to_string().into_bytes()))
        }
        b"intval" => {
            let n: i64 = eval_int(args.first()?, env, depth)?;
            Some(Value::Str(n.to_string().into_bytes()))
        }
        b"str_replace" => {
            let from: Vec<u8> = first?;
            let to: Vec<u8> = string_arg(args.get(1)?, env, depth)?;
            let subject: Vec<u8> = string_arg(args.get(2)?, env, depth)?;
            str_replace_bytes(&subject, &from, &to).map(Value::Str)
        }
        b"pack" => {
            let fmt: Vec<u8> = first?;
            if fmt.trim_ascii() != b"H*" {
                return None;
            }
            let hex: Vec<u8> = string_arg(args.get(1)?, env, depth)?;
            decode_hex_stream(&hex).map(Value::Str)
        }
        b"strtr" => {
            let subject: Vec<u8> = first?;
            let from: Vec<u8> = string_arg(args.get(1)?, env, depth)?;
            let to: Vec<u8> = string_arg(args.get(2)?, env, depth)?;
            Some(Value::Str(strtr_bytes(&subject, &from, &to)))
        }
        _ => None,
    }
}

fn string_arg(expr: &Expr, env: &Env, depth: u32) -> Option<Vec<u8>> {
    let Value::Str(s): Value = eval_expr(expr, env, depth)?;
    Some(s)
}

fn inflate_bounded<R: std::io::Read>(mut dec: R) -> Option<Vec<u8>> {
    let cap_plus_one: u64 = EXPR_INFLATE_CAP as u64 + 1;
    let mut out: Vec<u8> = Vec::with_capacity(EXPR_INITIAL_CAP);
    let read: u64 = std::io::Read::take(&mut dec, cap_plus_one)
        .read_to_end(&mut out)
        .ok()? as u64;
    if read > EXPR_INFLATE_CAP as u64 {
        return None;
    }
    Some(out)
}

fn inflate_raw(body: &[u8]) -> Option<Vec<u8>> {
    inflate_bounded(DeflateDecoder::new(body))
}

fn inflate_zlib(body: &[u8]) -> Option<Vec<u8>> {
    inflate_bounded(flate2::read::ZlibDecoder::new(body))
}

fn gunzip(body: &[u8]) -> Option<Vec<u8>> {
    inflate_bounded(flate2::read::GzDecoder::new(body))
}

const fn rot13_byte(b: u8) -> u8 {
    match b {
        b'A'..=b'M' | b'a'..=b'm' => b + 13,
        b'N'..=b'Z' | b'n'..=b'z' => b - 13,
        other => other,
    }
}

fn url_decode(buf: &[u8], plus_is_space: bool) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(buf.len());
    let mut i: usize = 0;
    while i < buf.len() {
        match buf[i] {
            b'%' if i + 2 < buf.len() => {
                if let (Some(hi), Some(lo)) = (hex_nibble(buf[i + 1]), hex_nibble(buf[i + 2])) {
                    out.push((hi << 4) | lo);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b'+' if plus_is_space => {
                out.push(b' ');
                i += 1;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    out
}

fn decode_hex_stream(buf: &[u8]) -> Option<Vec<u8>> {
    let clean: Vec<u8> = buf
        .iter()
        .copied()
        .filter(|b: &u8| !b.is_ascii_whitespace())
        .collect();
    if clean.is_empty() || !clean.len().is_multiple_of(2) {
        return None;
    }
    let mut out: Vec<u8> = Vec::with_capacity(clean.len() / 2);
    for pair in clean.chunks_exact(2) {
        let hi: u8 = hex_nibble(pair[0])?;
        let lo: u8 = hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

const fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn uudecode(buf: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for line in buf.split(|&b: &u8| b == b'\n') {
        let line: &[u8] = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let count: u8 = uu_byte(line[0]);
        if count == 0 {
            break;
        }
        let mut produced: usize = 0;
        let data: &[u8] = &line[1..];
        for chunk in data.chunks(4) {
            if chunk.len() < 4 {
                break;
            }
            let b0: u8 = uu_byte(chunk[0]);
            let b1: u8 = uu_byte(chunk[1]);
            let b2: u8 = uu_byte(chunk[2]);
            let b3: u8 = uu_byte(chunk[3]);
            let triple: [u8; 3] = [(b0 << 2) | (b1 >> 4), (b1 << 4) | (b2 >> 2), (b2 << 6) | b3];
            for &byte in &triple {
                if produced < count as usize {
                    out.push(byte);
                    produced += 1;
                }
            }
        }
    }
    out
}

const fn uu_byte(c: u8) -> u8 {
    if c == b'`' {
        0
    } else {
        (c.wrapping_sub(b' ')) & 0x3f
    }
}

const STR_REPLACE_OUTPUT_CAP: usize = EXPR_INFLATE_CAP;

fn str_replace_bytes(buf: &[u8], from: &[u8], to: &[u8]) -> Option<Vec<u8>> {
    str_replace_bytes_with_cap(buf, from, to, STR_REPLACE_OUTPUT_CAP)
}

fn str_replace_bytes_with_cap(buf: &[u8], from: &[u8], to: &[u8], cap: usize) -> Option<Vec<u8>> {
    if from.is_empty() {
        if buf.len() > cap {
            return None;
        }
        return Some(buf.to_vec());
    }
    let mut out: Vec<u8> = Vec::with_capacity(buf.len().min(cap));
    let mut i: usize = 0;
    while i < buf.len() {
        if buf[i..].starts_with(from) {
            extend_checked(&mut out, to, cap)?;
            i += from.len();
            continue;
        }
        if out.len() == cap {
            return None;
        }
        out.push(buf[i]);
        i += 1;
    }
    Some(out)
}

fn extend_checked(out: &mut Vec<u8>, bytes: &[u8], cap: usize) -> Option<()> {
    let next: usize = out.len().checked_add(bytes.len())?;
    if next > cap {
        return None;
    }
    out.extend_from_slice(bytes);
    Some(())
}

const STR_REPEAT_OUTPUT_CAP: usize = 256 * 1024 * 1024;

fn bin2hex(buf: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(buf.len() * 2);
    for &b in buf {
        out.push(hex_digit(b >> 4));
        out.push(hex_digit(b & 0x0f));
    }
    out
}

const fn hex_digit(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        _ => b'a' + (nibble - 10),
    }
}

fn str_repeat(s: &[u8], times: i64) -> Option<Vec<u8>> {
    let count: usize = usize::try_from(times).ok()?;
    let total: usize = s.len().checked_mul(count)?;
    if total > STR_REPEAT_OUTPUT_CAP {
        return None;
    }
    Some(s.repeat(count))
}

fn substr(s: &[u8], start: i64, len: Option<i64>) -> Vec<u8> {
    let n: i64 = s.len() as i64;
    let begin: i64 = if start < 0 {
        (n + start).max(0)
    } else {
        start.min(n)
    };
    let end: i64 = match len {
        None => n,
        Some(l) if l < 0 => (n + l).max(begin),
        Some(l) => (begin + l).min(n),
    };
    let (b, e): (usize, usize) = (begin as usize, end.max(begin) as usize);
    s.get(b..e).map(<[u8]>::to_vec).unwrap_or_default()
}

fn html_entity_decode(buf: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(buf.len());
    let mut i: usize = 0;
    while i < buf.len() {
        if buf[i] == b'&'
            && let Some(end) = buf[i..].iter().position(|b: &u8| *b == b';')
        {
            let entity: &[u8] = &buf[i + 1..i + end];
            if let Some(decoded) = decode_html_entity(entity) {
                out.push(decoded);
                i += end + 1;
                continue;
            }
        }
        out.push(buf[i]);
        i += 1;
    }
    out
}

fn decode_html_entity(entity: &[u8]) -> Option<u8> {
    match entity {
        b"amp" => Some(b'&'),
        b"lt" => Some(b'<'),
        b"gt" => Some(b'>'),
        b"quot" => Some(b'"'),
        b"apos" | b"#39" => Some(b'\''),
        _ => entity
            .strip_prefix(b"#")
            .and_then(|d: &[u8]| std::str::from_utf8(d).ok())
            .and_then(|t: &str| t.parse::<u32>().ok())
            .and_then(|c: u32| u8::try_from(c).ok()),
    }
}

fn apply_implode(args: &[Expr], env: &Env, depth: u32) -> Option<Value> {
    None.or_else(|| implode_two(args, env, depth))
        .or_else(|| implode_one(args, env, depth))
}

fn implode_two(args: &[Expr], env: &Env, depth: u32) -> Option<Value> {
    let glue: Vec<u8> = string_arg(args.first()?, env, depth)?;
    let pieces: Vec<Vec<u8>> = array_pieces(args.get(1)?, env, depth)?;
    Some(Value::Str(pieces.join(glue.as_slice())))
}

fn implode_one(args: &[Expr], env: &Env, depth: u32) -> Option<Value> {
    if args.len() != 1 {
        return None;
    }
    let pieces: Vec<Vec<u8>> = array_pieces(args.first()?, env, depth)?;
    Some(Value::Str(pieces.concat()))
}

fn array_pieces(expr: &Expr, env: &Env, depth: u32) -> Option<Vec<Vec<u8>>> {
    if let Expr::Var(name) = expr {
        return env.get_array(name).cloned();
    }
    inline_array_elements(expr, env, depth)
}

fn inline_array_elements(expr: &Expr, env: &Env, depth: u32) -> Option<Vec<Vec<u8>>> {
    let Expr::Call { name, args } = expr else {
        return None;
    };
    let CallName::Ident(ident) = name else {
        return None;
    };
    if !ident.eq_ignore_ascii_case(b"array") {
        return None;
    }
    let mut out: Vec<Vec<u8>> = Vec::with_capacity(args.len());
    for arg in args {
        let Value::Str(s): Value = eval_expr(arg, env, depth)?;
        out.push(s);
    }
    Some(out)
}

fn strtr_bytes(subject: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let n: usize = from.len().min(to.len());
    let mut map: [Option<u8>; 256] = [None; 256];
    for i in 0..n {
        map[from[i] as usize] = Some(to[i]);
    }
    subject
        .iter()
        .map(|b: &u8| map[*b as usize].unwrap_or(*b))
        .collect()
}

fn eval_xor_keystream_loop(body: &[u8], env: &Env) -> Option<(Vec<u8>, Vec<u8>)> {
    if !body.contains(&b'^') {
        return None;
    }
    let out: Vec<u8> = capture_accumulator_target(body)?;
    let key: Vec<u8> = capture_modulo_indexed_var(body)?;
    let cipher: Vec<u8> = capture_plain_indexed_var(body)?;
    if cipher == key {
        return None;
    }
    let Value::Str(cipher_bytes): Value = env.get(&cipher)?.clone();
    let Value::Str(key_bytes): Value = env.get(&key)?.clone();
    if key_bytes.is_empty() {
        return None;
    }
    let plaintext: Vec<u8> = xor_repeating_key(&cipher_bytes, &key_bytes);
    Some((out, plaintext))
}

fn eval_rc4_loop(src: &[u8], env: &Env) -> Option<(Vec<u8>, Vec<u8>)> {
    memchr::memmem::find(src, b"256")?;
    let key: Vec<u8> = capture_rc4_key_var(src)?;
    let (out, cipher): (Vec<u8>, Vec<u8>) = capture_rc4_prga(src)?;
    if cipher == key {
        return None;
    }
    let Value::Str(cipher_bytes): Value = env.get(&cipher)?.clone();
    let Value::Str(key_bytes): Value = env.get(&key)?.clone();
    if key_bytes.is_empty() {
        return None;
    }
    let plaintext: Vec<u8> = rc4_transform(&key_bytes, &cipher_bytes);
    Some((out, plaintext))
}

fn xor_repeating_key(buf: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return buf.to_vec();
    }
    buf.iter()
        .enumerate()
        .map(|(i, b): (usize, &u8)| b ^ key[i % key.len()])
        .collect()
}

fn rc4_transform(key: &[u8], data: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    let mut state: [u8; 256] = [0u8; 256];
    for (i, slot) in state.iter_mut().enumerate() {
        *slot = i as u8;
    }
    let mut j: usize = 0;
    for i in 0..256usize {
        j = (j + state[i] as usize + key[i % key.len()] as usize) % 256;
        state.swap(i, j);
    }
    let mut a: usize = 0;
    let mut b: usize = 0;
    let mut out: Vec<u8> = Vec::with_capacity(data.len());
    for &c in data {
        a = (a + 1) % 256;
        b = (b + state[a] as usize) % 256;
        state.swap(a, b);
        let stream: u8 = state[(state[a] as usize + state[b] as usize) % 256];
        out.push(c ^ stream);
    }
    out
}

fn strip_dollar(name: &[u8]) -> Option<Vec<u8>> {
    name.strip_prefix(b"$").map(<[u8]>::to_vec)
}

#[allow(clippy::expect_used)]
fn capture_accumulator_target(body: &[u8]) -> Option<Vec<u8>> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re: &Regex =
        RE.get_or_init(|| Regex::new(r"(?is)(\$\w+)\s*\.=").expect("accumulator target regex"));
    strip_dollar(re.captures(body)?.get(1)?.as_bytes())
}

#[allow(clippy::expect_used)]
fn capture_modulo_indexed_var(body: &[u8]) -> Option<Vec<u8>> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re: &Regex = RE.get_or_init(|| {
        Regex::new(r"(?is)(\$\w+)\s*\[\s*\$\w+\s*%[^\]]*\]").expect("modulo-indexed var regex")
    });
    strip_dollar(re.captures(body)?.get(1)?.as_bytes())
}

#[allow(clippy::expect_used)]
fn capture_plain_indexed_var(body: &[u8]) -> Option<Vec<u8>> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re: &Regex = RE.get_or_init(|| {
        Regex::new(r"(?is)(\$\w+)\s*\[\s*\$\w+\s*\]").expect("plain-indexed var regex")
    });
    strip_dollar(re.captures(body)?.get(1)?.as_bytes())
}

#[allow(clippy::expect_used)]
fn capture_rc4_key_var(src: &[u8]) -> Option<Vec<u8>> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re: &Regex = RE.get_or_init(|| {
        Regex::new(
            r"(?is)=\s*\(\s*\$\w+\s*\+\s*\$\w+\s*\[\s*\$\w+\s*\]\s*\+\s*(?:ord\s*\(\s*)?(\$\w+)\s*\[\s*\$\w+\s*%[^\]]*\]",
        )
        .expect("rc4 key-schedule regex")
    });
    strip_dollar(re.captures(src)?.get(1)?.as_bytes())
}

#[allow(clippy::expect_used)]
fn capture_rc4_prga(src: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    static DIRECT: OnceLock<Regex> = OnceLock::new();
    static WRAPPED: OnceLock<Regex> = OnceLock::new();
    let direct: &Regex = DIRECT.get_or_init(|| {
        Regex::new(r"(?is)(\$\w+)\s*\.=\s*(\$\w+)\s*\[\s*\$\w+\s*\]\s*\^")
            .expect("rc4 prga direct regex")
    });
    let wrapped: &Regex = WRAPPED.get_or_init(|| {
        Regex::new(
            r"(?is)(\$\w+)\s*\.=\s*chr\s*\(\s*ord\s*\(\s*(\$\w+)\s*\[\s*\$\w+\s*\]\s*\)\s*\^",
        )
        .expect("rc4 prga wrapped regex")
    });
    let caps: regex::bytes::Captures<'_> =
        direct.captures(src).or_else(|| wrapped.captures(src))?;
    let out: Vec<u8> = strip_dollar(caps.get(1)?.as_bytes())?;
    let cipher: Vec<u8> = strip_dollar(caps.get(2)?.as_bytes())?;
    Some((out, cipher))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn multi_statement_b64_gzinflate_loader() {
        let blob: &[u8] =
            b"<?php\n$a = 'S03OyFdQL05NLkotUShKTc4vSy1KTVG3BgA=';\n$b = base64_decode($a);\n$c = gzinflate($b);\neval($c);\n";
        let report: LoaderReport = peel_loader(blob, DEFAULT_LOADER_DEPTH).expect("recovered");
        assert_eq!(report.sink, LoaderSink::Eval);
        assert_eq!(report.recovered, b"echo 'secret recovered';");
        assert_eq!(report.bound_variable_count, 3);
    }

    #[test]
    fn single_statement_is_left_for_inline_peeler() {
        let blob: &[u8] = b"<?php eval(base64_decode('ZWNobyAxOw=='));";
        let report: Option<LoaderReport> = peel_loader(blob, DEFAULT_LOADER_DEPTH);
        assert!(
            report.is_none(),
            "single-statement inline eval is the inline peeler's job"
        );
    }

    #[test]
    fn variable_function_eval_recovers() {
        let blob: &[u8] = b"<?php $g = 'ev'.'al'; $g(base64_decode('ZWNobyAxOw=='));";
        let report: LoaderReport = peel_loader(blob, DEFAULT_LOADER_DEPTH).expect("recovered");
        assert_eq!(report.sink, LoaderSink::VariableFunction);
        assert_eq!(report.recovered, b"echo 1;");
    }

    #[test]
    fn pattern_e_modifier_detected() {
        assert!(pattern_has_e_modifier(b"/(.*)/e"));
        assert!(pattern_has_e_modifier(b"#x#sei"));
        assert!(!pattern_has_e_modifier(b"/(.*)/s"));
        assert!(!pattern_has_e_modifier(b"/abc/"));
    }

    #[test]
    fn strtr_roundtrip() {
        assert_eq!(strtr_bytes(b"abc", b"abc", b"xyz"), b"xyz");
    }

    #[test]
    fn hex_named_function_resolves_through_double_quoted_escapes() {
        let blob: &[u8] = b"<?php $x = \"\\x62\\x61\\x73\\x65\\x36\\x34\\x5f\\x64\\x65\\x63\\x6f\\x64\\x65\"; eval($x('ZWNobyAxOw=='));";
        let report: LoaderReport = peel_loader(blob, DEFAULT_LOADER_DEPTH).expect("recovered");
        assert_eq!(report.recovered, b"echo 1;");
    }

    #[test]
    fn octal_escapes_in_double_quoted_string_decode() {
        let blob: &[u8] =
            b"<?php $g = \"\\145\\166\\141\\154\"; $g(base64_decode('ZWNobyAxOw=='));";
        let report: LoaderReport = peel_loader(blob, DEFAULT_LOADER_DEPTH).expect("recovered");
        assert_eq!(report.sink, LoaderSink::VariableFunction);
        assert_eq!(report.recovered, b"echo 1;");
    }

    #[test]
    fn chunked_base64_concatenation_is_reassembled() {
        let blob: &[u8] = b"<?php $p = 'ZWNo' . 'byAx' . 'Ow=='; eval(base64_decode($p));";
        let report: LoaderReport = peel_loader(blob, DEFAULT_LOADER_DEPTH).expect("recovered");
        assert_eq!(report.recovered, b"echo 1;");
    }

    #[test]
    fn unresolved_dynamic_variable_yields_no_recovery() {
        let blob: &[u8] = b"<?php $k = $_GET['k']; eval(base64_decode($k));";
        assert!(
            peel_loader(blob, DEFAULT_LOADER_DEPTH).is_none(),
            "a runtime-sourced variable is not statically resolvable and must wall to None"
        );
    }

    #[test]
    fn malformed_inputs_never_panic() {
        let cases: &[&[u8]] = &[
            b"",
            b"<?php",
            b"<?php $",
            b"<?php $a =",
            b"<?php $a = '",
            b"<?php $a = \"unterminated",
            b"<?php eval(",
            b"<?php eval(base64_decode(",
            b"<?php $a = 'x'; $b = ((((",
            b"<?php /* unterminated comment $a = 'x';",
            b"<?php $a = 'x' . . . ;",
            b"\xff\xfe\x00\x01 not php at all",
        ];
        for case in cases {
            let _: Option<LoaderReport> = peel_loader(case, DEFAULT_LOADER_DEPTH);
        }
    }

    #[test]
    fn deeply_nested_parens_never_stack_overflow_the_expr_parser() {
        const NESTING: usize = 50_000;
        let mut src: Vec<u8> = b"<?php $a = ".to_vec();
        src.extend(std::iter::repeat_n(b'(', NESTING));
        src.push(b'1');
        src.extend(std::iter::repeat_n(b')', NESTING));
        src.push(b';');
        let _: Option<LoaderReport> = peel_loader(&src, DEFAULT_LOADER_DEPTH);
    }

    #[test]
    fn depth_zero_resolves_nothing() {
        let blob: &[u8] = b"<?php $a = 'ZWNobyAxOw=='; $b = base64_decode($a); eval($b);";
        assert!(
            peel_loader(blob, 0).is_none(),
            "a zero depth budget must not resolve any expression"
        );
    }

    #[test]
    fn substr_handles_negative_and_clamped_ranges() {
        assert_eq!(substr(b"abcdef", 1, Some(3)), b"bcd");
        assert_eq!(substr(b"abcdef", -2, None), b"ef");
        assert_eq!(substr(b"abcdef", 2, Some(-1)), b"cde");
        assert_eq!(substr(b"abc", 10, Some(5)), b"");
        assert_eq!(substr(b"abc", 0, Some(100)), b"abc");
    }

    #[test]
    fn bin2hex_and_hex2bin_are_inverse() {
        let raw: &[u8] = b"\x00\xff hello";
        let hex: Vec<u8> = bin2hex(raw);
        assert_eq!(hex, b"00ff2068656c6c6f");
        assert_eq!(decode_hex_stream(&hex).unwrap(), raw);
    }

    #[test]
    fn str_repeat_is_bounded() {
        assert_eq!(str_repeat(b"ab", 3), Some(b"ababab".to_vec()));
        assert_eq!(str_repeat(b"x", -1), None);
        assert!(str_repeat(b"abcd", i64::MAX).is_none());
    }

    #[test]
    fn str_replace_expansion_is_bounded() {
        assert!(str_replace_bytes_with_cap(b"aaaa", b"a", b"bbb", 8).is_none());
    }

    #[test]
    fn arithmetic_folds_a_dynamic_base64_decode_name() {
        let blob: &[u8] = b"<?php $f = 'base'.(32*2).'_decode'; eval($f('ZWNobyAxOw=='));";
        let report: LoaderReport = peel_loader(blob, DEFAULT_LOADER_DEPTH).expect("recovered");
        assert_eq!(report.recovered, b"echo 1;");
    }

    #[test]
    fn implode_of_array_variable_builds_function_name() {
        let blob: &[u8] =
            b"<?php $a = array('base64','_de','code'); $fn = implode('', $a); eval($fn('ZWNobyAxOw=='));";
        let report: LoaderReport = peel_loader(blob, DEFAULT_LOADER_DEPTH).expect("recovered");
        assert_eq!(report.recovered, b"echo 1;");
    }

    #[test]
    fn curly_variable_globals_assignment_resolves() {
        let blob: &[u8] =
            b"<?php ${'GLOBALS'}['fn'] = 'base64_decode'; $f = $GLOBALS['fn']; eval($f('ZWNobyAxOw=='));";
        let report: LoaderReport = peel_loader(blob, DEFAULT_LOADER_DEPTH).expect("recovered");
        assert_eq!(report.recovered, b"echo 1;");
    }

    #[test]
    fn dollar_dollar_assignment_target_resolves_indirect_variable() {
        let blob: &[u8] =
            b"<?php $k = 'payload'; $$k = 'ZWNobyAxOw=='; eval(base64_decode($payload));";
        let report: LoaderReport = peel_loader(blob, DEFAULT_LOADER_DEPTH).expect("recovered");
        assert_eq!(report.recovered, b"echo 1;");
    }

    #[test]
    fn curly_dynamic_assignment_target_resolves_indirect_variable() {
        let blob: &[u8] =
            b"<?php $k = 'payload'; ${$k} = 'ZWNobyAxOw=='; eval(base64_decode($payload));";
        let report: LoaderReport = peel_loader(blob, DEFAULT_LOADER_DEPTH).expect("recovered");
        assert_eq!(report.recovered, b"echo 1;");
    }

    #[test]
    fn dollar_dollar_call_site_indirection_resolves_eval_sink() {
        let blob: &[u8] = b"<?php $k = 'x'; $x = 'assert'; $$k(base64_decode('ZWNobyAxOw=='));";
        let report: LoaderReport = peel_loader(blob, DEFAULT_LOADER_DEPTH).expect("recovered");
        assert_eq!(report.sink, LoaderSink::VariableFunction);
        assert_eq!(report.recovered, b"echo 1;");
    }

    #[test]
    fn triple_dollar_variable_variable_reads_through_two_levels_of_indirection() {
        let blob: &[u8] =
            b"<?php $a = 'b'; $b = 'c'; $c = 'ZWNobyAxOw=='; eval(base64_decode($$$a));";
        let report: LoaderReport = peel_loader(blob, DEFAULT_LOADER_DEPTH).expect("recovered");
        assert_eq!(report.recovered, b"echo 1;");
    }

    #[test]
    fn dynamic_target_from_runtime_source_is_never_bound() {
        let blob: &[u8] =
            b"<?php $k = $_GET['k']; $$k = 'ZWNobyAxOw=='; eval(base64_decode($payload));";
        assert!(
            peel_loader(blob, DEFAULT_LOADER_DEPTH).is_none(),
            "a request-sourced variable-variable name must never be fabricated"
        );
    }

    #[test]
    fn deeply_chained_dollar_signs_never_stack_overflow_the_var_ref_parser() {
        const CHAIN: usize = 50_000;
        let mut src: Vec<u8> = b"<?php eval(".to_vec();
        src.extend(std::iter::repeat_n(b'$', CHAIN));
        src.extend_from_slice(b"a);");
        let _: Option<LoaderReport> = peel_loader(&src, DEFAULT_LOADER_DEPTH);
    }

    #[test]
    fn create_function_assignment_then_call_is_a_sink() {
        let blob: &[u8] =
            b"<?php $d = base64_decode('ZWNobyAxOw=='); $e = create_function('', $d); $e();";
        let report: LoaderReport = peel_loader(blob, DEFAULT_LOADER_DEPTH).expect("recovered");
        assert_eq!(report.sink, LoaderSink::CreateFunction);
        assert_eq!(report.recovered, b"echo 1;");
    }

    #[test]
    fn substr_carved_function_name_resolves() {
        let blob: &[u8] = b"<?php $n = substr('xbase64_decodex', 1, 13); eval($n('ZWNobyAxOw=='));";
        let report: LoaderReport = peel_loader(blob, DEFAULT_LOADER_DEPTH).expect("recovered");
        assert_eq!(report.recovered, b"echo 1;");
    }

    #[test]
    fn array_indexed_function_dispatch_recovers() {
        let blob: &[u8] =
            b"<?php $f = array('base64_decode','strrev'); eval($f[0]($f[1]('==wOxAyboNWZ')));";
        let report: LoaderReport = peel_loader(blob, DEFAULT_LOADER_DEPTH).expect("recovered");
        assert_eq!(report.sink, LoaderSink::Eval);
        assert_eq!(report.recovered, b"echo 1;");
    }

    #[test]
    fn array_indexed_eval_alias_is_a_variable_function_sink() {
        let blob: &[u8] =
            b"<?php $f = array('eval','base64_decode'); $f[0]($f[1]('ZWNobyAxOw=='));";
        let report: LoaderReport = peel_loader(blob, DEFAULT_LOADER_DEPTH).expect("recovered");
        assert_eq!(report.sink, LoaderSink::VariableFunction);
        assert_eq!(report.recovered, b"echo 1;");
    }

    #[test]
    fn array_index_value_resolves_as_string() {
        let blob: &[u8] =
            b"<?php $a = array('ZWNo','byAx','Ow=='); $p = $a[0] . $a[1] . $a[2]; eval(base64_decode($p));";
        let report: LoaderReport = peel_loader(blob, DEFAULT_LOADER_DEPTH).expect("recovered");
        assert_eq!(report.recovered, b"echo 1;");
    }

    #[test]
    fn html_entity_decode_handles_named_and_numeric_entities() {
        assert_eq!(html_entity_decode(b"a&lt;b&gt;c&#39;d"), b"a<b>c'd");
        assert_eq!(html_entity_decode(b"no entities"), b"no entities");
    }

    fn xor_encode(plain: &[u8], key: &[u8]) -> Vec<u8> {
        xor_repeating_key(plain, key)
    }

    #[test]
    fn static_xor_keystream_loop_materializes_plaintext() {
        let payload: &[u8] = b"echo 'xor-loop-recovered';";
        let key: &[u8] = b"K3yStream";
        let cipher_b64: String = B64_STD.encode(xor_encode(payload, key));
        let src: String = format!(
            "<?php $d=base64_decode('{cipher_b64}');$k='K3yStream';$o='';for($i=0;$i<strlen($d);$i++){{$o.=$d[$i]^$k[$i%strlen($k)];}}eval($o);"
        );
        let report: LoaderReport =
            peel_loader(src.as_bytes(), DEFAULT_LOADER_DEPTH).expect("recovered");
        assert_eq!(report.sink, LoaderSink::Eval);
        assert_eq!(report.recovered, payload);
    }

    #[test]
    fn static_xor_chr_ord_loop_materializes_plaintext() {
        let payload: &[u8] = b"echo 'chr-ord-xor';";
        let key: &[u8] = b"pw";
        let cipher_b64: String = B64_STD.encode(xor_encode(payload, key));
        let src: String = format!(
            "<?php $d=base64_decode('{cipher_b64}');$k='pw';$o='';for($i=0;$i<strlen($d);$i++)$o.=chr(ord($d[$i])^ord($k[$i%strlen($k)]));eval($o);"
        );
        let report: LoaderReport =
            peel_loader(src.as_bytes(), DEFAULT_LOADER_DEPTH).expect("recovered");
        assert_eq!(report.recovered, payload);
    }

    #[test]
    fn static_rc4_loop_materializes_plaintext() {
        let payload: &[u8] = b"echo 'rc4-static-recovered';";
        let key: &[u8] = b"staticrc4key";
        let cipher_b64: String = B64_STD.encode(rc4_transform(key, payload));
        let src: String = format!(
            "<?php $d=base64_decode('{cipher_b64}');$k='staticrc4key';$s=array();for($i=0;$i<256;$i++){{$s[$i]=$i;}}$j=0;for($i=0;$i<256;$i++){{$j=($j+$s[$i]+ord($k[$i%strlen($k)]))%256;$t=$s[$i];$s[$i]=$s[$j];$s[$j]=$t;}}$i=0;$j=0;$o='';for($y=0;$y<strlen($d);$y++){{$i=($i+1)%256;$j=($j+$s[$i])%256;$t=$s[$i];$s[$i]=$s[$j];$s[$j]=$t;$o.=$d[$y]^chr($s[($s[$i]+$s[$j])%256]);}}eval($o);"
        );
        let report: LoaderReport =
            peel_loader(src.as_bytes(), DEFAULT_LOADER_DEPTH).expect("recovered");
        assert_eq!(report.sink, LoaderSink::Eval);
        assert_eq!(report.recovered, payload);
    }

    #[test]
    fn dynamic_key_xor_loop_body_is_never_fabricated() {
        let payload: &[u8] = b"echo 'SHOULD-NOT-APPEAR';";
        let key: &[u8] = b"K3yStream";
        let cipher_b64: String = B64_STD.encode(xor_encode(payload, key));
        let src: String = format!(
            "<?php $d=base64_decode('{cipher_b64}');$k=$_GET['k'];$o='';for($i=0;$i<strlen($d);$i++){{$o.=$d[$i]^$k[$i%strlen($k)];}}eval($o);"
        );
        let report: Option<LoaderReport> = peel_loader(src.as_bytes(), DEFAULT_LOADER_DEPTH);
        if let Some(r) = report {
            assert!(
                !r.recovered
                    .windows(payload.len())
                    .any(|w: &[u8]| w == payload),
                "a request-sourced key is absent from the file; the loop plaintext must never be fabricated"
            );
        }
    }

    #[test]
    fn rc4_transform_is_symmetric() {
        let key: &[u8] = b"abc123";
        let plain: &[u8] = b"the quick brown fox";
        let cipher: Vec<u8> = rc4_transform(key, plain);
        assert_ne!(cipher, plain);
        assert_eq!(rc4_transform(key, &cipher), plain);
    }
}
