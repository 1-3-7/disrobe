use crate::error::{Error, Result};

pub const MAX_SOURCE_BYTES: usize = 8 << 20;
const MAX_TOKENS: usize = 1 << 20;
const MAX_NEST_DEPTH: usize = 200;
const MAX_BLOCK_STATEMENTS: usize = 1 << 18;
const MAX_LOCALS: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: u32,
    pub end: u32,
}

impl Span {
    #[inline]
    #[must_use]
    pub fn text(self, src: &str) -> &str {
        &src[self.start as usize..self.end as usize]
    }

    #[inline]
    #[must_use]
    const fn join(self, other: Self) -> Self {
        Self {
            start: self.start,
            end: other.end,
        }
    }
}

pub type LocalId = u32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Var {
    Local(LocalId),
    Global(Span),
}

#[derive(Debug, Clone)]
pub struct Block {
    pub stats: Vec<Stat>,
}

#[derive(Debug, Clone)]
pub struct Stat {
    pub kind: StatKind,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum StatKind {
    Local {
        targets: Vec<LocalId>,
        values: Vec<Expr>,
    },
    Assign {
        targets: Vec<AssignTarget>,
        values: Vec<Expr>,
    },
    ExprStat(Expr),
    Do(Block),
    While {
        cond: Expr,
        body: Block,
    },
    Repeat {
        body: Block,
        cond: Expr,
    },
    If {
        arms: Vec<(Expr, Block)>,
        else_body: Option<Block>,
    },
    NumericFor {
        var: LocalId,
        start: Expr,
        stop: Expr,
        step: Option<Expr>,
        body: Block,
    },
    GenericFor {
        vars: Vec<LocalId>,
        exprs: Vec<Expr>,
        body: Block,
    },
    Return(Vec<Expr>),
    Break,
}

#[derive(Debug, Clone)]
pub enum AssignTarget {
    Var(Var, Span),
    Index(Box<Expr>, Box<Expr>, Span),
}

#[derive(Debug, Clone)]
pub struct Expr {
    pub kind: ExprKind,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum ExprKind {
    Nil,
    True,
    False,
    Vararg,
    Number(f64),
    Str,
    Var(Var),
    Index(Box<Expr>, Box<Expr>),
    Call {
        base: Box<Expr>,
        args: Vec<Expr>,
    },
    MethodCall {
        base: Box<Expr>,
        method: Span,
        args: Vec<Expr>,
    },
    Function {
        params: Vec<LocalId>,
        is_vararg: bool,
        body: Block,
    },
    Table(Vec<TableField>),
    Binary(BinOp, Box<Expr>, Box<Expr>),
    Unary(UnOp, Box<Expr>),
    Paren(Box<Expr>),
}

#[derive(Debug, Clone)]
pub enum TableField {
    Positional(Expr),
    Named(Span, Expr),
    Indexed(Expr, Expr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Pow,
    Concat,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnOp {
    Neg,
    Not,
    Len,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tok {
    Name,
    Number,
    Str,
    KAnd,
    KBreak,
    KDo,
    KElse,
    KElseif,
    KEnd,
    KFalse,
    KFor,
    KFunction,
    KIf,
    KIn,
    KLocal,
    KNil,
    KNot,
    KOr,
    KRepeat,
    KReturn,
    KThen,
    KTrue,
    KUntil,
    KWhile,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Caret,
    Hash,
    EqEq,
    NotEq,
    LtEq,
    GtEq,
    Lt,
    Gt,
    Eq,
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Semi,
    Colon,
    Comma,
    Dot,
    DotDot,
    Ellipsis,
    Eof,
}

#[derive(Debug, Clone, Copy)]
struct Token {
    tok: Tok,
    span: Span,
    number: f64,
}

struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self { src, pos: 0 }
    }

    fn peek_byte(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn byte_at(&self, offset: usize) -> Option<u8> {
        self.src.get(self.pos + offset).copied()
    }

    fn skip_trivia(&mut self) -> Result<()> {
        loop {
            match self.peek_byte() {
                Some(b) if b.is_ascii_whitespace() => self.pos += 1,
                Some(b'-') if self.byte_at(1) == Some(b'-') => {
                    self.pos += 2;
                    if let Some(level) = self.long_bracket_level() {
                        self.skip_long_bracket(level)?;
                    } else {
                        while self.peek_byte().is_some_and(|b: u8| b != b'\n') {
                            self.pos += 1;
                        }
                    }
                }
                _ => return Ok(()),
            }
        }
    }

    fn long_bracket_level(&self) -> Option<usize> {
        if self.peek_byte() != Some(b'[') {
            return None;
        }
        let mut i: usize = 1;
        while self.byte_at(i) == Some(b'=') {
            i += 1;
        }
        if self.byte_at(i) == Some(b'[') {
            Some(i - 1)
        } else {
            None
        }
    }

    fn skip_long_bracket(&mut self, level: usize) -> Result<()> {
        self.pos += level + 2;
        loop {
            match self.peek_byte() {
                None => return Err(Error::DecompileUnsupported("unterminated long bracket")),
                Some(b']') => {
                    let mut i: usize = 1;
                    while self.byte_at(i) == Some(b'=') {
                        i += 1;
                    }
                    if i - 1 == level && self.byte_at(i) == Some(b']') {
                        self.pos += i + 1;
                        return Ok(());
                    }
                    self.pos += 1;
                }
                Some(_) => self.pos += 1,
            }
        }
    }

    fn skip_string(&mut self, quote: u8) -> Result<()> {
        self.pos += 1;
        loop {
            match self.peek_byte() {
                None | Some(b'\n') => {
                    return Err(Error::DecompileUnsupported("unterminated string literal"));
                }
                Some(b'\\') => self.pos += 2,
                Some(b) if b == quote => {
                    self.pos += 1;
                    return Ok(());
                }
                Some(_) => self.pos += 1,
            }
        }
    }

    fn lex_number(&mut self, start: usize) -> Result<f64> {
        if self.peek_byte() == Some(b'0') && matches!(self.byte_at(1), Some(b'x' | b'X')) {
            self.pos += 2;
            let hex_start: usize = self.pos;
            while self.peek_byte().is_some_and(|b: u8| b.is_ascii_hexdigit()) {
                self.pos += 1;
            }
            let text: &str = std::str::from_utf8(&self.src[hex_start..self.pos])
                .map_err(|_: std::str::Utf8Error| Error::DecompileUnsupported("bad hex digits"))?;
            let value: u64 =
                u64::from_str_radix(text, 16).map_err(|_: std::num::ParseIntError| {
                    Error::DecompileUnsupported("bad hex literal")
                })?;
            return Ok(value as f64);
        }
        while self.peek_byte().is_some_and(|b: u8| b.is_ascii_digit()) {
            self.pos += 1;
        }
        if self.peek_byte() == Some(b'.') {
            self.pos += 1;
            while self.peek_byte().is_some_and(|b: u8| b.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        if matches!(self.peek_byte(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek_byte(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            while self.peek_byte().is_some_and(|b: u8| b.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        let text: &str = std::str::from_utf8(&self.src[start..self.pos])
            .map_err(|_: std::str::Utf8Error| Error::DecompileUnsupported("bad number digits"))?;
        text.parse::<f64>().map_err(|_: std::num::ParseFloatError| {
            Error::DecompileUnsupported("bad number literal")
        })
    }

    fn next(&mut self) -> Result<Token> {
        self.skip_trivia()?;
        let start: usize = self.pos;
        let Some(byte): Option<u8> = self.peek_byte() else {
            return Ok(Token {
                tok: Tok::Eof,
                span: span_of(start, self.pos),
                number: 0.0,
            });
        };
        if byte.is_ascii_alphabetic() || byte == b'_' {
            while self
                .peek_byte()
                .is_some_and(|b: u8| b.is_ascii_alphanumeric() || b == b'_')
            {
                self.pos += 1;
            }
            let word: &[u8] = &self.src[start..self.pos];
            let tok: Tok = keyword_token(word).unwrap_or(Tok::Name);
            return Ok(Token {
                tok,
                span: span_of(start, self.pos),
                number: 0.0,
            });
        }
        if byte.is_ascii_digit()
            || (byte == b'.' && self.byte_at(1).is_some_and(|b: u8| b.is_ascii_digit()))
        {
            let value: f64 = self.lex_number(start)?;
            return Ok(Token {
                tok: Tok::Number,
                span: span_of(start, self.pos),
                number: value,
            });
        }
        if byte == b'"' || byte == b'\'' {
            self.skip_string(byte)?;
            return Ok(Token {
                tok: Tok::Str,
                span: span_of(start, self.pos),
                number: 0.0,
            });
        }
        if byte == b'[' {
            if let Some(level) = self.long_bracket_level() {
                self.skip_long_bracket(level)?;
                return Ok(Token {
                    tok: Tok::Str,
                    span: span_of(start, self.pos),
                    number: 0.0,
                });
            }
            self.pos += 1;
            return Ok(Token {
                tok: Tok::LBracket,
                span: span_of(start, self.pos),
                number: 0.0,
            });
        }
        let two: Option<u8> = self.byte_at(1);
        let (tok, len): (Tok, usize) = match (byte, two) {
            (b'=', Some(b'=')) => (Tok::EqEq, 2),
            (b'~', Some(b'=')) => (Tok::NotEq, 2),
            (b'<', Some(b'=')) => (Tok::LtEq, 2),
            (b'>', Some(b'=')) => (Tok::GtEq, 2),
            (b'.', Some(b'.')) => {
                if self.byte_at(2) == Some(b'.') {
                    (Tok::Ellipsis, 3)
                } else {
                    (Tok::DotDot, 2)
                }
            }
            (b'+', _) => (Tok::Plus, 1),
            (b'-', _) => (Tok::Minus, 1),
            (b'*', _) => (Tok::Star, 1),
            (b'/', _) => (Tok::Slash, 1),
            (b'%', _) => (Tok::Percent, 1),
            (b'^', _) => (Tok::Caret, 1),
            (b'#', _) => (Tok::Hash, 1),
            (b'<', _) => (Tok::Lt, 1),
            (b'>', _) => (Tok::Gt, 1),
            (b'=', _) => (Tok::Eq, 1),
            (b'(', _) => (Tok::LParen, 1),
            (b')', _) => (Tok::RParen, 1),
            (b'{', _) => (Tok::LBrace, 1),
            (b'}', _) => (Tok::RBrace, 1),
            (b']', _) => (Tok::RBracket, 1),
            (b';', _) => (Tok::Semi, 1),
            (b':', _) => (Tok::Colon, 1),
            (b',', _) => (Tok::Comma, 1),
            (b'.', _) => (Tok::Dot, 1),
            _ => return Err(Error::DecompileUnsupported("unrecognized Lua source byte")),
        };
        self.pos += len;
        Ok(Token {
            tok,
            span: span_of(start, self.pos),
            number: 0.0,
        })
    }
}

#[inline]
fn span_of(start: usize, end: usize) -> Span {
    Span {
        start: start as u32,
        end: end as u32,
    }
}

fn keyword_token(word: &[u8]) -> Option<Tok> {
    Some(match word {
        b"and" => Tok::KAnd,
        b"break" => Tok::KBreak,
        b"do" => Tok::KDo,
        b"else" => Tok::KElse,
        b"elseif" => Tok::KElseif,
        b"end" => Tok::KEnd,
        b"false" => Tok::KFalse,
        b"for" => Tok::KFor,
        b"function" => Tok::KFunction,
        b"if" => Tok::KIf,
        b"in" => Tok::KIn,
        b"local" => Tok::KLocal,
        b"nil" => Tok::KNil,
        b"not" => Tok::KNot,
        b"or" => Tok::KOr,
        b"repeat" => Tok::KRepeat,
        b"return" => Tok::KReturn,
        b"then" => Tok::KThen,
        b"true" => Tok::KTrue,
        b"until" => Tok::KUntil,
        b"while" => Tok::KWhile,
        _ => return None,
    })
}

fn tokenize(src: &str) -> Result<Vec<Token>> {
    if src.len() > MAX_SOURCE_BYTES {
        return Err(Error::DecompileUnsupported(
            "source exceeds parser byte budget",
        ));
    }
    let mut lexer: Lexer<'_> = Lexer::new(src.as_bytes());
    let mut tokens: Vec<Token> = Vec::new();
    loop {
        let tok: Token = lexer.next()?;
        let is_eof: bool = tok.tok == Tok::Eof;
        tokens.push(tok);
        if is_eof {
            break;
        }
        if tokens.len() > MAX_TOKENS {
            return Err(Error::DecompileUnsupported(
                "source exceeds parser token budget",
            ));
        }
    }
    Ok(tokens)
}

#[derive(Debug)]
struct ScopeStack {
    frames: Vec<Vec<(Vec<u8>, LocalId)>>,
    next_id: LocalId,
}

impl ScopeStack {
    fn new() -> Self {
        Self {
            frames: vec![Vec::new()],
            next_id: 0,
        }
    }

    fn push(&mut self) {
        self.frames.push(Vec::new());
    }

    fn pop(&mut self) {
        self.frames.pop();
    }

    fn declare(&mut self, name: &[u8]) -> Result<LocalId> {
        if self.next_id as usize >= MAX_LOCALS {
            return Err(Error::DecompileUnsupported("too many local declarations"));
        }
        let id: LocalId = self.next_id;
        self.next_id += 1;
        if let Some(top) = self.frames.last_mut() {
            top.push((name.to_vec(), id));
        }
        Ok(id)
    }

    fn resolve(&self, name: &[u8]) -> Option<LocalId> {
        for frame in self.frames.iter().rev() {
            for (n, id) in frame.iter().rev() {
                if n.as_slice() == name {
                    return Some(*id);
                }
            }
        }
        None
    }

    fn local_count(&self) -> u32 {
        self.next_id
    }
}

#[derive(Debug)]
pub struct Parser<'a> {
    src: &'a str,
    tokens: Vec<Token>,
    idx: usize,
    scope: ScopeStack,
    depth: usize,
}

impl<'a> Parser<'a> {
    pub fn new(src: &'a str) -> Result<Self> {
        let tokens: Vec<Token> = tokenize(src)?;
        Ok(Self {
            src,
            tokens,
            idx: 0,
            scope: ScopeStack::new(),
            depth: 0,
        })
    }

    #[must_use]
    pub fn local_count(&self) -> u32 {
        self.scope.local_count()
    }

    fn peek(&self) -> Tok {
        self.tokens[self.idx.min(self.tokens.len() - 1)].tok
    }

    fn peek_span(&self) -> Span {
        self.tokens[self.idx.min(self.tokens.len() - 1)].span
    }

    fn bump(&mut self) -> Token {
        let tok: Token = self.tokens[self.idx.min(self.tokens.len() - 1)];
        if self.idx + 1 < self.tokens.len() {
            self.idx += 1;
        }
        tok
    }

    fn expect(&mut self, tok: Tok) -> Result<Token> {
        if self.peek() == tok {
            Ok(self.bump())
        } else {
            Err(Error::DecompileUnsupported(
                "unexpected token while parsing Lua source",
            ))
        }
    }

    fn enter_nest(&mut self) -> Result<()> {
        self.depth += 1;
        if self.depth > MAX_NEST_DEPTH {
            return Err(Error::DecompileUnsupported(
                "Lua source nesting exceeds parser depth budget",
            ));
        }
        Ok(())
    }

    fn exit_nest(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    pub fn parse_chunk(&mut self) -> Result<Block> {
        let block: Block = self.parse_block()?;
        self.expect(Tok::Eof)?;
        Ok(block)
    }

    fn parse_block(&mut self) -> Result<Block> {
        self.enter_nest()?;
        let mut stats: Vec<Stat> = Vec::new();
        loop {
            while self.peek() == Tok::Semi {
                self.bump();
            }
            if block_follow(self.peek()) {
                break;
            }
            if self.peek() == Tok::KReturn {
                let start: Span = self.peek_span();
                self.bump();
                let values: Vec<Expr> = if !block_follow(self.peek()) && self.peek() != Tok::Semi {
                    self.parse_expr_list()?
                } else {
                    Vec::new()
                };
                let end: Span = self.peek_span();
                while self.peek() == Tok::Semi {
                    self.bump();
                }
                stats.push(Stat {
                    kind: StatKind::Return(values),
                    span: start.join(end),
                });
                break;
            }
            let stat: Stat = self.parse_statement()?;
            stats.push(stat);
            if stats.len() > MAX_BLOCK_STATEMENTS {
                return Err(Error::DecompileUnsupported(
                    "block exceeds parser statement budget",
                ));
            }
        }
        self.exit_nest();
        Ok(Block { stats })
    }

    fn parse_statement(&mut self) -> Result<Stat> {
        let start: Span = self.peek_span();
        match self.peek() {
            Tok::KBreak => {
                self.bump();
                Ok(Stat {
                    kind: StatKind::Break,
                    span: start,
                })
            }
            Tok::KDo => {
                self.bump();
                self.scope.push();
                let body: Block = self.parse_block()?;
                self.scope.pop();
                let end: Span = self.expect(Tok::KEnd)?.span;
                Ok(Stat {
                    kind: StatKind::Do(body),
                    span: start.join(end),
                })
            }
            Tok::KWhile => {
                self.bump();
                let cond: Expr = self.parse_expr()?;
                self.expect(Tok::KDo)?;
                self.scope.push();
                let body: Block = self.parse_block()?;
                self.scope.pop();
                let end: Span = self.expect(Tok::KEnd)?.span;
                Ok(Stat {
                    kind: StatKind::While { cond, body },
                    span: start.join(end),
                })
            }
            Tok::KRepeat => {
                self.bump();
                self.scope.push();
                let body: Block = self.parse_block()?;
                self.expect(Tok::KUntil)?;
                let cond: Expr = self.parse_expr()?;
                self.scope.pop();
                let end: Span = cond.span;
                Ok(Stat {
                    kind: StatKind::Repeat { body, cond },
                    span: start.join(end),
                })
            }
            Tok::KIf => self.parse_if(start),
            Tok::KFor => self.parse_for(start),
            Tok::KFunction => self.parse_function_stat(start),
            Tok::KLocal => self.parse_local(start),
            _ => self.parse_expr_or_assign_stat(start),
        }
    }

    fn parse_if(&mut self, start: Span) -> Result<Stat> {
        self.bump();
        let mut arms: Vec<(Expr, Block)> = Vec::new();
        let cond: Expr = self.parse_expr()?;
        self.expect(Tok::KThen)?;
        self.scope.push();
        let body: Block = self.parse_block()?;
        self.scope.pop();
        arms.push((cond, body));
        let mut else_body: Option<Block> = None;
        loop {
            match self.peek() {
                Tok::KElseif => {
                    self.bump();
                    let cond: Expr = self.parse_expr()?;
                    self.expect(Tok::KThen)?;
                    self.scope.push();
                    let body: Block = self.parse_block()?;
                    self.scope.pop();
                    arms.push((cond, body));
                }
                Tok::KElse => {
                    self.bump();
                    self.scope.push();
                    else_body = Some(self.parse_block()?);
                    self.scope.pop();
                    break;
                }
                _ => break,
            }
        }
        let end: Span = self.expect(Tok::KEnd)?.span;
        Ok(Stat {
            kind: StatKind::If { arms, else_body },
            span: start.join(end),
        })
    }

    fn parse_for(&mut self, start: Span) -> Result<Stat> {
        self.bump();
        let first_name: Span = self.expect(Tok::Name)?.span;
        if self.peek() == Tok::Eq {
            self.bump();
            let range_start: Expr = self.parse_expr()?;
            self.expect(Tok::Comma)?;
            let stop: Expr = self.parse_expr()?;
            let step: Option<Expr> = if self.peek() == Tok::Comma {
                self.bump();
                Some(self.parse_expr()?)
            } else {
                None
            };
            self.expect(Tok::KDo)?;
            self.scope.push();
            let var: LocalId = self.scope.declare(first_name.text(self.src).as_bytes())?;
            let body: Block = self.parse_block()?;
            self.scope.pop();
            let end: Span = self.expect(Tok::KEnd)?.span;
            return Ok(Stat {
                kind: StatKind::NumericFor {
                    var,
                    start: range_start,
                    stop,
                    step,
                    body,
                },
                span: start.join(end),
            });
        }
        let mut names: Vec<Span> = vec![first_name];
        while self.peek() == Tok::Comma {
            self.bump();
            names.push(self.expect(Tok::Name)?.span);
        }
        self.expect(Tok::KIn)?;
        let exprs: Vec<Expr> = self.parse_expr_list()?;
        self.expect(Tok::KDo)?;
        self.scope.push();
        let mut vars: Vec<LocalId> = Vec::with_capacity(names.len());
        for name in &names {
            vars.push(self.scope.declare(name.text(self.src).as_bytes())?);
        }
        let body: Block = self.parse_block()?;
        self.scope.pop();
        let end: Span = self.expect(Tok::KEnd)?.span;
        Ok(Stat {
            kind: StatKind::GenericFor { vars, exprs, body },
            span: start.join(end),
        })
    }

    fn parse_function_stat(&mut self, start: Span) -> Result<Stat> {
        self.bump();
        let base_name: Span = self.expect(Tok::Name)?.span;
        let var: Var = self
            .scope
            .resolve(base_name.text(self.src).as_bytes())
            .map_or(Var::Global(base_name), Var::Local);
        let mut target_expr: Expr = Expr {
            kind: ExprKind::Var(var),
            span: base_name,
        };
        let mut is_method: bool = false;
        loop {
            match self.peek() {
                Tok::Dot => {
                    self.bump();
                    let field: Span = self.expect(Tok::Name)?.span;
                    target_expr = Expr {
                        kind: ExprKind::Index(
                            Box::new(target_expr.clone()),
                            Box::new(Expr {
                                kind: ExprKind::Str,
                                span: field,
                            }),
                        ),
                        span: base_name.join(field),
                    };
                }
                Tok::Colon => {
                    self.bump();
                    let field: Span = self.expect(Tok::Name)?.span;
                    target_expr = Expr {
                        kind: ExprKind::Index(
                            Box::new(target_expr.clone()),
                            Box::new(Expr {
                                kind: ExprKind::Str,
                                span: field,
                            }),
                        ),
                        span: base_name.join(field),
                    };
                    is_method = true;
                    break;
                }
                _ => break,
            }
        }
        let func_expr: Expr = self.parse_function_body(start, is_method)?;
        let end: Span = func_expr.span;
        let assign_target: AssignTarget = match target_expr.kind {
            ExprKind::Var(v) => AssignTarget::Var(v, target_expr.span),
            ExprKind::Index(base, key) => AssignTarget::Index(base, key, target_expr.span),
            _ => {
                return Err(Error::DecompileUnsupported(
                    "malformed function statement target",
                ));
            }
        };
        Ok(Stat {
            kind: StatKind::Assign {
                targets: vec![assign_target],
                values: vec![func_expr],
            },
            span: start.join(end),
        })
    }

    fn parse_local(&mut self, start: Span) -> Result<Stat> {
        self.bump();
        if self.peek() == Tok::KFunction {
            self.bump();
            let name: Span = self.expect(Tok::Name)?.span;
            let id: LocalId = self.scope.declare(name.text(self.src).as_bytes())?;
            let func_expr: Expr = self.parse_function_body(name, false)?;
            let end: Span = func_expr.span;
            return Ok(Stat {
                kind: StatKind::Local {
                    targets: vec![id],
                    values: vec![func_expr],
                },
                span: start.join(end),
            });
        }
        let mut names: Vec<Span> = vec![self.expect(Tok::Name)?.span];
        while self.peek() == Tok::Comma {
            self.bump();
            names.push(self.expect(Tok::Name)?.span);
        }
        let values: Vec<Expr> = if self.peek() == Tok::Eq {
            self.bump();
            self.parse_expr_list()?
        } else {
            Vec::new()
        };
        let end: Span = values
            .last()
            .map_or(names[names.len() - 1], |e: &Expr| e.span);
        let mut targets: Vec<LocalId> = Vec::with_capacity(names.len());
        for name in &names {
            targets.push(self.scope.declare(name.text(self.src).as_bytes())?);
        }
        Ok(Stat {
            kind: StatKind::Local { targets, values },
            span: start.join(end),
        })
    }

    fn parse_expr_or_assign_stat(&mut self, start: Span) -> Result<Stat> {
        let first: Expr = self.parse_suffixed_expr()?;
        if matches!(self.peek(), Tok::Eq | Tok::Comma) {
            let mut targets: Vec<AssignTarget> = vec![expr_to_assign_target(first)?];
            while self.peek() == Tok::Comma {
                self.bump();
                let next: Expr = self.parse_suffixed_expr()?;
                targets.push(expr_to_assign_target(next)?);
            }
            self.expect(Tok::Eq)?;
            let values: Vec<Expr> = self.parse_expr_list()?;
            let end: Span = values[values.len() - 1].span;
            return Ok(Stat {
                kind: StatKind::Assign { targets, values },
                span: start.join(end),
            });
        }
        if !matches!(
            first.kind,
            ExprKind::Call { .. } | ExprKind::MethodCall { .. }
        ) {
            return Err(Error::DecompileUnsupported(
                "expression statement is not a call",
            ));
        }
        let end: Span = first.span;
        Ok(Stat {
            kind: StatKind::ExprStat(first),
            span: start.join(end),
        })
    }

    fn parse_function_body(&mut self, start: Span, is_method: bool) -> Result<Expr> {
        self.enter_nest()?;
        self.expect(Tok::LParen)?;
        self.scope.push();
        let mut params: Vec<LocalId> = Vec::new();
        if is_method {
            params.push(self.scope.declare(b"self")?);
        }
        let mut is_vararg: bool = false;
        if self.peek() != Tok::RParen {
            loop {
                if self.peek() == Tok::Ellipsis {
                    self.bump();
                    is_vararg = true;
                    break;
                }
                let name: Span = self.expect(Tok::Name)?.span;
                params.push(self.scope.declare(name.text(self.src).as_bytes())?);
                if self.peek() == Tok::Comma {
                    self.bump();
                } else {
                    break;
                }
            }
        }
        self.expect(Tok::RParen)?;
        let body: Block = self.parse_block()?;
        self.scope.pop();
        let end: Span = self.expect(Tok::KEnd)?.span;
        self.exit_nest();
        Ok(Expr {
            kind: ExprKind::Function {
                params,
                is_vararg,
                body,
            },
            span: start.join(end),
        })
    }

    fn parse_expr_list(&mut self) -> Result<Vec<Expr>> {
        let mut out: Vec<Expr> = vec![self.parse_expr()?];
        while self.peek() == Tok::Comma {
            self.bump();
            out.push(self.parse_expr()?);
        }
        Ok(out)
    }

    fn parse_expr(&mut self) -> Result<Expr> {
        self.parse_binary_expr(0)
    }

    fn parse_binary_expr(&mut self, min_prec: u8) -> Result<Expr> {
        self.enter_nest()?;
        let mut lhs: Expr = self.parse_unary_expr()?;
        while let Some((op, left_prec, right_prec)) = binop_of(self.peek()) {
            if left_prec < min_prec {
                break;
            }
            self.bump();
            let rhs: Expr = self.parse_binary_expr(right_prec)?;
            let span: Span = lhs.span.join(rhs.span);
            lhs = Expr {
                kind: ExprKind::Binary(op, Box::new(lhs), Box::new(rhs)),
                span,
            };
        }
        self.exit_nest();
        Ok(lhs)
    }

    fn parse_unary_expr(&mut self) -> Result<Expr> {
        let start: Span = self.peek_span();
        let op: Option<UnOp> = match self.peek() {
            Tok::KNot => Some(UnOp::Not),
            Tok::Minus => Some(UnOp::Neg),
            Tok::Hash => Some(UnOp::Len),
            _ => None,
        };
        if let Some(op) = op {
            self.bump();
            let operand: Expr = self.parse_binary_expr(UNARY_PREC)?;
            let span: Span = start.join(operand.span);
            return Ok(Expr {
                kind: ExprKind::Unary(op, Box::new(operand)),
                span,
            });
        }
        self.parse_pow_expr()
    }

    fn parse_pow_expr(&mut self) -> Result<Expr> {
        let base: Expr = self.parse_suffixed_expr()?;
        if self.peek() == Tok::Caret {
            self.bump();
            let exp: Expr = self.parse_binary_expr(UNARY_PREC)?;
            let span: Span = base.span.join(exp.span);
            return Ok(Expr {
                kind: ExprKind::Binary(BinOp::Pow, Box::new(base), Box::new(exp)),
                span,
            });
        }
        Ok(base)
    }

    fn parse_suffixed_expr(&mut self) -> Result<Expr> {
        let mut expr: Expr = self.parse_primary_expr()?;
        loop {
            match self.peek() {
                Tok::Dot => {
                    self.bump();
                    let field: Span = self.expect(Tok::Name)?.span;
                    let span: Span = expr.span.join(field);
                    expr = Expr {
                        kind: ExprKind::Index(
                            Box::new(expr),
                            Box::new(Expr {
                                kind: ExprKind::Str,
                                span: field,
                            }),
                        ),
                        span,
                    };
                }
                Tok::LBracket => {
                    self.bump();
                    let key: Expr = self.parse_expr()?;
                    let end: Span = self.expect(Tok::RBracket)?.span;
                    let span: Span = expr.span.join(end);
                    expr = Expr {
                        kind: ExprKind::Index(Box::new(expr), Box::new(key)),
                        span,
                    };
                }
                Tok::Colon => {
                    self.bump();
                    let method: Span = self.expect(Tok::Name)?.span;
                    let (args, args_end): (Vec<Expr>, Span) = self.parse_call_args()?;
                    let span: Span = expr.span.join(args_end);
                    expr = Expr {
                        kind: ExprKind::MethodCall {
                            base: Box::new(expr),
                            method,
                            args,
                        },
                        span,
                    };
                }
                Tok::LParen | Tok::Str | Tok::LBrace => {
                    let (args, args_end): (Vec<Expr>, Span) = self.parse_call_args()?;
                    let span: Span = expr.span.join(args_end);
                    expr = Expr {
                        kind: ExprKind::Call {
                            base: Box::new(expr),
                            args,
                        },
                        span,
                    };
                }
                _ => break,
            }
        }
        Ok(expr)
    }

    fn parse_call_args(&mut self) -> Result<(Vec<Expr>, Span)> {
        match self.peek() {
            Tok::LParen => {
                self.bump();
                let args: Vec<Expr> = if self.peek() == Tok::RParen {
                    Vec::new()
                } else {
                    self.parse_expr_list()?
                };
                let close: Span = self.expect(Tok::RParen)?.span;
                Ok((args, close))
            }
            Tok::Str => {
                let tok: Token = self.bump();
                Ok((
                    vec![Expr {
                        kind: ExprKind::Str,
                        span: tok.span,
                    }],
                    tok.span,
                ))
            }
            Tok::LBrace => {
                let table: Expr = self.parse_table()?;
                let span: Span = table.span;
                Ok((vec![table], span))
            }
            _ => Err(Error::DecompileUnsupported("expected call arguments")),
        }
    }

    fn parse_primary_expr(&mut self) -> Result<Expr> {
        let start: Span = self.peek_span();
        match self.peek() {
            Tok::KNil => {
                self.bump();
                Ok(Expr {
                    kind: ExprKind::Nil,
                    span: start,
                })
            }
            Tok::KTrue => {
                self.bump();
                Ok(Expr {
                    kind: ExprKind::True,
                    span: start,
                })
            }
            Tok::KFalse => {
                self.bump();
                Ok(Expr {
                    kind: ExprKind::False,
                    span: start,
                })
            }
            Tok::Ellipsis => {
                self.bump();
                Ok(Expr {
                    kind: ExprKind::Vararg,
                    span: start,
                })
            }
            Tok::Number => {
                let tok: Token = self.bump();
                Ok(Expr {
                    kind: ExprKind::Number(tok.number),
                    span: start,
                })
            }
            Tok::Str => {
                self.bump();
                Ok(Expr {
                    kind: ExprKind::Str,
                    span: start,
                })
            }
            Tok::Name => {
                let tok: Token = self.bump();
                let var: Var = self
                    .scope
                    .resolve(tok.span.text(self.src).as_bytes())
                    .map_or(Var::Global(tok.span), Var::Local);
                Ok(Expr {
                    kind: ExprKind::Var(var),
                    span: start,
                })
            }
            Tok::LParen => {
                self.bump();
                let inner: Expr = self.parse_expr()?;
                let end: Span = self.expect(Tok::RParen)?.span;
                Ok(Expr {
                    kind: ExprKind::Paren(Box::new(inner)),
                    span: start.join(end),
                })
            }
            Tok::LBrace => self.parse_table(),
            Tok::KFunction => {
                self.bump();
                self.parse_function_body(start, false)
            }
            _ => Err(Error::DecompileUnsupported(
                "unexpected token in expression",
            )),
        }
    }

    fn parse_table(&mut self) -> Result<Expr> {
        let start: Span = self.expect(Tok::LBrace)?.span;
        let mut fields: Vec<TableField> = Vec::new();
        while self.peek() != Tok::RBrace {
            match self.peek() {
                Tok::LBracket => {
                    self.bump();
                    let key: Expr = self.parse_expr()?;
                    self.expect(Tok::RBracket)?;
                    self.expect(Tok::Eq)?;
                    let value: Expr = self.parse_expr()?;
                    fields.push(TableField::Indexed(key, value));
                }
                Tok::Name if self.peek_ahead_is_eq() => {
                    let name: Span = self.bump().span;
                    self.expect(Tok::Eq)?;
                    let value: Expr = self.parse_expr()?;
                    fields.push(TableField::Named(name, value));
                }
                _ => {
                    let value: Expr = self.parse_expr()?;
                    fields.push(TableField::Positional(value));
                }
            }
            if matches!(self.peek(), Tok::Comma | Tok::Semi) {
                self.bump();
            } else {
                break;
            }
            if fields.len() > MAX_BLOCK_STATEMENTS {
                return Err(Error::DecompileUnsupported(
                    "table constructor exceeds parser field budget",
                ));
            }
        }
        let end: Span = self.expect(Tok::RBrace)?.span;
        Ok(Expr {
            kind: ExprKind::Table(fields),
            span: start.join(end),
        })
    }

    fn peek_ahead_is_eq(&self) -> bool {
        self.tokens
            .get(self.idx + 1)
            .is_some_and(|t: &Token| t.tok == Tok::Eq)
    }
}

fn expr_to_assign_target(expr: Expr) -> Result<AssignTarget> {
    match expr.kind {
        ExprKind::Var(v) => Ok(AssignTarget::Var(v, expr.span)),
        ExprKind::Index(base, key) => Ok(AssignTarget::Index(base, key, expr.span)),
        _ => Err(Error::DecompileUnsupported("invalid assignment target")),
    }
}

const UNARY_PREC: u8 = 8;

fn binop_of(tok: Tok) -> Option<(BinOp, u8, u8)> {
    Some(match tok {
        Tok::KOr => (BinOp::Or, 1, 2),
        Tok::KAnd => (BinOp::And, 2, 3),
        Tok::Lt => (BinOp::Lt, 3, 4),
        Tok::Gt => (BinOp::Gt, 3, 4),
        Tok::LtEq => (BinOp::Le, 3, 4),
        Tok::GtEq => (BinOp::Ge, 3, 4),
        Tok::NotEq => (BinOp::Ne, 3, 4),
        Tok::EqEq => (BinOp::Eq, 3, 4),
        Tok::DotDot => (BinOp::Concat, 5, 4),
        Tok::Plus => (BinOp::Add, 6, 7),
        Tok::Minus => (BinOp::Sub, 6, 7),
        Tok::Star => (BinOp::Mul, 7, 8),
        Tok::Slash => (BinOp::Div, 7, 8),
        Tok::Percent => (BinOp::Mod, 7, 8),
        _ => return None,
    })
}

fn block_follow(tok: Tok) -> bool {
    matches!(
        tok,
        Tok::Eof | Tok::KEnd | Tok::KElse | Tok::KElseif | Tok::KUntil
    )
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::float_cmp,
    clippy::expect_used
)]
mod tests {
    use super::*;

    fn parse(src: &str) -> Block {
        let mut p: Parser<'_> = Parser::new(src).expect("tokenize");
        p.parse_chunk().expect("parse")
    }

    #[test]
    fn parses_local_assignment() {
        let block: Block = parse("local a, b = 1, 2\n");
        assert_eq!(block.stats.len(), 1);
        let StatKind::Local { targets, values } = &block.stats[0].kind else {
            panic!("expected local decl")
        };
        assert_eq!(targets.len(), 2);
        assert_eq!(values.len(), 2);
    }

    #[test]
    fn resolves_shadowed_identifiers_per_scope() {
        let block: Block = parse("local K = 1\nlocal function f(K) return K end\nreturn K\n");
        assert_eq!(block.stats.len(), 3);
    }

    #[test]
    fn parses_while_dispatch_shape() {
        let src: &str = "local K = 1\nwhile K do if K > 5 then K = 10 else K = 20 end end\n";
        let block: Block = parse(src);
        assert_eq!(block.stats.len(), 2);
        assert!(matches!(block.stats[1].kind, StatKind::While { .. }));
    }

    #[test]
    fn parses_ternary_style_and_or_expression() {
        let block: Block = parse("local x = a and 1 or 2\n");
        let StatKind::Local { values, .. } = &block.stats[0].kind else {
            panic!("expected local")
        };
        assert!(matches!(values[0].kind, ExprKind::Binary(BinOp::Or, _, _)));
    }

    #[test]
    fn rejects_a_deeply_nested_paren_bomb() {
        let mut src: String = String::new();
        for _ in 0..5000 {
            src.push('(');
        }
        src.push('1');
        for _ in 0..5000 {
            src.push(')');
        }
        let full: String = format!("local x = {src}\n");
        let mut p: Parser<'_> = Parser::new(&full).expect("tokenize");
        assert!(p.parse_chunk().is_err());
    }

    #[test]
    fn parses_real_prometheus_vmify_preset_output() {
        let src: &str = include_str!("../../../../corpus/lua/prometheus/vmify/obfuscated.lua");
        let mut p: Parser<'_> = Parser::new(src).expect("tokenize real vmify output");
        let block: Block = p.parse_chunk().expect("parse real vmify output");
        assert!(!block.stats.is_empty());
        assert!(p.local_count() > 0);
    }

    #[test]
    fn parses_real_prometheus_weak_preset_output() {
        let src: &str =
            include_str!("../../../../corpus/lua/prometheus/gauntlet/gauntlet_weak_obfuscated.lua");
        let mut p: Parser<'_> = Parser::new(src).expect("tokenize real weak-preset output");
        let block: Block = p.parse_chunk().expect("parse real weak-preset output");
        assert!(!block.stats.is_empty());
        assert!(p.local_count() > 0);
    }

    #[test]
    fn method_call_desugars_with_self_param() {
        let block: Block = parse("function obj:add(x) self.value = x end\n");
        let StatKind::Assign { values, .. } = &block.stats[0].kind else {
            panic!("expected assign")
        };
        let ExprKind::Function { params, .. } = &values[0].kind else {
            panic!("expected function literal")
        };
        assert_eq!(params.len(), 2);
    }
}
