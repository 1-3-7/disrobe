#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::pedantic,
    clippy::nursery
)]

use disrobe_emit::c::ast::{
    AssignOp, BinaryOp, CBaseType, CExpr, CInit, CInitItem, CTypeSpec, DeclaratorChain, Designator,
    IntSuffix, PostfixOp, Radix, TypeName, UnaryOp,
};
use disrobe_emit::c::print::{ParenMode, render_expr_mode};
use disrobe_emit::{Interner, Symbol};
use proptest::prelude::*;
use proptest::test_runner::{Config, TestCaseError, TestRunner};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Num(u64),
    Punct(&'static str),
}

const PUNCTS: &[&str] = &[
    "<<=", ">>=", "->", "++", "--", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||", "+=", "-=",
    "*=", "/=", "%=", "&=", "|=", "^=", "+", "-", "*", "/", "%", "<", ">", "=", "!", "~", "&", "|",
    "^", "?", ":", ",", "(", ")", "[", "]", "{", "}", ".", ";",
];

fn tokenize(input: &str) -> Result<Vec<Tok>, String> {
    let mut out: Vec<Tok> = Vec::new();
    let mut rest: &str = input;
    'outer: while !rest.is_empty() {
        let first: char = rest.chars().next().expect("non-empty");
        if first.is_whitespace() {
            rest = &rest[first.len_utf8()..];
            continue;
        }
        if first.is_ascii_digit() {
            let end: usize = rest
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(rest.len());
            let value: u64 = rest[..end].parse().map_err(|_| "bad number".to_owned())?;
            out.push(Tok::Num(value));
            rest = &rest[end..];
            continue;
        }
        if first.is_ascii_alphabetic() || first == '_' {
            let end: usize = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            out.push(Tok::Ident(rest[..end].to_owned()));
            rest = &rest[end..];
            continue;
        }
        for punct in PUNCTS {
            if let Some(stripped) = rest.strip_prefix(*punct) {
                out.push(Tok::Punct(punct));
                rest = stripped;
                continue 'outer;
            }
        }
        return Err(format!("unexpected input at {rest:?}"));
    }
    Ok(out)
}

const TYPE_KEYWORDS: &[&str] = &[
    "void", "char", "short", "int", "long", "unsigned", "signed", "struct",
];

struct Parser<'i> {
    toks: Vec<Tok>,
    pos: usize,
    interner: &'i Interner,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn peek_punct(&self, value: &str) -> bool {
        matches!(self.peek(), Some(Tok::Punct(p)) if *p == value)
    }

    fn eat_punct(&mut self, value: &str) -> bool {
        if self.peek_punct(value) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect_punct(&mut self, value: &str) -> Result<(), String> {
        if self.eat_punct(value) {
            Ok(())
        } else {
            Err(format!("expected {value:?} at token {}", self.pos))
        }
    }

    fn sym(&self, name: &str) -> Result<Symbol, String> {
        self.interner
            .lookup(name)
            .ok_or_else(|| format!("unknown identifier {name:?}"))
    }

    fn assign_op(&self) -> Option<AssignOp> {
        let Some(Tok::Punct(p)) = self.peek() else {
            return None;
        };
        Some(match *p {
            "=" => AssignOp::Assign,
            "+=" => AssignOp::Add,
            "-=" => AssignOp::Sub,
            "*=" => AssignOp::Mul,
            "/=" => AssignOp::Div,
            "%=" => AssignOp::Rem,
            "<<=" => AssignOp::Shl,
            ">>=" => AssignOp::Shr,
            "&=" => AssignOp::And,
            "^=" => AssignOp::Xor,
            "|=" => AssignOp::Or,
            _ => return None,
        })
    }

    fn parse_expr(&mut self) -> Result<CExpr, String> {
        self.parse_comma()
    }

    fn parse_comma(&mut self) -> Result<CExpr, String> {
        let mut left: CExpr = self.parse_assign()?;
        while self.eat_punct(",") {
            let right: CExpr = self.parse_assign()?;
            left = CExpr::Comma {
                lhs: Box::new(left),
                rhs: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_assign(&mut self) -> Result<CExpr, String> {
        let left: CExpr = self.parse_ternary()?;
        if let Some(op) = self.assign_op() {
            self.pos += 1;
            let right: CExpr = self.parse_assign()?;
            return Ok(CExpr::Assign {
                op,
                lhs: Box::new(left),
                rhs: Box::new(right),
            });
        }
        Ok(left)
    }

    fn parse_ternary(&mut self) -> Result<CExpr, String> {
        let cond: CExpr = self.parse_binary(0)?;
        if self.eat_punct("?") {
            let then: CExpr = self.parse_expr()?;
            self.expect_punct(":")?;
            let els: CExpr = self.parse_ternary()?;
            return Ok(CExpr::Ternary {
                cond: Box::new(cond),
                then: Box::new(then),
                els: Box::new(els),
            });
        }
        Ok(cond)
    }

    fn binary_op_at(&self, level: usize) -> Option<BinaryOp> {
        let Some(Tok::Punct(p)) = self.peek() else {
            return None;
        };
        match_binary(level, p)
    }

    fn parse_binary(&mut self, level: usize) -> Result<CExpr, String> {
        if level >= BINARY_LEVELS.len() {
            return self.parse_unary();
        }
        let mut left: CExpr = self.parse_binary(level + 1)?;
        while let Some(op) = self.binary_op_at(level) {
            self.pos += 1;
            let right: CExpr = self.parse_binary(level + 1)?;
            left = CExpr::Binary {
                op,
                lhs: Box::new(left),
                rhs: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<CExpr, String> {
        if self.at_cast() {
            return self.parse_cast();
        }
        let Some(Tok::Punct(p)) = self.peek() else {
            return self.parse_postfix();
        };
        let op: UnaryOp = match *p {
            "-" => UnaryOp::Neg,
            "+" => UnaryOp::Pos,
            "!" => UnaryOp::Not,
            "~" => UnaryOp::BitNot,
            "*" => UnaryOp::Deref,
            "&" => UnaryOp::AddrOf,
            "++" => UnaryOp::PreInc,
            "--" => UnaryOp::PreDec,
            _ => return self.parse_postfix(),
        };
        self.pos += 1;
        let operand: CExpr = self.parse_unary()?;
        Ok(CExpr::Unary {
            op,
            operand: Box::new(operand),
        })
    }

    fn at_cast(&self) -> bool {
        if !self.peek_punct("(") {
            return false;
        }
        matches!(self.toks.get(self.pos + 1), Some(Tok::Ident(name)) if TYPE_KEYWORDS.contains(&name.as_str()))
    }

    fn parse_cast(&mut self) -> Result<CExpr, String> {
        self.expect_punct("(")?;
        let ty: TypeName = self.parse_type_name()?;
        self.expect_punct(")")?;
        if self.peek_punct("{") {
            let items: Vec<CInitItem> = self.parse_init_list()?;
            let literal: CExpr = CExpr::CompoundLiteral { ty, items };
            return self.parse_postfix_from(literal);
        }
        let operand: CExpr = self.parse_unary()?;
        Ok(CExpr::Cast {
            ty,
            operand: Box::new(operand),
        })
    }

    fn parse_init_list(&mut self) -> Result<Vec<CInitItem>, String> {
        self.expect_punct("{")?;
        let mut items: Vec<CInitItem> = Vec::new();
        if !self.peek_punct("}") {
            loop {
                items.push(self.parse_init_item()?);
                if !self.eat_punct(",") {
                    break;
                }
            }
        }
        self.expect_punct("}")?;
        Ok(items)
    }

    fn parse_init_item(&mut self) -> Result<CInitItem, String> {
        let mut designators: Vec<Designator> = Vec::new();
        loop {
            if self.eat_punct(".") {
                let field: String = self.expect_ident()?;
                designators.push(Designator::Field(self.sym(&field)?));
            } else if self.eat_punct("[") {
                let subscript: CExpr = self.parse_assign()?;
                self.expect_punct("]")?;
                designators.push(Designator::Index(subscript));
            } else {
                break;
            }
        }
        if !designators.is_empty() {
            self.expect_punct("=")?;
        }
        let value: CInit = if self.peek_punct("{") {
            CInit::List(self.parse_init_list()?)
        } else {
            CInit::Expr(self.parse_assign()?)
        };
        Ok(CInitItem { designators, value })
    }

    fn parse_type_name(&mut self) -> Result<TypeName, String> {
        let spec: CTypeSpec = self.parse_type_spec()?;
        let mut chain: DeclaratorChain = DeclaratorChain::Terminal;
        while self.eat_punct("*") {
            chain = chain.pointer_to();
        }
        let mut extents: Vec<CExpr> = Vec::new();
        while self.eat_punct("[") {
            let extent: CExpr = self.parse_assign()?;
            self.expect_punct("]")?;
            extents.push(extent);
        }
        for extent in extents.into_iter().rev() {
            chain = chain.array_of(Some(extent));
        }
        Ok(TypeName {
            base: CBaseType::plain(spec),
            declarator: chain,
        })
    }

    fn parse_type_spec(&mut self) -> Result<CTypeSpec, String> {
        if matches!(self.peek(), Some(Tok::Ident(name)) if name == "struct") {
            self.pos += 1;
            let tag: String = self.expect_ident()?;
            return Ok(CTypeSpec::Struct(Some(self.sym(&tag)?)));
        }
        let mut keywords: Vec<String> = Vec::new();
        while let Some(Tok::Ident(name)) = self.peek() {
            if !TYPE_KEYWORDS.contains(&name.as_str()) {
                break;
            }
            keywords.push(name.clone());
            self.pos += 1;
        }
        match keywords.join(" ").as_str() {
            "int" => Ok(CTypeSpec::Int),
            "unsigned int" => Ok(CTypeSpec::UnsignedInt),
            "long" => Ok(CTypeSpec::Long),
            "char" => Ok(CTypeSpec::Char),
            "short" => Ok(CTypeSpec::Short),
            other => Err(format!("unsupported cast type {other:?}")),
        }
    }

    fn parse_postfix(&mut self) -> Result<CExpr, String> {
        let base: CExpr = self.parse_primary()?;
        self.parse_postfix_from(base)
    }

    fn parse_postfix_from(&mut self, start: CExpr) -> Result<CExpr, String> {
        let mut base: CExpr = start;
        loop {
            if self.eat_punct("(") {
                let mut args: Vec<CExpr> = Vec::new();
                if !self.peek_punct(")") {
                    args.push(self.parse_assign()?);
                    while self.eat_punct(",") {
                        args.push(self.parse_assign()?);
                    }
                }
                self.expect_punct(")")?;
                base = CExpr::Call {
                    callee: Box::new(base),
                    args,
                };
            } else if self.eat_punct("[") {
                let index: CExpr = self.parse_expr()?;
                self.expect_punct("]")?;
                base = CExpr::Index {
                    base: Box::new(base),
                    index: Box::new(index),
                };
            } else if self.eat_punct(".") {
                let field: String = self.expect_ident()?;
                base = CExpr::Member {
                    base: Box::new(base),
                    arrow: false,
                    field: self.sym(&field)?,
                };
            } else if self.eat_punct("->") {
                let field: String = self.expect_ident()?;
                base = CExpr::Member {
                    base: Box::new(base),
                    arrow: true,
                    field: self.sym(&field)?,
                };
            } else if self.eat_punct("++") {
                base = CExpr::Postfix {
                    op: PostfixOp::PostInc,
                    operand: Box::new(base),
                };
            } else if self.eat_punct("--") {
                base = CExpr::Postfix {
                    op: PostfixOp::PostDec,
                    operand: Box::new(base),
                };
            } else {
                break;
            }
        }
        Ok(base)
    }

    fn expect_ident(&mut self) -> Result<String, String> {
        match self.peek() {
            Some(Tok::Ident(name)) => {
                let owned: String = name.clone();
                self.pos += 1;
                Ok(owned)
            }
            _ => Err(format!("expected identifier at token {}", self.pos)),
        }
    }

    fn parse_primary(&mut self) -> Result<CExpr, String> {
        match self.peek().cloned() {
            Some(Tok::Num(value)) => {
                self.pos += 1;
                Ok(CExpr::Int {
                    value,
                    radix: Radix::Dec,
                    suffix: IntSuffix::none(),
                })
            }
            Some(Tok::Ident(name)) => {
                self.pos += 1;
                Ok(CExpr::Ident(self.sym(&name)?))
            }
            Some(Tok::Punct("(")) => {
                self.pos += 1;
                let inner: CExpr = self.parse_expr()?;
                self.expect_punct(")")?;
                Ok(inner)
            }
            other => Err(format!("unexpected token {other:?}")),
        }
    }
}

const BINARY_LEVELS: &[&[(&str, BinaryOp)]] = &[
    &[("||", BinaryOp::LogOr)],
    &[("&&", BinaryOp::LogAnd)],
    &[("|", BinaryOp::BitOr)],
    &[("^", BinaryOp::BitXor)],
    &[("&", BinaryOp::BitAnd)],
    &[("==", BinaryOp::Eq), ("!=", BinaryOp::Ne)],
    &[
        ("<", BinaryOp::Lt),
        (">", BinaryOp::Gt),
        ("<=", BinaryOp::Le),
        (">=", BinaryOp::Ge),
    ],
    &[("<<", BinaryOp::Shl), (">>", BinaryOp::Shr)],
    &[("+", BinaryOp::Add), ("-", BinaryOp::Sub)],
    &[
        ("*", BinaryOp::Mul),
        ("/", BinaryOp::Div),
        ("%", BinaryOp::Rem),
    ],
];

fn match_binary(level: usize, punct: &str) -> Option<BinaryOp> {
    BINARY_LEVELS
        .get(level)?
        .iter()
        .find(|(symbol, _)| *symbol == punct)
        .map(|(_, op)| *op)
}

fn parse_c_expr(input: &str, interner: &Interner) -> Result<CExpr, String> {
    let toks: Vec<Tok> = tokenize(input)?;
    let mut parser: Parser<'_> = Parser {
        toks,
        pos: 0,
        interner,
    };
    let expr: CExpr = parser.parse_expr()?;
    if parser.pos != parser.toks.len() {
        return Err(format!("trailing tokens from {}", parser.pos));
    }
    Ok(expr)
}

fn arb_unary_op() -> impl Strategy<Value = UnaryOp> {
    prop::sample::select(vec![
        UnaryOp::Neg,
        UnaryOp::Pos,
        UnaryOp::Not,
        UnaryOp::BitNot,
        UnaryOp::Deref,
        UnaryOp::AddrOf,
    ])
}

fn arb_binary_op() -> impl Strategy<Value = BinaryOp> {
    prop::sample::select(vec![
        BinaryOp::Mul,
        BinaryOp::Div,
        BinaryOp::Rem,
        BinaryOp::Add,
        BinaryOp::Sub,
        BinaryOp::Shl,
        BinaryOp::Shr,
        BinaryOp::Lt,
        BinaryOp::Gt,
        BinaryOp::Le,
        BinaryOp::Ge,
        BinaryOp::Eq,
        BinaryOp::Ne,
        BinaryOp::BitAnd,
        BinaryOp::BitXor,
        BinaryOp::BitOr,
        BinaryOp::LogAnd,
        BinaryOp::LogOr,
    ])
}

fn arb_assign_op() -> impl Strategy<Value = AssignOp> {
    prop::sample::select(vec![
        AssignOp::Assign,
        AssignOp::Add,
        AssignOp::Sub,
        AssignOp::Mul,
        AssignOp::Div,
        AssignOp::Rem,
        AssignOp::Shl,
        AssignOp::Shr,
        AssignOp::And,
        AssignOp::Xor,
        AssignOp::Or,
    ])
}

fn arb_cast_type() -> impl Strategy<Value = TypeName> {
    (
        prop::sample::select(vec![
            CTypeSpec::Int,
            CTypeSpec::UnsignedInt,
            CTypeSpec::Long,
            CTypeSpec::Char,
            CTypeSpec::Short,
        ]),
        0usize..3,
    )
        .prop_map(|(spec, depth): (CTypeSpec, usize)| {
            let mut chain: DeclaratorChain = DeclaratorChain::Terminal;
            for _ in 0..depth {
                chain = chain.pointer_to();
            }
            TypeName {
                base: CBaseType::plain(spec),
                declarator: chain,
            }
        })
}

fn arb_literal_type(pool: Vec<Symbol>) -> impl Strategy<Value = TypeName> {
    prop_oneof![
        arb_cast_type(),
        prop::sample::select(pool).prop_map(|tag: Symbol| TypeName {
            base: CBaseType::plain(CTypeSpec::Struct(Some(tag))),
            declarator: DeclaratorChain::Terminal,
        }),
        (
            prop::sample::select(vec![CTypeSpec::Int, CTypeSpec::Char, CTypeSpec::Long]),
            prop::collection::vec(1u64..5, 1..3),
        )
            .prop_map(|(spec, extents): (CTypeSpec, Vec<u64>)| {
                let mut chain: DeclaratorChain = DeclaratorChain::Terminal;
                for extent in extents.into_iter().rev() {
                    chain = chain.array_of(Some(CExpr::int(extent)));
                }
                TypeName {
                    base: CBaseType::plain(spec),
                    declarator: chain,
                }
            }),
    ]
}

fn arb_designator(
    pool: Vec<Symbol>,
    value: BoxedStrategy<CExpr>,
) -> impl Strategy<Value = Designator> {
    prop_oneof![
        prop::sample::select(pool).prop_map(Designator::Field),
        value.prop_map(Designator::Index),
    ]
}

fn arb_init_items(
    pool: Vec<Symbol>,
    value: BoxedStrategy<CExpr>,
) -> impl Strategy<Value = Vec<CInitItem>> {
    let plain = value
        .clone()
        .prop_map(|expr: CExpr| CInitItem::expr(expr))
        .boxed();
    let nested = prop::collection::vec(plain.clone(), 1..3)
        .prop_map(CInitItem::nested)
        .boxed();
    let designated = (
        prop::collection::vec(arb_designator(pool, value.clone()), 1..3),
        value,
    )
        .prop_map(|(designators, expr): (Vec<Designator>, CExpr)| {
            CInitItem::at(designators, CInit::Expr(expr))
        })
        .boxed();
    prop::collection::vec(prop_oneof![plain, nested, designated], 0..4)
}

fn arb_expr(pool: Vec<Symbol>) -> impl Strategy<Value = CExpr> {
    let pool_leaf: Vec<Symbol> = pool.clone();
    let leaf = prop_oneof![
        (0u64..1000).prop_map(CExpr::int),
        prop::sample::select(pool_leaf).prop_map(CExpr::Ident),
    ];
    leaf.prop_recursive(6, 256, 4, move |inner: BoxedStrategy<CExpr>| {
        let pick = || prop::sample::select(pool.clone());
        prop_oneof![
            (arb_unary_op(), inner.clone()).prop_map(|(op, operand): (UnaryOp, CExpr)| {
                CExpr::Unary {
                    op,
                    operand: Box::new(operand),
                }
            }),
            (
                prop::sample::select(vec![UnaryOp::PreInc, UnaryOp::PreDec]),
                pick()
            )
                .prop_map(|(op, symbol): (UnaryOp, Symbol)| CExpr::Unary {
                    op,
                    operand: Box::new(CExpr::Ident(symbol)),
                }),
            (
                prop::sample::select(vec![PostfixOp::PostInc, PostfixOp::PostDec]),
                pick()
            )
                .prop_map(|(op, symbol): (PostfixOp, Symbol)| CExpr::Postfix {
                    op,
                    operand: Box::new(CExpr::Ident(symbol)),
                }),
            (arb_binary_op(), inner.clone(), inner.clone()).prop_map(
                |(op, lhs, rhs): (BinaryOp, CExpr, CExpr)| CExpr::Binary {
                    op,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                }
            ),
            (arb_assign_op(), pick(), inner.clone()).prop_map(
                |(op, symbol, rhs): (AssignOp, Symbol, CExpr)| CExpr::Assign {
                    op,
                    lhs: Box::new(CExpr::Ident(symbol)),
                    rhs: Box::new(rhs),
                }
            ),
            (inner.clone(), inner.clone(), inner.clone()).prop_map(
                |(cond, then, els): (CExpr, CExpr, CExpr)| CExpr::Ternary {
                    cond: Box::new(cond),
                    then: Box::new(then),
                    els: Box::new(els),
                }
            ),
            (inner.clone(), inner.clone()).prop_map(|(lhs, rhs): (CExpr, CExpr)| CExpr::Comma {
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            }),
            (pick(), prop::collection::vec(inner.clone(), 0..3)).prop_map(
                |(symbol, args): (Symbol, Vec<CExpr>)| CExpr::Call {
                    callee: Box::new(CExpr::Ident(symbol)),
                    args,
                }
            ),
            (pick(), inner.clone()).prop_map(|(symbol, index): (Symbol, CExpr)| CExpr::Index {
                base: Box::new(CExpr::Ident(symbol)),
                index: Box::new(index),
            }),
            (pick(), any::<bool>(), pick()).prop_map(
                |(base, arrow, field): (Symbol, bool, Symbol)| CExpr::Member {
                    base: Box::new(CExpr::Ident(base)),
                    arrow,
                    field,
                }
            ),
            (arb_cast_type(), inner.clone()).prop_map(|(ty, operand): (TypeName, CExpr)| {
                CExpr::Cast {
                    ty,
                    operand: Box::new(operand),
                }
            }),
            (
                arb_literal_type(pool.clone()),
                arb_init_items(pool.clone(), inner)
            )
                .prop_map(|(ty, items): (TypeName, Vec<CInitItem>)| {
                    CExpr::CompoundLiteral { ty, items }
                }),
        ]
    })
}

fn pool_interner() -> (Interner, Vec<Symbol>) {
    let mut interner: Interner = Interner::new();
    let pool: Vec<Symbol> = ["a", "b", "c", "d", "e", "f", "g", "h"]
        .iter()
        .map(|name: &&str| interner.intern(name))
        .collect();
    (interner, pool)
}

fn check_reparse(mode: ParenMode) {
    let (interner, pool): (Interner, Vec<Symbol>) = pool_interner();
    let strategy = arb_expr(pool);
    let mut runner: TestRunner = TestRunner::new(Config {
        cases: 2048,
        ..Config::default()
    });
    runner
        .run(&strategy, |expr: CExpr| {
            let rendered: String = render_expr_mode(&expr, &interner, 80, mode);
            let parsed: CExpr = parse_c_expr(&rendered, &interner)
                .map_err(|err: String| TestCaseError::fail(format!("parse {rendered:?}: {err}")))?;
            prop_assert_eq!(parsed, expr);
            Ok(())
        })
        .expect("reparse invariant");
}

#[test]
fn minimal_rendering_reparses_to_original() {
    check_reparse(ParenMode::Minimal);
}

#[test]
fn full_paren_rendering_reparses_to_original() {
    check_reparse(ParenMode::Full);
}

#[test]
fn minimal_never_wider_than_full() {
    let (interner, pool): (Interner, Vec<Symbol>) = pool_interner();
    let strategy = arb_expr(pool);
    let mut runner: TestRunner = TestRunner::new(Config {
        cases: 2048,
        ..Config::default()
    });
    runner
        .run(&strategy, |expr: CExpr| {
            let minimal: String = render_expr_mode(&expr, &interner, 80, ParenMode::Minimal);
            let full: String = render_expr_mode(&expr, &interner, 80, ParenMode::Full);
            prop_assert!(minimal.len() <= full.len());
            Ok(())
        })
        .expect("width invariant");
}
