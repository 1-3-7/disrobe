use serde::{Deserialize, Serialize};

use crate::etf::Term;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Expr {
    Var(String),
    Atom(String),
    Nil,
    Int(i64),
    BigInt {
        sign: u8,
        magnitude_le: Vec<u8>,
    },
    Float(String),
    Str(String),
    CharLit(u32),
    BinaryLit(Vec<u8>),
    Tuple(Vec<Expr>),
    List {
        elements: Vec<Expr>,
        tail: Box<Expr>,
    },
    Cons {
        head: Box<Expr>,
        tail: Box<Expr>,
    },
    Map {
        pairs: Vec<(Expr, Expr)>,
    },
    MapPattern {
        pairs: Vec<(Expr, Expr)>,
    },
    MapUpdate {
        base: Box<Expr>,
        exact: bool,
        pairs: Vec<(Expr, Expr)>,
    },
    TupleElement {
        tuple: Box<Expr>,
        index: u32,
    },
    RecordUpdate {
        base: Box<Expr>,
        updates: Vec<(u32, Expr)>,
    },
    Call {
        target: String,
        args: Vec<Expr>,
    },
    BinOp {
        op: String,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    UnOp {
        op: String,
        operand: Box<Expr>,
    },
    Guard {
        name: String,
        args: Vec<Expr>,
    },
    MakeFun {
        name: String,
        arity: u32,
        env: Vec<Expr>,
    },
    CallFun {
        fun: Box<Expr>,
        args: Vec<Expr>,
    },
    BinaryConstruct(Vec<BinSegment>),
    Catch(Box<Expr>),
    Case {
        subject: Box<Expr>,
        arms: Vec<CaseArm>,
    },
    If {
        arms: Vec<IfArm>,
    },
    Receive {
        arms: Vec<CaseArm>,
        after: Option<Box<AfterClause>>,
    },
    Try {
        body: Vec<Stmt>,
        of_arms: Vec<CaseArm>,
        catch_arms: Vec<CatchArm>,
        after: Vec<Stmt>,
    },
    Block(Vec<Stmt>),
    Raw(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseArm {
    pub pattern: Expr,
    pub guard: Option<Expr>,
    pub body: Vec<Stmt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IfArm {
    pub guard: Expr,
    pub body: Vec<Stmt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatchArm {
    pub class: String,
    pub pattern: Expr,
    pub stacktrace: Option<String>,
    pub body: Vec<Stmt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AfterClause {
    pub timeout: Expr,
    pub body: Vec<Stmt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Stmt {
    Bind { pattern: Expr, value: Expr },
    Expr(Expr),
    Match { pattern: Expr, value: Expr },
    Send { dest: Expr, msg: Expr },
    Return(Expr),
    Comment(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FnClause {
    pub patterns: Vec<Expr>,
    pub guard: Option<Expr>,
    pub body: Vec<Stmt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinSegment {
    pub value: Box<Expr>,
    pub size: Option<Box<Expr>>,
    pub unit: u32,
    pub kind: String,
    pub flags: Vec<String>,
}

impl Expr {
    #[must_use]
    pub fn from_term(term: &Term) -> Self {
        match term {
            Term::SmallInt(v) => Self::Int(i64::from(*v)),
            Term::Int(v) => Self::Int(i64::from(*v)),
            Term::BigInt { sign, magnitude_le } => Self::BigInt {
                sign: *sign,
                magnitude_le: magnitude_le.clone(),
            },
            Term::Float(f) => Self::Float(format_float(*f)),
            Term::Atom(a) => Self::Atom(a.clone()),
            Term::Nil => Self::Nil,
            Term::String(b) => Self::Str(String::from_utf8_lossy(b).into_owned()),
            Term::Binary(b) => Self::BinaryLit(b.clone()),
            Term::BitBinary { data, .. } => Self::BinaryLit(data.clone()),
            Term::Tuple(items) => Self::Tuple(items.iter().map(Self::from_term).collect()),
            Term::List { elements, tail } => Self::List {
                elements: elements.iter().map(Self::from_term).collect(),
                tail: Box::new(Self::from_term(tail)),
            },
            Term::Map(map) => Self::Map {
                pairs: map
                    .iter()
                    .map(|(k, v): (&String, &Term)| (Self::Atom(k.clone()), Self::from_term(v)))
                    .collect(),
            },
            Term::MapMixed(pairs) => Self::Map {
                pairs: pairs
                    .iter()
                    .map(|(k, v): &(Term, Term)| (Self::from_term(k), Self::from_term(v)))
                    .collect(),
            },
            Term::Pid { .. } => Self::Atom("<pid>".to_owned()),
            Term::Reference { .. } => Self::Atom("<ref>".to_owned()),
            Term::Export {
                module,
                function,
                arity,
            } => Self::Raw(format!("fun {module}:{function}/{arity}")),
        }
    }
}

#[must_use]
pub fn format_float(f: f64) -> String {
    let s: String = format!("{f}");
    if s.contains('.')
        || s.contains('e')
        || s.contains('E')
        || s.contains("inf")
        || s.contains("NaN")
    {
        s
    } else {
        format!("{s}.0")
    }
}

#[must_use]
pub fn bif_operator(name: &str, arity: u32) -> Option<BifKind> {
    let op: &'static str = match (name, arity) {
        ("+", 2) => "+",
        ("-", 2) => "-",
        ("*", 2) => "*",
        ("/", 2) => "/",
        ("div", 2) => "div",
        ("rem", 2) => "rem",
        ("band", 2) => "band",
        ("bor", 2) => "bor",
        ("bxor", 2) => "bxor",
        ("bsl", 2) => "bsl",
        ("bsr", 2) => "bsr",
        ("==", 2) => "==",
        ("/=", 2) => "/=",
        ("=:=", 2) => "=:=",
        ("=/=", 2) => "=/=",
        ("<", 2) => "<",
        (">", 2) => ">",
        ("=<", 2) => "=<",
        (">=", 2) => ">=",
        ("and", 2) => "and",
        ("or", 2) => "or",
        ("xor", 2) => "xor",
        ("++", 2) => "++",
        ("--", 2) => "--",
        ("-", 1) => return Some(BifKind::Unary("-")),
        ("+", 1) => return Some(BifKind::Unary("+")),
        ("bnot", 1) => return Some(BifKind::Unary("bnot")),
        ("not", 1) => return Some(BifKind::Unary("not")),
        _ => return None,
    };
    Some(BifKind::Binary(op))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BifKind {
    Binary(&'static str),
    Unary(&'static str),
}

pub(crate) const MAX_EXPR_NODES: usize = 1024;

pub(crate) fn expr_node_count_capped(e: &Expr, cap: usize) -> usize {
    fn walk(e: &Expr, cap: usize, acc: &mut usize) {
        if *acc >= cap {
            return;
        }
        *acc += 1;
        match e {
            Expr::Tuple(items)
            | Expr::Call { args: items, .. }
            | Expr::Guard { args: items, .. } => {
                for el in items {
                    walk(el, cap, acc);
                }
            }
            Expr::List { elements, tail } => {
                for el in elements {
                    walk(el, cap, acc);
                }
                walk(tail, cap, acc);
            }
            Expr::Cons { head, tail } => {
                walk(head, cap, acc);
                walk(tail, cap, acc);
            }
            Expr::Map { pairs } | Expr::MapPattern { pairs } => {
                for (k, v) in pairs {
                    walk(k, cap, acc);
                    walk(v, cap, acc);
                }
            }
            Expr::MapUpdate { base, pairs, .. } => {
                walk(base, cap, acc);
                for (k, v) in pairs {
                    walk(k, cap, acc);
                    walk(v, cap, acc);
                }
            }
            Expr::TupleElement { tuple, .. } => walk(tuple, cap, acc),
            Expr::RecordUpdate { base, updates } => {
                walk(base, cap, acc);
                for (_, v) in updates {
                    walk(v, cap, acc);
                }
            }
            Expr::BinOp { lhs, rhs, .. } => {
                walk(lhs, cap, acc);
                walk(rhs, cap, acc);
            }
            Expr::UnOp { operand, .. } => walk(operand, cap, acc),
            Expr::MakeFun { env, .. } => {
                for el in env {
                    walk(el, cap, acc);
                }
            }
            Expr::CallFun { fun, args } => {
                walk(fun, cap, acc);
                for el in args {
                    walk(el, cap, acc);
                }
            }
            Expr::BinaryConstruct(segments) => {
                for seg in segments {
                    walk(&seg.value, cap, acc);
                    if let Some(sz) = seg.size.as_deref() {
                        walk(sz, cap, acc);
                    }
                }
            }
            Expr::Catch(inner) => walk(inner, cap, acc),
            Expr::Var(_)
            | Expr::Atom(_)
            | Expr::Nil
            | Expr::Int(_)
            | Expr::BigInt { .. }
            | Expr::Float(_)
            | Expr::Str(_)
            | Expr::CharLit(_)
            | Expr::BinaryLit(_)
            | Expr::Case { .. }
            | Expr::If { .. }
            | Expr::Receive { .. }
            | Expr::Try { .. }
            | Expr::Block(_)
            | Expr::Raw(_) => {}
        }
    }
    let mut acc: usize = 0;
    walk(e, cap, &mut acc);
    acc
}

#[must_use]
pub fn is_guard_bif(name: &str) -> bool {
    matches!(
        name,
        "is_atom"
            | "is_binary"
            | "is_bitstring"
            | "is_boolean"
            | "is_float"
            | "is_function"
            | "is_integer"
            | "is_list"
            | "is_map"
            | "is_number"
            | "is_pid"
            | "is_port"
            | "is_record"
            | "is_reference"
            | "is_tuple"
            | "abs"
            | "byte_size"
            | "bit_size"
            | "element"
            | "hd"
            | "length"
            | "map_size"
            | "node"
            | "round"
            | "self"
            | "size"
            | "tl"
            | "trunc"
            | "tuple_size"
    )
}
