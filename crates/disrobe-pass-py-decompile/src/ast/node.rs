use std::collections::BTreeMap;

use crate::bytecode::opcode::{BinOp, CmpOp, UnaryOp};

pub type BinOpKind = BinOp;
pub type UnaryOpKind = UnaryOp;
pub type CmpOpKind = CmpOp;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExprCtx {
    Load,
    Store,
    Del,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BoolOpKind {
    And,
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompKind {
    List,
    Set,
    Dict,
    Generator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FormatConversion {
    None,
    Str,
    Repr,
    Ascii,
}

impl FormatConversion {
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            b's' => Self::Str,
            b'r' => Self::Repr,
            b'a' => Self::Ascii,
            _ => Self::None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct BigUint {
    pub sign: i8,
    pub digits: Vec<u16>,
}

impl Eq for BigUint {}

#[derive(Debug, Clone, PartialEq)]
pub struct CodeRef {
    pub name: String,
    pub qualname: String,
    pub firstlineno: u32,
}

impl Eq for CodeRef {}

#[derive(Debug, Clone, PartialEq)]
pub enum ConstValue {
    None,
    Ellipsis,
    True,
    False,
    Int(i128),
    BigInt(BigUint),
    Float(f64),
    Complex { real: f64, imag: f64 },
    Str(String),
    Bytes(Vec<u8>),
    Tuple(Vec<ConstValue>),
    Frozenset(Vec<ConstValue>),
    Code(CodeRef),
}

impl Eq for ConstValue {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alias {
    pub name: String,
    pub asname: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keyword {
    pub arg: Option<String>,
    pub value: Expr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithItem {
    pub context_expr: Expr,
    pub optional_vars: Option<Expr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_field_names)]
pub struct Arg {
    pub arg: String,
    pub annotation: Option<Box<Expr>>,
    pub default: Option<Box<Expr>>,
    pub line: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Arguments {
    pub posonly: Vec<Arg>,
    pub args: Vec<Arg>,
    pub vararg: Option<Box<Arg>>,
    pub kwonly: Vec<Arg>,
    pub kw_defaults: Vec<Option<Expr>>,
    pub kwarg: Option<Box<Arg>>,
    pub defaults: Vec<Expr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeParam {
    TypeVar {
        name: String,
        bound: Option<Expr>,
        default: Option<Expr>,
    },
    ParamSpec {
        name: String,
        default: Option<Expr>,
    },
    TypeVarTuple {
        name: String,
        default: Option<Expr>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comprehension {
    pub target: Expr,
    pub iter: Expr,
    pub ifs: Vec<Expr>,
    pub is_async: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptHandler {
    pub typ: Option<Expr>,
    pub name: Option<String>,
    pub body: Vec<Stmt>,
    pub line: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum Pattern {
    MatchValue(Expr),
    MatchSingleton(ConstValue),
    MatchSequence(Vec<Pattern>),
    MatchMapping {
        keys: Vec<Expr>,
        patterns: Vec<Pattern>,
        rest: Option<String>,
    },
    MatchClass {
        cls: Expr,
        patterns: Vec<Pattern>,
        kwd_attrs: Vec<String>,
        kwd_patterns: Vec<Pattern>,
    },
    MatchStar(Option<String>),
    MatchAs {
        pattern: Option<Box<Pattern>>,
        name: Option<String>,
    },
    MatchOr(Vec<Pattern>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchCase {
    pub pattern: Pattern,
    pub guard: Option<Expr>,
    pub body: Vec<Stmt>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TStrItem {
    Literal(String),
    Interp {
        value: Expr,
        conversion: FormatConversion,
        format_spec: Option<Expr>,
    },
}

impl Eq for TStrItem {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stmt {
    FunctionDef {
        name: String,
        type_params: Vec<TypeParam>,
        args: Arguments,
        body: Vec<Stmt>,
        decorators: Vec<Expr>,
        returns: Option<Expr>,
        is_async: bool,
        docstring: Option<String>,
        line: Option<u32>,
    },
    ClassDef {
        name: String,
        type_params: Vec<TypeParam>,
        bases: Vec<Expr>,
        keywords: Vec<Keyword>,
        body: Vec<Stmt>,
        decorators: Vec<Expr>,
        docstring: Option<String>,
        line: Option<u32>,
    },
    Return(Option<Expr>),
    Delete(Vec<Expr>),
    Assign {
        targets: Vec<Expr>,
        value: Expr,
        type_comment: Option<String>,
        line: Option<u32>,
    },
    AugAssign {
        target: Expr,
        op: BinOpKind,
        value: Expr,
        line: Option<u32>,
    },
    AnnAssign {
        target: Expr,
        annotation: Expr,
        value: Option<Expr>,
        simple: bool,
        line: Option<u32>,
    },
    TypeAlias {
        name: String,
        type_params: Vec<TypeParam>,
        value: Expr,
        line: Option<u32>,
    },
    For {
        target: Expr,
        iter: Expr,
        body: Vec<Stmt>,
        orelse: Vec<Stmt>,
        is_async: bool,
        line: Option<u32>,
    },
    While {
        test: Expr,
        body: Vec<Stmt>,
        orelse: Vec<Stmt>,
        line: Option<u32>,
    },
    If {
        test: Expr,
        body: Vec<Stmt>,
        orelse: Vec<Stmt>,
        line: Option<u32>,
    },
    With {
        items: Vec<WithItem>,
        body: Vec<Stmt>,
        is_async: bool,
        line: Option<u32>,
    },
    Match {
        subject: Expr,
        cases: Vec<MatchCase>,
        line: Option<u32>,
    },
    Raise {
        exc: Option<Expr>,
        cause: Option<Expr>,
        line: Option<u32>,
    },
    Try {
        body: Vec<Stmt>,
        handlers: Vec<ExceptHandler>,
        orelse: Vec<Stmt>,
        finalbody: Vec<Stmt>,
        line: Option<u32>,
    },
    TryStar {
        body: Vec<Stmt>,
        handlers: Vec<ExceptHandler>,
        orelse: Vec<Stmt>,
        finalbody: Vec<Stmt>,
        line: Option<u32>,
    },
    Assert {
        test: Expr,
        msg: Option<Expr>,
        line: Option<u32>,
    },
    Import(Vec<Alias>),
    ImportFrom {
        module: Option<String>,
        names: Vec<Alias>,
        level: u32,
        line: Option<u32>,
    },
    Global(Vec<String>),
    Nonlocal(Vec<String>),
    Expr(Expr),
    Pass,
    Break,
    Continue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum Expr {
    Constant {
        value: ConstValue,
        line: Option<u32>,
    },
    Name {
        id: String,
        ctx: ExprCtx,
        line: Option<u32>,
    },
    FormattedValue {
        value: Box<Expr>,
        conversion: FormatConversion,
        format_spec: Option<Box<Expr>>,
        line: Option<u32>,
    },
    JoinedStr {
        values: Vec<Expr>,
        line: Option<u32>,
    },
    TStr {
        items: Vec<TStrItem>,
        line: Option<u32>,
    },
    BoolOp {
        op: BoolOpKind,
        values: Vec<Expr>,
    },
    NamedExpr {
        target: Box<Expr>,
        value: Box<Expr>,
    },
    BinOp {
        left: Box<Expr>,
        op: BinOpKind,
        right: Box<Expr>,
    },
    UnaryOp {
        op: UnaryOpKind,
        operand: Box<Expr>,
    },
    Lambda {
        args: Box<Arguments>,
        body: Box<Expr>,
    },
    IfExp {
        test: Box<Expr>,
        body: Box<Expr>,
        orelse: Box<Expr>,
    },
    Dict {
        keys: Vec<Option<Expr>>,
        values: Vec<Expr>,
    },
    Set(Vec<Expr>),
    ListComp {
        elt: Box<Expr>,
        generators: Vec<Comprehension>,
    },
    SetComp {
        elt: Box<Expr>,
        generators: Vec<Comprehension>,
    },
    DictComp {
        key: Box<Expr>,
        value: Box<Expr>,
        generators: Vec<Comprehension>,
    },
    GeneratorExp {
        elt: Box<Expr>,
        generators: Vec<Comprehension>,
    },
    Await(Box<Expr>),
    Yield(Option<Box<Expr>>),
    YieldFrom(Box<Expr>),
    Compare {
        left: Box<Expr>,
        ops: Vec<CmpOpKind>,
        comparators: Vec<Expr>,
    },
    Call {
        func: Box<Expr>,
        args: Vec<Expr>,
        keywords: Vec<Keyword>,
    },
    Attribute {
        value: Box<Expr>,
        attr: String,
        ctx: ExprCtx,
    },
    Subscript {
        value: Box<Expr>,
        slice: Box<Expr>,
        ctx: ExprCtx,
    },
    Starred {
        value: Box<Expr>,
        ctx: ExprCtx,
    },
    List {
        elts: Vec<Expr>,
        ctx: ExprCtx,
    },
    Tuple {
        elts: Vec<Expr>,
        ctx: ExprCtx,
    },
    Slice {
        lower: Option<Box<Expr>>,
        upper: Option<Box<Expr>>,
        step: Option<Box<Expr>>,
    },
    EmptyDictUnpack,
    EmptyDictKeyUnpack,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AstModule {
    pub docstring: Option<String>,
    pub body: Vec<Stmt>,
    pub blank_lines: BTreeMap<u32, u8>,
}
