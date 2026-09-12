use std::rc::Rc;

#[derive(Debug, Clone, PartialEq)]
pub(super) enum Expr {
    Num(f64),
    Str(String),
    Bool(bool),
    Null,
    Undefined,
    Ident(String),
    Member {
        object: Box<Self>,
        property: Box<Self>,
        computed: bool,
    },
    Unary {
        op: UnaryOp,
        argument: Box<Self>,
    },
    Binary {
        op: BinaryOp,
        left: Box<Self>,
        right: Box<Self>,
    },
    Logical {
        op: LogicalOp,
        left: Box<Self>,
        right: Box<Self>,
    },
    Conditional {
        test: Box<Self>,
        consequent: Box<Self>,
        alternate: Box<Self>,
    },
    Assign {
        op: AssignOp,
        target: Box<Self>,
        value: Box<Self>,
    },
    ArrayDestructure {
        targets: Vec<Option<Self>>,
        value: Box<Self>,
    },
    Update {
        op: UpdateOp,
        prefix: bool,
        argument: Box<Self>,
    },
    Array(Vec<Option<Self>>),
    Object(Vec<(PropKey, Self)>),
    Sequence(Vec<Self>),
    Call {
        callee: Box<Self>,
        args: Vec<Self>,
        spread_last: bool,
    },
    New {
        callee: Box<Self>,
        args: Vec<Self>,
    },
    Func(Rc<FuncDef>),
    Template {
        quasis: Vec<String>,
        exprs: Vec<Self>,
    },
    Spread(Box<Self>),
    This,
    Raw(String),
}

#[derive(Debug, Clone, PartialEq)]
pub(super) enum PropKey {
    Ident(String),
    Str(String),
    Num(f64),
    Computed(Box<Expr>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UnaryOp {
    Neg,
    Pos,
    Not,
    BitNot,
    Typeof,
    Void,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UpdateOp {
    Inc,
    Dec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LogicalOp {
    And,
    Or,
    Coalesce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AssignOp {
    Assign,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    BitOr,
    BitAnd,
    BitXor,
    Shl,
    Shr,
    UShr,
    Pow,
    And,
    Or,
    Coalesce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Pow,
    Eq,
    Neq,
    StrictEq,
    StrictNeq,
    Lt,
    Lte,
    Gt,
    Gte,
    BitOr,
    BitAnd,
    BitXor,
    Shl,
    Shr,
    UShr,
    In,
    Instanceof,
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct FuncDef {
    pub name: Option<String>,
    pub params: Vec<Param>,
    pub body: Vec<Stmt>,
    pub is_generator: bool,
    pub is_async: bool,
    pub is_arrow: bool,
    pub expression_body: Option<Box<Expr>>,
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct Param {
    pub name: String,
    pub default: Option<Expr>,
    pub rest: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub(super) enum Stmt {
    Expr(Expr),
    VarDecl {
        kind: VarKind,
        decls: Vec<(String, Option<Expr>)>,
    },
    FuncDecl(Rc<FuncDef>),
    Return(Option<Expr>),
    Break(Option<String>),
    Continue(Option<String>),
    If {
        test: Expr,
        consequent: Vec<Self>,
        alternate: Vec<Self>,
    },
    While {
        test: Expr,
        body: Vec<Self>,
    },
    DoWhile {
        body: Vec<Self>,
        test: Expr,
    },
    For {
        init: Option<Box<Self>>,
        test: Option<Expr>,
        update: Option<Expr>,
        body: Vec<Self>,
    },
    ForIn {
        left: Box<Self>,
        right: Expr,
        body: Vec<Self>,
    },
    ForOf {
        left: Box<Self>,
        right: Expr,
        body: Vec<Self>,
    },
    Switch {
        discriminant: Expr,
        cases: Vec<SwitchCase>,
    },
    With {
        object: Expr,
        body: Vec<Self>,
    },
    Block(Vec<Self>),
    Empty,
    Throw(Expr),
    Labeled {
        label: String,
        body: Box<Self>,
    },
    Raw(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VarKind {
    Var,
    Let,
    Const,
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct SwitchCase {
    pub test: Option<Expr>,
    pub body: Vec<Stmt>,
}
