use crate::intern::{Interner, Symbol};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct CQuals {
    pub is_const: bool,
    pub is_volatile: bool,
    pub is_restrict: bool,
}

impl CQuals {
    #[must_use]
    pub const fn none() -> Self {
        Self {
            is_const: false,
            is_volatile: false,
            is_restrict: false,
        }
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        !self.is_const && !self.is_volatile && !self.is_restrict
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Storage {
    Extern,
    Static,
    Register,
    Auto,
    ThreadLocal,
    Inline,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum CTypeSpec {
    Void,
    Bool,
    Char,
    SignedChar,
    UnsignedChar,
    Short,
    UnsignedShort,
    Int,
    UnsignedInt,
    Long,
    UnsignedLong,
    LongLong,
    UnsignedLongLong,
    Float,
    Double,
    LongDouble,
    Named(Symbol),
    Struct(Option<Symbol>),
    Union(Option<Symbol>),
    Enum(Option<Symbol>),
    TypeofExpr(Box<CExpr>),
}

impl CTypeSpec {
    #[must_use]
    pub fn typeof_expr(subject: CExpr) -> Self {
        Self::TypeofExpr(Box::new(subject))
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct CBaseType {
    pub quals: CQuals,
    pub spec: CTypeSpec,
}

impl CBaseType {
    #[must_use]
    pub const fn plain(spec: CTypeSpec) -> Self {
        Self {
            quals: CQuals::none(),
            spec,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum DeclaratorChain {
    Terminal,
    Pointer {
        quals: CQuals,
        to: Box<Self>,
    },
    Array {
        of: Box<Self>,
        size: Option<Box<CExpr>>,
    },
    Function {
        returns: Box<Self>,
        params: Vec<CParam>,
        variadic: bool,
    },
}

impl DeclaratorChain {
    #[must_use]
    pub fn pointer_to(self) -> Self {
        Self::Pointer {
            quals: CQuals::none(),
            to: Box::new(self),
        }
    }

    #[must_use]
    pub fn array_of(self, size: Option<CExpr>) -> Self {
        Self::Array {
            of: Box::new(self),
            size: size.map(Box::new),
        }
    }

    #[must_use]
    pub fn returning(self, params: Vec<CParam>, variadic: bool) -> Self {
        Self::Function {
            returns: Box::new(self),
            params,
            variadic,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct CParam {
    pub base: CBaseType,
    pub name: Option<Symbol>,
    pub declarator: DeclaratorChain,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct TypeName {
    pub base: CBaseType,
    pub declarator: DeclaratorChain,
}

impl TypeName {
    #[must_use]
    pub const fn plain(spec: CTypeSpec) -> Self {
        Self {
            base: CBaseType::plain(spec),
            declarator: DeclaratorChain::Terminal,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Radix {
    Dec,
    Hex,
    Oct,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct IntSuffix {
    pub unsigned: bool,
    pub long: LongSuffix,
}

impl IntSuffix {
    #[must_use]
    pub const fn none() -> Self {
        Self {
            unsigned: false,
            long: LongSuffix::None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum LongSuffix {
    None,
    Long,
    LongLong,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum UnaryOp {
    Neg,
    Pos,
    Not,
    BitNot,
    Deref,
    AddrOf,
    PreInc,
    PreDec,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum PostfixOp {
    PostInc,
    PostDec,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum BinaryOp {
    Mul,
    Div,
    Rem,
    Add,
    Sub,
    Shl,
    Shr,
    Lt,
    Gt,
    Le,
    Ge,
    Eq,
    Ne,
    BitAnd,
    BitXor,
    BitOr,
    LogAnd,
    LogOr,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum AssignOp {
    Assign,
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    Shl,
    Shr,
    And,
    Xor,
    Or,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum CExpr {
    Int {
        value: u64,
        radix: Radix,
        suffix: IntSuffix,
    },
    Float(Box<str>),
    Char(char),
    Str(Box<str>),
    Ident(Symbol),
    Unary {
        op: UnaryOp,
        operand: Box<Self>,
    },
    Postfix {
        op: PostfixOp,
        operand: Box<Self>,
    },
    Binary {
        op: BinaryOp,
        lhs: Box<Self>,
        rhs: Box<Self>,
    },
    Assign {
        op: AssignOp,
        lhs: Box<Self>,
        rhs: Box<Self>,
    },
    Ternary {
        cond: Box<Self>,
        then: Box<Self>,
        els: Box<Self>,
    },
    Comma {
        lhs: Box<Self>,
        rhs: Box<Self>,
    },
    Call {
        callee: Box<Self>,
        args: Vec<Self>,
    },
    Index {
        base: Box<Self>,
        index: Box<Self>,
    },
    Member {
        base: Box<Self>,
        arrow: bool,
        field: Symbol,
    },
    Cast {
        ty: TypeName,
        operand: Box<Self>,
    },
    SizeofExpr(Box<Self>),
    SizeofType(TypeName),
    CompoundLiteral {
        ty: TypeName,
        items: Vec<CInitItem>,
    },
}

impl CExpr {
    #[must_use]
    pub fn ident(interner: &mut Interner, name: &str) -> Self {
        Self::Ident(interner.intern(name))
    }

    #[must_use]
    pub const fn int(value: u64) -> Self {
        Self::Int {
            value,
            radix: Radix::Dec,
            suffix: IntSuffix::none(),
        }
    }

    #[must_use]
    pub const fn compound(ty: TypeName, items: Vec<CInitItem>) -> Self {
        Self::CompoundLiteral { ty, items }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum Designator {
    Field(Symbol),
    Index(CExpr),
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct CInitItem {
    pub designators: Vec<Designator>,
    pub value: CInit,
}

impl CInitItem {
    #[must_use]
    pub const fn plain(value: CInit) -> Self {
        Self {
            designators: Vec::new(),
            value,
        }
    }

    #[must_use]
    pub const fn expr(value: CExpr) -> Self {
        Self::plain(CInit::Expr(value))
    }

    #[must_use]
    pub const fn nested(items: Vec<Self>) -> Self {
        Self::plain(CInit::List(items))
    }

    #[must_use]
    pub const fn at(designators: Vec<Designator>, value: CInit) -> Self {
        Self { designators, value }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum CInit {
    Expr(CExpr),
    List(Vec<CInitItem>),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CDecl {
    pub storage: Option<Storage>,
    pub base: CBaseType,
    pub name: Option<Symbol>,
    pub declarator: DeclaratorChain,
    pub init: Option<CInit>,
}

impl CDecl {
    #[must_use]
    pub fn simple(interner: &mut Interner, base: CBaseType, name: &str) -> Self {
        Self {
            storage: None,
            base,
            name: Some(interner.intern(name)),
            declarator: DeclaratorChain::Terminal,
            init: None,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CField {
    pub base: CBaseType,
    pub name: Option<Symbol>,
    pub declarator: DeclaratorChain,
    pub bitfield: Option<CExpr>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum AggregateKind {
    Struct,
    Union,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CStmt {
    Empty,
    Expr(CExpr),
    Decl(CDecl),
    Block(Vec<Self>),
    If {
        cond: CExpr,
        then: Box<Self>,
        els: Option<Box<Self>>,
    },
    While {
        cond: CExpr,
        body: Box<Self>,
    },
    DoWhile {
        body: Box<Self>,
        cond: CExpr,
    },
    For {
        init: Option<Box<Self>>,
        cond: Option<CExpr>,
        step: Option<CExpr>,
        body: Box<Self>,
    },
    Switch {
        value: CExpr,
        body: Box<Self>,
    },
    Case {
        value: CExpr,
        body: Box<Self>,
    },
    Default {
        body: Box<Self>,
    },
    Return(Option<CExpr>),
    Break,
    Continue,
    Goto(Symbol),
    Label {
        name: Symbol,
        body: Box<Self>,
    },
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CItem {
    Function {
        decl: CDecl,
        body: Vec<CStmt>,
    },
    Decl(CDecl),
    Typedef(CDecl),
    Aggregate {
        kind: AggregateKind,
        tag: Option<Symbol>,
        fields: Vec<CField>,
    },
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct CFile {
    pub items: Vec<CItem>,
}
