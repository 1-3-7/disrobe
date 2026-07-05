use proc_macro2::Span;
use quote::format_ident;
use syn::punctuated::Punctuated;
use syn::{
    BinOp, Block, Expr, ExprAssign, ExprBinary, ExprBlock, ExprCall, ExprCast, ExprField,
    ExprIndex, ExprLit, ExprMethodCall, ExprParen, ExprPath, ExprReference, ExprUnary, ExprUnsafe,
    FnArg, Ident, Item, ItemFn, Lit, LitInt, Local, LocalInit, Member, Pat, PatIdent, PatType,
    Path, PathSegment, ReturnType, Signature, Stmt, Type, TypePath, TypePtr, UnOp, Visibility,
};

fn tok<T: Default>() -> T {
    T::default()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RBinOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
    And,
    Or,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl RBinOp {
    fn to_syn(self) -> BinOp {
        match self {
            Self::Add => BinOp::Add(tok()),
            Self::Sub => BinOp::Sub(tok()),
            Self::Mul => BinOp::Mul(tok()),
            Self::Div => BinOp::Div(tok()),
            Self::Rem => BinOp::Rem(tok()),
            Self::BitAnd => BinOp::BitAnd(tok()),
            Self::BitOr => BinOp::BitOr(tok()),
            Self::BitXor => BinOp::BitXor(tok()),
            Self::Shl => BinOp::Shl(tok()),
            Self::Shr => BinOp::Shr(tok()),
            Self::And => BinOp::And(tok()),
            Self::Or => BinOp::Or(tok()),
            Self::Eq => BinOp::Eq(tok()),
            Self::Ne => BinOp::Ne(tok()),
            Self::Lt => BinOp::Lt(tok()),
            Self::Le => BinOp::Le(tok()),
            Self::Gt => BinOp::Gt(tok()),
            Self::Ge => BinOp::Ge(tok()),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RUnOp {
    Neg,
    Not,
    Deref,
}

impl RUnOp {
    fn to_syn(self) -> UnOp {
        match self {
            Self::Neg => UnOp::Neg(tok()),
            Self::Not => UnOp::Not(tok()),
            Self::Deref => UnOp::Deref(tok()),
        }
    }
}

#[must_use]
pub fn ident(name: &str) -> Ident {
    format_ident!("{}", name)
}

#[must_use]
pub fn var(name: &str) -> Expr {
    Expr::Path(ExprPath {
        attrs: Vec::new(),
        qself: None,
        path: Path::from(ident(name)),
    })
}

#[must_use]
pub fn path_expr(segments: &[&str]) -> Expr {
    let mut path: Path = Path {
        leading_colon: None,
        segments: Punctuated::new(),
    };
    for segment in segments {
        path.segments.push(PathSegment::from(ident(segment)));
    }
    Expr::Path(ExprPath {
        attrs: Vec::new(),
        qself: None,
        path,
    })
}

fn lit_int(repr: &str) -> Expr {
    Expr::Lit(ExprLit {
        attrs: Vec::new(),
        lit: Lit::Int(LitInt::new(repr, Span::call_site())),
    })
}

#[must_use]
pub fn int(value: u64) -> Expr {
    Expr::Lit(ExprLit {
        attrs: Vec::new(),
        lit: Lit::Int(LitInt::new(&value.to_string(), Span::call_site())),
    })
}

#[must_use]
pub fn int_dec(value: u128, suffix: &str) -> Expr {
    lit_int(&format!("{value}{suffix}"))
}

#[must_use]
pub fn int_hex(value: u128, suffix: &str) -> Expr {
    lit_int(&format!("0x{value:x}{suffix}"))
}

#[must_use]
pub fn signed_int(value: i64, suffix: &str) -> Expr {
    if value < 0 {
        unary(
            RUnOp::Neg,
            int_dec(u128::from(value.unsigned_abs()), suffix),
        )
    } else {
        int_dec(value as u128, suffix)
    }
}

#[must_use]
pub fn binary(op: RBinOp, lhs: Expr, rhs: Expr) -> Expr {
    Expr::Binary(ExprBinary {
        attrs: Vec::new(),
        left: Box::new(lhs),
        op: op.to_syn(),
        right: Box::new(rhs),
    })
}

#[must_use]
pub fn unary(op: RUnOp, operand: Expr) -> Expr {
    Expr::Unary(ExprUnary {
        attrs: Vec::new(),
        op: op.to_syn(),
        expr: Box::new(operand),
    })
}

#[must_use]
pub fn call(func: Expr, args: Vec<Expr>) -> Expr {
    Expr::Call(ExprCall {
        attrs: Vec::new(),
        func: Box::new(func),
        paren_token: tok(),
        args: args.into_iter().collect(),
    })
}

#[must_use]
pub fn method_call(receiver: Expr, method: &str, args: Vec<Expr>) -> Expr {
    Expr::MethodCall(ExprMethodCall {
        attrs: Vec::new(),
        receiver: Box::new(receiver),
        dot_token: tok(),
        method: ident(method),
        turbofish: None,
        paren_token: tok(),
        args: args.into_iter().collect(),
    })
}

#[must_use]
pub fn field(base: Expr, name: &str) -> Expr {
    Expr::Field(ExprField {
        attrs: Vec::new(),
        base: Box::new(base),
        dot_token: tok(),
        member: Member::Named(ident(name)),
    })
}

#[must_use]
pub fn index(base: Expr, subscript: Expr) -> Expr {
    Expr::Index(ExprIndex {
        attrs: Vec::new(),
        expr: Box::new(base),
        bracket_token: tok(),
        index: Box::new(subscript),
    })
}

#[must_use]
pub fn cast(operand: Expr, target: Type) -> Expr {
    Expr::Cast(ExprCast {
        attrs: Vec::new(),
        expr: Box::new(operand),
        as_token: tok(),
        ty: Box::new(target),
    })
}

#[must_use]
pub fn reference(mutable: bool, operand: Expr) -> Expr {
    Expr::Reference(ExprReference {
        attrs: Vec::new(),
        and_token: tok(),
        mutability: mutable.then(tok),
        expr: Box::new(operand),
    })
}

#[must_use]
pub fn assign(target: Expr, value: Expr) -> Expr {
    Expr::Assign(ExprAssign {
        attrs: Vec::new(),
        left: Box::new(target),
        eq_token: tok(),
        right: Box::new(value),
    })
}

#[must_use]
pub fn paren(inner: Expr) -> Expr {
    Expr::Paren(ExprParen {
        attrs: Vec::new(),
        paren_token: tok(),
        expr: Box::new(inner),
    })
}

#[must_use]
pub fn block_expr(stmts: Vec<Stmt>) -> Expr {
    Expr::Block(ExprBlock {
        attrs: Vec::new(),
        label: None,
        block: Block {
            brace_token: tok(),
            stmts,
        },
    })
}

#[must_use]
pub fn unsafe_block(inner: Expr) -> Expr {
    Expr::Unsafe(ExprUnsafe {
        attrs: Vec::new(),
        unsafe_token: tok(),
        block: Block {
            brace_token: tok(),
            stmts: vec![trailing_expr(inner)],
        },
    })
}

#[must_use]
pub fn if_else(cond: Expr, then_expr: Expr, else_expr: Expr) -> Expr {
    Expr::If(syn::ExprIf {
        attrs: Vec::new(),
        if_token: tok(),
        cond: Box::new(cond),
        then_branch: Block {
            brace_token: tok(),
            stmts: vec![trailing_expr(then_expr)],
        },
        else_branch: Some((tok(), Box::new(block_expr(vec![trailing_expr(else_expr)])))),
    })
}

#[must_use]
pub fn type_path(name: &str) -> Type {
    Type::Path(TypePath {
        qself: None,
        path: Path::from(ident(name)),
    })
}

#[must_use]
pub fn ptr_type(mutable: bool, elem: Type) -> Type {
    Type::Ptr(TypePtr {
        star_token: tok(),
        const_token: (!mutable).then(tok),
        mutability: mutable.then(tok),
        elem: Box::new(elem),
    })
}

#[must_use]
pub fn let_stmt(name: &str, value: Expr) -> Stmt {
    Stmt::Local(Local {
        attrs: Vec::new(),
        let_token: tok(),
        pat: Pat::Ident(PatIdent {
            attrs: Vec::new(),
            by_ref: None,
            mutability: None,
            ident: ident(name),
            subpat: None,
        }),
        init: Some(LocalInit {
            eq_token: tok(),
            expr: Box::new(value),
            diverge: None,
        }),
        semi_token: tok(),
    })
}

#[must_use]
pub fn expr_stmt(value: Expr) -> Stmt {
    Stmt::Expr(value, Some(tok()))
}

#[must_use]
pub const fn trailing_expr(value: Expr) -> Stmt {
    Stmt::Expr(value, None)
}

#[must_use]
pub fn function(
    name: &str,
    params: Vec<(String, Type)>,
    output: Option<Type>,
    body: Vec<Stmt>,
) -> Item {
    let inputs: Punctuated<FnArg, syn::token::Comma> = params
        .into_iter()
        .map(|(param_name, param_ty): (String, Type)| {
            FnArg::Typed(PatType {
                attrs: Vec::new(),
                pat: Box::new(Pat::Ident(PatIdent {
                    attrs: Vec::new(),
                    by_ref: None,
                    mutability: None,
                    ident: ident(&param_name),
                    subpat: None,
                })),
                colon_token: tok(),
                ty: Box::new(param_ty),
            })
        })
        .collect();
    let return_type: ReturnType = output.map_or(ReturnType::Default, |ty: Type| {
        ReturnType::Type(tok(), Box::new(ty))
    });
    Item::Fn(ItemFn {
        attrs: Vec::new(),
        vis: Visibility::Inherited,
        sig: Signature {
            constness: None,
            asyncness: None,
            unsafety: None,
            abi: None,
            fn_token: tok(),
            ident: ident(name),
            generics: tok(),
            paren_token: tok(),
            inputs,
            variadic: None,
            output: return_type,
        },
        block: Box::new(Block {
            brace_token: tok(),
            stmts: body,
        }),
    })
}

#[must_use]
pub const fn file(items: Vec<Item>) -> syn::File {
    syn::File {
        shebang: None,
        attrs: Vec::new(),
        items,
    }
}
