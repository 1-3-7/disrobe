#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::missing_const_for_fn,
    clippy::items_after_statements
)]

use disrobe_pass_py_decompile::ast::{
    Alias, Arg, Arguments, AstModule, ConstValue, ExceptHandler, Expr, ExprCtx, FormatConversion,
    Keyword, MatchCase, Pattern, Stmt, TStrItem, TypeParam, WithItem,
};
use disrobe_pass_py_decompile::bytecode::opcode::{BinOp, CmpOp, UnaryOp};

#[test]
fn construct_every_stmt_variant() {
    let stmts: Vec<Stmt> = vec![
        Stmt::FunctionDef {
            name: "f".to_owned(),
            type_params: Vec::new(),
            args: Arguments::default(),
            body: vec![Stmt::Pass],
            decorators: Vec::new(),
            returns: None,
            is_async: false,
            docstring: None,
            line: Some(1),
        },
        Stmt::ClassDef {
            name: "C".to_owned(),
            type_params: Vec::new(),
            bases: Vec::new(),
            keywords: Vec::new(),
            body: vec![Stmt::Pass],
            decorators: Vec::new(),
            docstring: None,
            line: Some(2),
        },
        Stmt::Return(None),
        Stmt::Delete(vec![name_expr("x", ExprCtx::Del)]),
        Stmt::Assign {
            targets: vec![name_expr("x", ExprCtx::Store)],
            value: int_expr(1),
            type_comment: None,
            line: Some(3),
        },
        Stmt::AugAssign {
            target: name_expr("x", ExprCtx::Store),
            op: BinOp::Add,
            value: int_expr(1),
            line: Some(4),
        },
        Stmt::AnnAssign {
            target: name_expr("x", ExprCtx::Store),
            annotation: name_expr("int", ExprCtx::Load),
            value: Some(int_expr(1)),
            simple: true,
            line: Some(5),
        },
        Stmt::TypeAlias {
            name: "Alias".to_owned(),
            type_params: vec![TypeParam::TypeVar {
                name: "T".to_owned(),
                bound: None,
                default: None,
            }],
            value: name_expr("int", ExprCtx::Load),
            line: Some(6),
        },
        Stmt::For {
            target: name_expr("i", ExprCtx::Store),
            iter: name_expr("xs", ExprCtx::Load),
            body: vec![Stmt::Pass],
            orelse: Vec::new(),
            is_async: false,
            line: Some(7),
        },
        Stmt::While {
            test: bool_expr(true),
            body: vec![Stmt::Break],
            orelse: Vec::new(),
            line: Some(8),
        },
        Stmt::If {
            test: bool_expr(true),
            body: vec![Stmt::Continue],
            orelse: Vec::new(),
            line: Some(9),
        },
        Stmt::With {
            items: vec![WithItem {
                context_expr: name_expr("cm", ExprCtx::Load),
                optional_vars: Some(name_expr("c", ExprCtx::Store)),
            }],
            body: vec![Stmt::Pass],
            is_async: false,
            line: Some(10),
        },
        Stmt::Match {
            subject: name_expr("x", ExprCtx::Load),
            cases: vec![MatchCase {
                pattern: Pattern::MatchValue(int_expr(1)),
                guard: None,
                body: vec![Stmt::Pass],
            }],
            line: Some(11),
        },
        Stmt::Raise {
            exc: Some(name_expr("E", ExprCtx::Load)),
            cause: None,
            line: Some(12),
        },
        Stmt::Try {
            body: vec![Stmt::Pass],
            handlers: vec![ExceptHandler {
                typ: Some(name_expr("Exception", ExprCtx::Load)),
                name: Some("e".to_owned()),
                body: vec![Stmt::Pass],
                line: Some(13),
            }],
            orelse: Vec::new(),
            finalbody: Vec::new(),
            line: Some(13),
        },
        Stmt::TryStar {
            body: vec![Stmt::Pass],
            handlers: Vec::new(),
            orelse: Vec::new(),
            finalbody: Vec::new(),
            line: Some(14),
        },
        Stmt::Assert {
            test: bool_expr(true),
            msg: Some(str_expr("oops")),
            line: Some(15),
        },
        Stmt::Import(vec![Alias {
            name: "os".to_owned(),
            asname: None,
        }]),
        Stmt::ImportFrom {
            module: Some("os".to_owned()),
            names: vec![Alias {
                name: "path".to_owned(),
                asname: Some("p".to_owned()),
            }],
            level: 0,
            line: Some(16),
        },
        Stmt::Global(vec!["g".to_owned()]),
        Stmt::Nonlocal(vec!["n".to_owned()]),
        Stmt::Expr(int_expr(1)),
        Stmt::Pass,
        Stmt::Break,
        Stmt::Continue,
    ];
    assert_eq!(stmts.len(), 25);
    let cloned: Vec<Stmt> = stmts.clone();
    assert_eq!(stmts, cloned);
    for s in &stmts {
        let debug_str: String = format!("{s:?}");
        assert!(!debug_str.is_empty());
    }
}

#[test]
fn construct_every_expr_variant() {
    let exprs: Vec<Expr> = vec![
        int_expr(42),
        name_expr("x", ExprCtx::Load),
        Expr::FormattedValue {
            value: Box::new(name_expr("x", ExprCtx::Load)),
            conversion: FormatConversion::Repr,
            format_spec: None,
            line: None,
        },
        Expr::JoinedStr {
            values: vec![str_expr("hi")],
            line: None,
        },
        Expr::TStr {
            items: vec![
                TStrItem::Literal("hi ".to_owned()),
                TStrItem::Interp {
                    value: name_expr("x", ExprCtx::Load),
                    expr_text: None,
                    conversion: FormatConversion::None,
                    format_spec: None,
                },
            ],
            line: None,
        },
        Expr::BoolOp {
            op: disrobe_pass_py_decompile::ast::BoolOpKind::And,
            values: vec![bool_expr(true), bool_expr(false)],
        },
        Expr::NamedExpr {
            target: Box::new(name_expr("y", ExprCtx::Store)),
            value: Box::new(int_expr(1)),
        },
        Expr::BinOp {
            left: Box::new(int_expr(1)),
            op: BinOp::Mul,
            right: Box::new(int_expr(2)),
        },
        Expr::UnaryOp {
            op: UnaryOp::Negative,
            operand: Box::new(int_expr(3)),
        },
        Expr::Lambda {
            args: Box::new(Arguments::default()),
            body: Box::new(int_expr(0)),
        },
        Expr::IfExp {
            test: Box::new(bool_expr(true)),
            body: Box::new(int_expr(1)),
            orelse: Box::new(int_expr(2)),
        },
        Expr::Dict {
            keys: vec![Some(str_expr("k"))],
            values: vec![int_expr(1)],
        },
        Expr::Set(vec![int_expr(1)]),
        Expr::ListComp {
            elt: Box::new(name_expr("x", ExprCtx::Load)),
            generators: Vec::new(),
        },
        Expr::SetComp {
            elt: Box::new(name_expr("x", ExprCtx::Load)),
            generators: Vec::new(),
        },
        Expr::DictComp {
            key: Box::new(name_expr("k", ExprCtx::Load)),
            value: Box::new(name_expr("v", ExprCtx::Load)),
            generators: Vec::new(),
        },
        Expr::GeneratorExp {
            elt: Box::new(name_expr("x", ExprCtx::Load)),
            generators: Vec::new(),
        },
        Expr::Await(Box::new(name_expr("a", ExprCtx::Load))),
        Expr::Yield(None),
        Expr::YieldFrom(Box::new(name_expr("g", ExprCtx::Load))),
        Expr::Compare {
            left: Box::new(int_expr(1)),
            ops: vec![CmpOp::Lt],
            comparators: vec![int_expr(2)],
        },
        Expr::Call {
            func: Box::new(name_expr("f", ExprCtx::Load)),
            args: vec![int_expr(1)],
            keywords: vec![Keyword {
                arg: Some("k".to_owned()),
                value: int_expr(2),
            }],
        },
        Expr::Attribute {
            value: Box::new(name_expr("o", ExprCtx::Load)),
            attr: "attr".to_owned(),
            ctx: ExprCtx::Load,
        },
        Expr::Subscript {
            value: Box::new(name_expr("o", ExprCtx::Load)),
            slice: Box::new(int_expr(0)),
            ctx: ExprCtx::Load,
        },
        Expr::Starred {
            value: Box::new(name_expr("o", ExprCtx::Load)),
            ctx: ExprCtx::Load,
        },
        Expr::List {
            elts: vec![int_expr(1)],
            ctx: ExprCtx::Load,
        },
        Expr::Tuple {
            elts: vec![int_expr(1)],
            ctx: ExprCtx::Load,
        },
        Expr::Slice {
            lower: Some(Box::new(int_expr(0))),
            upper: Some(Box::new(int_expr(1))),
            step: None,
        },
        Expr::EmptyDictUnpack,
        Expr::EmptyDictKeyUnpack,
    ];
    assert_eq!(exprs.len(), 30);
    let cloned: Vec<Expr> = exprs.clone();
    assert_eq!(exprs, cloned);
    for e in &exprs {
        let debug_str: String = format!("{e:?}");
        assert!(!debug_str.is_empty());
    }
}

#[test]
fn construct_every_pattern_variant() {
    let patterns: Vec<Pattern> = vec![
        Pattern::MatchValue(int_expr(1)),
        Pattern::MatchSingleton(ConstValue::None),
        Pattern::MatchSequence(vec![Pattern::MatchSingleton(ConstValue::True)]),
        Pattern::MatchMapping {
            keys: vec![str_expr("k")],
            patterns: vec![Pattern::MatchValue(int_expr(1))],
            rest: Some("rest".to_owned()),
        },
        Pattern::MatchClass {
            cls: name_expr("Point", ExprCtx::Load),
            patterns: vec![Pattern::MatchValue(int_expr(0))],
            kwd_attrs: vec!["x".to_owned()],
            kwd_patterns: vec![Pattern::MatchValue(int_expr(1))],
        },
        Pattern::MatchStar(Some("rest".to_owned())),
        Pattern::MatchAs {
            pattern: Some(Box::new(Pattern::MatchValue(int_expr(1)))),
            name: Some("a".to_owned()),
        },
        Pattern::MatchOr(vec![
            Pattern::MatchValue(int_expr(1)),
            Pattern::MatchValue(int_expr(2)),
        ]),
    ];
    assert_eq!(patterns.len(), 8);
    let cloned: Vec<Pattern> = patterns.clone();
    assert_eq!(patterns, cloned);
}

#[test]
fn type_params_cover_pep_695_and_696() {
    let tps: Vec<TypeParam> = vec![
        TypeParam::TypeVar {
            name: "T".to_owned(),
            bound: Some(name_expr("int", ExprCtx::Load)),
            default: Some(name_expr("int", ExprCtx::Load)),
        },
        TypeParam::ParamSpec {
            name: "P".to_owned(),
            default: Some(name_expr("None", ExprCtx::Load)),
        },
        TypeParam::TypeVarTuple {
            name: "Ts".to_owned(),
            default: None,
        },
    ];
    assert_eq!(tps.len(), 3);
}

#[test]
fn module_default_is_empty() {
    let m: AstModule = AstModule::default();
    assert!(m.body.is_empty());
    assert!(m.blank_lines.is_empty());
    assert!(m.docstring.is_none());
}

#[test]
fn arg_supports_full_pep_3102_570_695() {
    let args: Arguments = Arguments {
        posonly: vec![arg("p1")],
        args: vec![arg("a1"), arg("a2")],
        vararg: Some(Box::new(arg("args"))),
        kwonly: vec![arg("k1")],
        kw_defaults: vec![Some(int_expr(0))],
        kwarg: Some(Box::new(arg("kwargs"))),
        defaults: vec![int_expr(1)],
    };
    assert_eq!(args.posonly.len(), 1);
    assert_eq!(args.args.len(), 2);
    assert!(args.vararg.is_some());
    assert!(args.kwarg.is_some());
}

fn arg(name: &str) -> Arg {
    Arg {
        arg: name.to_owned(),
        annotation: None,
        default: None,
        line: None,
    }
}

fn int_expr(v: i128) -> Expr {
    Expr::Constant {
        value: ConstValue::Int(v),
        line: None,
    }
}

fn str_expr(v: &str) -> Expr {
    Expr::Constant {
        value: ConstValue::Str(v.to_owned()),
        line: None,
    }
}

fn bool_expr(v: bool) -> Expr {
    Expr::Constant {
        value: if v {
            ConstValue::True
        } else {
            ConstValue::False
        },
        line: None,
    }
}

fn name_expr(id: &str, ctx: ExprCtx) -> Expr {
    Expr::Name {
        id: id.to_owned(),
        ctx,
        line: None,
    }
}
