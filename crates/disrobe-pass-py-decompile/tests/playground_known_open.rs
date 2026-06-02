#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_const_for_fn,
    clippy::items_after_statements,
    clippy::too_many_lines,
    clippy::default_trait_access,
    clippy::approx_constant
)]

use disrobe_pass_py_decompile::ast::{
    Arg, Arguments, AstModule, ConstValue, ExceptHandler, Expr, ExprCtx, Keyword, MatchCase,
    Pattern, Stmt, WithItem,
};
use disrobe_pass_py_decompile::bytecode::opcode::{BinOp, CmpOp};
use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::codegen::{CodeEmitter, DefaultEmitter};

fn version() -> PyVersion {
    PyVersion::V3_13
}

fn name(id: &str) -> Expr {
    Expr::Name {
        id: id.to_owned(),
        ctx: ExprCtx::Load,
        line: None,
    }
}

fn name_store(id: &str) -> Expr {
    Expr::Name {
        id: id.to_owned(),
        ctx: ExprCtx::Store,
        line: None,
    }
}

fn int(n: i128) -> Expr {
    Expr::Constant {
        value: ConstValue::Int(n),
        line: None,
    }
}

fn str_lit(s: &str) -> Expr {
    Expr::Constant {
        value: ConstValue::Str(s.to_owned()),
        line: None,
    }
}

fn render(module: &AstModule) -> String {
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = version();
    em.emit_module(module, &v)
}

fn render_stmt(stmt: Stmt) -> String {
    let module: AstModule = AstModule {
        docstring: None,
        body: vec![stmt],
        blank_lines: Default::default(),
    };
    render(&module)
}

#[test]
fn known_open_01_assert_statements_preserves_body() {
    let func: Stmt = Stmt::FunctionDef {
        name: "assert_statements".to_owned(),
        type_params: Vec::new(),
        args: Arguments {
            args: vec![
                Arg {
                    arg: "value".to_owned(),
                    annotation: None,
                    default: None,
                    line: None,
                },
                Arg {
                    arg: "items".to_owned(),
                    annotation: None,
                    default: None,
                    line: None,
                },
            ],
            ..Default::default()
        },
        body: vec![
            Stmt::Assert {
                test: Expr::Compare {
                    left: Box::new(name("value")),
                    ops: vec![CmpOp::Ge],
                    comparators: vec![int(0)],
                },
                msg: None,
                line: None,
            },
            Stmt::Assert {
                test: name("items"),
                msg: Some(str_lit("items must be non-empty")),
                line: None,
            },
            Stmt::Return(Some(Expr::Subscript {
                value: Box::new(name("items")),
                slice: Box::new(name("value")),
                ctx: ExprCtx::Load,
            })),
        ],
        decorators: Vec::new(),
        returns: None,
        is_async: false,
        docstring: None,
        line: None,
    };
    let out: String = render_stmt(func);
    assert!(
        out.contains("assert value >= 0"),
        "first assert dropped: {out}"
    );
    assert!(
        out.contains("items must be non-empty"),
        "second assert message dropped"
    );
    assert!(
        out.contains("return items[value]"),
        "return after asserts dropped (DROP class)"
    );
    assert!(
        !out.trim_end().ends_with("pass"),
        "must NOT degrade body to pass"
    );
}

#[test]
fn known_open_02_generator_yield_from_preserved() {
    let func: Stmt = Stmt::FunctionDef {
        name: "generator_yield_from".to_owned(),
        type_params: Vec::new(),
        args: Arguments {
            args: vec![Arg {
                arg: "limit".to_owned(),
                annotation: None,
                default: None,
                line: None,
            }],
            ..Default::default()
        },
        body: vec![Stmt::Expr(Expr::YieldFrom(Box::new(Expr::Call {
            func: Box::new(name("range")),
            args: vec![name("limit")],
            keywords: Vec::new(),
        })))],
        decorators: Vec::new(),
        returns: None,
        is_async: false,
        docstring: None,
        line: None,
    };
    let out: String = render_stmt(func);
    assert!(
        out.contains("yield from range(limit)"),
        "yield from dropped (DROP class): {out}"
    );
}

#[test]
fn known_open_03_nested_try_finally() {
    let stmt: Stmt = Stmt::Try {
        body: vec![Stmt::Try {
            body: vec![Stmt::Return(Some(Expr::Call {
                func: Box::new(name("a")),
                args: Vec::new(),
                keywords: Vec::new(),
            }))],
            handlers: Vec::new(),
            orelse: Vec::new(),
            finalbody: vec![Stmt::Expr(Expr::Call {
                func: Box::new(name("print")),
                args: vec![str_lit("inner")],
                keywords: Vec::new(),
            })],
            line: None,
        }],
        handlers: Vec::new(),
        orelse: Vec::new(),
        finalbody: vec![Stmt::Expr(Expr::Call {
            func: Box::new(name("print")),
            args: vec![str_lit("outer")],
            keywords: Vec::new(),
        })],
        line: None,
    };
    let out: String = render_stmt(stmt);
    let try_count: usize = out.matches("try:").count();
    let finally_count: usize = out.matches("finally:").count();
    assert_eq!(try_count, 2, "nested try keyword count wrong: {out}");
    assert_eq!(
        finally_count, 2,
        "nested finally keyword count wrong: {out}"
    );
}

#[test]
fn known_open_04_finally_with_return_override() {
    let stmt: Stmt = Stmt::Try {
        body: vec![
            Stmt::If {
                test: name("flag"),
                body: vec![Stmt::Return(Some(int(1)))],
                orelse: Vec::new(),
                line: None,
            },
            Stmt::Return(Some(int(2))),
        ],
        handlers: Vec::new(),
        orelse: Vec::new(),
        finalbody: vec![Stmt::If {
            test: Expr::UnaryOp {
                op: disrobe_pass_py_decompile::bytecode::opcode::UnaryOp::Not,
                operand: Box::new(name("flag")),
            },
            body: vec![Stmt::Return(Some(int(3)))],
            orelse: Vec::new(),
            line: None,
        }],
        line: None,
    };
    let out: String = render_stmt(stmt);
    assert!(out.contains("try:"), "try keyword dropped: {out}");
    assert!(
        out.contains("finally:"),
        "finally keyword dropped (GARBAGE class): {out}"
    );
    assert!(out.contains("return 3"), "finally's return dropped: {out}");
}

#[test]
fn known_open_05_with_multiple_items() {
    let stmt: Stmt = Stmt::With {
        items: vec![
            WithItem {
                context_expr: name("a"),
                optional_vars: Some(name_store("first")),
            },
            WithItem {
                context_expr: name("b"),
                optional_vars: Some(name_store("second")),
            },
        ],
        body: vec![Stmt::Expr(Expr::Call {
            func: Box::new(name("print")),
            args: vec![name("first"), name("second")],
            keywords: Vec::new(),
        })],
        is_async: false,
        line: None,
    };
    let out: String = render_stmt(stmt);
    assert!(
        out.contains("with a as first, b as second:"),
        "multi-item with collapsed to a single nested with: {out}"
    );
    assert!(!out.contains("None"), "must not emit bare None context");
}

#[test]
fn known_open_06_with_parenthesized() {
    let stmt: Stmt = Stmt::With {
        items: vec![
            WithItem {
                context_expr: name("a"),
                optional_vars: Some(name_store("first")),
            },
            WithItem {
                context_expr: name("b"),
                optional_vars: Some(name_store("second")),
            },
            WithItem {
                context_expr: name("c"),
                optional_vars: Some(name_store("third")),
            },
        ],
        body: vec![Stmt::Expr(Expr::Call {
            func: Box::new(name("print")),
            args: vec![name("first"), name("second"), name("third")],
            keywords: Vec::new(),
        })],
        is_async: false,
        line: None,
    };
    let out: String = render_stmt(stmt);
    assert!(out.contains("with"), "with keyword");
    assert!(
        out.contains("as first") && out.contains("as second") && out.contains("as third"),
        "all three managers present: {out}"
    );
}

#[test]
fn known_open_07_with_return_wrapped_by_finally() {
    let inner_with: Stmt = Stmt::With {
        items: vec![WithItem {
            context_expr: name("lock"),
            optional_vars: None,
        }],
        body: vec![
            Stmt::Assign {
                targets: vec![name_store("cursor")],
                value: name("rowid"),
                type_comment: None,
                line: None,
            },
            Stmt::Return(Some(Expr::Call {
                func: Box::new(name("int")),
                args: vec![Expr::BoolOp {
                    op: disrobe_pass_py_decompile::ast::BoolOpKind::Or,
                    values: vec![name("cursor"), int(0)],
                }],
                keywords: Vec::new(),
            })),
        ],
        is_async: false,
        line: None,
    };
    let stmt: Stmt = Stmt::Try {
        body: vec![inner_with],
        handlers: Vec::new(),
        orelse: Vec::new(),
        finalbody: vec![Stmt::If {
            test: name("cursor"),
            body: vec![Stmt::Expr(Expr::Call {
                func: Box::new(name("release")),
                args: vec![name("cursor")],
                keywords: Vec::new(),
            })],
            orelse: Vec::new(),
            line: None,
        }],
        line: None,
    };
    let out: String = render_stmt(stmt);
    assert!(out.contains("try:"), "outer try");
    assert!(out.contains("finally:"), "finally preserved");
    assert!(out.contains("with lock"), "inner with preserved");
    assert!(out.contains("return"), "return preserved");
}

#[test]
fn known_open_08_with_await_in_except() {
    let with_stmt: Stmt = Stmt::With {
        items: vec![WithItem {
            context_expr: Expr::Call {
                func: Box::new(Expr::Attribute {
                    value: Box::new(name("contextlib")),
                    attr: "suppress".to_owned(),
                    ctx: ExprCtx::Load,
                }),
                args: vec![name("Exception")],
                keywords: Vec::new(),
            },
            optional_vars: None,
        }],
        body: vec![Stmt::Expr(Expr::Await(Box::new(Expr::Call {
            func: Box::new(Expr::Attribute {
                value: Box::new(name("pool")),
                attr: "recycle".to_owned(),
                ctx: ExprCtx::Load,
            }),
            args: Vec::new(),
            keywords: Vec::new(),
        })))],
        is_async: false,
        line: None,
    };
    let try_stmt: Stmt = Stmt::Try {
        body: vec![Stmt::Return(Some(Expr::Await(Box::new(Expr::Call {
            func: Box::new(Expr::Attribute {
                value: Box::new(name("pool")),
                attr: "read".to_owned(),
                ctx: ExprCtx::Load,
            }),
            args: Vec::new(),
            keywords: Vec::new(),
        }))))],
        handlers: vec![ExceptHandler {
            typ: Some(name("ConnectionError")),
            name: None,
            body: vec![with_stmt, Stmt::Return(Some(int(-1)))],
            line: None,
        }],
        orelse: Vec::new(),
        finalbody: Vec::new(),
        line: None,
    };
    let out: String = render_stmt(try_stmt);
    assert!(out.contains("try:"));
    assert!(out.contains("except ConnectionError"));
    assert!(
        out.contains("with contextlib.suppress(Exception)"),
        "with inside except: {out}"
    );
    assert!(
        out.contains("await pool.recycle()"),
        "await inside with-in-except: {out}"
    );
}

#[test]
fn known_open_09_async_with_in_try_finally() {
    let async_with: Stmt = Stmt::With {
        items: vec![WithItem {
            context_expr: name("resource"),
            optional_vars: Some(name_store("r")),
        }],
        body: vec![Stmt::Return(Some(Expr::Await(Box::new(Expr::Call {
            func: Box::new(Expr::Attribute {
                value: Box::new(name("r")),
                attr: "size".to_owned(),
                ctx: ExprCtx::Load,
            }),
            args: Vec::new(),
            keywords: Vec::new(),
        }))))],
        is_async: true,
        line: None,
    };
    let try_stmt: Stmt = Stmt::Try {
        body: vec![async_with],
        handlers: Vec::new(),
        orelse: Vec::new(),
        finalbody: vec![Stmt::Expr(Expr::Await(Box::new(Expr::Call {
            func: Box::new(Expr::Attribute {
                value: Box::new(name("resource")),
                attr: "aclose".to_owned(),
                ctx: ExprCtx::Load,
            }),
            args: Vec::new(),
            keywords: Vec::new(),
        })))],
        line: None,
    };
    let out: String = render_stmt(try_stmt);
    assert!(out.contains("try:"), "try preserved: {out}");
    assert!(out.contains("finally:"), "finally NOT inlined: {out}");
    assert!(
        out.contains("async with resource as r"),
        "async with preserved: {out}"
    );
}

#[test]
fn known_open_10_async_for_else() {
    let for_stmt: Stmt = Stmt::For {
        target: name_store("value"),
        iter: name("stream"),
        body: vec![Stmt::If {
            test: Expr::Compare {
                left: Box::new(name("value")),
                ops: vec![CmpOp::Gt],
                comparators: vec![int(100)],
            },
            body: vec![
                Stmt::Assign {
                    targets: vec![name_store("found")],
                    value: name("value"),
                    type_comment: None,
                    line: None,
                },
                Stmt::Break,
            ],
            orelse: Vec::new(),
            line: None,
        }],
        orelse: vec![Stmt::Assign {
            targets: vec![name_store("found")],
            value: int(0),
            type_comment: None,
            line: None,
        }],
        is_async: true,
        line: None,
    };
    let out: String = render_stmt(for_stmt);
    assert!(
        out.contains("async for value in stream"),
        "async for header: {out}"
    );
    assert!(out.contains("else:"), "async-for-else preserved: {out}");
    assert!(out.contains("found = 0"), "else body content: {out}");
}

#[test]
fn known_open_11_try_continue_finally() {
    let try_stmt: Stmt = Stmt::Try {
        body: vec![Stmt::AugAssign {
            target: name_store("total"),
            op: BinOp::Add,
            value: Expr::BinOp {
                left: Box::new(int(100)),
                op: BinOp::FloorDiv,
                right: Box::new(name("x")),
            },
            line: None,
        }],
        handlers: vec![ExceptHandler {
            typ: Some(name("ZeroDivisionError")),
            name: None,
            body: vec![Stmt::Continue],
            line: None,
        }],
        orelse: Vec::new(),
        finalbody: vec![Stmt::AugAssign {
            target: name_store("total"),
            op: BinOp::Add,
            value: int(1),
            line: None,
        }],
        line: None,
    };
    let for_stmt: Stmt = Stmt::For {
        target: name_store("x"),
        iter: name("xs"),
        body: vec![try_stmt],
        orelse: Vec::new(),
        is_async: false,
        line: None,
    };
    let out: String = render_stmt(for_stmt);
    assert!(out.contains("for x in xs"));
    assert!(out.contains("try:"));
    assert!(out.contains("except ZeroDivisionError"));
    assert!(out.contains("continue"), "continue preserved: {out}");
    assert!(out.contains("finally:"), "finally preserved: {out}");
}

#[test]
fn known_open_12_match_value_patterns() {
    let match_stmt: Stmt = Stmt::Match {
        subject: name("command"),
        cases: vec![
            MatchCase {
                pattern: Pattern::MatchValue(str_lit("start")),
                guard: None,
                body: vec![Stmt::Return(Some(int(1)))],
            },
            MatchCase {
                pattern: Pattern::MatchValue(str_lit("stop")),
                guard: None,
                body: vec![Stmt::Return(Some(int(2)))],
            },
            MatchCase {
                pattern: Pattern::MatchAs {
                    pattern: None,
                    name: None,
                },
                guard: None,
                body: vec![Stmt::Return(Some(int(0)))],
            },
        ],
        line: None,
    };
    let out: String = render_stmt(match_stmt);
    assert!(
        out.contains("match command"),
        "match keyword preserved: {out}"
    );
    assert!(
        !out.contains("if "),
        "must NOT degrade to if/elif chain (STRUCT class)"
    );
    assert!(
        out.matches("case ").count() >= 3,
        "all three cases preserved"
    );
}

#[test]
fn known_open_13_match_class_pattern() {
    let match_stmt: Stmt = Stmt::Match {
        subject: name("shape"),
        cases: vec![
            MatchCase {
                pattern: Pattern::MatchClass {
                    cls: name("Circle"),
                    patterns: Vec::new(),
                    kwd_attrs: vec!["radius".to_owned()],
                    kwd_patterns: vec![Pattern::MatchAs {
                        pattern: None,
                        name: Some("r".to_owned()),
                    }],
                },
                guard: None,
                body: vec![Stmt::Return(Some(Expr::BinOp {
                    left: Box::new(Expr::BinOp {
                        left: Box::new(Expr::Constant {
                            value: ConstValue::Float(3.14159),
                            line: None,
                        }),
                        op: BinOp::Mul,
                        right: Box::new(name("r")),
                    }),
                    op: BinOp::Mul,
                    right: Box::new(name("r")),
                }))],
            },
            MatchCase {
                pattern: Pattern::MatchAs {
                    pattern: None,
                    name: None,
                },
                guard: None,
                body: vec![Stmt::Return(Some(Expr::Constant {
                    value: ConstValue::Float(0.0),
                    line: None,
                }))],
            },
        ],
        line: None,
    };
    let out: String = render_stmt(match_stmt);
    assert!(out.contains("match shape"));
    assert!(out.contains("Circle"), "class name preserved: {out}");
    assert!(out.contains("radius"), "kw-attr preserved");
    assert!(out.matches("case ").count() >= 2);
}

#[test]
fn known_open_13b_match_sequence_pattern() {
    let match_stmt: Stmt = Stmt::Match {
        subject: name("seq"),
        cases: vec![
            MatchCase {
                pattern: Pattern::MatchSequence(Vec::new()),
                guard: None,
                body: vec![Stmt::Return(Some(str_lit("empty")))],
            },
            MatchCase {
                pattern: Pattern::MatchSequence(vec![
                    Pattern::MatchAs {
                        pattern: None,
                        name: Some("first".to_owned()),
                    },
                    Pattern::MatchStar(Some("rest".to_owned())),
                ]),
                guard: None,
                body: vec![Stmt::Return(Some(str_lit("non-empty")))],
            },
        ],
        line: None,
    };
    let out: String = render_stmt(match_stmt);
    assert!(out.contains("match seq"), "match keyword");
    assert!(out.contains("case ["), "sequence pattern: {out}");
    assert!(out.contains("*rest"), "star capture: {out}");
}

#[test]
fn known_open_13c_match_mapping_pattern() {
    let match_stmt: Stmt = Stmt::Match {
        subject: name("event"),
        cases: vec![MatchCase {
            pattern: Pattern::MatchMapping {
                keys: vec![str_lit("type")],
                patterns: vec![Pattern::MatchAs {
                    pattern: None,
                    name: Some("kind".to_owned()),
                }],
                rest: Some("extra".to_owned()),
            },
            guard: None,
            body: vec![Stmt::Return(Some(name("kind")))],
        }],
        line: None,
    };
    let out: String = render_stmt(match_stmt);
    assert!(out.contains("match event"));
    assert!(out.contains("case {"), "mapping pattern: {out}");
    assert!(out.contains("**extra"), "rest capture (**): {out}");
}

#[test]
fn known_open_14_multiple_inheritance_base_order_preserved() {
    let combined: Stmt = Stmt::ClassDef {
        name: "Combined".to_owned(),
        type_params: Vec::new(),
        bases: vec![name("MixinA"), name("MixinB")],
        keywords: Vec::new(),
        body: vec![Stmt::Pass],
        decorators: Vec::new(),
        docstring: None,
        line: None,
    };
    let out: String = render_stmt(combined);
    assert!(
        out.contains("class Combined(MixinA, MixinB)"),
        "base order must be MixinA, MixinB (STRUCT class): {out}"
    );
}

#[test]
fn known_open_15_chained_assignment_source_order() {
    let stmt: Stmt = Stmt::Assign {
        targets: vec![name_store("a"), name_store("b"), name_store("c")],
        value: name("total"),
        type_comment: None,
        line: None,
    };
    let out: String = render_stmt(stmt);
    assert_eq!(
        out.trim(),
        "a = b = c = total",
        "chained-assign source order must be a, b, c"
    );
}

#[test]
fn known_open_16_dict_double_unpack() {
    let stmt: Stmt = Stmt::Return(Some(Expr::Call {
        func: Box::new(name("dict")),
        args: Vec::new(),
        keywords: vec![
            Keyword {
                arg: None,
                value: name("base"),
            },
            Keyword {
                arg: None,
                value: name("extra"),
            },
            Keyword {
                arg: Some("flag".to_owned()),
                value: Expr::Constant {
                    value: ConstValue::True,
                    line: None,
                },
            },
        ],
    }));
    let out: String = render_stmt(stmt);
    assert!(out.contains("dict(**base"), "first ** unpack: {out}");
    assert!(out.contains("**extra"), "second ** unpack: {out}");
    assert!(out.contains("flag=True"), "kwarg preserved: {out}");
}

#[test]
fn known_open_17_generic_container_old_style() {
    let class_def: Stmt = Stmt::ClassDef {
        name: "GenericContainer".to_owned(),
        type_params: Vec::new(),
        bases: vec![Expr::Subscript {
            value: Box::new(name("Generic")),
            slice: Box::new(name("T")),
            ctx: ExprCtx::Load,
        }],
        keywords: Vec::new(),
        body: vec![Stmt::Pass],
        decorators: Vec::new(),
        docstring: None,
        line: None,
    };
    let out: String = render_stmt(class_def);
    assert!(
        out.contains("class GenericContainer(Generic[T])"),
        "old-style Generic[T] preserved (STRUCT class): {out}"
    );
}
