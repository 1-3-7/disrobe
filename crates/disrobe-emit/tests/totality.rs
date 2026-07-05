#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::pedantic,
    clippy::nursery
)]

use disrobe_emit::c::ast::{
    AggregateKind, AssignOp, BinaryOp, CBaseType, CDecl, CExpr, CField, CFile, CInit, CItem,
    CParam, CQuals, CStmt, CTypeSpec, DeclaratorChain, IntSuffix, LongSuffix, PostfixOp, Radix,
    Storage, TypeName, UnaryOp,
};
use disrobe_emit::c::print::{ParenMode, render_expr_mode, render_item, render_stmt};
use disrobe_emit::precedence::{Assoc, Precedence, Side, parenthesize_operand};
use disrobe_emit::{Interner, Symbol};

fn every_expr(interner: &mut Interner) -> Vec<CExpr> {
    let sa: Symbol = interner.intern("a");
    let sb: Symbol = interner.intern("b");
    let sf: Symbol = interner.intern("f");
    let sx: Symbol = interner.intern("x");
    let sarr: Symbol = interner.intern("arr");
    let sp: Symbol = interner.intern("p");
    let sfield: Symbol = interner.intern("field");
    let a = || Box::new(CExpr::Ident(sa));
    let b = || Box::new(CExpr::Ident(sb));

    let unary_ops: [UnaryOp; 8] = [
        UnaryOp::Neg,
        UnaryOp::Pos,
        UnaryOp::Not,
        UnaryOp::BitNot,
        UnaryOp::Deref,
        UnaryOp::AddrOf,
        UnaryOp::PreInc,
        UnaryOp::PreDec,
    ];
    let binary_ops: [BinaryOp; 18] = [
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
    ];
    let assign_ops: [AssignOp; 11] = [
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
    ];

    let mut exprs: Vec<CExpr> = vec![
        CExpr::Int {
            value: 255,
            radix: Radix::Hex,
            suffix: IntSuffix {
                unsigned: true,
                long: LongSuffix::LongLong,
            },
        },
        CExpr::Int {
            value: 8,
            radix: Radix::Oct,
            suffix: IntSuffix {
                unsigned: false,
                long: LongSuffix::Long,
            },
        },
        CExpr::int(0),
        CExpr::Float(Box::from("1.5e-3")),
        CExpr::Char('\n'),
        CExpr::Char('\''),
        CExpr::Char('A'),
        CExpr::Char('\u{100}'),
        CExpr::Str(Box::from("a\nb\"c\\d")),
        CExpr::Ident(sx),
        CExpr::Postfix {
            op: PostfixOp::PostInc,
            operand: a(),
        },
        CExpr::Postfix {
            op: PostfixOp::PostDec,
            operand: a(),
        },
        CExpr::Ternary {
            cond: a(),
            then: b(),
            els: Box::new(CExpr::int(1)),
        },
        CExpr::Comma { lhs: a(), rhs: b() },
        CExpr::Call {
            callee: Box::new(CExpr::Ident(sf)),
            args: Vec::new(),
        },
        CExpr::Call {
            callee: Box::new(CExpr::Ident(sf)),
            args: vec![CExpr::Ident(sa), CExpr::Comma { lhs: a(), rhs: b() }],
        },
        CExpr::Index {
            base: Box::new(CExpr::Ident(sarr)),
            index: a(),
        },
        CExpr::Member {
            base: Box::new(CExpr::Ident(sp)),
            arrow: true,
            field: sfield,
        },
        CExpr::Member {
            base: Box::new(CExpr::Ident(sp)),
            arrow: false,
            field: sfield,
        },
        CExpr::Cast {
            ty: TypeName::plain(CTypeSpec::UnsignedInt),
            operand: Box::new(CExpr::Unary {
                op: UnaryOp::Neg,
                operand: a(),
            }),
        },
        CExpr::SizeofExpr(a()),
        CExpr::SizeofType(TypeName {
            base: CBaseType::plain(CTypeSpec::Double),
            declarator: DeclaratorChain::Terminal.pointer_to(),
        }),
        CExpr::Unary {
            op: UnaryOp::Neg,
            operand: Box::new(CExpr::Unary {
                op: UnaryOp::Neg,
                operand: a(),
            }),
        },
    ];
    for op in unary_ops {
        exprs.push(CExpr::Unary { op, operand: a() });
    }
    for op in binary_ops {
        exprs.push(CExpr::Binary {
            op,
            lhs: a(),
            rhs: b(),
        });
    }
    for op in assign_ops {
        exprs.push(CExpr::Assign {
            op,
            lhs: a(),
            rhs: b(),
        });
    }
    exprs
}

#[test]
fn every_expr_variant_prints_in_both_modes() {
    let mut interner: Interner = Interner::new();
    let exprs: Vec<CExpr> = every_expr(&mut interner);
    for expr in exprs {
        let minimal: String = render_expr_mode(&expr, &interner, 60, ParenMode::Minimal);
        let full: String = render_expr_mode(&expr, &interner, 60, ParenMode::Full);
        assert!(!minimal.is_empty(), "empty minimal render for {expr:?}");
        assert!(!full.is_empty(), "empty full render for {expr:?}");
    }
}

#[test]
fn double_negation_keeps_a_space() {
    let mut interner: Interner = Interner::new();
    let sa: Symbol = interner.intern("a");
    let expr: CExpr = CExpr::Unary {
        op: UnaryOp::Neg,
        operand: Box::new(CExpr::Unary {
            op: UnaryOp::Neg,
            operand: Box::new(CExpr::Ident(sa)),
        }),
    };
    let minimal: String = render_expr_mode(&expr, &interner, 60, ParenMode::Minimal);
    assert!(!minimal.contains("--"), "token merge in {minimal:?}");
    assert_eq!(minimal, "- -a");
}

#[test]
fn unmapped_symbol_renders_sentinel() {
    let mut source: Interner = Interner::new();
    let ghost: Symbol = source.intern("ghost");
    let empty: Interner = Interner::new();
    let rendered: String = render_expr_mode(&CExpr::Ident(ghost), &empty, 60, ParenMode::Minimal);
    assert_eq!(rendered, format!("__sym{}", ghost.index()));
}

fn every_stmt(interner: &mut Interner) -> Vec<CStmt> {
    let si: Symbol = interner.intern("i");
    let sc: Symbol = interner.intern("c");
    let sx: Symbol = interner.intern("x");
    let sdone: Symbol = interner.intern("done");
    let decl: CDecl = CDecl {
        storage: Some(Storage::Register),
        base: CBaseType::plain(CTypeSpec::Int),
        name: Some(si),
        declarator: DeclaratorChain::Terminal,
        init: Some(CInit::Expr(CExpr::int(0))),
    };
    vec![
        CStmt::Empty,
        CStmt::Expr(CExpr::Ident(sx)),
        CStmt::Decl(decl.clone()),
        CStmt::Block(vec![CStmt::Break, CStmt::Continue]),
        CStmt::If {
            cond: CExpr::Ident(sc),
            then: Box::new(CStmt::Return(None)),
            els: Some(Box::new(CStmt::Return(Some(CExpr::int(1))))),
        },
        CStmt::If {
            cond: CExpr::Ident(sc),
            then: Box::new(CStmt::Break),
            els: None,
        },
        CStmt::While {
            cond: CExpr::Ident(sc),
            body: Box::new(CStmt::Continue),
        },
        CStmt::DoWhile {
            body: Box::new(CStmt::Break),
            cond: CExpr::Ident(sc),
        },
        CStmt::For {
            init: Some(Box::new(CStmt::Decl(decl))),
            cond: Some(CExpr::Ident(sc)),
            step: Some(CExpr::Unary {
                op: UnaryOp::PreInc,
                operand: Box::new(CExpr::Ident(si)),
            }),
            body: Box::new(CStmt::Block(Vec::new())),
        },
        CStmt::For {
            init: None,
            cond: None,
            step: None,
            body: Box::new(CStmt::Break),
        },
        CStmt::Switch {
            value: CExpr::Ident(sx),
            body: Box::new(CStmt::Block(vec![
                CStmt::Case {
                    value: CExpr::int(1),
                    body: Box::new(CStmt::Break),
                },
                CStmt::Default {
                    body: Box::new(CStmt::Break),
                },
            ])),
        },
        CStmt::Return(Some(CExpr::Ident(sx))),
        CStmt::Return(None),
        CStmt::Break,
        CStmt::Continue,
        CStmt::Goto(sdone),
        CStmt::Label {
            name: sdone,
            body: Box::new(CStmt::Empty),
        },
    ]
}

#[test]
fn every_stmt_variant_prints() {
    let mut interner: Interner = Interner::new();
    let stmts: Vec<CStmt> = every_stmt(&mut interner);
    for stmt in stmts {
        let rendered: String = render_stmt(&stmt, &interner, 60);
        assert!(!rendered.is_empty(), "empty render for {stmt:?}");
    }
}

#[test]
fn every_item_variant_prints() {
    let mut interner: Interner = Interner::new();
    let function: CItem = CItem::Function {
        decl: CDecl {
            storage: None,
            base: CBaseType::plain(CTypeSpec::Void),
            name: Some(interner.intern("f")),
            declarator: DeclaratorChain::Terminal.returning(Vec::new(), false),
            init: None,
        },
        body: vec![CStmt::Return(None)],
    };
    let declaration: CItem = CItem::Decl(CDecl::simple(
        &mut interner,
        CBaseType::plain(CTypeSpec::Int),
        "g",
    ));
    let typedef: CItem = CItem::Typedef(CDecl {
        storage: None,
        base: CBaseType::plain(CTypeSpec::Int),
        name: Some(interner.intern("word")),
        declarator: DeclaratorChain::Terminal,
        init: None,
    });
    let bits: Symbol = interner.intern("bits");
    let tag: Symbol = interner.intern("tag");
    let union_tag: Symbol = interner.intern("u");
    let aggregate: CItem = CItem::Aggregate {
        kind: AggregateKind::Union,
        tag: Some(union_tag),
        fields: vec![
            CField {
                base: CBaseType::plain(CTypeSpec::Int),
                name: Some(bits),
                declarator: DeclaratorChain::Terminal,
                bitfield: Some(CExpr::int(3)),
            },
            CField {
                base: CBaseType {
                    quals: CQuals {
                        is_const: true,
                        is_volatile: true,
                        is_restrict: false,
                    },
                    spec: CTypeSpec::Char,
                },
                name: Some(tag),
                declarator: DeclaratorChain::Terminal.pointer_to(),
                bitfield: None,
            },
        ],
    };
    for item in [function, declaration, typedef, aggregate] {
        let rendered: String = render_item(&item, &interner, 60);
        assert!(!rendered.is_empty(), "empty render for {item:?}");
    }
}

#[test]
fn empty_file_and_params_render() {
    let mut interner: Interner = Interner::new();
    assert_eq!(
        disrobe_emit::c::print::render_file(&CFile::default(), &interner, 60),
        ""
    );
    let count: Symbol = interner.intern("count");
    let name: Symbol = interner.intern("printf_like");
    let variadic: CParam = CParam {
        base: CBaseType::plain(CTypeSpec::Int),
        name: Some(count),
        declarator: DeclaratorChain::Terminal,
    };
    let decl: CDecl = CDecl {
        storage: None,
        base: CBaseType::plain(CTypeSpec::Int),
        name: Some(name),
        declarator: DeclaratorChain::Terminal.returning(vec![variadic], true),
        init: None,
    };
    assert_eq!(
        disrobe_emit::c::print::render_declaration(&decl, &interner, 80),
        "int printf_like(int count, ...);"
    );
}

#[test]
fn cx_builder_interns_on_the_fly() {
    use disrobe_emit::c::Cx;
    let mut interner: Interner = Interner::new();
    let expr: CExpr = {
        let mut cx: Cx<'_> = Cx::new(&mut interner);
        let p: CExpr = cx.var("p");
        let base: CExpr = cx.member(p, true, "field");
        let x: CExpr = cx.var("x");
        cx.call("f", vec![base, x])
    };
    let rendered: String = render_expr_mode(&expr, &interner, 80, ParenMode::Minimal);
    assert_eq!(rendered, "f(p->field, x)");
}

#[test]
fn interner_dedups_and_resolves() {
    let mut interner: Interner = Interner::new();
    assert!(interner.is_empty());
    let first: Symbol = interner.intern("alpha");
    let second: Symbol = interner.intern("beta");
    let first_again: Symbol = interner.intern("alpha");
    assert_eq!(first, first_again);
    assert_ne!(first, second);
    assert_eq!(interner.len(), 2);
    assert_eq!(interner.resolve(first), Some("alpha"));
    assert_eq!(interner.resolve(second), Some("beta"));
    assert_eq!(interner.lookup("alpha"), Some(first));
    assert_eq!(interner.lookup("missing"), None);
    assert_eq!(first.index(), 0);
}

#[test]
fn parenthesize_operand_associativity() {
    let low: Precedence = Precedence(1);
    let high: Precedence = Precedence(2);
    assert!(parenthesize_operand(low, high, Assoc::Left, Side::Left));
    assert!(!parenthesize_operand(high, low, Assoc::Left, Side::Left));
    assert!(!parenthesize_operand(low, low, Assoc::Left, Side::Left));
    assert!(parenthesize_operand(low, low, Assoc::Left, Side::Right));
    assert!(parenthesize_operand(low, low, Assoc::Right, Side::Left));
    assert!(!parenthesize_operand(low, low, Assoc::Right, Side::Right));
    assert!(parenthesize_operand(low, low, Assoc::None, Side::Left));
    assert!(Precedence::ATOM.tighter_than(high));
}
