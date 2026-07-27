#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::pedantic,
    clippy::nursery
)]

use std::path::PathBuf;
use std::process::Command;

use disrobe_core::scratch::ScratchFile;
use disrobe_emit::c::Cx;
use disrobe_emit::c::ast::{
    AggregateKind, BinaryOp, CBaseType, CDecl, CExpr, CField, CFile, CInit, CItem, CParam, CStmt,
    CTypeSpec, DeclaratorChain, Storage, TypeName, UnaryOp,
};
use disrobe_emit::c::print::{render_declaration, render_file, render_item};
use disrobe_emit::{Interner, Symbol};
use proptest::prelude::*;

fn int_type() -> CBaseType {
    CBaseType::plain(CTypeSpec::Int)
}

fn named_int_decl(interner: &mut Interner, name: &str, chain: DeclaratorChain) -> CDecl {
    CDecl {
        storage: None,
        base: int_type(),
        name: Some(interner.intern(name)),
        declarator: chain,
        init: None,
    }
}

fn int_param() -> CParam {
    CParam {
        base: int_type(),
        name: None,
        declarator: DeclaratorChain::Terminal,
    }
}

#[test]
fn declarator_spiral_golden() {
    let mut interner: Interner = Interner::new();
    let cases: [(DeclaratorChain, &str); 8] = [
        (DeclaratorChain::Terminal, "int x;"),
        (
            DeclaratorChain::Terminal.pointer_to().pointer_to(),
            "int **x;",
        ),
        (
            DeclaratorChain::Terminal
                .array_of(Some(CExpr::int(10)))
                .pointer_to(),
            "int (*x)[10];",
        ),
        (
            DeclaratorChain::Terminal
                .pointer_to()
                .array_of(Some(CExpr::int(10))),
            "int *x[10];",
        ),
        (
            DeclaratorChain::Terminal
                .returning(vec![int_param()], false)
                .pointer_to(),
            "int (*x)(int);",
        ),
        (
            DeclaratorChain::Terminal
                .pointer_to()
                .returning(vec![int_param()], false),
            "int *x(int);",
        ),
        (
            DeclaratorChain::Terminal
                .array_of(Some(CExpr::int(3)))
                .array_of(Some(CExpr::int(2))),
            "int x[2][3];",
        ),
        (
            DeclaratorChain::Terminal
                .array_of(Some(CExpr::int(5)))
                .pointer_to()
                .returning(vec![int_param()], false)
                .pointer_to(),
            "int (*(*x)(int))[5];",
        ),
    ];
    for (chain, expected) in cases {
        let decl: CDecl = named_int_decl(&mut interner, "x", chain);
        let rendered: String = render_declaration(&decl, &interner, 80);
        assert_eq!(rendered, expected, "declarator spiral mismatch");
    }
}

fn cc() -> Option<String> {
    for candidate in ["cc", "gcc", "clang"] {
        if Command::new(candidate)
            .arg("--version")
            .output()
            .is_ok_and(|out: std::process::Output| out.status.success())
        {
            return Some(candidate.to_owned());
        }
    }
    None
}

fn syntax_ok(compiler: &str, source: &str) -> Result<(), String> {
    let (scratch, handle): (ScratchFile, std::fs::File) =
        ScratchFile::create("disrobe-emit-cc", "c").expect("create scratch file");
    drop(handle);
    let path: PathBuf = scratch.path().to_path_buf();
    std::fs::write(&path, source).expect("write probe");
    let output: std::process::Output = Command::new(compiler)
        .args(["-fsyntax-only", "-w", "-std=c11"])
        .arg(&path)
        .output()
        .map_err(|err: std::io::Error| err.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}

#[test]
fn declarations_and_items_compile() {
    let Some(compiler): Option<String> = cc() else {
        eprintln!("skipping cc syntax oracle: no host c compiler found");
        return;
    };
    let mut interner: Interner = Interner::new();

    let golden_decls: [DeclaratorChain; 6] = [
        DeclaratorChain::Terminal
            .array_of(Some(CExpr::int(10)))
            .pointer_to(),
        DeclaratorChain::Terminal
            .pointer_to()
            .array_of(Some(CExpr::int(10))),
        DeclaratorChain::Terminal
            .returning(vec![int_param()], false)
            .pointer_to(),
        DeclaratorChain::Terminal
            .pointer_to()
            .returning(vec![int_param()], false),
        DeclaratorChain::Terminal
            .array_of(Some(CExpr::int(3)))
            .array_of(Some(CExpr::int(2))),
        DeclaratorChain::Terminal
            .array_of(Some(CExpr::int(5)))
            .pointer_to()
            .returning(vec![int_param()], false)
            .pointer_to(),
    ];
    let mut source: String = String::new();
    for (index, chain) in golden_decls.into_iter().enumerate() {
        let decl: CDecl = named_int_decl(&mut interner, &format!("g{index}"), chain);
        source.push_str(&render_declaration(&decl, &interner, 80));
        source.push('\n');
    }
    let program: CFile = sample_program(&mut interner);
    source.push_str(&render_file(&program, &interner, 80));
    source.push('\n');

    if let Err(stderr) = syntax_ok(&compiler, &source) {
        panic!("cc rejected emitted source:\n{source}\n--- stderr ---\n{stderr}");
    }
}

fn sample_program(interner: &mut Interner) -> CFile {
    let mut cx: Cx<'_> = Cx::new(interner);

    let clamp_body: Vec<CStmt> = vec![
        CStmt::If {
            cond: CExpr::Binary {
                op: BinaryOp::Lt,
                lhs: Box::new(cx.var("value")),
                rhs: Box::new(cx.var("lo")),
            },
            then: Box::new(CStmt::Return(Some(cx.var("lo")))),
            els: Some(Box::new(CStmt::If {
                cond: CExpr::Binary {
                    op: BinaryOp::Gt,
                    lhs: Box::new(cx.var("value")),
                    rhs: Box::new(cx.var("hi")),
                },
                then: Box::new(CStmt::Return(Some(cx.var("hi")))),
                els: None,
            })),
        },
        CStmt::Return(Some(cx.var("value"))),
    ];
    let clamp_name: Symbol = cx.sym("clamp");
    let value_name: Symbol = cx.sym("value");
    let lo_name: Symbol = cx.sym("lo");
    let hi_name: Symbol = cx.sym("hi");
    let clamp: CItem = CItem::Function {
        decl: CDecl {
            storage: None,
            base: int_type(),
            name: Some(clamp_name),
            declarator: DeclaratorChain::Terminal.returning(
                vec![
                    CParam {
                        base: int_type(),
                        name: Some(value_name),
                        declarator: DeclaratorChain::Terminal,
                    },
                    CParam {
                        base: int_type(),
                        name: Some(lo_name),
                        declarator: DeclaratorChain::Terminal,
                    },
                    CParam {
                        base: int_type(),
                        name: Some(hi_name),
                        declarator: DeclaratorChain::Terminal,
                    },
                ],
                false,
            ),
            init: None,
        },
        body: clamp_body,
    };

    let total_name: Symbol = cx.sym("total");
    let i_name: Symbol = cx.sym("i");
    let sum_body: Vec<CStmt> = vec![
        CStmt::Decl(CDecl {
            storage: None,
            base: int_type(),
            name: Some(total_name),
            declarator: DeclaratorChain::Terminal,
            init: Some(CInit::Expr(CExpr::int(0))),
        }),
        CStmt::For {
            init: Some(Box::new(CStmt::Decl(CDecl {
                storage: None,
                base: int_type(),
                name: Some(i_name),
                declarator: DeclaratorChain::Terminal,
                init: Some(CInit::Expr(CExpr::int(0))),
            }))),
            cond: Some(CExpr::Binary {
                op: BinaryOp::Lt,
                lhs: Box::new(cx.var("i")),
                rhs: Box::new(cx.var("n")),
            }),
            step: Some(CExpr::Unary {
                op: UnaryOp::PreInc,
                operand: Box::new(cx.var("i")),
            }),
            body: Box::new(CStmt::Expr(CExpr::Assign {
                op: disrobe_emit::c::ast::AssignOp::Add,
                lhs: Box::new(cx.var("total")),
                rhs: Box::new(cx.var("i")),
            })),
        },
        CStmt::Return(Some(cx.var("total"))),
    ];
    let sum_name: Symbol = cx.sym("sum_to");
    let n_name: Symbol = cx.sym("n");
    let sum: CItem = CItem::Function {
        decl: CDecl {
            storage: None,
            base: int_type(),
            name: Some(sum_name),
            declarator: DeclaratorChain::Terminal.returning(
                vec![CParam {
                    base: int_type(),
                    name: Some(n_name),
                    declarator: DeclaratorChain::Terminal,
                }],
                false,
            ),
            init: None,
        },
        body: sum_body,
    };

    let point_tag: Symbol = cx.sym("point");
    let x_name: Symbol = cx.sym("x");
    let y_name: Symbol = cx.sym("y");
    let point: CItem = CItem::Aggregate {
        kind: AggregateKind::Struct,
        tag: Some(point_tag),
        fields: vec![
            CField {
                base: int_type(),
                name: Some(x_name),
                declarator: DeclaratorChain::Terminal,
                bitfield: None,
            },
            CField {
                base: int_type(),
                name: Some(y_name),
                declarator: DeclaratorChain::Terminal,
                bitfield: None,
            },
        ],
    };

    let callback_name: Symbol = cx.sym("callback");
    let callback: CItem = CItem::Typedef(CDecl {
        storage: None,
        base: int_type(),
        name: Some(callback_name),
        declarator: DeclaratorChain::Terminal
            .returning(vec![int_param()], false)
            .pointer_to(),
        init: None,
    });

    CFile {
        items: vec![point, callback, clamp, sum],
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Role {
    Any,
    ArrayElem,
    FuncRet,
}

fn allowed(role: Role) -> &'static [u8] {
    match role {
        Role::Any => &[0, 1, 2, 3],
        Role::ArrayElem => &[0, 1, 2],
        Role::FuncRet => &[0, 1],
    }
}

fn build_chain(script: &[u8], cursor: &mut usize, role: Role, depth: u32) -> DeclaratorChain {
    if depth == 0 || *cursor >= script.len() {
        return DeclaratorChain::Terminal;
    }
    let byte: u8 = script[*cursor];
    *cursor += 1;
    let choices: &[u8] = allowed(role);
    let kind: u8 = choices[byte as usize % choices.len()];
    match kind {
        1 => DeclaratorChain::Pointer {
            quals: disrobe_emit::c::ast::CQuals::none(),
            to: Box::new(build_chain(script, cursor, Role::Any, depth - 1)),
        },
        2 => DeclaratorChain::Array {
            of: Box::new(build_chain(script, cursor, Role::ArrayElem, depth - 1)),
            size: Some(Box::new(CExpr::int(4))),
        },
        3 => {
            let param_count: usize = (*cursor % 3).min(2);
            let params: Vec<CParam> = (0..param_count).map(|_| int_param()).collect();
            DeclaratorChain::Function {
                returns: Box::new(build_chain(script, cursor, Role::FuncRet, depth - 1)),
                params,
                variadic: false,
            }
        }
        _ => DeclaratorChain::Terminal,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn random_valid_declarators_compile(script in prop::collection::vec(any::<u8>(), 0..10)) {
        let Some(compiler): Option<String> = cc() else {
            return Ok(());
        };
        let mut interner: Interner = Interner::new();
        let mut cursor: usize = 0;
        let chain: DeclaratorChain = build_chain(&script, &mut cursor, Role::Any, 5);
        let decl: CDecl = named_int_decl(&mut interner, "probe", chain);
        let source: String = format!("{}\n", render_declaration(&decl, &interner, 80));
        if let Err(stderr) = syntax_ok(&compiler, &source) {
            prop_assert!(false, "cc rejected {source:?}: {stderr}");
        }
    }
}

#[test]
fn type_name_and_storage_render() {
    let mut interner: Interner = Interner::new();
    let ty: TypeName = TypeName {
        base: int_type(),
        declarator: DeclaratorChain::Terminal.pointer_to(),
    };
    assert_eq!(
        disrobe_emit::c::print::render_type_name(&ty, &interner, 80),
        "int *"
    );

    let counter: CDecl = CDecl {
        storage: Some(Storage::Static),
        base: int_type(),
        name: Some(interner.intern("counter")),
        declarator: DeclaratorChain::Terminal,
        init: Some(CInit::Expr(CExpr::int(0))),
    };
    assert_eq!(
        render_declaration(&counter, &interner, 80),
        "static int counter = 0;"
    );

    let item: CItem = CItem::Decl(named_int_decl(
        &mut interner,
        "g",
        DeclaratorChain::Terminal,
    ));
    assert_eq!(render_item(&item, &interner, 80), "int g;");
}
