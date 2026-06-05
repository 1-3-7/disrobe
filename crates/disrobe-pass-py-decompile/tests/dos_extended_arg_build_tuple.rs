#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::missing_const_for_fn,
    clippy::items_after_statements
)]

use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use disrobe_py_marshal::PyVersion as MarshalVersion;
use disrobe_py_marshal::{CodeEra, CodeObject, Object};

use disrobe_pass_py_decompile::ast::{AstBuilder, AstModule, DefaultAstBuilder};
use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::frame_tree::{Frame, FrameId, FrameKind, FrameTree};

fn module_frame_tree(code_len: u32) -> FrameTree {
    let root: Frame = Frame {
        id: FrameId(0),
        kind: FrameKind::Module,
        range: Range {
            start: 0,
            end: code_len,
        },
        body_range: Range {
            start: 0,
            end: code_len,
        },
        child_ranges: Vec::new(),
        handlers: Vec::new(),
        finally_range: None,
        line: None,
        children: Vec::new(),
    };
    FrameTree {
        root,
        by_offset: BTreeMap::new(),
    }
}

fn opcode_for(name: &str, version: MarshalVersion) -> u8 {
    (0u16..=u16::from(u8::MAX))
        .map(|raw: u16| raw as u8)
        .find(|&raw: &u8| disrobe_pass_py_disasm::opname(raw, version) == name)
        .unwrap_or_else(|| panic!("opcode {name} not found for {version:?}"))
}

/// A crafted `EXTENDED_ARG`-saturated `BUILD_TUPLE 0xFFFF_FFFF` must not OOM or hang the builder.
#[test]
fn extended_arg_build_tuple_does_not_oom_or_hang() {
    const MARSHAL: MarshalVersion = MarshalVersion::PY312;
    let extended_arg: u8 = opcode_for("EXTENDED_ARG", MARSHAL);
    let build_tuple: u8 = opcode_for("BUILD_TUPLE", MARSHAL);
    let return_value: u8 = opcode_for("RETURN_VALUE", MARSHAL);

    let mut code: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    code.consts = vec![Object::Int(0)];
    code.code = vec![
        extended_arg,
        0xFF,
        extended_arg,
        0xFF,
        extended_arg,
        0xFF,
        build_tuple,
        0xFF,
        return_value,
        0,
    ];

    let (tx, rx): (mpsc::Sender<AstModule>, mpsc::Receiver<AstModule>) = mpsc::channel();
    let worker: thread::JoinHandle<()> = thread::Builder::new()
        .name("dos-build".to_owned())
        .stack_size(2 * 1024 * 1024)
        .spawn(move || {
            let tree: FrameTree = module_frame_tree(code.code.len() as u32);
            let builder: DefaultAstBuilder = DefaultAstBuilder::new();
            if let Ok(module) = builder.build_module(&code, &tree, &PyVersion::V3_12) {
                let _ = tx.send(module);
            }
        })
        .expect("spawn build thread");

    let module: AstModule = rx.recv_timeout(Duration::from_secs(10)).expect(
        "build_module must terminate quickly; an uncapped synthesized operand fill OOMs/hangs",
    );
    worker.join().expect("build thread joins cleanly");

    let total_exprs: usize = module.body.iter().map(count_stmt_exprs).sum();
    assert!(
        total_exprs < 1 << 17,
        "synthesized operand fill must stay bounded, saw {total_exprs} expression nodes"
    );
}

fn count_stmt_exprs(stmt: &disrobe_pass_py_decompile::ast::Stmt) -> usize {
    use disrobe_pass_py_decompile::ast::Stmt;
    match stmt {
        Stmt::Return(Some(e)) | Stmt::Expr(e) => count_expr_nodes(e),
        _ => 0,
    }
}

fn count_expr_nodes(expr: &disrobe_pass_py_decompile::ast::Expr) -> usize {
    use disrobe_pass_py_decompile::ast::Expr;
    match expr {
        Expr::Tuple { elts, .. } | Expr::List { elts, .. } | Expr::Set(elts) => {
            1 + elts.iter().map(count_expr_nodes).sum::<usize>()
        }
        _ => 1,
    }
}
