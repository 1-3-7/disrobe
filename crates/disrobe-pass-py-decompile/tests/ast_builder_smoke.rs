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

use disrobe_py_marshal::{CodeEra, CodeObject, Object};

use disrobe_pass_py_decompile::ast::{
    AstBuilder, AstModule, ConstValue, DefaultAstBuilder, Expr, Stmt,
};
use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::frame_tree::{Frame, FrameId, FrameKind, FrameTree};

const LOAD_CONST: u8 = 100;
const RETURN_VALUE_312: u8 = 83;

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

#[test]
fn smoke_load_const_int_then_return_value_312() {
    let mut code: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    code.consts = vec![Object::Int(1)];
    code.code = vec![LOAD_CONST, 0, RETURN_VALUE_312, 0];
    let tree: FrameTree = module_frame_tree(code.code.len() as u32);
    let builder: DefaultAstBuilder = DefaultAstBuilder::new();
    let module: AstModule = builder
        .build_module(&code, &tree, &PyVersion::V3_12)
        .expect("build succeeds");
    assert_eq!(module.body.len(), 1, "exactly one statement");
    match &module.body[0] {
        Stmt::Return(Some(Expr::Constant {
            value: ConstValue::Int(v),
            ..
        })) => assert_eq!(*v, 1),
        other => panic!("expected Return(Some(Int(1))), got {other:?}"),
    }
}

#[test]
fn smoke_load_const_str_then_return_value_312() {
    let mut code: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    code.consts = vec![Object::String {
        value: "hello".to_owned(),
        interned: false,
    }];
    code.code = vec![LOAD_CONST, 0, RETURN_VALUE_312, 0];
    let tree: FrameTree = module_frame_tree(code.code.len() as u32);
    let builder: DefaultAstBuilder = DefaultAstBuilder::new();
    let module: AstModule = builder
        .build_module(&code, &tree, &PyVersion::V3_12)
        .expect("build succeeds");
    assert_eq!(module.body.len(), 1);
    let Stmt::Return(Some(Expr::Constant {
        value: ConstValue::Str(s),
        ..
    })) = &module.body[0]
    else {
        panic!("expected Return(Some(Str))")
    };
    assert_eq!(s, "hello");
    assert_eq!(module.docstring.as_deref(), Some("hello"));
}

#[test]
fn smoke_empty_code_yields_empty_module() {
    let code: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    let tree: FrameTree = module_frame_tree(0);
    let builder: DefaultAstBuilder = DefaultAstBuilder::new();
    let module: AstModule = builder
        .build_module(&code, &tree, &PyVersion::V3_12)
        .expect("empty build succeeds");
    assert!(module.body.is_empty());
}
