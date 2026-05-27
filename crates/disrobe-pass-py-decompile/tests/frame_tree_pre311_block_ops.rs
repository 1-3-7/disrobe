#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::items_after_statements
)]

mod common;

use disrobe_pass_py_decompile::frame_tree::{
    Frame, FrameKind, FrameTree, FrameTreeBuilder, Pre311Builder,
};
use disrobe_py_marshal::{CodeObject, PyVersion};

use crate::common::empty_code;

const SETUP_FINALLY_310: u8 = 122;
const POP_BLOCK_310: u8 = 87;
const RETURN_VALUE_310: u8 = 83;

#[test]
fn py310_setup_finally_pop_block_forms_try_frame() {
    let version: PyVersion = PyVersion {
        major: 3,
        minor: 10,
    };
    let mut code: CodeObject = empty_code(version);
    code.code = vec![
        SETUP_FINALLY_310,
        0x08,
        POP_BLOCK_310,
        0x00,
        RETURN_VALUE_310,
        0x00,
    ];
    let builder: Pre311Builder = Pre311Builder::new();
    let tree: FrameTree = builder.build(&code, version).expect("build");
    assert_eq!(tree.root.kind, FrameKind::Module);
    assert_eq!(tree.root.children.len(), 1);
    let try_frame: &Frame = &tree.root.children[0];
    assert_eq!(try_frame.kind, FrameKind::Try);
    assert_eq!(try_frame.range.start, 0);
    assert_eq!(try_frame.range.end, 4);
}

#[test]
fn py27_setup_except_pop_block_end_finally_forms_try_frame() {
    let version: PyVersion = PyVersion { major: 2, minor: 7 };
    let mut code: CodeObject = empty_code(version);
    code.code = vec![121, 0x09, 0x00, 87, 88, RETURN_VALUE_310];
    let builder: Pre311Builder = Pre311Builder::new();
    let tree: FrameTree = builder.build(&code, version).expect("build");
    assert_eq!(tree.root.kind, FrameKind::Module);
    assert!(!tree.root.children.is_empty());
    let try_frame: &Frame = &tree.root.children[0];
    assert_eq!(try_frame.kind, FrameKind::Try);
    assert_eq!(try_frame.range.start, 0);
    assert!(try_frame.range.end >= 4);
}

#[test]
fn py310_setup_with_pop_block_forms_with_frame() {
    let version: PyVersion = PyVersion {
        major: 3,
        minor: 10,
    };
    let mut code: CodeObject = empty_code(version);
    code.code = vec![143, 0x06, 87, 0x00, RETURN_VALUE_310, 0x00];
    let builder: Pre311Builder = Pre311Builder::new();
    let tree: FrameTree = builder.build(&code, version).expect("build");
    assert_eq!(tree.root.children.len(), 1);
    assert_eq!(tree.root.children[0].kind, FrameKind::With);
}
