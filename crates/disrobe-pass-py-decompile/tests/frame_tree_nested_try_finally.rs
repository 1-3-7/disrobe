#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::items_after_statements
)]

mod common;

use disrobe_pass_py_decompile::frame_tree::{
    Frame, FrameKind, FrameTree, FrameTreeBuilder, Post311Builder, Pre311Builder,
};
use disrobe_py_marshal::{CodeObject, PyVersion};

use crate::common::{empty_code, encode_exc_entry};

const SETUP_FINALLY_310: u8 = 122;
const POP_BLOCK_310: u8 = 87;
const RESUME: u8 = 151;

#[test]
fn py310_nested_setup_finally_nests_in_tree() {
    let version: PyVersion = PyVersion {
        major: 3,
        minor: 10,
    };
    let mut code: CodeObject = empty_code(version);
    code.code = vec![
        SETUP_FINALLY_310,
        0x10,
        SETUP_FINALLY_310,
        0x08,
        POP_BLOCK_310,
        0x00,
        POP_BLOCK_310,
        0x00,
        83,
        0x00,
    ];
    let builder: Pre311Builder = Pre311Builder::new();
    let tree: FrameTree = builder.build(&code, version).expect("build");

    assert_eq!(tree.root.children.len(), 1);
    let outer: &Frame = &tree.root.children[0];
    assert_eq!(outer.kind, FrameKind::Try);
    assert!(!outer.children.is_empty(), "outer should contain inner");
    let inner: &Frame = &outer.children[0];
    assert_eq!(inner.kind, FrameKind::Try);
    assert!(outer.range.start <= inner.range.start);
    assert!(outer.range.end >= inner.range.end);
}

#[test]
fn py311_nested_exception_table_entries_nest_in_tree() {
    let version: PyVersion = PyVersion {
        major: 3,
        minor: 11,
    };
    let mut code: CodeObject = empty_code(version);
    let mut bytecode: Vec<u8> = Vec::new();
    for _ in 0..16 {
        bytecode.extend_from_slice(&[RESUME, 0x00]);
    }
    code.code = bytecode;
    let mut table: Vec<u8> = encode_exc_entry(0, 12, 24, 0, false);
    table.extend(encode_exc_entry(2, 4, 12, 1, false));
    code.exceptiontable = table;

    let builder: Post311Builder = Post311Builder::new();
    let tree: FrameTree = builder.build(&code, version).expect("build");

    let outer: &Frame = tree
        .root
        .children
        .iter()
        .max_by_key(|f: &&Frame| f.range.end - f.range.start)
        .expect("at least one frame");
    assert!(
        !outer.children.is_empty(),
        "outer try frame should contain nested inner"
    );
    let inner: &Frame = &outer.children[0];
    assert!(outer.range.start <= inner.range.start);
    assert!(outer.range.end >= inner.range.end);
}
