#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::items_after_statements
)]

mod common;

use disrobe_pass_py_decompile::frame_tree::{
    FrameKind, FrameTree, FrameTreeBuilder, Pre311Builder,
};
use disrobe_py_marshal::{CodeObject, PyVersion};

use crate::common::empty_code;

const SETUP_FINALLY_310: u8 = 122;
const POP_BLOCK_310: u8 = 87;
const POP_JUMP_IF_FALSE_310: u8 = 114;
const RETURN_VALUE_310: u8 = 83;

#[test]
fn py310_two_sibling_try_blocks_do_not_nest() {
    let version: PyVersion = PyVersion {
        major: 3,
        minor: 10,
    };
    let mut code: CodeObject = empty_code(version);
    code.code = vec![
        POP_JUMP_IF_FALSE_310,
        0x10,
        SETUP_FINALLY_310,
        0x04,
        POP_BLOCK_310,
        0x00,
        POP_JUMP_IF_FALSE_310,
        0x20,
        SETUP_FINALLY_310,
        0x04,
        POP_BLOCK_310,
        0x00,
        RETURN_VALUE_310,
        0x00,
    ];
    let builder: Pre311Builder = Pre311Builder::new();
    let tree: FrameTree = builder.build(&code, version).expect("build");

    let try_frames: Vec<_> = tree
        .root
        .children
        .iter()
        .filter(|f: &&disrobe_pass_py_decompile::frame_tree::Frame| f.kind == FrameKind::Try)
        .collect();
    assert_eq!(try_frames.len(), 2, "sibling tries must not collapse");
    for f in &try_frames {
        assert!(
            f.children.is_empty(),
            "siblings shouldn't have nested tries"
        );
    }
}
