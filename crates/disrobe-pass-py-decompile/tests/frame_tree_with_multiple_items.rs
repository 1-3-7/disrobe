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

const SETUP_WITH_310: u8 = 143;
const POP_BLOCK_310: u8 = 87;
const RETURN_VALUE_310: u8 = 83;

#[test]
fn py310_three_with_blocks_build_three_with_frames() {
    let version: PyVersion = PyVersion {
        major: 3,
        minor: 10,
    };
    let mut code: CodeObject = empty_code(version);
    code.code = vec![
        SETUP_WITH_310,
        0x14,
        SETUP_WITH_310,
        0x10,
        SETUP_WITH_310,
        0x0C,
        POP_BLOCK_310,
        0x00,
        POP_BLOCK_310,
        0x00,
        POP_BLOCK_310,
        0x00,
        RETURN_VALUE_310,
        0x00,
    ];
    let builder: Pre311Builder = Pre311Builder::new();
    let tree: FrameTree = builder.build(&code, version).expect("build");

    fn count(node: &disrobe_pass_py_decompile::frame_tree::Frame, kind: FrameKind) -> usize {
        let mut n: usize = usize::from(node.kind == kind);
        for c in &node.children {
            n += count(c, kind);
        }
        n
    }

    let with_count: usize = count(&tree.root, FrameKind::With);
    assert_eq!(
        with_count, 3,
        "three with blocks must produce three With frames"
    );
}
