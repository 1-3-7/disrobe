mod common;

use disrobe_pass_py_decompile::frame_tree::{Frame, FrameId, FrameKind, FrameTree, validate};
use disrobe_py_marshal::{CodeObject, PyVersion};

use crate::common::empty_code;

fn frame(id: u32, kind: FrameKind, start: u32, end: u32) -> Frame {
    Frame::new(FrameId(id), kind, start..end)
}

#[test]
fn validator_accepts_well_formed_tree() {
    let version: PyVersion = PyVersion {
        major: 3,
        minor: 10,
    };
    let mut code: CodeObject = empty_code(version);
    code.code = vec![0u8; 32];

    let mut root: Frame = frame(0, FrameKind::Module, 0, 32);
    let mut inner: Frame = frame(1, FrameKind::Try, 4, 16);
    inner.children.push(frame(2, FrameKind::With, 6, 12));
    root.children.push(inner);
    root.children.push(frame(3, FrameKind::Try, 20, 28));

    let tree: FrameTree = FrameTree::new(root);
    assert!(validate(&tree, &code).is_ok());
}

#[test]
fn validator_rejects_sibling_overlap() {
    let version: PyVersion = PyVersion {
        major: 3,
        minor: 10,
    };
    let mut code: CodeObject = empty_code(version);
    code.code = vec![0u8; 16];

    let mut root: Frame = frame(0, FrameKind::Module, 0, 16);
    root.children.push(frame(1, FrameKind::Try, 0, 10));
    root.children.push(frame(2, FrameKind::Try, 6, 12));
    let tree: FrameTree = FrameTree::new(root);
    assert!(validate(&tree, &code).is_err());
}

#[test]
fn validator_rejects_child_escaping_parent() {
    let version: PyVersion = PyVersion {
        major: 3,
        minor: 10,
    };
    let mut code: CodeObject = empty_code(version);
    code.code = vec![0u8; 16];

    let mut root: Frame = frame(0, FrameKind::Module, 0, 16);
    let mut try_frame: Frame = frame(1, FrameKind::Try, 4, 12);
    try_frame.children.push(frame(2, FrameKind::With, 2, 8));
    root.children.push(try_frame);
    let tree: FrameTree = FrameTree::new(root);
    assert!(validate(&tree, &code).is_err());
}

#[test]
fn validator_rejects_root_not_covering_code() {
    let version: PyVersion = PyVersion {
        major: 3,
        minor: 10,
    };
    let mut code: CodeObject = empty_code(version);
    code.code = vec![0u8; 32];
    let root: Frame = frame(0, FrameKind::Module, 0, 16);
    let tree: FrameTree = FrameTree::new(root);
    assert!(validate(&tree, &code).is_err());
}
