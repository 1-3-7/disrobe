#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::items_after_statements
)]

mod common;

use disrobe_pass_py_decompile::bytecode::flow::{ExceptionTableEntry, parse_exception_table};
use disrobe_pass_py_decompile::frame_tree::{
    FrameKind, FrameTree, FrameTreeBuilder, Post311Builder,
};
use disrobe_py_marshal::{CodeObject, PyVersion};

use crate::common::{empty_code, encode_exc_entry};

const PUSH_EXC_INFO: u8 = 35;
const RESUME: u8 = 151;
const RETURN_VALUE_311: u8 = 83;

fn make_311_code_with_one_try() -> CodeObject {
    let version: PyVersion = PyVersion {
        major: 3,
        minor: 11,
    };
    let mut code: CodeObject = empty_code(version);
    let mut bytecode: Vec<u8> = Vec::new();
    for _ in 0..6 {
        bytecode.extend_from_slice(&[RESUME, 0x00]);
    }
    bytecode[10] = PUSH_EXC_INFO;
    bytecode.extend_from_slice(&[RETURN_VALUE_311, 0x00]);
    code.code = bytecode;
    let entry: Vec<u8> = encode_exc_entry(0, 5, 5, 0, false);
    code.exceptiontable = entry;
    code
}

#[test]
fn py311_single_try_frame() {
    let version: PyVersion = PyVersion {
        major: 3,
        minor: 11,
    };
    let code: CodeObject = make_311_code_with_one_try();
    let builder: Post311Builder = Post311Builder::new();
    let tree: FrameTree = builder.build(&code, version).expect("build");
    assert_eq!(tree.root.kind, FrameKind::Module);
    assert_eq!(tree.root.children.len(), 1);
    assert_eq!(tree.root.children[0].kind, FrameKind::Try);
}

#[test]
fn py311_varint_decoder_round_trip() {
    let bytes: Vec<u8> = encode_exc_entry(64, 128, 1024, 3, true);
    let parsed: Vec<ExceptionTableEntry> = parse_exception_table(&bytes).expect("decode");
    assert_eq!(parsed.len(), 1);
    let e: ExceptionTableEntry = parsed[0];
    assert_eq!(e.start, 128);
    assert_eq!(e.length, 256);
    assert_eq!(e.target, 2048);
    assert_eq!(e.depth, 3);
    assert!(e.lasti);
}

#[test]
fn py311_multiple_disjoint_entries() {
    let mut bytes: Vec<u8> = encode_exc_entry(0, 4, 8, 0, false);
    bytes.extend(encode_exc_entry(16, 4, 24, 0, false));
    let parsed: Vec<ExceptionTableEntry> = parse_exception_table(&bytes).expect("decode");
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].start, 0);
    assert_eq!(parsed[1].start, 32);
}

#[test]
fn py312_py313_py314_use_post311_builder() {
    for minor in [12u8, 13u8, 14u8] {
        let version: PyVersion = PyVersion { major: 3, minor };
        let mut code: CodeObject = empty_code(version);
        let mut bytecode: Vec<u8> = vec![RESUME, 0x00];
        for _ in 0..7 {
            bytecode.extend_from_slice(&[RESUME, 0x00]);
        }
        code.code = bytecode;
        code.exceptiontable = encode_exc_entry(0, 3, 6, 0, false);
        let builder: Post311Builder = Post311Builder::new();
        let tree: FrameTree = builder.build(&code, version).expect("build");
        assert!(
            !tree.root.children.is_empty(),
            "{minor} should produce frames"
        );
    }
}
