#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_py_decompile::ast::{AstBuilder, AstModule, DefaultAstBuilder};
use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::codegen::{CodeEmitter, DefaultEmitter};
use disrobe_pass_py_decompile::frame_tree::{FrameTree, builder_for};
use disrobe_py_marshal::{CodeObject, Object, PyVersion as MarshalVersion, PycFile, read_pyc};

const TINY_3_14_PYC: &[u8] = include_bytes!(
    "../../../corpus/python/decompile/playground/__pycache__/tiny_3_14.cpython-314.pyc"
);

fn decompile_to_source(bytes: &[u8]) -> String {
    let pyc: PycFile = read_pyc(bytes).expect("read_pyc");
    let code: CodeObject = match pyc.code {
        Object::Code(b) => *b,
        _ => panic!("not code"),
    };
    let mv: MarshalVersion = pyc.header.version;
    let dv: PyVersion = match (mv.major, mv.minor) {
        (3, 14) => PyVersion::V3_14,
        _ => panic!("unexpected"),
    };
    let tree: FrameTree = builder_for(mv).build(&code, mv).expect("frame_tree");
    let module: AstModule = DefaultAstBuilder::new()
        .build_module(&code, &tree, &dv)
        .expect("ast");
    DefaultEmitter::new().emit_module(&module, &dv)
}

#[test]
fn tiny_3_14_recovers_literal_int() {
    let src: String = decompile_to_source(TINY_3_14_PYC);
    println!("--- tiny_3_14 emit ---\n{src}\n--- end ---");
    assert!(src.contains("x = 1"), "expected `x = 1`, got:\n{src}");
    assert!(
        src.contains("x + 2") || src.contains("(x + 2)"),
        "expected `x + 2`, got:\n{src}"
    );
    assert!(
        !src.contains("None + x"),
        "regression: `None + x` should never appear:\n{src}"
    );
}
