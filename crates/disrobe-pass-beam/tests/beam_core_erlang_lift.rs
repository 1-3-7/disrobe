#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::missing_const_for_fn
)]

mod common;

use disrobe_pass_beam::{BeamFile, CoreModule, lift};

use crate::common::{
    build_atu8, build_beam, build_chunk, build_code_chunk, build_expt, build_impt,
    encode_compact_small,
};

fn build_export_import_beam() -> Vec<u8> {
    let atoms: Vec<u8> = build_atu8(&["calc", "add", "erlang", "+"]);
    let mut code: Vec<u8> = Vec::new();
    code.push(1u8);
    code.extend(encode_compact_small(0, 1));
    code.push(2u8);
    code.extend(encode_compact_small(2, 1));
    code.extend(encode_compact_small(2, 2));
    code.extend(encode_compact_small(0, 2));
    code.push(1u8);
    code.extend(encode_compact_small(0, 2));
    code.push(64u8);
    code.extend(encode_compact_small(3, 0));
    code.extend(encode_compact_small(3, 2));
    code.push(19u8);
    code.push(3u8);

    let chunks: Vec<Vec<u8>> = vec![
        build_chunk(b"AtU8", &atoms),
        build_chunk(b"Code", &build_code_chunk(2, 1, &code)),
        build_chunk(b"ExpT", &build_expt(&[(2u32, 2u32, 2u32)])),
        build_chunk(b"ImpT", &build_impt(&[(3u32, 4u32, 2u32)])),
    ];
    build_beam(&chunks)
}

#[test]
fn lifts_module_with_exports_and_imports() {
    let buf: Vec<u8> = build_export_import_beam();
    let beam: BeamFile = BeamFile::parse(&buf).expect("parse");
    let core: CoreModule = lift(&beam).expect("lift");
    assert_eq!(core.module, "calc");
    assert_eq!(core.exports.len(), 1);
    assert_eq!(core.exports[0], ("add".to_owned(), 2));
    assert_eq!(core.imports.len(), 1);
    assert_eq!(core.imports[0], ("erlang".to_owned(), "+".to_owned(), 2));
    assert_eq!(core.functions.len(), 1);
    let f = &core.functions[0];
    assert_eq!(f.name, "add");
    assert_eq!(f.arity, 2);
    assert!(f.exported);
}
