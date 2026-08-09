use disrobe_py_marshal::{Object, PycFile, read_pyc};

const REAL_PYC: &[u8] =
    include_bytes!("../../../corpus/python/freezers/pyc_zipper/original.pyc.bin");

#[test]
fn normal_consumer_reads_pyc_without_semantic_capture()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let parsed: PycFile = read_pyc(REAL_PYC)?;
    assert!(matches!(parsed.code, Object::Code(_)));
    Ok(())
}
