#![no_main]

use core::hint::black_box;

use libfuzzer_sys::fuzz_target;

use disrobe_fuzz::{over_input_budget, selector};
use disrobe_py_marshal::{
    CodeObject, Object, PyVersion, PycFile, RefTableDump, dump, dump_reftable, load,
    load_with_reftable, pyversion_from_magic, read_pyc, validate_roundtrip, write_pyc,
};

const REPRESENTATIVE_VERSIONS: [PyVersion; 6] = [
    PyVersion::PY10,
    PyVersion::PY27,
    PyVersion::PY36,
    PyVersion::PY311,
    PyVersion::PY314,
    PyVersion::PY315,
];

fn versions_for(data: &[u8]) -> Vec<PyVersion> {
    let mut versions: Vec<PyVersion> = Vec::with_capacity(REPRESENTATIVE_VERSIONS.len() + 1);
    if let Some(from_magic) = pyversion_from_magic(selector(data)) {
        versions.push(from_magic);
    }
    versions.extend_from_slice(&REPRESENTATIVE_VERSIONS);
    versions
}

fn drive_pyc_container(data: &[u8]) {
    let Ok(file): disrobe_py_marshal::Result<PycFile> = read_pyc(data) else {
        return;
    };
    let _ = black_box(write_pyc(&file));
    if let Object::Code(boxed) = &file.code {
        let code: &CodeObject = boxed.as_ref();
        let _ = black_box(code.names.len());
        let _ = black_box(code.consts.len());
    }
}

fn drive_marshal_stream(data: &[u8], version: PyVersion) {
    let Ok(object): disrobe_py_marshal::Result<Object> = load(data, version) else {
        return;
    };
    let _ = black_box(dump(&object, version));
    let _ = black_box(validate_roundtrip(&object, version));
}

fn drive_reftable(data: &[u8], version: PyVersion) {
    let Ok((object, table)): disrobe_py_marshal::Result<(Object, RefTableDump)> =
        dump_reftable(data, version)
    else {
        return;
    };
    let _ = black_box(&object);
    for entry in &table.entries {
        let Some(end): Option<usize> = entry.byte_offset.checked_add(entry.byte_length) else {
            panic!("a reference-table entry range overflows usize");
        };
        assert!(
            end <= data.len(),
            "a reference-table entry claims bytes past the end of the marshal stream"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    if over_input_budget(data) {
        return;
    }
    drive_pyc_container(data);
    for version in versions_for(data) {
        drive_marshal_stream(data, version);
        drive_reftable(data, version);
        let _ = black_box(load_with_reftable(data, version));
    }
});
