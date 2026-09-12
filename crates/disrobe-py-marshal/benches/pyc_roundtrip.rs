#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_py_marshal::{CodeObject, Object, PyVersion, PycFile, PycHeader, read_pyc, write_pyc};

fn main() {
    divan::main();
}

fn synth_pyc() -> Vec<u8> {
    let co: CodeObject = CodeObject {
        era: disrobe_py_marshal::CodeEra::Py311Plus,
        argcount: 0,
        posonlyargcount: 0,
        kwonlyargcount: 0,
        nlocals: 0,
        stacksize: 1,
        flags: 0,
        code: vec![0x97, 0x00, 0x65, 0x00, 0x53, 0x00],
        consts: vec![Object::None],
        names: vec![],
        varnames: vec![],
        freevars: vec![],
        cellvars: vec![],
        localsplusnames: vec![],
        localspluskinds: vec![],
        filename: Object::ShortAscii {
            value: "synth.py".to_owned(),
            interned: false,
        },
        name: Object::ShortAscii {
            value: "<module>".to_owned(),
            interned: true,
        },
        qualname: Object::ShortAscii {
            value: "<module>".to_owned(),
            interned: true,
        },
        firstlineno: 1,
        lnotab: vec![],
        linetable: vec![],
        exceptiontable: vec![],
        pyarmor_trailer: vec![],
    };
    let header: PycHeader = PycHeader::deterministic(PyVersion::new(3, 12)).expect("header");
    let file: PycFile = PycFile {
        header,
        code: Object::Code(Box::new(co)),
    };
    write_pyc(&file).expect("write")
}

#[divan::bench]
fn write_pyc_small(bencher: divan::Bencher) {
    bencher.bench_local(|| {
        divan::black_box(synth_pyc());
    });
}

#[divan::bench]
fn read_then_write_pyc(bencher: divan::Bencher) {
    let bytes: Vec<u8> = synth_pyc();
    bencher.bench_local(|| {
        let file: PycFile = read_pyc(divan::black_box(&bytes)).expect("read");
        let bytes2: Vec<u8> = write_pyc(&file).expect("write");
        divan::black_box(bytes2);
    });
}
