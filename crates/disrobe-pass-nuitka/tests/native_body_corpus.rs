#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::PathBuf;

use disrobe_pass_nuitka::{NativeBodyRecovery, NativeOp, lift_native_bodies, parse_constants};

fn corpus_standalone() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/python/nuitka/real/sample_app-standalone.exe")
}

#[test]
fn locates_and_traces_impls_on_real_corpus_binary() {
    let path: PathBuf = corpus_standalone();
    if !path.is_file() {
        eprintln!("skip: real nuitka corpus exe absent");
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&path).expect("read corpus exe");
    let constants = parse_constants(&bytes);
    let Some(recovery): Option<NativeBodyRecovery> = lift_native_bodies(&bytes, &constants) else {
        panic!("native body lift produced nothing on the real corpus binary");
    };

    assert!(
        recovery.located_impls > 0,
        "expected to locate at least one function impl via the constructor cross-reference"
    );
    assert_eq!(
        recovery.located_impls,
        recovery.functions.len(),
        "every located impl must yield a function record"
    );

    let with_trace: usize = recovery
        .functions
        .iter()
        .filter(|f| !f.ops.is_empty())
        .count();
    assert!(
        with_trace > 0,
        "expected at least one impl to carry a recovered native operation trace"
    );

    for function in &recovery.functions {
        let has_return: bool = function.ops.iter().any(|op| matches!(op, NativeOp::Return));
        assert!(
            function.instruction_count > 0,
            "impl {} at {:#x} decoded no instructions",
            function.name,
            function.impl_address
        );
        assert!(
            has_return || function.instruction_count >= 1,
            "impl {} carried no return in its trace",
            function.name
        );
        if !function.recovered_stmts.is_empty() {
            let sound: bool = function
                .recovered_stmts
                .iter()
                .all(|stmt| matches!(stmt, disrobe_pass_nuitka::PythonStmt::Return(_)));
            assert!(
                sound,
                "reconstructed body for {} must be a single recovered return, got {:?}",
                function.name, function.recovered_stmts
            );
        }
    }

    eprintln!(
        "CORPUS native body lift: located {} impl(s); {} with operation traces; bound {} to \
         code-object names; reconstructed {} executable body/bodies",
        recovery.located_impls, with_trace, recovery.bound_functions, recovery.reconstructed_bodies
    );
}
