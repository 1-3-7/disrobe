#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::path::PathBuf;

use disrobe_pass_as3::abc::{self, ABC_MAJOR, ABC_MINOR, AbcFile, DisasmLine, MethodInfo, disasm};
use disrobe_pass_as3::lifter::{LiftedBody, Stmt, lift_body};
use disrobe_pass_as3::swf::{self, DoAbc, Swf, SwfCompression};

fn fixture_dir() -> PathBuf {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .expect("crates parent")
        .parent()
        .expect("workspace root")
        .join("corpus")
        .join("flash")
        .join("swf")
        .join("synthetic")
}

fn load(name: &str) -> Vec<u8> {
    let path: PathBuf = fixture_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "committed synthetic fixture {} must exist: {e}",
            path.display()
        )
    })
}

fn has_loop(stmts: &[Stmt]) -> bool {
    stmts.iter().any(|s: &Stmt| match s {
        Stmt::While { .. } | Stmt::For { .. } | Stmt::DoWhile { .. } => true,
        Stmt::IfBlock { body, .. } | Stmt::With { body, .. } => has_loop(body),
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => has_loop(then_body) || has_loop(else_body),
        _ => false,
    })
}

fn recover(bytes: &[u8], expected: SwfCompression) -> (Swf, AbcFile, LiftedBody) {
    let swf: Swf = swf::parse(bytes).expect("synthetic swf must parse");
    assert_eq!(swf.header.compression, expected);
    assert_eq!(swf.header.version, 13, "fixture pins SWF version 13");

    let attrs: disrobe_pass_as3::swf::FileAttributes = swf
        .file_attributes()
        .expect("FileAttributes tag must parse");
    assert!(
        attrs.action_script3,
        "FileAttributes must flag the SWF as ActionScript 3"
    );

    let symbols: Vec<disrobe_pass_as3::swf::SymbolClassEntry> = swf.symbol_classes();
    assert!(
        symbols.iter().any(|s| s.class_name == "Counter"),
        "SymbolClass must bind the Counter class: {symbols:?}"
    );

    let blobs: Vec<DoAbc> = swf.collect_do_abc();
    assert_eq!(blobs.len(), 1, "exactly one DoABC tag");
    let blob: &DoAbc = &blobs[0];
    assert_eq!(blob.name, "CounterScript");

    let abc: AbcFile = abc::parse(&blob.abc_bytes).expect("DoABC payload must parse as ABC");
    assert_eq!(abc.minor, ABC_MINOR);
    assert_eq!(abc.major, ABC_MAJOR);

    let body: &disrobe_pass_as3::abc::MethodBody = abc
        .method_bodies
        .iter()
        .max_by_key(|b| b.code.len())
        .expect("a non-trivial method body");
    let info: Option<&MethodInfo> = abc.methods.get(body.method as usize);
    let lifted: LiftedBody = lift_body(&abc, body, info).expect("lift the sumTo body");
    (swf, abc, lifted)
}

#[test]
fn synthetic_fws_swf_recovers_counter_class_and_while_loop() {
    let (_swf, abc, lifted): (Swf, AbcFile, LiftedBody) =
        recover(&load("synthetic_counter_fws.swf"), SwfCompression::None);

    let class_names: Vec<String> = abc.class_names();
    assert!(
        class_names.iter().any(|n| n == "Counter"),
        "ABC must define the Counter class: {class_names:?}"
    );

    assert!(
        lifted.dropped_opcodes.is_empty(),
        "every opcode in the synthetic body must be modelled: {:?}",
        lifted.dropped_opcodes
    );
    assert!(
        has_loop(&lifted.statements),
        "the counted loop must structure into a for/while, not raw branches: {:?}",
        lifted.statements
    );
    assert!(
        lifted.fully_recovered,
        "the synthetic sumTo body must lift with full fidelity: {:?}",
        lifted.fidelity_warning()
    );
}

#[test]
fn synthetic_cws_zlib_swf_decompresses_and_recovers_identically() {
    let (_swf, abc, lifted): (Swf, AbcFile, LiftedBody) =
        recover(&load("synthetic_counter_cws.swf"), SwfCompression::Zlib);

    assert!(abc.class_names().iter().any(|n| n == "Counter"));
    assert!(
        has_loop(&lifted.statements),
        "zlib-packed fixture must recover the same loop as the uncompressed one"
    );
    assert!(lifted.fully_recovered, "{:?}", lifted.fidelity_warning());
}

#[test]
fn synthetic_swf_disassembles_to_a_real_opcode_stream() {
    let bytes: Vec<u8> = load("synthetic_counter_fws.swf");
    let swf: Swf = swf::parse(&bytes).expect("parse");
    let blobs: Vec<DoAbc> = swf.collect_do_abc();
    let abc: AbcFile = abc::parse(&blobs[0].abc_bytes).expect("abc");
    let mut total_ops: usize = 0;
    let mut saw_back_branch: bool = false;
    for body in &abc.method_bodies {
        let lines: Vec<DisasmLine> = disasm(&body.code).expect("disasm");
        total_ops += lines.len();
        saw_back_branch |= lines.iter().any(|l: &DisasmLine| l.opcode == 0x0F);
    }
    assert!(total_ops >= 10, "real opcode stream, got {total_ops}");
    assert!(
        saw_back_branch,
        "the sumTo body must carry the iflt back-edge that drives the loop"
    );
}
