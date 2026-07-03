#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_nir::NirModule;
use disrobe_nir_lift::lift_classfile;
use disrobe_query::{
    CallSiteMatch, DecoderMatch, Function, FunctionMatch, Module, Query, QueryResult, XrefMatch,
    run,
};

const STRINGER_CLASS: &[u8] = include_bytes!("../../../corpus/jvm/stringer/StringerClassic.class");

fn lifted() -> Module {
    let nir: NirModule = lift_classfile(STRINGER_CLASS).expect("lift classfile to NIR");
    Module::from_nir(&nir)
}

fn function_names(module: &Module) -> Vec<String> {
    match run(module, &Query::Functions) {
        QueryResult::Functions { matches } => {
            matches.into_iter().map(|m: FunctionMatch| m.name).collect()
        }
        other => panic!("expected Functions, got {other:?}"),
    }
}

fn decoders(module: &Module) -> Vec<DecoderMatch> {
    match run(module, &Query::StringDecoders) {
        QueryResult::StringDecoders { matches } => matches,
        other => panic!("expected StringDecoders, got {other:?}"),
    }
}

fn xrefs_to(module: &Module, symbol: &str) -> Vec<XrefMatch> {
    match run(
        module,
        &Query::XrefsTo {
            symbol: symbol.to_owned(),
        },
    ) {
        QueryResult::XrefsTo { matches, .. } => matches,
        other => panic!("expected XrefsTo, got {other:?}"),
    }
}

fn calls_to(module: &Module, target: &str) -> Vec<CallSiteMatch> {
    match run(
        module,
        &Query::CallsTo {
            target: target.to_owned(),
        },
    ) {
        QueryResult::CallsTo { matches, .. } => matches,
        other => panic!("expected CallsTo, got {other:?}"),
    }
}

#[test]
fn classfile_methods_are_recovered_as_functions() {
    let module: Module = lifted();
    let names: Vec<String> = function_names(&module);
    for expected in [
        "buildKey",
        "decrypt",
        "dbUrl",
        "authHeader",
        "vaultUrl",
        "role",
        "keyPath",
        "main",
    ] {
        assert!(
            names.iter().any(|n: &String| n == expected),
            "method {expected} must be lifted: {names:?}"
        );
    }

    let dburl: &Function = module.function_by_name("dbUrl").expect("dbUrl");
    assert!(dburl.is_export, "public dbUrl must be flagged exported");
    let decrypt: &Function = module.function_by_name("decrypt").expect("decrypt");
    assert!(
        !decrypt.is_export,
        "private decrypt must not be flagged exported"
    );
}

#[test]
fn decrypt_loop_is_detected_as_a_byte_decoder() {
    let module: Module = lifted();
    let found: Vec<DecoderMatch> = decoders(&module);
    let decrypt: &DecoderMatch = found
        .iter()
        .find(|d: &&DecoderMatch| d.name == "decrypt")
        .expect("decrypt must be a decoder");
    assert!(
        decrypt.loop_back_edges >= 1,
        "the for-loop goto is a back-edge: {decrypt:?}"
    );
    assert!(
        decrypt.byte_arith_ops >= 1,
        "the ixor over a loaded char must count as byte-arith: {decrypt:?}"
    );
    assert!(
        decrypt.memory_ops >= 1,
        "the caload/castore must count as memory ops: {decrypt:?}"
    );
}

#[test]
fn accessor_methods_call_the_internal_decrypt() {
    let module: Module = lifted();

    let xrefs: Vec<XrefMatch> = xrefs_to(&module, "decrypt");
    let callers: Vec<&str> = xrefs
        .iter()
        .filter_map(|x: &XrefMatch| x.from_function.as_deref())
        .collect();
    for accessor in ["dbUrl", "authHeader", "vaultUrl", "role", "keyPath"] {
        assert!(
            callers.contains(&accessor),
            "{accessor} must reference decrypt: callers={callers:?}"
        );
    }
    assert!(
        xrefs
            .iter()
            .all(|x: &XrefMatch| x.mnemonic == "invokestatic"),
        "intra-class calls to decrypt are invokestatic: {xrefs:?}"
    );

    let call_sites: Vec<CallSiteMatch> = calls_to(&module, "decrypt");
    assert_eq!(
        call_sites.len(),
        5,
        "exactly the five accessors call decrypt: {call_sites:?}"
    );
}

#[test]
fn lift_is_deterministic() {
    let first: Module = lifted();
    let second: Module = lifted();
    assert_eq!(function_names(&first), function_names(&second));
    assert_eq!(decoders(&first).len(), decoders(&second).len());
}
