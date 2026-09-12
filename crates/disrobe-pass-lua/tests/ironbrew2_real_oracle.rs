#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

#[path = "support/lua_toolchain.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod lua_toolchain;

use std::fs;
use std::path::PathBuf;

use disrobe_pass_lua::ironbrew2_recover::recover_runnable;
use lua_toolchain::{LuaInterpreter, require_interpreter, run_lua};

fn corpus_dir() -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    let mut p: PathBuf = PathBuf::from(manifest_dir);
    p.push("..");
    p.push("..");
    p.push("corpus");
    p.push("lua");
    p.push("ironbrew2");
    p
}

fn load(rel: &str) -> String {
    let mut p: PathBuf = corpus_dir();
    for seg in rel.split('/') {
        p.push(seg);
    }
    fs::read_to_string(&p).unwrap_or_else(|_| panic!("missing fixture {rel}"))
}

fn oracle_mode(name: &str, mode: &str) {
    let graded: String = format!("the IronBrew2 execution differential for {name}.{mode}");
    let Some(interp): Option<LuaInterpreter> = require_interpreter(&graded) else {
        return;
    };
    let original_src: String = load(&format!("original/{name}.lua"));
    let obf_src: String = load(&format!("obfuscated/{name}.{mode}.lua"));

    let expected: String = run_lua(&interp, &format!("original/{name}.lua"), &original_src);
    assert!(
        !expected.trim().is_empty(),
        "original {name}.lua prints nothing, so comparing stdout would accept any recovered program"
    );

    let recovered: String = recover_runnable(&obf_src).expect("recover runnable");
    let actual: String = run_lua(&interp, &format!("{name}.{mode}.lua"), &recovered);

    assert_eq!(
        actual.trim_end(),
        expected.trim_end(),
        "{name}.{mode}: recovered output must match original\n--- recovered source ---\n{recovered}"
    );
    eprintln!("oracle {name}.{mode}: OK ({})", expected.trim_end());
}

fn oracle(name: &str) {
    oracle_mode(name, "min");
}

#[test]
fn real_peel_path_recovers_known_strings() {
    use disrobe_pass_lua::ironbrew2;
    use disrobe_pass_lua::obfuscator::DeobfOptions;

    let obf: String = load("obfuscated/hello.min.lua");
    let opts: DeobfOptions = DeobfOptions {
        i_have_authorization: true,
        strict: false,
    };
    let result = ironbrew2::peel(obf.as_bytes(), &opts).expect("peel real ironbrew2");
    assert!(
        result.fully_recovered,
        "hello.min must fully recover via the real run path; markers: {:?}",
        result.residual_markers
    );
    assert!(
        result
            .recovered_strings
            .iter()
            .any(|s: &String| s == "hello from ironbrew2 corpus"),
        "must recover the literal string constant from the real vm bytecode"
    );
    assert!(
        result
            .recovered_strings
            .iter()
            .any(|s: &String| s == "print")
    );
}

#[test]
fn real_peel_path_blocks_without_authorization() {
    use disrobe_pass_lua::ironbrew2;
    use disrobe_pass_lua::obfuscator::DeobfOptions;

    let obf: String = load("obfuscated/arith.min.lua");
    let err = ironbrew2::peel(obf.as_bytes(), &DeobfOptions::default()).unwrap_err();
    assert!(matches!(
        err,
        disrobe_pass_lua::Error::AuthorizationRequired("Ironbrew2")
    ));
}

#[test]
fn real_devirt_recovers_constants_and_opcode_table() {
    use disrobe_pass_lua::ironbrew2_recover::recover;

    let obf: String = load("obfuscated/arith.min.lua");
    let program = recover(&obf).expect("recover arith");
    assert!(program.stats.fully_recovered(), "arith.min fully recovers");
    assert_eq!(program.chunk.constants.len(), 3);
    assert_eq!(program.stats.xor_key, 144);
}

#[test]
fn oracle_hello() {
    oracle("hello");
}

#[test]
fn oracle_arith() {
    oracle("arith");
}

#[test]
fn oracle_control() {
    oracle("control");
}

#[test]
fn oracle_tables() {
    oracle("tables");
}

#[test]
fn oracle_edge() {
    oracle("edge");
}

#[test]
fn oracle_max_hello() {
    oracle_mode("hello", "max");
}

#[test]
fn oracle_max_arith() {
    oracle_mode("arith", "max");
}

#[test]
fn oracle_max_control() {
    oracle_mode("control", "max");
}

#[test]
fn oracle_max_tables() {
    oracle_mode("tables", "max");
}

#[test]
fn oracle_max_edge() {
    oracle_mode("edge", "max");
}
