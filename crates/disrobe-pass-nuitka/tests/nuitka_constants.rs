#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_pass_nuitka::{ConstantsPool, decode_const_file};

fn fixture(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/python/nuitka")
        .join(rel)
}

fn gt_strings_module() -> BTreeSet<String> {
    [
        "hello, ",
        "a",
        "greet",
        "disrobe",
        "fib",
        "origin",
        "has_location",
        "name",
        "return",
        "n",
        "main",
        "b",
        "_",
        "builtins",
        "str",
        "int",
        "__main__",
        "hello.py",
        "<module hello>",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn gt_strings_console() -> BTreeSet<String> {
    [
        "hello, ", "a", "greet", "disrobe", "fib", "name", "return", "n", "main", "b", "_",
        "builtins", "str", "int", "hello.py", "<module>",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn gt_ints() -> BTreeSet<i64> {
    [0i64, 1, 2, 20].into_iter().collect()
}

#[test]
fn module_const_recovers_superset_and_consumes_all_bytes() {
    let bytes: Vec<u8> = std::fs::read(fixture("module/hello.build/module.hello.const"))
        .expect("read module.hello.const");
    let pool: ConstantsPool = decode_const_file(&bytes, "module.hello.const", "hello")
        .expect("decode module.hello.const");
    assert_eq!(
        pool.bytes_consumed,
        bytes.len(),
        "must consume all 430 bytes (shared-memo)"
    );
    assert_eq!(pool.stream_count, 19);
    assert!(
        pool.strings.is_superset(&gt_strings_module()),
        "missing: {:?}",
        gt_strings_module()
            .difference(&pool.strings)
            .collect::<Vec<&String>>()
    );
    assert!(pool.ints.is_superset(&gt_ints()));
    assert!(
        pool.globals
            .contains(&("builtins".to_owned(), "str".to_owned()))
    );
    assert!(
        pool.globals
            .contains(&("builtins".to_owned(), "int".to_owned()))
    );
}

#[test]
fn console_disable_const_recovers_superset_and_consumes_all_bytes() {
    let bytes: Vec<u8> =
        std::fs::read(fixture("console-disable/hello.build/module.__main__.const"))
            .expect("read module.__main__.const");
    let pool: ConstantsPool = decode_const_file(&bytes, "module.__main__.const", "__main__")
        .expect("decode module.__main__.const");
    assert_eq!(
        pool.bytes_consumed,
        bytes.len(),
        "must consume all 353 bytes (shared-memo)"
    );
    assert_eq!(pool.stream_count, 16);
    assert!(
        pool.strings.is_superset(&gt_strings_console()),
        "missing: {:?}",
        gt_strings_console()
            .difference(&pool.strings)
            .collect::<Vec<&String>>()
    );
    assert!(pool.ints.is_superset(&gt_ints()));
}

#[test]
fn manifest_parses_both_fixtures() {
    use disrobe_pass_nuitka::parse_constant_manifest_from_file;
    let m: disrobe_pass_nuitka::ConstantManifest =
        parse_constant_manifest_from_file(&fixture("module/hello.build/blobs/__constant.txt"))
            .expect("parse manifest");
    assert_eq!(m.total, 122);
    assert_eq!(
        m.by_blob_name("hello").expect("hello entry").input_size,
        430
    );
    assert_eq!(m.by_blob_name("").expect("global entry").input_size, 2185);
    assert!(
        m.by_blob_name(".bytecode")
            .expect("bytecode entry")
            .is_bytecode()
    );
}

#[test]
fn exact_version_from_constants_c_is_4_1_1_release() {
    use disrobe_pass_nuitka::parse_exact_version_from_constants_c;
    let c: Vec<u8> =
        std::fs::read(fixture("module/hello.build/__constants.c")).expect("read __constants.c");
    let v: disrobe_pass_nuitka::ExactNuitkaVersion =
        parse_exact_version_from_constants_c(&c).expect("parse version");
    assert_eq!((v.major, v.minor, v.micro), (4, 1, 1));
    assert_eq!(v.release_level, "release");
}

#[test]
fn global_pool_const_supplies_runtime_identifiers_and_consumes_fully() {
    let bytes: Vec<u8> = std::fs::read(fixture("module/hello.build/__constants.const"))
        .expect("read __constants.const");
    let pool: ConstantsPool =
        decode_const_file(&bytes, "__constants.const", "").expect("decode __constants.const");
    assert_eq!(pool.bytes_consumed, bytes.len());
    assert_eq!(pool.bytes_consumed, 2185);
    assert!(pool.strings.contains("__module__"));
    assert!(pool.strings.contains("__compiled__"));
}

#[test]
fn decompile_build_dir_end_to_end() {
    use disrobe_pass_nuitka::{VersionConfidence, decompile_build_dir};
    let d: disrobe_pass_nuitka::NuitkaDecompilation =
        decompile_build_dir(&fixture("module/hello.build")).expect("decompile build dir");
    assert_eq!(d.version.confidence, VersionConfidence::Exact);
    assert_eq!(d.version.exact.as_ref().expect("exact").minor, 1);
    let pool: &ConstantsPool = d
        .constants
        .pools
        .get("module.hello.const")
        .expect("hello pool present");
    assert!(pool.strings.is_superset(&gt_strings_module()));
    assert!(d.constants.all_strings.contains("disrobe"));
    assert!(!d.constants.pools.contains_key("__bytecode.const"));
}
