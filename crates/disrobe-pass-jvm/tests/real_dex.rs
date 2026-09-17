#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use disrobe_pass_jvm::{
    BackendPreference, DEX_ENDIAN_TAG, DexHeader, DexVersion, android_decompile_dex,
    parse_dex_header,
};

const HELLO_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/Hello.dex");
const EDGECASES_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCases.dex");
const EDGECASES_KT_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCasesKt.dex");
static NEXT_JAVAC_DIR: AtomicUsize = AtomicUsize::new(0);

fn javac() -> PathBuf {
    let path_var = std::env::var_os("PATH").expect("PATH for javac");
    for directory in std::env::split_paths(&path_var) {
        let candidate = directory.join(if cfg!(windows) { "javac.exe" } else { "javac" });
        if candidate.is_file() {
            return candidate;
        }
    }
    panic!("javac (JDK) has to be on PATH")
}

fn assert_javac_compiles(name: &str, source: &str) {
    let unique = NEXT_JAVAC_DIR.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "disrobe-real-dex-{name}-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("create javac directory");
    let source_path = directory.join("EdgeCases.java");
    fs::write(&source_path, source).expect("write recovered Java");
    let output = Command::new(javac())
        .current_dir(&directory)
        .arg("-Xlint:none")
        .arg(&source_path)
        .output()
        .expect("run javac");
    let _ = fs::remove_dir_all(&directory);
    assert!(
        output.status.success(),
        "javac must compile the recovered source:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn contains_in_order(source: &str, snippets: &[&str]) -> bool {
    let mut offset = 0;
    for snippet in snippets {
        let Some(found) = source[offset..].find(snippet) else {
            return false;
        };
        offset += found + snippet.len();
    }
    true
}

#[test]
fn parses_real_hello_dex_from_d8() {
    assert_eq!(&HELLO_DEX[..4], b"dex\n");
    assert_eq!(&HELLO_DEX[4..7], b"035");
    let h: DexHeader = parse_dex_header(HELLO_DEX).expect("parse hello.dex");
    assert!(matches!(h.version, DexVersion::V035));
    let endian: u32 =
        u32::from_le_bytes([HELLO_DEX[40], HELLO_DEX[41], HELLO_DEX[42], HELLO_DEX[43]]);
    assert_eq!(endian, DEX_ENDIAN_TAG);
}

#[test]
fn parses_real_edgecases_dex_from_d8() {
    assert_eq!(&EDGECASES_DEX[..4], b"dex\n");
    assert_eq!(&EDGECASES_DEX[4..7], b"035");
    let h: DexHeader = parse_dex_header(EDGECASES_DEX).expect("parse edgecases.dex");
    assert!(matches!(h.version, DexVersion::V035));
    assert!(
        EDGECASES_DEX.len() > 10_000,
        "expected non-trivial dex size"
    );
}

#[test]
fn parses_real_kotlin_dex_v039_for_min_api_33() {
    assert_eq!(&EDGECASES_KT_DEX[..4], b"dex\n");
    assert_eq!(&EDGECASES_KT_DEX[4..7], b"039");
    let h: DexHeader = parse_dex_header(EDGECASES_KT_DEX).expect("parse kotlin dex");
    assert!(matches!(h.version, DexVersion::V039));
    assert!(
        EDGECASES_KT_DEX.len() > 50_000,
        "expected substantial kotlin dex"
    );
}

#[test]
fn edgecases_dex_preserves_static_long_and_reference_local_lifetimes() {
    let output = android_decompile_dex(EDGECASES_DEX, BackendPreference::PreferInHouse)
        .expect("decompile EdgeCases.dex");
    let source = output
        .sources
        .get("EdgeCases.java")
        .expect("EdgeCases source");
    let static_block = source
        .split_once("    static {\n")
        .and_then(|(_, tail)| tail.split_once("    public EdgeCases()"))
        .map(|(body, _)| body)
        .expect("static initializer");
    assert!(
        contains_in_order(
            static_block,
            &[
                "long var2;",
                "String var6;",
                "var2 = System.nanoTime();",
                "new java.util.concurrent.atomic.AtomicLong(var2)",
                "var6 = \"anon\";",
                "new java.util.concurrent.atomic.AtomicReference(var6)",
            ]
        ),
        "the static initializer must retain distinct writable long and reference locals:\n{static_block}"
    );
    assert_javac_compiles(
        "static-lifetimes",
        &format!(
            "import java.util.concurrent.atomic.*;\npublic final class EdgeCases {{\n    static AtomicInteger CTR;\n    static AtomicLong NANOS;\n    static AtomicReference NAME;\n    static {{\n{static_block}    final int finalField;\n    public EdgeCases(int arg0) {{ this.finalField = arg0; }}\n}}\n"
        ),
    );
}

#[test]
fn edgecases_dex_preserves_constructor_primitive_and_reference_local_lifetimes() {
    let output = android_decompile_dex(EDGECASES_DEX, BackendPreference::PreferInHouse)
        .expect("decompile EdgeCases.dex");
    let source = output
        .sources
        .get("EdgeCases.java")
        .expect("EdgeCases source");
    let constructor = source
        .split_once("    public EdgeCases(int arg0) {\n")
        .and_then(|(_, tail)| tail.split_once("    public static double accumulate"))
        .map(|(body, _)| body)
        .expect("int constructor");
    assert!(
        contains_in_order(
            constructor,
            &[
                "int var2;",
                "long var5;",
                "String var7;",
                "var2 = 7;",
                "this.instanceField = var2;",
                "var5 = 0L;",
                "this.volatileField = var5;",
                "var7 = \"skip-me\";",
                "this.transientField = var7;",
            ]
        ) && !constructor.contains("Object var2;"),
        "the constructor must retain distinct writable primitive and reference locals:\n{constructor}"
    );
    assert_javac_compiles(
        "constructor-lifetimes",
        &format!(
            "public final class EdgeCases {{\n    int instanceField;\n    volatile long volatileField;\n    transient String transientField;\n    final int finalField;\n    static void bumpStatic() {{}}\n    public EdgeCases(int arg0) {{\n{constructor}}}\n"
        ),
    );
}
