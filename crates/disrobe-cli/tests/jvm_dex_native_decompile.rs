#![cfg(feature = "jvm")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use common::{cli_binary, run_disrobe, temp_dir};

fn corpus_dex() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus/jvm/dex/EdgeCases.dex");
    p
}

fn gcd_body(java: &str) -> String {
    let start: usize = java
        .find("int gcd(")
        .expect("native EdgeCases.java must declare int gcd(");
    let rest: &str = &java[start..];
    let end: usize = rest.find("\n    }").map_or(rest.len(), |e| e + 6);
    rest[..end].to_string()
}

#[test]
fn native_dex_decompile_emits_real_method_bodies() {
    let dex: PathBuf = corpus_dex();
    assert!(
        dex.exists(),
        "{} is tracked in git and this case grades nothing without it, so its \
         absence is a damaged checkout rather than an optional dependency",
        dex.display()
    );
    assert!(
        cli_binary().exists(),
        "cargo builds the disrobe binary before this test binary runs, so a missing \
         {} would leave this case driving nothing",
        cli_binary().display()
    );

    let out_scratch: disrobe_core::scratch::ScratchDir = temp_dir("edgecases-dex-native");

    let out: PathBuf = out_scratch.path().to_path_buf();
    let run: common::Run = run_disrobe(&[
        "jvm",
        "decompile",
        dex.to_str().expect("utf8 path"),
        "--out",
        out.to_str().expect("utf8 out"),
        "--emit",
        "source",
    ]);
    assert_eq!(run.code, 0, "native dex decompile failed: {}", run.stderr);

    let java_path: PathBuf = out.join("EdgeCases.java");
    let java: String = std::fs::read_to_string(&java_path)
        .unwrap_or_else(|e| panic!("cannot read emitted java {java_path:?}: {e}"));

    let body: String = gcd_body(&java);
    assert!(body.contains('%'), "recovered gcd must contain `%`: {body}");
    assert!(
        body.contains("while"),
        "recovered gcd must contain a loop: {body}"
    );
    assert!(
        body.contains("Math.abs"),
        "recovered gcd must call Math.abs: {body}"
    );

    assert!(
        java.contains("long iterativeFactorial(") && java.contains("boolean isPalindrome("),
        "native java must recover multiple leaf method signatures"
    );

    let manifest: String =
        std::fs::read_to_string(out.join("manifest.json")).expect("manifest.json must exist");
    assert!(
        manifest.contains("disrobe-dalvik"),
        "manifest must record the in-house native decompiler as the default path"
    );

    let _ = std::fs::remove_dir_all(&out);
}
