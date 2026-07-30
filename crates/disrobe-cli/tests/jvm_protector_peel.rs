#![cfg(feature = "jvm")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use common::{cli_binary, run_disrobe, temp_dir};

fn corpus(rel: &str) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push(rel);
    p
}

#[test]
fn cli_peels_static_table_class_and_substitutes_plaintext() {
    let class: PathBuf = corpus("corpus/jvm/zkmshape/StaticTableCrypt.class");
    assert!(
        class.exists(),
        "{} is tracked in git and this case grades nothing without it, so its \
         absence is a damaged checkout rather than an optional dependency",
        class.display()
    );
    assert!(
        cli_binary().exists(),
        "cargo builds the disrobe binary before this test binary runs, so a missing \
         {} would leave this case driving nothing",
        cli_binary().display()
    );

    let out_scratch: disrobe_core::scratch::ScratchDir = temp_dir("zkm-peel");

    let out: PathBuf = out_scratch.path().to_path_buf();
    let run: common::Run = run_disrobe(&[
        "jvm",
        "decompile",
        class.to_str().expect("utf8 path"),
        "--out",
        out.to_str().expect("utf8 out"),
        "--emit",
        "source",
    ]);
    assert_eq!(run.code, 0, "jvm decompile failed: {}", run.stderr);

    assert!(
        run.stdout.contains("peeled:") && run.stdout.contains("Zelix KlassMaster"),
        "the CLI must report which protector it peeled; stdout was:\n{}",
        run.stdout
    );

    let java: String =
        std::fs::read_to_string(out.join("StaticTableCrypt.java")).expect("emitted java");
    for want in [
        "jdbc:mysql://10.0.0.5:3306/billing",
        "X-Internal-Auth: 9f8e7d6c",
    ] {
        assert!(
            java.contains(want),
            "the recovered plaintext {want:?} must be substituted into the emitted .java; got:\n{java}"
        );
    }
    assert!(
        !java.contains("d9nx04qdw9"),
        "the encrypted ciphertext must not survive in the peeled source"
    );

    let report: String =
        std::fs::read_to_string(out.join("protector-peel.json")).expect("protector-peel.json");
    assert!(report.contains("ZelixKlassMaster") && report.contains("StubRecovered"));

    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn cli_dex_decompile_surfaces_recovered_dexguard_strings() {
    let dex: PathBuf = corpus("corpus/jvm/dexguard/DexGuardReflectStrings.dex");
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

    let out_scratch: disrobe_core::scratch::ScratchDir = temp_dir("dexguard-peel");

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
    assert_eq!(run.code, 0, "jvm dex decompile failed: {}", run.stderr);

    let java: String = std::fs::read_to_string(out.join("DexGuardReflectStrings.java"))
        .expect("emitted dalvik java");
    for want in [
        "https://api.example.com/v1/auth",
        "X-Api-Key",
        "com.disrobe.sample.Secret",
    ] {
        assert!(
            java.contains(want),
            "the reflection-invoked decrypt plaintext {want:?} must be surfaced in the dalvik \
             decompile; got:\n{java}"
        );
    }

    let _ = std::fs::remove_dir_all(&out);
}
