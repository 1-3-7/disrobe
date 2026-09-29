#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::classfile::{ClassFile, parse};
use disrobe_pass_jvm::{DecompiledClass, decompile_class};
use sha2::{Digest, Sha256};

const AUTHORED: &str = include_str!("../fixtures/ecj_jsr/FinallyProbe.java");
const CLASS: &[u8] = include_bytes!("../fixtures/ecj_jsr/FinallyProbe.class");
const AUTHORED_SHA256: &str = "7905d8cc6afe11016751a231e12140bf4d930013fc41aaf14f114fa43b33b0e4";
const CLASS_SHA256: &str = "2dff71da4b8d549888ea8e3b717b74f7f3e6c3058d73fc3ee9e2102899f2e20a";
const DRIVER: &str = "public class PickDriver {\n    public static void main(String[] args) {\n        for (int k = 0; k < 6; k++) {\n            System.out.println(FinallyProbe.pick(k) + \" \" + FinallyProbe.log);\n        }\n    }\n}\n";
const OP_JSR: u8 = 0xA8;

fn tool(name: &str) -> PathBuf {
    let path_var: std::ffi::OsString = std::env::var_os("PATH").expect("PATH");
    let exts: &[&str] = if cfg!(windows) { &["", ".exe"] } else { &[""] };
    std::env::split_paths(&path_var)
        .flat_map(|dir: PathBuf| {
            exts.iter()
                .map(move |ext: &&str| dir.join(format!("{name}{ext}")))
        })
        .find(|candidate: &PathBuf| candidate.is_file())
        .unwrap_or_else(|| {
            panic!("the JDK is on PATH in every CI job that runs these tests: {name} not on PATH")
        })
}

fn javac(dir: &Path, sources: &[&Path]) {
    let out: Output = Command::new(tool("javac"))
        .arg("-nowarn")
        .arg("-proc:none")
        .arg("-cp")
        .arg(dir)
        .arg("-d")
        .arg(dir)
        .args(sources)
        .output()
        .expect("javac");
    assert!(
        out.status.success(),
        "javac failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn run(dir: &Path, main_class: &str) -> String {
    let out: Output = Command::new(tool("java"))
        .env_remove("FORCE_COLOR")
        .arg("-cp")
        .arg(dir)
        .arg(main_class)
        .output()
        .expect("java");
    assert!(
        out.status.success(),
        "running {main_class} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

fn pick_table(dir: &Path, probe: Option<&str>) -> String {
    if let Some(source) = probe {
        let path: PathBuf = dir.join("FinallyProbe.java");
        std::fs::write(&path, source).expect("write recovered source");
        javac(dir, &[&path]);
    } else {
        std::fs::write(dir.join("FinallyProbe.class"), CLASS).expect("write ecj class");
    }
    let driver: PathBuf = dir.join("PickDriver.java");
    std::fs::write(&driver, DRIVER).expect("write driver");
    javac(dir, &[&driver]);
    run(dir, "PickDriver")
}

#[test]
fn an_ecj_14_try_finally_with_jsr_recompiles_and_runs_like_the_original() {
    assert_eq!(
        format!("{:x}", Sha256::digest(AUTHORED.as_bytes())),
        AUTHORED_SHA256
    );
    assert_eq!(format!("{:x}", Sha256::digest(CLASS)), CLASS_SHA256);
    assert!(
        CLASS.contains(&OP_JSR),
        "the ecj 1.4 build must carry jsr subroutines"
    );
    let class: ClassFile = parse(CLASS).expect("the ecj class parses");
    let decompiled: DecompiledClass = decompile_class(&class);
    let source: &str = &decompiled.source;
    assert!(
        source.contains("static int guarded(")
            && (source.contains("not recovered")
                || !source.contains("UnsupportedOperationException")),
        "guarded must be recovered or carry a named refusal:\n{source}"
    );
    let original_dir: ScratchDir = ScratchDir::create("ecj_jsr_original").expect("scratch");
    let recovered_dir: ScratchDir = ScratchDir::create("ecj_jsr_recovered").expect("scratch");
    let original: String = pick_table(original_dir.path(), None);
    let recovered: String = pick_table(recovered_dir.path(), Some(source));
    assert_eq!(
        recovered, original,
        "pick inlines its finally subroutine; the recovered class must print the ecj build's table:\n{source}"
    );
}
