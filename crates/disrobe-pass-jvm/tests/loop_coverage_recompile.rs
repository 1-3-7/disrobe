#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{DecompiledClass, decompile_classfile_bytes};

const LOOP_HEADER_PROBE: &str = include_str!("fixtures/loop_coverage/LoopHeaderProbe.java");
const LOOP_HEADER_DRIVER: &str = include_str!("fixtures/loop_coverage/LoopHeaderDriver.java");
const LOOP_HEADER_EXIT_PROBE: &str =
    include_str!("fixtures/loop_coverage/LoopHeaderExitProbe.java");
const SYNC_LOOP_PROBE: &str = include_str!("fixtures/loop_coverage/SyncLoopProbe.java");
const SYNC_LOOP_DRIVER: &str = include_str!("fixtures/loop_coverage/SyncLoopDriver.java");

struct Jdk {
    javac: PathBuf,
    java: PathBuf,
    javap: PathBuf,
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) { &["", ".exe"] } else { &[""] };
    for dir in std::env::split_paths(&path_var) {
        for ext in exts {
            let candidate: PathBuf = dir.join(format!("{name}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn jdk() -> Jdk {
    let find = |name: &str| -> PathBuf {
        find_on_path(name).unwrap_or_else(|| {
            panic!("the JDK is on PATH in every CI job that runs these tests: {name} not on PATH")
        })
    };
    Jdk {
        javac: find("javac"),
        java: find("java"),
        javap: find("javap"),
    }
}

fn compile(jdk: &Jdk, dir: &Path, sources: &[(&str, &str)]) {
    let mut cmd: Command = Command::new(&jdk.javac);
    cmd.arg("-nowarn").arg("-proc:none").arg("-d").arg(dir);
    for (name, source) in sources {
        let path: PathBuf = dir.join(name);
        std::fs::write(&path, source).expect("write source");
        cmd.arg(&path);
    }
    let out: Output = cmd.output().expect("javac");
    assert!(
        out.status.success(),
        "javac failed: {}\n{}",
        String::from_utf8_lossy(&out.stderr),
        sources
            .iter()
            .map(|(name, source)| format!("--- {name}\n{source}"))
            .collect::<Vec<String>>()
            .join("\n")
    );
}

fn run(jdk: &Jdk, dir: &Path, main_class: &str) -> String {
    let out: Output = Command::new(&jdk.java)
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

fn monitorenter_count(jdk: &Jdk, dir: &Path, class: &str) -> usize {
    let out: Output = Command::new(&jdk.javap)
        .arg("-c")
        .arg("-p")
        .arg("-cp")
        .arg(dir)
        .arg(class)
        .output()
        .expect("javap");
    assert!(out.status.success(), "javap {class} failed");
    String::from_utf8_lossy(&out.stdout)
        .matches("monitorenter")
        .count()
}

struct Recovery {
    original_output: String,
    recompiled_output: String,
    recompiled_dir: ScratchDir,
    decompiled: DecompiledClass,
}

fn method_body<'a>(source: &'a str, signature: &str) -> &'a str {
    let start: usize = source.find(signature).unwrap_or_else(|| {
        panic!(
            "{signature} missing from the recovered source:
{source}"
        )
    });
    let rest: &str = &source[start..];
    let end: usize = rest
        .find(
            "
    }",
        )
        .map_or(rest.len(), |end: usize| end);
    &rest[..end]
}

fn recover(jdk: &Jdk, tag: &str, probe: (&str, &str), driver: (&str, &str)) -> Recovery {
    let original: ScratchDir =
        ScratchDir::create(&format!("disrobe_jvm_{tag}_orig")).expect("scratch dir");
    compile(jdk, original.path(), &[probe, driver]);
    let class_name: &str = probe.0.trim_end_matches(".java");
    let driver_name: &str = driver.0.trim_end_matches(".java");
    let bytes: Vec<u8> =
        std::fs::read(original.path().join(format!("{class_name}.class"))).expect("read class");
    let decompiled: DecompiledClass = decompile_classfile_bytes(&bytes).expect("decompile");
    let recompiled_dir: ScratchDir =
        ScratchDir::create(&format!("disrobe_jvm_{tag}_dec")).expect("scratch dir");
    compile(
        jdk,
        recompiled_dir.path(),
        &[(probe.0, decompiled.source.as_str()), driver],
    );
    Recovery {
        original_output: run(jdk, original.path(), driver_name),
        recompiled_output: run(jdk, recompiled_dir.path(), driver_name),
        recompiled_dir,
        decompiled,
    }
}

#[test]
fn a_loop_header_branch_without_an_exit_renders_inside_the_body() {
    let jdk: Jdk = jdk();
    let recovered: Recovery = recover(
        &jdk,
        "loop_header",
        ("LoopHeaderProbe.java", LOOP_HEADER_PROBE),
        ("LoopHeaderDriver.java", LOOP_HEADER_DRIVER),
    );
    let source: &str = &recovered.decompiled.source;
    assert_eq!(
        recovered.original_output, "0,4,0,12,8,12,20,28,44,",
        "the authored program's own output changed"
    );
    assert_eq!(
        recovered.recompiled_output, recovered.original_output,
        "the recovered loops must keep the header's branch; recovered source:\n{source}"
    );
    assert_eq!(
        recovered.decompiled.fully_lifted_methods, recovered.decompiled.method_count,
        "every probe method renders each reachable block; recovered source:\n{source}"
    );
}

#[test]
fn a_loop_header_branch_the_structurer_cannot_place_is_reported_incomplete() {
    let jdk: Jdk = jdk();
    let scratch: ScratchDir =
        ScratchDir::create("disrobe_jvm_loop_header_exit").expect("scratch dir");
    compile(
        &jdk,
        scratch.path(),
        &[("LoopHeaderExitProbe.java", LOOP_HEADER_EXIT_PROBE)],
    );
    let bytes: Vec<u8> =
        std::fs::read(scratch.path().join("LoopHeaderExitProbe.class")).expect("read class");
    let decompiled: DecompiledClass = decompile_classfile_bytes(&bytes).expect("decompile");
    let source: &str = &decompiled.source;
    let body: &str = method_body(source, "public int spinSwitchExit(int arg0, boolean arg1)");
    assert!(
        body.contains("// <decompile: incomplete: a reachable block has no rendered statement>"),
        "a loop whose header switch breaks out to code the loop shares with its skip path loses switch arms, so the method must carry the coverage marker; recovered source:
{source}"
    );
    assert_eq!(
        decompiled.fully_lifted_methods + 1,
        decompiled.method_count,
        "only spinSwitchExit is incomplete; recovered source:
{source}"
    );
}

#[test]
fn a_synchronized_block_in_a_loop_keeps_its_lock() {
    let jdk: Jdk = jdk();
    let recovered: Recovery = recover(
        &jdk,
        "sync_loop",
        ("SyncLoopProbe.java", SYNC_LOOP_PROBE),
        ("SyncLoopDriver.java", SYNC_LOOP_DRIVER),
    );
    let source: &str = &recovered.decompiled.source;
    assert_eq!(
        recovered.original_output, "10,3",
        "the authored program's own output changed"
    );
    assert_eq!(
        recovered.recompiled_output, recovered.original_output,
        "each synchronized body must still run holding the lock; recovered source:\n{source}"
    );
    assert_eq!(
        monitorenter_count(&jdk, recovered.recompiled_dir.path(), "SyncLoopProbe"),
        2,
        "both synchronized blocks recompile to a real monitorenter; recovered source:\n{source}"
    );
    assert_eq!(
        recovered.decompiled.fully_lifted_methods, recovered.decompiled.method_count,
        "every probe method consumes its monitors; recovered source:\n{source}"
    );
}
