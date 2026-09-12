#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::case_sensitive_file_extension_comparisons
)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_jvm::{
    ClassFile, DecompiledClass, contains_jsr, decompile_class, disassemble, inline_jsr_subroutines,
    parse_classfile,
};

const JSR_FINALLY: &[u8] = include_bytes!("../../../corpus/jvm/antidecompiler/JsrFinally.class");
const BAD_FRAMES: &[u8] = include_bytes!("../../../corpus/jvm/antidecompiler/BadFrames.class");

const JSR_EXPECTED_STDOUT: &str = "a=14\nb=40\nsum=54\n";
const BAD_FRAMES_EXPECTED_STDOUT: &str = "lo=100\nhi=200\n";

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) {
        &["", ".exe", ".bat"]
    } else {
        &[""]
    };
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

fn method_body(source: &str, signature_fragment: &str) -> String {
    let start: usize = source
        .find(signature_fragment)
        .unwrap_or_else(|| panic!("method {signature_fragment} not in:\n{source}"));
    let bytes: &[u8] = &source.as_bytes()[start..];
    let open: usize = source[start..].find('{').expect("method opening brace") + 1;
    let mut depth: i32 = 1;
    let mut i: usize = open;
    while i < bytes.len() && depth > 0 {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => depth -= 1,
            _ => {}
        }
        i += 1;
    }
    source[start + open..start + i - 1].to_string()
}

fn recompile_and_run(simple_name: &str, source: &str, sub_dir: &str) -> Option<String> {
    let javac: PathBuf = find_on_path("javac")?;
    let java: PathBuf = find_on_path("java")?;
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(sub_dir).expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    let src_path: PathBuf = dir.join(format!("{simple_name}.java"));
    std::fs::write(&src_path, source).expect("write java");
    let compile: std::process::Output = Command::new(&javac)
        .arg("-nowarn")
        .arg("-proc:none")
        .arg("-d")
        .arg(&dir)
        .arg(&src_path)
        .output()
        .expect("javac");
    assert!(
        compile.status.success(),
        "recovered {simple_name} did not recompile under real javac:\n{}\n--- source ---\n{source}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let run: std::process::Output = Command::new(&java)
        .arg("-cp")
        .arg(&dir)
        .arg(simple_name)
        .output()
        .expect("java");
    assert!(
        run.status.success(),
        "recovered {simple_name} did not run under the real JVM:\n{}",
        String::from_utf8_lossy(&run.stderr)
    );
    Some(String::from_utf8_lossy(&run.stdout).replace("\r\n", "\n"))
}

#[test]
fn jsr_subroutine_linearises_to_a_monotonic_jsr_free_stream() {
    let twice_code: &[u8] = &[
        0xa8, 0x00, 0x08, 0x1b, 0xac, 0x00, 0x00, 0x00, 0x3a, 0x02, 0x1a, 0x1a, 0x60, 0x3c, 0xa9,
        0x02,
    ];
    let raw: Vec<disrobe_pass_jvm::Instruction> = disassemble(twice_code).expect("disasm");
    assert!(
        contains_jsr(&raw),
        "the planted twice() body must carry a jsr/ret subroutine"
    );
    let (inlined, report): (Vec<disrobe_pass_jvm::Instruction>, _) = inline_jsr_subroutines(&raw);
    assert!(
        !report.bailed,
        "inliner must not bail on a single subroutine: {report:?}"
    );
    assert!(
        inlined
            .iter()
            .all(|i: &disrobe_pass_jvm::Instruction| i.opcode != 0xa8
                && i.opcode != 0xc9
                && i.opcode != 0xa9),
        "the linearised stream must be free of jsr/jsr_w/ret: {inlined:?}"
    );
    for w in inlined.windows(2) {
        assert!(
            w[0].pc < w[1].pc,
            "the structurer requires a pc-monotonic stream after inlining: {inlined:?}"
        );
    }
    let pcs: BTreeSet<u32> = inlined
        .iter()
        .map(|i: &disrobe_pass_jvm::Instruction| i.pc)
        .collect();
    for i in &inlined {
        if let disrobe_pass_jvm::Operands::Branch(off) = i.operands {
            let target: u32 =
                u32::try_from(i64::from(i.pc) + i64::from(off)).expect("branch target in range");
            assert!(
                pcs.contains(&target),
                "every recomputed branch must land on a real instruction pc: {inlined:?}"
            );
        }
    }
}

#[test]
fn jsr_finally_class_recovers_the_subroutine_body() {
    let cf: ClassFile = parse_classfile(JSR_FINALLY).expect("parse JsrFinally");
    let d: DecompiledClass = decompile_class(&cf);
    assert_eq!(
        d.fallback_methods, 0,
        "no method may fall back:\n{}",
        d.source
    );
    assert_eq!(
        d.fully_lifted_methods, d.method_count,
        "every method must fully lift"
    );
    let twice: String = method_body(&d.source, "int twice(");
    assert!(
        twice.contains("arg0 + arg0"),
        "the jsr/ret subroutine that computes x+x must be inlined, not dropped: {twice}"
    );
    assert!(
        twice.contains("return"),
        "the recovered twice() must return its computed value: {twice}"
    );
}

#[test]
fn bad_frames_class_recovers_despite_inconsistent_stackmaptable() {
    let cf: ClassFile = parse_classfile(BAD_FRAMES).expect("parse BadFrames");
    let d: DecompiledClass = decompile_class(&cf);
    assert_eq!(
        d.fallback_methods, 0,
        "no method may fall back:\n{}",
        d.source
    );
    assert!(
        d.source
            .contains("StackMapTable inconsistent with control flow"),
        "disrobe must flag that the planted StackMapTable disagrees with the recomputed CFG:\n{}",
        d.source
    );
    let pick: String = method_body(&d.source, "int pick(");
    assert!(
        pick.contains("arg0 < 10"),
        "the branch must structure into a real if despite the poisoned frames: {pick}"
    );
    assert!(
        pick.contains("100") && pick.contains("200"),
        "both branch arms must be recovered: {pick}"
    );
}

#[test]
fn recovered_jsr_finally_recompiles_and_reruns_matching_the_oracle() {
    let cf: ClassFile = parse_classfile(JSR_FINALLY).expect("parse JsrFinally");
    let d: DecompiledClass = decompile_class(&cf);
    let Some(stdout): Option<String> =
        recompile_and_run("JsrFinally", &d.source, "disrobe_anti_jsr")
    else {
        eprintln!("SKIP: javac/java not on PATH; real-JVM oracle not enforced on this machine");
        return;
    };
    assert_eq!(
        stdout, JSR_EXPECTED_STDOUT,
        "recovered JsrFinally must reproduce the clean program's stdout under the real JVM"
    );
}

#[test]
fn recovered_bad_frames_recompiles_and_reruns_matching_the_oracle() {
    let cf: ClassFile = parse_classfile(BAD_FRAMES).expect("parse BadFrames");
    let d: DecompiledClass = decompile_class(&cf);
    let Some(stdout): Option<String> =
        recompile_and_run("BadFrames", &d.source, "disrobe_anti_frames")
    else {
        eprintln!("SKIP: javac/java not on PATH; real-JVM oracle not enforced on this machine");
        return;
    };
    assert_eq!(
        stdout, BAD_FRAMES_EXPECTED_STDOUT,
        "recovered BadFrames must reproduce the clean program's stdout under the real JVM"
    );
}
