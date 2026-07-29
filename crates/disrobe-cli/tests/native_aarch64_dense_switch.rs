#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use object::{Object as _, ObjectSection as _};
use tempfile::TempDir;

const DENSE_SWITCH_C: &str = r"
unsigned dense_switch(unsigned selector, unsigned a, unsigned b) {
    switch (selector) {
        case 0: return a + b;
        case 1: return a - b;
        case 2: return b - a;
        case 3: return a * b;
        case 4: return a ^ b;
        case 5: return a | b;
        case 6: return a & b;
        case 7: return a * a;
        case 8: return b * b;
        case 9: return a * b + a;
        case 10: return a * b + b;
        case 11: return (a ^ b) + a;
        case 12: return (a | b) + b;
        case 13: return (a & b) + a;
        case 14: return a + b + 1U;
        case 15: return a - b + 1U;
        default: return 99U;
    }
}

unsigned plain_add(unsigned a, unsigned b) { return a + b; }
";

const DENSE_SWITCH_CASES: [i64; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const CASE_BODIES: [(i64, &[&str]); 16] = [
    (0, &["r_a64_x2", "+ (r_a64_x1)"]),
    (1, &["r_a64_x1", "- (r_a64_x2)"]),
    (2, &["r_a64_x2", "- (r_a64_x1)"]),
    (3, &["r_a64_x2", "* (r_a64_x1)"]),
    (4, &["r_a64_x2", "^ (r_a64_x1)"]),
    (5, &["r_a64_x2", "| (r_a64_x1)"]),
    (6, &["r_a64_x2", "& (r_a64_x1)"]),
    (7, &["r_a64_x1", "* (r_a64_x1)"]),
    (8, &["r_a64_x2", "* (r_a64_x2)"]),
    (9, &["* (r_a64_x2)", "+ (r_a64_tmp)"]),
    (10, &["* (r_a64_x1)", "+ (r_a64_tmp)"]),
    (11, &["^ (r_a64_x1)", "+ (r_a64_x1)"]),
    (12, &["| (r_a64_x1)", "+ (r_a64_x2)"]),
    (13, &["& (r_a64_x1)", "+ (r_a64_x1)"]),
    (14, &["+ (r_a64_x2)", "(uint64_t)(int64_t)1LL"]),
    (15, &["- (r_a64_x2)", "(uint64_t)(int64_t)1LL"]),
];

fn tool_path(clang: &str, tool: &str) -> Option<PathBuf> {
    let output: Output = Command::new(clang)
        .arg(format!("--print-prog-name={tool}"))
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let printed: String = String::from_utf8(output.stdout).ok()?;
    let candidate: PathBuf = PathBuf::from(printed.trim());
    if candidate.is_file() {
        return Some(candidate);
    }
    let with_exe: PathBuf = PathBuf::from(format!("{}.exe", candidate.display()));
    with_exe.is_file().then_some(with_exe)
}

fn aarch64_toolchain() -> Option<(String, PathBuf)> {
    let clang: String = "clang".to_owned();
    let linker: PathBuf = tool_path(&clang, "ld.lld")?;
    Some((clang, linker))
}

fn build_aarch64_image(
    directory: &Path,
    clang: &str,
    linker: &Path,
    stripped: bool,
) -> Option<PathBuf> {
    let source_path: PathBuf = directory.join("dense.c");
    let object_path: PathBuf = directory.join("dense.o");
    let image_path: PathBuf = directory.join("dense.so");
    std::fs::write(&source_path, DENSE_SWITCH_C).expect("fixture source must be writable");
    let compiled: Output = Command::new(clang)
        .arg("--target=aarch64-unknown-linux-gnu")
        .arg("-O2")
        .arg("-ffreestanding")
        .arg("-fno-stack-protector")
        .arg("-ffunction-sections")
        .arg("-c")
        .arg(&source_path)
        .arg("-o")
        .arg(&object_path)
        .output()
        .ok()?;
    if !compiled.status.success() {
        return None;
    }
    let mut link: Command = Command::new(linker);
    link.arg("-shared");
    if stripped {
        link.arg("-s");
    }
    let linked: Output = link
        .arg(&object_path)
        .arg("-o")
        .arg(&image_path)
        .output()
        .ok()?;
    linked.status.success().then_some(image_path)
}

fn rodata_file_range(image: &[u8]) -> (usize, usize) {
    let file: object::File<'_> = object::File::parse(image).expect("fixture must parse");
    let section: object::Section<'_, '_> = file
        .section_by_name(".rodata")
        .expect("fixture must carry a .rodata jump table");
    let (offset, size): (u64, u64) = section
        .file_range()
        .expect("the jump table must be backed by file bytes");
    let start: usize = usize::try_from(offset).expect("file offset fits in usize");
    let length: usize = usize::try_from(size).expect("table length fits in usize");
    (start, length)
}

fn decompiled_source(image: &Path, out_dir: &Path) -> String {
    let run: common::Run = common::run_disrobe(&[
        "native",
        "decompile",
        &image.display().to_string(),
        "--backend",
        "native",
        "--format",
        "c",
        "--out",
        &out_dir.display().to_string(),
    ]);
    assert_eq!(
        run.code, 0,
        "stdout:\n{}\nstderr:\n{}",
        run.stdout, run.stderr
    );
    std::fs::read_to_string(out_dir.join("dense.c")).expect("emitted source must be readable")
}

fn dense_switch_body(source: &str) -> &str {
    let start: usize = source
        .find("/* dense_switch @")
        .expect("dense_switch must be emitted");
    let rest: &str = &source[start..];
    rest[1..]
        .find("/* ")
        .map_or(rest, |next: usize| &rest[..=next])
}

#[test]
fn cli_recovers_every_dense_switch_case_from_the_object() {
    let Some((clang, linker)): Option<(String, PathBuf)> = aarch64_toolchain() else {
        eprintln!("SKIP aarch64 dense switch: no clang with ld.lld on PATH");
        return;
    };
    let directory: TempDir = tempfile::tempdir().expect("temporary directory must be available");
    let Some(image): Option<PathBuf> =
        build_aarch64_image(directory.path(), &clang, &linker, false)
    else {
        eprintln!("SKIP aarch64 dense switch: clang cannot target aarch64-unknown-linux-gnu");
        return;
    };

    let out_dir: PathBuf = directory.path().join("out");
    let source: String = decompiled_source(&image, &out_dir);
    let body: &str = dense_switch_body(&source);

    assert!(
        !body.contains("(unstructured control flow)"),
        "dense_switch must be structured:\n{body}"
    );
    assert!(body.contains("switch ("), "no switch dispatch:\n{body}");
    for case in DENSE_SWITCH_CASES {
        assert!(
            body.contains(&format!("case {case}:")),
            "case {case} missing:\n{body}"
        );
    }
    assert!(body.contains("default:"), "default arm missing:\n{body}");
    assert!(!body.contains("goto"), "residual goto:\n{body}");

    for (case, fragments) in CASE_BODIES {
        let arm_start: usize = body
            .find(&format!("case {case}:"))
            .expect("case arm must be present");
        let arm: &str = &body[arm_start..];
        let arm_end: usize = arm.find("        }").unwrap_or(arm.len());
        let arm: &str = &arm[..arm_end];
        for fragment in fragments {
            assert!(
                arm.contains(fragment),
                "case {case} arm lost `{fragment}`:\n{arm}"
            );
        }
    }

    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(out_dir.join("manifest.json")).expect("manifest must exist"),
    )
    .expect("manifest must be json");
    assert_eq!(
        manifest
            .get("functions_whole_program")
            .and_then(serde_json::Value::as_u64),
        Some(2),
        "{manifest}"
    );
    assert_eq!(
        manifest
            .get("functions_structured")
            .and_then(serde_json::Value::as_u64),
        Some(2),
        "{manifest}"
    );
}

#[test]
fn cli_recovers_the_dense_switch_from_a_stripped_image() {
    let Some((clang, linker)): Option<(String, PathBuf)> = aarch64_toolchain() else {
        eprintln!("SKIP aarch64 stripped dense switch: no clang with ld.lld on PATH");
        return;
    };
    let directory: TempDir = tempfile::tempdir().expect("temporary directory must be available");
    let Some(image): Option<PathBuf> = build_aarch64_image(directory.path(), &clang, &linker, true)
    else {
        eprintln!("SKIP aarch64 stripped dense switch: clang cannot target aarch64");
        return;
    };

    let out_dir: PathBuf = directory.path().join("out-stripped");
    let source: String = decompiled_source(&image, &out_dir);
    let body: &str = dense_switch_body(&source);

    assert!(body.contains("switch ("), "no switch dispatch:\n{body}");
    for case in DENSE_SWITCH_CASES {
        assert!(
            body.contains(&format!("case {case}:")),
            "case {case} missing:\n{body}"
        );
    }
    assert!(body.contains("default:"), "default arm missing:\n{body}");

    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(out_dir.join("manifest.json")).expect("manifest must exist"),
    )
    .expect("manifest must be json");
    assert_eq!(
        manifest
            .get("functions_image_leaf")
            .and_then(serde_json::Value::as_u64),
        Some(2),
        "{manifest}"
    );
}

#[test]
fn cli_refuses_a_corrupted_jump_table() {
    let Some((clang, linker)): Option<(String, PathBuf)> = aarch64_toolchain() else {
        eprintln!("SKIP aarch64 dense switch control: no clang with ld.lld on PATH");
        return;
    };
    let directory: TempDir = tempfile::tempdir().expect("temporary directory must be available");
    let Some(image): Option<PathBuf> =
        build_aarch64_image(directory.path(), &clang, &linker, false)
    else {
        eprintln!("SKIP aarch64 dense switch control: clang cannot target aarch64");
        return;
    };

    let mut bytes: Vec<u8> = std::fs::read(&image).expect("fixture must be readable");
    let (start, length): (usize, usize) = rodata_file_range(&bytes);
    assert!(length > 0, "the fixture must carry jump table bytes");
    for index in start..start.saturating_add(length) {
        if let Some(slot) = bytes.get_mut(index) {
            *slot = 0xff;
        }
    }
    let corrupted: PathBuf = directory.path().join("dense.so");
    std::fs::write(&corrupted, &bytes).expect("corrupted fixture must be writable");

    let out_dir: PathBuf = directory.path().join("out-corrupt");
    let source: String = decompiled_source(&corrupted, &out_dir);
    let body: &str = dense_switch_body(&source);

    assert!(
        !body.contains("switch ("),
        "a jump table whose every entry leaves the function must not produce a switch:\n{body}"
    );
    assert!(
        body.contains("(unstructured control flow)"),
        "dense_switch must fall back to the unstructured rendering:\n{body}"
    );
}
