#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_jvm::{
    Attribute, ClassFile, CodeAttribute, DecompiledClass, ExceptionEntry, Instruction, MethodInfo,
    decompile_classfile_bytes, disassemble, parse_classfile, parse_code_attribute,
};

const TABLE_SRC: &str = "public class TableShapes {\n\
    static int CTR = 0;\n\
    static int guarded(int n, int d) {\n\
        try {\n\
            return n / d;\n\
        } catch (ArithmeticException ex) {\n\
            return -1;\n\
        } finally {\n\
            CTR++;\n\
        }\n\
    }\n\
}\n";

const NESTED_DEPTH: usize = 60;

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

fn require_javac() -> PathBuf {
    let Some(javac): Option<PathBuf> = find_on_path("javac") else {
        panic!("exception-table edge-case gate requires javac on PATH");
    };
    javac
}

fn quietly<T>(body: impl FnOnce() -> T) -> std::thread::Result<T> {
    static GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let held: std::sync::MutexGuard<'_, ()> = GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let previous: Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Sync + Send> =
        std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result: std::thread::Result<T> = catch_unwind(AssertUnwindSafe(body));
    std::panic::set_hook(previous);
    drop(held);
    result
}

fn compile_class(javac: &PathBuf, dir: &PathBuf, name: &str, source: &str) -> Vec<u8> {
    std::fs::create_dir_all(dir).expect("mkdir");
    let path: PathBuf = dir.join(format!("{name}.java"));
    std::fs::write(&path, source).expect("write source");
    let out: std::process::Output = Command::new(javac)
        .arg("-proc:none")
        .arg("-d")
        .arg(dir)
        .arg(&path)
        .output()
        .expect("javac");
    assert!(
        out.status.success(),
        "fixture failed to compile: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::read(dir.join(format!("{name}.class"))).expect("read class")
}

#[derive(Debug)]
struct TableSite {
    count_offset: usize,
    entries_offset: usize,
    entries: Vec<ExceptionEntry>,
    code_length: usize,
    instruction_pcs: Vec<u32>,
}

fn locate_exception_table(bytes: &[u8], cf: &ClassFile) -> TableSite {
    for method in &cf.methods {
        let method: &MethodInfo = method;
        for attr in &method.attributes {
            let attr: &Attribute = attr;
            if cf.utf8_at(attr.name_index).ok() != Some("Code") {
                continue;
            }
            let Ok(code): Result<CodeAttribute, _> = parse_code_attribute(&attr.info) else {
                continue;
            };
            if code.exception_table.is_empty() {
                continue;
            }
            let matches: Vec<usize> = bytes
                .windows(attr.info.len())
                .enumerate()
                .filter(|(_, window): &(usize, &[u8])| *window == attr.info.as_slice())
                .map(|(i, _): (usize, &[u8])| i)
                .collect();
            let [info_offset]: [usize; 1] = matches
                .as_slice()
                .try_into()
                .expect("the Code attribute payload must appear exactly once in the class bytes");
            let count_offset: usize = info_offset + 2 + 2 + 4 + code.code.len();
            let stored_count: u16 =
                u16::from_be_bytes([bytes[count_offset], bytes[count_offset + 1]]);
            assert_eq!(
                usize::from(stored_count),
                code.exception_table.len(),
                "the located exception_table_length does not match the parsed table"
            );
            let instruction_pcs: Vec<u32> = disassemble(&code.code)
                .expect("fixture code disassembles")
                .iter()
                .map(|ins: &Instruction| ins.pc)
                .collect();
            return TableSite {
                count_offset,
                entries_offset: count_offset + 2,
                entries: code.exception_table.clone(),
                code_length: code.code.len(),
                instruction_pcs,
            };
        }
    }
    panic!("fixture carries no method with an exception table");
}

fn patched(bytes: &[u8], site: &TableSite, index: usize, entry: ExceptionEntry) -> Vec<u8> {
    let mut out: Vec<u8> = bytes.to_vec();
    let at: usize = site.entries_offset + index * 8;
    out[at..at + 2].copy_from_slice(&entry.start_pc.to_be_bytes());
    out[at + 2..at + 4].copy_from_slice(&entry.end_pc.to_be_bytes());
    out[at + 4..at + 6].copy_from_slice(&entry.handler_pc.to_be_bytes());
    out[at + 6..at + 8].copy_from_slice(&entry.catch_type.to_be_bytes());
    out
}

fn patched_count(bytes: &[u8], site: &TableSite, count: u16) -> Vec<u8> {
    let mut out: Vec<u8> = bytes.to_vec();
    out[site.count_offset..site.count_offset + 2].copy_from_slice(&count.to_be_bytes());
    out
}

fn mid_instruction_pc(site: &TableSite) -> u16 {
    let boundaries: &[u32] = &site.instruction_pcs;
    (1..site.code_length as u32)
        .find(|pc: &u32| !boundaries.contains(pc))
        .expect("fixture has at least one multi-byte instruction") as u16
}

fn malformed_variants(bytes: &[u8], site: &TableSite) -> Vec<(&'static str, Vec<u8>)> {
    let first: ExceptionEntry = site.entries[0].clone();
    let last_index: usize = site.entries.len() - 1;
    let last: ExceptionEntry = site.entries[last_index].clone();
    let mut out: Vec<(&'static str, Vec<u8>)> = vec![
        (
            "zero length range",
            patched(
                bytes,
                site,
                0,
                ExceptionEntry {
                    end_pc: first.start_pc,
                    ..first.clone()
                },
            ),
        ),
        (
            "end before start",
            patched(
                bytes,
                site,
                0,
                ExceptionEntry {
                    start_pc: first.end_pc,
                    end_pc: first.start_pc,
                    ..first.clone()
                },
            ),
        ),
        (
            "handler inside an instruction",
            patched(
                bytes,
                site,
                0,
                ExceptionEntry {
                    handler_pc: mid_instruction_pc(site),
                    ..first.clone()
                },
            ),
        ),
        (
            "handler covering itself",
            patched(
                bytes,
                site,
                0,
                ExceptionEntry {
                    start_pc: first.handler_pc,
                    end_pc: site.code_length as u16,
                    ..first.clone()
                },
            ),
        ),
        (
            "catch type index zero",
            patched(
                bytes,
                site,
                0,
                ExceptionEntry {
                    catch_type: 0,
                    ..first.clone()
                },
            ),
        ),
        (
            "catch type index out of the constant pool",
            patched(
                bytes,
                site,
                0,
                ExceptionEntry {
                    catch_type: u16::MAX,
                    ..first.clone()
                },
            ),
        ),
        (
            "range past the end of the code",
            patched(
                bytes,
                site,
                0,
                ExceptionEntry {
                    start_pc: site.code_length as u16,
                    end_pc: u16::MAX,
                    ..first.clone()
                },
            ),
        ),
        (
            "handler past the end of the code",
            patched(
                bytes,
                site,
                0,
                ExceptionEntry {
                    handler_pc: u16::MAX,
                    ..first
                },
            ),
        ),
        (
            "more entries than the table holds",
            patched_count(bytes, site, u16::MAX),
        ),
        ("zero entries declared", patched_count(bytes, site, 0)),
    ];
    if site.entries.len() >= 2 {
        out.push((
            "two identical ranges with different handlers",
            patched(
                bytes,
                site,
                last_index,
                ExceptionEntry {
                    start_pc: first.start_pc,
                    end_pc: first.end_pc,
                    ..last
                },
            ),
        ));
    }
    out
}

fn nested_try_source() -> String {
    let mut src: String = String::from(
        "public class DeepNest {\n    static int CTR = 0;\n    static int deep(int a) {\n",
    );
    for _ in 0..NESTED_DEPTH {
        src.push_str("        try {\n");
    }
    src.push_str("        CTR += a;\n");
    for _ in 0..NESTED_DEPTH {
        src.push_str("        } finally {\n            CTR++;\n        }\n");
    }
    src.push_str("        return CTR;\n    }\n}\n");
    src
}

#[test]
fn a_malformed_exception_table_is_refused_and_never_panics() {
    let javac: PathBuf = require_javac();
    let purpose: String = format!("disrobe_table_edges_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();

    let bytes: Vec<u8> = compile_class(&javac, &dir.join("orig"), "TableShapes", TABLE_SRC);
    let cf: ClassFile = parse_classfile(&bytes).expect("parse fixture");
    let site: TableSite = locate_exception_table(&bytes, &cf);
    assert!(
        site.entries.len() >= 2,
        "the fixture must carry a multi-entry table to exercise duplicate ranges"
    );

    let variants: Vec<(&'static str, Vec<u8>)> = malformed_variants(&bytes, &site);
    assert!(
        variants.len() >= 11,
        "the malformed-table matrix lost members: {}",
        variants.len()
    );

    let mut rendered_bodies: usize = 0;
    for (label, mutant) in &variants {
        assert_ne!(
            mutant, &bytes,
            "the {label} mutation did not change the class bytes, so it measures nothing"
        );
        let owned: Vec<u8> = mutant.clone();
        let outcome: std::thread::Result<Option<String>> = quietly(|| {
            decompile_classfile_bytes(&owned)
                .ok()
                .map(|c: DecompiledClass| c.source)
        });
        let Ok(source) = outcome else {
            panic!("the {label} mutation unwound the decompiler instead of rejecting the table");
        };
        let Some(source): Option<String> = source else {
            continue;
        };
        assert!(
            !source.contains("(stack reset)"),
            "the {label} mutation left a lifting hole in emitted java:\n{source}"
        );
        if source.contains("static int guarded") && !source.contains("not recovered:") {
            rendered_bodies += 1;
            let rec_dir: PathBuf = dir.join(format!("rec{rendered_bodies}"));
            std::fs::create_dir_all(&rec_dir).expect("mkdir rec");
            let rec_src: PathBuf = rec_dir.join("TableShapes.java");
            std::fs::write(&rec_src, &source).expect("write rec");
            let out: std::process::Output = Command::new(&javac)
                .arg("-proc:none")
                .arg("-d")
                .arg(&rec_dir)
                .arg(&rec_src)
                .output()
                .expect("javac rec");
            assert!(
                out.status.success(),
                "the {label} mutation produced a method body that real javac rejects:\n{}\n\
                 ---source---\n{source}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
    assert!(
        rendered_bodies > 0,
        "every malformed variant refused, so this gate never exercised the recovery path"
    );
}

#[test]
fn a_deeply_nested_try_region_stays_within_the_structurer_bounds() {
    let javac: PathBuf = require_javac();
    let purpose: String = format!("disrobe_table_depth_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    let source: String = nested_try_source();
    let bytes: Vec<u8> = compile_class(&javac, &dir.join("orig"), "DeepNest", &source);
    let cf: ClassFile = parse_classfile(&bytes).expect("parse fixture");
    let site: TableSite = locate_exception_table(&bytes, &cf);
    assert!(
        site.entries.len() >= NESTED_DEPTH,
        "the deep-nesting fixture collapsed to {} entries",
        site.entries.len()
    );

    let owned: Vec<u8> = bytes.clone();
    let outcome: std::thread::Result<bool> = quietly(|| decompile_classfile_bytes(&owned).is_ok());
    assert!(
        outcome.is_ok_and(|ok: bool| ok),
        "a {NESTED_DEPTH}-deep try nest unwound the decompiler instead of bounding itself"
    );

    let widened: Vec<u8> = patched(
        &bytes,
        &site,
        0,
        ExceptionEntry {
            start_pc: 0,
            end_pc: site.code_length as u16,
            handler_pc: 0,
            catch_type: 0,
        },
    );
    let outcome: std::thread::Result<()> = quietly(|| {
        let _ = decompile_classfile_bytes(&widened);
    });
    assert!(
        outcome.is_ok(),
        "a self-covering handler over the whole deep nest unwound the decompiler"
    );
}

#[test]
fn the_edge_case_gate_fails_when_javac_is_unavailable() {
    let test_binary: PathBuf = std::env::current_exe().expect("current test binary");
    let output: std::process::Output = Command::new(test_binary)
        .arg("--exact")
        .arg("a_malformed_exception_table_is_refused_and_never_panics")
        .arg("--test-threads=1")
        .env("PATH", "")
        .output()
        .expect("run edge-case gate without javac");
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        !output.status.success(),
        "the edge-case gate passed without javac; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        format!("{stdout}\n{stderr}").contains("exception-table edge-case gate requires javac"),
        "the edge-case gate failed for an unrelated reason; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}
