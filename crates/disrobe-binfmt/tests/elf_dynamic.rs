#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_binfmt::{ElfDynamic, NativeFile, parse_elf_dynamic, parse_native};

use common::fixture_path;
use common::requirement::{
    READELF, corpus_path, find_on_path, required_corpus, required_fixture, unmeasured,
};

const NIM_ELF: &str = "native/nim/hello.nim.elf";

const PYARMOR_RUNTIME: &str =
    "python/pyarmor/v9/platform_linux/pyarmor_runtime_000000/pyarmor_runtime.so";

const READELF_CANDIDATES: [&str; 3] = ["readelf", "llvm-readelf", "eu-readelf"];

const DYNAMIC_SECTION_BANNER: &str = "Dynamic section at offset";

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReadelfDynamic {
    needed: Vec<String>,
    soname: Option<String>,
    rpath: Option<String>,
    runpath: Option<String>,
    entry_count: usize,
}

fn find_readelf() -> Option<PathBuf> {
    READELF_CANDIDATES
        .into_iter()
        .find_map(|program: &str| find_on_path(program))
}

fn carries_tag(line: &str, tag: &str) -> bool {
    line.split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .any(|token: &str| token == tag)
}

fn bracketed(line: &str) -> Option<String> {
    let open: usize = line.find('[')?;
    let close: usize = line.rfind(']')?;
    let start: usize = open.checked_add(1)?;
    if close <= start {
        return None;
    }
    line.get(start..close).map(str::to_owned)
}

fn declared_entry_count(text: &str, tool: &Path, file: &Path) -> usize {
    let banner: &str = text
        .lines()
        .find(|line: &&str| line.contains(DYNAMIC_SECTION_BANNER))
        .unwrap_or_else(|| {
            panic!(
                "`{} -d {}` printed no `{DYNAMIC_SECTION_BANNER}` banner, so the reference read \
                 nothing and this case must not compare against an empty reference:\n{text}",
                tool.display(),
                file.display()
            )
        });
    let (_, after): (&str, &str) = banner
        .split_once("contains ")
        .unwrap_or_else(|| panic!("no entry count in the reference banner `{banner}`"));
    let digits: String = after
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    digits
        .parse::<usize>()
        .unwrap_or_else(|err: std::num::ParseIntError| {
            panic!("the reference banner `{banner}` carries no entry count: {err}")
        })
}

fn parse_readelf_dynamic(text: &str, tool: &Path, file: &Path) -> ReadelfDynamic {
    let mut needed: Vec<String> = Vec::new();
    let mut soname: Option<String> = None;
    let mut rpath: Option<String> = None;
    let mut runpath: Option<String> = None;
    for line in text.lines() {
        let Some(value): Option<String> = bracketed(line) else {
            continue;
        };
        if carries_tag(line, "NEEDED") {
            needed.push(value);
        } else if carries_tag(line, "SONAME") {
            soname = Some(value);
        } else if carries_tag(line, "RUNPATH") {
            runpath = Some(value);
        } else if carries_tag(line, "RPATH") {
            rpath = Some(value);
        }
    }
    ReadelfDynamic {
        needed,
        soname,
        rpath,
        runpath,
        entry_count: declared_entry_count(text, tool, file),
    }
}

fn readelf_dynamic(tool: &Path, file: &Path, graded: &str) -> ReadelfDynamic {
    let output: Output = Command::new(tool)
        .arg("-d")
        .arg(file)
        .output()
        .unwrap_or_else(|err: std::io::Error| {
            panic!(
                "`{}` is on PATH but could not be launched here ({err}), so {graded} cannot be \
                 measured. A tool that is present and unrunnable is never a skip, because that is \
                 how a permissions or quarantine problem silently stops grading",
                tool.display()
            )
        });
    assert!(
        output.status.success(),
        "`{} -d {}` exited {}, so {graded} would be compared against nothing:\n{}",
        tool.display(),
        file.display(),
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let text: String = String::from_utf8_lossy(&output.stdout).into_owned();
    parse_readelf_dynamic(&text, tool, file)
}

fn agrees_with_readelf(file: &Path, ours: &ElfDynamic, graded: &str) {
    let Some(tool): Option<PathBuf> = find_readelf() else {
        unmeasured(
            &READELF,
            graded,
            "none of readelf, llvm-readelf or eu-readelf is on PATH, so the expectations below \
             stand on nothing but the last person who typed them",
        );
        return;
    };
    let reference: ReadelfDynamic = readelf_dynamic(&tool, file, graded);
    assert!(
        !reference.needed.is_empty() || reference.entry_count > 0,
        "{} reports an empty dynamic section for {}, so agreeing with it would prove nothing",
        tool.display(),
        file.display()
    );
    assert_eq!(
        ours.needed,
        reference.needed,
        "DT_NEEDED disagrees with `{} -d {}`",
        tool.display(),
        file.display()
    );
    assert_eq!(
        ours.soname.as_deref(),
        reference.soname.as_deref(),
        "DT_SONAME disagrees with `{} -d {}`",
        tool.display(),
        file.display()
    );
    assert_eq!(
        ours.rpath.as_deref(),
        reference.rpath.as_deref(),
        "DT_RPATH disagrees with `{} -d {}`",
        tool.display(),
        file.display()
    );
    assert_eq!(
        ours.runpath.as_deref(),
        reference.runpath.as_deref(),
        "DT_RUNPATH disagrees with `{} -d {}`",
        tool.display(),
        file.display()
    );
    assert_eq!(
        ours.entry_count,
        reference.entry_count,
        "the dynamic entry count disagrees with `{} -d {}`",
        tool.display(),
        file.display()
    );
}

#[test]
fn crafted_so_matches_readelf_ground_truth() {
    let path: PathBuf = fixture_path("elf-dynamic", "sample.elf");
    let bytes: Vec<u8> = required_fixture("elf-dynamic", "sample.elf");

    let dynamic: ElfDynamic = parse_elf_dynamic(&bytes).expect("dynamic segment parses");

    assert_eq!(
        dynamic.needed,
        vec!["libc.so.6".to_owned(), "libm.so.6".to_owned()],
    );
    assert_eq!(dynamic.soname.as_deref(), Some("libsample.so.1"));
    assert_eq!(dynamic.rpath.as_deref(), Some("/opt/legacy/lib"));
    assert_eq!(
        dynamic.runpath.as_deref(),
        Some("$ORIGIN/../lib:/usr/local/sample/lib"),
    );
    assert_eq!(dynamic.entry_count, 8);

    agrees_with_readelf(
        &path,
        &dynamic,
        "the crafted shared object's dynamic section against readelf",
    );
}

#[test]
fn declared_string_table_crossing_load_boundary_rejects() {
    let mut bytes: Vec<u8> = required_fixture("elf-dynamic", "sample.elf");
    let strsz_tag_offset: usize = 0x170;
    let strsz_value_offset: usize = 0x178;
    let strsz_value_end: usize = strsz_value_offset
        .checked_add(8)
        .expect("string table size field should fit");
    let strsz_tag: u64 = disrobe_bytes::read_u64_le_at(&bytes, strsz_tag_offset)
        .expect("string table tag should parse");
    let oversized: [u8; 8] = 0xe1u64.to_le_bytes();
    let field: &mut [u8] = bytes
        .get_mut(strsz_value_offset..strsz_value_end)
        .expect("string table size field should exist");

    assert_eq!(strsz_tag, 10);
    field.copy_from_slice(&oversized);
    assert!(parse_elf_dynamic(&bytes).is_none());
}

#[test]
fn real_elf_dynamic_surfaced_through_native_file() {
    let bytes: Vec<u8> = required_corpus(NIM_ELF);
    let nf: NativeFile = parse_native(&bytes).expect("parse native elf");
    let dynamic: &ElfDynamic = nf
        .dynamic
        .as_ref()
        .expect("native file surfaces the dynamic segment for a dynamically linked elf");
    assert_eq!(
        dynamic.needed,
        vec![
            "libpthread.so.0".to_owned(),
            "libc.so.6".to_owned(),
            "ld-linux-x86-64.so.2".to_owned(),
        ],
    );
    agrees_with_readelf(
        &corpus_path(NIM_ELF),
        dynamic,
        "the dynamic segment the native file surfaces, against readelf",
    );
}

#[test]
fn real_nim_executable_needed_matches_readelf() {
    let bytes: Vec<u8> = required_corpus(NIM_ELF);
    let dynamic: ElfDynamic = parse_elf_dynamic(&bytes).expect("nim elf has a dynamic segment");
    assert_eq!(
        dynamic.needed,
        vec![
            "libpthread.so.0".to_owned(),
            "libc.so.6".to_owned(),
            "ld-linux-x86-64.so.2".to_owned(),
        ],
    );
    assert!(dynamic.soname.is_none());
    agrees_with_readelf(
        &corpus_path(NIM_ELF),
        &dynamic,
        "the real nim executable's dynamic section against readelf",
    );
}

#[test]
fn real_pyarmor_runtime_needed_matches_readelf() {
    let bytes: Vec<u8> = required_corpus(PYARMOR_RUNTIME);
    let dynamic: ElfDynamic =
        parse_elf_dynamic(&bytes).expect("pyarmor runtime has a dynamic segment");
    assert_eq!(
        dynamic.needed,
        vec![
            "libpthread.so.0".to_owned(),
            "libdl.so.2".to_owned(),
            "libc.so.6".to_owned(),
        ],
    );
    agrees_with_readelf(
        &corpus_path(PYARMOR_RUNTIME),
        &dynamic,
        "the real pyarmor runtime's dynamic section against readelf",
    );
}

#[test]
fn the_readelf_reader_would_notice_a_disagreement() {
    let text: &str = "\nDynamic section at offset 0x110 contains 3 entries:\n  Tag        Type     \
                      Name/Value\n 0x0000000000000001 (NEEDED)             Shared library: \
                      [libc.so.6]\n 0x000000000000000e (SONAME)             Library soname: \
                      [libsample.so.1]\n 0x0000000000000000 (NULL)               0x0\n";
    let parsed: ReadelfDynamic =
        parse_readelf_dynamic(text, Path::new("readelf"), Path::new("sample.elf"));
    assert_eq!(parsed.needed, vec!["libc.so.6".to_owned()]);
    assert_eq!(parsed.soname.as_deref(), Some("libsample.so.1"));
    assert_eq!(parsed.rpath, None);
    assert_eq!(parsed.runpath, None);
    assert_eq!(parsed.entry_count, 3);

    let runpath_only: &str = "\nDynamic section at offset 0x110 contains 2 entries:\n \
                              0x000000000000001d (RUNPATH)            Library runpath: \
                              [/opt/lib]\n 0x0000000000000000 (NULL)               0x0\n";
    let parsed: ReadelfDynamic =
        parse_readelf_dynamic(runpath_only, Path::new("readelf"), Path::new("sample.elf"));
    assert_eq!(
        parsed.rpath, None,
        "RUNPATH must never be read as RPATH, or a binary carrying only one of them would agree \
         with a reference carrying the other"
    );
    assert_eq!(parsed.runpath.as_deref(), Some("/opt/lib"));
}

#[test]
fn statically_shaped_input_has_no_dynamic() {
    let mut buf: Vec<u8> = vec![0u8; 0x80];
    buf[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    buf[4] = 2;
    buf[5] = 1;
    assert!(
        parse_elf_dynamic(&buf).is_none(),
        "no program headers means no dynamic segment"
    );
}
