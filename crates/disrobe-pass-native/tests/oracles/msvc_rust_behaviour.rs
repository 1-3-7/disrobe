#![cfg(all(windows, target_arch = "x86_64"))]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_native::RecoveredFunction;

use super::msvc_decompile_behaviour::{
    ADDRESS_TAKEN, Case, Fixture, GLOBALS, Grade, Image, PUSH_FRAMES, RUN_TIMEOUT, SLOT_CALLS,
    STACK_ARGS, VALID_INPUTS, bridge_target, load_image, recovered_at, target_address,
};
use crate::common::{COMPILE_TIMEOUT, MAX_CAPTURE_BYTES, scratch_dir};
use crate::compiler_toolchain;

struct Callee {
    name: String,
    arity: usize,
}

fn c_externs(c_source: &str) -> Vec<Callee> {
    c_source
        .lines()
        .filter_map(|line: &str| line.strip_prefix("extern uint64_t "))
        .map(|rest: &str| {
            let (name, params): (&str, &str) = rest.split_once('(').expect("extern declaration");
            let params: &str = params.trim_end_matches(");");
            let arity: usize = if params == "void" {
                0
            } else {
                params.split(',').count()
            };
            Callee {
                name: name.to_owned(),
                arity,
            }
        })
        .collect()
}

fn without_bridged_declarations(rust: &str, bridged: &BTreeSet<&str>) -> String {
    let mut kept: Vec<&str> = Vec::new();
    let mut block: Vec<&str> = Vec::new();
    let mut in_block: bool = false;
    for line in rust.lines() {
        if !in_block && line.trim_end() == "extern \"C\" {" {
            in_block = true;
            block.clear();
            continue;
        }
        if in_block {
            if line.trim() == "}" {
                in_block = false;
                if !block.is_empty() {
                    kept.push("extern \"C\" {");
                    kept.append(&mut block);
                    kept.push("}");
                }
                continue;
            }
            let declared: Option<&str> = line
                .trim()
                .strip_prefix("fn ")
                .and_then(|rest: &str| rest.split('(').next());
            if !declared.is_some_and(|name: &str| bridged.contains(name)) {
                block.push(line);
            }
            continue;
        }
        kept.push(line);
    }
    kept.join("\n")
}

fn rust_harness(image: &Image, function: &RecoveredFunction, case: &Case, rust: &str) -> String {
    let rva = |address: u64| address - image.preferred_base;
    let callees: Vec<Callee> = c_externs(&function.source);
    let bridged: BTreeSet<&str> = callees
        .iter()
        .map(|callee: &Callee| callee.name.as_str())
        .collect();
    let mut bridges: String = String::new();
    for callee in &callees {
        let params: Vec<String> = (0..callee.arity)
            .map(|i: usize| format!("b{i}: u64"))
            .collect();
        let forwarded: Vec<String> = (0..callee.arity).map(|i: usize| format!("b{i}")).collect();
        let pointer: String = format!(
            "extern \"C\" fn({}) -> u64",
            vec!["u64"; callee.arity].join(", ")
        );
        let _ = writeln!(
            bridges,
            "unsafe extern \"C\" fn {}({}) -> u64 {{ let target: {pointer} = unsafe {{ core::mem::transmute::<*const (), {pointer}>((G_BASE.load(Ordering::Relaxed) + {:#x}) as usize as *const ()) }}; target({}) }}",
            callee.name,
            params.join(", "),
            rva(bridge_target(image, &callee.name)),
            forwarded.join(", ")
        );
    }
    let recovered: String = without_bridged_declarations(rust, &bridged).replacen(
        &format!("pub fn {}(", function.name),
        "pub fn recovered_fn(",
        1,
    );
    let original_type: String = format!(
        "extern \"C\" fn({}) -> u64",
        vec!["u64"; case.params].join(", ")
    );
    let original_args: String = (0..case.params)
        .map(|i: usize| format!("v[{i}]"))
        .collect::<Vec<String>>()
        .join(", ");
    let recovered_args: String = (0..function.signature.callable_arity())
        .map(|i: usize| format!("v[{i}]"))
        .collect::<Vec<String>>()
        .join(", ");
    let mask: u64 = match case.return_bits {
        0 => 0,
        64 => u64::MAX,
        bits => (1_u64 << bits) - 1,
    };
    format!(
        r#"#![allow(unused, unused_parens, unused_unsafe, dead_code, non_snake_case, non_upper_case_globals)]
use std::sync::atomic::{{AtomicU64, Ordering}};
#[link(name = "kernel32")]
extern "system" {{
    fn LoadLibraryA(name: *const u8) -> *mut u8;
}}
static G_BASE: AtomicU64 = AtomicU64::new(0);
{bridges}
{recovered}
trait Widened {{
    fn widened(self) -> u64;
}}
impl Widened for u64 {{
    fn widened(self) -> u64 {{ self }}
}}
impl Widened for u32 {{
    fn widened(self) -> u64 {{ u64::from(self) }}
}}
impl Widened for u16 {{
    fn widened(self) -> u64 {{ u64::from(self) }}
}}
impl Widened for u8 {{
    fn widened(self) -> u64 {{ u64::from(self) }}
}}
impl Widened for () {{
    fn widened(self) -> u64 {{ 0 }}
}}
struct Rng(u64);
impl Rng {{
    fn next(&mut self) -> u64 {{
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }}
    fn pick(&mut self) -> u64 {{
        let r: u64 = self.next();
        match r % 10 {{
            0 => 0,
            1 => 1,
            2 => u64::MAX,
            3 => self.next() % 64,
            4 => u64::from(self.next() as u32),
            5 => 0x7fff_ffff,
            6 => 0xffff_ffff_8000_0000,
            7 => self.next() as u32 as i32 as i64 as u64,
            _ => self.next(),
        }}
    }}
}}
fn writable_sections(base: *mut u8) -> Vec<(*mut u8, usize)> {{
    let mut found: Vec<(*mut u8, usize)> = Vec::new();
    unsafe {{
        let read_u32 = |at: *const u8| core::ptr::read_unaligned(at as *const u32) as usize;
        let read_u16 = |at: *const u8| core::ptr::read_unaligned(at as *const u16) as usize;
        let pe: *mut u8 = base.add(read_u32(base.add(0x3c)));
        let count: usize = read_u16(pe.add(6));
        let mut header: *mut u8 = pe.add(24 + read_u16(pe.add(20)));
        for _ in 0..count {{
            if found.len() >= 16 {{
                break;
            }}
            if read_u32(header.add(36)) & 0x8000_0000 != 0 {{
                found.push((base.add(read_u32(header.add(12))), read_u32(header.add(8)).min(4096)));
            }}
            header = header.add(40);
        }}
    }}
    found
}}
fn snapshot(sections: &[(*mut u8, usize)]) -> Vec<Vec<u8>> {{
    sections
        .iter()
        .map(|&(at, len)| unsafe {{ std::slice::from_raw_parts(at, len) }}.to_vec())
        .collect()
}}
fn restore(sections: &[(*mut u8, usize)], saved: &[Vec<u8>]) {{
    for (&(at, len), bytes) in sections.iter().zip(saved) {{
        unsafe {{ std::ptr::copy_nonoverlapping(bytes.as_ptr(), at, len) }};
    }}
}}
fn main() {{
    let mode: String = std::env::args().nth(1).expect("a mode");
    let base: u64 = unsafe {{ LoadLibraryA(b"{dll}\0".as_ptr()) }} as u64;
    if base != {image_base:#x} {{
        println!("relocated");
        std::process::exit(3);
    }}
    G_BASE.store(base, Ordering::Relaxed);
    let sections: Vec<(*mut u8, usize)> = writable_sections(base as *mut u8);
    let loaded: Vec<Vec<u8>> = snapshot(&sections);
    let original: {original_type} = unsafe {{ core::mem::transmute::<*const (), {original_type}>((base + {original_rva:#x}) as usize as *const ()) }};
    let mut rng: Rng = Rng(0x2545f4914f6cdd1d);
    let (mut valid, mut equal, mut differ): (u32, u32, u32) = (0, 0, 0);
    while valid < {valid_inputs} {{
        let mut v: [u64; 16] = [0; 16];
        for slot in v.iter_mut() {{
            *slot = rng.pick();
        }}
        restore(&sections, &loaded);
        let a: u64 = original({original_args});
        let after: Vec<Vec<u8>> = snapshot(&sections);
        restore(&sections, &loaded);
        let b: u64 = if mode == "null" {{ original({original_args}) }} else {{ recovered_fn({recovered_args}).widened() }};
        let same: bool = snapshot(&sections) == after;
        valid += 1;
        if (a ^ b) & {mask:#x} == 0 && same {{
            equal += 1;
        }} else {{
            differ += 1;
        }}
    }}
    println!("result valid={{valid}} equal={{equal}} differ={{differ}}");
}}
"#,
        dll = image.path.file_name().unwrap().to_str().unwrap(),
        image_base = image.preferred_base,
        original_rva = rva(function.address),
        valid_inputs = VALID_INPUTS,
    )
}

struct Harness {
    _scratch: ScratchDir,
    exe: PathBuf,
}

fn build_harness(image: &Image, source: &str, tag: &str) -> Harness {
    let scratch: ScratchDir = scratch_dir("disrobe-msvc-rust-behaviour");
    let dir: &Path = scratch.path();
    std::fs::copy(&image.path, dir.join(image.path.file_name().unwrap()))
        .expect("stage the fixture dll");
    let source_path: PathBuf = dir.join(format!("{tag}.rs"));
    let exe: PathBuf = dir.join(format!("{tag}.exe"));
    std::fs::write(&source_path, source).expect("write the harness");
    let rustc: String = compiler_toolchain::require_one("rustc");
    let args: Vec<std::ffi::OsString> = vec![
        "--edition".into(),
        "2021".into(),
        "-C".into(),
        "overflow-checks=on".into(),
        "-o".into(),
        exe.clone().into_os_string(),
        source_path.into_os_string(),
    ];
    let compiled: CapturedOutput =
        run_captured(Path::new(&rustc), &args, COMPILE_TIMEOUT, MAX_CAPTURE_BYTES)
            .expect("spawn rustc")
            .expect("rustc finishes within the compile timeout");
    assert_eq!(
        compiled.exit_code,
        Some(0),
        "{tag}: the recovered Rust must compile: {}\n{source}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    Harness {
        _scratch: scratch,
        exe,
    }
}

fn run_harness(harness: &Harness, mode: &str, tag: &str) -> Result<Grade, String> {
    let ran: CapturedOutput = run_captured(&harness.exe, &[mode], RUN_TIMEOUT, MAX_CAPTURE_BYTES)
        .expect("spawn the harness")
        .expect("the harness finishes within its timeout");
    let stdout: String = String::from_utf8_lossy(&ran.stdout).into_owned();
    if ran.exit_code != Some(0) {
        return Err(format!(
            "{tag} {mode}: the harness exited with {:?}: {stdout}{}",
            ran.exit_code,
            String::from_utf8_lossy(&ran.stderr)
        ));
    }
    let line: &str = stdout
        .lines()
        .find(|line: &&str| line.starts_with("result "))
        .unwrap_or_else(|| panic!("{tag} {mode}: no result line: {stdout}"));
    let field = |key: &str| -> u32 {
        line.split_whitespace()
            .find_map(|item: &str| item.strip_prefix(key)?.strip_prefix('=')?.parse().ok())
            .unwrap_or_else(|| panic!("{tag}: missing {key} in {line}"))
    };
    Ok(Grade {
        valid: field("valid"),
        equal: field("equal"),
        differ: field("differ"),
    })
}

const EVERY_INPUT_AGREES: Grade = Grade {
    valid: VALID_INPUTS,
    equal: VALID_INPUTS,
    differ: 0,
};

fn grade_rust_fixture(fixture: &Fixture) {
    let image: Image = load_image(fixture.dll);
    for case in fixture.cases {
        let address: u64 = target_address(&image, case.target);
        let function: &RecoveredFunction = recovered_at(&image, address);
        let tag: String = format!("rs_{address:x}");
        let rust: &str = function.rust_source.as_deref().unwrap_or_else(|| {
            panic!(
                "{tag}: the Rust emitter declined {} whose C is graded:\n{}",
                function.name, function.source
            )
        });
        let harness: Harness = build_harness(
            &image,
            &rust_harness(&image, function, case, rust),
            &format!("{tag}_recovered"),
        );
        let null: Grade =
            run_harness(&harness, "null", &tag).unwrap_or_else(|failure| panic!("{failure}"));
        assert_eq!(
            null, EVERY_INPUT_AGREES,
            "{tag}: the original-against-original null control must agree on every input"
        );
        let recovered: Grade =
            run_harness(&harness, "recovered", &tag).unwrap_or_else(|failure| panic!("{failure}"));
        assert_eq!(
            recovered, EVERY_INPUT_AGREES,
            "{tag}: the recovered Rust must behave like the original on every input:\n{rust}"
        );
        let mutated_rust: String = (case.mutate_rust)(rust);
        assert_ne!(
            mutated_rust, rust,
            "{tag}: the mutation control must change the Rust"
        );
        let mutated_harness: Harness = build_harness(
            &image,
            &rust_harness(&image, function, case, &mutated_rust),
            &format!("{tag}_mutated"),
        );
        let mutated: Result<Grade, String> = run_harness(&mutated_harness, "recovered", &tag);
        assert!(
            mutated.as_ref().is_err()
                || mutated.as_ref().is_ok_and(|grade: &Grade| grade.differ > 0),
            "{tag}: the mutation control must turn the grade red: {mutated:?}\n{mutated_rust}"
        );
    }
}

pub(super) fn rust_add_one_to_every_returned_value(source: &str) -> String {
    let mut lines: Vec<String> = source.lines().map(str::to_owned).collect();
    let close: Option<usize> = lines.iter().rposition(|line: &String| line == "}");
    let trailing: Option<usize> = close.and_then(|close: usize| {
        lines[..close]
            .iter()
            .rposition(|line: &String| !line.trim().is_empty())
    });
    for (index, line) in lines.iter_mut().enumerate() {
        let indent: usize = line.len() - line.trim_start().len();
        let text: &str = line.trim();
        if let Some(returned) = text
            .strip_prefix("return ")
            .and_then(|rest: &str| rest.strip_suffix(';'))
        {
            *line = format!("{}return ({returned}).wrapping_add(1);", &line[..indent]);
        } else if Some(index) == trailing && text != "}" && !text.ends_with(';') {
            *line = format!("{}({text}).wrapping_add(1)", &line[..indent]);
        }
    }
    lines.join(
        "
",
    )
}

pub(super) fn rust_write_one_more_at_the_first_store(source: &str) -> String {
    let Some(store): Option<usize> = source.find("core::ptr::write_unaligned(") else {
        return source.to_owned();
    };
    let Some(pointer): Option<usize> = source[store..]
        .find(" as *mut ")
        .map(|at: usize| store + at)
    else {
        return source.to_owned();
    };
    let Some(value): Option<usize> = source[pointer..]
        .find(", ")
        .map(|at: usize| pointer + at + 2)
    else {
        return source.to_owned();
    };
    let Some(end): Option<usize> = source[value..].find(", ) };").map(|at: usize| value + at)
    else {
        return source.to_owned();
    };
    format!(
        "{}({}).wrapping_add(1){}",
        &source[..value],
        &source[value..end],
        &source[end..]
    )
}

#[test]
fn msvc_o2_outgoing_stack_arguments_recover_to_rust_that_behaves_like_the_original() {
    grade_rust_fixture(&STACK_ARGS);
}

#[test]
fn msvc_o2_push_built_frames_recover_to_rust_that_behaves_like_the_original() {
    grade_rust_fixture(&PUSH_FRAMES);
}

#[test]
fn msvc_o2_calls_through_import_and_pointer_slots_recover_to_rust_that_behaves_like_the_original() {
    grade_rust_fixture(&SLOT_CALLS);
}

#[test]
fn msvc_o2_rip_relative_globals_recover_to_rust_that_behaves_like_the_original() {
    grade_rust_fixture(&GLOBALS);
}

#[test]
fn msvc_o2_address_taken_locals_recover_to_rust_that_behaves_like_the_original() {
    grade_rust_fixture(&ADDRESS_TAKEN);
}
