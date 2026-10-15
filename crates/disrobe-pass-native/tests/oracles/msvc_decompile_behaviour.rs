#![cfg(all(windows, target_arch = "x86_64"))]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_native::{
    Arch, DisasmInsn, ProgramFunction, PseudoAbi, RecoveredFunction, RecoveredProgram,
    build_disasm_payload, disassemble, recover_program,
};
use object::{Object as _, ObjectSection as _};

use super::msvc_rust_behaviour::{
    rust_add_one_to_every_returned_value, rust_write_one_more_at_the_first_store,
};
use crate::common::{COMPILE_TIMEOUT, MAX_CAPTURE_BYTES, scratch_dir};
use crate::compiler_toolchain;

const FIXTURE_ROOT: &str = "corpus/native/decompile";
pub(super) const VALID_INPUTS: u32 = 1000;
pub(super) const RUN_TIMEOUT: Duration = Duration::from_mins(1);

#[derive(Clone, Copy)]
pub(super) enum Target {
    Export(&'static str),
    JumpThunk(&'static str),
}

pub(super) struct Case {
    pub(super) target: Target,
    pub(super) params: usize,
    pub(super) return_bits: u32,
    pub(super) mutate_c: fn(&str) -> String,
    pub(super) mutate_rust: fn(&str) -> String,
}

pub(super) struct Fixture {
    pub(super) dll: &'static str,
    pub(super) cases: &'static [Case],
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Recovered,
    OriginalTwice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Grade {
    pub(super) valid: u32,
    pub(super) equal: u32,
    pub(super) differ: u32,
}

pub(super) struct Image {
    bytes: Vec<u8>,
    pub(super) path: PathBuf,
    pub(super) preferred_base: u64,
    pub(super) program: RecoveredProgram,
    names: BTreeMap<String, u64>,
}

pub(super) fn fixture_path(relative: &str) -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root.join(FIXTURE_ROOT).join(relative)
}

fn mapped_bytes(file: &object::File<'_>, start: u64, end: u64) -> Option<Vec<u8>> {
    let len: usize = usize::try_from(end.checked_sub(start)?).ok()?;
    file.sections()
        .find_map(|section: object::Section<'_, '_>| {
            let offset: u64 = start.checked_sub(section.address())?;
            let data: &[u8] = section.data().ok()?;
            let from: usize = usize::try_from(offset).ok()?;
            (from < data.len()).then(|| data[from..data.len().min(from + len)].to_vec())
        })
}

pub(super) fn load_image(relative: &str) -> Image {
    let path: PathBuf = fixture_path(relative);
    let bytes: Vec<u8> = std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "the committed fixture {} must exist: {error}",
            path.display()
        )
    });
    let payload = build_disasm_payload(&bytes).expect("the fixture disassembles");
    let module: disrobe_query::Module = disrobe_query::Module::from_disasm(&payload);
    let file: object::File<'_> = object::File::parse(bytes.as_slice()).expect("the fixture parses");
    let image_base: u64 = file.relative_address_base();
    let mut functions: Vec<ProgramFunction> = Vec::new();
    let mut names: BTreeMap<String, u64> = BTreeMap::new();
    for function in module.functions() {
        let code: Vec<u8> = mapped_bytes(&file, function.address, function.end)
            .expect("every discovered function is mapped");
        names.insert(function.name.clone(), function.address);
        functions.push(ProgramFunction {
            name: function.name.clone(),
            address: function.address,
            code,
        });
    }
    let program: RecoveredProgram = recover_program(&bytes, &functions, PseudoAbi::MsX64);
    Image {
        bytes,
        path,
        preferred_base: image_base,
        program,
        names,
    }
}

pub(super) fn target_address(image: &Image, target: Target) -> u64 {
    match target {
        Target::Export(name) => *image
            .names
            .get(name)
            .unwrap_or_else(|| panic!("{name} must be discovered in the fixture")),
        Target::JumpThunk(name) => {
            let thunk: u64 = target_address(image, Target::Export(name));
            let file: object::File<'_> = object::File::parse(image.bytes.as_slice()).unwrap();
            let code: Vec<u8> = mapped_bytes(&file, thunk, thunk + 16).unwrap();
            let insns: Vec<DisasmInsn> = disassemble(Arch::X86_64, thunk, &code).unwrap();
            let first: &DisasmInsn = insns.first().unwrap();
            assert_eq!(
                first.mnemonic, "jmp",
                "{name} must be a jump thunk: {insns:?}"
            );
            u64::from_str_radix(
                first
                    .operands
                    .trim()
                    .trim_start_matches("0x")
                    .trim_end_matches('h'),
                16,
            )
            .unwrap_or_else(|_| panic!("{name} jump target: {}", first.operands))
        }
    }
}

pub(super) fn recovered_at(image: &Image, address: u64) -> &RecoveredFunction {
    image
        .program
        .recovered
        .iter()
        .find(|function: &&RecoveredFunction| function.address == address)
        .unwrap_or_else(|| {
            let refusal: Option<&str> = image
                .program
                .unrecovered
                .iter()
                .find(|function| function.address == address)
                .map(|function| function.reason.as_str());
            panic!("the function at {address:#x} must recover, refused: {refusal:?}")
        })
}

pub(super) fn bridge_target(image: &Image, name: &str) -> u64 {
    if let Some(hex) = name.strip_prefix("sub_")
        && let Ok(address) = u64::from_str_radix(hex, 16)
    {
        return address;
    }
    *image
        .names
        .get(name)
        .unwrap_or_else(|| panic!("extern {name} has no address in the fixture"))
}

fn harness_source(
    image: &Image,
    function: &RecoveredFunction,
    case: &Case,
    body: &str,
    mode: Mode,
) -> String {
    let rva = |address: u64| address - image.preferred_base;
    let mut bridges: String = String::new();
    let mut kept: Vec<&str> = Vec::new();
    for line in body.lines() {
        let Some(rest): Option<&str> = line.strip_prefix("extern uint64_t ") else {
            kept.push(line);
            continue;
        };
        let (name, params): (&str, &str) = rest.split_once('(').expect("extern declaration");
        let params: &str = params.trim_end_matches(");");
        let arity: usize = if params == "void" {
            0
        } else {
            params.split(',').count()
        };
        let typed: Vec<String> = (0..arity)
            .map(|i: usize| format!("uint64_t b{i}"))
            .collect();
        let forwarded: Vec<String> = (0..arity).map(|i: usize| format!("b{i}")).collect();
        let pointer: String = format!(
            "uint64_t (*)({})",
            if arity == 0 {
                "void".to_owned()
            } else {
                vec!["uint64_t"; arity].join(", ")
            }
        );
        let _ = writeln!(
            bridges,
            "uint64_t {name}({}) {{ return (({pointer})(g_base + {:#x}ULL))({}); }}",
            if arity == 0 {
                "void".to_owned()
            } else {
                typed.join(", ")
            },
            rva(bridge_target(image, name)),
            forwarded.join(", ")
        );
    }
    let renamed: String =
        kept.join("\n")
            .replacen(&format!("{}(", function.name), "recovered_fn(", 1);
    let pointer: String = format!("uint64_t (*)({})", vec!["uint64_t"; case.params].join(", "));
    let args: Vec<String> = (0..case.params).map(|i: usize| format!("v[{i}]")).collect();
    let recovered_args: Vec<String> = (0..function.signature.callable_arity())
        .map(|i: usize| format!("v[{i}]"))
        .collect();
    let original_call: String = format!(
        "(({pointer})(g_base + {:#x}ULL))({})",
        rva(function.address),
        args.join(", ")
    );
    let other_call: String = match mode {
        Mode::Recovered => format!("(uint64_t)recovered_fn({})", recovered_args.join(", ")),
        Mode::OriginalTwice => original_call.clone(),
    };
    let mask: u64 = match case.return_bits {
        0 => 0,
        64 => u64::MAX,
        bits => (1_u64 << bits) - 1,
    };
    format!(
        r#"#include <stdint.h>
#include <stdio.h>
#include <string.h>
__declspec(dllimport) void *__stdcall LoadLibraryA(const char *);
static unsigned char *g_base;
{bridges}
{renamed}
static uint64_t rng = 0x2545f4914f6cdd1dULL;
static uint64_t next(void) {{ rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }}
static uint64_t pick(void) {{
    uint64_t r = next();
    switch (r % 10) {{
    case 0: return 0;
    case 1: return 1;
    case 2: return (uint64_t)-1;
    case 3: return next() % 64;
    case 4: return (uint32_t)next();
    case 5: return 0x7fffffffULL;
    case 6: return 0xffffffff80000000ULL;
    case 7: return (uint64_t)(int64_t)(int32_t)next();
    default: return next();
    }}
}}
static unsigned char *section_at[16];
static uint32_t section_len[16];
static unsigned char section_load[16][4096];
static unsigned char section_after[16][4096];
static int sections;
static void find_writable_sections(void) {{
    unsigned char *pe = g_base + *(uint32_t *)(g_base + 0x3c);
    unsigned count = *(uint16_t *)(pe + 6);
    unsigned char *header = pe + 24 + *(uint16_t *)(pe + 20);
    for (unsigned i = 0; i < count && sections < 16; i++, header += 40) {{
        if (!(*(uint32_t *)(header + 36) & 0x80000000u)) continue;
        uint32_t size = *(uint32_t *)(header + 8);
        section_at[sections] = g_base + *(uint32_t *)(header + 12);
        section_len[sections] = size < 4096 ? size : 4096;
        memcpy(section_load[sections], section_at[sections], section_len[sections]);
        sections++;
    }}
}}
static void restore_sections(void) {{
    for (int i = 0; i < sections; i++) memcpy(section_at[i], section_load[i], section_len[i]);
}}
static void keep_sections(void) {{
    for (int i = 0; i < sections; i++) memcpy(section_after[i], section_at[i], section_len[i]);
}}
static int sections_match(void) {{
    for (int i = 0; i < sections; i++) if (memcmp(section_after[i], section_at[i], section_len[i])) return 0;
    return 1;
}}
int main(void) {{
    g_base = (unsigned char *)LoadLibraryA("{dll}");
    if ((uint64_t)(uintptr_t)g_base != {image_base:#x}ULL) {{ printf("relocated\n"); return 3; }}
    find_writable_sections();
    unsigned valid = 0, equal = 0, differ = 0;
    uint64_t v[16];
    while (valid < {valid_inputs}) {{
        for (int i = 0; i < 16; i++) v[i] = pick();
        restore_sections();
        uint64_t a = {original_call};
        keep_sections();
        restore_sections();
        uint64_t b = {other_call};
        int same = sections_match();
        valid++;
        if (((a ^ b) & {mask:#x}ULL) == 0 && same) equal++; else differ++;
    }}
    printf("result valid=%u equal=%u differ=%u\n", valid, equal, differ);
    return 0;
}}
"#,
        dll = image.path.file_name().unwrap().to_str().unwrap(),
        image_base = image.preferred_base,
        valid_inputs = VALID_INPUTS,
    )
}

fn run_harness(image: &Image, source: &str, tag: &str) -> Result<Grade, String> {
    let scratch: ScratchDir = scratch_dir("disrobe-msvc-decompile-behaviour");
    let dir: &Path = scratch.path();
    std::fs::copy(&image.path, dir.join(image.path.file_name().unwrap()))
        .expect("stage the fixture dll");
    let c_path: PathBuf = dir.join(format!("{tag}.c"));
    let exe_path: PathBuf = dir.join(format!("{tag}.exe"));
    std::fs::write(&c_path, source).expect("write the harness");
    let compiler: String = compiler_toolchain::require_one("clang");
    let args: Vec<std::ffi::OsString> = vec![
        "-O1".into(),
        "-w".into(),
        "-o".into(),
        exe_path.clone().into_os_string(),
        c_path.into_os_string(),
    ];
    let compiled: CapturedOutput = run_captured(
        Path::new(&compiler),
        &args,
        COMPILE_TIMEOUT,
        MAX_CAPTURE_BYTES,
    )
    .expect("spawn clang")
    .expect("clang finishes within the compile timeout");
    assert_eq!(
        compiled.exit_code,
        Some(0),
        "{tag}: the recovered C must compile: {}\n{source}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let no_args: [&str; 0] = [];
    let ran: CapturedOutput = run_captured(&exe_path, &no_args, RUN_TIMEOUT, MAX_CAPTURE_BYTES)
        .expect("spawn the harness")
        .expect("the harness finishes within its timeout");
    let stdout: String = String::from_utf8_lossy(&ran.stdout).into_owned();
    if ran.exit_code != Some(0) {
        return Err(format!(
            "{tag}: the harness exited with {:?}: {stdout}",
            ran.exit_code
        ));
    }
    let line: &str = stdout
        .lines()
        .find(|line: &&str| line.starts_with("result "))
        .unwrap_or_else(|| panic!("{tag}: no result line: {stdout}"));
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

fn grade_fixture(fixture: &Fixture) {
    let image: Image = load_image(fixture.dll);
    for case in fixture.cases {
        let address: u64 = target_address(&image, case.target);
        let function: &RecoveredFunction = recovered_at(&image, address);
        let tag: String = format!("f_{address:x}");
        let null: Grade = run_harness(
            &image,
            &harness_source(
                &image,
                function,
                case,
                &function.source,
                Mode::OriginalTwice,
            ),
            &format!("{tag}_null"),
        )
        .unwrap_or_else(|failure: String| panic!("{failure}"));
        assert_eq!(
            null,
            Grade {
                valid: VALID_INPUTS,
                equal: VALID_INPUTS,
                differ: 0
            },
            "{tag}: the original-against-original null control must agree on every input"
        );
        let recovered: Grade = run_harness(
            &image,
            &harness_source(&image, function, case, &function.source, Mode::Recovered),
            &format!("{tag}_recovered"),
        )
        .unwrap_or_else(|failure: String| panic!("{failure}"));
        assert_eq!(
            recovered,
            Grade {
                valid: VALID_INPUTS,
                equal: VALID_INPUTS,
                differ: 0
            },
            "{tag}: the recovered C must behave like the original on every input:\n{}",
            function.source
        );
        let mutated_source: String = (case.mutate_c)(&function.source);
        assert_ne!(
            mutated_source, function.source,
            "{tag}: the mutation control must change the source"
        );
        let mutated: Result<Grade, String> = run_harness(
            &image,
            &harness_source(&image, function, case, &mutated_source, Mode::Recovered),
            &format!("{tag}_mutated"),
        );
        assert!(
            mutated.as_ref().is_err()
                || mutated.as_ref().is_ok_and(|grade: &Grade| grade.differ > 0),
            "{tag}: the mutation control must turn the grade red: {mutated:?}\n{mutated_source}"
        );
    }
}

fn drop_stack_arguments(source: &str) -> String {
    let lines: Vec<String> = source
        .lines()
        .map(|line: &str| {
            if let Some(rest) = line.strip_prefix("extern uint64_t ") {
                let (name, params): (&str, &str) = rest.split_once('(').unwrap();
                let kept: Vec<&str> = params.trim_end_matches(");").split(", ").take(4).collect();
                return format!("extern uint64_t {name}({});", kept.join(", "));
            }
            let Some(start): Option<usize> = line.find(", r_x86_out0") else {
                return line.to_owned();
            };
            let end: usize = line[start..]
                .find(')')
                .map(|offset: usize| start + offset)
                .unwrap();
            let call: String = format!("{}{}", &line[..start], &line[end..]);
            let pointer: &str = "(uint64_t (*)(";
            let Some(open): Option<usize> = call.find(pointer) else {
                return call;
            };
            let params_start: usize = open + pointer.len();
            let params_end: usize = call[params_start..]
                .find(')')
                .map(|offset: usize| params_start + offset)
                .unwrap();
            format!(
                "{}uint64_t, uint64_t, uint64_t, uint64_t{}",
                &call[..params_start],
                &call[params_end..]
            )
        })
        .collect();
    lines.join("\n")
}

fn pass_a_register_for_the_null_argument(source: &str) -> String {
    source.replacen("r_r9, r_x86_out0)", "r_r9, r_r8)", 1)
}

fn swap_first_two_stack_parameters(source: &str) -> String {
    source
        .replacen("r_x86_stack0", "r_x86_stack_swap", 1)
        .replacen("r_x86_stack1", "r_x86_stack0", 1)
        .replacen("r_x86_stack_swap", "r_x86_stack1", 1)
}

pub(super) const STACK_ARGS: Fixture = Fixture {
    dll: "stack_args/stack_args.dll",
    cases: &[
        Case {
            target: Target::Export("pass_six"),
            params: 2,
            return_bits: 64,
            mutate_c: drop_stack_arguments,
            mutate_rust: rust_add_one_to_every_returned_value,
        },
        Case {
            target: Target::Export("pass_unresolved"),
            params: 2,
            return_bits: 64,
            mutate_c: drop_stack_arguments,
            mutate_rust: rust_add_one_to_every_returned_value,
        },
        Case {
            target: Target::Export("pass_null"),
            params: 2,
            return_bits: 64,
            mutate_c: pass_a_register_for_the_null_argument,
            mutate_rust: rust_add_one_to_every_returned_value,
        },
        Case {
            target: Target::Export("pass_five_int"),
            params: 2,
            return_bits: 32,
            mutate_c: drop_stack_arguments,
            mutate_rust: rust_add_one_to_every_returned_value,
        },
        Case {
            target: Target::JumpThunk("call_mix6"),
            params: 6,
            return_bits: 64,
            mutate_c: swap_first_two_stack_parameters,
            mutate_rust: rust_add_one_to_every_returned_value,
        },
        Case {
            target: Target::JumpThunk("call_mix7"),
            params: 7,
            return_bits: 32,
            mutate_c: swap_first_two_stack_parameters,
            mutate_rust: rust_add_one_to_every_returned_value,
        },
    ],
};

#[test]
fn msvc_o2_outgoing_stack_arguments_behave_like_the_original() {
    let source: String =
        std::fs::read_to_string(fixture_path("stack_args/stack_args.c")).expect("fixture source");
    assert!(source.contains(
        "int64_t mix6(int64_t a, int64_t b, int64_t c, int64_t d, int64_t e, int64_t f)"
    ));
    grade_fixture(&STACK_ARGS);
}

fn store_the_rcx_home_save_at_its_entry_displacement(source: &str) -> String {
    source.replacen(
        "(int64_t)96LL))->value) = r_rcx;",
        "(int64_t)8LL))->value) = r_rcx;",
        1,
    )
}

fn scale_the_first_product_differently(source: &str) -> String {
    source.replacen("(uint64_t)(int64_t)11LL", "(uint64_t)(int64_t)13LL", 1)
}

fn add_one_to_the_first_return(source: &str) -> String {
    source.replacen("    return ", "    return 1 + ", 1)
}

pub(super) const PUSH_FRAMES: Fixture = Fixture {
    dll: "push_frames/push_frames.dll",
    cases: &[
        Case {
            target: Target::Export("pass_seven_twice"),
            params: 3,
            return_bits: 32,
            mutate_c: drop_stack_arguments,
            mutate_rust: rust_add_one_to_every_returned_value,
        },
        Case {
            target: Target::Export("spill_across_calls"),
            params: 4,
            return_bits: 64,
            mutate_c: store_the_rcx_home_save_at_its_entry_displacement,
            mutate_rust: rust_add_one_to_every_returned_value,
        },
        Case {
            target: Target::Export("stack_args_across_call"),
            params: 6,
            return_bits: 64,
            mutate_c: swap_first_two_stack_parameters,
            mutate_rust: rust_add_one_to_every_returned_value,
        },
        Case {
            target: Target::Export("keep_across_calls"),
            params: 4,
            return_bits: 64,
            mutate_c: scale_the_first_product_differently,
            mutate_rust: rust_add_one_to_every_returned_value,
        },
        Case {
            target: Target::Export("chain_calls"),
            params: 2,
            return_bits: 64,
            mutate_c: add_one_to_the_first_return,
            mutate_rust: rust_add_one_to_every_returned_value,
        },
        Case {
            target: Target::Export("wide_leaf"),
            params: 6,
            return_bits: 64,
            mutate_c: swap_first_two_stack_parameters,
            mutate_rust: rust_add_one_to_every_returned_value,
        },
    ],
};

#[test]
fn msvc_o2_push_built_frames_behave_like_the_original() {
    let source: String =
        std::fs::read_to_string(fixture_path("push_frames/push_frames.c")).expect("fixture source");
    assert!(
        source.contains("int64_t spill_across_calls(int64_t a, int64_t b, int64_t c, int64_t d)")
    );
    grade_fixture(&PUSH_FRAMES);
}

fn exchange_the_multiplier_and_the_divisor(source: &str) -> String {
    source.replacen(
        "(r_rcx, r_rdx, r_r8, r_r9)",
        "(r_rcx, r_r8, r_rdx, r_r9)",
        1,
    )
}

fn swap_the_first_two_call_arguments(source: &str) -> String {
    source.replacen(
        "(r_rcx, r_rdx, r_r8, r_r9)",
        "(r_rdx, r_rcx, r_r8, r_r9)",
        1,
    )
}

pub(super) const SLOT_CALLS: Fixture = Fixture {
    dll: "slot_calls/slot_calls.dll",
    cases: &[
        Case {
            target: Target::Export("scale_by_import"),
            params: 3,
            return_bits: 32,
            mutate_c: exchange_the_multiplier_and_the_divisor,
            mutate_rust: rust_add_one_to_every_returned_value,
        },
        Case {
            target: Target::Export("compare_through_import"),
            params: 2,
            return_bits: 32,
            mutate_c: drop_stack_arguments,
            mutate_rust: rust_add_one_to_every_returned_value,
        },
        Case {
            target: Target::Export("call_through_global"),
            params: 2,
            return_bits: 64,
            mutate_c: swap_the_first_two_call_arguments,
            mutate_rust: rust_add_one_to_every_returned_value,
        },
        Case {
            target: Target::Export("call_through_register"),
            params: 3,
            return_bits: 64,
            mutate_c: add_one_to_the_first_return,
            mutate_rust: rust_add_one_to_every_returned_value,
        },
        Case {
            target: Target::Export("release_twice"),
            params: 2,
            return_bits: 64,
            mutate_c: add_one_to_the_first_return,
            mutate_rust: rust_add_one_to_every_returned_value,
        },
    ],
};

#[test]
fn msvc_o2_calls_through_import_and_pointer_slots_behave_like_the_original() {
    let source: String =
        std::fs::read_to_string(fixture_path("slot_calls/slot_calls.c")).expect("fixture source");
    assert!(source.contains("return MulDiv(a, b, c) + 1;"));
    grade_fixture(&SLOT_CALLS);
    let image: Image = load_image("slot_calls/slot_calls.dll");
    let scale: &RecoveredFunction = recovered_at(
        &image,
        target_address(&image, Target::Export("scale_by_import")),
    );
    assert!(
        scale.source.contains("/* import MulDiv */"),
        "{}",
        scale.source
    );
    let rounding: u64 = target_address(&image, Target::Export("round_through_import"));
    let refusal: &str = image
        .program
        .unrecovered
        .iter()
        .find(|function| function.address == rounding)
        .map(|function| function.reason.as_str())
        .expect("a double passed to an import of unknown signature is refused");
    assert!(refusal.contains("floating-point argument"), "{refusal}");
}

fn store_the_counter_one_word_higher(source: &str) -> String {
    source.replacen(
        "(uintptr_t)((uint64_t)0x180003000ULL))->value) = ",
        "(uintptr_t)((uint64_t)0x180003008ULL))->value) = ",
        1,
    )
}

fn test_a_different_bit(source: &str) -> String {
    source
        .replacen("& 0x10ULL) == 0", "& 0x20ULL) == 0", 1)
        .replacen("& 0x2ULL) == 0", "& 0x1ULL) == 0", 1)
}

fn test_the_complement(source: &str) -> String {
    source.replacen(
        "r_x86_scratch = r_x86_scratch & (r_rax);",
        "r_x86_scratch = r_x86_scratch & ~(r_rax);",
        1,
    )
}

fn flip_the_written_mode(source: &str) -> String {
    source.replacen(
        "^ ((uint64_t)(int64_t)3LL)",
        "^ ((uint64_t)(int64_t)5LL)",
        1,
    )
}

pub(super) const GLOBALS: Fixture = Fixture {
    dll: "globals/globals.dll",
    cases: &[
        Case {
            target: Target::Export("bump"),
            params: 1,
            return_bits: 64,
            mutate_c: store_the_counter_one_word_higher,
            mutate_rust: rust_add_one_to_every_returned_value,
        },
        Case {
            target: Target::Export("clamp_counter"),
            params: 1,
            return_bits: 64,
            mutate_c: store_the_counter_one_word_higher,
            mutate_rust: rust_add_one_to_every_returned_value,
        },
        Case {
            target: Target::Export("set_mode"),
            params: 1,
            return_bits: 0,
            mutate_c: flip_the_written_mode,
            mutate_rust: rust_write_one_more_at_the_first_store,
        },
        Case {
            target: Target::Export("mode_flags"),
            params: 1,
            return_bits: 32,
            mutate_c: add_one_to_the_first_return,
            mutate_rust: rust_add_one_to_every_returned_value,
        },
        Case {
            target: Target::Export("table_pick"),
            params: 1,
            return_bits: 32,
            mutate_c: add_one_to_the_first_return,
            mutate_rust: rust_add_one_to_every_returned_value,
        },
        Case {
            target: Target::Export("bits_select"),
            params: 1,
            return_bits: 32,
            mutate_c: test_a_different_bit,
            mutate_rust: rust_add_one_to_every_returned_value,
        },
        Case {
            target: Target::Export("byte_table_test"),
            params: 1,
            return_bits: 32,
            mutate_c: test_a_different_bit,
            mutate_rust: rust_add_one_to_every_returned_value,
        },
        Case {
            target: Target::Export("masked_counter"),
            params: 1,
            return_bits: 64,
            mutate_c: test_the_complement,
            mutate_rust: rust_add_one_to_every_returned_value,
        },
        Case {
            target: Target::Export("bits_test"),
            params: 1,
            return_bits: 32,
            mutate_c: add_one_to_the_first_return,
            mutate_rust: rust_add_one_to_every_returned_value,
        },
        Case {
            target: Target::Export("toggle_flags"),
            params: 1,
            return_bits: 32,
            mutate_c: add_one_to_the_first_return,
            mutate_rust: rust_add_one_to_every_returned_value,
        },
    ],
};

#[test]
fn msvc_o2_rip_relative_globals_behave_like_the_original() {
    let source: String =
        std::fs::read_to_string(fixture_path("globals/globals.c")).expect("fixture source");
    assert!(source.contains("g_counter += by;"));
    grade_fixture(&GLOBALS);
}

fn store_one_where_the_buffer_is_zeroed(source: &str) -> String {
    source.replacen(
        "->value) = (uint64_t)(int64_t)0LL;",
        "->value) = (uint64_t)(int64_t)1LL;",
        1,
    )
}

pub(super) const ADDRESS_TAKEN: Fixture = Fixture {
    dll: "address_taken/address_taken.dll",
    cases: &[
        Case {
            target: Target::Export("through_struct"),
            params: 1,
            return_bits: 64,
            mutate_c: add_one_to_the_first_return,
            mutate_rust: rust_add_one_to_every_returned_value,
        },
        Case {
            target: Target::Export("through_array"),
            params: 1,
            return_bits: 32,
            mutate_c: add_one_to_the_first_return,
            mutate_rust: rust_add_one_to_every_returned_value,
        },
        Case {
            target: Target::Export("guarded_scan"),
            params: 2,
            return_bits: 32,
            mutate_c: store_one_where_the_buffer_is_zeroed,
            mutate_rust: rust_add_one_to_every_returned_value,
        },
        Case {
            target: Target::Export("call_va"),
            params: 2,
            return_bits: 64,
            mutate_c: drop_stack_arguments,
            mutate_rust: rust_add_one_to_every_returned_value,
        },
    ],
};

#[test]
fn msvc_o2_address_taken_locals_behave_like_the_original() {
    let source: String = std::fs::read_to_string(fixture_path("address_taken/address_taken.c"))
        .expect("fixture source");
    assert!(source.contains("fill_pair(&p, value);"));
    grade_fixture(&ADDRESS_TAKEN);
    let image: Image = load_image("address_taken/address_taken.dll");
    let out_params: u64 = target_address(&image, Target::Export("through_out_params"));
    let refusal: &str = image
        .program
        .unrecovered
        .iter()
        .find(|function| function.address == out_params)
        .map(|function| function.reason.as_str())
        .expect("out-parameters kept in the home area are refused");
    assert!(refusal.contains("taken outside"), "{refusal}");
    assert!(
        image.program.unrecovered.iter().any(|function| {
            function.reason.contains("va_list") && function.address != out_params
        }),
        "the variadic callee that walks its home area must be refused: {:?}",
        image.program.unrecovered
    );
}
