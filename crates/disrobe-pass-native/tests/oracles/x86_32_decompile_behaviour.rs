#![cfg(all(windows, target_arch = "x86_64"))]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_native::{
    ProgramFunction, PseudoAbi, RecoveredFunction, RecoveredProgram, build_disasm_payload,
    recover_program,
};
use object::{Object as _, ObjectSection as _, ObjectSegment as _};

use crate::common::{COMPILE_TIMEOUT, MAX_CAPTURE_BYTES, scratch_dir};
use crate::compiler_toolchain;

const FIXTURE_ROOT: &str = "corpus/native/decompile32";
const VALID_INPUTS: u32 = 1000;
const RUN_TIMEOUT: Duration = Duration::from_mins(2);
const ARENA_WORDS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arg {
    I32,
    I64,
    Ptr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ret {
    I32,
    I64,
    Void,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Conv {
    Cdecl,
    Stdcall,
    Fastcall,
    Thiscall,
}

impl Conv {
    const fn attribute(self) -> &'static str {
        match self {
            Self::Cdecl => "",
            Self::Stdcall => "__attribute__((stdcall))",
            Self::Fastcall => "__attribute__((fastcall))",
            Self::Thiscall => "__attribute__((thiscall))",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    Equal,
    Refused(&'static str),
}

#[derive(Debug, Clone, Copy)]
struct Case {
    name: &'static str,
    group: &'static str,
    conv: Conv,
    params: &'static [Arg],
    ret: Ret,
    expect: Expect,
}

const fn case(
    name: &'static str,
    group: &'static str,
    conv: Conv,
    params: &'static [Arg],
    ret: Ret,
) -> Case {
    Case {
        name,
        group,
        conv,
        params,
        ret,
        expect: Expect::Equal,
    }
}

const CONVENTION_CASES: [Case; 22] = [
    case("cd_add3", "cdecl", Conv::Cdecl, &[Arg::I32; 3], Ret::I32),
    case("cd_clamp", "cdecl", Conv::Cdecl, &[Arg::I32; 3], Ret::I32),
    case("cd_mix", "cdecl", Conv::Cdecl, &[Arg::I32; 2], Ret::I32),
    case("cd_many", "cdecl", Conv::Cdecl, &[Arg::I32; 7], Ret::I32),
    case("cd_add64", "edx:eax", Conv::Cdecl, &[Arg::I64; 2], Ret::I64),
    case("cd_sub64", "edx:eax", Conv::Cdecl, &[Arg::I64; 2], Ret::I64),
    case("cd_widen", "edx:eax", Conv::Cdecl, &[Arg::I32; 2], Ret::I64),
    case(
        "cd_chain",
        "cdecl calls",
        Conv::Cdecl,
        &[Arg::I32; 2],
        Ret::I32,
    ),
    case(
        "cd_keep",
        "cdecl calls",
        Conv::Cdecl,
        &[Arg::I32; 3],
        Ret::I32,
    ),
    case("sc_sub", "stdcall", Conv::Stdcall, &[Arg::I32; 2], Ret::I32),
    case(
        "sc_select",
        "stdcall",
        Conv::Stdcall,
        &[Arg::I32; 3],
        Ret::I32,
    ),
    case(
        "cd_calls_stdcall",
        "stdcall calls",
        Conv::Cdecl,
        &[Arg::I32; 2],
        Ret::I32,
    ),
    case(
        "fc_lin",
        "fastcall",
        Conv::Fastcall,
        &[Arg::I32; 3],
        Ret::I32,
    ),
    case("fc_one", "fastcall", Conv::Fastcall, &[Arg::I32], Ret::I32),
    case(
        "cd_calls_fastcall",
        "fastcall calls",
        Conv::Cdecl,
        &[Arg::I32],
        Ret::I32,
    ),
    case(
        "tc_get",
        "thiscall",
        Conv::Thiscall,
        &[Arg::Ptr, Arg::I32],
        Ret::I32,
    ),
    case(
        "tc_add",
        "thiscall",
        Conv::Thiscall,
        &[Arg::Ptr, Arg::I32],
        Ret::Void,
    ),
    case(
        "cd_calls_thiscall",
        "thiscall calls",
        Conv::Cdecl,
        &[Arg::Ptr, Arg::I32],
        Ret::I32,
    ),
    case(
        "g_table_pick",
        "globals",
        Conv::Cdecl,
        &[Arg::I32],
        Ret::I32,
    ),
    case("g_bump", "globals", Conv::Cdecl, &[Arg::I32], Ret::I32),
    Case {
        name: "fp_half",
        group: "x87 return",
        conv: Conv::Cdecl,
        params: &[Arg::I32],
        ret: Ret::Void,
        expect: Expect::Refused("x87"),
    },
    Case {
        name: "fp_scale",
        group: "x87 return",
        conv: Conv::Cdecl,
        params: &[Arg::I32; 2],
        ret: Ret::Void,
        expect: Expect::Refused("x87"),
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Pe,
    Elf,
}

#[derive(Debug, Clone, Copy)]
struct Build {
    file: &'static str,
    toolchain: &'static str,
    level: &'static str,
    format: Format,
    has_thiscall: bool,
}

const fn build(
    file: &'static str,
    toolchain: &'static str,
    level: &'static str,
    format: Format,
    has_thiscall: bool,
) -> Build {
    Build {
        file,
        toolchain,
        level,
        format,
        has_thiscall,
    }
}

const PIC_THUNK_CASES: [Case; 3] = [
    case(
        "thunk_table_pick",
        "PIC thunk",
        Conv::Cdecl,
        &[Arg::I32],
        Ret::I32,
    ),
    case(
        "thunk_bump",
        "PIC thunk",
        Conv::Cdecl,
        &[Arg::I32],
        Ret::I32,
    ),
    case(
        "thunk_call_pop",
        "PIC call/pop",
        Conv::Cdecl,
        &[Arg::I32],
        Ret::I32,
    ),
];

const MSVC_THISCALL_CASES: [Case; 4] = [
    case(
        "get",
        "thiscall",
        Conv::Thiscall,
        &[Arg::Ptr, Arg::I32],
        Ret::I32,
    ),
    case(
        "add",
        "thiscall",
        Conv::Thiscall,
        &[Arg::Ptr, Arg::I32],
        Ret::Void,
    ),
    case(
        "add_then_get",
        "thiscall calls",
        Conv::Thiscall,
        &[Arg::Ptr, Arg::I32],
        Ret::I32,
    ),
    case(
        "mix",
        "thiscall",
        Conv::Thiscall,
        &[Arg::Ptr, Arg::I32, Arg::I32, Arg::I32],
        Ret::I32,
    ),
];

const PIC_THUNK_BUILDS: [Build; 1] = [build(
    "pic_thunk/pic_thunk.so",
    "authored ELF PIC",
    "asm",
    Format::Elf,
    true,
)];

const MSVC_THISCALL_BUILDS: [Build; 3] = [
    build(
        "thiscall_msvc/thiscall_msvc_o0.dll",
        "MSVC C++ PE",
        "/Od",
        Format::Pe,
        true,
    ),
    build(
        "thiscall_msvc/thiscall_msvc_o1.dll",
        "MSVC C++ PE",
        "/O1",
        Format::Pe,
        true,
    ),
    build(
        "thiscall_msvc/thiscall_msvc_o2.dll",
        "MSVC C++ PE",
        "/O2",
        Format::Pe,
        true,
    ),
];

const CONVENTION_BUILDS: [Build; 12] = [
    build(
        "conventions/conventions_clang_o0.dll",
        "clang PE",
        "-O0",
        Format::Pe,
        true,
    ),
    build(
        "conventions/conventions_clang_o1.dll",
        "clang PE",
        "-O1",
        Format::Pe,
        true,
    ),
    build(
        "conventions/conventions_clang_o2.dll",
        "clang PE",
        "-O2",
        Format::Pe,
        true,
    ),
    build(
        "conventions/conventions_gcc_o0.dll",
        "gcc PE",
        "-O0",
        Format::Pe,
        true,
    ),
    build(
        "conventions/conventions_gcc_o1.dll",
        "gcc PE",
        "-O1",
        Format::Pe,
        true,
    ),
    build(
        "conventions/conventions_gcc_o2.dll",
        "gcc PE",
        "-O2",
        Format::Pe,
        true,
    ),
    build(
        "conventions/conventions_msvc_o0.dll",
        "MSVC PE",
        "/Od",
        Format::Pe,
        false,
    ),
    build(
        "conventions/conventions_msvc_o1.dll",
        "MSVC PE",
        "/O1",
        Format::Pe,
        false,
    ),
    build(
        "conventions/conventions_msvc_o2.dll",
        "MSVC PE",
        "/O2",
        Format::Pe,
        false,
    ),
    build(
        "conventions/conventions_elf_o0.so",
        "clang ELF PIC",
        "-O0",
        Format::Elf,
        true,
    ),
    build(
        "conventions/conventions_elf_o1.so",
        "clang ELF PIC",
        "-O1",
        Format::Elf,
        true,
    ),
    build(
        "conventions/conventions_elf_o2.so",
        "clang ELF PIC",
        "-O2",
        Format::Elf,
        true,
    ),
];

struct Image {
    bytes: Vec<u8>,
    path: PathBuf,
    format: Format,
    base: u64,
    program: RecoveredProgram,
    names: BTreeMap<String, u64>,
}

fn fixture_path(relative: &str) -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root.join(FIXTURE_ROOT).join(relative)
}

fn undecorated(name: &str) -> &str {
    let trimmed: &str = name
        .strip_prefix('?')
        .unwrap_or_else(|| name.trim_start_matches(['_', '@']));
    trimmed.split('@').next().unwrap_or(trimmed)
}

fn c_identifier(name: &str) -> String {
    undecorated(name)
        .chars()
        .map(|c: char| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
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

fn load_image(fixture: &Build) -> Image {
    let path: PathBuf = fixture_path(fixture.file);
    let bytes: Vec<u8> = std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "the committed fixture {} must exist: {error}",
            path.display()
        )
    });
    let payload = build_disasm_payload(&bytes).expect("the fixture disassembles");
    let module: disrobe_query::Module = disrobe_query::Module::from_disasm(&payload);
    let file: object::File<'_> = object::File::parse(bytes.as_slice()).expect("the fixture parses");
    assert_eq!(file.architecture(), object::Architecture::I386);
    let base: u64 = match fixture.format {
        Format::Pe => file.relative_address_base(),
        Format::Elf => file
            .segments()
            .map(|segment: object::Segment<'_, '_>| segment.address())
            .min()
            .expect("the shared object has a load segment"),
    };
    let mut functions: Vec<ProgramFunction> = Vec::new();
    let mut names: BTreeMap<String, u64> = BTreeMap::new();
    for function in module.functions() {
        let Some(code): Option<Vec<u8>> = mapped_bytes(&file, function.address, function.end)
        else {
            continue;
        };
        let name: String = c_identifier(&function.name);
        names.insert(name.clone(), function.address);
        functions.push(ProgramFunction {
            name,
            address: function.address,
            code,
        });
    }
    let program: RecoveredProgram = recover_program(&bytes, &functions, PseudoAbi::I386);
    Image {
        bytes,
        path,
        format: fixture.format,
        base,
        program,
        names,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Missing,
    Refused(String),
    Recovered,
}

fn outcome(image: &Image, address: u64) -> (Outcome, Option<&RecoveredFunction>) {
    if let Some(function) = image
        .program
        .recovered
        .iter()
        .find(|function: &&RecoveredFunction| function.address == address)
    {
        return (Outcome::Recovered, Some(function));
    }
    let reason: Option<String> = image
        .program
        .unrecovered
        .iter()
        .find(|function| function.address == address)
        .map(|function| function.reason.clone());
    (reason.map_or(Outcome::Missing, Outcome::Refused), None)
}

fn split_prototype(line: &str) -> Option<(String, String, Vec<String>)> {
    let declaration: &str = line.trim().strip_prefix("extern ")?.strip_suffix(';')?;
    let open: usize = declaration.rfind('(')?;
    let params: &str = declaration[open + 1..].strip_suffix(')')?;
    let head: &str = declaration[..open].trim_end();
    let name_start: usize = head.rfind(' ')? + 1;
    let name: String = head[name_start..].to_owned();
    let returned: String = head[..name_start].trim_end().to_owned();
    let params: Vec<String> = if params == "void" {
        Vec::new()
    } else {
        params
            .split(',')
            .map(|p: &str| p.trim().to_owned())
            .collect()
    };
    Some((returned, name, params))
}

struct Unit {
    file: String,
    text: String,
}

fn recovered_unit(
    source: &str,
    function_name: &str,
    renamed: &str,
    bridges: &mut BTreeMap<String, String>,
    image: &Image,
) -> Unit {
    let mut kept: Vec<String> = Vec::new();
    for line in source.lines() {
        if let Some((returned, name, params)) = split_prototype(line) {
            let target: u64 = *image
                .names
                .get(&name)
                .or_else(|| {
                    name.strip_prefix("sub_")
                        .and_then(|hex: &str| u64::from_str_radix(hex, 16).ok())
                        .as_ref()
                        .and_then(|address: &u64| {
                            image
                                .names
                                .values()
                                .find(|known: &&u64| **known == *address)
                        })
                })
                .unwrap_or_else(|| panic!("extern `{name}` has no address in the fixture"));
            let typed: Vec<String> = params
                .iter()
                .enumerate()
                .map(|(i, ty): (usize, &String)| format!("{ty} b{i}"))
                .collect();
            let forwarded: Vec<String> =
                (0..params.len()).map(|i: usize| format!("b{i}")).collect();
            let (ret_type, attribute): (&str, &str) = returned
                .split_once(' ')
                .map_or((returned.as_str(), ""), |(ret, attr): (&str, &str)| {
                    (ret, attr)
                });
            let pointer: String = format!(
                "{ret_type} ({attribute} *)({})",
                if params.is_empty() {
                    "void".to_owned()
                } else {
                    params.join(", ")
                }
            );
            bridges.entry(name.clone()).or_insert_with(|| {
                format!(
                    "{returned} {name}({}) {{ return (({pointer})(uintptr_t){target:#x}u)({}); }}",
                    if typed.is_empty() {
                        "void".to_owned()
                    } else {
                        typed.join(", ")
                    },
                    forwarded.join(", ")
                )
            });
            kept.push(line.to_owned());
            continue;
        }
        kept.push(line.to_owned());
    }
    let text: String =
        kept.join("\n")
            .replacen(&format!("{function_name}("), &format!("{renamed}("), 1);
    Unit {
        file: format!("{renamed}.c"),
        text,
    }
}

fn arg_words(params: &[Arg]) -> usize {
    params
        .iter()
        .map(|arg: &Arg| match arg {
            Arg::I32 | Arg::Ptr => 1,
            Arg::I64 => 2,
        })
        .sum()
}

fn original_call(case: &Case, address: u64) -> String {
    let mut types: Vec<&str> = Vec::new();
    let mut values: Vec<String> = Vec::new();
    let mut word: usize = 0;
    for arg in case.params {
        match arg {
            Arg::I32 => {
                types.push("int32_t");
                values.push(format!("(int32_t)w[{word}]"));
                word += 1;
            }
            Arg::Ptr => {
                types.push("void *");
                values.push(format!("(void *)(uintptr_t)w[{word}]"));
                word += 1;
            }
            Arg::I64 => {
                types.push("int64_t");
                values.push(format!(
                    "(int64_t)((uint64_t)w[{word}] | ((uint64_t)w[{}] << 32))",
                    word + 1
                ));
                word += 2;
            }
        }
    }
    let returned: &str = match case.ret {
        Ret::I32 => "uint32_t",
        Ret::I64 => "uint64_t",
        Ret::Void => "void",
    };
    let call: String = format!(
        "(({returned} ({} *)({}))(uintptr_t){address:#x}u)({})",
        case.conv.attribute(),
        types.join(", "),
        values.join(", ")
    );
    match case.ret {
        Ret::Void => format!("({call}, 0ull)"),
        Ret::I32 | Ret::I64 => format!("(uint64_t){call}"),
    }
}

fn recovered_call(case: &Case, renamed: &str, arity: usize) -> String {
    let args: Vec<String> = (0..arity).map(|i: usize| format!("w[{i}]")).collect();
    match case.ret {
        Ret::Void => format!("({renamed}({}), 0ull)", args.join(", ")),
        Ret::I32 | Ret::I64 => format!("(uint64_t){renamed}({})", args.join(", ")),
    }
}

const fn return_mask(ret: Ret) -> u64 {
    match ret {
        Ret::I32 => 0xffff_ffff,
        Ret::I64 => u64::MAX,
        Ret::Void => 0,
    }
}

fn add_one_to_the_first_return(source: &str) -> String {
    source.replacen("    return ", "    return 1 + ", 1)
}

fn store_one_more(source: &str) -> String {
    let mut done: bool = false;
    source
        .lines()
        .map(|line: &str| {
            let store: bool = line
                .split_once(" = ")
                .is_some_and(|(target, _): (&str, &str)| {
                    target.contains("->") && !target.contains("r_rsp")
                });
            if done || !store {
                return line.to_owned();
            }
            done = true;
            line.replacen(" = ", " = 1 + ", 1)
        })
        .collect::<Vec<String>>()
        .join(
            "
",
        )
        + "
"
}

fn mutate(case: &Case, source: &str) -> String {
    match case.ret {
        Ret::Void => store_one_more(source),
        Ret::I32 | Ret::I64 => add_one_to_the_first_return(source),
    }
}

fn writable_ranges(image: &Image) -> Vec<(u64, u64)> {
    let file: object::File<'_> = object::File::parse(image.bytes.as_slice()).unwrap();
    match image.format {
        Format::Pe => file
            .sections()
            .filter(|section: &object::Section<'_, '_>| {
                matches!(
                    section.flags(),
                    object::SectionFlags::Coff { characteristics }
                        if characteristics & 0x8000_0000 != 0
                )
            })
            .map(|section: object::Section<'_, '_>| {
                (section.address(), section.address() + section.size())
            })
            .collect(),
        Format::Elf => file
            .segments()
            .filter(|segment: &object::Segment<'_, '_>| {
                matches!(segment.flags(), object::SegmentFlags::Elf { p_flags } if p_flags & 2 != 0)
            })
            .map(|segment: object::Segment<'_, '_>| {
                (segment.address(), segment.address() + segment.size())
            })
            .collect(),
    }
}

fn elf_image_array(image: &Image) -> (String, u64) {
    let file: object::File<'_> = object::File::parse(image.bytes.as_slice()).unwrap();
    let end: u64 = file
        .segments()
        .map(|segment: object::Segment<'_, '_>| segment.address() + segment.size())
        .max()
        .unwrap();
    let size: u64 = (end - image.base + 0xfff) & !0xfff;
    let mut flat: Vec<u8> = vec![0; usize::try_from(size).unwrap()];
    for segment in file.segments() {
        let data: &[u8] = segment.data().unwrap();
        let at: usize = usize::try_from(segment.address() - image.base).unwrap();
        flat[at..at + data.len()].copy_from_slice(data);
    }
    let mut out: String = String::from("static const unsigned char g_image[] = {");
    for (index, byte) in flat.iter().enumerate() {
        if index % 32 == 0 {
            out.push('\n');
        }
        let _ = write!(out, "{byte},");
    }
    out.push_str("\n};\n");
    (out, size)
}

fn assert_only_relative_relocations(image: &Image) {
    let file: object::File<'_> = object::File::parse(image.bytes.as_slice()).unwrap();
    if let Some(relocations) = file.dynamic_relocations() {
        for (_, relocation) in relocations {
            assert!(
                matches!(relocation.flags(), object::RelocationFlags::Elf { r_type } if r_type == object::elf::R_386_RELATIVE),
                "the ELF fixture must load at its link address without symbol relocations: {relocation:?}"
            );
        }
    }
}

struct Graded {
    case: Case,
    renamed: String,
    mutated: String,
    address: u64,
    arity: usize,
}

fn harness(
    image: &Image,
    graded: &[Graded],
    units: &[Unit],
    bridges: &BTreeMap<String, String>,
) -> String {
    let mut out: String = String::from(
        "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n\
         __declspec(dllimport) void *__stdcall LoadLibraryA(const char *);\n\
         __declspec(dllimport) void *__stdcall VirtualAlloc(void *, uint32_t, uint32_t, uint32_t);\n",
    );
    for unit in units {
        for line in unit.text.lines() {
            if let Some(name) = line
                .trim_end()
                .strip_suffix('{')
                .filter(|_| !line.starts_with(' ') && line.contains('('))
                && (name.contains(" rec_") || name.contains(" mut_"))
            {
                let _ = writeln!(out, "{};", name.trim_end());
            }
        }
    }
    for bridge in bridges.values() {
        let _ = writeln!(out, "{bridge}");
    }
    let ranges: Vec<(u64, u64)> = writable_ranges(image);
    let _ = writeln!(
        out,
        "static unsigned char g_snapshot[{}][65536];",
        ranges.len().max(1)
    );
    let _ = writeln!(
        out,
        "static unsigned char g_after[{}][65536];",
        ranges.len().max(1)
    );
    let mut starts: String = String::new();
    let mut lengths: String = String::new();
    for (start, end) in &ranges {
        let _ = write!(starts, "{start:#x}u,");
        let _ = write!(lengths, "{}u,", (end - start).min(65536));
    }
    let _ = writeln!(out, "static const uint32_t g_range_at[] = {{{starts}0}};");
    let _ = writeln!(out, "static const uint32_t g_range_len[] = {{{lengths}0}};");
    let _ = writeln!(out, "static const int g_ranges = {};", ranges.len());
    if image.format == Format::Elf {
        let (array, size) = elf_image_array(image);
        out.push_str(&array);
        let _ = writeln!(
            out,
            "static int map_image(void) {{ unsigned char *at = VirtualAlloc((void *)(uintptr_t){:#x}u, {size}u, 0x3000u, 0x40u); if (at != (unsigned char *)(uintptr_t){:#x}u) return 0; memcpy(at, g_image, sizeof g_image); return 1; }}",
            image.base, image.base
        );
    } else {
        let _ = writeln!(
            out,
            "static int map_image(void) {{ return (uintptr_t)LoadLibraryA(\"{}\") == {:#x}u; }}",
            image.path.file_name().unwrap().to_str().unwrap(),
            image.base
        );
    }
    let _ = write!(
        out,
        r"static uint32_t g_arena[{ARENA_WORDS}];
static uint32_t g_arena_seed[{ARENA_WORDS}];
static uint32_t g_arena_after[{ARENA_WORDS}];
static uint64_t rng;
static uint64_t next(void) {{ rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }}
static uint32_t pick(void) {{
    uint64_t r = next();
    switch (r % 9) {{
    case 0: return 0;
    case 1: return 1;
    case 2: return 0xffffffffu;
    case 3: return (uint32_t)(next() % 64);
    case 4: return 0x7fffffffu;
    case 5: return 0x80000000u;
    case 6: return (uint32_t)(next() % 200) - 100u;
    default: return (uint32_t)next();
    }}
}}
static void restore(void) {{
    for (int i = 0; i < g_ranges; i++) memcpy((void *)(uintptr_t)g_range_at[i], g_snapshot[i], g_range_len[i]);
    memcpy(g_arena, g_arena_seed, sizeof g_arena);
}}
static void keep(void) {{
    for (int i = 0; i < g_ranges; i++) memcpy(g_after[i], (void *)(uintptr_t)g_range_at[i], g_range_len[i]);
    memcpy(g_arena_after, g_arena, sizeof g_arena);
}}
static int same(void) {{
    for (int i = 0; i < g_ranges; i++) if (memcmp(g_after[i], (void *)(uintptr_t)g_range_at[i], g_range_len[i])) return 0;
    return memcmp(g_arena_after, g_arena, sizeof g_arena) == 0;
}}
"
    );
    for (index, item) in graded.iter().enumerate() {
        let words: usize = arg_words(item.case.params).max(1);
        let pointer_words: Vec<usize> = {
            let mut at: usize = 0;
            let mut out: Vec<usize> = Vec::new();
            for arg in item.case.params {
                match arg {
                    Arg::Ptr => {
                        out.push(at);
                        at += 1;
                    }
                    Arg::I32 => at += 1,
                    Arg::I64 => at += 2,
                }
            }
            out
        };
        let mut pointers: String = String::new();
        for word in &pointer_words {
            let _ = write!(
                pointers,
                "w[{word}] = (uint32_t)(uintptr_t)&g_arena[(w[{word}] % {}) & ~3u];",
                ARENA_WORDS / 2
            );
        }
        let mask: u64 = return_mask(item.case.ret);
        let original: String = original_call(&item.case, item.address);
        let recovered: String = recovered_call(&item.case, &item.renamed, item.arity);
        let mutated: String = recovered_call(&item.case, &item.mutated, item.arity);
        let _ = write!(
            out,
            r#"static void grade_{index}(void) {{
    const char *modes[3] = {{"null", "recovered", "mutated"}};
    for (int mode = 0; mode < 3; mode++) {{
        unsigned valid = 0, equal = 0, differ = 0;
        rng = 0x2545f4914f6cdd1dULL ^ {index}u;
        while (valid < {VALID_INPUTS}u) {{
            uint32_t w[{words}];
            for (int i = 0; i < {words}; i++) w[i] = pick();
            {pointers}
            for (int i = 0; i < {ARENA_WORDS}; i++) g_arena_seed[i] = (uint32_t)next();
            restore();
            uint64_t a = {original};
            keep();
            restore();
            uint64_t b = mode == 0 ? {original} : mode == 1 ? {recovered} : {mutated};
            int memory = same();
            valid++;
            if (((a ^ b) & {mask:#x}ull) == 0 && memory) equal++; else differ++;
        }}
        printf("result {name} %s valid=%u equal=%u differ=%u\n", modes[mode], valid, equal, differ);
    }}
}}
"#,
            name = item.case.name,
        );
    }
    out.push_str(
        "int main(void) {\n    if (!map_image()) { printf(\"unmapped\\n\"); return 3; }\n",
    );
    out.push_str(
        "    for (int i = 0; i < g_ranges; i++) memcpy(g_snapshot[i], (void *)(uintptr_t)g_range_at[i], g_range_len[i]);\n",
    );
    for index in 0..graded.len() {
        let _ = writeln!(out, "    grade_{index}();");
    }
    out.push_str("    return 0;\n}\n");
    out
}

#[derive(Debug, Clone, Copy, Default)]
struct Grade {
    valid: u32,
    equal: u32,
    differ: u32,
}

fn run_harness(
    image: &Image,
    main: &str,
    units: &[Unit],
    tag: &str,
) -> BTreeMap<(String, String), Grade> {
    let scratch: ScratchDir = scratch_dir("disrobe-x86-32-decompile-behaviour");
    let dir: &Path = scratch.path();
    if image.format == Format::Pe {
        std::fs::copy(&image.path, dir.join(image.path.file_name().unwrap()))
            .expect("stage the fixture dll");
    }
    let mut sources: Vec<std::ffi::OsString> = Vec::new();
    let main_path: PathBuf = dir.join("harness.c");
    std::fs::write(&main_path, main).expect("write the harness");
    sources.push(main_path.into_os_string());
    for unit in units {
        let path: PathBuf = dir.join(&unit.file);
        std::fs::write(&path, &unit.text).expect("write a recovered unit");
        sources.push(path.into_os_string());
    }
    let exe_path: PathBuf = dir.join(format!("{tag}.exe"));
    let compiler: String = compiler_toolchain::require_one("clang");
    let mut args: Vec<std::ffi::OsString> = vec![
        "--target=i686-pc-windows-msvc".into(),
        "-O1".into(),
        "-w".into(),
        "-fno-builtin".into(),
        "-o".into(),
        exe_path.clone().into_os_string(),
    ];
    args.extend(sources);
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
        "{tag}: the harness and the recovered C must compile for i686: {}\n{main}\n{}",
        String::from_utf8_lossy(&compiled.stderr),
        units
            .iter()
            .map(|unit: &Unit| format!("// {}\n{}", unit.file, unit.text))
            .collect::<Vec<String>>()
            .join("\n")
    );
    let no_args: [&str; 0] = [];
    let ran: CapturedOutput = run_captured(&exe_path, &no_args, RUN_TIMEOUT, MAX_CAPTURE_BYTES)
        .expect("spawn the harness")
        .expect("the harness finishes within its timeout");
    let stdout: String = String::from_utf8_lossy(&ran.stdout).into_owned();
    assert_eq!(
        ran.exit_code,
        Some(0),
        "{tag}: the harness exited with {:?}: {stdout}",
        ran.exit_code
    );
    let mut grades: BTreeMap<(String, String), Grade> = BTreeMap::new();
    for line in stdout.lines() {
        let Some(rest) = line.strip_prefix("result ") else {
            continue;
        };
        let mut words = rest.split_whitespace();
        let name: String = words.next().unwrap().to_owned();
        let mode: String = words.next().unwrap().to_owned();
        let mut grade: Grade = Grade::default();
        for item in words {
            let (key, value): (&str, &str) = item.split_once('=').unwrap();
            let value: u32 = value.parse().unwrap();
            match key {
                "valid" => grade.valid = value,
                "equal" => grade.equal = value,
                "differ" => grade.differ = value,
                _ => {}
            }
        }
        grades.insert((name, mode), grade);
    }
    grades
}

#[derive(Debug, Default)]
struct Row {
    found: usize,
    recovered: usize,
    equal: usize,
    refused: BTreeMap<String, usize>,
}

fn refusal_class(reason: &str) -> String {
    let lowered: String = reason.to_ascii_lowercase();
    if lowered.contains("x87") {
        "x87 return".to_owned()
    } else {
        reason.chars().take(90).collect()
    }
}

fn grade_build(
    fixture: &Build,
    cases: &[Case],
    report: &mut BTreeMap<(String, String, String), Row>,
    failures: &mut Vec<String>,
) {
    let image: Image = load_image(fixture);
    if image.format == Format::Elf {
        assert_only_relative_relocations(&image);
    }
    let mut graded: Vec<Graded> = Vec::new();
    let mut units: Vec<Unit> = Vec::new();
    let mut bridges: BTreeMap<String, String> = BTreeMap::new();
    for case in cases.iter().filter(|case: &&Case| {
        fixture.has_thiscall || case.conv != Conv::Thiscall && !case.name.contains("thiscall")
    }) {
        let row: &mut Row = report
            .entry((
                fixture.level.to_owned(),
                fixture.toolchain.to_owned(),
                case.group.to_owned(),
            ))
            .or_default();
        let Some(&address) = image.names.get(case.name) else {
            failures.push(format!(
                "{} {}: `{}` is not discovered",
                fixture.toolchain, fixture.level, case.name
            ));
            continue;
        };
        row.found += 1;
        let (found, function): (Outcome, Option<&RecoveredFunction>) = outcome(&image, address);
        match (case.expect, found, function) {
            (Expect::Refused(needle), Outcome::Refused(reason), _) => {
                *row.refused.entry(refusal_class(&reason)).or_default() += 1;
                if !reason.contains(needle) {
                    failures.push(format!(
                        "{} {} {}: refused for `{reason}`, expected `{needle}`",
                        fixture.toolchain, fixture.level, case.name
                    ));
                }
            }
            (Expect::Refused(needle), other, _) => {
                failures.push(format!(
                    "{} {} {}: expected a `{needle}` refusal, got {other:?}",
                    fixture.toolchain, fixture.level, case.name
                ));
            }
            (Expect::Equal, Outcome::Recovered, Some(function)) => {
                row.recovered += 1;
                let renamed: String = format!("rec_{}", case.name);
                let mutated_name: String = format!("mut_{}", case.name);
                let unit: Unit = recovered_unit(
                    &function.source,
                    &function.name,
                    &renamed,
                    &mut bridges,
                    &image,
                );
                let mutated_source: String = mutate(case, &function.source);
                if mutated_source == function.source {
                    failures.push(format!(
                        "{} {} {}: the mutation control does not change the source",
                        fixture.toolchain, fixture.level, case.name
                    ));
                }
                let mutated_unit: Unit = recovered_unit(
                    &mutated_source,
                    &function.name,
                    &mutated_name,
                    &mut bridges,
                    &image,
                );
                units.push(unit);
                units.push(mutated_unit);
                graded.push(Graded {
                    case: *case,
                    renamed,
                    mutated: mutated_name,
                    address,
                    arity: function.signature.callable_arity(),
                });
            }
            (Expect::Equal, other, _) => {
                if let Outcome::Refused(reason) = &other {
                    *row.refused.entry(refusal_class(reason)).or_default() += 1;
                }
                failures.push(format!(
                    "{} {} {}: expected recovery, got {other:?}",
                    fixture.toolchain, fixture.level, case.name
                ));
            }
        }
    }
    if graded.is_empty() {
        return;
    }
    let main: String = harness(&image, &graded, &units, &bridges);
    let tag: String = format!(
        "{}_{}",
        fixture.toolchain.replace(' ', "_"),
        fixture.level.trim_start_matches(['-', '/'])
    );
    let grades: BTreeMap<(String, String), Grade> = run_harness(&image, &main, &units, &tag);
    for item in &graded {
        let grade = |mode: &str| -> Grade {
            grades
                .get(&(item.case.name.to_owned(), mode.to_owned()))
                .copied()
                .unwrap_or_else(|| panic!("{tag}: no {mode} result for {}", item.case.name))
        };
        let null: Grade = grade("null");
        let recovered: Grade = grade("recovered");
        let mutated: Grade = grade("mutated");
        let row: &mut Row = report
            .get_mut(&(
                fixture.level.to_owned(),
                fixture.toolchain.to_owned(),
                item.case.group.to_owned(),
            ))
            .unwrap();
        if null.valid != VALID_INPUTS || null.differ != 0 {
            failures.push(format!(
                "{tag} {}: the original-against-original null control disagrees: {null:?}",
                item.case.name
            ));
            continue;
        }
        if recovered.valid == VALID_INPUTS && recovered.differ == 0 {
            row.equal += 1;
        } else {
            failures.push(format!(
                "{tag} {}: the recovered C differs from the original: {recovered:?}",
                item.case.name
            ));
        }
        if mutated.differ == 0 {
            failures.push(format!(
                "{tag} {}: the mutation control stays green: {mutated:?}",
                item.case.name
            ));
        }
    }
}

fn grade_family(source: &str, marker: &str, builds: &[Build], cases: &[Case]) {
    let text: String = std::fs::read_to_string(fixture_path(source)).expect("fixture source");
    assert!(text.contains(marker), "{source} must contain `{marker}`");
    let mut report: BTreeMap<(String, String, String), Row> = BTreeMap::new();
    let mut failures: Vec<String> = Vec::new();
    for fixture in builds {
        grade_build(fixture, cases, &mut report, &mut failures);
    }
    let mut table: String = String::from(
        "level | toolchain | convention | found | recovered | behaviour-equal | refused by reason\n",
    );
    for ((level, toolchain, group), row) in &report {
        let refused: String = row
            .refused
            .iter()
            .map(|(reason, count): (&String, &usize)| format!("{count} {reason}"))
            .collect::<Vec<String>>()
            .join("; ");
        let _ = writeln!(
            table,
            "{level} | {toolchain} | {group} | {} | {} | {} | {refused}",
            row.found, row.recovered, row.equal
        );
    }
    println!("{table}");
    assert!(failures.is_empty(), "{}\n{table}", failures.join("\n"));
}

#[test]
fn x86_32_conventions_recover_and_behave_like_the_original() {
    grade_family(
        "conventions/conventions.c",
        "API int STDCALL sc_sub(int a, int b)",
        &CONVENTION_BUILDS,
        &CONVENTION_CASES,
    );
}

#[test]
fn x86_32_pc_thunk_and_call_pop_resolve_got_relative_accesses() {
    grade_family(
        "pic_thunk/pic_thunk.S",
        "call __x86.get_pc_thunk.bx",
        &PIC_THUNK_BUILDS,
        &PIC_THUNK_CASES,
    );
}

#[test]
fn x86_32_msvc_member_functions_recover_as_thiscall() {
    grade_family(
        "thiscall_msvc/thiscall_msvc.cpp",
        "int acc::add_then_get(int v)",
        &MSVC_THISCALL_BUILDS,
        &MSVC_THISCALL_CASES,
    );
}
