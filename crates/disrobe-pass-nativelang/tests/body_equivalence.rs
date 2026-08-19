#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::too_many_lines
)]
mod common;

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use common::{
    CRYSTAL_PE, NIM_ELF, ZIG_ELF, ZIG_MODES_SOURCE, ZIG_RELEASEFAST_ELF, crate_fixture_or_fail,
    crate_fixture_path, fixture_or_fail, tool_or_unmeasured,
};
use disrobe_pass_nativelang::{
    BodyStatus, FunctionBody, NativeImage, NativeLangAnalysis, RustBody, Section, analyze,
};

const RUN_LIMIT: Duration = Duration::from_mins(1);
const POLL_INTERVAL: Duration = Duration::from_millis(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    Corpus(&'static str),
    CrateFixture(&'static str),
}

impl Origin {
    fn bytes(self) -> Vec<u8> {
        match self {
            Self::Corpus(rel) => fixture_or_fail(rel),
            Self::CrateFixture(rel) => crate_fixture_or_fail(rel),
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Corpus(rel) | Self::CrateFixture(rel) => rel,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Reference {
    Model(fn(&[u64]) -> u64),
    RipRelativeLea64,
    MovImmediate32,
    MovImmediate8,
}

struct Case {
    name: &'static str,
    address: u64,
    anchor: &'static [u8],
    disassembly: &'static str,
    reference: Reference,
    reference_source: &'static str,
    inputs: &'static [&'static [u64]],
}

struct Subject {
    language: &'static str,
    build: &'static str,
    toolchain: &'static str,
    origin: Origin,
    cases: &'static [Case],
}

fn at(args: &[u64], index: usize) -> u64 {
    *args
        .get(index)
        .unwrap_or_else(|| panic!("argument {index} must be supplied, got {args:?}"))
}

fn signed(args: &[u64], index: usize) -> i64 {
    at(args, index) as i64
}

fn ref_mix(args: &[u64]) -> u64 {
    at(args, 0)
        .wrapping_mul(3)
        .wrapping_add(at(args, 1).wrapping_mul(5))
}

fn ref_gcd(args: &[u64]) -> u64 {
    let mut a: u64 = at(args, 0);
    let mut b: u64 = at(args, 1);
    while b != 0 {
        let t: u64 = b;
        b = a % b;
        a = t;
    }
    a
}

fn ref_clamp(args: &[u64]) -> u64 {
    let v: i64 = signed(args, 0);
    let lo: i64 = signed(args, 1);
    let hi: i64 = signed(args, 2);
    if v < lo {
        return lo as u64;
    }
    if v > hi {
        return hi as u64;
    }
    v as u64
}

fn ref_popcount(args: &[u64]) -> u64 {
    u64::from(at(args, 0).count_ones())
}

fn ref_sum_to(args: &[u64]) -> u64 {
    let n: u64 = at(args, 0);
    let mut acc: u64 = 0;
    let mut i: u64 = 0;
    while i <= n {
        acc = acc.wrapping_add(i);
        i = i.wrapping_add(1);
    }
    acc
}

fn ref_select(args: &[u64]) -> u64 {
    if at(args, 0) == 0 {
        at(args, 2)
    } else {
        at(args, 1)
    }
}

fn ref_abs_diff(args: &[u64]) -> u64 {
    let a: i64 = signed(args, 0);
    let b: i64 = signed(args, 1);
    if a > b {
        a.wrapping_sub(b) as u64
    } else {
        b.wrapping_sub(a) as u64
    }
}

fn ref_wrapping_add(args: &[u64]) -> u64 {
    at(args, 0).wrapping_add(at(args, 1))
}

fn ref_wrapping_sub(args: &[u64]) -> u64 {
    at(args, 0).wrapping_sub(at(args, 1))
}

const PAIRS_U64: &[&[u64]] = &[
    &[0, 0],
    &[1, 0],
    &[0, 1],
    &[1, 1],
    &[3, 4],
    &[7, 11],
    &[0xffff_ffff, 1],
    &[1, 0xffff_ffff],
    &[0x7fff_ffff_ffff_ffff, 1],
    &[0x8000_0000_0000_0000, 0x8000_0000_0000_0000],
    &[u64::MAX, 1],
    &[u64::MAX, u64::MAX],
    &[u64::MAX - 1, 2],
    &[0xdead_beef_cafe_babe, 0x0123_4567_89ab_cdef],
];

const GCD_PAIRS: &[&[u64]] = &[
    &[0, 0],
    &[0, 5],
    &[5, 0],
    &[1, 1],
    &[12, 18],
    &[18, 12],
    &[270, 192],
    &[97, 89],
    &[0xffff_ffff, 0xffff_fffe],
    &[0x0000_0100_0000_0000, 0x0000_0000_0010_0000],
    &[u64::MAX, 3],
    &[u64::MAX, u64::MAX],
];

const CLAMP_TRIPLES: &[&[u64]] = &[
    &[7, 1, 5],
    &[0, 1, 5],
    &[3, 1, 5],
    &[1, 1, 5],
    &[5, 1, 5],
    &[(-9_i64) as u64, (-4_i64) as u64, 4],
    &[(-1_i64) as u64, (-4_i64) as u64, 4],
    &[i64::MAX as u64, 0, 100],
    &[i64::MIN as u64, (-100_i64) as u64, 100],
    &[0, i64::MIN as u64, i64::MAX as u64],
];

const SINGLES_U64: &[&[u64]] = &[
    &[0],
    &[1],
    &[2],
    &[3],
    &[255],
    &[0xffff],
    &[0x8000_0000],
    &[0xffff_ffff],
    &[0x8000_0000_0000_0000],
    &[0x5555_5555_5555_5555],
    &[u64::MAX],
];

const SUM_INPUTS: &[&[u64]] = &[&[0], &[1], &[2], &[10], &[63], &[64], &[255], &[1000]];

const SELECT_TRIPLES: &[&[u64]] = &[
    &[0, 7, 9],
    &[1, 7, 9],
    &[u64::MAX, 7, 9],
    &[0x1_0000_0000, 7, 9],
    &[0, u64::MAX, 0],
    &[1, 0, u64::MAX],
];

const ABS_DIFF_PAIRS: &[&[u64]] = &[
    &[3, 9],
    &[9, 3],
    &[0, 0],
    &[(-5_i64) as u64, 5],
    &[5, (-5_i64) as u64],
    &[i64::MAX as u64, 0],
    &[0, i64::MIN as u64],
    &[i64::MIN as u64, i64::MAX as u64],
];

const NO_ARGS: &[&[u64]] = &[&[]];

const ZIG_CASES: &[Case] = &[
    Case {
        name: "dr_mix",
        address: 0x0100_1cc0,
        anchor: &[
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x8d, 0x0c, 0x7f, 0x48, 0x8d, 0x04, 0xb6, 0x48, 0x01,
            0xc8, 0x5d, 0xc3,
        ],
        disassembly: "1001cc0: push rbp; mov rbp,rsp; lea rcx,[rdi+rdi*2]; lea \
                      rax,[rsi+rsi*4]; add rax,rcx; pop rbp; ret",
        reference: Reference::Model(ref_mix),
        reference_source: "arith.zig: return a *% 3 +% b *% 5;",
        inputs: PAIRS_U64,
    },
    Case {
        name: "dr_gcd",
        address: 0x0100_1c60,
        anchor: &[
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0xf8, 0x48, 0x85, 0xf6, 0x74, 0x41, 0x48, 0x89,
            0xf2, 0xeb, 0x1c,
        ],
        disassembly: "1001c60: push rbp; mov rbp,rsp; mov rax,rdi; test rsi,rsi; je \
                      +0x41; mov rdx,rsi; jmp +0x1c",
        reference: Reference::Model(ref_gcd),
        reference_source: "arith.zig: while (b != 0) { const t = b; b = a % b; a = t; }",
        inputs: GCD_PAIRS,
    },
    Case {
        name: "dr_clamp",
        address: 0x0100_1b70,
        anchor: &[
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0xd0, 0x48, 0x39, 0xd7, 0x48, 0x0f, 0x4c, 0xc7,
            0x48, 0x39, 0xf7, 0x48, 0x0f, 0x4c, 0xc6, 0x5d, 0xc3,
        ],
        disassembly: "1001b70: push rbp; mov rbp,rsp; mov rax,rdx; cmp rdi,rdx; cmovl \
                      rax,rdi; cmp rdi,rsi; cmovl rax,rsi; pop rbp; ret",
        reference: Reference::Model(ref_clamp),
        reference_source: "arith.zig: if (v < lo) return lo; if (v > hi) return hi; return v;",
        inputs: CLAMP_TRIPLES,
    },
    Case {
        name: "dr_popcount",
        address: 0x0100_1c00,
        anchor: &[
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0xf8, 0x48, 0xd1, 0xe8, 0x48, 0xb9, 0x55, 0x55,
            0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x48, 0x21, 0xc1,
        ],
        disassembly: "1001c00: push rbp; mov rbp,rsp; mov rax,rdi; shr rax,1; movabs \
                      rcx,0x5555555555555555; and rcx,rax",
        reference: Reference::Model(ref_popcount),
        reference_source: "arith.zig: return @popCount(x);",
        inputs: SINGLES_U64,
    },
    Case {
        name: "dr_sum_to",
        address: 0x0100_1bc0,
        anchor: &[0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x31, 0xc9],
        disassembly: "1001bc0: push rbp; mov rbp,rsp; xor eax,eax; xor ecx,ecx",
        reference: Reference::Model(ref_sum_to),
        reference_source: "arith.zig: while (i <= n) : (i +%= 1) { acc +%= i; }",
        inputs: SUM_INPUTS,
    },
    Case {
        name: "dr_select",
        address: 0x0100_1bb0,
        anchor: &[
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0xf0, 0x48, 0x85, 0xff, 0x48, 0x0f, 0x44, 0xc2,
            0x5d, 0xc3,
        ],
        disassembly: "1001bb0: push rbp; mov rbp,rsp; mov rax,rsi; test rdi,rdi; cmove \
                      rax,rdx; pop rbp; ret",
        reference: Reference::Model(ref_select),
        reference_source: "arith.zig: return if (flag != 0) a else b;",
        inputs: SELECT_TRIPLES,
    },
    Case {
        name: "dr_abs_diff",
        address: 0x0100_1b90,
        anchor: &[
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0xf8, 0x48, 0x29, 0xf0, 0x48, 0x29, 0xfe, 0x48,
            0x0f, 0x4d, 0xc6, 0x5d, 0xc3,
        ],
        disassembly: "1001b90: push rbp; mov rbp,rsp; mov rax,rdi; sub rax,rsi; sub \
                      rsi,rdi; cmovge rax,rsi; pop rbp; ret",
        reference: Reference::Model(ref_abs_diff),
        reference_source: "arith.zig: return if (a > b) a -% b else b -% a;",
        inputs: ABS_DIFF_PAIRS,
    },
];

const NIM_CASES: &[Case] = &[
    Case {
        name: "system.+%",
        address: 0x0100_c590,
        anchor: &[
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x7d, 0xf8, 0x48, 0x89, 0x75, 0xf0, 0x48, 0x8b,
            0x45, 0xf8, 0x48, 0x03, 0x45, 0xf0,
        ],
        disassembly: "100c590 _ZN6system12pluspercent_E3int3int: push rbp; mov rbp,rsp; mov \
                      [rbp-0x8],rdi; mov [rbp-0x10],rsi; mov rax,[rbp-0x8]; add \
                      rax,[rbp-0x10]",
        reference: Reference::Model(ref_wrapping_add),
        reference_source: "Nim manual, system module: `+%` adds two ints treating them as \
                           unsigned, wrapping on overflow",
        inputs: PAIRS_U64,
    },
    Case {
        name: "system.-%",
        address: 0x0100_8140,
        anchor: &[
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x7d, 0xf8, 0x48, 0x89, 0x75, 0xf0, 0x48, 0x8b,
            0x45, 0xf8, 0x48, 0x2b, 0x45, 0xf0,
        ],
        disassembly: "1008140 _ZN6system13minuspercent_E3int3int: push rbp; mov rbp,rsp; mov \
                      [rbp-0x8],rdi; mov [rbp-0x10],rsi; mov rax,[rbp-0x8]; sub \
                      rax,[rbp-0x10]",
        reference: Reference::Model(ref_wrapping_sub),
        reference_source: "Nim manual, system module: `-%` subtracts two ints treating them as \
                           unsigned, wrapping on overflow",
        inputs: PAIRS_U64,
    },
    Case {
        name: "system.-%",
        address: 0x0100_c5f0,
        anchor: &[
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x7d, 0xf8, 0x48, 0x89, 0x75, 0xf0, 0x48, 0x8b,
            0x45, 0xf8, 0x48, 0x2b, 0x45, 0xf0,
        ],
        disassembly: "100c5f0 _ZN6system13minuspercent_E3int3int: push rbp; mov rbp,rsp; mov \
                      [rbp-0x8],rdi; mov [rbp-0x10],rsi; mov rax,[rbp-0x8]; sub \
                      rax,[rbp-0x10]",
        reference: Reference::Model(ref_wrapping_sub),
        reference_source: "Nim manual, system module: `-%` subtracts two ints treating them as \
                           unsigned, wrapping on overflow",
        inputs: PAIRS_U64,
    },
];

const CRYSTAL_CASES: &[Case] = &[
    Case {
        name: "sub_140025030",
        address: 0x0001_4002_5030,
        anchor: &[0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3],
        disassembly: "140025030: b8 01 00 00 00  mov eax,0x1 / 140025035: c3  ret",
        reference: Reference::MovImmediate32,
        reference_source: "objdump -d -M intel over the committed crystal PE, plus the x86-64 \
                           rule that mov r32,imm32 zero-extends into rax",
        inputs: NO_ARGS,
    },
    Case {
        name: "sub_140025bd0",
        address: 0x0001_4002_5bd0,
        anchor: &[0xb0, 0x01, 0xc3],
        disassembly: "140025bd0: b0 01  mov al,0x1 / 140025bd2: c3  ret",
        reference: Reference::MovImmediate8,
        reference_source: "objdump -d -M intel over the committed crystal PE, plus the x86-64 \
                           rule that mov r8,imm8 writes only the low byte",
        inputs: NO_ARGS,
    },
    Case {
        name: "sub_140025120",
        address: 0x0001_4002_5120,
        anchor: &[0x48, 0x8d, 0x05, 0xf9, 0x02, 0x02, 0x00, 0xc3],
        disassembly: "140025120: 48 8d 05 f9 02 02 00  lea rax,[rip+0x202f9]  # 0x140045420",
        reference: Reference::RipRelativeLea64,
        reference_source: "objdump -d -M intel over the committed crystal PE, plus the x86-64 \
                           rule that a rip-relative displacement is added to the address of the \
                           next instruction",
        inputs: NO_ARGS,
    },
    Case {
        name: "sub_140025130",
        address: 0x0001_4002_5130,
        anchor: &[0x48, 0x8d, 0x05, 0xe1, 0x02, 0x02, 0x00, 0xc3],
        disassembly: "140025130: 48 8d 05 e1 02 02 00  lea rax,[rip+0x202e1]  # 0x140045418",
        reference: Reference::RipRelativeLea64,
        reference_source: "objdump -d -M intel over the committed crystal PE, plus the x86-64 \
                           rule that a rip-relative displacement is added to the address of the \
                           next instruction",
        inputs: NO_ARGS,
    },
];

const SUBJECTS: &[Subject] = &[
    Subject {
        language: "zig",
        build: "ReleaseFast x86_64-linux-gnu",
        toolchain: "zig 0.16.0",
        origin: Origin::CrateFixture(ZIG_RELEASEFAST_ELF),
        cases: ZIG_CASES,
    },
    Subject {
        language: "nim",
        build: "C backend, safety-checked, x86_64 ELF",
        toolchain: "nim 2.0.8",
        origin: Origin::Corpus(NIM_ELF),
        cases: NIM_CASES,
    },
    Subject {
        language: "crystal",
        build: "LLVM backend, stripped x86_64 PE",
        toolchain: "crystal (version not recorded in the artifact)",
        origin: Origin::Corpus(CRYSTAL_PE),
        cases: CRYSTAL_CASES,
    },
];

fn analyze_origin(origin: Origin) -> NativeLangAnalysis {
    let bytes: Vec<u8> = origin.bytes();
    analyze(&bytes).unwrap_or_else(|error| panic!("{} must analyze, got {error}", origin.label()))
}

fn body_at<'a>(analysis: &'a NativeLangAnalysis, case: &Case) -> &'a FunctionBody {
    analysis
        .bodies
        .bodies
        .iter()
        .find(|body: &&FunctionBody| {
            let named: bool = body.name == case.name;
            named && body.start == case.address
        })
        .unwrap_or_else(|| {
            panic!(
                "{} at {:#x} must be carved for the equivalence grade",
                case.name, case.address
            )
        })
}

fn image_window(bytes: &[u8], address: u64, len: usize) -> Vec<u8> {
    let image: NativeImage<'_> = NativeImage::parse(bytes).expect("parse the graded image");
    for section in &image.sections {
        let size: u64 = section.data.len() as u64;
        if address < section.address || address >= section.address.saturating_add(size) {
            continue;
        }
        let start: usize = usize::try_from(address - section.address).expect("section offset");
        let end: usize = start.saturating_add(len);
        if let Some(window) = section.data.get(start..end) {
            return window.to_vec();
        }
    }
    panic!("{address:#x} is not inside any mapped section of the graded image");
}

fn expected_value(case: &Case, args: &[u64]) -> u64 {
    match case.reference {
        Reference::Model(model) => model(args),
        Reference::RipRelativeLea64 => {
            let displacement: i32 = i32::from_le_bytes([
                case.anchor[3],
                case.anchor[4],
                case.anchor[5],
                case.anchor[6],
            ]);
            case.address
                .wrapping_add(7)
                .wrapping_add(displacement as i64 as u64)
        }
        Reference::MovImmediate32 => u64::from(u32::from_le_bytes([
            case.anchor[1],
            case.anchor[2],
            case.anchor[3],
            case.anchor[4],
        ])),
        Reference::MovImmediate8 => u64::from(case.anchor[1]),
    }
}

fn recovered_c(body: &FunctionBody) -> &str {
    match &body.status {
        BodyStatus::Recovered { pseudo_c, .. } => pseudo_c.as_str(),
        other => panic!("{} must recover a pseudo-C body, got {other:?}", body.name),
    }
}

fn recovered_rust(body: &FunctionBody) -> &str {
    match &body.status {
        BodyStatus::Recovered {
            pseudo_rust: RustBody::Emitted(rust),
            ..
        } => rust.as_str(),
        other => panic!("{} must emit a pseudo-Rust body, got {other:?}", body.name),
    }
}

fn definition_line<'a>(source: &'a str, name: &str) -> &'a str {
    let needle: String = format!(" {name}(");
    source
        .lines()
        .find(|line: &&str| {
            line.contains(needle.as_str())
                && line.trim_end().ends_with(") {")
                && !line.trim_start().starts_with("extern ")
        })
        .unwrap_or_else(|| panic!("{name} must be defined in the recovered body:\n{source}"))
}

fn c_definition(source: &str, name: &str) -> (String, Vec<String>) {
    let line: &str = definition_line(source, name);
    let needle: String = format!(" {name}(");
    let open: usize = line.find(needle.as_str()).expect("the definition opens");
    let ret: String = line
        .get(..open)
        .expect("a return type precedes the name")
        .trim()
        .to_owned();
    let inner_start: usize = open + needle.len();
    let close: usize = line.rfind(')').expect("the parameter list closes");
    let inner: &str = line
        .get(inner_start..close)
        .expect("the parameter list is well formed")
        .trim();
    let params: Vec<String> = if inner.is_empty() || inner == "void" {
        Vec::new()
    } else {
        inner
            .split(',')
            .map(|part: &str| part.trim().to_owned())
            .collect()
    };
    (ret, params)
}

fn rust_definition(source: &str, name: &str) -> (Vec<String>, String) {
    let needle: String = format!("fn {name}(");
    let line: &str = source
        .lines()
        .find(|line: &&str| line.contains(needle.as_str()))
        .unwrap_or_else(|| panic!("{name} must be defined in the recovered body:\n{source}"));
    let open: usize = line.find(needle.as_str()).expect("the definition opens") + needle.len();
    let close: usize = line.rfind(')').expect("the parameter list closes");
    let inner: &str = line
        .get(open..close)
        .expect("the parameter list is well formed")
        .trim();
    let params: Vec<String> = if inner.is_empty() {
        Vec::new()
    } else {
        inner
            .split(',')
            .map(|part: &str| {
                part.split_once(':').map_or_else(
                    || panic!("parameter {part} must be typed"),
                    |(_, ty): (&str, &str)| ty.trim().to_owned(),
                )
            })
            .collect()
    };
    let ret: String = line.rsplit_once("->").map_or_else(
        || "u64".to_owned(),
        |(_, tail): (&str, &str)| tail.trim_end().trim_end_matches('{').trim().to_owned(),
    );
    (params, ret)
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "disrobe-nativelang-equivalence-{tag}-{}",
        std::process::id()
    ));
    drop(std::fs::remove_dir_all(&dir));
    std::fs::create_dir_all(&dir).expect("create the scratch directory for the equivalence grade");
    dir
}

fn run_bounded(mut command: Command, what: &str) -> String {
    let dir: PathBuf = std::env::temp_dir();
    let out_path: PathBuf = dir.join(format!(
        "disrobe-nativelang-run-{}-{what}.txt",
        std::process::id()
    ));
    let sink: std::fs::File = std::fs::File::create(&out_path).expect("create the run log");
    let mut child: Child = command
        .stdout(Stdio::from(sink))
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .unwrap_or_else(|error| panic!("start the graded program for {what}: {error}"));
    let deadline: Instant = Instant::now() + RUN_LIMIT;
    loop {
        if let Some(status) = child.try_wait().expect("poll the graded program") {
            assert!(
                status.success(),
                "{what}: the graded program exited {status}"
            );
            break;
        }
        if Instant::now() >= deadline {
            drop(child.kill());
            drop(child.wait());
            panic!("{what}: the graded program exceeded {RUN_LIMIT:?}");
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    let text: String = std::fs::read_to_string(&out_path).expect("read the graded program output");
    drop(std::fs::remove_file(&out_path));
    text
}

fn parse_values(text: &str, what: &str) -> Vec<u64> {
    text.lines()
        .filter(|line: &&str| !line.trim().is_empty())
        .map(|line: &str| {
            line.trim()
                .parse::<u64>()
                .unwrap_or_else(|error| panic!("{what}: `{line}` is not a value: {error}"))
        })
        .collect()
}

struct Graded {
    functions: usize,
    comparisons: usize,
}

fn grade_c(subject: &Subject, compiler: &str) -> Graded {
    let analysis: NativeLangAnalysis = analyze_origin(subject.origin);
    let dir: PathBuf = scratch_dir(&format!("{}-{}-c", subject.language, subject.cases.len()));
    let mut inputs: Vec<PathBuf> = Vec::new();
    let mut driver: String = String::from("#include <stdint.h>\n#include <stdio.h>\n");
    let mut calls: String = String::from("int main(void) {\n");
    let mut expectations: Vec<u64> = Vec::new();
    let mut functions: usize = 0;
    for case in subject.cases {
        let body: &FunctionBody = body_at(&analysis, case);
        let source: &str = recovered_c(body);
        let emitted: &str = body.emitted_name.as_str();
        let (ret, params): (String, Vec<String>) = c_definition(source, emitted);
        let file: PathBuf = dir.join(format!("{:016x}.c", case.address));
        std::fs::write(&file, source).expect("write a graded body");
        inputs.push(file);
        let prototype: String = if params.is_empty() {
            "void".to_owned()
        } else {
            params.join(", ")
        };
        writeln!(driver, "extern {ret} {emitted}({prototype});").expect("declare the graded body");
        for args in case.inputs {
            let mut supplied: Vec<String> = Vec::new();
            for index in 0..params.len() {
                let value: u64 = args.get(index).copied().unwrap_or(0);
                supplied.push(format!("UINT64_C({value})"));
            }
            writeln!(
                calls,
                "    printf(\"%llu\\n\", (unsigned long long)(uint64_t){emitted}({}));",
                supplied.join(", ")
            )
            .expect("call the graded body");
            expectations.push(expected_value(case, args));
        }
        functions = functions.saturating_add(1);
    }
    calls.push_str("    return 0;\n}\n");
    driver.push_str(&calls);
    let driver_path: PathBuf = dir.join("driver.c");
    std::fs::write(&driver_path, &driver).expect("write the equivalence driver");
    let exe: PathBuf = dir.join(if cfg!(windows) {
        "graded.exe"
    } else {
        "graded"
    });
    let compile: Output = Command::new(compiler)
        .arg("-std=c11")
        .arg("-w")
        .arg("-O0")
        .arg("-o")
        .arg(&exe)
        .arg(&driver_path)
        .args(&inputs)
        .output()
        .expect("run the C compiler over the recovered bodies");
    assert!(
        compile.status.success(),
        "{}: {compiler} could not link the recovered bodies into the equivalence driver:\n{}",
        subject.language,
        String::from_utf8_lossy(&compile.stderr)
    );
    let text: String = run_bounded(Command::new(&exe), &format!("{}-c", subject.language));
    let observed: Vec<u64> = parse_values(&text, subject.language);
    assert_eq!(
        observed.len(),
        expectations.len(),
        "{}: the driver must report one value per graded input",
        subject.language
    );
    let mut cursor: usize = 0;
    for case in subject.cases {
        for args in case.inputs {
            let got: u64 = observed[cursor];
            let want: u64 = expectations[cursor];
            assert_eq!(
                got, want,
                "{} {} {}: the recompiled pseudo-C body disagrees with the reference on {args:?}; \
                 reference is {}",
                subject.language, subject.build, case.name, case.reference_source
            );
            cursor = cursor.saturating_add(1);
        }
    }
    drop(std::fs::remove_dir_all(&dir));
    Graded {
        functions,
        comparisons: expectations.len(),
    }
}

fn rust_literal(value: u64, ty: &str) -> String {
    match ty {
        "u64" => format!("{value}u64"),
        other => format!("({value}u64 as {other})"),
    }
}

fn grade_rust(subject: &Subject, compiler: &str) -> Graded {
    let analysis: NativeLangAnalysis = analyze_origin(subject.origin);
    let dir: PathBuf = scratch_dir(&format!(
        "{}-{}-rust",
        subject.language,
        subject.cases.len()
    ));
    let mut crate_source: String =
        String::from("#![allow(dead_code, non_snake_case, unused_imports, unused_parens)]\n");
    let mut calls: String = String::from("fn main() {\n");
    let mut expectations: Vec<u64> = Vec::new();
    let mut functions: usize = 0;
    for case in subject.cases {
        let body: &FunctionBody = body_at(&analysis, case);
        let source: &str = recovered_rust(body);
        let emitted: &str = body.emitted_name.as_str();
        let module: String = format!("body_{:016x}", case.address);
        writeln!(
            crate_source,
            "#[allow(dead_code, non_snake_case, unused_imports)]\nmod {module} {{\n{source}\n}}"
        )
        .expect("append a graded body");
        let (params, ret): (Vec<String>, String) = rust_definition(source, emitted);
        for args in case.inputs {
            let mut supplied: Vec<String> = Vec::new();
            for (index, ty) in params.iter().enumerate() {
                let value: u64 = args.get(index).copied().unwrap_or(0);
                supplied.push(rust_literal(value, ty.as_str()));
            }
            let call: String = format!("{module}::{emitted}({})", supplied.join(", "));
            let widened: String = if ret == "u64" {
                call
            } else {
                format!("({call} as u64)")
            };
            writeln!(calls, "    println!(\"{{}}\", {widened});").expect("call the graded body");
            expectations.push(expected_value(case, args));
        }
        functions = functions.saturating_add(1);
    }
    calls.push_str("}\n");
    crate_source.push_str(&calls);
    let file: PathBuf = dir.join("graded.rs");
    std::fs::write(&file, &crate_source).expect("write the graded crate");
    let exe: PathBuf = dir.join(if cfg!(windows) {
        "graded.exe"
    } else {
        "graded"
    });
    let compile: Output = Command::new(compiler)
        .arg("--edition")
        .arg("2021")
        .arg("-A")
        .arg("warnings")
        .arg("-o")
        .arg(&exe)
        .arg(&file)
        .output()
        .expect("run rustc over the recovered bodies");
    assert!(
        compile.status.success(),
        "{}: rustc could not build the recovered pseudo-Rust bodies into the equivalence \
         driver:\n{}",
        subject.language,
        String::from_utf8_lossy(&compile.stderr)
    );
    let text: String = run_bounded(Command::new(&exe), &format!("{}-rust", subject.language));
    let observed: Vec<u64> = parse_values(&text, subject.language);
    assert_eq!(
        observed.len(),
        expectations.len(),
        "{}: the driver must report one value per graded input",
        subject.language
    );
    let mut cursor: usize = 0;
    for case in subject.cases {
        for args in case.inputs {
            assert_eq!(
                observed[cursor], expectations[cursor],
                "{} {} {}: the recompiled pseudo-Rust body disagrees with the reference on \
                 {args:?}; reference is {}",
                subject.language, subject.build, case.name, case.reference_source
            );
            cursor = cursor.saturating_add(1);
        }
    }
    drop(std::fs::remove_dir_all(&dir));
    Graded {
        functions,
        comparisons: expectations.len(),
    }
}

#[test]
fn every_graded_case_still_covers_the_bytes_its_reference_was_read_from() {
    for subject in SUBJECTS {
        let bytes: Vec<u8> = subject.origin.bytes();
        let analysis: NativeLangAnalysis = analyze_origin(subject.origin);
        for case in subject.cases {
            let window: Vec<u8> = image_window(&bytes, case.address, case.anchor.len());
            assert_eq!(
                window, case.anchor,
                "{} {}: {} at {:#x} no longer starts with the bytes the reference was derived \
                 from ({}); the grade would compare against a stale reference",
                subject.language, subject.build, case.name, case.address, case.disassembly
            );
            let body: &FunctionBody = body_at(&analysis, case);
            assert!(
                body.byte_len >= case.anchor.len() as u64,
                "{}: the carve for {} is shorter than the anchored bytes",
                subject.language,
                case.name
            );
        }
    }
}

#[test]
fn recovered_pseudo_c_bodies_recompile_to_the_reference() {
    let Some(compiler): Option<String> = tool_or_unmeasured(
        &["gcc", "clang", "cc"],
        "the nativelang pseudo-C body equivalence grade",
    ) else {
        return;
    };
    let mut functions: usize = 0;
    let mut comparisons: usize = 0;
    for subject in SUBJECTS {
        let graded: Graded = grade_c(subject, &compiler);
        println!(
            "{} [{}] [{}]: {}/{} recovered pseudo-C bodies match the reference over {} inputs",
            subject.language,
            subject.toolchain,
            subject.build,
            graded.functions,
            subject.cases.len(),
            graded.comparisons
        );
        assert_eq!(
            graded.functions,
            subject.cases.len(),
            "{}: every declared case must be graded",
            subject.language
        );
        functions = functions.saturating_add(graded.functions);
        comparisons = comparisons.saturating_add(graded.comparisons);
    }
    assert_eq!(
        functions, 14,
        "the pseudo-C equivalence grade must cover 14 recovered bodies, covered {functions}"
    );
    assert!(
        comparisons >= 115,
        "the pseudo-C equivalence grade must compare at least 115 input rows, compared \
         {comparisons}"
    );
}

#[test]
fn recovered_pseudo_rust_bodies_recompile_to_the_reference() {
    let Some(compiler): Option<String> = tool_or_unmeasured(
        &["rustc"],
        "the nativelang pseudo-Rust body equivalence grade",
    ) else {
        return;
    };
    let mut functions: usize = 0;
    let mut comparisons: usize = 0;
    for subject in SUBJECTS {
        let graded: Graded = grade_rust(subject, &compiler);
        println!(
            "{} [{}] [{}]: {}/{} recovered pseudo-Rust bodies match the reference over {} inputs",
            subject.language,
            subject.toolchain,
            subject.build,
            graded.functions,
            subject.cases.len(),
            graded.comparisons
        );
        functions = functions.saturating_add(graded.functions);
        comparisons = comparisons.saturating_add(graded.comparisons);
    }
    assert_eq!(
        functions, 14,
        "the pseudo-Rust equivalence grade must cover 14 recovered bodies, covered {functions}"
    );
    assert!(
        comparisons >= 115,
        "the pseudo-Rust equivalence grade must compare at least 115 input rows, compared \
         {comparisons}"
    );
}

#[test]
fn a_function_the_decompiler_cannot_lift_abstains_with_a_named_reason() {
    let zig: NativeLangAnalysis = analyze_origin(Origin::CrateFixture(ZIG_RELEASEFAST_ELF));
    let rotl: &FunctionBody = zig
        .bodies
        .bodies
        .iter()
        .find(|body: &&FunctionBody| body.name == "dr_rotl")
        .expect("arith.zig exports dr_rotl, so it must be carved");
    let BodyStatus::Rejected { ref reason } = rotl.status else {
        panic!(
            "dr_rotl must abstain rather than publish a partial body, got {:?}",
            rotl.status
        );
    };
    let text: String = format!("{reason:?}");
    assert!(
        text.contains("rol"),
        "the abstention must name what stopped the lift, got {text}"
    );

    let nim: NativeLangAnalysis = analyze_origin(Origin::Corpus(NIM_ELF));
    let fib: &FunctionBody = nim
        .bodies
        .bodies
        .iter()
        .find(|body: &&FunctionBody| body.name == "hello.fib")
        .expect("corpus/native/nim/hello.nim declares fib, so hello.fib must be carved");
    let BodyStatus::Rejected { ref reason } = fib.status else {
        panic!(
            "hello.fib must abstain rather than publish a partial body, got {:?}",
            fib.status
        );
    };
    assert!(
        format!("{reason:?}").contains("seto"),
        "the abstention must name the instruction that stopped the lift, got {reason:?}"
    );
}

#[test]
fn the_two_graded_zig_builds_are_different_optimisation_modes() {
    let safety_checked: Vec<u8> = fixture_or_fail(ZIG_ELF);
    let release_fast: Vec<u8> = crate_fixture_or_fail(ZIG_RELEASEFAST_ELF);
    for marker in ["panicOutOfBounds", "panicUnwrap"] {
        assert!(
            contains(&safety_checked, marker),
            "the corpus zig build is the safety-checked mode and must emit {marker}"
        );
        assert!(
            !contains(&release_fast, marker),
            "the ReleaseFast build must not emit {marker}; without that difference the two \
             fixtures are the same build mode"
        );
    }
    for marker in ["start.posixCallMainAndExit", "compiler_rt"] {
        assert!(
            contains(&safety_checked, marker) && contains(&release_fast, marker),
            "both graded zig builds must carry {marker}, which is what fingerprints them as zig"
        );
    }
    let source: PathBuf = crate_fixture_path(ZIG_MODES_SOURCE);
    let text: String = std::fs::read_to_string(&source).unwrap_or_else(|error| {
        panic!(
            "{} is the reference the zig equivalence cases transliterate: {error}",
            source.display()
        )
    });
    for case in ZIG_CASES {
        assert!(
            text.contains(&format!("export fn {}(", case.name)),
            "{} must be declared in the committed zig source the reference comes from",
            case.name
        );
    }
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    let needle: &[u8] = needle.as_bytes();
    haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
}

struct ModeRate {
    language: &'static str,
    build: &'static str,
    toolchain: &'static str,
    origin: Origin,
    functions: u32,
    recovered: u32,
    rust: u32,
}

const MODE_RATES: &[ModeRate] = &[
    ModeRate {
        language: "nim",
        build: "C backend, safety-checked, x86_64 ELF",
        toolchain: "nim 2.0.8",
        origin: Origin::Corpus(NIM_ELF),
        functions: 183,
        recovered: 75,
        rust: 75,
    },
    ModeRate {
        language: "nim",
        build: "--mm:arc, x86_64 PE",
        toolchain: "nim (mingw-w64 gcc 13.2.0 backend)",
        origin: Origin::CrateFixture("nim_mm/mm_arc.exe"),
        functions: 2,
        recovered: 1,
        rust: 1,
    },
    ModeRate {
        language: "nim",
        build: "--mm:orc, x86_64 PE",
        toolchain: "nim (mingw-w64 gcc 13.2.0 backend)",
        origin: Origin::CrateFixture("nim_mm/mm_orc.exe"),
        functions: 2,
        recovered: 1,
        rust: 1,
    },
    ModeRate {
        language: "nim",
        build: "--mm:refc, x86_64 PE",
        toolchain: "nim (mingw-w64 gcc 13.2.0 backend)",
        origin: Origin::CrateFixture("nim_mm/mm_refc.exe"),
        functions: 2,
        recovered: 1,
        rust: 1,
    },
    ModeRate {
        language: "nim",
        build: "--mm:boehm, x86_64 PE",
        toolchain: "nim (mingw-w64 gcc 13.2.0 backend)",
        origin: Origin::CrateFixture("nim_mm/mm_boehm.exe"),
        functions: 93,
        recovered: 12,
        rust: 12,
    },
    ModeRate {
        language: "nim",
        build: "--mm:markAndSweep, x86_64 PE",
        toolchain: "nim (mingw-w64 gcc 13.2.0 backend)",
        origin: Origin::CrateFixture("nim_mm/mm_markAndSweep.exe"),
        functions: 2,
        recovered: 1,
        rust: 1,
    },
    ModeRate {
        language: "nim",
        build: "--mm:go, x86_64 PE",
        toolchain: "nim (mingw-w64 gcc 13.2.0 backend)",
        origin: Origin::CrateFixture("nim_mm/mm_go.exe"),
        functions: 2,
        recovered: 1,
        rust: 1,
    },
    ModeRate {
        language: "nim",
        build: "--mm:none, x86_64 PE",
        toolchain: "nim (mingw-w64 gcc 13.2.0 backend)",
        origin: Origin::CrateFixture("nim_mm/mm_none.exe"),
        functions: 2,
        recovered: 1,
        rust: 1,
    },
    ModeRate {
        language: "zig",
        build: "safety-checked, x86_64 ELF",
        toolchain: "zig 0.13.0",
        origin: Origin::Corpus(ZIG_ELF),
        functions: 1356,
        recovered: 312,
        rust: 309,
    },
    ModeRate {
        language: "zig",
        build: "ReleaseFast, x86_64-linux-gnu ELF",
        toolchain: "zig 0.16.0",
        origin: Origin::CrateFixture(ZIG_RELEASEFAST_ELF),
        functions: 23,
        recovered: 9,
        rust: 9,
    },
    ModeRate {
        language: "crystal",
        build: "LLVM backend, stripped x86_64 PE",
        toolchain: "crystal (version not recorded in the artifact)",
        origin: Origin::Corpus(CRYSTAL_PE),
        functions: 314,
        recovered: 19,
        rust: 19,
    },
];

#[test]
fn the_body_recovery_rate_is_recorded_per_language_and_build_mode() {
    for rate in MODE_RATES {
        let analysis: NativeLangAnalysis = analyze_origin(rate.origin);
        println!(
            "{} [{}] [{}]: {}/{} carved functions recovered a pseudo-C body, {}/{} a pseudo-Rust \
             body",
            rate.language,
            rate.toolchain,
            rate.build,
            analysis.bodies.recovered,
            analysis.bodies.function_count,
            analysis.bodies.rust_bodies,
            analysis.bodies.function_count
        );
        assert_eq!(
            analysis.bodies.function_count, rate.functions,
            "{} [{}]: the carved function count moved",
            rate.language, rate.build
        );
        assert_eq!(
            analysis.bodies.recovered, rate.recovered,
            "{} [{}]: the recovered pseudo-C body count moved",
            rate.language, rate.build
        );
        assert_eq!(
            analysis.bodies.rust_bodies, rate.rust,
            "{} [{}]: the emitted pseudo-Rust body count moved",
            rate.language, rate.build
        );
    }
    for language in ["nim", "zig"] {
        let modes: usize = MODE_RATES
            .iter()
            .filter(|rate: &&ModeRate| rate.language == language)
            .count();
        assert!(
            modes >= 2,
            "{language} must be measured across at least two build modes, measured {modes}"
        );
    }
}

#[test]
fn a_low_confidence_carve_is_never_given_a_body_in_any_measured_mode() {
    for rate in MODE_RATES {
        let analysis: NativeLangAnalysis = analyze_origin(rate.origin);
        for body in &analysis.bodies.bodies {
            if body.boundary_confidence == disrobe_pass_nativelang::BoundaryConfidence::Low {
                assert!(
                    matches!(body.status, BodyStatus::NotAttempted { .. }),
                    "{} [{}]: {} at {:#x} has a low-confidence boundary and must not be lifted, \
                     got {:?}",
                    rate.language,
                    rate.build,
                    body.name,
                    body.start,
                    body.status
                );
            }
        }
    }
}

#[test]
fn every_measured_mode_partitions_its_outcomes() {
    for rate in MODE_RATES {
        let analysis: NativeLangAnalysis = analyze_origin(rate.origin);
        let total: u32 = analysis.bodies.recovered
            + analysis.bodies.recovered_elided
            + analysis.bodies.rejected
            + analysis.bodies.not_attempted;
        assert_eq!(
            total, analysis.bodies.function_count,
            "{} [{}]: the outcome counts must sum to the carved function count",
            rate.language, rate.build
        );
    }
}

#[test]
fn the_graded_sections_are_reachable_through_the_public_image_api() {
    let bytes: Vec<u8> = crate_fixture_or_fail(ZIG_RELEASEFAST_ELF);
    let image: NativeImage<'_> = NativeImage::parse(&bytes).expect("parse the zig fixture");
    let text: &Section<'_> = image
        .sections
        .iter()
        .find(|section: &&Section<'_>| section.name == ".text")
        .expect("the zig fixture maps a .text section");
    assert!(
        text.data.len() > 1024,
        "the graded .text section must carry the recovered bodies, mapped {} bytes",
        text.data.len()
    );
}
