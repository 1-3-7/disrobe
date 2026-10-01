#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::OnceLock;
use std::time::Duration;

use common::{
    CRYSTAL_PE, NIM_ELF, ZIG_ELF, ZIG_MODES_SOURCE, ZIG_RELEASEFAST_ELF, crate_fixture_or_fail,
    crate_fixture_path, fixture_or_fail, tool_or_unmeasured,
};
use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::{
    CaptureOutcome, CapturedStream, CommandSpec, Completion, Execution,
};
use disrobe_pass_nativelang::{
    BodyStatus, FunctionBody, NativeImage, NativeLangAnalysis, RustBody, Section, analyze,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const RUN_LIMIT: Duration = Duration::from_mins(1);
const COMPILE_LIMIT: Duration = Duration::from_mins(2);
const METADATA_COMPILE_LIMIT: Duration = Duration::from_secs(30);
const RUN_OUTPUT_LIMIT: usize = 1 << 20;

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
    callees: &'static [&'static str],
}

#[derive(Debug, Clone, Copy)]
struct RecordedAs {
    record: Origin,
    artifact: &'static str,
    schema: &'static str,
    source: &'static str,
}

struct Subject {
    language: &'static str,
    build: &'static str,
    toolchain: &'static str,
    origin: Origin,
    recorded: RecordedAs,
    cases: &'static [Case],
}

#[derive(Debug, Deserialize)]
struct BuildRecord {
    schema: String,
    producer: String,
    source: String,
    source_sha256: String,
    artifacts: Vec<RecordedArtifact>,
}

#[derive(Debug, Deserialize)]
struct RecordedArtifact {
    path: String,
    sha256: String,
    build_command: String,
}

const NIM_HELLO: RecordedAs = RecordedAs {
    record: Origin::Corpus("nim/provenance.toml"),
    artifact: "hello.nim.elf",
    schema: "disrobe.nativelang.source-build/v1",
    source: "hello.nim",
};
const CRYSTAL_HELLO_PE: &str = "crystal_hello/hello.cr.exe";
const CRYSTAL_HELLO: RecordedAs = RecordedAs {
    record: Origin::CrateFixture("crystal_hello/provenance.toml"),
    artifact: "hello.cr.exe",
    schema: "disrobe.nativelang.hello-rebuild/v1",
    source: "../../../../../corpus/native/crystal/hello.cr",
};
const CRYSTAL_TOOLCHAIN: &str = "crystal 1.20.2";
const ZIG_HELLO: RecordedAs = RecordedAs {
    record: Origin::Corpus("zig/provenance.toml"),
    artifact: "hello.zig.elf",
    schema: "disrobe.nativelang.source-build/v1",
    source: "hello.zig",
};
const ZIG_HELLO_TOOLCHAIN: &str = "zig 0.13.0";

fn assert_recorded(origin: Origin, recorded: RecordedAs, toolchain: &str) {
    let RecordedAs {
        record,
        artifact,
        schema,
        source,
    } = recorded;
    let path: PathBuf = match record {
        Origin::Corpus(rel) => common::corpus_path(rel),
        Origin::CrateFixture(rel) => crate_fixture_path(rel),
    };
    let record_label: &str = record.label();
    let text: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", path.display()));
    let parsed: BuildRecord = toml::from_str(&text)
        .unwrap_or_else(|error: toml::de::Error| panic!("parse {}: {error}", path.display()));
    assert_eq!(
        parsed.schema, schema,
        "{record_label} has a changed build-record schema"
    );
    assert_eq!(
        parsed.source, source,
        "{record_label} names a different authored source"
    );
    let Some(entry): Option<&RecordedArtifact> = parsed
        .artifacts
        .iter()
        .find(|entry: &&RecordedArtifact| entry.path == artifact)
    else {
        panic!("{record_label} records no artifact named {artifact}");
    };
    assert!(
        !entry.build_command.is_empty(),
        "{record_label} must record the command that built {artifact}"
    );
    assert_eq!(
        parsed.producer, toolchain,
        "{record_label} records the producer {}, but the grade reports {toolchain}",
        parsed.producer
    );
    let parent: &Path = path
        .parent()
        .unwrap_or_else(|| panic!("{} has no parent", path.display()));
    let source_path: PathBuf = parent.join(&parsed.source);
    let source: Vec<u8> = std::fs::read(&source_path)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", source_path.display()));
    let source_actual: String = format!("{:x}", Sha256::digest(source));
    assert_eq!(
        source_actual,
        parsed.source_sha256,
        "{} does not match the sha256 its build record {record_label} pins",
        source_path.display()
    );
    let actual: String = format!("{:x}", Sha256::digest(origin.bytes()));
    assert_eq!(
        actual,
        entry.sha256,
        "{} does not match the sha256 its build record {record_label} pins, so its recovered functions \
         must not run natively",
        origin.label()
    );
}

fn assert_build_record(subject: &Subject) {
    assert_recorded(subject.origin, subject.recorded, subject.toolchain);
}

fn authored_origin(recorded: RecordedAs) -> PathBuf {
    let record: PathBuf = match recorded.record {
        Origin::Corpus(rel) => common::corpus_path(rel),
        Origin::CrateFixture(rel) => crate_fixture_path(rel),
    };
    record
        .parent()
        .expect("build record has a parent")
        .join(recorded.source)
        .canonicalize()
        .expect("recorded source exists")
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

fn ref_fib(args: &[u64]) -> u64 {
    let n: i64 = signed(args, 0);
    let (mut previous, mut current): (i64, i64) = (0, 1);
    for _step in 0..n {
        let next: i64 = previous
            .checked_add(current)
            .expect("the graded fib inputs stay inside Int64");
        previous = current;
        current = next;
    }
    previous as u64
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

const FIB_INPUTS: &[&[u64]] = &[&[0], &[1], &[2], &[3], &[7], &[10], &[20], &[25]];

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
        callees: &[],
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
        callees: &[],
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
        callees: &[],
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
        callees: &[],
    },
    Case {
        name: "dr_sum_to",
        address: 0x0100_1bc0,
        anchor: &[0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x31, 0xc9],
        disassembly: "1001bc0: push rbp; mov rbp,rsp; xor eax,eax; xor ecx,ecx",
        reference: Reference::Model(ref_sum_to),
        reference_source: "arith.zig: while (i <= n) : (i +%= 1) { acc +%= i; }",
        inputs: SUM_INPUTS,
        callees: &[],
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
        callees: &[],
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
        callees: &[],
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
        callees: &[],
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
        callees: &[],
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
        callees: &[],
    },
];

const CRYSTAL_CASES: &[Case] = &[
    Case {
        name: "sub_140024b84",
        address: 0x0001_4002_4b84,
        anchor: &[0xb0, 0x01, 0xc3],
        disassembly: "140024b84: b0 01  mov al,0x1 / 140024b86: c3  ret",
        reference: Reference::MovImmediate8,
        reference_source: "llvm-objdump -d -M intel over the recorded crystal PE, plus the x86-64 \
                           rule that mov r8,imm8 writes only the low byte",
        inputs: NO_ARGS,
        callees: &[],
    },
    Case {
        name: "sub_140024bc4",
        address: 0x0001_4002_4bc4,
        anchor: &[0x48, 0x8d, 0x05, 0x4d, 0x08, 0x02, 0x00, 0xc3],
        disassembly: "140024bc4: 48 8d 05 4d 08 02 00  lea rax,[rip+0x2084d]  # 0x140045418",
        reference: Reference::RipRelativeLea64,
        reference_source: "llvm-objdump -d -M intel over the recorded crystal PE, plus the x86-64 \
                           rule that a rip-relative displacement is added to the address of the \
                           next instruction",
        inputs: NO_ARGS,
        callees: &[],
    },
    Case {
        name: "sub_140024bcc",
        address: 0x0001_4002_4bcc,
        anchor: &[0x48, 0x8d, 0x05, 0x3d, 0x08, 0x02, 0x00, 0xc3],
        disassembly: "140024bcc: 48 8d 05 3d 08 02 00  lea rax,[rip+0x2083d]  # 0x140045410",
        reference: Reference::RipRelativeLea64,
        reference_source: "llvm-objdump -d -M intel over the recorded crystal PE, plus the x86-64 \
                           rule that a rip-relative displacement is added to the address of the \
                           next instruction",
        inputs: NO_ARGS,
        callees: &[],
    },
    Case {
        name: "sub_140022ca0",
        address: 0x0001_4002_2ca0,
        anchor: &[
            0x56, 0x57, 0x48, 0x83, 0xec, 0x28, 0x48, 0x89, 0xc8, 0x48, 0x83, 0xf9, 0x01, 0x76,
            0x20,
        ],
        disassembly: "140022ca0: push rsi; push rdi; sub rsp,0x28; mov rax,rcx; cmp rcx,0x1; jbe \
                      +0x20; the two recursive calls, then add rax,rdi; jo to the overflow raise",
        reference: Reference::Model(ref_fib),
        reference_source: "corpus/native/crystal/hello.cr: `n < 2 ? n : fib(n - 1) + fib(n - 2)` \
                           over Int64, which raises on overflow; every graded input is \
                           non-negative, the only values the program passes",
        inputs: FIB_INPUTS,
        callees: &["sub_140001000"],
    },
];

const SUBJECTS: &[Subject] = &[
    Subject {
        language: "zig",
        build: "ReleaseFast x86_64-linux-gnu",
        toolchain: "zig 0.16.0",
        origin: Origin::CrateFixture(ZIG_RELEASEFAST_ELF),
        recorded: RecordedAs {
            record: Origin::CrateFixture("zig_modes/provenance.toml"),
            artifact: "arith_releasefast_x86_64_linux.elf",
            schema: "disrobe.nativelang.zig-build-modes/v1",
            source: "arith.zig",
        },
        cases: ZIG_CASES,
    },
    Subject {
        language: "nim",
        build: "C backend, safety-checked, x86_64 ELF",
        toolchain: "nim 2.0.8",
        origin: Origin::Corpus(NIM_ELF),
        recorded: NIM_HELLO,
        cases: NIM_CASES,
    },
    Subject {
        language: "crystal",
        build: "LLVM backend, x86_64 PE linked without debug information",
        toolchain: CRYSTAL_TOOLCHAIN,
        origin: Origin::CrateFixture(CRYSTAL_HELLO_PE),
        recorded: CRYSTAL_HELLO,
        cases: CRYSTAL_CASES,
    },
];

struct RebuiltSubject {
    origin: Origin,
    analysis: OnceLock<NativeLangAnalysis>,
}

static REBUILT_SUBJECTS: [RebuiltSubject; 3] = [
    RebuiltSubject {
        origin: Origin::Corpus(NIM_ELF),
        analysis: OnceLock::new(),
    },
    RebuiltSubject {
        origin: Origin::CrateFixture(CRYSTAL_HELLO_PE),
        analysis: OnceLock::new(),
    },
    RebuiltSubject {
        origin: Origin::Corpus(ZIG_ELF),
        analysis: OnceLock::new(),
    },
];

fn analyze_origin(origin: Origin) -> &'static NativeLangAnalysis {
    let cache: &OnceLock<NativeLangAnalysis> = MODE_RATES
        .iter()
        .find(|rate: &&ModeRate| rate.origin == origin)
        .map(|rate: &ModeRate| &rate.analysis)
        .or_else(|| {
            REBUILT_SUBJECTS
                .iter()
                .find(|rebuilt: &&RebuiltSubject| rebuilt.origin == origin)
                .map(|rebuilt: &RebuiltSubject| &rebuilt.analysis)
        })
        .expect("every graded origin is a measured mode or a recorded rebuild");
    cache.get_or_init(|| {
        let bytes: Vec<u8> = origin.bytes();
        analyze(&bytes)
            .unwrap_or_else(|error| panic!("{} must analyze, got {error}", origin.label()))
    })
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

fn scratch_dir(tag: &str) -> ScratchDir {
    ScratchDir::create(&format!("nativelang-equivalence-{tag}"))
        .expect("create the scratch directory for the equivalence grade")
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("native-language crate belongs to the workspace")
        .to_path_buf()
}

fn resolve_program(program: &str, what: &str) -> PathBuf {
    let named: &Path = Path::new(program);
    if named.components().count() > 1 {
        return named.canonicalize().unwrap_or_else(|error| {
            panic!(
                "{what}: compiler {} cannot be resolved: {error}",
                named.display()
            )
        });
    }
    let path_var: OsString = std::env::var_os("PATH")
        .unwrap_or_else(|| panic!("{what}: PATH is unset, so {program} cannot be resolved"));
    let exts: &[&str] = if cfg!(windows) {
        &["", ".exe", ".bat", ".cmd"]
    } else {
        &[""]
    };
    for dir in std::env::split_paths(&path_var) {
        for ext in exts {
            let candidate: PathBuf = dir.join(format!("{program}{ext}"));
            if candidate.is_file() {
                return candidate.canonicalize().unwrap_or_else(|error| {
                    panic!(
                        "{what}: compiler {} cannot be resolved: {error}",
                        candidate.display()
                    )
                });
            }
        }
    }
    panic!("{what}: compiler {program} is not on PATH")
}

fn support_source(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("support")
        .join(name)
}

fn assert_compiles(
    compiler: &str,
    cwd: &Path,
    arguments: Vec<OsString>,
    what: &str,
) -> CompilerInvocation {
    let program: PathBuf = resolve_program(compiler, what);
    let invocation: CompilerInvocation = CompilerInvocation {
        program: program.display().to_string(),
        arguments: arguments
            .iter()
            .map(|argument: &OsString| argument.to_string_lossy().into_owned())
            .collect(),
        toolchain: compiler_identity(&program, cwd, what),
    };
    let execution: Execution = CommandSpec::new(program, COMPILE_LIMIT)
        .current_dir(cwd.to_path_buf())
        .capture_limits(RUN_OUTPUT_LIMIT, RUN_OUTPUT_LIMIT)
        .args(arguments)
        .run()
        .unwrap_or_else(|error| panic!("{what}: compiler failed to run: {error}"));
    let status: ExitStatus = match execution.completion {
        Completion::Exited(status) => status,
        Completion::TimedOut(_) => panic!("{what}: compilation exceeded {COMPILE_LIMIT:?}"),
    };
    let stdout: &CapturedStream = match &execution.stdout {
        CaptureOutcome::Complete(stdout) => stdout,
        other => panic!("{what}: compiler stdout was not completely captured: {other:?}"),
    };
    assert!(
        !stdout.truncated,
        "{what}: compiler stdout exceeded the {RUN_OUTPUT_LIMIT}-byte capture limit"
    );
    let stderr: &CapturedStream = match &execution.stderr {
        CaptureOutcome::Complete(stderr) => stderr,
        other => panic!("{what}: compiler stderr was not completely captured: {other:?}"),
    };
    assert!(
        !stderr.truncated,
        "{what}: compiler stderr exceeded the {RUN_OUTPUT_LIMIT}-byte capture limit"
    );
    assert!(
        status.success(),
        "{what}: compiler exited {status}:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&stdout.bytes),
        String::from_utf8_lossy(&stderr.bytes)
    );
    invocation
}

fn assert_metadata_compiles(compiler: &str, cwd: &Path, source: &Path, what: &str) {
    let output: PathBuf = cwd.join("graded.rmeta");
    let execution: Execution = CommandSpec::new(compiler, METADATA_COMPILE_LIMIT)
        .current_dir(cwd.to_path_buf())
        .capture_limits(RUN_OUTPUT_LIMIT, RUN_OUTPUT_LIMIT)
        .args([
            "--edition",
            "2021",
            "-A",
            "warnings",
            "--emit=metadata",
            "-o",
        ])
        .arg(output.as_os_str())
        .arg(source.as_os_str())
        .run()
        .unwrap_or_else(|error| panic!("{what}: metadata compilation did not run: {error}"));
    let status: ExitStatus = match execution.completion {
        Completion::Exited(status) => status,
        Completion::TimedOut(_) => panic!(
            "{what}: metadata compilation exceeded {METADATA_COMPILE_LIMIT:?}; the recovered \
             source is pathological before linking"
        ),
    };
    let stderr: &CapturedStream = match &execution.stderr {
        CaptureOutcome::Complete(stderr) => stderr,
        other => panic!("{what}: metadata compiler stderr was not completely captured: {other:?}"),
    };
    assert!(
        !stderr.truncated,
        "{what}: metadata compiler stderr exceeded the {RUN_OUTPUT_LIMIT}-byte capture limit"
    );
    assert!(
        status.success(),
        "{what}: metadata compiler exited {status}:\n{}",
        String::from_utf8_lossy(&stderr.bytes)
    );
    assert!(
        output.is_file(),
        "{what}: metadata compiler succeeded without producing {}",
        output.display()
    );
}

struct CompilerInvocation {
    program: String,
    arguments: Vec<String>,
    toolchain: String,
}

fn compiler_identity(compiler: &Path, cwd: &Path, what: &str) -> String {
    let execution: Execution = CommandSpec::new(compiler, COMPILE_LIMIT)
        .current_dir(cwd.to_path_buf())
        .capture_limits(RUN_OUTPUT_LIMIT, RUN_OUTPUT_LIMIT)
        .arg("--version")
        .run()
        .unwrap_or_else(|error| panic!("{what}: compiler identity did not run: {error}"));
    let Completion::Exited(status) = execution.completion else {
        panic!("{what}: compiler identity exceeded {COMPILE_LIMIT:?}");
    };
    assert!(
        status.success(),
        "{what}: compiler identity exited {status}"
    );
    let Some(stdout): Option<&CapturedStream> = execution.stdout.captured() else {
        panic!("{what}: compiler identity stdout was not captured");
    };
    assert!(
        !stdout.truncated,
        "{what}: compiler identity exceeded the {RUN_OUTPUT_LIMIT}-byte capture limit"
    );
    let identity: String = String::from_utf8_lossy(&stdout.bytes).trim().to_owned();
    assert!(
        !identity.is_empty(),
        "{what}: compiler identity output must name the compiler version"
    );
    identity
}

fn rustc_compiler(graded: &str) -> Option<String> {
    if let Some(configured) = std::env::var_os("RUSTC") {
        let configured: PathBuf = PathBuf::from(configured);
        let canonical: PathBuf = configured.canonicalize().unwrap_or_else(|error| {
            panic!(
                "{graded}: RUSTC must name the real rustc executable, but {} cannot be resolved: {error}",
                configured.display()
            )
        });
        assert!(
            canonical.is_file(),
            "{graded}: RUSTC must name the real rustc executable, got {}",
            canonical.display()
        );
        return Some(canonical.display().to_string());
    }
    let rustup: String = tool_or_unmeasured(&["rustup"], graded)?;
    let cwd: PathBuf = workspace_root();
    let execution: Execution = CommandSpec::new(rustup, COMPILE_LIMIT)
        .current_dir(cwd)
        .capture_limits(RUN_OUTPUT_LIMIT, RUN_OUTPUT_LIMIT)
        .args(["which", "rustc"])
        .run()
        .unwrap_or_else(|error| panic!("{graded}: rustup lookup did not run: {error}"));
    let Completion::Exited(status) = execution.completion else {
        panic!("{graded}: rustup lookup exceeded {COMPILE_LIMIT:?}");
    };
    assert!(status.success(), "{graded}: rustup lookup exited {status}");
    let Some(stdout): Option<&CapturedStream> = execution.stdout.captured() else {
        panic!("{graded}: rustup lookup stdout was not captured");
    };
    assert!(
        !stdout.truncated,
        "{graded}: rustup lookup exceeded the {RUN_OUTPUT_LIMIT}-byte capture limit"
    );
    let reported: &str = std::str::from_utf8(&stdout.bytes)
        .unwrap_or_else(|error| panic!("{graded}: rustup reported non-UTF-8 rustc path: {error}"))
        .trim();
    assert!(
        !reported.is_empty(),
        "{graded}: rustup did not report a rustc executable; set RUSTC to the real rustc path"
    );
    let canonical: PathBuf = PathBuf::from(reported)
        .canonicalize()
        .unwrap_or_else(|error| {
            panic!("{graded}: rustup reported an unusable rustc path {reported}: {error}")
        });
    assert!(
        canonical.is_file(),
        "{graded}: rustup reported a non-file rustc path {}",
        canonical.display()
    );
    Some(canonical.display().to_string())
}

fn run_contained(
    exe: &Path,
    source: &Path,
    origin: &Path,
    inputs: &[&Path],
    compiler: &CompilerInvocation,
    what: &str,
) -> String {
    let source_sha256: [u8; 32] =
        Sha256::digest(std::fs::read(source).expect("read recovered source for build record"))
            .into();
    let origin_sha256: [u8; 32] =
        Sha256::digest(std::fs::read(origin).expect("read repository origin for build record"))
            .into();
    let artifact_sha256: [u8; 32] =
        Sha256::digest(std::fs::read(exe).expect("read recovered executable for build record"))
            .into();
    let record: PathBuf = exe.with_extension("build-record.json");
    let record_bytes: Vec<u8> = serde_json::to_vec(&serde_json::json!({
        "source": source,
        "source_sha256": source_sha256,
        "origin": { "path": origin, "sha256": origin_sha256 },
        "inputs": inputs.iter().map(|input: &&Path| {
            let sha256: [u8; 32] = Sha256::digest(
                std::fs::read(input).expect("read recovered build input"),
            ).into();
            serde_json::json!({ "path": input, "sha256": sha256 })
        }).collect::<Vec<serde_json::Value>>(),
        "toolchain": &compiler.toolchain,
        "command": &compiler.program,
        "arguments": &compiler.arguments,
        "artifact": { "path": exe, "sha256": artifact_sha256 },
    }))
    .expect("serialize recovered build record");
    std::fs::write(&record, &record_bytes).expect("write recovered build record");
    let execution: Execution = CommandSpec::new(exe, RUN_LIMIT)
        .current_dir(
            exe.parent()
                .expect("recovered executable has a parent")
                .to_path_buf(),
        )
        .capture_limits(RUN_OUTPUT_LIMIT, RUN_OUTPUT_LIMIT)
        .run()
        .unwrap_or_else(|error| panic!("{what}: the graded program did not run: {error}"));
    let status: ExitStatus = match execution.completion {
        Completion::Exited(status) => status,
        Completion::TimedOut(_) => panic!("{what}: the graded program exceeded {RUN_LIMIT:?}"),
    };
    assert!(
        status.success(),
        "{what}: the graded program exited {status}"
    );
    let Some(stdout): Option<&CapturedStream> = execution.stdout.captured() else {
        panic!(
            "{what}: the graded program's stdout was not captured: {:?}",
            execution.stdout
        );
    };
    assert!(
        !stdout.truncated,
        "{what}: the graded program printed more than {RUN_OUTPUT_LIMIT} bytes"
    );
    String::from_utf8(stdout.bytes.clone()).unwrap_or_else(|error: std::string::FromUtf8Error| {
        panic!("{what}: the graded program printed non-UTF-8: {error}")
    })
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
    assert_build_record(subject);
    let analysis: &NativeLangAnalysis = analyze_origin(subject.origin);
    let scratch: ScratchDir = scratch_dir(&format!("{}-c", subject.language));
    let dir: &Path = scratch.path();
    let mut inputs: Vec<PathBuf> = Vec::new();
    let mut driver: String =
        String::from("#include <stdint.h>\n#include <stdio.h>\n#include <stdlib.h>\n");
    let mut calls: String = String::from("int main(void) {\n");
    let mut expectations: Vec<u64> = Vec::new();
    let mut functions: usize = 0;
    let callees: BTreeSet<&str> = subject
        .cases
        .iter()
        .flat_map(|case: &Case| case.callees.iter().copied())
        .collect();
    for callee in callees {
        writeln!(
            driver,
            "uint64_t {callee}(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3) {{ (void)a0; \
             (void)a1; (void)a2; (void)a3; abort(); }}"
        )
        .expect("define an aborting stub for a callee the graded inputs never reach");
    }
    for case in subject.cases {
        let body: &FunctionBody = body_at(analysis, case);
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
    let mut compile_arguments: Vec<OsString> = vec![
        "-std=c11".into(),
        "-w".into(),
        "-O0".into(),
        "-o".into(),
        exe.clone().into_os_string(),
        driver_path.clone().into_os_string(),
    ];
    compile_arguments.extend(inputs.iter().cloned().map(PathBuf::into_os_string));
    let compiler_invocation: CompilerInvocation = assert_compiles(
        compiler,
        dir,
        compile_arguments,
        &format!("{}: link recovered pseudo-C bodies", subject.language),
    );
    let mut build_inputs: Vec<&Path> = Vec::with_capacity(inputs.len() + 1);
    build_inputs.push(&driver_path);
    build_inputs.extend(inputs.iter().map(PathBuf::as_path));
    let text: String = run_contained(
        &exe,
        &driver_path,
        &authored_origin(subject.recorded),
        &build_inputs,
        &compiler_invocation,
        &format!("{}-c", subject.language),
    );
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
    assert_build_record(subject);
    let analysis: &NativeLangAnalysis = analyze_origin(subject.origin);
    let scratch: ScratchDir = scratch_dir(&format!("{}-rust", subject.language));
    let dir: &Path = scratch.path();
    let mut crate_source: String =
        String::from("#![allow(dead_code, non_snake_case, unused_imports, unused_parens)]\n");
    let mut calls: String = String::from("fn main() {\n");
    let mut expectations: Vec<u64> = Vec::new();
    let mut functions: usize = 0;
    let callees: BTreeSet<&str> = subject
        .cases
        .iter()
        .flat_map(|case: &Case| case.callees.iter().copied())
        .collect();
    for callee in callees {
        writeln!(
            crate_source,
            "#[no_mangle]\npub extern \"C\" fn {callee}(_: u64, _: u64, _: u64, _: u64) -> u64 {{\n    \
             std::process::abort()\n}}"
        )
        .expect("define an aborting stub for a callee the graded inputs never reach");
    }
    for case in subject.cases {
        let body: &FunctionBody = body_at(analysis, case);
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
    let source_bytes: usize = crate_source.len();
    let file: PathBuf = dir.join("graded.rs");
    std::fs::write(&file, &crate_source).expect("write the graded crate");
    let compile_what: String = format!("{}: link recovered pseudo-Rust bodies", subject.language);
    println!(
        "{} pseudo-Rust grade source bytes: {source_bytes}",
        subject.language
    );
    assert_metadata_compiles(compiler, dir, &file, &compile_what);
    let exe: PathBuf = dir.join(if cfg!(windows) {
        "graded.exe"
    } else {
        "graded"
    });
    let compiler_invocation: CompilerInvocation = assert_compiles(
        compiler,
        dir,
        vec![
            "--edition".into(),
            "2021".into(),
            "-A".into(),
            "warnings".into(),
            "-o".into(),
            exe.clone().into_os_string(),
            file.clone().into_os_string(),
        ],
        &compile_what,
    );
    let text: String = run_contained(
        &exe,
        &file,
        &authored_origin(subject.recorded),
        &[file.as_path()],
        &compiler_invocation,
        &format!("{}-rust", subject.language),
    );
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
    Graded {
        functions,
        comparisons: expectations.len(),
    }
}

#[test]
fn every_graded_case_still_covers_the_bytes_its_reference_was_read_from() {
    for subject in SUBJECTS {
        let bytes: Vec<u8> = subject.origin.bytes();
        let analysis: &NativeLangAnalysis = analyze_origin(subject.origin);
        for case in subject.cases {
            let window: Vec<u8> = image_window(&bytes, case.address, case.anchor.len());
            assert_eq!(
                window, case.anchor,
                "{} {}: {} at {:#x} no longer starts with the bytes the reference was derived \
                 from ({}); the grade would compare against a stale reference",
                subject.language, subject.build, case.name, case.address, case.disassembly
            );
            let body: &FunctionBody = body_at(analysis, case);
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
        &["clang", "gcc", "cc"],
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
fn every_graded_subject_matches_its_build_record() {
    for subject in SUBJECTS {
        assert_build_record(subject);
    }
}

#[test]
#[should_panic(expected = "missing-provenance.toml")]
fn a_subject_without_a_build_record_is_refused_before_recovered_code_can_run() {
    assert_recorded(
        Origin::Corpus(NIM_ELF),
        RecordedAs {
            record: Origin::Corpus("nim/missing-provenance.toml"),
            artifact: "hello.nim.elf",
            schema: "disrobe.nativelang.source-build/v1",
            source: "hello.nim",
        },
        "nim 2.0.8",
    );
}

#[test]
#[should_panic(
    expected = "does not match the sha256 its build record zig_modes/provenance.toml pins"
)]
fn a_subject_whose_bytes_differ_from_its_record_is_refused() {
    let drifted: Subject = Subject {
        language: "zig",
        build: "safety-checked x86_64 ELF presented as the recorded ReleaseFast build",
        toolchain: "zig 0.16.0",
        origin: Origin::Corpus(ZIG_ELF),
        recorded: RecordedAs {
            record: Origin::CrateFixture("zig_modes/provenance.toml"),
            artifact: "arith_releasefast_x86_64_linux.elf",
            schema: "disrobe.nativelang.zig-build-modes/v1",
            source: "arith.zig",
        },
        cases: &[],
    };
    assert_build_record(&drifted);
}

#[test]
#[should_panic(
    expected = "crystal_hello/provenance.toml records the producer crystal 1.20.2, but the grade reports crystal 1.19.1"
)]
fn a_subject_reporting_another_toolchain_is_refused() {
    assert_recorded(
        Origin::CrateFixture(CRYSTAL_HELLO_PE),
        CRYSTAL_HELLO,
        "crystal 1.19.1",
    );
}

fn crystal_pairing_heap_body() -> &'static FunctionBody {
    assert_recorded(
        Origin::CrateFixture(CRYSTAL_HELLO_PE),
        CRYSTAL_HELLO,
        CRYSTAL_TOOLCHAIN,
    );
    let analysis: &NativeLangAnalysis = analyze_origin(Origin::CrateFixture(CRYSTAL_HELLO_PE));
    let body: &FunctionBody = analysis
        .bodies
        .bodies
        .iter()
        .find(|body: &&FunctionBody| body.start == 0x0001_4001_4e50)
        .expect("the recorded Crystal pairing-heap combine function must be carved");
    assert_eq!(body.end, 0x0001_4001_4fe0);
    assert_eq!(body.byte_len, 400);
    let bytes: Vec<u8> = crate_fixture_or_fail(CRYSTAL_HELLO_PE);
    assert_eq!(
        image_window(&bytes, body.start, 16),
        [
            0x48, 0x83, 0xec, 0x28, 0x31, 0xc0, 0x48, 0x85, 0xc9, 0x75, 0x26, 0x48, 0x83, 0xc4,
            0x28, 0xc3,
        ],
        "the independent objdump entry anchor must match the graded body"
    );
    body
}

#[test]
fn crystal_pairing_heap_body_matches_the_reference() {
    let compiler: String = tool_or_unmeasured(
        &["clang", "gcc", "cc"],
        "the Crystal pairing-heap body equivalence grade",
    )
    .expect("a C compiler is required for the tracked Crystal pairing-heap grade");
    let body: &FunctionBody = crystal_pairing_heap_body();
    let BodyStatus::Recovered { pseudo_c, .. } = &body.status else {
        panic!("the pairing-heap body must recover, got {:?}", body.status);
    };
    let scratch: ScratchDir = scratch_dir("crystal-pairing-heap");
    let dir: &Path = scratch.path();
    let source: PathBuf = dir.join("recovered.c");
    let reference: PathBuf = support_source("crystal_pairing_heap_reference.c");
    let exe: PathBuf = dir.join(if cfg!(windows) { "grade.exe" } else { "grade" });
    std::fs::write(&source, pseudo_c).expect("write the recovered pairing-heap body");
    let compiler_invocation: CompilerInvocation = assert_compiles(
        compiler.as_str(),
        dir,
        vec![
            "-std=c11".into(),
            "-O0".into(),
            "-o".into(),
            exe.clone().into_os_string(),
            source.clone().into_os_string(),
            reference.clone().into_os_string(),
        ],
        "Crystal pairing-heap C grade",
    );
    let observed: String = run_contained(
        &exe,
        &source,
        &authored_origin(CRYSTAL_HELLO),
        &[source.as_path(), reference.as_path()],
        &compiler_invocation,
        "crystal-pairing-heap",
    );
    assert_eq!(
        observed.trim(),
        "929",
        "all bounded empty, odd, even, signed, tied, and child-linked graphs must be graded"
    );
}

#[test]
fn crystal_pairing_heap_rust_body_matches_the_reference() {
    let compiler: String =
        rustc_compiler("the Crystal pairing-heap pseudo-Rust body equivalence grade")
            .expect("rustc is required for the tracked Crystal pairing-heap pseudo-Rust grade");
    let body: &FunctionBody = crystal_pairing_heap_body();
    let pseudo_rust: &str = recovered_rust(body);
    assert!(pseudo_rust.contains("fn sub_140014e50("), "{pseudo_rust}");
    assert_eq!(
        pseudo_rust.matches("break 'recover_l").count(),
        1,
        "the first loop's exit past the pending-list tail must leave through one labeled block:\n{pseudo_rust}"
    );
    let scratch: ScratchDir = scratch_dir("crystal-pairing-heap-rust");
    let dir: &Path = scratch.path();
    let source: PathBuf = dir.join("graded.rs");
    let exe: PathBuf = dir.join(if cfg!(windows) {
        "graded.exe"
    } else {
        "graded"
    });
    let grade_source: String = format!(
        "#![allow(dead_code, non_snake_case, unused_imports, unused_parens)]\nmod body {{\n{pseudo_rust}\n}}\n{}",
        include_str!("support/crystal_pairing_heap_reference.rs")
    );
    let source_bytes: usize = grade_source.len();
    std::fs::write(&source, grade_source)
        .expect("write the recovered pairing-heap pseudo-Rust grade");
    println!("Crystal pairing-heap pseudo-Rust grade source bytes: {source_bytes}");
    assert_metadata_compiles(
        compiler.as_str(),
        dir,
        &source,
        "Crystal pairing-heap pseudo-Rust grade",
    );
    let compiler_invocation: CompilerInvocation = assert_compiles(
        compiler.as_str(),
        dir,
        vec![
            "--edition".into(),
            "2021".into(),
            "-A".into(),
            "warnings".into(),
            "-o".into(),
            exe.clone().into_os_string(),
            source.clone().into_os_string(),
        ],
        "Crystal pairing-heap pseudo-Rust grade",
    );
    let observed: String = run_contained(
        &exe,
        &source,
        &authored_origin(CRYSTAL_HELLO),
        &[source.as_path()],
        &compiler_invocation,
        "crystal-pairing-heap-rust",
    );
    assert_eq!(
        observed.trim(),
        "929",
        "all bounded empty, odd, even, signed, tied, and child-linked graphs must be graded"
    );
}

#[test]
fn zig_float_rounding_preserves_branch_predecessor_conditions() {
    let compiler: String = tool_or_unmeasured(
        &["clang", "gcc", "cc"],
        "the Zig floating-point rounding grade",
    )
    .expect("a C compiler is required for the tracked Zig rounding grade");
    assert_recorded(Origin::Corpus(ZIG_ELF), ZIG_HELLO, ZIG_HELLO_TOOLCHAIN);
    let analysis: &NativeLangAnalysis = analyze_origin(Origin::Corpus(ZIG_ELF));
    let body: &FunctionBody = analysis
        .bodies
        .bodies
        .iter()
        .find(|body: &&FunctionBody| body.start == 0x10b_df30)
        .expect("the recorded Zig extended-to-float conversion must be carved");
    assert_eq!(body.name, "__truncxfsf2");
    assert_eq!(body.end, 0x10b_e03b);
    let BodyStatus::Recovered { pseudo_c, .. } = &body.status else {
        panic!("the conversion must recover, got {:?}", body.status);
    };
    let scratch: ScratchDir = scratch_dir("zig-float-rounding");
    let dir: &Path = scratch.path();
    let source: PathBuf = dir.join("recovered.c");
    let reference: PathBuf = support_source("zig_float_rounding_reference.c");
    let exe: PathBuf = dir.join(if cfg!(windows) { "grade.exe" } else { "grade" });
    assert!(pseudo_c.contains("float __truncxfsf2("));
    std::fs::write(
        &source,
        pseudo_c.replacen("float __truncxfsf2(", "float recovered_truncxfsf2(", 1),
    )
    .expect("write the recovered conversion under a non-builtin symbol");
    let compiler_invocation: CompilerInvocation = assert_compiles(
        compiler.as_str(),
        dir,
        vec![
            "-std=c11".into(),
            "-O0".into(),
            "-o".into(),
            exe.clone().into_os_string(),
            source.clone().into_os_string(),
            reference.clone().into_os_string(),
        ],
        "Zig float-rounding grade",
    );
    let observed: String = run_contained(
        &exe,
        &source,
        &authored_origin(ZIG_HELLO),
        &[source.as_path(), reference.as_path()],
        &compiler_invocation,
        "zig-float-rounding",
    );
    assert_eq!(observed.trim(), "42");
}

#[test]
fn recovered_pseudo_rust_bodies_recompile_to_the_reference() {
    let Some(compiler): Option<String> =
        rustc_compiler("the nativelang pseudo-Rust body equivalence grade")
    else {
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
    let zig: &NativeLangAnalysis = analyze_origin(Origin::CrateFixture(ZIG_RELEASEFAST_ELF));
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
}

#[test]
fn nim_fib_recovers_pseudo_c_and_pseudo_rust() {
    let nim: &NativeLangAnalysis = analyze_origin(Origin::Corpus(NIM_ELF));
    let fib: &FunctionBody = nim
        .bodies
        .bodies
        .iter()
        .find(|body: &&FunctionBody| body.name == "hello.fib")
        .expect("corpus/native/nim/hello.nim declares fib, so hello.fib must be carved");
    let BodyStatus::Recovered {
        ref pseudo_c,
        pseudo_rust: RustBody::Emitted(ref pseudo_rust),
    } = fib.status
    else {
        panic!(
            "hello.fib must recover pseudo-C and pseudo-Rust through nativelang analysis, got {:?}",
            fib.status
        );
    };
    assert!(
        pseudo_c.contains("return"),
        "the recovered Nim pseudo-C body must expose an executable return path, got {pseudo_c}"
    );
    assert!(
        pseudo_rust.contains("return"),
        "the recovered Nim pseudo-Rust body must expose an executable return path, got {pseudo_rust}"
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

#[test]
fn every_recorded_toolchain_version_is_backed_by_the_artifact_or_its_provenance() {
    assert!(
        contains(&fixture_or_fail(NIM_ELF), "nim-2.0.8"),
        "the nim equivalence cases report nim 2.0.8, so the graded artifact must carry that \
         version string"
    );
    assert!(
        contains(&fixture_or_fail(ZIG_ELF), "zig 0.13.0"),
        "the zig safety-checked mode is reported as zig 0.13.0, so the graded artifact must carry \
         that version string"
    );
    let mm: Vec<u8> = crate_fixture_or_fail("nim_mm/mm_arc.exe");
    assert!(
        contains(&mm, "MinGW-W64") && contains(&mm, "13.2.0"),
        "the nim memory-management modes are reported as mingw-w64 gcc 13.2.0 builds, so the \
         graded artifacts must carry that backend string"
    );
    let crystal: Vec<u8> = fixture_or_fail(CRYSTAL_PE);
    for spelling in ["Crystal 1.", "crystal-1.", "Crystal 0.", "crystal-0."] {
        assert!(
            !contains(&crystal, spelling),
            "the crystal build mode is reported as version-unrecorded, but the artifact carries \
             {spelling}; record the real version instead"
        );
    }

    let provenance: PathBuf = crate_fixture_path("zig_modes/provenance.toml");
    let text: String = std::fs::read_to_string(&provenance).unwrap_or_else(|error| {
        panic!(
            "{} records the pinned toolchain for the ReleaseFast fixture: {error}",
            provenance.display()
        )
    });
    for required in [
        "producer = \"zig 0.16.0\"",
        "build_mode = \"ReleaseFast\"",
        "target = \"x86_64-linux-gnu\"",
        "zig build-exe arith.zig -OReleaseFast",
    ] {
        assert!(
            text.contains(required),
            "the zig fixture provenance must record {required}"
        );
    }
    for case in ZIG_CASES {
        assert!(
            text.contains(&format!("\"{}\",", case.name)),
            "the zig fixture provenance must list {} among the graded functions",
            case.name
        );
    }
    assert!(
        text.contains("\"dr_rotl\""),
        "the zig fixture provenance must record dr_rotl as the abstaining function"
    );
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
    analysis: OnceLock<NativeLangAnalysis>,
}

static MODE_RATES: [ModeRate; 11] = [
    ModeRate {
        language: "nim",
        build: "C backend, safety-checked, x86_64 ELF",
        toolchain: "nim 2.0.8",
        origin: Origin::Corpus(NIM_ELF),
        functions: 185,
        recovered: 84,
        rust: 84,
        analysis: OnceLock::new(),
    },
    ModeRate {
        language: "nim",
        build: "--mm:arc, x86_64 PE",
        toolchain: "nim (mingw-w64 gcc 13.2.0 backend)",
        origin: Origin::CrateFixture("nim_mm/mm_arc.exe"),
        functions: 559,
        recovered: 179,
        rust: 173,
        analysis: OnceLock::new(),
    },
    ModeRate {
        language: "nim",
        build: "--mm:orc, x86_64 PE",
        toolchain: "nim (mingw-w64 gcc 13.2.0 backend)",
        origin: Origin::CrateFixture("nim_mm/mm_orc.exe"),
        functions: 583,
        recovered: 186,
        rust: 180,
        analysis: OnceLock::new(),
    },
    ModeRate {
        language: "nim",
        build: "--mm:refc, x86_64 PE",
        toolchain: "nim (mingw-w64 gcc 13.2.0 backend)",
        origin: Origin::CrateFixture("nim_mm/mm_refc.exe"),
        functions: 620,
        recovered: 205,
        rust: 196,
        analysis: OnceLock::new(),
    },
    ModeRate {
        language: "nim",
        build: "--mm:boehm, x86_64 PE",
        toolchain: "nim (mingw-w64 gcc 13.2.0 backend)",
        origin: Origin::CrateFixture("nim_mm/mm_boehm.exe"),
        functions: 255,
        recovered: 52,
        rust: 52,
        analysis: OnceLock::new(),
    },
    ModeRate {
        language: "nim",
        build: "--mm:markAndSweep, x86_64 PE",
        toolchain: "nim (mingw-w64 gcc 13.2.0 backend)",
        origin: Origin::CrateFixture("nim_mm/mm_markAndSweep.exe"),
        functions: 600,
        recovered: 200,
        rust: 194,
        analysis: OnceLock::new(),
    },
    ModeRate {
        language: "nim",
        build: "--mm:go, x86_64 PE",
        toolchain: "nim (mingw-w64 gcc 13.2.0 backend)",
        origin: Origin::CrateFixture("nim_mm/mm_go.exe"),
        functions: 528,
        recovered: 172,
        rust: 166,
        analysis: OnceLock::new(),
    },
    ModeRate {
        language: "nim",
        build: "--mm:none, x86_64 PE",
        toolchain: "nim (mingw-w64 gcc 13.2.0 backend)",
        origin: Origin::CrateFixture("nim_mm/mm_none.exe"),
        functions: 539,
        recovered: 175,
        rust: 169,
        analysis: OnceLock::new(),
    },
    ModeRate {
        language: "zig",
        build: "safety-checked, x86_64 ELF",
        toolchain: "zig 0.13.0",
        origin: Origin::Corpus(ZIG_ELF),
        functions: 1356,
        recovered: 331,
        rust: 327,
        analysis: OnceLock::new(),
    },
    ModeRate {
        language: "zig",
        build: "ReleaseFast, x86_64-linux-gnu ELF",
        toolchain: "zig 0.16.0",
        origin: Origin::CrateFixture(ZIG_RELEASEFAST_ELF),
        functions: 23,
        recovered: 9,
        rust: 9,
        analysis: OnceLock::new(),
    },
    ModeRate {
        language: "crystal",
        build: "LLVM backend, stripped x86_64 PE",
        toolchain: "crystal (version not recorded in the artifact)",
        origin: Origin::Corpus(CRYSTAL_PE),
        functions: 438,
        recovered: 38,
        rust: 38,
        analysis: OnceLock::new(),
    },
];

#[test]
fn the_body_recovery_rate_is_recorded_per_language_and_build_mode() {
    for rate in &MODE_RATES {
        let bodies: &disrobe_pass_nativelang::BodyRecovery = &analyze_origin(rate.origin).bodies;
        println!(
            "{} [{}] [{}]: {}/{} carved functions recovered a pseudo-C body, {}/{} a pseudo-Rust \
             body",
            rate.language,
            rate.toolchain,
            rate.build,
            bodies.recovered,
            bodies.function_count,
            bodies.rust_bodies,
            bodies.function_count
        );
        assert_eq!(
            bodies.function_count, rate.functions,
            "{} [{}]: the carved function count moved",
            rate.language, rate.build
        );
        assert_eq!(
            bodies.recovered, rate.recovered,
            "{} [{}]: the recovered pseudo-C body count moved",
            rate.language, rate.build
        );
        assert_eq!(
            bodies.rust_bodies, rate.rust,
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
    for rate in &MODE_RATES {
        let bodies: &disrobe_pass_nativelang::BodyRecovery = &analyze_origin(rate.origin).bodies;
        for body in &bodies.bodies {
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
    for rate in &MODE_RATES {
        let bodies: &disrobe_pass_nativelang::BodyRecovery = &analyze_origin(rate.origin).bodies;
        let total: u32 =
            bodies.recovered + bodies.recovered_elided + bodies.rejected + bodies.not_attempted;
        assert_eq!(
            total, bodies.function_count,
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
