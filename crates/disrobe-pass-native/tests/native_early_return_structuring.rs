#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines,
    clippy::too_many_arguments
)]

mod common;

use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::Mutex;

use common::{
    CompileOutcome, CompilerFamily, CompilerId, RunOutcome, available_compilers, codegen_flags,
    compile_object_reasoned, function_code, link_and_run_reasoned, scratch_dir, strip_includes,
};
use disrobe_core::rng::seeded;
use disrobe_pass_native::{
    ProgramFunction, PseudoAbi, RecoveredFunction, RecoveredProgram, recover_program,
};
use rand::RngExt as _;

const MASTER_SEED: u64 = 0x0EA7_1E5E_7C0D_E001;
const INPUT_MAGNITUDE: i64 = 1000;
const RANDOM_DRAWS_PER_ROW: usize = 8;
const WORKER_COUNT: usize = 4;
const RUN_TIMEOUT_SECS: u64 = 20;
const GRADED_OPT_LEVELS: [&str; 3] = ["-O0", "-O1", "-O2"];
const REPORTED_OPT_LEVELS: [&str; 1] = ["-O3"];
const ABI_TARGETS: [AbiTarget; 2] = [AbiTarget::MsX64, AbiTarget::SysV];
const EQUIVALENT_ROW_FLOOR: usize = 350;
const ENTRY_ARITY: usize = 3;
const OVER_INFERRED_ARGUMENT: u64 = 0xA5A5_5A5A_C3C3_3C3C;
const REJECTION_MARKER: &str = "multiple/early returns not in forward-skip class";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AbiTarget {
    MsX64,
    SysV,
}

impl AbiTarget {
    const fn tag(self) -> &'static str {
        match self {
            Self::MsX64 => "ms_x64",
            Self::SysV => "sysv",
        }
    }

    const fn as_pseudo(self) -> PseudoAbi {
        match self {
            Self::MsX64 => PseudoAbi::MsX64,
            Self::SysV => PseudoAbi::SysV,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResultChannel {
    Integer64,
    VoidPointerOut,
}

impl ResultChannel {
    const fn compares_return_register(self) -> bool {
        matches!(self, Self::Integer64)
    }

    const fn host_result_type(self) -> &'static str {
        match self {
            Self::Integer64 => "long long",
            Self::VoidPointerOut => "void",
        }
    }

    const fn host_last_parameter(self) -> &'static str {
        match self {
            Self::Integer64 => "long long",
            Self::VoidPointerOut => "long long *",
        }
    }
}

struct ExitShape {
    tag: &'static str,
    entry: &'static str,
    functions: &'static [&'static str],
    c_source: &'static str,
    extra_boundaries: &'static [i64],
    permit_sibling_calls: bool,
    channel: ResultChannel,
}

const SHAPES: &[ExitShape] = &[
    ExitShape {
        tag: "guard_single",
        entry: "er_guard_single",
        functions: &["er_guard_single"],
        c_source: "long long er_guard_single(long long a, long long b, long long c){ if (a < 0) return -1; return a + b + c; }",
        extra_boundaries: &[],
        permit_sibling_calls: false,
        channel: ResultChannel::Integer64,
    },
    ExitShape {
        tag: "guard_chain",
        entry: "er_guard_chain",
        functions: &["er_guard_chain"],
        c_source: "long long er_guard_chain(long long a, long long b, long long c){ if (a < 0) return -1; if (b < 0) return -2; if (c < 0) return -3; return a + b + c; }",
        extra_boundaries: &[],
        permit_sibling_calls: false,
        channel: ResultChannel::Integer64,
    },
    ExitShape {
        tag: "return_in_nested_if",
        entry: "er_nested_if",
        functions: &["er_nested_if"],
        c_source: "long long er_nested_if(long long a, long long b, long long c){ if (a > 0) { if (b > 0) { if (c > 0) return a + b + c; } return a - b; } return 0; }",
        extra_boundaries: &[],
        permit_sibling_calls: false,
        channel: ResultChannel::Integer64,
    },
    ExitShape {
        tag: "return_in_loop",
        entry: "er_loop_find",
        functions: &["er_loop_find"],
        c_source: "long long er_loop_find(long long a, long long b, long long c){ for (long long i = 0; i < 64; i++) { if (a + i == b) return i; } return c - 1; }",
        extra_boundaries: &[3, 7, 63, 64],
        permit_sibling_calls: false,
        channel: ResultChannel::Integer64,
    },
    ExitShape {
        tag: "return_in_loop_accumulator",
        entry: "er_loop_accum",
        functions: &["er_loop_accum"],
        c_source: "long long er_loop_accum(long long a, long long b, long long c){ long long s = 0; for (long long i = 0; i < 64; i++) { s += a; if (s > b) return i + c; } return -1; }",
        extra_boundaries: &[2, 5],
        permit_sibling_calls: false,
        channel: ResultChannel::Integer64,
    },
    ExitShape {
        tag: "return_in_nested_loop",
        entry: "er_nested_loop",
        functions: &["er_nested_loop"],
        c_source: "long long er_nested_loop(long long a, long long b, long long c){ for (long long i = 1; i < 32; i++) { for (long long j = 1; j < 32; j++) { if (i * j == a) return i + j + b; } } return c - 1; }",
        extra_boundaries: &[1, 4, 9, 25, 31],
        permit_sibling_calls: false,
        channel: ResultChannel::Integer64,
    },
    ExitShape {
        tag: "return_in_switch_case",
        entry: "er_switch_case",
        functions: &["er_switch_case"],
        c_source: "long long er_switch_case(long long a, long long b, long long c){ switch (a & 7) { case 0: return b; case 1: return c; case 2: return b + c; case 3: return b - c; case 4: return b * 2; default: break; } return a + b + c; }",
        extra_boundaries: &[0, 1, 2, 3, 4, 5, 6, 7, 8],
        permit_sibling_calls: false,
        channel: ResultChannel::Integer64,
    },
    ExitShape {
        tag: "shared_epilogue_over_call",
        entry: "er_shared_entry",
        functions: &["er_shared_entry", "er_shared_h"],
        c_source: "__attribute__((noinline,noclone)) long long er_shared_h(long long x, long long y){ return x * 2 + y; }\n\
                    long long er_shared_entry(long long a, long long b, long long c){ if (a < 0) return er_shared_h(a, b); if (b < 0) return er_shared_h(b, c); return er_shared_h(c, a); }",
        extra_boundaries: &[],
        permit_sibling_calls: false,
        channel: ResultChannel::Integer64,
    },
    ExitShape {
        tag: "four_return_sites",
        entry: "er_four_sites",
        functions: &["er_four_sites"],
        c_source: "long long er_four_sites(long long a, long long b, long long c){ if (a > 0) return a; if (b > 0) return b; if (c > 0) return c; return 0; }",
        extra_boundaries: &[],
        permit_sibling_calls: false,
        channel: ResultChannel::Integer64,
    },
    ExitShape {
        tag: "returns_after_loop",
        entry: "er_after_loop",
        functions: &["er_after_loop"],
        c_source: "long long er_after_loop(long long a, long long b, long long c){ long long s = 0; long long i = 0; while (i < a) { s += b; i++; } if (s > c) return s; return c; }",
        extra_boundaries: &[0, 1, 2, 16],
        permit_sibling_calls: false,
        channel: ResultChannel::Integer64,
    },
    ExitShape {
        tag: "noreturn_exit_path",
        entry: "er_noreturn_entry",
        functions: &["er_noreturn_entry"],
        c_source: "long long er_noreturn_entry(long long a, long long b, long long c){ if (a == 4242) { __builtin_trap(); } if (b < 0) return -1; return a + b + c; }",
        extra_boundaries: &[],
        permit_sibling_calls: false,
        channel: ResultChannel::Integer64,
    },
    ExitShape {
        tag: "multi_return_in_loop",
        entry: "er_multi_in_loop",
        functions: &["er_multi_in_loop"],
        c_source: "long long er_multi_in_loop(long long a, long long b, long long c){ for (long long i = 0; i < 64; i++) { if (a + i == b) return i; if (a - i == c) return -i; } return 0; }",
        extra_boundaries: &[1, 5, 63],
        permit_sibling_calls: false,
        channel: ResultChannel::Integer64,
    },
    ExitShape {
        tag: "loop_inside_guard",
        entry: "er_loop_in_guard",
        functions: &["er_loop_in_guard"],
        c_source: "long long er_loop_in_guard(long long a, long long b, long long c){ if (a > 0) { for (long long i = 0; i < 64; i++) { if (i * i > a) return i + b; } } return c - 1; }",
        extra_boundaries: &[4, 9, 100],
        permit_sibling_calls: false,
        channel: ResultChannel::Integer64,
    },
    ExitShape {
        tag: "loop_break_and_return",
        entry: "er_break_and_return",
        functions: &["er_break_and_return"],
        c_source: "long long er_break_and_return(long long a, long long b, long long c){ long long s = 0; for (long long i = 0; i < 64; i++) { if (i > b) break; if (i == c) return 999; s += i + a; } return s; }",
        extra_boundaries: &[0, 3, 8, 63],
        permit_sibling_calls: false,
        channel: ResultChannel::Integer64,
    },
    ExitShape {
        tag: "do_while_early_return",
        entry: "er_do_while",
        functions: &["er_do_while"],
        c_source: "long long er_do_while(long long a, long long b, long long c){ long long i = 0; do { if (a + i == b) return i; i++; } while (i < 32); return c - 1; }",
        extra_boundaries: &[0, 6, 31],
        permit_sibling_calls: false,
        channel: ResultChannel::Integer64,
    },
    ExitShape {
        tag: "nested_loops_two_returns",
        entry: "er_nested_two_returns",
        functions: &["er_nested_two_returns"],
        c_source: "long long er_nested_two_returns(long long a, long long b, long long c){ for (long long i = 1; i < 16; i++) { for (long long j = 1; j < 16; j++) { if (i * j == a) return i; } if (i == b) return -i; } return c; }",
        extra_boundaries: &[1, 6, 15, 30],
        permit_sibling_calls: false,
        channel: ResultChannel::Integer64,
    },
    ExitShape {
        tag: "guard_loop_tail",
        entry: "er_guard_loop_tail",
        functions: &["er_guard_loop_tail"],
        c_source: "long long er_guard_loop_tail(long long a, long long b, long long c){ if (a < 0) return -1; long long s = 0; for (long long i = 0; i < 32; i++) { if (s > b) return s; s += a; } return s + c; }",
        extra_boundaries: &[0, 2, 17],
        permit_sibling_calls: false,
        channel: ResultChannel::Integer64,
    },
    ExitShape {
        tag: "switch_in_loop_return",
        entry: "er_switch_in_loop",
        functions: &["er_switch_in_loop"],
        c_source: "long long er_switch_in_loop(long long a, long long b, long long c){ long long s = 0; for (long long i = 0; i < 16; i++) { switch ((a + i) & 3) { case 0: s += 1; break; case 1: return i + b; case 2: s += 2; break; default: s += 3; } } return s + c; }",
        extra_boundaries: &[0, 1, 2, 3],
        permit_sibling_calls: false,
        channel: ResultChannel::Integer64,
    },
    ExitShape {
        tag: "call_in_loop_early_return",
        entry: "er_call_loop_entry",
        functions: &["er_call_loop_entry", "er_call_loop_h"],
        c_source: "__attribute__((noinline,noclone)) long long er_call_loop_h(long long x, long long y){ return x * 2 + y; }\n\
                    long long er_call_loop_entry(long long a, long long b, long long c){ for (long long i = 0; i < 16; i++) { long long v = er_call_loop_h(a + i, b); if (v > c) return i; } return -1; }",
        extra_boundaries: &[0, 4, 15],
        permit_sibling_calls: false,
        channel: ResultChannel::Integer64,
    },
    ExitShape {
        tag: "three_way_join_then_return",
        entry: "er_join_tail",
        functions: &["er_join_tail"],
        c_source: "long long er_join_tail(long long a, long long b, long long c){ long long s = 0; for (long long i = 0; i < 16; i++) { long long t; if (((a + i) & 3) == 0) { t = i * 2; } else if (((a + i) & 3) == 1) { s += 5; continue; } else { t = i * 3; } if (t == b) return t + c; s += t; } return s; }",
        extra_boundaries: &[0, 2, 6, 9],
        permit_sibling_calls: false,
        channel: ResultChannel::Integer64,
    },
    ExitShape {
        tag: "guard_chain_shared_tail",
        entry: "er_shared_tail",
        functions: &["er_shared_tail"],
        c_source: "long long er_shared_tail(long long a, long long b, long long c){ long long r; if (a > b) { r = a - b; } else if (b > c) { r = b - c; } else if (c > a) { return 0; } else { r = a + b; } return r * 2 + c; }",
        extra_boundaries: &[],
        permit_sibling_calls: false,
        channel: ResultChannel::Integer64,
    },
    ExitShape {
        tag: "two_breaks_shared_tail",
        entry: "er_two_breaks",
        functions: &["er_two_breaks"],
        c_source: "long long er_two_breaks(long long a, long long b, long long c){ long long s = 0; for (long long i = 0; i < 32; i++) { if (i == a) { s += 1; break; } if (i == b) { s += 2; break; } s += i; } return s + c; }",
        extra_boundaries: &[0, 1, 7, 31],
        permit_sibling_calls: false,
        channel: ResultChannel::Integer64,
    },
    ExitShape {
        tag: "two_latch_continue_and_return",
        entry: "er_two_latch",
        functions: &["er_two_latch"],
        c_source: "long long er_two_latch(long long a, long long b, long long c){ long long s = 0; for (long long i = 0; i < 32; i++) { if ((i & 1) == 0) { s += a; continue; } if (i == b) return s; s += c; } return s + 1; }",
        extra_boundaries: &[0, 1, 3, 30, 31],
        permit_sibling_calls: false,
        channel: ResultChannel::Integer64,
    },
    ExitShape {
        tag: "three_latch_continue_and_return",
        entry: "er_three_latch",
        functions: &["er_three_latch"],
        c_source: "long long er_three_latch(long long a, long long b, long long c){ long long s = 0; for (long long i = 0; i < 32; i++) { if ((i & 3) == 0) { s += a; continue; } if ((i & 3) == 1) { s += b; continue; } if (i == c) return s; s += 1; } return s; }",
        extra_boundaries: &[0, 1, 2, 5, 31],
        permit_sibling_calls: false,
        channel: ResultChannel::Integer64,
    },
    ExitShape {
        tag: "nested_loop_multi_latch_return",
        entry: "er_nested_multi_latch",
        functions: &["er_nested_multi_latch"],
        c_source: "long long er_nested_multi_latch(long long a, long long b, long long c){ long long s = 0; for (long long i = 1; i < 16; i++) { for (long long j = 1; j < 16; j++) { if (((i + j) & 1) == 0) { s += a; continue; } if (i * j == b) return s + i; s += j; } } return s + c; }",
        extra_boundaries: &[1, 4, 9, 15, 225],
        permit_sibling_calls: false,
        channel: ResultChannel::Integer64,
    },
    ExitShape {
        tag: "void_return_from_loop",
        entry: "er_void_loop",
        functions: &["er_void_loop"],
        c_source: "void er_void_loop(long long a, long long b, long long *out){ for (long long i = 0; i < 32; i++) { if (a + i == b) { *out = i; return; } } *out = -1; }",
        extra_boundaries: &[0, 1, 7, 31, 32],
        permit_sibling_calls: false,
        channel: ResultChannel::VoidPointerOut,
    },
    ExitShape {
        tag: "void_guard_chain",
        entry: "er_void_guards",
        functions: &["er_void_guards"],
        c_source: "void er_void_guards(long long a, long long b, long long *out){ if (a < 0) { *out = -1; return; } if (b < 0) { *out = -2; return; } *out = a + b; }",
        extra_boundaries: &[],
        permit_sibling_calls: false,
        channel: ResultChannel::VoidPointerOut,
    },
    ExitShape {
        tag: "tail_call_only_exit",
        entry: "er_tail_entry",
        functions: &["er_tail_entry", "er_tail_h"],
        c_source: "__attribute__((noinline,noclone)) long long er_tail_h(long long a, long long b){ return a + b * 3; }\n\
                    long long er_tail_entry(long long a, long long b, long long c){ return er_tail_h(a, b + c); }",
        extra_boundaries: &[],
        permit_sibling_calls: true,
        channel: ResultChannel::Integer64,
    },
];

#[derive(Debug, Clone)]
enum Verdict {
    Equivalent,
    Mismatch(String),
    Abstained(String),
    NotGraded(String),
}

impl Verdict {
    const fn label(&self) -> &'static str {
        match self {
            Self::Equivalent => "equivalent",
            Self::Mismatch(_) => "MISMATCH",
            Self::Abstained(_) => "abstained",
            Self::NotGraded(_) => "not_graded",
        }
    }

    fn detail(&self) -> &str {
        match self {
            Self::Equivalent => "",
            Self::Mismatch(reason) | Self::Abstained(reason) | Self::NotGraded(reason) => reason,
        }
    }
}

#[derive(Debug, Clone)]
struct ExitRow {
    shape: &'static str,
    compiler: String,
    opt: &'static str,
    abi: &'static str,
    verdict: Verdict,
    teeth_confirmed: bool,
    floor_graded: bool,
}

fn row_key(row: &ExitRow) -> String {
    format!("{}|{}|{}|{}", row.shape, row.compiler, row.opt, row.abi)
}

fn row_seed(shape: &ExitShape, compiler: &str, opt: &str, abi: AbiTarget) -> u64 {
    use std::hash::{Hash as _, Hasher as _};
    let mut hasher: std::collections::hash_map::DefaultHasher =
        std::collections::hash_map::DefaultHasher::new();
    MASTER_SEED.hash(&mut hasher);
    shape.tag.hash(&mut hasher);
    compiler.hash(&mut hasher);
    opt.hash(&mut hasher);
    abi.tag().hash(&mut hasher);
    hasher.finish()
}

fn shape_inputs(shape: &ExitShape, seed: u64) -> Vec<(i64, i64, i64)> {
    let mut inputs: Vec<(i64, i64, i64)> = [0i64, 1, -1, INPUT_MAGNITUDE, -INPUT_MAGNITUDE]
        .into_iter()
        .chain(shape.extra_boundaries.iter().copied())
        .map(|v: i64| (v, v, v))
        .collect();
    for &v in shape.extra_boundaries {
        inputs.push((v, 3, 5));
        inputs.push((7, v, 11));
    }
    let mut rng = seeded(seed);
    for _ in 0..RANDOM_DRAWS_PER_ROW {
        let a: i64 = rng.random_range(-INPUT_MAGNITUDE..=INPUT_MAGNITUDE);
        let b: i64 = rng.random_range(-INPUT_MAGNITUDE..=INPUT_MAGNITUDE);
        let c: i64 = rng.random_range(-INPUT_MAGNITUDE..=INPUT_MAGNITUDE);
        inputs.push((a, b, c));
    }
    inputs
}

fn build_driver(
    shape: &ExitShape,
    inputs: &[(i64, i64, i64)],
    entry_params: usize,
    tu: &str,
) -> String {
    let entry: &str = shape.entry;
    let name: &str = shape.tag;
    let rec_args: String = (0..entry_params)
        .map(|i: usize| match (shape.channel, i) {
            (ResultChannel::VoidPointerOut, 2) => "(uint64_t)(uintptr_t)&got".to_owned(),
            (_, i) if i < ENTRY_ARITY => format!("(uint64_t)in[{i}]"),
            _ => format!("{OVER_INFERRED_ARGUMENT}ULL"),
        })
        .collect::<Vec<String>>()
        .join(", ");
    let inputs_literal: String = inputs
        .iter()
        .map(|(a, b, c): &(i64, i64, i64)| format!("{{{a}LL,{b}LL,{c}LL}}"))
        .collect::<Vec<String>>()
        .join(",");
    let mut body: String = String::new();
    let _: core::fmt::Result = match shape.channel {
        ResultChannel::Integer64 => write!(
            body,
            "    for (size_t k = 0; k < n_inputs; k++) {{\n\
             \x20       long long in[3] = {{ inputs[k][0], inputs[k][1], inputs[k][2] }};\n\
             \x20       unsigned long long want = (unsigned long long){entry}(in[0], in[1], in[2]);\n\
             \x20       unsigned long long got = (unsigned long long)rec_{entry}({rec_args});\n\
             \x20       if (want != got) {{ printf(\"MISMATCH {name} in=%lld,%lld,%lld want=%llu got=%llu\\n\", in[0], in[1], in[2], want, got); return 1; }}\n\
             \x20   }}\n",
        ),
        ResultChannel::VoidPointerOut => write!(
            body,
            "    for (size_t k = 0; k < n_inputs; k++) {{\n\
             \x20       long long in[3] = {{ inputs[k][0], inputs[k][1], inputs[k][2] }};\n\
             \x20       long long want = 0x5EEDC0DELL;\n\
             \x20       long long got = 0x5EEDC0DELL;\n\
             \x20       {entry}(in[0], in[1], &want);\n\
             \x20       (void)rec_{entry}({rec_args});\n\
             \x20       if (want != got) {{ printf(\"MISMATCH {name} in=%lld,%lld,%lld want=%lld got=%lld\\n\", in[0], in[1], in[2], want, got); return 1; }}\n\
             \x20   }}\n",
        ),
    };
    let result: &str = shape.channel.host_result_type();
    let last: &str = shape.channel.host_last_parameter();
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n{tu}\n\
         extern {result} {entry}(long long, long long, {last});\n\
         int main(void) {{\n\
         \x20   long long inputs[][3] = {{ {inputs_literal} }};\n\
         \x20   size_t n_inputs = sizeof(inputs)/sizeof(inputs[0]);\n\
         {body}\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n",
    )
}

fn entry_body_range(tu: &str, fn_marker: &str) -> Option<(usize, usize)> {
    let start_sig: usize = tu.find(fn_marker)?;
    let body_open: usize = start_sig + tu[start_sig..].find('{')?;
    let mut depth: i32 = 0;
    for (i, ch) in tu[body_open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((body_open, body_open + i));
                }
            }
            _ => {}
        }
    }
    None
}

fn corrupt_every_pointer_store(tu: &str, fn_marker: &str) -> Option<String> {
    let (body_open, body_close): (usize, usize) = entry_body_range(tu, fn_marker)?;
    let body: &str = &tu[body_open..=body_close];
    let mut any: bool = false;
    let mut rewritten: Vec<String> = Vec::new();
    for line in body.lines() {
        let unpadded: &str = line.trim_end();
        let statement: &str = unpadded.trim_start();
        let indent: &str = &unpadded[..unpadded.len().saturating_sub(statement.len())];
        let stored: Option<(&str, &str)> = statement
            .strip_suffix(';')
            .filter(|write: &&str| {
                write.starts_with("(*(") && !write.contains("r_rsp") && !write.contains("r_rbp")
            })
            .and_then(|write: &str| write.split_once(") = "));
        if let Some((lhs, rhs)) = stored {
            rewritten.push(format!("{indent}{lhs}) = ({rhs}) + 1;"));
            any = true;
        } else {
            rewritten.push(line.to_owned());
        }
    }
    any.then(|| {
        let mut out: String = String::with_capacity(tu.len().saturating_add(128));
        out.push_str(&tu[..body_open]);
        out.push_str(&rewritten.join("\n"));
        out.push_str(&tu[body_close.saturating_add(1)..]);
        out
    })
}

fn corrupt_every_return(tu: &str, fn_marker: &str) -> Option<String> {
    let (body_open, body_close): (usize, usize) = entry_body_range(tu, fn_marker)?;
    let body: &str = &tu[body_open..=body_close];
    let mut mutated_body: String = String::with_capacity(body.len().saturating_add(64));
    let mut rest: &str = body;
    let mut any: bool = false;
    while let Some(pos) = rest.find("return ") {
        let marker_len: usize = "return ".len();
        mutated_body.push_str(&rest[..pos.saturating_add(marker_len)]);
        let after: &str = &rest[pos.saturating_add(marker_len)..];
        let Some(semi) = after.find(';') else {
            mutated_body.push_str(after);
            rest = "";
            break;
        };
        let expr: &str = &after[..semi];
        mutated_body.push('(');
        mutated_body.push_str(expr);
        mutated_body.push_str(") + 1");
        rest = &after[semi..];
        any = true;
    }
    mutated_body.push_str(rest);
    if !any {
        return None;
    }
    let mut out: String = String::with_capacity(tu.len().saturating_add(64));
    out.push_str(&tu[..body_open]);
    out.push_str(&mutated_body);
    out.push_str(&tu[body_close.saturating_add(1)..]);
    Some(out)
}

fn compile_flags(family: CompilerFamily, permit_sibling_calls: bool) -> Vec<&'static str> {
    let mut flags: Vec<&'static str> = codegen_flags(family).to_vec();
    if permit_sibling_calls {
        flags.retain(|f: &&str| *f != "-fno-optimize-sibling-calls");
    }
    flags
}

struct RecoveredShape {
    tu: String,
    entry_params: usize,
    entry_return_width: u32,
}

enum RecoverOutcome {
    Ok(Box<RecoveredShape>),
    Abstained(String),
}

fn recover_shape(object: &[u8], shape: &ExitShape, abi: PseudoAbi) -> RecoverOutcome {
    let mut functions: Vec<ProgramFunction> = Vec::with_capacity(shape.functions.len());
    for &fname in shape.functions {
        let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(object, fname) else {
            return RecoverOutcome::Abstained(format!("{fname} symbol not located in object"));
        };
        functions.push(ProgramFunction {
            name: format!("rec_{fname}"),
            address: base,
            code,
        });
    }
    let result: RecoveredProgram = recover_program(object, &functions, abi);
    if !result.unrecovered.is_empty() {
        let reasons: String = result
            .unrecovered
            .iter()
            .map(|u| format!("{}: {}", u.name, u.reason))
            .collect::<Vec<String>>()
            .join("; ");
        return RecoverOutcome::Abstained(reasons);
    }
    let mut tu: String = String::new();
    let mut entry_params: usize = 0;
    let mut entry_return_width: u32 = 0;
    for (idx, &fname) in shape.functions.iter().enumerate() {
        let rec: &RecoveredFunction = &result.recovered[idx];
        tu.push_str(&strip_includes(&rec.source));
        tu.push('\n');
        if fname == shape.entry {
            entry_params = rec.signature.callable_arity();
            entry_return_width = rec.return_width_bits;
        }
    }
    RecoverOutcome::Ok(Box::new(RecoveredShape {
        tu,
        entry_params,
        entry_return_width,
    }))
}

fn grade_row(
    shape: &'static ExitShape,
    compiler: &CompilerId,
    opt: &'static str,
    abi: AbiTarget,
    floor_graded: bool,
) -> ExitRow {
    let mut row: ExitRow = ExitRow {
        shape: shape.tag,
        compiler: compiler.bin.to_owned(),
        opt,
        abi: abi.tag(),
        verdict: Verdict::NotGraded("ungraded".to_owned()),
        teeth_confirmed: false,
        floor_graded,
    };
    let tag: String = format!(
        "er_{}_{}_{}_{}",
        shape.tag,
        compiler.bin,
        opt.trim_start_matches('-'),
        abi.tag()
    );
    let source: &str = shape.c_source;

    let mut host_flags: Vec<&str> = compile_flags(compiler.family, shape.permit_sibling_calls);
    host_flags.push("-c");
    let scratch: disrobe_core::scratch::ScratchDir = scratch_dir("disrobe-early-return-host");
    let host_out: PathBuf = scratch.path().join(format!("{tag}_host.o"));
    let host_object: Vec<u8> =
        match compile_object_reasoned(compiler.bin, opt, &host_flags, source, &host_out) {
            CompileOutcome::Object(bytes) => bytes,
            CompileOutcome::Rejected(reason) => {
                row.verdict = Verdict::NotGraded(reason);
                return row;
            }
        };

    let object_for_recovery: Vec<u8> = match abi {
        AbiTarget::MsX64 => host_object.clone(),
        AbiTarget::SysV => {
            let mut sysv_flags: Vec<&str> = vec![
                "--target=x86_64-unknown-linux-gnu",
                "-fno-stack-protector",
                "-fcf-protection=none",
                "-c",
            ];
            if !shape.permit_sibling_calls {
                sysv_flags.push("-fno-optimize-sibling-calls");
            }
            let sysv_scratch: disrobe_core::scratch::ScratchDir =
                scratch_dir("disrobe-early-return-sysv");
            let sysv_out: PathBuf = sysv_scratch.path().join(format!("{tag}_sysv.o"));
            match compile_object_reasoned("clang", opt, &sysv_flags, source, &sysv_out) {
                CompileOutcome::Object(bytes) => bytes,
                CompileOutcome::Rejected(reason) => {
                    row.verdict = Verdict::NotGraded(format!("sysv cross-compile: {reason}"));
                    return row;
                }
            }
        }
    };

    let recovered: Box<RecoveredShape> =
        match recover_shape(&object_for_recovery, shape, abi.as_pseudo()) {
            RecoverOutcome::Ok(r) => r,
            RecoverOutcome::Abstained(reason) => {
                row.verdict = Verdict::Abstained(reason);
                return row;
            }
        };
    if shape.channel.compares_return_register() && recovered.entry_return_width != 64 {
        row.verdict = Verdict::NotGraded(format!(
            "the recovered return channel is {} bits wide, so a 64-bit source result has no defined comparison",
            recovered.entry_return_width
        ));
        return row;
    }
    if recovered.entry_params < ENTRY_ARITY {
        row.verdict = Verdict::NotGraded(format!(
            "the recovered prototype takes only {} parameters, so the three source arguments cannot be bound positionally",
            recovered.entry_params
        ));
        return row;
    }

    let inputs: Vec<(i64, i64, i64)> = shape_inputs(shape, row_seed(shape, compiler.bin, opt, abi));
    let driver: String = build_driver(
        shape,
        &inputs,
        recovered.entry_params,
        &strip_includes(&recovered.tu),
    );
    match link_and_run_reasoned(compiler.bin, &driver, &host_object, &tag, RUN_TIMEOUT_SECS) {
        RunOutcome::Ok(stdout) => {
            if stdout.contains("OK") && !stdout.contains("MISMATCH") {
                row.verdict = Verdict::Equivalent;
            } else {
                row.verdict = Verdict::Mismatch(stdout.trim().to_owned());
            }
        }
        RunOutcome::Failed(reason) => {
            row.verdict = Verdict::NotGraded(format!("link/run: {reason}"));
        }
    }

    if matches!(row.verdict, Verdict::Equivalent) {
        let marker: String = format!("rec_{}(", shape.entry);
        let corrupted: Option<String> = match shape.channel {
            ResultChannel::Integer64 => corrupt_every_return(&recovered.tu, &marker),
            ResultChannel::VoidPointerOut => corrupt_every_pointer_store(&recovered.tu, &marker),
        };
        let mutated: String = corrupted.unwrap_or_else(|| {
            panic!(
                "teeth setup failed for {}: the recovered body of rec_{} has no observed write to corrupt",
                shape.tag, shape.entry
            )
        });
        let mutated_driver: String = build_driver(
            shape,
            &inputs,
            recovered.entry_params,
            &strip_includes(&mutated),
        );
        match link_and_run_reasoned(
            compiler.bin,
            &mutated_driver,
            &host_object,
            &format!("{tag}_teeth"),
            RUN_TIMEOUT_SECS,
        ) {
            RunOutcome::Ok(stdout) => {
                assert!(
                    stdout.contains("MISMATCH") && !stdout.contains("OK"),
                    "teeth failed for {}: corrupting every observed write in the recovered body must diverge, got: {stdout}",
                    shape.tag
                );
                row.teeth_confirmed = true;
            }
            RunOutcome::Failed(reason) => {
                panic!("teeth harness for {} failed: {reason}", shape.tag)
            }
        }
    }
    row
}

type ExitTask = (
    &'static ExitShape,
    CompilerId,
    &'static str,
    AbiTarget,
    bool,
);

fn run_matrix() -> Vec<ExitRow> {
    let compilers: Vec<CompilerId> = available_compilers();
    assert!(
        !compilers.is_empty(),
        "the early-exit structuring matrix needs a host C compiler: none of gcc/clang/cc answered --version"
    );
    let mut tasks: Vec<ExitTask> = Vec::new();
    for shape in SHAPES {
        for compiler in &compilers {
            for &opt in &GRADED_OPT_LEVELS {
                for &abi in &ABI_TARGETS {
                    tasks.push((shape, compiler.clone(), opt, abi, true));
                }
            }
            for &opt in &REPORTED_OPT_LEVELS {
                for &abi in &ABI_TARGETS {
                    tasks.push((shape, compiler.clone(), opt, abi, false));
                }
            }
        }
    }
    let indexed: Vec<(usize, ExitTask)> = tasks.into_iter().enumerate().collect();
    let total: usize = indexed.len();
    let queue: Mutex<Vec<(usize, ExitTask)>> = Mutex::new(indexed);
    let results: Mutex<Vec<(usize, ExitRow)>> = Mutex::new(Vec::with_capacity(total));
    let workers: usize = WORKER_COUNT
        .min(std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get))
        .max(1);
    std::thread::scope(|scope: &std::thread::Scope<'_, '_>| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let next: Option<(usize, ExitTask)> = {
                        let mut guard = queue
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        guard.pop()
                    };
                    let Some((idx, (shape, compiler, opt, abi, floor_graded))) = next else {
                        break;
                    };
                    let row: ExitRow = grade_row(shape, &compiler, opt, abi, floor_graded);
                    results
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push((idx, row));
                }
            });
        }
    });
    let mut graded: Vec<(usize, ExitRow)> = results
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    graded.sort_by_key(|(idx, _): &(usize, ExitRow)| *idx);
    graded
        .into_iter()
        .map(|(_, row): (usize, ExitRow)| row)
        .collect()
}

#[test]
fn early_exit_shapes_recompile_to_equivalence_or_name_their_abstention() {
    let rows: Vec<ExitRow> = run_matrix();
    let mut equivalent: usize = 0;
    let mut abstained: usize = 0;
    let mut hit_marker: usize = 0;
    let mut mismatched: Vec<String> = Vec::new();
    let mut unnamed: Vec<String> = Vec::new();
    let mut teeth: usize = 0;
    let mut reported_equivalent: usize = 0;
    let mut equivalent_by_shape: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();

    for shape in SHAPES {
        equivalent_by_shape.insert(shape.tag, 0);
    }
    for row in &rows {
        println!(
            "row {} verdict={} teeth={} floor_graded={} detail={}",
            row_key(row),
            row.verdict.label(),
            row.teeth_confirmed,
            row.floor_graded,
            row.verdict.detail()
        );
        if row.teeth_confirmed {
            teeth += 1;
        }
        match &row.verdict {
            Verdict::Equivalent => {
                if row.floor_graded {
                    equivalent += 1;
                    *equivalent_by_shape.entry(row.shape).or_default() += 1;
                } else {
                    reported_equivalent += 1;
                }
            }
            Verdict::Mismatch(detail) => {
                mismatched.push(format!("{}: {detail}", row_key(row)));
            }
            Verdict::Abstained(detail) => {
                abstained += 1;
                if detail.contains(REJECTION_MARKER) {
                    hit_marker += 1;
                }
                if detail.trim().is_empty() {
                    unnamed.push(row_key(row));
                }
            }
            Verdict::NotGraded(_) => {}
        }
    }

    println!(
        "early-exit census: rows={} floor_equivalent={equivalent} reported_o3_equivalent={reported_equivalent} abstained={abstained} still_hitting_the_multi_return_reject={hit_marker} teeth_confirmed={teeth}",
        rows.len()
    );

    assert!(
        mismatched.is_empty(),
        "a recovered early-exit body computed a different value than the compiled function: {mismatched:#?}"
    );
    assert!(
        unnamed.is_empty(),
        "an abstention carried no reason: {unnamed:#?}"
    );
    assert!(
        equivalent >= EQUIVALENT_ROW_FLOOR,
        "early-exit recompile equivalence fell below the recorded floor: {equivalent} of {} graded rows, floor {EQUIVALENT_ROW_FLOOR}",
        rows.iter().filter(|r: &&ExitRow| r.floor_graded).count()
    );
    assert!(
        teeth >= equivalent,
        "every equivalent row must carry a confirmed mutation: {teeth} confirmed for {equivalent} equivalent rows"
    );
    let unexercised: Vec<&'static str> = equivalent_by_shape
        .iter()
        .filter(|(_, count): &(&&'static str, &usize)| **count == 0)
        .map(|(tag, _): (&&'static str, &usize)| *tag)
        .collect();
    assert!(
        unexercised.is_empty(),
        "every declared exit shape must recompile to equivalence on at least one graded row, otherwise its coverage is claimed but never exercised: {unexercised:#?}"
    );
}
