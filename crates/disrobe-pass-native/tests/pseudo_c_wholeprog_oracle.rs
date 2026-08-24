#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout,
    clippy::print_stderr
)]

mod common;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_native::{
    Arch, DisasmInsn, LeafRecovery, ProgramFunction, PseudoAbi,
    RecoveredFunction as LibRecoveredFunction, RecoveredProgram as LibRecoveredProgram,
    ResolvedCall, disassemble, recover_leaf_function_abi, recover_leaf_function_in_object,
    recover_leaf_function_with_calls, recover_program as lib_recover_program,
};
use object::{Object as _, ObjectSection as _, ObjectSymbol as _};

use common::{
    HOST_ABI, cc, clang, compile_object, compile_object_opt, function_code, gcc, link_and_run,
    scratch_dir, strip_includes,
};

const WIDE_INPUTS: &str = "{0,0,0},{1,1,1},{-1,-1,-1},{7,3,5},{-7,3,-5},\
     {123456,-654321,99},{2147483647,1,2},{-2147483648,-1,-2},\
     {0x7fffffffffffffffLL,2,3},{100,200,300},{-100,50,-25},\
     {1<<20,1<<10,1<<5},{42,42,42},{0xdeadbeef,0xcafef00d,0x1234}";

const SMALL_INPUTS: &str = "{0,0,0},{1,2,3},{5,1,1},{10,4,2},{-3,7,1},{20,5,3},\
     {0,10,10},{63,2,1},{7,7,7},{-1,-1,-1},{16,8,4},{2,50,25},{40,3,9},{9,40,4}";

const ENTRY_RETURN_WIDTH: u32 = 64;

const CC_FLAGS: [&str; 6] = [
    "-fno-stack-protector",
    "-fno-optimize-sibling-calls",
    "-fno-if-conversion",
    "-fno-if-conversion2",
    "-fno-tree-loop-if-convert",
    "-c",
];

struct WholeProgram {
    name: &'static str,
    entry: &'static str,
    entry_arity: usize,
    loopy: bool,
    functions: &'static [&'static str],
    c_source: &'static str,
}

const PROGRAMS: &[WholeProgram] = &[
    WholeProgram {
        name: "wp_addone",
        entry: "wp_addone_entry",
        entry_arity: 1,
        loopy: false,
        functions: &["wp_addone_entry", "wp_addone_sq"],
        c_source: "__attribute__((noinline,noclone)) long long wp_addone_sq(long long x){ return x * x; }\n\
                   long long wp_addone_entry(long long a){ return wp_addone_sq(a) + 1; }",
    },
    WholeProgram {
        name: "wp_two",
        entry: "wp_two_entry",
        entry_arity: 1,
        loopy: false,
        functions: &["wp_two_entry", "wp_two_sq", "wp_two_dbl"],
        c_source: "__attribute__((noinline,noclone)) long long wp_two_sq(long long x){ return x * x; }\n\
                   __attribute__((noinline,noclone)) long long wp_two_dbl(long long x){ return x + x; }\n\
                   long long wp_two_entry(long long a){ return wp_two_sq(a) + wp_two_dbl(a); }",
    },
    WholeProgram {
        name: "wp_chain",
        entry: "wp_chain_entry",
        entry_arity: 1,
        loopy: false,
        functions: &["wp_chain_entry", "wp_chain_mid", "wp_chain_leaf"],
        c_source: "__attribute__((noinline,noclone)) long long wp_chain_leaf(long long x){ return x + 3; }\n\
                   __attribute__((noinline,noclone)) long long wp_chain_mid(long long x){ return wp_chain_leaf(x) * 2; }\n\
                   long long wp_chain_entry(long long a){ return wp_chain_mid(a) + a; }",
    },
    WholeProgram {
        name: "wp_lincomb",
        entry: "wp_lincomb_entry",
        entry_arity: 3,
        loopy: false,
        functions: &["wp_lincomb_entry", "wp_lincomb_lin"],
        c_source: "__attribute__((noinline,noclone)) long long wp_lincomb_lin(long long a, long long b){ return a * 3 + b; }\n\
                   long long wp_lincomb_entry(long long a, long long b, long long c){ return wp_lincomb_lin(a, b) + c * 11; }",
    },
    WholeProgram {
        name: "wp_absdiff",
        entry: "wp_absdiff_entry",
        entry_arity: 2,
        loopy: false,
        functions: &["wp_absdiff_entry", "wp_absdiff_h"],
        c_source: "__attribute__((noinline,noclone)) long long wp_absdiff_h(long long a, long long b){ long long d = a - b; if (d < 0) d = -d; return d; }\n\
                   long long wp_absdiff_entry(long long a, long long b){ return wp_absdiff_h(a, b) + 1; }",
    },
    WholeProgram {
        name: "wp_sum",
        entry: "wp_sum_entry",
        entry_arity: 1,
        loopy: true,
        functions: &["wp_sum_entry", "wp_sum_h"],
        c_source: "__attribute__((noinline,noclone)) long long wp_sum_h(long long n){ long long s = 0; long long i = 0; while (i < n) { s += i; i++; } return s; }\n\
                   long long wp_sum_entry(long long n){ return wp_sum_h(n) + 1; }",
    },
    WholeProgram {
        name: "wp_nested_arg",
        entry: "wp_nested_arg_entry",
        entry_arity: 2,
        loopy: false,
        functions: &[
            "wp_nested_arg_entry",
            "wp_nested_arg_sub",
            "wp_nested_arg_dbl",
        ],
        c_source: "__attribute__((noinline,noclone)) long long wp_nested_arg_sub(long long a, long long b){ return a - b; }\n\
                   __attribute__((noinline,noclone)) long long wp_nested_arg_dbl(long long x){ return x + x; }\n\
                   long long wp_nested_arg_entry(long long a, long long b){ return wp_nested_arg_dbl(wp_nested_arg_sub(a, b)); }",
    },
    WholeProgram {
        name: "wp_switch",
        entry: "wp_switch_entry",
        entry_arity: 1,
        loopy: false,
        functions: &["wp_switch_entry", "wp_switch_pick"],
        c_source: "__attribute__((noinline,noclone)) long long wp_switch_pick(long long k){ switch(k){ case 0: return 10; case 1: return 21; case 2: return 32; case 3: return 43; case 4: return 54; default: return -1; } }\n\
                   long long wp_switch_entry(long long k){ return wp_switch_pick(k) + k; }",
    },
    WholeProgram {
        name: "wp_vswitch",
        entry: "wp_vswitch_entry",
        entry_arity: 1,
        loopy: false,
        functions: &["wp_vswitch_entry", "wp_vswitch_pick"],
        c_source: "__attribute__((noinline,noclone)) long long wp_vswitch_pick(long long k){ switch(k){ case 0: return 7; case 1: return 3; case 2: return 91; case 3: return 5; case 4: return 42; case 5: return 8; case 6: return 64; default: return -1; } }\n\
                   long long wp_vswitch_entry(long long k){ return wp_vswitch_pick(k) + k; }",
    },
    WholeProgram {
        name: "wp_vswitch_neg",
        entry: "wp_vswitch_neg_entry",
        entry_arity: 1,
        loopy: false,
        functions: &["wp_vswitch_neg_entry", "wp_vswitch_neg_pick"],
        c_source: "__attribute__((noinline,noclone)) long long wp_vswitch_neg_pick(long long k){ switch(k){ case 0: return -5; case 1: return 12; case 2: return -700; case 3: return 3; case 4: return -1000000; default: return 77; } }\n\
                   long long wp_vswitch_neg_entry(long long k){ return wp_vswitch_neg_pick(k) + k; }",
    },
    WholeProgram {
        name: "wp_sparse_switch",
        entry: "wp_sparse_switch_entry",
        entry_arity: 1,
        loopy: false,
        functions: &["wp_sparse_switch_entry", "wp_sparse_switch_pick"],
        c_source: "__attribute__((noinline,noclone)) long long wp_sparse_switch_pick(long long k){ switch(k){ case 1: return 11; case 7: return 22; case 42: return 33; case 100: return 44; default: return -1; } }\n\
                   long long wp_sparse_switch_entry(long long k){ return wp_sparse_switch_pick(k) + k; }",
    },
];

const NEAR_BRANCH_PROGRAM: WholeProgram = WholeProgram {
    name: "wp_near_branch",
    entry: "wp_near_branch_entry",
    entry_arity: 1,
    loopy: false,
    functions: &["wp_near_branch_entry", "wp_near_branch_h"],
    c_source: "__attribute__((noinline,noclone)) long long wp_near_branch_h(long long a){ volatile unsigned long long v[24]; v[0] = (unsigned long long)a; v[1] = 1; v[2] = 2; v[3] = 3; v[4] = 4; v[5] = 5; v[6] = 6; v[7] = 7; v[8] = 8; v[9] = 9; v[10] = 10; v[11] = 11; v[12] = 12; v[13] = 13; v[14] = 14; v[15] = 15; v[16] = 16; v[17] = 17; v[18] = 18; v[19] = 19; v[20] = 20; v[21] = 21; v[22] = 22; v[23] = 23; if (a > 0) { v[0] ^= 1ULL; v[0] ^= 2ULL; v[0] ^= 3ULL; v[0] ^= 4ULL; v[0] ^= 5ULL; v[0] ^= 6ULL; v[0] ^= 7ULL; v[0] ^= 8ULL; v[0] ^= 9ULL; v[0] ^= 10ULL; v[0] ^= 11ULL; v[0] ^= 12ULL; v[0] ^= 13ULL; v[0] ^= 14ULL; v[0] ^= 15ULL; v[0] ^= 16ULL; v[0] ^= 17ULL; v[0] ^= 18ULL; v[0] ^= 19ULL; v[0] ^= 20ULL; v[0] ^= 21ULL; v[0] ^= 22ULL; v[0] ^= 23ULL; v[0] ^= 24ULL; v[0] ^= 25ULL; v[0] ^= 26ULL; v[0] ^= 27ULL; v[0] ^= 28ULL; v[0] ^= 29ULL; v[0] ^= 30ULL; v[0] ^= 31ULL; v[0] ^= 32ULL; } return (long long)(v[0] ^ v[1] ^ v[2] ^ v[3] ^ v[4] ^ v[5] ^ v[6] ^ v[7] ^ v[8] ^ v[9] ^ v[10] ^ v[11] ^ v[12] ^ v[13] ^ v[14] ^ v[15] ^ v[16] ^ v[17] ^ v[18] ^ v[19] ^ v[20] ^ v[21] ^ v[22] ^ v[23]); }\n\
               long long wp_near_branch_entry(long long a){ return wp_near_branch_h(a) + 1; }",
};

const SHAPE_PROGRAMS: &[WholeProgram] = &[
    WholeProgram {
        name: "wp_ifelse_chain",
        entry: "wp_ifelse_chain_entry",
        entry_arity: 1,
        loopy: false,
        functions: &["wp_ifelse_chain_entry", "wp_ifelse_chain_h"],
        c_source: "__attribute__((noinline,noclone)) long long wp_ifelse_chain_h(long long a){ if (a > 100) return 3; else if (a > 10) return 2; else if (a > 0) return 1; else return 0; }\n\
                   long long wp_ifelse_chain_entry(long long a){ return wp_ifelse_chain_h(a) * 7 + a; }",
    },
    WholeProgram {
        name: "wp_nested_if",
        entry: "wp_nested_if_entry",
        entry_arity: 2,
        loopy: false,
        functions: &["wp_nested_if_entry", "wp_nested_if_h"],
        c_source: "__attribute__((noinline,noclone)) long long wp_nested_if_h(long long a, long long b){ long long r = 0; if (a > 0) { if (b > 0) { r = a + b; } else { r = a - b; } } return r; }\n\
                   long long wp_nested_if_entry(long long a, long long b){ return wp_nested_if_h(a, b) + 1; }",
    },
    WholeProgram {
        name: "wp_for",
        entry: "wp_for_entry",
        entry_arity: 1,
        loopy: true,
        functions: &["wp_for_entry", "wp_for_h"],
        c_source: "__attribute__((noinline,noclone)) long long wp_for_h(long long n){ long long s = 0; for (long long i = 0; i < n; i++) { s += i * i; } return s; }\n\
                   long long wp_for_entry(long long n){ return wp_for_h(n) + 1; }",
    },
    WholeProgram {
        name: "wp_dowhile",
        entry: "wp_dowhile_entry",
        entry_arity: 1,
        loopy: true,
        functions: &["wp_dowhile_entry", "wp_dowhile_h"],
        c_source: "__attribute__((noinline,noclone)) long long wp_dowhile_h(long long n){ long long s = 0; long long i = 1; do { s += i; i++; } while (i <= n); return s; }\n\
                   long long wp_dowhile_entry(long long n){ return wp_dowhile_h(n) + 1; }",
    },
    WholeProgram {
        name: "wp_nested_loop",
        entry: "wp_nested_loop_entry",
        entry_arity: 2,
        loopy: true,
        functions: &["wp_nested_loop_entry", "wp_nested_loop_h"],
        c_source: "__attribute__((noinline,noclone)) long long wp_nested_loop_h(long long n, long long m){ long long s = 0; for (long long i = 0; i < n; i++) { for (long long j = 0; j < m; j++) { s += i + j; } } return s; }\n\
                   long long wp_nested_loop_entry(long long n, long long m){ return wp_nested_loop_h(n, m) + 1; }",
    },
    WholeProgram {
        name: "wp_multiret",
        entry: "wp_multiret_entry",
        entry_arity: 2,
        loopy: false,
        functions: &["wp_multiret_entry", "wp_multiret_h"],
        c_source: "__attribute__((noinline,noclone)) long long wp_multiret_h(long long a, long long b){ if (a < 0) return -1; if (b < 0) return -2; if (a > b) return a - b; return b - a; }\n\
                   long long wp_multiret_entry(long long a, long long b){ return wp_multiret_h(a, b) + 5; }",
    },
    WholeProgram {
        name: "wp_sc_and",
        entry: "wp_sc_and_entry",
        entry_arity: 2,
        loopy: false,
        functions: &["wp_sc_and_entry", "wp_sc_and_h"],
        c_source: "__attribute__((noinline,noclone)) long long wp_sc_and_h(long long a, long long b){ long long r = a - b; if (a > 0 && b > 0) { r = a + b; } return r; }\n\
                   long long wp_sc_and_entry(long long a, long long b){ return wp_sc_and_h(a, b) + 1; }",
    },
    WholeProgram {
        name: "wp_sc_or",
        entry: "wp_sc_or_entry",
        entry_arity: 2,
        loopy: false,
        functions: &["wp_sc_or_entry", "wp_sc_or_h"],
        c_source: "__attribute__((noinline,noclone)) long long wp_sc_or_h(long long a, long long b){ long long r; if (a < 0 || b < 0) { r = a + b; } else { r = a - b; } return r; }\n\
                   long long wp_sc_or_entry(long long a, long long b){ return wp_sc_or_h(a, b) + 1; }",
    },
    WholeProgram {
        name: "wp_loop_break",
        entry: "wp_loop_break_entry",
        entry_arity: 1,
        loopy: true,
        functions: &["wp_loop_break_entry", "wp_loop_break_h"],
        c_source: "__attribute__((noinline,noclone)) long long wp_loop_break_h(long long n){ long long s = 0; for (long long i = 0; i < n; i++) { if (i > 5) break; s += i; } return s; }\n\
                   long long wp_loop_break_entry(long long n){ return wp_loop_break_h(n) + 1; }",
    },
    WholeProgram {
        name: "wp_loop_continue",
        entry: "wp_loop_continue_entry",
        entry_arity: 1,
        loopy: true,
        functions: &["wp_loop_continue_entry", "wp_loop_continue_h"],
        c_source: "__attribute__((noinline,noclone)) long long wp_loop_continue_h(long long n){ long long s = 0; for (long long i = 0; i < n; i++) { if ((i & 1) == 0) continue; s += i; } return s; }\n\
                   long long wp_loop_continue_entry(long long n){ return wp_loop_continue_h(n) + 1; }",
    },
];

const TEETH_SQ: WholeProgram = WholeProgram {
    name: "teeth_sq",
    entry: "teeth_sq_entry",
    entry_arity: 1,
    loopy: false,
    functions: &["teeth_sq_entry", "teeth_sq_h"],
    c_source: "__attribute__((noinline,noclone)) long long teeth_sq_h(long long x){ return x * x; }\n\
               long long teeth_sq_entry(long long a){ return teeth_sq_h(a) + 1; }",
};

const TEETH_SUB: WholeProgram = WholeProgram {
    name: "teeth_sub",
    entry: "teeth_sub_entry",
    entry_arity: 2,
    loopy: false,
    functions: &["teeth_sub_entry", "teeth_sub_h"],
    c_source: "__attribute__((noinline,noclone)) long long teeth_sub_h(long long a, long long b){ return a - b; }\n\
               long long teeth_sub_entry(long long a, long long b){ return teeth_sub_h(a, b) + 100; }",
};

struct RecoveredProgram {
    tu: String,
    entry_params: usize,
    entry_return_width: u32,
}

fn recover_program(
    object: &[u8],
    program: &WholeProgram,
    abi: PseudoAbi,
) -> Option<RecoveredProgram> {
    let mut functions: Vec<ProgramFunction> = Vec::with_capacity(program.functions.len());
    for &fname in program.functions {
        let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(object, fname) else {
            eprintln!("skip {}: {fname} symbol not located", program.name);
            return None;
        };
        functions.push(ProgramFunction {
            name: format!("rec_{fname}"),
            address: base,
            code,
        });
    }
    let result: LibRecoveredProgram = lib_recover_program(object, &functions, abi);
    if !result.unrecovered.is_empty() {
        for bad in &result.unrecovered {
            eprintln!(
                "sound-reject {}: {} not in call class ({})",
                program.name, bad.name, bad.reason
            );
        }
        return None;
    }
    let mut tu: String = String::new();
    let mut entry_params: usize = 0;
    let mut entry_return_width: u32 = 64;
    for (idx, &fname) in program.functions.iter().enumerate() {
        let rec: &LibRecoveredFunction = &result.recovered[idx];
        tu.push_str(&strip_includes(&rec.source));
        tu.push('\n');
        if fname == program.entry {
            entry_params = rec.signature.callable_arity();
            entry_return_width = rec.return_width_bits;
        }
    }
    if entry_params > 3 {
        eprintln!(
            "sound-reject {}: entry arity {entry_params} exceeds the 3-input driver",
            program.name
        );
        return None;
    }
    Some(RecoveredProgram {
        tu,
        entry_params,
        entry_return_width,
    })
}

fn build_program_driver(program: &WholeProgram, recovered: &RecoveredProgram) -> String {
    let inputs: &str = if program.loopy {
        SMALL_INPUTS
    } else {
        WIDE_INPUTS
    };
    assert_eq!(
        recovered.entry_return_width, ENTRY_RETURN_WIDTH,
        "{} recovered entry width differs from its long long fixture contract",
        program.name
    );
    let return_mask: &str = "0xFFFFFFFFFFFFFFFFULL";
    let orig_args: String = (0..program.entry_arity)
        .map(|i: usize| format!("in[{i}]"))
        .collect::<Vec<String>>()
        .join(", ");
    let rec_args: String = (0..recovered.entry_params)
        .map(|i: usize| format!("(uint64_t)in[{i}]"))
        .collect::<Vec<String>>()
        .join(", ");
    let entry: &str = program.entry;
    let name: &str = program.name;
    let mut body: String = String::new();
    let _ = write!(
        body,
        "    for (size_t k = 0; k < n_inputs; k++) {{\n\
         \x20       long long in[3] = {{ inputs[k][0], inputs[k][1], inputs[k][2] }};\n\
         \x20       unsigned long long want = (unsigned long long){entry}({orig_args}) & {return_mask};\n\
         \x20       unsigned long long got = (unsigned long long)rec_{entry}({rec_args}) & {return_mask};\n\
         \x20       if (want != got) {{ printf(\"MISMATCH {name} in=%lld,%lld,%lld want=%llu got=%llu\\n\", in[0], in[1], in[2], want, got); return 1; }}\n\
         \x20   }}\n",
    );
    let sig: String = vec!["long long"; program.entry_arity].join(", ");
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n{tu}\n\
         extern long long {entry}({sig});\n\
         int main(void) {{\n\
         \x20   long long inputs[][3] = {{ {inputs} }};\n\
         \x20   size_t n_inputs = sizeof(inputs)/sizeof(inputs[0]);\n\
         {body}\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n",
        tu = recovered.tu,
    )
}

#[test]
fn whole_programs_recompile_to_behavioral_equivalence_hostabi() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv guard"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!(
            "skipping whole-program host oracle: gcc (needed for the call idiom) not on PATH"
        );
        return;
    };
    let scratch: ScratchDir = scratch_dir("disrobe-pseudo-wp");
    let dir: PathBuf = scratch.path().to_path_buf();
    let mut recovered_count: usize = 0;
    let mut rejected_count: usize = 0;
    let mut chain_recovered: bool = false;

    for program in PROGRAMS {
        let obj_path: PathBuf = dir.join(format!("{}_host.o", program.name));
        let Some(object): Option<Vec<u8>> =
            compile_object(&builder, &CC_FLAGS, program.c_source, &obj_path)
        else {
            eprintln!("skip {}: host compile failed", program.name);
            continue;
        };
        let Some(recovered): Option<RecoveredProgram> = recover_program(&object, program, HOST_ABI)
        else {
            rejected_count += 1;
            continue;
        };
        let driver: String = build_program_driver(program, &recovered);
        let watchdog: u64 = if program.loopy { 20 } else { 10 };
        let stdout: String = link_and_run(&builder, &driver, &object, program.name, watchdog);
        assert!(
            stdout.contains("OK") && !stdout.contains("MISMATCH"),
            "whole-program differential FAILED for {}: {stdout}",
            program.name
        );
        recovered_count += 1;
        chain_recovered |= program.name == "wp_chain";
        println!("whole-program (MS x64) end-to-end PASSED: {}", program.name);
    }

    assert!(
        recovered_count >= 3,
        "whole-program stitching must recover the entry chain of at least 3 of the {} programs, only recovered {recovered_count} ({rejected_count} sound-rejected)",
        PROGRAMS.len()
    );
    assert!(
        chain_recovered,
        "the three-deep nested-call chain wp_chain must recover its single-argument entry end-to-end"
    );
    println!(
        "whole-program host oracle: {recovered_count} recovered end-to-end, {rejected_count} sound-rejected of {}",
        PROGRAMS.len()
    );
}

fn compile_dual(program: &WholeProgram) -> Option<(String, Vec<u8>, Vec<u8>)> {
    let host_cc: String = cc()?;
    let clang_cc: String = clang()?;
    let scratch: ScratchDir = scratch_dir("disrobe-pseudo-wp");
    let dir: PathBuf = scratch.path().to_path_buf();
    let host_path: PathBuf = dir.join(format!("{}_gt.o", program.name));
    let host_obj: Vec<u8> = compile_object(&host_cc, &CC_FLAGS, program.c_source, &host_path)?;
    let sysv_path: PathBuf = dir.join(format!("{}_sysv.o", program.name));
    let sysv_flags: [&str; 5] = [
        "--target=x86_64-unknown-linux-gnu",
        "-fno-stack-protector",
        "-fno-optimize-sibling-calls",
        "-fcf-protection=none",
        "-c",
    ];
    let Some(sysv_obj): Option<Vec<u8>> =
        compile_object(&clang_cc, &sysv_flags, program.c_source, &sysv_path)
    else {
        eprintln!(
            "skipping {}: clang cannot emit a linux/SysV object on this host",
            program.name
        );
        return None;
    };
    Some((host_cc, host_obj, sysv_obj))
}

#[test]
fn object_backed_value_switches_keep_the_proven_switch_route() {
    for name in ["wp_vswitch", "wp_vswitch_neg"] {
        let program: &WholeProgram = PROGRAMS
            .iter()
            .find(|program: &&WholeProgram| program.name == name)
            .expect("named value-switch fixture");
        let (_, host_object, sysv_object): (String, Vec<u8>, Vec<u8>) =
            compile_dual(program).expect("host and sysv compilers");
        for (object, abi) in [(&host_object, HOST_ABI), (&sysv_object, PseudoAbi::SysV)] {
            let recovered: RecoveredProgram = recover_program(object, program, abi)
                .expect("the object-backed value switch must recover");
            assert!(
                recovered.tu.contains("switch ("),
                "{name} under {abi:?} must use the object-proven switch route: {}",
                recovered.tu
            );
        }
    }
}

#[test]
fn object_backed_size_optimized_value_switches_never_use_generic_rip_lea() {
    if !cfg!(windows) {
        eprintln!(
            "skipping object_backed_size_optimized_value_switches_never_use_generic_rip_lea: this case reads a host-native object and only applies where cfg!(windows) holds, so it grades nothing here and must not be cited as coverage on this platform"
        );
        return;
    }
    let host_cc: String = gcc().expect("host gcc");
    let clang_cc: String = clang().expect("sysv clang");
    let scratch: ScratchDir = scratch_dir("disrobe-pseudo-wp");
    let dir: PathBuf = scratch.path().to_path_buf();
    let sysv_flags: [&str; 5] = [
        "--target=x86_64-unknown-linux-gnu",
        "-fno-stack-protector",
        "-fno-optimize-sibling-calls",
        "-fcf-protection=none",
        "-c",
    ];
    let mut generic_recoveries: Vec<&str> = Vec::new();
    for name in ["wp_vswitch", "wp_vswitch_neg"] {
        let program: &WholeProgram = PROGRAMS
            .iter()
            .find(|program: &&WholeProgram| program.name == name)
            .expect("named value-switch fixture");
        let host_path: PathBuf = dir.join(format!("{name}_os_host.o"));
        let host_object: Vec<u8> =
            compile_object_opt(&host_cc, "-Os", &CC_FLAGS, program.c_source, &host_path)
                .expect("size-optimized host object");
        if let Some(host_recovered) = recover_program(&host_object, program, HOST_ABI)
            && !host_recovered.tu.contains("switch (")
        {
            generic_recoveries.push(name);
        }
        let sysv_path: PathBuf = dir.join(format!("{name}_os_sysv.o"));
        let sysv_object: Vec<u8> =
            compile_object_opt(&clang_cc, "-Os", &sysv_flags, program.c_source, &sysv_path)
                .expect("size-optimized sysv object");
        let sysv_recovered: RecoveredProgram =
            recover_program(&sysv_object, program, PseudoAbi::SysV)
                .expect("the sysv value switch must recover");
        assert!(
            sysv_recovered.tu.contains("switch ("),
            "{name} under SysV must keep the proven value-switch route: {}",
            sysv_recovered.tu
        );
    }
    assert!(
        generic_recoveries.is_empty(),
        "size-optimized host value-tables must not use generic RIP lea: {generic_recoveries:?}"
    );
}

#[test]
fn object_backed_size_optimized_host_value_switches_recover_relocated_tables() {
    if !cfg!(windows) {
        eprintln!(
            "skipping object_backed_size_optimized_host_value_switches_recover_relocated_tables: this case reads a host-native object and only applies where cfg!(windows) holds, so it grades nothing here and must not be cited as coverage on this platform"
        );
        return;
    }
    let host_cc: String = gcc().expect("host gcc");
    let scratch: ScratchDir = scratch_dir("disrobe-pseudo-wp");
    let dir: PathBuf = scratch.path().to_path_buf();
    for name in ["wp_vswitch", "wp_vswitch_neg"] {
        let program: &WholeProgram = PROGRAMS
            .iter()
            .find(|program: &&WholeProgram| program.name == name)
            .expect("named value-switch fixture");
        let host_path: PathBuf = dir.join(format!("{name}_os_relocated.o"));
        let host_object: Vec<u8> =
            compile_object_opt(&host_cc, "-Os", &CC_FLAGS, program.c_source, &host_path)
                .expect("size-optimized host object");
        let recovered: RecoveredProgram = recover_program(&host_object, program, HOST_ABI)
            .expect("the relocated host value switch must recover");
        assert!(
            recovered.tu.contains("switch ("),
            "{name} must recover through the object-backed value-table: {}",
            recovered.tu
        );
        let driver: String = build_program_driver(program, &recovered);
        let stdout: String = link_and_run(&host_cc, &driver, &host_object, name, 10);
        assert!(
            stdout.contains("OK") && !stdout.contains("MISMATCH"),
            "{name} relocated value-table recovery diverged: {stdout}"
        );
    }
}

#[test]
fn object_backed_value_switch_normalizes_nonzero_section_addresses() {
    if !cfg!(windows) {
        eprintln!(
            "skipping object_backed_value_switch_normalizes_nonzero_section_addresses: this case reads a host-native object and only applies where cfg!(windows) holds, so it grades nothing here and must not be cited as coverage on this platform"
        );
        return;
    }
    let host_cc: String = gcc().expect("host gcc");
    let program: &WholeProgram = PROGRAMS
        .iter()
        .find(|program: &&WholeProgram| program.name == "wp_vswitch_neg")
        .expect("negative value-switch fixture");
    let scratch: ScratchDir = scratch_dir("disrobe-pseudo-value-table-addresses");
    let object_path: PathBuf = scratch.path().join("value_table_addresses.o");
    let mut object: Vec<u8> =
        compile_object_opt(&host_cc, "-Os", &CC_FLAGS, program.c_source, &object_path)
            .expect("size-optimized host object");
    let section_count: usize = u16::from_le_bytes([object[2], object[3]]) as usize;
    let optional_header_size: usize = u16::from_le_bytes([object[16], object[17]]) as usize;
    let section_table: usize = 20 + optional_header_size;
    let section_header = |name: &[u8]| -> usize {
        (0..section_count)
            .map(|index: usize| section_table + index * 40)
            .find(|offset: &usize| object[*offset..*offset + name.len()] == *name)
            .expect("named COFF section")
    };
    let text_header: usize = section_header(b".text");
    let table_header: usize = section_header(b".rdata");
    object[text_header + 12..text_header + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
    object[table_header + 12..table_header + 16].copy_from_slice(&0x3000_u32.to_le_bytes());
    let file: object::File<'_> =
        object::File::parse(object.as_slice()).expect("addressed COFF object");
    let text: object::Section<'_, '_> = file
        .section_by_name(".text")
        .expect("addressed text section");
    let table: object::Section<'_, '_> = file
        .section_by_name(".rdata")
        .expect("addressed value-table section");
    assert_eq!(text.address(), 0x1000);
    assert_eq!(table.address(), 0x3000);
    let recovered: RecoveredProgram = recover_program(&object, program, HOST_ABI)
        .expect("nonzero section addresses must preserve value-table recovery");
    assert!(recovered.tu.contains("switch ("));
    let text_raw_data: usize = u32::from_le_bytes(
        object[text_header + 20..text_header + 24]
            .try_into()
            .expect("text raw-data pointer"),
    ) as usize;
    let text_relocation_table: usize = u32::from_le_bytes(
        object[text_header + 24..text_header + 28]
            .try_into()
            .expect("text relocation pointer"),
    ) as usize;
    let text_relocation_count: u16 = u16::from_le_bytes(
        object[text_header + 32..text_header + 34]
            .try_into()
            .expect("text relocation count"),
    );
    assert!(text_relocation_count > 0);
    let mut table_relocated: Vec<u8> = object.clone();
    let mut table_relocation: [u8; 10] = table_relocated
        [text_relocation_table..text_relocation_table + 10]
        .try_into()
        .expect("table relocation record");
    let displacement_offset: usize = u32::from_le_bytes(
        table_relocation[..4]
            .try_into()
            .expect("displacement offset"),
    ) as usize;
    table_relocated[text_raw_data + displacement_offset..text_raw_data + displacement_offset + 4]
        .copy_from_slice(&8_i32.to_le_bytes());
    table_relocation[..4].copy_from_slice(&8_u32.to_le_bytes());
    let table_relocation_pointer: u32 =
        u32::try_from(table_relocated.len()).expect("table relocation pointer range");
    table_relocated.extend_from_slice(&table_relocation);
    table_relocated[table_header + 24..table_header + 28]
        .copy_from_slice(&table_relocation_pointer.to_le_bytes());
    table_relocated[table_header + 32..table_header + 34].copy_from_slice(&1_u16.to_le_bytes());
    let (picker_code, picker_base): (Vec<u8>, u64) =
        function_code(&table_relocated, "wp_vswitch_neg_pick").expect("relocated table picker");
    let table_relocation_result =
        recover_leaf_function_in_object(&table_relocated, &picker_code, picker_base, HOST_ABI, &[]);
    assert!(
        table_relocation_result.is_err(),
        "a relocation inside the nonzero-address value-table must refuse: {table_relocation_result:?}"
    );
    let first_header: usize = section_table;
    let real_text_header: usize = if text_header == first_header {
        first_header + 40
    } else {
        text_header
    };
    let text_header_bytes: [u8; 40] = object[text_header..text_header + 40]
        .try_into()
        .expect("value-table text header");
    let mut overlapping_text: Vec<u8> = object.clone();
    overlapping_text[real_text_header..real_text_header + 40].copy_from_slice(&text_header_bytes);
    overlapping_text[first_header..first_header + 40].copy_from_slice(&text_header_bytes);
    let (overlap_code, overlap_base): (Vec<u8>, u64) =
        function_code(&overlapping_text, "wp_vswitch_neg_pick").expect("overlapping table picker");
    let overlap_result = recover_leaf_function_in_object(
        &overlapping_text,
        &overlap_code,
        overlap_base,
        HOST_ABI,
        &[],
    );
    assert!(
        overlap_result.is_err(),
        "overlapping text sections must not choose a value-table relocation source: {overlap_result:?}"
    );
}

#[test]
fn object_backed_relocated_leaf_lea_never_uses_the_raw_displacement() {
    if !cfg!(windows) {
        eprintln!(
            "skipping object_backed_relocated_leaf_lea_never_uses_the_raw_displacement: this case reads a host-native object and only applies where cfg!(windows) holds, so it grades nothing here and must not be cited as coverage on this platform"
        );
        return;
    }
    let host_cc: String = gcc().expect("host gcc");
    let scratch: ScratchDir = scratch_dir("disrobe-pseudo-rip-reloc");
    let object_path: PathBuf = scratch.path().join("relocated_leaf.o");
    let source: &str = "static long long relocated_value;\n\
        __attribute__((noinline,noclone)) long long *relocated_leaf(void){ return &relocated_value; }";
    let mut object: Vec<u8> = compile_object_opt(&host_cc, "-Os", &CC_FLAGS, source, &object_path)
        .expect("size-optimized host object");
    let section_count: usize = u16::from_le_bytes([object[2], object[3]]) as usize;
    let optional_header_size: usize = u16::from_le_bytes([object[16], object[17]]) as usize;
    let section_table: usize = 20 + optional_header_size;
    let text_header: usize = (0..section_count)
        .map(|index: usize| section_table + index * 40)
        .find(|offset: &usize| object[*offset..*offset + 5] == *b".text")
        .expect("COFF text section header");
    let text_address: u32 = 0x1000;
    object[text_header + 12..text_header + 16].copy_from_slice(&text_address.to_le_bytes());
    let file: object::File<'_> =
        object::File::parse(object.as_slice()).expect("patched COFF object");
    let text: object::Section<'_, '_> = file
        .sections()
        .find(|section: &object::Section<'_, '_>| section.kind() == object::SectionKind::Text)
        .expect("patched text section");
    assert_eq!(text.address(), u64::from(text_address));
    let (code, base): (Vec<u8>, u64) =
        function_code(&object, "relocated_leaf").expect("relocated leaf code");
    let lea: DisasmInsn = disassemble(Arch::X86_64, base, &code)
        .expect("disassemble relocated leaf")
        .into_iter()
        .find(|insn: &DisasmInsn| insn.mnemonic == "lea")
        .expect("RIP-relative lea");
    let displacement_field: u64 = lea.address + lea.bytes.len() as u64 - 4;
    assert!(
        text.relocations()
            .any(|(offset, _)| { text.address().checked_add(offset) == Some(displacement_field) })
    );
    let result = recover_leaf_function_in_object(&object, &code, base, HOST_ABI, &[]);
    assert!(
        result.is_err(),
        "an unresolved object relocation must not be interpreted as its raw displacement: {result:?}"
    );
    let relocation_table: usize = u32::from_le_bytes(
        object[text_header + 24..text_header + 28]
            .try_into()
            .expect("text relocation pointer"),
    ) as usize;
    let relocation_count: usize = usize::from(u16::from_le_bytes(
        object[text_header + 32..text_header + 34]
            .try_into()
            .expect("text relocation count"),
    ));
    let displacement_offset: u32 =
        u32::try_from(displacement_field - text.address()).expect("displacement offset");
    let relocation: usize = (0..relocation_count)
        .map(|index: usize| relocation_table + index * 10)
        .find(|record: &usize| {
            u32::from_le_bytes(
                object[*record..*record + 4]
                    .try_into()
                    .expect("relocation offset"),
            ) == displacement_offset
        })
        .expect("LEA relocation");
    let mut preceding_overlap: Vec<u8> = object.clone();
    preceding_overlap[relocation..relocation + 4]
        .copy_from_slice(&(displacement_offset - 1).to_le_bytes());
    let preceding_overlap_result =
        recover_leaf_function_in_object(&preceding_overlap, &code, base, HOST_ABI, &[]);
    assert!(
        preceding_overlap_result.is_err(),
        "a relocation overlapping the LEA displacement from its preceding byte must refuse: {preceding_overlap_result:?}"
    );
    assert!(section_count >= 2);
    let first_header: usize = section_table;
    let relocated_header: [u8; 40] = object[text_header..text_header + 40]
        .try_into()
        .expect("relocated text header");
    let real_header: usize = if text_header == first_header {
        first_header + 40
    } else {
        text_header
    };
    let mut ambiguous: Vec<u8> = object.clone();
    ambiguous[real_header..real_header + 40].copy_from_slice(&relocated_header);
    ambiguous[first_header..first_header + 40].copy_from_slice(&relocated_header);
    ambiguous[first_header + 24..first_header + 28].fill(0);
    ambiguous[first_header + 32..first_header + 34].fill(0);
    let ambiguous_file: object::File<'_> =
        object::File::parse(ambiguous.as_slice()).expect("overlapping COFF text sections");
    let matching_text_sections: usize = ambiguous_file
        .sections()
        .filter(|section: &object::Section<'_, '_>| {
            section.kind() == object::SectionKind::Text
                && (section.address()..section.address() + section.size()).contains(&base)
        })
        .count();
    assert_eq!(matching_text_sections, 2);
    let ambiguous_result = recover_leaf_function_in_object(&ambiguous, &code, base, HOST_ABI, &[]);
    assert!(
        ambiguous_result.is_err(),
        "ambiguous text-section identity must retain relocation refusal: {ambiguous_result:?}"
    );
    let mut truncated: Vec<u8> = object.clone();
    truncated[text_header + 16..text_header + 20].copy_from_slice(&1_u32.to_le_bytes());
    truncated[text_header + 32..text_header + 34].fill(0);
    let truncated_result = recover_leaf_function_in_object(&truncated, &code, base, HOST_ABI, &[]);
    assert!(
        truncated_result.is_err(),
        "object recovery must bind the complete instruction span to its text section: {truncated_result:?}"
    );
}

#[test]
fn direct_instruction_trap_arm_recovers_as_a_guard() {
    if !cfg!(target_arch = "x86_64") {
        eprintln!(
            "skipping direct_instruction_trap_arm_recovers_as_a_guard: this case reads a host-native object and only applies on an x86-64 target architecture, so it grades nothing here and must not be cited as coverage on this platform"
        );
        return;
    }
    let compiler: String = clang().expect("clang");
    let scratch: ScratchDir = scratch_dir("disrobe-pseudo-direct-trap-guard");
    let object_path: PathBuf = scratch.path().join("direct_trap_guard.o");
    let source: &str = "__attribute__((noinline)) long long direct_trap_guard(long long x){ if (x < 0) __builtin_trap(); return x + 1; }";
    let flags: [&str; 2] = ["-fno-stack-protector", "-c"];
    let object: Vec<u8> = compile_object_opt(&compiler, "-O1", &flags, source, &object_path)
        .expect("authored direct-trap object");
    let (code, base): (Vec<u8>, u64) =
        function_code(&object, "direct_trap_guard").expect("direct-trap symbol");
    let instructions: Vec<DisasmInsn> =
        disassemble(Arch::X86_64, base, &code).expect("direct-trap disassembly");
    assert!(
        instructions
            .iter()
            .any(|instruction: &DisasmInsn| instruction.mnemonic == "ud2"),
        "clang must emit direct UD2 evidence: {instructions:?}"
    );
    let recovered: LeafRecovery =
        recover_leaf_function_in_object(&object, &code, base, HOST_ABI, &[])
            .expect("recover direct-trap guard");
    assert!(recovered.call_targets.is_empty());
    assert!(recovered.source.contains("if ("), "{}", recovered.source);
    assert!(
        recovered.source.contains("__builtin_trap();"),
        "{}",
        recovered.source
    );
    assert!(!recovered.source.contains("goto "), "{}", recovered.source);
    assert!(
        !recovered.source.contains("sub_ffffffff"),
        "{}",
        recovered.source
    );
    let rust_source: &str = recovered.rust_source.as_deref().expect("Rust recovery");
    assert!(rust_source.contains("if "), "{rust_source}");
    assert!(
        rust_source.contains("std::process::abort();"),
        "{rust_source}"
    );
    let driver: String = format!(
        "{}\n#include <stdio.h>\nextern long long direct_trap_guard(long long);\nint main(void){{ long long values[]={{0,1,7,1024,9223372036854775806LL}}; for(unsigned long long i=0;i<sizeof(values)/sizeof(values[0]);i++){{ long long want=direct_trap_guard(values[i]); unsigned long long got=recovered((unsigned long long)values[i]); if((unsigned long long)want!=got){{ printf(\"MISMATCH %llu\\n\",i); return 1; }} }} puts(\"OK\"); return 0; }}",
        recovered.source
    );
    let stdout: String = link_and_run(
        &compiler,
        &driver,
        &object,
        "direct_instruction_trap_guard",
        10,
    );
    assert!(
        stdout.contains("OK") && !stdout.contains("MISMATCH"),
        "non-trapping differential failed: {stdout}"
    );
}

#[test]
fn imported_stack_failure_guard_recovers_through_the_whole_program_consumer() {
    if !cfg!(target_arch = "x86_64") {
        eprintln!(
            "skipping imported_stack_failure_guard_recovers_through_the_whole_program_consumer: this case requires x86-64 object recovery"
        );
        return;
    }
    let compilers: Vec<String> = [gcc(), clang()].into_iter().flatten().collect();
    assert!(
        !compilers.is_empty(),
        "the stack-protector guard grade requires gcc or clang"
    );
    let program: WholeProgram = WholeProgram {
        name: "stack_protected",
        entry: "stack_protected",
        entry_arity: 1,
        loopy: false,
        functions: &["stack_protected"],
        c_source: "__attribute__((noinline)) long long stack_protected(long long x){ volatile char buffer[32]; buffer[0] = (char)x; return (long long)buffer[0] + 1; }",
    };
    let scratch: ScratchDir = scratch_dir("disrobe-pseudo-stack-guard");
    let mut graded: usize = 0;
    for compiler in compilers {
        let object_path: PathBuf = scratch.path().join(format!("{compiler}_stack_guard.o"));
        let flags: [&str; 4] = [
            "-fstack-protector-strong",
            "-mstack-protector-guard=global",
            "-fno-omit-frame-pointer",
            "-c",
        ];
        let object: Vec<u8> =
            compile_object_opt(&compiler, "-O1", &flags, program.c_source, &object_path)
                .unwrap_or_else(|| panic!("{compiler} must compile the stack-protector fixture"));
        let file: object::File<'_> =
            object::File::parse(object.as_slice()).expect("stack-protected object parses");
        let mut imported_stack_failure: bool = false;
        for section in file.sections() {
            for (_, relocation) in section.relocations() {
                let object::RelocationTarget::Symbol(index) = relocation.target() else {
                    continue;
                };
                let symbol: object::Symbol<'_, '_> = file
                    .symbol_by_index(index)
                    .expect("relocation symbol resolves");
                imported_stack_failure |= symbol.name().ok() == Some("__stack_chk_fail");
            }
        }
        if !imported_stack_failure {
            eprintln!(
                "not grading {compiler}: the requested flags emitted no __stack_chk_fail import"
            );
            continue;
        }
        let recovered: RecoveredProgram = recover_program(&object, &program, HOST_ABI)
            .unwrap_or_else(|| panic!("{compiler} stack-protector program must recover"));
        assert!(
            !recovered.tu.contains("__stack_chk_fail"),
            "{}",
            recovered.tu
        );
        assert!(!recovered.tu.contains("r_rdx"), "{}", recovered.tu);
        assert_eq!(recovered.entry_params, 1, "{}", recovered.tu);
        assert_eq!(
            recovered.tu.matches("goto ").count(),
            0,
            "{compiler} imported failure side must collapse to a guard: {}",
            recovered.tu
        );
        graded += 1;
    }
    assert!(
        graded > 0,
        "no available compiler emitted the imported stack-failure path this test grades"
    );
}

#[test]
fn imported_stack_guard_recompiles_without_leaking_guard_state_into_the_entry() {
    if !cfg!(target_arch = "x86_64") {
        eprintln!(
            "skipping imported_stack_guard_recompiles_without_leaking_guard_state_into_the_entry: this case requires x86-64 object recovery"
        );
        return;
    }
    let compiler: String = gcc().expect("gcc is required for the imported stack-guard grade");
    let program: WholeProgram = WholeProgram {
        name: "stack_guard_state",
        entry: "stack_guard_state",
        entry_arity: 1,
        loopy: false,
        functions: &["stack_guard_state"],
        c_source: "__attribute__((noinline)) long long stack_guard_state(long long x){ volatile char buffer[32]; buffer[0] = (char)x; return (long long)buffer[0] + 1; }",
    };
    let scratch: ScratchDir = scratch_dir("disrobe-pseudo-stack-guard-state");
    let object_path: PathBuf = scratch.path().join("stack_guard_state.o");
    let flags: [&str; 4] = [
        "-fstack-protector-strong",
        "-mstack-protector-guard=global",
        "-fno-omit-frame-pointer",
        "-c",
    ];
    let object: Vec<u8> =
        compile_object_opt(&compiler, "-O1", &flags, program.c_source, &object_path)
            .expect("gcc must compile the stack-guard fixture");
    let recovered: RecoveredProgram = recover_program(&object, &program, HOST_ABI)
        .expect("the stack-protected entry must recover with the host ABI");
    assert_eq!(
        recovered.entry_params, 1,
        "the stack guard must not become a recovered function input: {}",
        recovered.tu
    );
    let driver: String = format!(
        "#include <stdint.h>\n#include <stdio.h>\nvolatile uint64_t __stack_chk_guard = 0x9e3779b97f4a7c15ULL;\n{}\nextern long long stack_guard_state(long long);\nint main(void){{ long long want = stack_guard_state(7); long long got = rec_stack_guard_state(7); if(want != got){{ printf(\"MISMATCH want=%lld got=%lld\\n\", want, got); return 1; }} printf(\"OK\\n\"); return 0; }}\n",
        recovered.tu
    );
    let stdout: String = link_and_run(&compiler, &driver, &object, "stack_guard_state", 20);
    assert!(
        stdout.contains("OK") && !stdout.contains("MISMATCH"),
        "stack-guard recovery must preserve the normal result without an inferred guard input: {stdout}\n--- recovered ---\n{}",
        recovered.tu
    );
}

#[test]
fn local_and_unresolved_stack_failure_lookalikes_stay_returning_calls() {
    let compiler: String = gcc().expect("gcc is required for the imported-stack-failure grade");
    let cases: [(&'static str, &'static str, &'static str); 2] = [
        (
            "local",
            "__attribute__((noinline)) void __stack_chk_fail(void){ volatile int state = 0; (void)state; } __attribute__((noinline)) long long local_lookalike(long long x){ if (x < 0) __stack_chk_fail(); return x + 1; }",
            "local_lookalike",
        ),
        (
            "unresolved",
            "extern void stack_failure_lookalike(void); __attribute__((noinline)) long long unresolved_lookalike(long long x){ if (x < 0) stack_failure_lookalike(); return x + 1; }",
            "unresolved_lookalike",
        ),
    ];
    let scratch: ScratchDir = scratch_dir("disrobe-pseudo-stack-lookalike");
    let flags: [&str; 2] = ["-fno-stack-protector", "-c"];
    for (tag, source, entry) in cases {
        let object_path: PathBuf = scratch.path().join(format!("{tag}.o"));
        let object: Vec<u8> = compile_object_opt(&compiler, "-O1", &flags, source, &object_path)
            .unwrap_or_else(|| panic!("{tag} fixture compiles"));
        let (code, base): (Vec<u8>, u64) =
            function_code(&object, entry).unwrap_or_else(|| panic!("{tag} caller symbol"));
        let recovered: LeafRecovery =
            recover_leaf_function_in_object(&object, &code, base, HOST_ABI, &[]).unwrap_or_else(
                |error| panic!("{tag} lookalike must recover as a returning call: {error}"),
            );
        assert!(
            !recovered.source.contains("__stack_chk_fail();"),
            "{tag} must not obtain imported no-return evidence: {}",
            recovered.source
        );
        assert!(
            recovered.source.contains("sub_"),
            "{tag} must remain an unresolved or local direct call: {}",
            recovered.source
        );
    }
}

#[test]
fn every_declared_direct_trap_encoding_structures_as_a_guard() {
    let traps: [&[u8]; 5] = [
        &[0x0f, 0x0b],
        &[0x0f, 0xff, 0xc0],
        &[0x0f, 0xb9, 0xc0],
        &[0xcc],
        &[0xcd, 0x29],
    ];
    for trap in traps {
        let displacement: u8 = u8::try_from(trap.len()).expect("bounded trap length");
        let mut code: Vec<u8> = vec![0x48, 0x85, 0xc9, 0x79, displacement];
        code.extend_from_slice(trap);
        code.extend_from_slice(&[0x48, 0x8d, 0x41, 0x01, 0xc3]);
        let recovered: LeafRecovery = recover_leaf_function_abi(&code, 0x1000, HOST_ABI)
            .unwrap_or_else(|error| panic!("{trap:02x?}: {error}"));
        assert!(
            recovered.source.contains("__builtin_trap();") && !recovered.source.contains("goto "),
            "{trap:02x?}: {}",
            recovered.source
        );
        let rust_source: &str = recovered.rust_source.as_deref().expect("Rust recovery");
        assert!(
            rust_source.contains("std::process::abort();"),
            "{trap:02x?}: {rust_source}"
        );
    }
}

#[test]
fn maximum_address_zero_arity_resolved_call_remains_a_call() {
    const CODE: [u8; 6] = [0xe8, 0xfa, 0xff, 0xff, 0xff, 0xc3];
    let call: ResolvedCall = ResolvedCall::from_integer_arity(u64::MAX, None, PseudoAbi::SysV, 0)
        .expect("zero-arity resolved call");
    let recovered: LeafRecovery =
        recover_leaf_function_with_calls(&CODE, 0, PseudoAbi::SysV, &[call])
            .expect("maximum-address call recovery");
    assert_eq!(recovered.call_targets, vec![u64::MAX]);
    assert!(
        recovered.source.contains("sub_ffffffffffffffff()")
            && !recovered.source.contains("__builtin_trap"),
        "{}",
        recovered.source
    );
    let rust_source: &str = recovered.rust_source.as_deref().expect("Rust recovery");
    assert!(
        rust_source.contains("sub_ffffffffffffffff()")
            && !rust_source.contains("std::process::abort"),
        "{rust_source}"
    );
}

#[test]
fn punpcklqdq_assigned_high_qword_is_observable_after_a_lane_shuffle() {
    const CODE: [u8; 25] = [
        0x66, 0x48, 0x0f, 0x6e, 0xc7, 0x66, 0x48, 0x0f, 0x6e, 0xce, 0x66, 0x0f, 0x6c, 0xc1, 0x66,
        0x0f, 0x73, 0xd8, 0x08, 0x66, 0x48, 0x0f, 0x7e, 0xc0, 0xc3,
    ];
    let recovery: LeafRecovery = recover_leaf_function_abi(&CODE, 0xb630, PseudoAbi::SysV)
        .expect("the unpacked high qword must remain observable through a lane shuffle");
    let compiler: String = cc().expect("host C compiler");
    let scratch: ScratchDir = scratch_dir("disrobe-pseudo-punpcklqdq");
    let object_path: PathBuf = scratch.path().join("anchor.o");
    let anchor: Vec<u8> = compile_object(
        &compiler,
        &CC_FLAGS,
        "int punpcklqdq_oracle_anchor;",
        &object_path,
    )
    .expect("oracle anchor object");
    let driver: String = format!(
        "{}\n#include <stdio.h>\nint main(void) {{\n\
             const uint64_t inputs[][2] = {{{{1, 9}}, {{0x1122334455667788ULL, 0x8877665544332211ULL}}, {{~0ULL, 7}}}};\n\
             for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {{\n\
                 if (recovered(inputs[i][0], inputs[i][1]) != inputs[i][1]) return 1;\n\
             }}\n\
             puts(\"OK\");\n\
             return 0;\n\
         }}\n",
        recovery.source
    );
    let stdout: String = link_and_run(&compiler, &driver, &anchor, "punpcklqdq_high", 10);
    assert!(
        stdout.contains("OK"),
        "the returned qword must be the assigned source low lane, not the preserved destination high lane: {stdout}"
    );
}

#[test]
fn host_o3_nested_loop_recovers_after_vector_lane_reduction() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host_o3_nested_loop_recovers_after_vector_lane_reduction: this case reads a host-native object and only applies where cfg!(windows) holds, so it grades nothing here and must not be cited as coverage on this platform"
        );
        return;
    }
    let host_cc: String = gcc().expect("host gcc");
    let program: &WholeProgram = SHAPE_PROGRAMS
        .iter()
        .find(|program: &&WholeProgram| program.name == "wp_nested_loop")
        .expect("nested-loop fixture");
    let scratch: ScratchDir = scratch_dir("disrobe-pseudo-nested-loop-o3");
    let object_path: PathBuf = scratch.path().join("wp_nested_loop_o3.o");
    let object: Vec<u8> =
        compile_object_opt(&host_cc, "-O3", &CC_FLAGS, program.c_source, &object_path)
            .expect("host O3 nested-loop object");
    let recovered: RecoveredProgram = recover_program(&object, program, HOST_ABI)
        .expect("the host O3 nested loop must recover after its vector lane reduction");
    for declaration in [
        "uint64_t r_r10",
        "uint64_t v0_lo",
        "uint64_t v1_lo",
        "uint64_t v2_lo",
        "uint64_t v3_lo",
    ] {
        assert!(
            recovered.tu.contains(declaration),
            "the exact outer-body resume tree must retain {declaration}: {}",
            recovered.tu
        );
    }
    assert_eq!(recovered.tu.matches("recover_L4:").count(), 1);
    assert_eq!(recovered.tu.matches("goto recover_L4;").count(), 1);
    let driver: String = build_program_driver(program, &recovered);
    let stdout: String = link_and_run(&host_cc, &driver, &object, program.name, 20);
    assert!(
        stdout.contains("OK") && !stdout.contains("MISMATCH"),
        "host O3 nested-loop recovery diverged: {stdout}"
    );
}

#[test]
fn whole_programs_recompile_to_behavioral_equivalence_sysv() {
    if cfg!(target_os = "macos") {
        eprintln!(
            "skipping sysv whole-program oracle on macos: the host gcc is an apple-clang alias that rejects the gcc-only if-conversion flags in CC_FLAGS, and arm64 cannot execute the x86-64 sysv battery; ubuntu carries the cross-platform sysv floor"
        );
        return;
    }
    let Some(_host): Option<String> = cc() else {
        eprintln!("skipping: no host C compiler on PATH");
        return;
    };
    let Some(_clang): Option<String> = clang() else {
        eprintln!("skipping sysv whole-program: clang (needed for SysV object) not on PATH");
        return;
    };
    let mut recovered_count: usize = 0;
    let mut rejected_count: usize = 0;
    let mut chain_recovered: bool = false;

    for program in PROGRAMS {
        let Some((host_cc, host_obj, sysv_obj)): Option<(String, Vec<u8>, Vec<u8>)> =
            compile_dual(program)
        else {
            continue;
        };
        let Some(recovered): Option<RecoveredProgram> =
            recover_program(&sysv_obj, program, PseudoAbi::SysV)
        else {
            rejected_count += 1;
            continue;
        };
        let driver: String = build_program_driver(program, &recovered);
        let watchdog: u64 = if program.loopy { 20 } else { 10 };
        let tag: String = format!("{}_sysv", program.name);
        let stdout: String = link_and_run(&host_cc, &driver, &host_obj, &tag, watchdog);
        assert!(
            stdout.contains("OK") && !stdout.contains("MISMATCH"),
            "sysv whole-program differential FAILED for {}: {stdout}",
            program.name
        );
        recovered_count += 1;
        chain_recovered |= program.name == "wp_chain";
        println!("whole-program (SysV) end-to-end PASSED: {}", program.name);
    }

    assert!(
        recovered_count >= 1,
        "sysv whole-program stitching recovered no entry chains ({rejected_count} sound-rejected of {})",
        PROGRAMS.len()
    );
    assert!(
        chain_recovered,
        "the three-deep nested-call chain wp_chain must recover its single-argument entry end-to-end on sysv"
    );
    println!(
        "whole-program sysv oracle: {recovered_count} recovered end-to-end, {rejected_count} sound-rejected of {}",
        PROGRAMS.len()
    );
}

fn neutralize_helper_call(tu: &str, helper_rec_name: &str) -> Option<String> {
    let needle: String = format!("= {helper_rec_name}(");
    let pos: usize = tu.find(&needle)?;
    let call_start: usize = pos + 2;
    let open: usize = pos + needle.len() - 1;
    let rel_close: usize = tu[open + 1..].find(')')?;
    let close: usize = open + 1 + rel_close;
    let mut out: String = String::with_capacity(tu.len());
    out.push_str(&tu[..call_start]);
    out.push('0');
    out.push_str(&tu[close + 1..]);
    Some(out)
}

fn swap_helper_call_args(tu: &str, helper_rec_name: &str) -> Option<String> {
    let needle: String = format!("= {helper_rec_name}(");
    let pos: usize = tu.find(&needle)?;
    let open: usize = pos + needle.len() - 1;
    let rel_close: usize = tu[open + 1..].find(')')?;
    let close: usize = open + 1 + rel_close;
    let inner: &str = &tu[open + 1..close];
    let mut parts: Vec<&str> = inner.split(',').map(str::trim).collect::<Vec<&str>>();
    if parts.len() < 2 {
        return None;
    }
    parts.reverse();
    let mut out: String = String::with_capacity(tu.len());
    out.push_str(&tu[..=open]);
    out.push_str(&parts.join(", "));
    out.push_str(&tu[close..]);
    (out != tu).then_some(out)
}

fn teeth_baseline(program: &WholeProgram) -> Option<(String, Vec<u8>, RecoveredProgram)> {
    let (host_cc, host_obj, sysv_obj): (String, Vec<u8>, Vec<u8>) = compile_dual(program)?;
    let Some(recovered): Option<RecoveredProgram> =
        recover_program(&sysv_obj, program, PseudoAbi::SysV)
    else {
        eprintln!(
            "skipping teeth for {}: this compiler build did not stitch the entry chain",
            program.name
        );
        return None;
    };
    let driver: String = build_program_driver(program, &recovered);
    let stdout: String = link_and_run(
        &host_cc,
        &driver,
        &host_obj,
        &format!("{}_baseline", program.name),
        10,
    );
    assert!(
        stdout.contains("OK") && !stdout.contains("MISMATCH"),
        "teeth baseline must first agree before mutation: {stdout}"
    );
    Some((host_cc, host_obj, recovered))
}

#[test]
fn teeth_dropping_a_helper_call_diverges() {
    let Some(_host): Option<String> = cc() else {
        eprintln!("skipping: no host C compiler on PATH");
        return;
    };
    let Some(_clang): Option<String> = clang() else {
        eprintln!("skipping teeth: clang not on PATH");
        return;
    };
    let Some((host_cc, host_obj, recovered)): Option<(String, Vec<u8>, RecoveredProgram)> =
        teeth_baseline(&TEETH_SQ)
    else {
        return;
    };
    let Some(mutated): Option<String> = neutralize_helper_call(&recovered.tu, "rec_teeth_sq_h")
    else {
        eprintln!("skipping teeth: no helper call statement to neutralize");
        return;
    };
    assert_ne!(
        mutated, recovered.tu,
        "neutralizing the helper call must change the recovered translation unit"
    );
    let mutated_program: RecoveredProgram = RecoveredProgram {
        tu: mutated,
        entry_params: recovered.entry_params,
        entry_return_width: recovered.entry_return_width,
    };
    let driver: String = build_program_driver(&TEETH_SQ, &mutated_program);
    let stdout: String = link_and_run(&host_cc, &driver, &host_obj, "teeth_sq_drop", 10);
    assert!(
        stdout.contains("MISMATCH") && !stdout.contains("OK"),
        "teeth FAILED: dropping the squared helper call must diverge from the original: {stdout}"
    );
    println!("teeth confirmed: neutralizing the helper call diverges (MISMATCH observed)");
}

#[test]
fn teeth_swapping_a_call_argument_diverges() {
    let Some(_host): Option<String> = cc() else {
        eprintln!("skipping: no host C compiler on PATH");
        return;
    };
    let Some(_clang): Option<String> = clang() else {
        eprintln!("skipping teeth: clang not on PATH");
        return;
    };
    let Some((host_cc, host_obj, recovered)): Option<(String, Vec<u8>, RecoveredProgram)> =
        teeth_baseline(&TEETH_SUB)
    else {
        return;
    };
    let Some(mutated): Option<String> = swap_helper_call_args(&recovered.tu, "rec_teeth_sub_h")
    else {
        eprintln!("skipping teeth: helper call did not carry two distinct arguments to swap");
        return;
    };
    assert_ne!(
        mutated, recovered.tu,
        "swapping the call arguments must change the recovered translation unit"
    );
    let mutated_program: RecoveredProgram = RecoveredProgram {
        tu: mutated,
        entry_params: recovered.entry_params,
        entry_return_width: recovered.entry_return_width,
    };
    let driver: String = build_program_driver(&TEETH_SUB, &mutated_program);
    let stdout: String = link_and_run(&host_cc, &driver, &host_obj, "teeth_sub_swap", 10);
    assert!(
        stdout.contains("MISMATCH") && !stdout.contains("OK"),
        "teeth FAILED: swapping the subtraction operands must diverge from the original: {stdout}"
    );
    println!("teeth confirmed: swapping a call argument diverges (MISMATCH observed)");
}

const OPT_LEVELS: [&str; 6] = ["-O0", "-O1", "-O2", "-O3", "-Os", "-Og"];

#[derive(Clone, Copy, PartialEq, Eq)]
enum ShapeOutcome {
    Equivalent,
    Mismatch,
    SoundRejected,
    Skipped,
}

fn opt_tag(opt: &str) -> &str {
    opt.trim_start_matches('-')
}

#[test]
fn optimization_matrix_includes_aggressive_and_size_modes() {
    assert!(OPT_LEVELS.contains(&"-O3"));
    assert!(OPT_LEVELS.contains(&"-Os"));
    assert!(OPT_LEVELS.contains(&"-Og"));
}

#[test]
fn near_conditional_branch_recompiles_to_behavioral_equivalence() {
    if cfg!(target_os = "macos") {
        eprintln!("skipping near-branch comparison on macos: x86-64 execution is unavailable");
        return;
    }
    let Some(_host): Option<String> = cc() else {
        eprintln!("skipping near-branch comparison: no host C compiler on PATH");
        return;
    };
    let Some(_clang): Option<String> = clang() else {
        eprintln!("skipping near-branch comparison: clang not on PATH");
        return;
    };
    let program: &WholeProgram = &NEAR_BRANCH_PROGRAM;
    let (host_cc, host_obj, sysv_obj): (String, Vec<u8>, Vec<u8>) =
        compile_dual(program).expect("compile near-branch program");
    let (code, base): (Vec<u8>, u64) =
        function_code(&sysv_obj, "wp_near_branch_h").expect("near-branch body");
    let insns: Vec<DisasmInsn> =
        disassemble(Arch::X86_64, base, &code).expect("decode near-branch body");
    assert!(
        insns.iter().any(|insn: &DisasmInsn| {
            insn.mnemonic.starts_with('j')
                && insn.mnemonic != "jmp"
                && insn.operands.starts_with("near ")
        }),
        "compiler did not emit a near conditional branch: {insns:?}"
    );
    let recovered: RecoveredProgram =
        recover_program(&sysv_obj, program, PseudoAbi::SysV).expect("recover near-branch program");
    let driver: String = build_program_driver(program, &recovered);
    let stdout: String = link_and_run(&host_cc, &driver, &host_obj, "wp_near_branch_sysv", 10);
    assert!(
        stdout.contains("OK") && !stdout.contains("MISMATCH"),
        "near-branch comparison failed: {stdout}"
    );
}

fn full_battery() -> Vec<&'static WholeProgram> {
    PROGRAMS.iter().chain(SHAPE_PROGRAMS).collect()
}

fn measure_host_program(
    builder: &str,
    program: &WholeProgram,
    opt: &str,
    dir: &Path,
) -> ShapeOutcome {
    let obj_path: PathBuf = dir.join(format!("{}_{}_host.o", program.name, opt_tag(opt)));
    let Some(object): Option<Vec<u8>> =
        compile_object_opt(builder, opt, &CC_FLAGS, program.c_source, &obj_path)
    else {
        return ShapeOutcome::Skipped;
    };
    let Some(recovered): Option<RecoveredProgram> = recover_program(&object, program, HOST_ABI)
    else {
        return ShapeOutcome::SoundRejected;
    };
    let driver: String = build_program_driver(program, &recovered);
    let watchdog: u64 = if program.loopy { 20 } else { 10 };
    let tag: String = format!("{}_{}_host", program.name, opt_tag(opt));
    let stdout: String = link_and_run(builder, &driver, &object, &tag, watchdog);
    if stdout.contains("OK") && !stdout.contains("MISMATCH") {
        ShapeOutcome::Equivalent
    } else {
        eprintln!("MISMATCH host {} at {opt}: {}", program.name, stdout.trim());
        ShapeOutcome::Mismatch
    }
}

fn measure_sysv_program(
    host_cc: &str,
    clang_cc: &str,
    program: &WholeProgram,
    opt: &str,
    dir: &Path,
) -> ShapeOutcome {
    let host_path: PathBuf = dir.join(format!("{}_{}_gt.o", program.name, opt_tag(opt)));
    let Some(host_obj): Option<Vec<u8>> =
        compile_object_opt(host_cc, opt, &CC_FLAGS, program.c_source, &host_path)
    else {
        return ShapeOutcome::Skipped;
    };
    let sysv_path: PathBuf = dir.join(format!("{}_{}_sysv.o", program.name, opt_tag(opt)));
    let sysv_flags: [&str; 5] = [
        "--target=x86_64-unknown-linux-gnu",
        "-fno-stack-protector",
        "-fno-optimize-sibling-calls",
        "-fcf-protection=none",
        "-c",
    ];
    let Some(sysv_obj): Option<Vec<u8>> =
        compile_object_opt(clang_cc, opt, &sysv_flags, program.c_source, &sysv_path)
    else {
        return ShapeOutcome::Skipped;
    };
    let Some(recovered): Option<RecoveredProgram> =
        recover_program(&sysv_obj, program, PseudoAbi::SysV)
    else {
        return ShapeOutcome::SoundRejected;
    };
    let driver: String = build_program_driver(program, &recovered);
    let watchdog: u64 = if program.loopy { 20 } else { 10 };
    let tag: String = format!("{}_{}_sysv", program.name, opt_tag(opt));
    let stdout: String = link_and_run(host_cc, &driver, &host_obj, &tag, watchdog);
    if stdout.contains("OK") && !stdout.contains("MISMATCH") {
        ShapeOutcome::Equivalent
    } else {
        eprintln!("MISMATCH sysv {} at {opt}: {}", program.name, stdout.trim());
        ShapeOutcome::Mismatch
    }
}

#[test]
fn shape_battery_recompile_to_behavioral_equivalence_hostabi() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native shape oracle on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; the sysv class is the cross-platform x86-64 guard"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!("skipping host shape oracle: gcc not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir("disrobe-pseudo-wp");
    let dir: PathBuf = scratch.path().to_path_buf();
    let battery: Vec<&WholeProgram> = full_battery();
    let mut total_equivalent: usize = 0;
    let mut total_slots: usize = 0;
    let mut mismatches: Vec<String> = Vec::new();

    for opt in OPT_LEVELS {
        let mut equivalent: usize = 0;
        let mut rejected: Vec<&str> = Vec::new();
        let mut skipped: usize = 0;
        for program in &battery {
            match measure_host_program(&builder, program, opt, &dir) {
                ShapeOutcome::Equivalent => equivalent += 1,
                ShapeOutcome::Mismatch => mismatches.push(format!("{} {opt}", program.name)),
                ShapeOutcome::SoundRejected => rejected.push(program.name),
                ShapeOutcome::Skipped => skipped += 1,
            }
        }
        let graded: usize = battery.len() - skipped;
        total_equivalent += equivalent;
        total_slots += graded;
        assert!(
            skipped == 0 && equivalent.saturating_mul(10) >= graded.saturating_mul(9),
            "host shape matrix {opt} execution equivalence below 90%: {equivalent}/{graded} equivalent, {} sound-rejected, {skipped} env-skipped",
            rejected.len()
        );
        println!(
            "host shape oracle {opt}: {equivalent}/{graded} whole programs behaviorally equivalent ({} sound-rejected: {rejected:?}, {skipped} env-skipped)",
            rejected.len()
        );
    }

    assert!(
        mismatches.is_empty(),
        "host shape battery has UNSOUND recoveries (recovered but behaviorally wrong): {mismatches:?}"
    );
    assert!(
        total_equivalent >= 32,
        "host shape battery regressed below the CI-portable floor: {total_equivalent}/{total_slots} equivalent across {} opt levels",
        OPT_LEVELS.len()
    );
    println!(
        "host shape oracle TOTAL: {total_equivalent}/{total_slots} equivalent across {} opt levels x {} programs",
        OPT_LEVELS.len(),
        battery.len()
    );
}

#[test]
fn shape_battery_recompile_to_behavioral_equivalence_sysv() {
    if cfg!(target_os = "macos") {
        eprintln!(
            "skipping sysv shape oracle on macos: the host gcc is an apple-clang alias that rejects the gcc-only if-conversion flags in CC_FLAGS, and arm64 cannot execute the x86-64 sysv battery; ubuntu carries the cross-platform sysv floor"
        );
        return;
    }
    let Some(host_cc): Option<String> = cc() else {
        eprintln!("skipping sysv shape oracle: no host C compiler on PATH");
        return;
    };
    let Some(clang_cc): Option<String> = clang() else {
        eprintln!("skipping sysv shape oracle: clang (needed for the SysV object) not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir("disrobe-pseudo-wp");
    let dir: PathBuf = scratch.path().to_path_buf();
    let battery: Vec<&WholeProgram> = full_battery();
    let mut total_equivalent: usize = 0;
    let mut total_slots: usize = 0;
    let mut mismatches: Vec<String> = Vec::new();

    for opt in OPT_LEVELS {
        let mut equivalent: usize = 0;
        let mut rejected: Vec<&str> = Vec::new();
        let mut skipped: usize = 0;
        for program in &battery {
            match measure_sysv_program(&host_cc, &clang_cc, program, opt, &dir) {
                ShapeOutcome::Equivalent => equivalent += 1,
                ShapeOutcome::Mismatch => mismatches.push(format!("{} {opt}", program.name)),
                ShapeOutcome::SoundRejected => rejected.push(program.name),
                ShapeOutcome::Skipped => skipped += 1,
            }
        }
        let graded: usize = battery.len() - skipped;
        total_equivalent += equivalent;
        total_slots += graded;
        assert!(
            skipped == 0 && equivalent.saturating_mul(10) >= graded.saturating_mul(9),
            "sysv shape matrix {opt} execution equivalence below 90%: {equivalent}/{graded} equivalent, {} sound-rejected, {skipped} env-skipped",
            rejected.len()
        );
        println!(
            "sysv shape oracle {opt}: {equivalent}/{graded} whole programs behaviorally equivalent ({} sound-rejected: {rejected:?}, {skipped} env-skipped)",
            rejected.len()
        );
    }

    assert!(
        mismatches.is_empty(),
        "sysv shape battery has UNSOUND recoveries (recovered but behaviorally wrong): {mismatches:?}"
    );
    assert!(
        total_equivalent >= 32,
        "sysv shape battery regressed below the CI-portable floor: {total_equivalent}/{total_slots} equivalent across {} opt levels",
        OPT_LEVELS.len()
    );
    println!(
        "sysv shape oracle TOTAL: {total_equivalent}/{total_slots} equivalent across {} opt levels x {} programs",
        OPT_LEVELS.len(),
        battery.len()
    );
}
