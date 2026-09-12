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
use std::path::PathBuf;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_native::{
    ProgramFunction, PseudoAbi, RecoveredFunction as LibRecoveredFunction,
    RecoveredProgram as LibRecoveredProgram, recover_program as lib_recover_program,
};

use common::{
    HOST_ABI, cc, compile_object_opt, function_code, link_and_run, scratch_dir, strip_includes,
};

const CC_FLAGS: [&str; 6] = [
    "-fno-stack-protector",
    "-fno-optimize-sibling-calls",
    "-fno-if-conversion",
    "-fno-if-conversion2",
    "-fno-tree-loop-if-convert",
    "-c",
];

const SCRATCH_SLOTS: usize = 8;

const INPUT_ROWS: &str = "{1,0},{1,1},{-3,7},{0,0},{5,-2},{9,9},{-1,-1},{7,0},{2,13},{-8,4}";

const BOTH_LEVELS: [&str; 2] = ["-O0", "-O1"];

const OPTIMIZED_ONLY: [&str; 1] = ["-O1"];

struct EffectProgram {
    name: &'static str,
    entry: &'static str,
    functions: &'static [&'static str],
    null_probe: bool,
    levels: &'static [&'static str],
    c_source: &'static str,
}

const EFFECT_PROGRAMS: &[EffectProgram] = &[
    EffectProgram {
        name: "ef_alias",
        entry: "ef_alias_entry",
        functions: &["ef_alias_entry"],
        null_probe: false,
        levels: &BOTH_LEVELS,
        c_source: "long long ef_alias_entry(long long a, long long *buf){ long long v = buf[0]; buf[1] = v + a; return v * 3 + buf[0]; }",
    },
    EffectProgram {
        name: "ef_twice_load",
        entry: "ef_twice_load_entry",
        functions: &["ef_twice_load_entry"],
        null_probe: false,
        levels: &BOTH_LEVELS,
        c_source: "long long ef_twice_load_entry(long long a, long long *buf){ long long v = buf[0] + a; buf[0] = v; return v + buf[0] + v; }",
    },
    EffectProgram {
        name: "ef_order",
        entry: "ef_order_entry",
        functions: &["ef_order_entry"],
        null_probe: false,
        levels: &BOTH_LEVELS,
        c_source: "long long ef_order_entry(long long a, long long *buf){ buf[0] = a; buf[1] = buf[0] + 1; buf[0] = a + 5; buf[2] = buf[1] + buf[0]; return buf[2]; }",
    },
    EffectProgram {
        name: "ef_call_once",
        entry: "ef_call_once_entry",
        functions: &["ef_call_once_entry", "ef_call_once_h"],
        null_probe: false,
        levels: &BOTH_LEVELS,
        c_source: "__attribute__((noinline,noclone)) long long ef_call_once_h(long long *buf, long long x){ buf[0] = buf[0] + 1; buf[1] = x; return x * 2; }\n\
                   long long ef_call_once_entry(long long a, long long *buf){ long long v = ef_call_once_h(buf, a); return v + v + buf[0]; }",
    },
    EffectProgram {
        name: "ef_loop_store",
        entry: "ef_loop_store_entry",
        functions: &["ef_loop_store_entry"],
        null_probe: false,
        levels: &BOTH_LEVELS,
        c_source: "long long ef_loop_store_entry(long long a, long long *buf){ long long s = 0; long long i = 0; while (i < 4) { s += buf[0]; buf[0] = buf[0] + a; i++; } buf[2] = s; return s; }",
    },
    EffectProgram {
        name: "ef_guard_load",
        entry: "ef_guard_load_entry",
        functions: &["ef_guard_load_entry"],
        null_probe: true,
        levels: &BOTH_LEVELS,
        c_source: "long long ef_guard_load_entry(long long a, long long *buf){ if (buf == 0) { return -1; } return buf[0] + a; }",
    },
    EffectProgram {
        name: "ef_guard_div",
        entry: "ef_guard_div_entry",
        functions: &["ef_guard_div_entry"],
        null_probe: false,
        levels: &OPTIMIZED_ONLY,
        c_source: "long long ef_guard_div_entry(long long a, long long *buf){ long long d = buf[0]; if (d == 0) { buf[1] = -1; return -1; } buf[1] = a / d; return buf[1]; }",
    },
];

struct RecoveredEffectProgram {
    tu: String,
}

fn recover_effect_program(
    object: &[u8],
    program: &EffectProgram,
    abi: PseudoAbi,
) -> Option<RecoveredEffectProgram> {
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
            eprintln!("reject {}: {} ({})", program.name, bad.name, bad.reason);
        }
        return None;
    }
    let mut tu: String = String::new();
    let mut entry_params: usize = 0;
    for (idx, &fname) in program.functions.iter().enumerate() {
        let rec: &LibRecoveredFunction = &result.recovered[idx];
        tu.push_str(&strip_includes(&rec.source));
        tu.push('\n');
        if fname == program.entry {
            entry_params = rec.signature.callable_arity();
        }
    }
    if entry_params != 2 {
        eprintln!(
            "reject {}: recovered entry arity {entry_params} is not the (value, pointer) contract",
            program.name
        );
        return None;
    }
    Some(RecoveredEffectProgram { tu })
}

fn build_effect_driver(program: &EffectProgram, tu: &str) -> String {
    let entry: &str = program.entry;
    let name: &str = program.name;
    let mut null_case: String = String::new();
    if program.null_probe {
        let _ = write!(
            null_case,
            "        {{\n\
             \x20           long long want_null = {entry}(in0, (long long *)0);\n\
             \x20           long long got_null = (long long)rec_{entry}((uint64_t)in0, (uint64_t)0);\n\
             \x20           if (want_null != got_null) {{ printf(\"MISMATCH {name} nullguard in=%lld want=%lld got=%lld\\n\", in0, want_null, got_null); return 1; }}\n\
             \x20       }}\n",
        );
    }
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n#include <string.h>\n{tu}\n\
         extern long long {entry}(long long, long long *);\n\
         int main(void) {{\n\
         \x20   long long inputs[][2] = {{ {INPUT_ROWS} }};\n\
         \x20   size_t n_inputs = sizeof(inputs)/sizeof(inputs[0]);\n\
         \x20   for (size_t k = 0; k < n_inputs; k++) {{\n\
         \x20       long long in0 = inputs[k][0];\n\
         \x20       long long seed = inputs[k][1];\n\
         \x20       long long want_buf[{SCRATCH_SLOTS}];\n\
         \x20       long long got_buf[{SCRATCH_SLOTS}];\n\
         \x20       for (size_t s = 0; s < {SCRATCH_SLOTS}; s++) {{ want_buf[s] = seed + (long long)s; got_buf[s] = seed + (long long)s; }}\n\
         \x20       long long want = {entry}(in0, want_buf);\n\
         \x20       long long got = (long long)rec_{entry}((uint64_t)in0, (uint64_t)(uintptr_t)got_buf);\n\
         \x20       if (want != got) {{ printf(\"MISMATCH {name} value in=%lld seed=%lld want=%lld got=%lld\\n\", in0, seed, want, got); return 1; }}\n\
         \x20       for (size_t s = 0; s < {SCRATCH_SLOTS}; s++) {{\n\
         \x20           if (want_buf[s] != got_buf[s]) {{ printf(\"MISMATCH {name} effect in=%lld seed=%lld slot=%zu want=%lld got=%lld\\n\", in0, seed, s, want_buf[s], got_buf[s]); return 1; }}\n\
         \x20       }}\n\
         {null_case}\
         \x20   }}\n\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n",
    )
}

struct EffectBaseline {
    builder: String,
    object: Vec<u8>,
    recovered: RecoveredEffectProgram,
}

fn effect_baseline(program: &EffectProgram) -> Option<EffectBaseline> {
    effect_baseline_at(program, "-O1")
}

fn effect_baseline_at(program: &EffectProgram, opt: &str) -> Option<EffectBaseline> {
    let builder: String = cc()?;
    let scratch: ScratchDir = scratch_dir("disrobe-effect-spill");
    let dir: PathBuf = scratch.path().to_path_buf();
    let obj_path: PathBuf = dir.join(format!("{}_{}_host.o", program.name, opt_tag(opt)));
    let object: Vec<u8> =
        compile_object_opt(&builder, opt, &CC_FLAGS, program.c_source, &obj_path)?;
    let recovered: RecoveredEffectProgram = recover_effect_program(&object, program, HOST_ABI)?;
    Some(EffectBaseline {
        builder,
        object,
        recovered,
    })
}

fn opt_tag(opt: &str) -> &str {
    opt.trim_start_matches('-')
}

fn require_windows_host(check: &str) -> bool {
    if cfg!(windows) {
        return true;
    }
    eprintln!(
        "skipping {check}: the host recompile class is pinned to the windows ms-x64 toolchain in this crate"
    );
    false
}

#[test]
fn recovered_effects_keep_their_original_count_and_order() {
    if !require_windows_host("effect spill differential") {
        return;
    }
    let Some(_builder): Option<String> = cc() else {
        eprintln!("skipping effect spill differential: no host cc on PATH");
        return;
    };
    let mut graded: Vec<&str> = Vec::new();
    let mut rejected: Vec<&str> = Vec::new();
    for program in EFFECT_PROGRAMS {
        let Some(baseline): Option<EffectBaseline> = effect_baseline(program) else {
            rejected.push(program.name);
            continue;
        };
        let driver: String = build_effect_driver(program, &baseline.recovered.tu);
        let stdout: String = link_and_run(
            &baseline.builder,
            &driver,
            &baseline.object,
            program.name,
            20,
        );
        assert!(
            stdout.contains("OK") && !stdout.contains("MISMATCH"),
            "effect differential FAILED for {}: {stdout}\n--- recovered translation unit ---\n{}",
            program.name,
            baseline.recovered.tu
        );
        graded.push(program.name);
    }
    assert!(
        rejected.is_empty(),
        "every effect battery member must recover; rejected: {rejected:?}"
    );
    assert_eq!(
        graded.len(),
        EFFECT_PROGRAMS.len(),
        "the effect battery must grade every member, graded: {graded:?}"
    );
    println!("effect spill differential graded {} programs", graded.len());
}

fn first_call_line(tu: &str, callee: &str) -> Option<String> {
    tu.lines()
        .find(|line: &&str| {
            let trimmed: &str = line.trim();
            !trimmed.starts_with("extern") && trimmed.contains(callee) && trimmed.ends_with(");")
        })
        .map(str::to_owned)
}

fn is_effect_store(line: &str) -> bool {
    let trimmed: &str = line.trim();
    if !trimmed.ends_with(';') {
        return false;
    }
    let Some((lhs, _)): Option<(&str, &str)> = trimmed.split_once(" = ") else {
        return false;
    };
    lhs.starts_with("(*(") || lhs.starts_with("*(") || lhs.contains("->field_")
}

const CENSUS_BEFORE_SPILLING: usize = 113;

fn temporary_statements(tu: &str) -> usize {
    tu.lines()
        .filter(|line: &&str| {
            let trimmed: &str = line.trim();
            trimmed.starts_with("r_") && trimmed.ends_with(';')
        })
        .count()
}

#[test]
fn recovered_effect_programs_report_their_temporary_counts() {
    if !require_windows_host("temporary census") {
        return;
    }
    let mut total: usize = 0;
    let mut measured: usize = 0;
    let mut expected: usize = 0;
    for program in EFFECT_PROGRAMS {
        expected += program.levels.len();
        for opt in program.levels {
            let Some(baseline): Option<EffectBaseline> = effect_baseline_at(program, opt) else {
                panic!(
                    "{} at {opt} must recover before its temporaries are counted",
                    program.name
                );
            };
            let count: usize = temporary_statements(&baseline.recovered.tu);
            println!("temporary census {opt} {}: {count}", program.name);
            total += count;
            measured += 1;
        }
    }
    assert_eq!(measured, expected);
    println!("temporary census total: {total}");
    assert!(
        total < CENSUS_BEFORE_SPILLING,
        "use-counted spilling must keep the recovered temporary count below the {CENSUS_BEFORE_SPILLING} statements the renderer emitted without it, measured {total}"
    );
}

#[test]
fn recovering_the_same_object_twice_produces_identical_source() {
    if !require_windows_host("recovery determinism") {
        return;
    }
    for program in EFFECT_PROGRAMS {
        for opt in program.levels {
            let Some(first): Option<EffectBaseline> = effect_baseline_at(program, opt) else {
                panic!(
                    "{} at {opt} must recover before determinism is graded",
                    program.name
                );
            };
            let Some(second): Option<RecoveredEffectProgram> =
                recover_effect_program(&first.object, program, HOST_ABI)
            else {
                panic!("{} at {opt} must recover on the repeat run", program.name);
            };
            assert_eq!(
                first.recovered.tu, second.tu,
                "{} at {opt} recovered different source on a repeat run of the same object",
                program.name
            );
        }
    }
    println!("recovery determinism graded every effect battery member");
}

#[test]
fn recovered_effects_survive_the_unoptimized_build() {
    if !require_windows_host("unoptimized effect differential") {
        return;
    }
    let mut graded: Vec<&str> = Vec::new();
    let unoptimized: Vec<&EffectProgram> = EFFECT_PROGRAMS
        .iter()
        .filter(|program: &&EffectProgram| program.levels.contains(&"-O0"))
        .collect();
    for program in &unoptimized {
        let Some(baseline): Option<EffectBaseline> = effect_baseline_at(program, "-O0") else {
            panic!("{} must recover at -O0", program.name);
        };
        let driver: String = build_effect_driver(program, &baseline.recovered.tu);
        let stdout: String = link_and_run(
            &baseline.builder,
            &driver,
            &baseline.object,
            &format!("{}_o0", program.name),
            20,
        );
        assert!(
            stdout.contains("OK") && !stdout.contains("MISMATCH"),
            "unoptimized effect differential FAILED for {}: {stdout}\n--- recovered translation unit ---\n{}",
            program.name,
            baseline.recovered.tu
        );
        graded.push(program.name);
    }
    assert_eq!(graded.len(), unoptimized.len());
    println!(
        "unoptimized effect differential graded {} programs",
        graded.len()
    );
}

#[test]
fn the_recorded_unoptimized_exclusion_is_still_a_lifter_gap() {
    if !require_windows_host("unoptimized exclusion audit") {
        return;
    }
    for program in EFFECT_PROGRAMS {
        if program.levels.contains(&"-O0") {
            continue;
        }
        assert!(
            effect_baseline_at(program, "-O0").is_none(),
            "{} now recovers at -O0; move it back onto the unoptimized battery instead of leaving the exclusion in place",
            program.name
        );
        println!(
            "recorded unoptimized exclusion still holds: {}",
            program.name
        );
    }
}

#[test]
fn teeth_duplicating_a_recovered_call_diverges() {
    if !require_windows_host("duplicated effect teeth") {
        return;
    }
    let program: &EffectProgram = EFFECT_PROGRAMS
        .iter()
        .find(|p: &&EffectProgram| p.name == "ef_call_once")
        .expect("ef_call_once is part of the effect battery");
    let Some(baseline): Option<EffectBaseline> = effect_baseline(program) else {
        panic!("ef_call_once must recover before its teeth can be graded");
    };
    let Some(call_line): Option<String> =
        first_call_line(&baseline.recovered.tu, "rec_ef_call_once_h(")
    else {
        panic!(
            "the recovered entry must contain a call to the recovered helper:\n{}",
            baseline.recovered.tu
        );
    };
    let duplicated: String =
        baseline
            .recovered
            .tu
            .replacen(&call_line, &format!("{call_line}\n{call_line}"), 1);
    assert_ne!(
        duplicated, baseline.recovered.tu,
        "the duplication mutation must change the recovered translation unit"
    );
    let driver: String = build_effect_driver(program, &duplicated);
    let stdout: String = link_and_run(
        &baseline.builder,
        &driver,
        &baseline.object,
        "ef_call_once_dup",
        20,
    );
    assert!(
        stdout.contains("MISMATCH"),
        "performing the recovered call twice must diverge from the original; the differential reported: {stdout}"
    );
    println!("duplicated-effect teeth confirmed: {}", stdout.trim());
}

#[test]
fn teeth_sinking_a_recovered_load_past_a_store_diverges() {
    if !require_windows_host("reordered effect teeth") {
        return;
    }
    let program: &EffectProgram = EFFECT_PROGRAMS
        .iter()
        .find(|p: &&EffectProgram| p.name == "ef_order")
        .expect("ef_order is part of the effect battery");
    let Some(baseline): Option<EffectBaseline> = effect_baseline(program) else {
        panic!("ef_order must recover before its teeth can be graded");
    };
    let Some(reordered): Option<String> =
        swap_first_adjacent_body_statements(&baseline.recovered.tu)
    else {
        panic!(
            "the recovered entry must expose two adjacent effect statements to swap:\n{}",
            baseline.recovered.tu
        );
    };
    let driver: String = build_effect_driver(program, &reordered);
    let stdout: String = link_and_run(
        &baseline.builder,
        &driver,
        &baseline.object,
        "ef_order_swap",
        20,
    );
    assert!(
        stdout.contains("MISMATCH"),
        "moving a recovered store past its neighbour must diverge from the original; the differential reported: {stdout}"
    );
    println!("reordered-effect teeth confirmed: {}", stdout.trim());
}

fn swap_first_adjacent_body_statements(tu: &str) -> Option<String> {
    let lines: Vec<&str> = tu.lines().collect();
    let store_positions: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter_map(|(idx, line): (usize, &&str)| is_effect_store(line).then_some(idx))
        .collect();
    let &first: &usize = store_positions.first()?;
    let &second: &usize = store_positions.get(1)?;
    let mut swapped: Vec<&str> = lines.clone();
    swapped.swap(first, second);
    let mut out: String = swapped.join("\n");
    out.push('\n');
    (out != tu).then_some(out)
}
