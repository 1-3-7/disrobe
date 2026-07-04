#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unreadable_literal
)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_native::{
    LeafRecovery, PseudoAbi, ResolvedCall, recover_leaf_function_in_object,
    resolved_int_arity_in_object,
};
use object::{Object as _, ObjectSection as _, ObjectSymbol as _};

const HOST_ABI: PseudoAbi = if cfg!(windows) {
    PseudoAbi::MsX64
} else {
    PseudoAbi::SysV
};

const WIDE_INPUTS: &[[i64; 3]] = &[
    [0, 0, 0],
    [1, 1, 1],
    [-1, -1, -1],
    [7, 3, 5],
    [-7, 3, -5],
    [123456, -654321, 99],
    [2147483647, 1, 2],
    [-2147483648, -1, -2],
    [9223372036854775807, 2, 3],
    [100, 200, 300],
    [-100, 50, -25],
    [1048576, 1024, 32],
    [42, 42, 42],
    [3735928559, 3405705229, 4660],
];

const SMALL_INPUTS: &[[i64; 3]] = &[
    [0, 0, 0],
    [1, 2, 3],
    [5, 1, 1],
    [10, 4, 2],
    [-3, 7, 1],
    [20, 5, 3],
    [0, 10, 10],
    [63, 2, 1],
    [7, 7, 7],
    [-1, -1, -1],
    [16, 8, 4],
    [2, 50, 25],
    [40, 3, 9],
    [9, 40, 4],
];

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
];

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

fn full_battery() -> Vec<&'static WholeProgram> {
    PROGRAMS.iter().chain(SHAPE_PROGRAMS).collect()
}

fn cc() -> Option<String> {
    ["gcc", "clang", "cc"]
        .into_iter()
        .find(|c: &&str| {
            Command::new(c)
                .arg("--version")
                .output()
                .is_ok_and(|o: std::process::Output| o.status.success())
        })
        .map(str::to_owned)
}

fn gcc() -> Option<String> {
    Command::new("gcc")
        .arg("--version")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
        .then(|| "gcc".to_owned())
}

fn clang() -> Option<String> {
    Command::new("clang")
        .arg("--version")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
        .then(|| "clang".to_owned())
}

fn rustc() -> Option<String> {
    Command::new("rustc")
        .arg("--version")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
        .then(|| "rustc".to_owned())
}

fn scratch_dir() -> PathBuf {
    let dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe-pseudo-rustwp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn function_code(object_bytes: &[u8], name: &str) -> Option<(Vec<u8>, u64)> {
    let file: object::File<'_> = object::File::parse(object_bytes).ok()?;
    let candidates: [String; 2] = [name.to_owned(), format!("_{name}")];
    let sym: object::Symbol<'_, '_> = file.symbols().find(|s: &object::Symbol<'_, '_>| {
        s.name()
            .is_ok_and(|n: &str| candidates.iter().any(|c: &String| c == n))
    })?;
    let section_index: object::SectionIndex = match sym.section() {
        object::SymbolSection::Section(idx) => idx,
        _ => return None,
    };
    let section: object::Section<'_, '_> = file.section_by_index(section_index).ok()?;
    let data: &[u8] = section.data().ok()?;
    let sym_addr: u64 = sym.address();
    let start: usize = usize::try_from(sym_addr.saturating_sub(section.address())).ok()?;
    let size: usize = usize::try_from(sym.size()).ok()?;
    let end: usize = if size == 0 {
        let next_off: usize = file
            .symbols()
            .filter(|s: &object::Symbol<'_, '_>| {
                matches!(s.section(), object::SymbolSection::Section(idx) if idx == section_index)
                    && s.address() > sym_addr
                    && s.kind() == object::SymbolKind::Text
                    && s.name().is_ok_and(|n: &str| !n.is_empty())
            })
            .filter_map(|s: object::Symbol<'_, '_>| {
                usize::try_from(s.address().saturating_sub(section.address())).ok()
            })
            .min()
            .unwrap_or(data.len());
        next_off.min(data.len())
    } else {
        start.saturating_add(size).min(data.len())
    };
    let slice: &[u8] = data.get(start..end)?;
    Some((slice.to_vec(), sym_addr))
}

fn function_code_at(object_bytes: &[u8], addr: u64) -> Option<(Vec<u8>, u64, String)> {
    let file: object::File<'_> = object::File::parse(object_bytes).ok()?;
    let sym: object::Symbol<'_, '_> = file.symbols().find(|s: &object::Symbol<'_, '_>| {
        s.address() == addr && s.kind() == object::SymbolKind::Text
    })?;
    let name: String = sym.name().ok()?.to_owned();
    let bare: &str = name.strip_prefix('_').unwrap_or(&name);
    let (code, base): (Vec<u8>, u64) = function_code(object_bytes, bare)?;
    Some((code, base, bare.to_owned()))
}

fn call_callee_for_target(object_bytes: &[u8], caller: &str, target: u64) -> Option<String> {
    let file: object::File<'_> = object::File::parse(object_bytes).ok()?;
    let candidates: [String; 2] = [caller.to_owned(), format!("_{caller}")];
    let caller_sym: object::Symbol<'_, '_> =
        file.symbols().find(|s: &object::Symbol<'_, '_>| {
            s.name()
                .is_ok_and(|n: &str| candidates.iter().any(|c: &String| c == n))
        })?;
    let section_index: object::SectionIndex = match caller_sym.section() {
        object::SymbolSection::Section(idx) => idx,
        _ => return None,
    };
    let section: object::Section<'_, '_> = file.section_by_index(section_index).ok()?;
    let caller_start: u64 = caller_sym.address();
    let caller_end: u64 = caller_start.saturating_add(caller_sym.size());
    let target_offset: u64 = target.saturating_sub(4).saturating_sub(section.address());
    for (offset, reloc) in section.relocations() {
        let reloc_addr: u64 = section.address().saturating_add(offset);
        if !(reloc_addr >= caller_start && reloc_addr < caller_end) || offset != target_offset {
            continue;
        }
        let object::RelocationTarget::Symbol(sym_index) = reloc.target() else {
            continue;
        };
        let sym: object::Symbol<'_, '_> = file.symbol_by_index(sym_index).ok()?;
        let name: &str = sym.name().ok()?;
        return Some(name.strip_prefix('_').unwrap_or(name).to_owned());
    }
    None
}

fn locate_callee(object: &[u8], caller: &str, target: u64) -> Option<(Vec<u8>, u64, String)> {
    function_code_at(object, target).or_else(|| {
        let resolved: String = call_callee_for_target(object, caller, target)?;
        let (code, base): (Vec<u8>, u64) = function_code(object, &resolved)?;
        Some((code, base, resolved))
    })
}

fn resolve_recovered_calls(
    object: &[u8],
    caller: &str,
    targets: &[u64],
    program: &WholeProgram,
    abi: PseudoAbi,
) -> Option<Vec<ResolvedCall>> {
    let mut out: Vec<ResolvedCall> = Vec::new();
    let mut seen: Vec<u64> = Vec::new();
    for &target in targets {
        if seen.contains(&target) {
            continue;
        }
        seen.push(target);
        let (code, base, name): (Vec<u8>, u64, String) = locate_callee(object, caller, target)?;
        if !program.functions.contains(&name.as_str()) {
            eprintln!(
                "sound-reject {}: {caller} calls unlisted callee {name}",
                program.name
            );
            return None;
        }
        let arg_count: usize = resolved_int_arity_in_object(object, &code, base, abi)?;
        out.push(ResolvedCall {
            target,
            name: Some(format!("rec_{name}")),
            arg_count,
        });
    }
    Some(out)
}

struct RecoveredProgram {
    module: String,
    entry_params: usize,
    entry_return_width: u32,
    used_frame: bool,
}

fn strip_extern_prefix(rust: &str) -> &str {
    rust.find("#[allow(unused_mut")
        .map_or(rust, |pos: usize| &rust[pos..])
}

fn recover_program(
    object: &[u8],
    program: &WholeProgram,
    abi: PseudoAbi,
) -> Option<RecoveredProgram> {
    let mut module: String = String::new();
    let mut entry_params: usize = 0;
    let mut entry_return_width: u32 = 64;
    let mut used_frame: bool = false;
    for &fname in program.functions {
        let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(object, fname) else {
            eprintln!("skip {}: {fname} symbol not located", program.name);
            return None;
        };
        let probe: LeafRecovery =
            match recover_leaf_function_in_object(object, &code, base, abi, &[]) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("sound-reject {}: {fname} not in class ({e})", program.name);
                    return None;
                }
            };
        let resolved: Vec<ResolvedCall> =
            resolve_recovered_calls(object, fname, &probe.call_targets, program, abi)?;
        let rec: LeafRecovery =
            match recover_leaf_function_in_object(object, &code, base, abi, &resolved) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!(
                        "sound-reject {}: {fname} not in call class ({e})",
                        program.name
                    );
                    return None;
                }
            };
        let Some(rust): Option<String> = rec.rust_source else {
            eprintln!(
                "sound-reject {}: {fname} not pure-safe rust-emittable (sret/block-op)",
                program.name
            );
            return None;
        };
        let body: &str = strip_extern_prefix(&rust);
        used_frame |= body.contains("stack_frame");
        let def: String = body.replacen("pub fn recovered(", &format!("pub fn rec_{fname}("), 1);
        module.push_str(&def);
        module.push('\n');
        if fname == program.entry {
            entry_params = rec.params.len();
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
        module,
        entry_params,
        entry_return_width,
        used_frame,
    })
}

fn mask_c(bits: u32) -> String {
    if bits >= 64 {
        "0xFFFFFFFFFFFFFFFFULL".to_owned()
    } else {
        format!("0x{:x}ULL", (1u128 << bits) - 1)
    }
}

fn mask_rs(bits: u32) -> String {
    if bits >= 64 {
        "0xFFFFFFFFFFFFFFFFu64".to_owned()
    } else {
        format!("0x{:x}u64", (1u128 << bits) - 1)
    }
}

const fn inputs_for(program: &WholeProgram) -> &'static [[i64; 3]] {
    if program.loopy {
        SMALL_INPUTS
    } else {
        WIDE_INPUTS
    }
}

fn build_c_ground(program: &WholeProgram, recovered: &RecoveredProgram) -> String {
    let inputs: &[[i64; 3]] = inputs_for(program);
    let mut arr: String = String::new();
    for row in inputs {
        let _ = write!(arr, "{{{},{},{}}},", row[0], row[1], row[2]);
    }
    let orig_args: String = (0..program.entry_arity)
        .map(|i: usize| format!("in[{i}]"))
        .collect::<Vec<String>>()
        .join(", ");
    let mask: String = mask_c(recovered.entry_return_width);
    let entry: &str = program.entry;
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n{src}\n\
         int main(void) {{\n\
         \x20   long long inputs[][3] = {{ {arr} }};\n\
         \x20   size_t n = sizeof(inputs)/sizeof(inputs[0]);\n\
         \x20   for (size_t k = 0; k < n; k++) {{\n\
         \x20       long long in[3] = {{ inputs[k][0], inputs[k][1], inputs[k][2] }};\n\
         \x20       (void)in;\n\
         \x20       printf(\"%llu\\n\", (unsigned long long){entry}({orig_args}) & {mask});\n\
         \x20   }}\n\
         \x20   return 0;\n\
         }}\n",
        src = program.c_source,
    )
}

fn build_rust_program(program: &WholeProgram, recovered: &RecoveredProgram) -> String {
    let inputs: &[[i64; 3]] = inputs_for(program);
    let mut arr: String = String::new();
    for row in inputs {
        let _ = write!(arr, "[{},{},{}],", row[0], row[1], row[2]);
    }
    let rec_args: String = (0..recovered.entry_params)
        .map(|i: usize| format!("row[{i}] as u64"))
        .collect::<Vec<String>>()
        .join(", ");
    let mask: String = mask_rs(recovered.entry_return_width);
    let entry: &str = program.entry;
    format!(
        "#![allow(unused, unused_parens, dead_code, non_snake_case, non_upper_case_globals)]\n\
         {module}\n\
         fn main() {{\n\
         \x20   let inputs: [[i64; 3]; {n}] = [{arr}];\n\
         \x20   for k in 0..inputs.len() {{\n\
         \x20       let row: [i64; 3] = inputs[k];\n\
         \x20       let _ = row;\n\
         \x20       println!(\"{{}}\", rec_{entry}({rec_args}) & {mask});\n\
         \x20   }}\n\
         }}\n",
        module = recovered.module,
        n = inputs.len(),
    )
}

enum BoundedRun {
    Exited(std::process::Output),
    TimedOut,
}

fn run_bounded(exe: &Path, secs: u64) -> BoundedRun {
    use std::process::Stdio;
    use wait_timeout::ChildExt as _;

    let mut child: std::process::Child = Command::new(exe)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bounded harness");
    let finished: bool = child
        .wait_timeout(std::time::Duration::from_secs(secs))
        .expect("wait_timeout")
        .is_some();
    if finished {
        BoundedRun::Exited(child.wait_with_output().expect("collect harness output"))
    } else {
        let _ = child.kill();
        let _ = child.wait();
        BoundedRun::TimedOut
    }
}

fn parse_values(stdout: &str) -> Vec<u64> {
    stdout
        .lines()
        .filter_map(|l: &str| l.trim().parse::<u64>().ok())
        .collect()
}

fn compile_object_opt(
    compiler: &str,
    opt: &str,
    extra: &[&str],
    source: &str,
    out: &Path,
) -> Option<Vec<u8>> {
    let dir: PathBuf = scratch_dir();
    let src: PathBuf = dir.join(format!(
        "{}.c",
        out.file_stem().and_then(|s| s.to_str()).unwrap_or("unit")
    ));
    std::fs::write(&src, source.as_bytes()).expect("write source");
    let compiled: std::process::Output = Command::new(compiler)
        .arg(opt)
        .args(extra)
        .arg("-o")
        .arg(out)
        .arg(&src)
        .output()
        .expect("invoke compiler");
    if !compiled.status.success() {
        eprintln!(
            "compile with {compiler} failed: {}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        return None;
    }
    std::fs::read(out).ok()
}

fn c_ground_values(
    host_cc: &str,
    program: &WholeProgram,
    opt: &str,
    recovered: &RecoveredProgram,
    dir: &Path,
    tag: &str,
) -> Option<Vec<u64>> {
    let driver: String = build_c_ground(program, recovered);
    let driver_c: PathBuf = dir.join(format!("{tag}_ground.c"));
    std::fs::write(&driver_c, driver.as_bytes()).expect("write ground c");
    let exe: PathBuf = dir.join(if cfg!(windows) {
        format!("{tag}_ground.exe")
    } else {
        format!("{tag}_ground")
    });
    let link: std::process::Output = Command::new(host_cc)
        .args([opt, "-fno-stack-protector", "-o"])
        .arg(&exe)
        .arg(&driver_c)
        .output()
        .expect("invoke c ground compiler");
    if !link.status.success() {
        eprintln!(
            "{tag} c ground compile failed: {}",
            String::from_utf8_lossy(&link.stderr)
        );
        return None;
    }
    let watchdog: u64 = if program.loopy { 30 } else { 10 };
    match run_bounded(&exe, watchdog) {
        BoundedRun::Exited(out) if out.status.success() => {
            Some(parse_values(&String::from_utf8_lossy(&out.stdout)))
        }
        BoundedRun::Exited(_) => None,
        BoundedRun::TimedOut => panic!("{tag} c ground truth did not terminate within watchdog"),
    }
}

fn rust_recovered_values(
    rustc_bin: &str,
    program: &WholeProgram,
    recovered: &RecoveredProgram,
    dir: &Path,
    tag: &str,
) -> Vec<u64> {
    let src: String = build_rust_program(program, recovered);
    let src_path: PathBuf = dir.join(format!("{tag}_recovered.rs"));
    std::fs::write(&src_path, src.as_bytes()).expect("write recovered rust");
    let exe: PathBuf = dir.join(if cfg!(windows) {
        format!("{tag}_recovered.exe")
    } else {
        format!("{tag}_recovered")
    });
    let build: std::process::Output = Command::new(rustc_bin)
        .args(["--edition", "2021", "-C", "overflow-checks=on", "-o"])
        .arg(&exe)
        .arg(&src_path)
        .output()
        .expect("invoke rustc for recovered whole program");
    assert!(
        build.status.success(),
        "{tag} recovered rust compile failed: {}\n--- recovered.rs ---\n{src}",
        String::from_utf8_lossy(&build.stderr)
    );
    let watchdog: u64 = if program.loopy { 30 } else { 10 };
    match run_bounded(&exe, watchdog) {
        BoundedRun::Exited(out) => {
            assert!(
                out.status.success(),
                "{tag} recovered rust run failed (overflow-checks caught a non-wrapping op or a poison divide): {}",
                String::from_utf8_lossy(&out.stderr)
            );
            parse_values(&String::from_utf8_lossy(&out.stdout))
        }
        BoundedRun::TimedOut => panic!(
            "{tag} recovered rust did not terminate within watchdog; a recovered loop is non-terminating"
        ),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Equivalent,
    Mismatch,
    SoundRejected,
    Skipped,
}

const OPT_LEVELS: [&str; 3] = ["-O0", "-O1", "-O2"];

fn opt_tag(opt: &str) -> &str {
    opt.trim_start_matches('-')
}

struct Env {
    host_cc: String,
    rustc_bin: String,
}

fn measure(
    env: &Env,
    object: &[u8],
    program: &WholeProgram,
    abi: PseudoAbi,
    opt: &str,
    dir: &Path,
    tag: &str,
    frame_seen: &mut bool,
) -> Outcome {
    let Some(recovered): Option<RecoveredProgram> = recover_program(object, program, abi) else {
        return Outcome::SoundRejected;
    };
    *frame_seen |= recovered.used_frame;
    let Some(golden): Option<Vec<u64>> =
        c_ground_values(&env.host_cc, program, opt, &recovered, dir, tag)
    else {
        return Outcome::Skipped;
    };
    let got: Vec<u64> = rust_recovered_values(&env.rustc_bin, program, &recovered, dir, tag);
    if golden.is_empty() || golden.len() != got.len() {
        eprintln!(
            "MISMATCH {tag}: result count c={} rust={}",
            golden.len(),
            got.len()
        );
        return Outcome::Mismatch;
    }
    if golden == got {
        Outcome::Equivalent
    } else {
        eprintln!("MISMATCH {tag}: c={golden:?} rust={got:?}");
        Outcome::Mismatch
    }
}

#[test]
fn whole_programs_recompile_to_rust_equivalence_hostabi() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native rust whole-program oracle on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; the sysv class is the cross-platform x86-64 guard"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!("skipping host rust whole-program oracle: gcc not on PATH");
        return;
    };
    let Some(rustc_bin): Option<String> = rustc() else {
        eprintln!("skipping host rust whole-program oracle: rustc not on PATH");
        return;
    };
    let env: Env = Env {
        host_cc: builder.clone(),
        rustc_bin,
    };
    let dir: PathBuf = scratch_dir();
    let battery: Vec<&WholeProgram> = full_battery();
    let mut total_equivalent: usize = 0;
    let mut total_slots: usize = 0;
    let mut mismatches: Vec<String> = Vec::new();
    let mut chain_recovered: bool = false;
    let mut frame_seen: bool = false;

    for opt in OPT_LEVELS {
        let mut equivalent: usize = 0;
        let mut rejected: Vec<&str> = Vec::new();
        let mut skipped: usize = 0;
        for program in &battery {
            let obj_path: PathBuf = dir.join(format!("{}_{}_host.o", program.name, opt_tag(opt)));
            let Some(object): Option<Vec<u8>> =
                compile_object_opt(&builder, opt, &CC_FLAGS, program.c_source, &obj_path)
            else {
                skipped += 1;
                continue;
            };
            let tag: String = format!("{}_{}_host", program.name, opt_tag(opt));
            match measure(
                &env,
                &object,
                program,
                HOST_ABI,
                opt,
                &dir,
                &tag,
                &mut frame_seen,
            ) {
                Outcome::Equivalent => {
                    equivalent += 1;
                    chain_recovered |= program.name == "wp_chain";
                }
                Outcome::Mismatch => mismatches.push(format!("{} {opt}", program.name)),
                Outcome::SoundRejected => rejected.push(program.name),
                Outcome::Skipped => skipped += 1,
            }
        }
        let graded: usize = battery.len() - skipped;
        total_equivalent += equivalent;
        total_slots += graded;
        println!(
            "host rust whole-program {opt}: {equivalent}/{graded} behaviorally equivalent ({} sound-rejected: {rejected:?}, {skipped} env-skipped)",
            rejected.len()
        );
    }

    assert!(
        mismatches.is_empty(),
        "host rust whole-program battery has UNSOUND recoveries (recovered but behaviorally wrong): {mismatches:?}"
    );
    assert!(
        chain_recovered,
        "the three-deep nested-call chain wp_chain must recover its entry end-to-end into equivalent rust"
    );
    assert!(
        frame_seen,
        "no recovered rust program carried a stack_frame: the O0 frame/memory rust path was never graded (teeth missing)"
    );
    assert!(
        total_equivalent >= 44,
        "host rust whole-program battery regressed below the measured floor: {total_equivalent}/{total_slots} equivalent across {} opt levels",
        OPT_LEVELS.len()
    );
    println!(
        "host rust whole-program oracle TOTAL: {total_equivalent}/{total_slots} equivalent across {} opt levels x {} programs",
        OPT_LEVELS.len(),
        battery.len()
    );
}

#[test]
fn whole_programs_recompile_to_rust_equivalence_sysv() {
    let Some(host_cc): Option<String> = cc() else {
        eprintln!("skipping sysv rust whole-program oracle: no host C compiler on PATH");
        return;
    };
    let Some(clang_cc): Option<String> = clang() else {
        eprintln!(
            "skipping sysv rust whole-program oracle: clang (needed for the SysV object) not on PATH"
        );
        return;
    };
    let Some(rustc_bin): Option<String> = rustc() else {
        eprintln!("skipping sysv rust whole-program oracle: rustc not on PATH");
        return;
    };
    let env: Env = Env {
        host_cc,
        rustc_bin,
    };
    let dir: PathBuf = scratch_dir();
    let battery: Vec<&WholeProgram> = full_battery();
    let sysv_flags: [&str; 5] = [
        "--target=x86_64-unknown-linux-gnu",
        "-fno-stack-protector",
        "-fno-optimize-sibling-calls",
        "-fcf-protection=none",
        "-c",
    ];
    let mut total_equivalent: usize = 0;
    let mut total_slots: usize = 0;
    let mut mismatches: Vec<String> = Vec::new();
    let mut chain_recovered: bool = false;
    let mut frame_seen: bool = false;

    for opt in OPT_LEVELS {
        let mut equivalent: usize = 0;
        let mut rejected: Vec<&str> = Vec::new();
        let mut skipped: usize = 0;
        for program in &battery {
            let obj_path: PathBuf = dir.join(format!("{}_{}_sysv.o", program.name, opt_tag(opt)));
            let Some(object): Option<Vec<u8>> =
                compile_object_opt(&clang_cc, opt, &sysv_flags, program.c_source, &obj_path)
            else {
                skipped += 1;
                continue;
            };
            let tag: String = format!("{}_{}_sysv", program.name, opt_tag(opt));
            match measure(
                &env,
                &object,
                program,
                PseudoAbi::SysV,
                opt,
                &dir,
                &tag,
                &mut frame_seen,
            ) {
                Outcome::Equivalent => {
                    equivalent += 1;
                    chain_recovered |= program.name == "wp_chain";
                }
                Outcome::Mismatch => mismatches.push(format!("{} {opt}", program.name)),
                Outcome::SoundRejected => rejected.push(program.name),
                Outcome::Skipped => skipped += 1,
            }
        }
        let graded: usize = battery.len() - skipped;
        total_equivalent += equivalent;
        total_slots += graded;
        println!(
            "sysv rust whole-program {opt}: {equivalent}/{graded} behaviorally equivalent ({} sound-rejected: {rejected:?}, {skipped} env-skipped)",
            rejected.len()
        );
    }

    assert!(
        mismatches.is_empty(),
        "sysv rust whole-program battery has UNSOUND recoveries (recovered but behaviorally wrong): {mismatches:?}"
    );
    assert!(
        chain_recovered,
        "the three-deep nested-call chain wp_chain must recover its entry end-to-end into equivalent rust on sysv"
    );
    assert!(
        frame_seen,
        "no recovered rust program carried a stack_frame: the O0 frame/memory rust path was never graded (teeth missing)"
    );
    assert!(
        total_equivalent >= 47,
        "sysv rust whole-program battery regressed below the measured floor: {total_equivalent}/{total_slots} equivalent across {} opt levels",
        OPT_LEVELS.len()
    );
    println!(
        "sysv rust whole-program oracle TOTAL: {total_equivalent}/{total_slots} equivalent across {} opt levels x {} programs",
        OPT_LEVELS.len(),
        battery.len()
    );
}
