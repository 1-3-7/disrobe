#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_native::{
    LeafRecovery, PseudoAbi, ResolvedCall, recover_leaf_function_abi,
    recover_leaf_function_with_calls, resolved_int_arity_in_object,
};
use object::{Object as _, ObjectSection as _, ObjectSymbol as _};

const HOST_ABI: PseudoAbi = if cfg!(windows) {
    PseudoAbi::MsX64
} else {
    PseudoAbi::SysV
};

const WIDE_INPUTS: &str = "{0,0,0},{1,1,1},{-1,-1,-1},{7,3,5},{-7,3,-5},\
     {123456,-654321,99},{2147483647,1,2},{-2147483648,-1,-2},\
     {0x7fffffffffffffffLL,2,3},{100,200,300},{-100,50,-25},\
     {1<<20,1<<10,1<<5},{42,42,42},{0xdeadbeef,0xcafef00d,0x1234}";

const SMALL_INPUTS: &str = "{0,0,0},{1,2,3},{5,1,1},{10,4,2},{-3,7,1},{20,5,3},\
     {0,10,10},{63,2,1},{7,7,7},{-1,-1,-1},{16,8,4},{2,50,25},{40,3,9},{9,40,4}";

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

fn scratch_dir() -> PathBuf {
    let dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe-pseudo-wp-{}", std::process::id()));
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

fn rename_recovered(source: &str, new_name: &str) -> String {
    source
        .replacen("uint64_t recovered(", &format!("uint64_t {new_name}("), 1)
        .lines()
        .filter(|l: &&str| !l.starts_with("#include"))
        .collect::<Vec<&str>>()
        .join("\n")
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

fn compile_object(compiler: &str, extra: &[&str], source: &str, out: &Path) -> Option<Vec<u8>> {
    let dir: PathBuf = scratch_dir();
    let src: PathBuf = dir.join(format!(
        "{}.c",
        out.file_stem().and_then(|s| s.to_str()).unwrap_or("unit")
    ));
    std::fs::write(&src, source.as_bytes()).expect("write source");
    let compiled: std::process::Output = Command::new(compiler)
        .arg("-O1")
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

struct RecoveredProgram {
    tu: String,
    entry_params: usize,
    entry_return_width: u32,
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
        let (code, base, name): (Vec<u8>, u64, String) =
            function_code_at(object, target).or_else(|| {
                let resolved: String = call_callee_for_target(object, caller, target)?;
                let (code, base): (Vec<u8>, u64) = function_code(object, &resolved)?;
                Some((code, base, resolved))
            })?;
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

fn recover_program(
    object: &[u8],
    program: &WholeProgram,
    abi: PseudoAbi,
) -> Option<RecoveredProgram> {
    let mut tu: String = String::new();
    let mut entry_params: usize = 0;
    let mut entry_return_width: u32 = 64;
    for &fname in program.functions {
        let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(object, fname) else {
            eprintln!("skip {}: {fname} symbol not located", program.name);
            return None;
        };
        let probe: LeafRecovery = match recover_leaf_function_abi(&code, base, abi) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("sound-reject {}: {fname} not in class ({e})", program.name);
                return None;
            }
        };
        let resolved: Vec<ResolvedCall> =
            resolve_recovered_calls(object, fname, &probe.call_targets, program, abi)?;
        let rec: LeafRecovery = match recover_leaf_function_with_calls(&code, base, abi, &resolved)
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "sound-reject {}: {fname} not in call class ({e})",
                    program.name
                );
                return None;
            }
        };
        tu.push_str(&rename_recovered(&rec.source, &format!("rec_{fname}")));
        tu.push('\n');
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
    let return_mask: String = if recovered.entry_return_width >= 64 {
        "0xFFFFFFFFFFFFFFFFULL".to_owned()
    } else {
        format!("0x{:x}ULL", (1u128 << recovered.entry_return_width) - 1)
    };
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

fn link_and_run(
    compiler: &str,
    driver: &str,
    link_object: &[u8],
    tag: &str,
    secs: u64,
) -> Option<String> {
    let dir: PathBuf = scratch_dir();
    let obj: PathBuf = dir.join(format!("{tag}_link.o"));
    std::fs::write(&obj, link_object).ok()?;
    let driver_c: PathBuf = dir.join(format!("{tag}_driver.c"));
    std::fs::write(&driver_c, driver.as_bytes()).expect("write driver");
    let exe: PathBuf = dir.join(if cfg!(windows) {
        format!("{tag}.exe")
    } else {
        tag.to_owned()
    });
    let link: std::process::Output = Command::new(compiler)
        .args(["-O1", "-o"])
        .arg(&exe)
        .arg(&driver_c)
        .arg(&obj)
        .output()
        .expect("invoke linker");
    assert!(
        link.status.success(),
        "{tag} link failed: {}\n--- {tag} driver ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );
    match run_bounded(&exe, secs) {
        BoundedRun::Exited(out) => Some(String::from_utf8_lossy(&out.stdout).into_owned()),
        BoundedRun::TimedOut => {
            panic!(
                "{tag} harness did not terminate within the watchdog; a recovered loop is non-terminating"
            )
        }
    }
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
    let dir: PathBuf = scratch_dir();
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
        let stdout: String = link_and_run(&builder, &driver, &object, program.name, watchdog)
            .expect("link and run host whole-program harness");
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
    let dir: PathBuf = scratch_dir();
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
fn whole_programs_recompile_to_behavioral_equivalence_sysv() {
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
        let stdout: String = link_and_run(&host_cc, &driver, &host_obj, &tag, watchdog)
            .expect("link and run sysv whole-program harness");
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
    )
    .expect("run teeth baseline");
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
    let stdout: String = link_and_run(&host_cc, &driver, &host_obj, "teeth_sq_drop", 10)
        .expect("run neutralized teeth harness");
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
    let stdout: String = link_and_run(&host_cc, &driver, &host_obj, "teeth_sub_swap", 10)
        .expect("run arg-swapped teeth harness");
    assert!(
        stdout.contains("MISMATCH") && !stdout.contains("OK"),
        "teeth FAILED: swapping the subtraction operands must diverge from the original: {stdout}"
    );
    println!("teeth confirmed: swapping a call argument diverges (MISMATCH observed)");
}
