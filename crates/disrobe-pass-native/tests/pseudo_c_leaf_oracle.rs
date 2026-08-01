#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::Command;

use std::collections::BTreeSet;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_native::pseudo_c::fp_semantics;
use disrobe_pass_native::{
    Arch, DisasmInsn, FpConstant, JumpTable, LeafRecovery, PseudoAbi,
    PseudoScalarType as ScalarType, ResolvedCall, callee_int_arity, disassemble,
    recover_leaf_function_abi, recover_leaf_function_const_abi, recover_leaf_function_in_object,
    recover_leaf_function_switch_abi, recover_leaf_function_switch_const_abi,
    recover_leaf_function_with_calls,
};
use object::{Object as _, ObjectSection as _, ObjectSymbol as _};

const HOST_ABI: PseudoAbi = if cfg!(windows) {
    PseudoAbi::MsX64
} else {
    PseudoAbi::SysV
};

struct Case {
    name: &'static str,
    arity: usize,
    c_source: &'static str,
}

const BATTERY: &[Case] = &[
    Case {
        name: "f_add",
        arity: 2,
        c_source: "long long f_add(long long a, long long b){ return a + b; }",
    },
    Case {
        name: "f_sub",
        arity: 2,
        c_source: "long long f_sub(long long a, long long b){ return a - b; }",
    },
    Case {
        name: "f_mix",
        arity: 2,
        c_source: "int f_mix(int a, int b){ return (a + b) * 3 - (a ^ b); }",
    },
    Case {
        name: "f_andor",
        arity: 3,
        c_source: "long long f_andor(long long a, long long b, long long c){ return (a & b) | (c & ~a); }",
    },
    Case {
        name: "f_shifts",
        arity: 1,
        c_source: "unsigned f_shifts(unsigned a){ return (a >> 2) | (a << 3); }",
    },
    Case {
        name: "f_mac",
        arity: 3,
        c_source: "long long f_mac(long long a, long long b, long long c){ return a * b + c; }",
    },
    Case {
        name: "f_neg",
        arity: 1,
        c_source: "long long f_neg(long long a){ return -a; }",
    },
    Case {
        name: "f_poly",
        arity: 2,
        c_source: "int f_poly(int a, int b){ return a * a + 2 * a * b + b * b; }",
    },
    Case {
        name: "f_abs",
        arity: 1,
        c_source: "long long f_abs(long long a){ return a < 0 ? -a : a; }",
    },
    Case {
        name: "f_max",
        arity: 2,
        c_source: "long long f_max(long long a, long long b){ return a > b ? a : b; }",
    },
    Case {
        name: "f_clamp",
        arity: 3,
        c_source: "long long f_clamp(long long a, long long lo, long long hi){ long long r = a; if (r < lo) r = lo; if (r > hi) r = hi; return r; }",
    },
    Case {
        name: "f_sign",
        arity: 1,
        c_source: "long long f_sign(long long a){ if (a > 0) return 1; if (a < 0) return -1; return 0; }",
    },
    Case {
        name: "f_cacc",
        arity: 2,
        c_source: "long long f_cacc(long long a, long long b){ return a > b ? a + b : a - b; }",
    },
    Case {
        name: "f_max32",
        arity: 2,
        c_source: "int f_max32(int a, int b){ return a > b ? a : b; }",
    },
    Case {
        name: "f_prec_shladd",
        arity: 2,
        c_source: "int f_prec_shladd(int a, int b){ return (a + b) << 2; }",
    },
    Case {
        name: "f_prec_addshl",
        arity: 2,
        c_source: "int f_prec_addshl(int a, int b){ return a + (b << 2); }",
    },
    Case {
        name: "f_prec_sub3",
        arity: 3,
        c_source: "long long f_prec_sub3(long long a, long long b, long long c){ return a - b - c; }",
    },
    Case {
        name: "f_prec_orand",
        arity: 3,
        c_source: "long long f_prec_orand(long long a, long long b, long long c){ return (a | b) & c; }",
    },
    Case {
        name: "f_prec_negadd",
        arity: 2,
        c_source: "long long f_prec_negadd(long long a, long long b){ return -(a + b); }",
    },
    Case {
        name: "f_prec_notadd",
        arity: 2,
        c_source: "long long f_prec_notadd(long long a, long long b){ return ~(a + b); }",
    },
    Case {
        name: "f_prec_submul",
        arity: 3,
        c_source: "long long f_prec_submul(long long a, long long b, long long c){ return (a - b) * c; }",
    },
    Case {
        name: "f_prec_nesttern",
        arity: 3,
        c_source: "long long f_prec_nesttern(long long a, long long b, long long c){ return a > b ? a : (b > c ? b : c); }",
    },
];

fn cc() -> Option<String> {
    for c in ["gcc", "clang", "cc"] {
        if Command::new(c)
            .arg("--version")
            .output()
            .is_ok_and(|o: std::process::Output| o.status.success())
        {
            return Some(c.to_owned());
        }
    }
    None
}

fn sysv_host_can_run() -> bool {
    if cfg!(target_os = "macos") {
        eprintln!(
            "skipping x86-64 sysv recompile-differential on macos: the host gcc is an apple-clang alias that rejects the gcc-only codegen flags, and arm64 cannot execute an x86-64 sysv battery; ubuntu carries the cross-platform sysv floor"
        );
        return false;
    }
    true
}

fn scratch_dir() -> ScratchDir {
    ScratchDir::create("disrobe-pseudo-c").expect("create scratch directory")
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

struct Lifted {
    decls: String,
    driver_snippet: String,
}

fn process_case(case: &Case, object_bytes: &[u8], abi: PseudoAbi) -> Option<Lifted> {
    let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(object_bytes, case.name) else {
        eprintln!("skip {}: symbol not located", case.name);
        return None;
    };
    let recovery: LeafRecovery = match recover_leaf_function_abi(&code, base, abi) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("skip {} ({abi:?}): not in leaf class ({e})", case.name);
            return None;
        }
    };
    let recovered_name: String = format!("rec_{}", case.name);
    let renamed: String = recovery
        .source
        .replacen(
            "uint64_t recovered(",
            &format!("uint64_t {recovered_name}("),
            1,
        )
        .lines()
        .filter(|l: &&str| !l.starts_with("#include"))
        .collect::<Vec<&str>>()
        .join("\n");
    let mut decls: String = String::new();
    decls.push_str(&renamed);
    decls.push('\n');
    let original_decl: String = format!(
        "extern long long {}({});\n",
        case.name,
        vec!["long long"; case.arity].join(", ")
    );
    decls.push_str(&original_decl);

    let return_mask: String = if recovery.return_width_bits == 64 {
        "0xFFFFFFFFFFFFFFFFULL".to_owned()
    } else {
        format!("0x{:x}ULL", (1u128 << recovery.return_width_bits) - 1)
    };
    let args: Vec<String> = (0..case.arity).map(|i: usize| format!("in[{i}]")).collect();
    let rec_args: Vec<String> = (0..recovery.params.len())
        .map(|i: usize| format!("(uint64_t)in[{i}]"))
        .collect();

    let mut driver_snippet: String = String::new();
    let _ = write!(
        driver_snippet,
        "    for (size_t k = 0; k < n_inputs; k++) {{\n\
         \x20       long long in[3] = {{ inputs[k][0], inputs[k][1], inputs[k][2] }};\n\
         \x20       unsigned long long want = (unsigned long long){}({}) & {return_mask};\n\
         \x20       unsigned long long got = {recovered_name}({}) & {return_mask};\n\
         \x20       if (want != got) {{ printf(\"MISMATCH {} in=%lld,%lld,%lld want=%llu got=%llu\\n\", in[0], in[1], in[2], want, got); return 1; }}\n\
         \x20   }}\n",
        case.name,
        args.join(", "),
        rec_args.join(", "),
        case.name,
    );
    Some(Lifted {
        decls,
        driver_snippet,
    })
}

fn build_driver(recovered_decls: &str, driver_body: &str) -> String {
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n{recovered_decls}\n\
         int main(void) {{\n\
         \x20   long long inputs[][3] = {{\n\
         \x20       {{0,0,0}},{{1,1,1}},{{-1,-1,-1}},{{7,3,5}},{{-7,3,-5}},\n\
         \x20       {{123456,-654321,99}},{{2147483647,1,2}},{{-2147483648,-1,-2}},\n\
         \x20       {{0x7fffffffffffffffLL,2,3}},{{100,200,300}},{{-100,50,-25}},\n\
         \x20       {{1<<20,1<<10,1<<5}},{{42,42,42}},{{0xdeadbeef,0xcafef00d,0x1234}}\n\
         \x20   }};\n\
         \x20   size_t n_inputs = sizeof(inputs)/sizeof(inputs[0]);\n\
         {driver_body}\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n"
    )
}

#[test]
fn leaf_functions_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(compiler): Option<String> = cc() else {
        eprintln!("skipping: no C compiler (gcc/clang/cc) on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let mut battery_src: String = String::new();
    for case in BATTERY {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let battery_c: PathBuf = dir.join("battery.c");
    std::fs::write(&battery_c, battery_src.as_bytes()).expect("write battery.c");
    let battery_o: PathBuf = dir.join("battery.o");
    let compile_battery: std::process::Output = Command::new(&compiler)
        .args(["-O1", "-fno-stack-protector", "-c", "-o"])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke cc for battery");
    assert!(
        compile_battery.status.success(),
        "battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read battery.o");

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;

    for case in BATTERY {
        let outcome: Option<Lifted> = process_case(case, &object_bytes, HOST_ABI);
        if let Some(lifted) = outcome {
            recovered_decls.push_str(&lifted.decls);
            driver_body.push_str(&lifted.driver_snippet);
            lifted_count += 1;
        }
    }

    if lifted_count == 0 {
        eprintln!(
            "skipping leaf behavioral differential: this compiler build lowered none of the {} battery cases into the leaf class",
            BATTERY.len()
        );
        return;
    }

    let driver: String = build_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "harness.exe"
    } else {
        "harness"
    });
    let link: std::process::Output = Command::new(&compiler)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke cc to link harness");
    assert!(
        link.status.success(),
        "harness link failed: {}\n--- driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe).output().expect("run harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "behavioral differential FAILED ({lifted_count} cases): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!("behavioral differential PASSED for {lifted_count} leaf functions (MS x64 ABI)");
}

fn clang() -> Option<String> {
    if Command::new("clang")
        .arg("--version")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
    {
        Some("clang".to_owned())
    } else {
        None
    }
}

struct SysvCrossObjects {
    host_object: Vec<u8>,
    sysv_object: Vec<u8>,
}

fn compile_sysv_cross(tag: &str, battery_src: &str) -> Option<SysvCrossObjects> {
    let host_cc: String = cc()?;
    let clang_cc: String = clang()?;
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let battery_c: PathBuf = dir.join(format!("{tag}_sysv_battery.c"));
    std::fs::write(&battery_c, battery_src.as_bytes()).expect("write sysv battery");

    let host_o: PathBuf = dir.join(format!("{tag}_sysv_host.o"));
    let compile_host: std::process::Output = Command::new(&host_cc)
        .args(["-O1", "-fno-stack-protector", "-c", "-o"])
        .arg(&host_o)
        .arg(&battery_c)
        .output()
        .expect("invoke host cc for sysv ground-truth object");
    assert!(
        compile_host.status.success(),
        "{tag} sysv ground-truth compile failed: {}",
        String::from_utf8_lossy(&compile_host.stderr)
    );

    let sysv_o: PathBuf = dir.join(format!("{tag}_sysv_target.o"));
    let compile_sysv: std::process::Output = Command::new(&clang_cc)
        .args([
            "--target=x86_64-unknown-linux-gnu",
            "-O1",
            "-fno-stack-protector",
            "-fcf-protection=none",
            "-c",
            "-o",
        ])
        .arg(&sysv_o)
        .arg(&battery_c)
        .output()
        .expect("invoke clang for sysv target object");
    if !compile_sysv.status.success() {
        eprintln!(
            "skipping {tag} sysv: clang cannot emit a linux/SysV object on this host: {}",
            String::from_utf8_lossy(&compile_sysv.stderr)
        );
        return None;
    }

    Some(SysvCrossObjects {
        host_object: std::fs::read(&host_o).expect("read sysv host object"),
        sysv_object: std::fs::read(&sysv_o).expect("read sysv target object"),
    })
}

fn link_and_run_sysv(tag: &str, driver: &str, host_object: &[u8], watchdog_secs: u64) -> String {
    let host_cc: String = cc().expect("host cc present when linking sysv harness");
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let host_o: PathBuf = dir.join(format!("{tag}_sysv_link_host.o"));
    std::fs::write(&host_o, host_object).expect("write sysv host object for link");
    let driver_c: PathBuf = dir.join(format!("{tag}_sysv_driver.c"));
    std::fs::write(&driver_c, driver.as_bytes()).expect("write sysv driver");
    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        format!("{tag}_sysv_harness.exe")
    } else {
        format!("{tag}_sysv_harness")
    });
    let link: std::process::Output = Command::new(&host_cc)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&host_o)
        .arg("-lm")
        .output()
        .expect("invoke host cc to link sysv harness");
    assert!(
        link.status.success(),
        "{tag} sysv harness link failed: {}\n--- {tag} sysv driver ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );
    let BoundedRun::Exited(out): BoundedRun = run_bounded(&harness_exe, watchdog_secs) else {
        panic!(
            "{tag} sysv harness did not terminate within the watchdog window; a recovered loop is non-terminating"
        );
    };
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn sysv_leaf_functions_recompile_to_behavioral_equivalence() {
    if !sysv_host_can_run() {
        return;
    }
    let Some(host_cc): Option<String> = cc() else {
        eprintln!("skipping: no C compiler on PATH");
        return;
    };
    let Some(clang_cc): Option<String> = clang() else {
        eprintln!("skipping sysv: clang (needed for SysV cross object) not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let mut battery_src: String = String::new();
    for case in BATTERY {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let battery_c: PathBuf = dir.join("sysv_battery.c");
    std::fs::write(&battery_c, battery_src.as_bytes()).expect("write sysv_battery.c");

    let host_o: PathBuf = dir.join("sysv_host.o");
    let compile_host: std::process::Output = Command::new(&host_cc)
        .args(["-O1", "-fno-stack-protector", "-c", "-o"])
        .arg(&host_o)
        .arg(&battery_c)
        .output()
        .expect("invoke host cc for ground-truth object");
    assert!(
        compile_host.status.success(),
        "sysv ground-truth compile failed: {}",
        String::from_utf8_lossy(&compile_host.stderr)
    );

    let sysv_o: PathBuf = dir.join("sysv_target.o");
    let compile_sysv: std::process::Output = Command::new(&clang_cc)
        .args([
            "--target=x86_64-unknown-linux-gnu",
            "-O1",
            "-fno-stack-protector",
            "-fcf-protection=none",
            "-c",
            "-o",
        ])
        .arg(&sysv_o)
        .arg(&battery_c)
        .output()
        .expect("invoke clang for SysV target object");
    if !compile_sysv.status.success() {
        eprintln!(
            "skipping sysv: clang cannot emit linux/SysV object on this host: {}",
            String::from_utf8_lossy(&compile_sysv.stderr)
        );
        return;
    }

    let sysv_bytes: Vec<u8> = std::fs::read(&sysv_o).expect("read sysv object");

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    for case in BATTERY {
        let outcome: Option<Lifted> = process_case(case, &sysv_bytes, PseudoAbi::SysV);
        if let Some(lifted) = outcome {
            recovered_decls.push_str(&lifted.decls);
            driver_body.push_str(&lifted.driver_snippet);
            lifted_count += 1;
        }
    }

    assert!(
        lifted_count >= 13,
        "SysV leaf lifter must handle at least 13 of the {} cases, only lifted {lifted_count}",
        BATTERY.len()
    );

    let driver: String = build_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("sysv_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write sysv_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "sysv_harness.exe"
    } else {
        "sysv_harness"
    });
    let link: std::process::Output = Command::new(&host_cc)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&host_o)
        .output()
        .expect("invoke host cc to link sysv harness");
    assert!(
        link.status.success(),
        "sysv harness link failed: {}\n--- sysv_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run sysv harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "sysv behavioral differential FAILED ({lifted_count} cases): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!("behavioral differential PASSED for {lifted_count} leaf functions (SysV ABI)");
}

struct MemCase {
    name: &'static str,
    elem_ty: &'static str,
    n_elems: usize,
    n_scalars: usize,
    returns: bool,
    access_shape: ExpectedAggregateShape,
    c_source: &'static str,
}

#[derive(Clone, Copy)]
enum ExpectedAggregateShape {
    Struct,
    Array,
    NoAggregate,
}

const MEM_BATTERY: &[MemCase] = &[
    MemCase {
        name: "m_sum2",
        elem_ty: "long long",
        n_elems: 2,
        n_scalars: 0,
        returns: true,
        access_shape: ExpectedAggregateShape::Struct,
        c_source: "long long m_sum2(long long *p){ return p[0] + p[1]; }",
    },
    MemCase {
        name: "m_sum2i",
        elem_ty: "int",
        n_elems: 2,
        n_scalars: 0,
        returns: true,
        access_shape: ExpectedAggregateShape::Struct,
        c_source: "int m_sum2i(int *p){ return p[0] + p[1]; }",
    },
    MemCase {
        name: "m_diff",
        elem_ty: "long long",
        n_elems: 3,
        n_scalars: 0,
        returns: true,
        access_shape: ExpectedAggregateShape::Struct,
        c_source: "long long m_diff(long long *p){ return p[0] - p[2]; }",
    },
    MemCase {
        name: "m_index",
        elem_ty: "long long",
        n_elems: 6,
        n_scalars: 1,
        returns: true,
        access_shape: ExpectedAggregateShape::Array,
        c_source: "long long m_index(long long *p, long long i){ return p[i]; }",
    },
    MemCase {
        name: "m_swap",
        elem_ty: "long long",
        n_elems: 2,
        n_scalars: 0,
        returns: false,
        access_shape: ExpectedAggregateShape::Struct,
        c_source: "void m_swap(long long *p){ long long t = p[0]; p[0] = p[1]; p[1] = t; }",
    },
    MemCase {
        name: "m_acc",
        elem_ty: "long long",
        n_elems: 1,
        n_scalars: 1,
        returns: true,
        access_shape: ExpectedAggregateShape::NoAggregate,
        c_source: "long long m_acc(long long *p, long long v){ *p = *p + v; return *p; }",
    },
    MemCase {
        name: "m_store_idx",
        elem_ty: "long long",
        n_elems: 6,
        n_scalars: 2,
        returns: false,
        access_shape: ExpectedAggregateShape::Array,
        c_source: "void m_store_idx(long long *p, long long i, long long v){ p[i] = v; }",
    },
    MemCase {
        name: "m_mask32",
        elem_ty: "int",
        n_elems: 3,
        n_scalars: 0,
        returns: true,
        access_shape: ExpectedAggregateShape::Struct,
        c_source: "int m_mask32(int *p){ return (p[0] & p[1]) | p[2]; }",
    },
];

fn mem_original_decl(case: &MemCase) -> String {
    let ret_ty: &str = if case.returns { "long long" } else { "void" };
    let mut params: Vec<String> = vec![format!("{}*", case.elem_ty)];
    for _ in 0..case.n_scalars {
        params.push("long long".to_owned());
    }
    format!("extern {ret_ty} {}({});\n", case.name, params.join(", "))
}

fn mem_recovered_signature(recovery: &LeafRecovery, recovered_name: &str) -> String {
    recovery
        .source
        .replacen(" recovered(", &format!(" {recovered_name}("), 1)
        .lines()
        .filter(|l: &&str| !l.starts_with("#include"))
        .collect::<Vec<&str>>()
        .join("\n")
}

fn mem_driver_snippet(case: &MemCase, recovery: &LeafRecovery) -> Option<String> {
    let recovered_name: String = format!("rec_{}", case.name);
    let return_mask: String = if recovery.return_width_bits == 64 {
        "0xFFFFFFFFFFFFFFFFULL".to_owned()
    } else {
        format!("0x{:x}ULL", (1u128 << recovery.return_width_bits) - 1)
    };

    let mut scalar_args: Vec<String> = Vec::new();
    for s in 0..case.n_scalars {
        scalar_args.push(format!("scalars[{s}]"));
    }
    let orig_call_args: String = std::iter::once("orig".to_owned())
        .chain(scalar_args.iter().cloned())
        .collect::<Vec<String>>()
        .join(", ");

    let rec_arg_count: usize = recovery.params.len();
    if rec_arg_count == 0 || rec_arg_count > 1 + case.n_scalars {
        return None;
    }
    let mut rec_args: Vec<String> = vec!["(uint64_t)(uintptr_t)rec".to_owned()];
    for s in 0..(rec_arg_count - 1) {
        rec_args.push(format!("(uint64_t)scalars[{s}]"));
    }
    let rec_call_args: String = rec_args.join(", ");

    let elem_ty: &str = case.elem_ty;
    let n: usize = case.n_elems;
    let mut snippet: String = String::new();
    let _ = write!(
        snippet,
        "    for (size_t k = 0; k < n_seeds; k++) {{\n\
         \x20       {elem_ty} orig[{n}]; {elem_ty} rec[{n}];\n\
         \x20       for (size_t e = 0; e < {n}; e++) {{ orig[e] = ({elem_ty})(seeds[k] + (long long)e*7 - 3); rec[e] = orig[e]; }}\n\
         \x20       long long scalars[2] = {{ (long long)(seeds[k] % {n} < 0 ? -(seeds[k] % {n}) : seeds[k] % {n}), seeds[k] ^ 0x55 }};\n",
    );
    if case.returns {
        let _ = write!(
            snippet,
            "        unsigned long long want = (unsigned long long){}({orig_call_args}) & {return_mask};\n\
             \x20       unsigned long long got = {recovered_name}({rec_call_args}) & {return_mask};\n\
             \x20       if (want != got) {{ printf(\"MISMATCH {} ret seed=%lld want=%llu got=%llu\\n\", seeds[k], want, got); return 1; }}\n",
            case.name, case.name,
        );
    } else {
        let _ = write!(
            snippet,
            "        {}({orig_call_args});\n\
             \x20       {recovered_name}({rec_call_args});\n",
            case.name,
        );
    }
    let _ = write!(
        snippet,
        "        for (size_t e = 0; e < {n}; e++) {{ if (orig[e] != rec[e]) {{ printf(\"MISMATCH {} mem seed=%lld idx=%zu orig=%lld rec=%lld\\n\", seeds[k], e, (long long)orig[e], (long long)rec[e]); return 1; }} }}\n\
         \x20   }}\n",
        case.name,
    );
    Some(snippet)
}

fn build_mem_driver(recovered_decls: &str, driver_body: &str) -> String {
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n{recovered_decls}\n\
         int main(void) {{\n\
         \x20   long long seeds[] = {{ 0, 1, -1, 7, -7, 13, 100, -100, 255, 1024, -1024, 65535, 0x7fffffffLL, -2147483648LL, 0x12345678LL }};\n\
         \x20   size_t n_seeds = sizeof(seeds)/sizeof(seeds[0]);\n\
         {driver_body}\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n"
    )
}

#[test]
fn memory_access_leaf_functions_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(compiler): Option<String> = cc() else {
        eprintln!("skipping: no C compiler (gcc/clang/cc) on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let mut battery_src: String = String::new();
    for case in MEM_BATTERY {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let battery_c: PathBuf = dir.join("mem_battery.c");
    std::fs::write(&battery_c, battery_src.as_bytes()).expect("write mem_battery.c");
    let battery_o: PathBuf = dir.join("mem_battery.o");
    let compile_battery: std::process::Output = Command::new(&compiler)
        .args(["-O1", "-fno-stack-protector", "-c", "-o"])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke cc for mem battery");
    assert!(
        compile_battery.status.success(),
        "mem battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read mem_battery.o");

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;

    for case in MEM_BATTERY {
        let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(&object_bytes, case.name)
        else {
            eprintln!("skip {}: symbol not located", case.name);
            continue;
        };
        let recovery: LeafRecovery = match recover_leaf_function_abi(&code, base, HOST_ABI) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skip {}: not in leaf class ({e})", case.name);
                continue;
            }
        };
        match case.access_shape {
            ExpectedAggregateShape::Struct => {
                assert!(
                    recovery.source.contains("recovered_struct_0_t")
                        && recovery.source.contains("->field_"),
                    "{} must recover constant offsets as fields:\n{}",
                    case.name,
                    recovery.source
                );
            }
            ExpectedAggregateShape::Array => {
                assert!(
                    recovery.source.contains("recovered_array_0_t")
                        && recovery.source.contains("recovered_array_0["),
                    "{} must recover scaled indexing as an array:\n{}",
                    case.name,
                    recovery.source
                );
            }
            ExpectedAggregateShape::NoAggregate => {
                assert!(
                    !recovery.source.contains("recovered_struct_")
                        && !recovery.source.contains("recovered_array_"),
                    "{} has insufficient aggregate evidence:\n{}",
                    case.name,
                    recovery.source
                );
            }
        }
        let Some(snippet): Option<String> = mem_driver_snippet(case, &recovery) else {
            eprintln!("skip {}: arg mapping unsupported", case.name);
            continue;
        };
        let recovered_name: String = format!("rec_{}", case.name);
        recovered_decls.push_str(&mem_recovered_signature(&recovery, &recovered_name));
        recovered_decls.push('\n');
        recovered_decls.push_str(&mem_original_decl(case));
        driver_body.push_str(&snippet);
        lifted_count += 1;
    }

    if lifted_count == 0 {
        eprintln!(
            "skipping memory-access behavioral differential: this compiler build lowered none of the {} battery cases into the leaf class",
            MEM_BATTERY.len()
        );
        return;
    }

    let driver: String = build_mem_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("mem_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write mem_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "mem_harness.exe"
    } else {
        "mem_harness"
    });
    let link: std::process::Output = Command::new(&compiler)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke cc to link mem harness");
    assert!(
        link.status.success(),
        "mem harness link failed: {}\n--- mem_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run mem harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "memory-access behavioral differential FAILED ({lifted_count} cases): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "memory-access behavioral differential PASSED for {lifted_count} leaf functions (MS x64 ABI)"
    );
}

const AGGREGATE_SOURCE: &str = "\
typedef struct { unsigned long long first; unsigned second; unsigned short third; } AggregateFields;
typedef struct { long long left; long long right; } AggregateInner;
typedef struct { AggregateInner *inner; long long tail; } AggregateOuter;
typedef struct { long long *items; long long tail; } AggregateArrayOuter;
unsigned long long aggregate_fields(AggregateFields *p){ return p->first + p->second + p->third; }
long long aggregate_array(long long *p, long long i){ return p[i]; }
long long aggregate_nested(AggregateOuter *p){ return p->inner->left + p->inner->right + p->tail; }
long long aggregate_nested_array(AggregateArrayOuter *p, long long i){ return p->items[i] + p->tail; }
void aggregate_update(AggregateFields *p, unsigned long long delta){ p->first += delta; p->second ^= (unsigned)delta; }
";

const UNION_SOURCE: &str = "\
typedef unsigned long long UnionU64;
typedef unsigned UnionU32;
typedef union { UnionU64 wide; UnionU32 word; } UnionWideWord;
typedef union { UnionU32 word; float real; } UnionWordFloat;
typedef union { UnionU64 wide; struct { UnionU32 low; UnionU32 high; } parts; } UnionPartial;
UnionU64 union_wide_word(volatile UnionWideWord *p){ return p->wide + p->word; }
float union_word_float(volatile UnionWordFloat *p){ (void)p->word; return p->real; }
float union_word_float_store(volatile UnionWordFloat *p){ p->word = 0x3f800000U; p->real = p->real; return p->real; }
UnionU64 union_partial(volatile UnionPartial *p){ return p->wide + p->parts.high; }
";

fn union_driver(recovered: &str) -> String {
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n\
         typedef unsigned long long UnionU64;\n\
         typedef unsigned UnionU32;\n\
         typedef union {{ UnionU64 wide; UnionU32 word; }} UnionWideWord;\n\
         typedef union {{ UnionU32 word; float real; }} UnionWordFloat;\n\
         typedef union {{ UnionU64 wide; struct {{ UnionU32 low; UnionU32 high; }} parts; }} UnionPartial;\n\
         extern UnionU64 union_wide_word(volatile UnionWideWord *p);\n\
         extern float union_word_float(volatile UnionWordFloat *p);\n\
         extern float union_word_float_store(volatile UnionWordFloat *p);\n\
         extern UnionU64 union_partial(volatile UnionPartial *p);\n\
         {recovered}\n\
         int main(void) {{\n\
             UnionU64 wide_inputs[] = {{ 0ULL, 1ULL, 0x3f800000ULL, 0x41200000a5a5a5a5ULL, 0xffffffffffffffffULL }};\n\
             UnionU32 float_inputs[] = {{ 0U, 0x3f800000U, 0x41200000U, 0x4f000000U }};\n\
             for (size_t i = 0; i < sizeof(wide_inputs) / sizeof(wide_inputs[0]); i++) {{\n\
                 UnionWideWord wide = {{ .wide = wide_inputs[i] }};\n\
                 UnionPartial partial = {{ .wide = wide_inputs[i] }};\n\
                 UnionU64 want_wide = union_wide_word(&wide);\n\
                 UnionU64 got_wide = rec_union_wide_word((uint64_t)(uintptr_t)&wide);\n\
                 UnionU64 want_partial = union_partial(&partial);\n\
                 UnionU64 got_partial = rec_union_partial((uint64_t)(uintptr_t)&partial);\n\
                 if (want_wide != got_wide || want_partial != got_partial) return 1;\n\
             }}\n\
             for (size_t i = 0; i < sizeof(float_inputs) / sizeof(float_inputs[0]); i++) {{\n\
                 UnionWordFloat value = {{ .word = float_inputs[i] }};\n\
                 UnionWordFloat original_store = {{ .word = 0U }};\n\
                 UnionWordFloat recovered_store = {{ .word = 0U }};\n\
                 float want = union_word_float(&value);\n\
                 float got = rec_union_word_float((uint64_t)(uintptr_t)&value);\n\
                 float want_store = union_word_float_store(&original_store);\n\
                 float got_store = rec_union_word_float_store((uint64_t)(uintptr_t)&recovered_store);\n\
                 if (want != got || want_store != got_store || original_store.word != recovered_store.word) return 2;\n\
             }}\n\
             printf(\"OK\\n\");\n\
             return 0;\n\
         }}\n"
    )
}

fn union_rust_driver(recovered: &str) -> String {
    format!(
        "#![allow(unused, unused_parens, dead_code)]\n{recovered}\n\
         #[repr(C)]\nunion UnionWideWord {{ wide: u64, word: u32 }}\n\
         #[repr(C)]\nunion UnionWordFloat {{ word: u32, real: f32 }}\n\
         fn main() {{\n\
             let wide_inputs: [u64; 5] = [0, 1, 0x3f800000, 0x41200000a5a5a5a5, u64::MAX];\n\
             let float_inputs: [u32; 4] = [0, 0x3f800000, 0x41200000, 0x4f000000];\n\
             for bits in wide_inputs {{\n\
                 let mut value = UnionWideWord {{ wide: bits }};\n\
                 let want: u64 = bits.wrapping_add(bits as u32 as u64);\n\
                 let got: u64 = rec_union_wide_word((&mut value as *mut UnionWideWord) as usize as u64);\n\
                 assert_eq!(got, want);\n\
             }}\n\
             for bits in float_inputs {{\n\
                 let mut value = UnionWordFloat {{ word: bits }};\n\
                 let mut stored = UnionWordFloat {{ word: 0 }};\n\
                 let want: f32 = f32::from_bits(bits);\n\
                 let got: f32 = rec_union_word_float((&mut value as *mut UnionWordFloat) as usize as u64);\n\
                 assert_eq!(got.to_bits(), want.to_bits());\n\
                 let got_store: f32 = rec_union_word_float_store((&mut stored as *mut UnionWordFloat) as usize as u64);\n\
                 assert_eq!(got_store.to_bits(), 0x3f800000);\n\
                 assert_eq!(unsafe {{ stored.word }}, 0x3f800000);\n\
             }}\n\
         }}\n"
    )
}

fn aggregate_driver(recovered: &str) -> String {
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n\
         typedef struct {{ unsigned long long first; unsigned second; unsigned short third; }} AggregateFields;\n\
         typedef struct {{ long long left; long long right; }} AggregateInner;\n\
         typedef struct {{ AggregateInner *inner; long long tail; }} AggregateOuter;\n\
         typedef struct {{ long long *items; long long tail; }} AggregateArrayOuter;\n\
         extern unsigned long long aggregate_fields(AggregateFields *p);\n\
         extern long long aggregate_array(long long *p, long long i);\n\
         extern long long aggregate_nested(AggregateOuter *p);\n\
         extern long long aggregate_nested_array(AggregateArrayOuter *p, long long i);\n\
         extern void aggregate_update(AggregateFields *p, unsigned long long delta);\n\
         {recovered}\n\
         int main(void) {{\n\
             long long seeds[] = {{ 0, 1, -1, 7, -7, 255, -1024, 0x12345678LL }};\n\
             size_t count = sizeof(seeds) / sizeof(seeds[0]);\n\
             for (size_t i = 0; i < count; i++) {{\n\
                 AggregateFields fields = {{ (unsigned long long)seeds[i], (unsigned)(seeds[i] * 3), (unsigned short)(seeds[i] + 17) }};\n\
                 AggregateInner inner = {{ seeds[i] - 9, seeds[i] + 23 }};\n\
                 AggregateOuter outer = {{ &inner, seeds[i] * 5 }};\n\
                 long long values[8];\n\
                 for (size_t j = 0; j < 8; j++) values[j] = seeds[i] + (long long)j * 11;\n\
                 size_t at = i % 8;\n\
                 AggregateArrayOuter array_outer = {{ values, seeds[i] * 7 }};\n\
                 AggregateFields updated_original = fields;\n\
                 AggregateFields updated_recovered = fields;\n\
                 uint64_t delta = ((uint64_t)seeds[i]) ^ 0xa5a55a5a11223344ULL;\n\
                 uint64_t want_fields = (uint64_t)aggregate_fields(&fields);\n\
                 uint64_t got_fields = rec_aggregate_fields((uint64_t)(uintptr_t)&fields);\n\
                 uint64_t want_array = (uint64_t)aggregate_array(values, (long long)at);\n\
                 uint64_t got_array = rec_aggregate_array((uint64_t)(uintptr_t)values, (uint64_t)at);\n\
                 uint64_t want_nested = (uint64_t)aggregate_nested(&outer);\n\
                 uint64_t got_nested = rec_aggregate_nested((uint64_t)(uintptr_t)&outer);\n\
                 uint64_t want_nested_array = (uint64_t)aggregate_nested_array(&array_outer, (long long)at);\n\
                 uint64_t got_nested_array = rec_aggregate_nested_array((uint64_t)(uintptr_t)&array_outer, (uint64_t)at);\n\
                 aggregate_update(&updated_original, delta);\n\
                 (void)rec_aggregate_update((uint64_t)(uintptr_t)&updated_recovered, delta);\n\
                 int update_mismatch = updated_original.first != updated_recovered.first || updated_original.second != updated_recovered.second || updated_original.third != updated_recovered.third;\n\
                 if (want_fields != got_fields || want_array != got_array || want_nested != got_nested || want_nested_array != got_nested_array || update_mismatch) {{\n\
                     printf(\"MISMATCH %zu %llu %llu %llu %llu %llu %llu %llu %llu\\n\", i, (unsigned long long)want_fields, (unsigned long long)got_fields, (unsigned long long)want_array, (unsigned long long)got_array, (unsigned long long)want_nested, (unsigned long long)got_nested, (unsigned long long)want_nested_array, (unsigned long long)got_nested_array);\n\
                     return 1;\n\
                 }}\n\
             }}\n\
             printf(\"OK\\n\");\n\
             return 0;\n\
         }}\n"
    )
}

fn aggregate_rust_driver(recovered: &str) -> String {
    format!(
        "#![allow(unused, unused_parens, dead_code)]\n{recovered}\n\
         #[repr(C)]\nstruct AggregateFields {{ first: u64, second: u32, third: u16 }}\n\
         #[repr(C)]\nstruct AggregateInner {{ left: i64, right: i64 }}\n\
         #[repr(C)]\nstruct AggregateOuter {{ inner: *mut AggregateInner, tail: i64 }}\n\
         #[repr(C)]\nstruct AggregateArrayOuter {{ items: *mut i64, tail: i64 }}\n\
         fn main() {{\n\
         \x20   let seeds: [i64; 8] = [0, 1, -1, 7, -7, 255, -1024, 0x12345678];\n\
         \x20   for (i, seed) in seeds.into_iter().enumerate() {{\n\
         \x20       let mut fields = AggregateFields {{ first: seed as u64, second: seed.wrapping_mul(3) as u32, third: seed.wrapping_add(17) as u16 }};\n\
         \x20       let mut inner = AggregateInner {{ left: seed - 9, right: seed + 23 }};\n\
         \x20       let mut outer = AggregateOuter {{ inner: &mut inner, tail: seed * 5 }};\n\
         \x20       let mut values: [i64; 8] = core::array::from_fn(|j| seed + (j as i64) * 11);\n\
         \x20       let at: usize = i % values.len();\n\
         \x20       let mut array_outer = AggregateArrayOuter {{ items: values.as_mut_ptr(), tail: seed * 7 }};\n\
         \x20       let delta: u64 = (seed as u64) ^ 0xa5a55a5a11223344u64;\n\
         \x20       let mut updated = AggregateFields {{ first: seed as u64, second: seed.wrapping_mul(3) as u32, third: seed.wrapping_add(17) as u16 }};\n\
         \x20       let want_updated: (u64, u32, u16) = (updated.first.wrapping_add(delta), updated.second ^ (delta as u32), updated.third);\n\
         \x20       let want_fields: u64 = fields.first.wrapping_add(u64::from(fields.second)).wrapping_add(u64::from(fields.third));\n\
         \x20       let got_fields: u64 = rec_aggregate_fields((&mut fields as *mut AggregateFields) as usize as u64);\n\
         \x20       let want_array: u64 = values[at] as u64;\n\
         \x20       let got_array: u64 = rec_aggregate_array(values.as_mut_ptr() as usize as u64, at as u64);\n\
         \x20       let want_nested: u64 = (inner.left + inner.right + outer.tail) as u64;\n\
         \x20       let got_nested: u64 = rec_aggregate_nested((&mut outer as *mut AggregateOuter) as usize as u64);\n\
         \x20       let want_nested_array: u64 = values[at].wrapping_add(array_outer.tail) as u64;\n\
         \x20       let got_nested_array: u64 = rec_aggregate_nested_array((&mut array_outer as *mut AggregateArrayOuter) as usize as u64, at as u64);\n\
         \x20       let _ = rec_aggregate_update((&mut updated as *mut AggregateFields) as usize as u64, delta);\n\
         \x20       assert_eq!((got_fields, got_array, got_nested, got_nested_array), (want_fields, want_array, want_nested, want_nested_array));\n\
         \x20       assert_eq!((updated.first, updated.second, updated.third), want_updated);\n\
         \x20   }}\n\
         }}\n"
    )
}

fn aggregate_fields_driver(recovered: &str) -> String {
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n\
         typedef struct {{ unsigned long long first; unsigned second; unsigned short third; }} AggregateFields;\n\
         {recovered}\n\
         int main(void) {{\n\
         \x20   long long seeds[] = {{ 0, 1, -1, 7, -7, 255, -1024, 0x12345678LL }};\n\
         \x20   size_t count = sizeof(seeds) / sizeof(seeds[0]);\n\
         \x20   for (size_t i = 0; i < count; i++) {{\n\
         \x20       AggregateFields value = {{ (unsigned long long)seeds[i], (unsigned)(seeds[i] * 3), (unsigned short)(seeds[i] + 17) }};\n\
         \x20       uint64_t want = value.first + value.second + value.third;\n\
         \x20       uint64_t got = rec_aggregate_fields((uint64_t)(uintptr_t)&value);\n\
         \x20       if (want != got) return 1;\n\
         \x20   }}\n\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n"
    )
}

fn aggregate_fields_rust_driver(recovered: &str) -> String {
    format!(
        "#![allow(unused, unused_parens, dead_code)]\n{recovered}\n\
         #[repr(C)]\nstruct AggregateFields {{ first: u64, second: u32, third: u16 }}\n\
         fn main() {{\n\
         \x20   let seeds: [i64; 8] = [0, 1, -1, 7, -7, 255, -1024, 0x12345678];\n\
         \x20   for seed in seeds {{\n\
         \x20       let mut value = AggregateFields {{ first: seed as u64, second: seed.wrapping_mul(3) as u32, third: seed.wrapping_add(17) as u16 }};\n\
         \x20       let want: u64 = value.first.wrapping_add(u64::from(value.second)).wrapping_add(u64::from(value.third));\n\
         \x20       let got: u64 = rec_aggregate_fields((&mut value as *mut AggregateFields) as usize as u64);\n\
         \x20       assert_eq!(got, want);\n\
         \x20   }}\n\
         }}\n"
    )
}

#[test]
fn gcc_and_clang_aggregate_accesses_recompile_to_c_and_rust_equivalence() {
    if !cfg!(target_arch = "x86_64") {
        eprintln!("skipping aggregate compiler differential on a non-x86-64 host");
        return;
    }
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let source_path: PathBuf = dir.join("aggregate_types.c");
    std::fs::write(&source_path, AGGREGATE_SOURCE.as_bytes()).expect("write aggregate source");
    assert!(
        Command::new("rustc")
            .arg("--version")
            .output()
            .is_ok_and(|output: std::process::Output| output.status.success()),
        "rustc is required for aggregate grading"
    );
    let mut graded_compilers: usize = 0;
    for compiler in ["gcc", "clang"] {
        if !Command::new(compiler)
            .arg("--version")
            .output()
            .is_ok_and(|o: std::process::Output| o.status.success())
        {
            continue;
        }
        let object_path: PathBuf = dir.join(format!("aggregate_types_{compiler}.o"));
        let compile: std::process::Output = Command::new(compiler)
            .args(["-O1", "-fno-stack-protector", "-c", "-o"])
            .arg(&object_path)
            .arg(&source_path)
            .output()
            .expect("compile aggregate source");
        assert!(
            compile.status.success(),
            "{compiler} aggregate compile failed: {}",
            String::from_utf8_lossy(&compile.stderr)
        );
        let object_bytes: Vec<u8> = std::fs::read(&object_path).expect("read aggregate object");
        let mut recovered: String = String::new();
        let mut recovered_rust: String = String::new();
        for (name, expected) in [
            ("aggregate_fields", ExpectedAggregateShape::Struct),
            ("aggregate_array", ExpectedAggregateShape::Array),
            ("aggregate_nested", ExpectedAggregateShape::Struct),
            ("aggregate_nested_array", ExpectedAggregateShape::Struct),
            ("aggregate_update", ExpectedAggregateShape::Struct),
        ] {
            let (code, base): (Vec<u8>, u64) =
                function_code(&object_bytes, name).expect("locate aggregate function");
            let recovery: LeafRecovery = recover_leaf_function_abi(&code, base, HOST_ABI)
                .expect("recover aggregate function");
            match expected {
                ExpectedAggregateShape::Struct => {
                    assert!(
                        recovery.source.contains("recovered_struct_0_t")
                            && recovery.source.contains("->field_"),
                        "{compiler} {name} did not recover fields:\n{}",
                        recovery.source
                    );
                }
                ExpectedAggregateShape::Array => {
                    assert!(
                        recovery.source.contains("recovered_array_0_t")
                            && recovery.source.contains("recovered_array_0["),
                        "{compiler} {name} did not recover indexing:\n{}",
                        recovery.source
                    );
                }
                ExpectedAggregateShape::NoAggregate => unreachable!(),
            }
            let rust: &str = recovery
                .rust_source
                .as_deref()
                .expect("aggregate rust output");
            assert!(
                rust.contains("RecoveredStruct") || rust.contains("RecoveredArray"),
                "{compiler} {name} did not carry the recovered type into Rust:\n{rust}"
            );
            if name == "aggregate_nested_array" {
                assert!(
                    recovery.source.contains("recovered_array_1_t *field_0")
                        && recovery
                            .source
                            .contains("((recovered_array_1_t *)(uintptr_t)"),
                    "{compiler} nested array did not link its field and elements:\n{}",
                    recovery.source
                );
                assert!(
                    rust.contains("*mut RecoveredArray1") && rust.contains("wrapping_add"),
                    "{compiler} nested array did not carry into Rust:\n{rust}"
                );
            }
            recovered.push_str(&mem_recovered_signature(&recovery, &format!("rec_{name}")));
            recovered.push('\n');
            recovered_rust.push_str(&rust.replacen(
                "pub fn recovered(",
                &format!("pub fn rec_{name}("),
                1,
            ));
            recovered_rust.push('\n');
        }
        let driver: String = aggregate_driver(&recovered);
        let driver_path: PathBuf = dir.join(format!("aggregate_driver_{compiler}.c"));
        std::fs::write(&driver_path, driver.as_bytes()).expect("write aggregate driver");
        let executable_path: PathBuf = dir.join(format!("aggregate_driver_{compiler}.exe"));
        let link: std::process::Output = Command::new(compiler)
            .args([
                "-O3",
                "-fstrict-aliasing",
                "-Werror=ignored-attributes",
                "-o",
            ])
            .arg(&executable_path)
            .arg(&driver_path)
            .arg(&object_path)
            .output()
            .expect("link aggregate driver");
        assert!(
            link.status.success(),
            "{compiler} aggregate link failed: {}\n{driver}",
            String::from_utf8_lossy(&link.stderr)
        );
        let run: std::process::Output = Command::new(&executable_path)
            .output()
            .expect("run aggregate driver");
        assert!(
            run.status.success() && String::from_utf8_lossy(&run.stdout).contains("OK"),
            "{compiler} aggregate result mismatch: {}\n{}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );
        let rust_driver: String = aggregate_rust_driver(&recovered_rust);
        let rust_driver_path: PathBuf = dir.join(format!("aggregate_driver_{compiler}.rs"));
        std::fs::write(&rust_driver_path, rust_driver.as_bytes())
            .expect("write aggregate rust driver");
        let rust_executable_path: PathBuf = dir.join(format!("aggregate_rust_{compiler}.exe"));
        let rust_build: std::process::Output = Command::new("rustc")
            .args(["--edition", "2021", "-C", "overflow-checks=on", "-o"])
            .arg(&rust_executable_path)
            .arg(&rust_driver_path)
            .output()
            .expect("compile aggregate rust driver");
        assert!(
            rust_build.status.success(),
            "{compiler} aggregate Rust compile failed: {}\n{rust_driver}",
            String::from_utf8_lossy(&rust_build.stderr)
        );
        let rust_run: std::process::Output = Command::new(&rust_executable_path)
            .output()
            .expect("run aggregate rust driver");
        assert!(
            rust_run.status.success(),
            "{compiler} aggregate Rust result mismatch: {}\n{}",
            String::from_utf8_lossy(&rust_run.stdout),
            String::from_utf8_lossy(&rust_run.stderr)
        );
        graded_compilers += 1;
    }
    assert_eq!(
        graded_compilers, 2,
        "aggregate grading requires both GCC and Clang"
    );
    println!(
        "aggregate C/Rust compiler differential PASSED: {}/{} recovered, 0 rejected, 0 mismatches",
        graded_compilers * 5,
        graded_compilers * 5
    );
}

#[test]
fn gcc_and_clang_union_accesses_recompile_to_c_and_rust_equivalence() {
    if !cfg!(target_arch = "x86_64") {
        eprintln!("skipping union compiler differential on a non-x86-64 host");
        return;
    }
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let source_path: PathBuf = dir.join("union_types.c");
    std::fs::write(&source_path, UNION_SOURCE.as_bytes()).expect("write union source");
    assert!(
        Command::new("rustc")
            .arg("--version")
            .output()
            .is_ok_and(|output: std::process::Output| output.status.success()),
        "rustc is required for union grading"
    );
    let mut recovered_count: usize = 0;
    let mut rejected_count: usize = 0;
    for compiler in ["gcc", "clang"] {
        assert!(
            Command::new(compiler)
                .arg("--version")
                .output()
                .is_ok_and(|output: std::process::Output| output.status.success()),
            "union grading requires {compiler}"
        );
        let object_path: PathBuf = dir.join(format!("union_types_{compiler}.o"));
        let compile: std::process::Output = Command::new(compiler)
            .args(["-O1", "-fno-stack-protector", "-c", "-o"])
            .arg(&object_path)
            .arg(&source_path)
            .output()
            .expect("compile union source");
        assert!(
            compile.status.success(),
            "{compiler} union compile failed: {}",
            String::from_utf8_lossy(&compile.stderr)
        );
        let object_bytes: Vec<u8> = std::fs::read(&object_path).expect("read union object");
        let mut recovered_c: String = String::new();
        let mut recovered_rust: String = String::new();
        for name in [
            "union_wide_word",
            "union_word_float",
            "union_word_float_store",
        ] {
            let (code, base): (Vec<u8>, u64) =
                function_code(&object_bytes, name).expect("locate union function");
            let recovery: LeafRecovery =
                recover_leaf_function_abi(&code, base, HOST_ABI).expect("recover union function");
            assert!(
                recovery.source.contains("recovered_union_0_t")
                    && recovery.source.contains("recovered_union_0->field_0_"),
                "{compiler} {name} did not recover a union:\n{}",
                recovery.source
            );
            let rust: &str = recovery.rust_source.as_deref().expect("union rust output");
            assert!(
                rust.contains("union RecoveredUnion0") && rust.contains("field_0_"),
                "{compiler} {name} did not carry the union into Rust:\n{rust}"
            );
            let mut recovered_function: String =
                mem_recovered_signature(&recovery, &format!("rec_{name}"));
            if recovered_c.contains("static inline double fp_d_from_bits") {
                recovered_function = recovered_function
                    .lines()
                    .filter(|line: &&str| !line.starts_with("static inline"))
                    .collect::<Vec<&str>>()
                    .join("\n");
            }
            recovered_c.push_str(&recovered_function);
            recovered_c.push('\n');
            recovered_rust.push_str(&rust.replacen(
                "pub fn recovered(",
                &format!("pub fn rec_{name}("),
                1,
            ));
            recovered_rust.push('\n');
            recovered_count += 1;
        }
        let (partial_code, partial_base): (Vec<u8>, u64) =
            function_code(&object_bytes, "union_partial").expect("locate partial union function");
        let partial: LeafRecovery =
            recover_leaf_function_abi(&partial_code, partial_base, HOST_ABI)
                .expect("recover partial union function");
        assert!(
            !partial.source.contains("recovered_union_")
                && !partial.source.contains("recovered_struct_")
                && partial.source.contains("(*(uint64_t*)")
                && partial.source.contains("(*(uint32_t*)"),
            "{compiler} shifted partial overlap must remain raw:\n{}",
            partial.source
        );
        recovered_c.push_str(&mem_recovered_signature(&partial, "rec_union_partial"));
        recovered_c.push('\n');
        rejected_count += 1;

        let driver: String = union_driver(&recovered_c);
        let driver_path: PathBuf = dir.join(format!("union_driver_{compiler}.c"));
        std::fs::write(&driver_path, driver.as_bytes()).expect("write union driver");
        let executable_path: PathBuf = dir.join(format!("union_driver_{compiler}.exe"));
        let link: std::process::Output = Command::new(compiler)
            .args([
                "-O3",
                "-fstrict-aliasing",
                "-Werror=ignored-attributes",
                "-o",
            ])
            .arg(&executable_path)
            .arg(&driver_path)
            .arg(&object_path)
            .output()
            .expect("link union driver");
        assert!(
            link.status.success(),
            "{compiler} union link failed: {}\n{driver}",
            String::from_utf8_lossy(&link.stderr)
        );
        let run: std::process::Output = Command::new(&executable_path)
            .output()
            .expect("run union driver");
        assert!(
            run.status.success() && String::from_utf8_lossy(&run.stdout).contains("OK"),
            "{compiler} union result mismatch: {}\n{}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );

        let rust_driver: String = union_rust_driver(&recovered_rust);
        let rust_driver_path: PathBuf = dir.join(format!("union_driver_{compiler}.rs"));
        std::fs::write(&rust_driver_path, rust_driver.as_bytes()).expect("write union rust driver");
        let rust_executable_path: PathBuf = dir.join(format!("union_rust_{compiler}.exe"));
        let rust_build: std::process::Output = Command::new("rustc")
            .args(["--edition", "2021", "-C", "overflow-checks=on", "-o"])
            .arg(&rust_executable_path)
            .arg(&rust_driver_path)
            .output()
            .expect("compile union rust driver");
        assert!(
            rust_build.status.success(),
            "{compiler} union Rust compile failed: {}\n{rust_driver}",
            String::from_utf8_lossy(&rust_build.stderr)
        );
        let rust_run: std::process::Output = Command::new(&rust_executable_path)
            .output()
            .expect("run union rust driver");
        assert!(
            rust_run.status.success(),
            "{compiler} union Rust result mismatch: {}\n{}",
            String::from_utf8_lossy(&rust_run.stdout),
            String::from_utf8_lossy(&rust_run.stderr)
        );
    }
    assert_eq!(recovered_count, 6);
    assert_eq!(rejected_count, 2);
    println!(
        "union C/Rust compiler differential PASSED: {recovered_count} recovered, {rejected_count} rejected, 0 mismatches"
    );
}

#[test]
fn clang_frame_spill_recovers_one_struct_across_reload_registers() {
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let source_path: PathBuf = dir.join("aggregate_frame_types.c");
    std::fs::write(&source_path, AGGREGATE_SOURCE.as_bytes())
        .expect("write frame aggregate source");
    if clang().is_none() {
        eprintln!("skipping frame aggregate cross-check: clang not on PATH");
        return;
    }
    let object_path: PathBuf = dir.join("aggregate_frame_clang.o");
    let compile: std::process::Output = Command::new("clang")
        .args([
            "--target=x86_64-unknown-linux-gnu",
            "-O0",
            "-fno-stack-protector",
            "-c",
            "-o",
        ])
        .arg(&object_path)
        .arg(&source_path)
        .output()
        .expect("compile frame aggregate source");
    assert!(
        compile.status.success(),
        "clang frame aggregate compile failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&object_path).expect("read frame aggregate object");
    let (code, base): (Vec<u8>, u64) =
        function_code(&object_bytes, "aggregate_fields").expect("locate frame aggregate function");
    let instructions: Vec<DisasmInsn> =
        disassemble(Arch::X86_64, base, &code).expect("disassemble frame aggregate function");
    let frame_reloads: usize = instructions
        .iter()
        .filter(|insn: &&DisasmInsn| insn.operands.contains("[rbp-8]"))
        .count();
    assert!(
        frame_reloads >= 3,
        "clang frame aggregate must reload one pointer slot at least three times: {instructions:?}"
    );
    let recovery: LeafRecovery = recover_leaf_function_abi(&code, base, PseudoAbi::SysV)
        .expect("recover frame aggregate function");
    assert!(
        recovery.source.matches("recovered_struct_0_t").count() >= 3
            && recovery.source.contains("->field_0")
            && recovery.source.contains("->field_8")
            && recovery.source.contains("->field_c"),
        "clang did not combine frame reload registers into one struct:\n{}",
        recovery.source
    );
    let rust: &str = recovery
        .rust_source
        .as_deref()
        .expect("frame aggregate rust output");
    assert!(rust.contains("struct RecoveredStruct0"));
    let recovered_c: String = mem_recovered_signature(&recovery, "rec_aggregate_fields");
    let c_driver: String = aggregate_fields_driver(&recovered_c);
    let c_driver_path: PathBuf = dir.join("aggregate_frame_recovered.c");
    std::fs::write(&c_driver_path, c_driver.as_bytes()).expect("write frame C driver");
    let c_executable: PathBuf = dir.join("aggregate_frame_recovered.exe");
    let c_link: std::process::Output = Command::new("clang")
        .args([
            "-O3",
            "-fstrict-aliasing",
            "-Werror=ignored-attributes",
            "-o",
        ])
        .arg(&c_executable)
        .arg(&c_driver_path)
        .output()
        .expect("link frame C driver");
    assert!(
        c_link.status.success(),
        "recovered frame C did not compile: {}\n{c_driver}",
        String::from_utf8_lossy(&c_link.stderr)
    );
    let c_run: std::process::Output = Command::new(&c_executable)
        .output()
        .expect("run frame C driver");
    assert!(
        c_run.status.success() && String::from_utf8_lossy(&c_run.stdout).contains("OK"),
        "recovered frame C result mismatch: {}\n{}",
        String::from_utf8_lossy(&c_run.stdout),
        String::from_utf8_lossy(&c_run.stderr)
    );
    let recovered_rust: String =
        rust.replacen("pub fn recovered(", "pub fn rec_aggregate_fields(", 1);
    let rust_driver: String = aggregate_fields_rust_driver(&recovered_rust);
    let rust_driver_path: PathBuf = dir.join("aggregate_frame_recovered.rs");
    std::fs::write(&rust_driver_path, rust_driver.as_bytes()).expect("write frame Rust driver");
    let rust_executable: PathBuf = dir.join("aggregate_frame_rust.exe");
    let rust_build: std::process::Output = Command::new("rustc")
        .args(["--edition", "2021", "-C", "overflow-checks=on", "-o"])
        .arg(&rust_executable)
        .arg(&rust_driver_path)
        .output()
        .expect("compile frame Rust driver");
    assert!(
        rust_build.status.success(),
        "recovered frame Rust did not compile: {}\n{rust_driver}",
        String::from_utf8_lossy(&rust_build.stderr)
    );
    let rust_run: std::process::Output = Command::new(&rust_executable)
        .output()
        .expect("run frame Rust driver");
    assert!(
        rust_run.status.success(),
        "recovered frame Rust result mismatch: {}\n{}",
        String::from_utf8_lossy(&rust_run.stdout),
        String::from_utf8_lossy(&rust_run.stderr)
    );
    println!("frame aggregate C/Rust differential PASSED: 1 recovered, 0 rejected, 0 mismatches");
}

fn gcc() -> Option<String> {
    if Command::new("gcc")
        .arg("--version")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
    {
        Some("gcc".to_owned())
    } else {
        None
    }
}

const CF_BATTERY: &[Case] = &[
    Case {
        name: "g_cap",
        arity: 2,
        c_source: "long long g_cap(long long a, long long b){ long long r = a + b; if (a > b) r += 10; return r; }",
    },
    Case {
        name: "g_mul",
        arity: 2,
        c_source: "long long g_mul(long long a, long long b){ long long r = a + b; if (a > b) r *= 3; return r; }",
    },
    Case {
        name: "g_sub",
        arity: 2,
        c_source: "long long g_sub(long long a, long long b){ long long r = a + b; if (a > b) r -= 7; return r; }",
    },
    Case {
        name: "g_or",
        arity: 2,
        c_source: "long long g_or(long long a, long long b){ long long r = a + b; if (a > b) r |= 0xff; return r; }",
    },
    Case {
        name: "g_and",
        arity: 2,
        c_source: "long long g_and(long long a, long long b){ long long r = a + b; if (a > b) r &= 0x3f; return r; }",
    },
    Case {
        name: "g_xor",
        arity: 2,
        c_source: "long long g_xor(long long a, long long b){ long long r = a + b; if (a != b) r ^= 0x55; return r; }",
    },
    Case {
        name: "g_uadj",
        arity: 2,
        c_source: "unsigned long long g_uadj(unsigned long long a, unsigned long long b){ unsigned long long r = a; if (a > b) r = a - b; return r; }",
    },
    Case {
        name: "g_nest",
        arity: 3,
        c_source: "long long g_nest(long long a, long long b, long long c){ long long r = c; if (a > 0) if (b > 0) r = a + b; return r; }",
    },
    Case {
        name: "g_mask",
        arity: 2,
        c_source: "long long g_mask(long long a, long long b){ long long r = a * b; if (a > b) r &= 0x3f; return r; }",
    },
    Case {
        name: "g_shr",
        arity: 2,
        c_source: "long long g_shr(long long a, long long b){ long long r = a + b; if (a > b) r += (r >> 2); return r; }",
    },
    Case {
        name: "g_sign",
        arity: 1,
        c_source: "long long g_sign(long long a){ if (a > 0) return 1; if (a < 0) return -1; return 0; }",
    },
    Case {
        name: "g_setflag",
        arity: 2,
        c_source: "long long g_setflag(long long a, long long b){ long long r = a * b; if (a == 0) r = 7; return r; }",
    },
];

#[test]
fn control_flow_leaf_functions_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!(
            "skipping control-flow oracle: gcc (needed to suppress if-conversion) not on PATH"
        );
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let mut battery_src: String = String::new();
    for case in CF_BATTERY {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let battery_c: PathBuf = dir.join("cf_battery.c");
    std::fs::write(&battery_c, battery_src.as_bytes()).expect("write cf_battery.c");
    let battery_o: PathBuf = dir.join("cf_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args([
            "-O1",
            "-fno-stack-protector",
            "-fno-if-conversion",
            "-fno-if-conversion2",
            "-fno-tree-loop-if-convert",
            "-c",
            "-o",
        ])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke gcc for cf battery");
    assert!(
        compile_battery.status.success(),
        "cf battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read cf_battery.o");

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    let mut branchy_count: usize = 0;

    for case in CF_BATTERY {
        let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(&object_bytes, case.name)
        else {
            eprintln!("skip {}: symbol not located", case.name);
            continue;
        };
        let recovery: LeafRecovery = match recover_leaf_function_abi(&code, base, HOST_ABI) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skip {}: not in control-flow leaf class ({e})", case.name);
                continue;
            }
        };
        if recovery.source.contains("if (") {
            branchy_count += 1;
        }
        let Some(lifted): Option<Lifted> = process_case(case, &object_bytes, HOST_ABI) else {
            continue;
        };
        recovered_decls.push_str(&lifted.decls);
        driver_body.push_str(&lifted.driver_snippet);
        lifted_count += 1;
    }

    if lifted_count == 0 {
        eprintln!(
            "skipping control-flow behavioral differential: this compiler build lowered none of the {} battery cases into the control-flow leaf class ({branchy_count} branchy)",
            CF_BATTERY.len()
        );
        return;
    }

    let driver: String = build_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("cf_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write cf_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "cf_harness.exe"
    } else {
        "cf_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke gcc to link cf harness");
    assert!(
        link.status.success(),
        "cf harness link failed: {}\n--- cf_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe).output().expect("run cf harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "control-flow behavioral differential FAILED ({lifted_count} cases, {branchy_count} branchy): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "control-flow behavioral differential PASSED for {lifted_count} leaf functions ({branchy_count} structured-branch, MS x64 ABI)"
    );
}

const SPLIT_RETURN_BATTERY: &[Case] = &[
    Case {
        name: "s_sign",
        arity: 1,
        c_source: "long long s_sign(long long a){ if (a > 0) return 1; if (a < 0) return -1; return 0; }",
    },
    Case {
        name: "s_step",
        arity: 1,
        c_source: "long long s_step(long long a){ long long r = 5; if (a > 10) r = 99; return r; }",
    },
    Case {
        name: "s_setz",
        arity: 2,
        c_source: "long long s_setz(long long a, long long b){ long long r = a * b; if (a == 0) r = 7; return r; }",
    },
    Case {
        name: "s_pick3",
        arity: 1,
        c_source: "long long s_pick3(long long a){ long long r; if (a > 0) r = 1; else if (a < 0) r = -1; else r = 0; return r; }",
    },
    Case {
        name: "s_ucap",
        arity: 2,
        c_source: "unsigned long long s_ucap(unsigned long long a, unsigned long long b){ unsigned long long r = a + b; if (a > b) r = 0; return r; }",
    },
    Case {
        name: "s_signi",
        arity: 1,
        c_source: "int s_signi(int a){ if (a > 0) return 1; if (a < 0) return -1; return 0; }",
    },
    Case {
        name: "s_orconst",
        arity: 2,
        c_source: "long long s_orconst(long long a, long long b){ long long r = a + b; if (a == b) r = 0xdead; return r; }",
    },
];

fn recovered_is_split_return(object_bytes: &[u8], name: &str) -> bool {
    let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(object_bytes, name) else {
        return false;
    };
    let recovery: LeafRecovery = match recover_leaf_function_abi(&code, base, HOST_ABI) {
        Ok(r) => r,
        Err(_) => return false,
    };
    recovery.lifted_split_return && recovery.source.matches("return ").count() == 1
}

#[test]
fn split_return_leaf_functions_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!(
            "skipping split-return oracle: gcc (needed for the out-of-line return idiom) not on PATH"
        );
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let mut battery_src: String = String::new();
    for case in SPLIT_RETURN_BATTERY {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let battery_c: PathBuf = dir.join("split_battery.c");
    std::fs::write(&battery_c, battery_src.as_bytes()).expect("write split_battery.c");
    let battery_o: PathBuf = dir.join("split_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args([
            "-O1",
            "-fno-stack-protector",
            "-fno-if-conversion",
            "-fno-if-conversion2",
            "-fno-tree-loop-if-convert",
            "-c",
            "-o",
        ])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke gcc for split battery");
    assert!(
        compile_battery.status.success(),
        "split battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read split_battery.o");

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    let mut split_idiom_count: usize = 0;

    for case in SPLIT_RETURN_BATTERY {
        if recovered_is_split_return(&object_bytes, case.name) {
            split_idiom_count += 1;
        } else {
            eprintln!(
                "note {}: gcc did not emit the out-of-line tail-return idiom this build",
                case.name
            );
        }
        let Some(lifted): Option<Lifted> = process_case(case, &object_bytes, HOST_ABI) else {
            continue;
        };
        recovered_decls.push_str(&lifted.decls);
        driver_body.push_str(&lifted.driver_snippet);
        lifted_count += 1;
    }

    if lifted_count == 0 {
        eprintln!(
            "skipping split-return behavioral differential: this compiler build lowered none of the {} battery cases into the leaf class ({split_idiom_count} out-of-line tail-return idiom)",
            SPLIT_RETURN_BATTERY.len()
        );
        return;
    }

    let driver: String = build_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("split_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write split_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "split_harness.exe"
    } else {
        "split_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke gcc to link split harness");
    assert!(
        link.status.success(),
        "split harness link failed: {}\n--- split_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run split harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "split-return behavioral differential FAILED ({lifted_count} cases, {split_idiom_count} idiom): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "split-return behavioral differential PASSED for {lifted_count} leaf functions ({split_idiom_count} out-of-line tail-return idiom, MS x64 ABI)"
    );
}

enum BoundedRun {
    Exited(std::process::Output),
    TimedOut,
}

fn run_bounded(exe: &std::path::Path, secs: u64) -> BoundedRun {
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
        let out: std::process::Output = child.wait_with_output().expect("collect harness output");
        BoundedRun::Exited(out)
    } else {
        let _ = child.kill();
        let _ = child.wait();
        BoundedRun::TimedOut
    }
}

struct LoopCase {
    name: &'static str,
    arity: usize,
    c_source: &'static str,
}

const LOOP_BATTERY: &[LoopCase] = &[
    LoopCase {
        name: "lp_sum",
        arity: 1,
        c_source: "long long lp_sum(long long n){ long long s = 0; long long i = 0; do { i++; s += i; } while (i != n); return s; }",
    },
    LoopCase {
        name: "lp_mul",
        arity: 2,
        c_source: "long long lp_mul(long long a, long long n){ long long r = 0; long long i = 0; do { r += a; i++; } while (i != n); return r; }",
    },
    LoopCase {
        name: "lp_fact",
        arity: 1,
        c_source: "long long lp_fact(long long n){ long long r = 1; long long i = 1; do { r *= i; i++; } while (i != n + 1); return r; }",
    },
    LoopCase {
        name: "lp_pow2",
        arity: 1,
        c_source: "long long lp_pow2(long long k){ long long r = 1; long long i = 0; do { r += r; i++; } while (i != k); return r; }",
    },
    LoopCase {
        name: "lp_popcount",
        arity: 1,
        c_source: "long long lp_popcount(unsigned long long x){ long long c = 0; do { c += (long long)(x & 1); x >>= 1; } while (x != 0); return c; }",
    },
    LoopCase {
        name: "lp_count",
        arity: 1,
        c_source: "long long lp_count(long long n){ long long c = 0; long long i = n; do { c++; i--; } while (i != 0); return c; }",
    },
    LoopCase {
        name: "lp_acc",
        arity: 2,
        c_source: "long long lp_acc(long long a, long long n){ long long r = a; long long i = 0; do { r += a; i++; } while (i != n); return r; }",
    },
    LoopCase {
        name: "lp_gauss",
        arity: 2,
        c_source: "long long lp_gauss(long long a, long long n){ long long r = 0; long long i = 0; do { r += a + i; i++; } while (i != n); return r; }",
    },
    LoopCase {
        name: "lp_shiftcount",
        arity: 1,
        c_source: "long long lp_shiftcount(unsigned long long x){ long long n = 0; do { x <<= 1; n++; } while (x != 0); return n; }",
    },
];

fn loop_lift(case: &LoopCase, object_bytes: &[u8]) -> Option<(LeafRecovery, String, String)> {
    let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(object_bytes, case.name) else {
        eprintln!("skip {}: symbol not located", case.name);
        return None;
    };
    let recovery: LeafRecovery = match recover_leaf_function_abi(&code, base, HOST_ABI) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("skip {}: not in loop leaf class ({e})", case.name);
            return None;
        }
    };
    let recovered_name: String = format!("rec_{}", case.name);
    let renamed: String = recovery
        .source
        .replacen(
            "uint64_t recovered(",
            &format!("uint64_t {recovered_name}("),
            1,
        )
        .lines()
        .filter(|l: &&str| !l.starts_with("#include"))
        .collect::<Vec<&str>>()
        .join("\n");
    Some((recovery, renamed, recovered_name))
}

fn loop_driver_snippet(case: &LoopCase, recovery: &LeafRecovery, recovered_name: &str) -> String {
    let return_mask: String = if recovery.return_width_bits == 64 {
        "0xFFFFFFFFFFFFFFFFULL".to_owned()
    } else {
        format!("0x{:x}ULL", (1u128 << recovery.return_width_bits) - 1)
    };
    let args: Vec<String> = (0..case.arity).map(|i: usize| format!("in[{i}]")).collect();
    let rec_args: Vec<String> = (0..recovery.params.len())
        .map(|i: usize| format!("(uint64_t)in[{i}]"))
        .collect();
    let mut snippet: String = String::new();
    let _ = write!(
        snippet,
        "    for (size_t k = 0; k < n_trips; k++) {{\n\
         \x20       long long in[2] = {{ trips[k][0], trips[k][1] }};\n\
         \x20       unsigned long long want = (unsigned long long){}({}) & {return_mask};\n\
         \x20       unsigned long long got = {recovered_name}({}) & {return_mask};\n\
         \x20       if (want != got) {{ printf(\"MISMATCH {} in=%lld,%lld want=%llu got=%llu\\n\", in[0], in[1], want, got); return 1; }}\n\
         \x20   }}\n",
        case.name,
        args.join(", "),
        rec_args.join(", "),
        case.name,
    );
    snippet
}

fn build_loop_driver(recovered_decls: &str, driver_body: &str) -> String {
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n{recovered_decls}\n\
         int main(void) {{\n\
         \x20   long long trips[][2] = {{\n\
         \x20       {{1,1}},{{2,2}},{{3,1}},{{4,3}},{{5,2}},{{6,4}},{{7,7}},\n\
         \x20       {{8,3}},{{10,5}},{{12,2}},{{15,6}},{{16,9}},{{20,4}},{{31,11}},{{40,13}}\n\
         \x20   }};\n\
         \x20   size_t n_trips = sizeof(trips)/sizeof(trips[0]);\n\
         {driver_body}\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n"
    )
}

#[test]
fn natural_loop_leaf_functions_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!("skipping loop oracle: gcc (needed for the rotated do-while idiom) not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let mut battery_src: String = String::new();
    for case in LOOP_BATTERY {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let battery_c: PathBuf = dir.join("loop_battery.c");
    std::fs::write(&battery_c, battery_src.as_bytes()).expect("write loop_battery.c");
    let battery_o: PathBuf = dir.join("loop_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args([
            "-O1",
            "-fno-stack-protector",
            "-fno-if-conversion",
            "-fno-if-conversion2",
            "-fno-tree-loop-if-convert",
            "-c",
            "-o",
        ])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke gcc for loop battery");
    assert!(
        compile_battery.status.success(),
        "loop battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read loop_battery.o");

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    let mut loop_count: usize = 0;

    for case in LOOP_BATTERY {
        let Some((recovery, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
            loop_lift(case, &object_bytes)
        else {
            continue;
        };
        if recovery.lifted_loop && recovery.source.contains("do {") {
            loop_count += 1;
        } else {
            eprintln!(
                "note {}: recovered without a reconstructed loop this build",
                case.name
            );
            continue;
        }
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        let _ = writeln!(
            recovered_decls,
            "extern long long {}({});",
            case.name,
            vec!["long long"; case.arity].join(", ")
        );
        driver_body.push_str(&loop_driver_snippet(case, &recovery, &recovered_name));
        lifted_count += 1;
    }

    if lifted_count == 0 {
        eprintln!(
            "skipping loop behavioral differential: this compiler build reconstructed no structured do-while loop from the {} battery cases ({loop_count} loops)",
            LOOP_BATTERY.len()
        );
        return;
    }

    let driver: String = build_loop_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("loop_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write loop_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "loop_harness.exe"
    } else {
        "loop_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke gcc to link loop harness");
    assert!(
        link.status.success(),
        "loop harness link failed: {}\n--- loop_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: BoundedRun = run_bounded(&harness_exe, 20);
    let BoundedRun::Exited(out): BoundedRun = run else {
        panic!(
            "loop harness did not terminate within the watchdog window; a recovered loop is non-terminating"
        );
    };
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("OK"),
        "loop behavioral differential FAILED ({lifted_count} cases, {loop_count} loops): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    println!(
        "natural-loop behavioral differential PASSED for {lifted_count} leaf functions ({loop_count} reconstructed do-while, MS x64 ABI)"
    );
}

#[test]
fn loop_oracle_has_teeth_a_wrong_bound_diverges() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!("skipping loop teeth check: gcc not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let probe: LoopCase = LoopCase {
        name: "lp_sum",
        arity: 1,
        c_source: LOOP_BATTERY[0].c_source,
    };
    let battery_c: PathBuf = dir.join("teeth_battery.c");
    std::fs::write(&battery_c, probe.c_source.as_bytes()).expect("write teeth_battery.c");
    let battery_o: PathBuf = dir.join("teeth_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args([
            "-O1",
            "-fno-stack-protector",
            "-fno-if-conversion",
            "-fno-if-conversion2",
            "-fno-tree-loop-if-convert",
            "-c",
            "-o",
        ])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke gcc for teeth battery");
    assert!(
        compile_battery.status.success(),
        "teeth battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read teeth_battery.o");

    let Some((recovery, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
        loop_lift(&probe, &object_bytes)
    else {
        eprintln!(
            "skipping loop teeth check: this compiler build did not lower the probe into the loop leaf class, so there is no reconstructed loop to corrupt"
        );
        return;
    };
    if !(recovery.lifted_loop && renamed.contains("} while (")) {
        eprintln!(
            "skipping loop teeth check: this compiler build did not reconstruct a do-while shape to corrupt"
        );
        return;
    }

    let corrupted: String = renamed.replacen(
        "!= ((int64_t)(int64_t)(r_rcx))",
        "!= ((int64_t)(int64_t)(r_rax))",
        1,
    );
    if corrupted == renamed {
        eprintln!(
            "skipping loop teeth check: this compiler build did not emit the r_rcx exit-bound comparison this teeth check corrupts"
        );
        return;
    }

    let mut decls: String = corrupted;
    decls.push('\n');
    let _ = writeln!(decls, "extern long long {}(long long);", probe.name);
    let snippet: String = loop_driver_snippet(&probe, &recovery, &recovered_name);
    let driver: String = build_loop_driver(&decls, &snippet);
    let driver_c: PathBuf = dir.join("teeth_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write teeth_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "teeth_harness.exe"
    } else {
        "teeth_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke gcc to link teeth harness");
    assert!(
        link.status.success(),
        "teeth harness link failed: {}\n--- teeth_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    match run_bounded(&harness_exe, 10) {
        BoundedRun::Exited(out) => {
            let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&out.stdout);
            assert!(
                !stdout.contains("OK") && stdout.contains("MISMATCH"),
                "teeth check FAILED: a corrupted loop bound must diverge from the original, got: {stdout}"
            );
            println!(
                "loop oracle teeth confirmed: corrupting the exit bound diverges (MISMATCH observed)"
            );
        }
        BoundedRun::TimedOut => {
            println!(
                "loop oracle teeth confirmed: corrupting the exit bound diverges (corrupted loop did not terminate)"
            );
        }
    }
}

const GUARDED_WHILE_BATTERY: &[LoopCase] = &[
    LoopCase {
        name: "wg_count",
        arity: 1,
        c_source: "long long wg_count(long long n){ long long c = 0; long long i = 0; while (i != n) { c++; i++; } return c; }",
    },
    LoopCase {
        name: "wg_xoracc",
        arity: 1,
        c_source: "long long wg_xoracc(long long n){ long long r = 0; long long i = 0; while (i != n) { r ^= (i * 3 + 1); i++; } return r; }",
    },
    LoopCase {
        name: "wg_andmix",
        arity: 2,
        c_source: "long long wg_andmix(long long a, long long n){ long long r = a; long long i = 0; while (i != n) { r += (r & 0x3f) + i; i++; } return r; }",
    },
    LoopCase {
        name: "wg_decxor",
        arity: 1,
        c_source: "long long wg_decxor(long long n){ long long r = 0; while (n != 0) { r ^= (n * 5 + 2); n--; } return r; }",
    },
    LoopCase {
        name: "wg_seedadd",
        arity: 2,
        c_source: "long long wg_seedadd(long long a, long long n){ long long r = a; long long i = 0; while (i != n) { r += (r * 3) + i; i++; } return r; }",
    },
    LoopCase {
        name: "wg_seedor",
        arity: 2,
        c_source: "long long wg_seedor(long long a, long long n){ long long r = a; long long i = 0; while (i != n) { r += (r | 1) + i; i++; } return r; }",
    },
    LoopCase {
        name: "wg_seedsub",
        arity: 2,
        c_source: "long long wg_seedsub(long long a, long long n){ long long r = a; long long i = 0; while (i != n) { r += (r - i); i++; } return r; }",
    },
    LoopCase {
        name: "wg_prod",
        arity: 2,
        c_source: "long long wg_prod(long long a, long long n){ long long r = 1; long long i = 0; while (i != n) { r *= a; i++; } return r; }",
    },
];

fn build_zero_trip_driver(recovered_decls: &str, driver_body: &str) -> String {
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n{recovered_decls}\n\
         int main(void) {{\n\
         \x20   long long trips[][2] = {{\n\
         \x20       {{0,0}},{{5,0}},{{0,3}},{{0,1}},{{7,0}},\n\
         \x20       {{1,1}},{{2,2}},{{3,3}},{{4,1}},{{7,4}},{{9,6}},\n\
         \x20       {{11,2}},{{16,8}},{{20,13}},{{33,21}},{{6,12}}\n\
         \x20   }};\n\
         \x20   size_t n_trips = sizeof(trips)/sizeof(trips[0]);\n\
         {driver_body}\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n"
    )
}

fn guarded_while_recovered(
    case: &LoopCase,
    object_bytes: &[u8],
) -> Option<(LeafRecovery, String, String)> {
    let (recovery, renamed, recovered_name): (LeafRecovery, String, String) =
        loop_lift(case, object_bytes)?;
    let is_guarded: bool = recovery.lifted_loop
        && recovery
            .source
            .find("if (")
            .zip(recovery.source.find("do {"))
            .is_some_and(|(g, d): (usize, usize)| g < d);
    if is_guarded {
        Some((recovery, renamed, recovered_name))
    } else {
        eprintln!(
            "note {}: gcc did not emit the in-line top-guarded while idiom this build",
            case.name
        );
        None
    }
}

#[test]
fn top_guarded_while_loops_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!(
            "skipping guarded-while oracle: gcc (needed for the rotated while idiom) not on PATH"
        );
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let mut battery_src: String = String::new();
    for case in GUARDED_WHILE_BATTERY {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let battery_c: PathBuf = dir.join("wg_battery.c");
    std::fs::write(&battery_c, battery_src.as_bytes()).expect("write wg_battery.c");
    let battery_o: PathBuf = dir.join("wg_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args([
            "-O1",
            "-fno-stack-protector",
            "-fno-if-conversion",
            "-fno-if-conversion2",
            "-fno-tree-loop-if-convert",
            "-c",
            "-o",
        ])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke gcc for wg battery");
    assert!(
        compile_battery.status.success(),
        "wg battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read wg_battery.o");

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    let mut guarded_count: usize = 0;

    for case in GUARDED_WHILE_BATTERY {
        let Some((recovery, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
            guarded_while_recovered(case, &object_bytes)
        else {
            continue;
        };
        guarded_count += 1;
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        let _ = writeln!(
            recovered_decls,
            "extern long long {}({});",
            case.name,
            vec!["long long"; case.arity].join(", ")
        );
        driver_body.push_str(&loop_driver_snippet(case, &recovery, &recovered_name));
        lifted_count += 1;
    }

    if lifted_count == 0 {
        eprintln!(
            "skipping guarded-while behavioral differential: this compiler build reconstructed no top-guarded while loop from the {} battery cases ({guarded_count} guarded)",
            GUARDED_WHILE_BATTERY.len()
        );
        return;
    }

    let driver: String = build_zero_trip_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("wg_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write wg_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "wg_harness.exe"
    } else {
        "wg_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke gcc to link wg harness");
    assert!(
        link.status.success(),
        "wg harness link failed: {}\n--- wg_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: BoundedRun = run_bounded(&harness_exe, 20);
    let BoundedRun::Exited(out): BoundedRun = run else {
        panic!(
            "guarded-while harness did not terminate within the watchdog window; a recovered loop is non-terminating"
        );
    };
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("OK"),
        "guarded-while behavioral differential FAILED ({lifted_count} cases, {guarded_count} guarded): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    println!(
        "top-guarded-while behavioral differential PASSED for {lifted_count} leaf functions ({guarded_count} guarded zero-trip loops, MS x64 ABI)"
    );
}

#[test]
fn guarded_while_oracle_has_teeth_dropping_the_guard_diverges_on_zero_trip() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!("skipping guarded-while teeth check: gcc not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let probe: LoopCase = LoopCase {
        name: "wg_count",
        arity: 1,
        c_source: GUARDED_WHILE_BATTERY[0].c_source,
    };
    let battery_c: PathBuf = dir.join("wg_teeth_battery.c");
    std::fs::write(&battery_c, probe.c_source.as_bytes()).expect("write wg_teeth_battery.c");
    let battery_o: PathBuf = dir.join("wg_teeth_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args([
            "-O1",
            "-fno-stack-protector",
            "-fno-if-conversion",
            "-fno-if-conversion2",
            "-fno-tree-loop-if-convert",
            "-c",
            "-o",
        ])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke gcc for wg teeth battery");
    assert!(
        compile_battery.status.success(),
        "wg teeth battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read wg_teeth_battery.o");

    let Some((recovery, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
        guarded_while_recovered(&probe, &object_bytes)
    else {
        eprintln!(
            "skipping guarded-while teeth check: this compiler build did not reconstruct a top-guarded while to corrupt"
        );
        return;
    };
    let Some(if_line): Option<&str> = renamed
        .lines()
        .find(|l: &&str| l.trim_start().starts_with("if ("))
    else {
        eprintln!(
            "skipping guarded-while teeth check: no reconstructed guard line to neutralize on this build"
        );
        return;
    };
    let stripped_guard: String = renamed.replacen(if_line, "    if (1) {", 1);
    if stripped_guard == renamed {
        eprintln!(
            "skipping guarded-while teeth check: neutralizing the guard was a no-op on this build's reconstruction"
        );
        return;
    }

    let mut decls: String = stripped_guard;
    decls.push('\n');
    let _ = writeln!(decls, "extern long long {}(long long);", probe.name);
    let snippet: String = loop_driver_snippet(&probe, &recovery, &recovered_name);
    let driver: String = build_zero_trip_driver(&decls, &snippet);
    let driver_c: PathBuf = dir.join("wg_teeth_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write wg_teeth_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "wg_teeth_harness.exe"
    } else {
        "wg_teeth_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke gcc to link wg teeth harness");
    assert!(
        link.status.success(),
        "wg teeth harness link failed: {}\n--- wg_teeth_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    match run_bounded(&harness_exe, 10) {
        BoundedRun::Exited(out) => {
            let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&out.stdout);
            assert!(
                !stdout.contains("OK") && stdout.contains("MISMATCH"),
                "teeth check FAILED: forcing the zero-trip guard always-true must diverge from the original, got: {stdout}"
            );
            println!(
                "guarded-while oracle teeth confirmed: neutralizing the guard diverges on the zero-trip input (MISMATCH observed)"
            );
        }
        BoundedRun::TimedOut => {
            println!(
                "guarded-while oracle teeth confirmed: neutralizing the guard diverges (corrupted loop did not terminate)"
            );
        }
    }
}

const WIDTH_EXT_BATTERY: &[Case] = &[
    Case {
        name: "x_zext16",
        arity: 1,
        c_source: "long long x_zext16(long long a){ return (long long)(unsigned short)a + 1; }",
    },
    Case {
        name: "x_sext8",
        arity: 1,
        c_source: "long long x_sext8(long long a){ return (long long)(signed char)a * 3; }",
    },
    Case {
        name: "x_uchar",
        arity: 1,
        c_source: "long long x_uchar(long long a){ return (long long)(unsigned char)a ^ 0x5a; }",
    },
    Case {
        name: "x_short2",
        arity: 2,
        c_source: "long long x_short2(long long a, long long b){ return (long long)(short)a + (long long)(short)b; }",
    },
    Case {
        name: "x_cdqe",
        arity: 2,
        c_source: "long long x_cdqe(long long a, long long b){ int s = (int)a + (int)b; return (long long)s + 100; }",
    },
    Case {
        name: "x_shl",
        arity: 1,
        c_source: "long long x_shl(long long a){ return (long long)((int)a << 2); }",
    },
    Case {
        name: "x_sxd",
        arity: 1,
        c_source: "long long x_sxd(long long a){ return (long long)(int)a; }",
    },
    Case {
        name: "x_zxmix",
        arity: 2,
        c_source: "long long x_zxmix(long long a, long long b){ unsigned char x = (unsigned char)a; unsigned short y = (unsigned short)b; return (long long)x + (long long)y; }",
    },
];

fn recovered_has_width_extension(object_bytes: &[u8], name: &str) -> bool {
    let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(object_bytes, name) else {
        return false;
    };
    let recovery: LeafRecovery = match recover_leaf_function_abi(&code, base, HOST_ABI) {
        Ok(r) => r,
        Err(_) => return false,
    };
    recovery.source.contains("(int8_t)")
        || recovery.source.contains("(int16_t)")
        || recovery.source.contains("(int32_t)(")
        || recovery.source.contains("(uint8_t)(")
        || recovery.source.contains("(uint16_t)(")
}

#[test]
fn width_extension_leaf_functions_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!(
            "skipping width-extension oracle: gcc (needed for the movzx/movsx/cdqe idioms) not on PATH"
        );
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let mut battery_src: String = String::new();
    for case in WIDTH_EXT_BATTERY {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let battery_c: PathBuf = dir.join("wx_battery.c");
    std::fs::write(&battery_c, battery_src.as_bytes()).expect("write wx_battery.c");
    let battery_o: PathBuf = dir.join("wx_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args([
            "-O1",
            "-fno-stack-protector",
            "-fno-if-conversion",
            "-fno-if-conversion2",
            "-fno-tree-loop-if-convert",
            "-c",
            "-o",
        ])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke gcc for wx battery");
    assert!(
        compile_battery.status.success(),
        "wx battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read wx_battery.o");

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    let mut ext_count: usize = 0;

    for case in WIDTH_EXT_BATTERY {
        if recovered_has_width_extension(&object_bytes, case.name) {
            ext_count += 1;
        } else {
            eprintln!(
                "note {}: gcc did not emit a width-extension this build",
                case.name
            );
        }
        let Some(lifted): Option<Lifted> = process_case(case, &object_bytes, HOST_ABI) else {
            continue;
        };
        recovered_decls.push_str(&lifted.decls);
        driver_body.push_str(&lifted.driver_snippet);
        lifted_count += 1;
    }

    if lifted_count == 0 {
        eprintln!(
            "skipping width-extension behavioral differential: this compiler build lowered none of the {} battery cases into the leaf class ({ext_count} extension casts)",
            WIDTH_EXT_BATTERY.len()
        );
        return;
    }

    let driver: String = build_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("wx_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write wx_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "wx_harness.exe"
    } else {
        "wx_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke gcc to link wx harness");
    assert!(
        link.status.success(),
        "wx harness link failed: {}\n--- wx_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe).output().expect("run wx harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "width-extension behavioral differential FAILED ({lifted_count} cases, {ext_count} ext): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "width-extension behavioral differential PASSED for {lifted_count} leaf functions ({ext_count} movzx/movsx/cdqe casts, MS x64 ABI)"
    );
}

#[test]
fn width_extension_oracle_has_teeth_flipping_sign_to_zero_extend_diverges() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!("skipping width-extension teeth check: gcc not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let probe: Case = Case {
        name: "x_sext8",
        arity: 1,
        c_source: WIDTH_EXT_BATTERY[1].c_source,
    };
    let battery_c: PathBuf = dir.join("wx_teeth_battery.c");
    std::fs::write(&battery_c, probe.c_source.as_bytes()).expect("write wx_teeth_battery.c");
    let battery_o: PathBuf = dir.join("wx_teeth_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args([
            "-O1",
            "-fno-stack-protector",
            "-fno-if-conversion",
            "-fno-if-conversion2",
            "-fno-tree-loop-if-convert",
            "-c",
            "-o",
        ])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke gcc for wx teeth battery");
    assert!(
        compile_battery.status.success(),
        "wx teeth battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read wx_teeth_battery.o");

    let Some(lifted): Option<Lifted> = process_case(&probe, &object_bytes, HOST_ABI) else {
        eprintln!(
            "skipping width-extension teeth check: this compiler build did not lower the probe into the leaf class"
        );
        return;
    };
    if !lifted.decls.contains("(int64_t)(int8_t)") {
        eprintln!(
            "skipping width-extension teeth check: this compiler build did not reconstruct a signed byte extension to corrupt"
        );
        return;
    }

    let corrupted: String = lifted
        .decls
        .replacen("(int64_t)(int8_t)", "(uint64_t)(uint8_t)", 1);
    assert_ne!(
        corrupted, lifted.decls,
        "teeth corruption must flip the sign-extend to a zero-extend: {}",
        lifted.decls
    );

    let driver: String = build_driver(&corrupted, &lifted.driver_snippet);
    let driver_c: PathBuf = dir.join("wx_teeth_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write wx_teeth_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "wx_teeth_harness.exe"
    } else {
        "wx_teeth_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke gcc to link wx teeth harness");
    assert!(
        link.status.success(),
        "wx teeth harness link failed: {}\n--- wx_teeth_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run wx teeth harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        !stdout.contains("OK") && stdout.contains("MISMATCH"),
        "teeth check FAILED: flipping the sign-extend to a zero-extend must diverge on negative bytes, got: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "width-extension oracle teeth confirmed: zero-extending a signed byte diverges on negative inputs (MISMATCH observed)"
    );
}

struct CallCase {
    caller: &'static str,
    arity: usize,
    c_source: &'static str,
}

const CALL_BATTERY: &[CallCase] = &[
    CallCase {
        caller: "k_sq",
        arity: 1,
        c_source: "__attribute__((noinline,noclone)) long long h_sq(long long x){ return x * x; }\n\
                   long long k_sq(long long a){ return h_sq(a) + 1; }",
    },
    CallCase {
        caller: "k_addmul",
        arity: 2,
        c_source: "__attribute__((noinline,noclone)) long long h_add(long long a, long long b){ return a + b; }\n\
                   long long k_addmul(long long a, long long b){ return h_add(a, b) * 2; }",
    },
    CallCase {
        caller: "k_lin",
        arity: 3,
        c_source: "__attribute__((noinline,noclone)) long long h_lin(long long a, long long b){ return a * 3 + b; }\n\
                   long long k_lin(long long a, long long b, long long c){ return h_lin(a, b) + c; }",
    },
    CallCase {
        caller: "k_clampmax",
        arity: 2,
        c_source: "__attribute__((noinline,noclone)) long long h_max(long long a, long long b){ return a > b ? a : b; }\n\
                   long long k_clampmax(long long a, long long b){ return h_max(a, b) + 7; }",
    },
    CallCase {
        caller: "k_xormix",
        arity: 2,
        c_source: "__attribute__((noinline,noclone)) long long h_xor(long long a, long long b){ return (a ^ b) + 5; }\n\
                   long long k_xormix(long long a, long long b){ return h_xor(a, b) ^ 0x3f; }",
    },
    CallCase {
        caller: "k_savearg",
        arity: 3,
        c_source: "__attribute__((noinline,noclone)) long long h_diff(long long a, long long b){ return a - b; }\n\
                   long long k_savearg(long long a, long long b, long long c){ return h_diff(a, b) + c * 11; }",
    },
    CallCase {
        caller: "k_negret",
        arity: 1,
        c_source: "__attribute__((noinline,noclone)) long long h_id(long long a){ return a + 100; }\n\
                   long long k_negret(long long a){ return -h_id(a); }",
    },
];

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

fn rename_recovered(source: &str, new_name: &str) -> String {
    source
        .replacen("uint64_t recovered(", &format!("uint64_t {new_name}("), 1)
        .lines()
        .filter(|l: &&str| !l.starts_with("#include"))
        .collect::<Vec<&str>>()
        .join("\n")
}

fn pad_callee_signature(renamed: &str, name: &str, full_arity: usize) -> String {
    let needle: String = format!("uint64_t {name}(");
    let Some(open): Option<usize> = renamed.find(&needle) else {
        return renamed.to_owned();
    };
    let args_start: usize = open + needle.len();
    let Some(rel_close): Option<usize> = renamed[args_start..].find(')') else {
        return renamed.to_owned();
    };
    let close: usize = args_start + rel_close;
    let existing: &str = renamed[args_start..close].trim();
    let current: usize = if existing.is_empty() || existing == "void" {
        0
    } else {
        existing.matches(',').count() + 1
    };
    let mut params: Vec<String> = Vec::new();
    if !(existing.is_empty() || existing == "void") {
        params.push(existing.to_owned());
    }
    for i in current..full_arity {
        params.push(format!("uint64_t pad{i}"));
    }
    let new_sig: String = params.join(", ");
    format!("{}{}{}", &renamed[..args_start], new_sig, &renamed[close..])
}

fn build_call_driver(recovered_decls: &str, driver_body: &str) -> String {
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n{recovered_decls}\n\
         int main(void) {{\n\
         \x20   long long inputs[][3] = {{\n\
         \x20       {{0,0,0}},{{1,1,1}},{{-1,-1,-1}},{{7,3,5}},{{-7,3,-5}},\n\
         \x20       {{123456,-654321,99}},{{2147483647,1,2}},{{-2147483648,-1,-2}},\n\
         \x20       {{0x7fffffffffffffffLL,2,3}},{{100,200,300}},{{-100,50,-25}},\n\
         \x20       {{1<<20,1<<10,1<<5}},{{42,42,42}},{{0xdeadbeef,0xcafef00d,0x1234}}\n\
         \x20   }};\n\
         \x20   size_t n_inputs = sizeof(inputs)/sizeof(inputs[0]);\n\
         {driver_body}\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n"
    )
}

fn lift_call_case(case: &CallCase, object_bytes: &[u8]) -> Option<(String, String, usize)> {
    let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(object_bytes, case.caller)
    else {
        eprintln!("skip {}: caller symbol not located", case.caller);
        return None;
    };
    let recovery: LeafRecovery = match recover_leaf_function_abi(&code, base, HOST_ABI) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("skip {}: caller not in call leaf class ({e})", case.caller);
            return None;
        }
    };
    if recovery.call_targets.is_empty() {
        eprintln!("skip {}: no call lifted", case.caller);
        return None;
    }
    let full_arity: usize = recovery.params.len();
    let mut decls: String = String::new();
    let mut seen: Vec<u64> = Vec::new();
    for target in &recovery.call_targets {
        if seen.contains(target) {
            continue;
        }
        seen.push(*target);
        let Some((callee_code, callee_base, _)): Option<(Vec<u8>, u64, String)> =
            function_code_at(object_bytes, *target)
        else {
            eprintln!("skip {}: callee at {target:#x} not located", case.caller);
            return None;
        };
        let callee: LeafRecovery =
            match recover_leaf_function_abi(&callee_code, callee_base, HOST_ABI) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("skip {}: callee not in leaf class ({e})", case.caller);
                    return None;
                }
            };
        let callee_name: String = format!("sub_{target:x}");
        let callee_renamed: String = rename_recovered(&callee.source, &callee_name);
        let callee_padded: String = pad_callee_signature(&callee_renamed, &callee_name, full_arity);
        decls.push_str(&callee_padded);
        decls.push('\n');
    }
    let caller_name: String = format!("rec_{}", case.caller);
    let caller_renamed: String = rename_recovered(&recovery.source, &caller_name);
    decls.push_str(&caller_renamed);
    decls.push('\n');
    let _ = writeln!(
        decls,
        "extern long long {}({});",
        case.caller,
        vec!["long long"; case.arity].join(", ")
    );

    let args: Vec<String> = (0..case.arity).map(|i: usize| format!("in[{i}]")).collect();
    let rec_args: Vec<String> = (0..full_arity)
        .map(|i: usize| format!("(uint64_t)in[{i}]"))
        .collect();
    let mut snippet: String = String::new();
    let _ = write!(
        snippet,
        "    for (size_t k = 0; k < n_inputs; k++) {{\n\
         \x20       long long in[3] = {{ inputs[k][0], inputs[k][1], inputs[k][2] }};\n\
         \x20       unsigned long long want = (unsigned long long){}({});\n\
         \x20       unsigned long long got = {caller_name}({});\n\
         \x20       if (want != got) {{ printf(\"MISMATCH {} in=%lld,%lld,%lld want=%llu got=%llu\\n\", in[0], in[1], in[2], want, got); return 1; }}\n\
         \x20   }}\n",
        case.caller,
        args.join(", "),
        rec_args.join(", "),
        case.caller,
    );
    Some((decls, snippet, full_arity))
}

#[test]
fn same_object_call_leaf_functions_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!("skipping call oracle: gcc (needed for the noinline call idiom) not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let mut battery_src: String = String::new();
    for case in CALL_BATTERY {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let battery_c: PathBuf = dir.join("call_battery.c");
    std::fs::write(&battery_c, battery_src.as_bytes()).expect("write call_battery.c");
    let battery_o: PathBuf = dir.join("call_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args([
            "-O1",
            "-fno-stack-protector",
            "-fno-optimize-sibling-calls",
            "-fno-if-conversion",
            "-fno-if-conversion2",
            "-fno-tree-loop-if-convert",
            "-c",
            "-o",
        ])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke gcc for call battery");
    assert!(
        compile_battery.status.success(),
        "call battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read call_battery.o");

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;

    for case in CALL_BATTERY {
        let Some((decls, snippet, _)): Option<(String, String, usize)> =
            lift_call_case(case, &object_bytes)
        else {
            continue;
        };
        recovered_decls.push_str(&decls);
        driver_body.push_str(&snippet);
        lifted_count += 1;
    }

    if lifted_count == 0 {
        eprintln!(
            "skipping call behavioral differential: this compiler build reconstructed none of the {} caller/helper pairs into the call leaf class",
            CALL_BATTERY.len()
        );
        return;
    }

    let driver: String = build_call_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("call_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write call_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "call_harness.exe"
    } else {
        "call_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke gcc to link call harness");
    assert!(
        link.status.success(),
        "call harness link failed: {}\n--- call_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run call harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "call behavioral differential FAILED ({lifted_count} cases): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "same-object-call behavioral differential PASSED for {lifted_count} caller/helper pairs (MS x64 ABI)"
    );
}

#[test]
fn call_oracle_has_teeth_dropping_the_helper_call_diverges() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!("skipping call teeth check: gcc not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let probe: CallCase = CallCase {
        caller: CALL_BATTERY[0].caller,
        arity: CALL_BATTERY[0].arity,
        c_source: CALL_BATTERY[0].c_source,
    };
    let battery_c: PathBuf = dir.join("call_teeth_battery.c");
    std::fs::write(&battery_c, probe.c_source.as_bytes()).expect("write call_teeth_battery.c");
    let battery_o: PathBuf = dir.join("call_teeth_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args([
            "-O1",
            "-fno-stack-protector",
            "-fno-optimize-sibling-calls",
            "-c",
            "-o",
        ])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke gcc for call teeth battery");
    assert!(
        compile_battery.status.success(),
        "call teeth battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read call_teeth_battery.o");

    let Some((decls, snippet, _)): Option<(String, String, usize)> =
        lift_call_case(&probe, &object_bytes)
    else {
        eprintln!(
            "skipping call teeth check: this compiler build did not reconstruct the caller/helper pair into the call leaf class"
        );
        return;
    };
    if !decls.contains("sub_") {
        eprintln!(
            "skipping call teeth check: this compiler build did not reconstruct a helper call to neutralize"
        );
        return;
    }

    let Some(callee_open): Option<usize> = decls.find("r_rax = sub_") else {
        eprintln!(
            "skipping call teeth check: this compiler build did not lower the helper call into the r_rax = sub_ idiom this check corrupts"
        );
        return;
    };
    let semicolon: usize = decls[callee_open..]
        .find(';')
        .map(|p: usize| p + callee_open)
        .expect("call statement terminator");
    let corrupted: String = format!(
        "{}r_rax = r_rcx{}",
        &decls[..callee_open],
        &decls[semicolon..]
    );
    assert_ne!(
        corrupted, decls,
        "teeth corruption must neutralize the helper call: {decls}"
    );

    let driver: String = build_call_driver(&corrupted, &snippet);
    let driver_c: PathBuf = dir.join("call_teeth_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write call_teeth_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "call_teeth_harness.exe"
    } else {
        "call_teeth_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke gcc to link call teeth harness");
    assert!(
        link.status.success(),
        "call teeth harness link failed: {}\n--- call_teeth_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run call teeth harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        !stdout.contains("OK") && stdout.contains("MISMATCH"),
        "teeth check FAILED: replacing the helper call with a passthrough must diverge, got: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "call oracle teeth confirmed: dropping the helper call diverges from the original (MISMATCH observed)"
    );
}

fn resolve_calls(
    object_bytes: &[u8],
    caller: &str,
    targets: &[u64],
    abi: PseudoAbi,
) -> Option<Vec<ResolvedCall>> {
    let mut out: Vec<ResolvedCall> = Vec::new();
    let mut seen: Vec<u64> = Vec::new();
    for &target in targets {
        if seen.contains(&target) {
            continue;
        }
        seen.push(target);
        let (code, base, name): (Vec<u8>, u64, String) = function_code_at(object_bytes, target)
            .or_else(|| {
                let resolved: String = elf_call_callee_for_target(object_bytes, caller, target)?;
                let (code, base): (Vec<u8>, u64) = function_code(object_bytes, &resolved)?;
                Some((code, base, resolved))
            })?;
        let arg_count: usize = callee_int_arity(&code, base, abi)?;
        out.push(ResolvedCall {
            target,
            name: Some(name),
            arg_count,
        });
    }
    Some(out)
}

fn lift_precise_call_case(
    case: &CallCase,
    object_bytes: &[u8],
    abi: PseudoAbi,
) -> Option<(String, String)> {
    let (code, base): (Vec<u8>, u64) = function_code(object_bytes, case.caller)?;
    let base_rec: LeafRecovery = match recover_leaf_function_abi(&code, base, abi) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("skip {}: caller not in call leaf class ({e})", case.caller);
            return None;
        }
    };
    if base_rec.call_targets.is_empty() {
        eprintln!("skip {}: no call lifted", case.caller);
        return None;
    }
    let resolved: Vec<ResolvedCall> =
        resolve_calls(object_bytes, case.caller, &base_rec.call_targets, abi)?;
    let rec: LeafRecovery = recover_leaf_function_with_calls(&code, base, abi, &resolved).ok()?;
    if rec.params.len() > 3 {
        eprintln!(
            "skip {}: recovered arity beyond 3-input driver",
            case.caller
        );
        return None;
    }
    let recovered_name: String = format!("rec_{}", case.caller);
    let renamed: String = rename_recovered(&rec.source, &recovered_name);
    let mut decls: String = String::new();
    decls.push_str(&renamed);
    decls.push('\n');
    let _ = writeln!(
        decls,
        "extern long long {}({});",
        case.caller,
        vec!["long long"; case.arity].join(", ")
    );

    let args: Vec<String> = (0..case.arity).map(|i: usize| format!("in[{i}]")).collect();
    let rec_args: Vec<String> = (0..rec.params.len())
        .map(|i: usize| format!("(uint64_t)in[{i}]"))
        .collect();
    let mut snippet: String = String::new();
    let _ = write!(
        snippet,
        "    for (size_t k = 0; k < n_inputs; k++) {{\n\
         \x20       long long in[3] = {{ inputs[k][0], inputs[k][1], inputs[k][2] }};\n\
         \x20       unsigned long long want = (unsigned long long){}({});\n\
         \x20       unsigned long long got = {recovered_name}({});\n\
         \x20       if (want != got) {{ printf(\"MISMATCH {} in=%lld,%lld,%lld want=%llu got=%llu\\n\", in[0], in[1], in[2], want, got); return 1; }}\n\
         \x20   }}\n",
        case.caller,
        args.join(", "),
        rec_args.join(", "),
        case.caller,
    );
    Some((decls, snippet))
}

#[test]
fn precise_call_recovery_recompiles_against_real_helpers() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!("skipping precise call oracle: gcc not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let mut battery_src: String = String::new();
    for case in CALL_BATTERY {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let battery_c: PathBuf = dir.join("precise_call_battery.c");
    std::fs::write(&battery_c, battery_src.as_bytes()).expect("write precise_call_battery.c");
    let battery_o: PathBuf = dir.join("precise_call_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args([
            "-O1",
            "-fno-stack-protector",
            "-fno-optimize-sibling-calls",
            "-fno-if-conversion",
            "-fno-if-conversion2",
            "-fno-tree-loop-if-convert",
            "-c",
            "-o",
        ])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke gcc for precise call battery");
    assert!(
        compile_battery.status.success(),
        "precise call battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read precise_call_battery.o");

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;

    for case in CALL_BATTERY {
        let Some((decls, snippet)): Option<(String, String)> =
            lift_precise_call_case(case, &object_bytes, HOST_ABI)
        else {
            continue;
        };
        recovered_decls.push_str(&decls);
        driver_body.push_str(&snippet);
        lifted_count += 1;
    }

    if lifted_count == 0 {
        eprintln!(
            "skipping precise call differential: this compiler build reconstructed none of the {} caller/helper pairs",
            CALL_BATTERY.len()
        );
        return;
    }
    assert!(
        recovered_decls.contains("extern uint64_t h_sq(uint64_t);")
            && recovered_decls.contains("r_rax = h_sq("),
        "the callee must be named from its symbol and declared with its recovered single-argument arity: {recovered_decls}"
    );
    assert!(
        !recovered_decls.contains("sub_"),
        "every same-object helper resolves to a symbol, so no synthetic sub_<va> name should remain: {recovered_decls}"
    );

    let driver: String = build_call_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("precise_call_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write precise_call_driver.c");

    let harness_exe: PathBuf = dir.join("precise_call_harness.exe");
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke gcc to link precise call harness");
    assert!(
        link.status.success(),
        "precise call harness link failed: {}\n--- precise_call_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run precise call harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "precise call differential FAILED ({lifted_count} cases): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "precise call recovery (symbol-named, callee-arity args) recompiled against the REAL helpers PASSED for {lifted_count} caller/helper pairs (MS x64 ABI)"
    );
}

const IF_IN_LOOP_BATTERY: &[LoopCase] = &[
    LoopCase {
        name: "il_sumeven",
        arity: 1,
        c_source: "long long il_sumeven(long long n){ long long s = 0; long long i = 0; while (i < n) { if ((i & 1) == 0) s += i; i++; } return s; }",
    },
    LoopCase {
        name: "il_continue",
        arity: 1,
        c_source: "long long il_continue(long long n){ long long s = 0; long long i = 0; while (i < n) { i++; if ((i & 3) == 0) continue; s += i; } return s; }",
    },
    LoopCase {
        name: "il_rotsum",
        arity: 1,
        c_source: "long long il_rotsum(long long n){ long long s = 0; for (long long i = 0; i < n; i++) s += i; return s; }",
    },
    LoopCase {
        name: "il_branchacc",
        arity: 2,
        c_source: "long long il_branchacc(long long a, long long n){ long long r = 0; long long i = 0; while (i < n) { if (i > a) r += i; else r -= i; i++; } return r; }",
    },
    LoopCase {
        name: "il_clampsum",
        arity: 2,
        c_source: "long long il_clampsum(long long a, long long n){ long long r = 0; long long i = 0; while (i < n) { long long v = a + i; if (v > 100) v = 100; r += v; i++; } return r; }",
    },
    LoopCase {
        name: "il_maskcount",
        arity: 1,
        c_source: "long long il_maskcount(long long n){ long long c = 0; long long i = 0; while (i < n) { if ((i & 7) != 0) c++; i++; } return c; }",
    },
    LoopCase {
        name: "il_skipmul",
        arity: 2,
        c_source: "long long il_skipmul(long long a, long long n){ long long r = 1; long long i = 1; while (i < n) { if (i == a) { i++; continue; } r *= i; i++; } return r; }",
    },
    LoopCase {
        name: "il_forif",
        arity: 1,
        c_source: "long long il_forif(long long n){ long long r = 0; for (long long i = 0; i < n; i++) { if (i & 1) r += i; } return r; }",
    },
];

fn if_in_loop_recovered(
    case: &LoopCase,
    object_bytes: &[u8],
) -> Option<(LeafRecovery, String, String)> {
    let (recovery, renamed, recovered_name): (LeafRecovery, String, String) =
        loop_lift(case, object_bytes)?;
    let is_if_in_loop: bool = recovery.lifted_loop
        && recovery.source.contains("while (1) {")
        && recovery
            .source
            .find("while (1) {")
            .and_then(|w: usize| recovery.source[w..].find("if ("))
            .is_some();
    if is_if_in_loop {
        Some((recovery, renamed, recovered_name))
    } else {
        eprintln!(
            "note {}: gcc did not emit the rotated if-in-loop idiom this build",
            case.name
        );
        None
    }
}

#[test]
fn if_in_loop_leaf_functions_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!(
            "skipping if-in-loop oracle: gcc (needed for the rotated loop idiom) not on PATH"
        );
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let mut battery_src: String = String::new();
    for case in IF_IN_LOOP_BATTERY {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let battery_c: PathBuf = dir.join("il_battery.c");
    std::fs::write(&battery_c, battery_src.as_bytes()).expect("write il_battery.c");
    let battery_o: PathBuf = dir.join("il_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args([
            "-O1",
            "-fno-stack-protector",
            "-fno-if-conversion",
            "-fno-if-conversion2",
            "-fno-tree-loop-if-convert",
            "-c",
            "-o",
        ])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke gcc for il battery");
    assert!(
        compile_battery.status.success(),
        "il battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read il_battery.o");

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    let mut if_in_loop_count: usize = 0;

    for case in IF_IN_LOOP_BATTERY {
        let Some((recovery, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
            if_in_loop_recovered(case, &object_bytes)
        else {
            continue;
        };
        if_in_loop_count += 1;
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        let _ = writeln!(
            recovered_decls,
            "extern long long {}({});",
            case.name,
            vec!["long long"; case.arity].join(", ")
        );
        driver_body.push_str(&loop_driver_snippet(case, &recovery, &recovered_name));
        lifted_count += 1;
    }

    if lifted_count == 0 {
        eprintln!(
            "skipping if-in-loop behavioral differential: this compiler build reconstructed no rotated if-in-loop from the {} battery cases ({if_in_loop_count} if-in-loop)",
            IF_IN_LOOP_BATTERY.len()
        );
        return;
    }

    let driver: String = build_zero_trip_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("il_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write il_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "il_harness.exe"
    } else {
        "il_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke gcc to link il harness");
    assert!(
        link.status.success(),
        "il harness link failed: {}\n--- il_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: BoundedRun = run_bounded(&harness_exe, 20);
    let BoundedRun::Exited(out): BoundedRun = run else {
        panic!(
            "if-in-loop harness did not terminate within the watchdog window; a recovered loop is non-terminating"
        );
    };
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("OK"),
        "if-in-loop behavioral differential FAILED ({lifted_count} cases, {if_in_loop_count} if-in-loop): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    println!(
        "if-in-loop behavioral differential PASSED for {lifted_count} leaf functions ({if_in_loop_count} rotated if-in-loop, MS x64 ABI)"
    );
}

#[test]
fn if_in_loop_oracle_has_teeth_dropping_the_inner_guard_diverges() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!("skipping if-in-loop teeth check: gcc not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let probe: LoopCase = LoopCase {
        name: "il_sumeven",
        arity: 1,
        c_source: IF_IN_LOOP_BATTERY[0].c_source,
    };
    let battery_c: PathBuf = dir.join("il_teeth_battery.c");
    std::fs::write(&battery_c, probe.c_source.as_bytes()).expect("write il_teeth_battery.c");
    let battery_o: PathBuf = dir.join("il_teeth_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args([
            "-O1",
            "-fno-stack-protector",
            "-fno-if-conversion",
            "-fno-if-conversion2",
            "-fno-tree-loop-if-convert",
            "-c",
            "-o",
        ])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke gcc for il teeth battery");
    assert!(
        compile_battery.status.success(),
        "il teeth battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read il_teeth_battery.o");

    let Some((recovery, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
        if_in_loop_recovered(&probe, &object_bytes)
    else {
        eprintln!(
            "skipping if-in-loop teeth check: this compiler build did not reconstruct a rotated if-in-loop to corrupt"
        );
        return;
    };
    let Some(guard_line): Option<&str> = renamed
        .lines()
        .find(|l: &&str| l.trim_start().starts_with("if (") && l.contains("0x1ULL"))
    else {
        eprintln!(
            "skipping if-in-loop teeth check: this compiler build did not emit the inner even-mask guard this check corrupts"
        );
        return;
    };
    let indent: &str = &guard_line[..guard_line.len() - guard_line.trim_start().len()];
    let neutralized: String = format!("{indent}if (1) {{");
    let corrupted: String = renamed.replacen(guard_line, &neutralized, 1);
    if corrupted == renamed {
        eprintln!(
            "skipping if-in-loop teeth check: neutralizing the inner even-mask guard was a no-op on this build"
        );
        return;
    }

    let mut decls: String = corrupted;
    decls.push('\n');
    let _ = writeln!(decls, "extern long long {}(long long);", probe.name);
    let snippet: String = loop_driver_snippet(&probe, &recovery, &recovered_name);
    let driver: String = build_zero_trip_driver(&decls, &snippet);
    let driver_c: PathBuf = dir.join("il_teeth_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write il_teeth_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "il_teeth_harness.exe"
    } else {
        "il_teeth_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke gcc to link il teeth harness");
    assert!(
        link.status.success(),
        "il teeth harness link failed: {}\n--- il_teeth_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    match run_bounded(&harness_exe, 10) {
        BoundedRun::Exited(out) => {
            let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&out.stdout);
            assert!(
                !stdout.contains("OK") && stdout.contains("MISMATCH"),
                "teeth check FAILED: forcing the inner even-mask guard always-true must diverge, got: {stdout}"
            );
            println!(
                "if-in-loop oracle teeth confirmed: neutralizing the inner guard diverges (MISMATCH observed)"
            );
        }
        BoundedRun::TimedOut => {
            println!(
                "if-in-loop oracle teeth confirmed: neutralizing the inner guard diverges (corrupted loop did not terminate)"
            );
        }
    }
}

struct PtrLoopCase {
    name: &'static str,
    elem_ty: &'static str,
    n_elems: usize,
    n_scalars: usize,
    c_source: &'static str,
}

const PTR_LOOP_BATTERY: &[PtrLoopCase] = &[
    PtrLoopCase {
        name: "pl_countmatch",
        elem_ty: "long long",
        n_elems: 8,
        n_scalars: 2,
        c_source: "long long pl_countmatch(long long *p, long long n, long long t){ long long c = 0; long long i = 0; while (i < n) { if (p[i] == t) c++; i++; } return c; }",
    },
    PtrLoopCase {
        name: "pl_sumpos",
        elem_ty: "long long",
        n_elems: 8,
        n_scalars: 1,
        c_source: "long long pl_sumpos(long long *p, long long n){ long long s = 0; long long i = 0; while (i < n) { if (p[i] > 0) s += p[i]; i++; } return s; }",
    },
    PtrLoopCase {
        name: "pl_maxscan",
        elem_ty: "long long",
        n_elems: 8,
        n_scalars: 1,
        c_source: "long long pl_maxscan(long long *p, long long n){ long long m = p[0]; long long i = 1; while (i < n) { if (p[i] > m) m = p[i]; i++; } return m; }",
    },
];

#[test]
fn pointer_walk_if_in_loop_recompiles_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!("skipping pointer-walk if-in-loop oracle: gcc not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let mut battery_src: String = String::new();
    for case in PTR_LOOP_BATTERY {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let battery_c: PathBuf = dir.join("pl_battery.c");
    std::fs::write(&battery_c, battery_src.as_bytes()).expect("write pl_battery.c");
    let battery_o: PathBuf = dir.join("pl_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args([
            "-O1",
            "-fno-stack-protector",
            "-fno-if-conversion",
            "-fno-if-conversion2",
            "-fno-tree-loop-if-convert",
            "-c",
            "-o",
        ])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke gcc for pl battery");
    assert!(
        compile_battery.status.success(),
        "pl battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read pl_battery.o");

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;

    for case in PTR_LOOP_BATTERY {
        let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(&object_bytes, case.name)
        else {
            eprintln!("skip {}: symbol not located", case.name);
            continue;
        };
        let recovery: LeafRecovery = match recover_leaf_function_abi(&code, base, HOST_ABI) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skip {}: not in pointer-loop class ({e})", case.name);
                continue;
            }
        };
        if !(recovery.lifted_loop && recovery.source.contains("while (1) {")) {
            eprintln!("note {}: no structured loop this build", case.name);
            continue;
        }
        let rec_arg_count: usize = recovery.params.len();
        if rec_arg_count == 0 || rec_arg_count > 1 + case.n_scalars {
            eprintln!("skip {}: arg mapping unsupported", case.name);
            continue;
        }
        let recovered_name: String = format!("rec_{}", case.name);
        let renamed: String = recovery
            .source
            .replacen(
                "uint64_t recovered(",
                &format!("uint64_t {recovered_name}("),
                1,
            )
            .lines()
            .filter(|l: &&str| !l.starts_with("#include"))
            .collect::<Vec<&str>>()
            .join("\n");
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        let _ = writeln!(
            recovered_decls,
            "extern long long {}({}*{});",
            case.name,
            case.elem_ty,
            ", long long".repeat(case.n_scalars)
        );

        let n: usize = case.n_elems;
        let elem_ty: &str = case.elem_ty;
        let mut scalar_args: Vec<String> = Vec::new();
        for s in 0..case.n_scalars {
            scalar_args.push(format!("scalars[{s}]"));
        }
        let orig_args: String = std::iter::once("buf".to_owned())
            .chain(scalar_args.iter().cloned())
            .collect::<Vec<String>>()
            .join(", ");
        let mut rec_args: Vec<String> = vec!["(uint64_t)(uintptr_t)buf".to_owned()];
        for s in 0..(rec_arg_count - 1) {
            rec_args.push(format!("(uint64_t)scalars[{s}]"));
        }
        let rec_call_args: String = rec_args.join(", ");
        let _ = write!(
            driver_body,
            "    for (size_t k = 0; k < n_seeds; k++) {{\n\
             \x20       {elem_ty} buf[{n}];\n\
             \x20       for (size_t e = 0; e < {n}; e++) {{ buf[e] = ({elem_ty})((seeds[k] * 31 + (long long)e * 7 - 11) % 17); }}\n\
             \x20       long long scalars[2] = {{ (seeds[k] % ({n} + 1)), (seeds[k] % 17) - 5 }};\n\
             \x20       unsigned long long want = (unsigned long long){}({orig_args});\n\
             \x20       unsigned long long got = {recovered_name}({rec_call_args});\n\
             \x20       if (want != got) {{ printf(\"MISMATCH {} seed=%lld want=%llu got=%llu\\n\", seeds[k], want, got); return 1; }}\n\
             \x20   }}\n",
            case.name, case.name,
        );
        lifted_count += 1;
    }

    if lifted_count == 0 {
        eprintln!(
            "skipping pointer-walk if-in-loop behavioral differential: this compiler build reconstructed none of the {} pointer-walk cases into a structured loop",
            PTR_LOOP_BATTERY.len()
        );
        return;
    }

    let driver: String = format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n{recovered_decls}\n\
         int main(void) {{\n\
         \x20   long long seeds[] = {{ 0, 1, -1, 2, 3, 5, 7, -3, 11, 13, -8, 21, 34, -19, 50 }};\n\
         \x20   size_t n_seeds = sizeof(seeds)/sizeof(seeds[0]);\n\
         {driver_body}\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n"
    );
    let driver_c: PathBuf = dir.join("pl_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write pl_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "pl_harness.exe"
    } else {
        "pl_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke gcc to link pl harness");
    assert!(
        link.status.success(),
        "pl harness link failed: {}\n--- pl_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: BoundedRun = run_bounded(&harness_exe, 20);
    let BoundedRun::Exited(out): BoundedRun = run else {
        panic!("pointer-walk harness did not terminate within the watchdog window");
    };
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("OK"),
        "pointer-walk if-in-loop behavioral differential FAILED ({lifted_count} cases): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    println!(
        "pointer-walk if-in-loop behavioral differential PASSED for {lifted_count} leaf functions (MS x64 ABI)"
    );
}

fn battery_source(cases: &[Case]) -> String {
    let mut src: String = String::new();
    for case in cases {
        src.push_str(case.c_source);
        src.push('\n');
    }
    src
}

struct NestedLoopCase {
    name: &'static str,
    rows: usize,
    cols: usize,
    c_source: &'static str,
}

const NESTED_LOOP_BATTERY: &[NestedLoopCase] = &[
    NestedLoopCase {
        name: "nl_matsum",
        rows: 4,
        cols: 5,
        c_source: "long long nl_matsum(long long *p, long long rows, long long cols){ long long s = 0; long long r = 0; do { long long c = 0; do { s += p[r*cols + c]; c++; } while (c != cols); r++; } while (r != rows); return s; }",
    },
    NestedLoopCase {
        name: "nl_matxor",
        rows: 4,
        cols: 5,
        c_source: "long long nl_matxor(long long *p, long long rows, long long cols){ long long acc = 0; long long r = 0; do { long long c = 0; do { acc ^= (p[r*cols + c] + c); c++; } while (c != cols); r++; } while (r != rows); return acc; }",
    },
    NestedLoopCase {
        name: "nl_wmatsum",
        rows: 4,
        cols: 5,
        c_source: "long long nl_wmatsum(long long *p, long long rows, long long cols){ long long s = 0; long long r = 0; while (r < rows) { long long c = 0; while (c < cols) { s += p[r*cols + c]; c++; } r++; } return s; }",
    },
    NestedLoopCase {
        name: "nl_countge",
        rows: 4,
        cols: 5,
        c_source: "long long nl_countge(long long *p, long long rows, long long cols){ long long n = 0; long long r = 0; do { long long c = 0; do { if (p[r*cols + c] >= 0) n++; c++; } while (c != cols); r++; } while (r != rows); return n; }",
    },
    NestedLoopCase {
        name: "nl_rowmax",
        rows: 4,
        cols: 5,
        c_source: "long long nl_rowmax(long long *p, long long rows, long long cols){ long long best = 0; long long r = 0; do { long long rowsum = 0; long long c = 0; do { rowsum += p[r*cols + c]; c++; } while (c != cols); if (rowsum > best) best = rowsum; r++; } while (r != rows); return best; }",
    },
];

fn nested_loop_source() -> String {
    let mut src: String = String::new();
    for case in NESTED_LOOP_BATTERY {
        src.push_str(case.c_source);
        src.push('\n');
    }
    src
}

fn nested_loop_is_nested(recovery: &LeafRecovery) -> bool {
    if !recovery.lifted_loop {
        return false;
    }
    let first: Option<usize> = recovery.source.find("while (1) {");
    let Some(outer): Option<usize> = first else {
        return false;
    };
    recovery.source[outer + "while (1) {".len()..].contains("while (1) {")
}

fn nested_loop_lift(
    case: &NestedLoopCase,
    object_bytes: &[u8],
    abi: PseudoAbi,
) -> Option<(LeafRecovery, String, String)> {
    let (code, base): (Vec<u8>, u64) = function_code(object_bytes, case.name)?;
    let recovery: LeafRecovery = match recover_leaf_function_abi(&code, base, abi) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("skip {}: not in nested-loop class ({e})", case.name);
            return None;
        }
    };
    if !nested_loop_is_nested(&recovery) {
        eprintln!(
            "note {}: recovered without a reconstructed inner+outer loop this build",
            case.name
        );
        return None;
    }
    if recovery.params.is_empty() || recovery.params.len() > 3 {
        eprintln!("skip {}: arg mapping unsupported", case.name);
        return None;
    }
    let recovered_name: String = format!("rec_{}", case.name);
    let renamed: String = recovery
        .source
        .replacen(
            "uint64_t recovered(",
            &format!("uint64_t {recovered_name}("),
            1,
        )
        .lines()
        .filter(|l: &&str| !l.starts_with("#include"))
        .collect::<Vec<&str>>()
        .join("\n");
    Some((recovery, renamed, recovered_name))
}

fn nested_loop_snippet(
    case: &NestedLoopCase,
    recovery: &LeafRecovery,
    recovered_name: &str,
) -> String {
    let n: usize = case.rows * case.cols;
    let return_mask: String = if recovery.return_width_bits == 64 {
        "0xFFFFFFFFFFFFFFFFULL".to_owned()
    } else {
        format!("0x{:x}ULL", (1u128 << recovery.return_width_bits) - 1)
    };
    let rec_arg_count: usize = recovery.params.len();
    let mut rec_args: Vec<String> = vec!["(uint64_t)(uintptr_t)buf".to_owned()];
    for s in 0..(rec_arg_count - 1) {
        rec_args.push(format!("(uint64_t)scalars[{s}]"));
    }
    let rec_call_args: String = rec_args.join(", ");
    let mut snippet: String = String::new();
    let _ = write!(
        snippet,
        "    for (size_t k = 0; k < n_seeds; k++) {{\n\
         \x20       long long buf[{n}];\n\
         \x20       for (size_t e = 0; e < {n}; e++) {{ buf[e] = (seeds[k] * 37 + (long long)e * 13 - 29) % 23; }}\n\
         \x20       long long scalars[2] = {{ {rows}, {cols} }};\n\
         \x20       unsigned long long want = (unsigned long long){}(buf, {rows}, {cols}) & {return_mask};\n\
         \x20       unsigned long long got = {recovered_name}({rec_call_args}) & {return_mask};\n\
         \x20       if (want != got) {{ printf(\"MISMATCH {} seed=%lld want=%llu got=%llu\\n\", seeds[k], want, got); return 1; }}\n\
         \x20   }}\n",
        case.name,
        case.name,
        rows = case.rows,
        cols = case.cols,
    );
    snippet
}

fn build_nested_loop_driver(recovered_decls: &str, driver_body: &str) -> String {
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n{recovered_decls}\n\
         int main(void) {{\n\
         \x20   long long seeds[] = {{ 0, 1, -1, 2, 3, 5, 7, -3, 11, 13, -8, 21, 34, -19, 50 }};\n\
         \x20   size_t n_seeds = sizeof(seeds)/sizeof(seeds[0]);\n\
         {driver_body}\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n"
    )
}

fn nested_loop_decl(case: &NestedLoopCase) -> String {
    format!(
        "extern long long {}(long long *, long long, long long);\n",
        case.name
    )
}

#[test]
fn nested_loop_leaf_functions_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!(
            "skipping nested-loop oracle: gcc (needed for the nested do-while idiom) not on PATH"
        );
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let battery_c: PathBuf = dir.join("nl_battery.c");
    std::fs::write(&battery_c, nested_loop_source().as_bytes()).expect("write nl_battery.c");
    let battery_o: PathBuf = dir.join("nl_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args([
            "-O1",
            "-fno-stack-protector",
            "-fno-if-conversion",
            "-fno-if-conversion2",
            "-fno-tree-loop-if-convert",
            "-fno-tree-vectorize",
            "-fno-unroll-loops",
            "-c",
            "-o",
        ])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke gcc for nl battery");
    assert!(
        compile_battery.status.success(),
        "nl battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read nl_battery.o");

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    let mut nested_count: usize = 0;

    for case in NESTED_LOOP_BATTERY {
        let Some((recovery, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
            nested_loop_lift(case, &object_bytes, HOST_ABI)
        else {
            continue;
        };
        nested_count += 1;
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        recovered_decls.push_str(&nested_loop_decl(case));
        driver_body.push_str(&nested_loop_snippet(case, &recovery, &recovered_name));
        lifted_count += 1;
    }

    if lifted_count == 0 {
        eprintln!(
            "skipping nested-loop behavioral differential: this compiler build reconstructed no nested inner+outer loop from the {} battery cases ({nested_count} nested)",
            NESTED_LOOP_BATTERY.len()
        );
        return;
    }

    let driver: String = build_nested_loop_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("nl_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write nl_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "nl_harness.exe"
    } else {
        "nl_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke gcc to link nl harness");
    assert!(
        link.status.success(),
        "nl harness link failed: {}\n--- nl_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: BoundedRun = run_bounded(&harness_exe, 20);
    let BoundedRun::Exited(out): BoundedRun = run else {
        panic!(
            "nested-loop harness did not terminate within the watchdog window; a recovered loop is non-terminating"
        );
    };
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("OK"),
        "nested-loop behavioral differential FAILED ({lifted_count} cases, {nested_count} nested): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    println!(
        "nested-loop behavioral differential PASSED for {lifted_count} leaf functions ({nested_count} reconstructed inner+outer loop, MS x64 ABI)"
    );
}

#[test]
fn nested_loop_oracle_has_teeth_a_wrong_inner_bound_diverges() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!("skipping nested-loop teeth check: gcc not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let probe: &NestedLoopCase = &NESTED_LOOP_BATTERY[0];
    let battery_c: PathBuf = dir.join("nl_teeth_battery.c");
    std::fs::write(&battery_c, probe.c_source.as_bytes()).expect("write nl_teeth_battery.c");
    let battery_o: PathBuf = dir.join("nl_teeth_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args([
            "-O1",
            "-fno-stack-protector",
            "-fno-if-conversion",
            "-fno-if-conversion2",
            "-fno-tree-loop-if-convert",
            "-fno-tree-vectorize",
            "-fno-unroll-loops",
            "-c",
            "-o",
        ])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke gcc for nl teeth battery");
    assert!(
        compile_battery.status.success(),
        "nl teeth battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read nl_teeth_battery.o");

    let Some((recovery, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
        nested_loop_lift(probe, &object_bytes, HOST_ABI)
    else {
        eprintln!(
            "skipping nested-loop teeth check: this compiler build did not reconstruct a nested inner+outer loop to corrupt"
        );
        return;
    };
    let Some(inner_open): Option<usize> = renamed.find("while (1) {").and_then(|o: usize| {
        renamed[o + "while (1) {".len()..]
            .find("while (1) {")
            .map(|p: usize| p + o + "while (1) {".len())
    }) else {
        eprintln!(
            "skipping nested-loop teeth check: this build did not reconstruct a distinct inner while to corrupt"
        );
        return;
    };
    let Some(inner_break): Option<usize> = renamed[inner_open..]
        .find("break;")
        .map(|p: usize| p + inner_open)
    else {
        eprintln!(
            "skipping nested-loop teeth check: this build's inner loop carries no break to bound the guard search"
        );
        return;
    };
    let Some(guard_open): Option<usize> = renamed[inner_open..inner_break]
        .rfind("if (")
        .map(|p: usize| p + inner_open)
    else {
        eprintln!(
            "skipping nested-loop teeth check: this build did not emit an inner exit guard to neutralize"
        );
        return;
    };
    let Some(guard_close): Option<usize> = renamed[guard_open..]
        .find(") {")
        .map(|p: usize| p + guard_open)
    else {
        eprintln!(
            "skipping nested-loop teeth check: this build's inner exit guard has no recognizable close this check corrupts"
        );
        return;
    };
    let corrupted: String = format!("{}if (0{}", &renamed[..guard_open], &renamed[guard_close..]);
    assert_ne!(
        corrupted, renamed,
        "teeth corruption must neutralize the inner-loop exit guard: {renamed}"
    );

    let mut decls: String = corrupted;
    decls.push('\n');
    decls.push_str(&nested_loop_decl(probe));
    let snippet: String = nested_loop_snippet(probe, &recovery, &recovered_name);
    let driver: String = build_nested_loop_driver(&decls, &snippet);
    let driver_c: PathBuf = dir.join("nl_teeth_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write nl_teeth_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "nl_teeth_harness.exe"
    } else {
        "nl_teeth_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke gcc to link nl teeth harness");
    assert!(
        link.status.success(),
        "nl teeth harness link failed: {}\n--- nl_teeth_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    match run_bounded(&harness_exe, 10) {
        BoundedRun::Exited(out) => {
            let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&out.stdout);
            assert!(
                !stdout.contains("OK") && stdout.contains("MISMATCH"),
                "teeth check FAILED: neutralizing the inner-loop exit bound must diverge, got: {stdout}"
            );
            println!(
                "nested-loop oracle teeth confirmed: neutralizing the inner exit bound diverges (MISMATCH observed)"
            );
        }
        BoundedRun::TimedOut => {
            println!(
                "nested-loop oracle teeth confirmed: neutralizing the inner exit bound diverges (corrupted loop did not terminate)"
            );
        }
    }
}

#[test]
fn sysv_nested_loop_leaf_functions_recompile_to_behavioral_equivalence() {
    if !sysv_host_can_run() {
        return;
    }
    let Some(objs): Option<SysvCrossObjects> = compile_sysv_cross("nl", &nested_loop_source())
    else {
        return;
    };

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    let mut nested_count: usize = 0;

    for case in NESTED_LOOP_BATTERY {
        let Some((recovery, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
            nested_loop_lift(case, &objs.sysv_object, PseudoAbi::SysV)
        else {
            continue;
        };
        nested_count += 1;
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        recovered_decls.push_str(&nested_loop_decl(case));
        driver_body.push_str(&nested_loop_snippet(case, &recovery, &recovered_name));
        lifted_count += 1;
    }

    assert!(
        nested_count >= 4,
        "SysV nested-loop oracle must reconstruct inner+outer loops; only {nested_count} cases produced a nested while(1)/while(1)"
    );

    let driver: String = build_nested_loop_driver(&recovered_decls, &driver_body);
    let stdout: String = link_and_run_sysv("nl", &driver, &objs.host_object, 30);
    assert!(
        stdout.contains("OK"),
        "SysV nested-loop behavioral differential FAILED ({lifted_count} cases, {nested_count} nested): {stdout}"
    );
    println!(
        "SysV nested-loop behavioral differential PASSED for {lifted_count} leaf functions ({nested_count} reconstructed inner+outer loop, SysV ABI)"
    );
}

const CLOSED_FORM_BATTERY: &[Case] = &[
    Case {
        name: "cf_shld",
        arity: 2,
        c_source: "long long cf_shld(long long a, long long b){ return (long long)(((unsigned long long)a << 5) | ((unsigned long long)b >> 59)); }",
    },
    Case {
        name: "cf_shrd",
        arity: 2,
        c_source: "long long cf_shrd(long long a, long long b){ return (long long)(((unsigned long long)a >> 5) | ((unsigned long long)b << 59)); }",
    },
    Case {
        name: "cf_mulimm",
        arity: 1,
        c_source: "long long cf_mulimm(long long a){ return a * 100; }",
    },
    Case {
        name: "cf_mulimm2",
        arity: 1,
        c_source: "long long cf_mulimm2(long long a){ return a * 1000003; }",
    },
    Case {
        name: "cf_umulhi",
        arity: 2,
        c_source: "long long cf_umulhi(long long a, long long b){ return (long long)(((unsigned __int128)(unsigned long long)a * (unsigned long long)b) >> 64); }",
    },
    Case {
        name: "cf_widelo",
        arity: 2,
        c_source: "long long cf_widelo(long long a, long long b){ unsigned __int128 p = (unsigned __int128)(unsigned long long)a * (unsigned long long)b; return (long long)((unsigned long long)p + (unsigned long long)(p >> 64)); }",
    },
];

fn recovered_wide_arith(object_bytes: &[u8], name: &str, abi: PseudoAbi) -> bool {
    let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(object_bytes, name) else {
        return false;
    };
    let recovery: LeafRecovery = match recover_leaf_function_abi(&code, base, abi) {
        Ok(r) => r,
        Err(_) => return false,
    };
    recovery.source.contains("unsigned __int128 wide_prod")
        || recovery.source.contains(" * (uint64_t)(int64_t)")
}

fn recovered_double_shift(object_bytes: &[u8], name: &str, abi: PseudoAbi) -> bool {
    let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(object_bytes, name) else {
        return false;
    };
    let recovery: LeafRecovery = match recover_leaf_function_abi(&code, base, abi) {
        Ok(r) => r,
        Err(_) => return false,
    };
    recovery.source.lines().any(|l: &str| {
        let t: &str = l.trim();
        t.contains(" | ") && t.contains("<<") && t.contains(">>")
    })
}

#[test]
fn closed_form_mul_shift_leaf_functions_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(builder): Option<String> = clang() else {
        eprintln!(
            "skipping closed-form oracle: clang (needed for the mul/shld/shrd closed-form lowering) not on PATH"
        );
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let battery_c: PathBuf = dir.join("cform_battery.c");
    std::fs::write(&battery_c, battery_source(CLOSED_FORM_BATTERY).as_bytes())
        .expect("write cform_battery.c");
    let battery_o: PathBuf = dir.join("cform_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args(["-O1", "-fno-stack-protector", "-c", "-o"])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke clang for closed-form battery");
    assert!(
        compile_battery.status.success(),
        "closed-form battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read cform_battery.o");

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    let mut wide_count: usize = 0;
    let mut dshift_count: usize = 0;

    for case in CLOSED_FORM_BATTERY {
        if recovered_wide_arith(&object_bytes, case.name, HOST_ABI) {
            wide_count += 1;
        }
        if recovered_double_shift(&object_bytes, case.name, HOST_ABI) {
            dshift_count += 1;
        }
        let Some(lifted): Option<Lifted> = process_case(case, &object_bytes, HOST_ABI) else {
            continue;
        };
        recovered_decls.push_str(&lifted.decls);
        driver_body.push_str(&lifted.driver_snippet);
        lifted_count += 1;
    }

    if lifted_count == 0 {
        eprintln!(
            "skipping closed-form behavioral differential: this compiler build lowered none of the {} battery cases into the leaf class ({wide_count} wide, {dshift_count} dshift)",
            CLOSED_FORM_BATTERY.len()
        );
        return;
    }

    let driver: String = build_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("cform_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write cform_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "cform_harness.exe"
    } else {
        "cform_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke clang to link cform harness");
    assert!(
        link.status.success(),
        "cform harness link failed: {}\n--- cform_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run cform harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "closed-form behavioral differential FAILED ({lifted_count} cases, {wide_count} wide, {dshift_count} dshift): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "closed-form behavioral differential PASSED for {lifted_count} leaf functions ({wide_count} mul/imul-imm, {dshift_count} shld/shrd, host ABI)"
    );
}

#[test]
fn closed_form_oracle_has_teeth_flipping_the_shift_amount_diverges() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(builder): Option<String> = clang() else {
        eprintln!("skipping closed-form teeth check: clang not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let probe: Case = Case {
        name: CLOSED_FORM_BATTERY[0].name,
        arity: CLOSED_FORM_BATTERY[0].arity,
        c_source: CLOSED_FORM_BATTERY[0].c_source,
    };
    let battery_c: PathBuf = dir.join("cform_teeth_battery.c");
    std::fs::write(&battery_c, probe.c_source.as_bytes()).expect("write cform_teeth_battery.c");
    let battery_o: PathBuf = dir.join("cform_teeth_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args(["-O1", "-fno-stack-protector", "-c", "-o"])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke clang for cform teeth battery");
    assert!(
        compile_battery.status.success(),
        "cform teeth battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read cform_teeth_battery.o");

    let Some(lifted): Option<Lifted> = process_case(&probe, &object_bytes, HOST_ABI) else {
        eprintln!(
            "skipping closed-form teeth check: this compiler build did not lower the probe into the leaf class"
        );
        return;
    };
    if !lifted.decls.contains("<< 5)") {
        eprintln!(
            "skipping closed-form teeth check: this compiler build did not reconstruct the double-precision left shift this check corrupts"
        );
        return;
    }

    let corrupted: String = lifted.decls.replacen("<< 5)", "<< 7)", 1);
    assert_ne!(
        corrupted, lifted.decls,
        "teeth corruption must change the double-shift amount: {}",
        lifted.decls
    );

    let driver: String = build_driver(&corrupted, &lifted.driver_snippet);
    let driver_c: PathBuf = dir.join("cform_teeth_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write cform_teeth_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "cform_teeth_harness.exe"
    } else {
        "cform_teeth_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke clang to link cform teeth harness");
    assert!(
        link.status.success(),
        "cform teeth harness link failed: {}\n--- cform_teeth_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run cform teeth harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        !stdout.contains("OK") && stdout.contains("MISMATCH"),
        "teeth check FAILED: perturbing the double-shift amount must diverge, got: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "closed-form oracle teeth confirmed: perturbing the closed-form extraction shift diverges (MISMATCH observed)"
    );
}

#[test]
fn sysv_memory_access_leaf_functions_recompile_to_behavioral_equivalence() {
    if !sysv_host_can_run() {
        return;
    }
    let mut battery_src: String = String::new();
    for case in MEM_BATTERY {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let Some(objs): Option<SysvCrossObjects> = compile_sysv_cross("mem", &battery_src) else {
        return;
    };

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;

    for case in MEM_BATTERY {
        let Some((code, base)): Option<(Vec<u8>, u64)> =
            function_code(&objs.sysv_object, case.name)
        else {
            eprintln!("skip {}: symbol not located", case.name);
            continue;
        };
        let recovery: LeafRecovery = match recover_leaf_function_abi(&code, base, PseudoAbi::SysV) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skip {}: not in leaf class ({e})", case.name);
                continue;
            }
        };
        let Some(snippet): Option<String> = mem_driver_snippet(case, &recovery) else {
            eprintln!("skip {}: arg mapping unsupported", case.name);
            continue;
        };
        let recovered_name: String = format!("rec_{}", case.name);
        recovered_decls.push_str(&mem_recovered_signature(&recovery, &recovered_name));
        recovered_decls.push('\n');
        recovered_decls.push_str(&mem_original_decl(case));
        driver_body.push_str(&snippet);
        lifted_count += 1;
    }

    assert!(
        lifted_count >= 6,
        "SysV memory-access lifter must handle at least 6 of the {} cases, only lifted {lifted_count}",
        MEM_BATTERY.len()
    );

    let driver: String = build_mem_driver(&recovered_decls, &driver_body);
    let stdout: String = link_and_run_sysv("mem", &driver, &objs.host_object, 30);
    assert!(
        stdout.contains("OK"),
        "SysV memory-access behavioral differential FAILED ({lifted_count} cases): {stdout}"
    );
    println!(
        "SysV memory-access behavioral differential PASSED for {lifted_count} leaf functions (SysV ABI)"
    );
}

const IMUL_MEM_BATTERY: &[MemCase] = &[
    MemCase {
        name: "mi_scale64",
        elem_ty: "unsigned long long",
        n_elems: 2,
        n_scalars: 0,
        returns: true,
        access_shape: ExpectedAggregateShape::NoAggregate,
        c_source: "unsigned long long mi_scale64(unsigned long long *p){ return p[0] * 1000003ull; }",
    },
    MemCase {
        name: "mi_scale32",
        elem_ty: "unsigned",
        n_elems: 2,
        n_scalars: 0,
        returns: true,
        access_shape: ExpectedAggregateShape::NoAggregate,
        c_source: "unsigned mi_scale32(unsigned *p){ return p[0] * 100u; }",
    },
    MemCase {
        name: "mi_disp",
        elem_ty: "unsigned long long",
        n_elems: 3,
        n_scalars: 0,
        returns: true,
        access_shape: ExpectedAggregateShape::NoAggregate,
        c_source: "unsigned long long mi_disp(unsigned long long *p){ return p[1] * 12345ull; }",
    },
    MemCase {
        name: "mi_idx",
        elem_ty: "unsigned long long",
        n_elems: 6,
        n_scalars: 1,
        returns: true,
        access_shape: ExpectedAggregateShape::Array,
        c_source: "unsigned long long mi_idx(unsigned long long *p, unsigned long long i){ return p[i] * 100ull; }",
    },
];

fn recovered_has_imul_mem(object_bytes: &[u8], name: &str, abi: PseudoAbi) -> bool {
    let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(object_bytes, name) else {
        return false;
    };
    let recovery: LeafRecovery = match recover_leaf_function_abi(&code, base, abi) {
        Ok(r) => r,
        Err(_) => return false,
    };
    recovery.source.lines().any(|l: &str| {
        let t: &str = l.trim();
        t.find("* (uint64_t)(int64_t)")
            .is_some_and(|mul: usize| t[..mul].contains("*(uint"))
    })
}

#[test]
fn imul_mem_source_leaf_functions_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(compiler): Option<String> = cc() else {
        eprintln!("skipping: no C compiler (gcc/clang/cc) on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let mut battery_src: String = String::new();
    for case in IMUL_MEM_BATTERY {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let battery_c: PathBuf = dir.join("imul_mem_battery.c");
    std::fs::write(&battery_c, battery_src.as_bytes()).expect("write imul_mem_battery.c");
    let battery_o: PathBuf = dir.join("imul_mem_battery.o");
    let compile_battery: std::process::Output = Command::new(&compiler)
        .args(["-O1", "-fno-stack-protector", "-c", "-o"])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke cc for imul-mem battery");
    assert!(
        compile_battery.status.success(),
        "imul-mem battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read imul_mem_battery.o");

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    let mut saw_imul_mem: bool = false;

    for case in IMUL_MEM_BATTERY {
        let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(&object_bytes, case.name)
        else {
            eprintln!("skip {}: symbol not located", case.name);
            continue;
        };
        let recovery: LeafRecovery = match recover_leaf_function_abi(&code, base, HOST_ABI) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skip {}: not in leaf class ({e})", case.name);
                continue;
            }
        };
        let Some(snippet): Option<String> = mem_driver_snippet(case, &recovery) else {
            eprintln!("skip {}: arg mapping unsupported", case.name);
            continue;
        };
        if recovered_has_imul_mem(&object_bytes, case.name, HOST_ABI) {
            saw_imul_mem = true;
        }
        let recovered_name: String = format!("rec_{}", case.name);
        recovered_decls.push_str(&mem_recovered_signature(&recovery, &recovered_name));
        recovered_decls.push('\n');
        recovered_decls.push_str(&mem_original_decl(case));
        driver_body.push_str(&snippet);
        lifted_count += 1;
    }

    if !saw_imul_mem {
        eprintln!(
            "skipping imul-mem behavioral differential: this compiler build fused none of the {} battery cases into `imul reg, [mem], imm`",
            IMUL_MEM_BATTERY.len()
        );
        return;
    }

    let driver: String = build_mem_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("imul_mem_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write imul_mem_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "imul_mem_harness.exe"
    } else {
        "imul_mem_harness"
    });
    let link: std::process::Output = Command::new(&compiler)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke cc to link imul-mem harness");
    assert!(
        link.status.success(),
        "imul-mem harness link failed: {}\n--- imul_mem_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run imul-mem harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "imul-mem behavioral differential FAILED ({lifted_count} cases): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "imul-mem behavioral differential PASSED for {lifted_count} leaf functions (MS x64 ABI)"
    );
}

#[test]
fn sysv_imul_mem_source_leaf_functions_recompile_to_behavioral_equivalence() {
    if !sysv_host_can_run() {
        return;
    }
    let mut battery_src: String = String::new();
    for case in IMUL_MEM_BATTERY {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let Some(objs): Option<SysvCrossObjects> = compile_sysv_cross("imul_mem", &battery_src) else {
        return;
    };

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    let mut saw_imul_mem: bool = false;

    for case in IMUL_MEM_BATTERY {
        let Some((code, base)): Option<(Vec<u8>, u64)> =
            function_code(&objs.sysv_object, case.name)
        else {
            eprintln!("skip {}: symbol not located", case.name);
            continue;
        };
        let recovery: LeafRecovery = match recover_leaf_function_abi(&code, base, PseudoAbi::SysV) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skip {}: not in leaf class ({e})", case.name);
                continue;
            }
        };
        let Some(snippet): Option<String> = mem_driver_snippet(case, &recovery) else {
            eprintln!("skip {}: arg mapping unsupported", case.name);
            continue;
        };
        if recovered_has_imul_mem(&objs.sysv_object, case.name, PseudoAbi::SysV) {
            saw_imul_mem = true;
        }
        let recovered_name: String = format!("rec_{}", case.name);
        recovered_decls.push_str(&mem_recovered_signature(&recovery, &recovered_name));
        recovered_decls.push('\n');
        recovered_decls.push_str(&mem_original_decl(case));
        driver_body.push_str(&snippet);
        lifted_count += 1;
    }

    if !saw_imul_mem {
        eprintln!(
            "skipping SysV imul-mem behavioral differential: clang fused none of the {} battery cases into `imul reg, [mem], imm`",
            IMUL_MEM_BATTERY.len()
        );
        return;
    }

    let driver: String = build_mem_driver(&recovered_decls, &driver_body);
    let stdout: String = link_and_run_sysv("imul_mem", &driver, &objs.host_object, 30);
    assert!(
        stdout.contains("OK"),
        "SysV imul-mem behavioral differential FAILED ({lifted_count} cases): {stdout}"
    );
    println!(
        "SysV imul-mem behavioral differential PASSED for {lifted_count} leaf functions (SysV ABI)"
    );
}

#[test]
fn imul_mem_oracle_has_teeth_perturbing_the_immediate_diverges() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(compiler): Option<String> = cc() else {
        eprintln!("skipping imul-mem teeth check: no C compiler on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let probe: &MemCase = &IMUL_MEM_BATTERY[0];
    let battery_c: PathBuf = dir.join("imul_mem_teeth_battery.c");
    std::fs::write(&battery_c, probe.c_source.as_bytes()).expect("write imul_mem_teeth_battery.c");
    let battery_o: PathBuf = dir.join("imul_mem_teeth_battery.o");
    let compile_battery: std::process::Output = Command::new(&compiler)
        .args(["-O1", "-fno-stack-protector", "-c", "-o"])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke cc for imul-mem teeth battery");
    assert!(
        compile_battery.status.success(),
        "imul-mem teeth battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read imul_mem_teeth_battery.o");

    let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(&object_bytes, probe.name)
    else {
        eprintln!("skipping imul-mem teeth check: probe symbol not located");
        return;
    };
    let recovery: LeafRecovery = match recover_leaf_function_abi(&code, base, HOST_ABI) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("skipping imul-mem teeth check: probe not in leaf class ({e})");
            return;
        }
    };
    if !recovered_has_imul_mem(&object_bytes, probe.name, HOST_ABI) {
        eprintln!(
            "skipping imul-mem teeth check: this compiler build did not fuse the probe into `imul reg, [mem], imm`"
        );
        return;
    }
    let Some(snippet): Option<String> = mem_driver_snippet(probe, &recovery) else {
        eprintln!("skipping imul-mem teeth check: arg mapping unsupported");
        return;
    };

    let recovered_name: String = format!("rec_{}", probe.name);
    let mut recovered_decls: String = mem_recovered_signature(&recovery, &recovered_name);
    recovered_decls.push('\n');
    recovered_decls.push_str(&mem_original_decl(probe));
    assert!(
        recovered_decls.contains("1000003LL"),
        "expected the recovered multiplier literal to perturb: {recovered_decls}"
    );
    let corrupted: String = recovered_decls.replacen("1000003LL", "1000009LL", 1);
    assert_ne!(
        corrupted, recovered_decls,
        "teeth corruption must change the multiplier: {recovered_decls}"
    );

    let driver: String = build_mem_driver(&corrupted, &snippet);
    let driver_c: PathBuf = dir.join("imul_mem_teeth_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write imul_mem_teeth_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "imul_mem_teeth_harness.exe"
    } else {
        "imul_mem_teeth_harness"
    });
    let link: std::process::Output = Command::new(&compiler)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke cc to link imul-mem teeth harness");
    assert!(
        link.status.success(),
        "imul-mem teeth harness link failed: {}\n--- imul_mem_teeth_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run imul-mem teeth harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        !stdout.contains("OK") && stdout.contains("MISMATCH"),
        "teeth check FAILED: perturbing the imul-mem multiplier must diverge, got: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "imul-mem oracle teeth confirmed: perturbing the ternary multiplier diverges (MISMATCH observed)"
    );
}

struct RmwCase {
    name: &'static str,
    elem_ty: &'static str,
    n_elems: usize,
    takes_value: bool,
    c_source: &'static str,
}

const RMW_BATTERY: &[RmwCase] = &[
    RmwCase {
        name: "rmw_add",
        elem_ty: "unsigned long long",
        n_elems: 1,
        takes_value: true,
        c_source: "void rmw_add(unsigned long long *p, unsigned long long x){ *p += x; }",
    },
    RmwCase {
        name: "rmw_sub",
        elem_ty: "unsigned long long",
        n_elems: 1,
        takes_value: true,
        c_source: "void rmw_sub(unsigned long long *p, unsigned long long x){ *p -= x; }",
    },
    RmwCase {
        name: "rmw_add32",
        elem_ty: "unsigned",
        n_elems: 1,
        takes_value: true,
        c_source: "void rmw_add32(unsigned *p, unsigned x){ *p += x; }",
    },
    RmwCase {
        name: "rmw_and",
        elem_ty: "unsigned long long",
        n_elems: 1,
        takes_value: true,
        c_source: "void rmw_and(unsigned long long *p, unsigned long long x){ *p &= x; }",
    },
    RmwCase {
        name: "rmw_xor",
        elem_ty: "unsigned long long",
        n_elems: 1,
        takes_value: true,
        c_source: "void rmw_xor(unsigned long long *p, unsigned long long x){ *p ^= x; }",
    },
    RmwCase {
        name: "rmw_or_imm",
        elem_ty: "unsigned",
        n_elems: 1,
        takes_value: false,
        c_source: "void rmw_or_imm(unsigned *p){ *p |= 0x5aa5u; }",
    },
    RmwCase {
        name: "rmw_and_imm",
        elem_ty: "unsigned long long",
        n_elems: 1,
        takes_value: false,
        c_source: "void rmw_and_imm(unsigned long long *p){ *p &= 0x3f; }",
    },
    RmwCase {
        name: "rmw_field",
        elem_ty: "unsigned long long",
        n_elems: 3,
        takes_value: true,
        c_source: "void rmw_field(unsigned long long *p, unsigned long long x){ p[1] += x; }",
    },
    RmwCase {
        name: "rmw_shl",
        elem_ty: "unsigned",
        n_elems: 1,
        takes_value: false,
        c_source: "void rmw_shl(unsigned *p){ *p <<= 3; }",
    },
    RmwCase {
        name: "rmw_shr",
        elem_ty: "unsigned",
        n_elems: 1,
        takes_value: false,
        c_source: "void rmw_shr(unsigned *p){ *p >>= 2; }",
    },
    RmwCase {
        name: "rmw_sar",
        elem_ty: "int",
        n_elems: 1,
        takes_value: false,
        c_source: "void rmw_sar(int *p){ *p >>= 2; }",
    },
    RmwCase {
        name: "rmw_inc",
        elem_ty: "unsigned long long",
        n_elems: 1,
        takes_value: false,
        c_source: "void rmw_inc(unsigned long long *p){ (*p)++; }",
    },
    RmwCase {
        name: "rmw_dec",
        elem_ty: "int",
        n_elems: 1,
        takes_value: false,
        c_source: "void rmw_dec(int *p){ (*p)--; }",
    },
    RmwCase {
        name: "rmw_neg",
        elem_ty: "unsigned long long",
        n_elems: 1,
        takes_value: false,
        c_source: "void rmw_neg(unsigned long long *p){ *p = -*p; }",
    },
    RmwCase {
        name: "rmw_not",
        elem_ty: "unsigned",
        n_elems: 1,
        takes_value: false,
        c_source: "void rmw_not(unsigned *p){ *p = ~*p; }",
    },
];

fn rmw_battery_source() -> String {
    let mut src: String = String::new();
    for case in RMW_BATTERY {
        src.push_str(case.c_source);
        src.push('\n');
    }
    src
}

fn rmw_original_decl(case: &RmwCase) -> String {
    if case.takes_value {
        format!(
            "extern void {}({}*, {});\n",
            case.name, case.elem_ty, case.elem_ty
        )
    } else {
        format!("extern void {}({}*);\n", case.name, case.elem_ty)
    }
}

fn function_has_mem_rmw(object_bytes: &[u8], name: &str) -> bool {
    let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(object_bytes, name) else {
        return false;
    };
    let Ok(insns): Result<Vec<disrobe_pass_native::DisasmInsn>, _> =
        disassemble(Arch::X86_64, base, &code)
    else {
        return false;
    };
    insns.iter().any(|insn: &disrobe_pass_native::DisasmInsn| {
        matches!(
            insn.mnemonic.as_str(),
            "add"
                | "sub"
                | "and"
                | "or"
                | "xor"
                | "shl"
                | "sal"
                | "shr"
                | "sar"
                | "inc"
                | "dec"
                | "neg"
                | "not"
        ) && operand_is_memory(insn.operands.split(',').next().unwrap_or("").trim())
    })
}

fn operand_is_memory(first: &str) -> bool {
    first.starts_with('[')
        || first
            .split_once(char::is_whitespace)
            .is_some_and(|(kw, rest): (&str, &str)| {
                matches!(kw, "byte" | "word" | "dword" | "qword") && rest.trim().starts_with('[')
            })
}

fn rmw_driver_snippet(case: &RmwCase, recovery: &LeafRecovery) -> Option<String> {
    let recovered_name: String = format!("rec_{}", case.name);
    let rec_arg_count: usize = recovery.params.len();
    let expected: usize = if case.takes_value { 2 } else { 1 };
    if rec_arg_count != expected {
        return None;
    }
    let elem_ty: &str = case.elem_ty;
    let n: usize = case.n_elems;
    let orig_call: String = if case.takes_value {
        format!("{}(orig, ({elem_ty})v);", case.name)
    } else {
        format!("{}(orig);", case.name)
    };
    let rec_call: String = if case.takes_value {
        format!("{recovered_name}((uint64_t)(uintptr_t)rec, (uint64_t)v);")
    } else {
        format!("{recovered_name}((uint64_t)(uintptr_t)rec);")
    };
    let mut snippet: String = String::new();
    let _ = write!(
        snippet,
        "    for (size_t k = 0; k < n_seeds; k++) {{\n\
         \x20       {elem_ty} orig[{n}]; {elem_ty} rec[{n}];\n\
         \x20       for (size_t e = 0; e < {n}; e++) {{ orig[e] = ({elem_ty})(seeds[k] + (long long)e*7 - 3); rec[e] = orig[e]; }}\n\
         \x20       long long v = seeds[k] ^ 0x2f;\n\
         \x20       {orig_call}\n\
         \x20       {rec_call}\n\
         \x20       for (size_t e = 0; e < {n}; e++) {{ if (orig[e] != rec[e]) {{ printf(\"MISMATCH {} seed=%lld idx=%zu orig=%lld rec=%lld\\n\", seeds[k], e, (long long)orig[e], (long long)rec[e]); return 1; }} }}\n\
         \x20   }}\n",
        case.name,
    );
    Some(snippet)
}

#[test]
fn read_modify_write_memory_leaf_functions_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(compiler): Option<String> = cc() else {
        eprintln!("skipping: no C compiler (gcc/clang/cc) on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let battery_src: String = rmw_battery_source();
    let battery_c: PathBuf = dir.join("rmw_battery.c");
    std::fs::write(&battery_c, battery_src.as_bytes()).expect("write rmw_battery.c");
    let battery_o: PathBuf = dir.join("rmw_battery.o");
    let compile_battery: std::process::Output = Command::new(&compiler)
        .args(["-O1", "-fno-stack-protector", "-c", "-o"])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke cc for rmw battery");
    assert!(
        compile_battery.status.success(),
        "rmw battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read rmw_battery.o");

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    let mut rmw_seen: usize = 0;

    for case in RMW_BATTERY {
        if !function_has_mem_rmw(&object_bytes, case.name) {
            eprintln!(
                "skip {}: this compiler build did not fuse it into a memory read-modify-write",
                case.name
            );
            continue;
        }
        let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(&object_bytes, case.name)
        else {
            eprintln!("skip {}: symbol not located", case.name);
            continue;
        };
        let recovery: LeafRecovery = match recover_leaf_function_abi(&code, base, HOST_ABI) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skip {}: not in leaf class ({e})", case.name);
                continue;
            }
        };
        let Some(snippet): Option<String> = rmw_driver_snippet(case, &recovery) else {
            eprintln!("skip {}: arg mapping unsupported", case.name);
            continue;
        };
        let recovered_name: String = format!("rec_{}", case.name);
        recovered_decls.push_str(&mem_recovered_signature(&recovery, &recovered_name));
        recovered_decls.push('\n');
        recovered_decls.push_str(&rmw_original_decl(case));
        driver_body.push_str(&snippet);
        lifted_count += 1;
        rmw_seen += 1;
    }

    assert!(
        rmw_seen >= 8,
        "memory read-modify-write lifter must recover at least 8 of the {} fused cases, only lifted {rmw_seen}",
        RMW_BATTERY.len()
    );

    let driver: String = build_mem_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("rmw_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write rmw_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "rmw_harness.exe"
    } else {
        "rmw_harness"
    });
    let link: std::process::Output = Command::new(&compiler)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke cc to link rmw harness");
    assert!(
        link.status.success(),
        "rmw harness link failed: {}\n--- rmw_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run rmw harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "memory read-modify-write behavioral differential FAILED ({lifted_count} cases): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "memory read-modify-write behavioral differential PASSED for {lifted_count} leaf functions (MS x64 ABI)"
    );
}

#[test]
fn sysv_read_modify_write_memory_leaf_functions_recompile_to_behavioral_equivalence() {
    if !sysv_host_can_run() {
        return;
    }
    let battery_src: String = rmw_battery_source();
    let Some(objs): Option<SysvCrossObjects> = compile_sysv_cross("rmw", &battery_src) else {
        return;
    };

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;

    for case in RMW_BATTERY {
        if !function_has_mem_rmw(&objs.sysv_object, case.name) {
            eprintln!(
                "skip {}: sysv build did not fuse it into a memory read-modify-write",
                case.name
            );
            continue;
        }
        let Some((code, base)): Option<(Vec<u8>, u64)> =
            function_code(&objs.sysv_object, case.name)
        else {
            eprintln!("skip {}: symbol not located", case.name);
            continue;
        };
        let recovery: LeafRecovery = match recover_leaf_function_abi(&code, base, PseudoAbi::SysV) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skip {}: not in leaf class ({e})", case.name);
                continue;
            }
        };
        let Some(snippet): Option<String> = rmw_driver_snippet(case, &recovery) else {
            eprintln!("skip {}: arg mapping unsupported", case.name);
            continue;
        };
        let recovered_name: String = format!("rec_{}", case.name);
        recovered_decls.push_str(&mem_recovered_signature(&recovery, &recovered_name));
        recovered_decls.push('\n');
        recovered_decls.push_str(&rmw_original_decl(case));
        driver_body.push_str(&snippet);
        lifted_count += 1;
    }

    assert!(
        lifted_count >= 8,
        "SysV memory read-modify-write lifter must handle at least 8 of the {} cases, only lifted {lifted_count}",
        RMW_BATTERY.len()
    );

    let driver: String = build_mem_driver(&recovered_decls, &driver_body);
    let stdout: String = link_and_run_sysv("rmw", &driver, &objs.host_object, 30);
    assert!(
        stdout.contains("OK"),
        "SysV memory read-modify-write behavioral differential FAILED ({lifted_count} cases): {stdout}"
    );
    println!(
        "SysV memory read-modify-write behavioral differential PASSED for {lifted_count} leaf functions (SysV ABI)"
    );
}

#[test]
fn read_modify_write_oracle_has_teeth_perturbing_the_or_mask_diverges() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(compiler): Option<String> = cc() else {
        eprintln!("skipping rmw teeth check: no C compiler on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let probe: &RmwCase = RMW_BATTERY
        .iter()
        .find(|c: &&RmwCase| c.name == "rmw_or_imm")
        .expect("rmw_or_imm probe present");
    let battery_c: PathBuf = dir.join("rmw_teeth_battery.c");
    std::fs::write(&battery_c, probe.c_source.as_bytes()).expect("write rmw_teeth_battery.c");
    let battery_o: PathBuf = dir.join("rmw_teeth_battery.o");
    let compile_battery: std::process::Output = Command::new(&compiler)
        .args(["-O1", "-fno-stack-protector", "-c", "-o"])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke cc for rmw teeth battery");
    assert!(
        compile_battery.status.success(),
        "rmw teeth battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read rmw_teeth_battery.o");

    if !function_has_mem_rmw(&object_bytes, probe.name) {
        eprintln!("skipping rmw teeth check: this compiler build did not fuse the probe");
        return;
    }
    let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(&object_bytes, probe.name)
    else {
        eprintln!("skipping rmw teeth check: probe symbol not located");
        return;
    };
    let recovery: LeafRecovery = match recover_leaf_function_abi(&code, base, HOST_ABI) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("skipping rmw teeth check: probe not in leaf class ({e})");
            return;
        }
    };
    let Some(snippet): Option<String> = rmw_driver_snippet(probe, &recovery) else {
        eprintln!("skipping rmw teeth check: arg mapping unsupported");
        return;
    };

    let recovered_name: String = format!("rec_{}", probe.name);
    let mut recovered_decls: String = mem_recovered_signature(&recovery, &recovered_name);
    recovered_decls.push('\n');
    recovered_decls.push_str(&rmw_original_decl(probe));
    assert!(
        recovered_decls.contains("23205LL"),
        "expected the recovered OR mask literal to perturb: {recovered_decls}"
    );
    let corrupted: String = recovered_decls.replacen("23205LL", "10837LL", 1);
    assert_ne!(
        corrupted, recovered_decls,
        "teeth corruption must change the OR mask: {recovered_decls}"
    );

    let driver: String = build_mem_driver(&corrupted, &snippet);
    let driver_c: PathBuf = dir.join("rmw_teeth_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write rmw_teeth_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "rmw_teeth_harness.exe"
    } else {
        "rmw_teeth_harness"
    });
    let link: std::process::Output = Command::new(&compiler)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke cc to link rmw teeth harness");
    assert!(
        link.status.success(),
        "rmw teeth harness link failed: {}\n--- rmw_teeth_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run rmw teeth harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        !stdout.contains("OK") && stdout.contains("MISMATCH"),
        "teeth check FAILED: perturbing the OR mask must diverge, got: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!("rmw oracle teeth confirmed: perturbing the OR mask diverges (MISMATCH observed)");
}

#[test]
fn sysv_control_flow_leaf_functions_recompile_to_behavioral_equivalence() {
    if !sysv_host_can_run() {
        return;
    }
    let Some(objs): Option<SysvCrossObjects> =
        compile_sysv_cross("cf", &battery_source(CF_BATTERY))
    else {
        return;
    };

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;

    for case in CF_BATTERY {
        let Some(lifted): Option<Lifted> = process_case(case, &objs.sysv_object, PseudoAbi::SysV)
        else {
            continue;
        };
        recovered_decls.push_str(&lifted.decls);
        driver_body.push_str(&lifted.driver_snippet);
        lifted_count += 1;
    }

    assert!(
        lifted_count >= 8,
        "SysV control-flow lifter must handle at least 8 of the {} cases, only lifted {lifted_count}",
        CF_BATTERY.len()
    );

    let driver: String = build_driver(&recovered_decls, &driver_body);
    let stdout: String = link_and_run_sysv("cf", &driver, &objs.host_object, 30);
    assert!(
        stdout.contains("OK"),
        "SysV control-flow behavioral differential FAILED ({lifted_count} cases): {stdout}"
    );
    println!(
        "SysV control-flow behavioral differential PASSED for {lifted_count} leaf functions (SysV ABI)"
    );
}

#[test]
fn sysv_split_return_leaf_functions_recompile_to_behavioral_equivalence() {
    if !sysv_host_can_run() {
        return;
    }
    let Some(objs): Option<SysvCrossObjects> =
        compile_sysv_cross("split", &battery_source(SPLIT_RETURN_BATTERY))
    else {
        return;
    };

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;

    for case in SPLIT_RETURN_BATTERY {
        let Some(lifted): Option<Lifted> = process_case(case, &objs.sysv_object, PseudoAbi::SysV)
        else {
            continue;
        };
        recovered_decls.push_str(&lifted.decls);
        driver_body.push_str(&lifted.driver_snippet);
        lifted_count += 1;
    }

    assert!(
        lifted_count >= 6,
        "SysV split-return lifter must handle at least 6 of the {} cases, only lifted {lifted_count}",
        SPLIT_RETURN_BATTERY.len()
    );

    let driver: String = build_driver(&recovered_decls, &driver_body);
    let stdout: String = link_and_run_sysv("split", &driver, &objs.host_object, 30);
    assert!(
        stdout.contains("OK"),
        "SysV split-return behavioral differential FAILED ({lifted_count} cases): {stdout}"
    );
    println!(
        "SysV split-return behavioral differential PASSED for {lifted_count} leaf functions (SysV ABI)"
    );
}

fn sysv_loop_lift(case: &LoopCase, object_bytes: &[u8]) -> Option<(LeafRecovery, String, String)> {
    let (code, base): (Vec<u8>, u64) = function_code(object_bytes, case.name)?;
    let recovery: LeafRecovery = match recover_leaf_function_abi(&code, base, PseudoAbi::SysV) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("skip {}: not in loop leaf class ({e})", case.name);
            return None;
        }
    };
    let recovered_name: String = format!("rec_{}", case.name);
    let renamed: String = recovery
        .source
        .replacen(
            "uint64_t recovered(",
            &format!("uint64_t {recovered_name}("),
            1,
        )
        .lines()
        .filter(|l: &&str| !l.starts_with("#include"))
        .collect::<Vec<&str>>()
        .join("\n");
    Some((recovery, renamed, recovered_name))
}

fn run_sysv_loop_class(
    tag: &str,
    cases: &[LoopCase],
    builder: &dyn Fn(&str, &str) -> String,
    floor: usize,
) {
    let mut battery_src: String = String::new();
    for case in cases {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let Some(objs): Option<SysvCrossObjects> = compile_sysv_cross(tag, &battery_src) else {
        return;
    };

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;

    for case in cases {
        let Some((recovery, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
            sysv_loop_lift(case, &objs.sysv_object)
        else {
            continue;
        };
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        let _ = writeln!(
            recovered_decls,
            "extern long long {}({});",
            case.name,
            vec!["long long"; case.arity].join(", ")
        );
        driver_body.push_str(&loop_driver_snippet(case, &recovery, &recovered_name));
        lifted_count += 1;
    }

    assert!(
        lifted_count >= floor,
        "SysV {tag} lifter must handle at least {floor} of the {} cases, only lifted {lifted_count}",
        cases.len()
    );

    let driver: String = builder(&recovered_decls, &driver_body);
    let stdout: String = link_and_run_sysv(tag, &driver, &objs.host_object, 30);
    assert!(
        stdout.contains("OK"),
        "SysV {tag} behavioral differential FAILED ({lifted_count} cases): {stdout}"
    );
    println!(
        "SysV {tag} behavioral differential PASSED for {lifted_count} leaf functions (SysV ABI)"
    );
}

#[test]
fn sysv_natural_loop_leaf_functions_recompile_to_behavioral_equivalence() {
    if !sysv_host_can_run() {
        return;
    }
    run_sysv_loop_class("loop", LOOP_BATTERY, &build_loop_driver, 8);
}

#[test]
fn sysv_top_guarded_while_loops_recompile_to_behavioral_equivalence() {
    if !sysv_host_can_run() {
        return;
    }
    run_sysv_loop_class("wg", GUARDED_WHILE_BATTERY, &build_zero_trip_driver, 6);
}

#[test]
fn sysv_width_extension_leaf_functions_recompile_to_behavioral_equivalence() {
    if !sysv_host_can_run() {
        return;
    }
    let Some(objs): Option<SysvCrossObjects> =
        compile_sysv_cross("wx", &battery_source(WIDTH_EXT_BATTERY))
    else {
        return;
    };

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;

    for case in WIDTH_EXT_BATTERY {
        let Some(lifted): Option<Lifted> = process_case(case, &objs.sysv_object, PseudoAbi::SysV)
        else {
            continue;
        };
        recovered_decls.push_str(&lifted.decls);
        driver_body.push_str(&lifted.driver_snippet);
        lifted_count += 1;
    }

    assert!(
        lifted_count >= 7,
        "SysV width-extension lifter must handle at least 7 of the {} cases, only lifted {lifted_count}",
        WIDTH_EXT_BATTERY.len()
    );

    let driver: String = build_driver(&recovered_decls, &driver_body);
    let stdout: String = link_and_run_sysv("wx", &driver, &objs.host_object, 30);
    assert!(
        stdout.contains("OK"),
        "SysV width-extension behavioral differential FAILED ({lifted_count} cases): {stdout}"
    );
    println!(
        "SysV width-extension behavioral differential PASSED for {lifted_count} leaf functions (SysV ABI)"
    );
}

fn elf_call_callee_for_target(object_bytes: &[u8], caller: &str, target: u64) -> Option<String> {
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
        if !(reloc_addr >= caller_start && reloc_addr < caller_end) {
            continue;
        }
        if offset != target_offset {
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

fn sysv_lift_call_case(case: &CallCase, object_bytes: &[u8]) -> Option<(String, String, usize)> {
    let (code, base): (Vec<u8>, u64) = function_code(object_bytes, case.caller)?;
    let recovery: LeafRecovery = match recover_leaf_function_abi(&code, base, PseudoAbi::SysV) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("skip {}: caller not in call leaf class ({e})", case.caller);
            return None;
        }
    };
    if recovery.call_targets.is_empty() {
        eprintln!("skip {}: no call lifted", case.caller);
        return None;
    }
    let full_arity: usize = recovery.params.len();
    let mut decls: String = String::new();
    let mut seen: Vec<u64> = Vec::new();
    for target in &recovery.call_targets {
        if seen.contains(target) {
            continue;
        }
        seen.push(*target);
        let resolved: Option<(Vec<u8>, u64)> = function_code_at(object_bytes, *target)
            .map(|(c, b, _): (Vec<u8>, u64, String)| (c, b))
            .or_else(|| {
                let callee_name: String =
                    elf_call_callee_for_target(object_bytes, case.caller, *target)?;
                function_code(object_bytes, &callee_name)
            });
        let Some((callee_code, callee_base)): Option<(Vec<u8>, u64)> = resolved else {
            eprintln!("skip {}: callee at {target:#x} not located", case.caller);
            return None;
        };
        let callee: LeafRecovery =
            match recover_leaf_function_abi(&callee_code, callee_base, PseudoAbi::SysV) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("skip {}: callee not in leaf class ({e})", case.caller);
                    return None;
                }
            };
        let callee_name: String = format!("sub_{target:x}");
        let callee_renamed: String = rename_recovered(&callee.source, &callee_name);
        let callee_padded: String = pad_callee_signature(&callee_renamed, &callee_name, full_arity);
        decls.push_str(&callee_padded);
        decls.push('\n');
    }
    let caller_name: String = format!("rec_{}", case.caller);
    let caller_renamed: String = rename_recovered(&recovery.source, &caller_name);
    decls.push_str(&caller_renamed);
    decls.push('\n');
    let _ = writeln!(
        decls,
        "extern long long {}({});",
        case.caller,
        vec!["long long"; case.arity].join(", ")
    );

    let args: Vec<String> = (0..case.arity).map(|i: usize| format!("in[{i}]")).collect();
    let rec_args: Vec<String> = (0..full_arity)
        .map(|i: usize| format!("(uint64_t)in[{i}]"))
        .collect();
    let mut snippet: String = String::new();
    let _ = write!(
        snippet,
        "    for (size_t k = 0; k < n_inputs; k++) {{\n\
         \x20       long long in[3] = {{ inputs[k][0], inputs[k][1], inputs[k][2] }};\n\
         \x20       unsigned long long want = (unsigned long long){}({});\n\
         \x20       unsigned long long got = {caller_name}({});\n\
         \x20       if (want != got) {{ printf(\"MISMATCH {} in=%lld,%lld,%lld want=%llu got=%llu\\n\", in[0], in[1], in[2], want, got); return 1; }}\n\
         \x20   }}\n",
        case.caller,
        args.join(", "),
        rec_args.join(", "),
        case.caller,
    );
    Some((decls, snippet, full_arity))
}

#[test]
fn sysv_same_object_call_leaf_functions_recompile_to_behavioral_equivalence() {
    if !sysv_host_can_run() {
        return;
    }
    let mut battery_src: String = String::new();
    for case in CALL_BATTERY {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let Some(objs): Option<SysvCrossObjects> = compile_sysv_cross("call", &battery_src) else {
        return;
    };

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;

    for case in CALL_BATTERY {
        let Some((decls, snippet, _)): Option<(String, String, usize)> =
            sysv_lift_call_case(case, &objs.sysv_object)
        else {
            continue;
        };
        recovered_decls.push_str(&decls);
        driver_body.push_str(&snippet);
        lifted_count += 1;
    }

    assert!(
        lifted_count >= 5,
        "SysV call leaf lifter must reconstruct at least 5 of the {} caller/helper pairs, only lifted {lifted_count}",
        CALL_BATTERY.len()
    );

    let driver: String = build_call_driver(&recovered_decls, &driver_body);
    let stdout: String = link_and_run_sysv("call", &driver, &objs.host_object, 30);
    assert!(
        stdout.contains("OK"),
        "SysV call behavioral differential FAILED ({lifted_count} cases): {stdout}"
    );
    println!(
        "SysV same-object-call behavioral differential PASSED for {lifted_count} caller/helper pairs (SysV ABI)"
    );
}

#[test]
fn sysv_precise_call_recovery_recompiles_against_real_helpers() {
    if !sysv_host_can_run() {
        return;
    }
    let mut battery_src: String = String::new();
    for case in CALL_BATTERY {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let Some(objs): Option<SysvCrossObjects> = compile_sysv_cross("pcall", &battery_src) else {
        return;
    };

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;

    for case in CALL_BATTERY {
        let Some((decls, snippet)): Option<(String, String)> =
            lift_precise_call_case(case, &objs.sysv_object, PseudoAbi::SysV)
        else {
            continue;
        };
        recovered_decls.push_str(&decls);
        driver_body.push_str(&snippet);
        lifted_count += 1;
    }

    assert!(
        lifted_count >= 5,
        "SysV precise call lifter must reconstruct at least 5 of the {} caller/helper pairs, only lifted {lifted_count}",
        CALL_BATTERY.len()
    );
    assert!(
        recovered_decls.contains("extern uint64_t h_sq(uint64_t);")
            && recovered_decls.contains("r_rax = h_sq("),
        "the callee must be named from its relocation symbol with its recovered single-argument arity: {recovered_decls}"
    );
    assert!(
        !recovered_decls.contains("sub_"),
        "every same-object helper resolves via relocation, so no synthetic sub_<va> name should remain: {recovered_decls}"
    );

    let driver: String = build_call_driver(&recovered_decls, &driver_body);
    let stdout: String = link_and_run_sysv("pcall", &driver, &objs.host_object, 30);
    assert!(
        stdout.contains("OK"),
        "SysV precise call differential FAILED ({lifted_count} cases): {stdout}"
    );
    println!(
        "SysV precise call recovery (relocation-named, callee-arity args) recompiled against the REAL helpers PASSED for {lifted_count} caller/helper pairs (SysV ABI)"
    );
}

#[test]
fn sysv_closed_form_mul_shift_leaf_functions_recompile_to_behavioral_equivalence() {
    if !sysv_host_can_run() {
        return;
    }
    let Some(objs): Option<SysvCrossObjects> =
        compile_sysv_cross("cform", &battery_source(CLOSED_FORM_BATTERY))
    else {
        return;
    };

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    let mut wide_count: usize = 0;
    let mut dshift_count: usize = 0;

    for case in CLOSED_FORM_BATTERY {
        if recovered_wide_arith(&objs.sysv_object, case.name, PseudoAbi::SysV) {
            wide_count += 1;
        }
        if recovered_double_shift(&objs.sysv_object, case.name, PseudoAbi::SysV) {
            dshift_count += 1;
        }
        let Some(lifted): Option<Lifted> = process_case(case, &objs.sysv_object, PseudoAbi::SysV)
        else {
            continue;
        };
        recovered_decls.push_str(&lifted.decls);
        driver_body.push_str(&lifted.driver_snippet);
        lifted_count += 1;
    }

    assert!(
        wide_count >= 4,
        "SysV closed-form oracle must exercise mul/imul-imm lifting; only {wide_count} recovered functions carried wide multiply arithmetic"
    );
    assert!(
        dshift_count >= 2,
        "SysV closed-form oracle must exercise shld/shrd lifting; only {dshift_count} recovered functions carried a double-precision shift"
    );
    assert!(
        lifted_count >= 5,
        "SysV closed-form lifter must handle at least 5 of the {} cases, only lifted {lifted_count}",
        CLOSED_FORM_BATTERY.len()
    );

    let driver: String = build_driver(&recovered_decls, &driver_body);
    let stdout: String = link_and_run_sysv("cform", &driver, &objs.host_object, 30);
    assert!(
        stdout.contains("OK"),
        "SysV closed-form behavioral differential FAILED ({lifted_count} cases, {wide_count} wide, {dshift_count} dshift): {stdout}"
    );
    println!(
        "SysV closed-form behavioral differential PASSED for {lifted_count} leaf functions ({wide_count} mul/imul-imm, {dshift_count} shld/shrd, SysV ABI)"
    );
}

const DIV_BATTERY: &[Case] = &[
    Case {
        name: "dv_sdiv",
        arity: 2,
        c_source: "long long dv_sdiv(long long a, long long b){ return a / b; }",
    },
    Case {
        name: "dv_srem",
        arity: 2,
        c_source: "long long dv_srem(long long a, long long b){ return a % b; }",
    },
    Case {
        name: "dv_udiv",
        arity: 2,
        c_source: "unsigned long long dv_udiv(unsigned long long a, unsigned long long b){ return a / b; }",
    },
    Case {
        name: "dv_urem",
        arity: 2,
        c_source: "unsigned long long dv_urem(unsigned long long a, unsigned long long b){ return a % b; }",
    },
    Case {
        name: "dv_sdiv32",
        arity: 2,
        c_source: "int dv_sdiv32(int a, int b){ return a / b; }",
    },
    Case {
        name: "dv_srem32",
        arity: 2,
        c_source: "int dv_srem32(int a, int b){ return a % b; }",
    },
    Case {
        name: "dv_udiv32",
        arity: 2,
        c_source: "unsigned dv_udiv32(unsigned a, unsigned b){ return a / b; }",
    },
    Case {
        name: "dv_divmod",
        arity: 2,
        c_source: "long long dv_divmod(long long a, long long b){ return (a / b) + (a % b); }",
    },
];

fn div_lift(
    case: &Case,
    object_bytes: &[u8],
    abi: PseudoAbi,
) -> Option<(LeafRecovery, String, String)> {
    let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(object_bytes, case.name) else {
        eprintln!("skip {}: symbol not located", case.name);
        return None;
    };
    let recovery: LeafRecovery = match recover_leaf_function_abi(&code, base, abi) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "skip {} ({abi:?}): not in divide leaf class ({e})",
                case.name
            );
            return None;
        }
    };
    let recovered_name: String = format!("rec_{}", case.name);
    let renamed: String = recovery
        .source
        .replacen(
            "uint64_t recovered(",
            &format!("uint64_t {recovered_name}("),
            1,
        )
        .lines()
        .filter(|l: &&str| !l.starts_with("#include"))
        .collect::<Vec<&str>>()
        .join("\n");
    Some((recovery, renamed, recovered_name))
}

fn div_driver_snippet(case: &Case, recovery: &LeafRecovery, recovered_name: &str) -> String {
    let return_mask: String = if recovery.return_width_bits == 64 {
        "0xFFFFFFFFFFFFFFFFULL".to_owned()
    } else {
        format!("0x{:x}ULL", (1u128 << recovery.return_width_bits) - 1)
    };
    let args: Vec<String> = (0..case.arity).map(|i: usize| format!("in[{i}]")).collect();
    let rec_args: Vec<String> = (0..recovery.params.len())
        .map(|i: usize| format!("(uint64_t)in[{i}]"))
        .collect();
    let mut snippet: String = String::new();
    let _ = write!(
        snippet,
        "    for (size_t k = 0; k < n_pairs; k++) {{\n\
         \x20       long long in[2] = {{ pairs[k][0], pairs[k][1] }};\n\
         \x20       unsigned long long want = (unsigned long long){}({}) & {return_mask};\n\
         \x20       unsigned long long got = {recovered_name}({}) & {return_mask};\n\
         \x20       if (want != got) {{ printf(\"MISMATCH {} in=%lld,%lld want=%llu got=%llu\\n\", in[0], in[1], want, got); return 1; }}\n\
         \x20   }}\n",
        case.name,
        args.join(", "),
        rec_args.join(", "),
        case.name,
    );
    snippet
}

fn build_div_driver(recovered_decls: &str, driver_body: &str) -> String {
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n{recovered_decls}\n\
         int main(void) {{\n\
         \x20   long long pairs[][2] = {{\n\
         \x20       {{0,1}},{{1,1}},{{-1,1}},{{7,3}},{{-7,3}},{{7,-3}},{{-7,-3}},\n\
         \x20       {{100,7}},{{-100,7}},{{123456,789}},{{-123456,789}},\n\
         \x20       {{2147483647,3}},{{-2147483648LL,3}},{{0x7fffffffffffffffLL,1000000007LL}},\n\
         \x20       {{255,16}},{{65535,256}},{{1000000000LL,3}},{{-1000000000LL,-3}},\n\
         \x20       {{42,42}},{{5,9}},{{0,-7}},{{2147483647,2147483646}}\n\
         \x20   }};\n\
         \x20   size_t n_pairs = sizeof(pairs)/sizeof(pairs[0]);\n\
         {driver_body}\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n"
    )
}

fn div_recovered(object_bytes: &[u8], name: &str, abi: PseudoAbi) -> bool {
    let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(object_bytes, name) else {
        return false;
    };
    let recovery: LeafRecovery = match recover_leaf_function_abi(&code, base, abi) {
        Ok(r) => r,
        Err(_) => return false,
    };
    recovery.source.contains("div_lhs / div_rhs") || recovery.source.contains("div_lhs % div_rhs")
}

#[test]
fn divide_leaf_functions_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(builder): Option<String> = clang() else {
        eprintln!(
            "skipping divide oracle: clang (needed for a plain cqo/idiv, div lowering) not on PATH"
        );
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let battery_c: PathBuf = dir.join("div_battery.c");
    std::fs::write(&battery_c, battery_source(DIV_BATTERY).as_bytes())
        .expect("write div_battery.c");
    let battery_o: PathBuf = dir.join("div_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args(["-O1", "-fno-stack-protector", "-c", "-o"])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke clang for divide battery");
    assert!(
        compile_battery.status.success(),
        "divide battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read div_battery.o");

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    let mut div_count: usize = 0;

    for case in DIV_BATTERY {
        if div_recovered(&object_bytes, case.name, HOST_ABI) {
            div_count += 1;
        }
        let Some((recovery, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
            div_lift(case, &object_bytes, HOST_ABI)
        else {
            continue;
        };
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        let _ = writeln!(
            recovered_decls,
            "extern long long {}({});",
            case.name,
            vec!["long long"; case.arity].join(", ")
        );
        driver_body.push_str(&div_driver_snippet(case, &recovery, &recovered_name));
        lifted_count += 1;
    }

    if lifted_count == 0 {
        eprintln!(
            "skipping divide behavioral differential: this compiler build lowered none of the {} battery cases into the divide leaf class ({div_count} carried a division)",
            DIV_BATTERY.len()
        );
        return;
    }

    let driver: String = build_div_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("div_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write div_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "div_harness.exe"
    } else {
        "div_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke clang to link div harness");
    assert!(
        link.status.success(),
        "div harness link failed: {}\n--- div_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run div harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "divide behavioral differential FAILED ({lifted_count} cases, {div_count} carried a division): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "divide behavioral differential PASSED for {lifted_count} leaf functions ({div_count} idiv/div, host ABI)"
    );
}

#[test]
fn divide_oracle_has_teeth_swapping_signedness_diverges() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(builder): Option<String> = clang() else {
        eprintln!("skipping divide teeth check: clang not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let probe: &Case = &DIV_BATTERY[0];
    let battery_c: PathBuf = dir.join("div_teeth_battery.c");
    std::fs::write(&battery_c, probe.c_source.as_bytes()).expect("write div_teeth_battery.c");
    let battery_o: PathBuf = dir.join("div_teeth_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args(["-O1", "-fno-stack-protector", "-c", "-o"])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke clang for div teeth battery");
    assert!(
        compile_battery.status.success(),
        "div teeth battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read div_teeth_battery.o");

    let Some((recovery, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
        div_lift(probe, &object_bytes, HOST_ABI)
    else {
        eprintln!("skipping divide teeth check: probe did not lift into the divide class");
        return;
    };
    let sabotaged: String = renamed
        .replace(
            "int64_t div_lhs = (int64_t)",
            "uint64_t div_lhs = (uint64_t)",
        )
        .replace(
            "int64_t div_rhs = (int64_t)",
            "uint64_t div_rhs = (uint64_t)",
        );
    assert_ne!(
        sabotaged, renamed,
        "the signed divide must declare int64_t div operands to sabotage"
    );

    let mut decls: String = String::new();
    decls.push_str(&sabotaged);
    decls.push('\n');
    let _ = writeln!(
        decls,
        "extern long long {}({});",
        probe.name,
        vec!["long long"; probe.arity].join(", ")
    );
    let driver_body: String = div_driver_snippet(probe, &recovery, &recovered_name);
    let driver: String = build_div_driver(&decls, &driver_body);
    let driver_c: PathBuf = dir.join("div_teeth_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write div_teeth_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "div_teeth_harness.exe"
    } else {
        "div_teeth_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke clang to link div teeth harness");
    assert!(
        link.status.success(),
        "div teeth harness link failed: {}\n--- div_teeth_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run div teeth harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        stdout.contains("MISMATCH") || !run.status.success(),
        "reinterpreting a signed divide as unsigned must diverge on negative dividends; instead the harness reported: {stdout}"
    );
    println!(
        "divide oracle teeth confirmed: unsigned reinterpretation diverges on negative inputs"
    );
}

#[test]
fn sysv_divide_leaf_functions_recompile_to_behavioral_equivalence() {
    if !sysv_host_can_run() {
        return;
    }
    let Some(objs): Option<SysvCrossObjects> =
        compile_sysv_cross("div", &battery_source(DIV_BATTERY))
    else {
        return;
    };

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    let mut div_count: usize = 0;

    for case in DIV_BATTERY {
        if div_recovered(&objs.sysv_object, case.name, PseudoAbi::SysV) {
            div_count += 1;
        }
        let Some((recovery, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
            div_lift(case, &objs.sysv_object, PseudoAbi::SysV)
        else {
            continue;
        };
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        let _ = writeln!(
            recovered_decls,
            "extern long long {}({});",
            case.name,
            vec!["long long"; case.arity].join(", ")
        );
        driver_body.push_str(&div_driver_snippet(case, &recovery, &recovered_name));
        lifted_count += 1;
    }

    assert!(
        div_count >= 6,
        "SysV divide oracle must exercise idiv/div lifting; only {div_count} recovered functions carried a division"
    );
    assert!(
        lifted_count >= 6,
        "SysV divide lifter must handle at least 6 of the {} cases, only lifted {lifted_count}",
        DIV_BATTERY.len()
    );

    let driver: String = build_div_driver(&recovered_decls, &driver_body);
    let stdout: String = link_and_run_sysv("div", &driver, &objs.host_object, 30);
    assert!(
        stdout.contains("OK"),
        "SysV divide behavioral differential FAILED ({lifted_count} cases, {div_count} idiv/div): {stdout}"
    );
    println!(
        "SysV divide behavioral differential PASSED for {lifted_count} leaf functions ({div_count} idiv/div, SysV ABI)"
    );
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FpArg {
    Double,
    Float,
    LongLong,
    Int,
}

impl FpArg {
    const fn c_type(self) -> &'static str {
        match self {
            Self::Double => "double",
            Self::Float => "float",
            Self::LongLong => "long long",
            Self::Int => "int",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FpRet {
    Double,
    Float,
    LongLong,
}

struct FpCase {
    name: &'static str,
    args: &'static [FpArg],
    ret: FpRet,
    c_source: &'static str,
}

const FP_BATTERY: &[FpCase] = &[
    FpCase {
        name: "fv_addd",
        args: &[FpArg::Double, FpArg::Double],
        ret: FpRet::Double,
        c_source: "double fv_addd(double a, double b){ return a + b; }",
    },
    FpCase {
        name: "fv_subd",
        args: &[FpArg::Double, FpArg::Double],
        ret: FpRet::Double,
        c_source: "double fv_subd(double a, double b){ return a - b; }",
    },
    FpCase {
        name: "fv_muld",
        args: &[FpArg::Double, FpArg::Double],
        ret: FpRet::Double,
        c_source: "double fv_muld(double a, double b){ return a * b; }",
    },
    FpCase {
        name: "fv_divd",
        args: &[FpArg::Double, FpArg::Double],
        ret: FpRet::Double,
        c_source: "double fv_divd(double a, double b){ return a / b; }",
    },
    FpCase {
        name: "fv_adds",
        args: &[FpArg::Float, FpArg::Float],
        ret: FpRet::Float,
        c_source: "float fv_adds(float a, float b){ return a + b; }",
    },
    FpCase {
        name: "fv_muls",
        args: &[FpArg::Float, FpArg::Float],
        ret: FpRet::Float,
        c_source: "float fv_muls(float a, float b){ return a * b; }",
    },
    FpCase {
        name: "fv_divs",
        args: &[FpArg::Float, FpArg::Float],
        ret: FpRet::Float,
        c_source: "float fv_divs(float a, float b){ return a / b; }",
    },
    FpCase {
        name: "fv_i2d",
        args: &[FpArg::LongLong],
        ret: FpRet::Double,
        c_source: "double fv_i2d(long long a){ return (double)a; }",
    },
    FpCase {
        name: "fv_i2s",
        args: &[FpArg::LongLong],
        ret: FpRet::Float,
        c_source: "float fv_i2s(long long a){ return (float)a; }",
    },
    FpCase {
        name: "fv_d2i",
        args: &[FpArg::Double],
        ret: FpRet::LongLong,
        c_source: "long long fv_d2i(double a){ return (long long)a; }",
    },
    FpCase {
        name: "fv_f2d",
        args: &[FpArg::Float],
        ret: FpRet::Double,
        c_source: "double fv_f2d(float a){ return (double)a; }",
    },
    FpCase {
        name: "fv_d2f",
        args: &[FpArg::Double],
        ret: FpRet::Float,
        c_source: "float fv_d2f(double a){ return (float)a; }",
    },
    FpCase {
        name: "fv_cmpdiv",
        args: &[FpArg::Double, FpArg::Double],
        ret: FpRet::Double,
        c_source: "double fv_cmpdiv(double a, double b){ if (a < b) return a / b; return b / a; }",
    },
    FpCase {
        name: "fv_mixed",
        args: &[FpArg::Double, FpArg::Int],
        ret: FpRet::Double,
        c_source: "double fv_mixed(double a, int n){ return a * (double)n; }",
    },
    FpCase {
        name: "fv_chain",
        args: &[FpArg::Double, FpArg::Double],
        ret: FpRet::Double,
        c_source: "double fv_chain(double a, double b){ double r = a + b; r = r * a; r = r - b; return r; }",
    },
    FpCase {
        name: "fv_add15",
        args: &[FpArg::Double],
        ret: FpRet::Double,
        c_source: "double fv_add15(double a){ return a + 1.5; }",
    },
    FpCase {
        name: "fv_mulpi",
        args: &[FpArg::Double],
        ret: FpRet::Double,
        c_source: "double fv_mulpi(double a){ return a * 3.14159; }",
    },
    FpCase {
        name: "fv_subhalff",
        args: &[FpArg::Float],
        ret: FpRet::Float,
        c_source: "float fv_subhalff(float a){ return a - 0.5f; }",
    },
    FpCase {
        name: "fv_eqd",
        args: &[FpArg::Double, FpArg::Double],
        ret: FpRet::LongLong,
        c_source: "long long fv_eqd(double a, double b){ return a == b; }",
    },
    FpCase {
        name: "fv_ltd",
        args: &[FpArg::Double, FpArg::Double],
        ret: FpRet::LongLong,
        c_source: "long long fv_ltd(double a, double b){ return a < b; }",
    },
    FpCase {
        name: "fv_arg4d",
        args: &[FpArg::Double, FpArg::Double, FpArg::Double, FpArg::Double],
        ret: FpRet::Double,
        c_source: "double fv_arg4d(double a, double b, double c, double d){ return a * b + c - d; }",
    },
];

fn fp_battery_source(cases: &[FpCase]) -> String {
    let mut src: String = String::new();
    for case in cases {
        src.push_str(case.c_source);
        src.push('\n');
    }
    src
}

fn fp_signature(args: &[FpArg]) -> String {
    if args.is_empty() {
        return "void".to_owned();
    }
    args.iter()
        .enumerate()
        .map(|(i, a): (usize, &FpArg)| format!("{} p{i}", a.c_type()))
        .collect::<Vec<String>>()
        .join(", ")
}

fn fp_extern_decl(case: &FpCase) -> String {
    let ret: &str = match case.ret {
        FpRet::Double => "double",
        FpRet::Float => "float",
        FpRet::LongLong => "long long",
    };
    format!("extern {ret} {}({});", case.name, fp_signature(case.args))
}

fn fp_lift(
    case: &FpCase,
    object_bytes: &[u8],
    abi: PseudoAbi,
) -> Option<(LeafRecovery, String, String)> {
    let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(object_bytes, case.name) else {
        eprintln!("skip {}: symbol not located", case.name);
        return None;
    };
    let consts: Vec<FpConstant> = resolve_fp_constants(object_bytes, &code, base);
    let recovery: LeafRecovery = match recover_leaf_function_const_abi(&code, base, abi, &consts) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "skip {} ({abi:?}): not in scalar float leaf class ({e})",
                case.name
            );
            return None;
        }
    };
    assert_eq!(
        recovery.returns_fp.is_none(),
        matches!(case.ret, FpRet::LongLong),
        "{} ({abi:?}): the recovered return class must follow the source return type, not the last floating register the body happens to load; got returns_fp={:?} for {}",
        case.name,
        recovery.returns_fp,
        case.c_source
    );
    let recovered_name: String = format!("rec_{}", case.name);
    let ret_type: &str = match case.ret {
        FpRet::Double => "double",
        FpRet::Float => "float",
        FpRet::LongLong => "uint64_t",
    };
    let renamed: String = recovery.source.replacen(
        &format!("{ret_type} recovered("),
        &format!("{ret_type} {recovered_name}("),
        1,
    );
    let renamed: String = strip_shared_fp_prelude(&renamed);
    Some((recovery, renamed, recovered_name))
}

fn fp_arg_expr(arg: FpArg, slot: usize) -> String {
    match arg {
        FpArg::Double => format!("pairs[k][{slot}]"),
        FpArg::Float => format!("(float)pairs[k][{slot}]"),
        FpArg::LongLong => format!("(long long)pairs[k][{slot}]"),
        FpArg::Int => format!("(int)pairs[k][{slot}]"),
    }
}

fn fp_driver_snippet(case: &FpCase, recovered_name: &str) -> String {
    let call_args: Vec<String> = case
        .args
        .iter()
        .enumerate()
        .map(|(slot, a): (usize, &FpArg)| fp_arg_expr(*a, slot))
        .collect();
    let joined: String = call_args.join(", ");
    let (bit_ty, to_bits): (&str, &str) = match case.ret {
        FpRet::Double => ("uint64_t", "d_bits"),
        FpRet::Float => ("uint32_t", "f_bits"),
        FpRet::LongLong => ("uint64_t", "i_bits"),
    };
    let mut snippet: String = String::new();
    let _ = write!(
        snippet,
        "    for (size_t k = 0; k < n_pairs; k++) {{\n\
         \x20       {bit_ty} want = {to_bits}({}({joined}));\n\
         \x20       {bit_ty} got = {to_bits}({recovered_name}({joined}));\n\
         \x20       if (want != got) {{ printf(\"MISMATCH {} in=%g,%g want=%llu got=%llu\\n\", pairs[k][0], pairs[k][1], (unsigned long long)want, (unsigned long long)got); return 1; }}\n\
         \x20   }}\n",
        case.name, case.name,
    );
    snippet
}

fn strip_shared_fp_prelude(source: &str) -> String {
    let prelude: BTreeSet<String> = fp_semantics::prelude_lines().into_iter().collect();
    let lines: Vec<&str> = source.lines().collect();
    let mut start: usize = 0;
    while let Some(line) = lines.get(start) {
        let shared: bool = line.starts_with("#include")
            || line.trim_start().starts_with("static inline")
            || prelude.contains(*line);
        if !shared {
            break;
        }
        start = start.saturating_add(1);
    }
    lines.get(start..).unwrap_or_default().join("\n")
}

fn build_fp_driver(recovered_decls: &str, driver_body: &str) -> String {
    format!(
        "#include <stdint.h>\n#include <string.h>\n#include <stdio.h>\n#include <stddef.h>\n\
         static inline double fp_d_from_bits(uint64_t b){{ double v; memcpy(&v,&b,8); return v; }}\n\
         static inline uint64_t fp_d_to_bits(double v){{ uint64_t b; memcpy(&b,&v,8); return b; }}\n\
         static inline float fp_f_from_bits(uint32_t b){{ float v; memcpy(&v,&b,4); return v; }}\n\
         static inline uint32_t fp_f_to_bits(float v){{ uint32_t b; memcpy(&b,&v,4); return b; }}\n\
         static inline uint64_t d_bits(double v){{ uint64_t b; memcpy(&b,&v,8); return b; }}\n\
         static inline uint32_t f_bits(float v){{ uint32_t b; memcpy(&b,&v,4); return b; }}\n\
         static inline uint64_t i_bits(long long v){{ uint64_t b; memcpy(&b,&v,8); return b; }}\n\
         {}\n\
         {recovered_decls}\n\
         int main(void) {{\n\
         \x20   double pairs[][4] = {{\n\
         \x20       {{0.0,1.0,2.0,3.0}},{{1.0,1.0,-1.0,0.5}},{{-1.0,1.0,6.0,-2.0}},\n\
         \x20       {{7.0,3.0,0.25,11.0}},{{-7.0,3.0,-0.25,4.0}},{{7.0,-3.0,8.5,-8.5}},\n\
         \x20       {{3.5,2.25,1.75,0.125}},{{-3.5,2.25,-1.75,9.0}},{{100.0,7.0,13.0,-6.0}},\n\
         \x20       {{-100.0,-7.0,-13.0,6.0}},{{0.1,0.2,0.3,0.4}},{{123456.75,789.5,2.5,-64.0}},\n\
         \x20       {{2147483647.0,3.0,-5.0,17.0}},{{1e18,1e-3,1e6,-1e6}},{{-1e18,3.0,7.5,0.0}},\n\
         \x20       {{42.0,42.0,42.0,42.0}},{{5.0,9.0,-9.0,-5.0}},{{0.0,-7.0,14.0,0.5}},\n\
         \x20       {{1e-30,1e30,1.0,-1.0}},{{-0.0,4.0,-4.0,0.0}}\n\
         \x20   }};\n\
         \x20   size_t n_pairs = sizeof(pairs)/sizeof(pairs[0]);\n\
         {driver_body}\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n",
        fp_semantics::prelude_source()
    )
}

fn fp_lifts_to_scalar_float(object_bytes: &[u8], name: &str, abi: PseudoAbi) -> bool {
    let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(object_bytes, name) else {
        return false;
    };
    let consts: Vec<FpConstant> = resolve_fp_constants(object_bytes, &code, base);
    match recover_leaf_function_const_abi(&code, base, abi, &consts) {
        Ok(r) => {
            r.source.contains("fp_d_from_bits")
                || r.source.contains("fp_f_from_bits")
                || r.source.contains("fp_d_to_bits")
                || r.source.contains("fp_f_to_bits")
        }
        Err(_) => false,
    }
}

fn fp_width_bytes(mnemonic: &str) -> Option<usize> {
    match mnemonic {
        "movsd" | "addsd" | "subsd" | "mulsd" | "divsd" | "ucomisd" | "comisd" | "minsd"
        | "maxsd" => Some(8),
        "movss" | "addss" | "subss" | "mulss" | "divss" | "ucomiss" | "comiss" | "minss"
        | "maxss" => Some(4),
        _ => None,
    }
}

fn resolve_fp_constants(object_bytes: &[u8], code: &[u8], base: u64) -> Vec<FpConstant> {
    let Ok(file): Result<object::File<'_>, _> = object::File::parse(object_bytes) else {
        return Vec::new();
    };
    let Ok(insns): Result<Vec<disrobe_pass_native::DisasmInsn>, _> =
        disassemble(Arch::X86_64, base, code)
    else {
        return Vec::new();
    };
    let Some(text): Option<object::Section<'_, '_>> = file.section_by_name(".text") else {
        return Vec::new();
    };
    let mut out: Vec<FpConstant> = Vec::new();
    for insn in &insns {
        let Some(len): Option<usize> = fp_width_bytes(&insn.mnemonic) else {
            continue;
        };
        if !insn.operands.contains("[rel ") {
            continue;
        }
        let disp_off: u64 = insn.address + insn.bytes.len() as u64 - 4;
        for (off, reloc) in text.relocations() {
            if off != disp_off {
                continue;
            }
            let object::RelocationTarget::Symbol(si) = reloc.target() else {
                continue;
            };
            let Ok(sym): Result<object::Symbol<'_, '_>, _> = file.symbol_by_index(si) else {
                continue;
            };
            let implicit_addend: i64 = if reloc.has_implicit_addend() {
                let Ok(slot): Result<usize, _> = usize::try_from(off - text.address()) else {
                    continue;
                };
                let Some(bytes): Option<[u8; 4]> = text
                    .data()
                    .ok()
                    .and_then(|d: &[u8]| d.get(slot..slot + 4))
                    .and_then(|s: &[u8]| s.try_into().ok())
                else {
                    continue;
                };
                i64::from(i32::from_le_bytes(bytes)) + reloc.addend()
            } else {
                reloc.addend()
            };
            let target_va: i64 = sym.address() as i64 + implicit_addend + 4;
            let Some((section, section_va)): Option<(object::Section<'_, '_>, u64)> =
                (match sym.section() {
                    object::SymbolSection::Section(idx) => {
                        file.section_by_index(idx)
                            .ok()
                            .map(|s: object::Section<'_, '_>| {
                                let addr: u64 = s.address();
                                (s, addr)
                            })
                    }
                    _ => None,
                })
            else {
                continue;
            };
            let Ok(rel_off): Result<usize, _> = usize::try_from(target_va - section_va as i64)
            else {
                continue;
            };
            let Some(raw): Option<&[u8]> = section
                .data()
                .ok()
                .and_then(|d: &[u8]| d.get(rel_off..rel_off + len))
            else {
                continue;
            };
            let mut le: [u8; 8] = [0u8; 8];
            le[..len].copy_from_slice(raw);
            out.push(FpConstant {
                site: insn.address,
                bits: u64::from_le_bytes(le),
            });
        }
    }
    out
}

#[test]
fn scalar_float_leaf_functions_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guard"
        );
        return;
    }
    let Some(builder): Option<String> = clang() else {
        eprintln!(
            "skipping scalar float oracle: clang (needed for a clean scalar SSE lowering) not on PATH"
        );
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let battery_c: PathBuf = dir.join("fp_battery.c");
    std::fs::write(&battery_c, fp_battery_source(FP_BATTERY).as_bytes())
        .expect("write fp_battery.c");
    let battery_o: PathBuf = dir.join("fp_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args(["-O1", "-fno-stack-protector", "-c", "-o"])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke clang for scalar float battery");
    assert!(
        compile_battery.status.success(),
        "scalar float battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read fp_battery.o");

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    let mut fp_count: usize = 0;

    for case in FP_BATTERY {
        if fp_lifts_to_scalar_float(&object_bytes, case.name, HOST_ABI) {
            fp_count += 1;
        }
        let Some((_, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
            fp_lift(case, &object_bytes, HOST_ABI)
        else {
            continue;
        };
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        recovered_decls.push_str(&fp_extern_decl(case));
        recovered_decls.push('\n');
        driver_body.push_str(&fp_driver_snippet(case, &recovered_name));
        lifted_count += 1;
    }

    if lifted_count == 0 {
        eprintln!(
            "skipping scalar float behavioral differential: this compiler build lowered none of the {} battery cases into the scalar float leaf class ({fp_count} carried scalar SSE)",
            FP_BATTERY.len()
        );
        return;
    }

    let driver: String = build_fp_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("fp_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write fp_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "fp_harness.exe"
    } else {
        "fp_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke clang to link fp harness");
    assert!(
        link.status.success(),
        "fp harness link failed: {}\n--- fp_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe).output().expect("run fp harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "scalar float behavioral differential FAILED ({lifted_count} cases, {fp_count} carried scalar SSE): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "scalar float behavioral differential PASSED for {lifted_count} leaf functions ({fp_count} scalar SSE, host ABI)"
    );
}

#[test]
fn scalar_float_oracle_has_teeth_swapping_op_and_width_diverges() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guard"
        );
        return;
    }
    let Some(builder): Option<String> = clang() else {
        eprintln!("skipping scalar float teeth check: clang not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let probe: &FpCase = &FP_BATTERY[0];
    let battery_c: PathBuf = dir.join("fp_teeth_battery.c");
    std::fs::write(&battery_c, probe.c_source.as_bytes()).expect("write fp_teeth_battery.c");
    let battery_o: PathBuf = dir.join("fp_teeth_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args(["-O1", "-fno-stack-protector", "-c", "-o"])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke clang for fp teeth battery");
    assert!(
        compile_battery.status.success(),
        "fp teeth battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read fp_teeth_battery.o");

    let Some((_, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
        fp_lift(probe, &object_bytes, HOST_ABI)
    else {
        eprintln!("skipping scalar float teeth check: probe did not lift into the scalar class");
        return;
    };
    let sabotaged: String = renamed.replacen(
        "fp_d_from_bits(x_xmm0) + fp_d_from_bits(x_xmm1)",
        "fp_d_from_bits(x_xmm0) - fp_d_from_bits(x_xmm1)",
        1,
    );
    assert_ne!(
        sabotaged, renamed,
        "the double add must be present to be sabotaged into a subtract"
    );

    let mut decls: String = String::new();
    decls.push_str(&sabotaged);
    decls.push('\n');
    decls.push_str(&fp_extern_decl(probe));
    decls.push('\n');
    let driver_body: String = fp_driver_snippet(probe, &recovered_name);
    let driver: String = build_fp_driver(&decls, &driver_body);
    let driver_c: PathBuf = dir.join("fp_teeth_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write fp_teeth_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "fp_teeth_harness.exe"
    } else {
        "fp_teeth_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke clang to link fp teeth harness");
    assert!(
        link.status.success(),
        "fp teeth harness link failed: {}\n--- fp_teeth_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run fp teeth harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        stdout.contains("MISMATCH") || !run.status.success(),
        "swapping addsd for subsd must diverge on the input battery; instead the harness reported: {stdout}"
    );
    println!("scalar float oracle teeth confirmed: add/sub swap diverges");
}

#[test]
fn sysv_scalar_float_leaf_functions_recompile_to_behavioral_equivalence() {
    if !sysv_host_can_run() {
        return;
    }
    let Some(objs): Option<SysvCrossObjects> =
        compile_sysv_cross("fp", &fp_battery_source(FP_BATTERY))
    else {
        return;
    };

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    let mut fp_count: usize = 0;

    for case in FP_BATTERY {
        if fp_lifts_to_scalar_float(&objs.sysv_object, case.name, PseudoAbi::SysV) {
            fp_count += 1;
        }
        let Some((_, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
            fp_lift(case, &objs.sysv_object, PseudoAbi::SysV)
        else {
            continue;
        };
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        recovered_decls.push_str(&fp_extern_decl(case));
        recovered_decls.push('\n');
        driver_body.push_str(&fp_driver_snippet(case, &recovered_name));
        lifted_count += 1;
    }

    assert!(
        fp_count >= 10,
        "SysV scalar float oracle must exercise scalar SSE lifting; only {fp_count} recovered functions carried scalar float ops"
    );
    assert!(
        lifted_count >= 10,
        "SysV scalar float lifter must handle at least 10 of the {} cases, only lifted {lifted_count}",
        FP_BATTERY.len()
    );

    let driver: String = build_fp_driver(&recovered_decls, &driver_body);
    let stdout: String = link_and_run_sysv("fp", &driver, &objs.host_object, 30);
    assert!(
        stdout.contains("OK"),
        "SysV scalar float behavioral differential FAILED ({lifted_count} cases, {fp_count} scalar SSE): {stdout}"
    );
    println!(
        "SysV scalar float behavioral differential PASSED for {lifted_count} leaf functions ({fp_count} scalar SSE, SysV ABI)"
    );
}

const MINMAX_BATTERY: &[FpCase] = &[
    FpCase {
        name: "mm_mind",
        args: &[FpArg::Double, FpArg::Double],
        ret: FpRet::Double,
        c_source: "double mm_mind(double a, double b){ return a < b ? a : b; }",
    },
    FpCase {
        name: "mm_maxd",
        args: &[FpArg::Double, FpArg::Double],
        ret: FpRet::Double,
        c_source: "double mm_maxd(double a, double b){ return a > b ? a : b; }",
    },
    FpCase {
        name: "mm_mins",
        args: &[FpArg::Float, FpArg::Float],
        ret: FpRet::Float,
        c_source: "float mm_mins(float a, float b){ return a < b ? a : b; }",
    },
    FpCase {
        name: "mm_maxs",
        args: &[FpArg::Float, FpArg::Float],
        ret: FpRet::Float,
        c_source: "float mm_maxs(float a, float b){ return a > b ? a : b; }",
    },
    FpCase {
        name: "mm_min3",
        args: &[FpArg::Double, FpArg::Double, FpArg::Double],
        ret: FpRet::Double,
        c_source: "double mm_min3(double a, double b, double c){ double m = a < b ? a : b; return m < c ? m : c; }",
    },
    FpCase {
        name: "mm_max3",
        args: &[FpArg::Double, FpArg::Double, FpArg::Double],
        ret: FpRet::Double,
        c_source: "double mm_max3(double a, double b, double c){ double m = a > b ? a : b; return m > c ? m : c; }",
    },
    FpCase {
        name: "mm_clamp",
        args: &[FpArg::Double, FpArg::Double, FpArg::Double],
        ret: FpRet::Double,
        c_source: "double mm_clamp(double a, double lo, double hi){ double r = a > lo ? a : lo; return r < hi ? r : hi; }",
    },
    FpCase {
        name: "mm_clampf",
        args: &[FpArg::Float, FpArg::Float, FpArg::Float],
        ret: FpRet::Float,
        c_source: "float mm_clampf(float a, float lo, float hi){ float r = a > lo ? a : lo; return r < hi ? r : hi; }",
    },
    FpCase {
        name: "mm_minsum",
        args: &[FpArg::Double, FpArg::Double, FpArg::Double],
        ret: FpRet::Double,
        c_source: "double mm_minsum(double a, double b, double c){ double s = a + b; return s < c ? s : c; }",
    },
    FpCase {
        name: "mm_scaledmin",
        args: &[FpArg::Double, FpArg::Double],
        ret: FpRet::Double,
        c_source: "double mm_scaledmin(double a, double b){ double m = a < b ? a : b; return m * 2.0; }",
    },
    FpCase {
        name: "mm_minc",
        args: &[FpArg::Double],
        ret: FpRet::Double,
        c_source: "double mm_minc(double a){ return a < 4.5 ? a : 4.5; }",
    },
];

fn minmax_arg_expr(arg: FpArg, slot: usize) -> String {
    match arg {
        FpArg::Double => format!("triples[k][{slot}]"),
        FpArg::Float => format!("(float)triples[k][{slot}]"),
        FpArg::LongLong => format!("(long long)triples[k][{slot}]"),
        FpArg::Int => format!("(int)triples[k][{slot}]"),
    }
}

fn minmax_driver_snippet(case: &FpCase, recovered_name: &str) -> String {
    let call_args: Vec<String> = case
        .args
        .iter()
        .enumerate()
        .map(|(slot, a): (usize, &FpArg)| minmax_arg_expr(*a, slot))
        .collect();
    let joined: String = call_args.join(", ");
    let (bit_ty, to_bits): (&str, &str) = match case.ret {
        FpRet::Double => ("uint64_t", "d_bits"),
        FpRet::Float => ("uint32_t", "f_bits"),
        FpRet::LongLong => ("uint64_t", "i_bits"),
    };
    let mut snippet: String = String::new();
    let _ = write!(
        snippet,
        "    for (size_t k = 0; k < n_triples; k++) {{\n\
         \x20       {bit_ty} want = {to_bits}({}({joined}));\n\
         \x20       {bit_ty} got = {to_bits}({recovered_name}({joined}));\n\
         \x20       if (want != got) {{ printf(\"MISMATCH {} in=%g,%g,%g want=%llu got=%llu\\n\", triples[k][0], triples[k][1], triples[k][2], (unsigned long long)want, (unsigned long long)got); return 1; }}\n\
         \x20   }}\n",
        case.name, case.name,
    );
    snippet
}

fn build_minmax_driver(recovered_decls: &str, driver_body: &str) -> String {
    format!(
        "#include <stdint.h>\n#include <string.h>\n#include <stdio.h>\n#include <stddef.h>\n\
         static inline double fp_d_from_bits(uint64_t b){{ double v; memcpy(&v,&b,8); return v; }}\n\
         static inline uint64_t fp_d_to_bits(double v){{ uint64_t b; memcpy(&b,&v,8); return b; }}\n\
         static inline float fp_f_from_bits(uint32_t b){{ float v; memcpy(&v,&b,4); return v; }}\n\
         static inline uint32_t fp_f_to_bits(float v){{ uint32_t b; memcpy(&b,&v,4); return b; }}\n\
         static inline uint64_t d_bits(double v){{ uint64_t b; memcpy(&b,&v,8); return b; }}\n\
         static inline uint32_t f_bits(float v){{ uint32_t b; memcpy(&b,&v,4); return b; }}\n\
         static inline uint64_t i_bits(long long v){{ uint64_t b; memcpy(&b,&v,8); return b; }}\n\
         {}\n\
         {recovered_decls}\n\
         int main(void) {{\n\
         \x20   double triples[][3] = {{\n\
         \x20       {{0.0,1.0,2.0}},{{1.0,0.0,-1.0}},{{-1.0,1.0,0.0}},{{7.0,3.0,5.0}},{{-7.0,3.0,-5.0}},\n\
         \x20       {{3.5,2.25,4.0}},{{42.0,42.0,42.0}},{{5.0,9.0,1.0}},{{-0.0,0.0,1.0}},{{0.0,-0.0,-0.0}},\n\
         \x20       {{100.0,-100.0,50.0}},{{1e18,1e-3,-1e18}},{{2.5,2.5,2.5}},{{-3.0,-3.0,-2.0}},{{4.5,4.5,4.5}},\n\
         \x20       {{6.0,4.5,4.5}},{{4.5,6.0,1.0}},{{123456.75,789.5,-1000.0}}\n\
         \x20   }};\n\
         \x20   size_t n_triples = sizeof(triples)/sizeof(triples[0]);\n\
         {driver_body}\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n",
        fp_semantics::prelude_source()
    )
}

fn minmax_is_lifted(recovery: &LeafRecovery) -> bool {
    recovery.source.contains("? fp_d_from_bits") || recovery.source.contains("? fp_f_from_bits")
}

#[test]
fn scalar_minmax_leaf_functions_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guard"
        );
        return;
    }
    let Some(builder): Option<String> = clang() else {
        eprintln!(
            "skipping scalar min/max oracle: clang (needed to lower the ternary into scalar min/max SSE) not on PATH"
        );
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let battery_c: PathBuf = dir.join("minmax_battery.c");
    std::fs::write(&battery_c, fp_battery_source(MINMAX_BATTERY).as_bytes())
        .expect("write minmax_battery.c");
    let battery_o: PathBuf = dir.join("minmax_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args(["-O1", "-fno-stack-protector", "-c", "-o"])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke clang for scalar min/max battery");
    assert!(
        compile_battery.status.success(),
        "scalar min/max battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read minmax_battery.o");

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    let mut minmax_count: usize = 0;

    for case in MINMAX_BATTERY {
        let Some((recovery, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
            fp_lift(case, &object_bytes, HOST_ABI)
        else {
            continue;
        };
        if minmax_is_lifted(&recovery) {
            minmax_count += 1;
        }
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        recovered_decls.push_str(&fp_extern_decl(case));
        recovered_decls.push('\n');
        driver_body.push_str(&minmax_driver_snippet(case, &recovered_name));
        lifted_count += 1;
    }

    if lifted_count == 0 {
        eprintln!(
            "skipping scalar min/max behavioral differential: this compiler build lowered none of the {} battery cases into the scalar min/max leaf class",
            MINMAX_BATTERY.len()
        );
        return;
    }

    let driver: String = build_minmax_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("minmax_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write minmax_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "minmax_harness.exe"
    } else {
        "minmax_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke clang to link min/max harness");
    assert!(
        link.status.success(),
        "min/max harness link failed: {}\n--- minmax_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run min/max harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "scalar min/max behavioral differential FAILED ({lifted_count} cases, {minmax_count} carried scalar min/max): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(
        minmax_count >= 8,
        "scalar min/max oracle must exercise the min/max lowering; only {minmax_count} recovered functions carried a min/max ternary"
    );
    println!(
        "scalar min/max behavioral differential PASSED for {lifted_count} leaf functions ({minmax_count} scalar min/max, host ABI)"
    );
}

#[test]
fn scalar_minmax_oracle_has_teeth_flipping_min_to_max_diverges() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guard"
        );
        return;
    }
    let Some(builder): Option<String> = clang() else {
        eprintln!("skipping scalar min/max teeth check: clang not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let probe: &FpCase = &MINMAX_BATTERY[0];
    let battery_c: PathBuf = dir.join("minmax_teeth_battery.c");
    std::fs::write(&battery_c, probe.c_source.as_bytes()).expect("write minmax_teeth_battery.c");
    let battery_o: PathBuf = dir.join("minmax_teeth_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args(["-O1", "-fno-stack-protector", "-c", "-o"])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke clang for min/max teeth battery");
    assert!(
        compile_battery.status.success(),
        "min/max teeth battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read minmax_teeth_battery.o");

    let Some((_, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
        fp_lift(probe, &object_bytes, HOST_ABI)
    else {
        eprintln!("skipping scalar min/max teeth check: probe did not lift into the min/max class");
        return;
    };
    let sabotaged: String = renamed.replacen(
        "fp_d_from_bits(x_xmm0) < fp_d_from_bits(x_xmm1)",
        "fp_d_from_bits(x_xmm0) > fp_d_from_bits(x_xmm1)",
        1,
    );
    assert_ne!(
        sabotaged, renamed,
        "the min ternary condition must be present to be sabotaged into a max"
    );

    let mut decls: String = String::new();
    decls.push_str(&sabotaged);
    decls.push('\n');
    decls.push_str(&fp_extern_decl(probe));
    decls.push('\n');
    let driver_body: String = minmax_driver_snippet(probe, &recovered_name);
    let driver: String = build_minmax_driver(&decls, &driver_body);
    let driver_c: PathBuf = dir.join("minmax_teeth_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write minmax_teeth_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "minmax_teeth_harness.exe"
    } else {
        "minmax_teeth_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke clang to link min/max teeth harness");
    assert!(
        link.status.success(),
        "min/max teeth harness link failed: {}\n--- minmax_teeth_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run min/max teeth harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        stdout.contains("MISMATCH") || !run.status.success(),
        "flipping the min ternary into a max must diverge on the input battery; instead the harness reported: {stdout}"
    );
    println!("scalar min/max oracle teeth confirmed: min/max flip diverges");
}

#[test]
fn sysv_scalar_minmax_leaf_functions_recompile_to_behavioral_equivalence() {
    if !sysv_host_can_run() {
        return;
    }
    let Some(objs): Option<SysvCrossObjects> =
        compile_sysv_cross("minmax", &fp_battery_source(MINMAX_BATTERY))
    else {
        return;
    };

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    let mut minmax_count: usize = 0;

    for case in MINMAX_BATTERY {
        let Some((recovery, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
            fp_lift(case, &objs.sysv_object, PseudoAbi::SysV)
        else {
            continue;
        };
        if minmax_is_lifted(&recovery) {
            minmax_count += 1;
        }
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        recovered_decls.push_str(&fp_extern_decl(case));
        recovered_decls.push('\n');
        driver_body.push_str(&minmax_driver_snippet(case, &recovered_name));
        lifted_count += 1;
    }

    assert!(
        minmax_count >= 8,
        "SysV scalar min/max oracle must exercise min/max lifting; only {minmax_count} recovered functions carried a min/max ternary"
    );
    assert!(
        lifted_count >= 8,
        "SysV scalar min/max lifter must handle at least 8 of the {} cases, only lifted {lifted_count}",
        MINMAX_BATTERY.len()
    );

    let driver: String = build_minmax_driver(&recovered_decls, &driver_body);
    let stdout: String = link_and_run_sysv("minmax", &driver, &objs.host_object, 30);
    assert!(
        stdout.contains("OK"),
        "SysV scalar min/max behavioral differential FAILED ({lifted_count} cases, {minmax_count} scalar min/max): {stdout}"
    );
    println!(
        "SysV scalar min/max behavioral differential PASSED for {lifted_count} leaf functions ({minmax_count} scalar min/max, SysV ABI)"
    );
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FcArg {
    Double,
    Float,
    DoublePtr,
    FloatPtr,
    Long,
}

impl FcArg {
    const fn c_type(self) -> &'static str {
        match self {
            Self::Double => "double",
            Self::Float => "float",
            Self::DoublePtr => "double*",
            Self::FloatPtr => "float*",
            Self::Long => "long long",
        }
    }
}

struct FcCase {
    name: &'static str,
    args: &'static [FcArg],
    ret: FpRet,
    wants_const: bool,
    wants_mem: bool,
    c_source: &'static str,
}

const FP_CONST_BATTERY: &[FcCase] = &[
    FcCase {
        name: "fc_add15",
        args: &[FcArg::Double],
        ret: FpRet::Double,
        wants_const: true,
        wants_mem: false,
        c_source: "double fc_add15(double a){ return a + 1.5; }",
    },
    FcCase {
        name: "fc_mulpi",
        args: &[FcArg::Double],
        ret: FpRet::Double,
        wants_const: true,
        wants_mem: false,
        c_source: "double fc_mulpi(double a){ return a * 3.14159265358979; }",
    },
    FcCase {
        name: "fc_subf",
        args: &[FcArg::Float],
        ret: FpRet::Float,
        wants_const: true,
        wants_mem: false,
        c_source: "float fc_subf(float a){ return a - 2.5f; }",
    },
    FcCase {
        name: "fc_ptr",
        args: &[FcArg::DoublePtr],
        ret: FpRet::Double,
        wants_const: false,
        wants_mem: true,
        c_source: "double fc_ptr(double *p){ return p[0] + p[1]; }",
    },
    FcCase {
        name: "fc_ptrf",
        args: &[FcArg::FloatPtr],
        ret: FpRet::Float,
        wants_const: false,
        wants_mem: true,
        c_source: "float fc_ptrf(float *p){ return p[0] + p[1]; }",
    },
    FcCase {
        name: "fc_scaled",
        args: &[FcArg::DoublePtr, FcArg::Long],
        ret: FpRet::Double,
        wants_const: true,
        wants_mem: true,
        c_source: "double fc_scaled(double *p, long long n){ return p[n] * 3.0; }",
    },
    FcCase {
        name: "fc_gate",
        args: &[FcArg::Double],
        ret: FpRet::LongLong,
        wants_const: true,
        wants_mem: false,
        c_source: "long long fc_gate(double a){ long long r = 20; if (a > 2.5) r = 10; return r; }",
    },
];

fn fc_battery_source(cases: &[FcCase]) -> String {
    let mut src: String = String::new();
    for case in cases {
        src.push_str(case.c_source);
        src.push('\n');
    }
    src
}

fn fc_signature(args: &[FcArg]) -> String {
    args.iter()
        .enumerate()
        .map(|(i, a): (usize, &FcArg)| format!("{} p{i}", a.c_type()))
        .collect::<Vec<String>>()
        .join(", ")
}

fn fc_extern_decl(case: &FcCase) -> String {
    let ret: &str = match case.ret {
        FpRet::Double => "double",
        FpRet::Float => "float",
        FpRet::LongLong => "long long",
    };
    format!("extern {ret} {}({});", case.name, fc_signature(case.args))
}

fn fc_lift(
    case: &FcCase,
    object_bytes: &[u8],
    abi: PseudoAbi,
) -> Option<(LeafRecovery, String, String)> {
    let (code, base): (Vec<u8>, u64) = function_code(object_bytes, case.name)?;
    let consts: Vec<FpConstant> = resolve_fp_constants(object_bytes, &code, base);
    let recovery: LeafRecovery = match recover_leaf_function_const_abi(&code, base, abi, &consts) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "skip {} ({abi:?}): not in scalar float leaf class ({e})",
                case.name
            );
            return None;
        }
    };
    if case.wants_const && !recovery.source.contains("from_bits(0x") {
        eprintln!(
            "skip {}: this build did not lower a rip-relative constant",
            case.name
        );
        return None;
    }
    if case.wants_mem
        && !(recovery.source.contains("*(double*)") || recovery.source.contains("*(float*)"))
    {
        eprintln!(
            "skip {}: this build did not lower a float memory operand",
            case.name
        );
        return None;
    }
    let recovered_name: String = format!("rec_{}", case.name);
    let ret_type: &str = match case.ret {
        FpRet::Double => "double",
        FpRet::Float => "float",
        FpRet::LongLong => "uint64_t",
    };
    let renamed: String = recovery.source.replacen(
        &format!("{ret_type} recovered("),
        &format!("{ret_type} {recovered_name}("),
        1,
    );
    let renamed: String = strip_shared_fp_prelude(&renamed);
    Some((recovery, renamed, recovered_name))
}

fn fc_call_exprs(case: &FcCase, recovered: bool) -> String {
    case.args
        .iter()
        .map(|arg: &FcArg| -> String {
            match arg {
                FcArg::Double => "seeds[k]".to_owned(),
                FcArg::Float => "(float)seeds[k]".to_owned(),
                FcArg::DoublePtr if recovered => "(uint64_t)(uintptr_t)dbuf".to_owned(),
                FcArg::DoublePtr => "dbuf".to_owned(),
                FcArg::FloatPtr if recovered => "(uint64_t)(uintptr_t)fbuf".to_owned(),
                FcArg::FloatPtr => "fbuf".to_owned(),
                FcArg::Long if recovered => "(uint64_t)idx".to_owned(),
                FcArg::Long => "idx".to_owned(),
            }
        })
        .collect::<Vec<String>>()
        .join(", ")
}

fn fc_driver_snippet(case: &FcCase, recovered_name: &str) -> String {
    let orig_args: String = fc_call_exprs(case, false);
    let rec_args: String = fc_call_exprs(case, true);
    let (bit_ty, to_bits): (&str, &str) = match case.ret {
        FpRet::Double => ("uint64_t", "d_bits"),
        FpRet::Float => ("uint32_t", "f_bits"),
        FpRet::LongLong => ("uint64_t", "i_bits"),
    };
    let mut snippet: String = String::new();
    let _ = write!(
        snippet,
        "    for (size_t k = 0; k < n_seeds; k++) {{\n\
         \x20       long long idx = (k % 2 == 0) ? 0 : 1;\n\
         \x20       double dbuf[2] = {{ seeds[k], seeds[k] * 0.5 - 3.0 }};\n\
         \x20       float fbuf[2] = {{ (float)seeds[k], (float)(seeds[k] * 0.5 - 3.0) }};\n\
         \x20       {bit_ty} want = {to_bits}({}({orig_args}));\n\
         \x20       {bit_ty} got = {to_bits}({recovered_name}({rec_args}));\n\
         \x20       if (want != got) {{ printf(\"MISMATCH {} seed=%g want=%llu got=%llu\\n\", seeds[k], (unsigned long long)want, (unsigned long long)got); return 1; }}\n\
         \x20   }}\n",
        case.name, case.name,
    );
    snippet
}

fn build_fc_driver(recovered_decls: &str, driver_body: &str) -> String {
    format!(
        "#include <stdint.h>\n#include <string.h>\n#include <stdio.h>\n#include <stddef.h>\n\
         static inline double fp_d_from_bits(uint64_t b){{ double v; memcpy(&v,&b,8); return v; }}\n\
         static inline uint64_t fp_d_to_bits(double v){{ uint64_t b; memcpy(&b,&v,8); return b; }}\n\
         static inline float fp_f_from_bits(uint32_t b){{ float v; memcpy(&v,&b,4); return v; }}\n\
         static inline uint32_t fp_f_to_bits(float v){{ uint32_t b; memcpy(&b,&v,4); return b; }}\n\
         static inline uint64_t d_bits(double v){{ uint64_t b; memcpy(&b,&v,8); return b; }}\n\
         static inline uint32_t f_bits(float v){{ uint32_t b; memcpy(&b,&v,4); return b; }}\n\
         static inline uint64_t i_bits(long long v){{ uint64_t b; memcpy(&b,&v,8); return b; }}\n\
         {}\n\
         {recovered_decls}\n\
         int main(void) {{\n\
         \x20   double seeds[] = {{ 0.0, 1.0, -1.0, 2.5, 4.0, -4.0, 7.25, -7.25, 0.5, 100.0, -100.0, 3.5, 1.25, -0.5, 42.0 }};\n\
         \x20   size_t n_seeds = sizeof(seeds)/sizeof(seeds[0]);\n\
         {driver_body}\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n",
        fp_semantics::prelude_source()
    )
}

fn run_fc_oracle(object_bytes: &[u8], abi: PseudoAbi) -> FcOracleOutcome {
    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    let mut const_count: usize = 0;
    let mut mem_count: usize = 0;
    for case in FP_CONST_BATTERY {
        let Some((recovery, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
            fc_lift(case, object_bytes, abi)
        else {
            continue;
        };
        if recovery.source.contains("from_bits(0x") {
            const_count += 1;
        }
        if recovery.source.contains("*(double*)") || recovery.source.contains("*(float*)") {
            mem_count += 1;
        }
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        recovered_decls.push_str(&fc_extern_decl(case));
        recovered_decls.push('\n');
        driver_body.push_str(&fc_driver_snippet(case, &recovered_name));
        lifted_count += 1;
    }
    FcOracleOutcome {
        recovered_decls,
        driver_body,
        lifted_count,
        const_count,
        mem_count,
    }
}

struct FcOracleOutcome {
    recovered_decls: String,
    driver_body: String,
    lifted_count: usize,
    const_count: usize,
    mem_count: usize,
}

#[test]
fn fp_const_and_memory_leaf_functions_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guard"
        );
        return;
    }
    let Some(builder): Option<String> = clang() else {
        eprintln!("skipping fp const/mem oracle: clang not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let battery_c: PathBuf = dir.join("fc_battery.c");
    std::fs::write(&battery_c, fc_battery_source(FP_CONST_BATTERY).as_bytes())
        .expect("write fc_battery.c");
    let battery_o: PathBuf = dir.join("fc_battery.o");
    let compile: std::process::Output = Command::new(&builder)
        .args(["-O1", "-fno-stack-protector", "-c", "-o"])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke clang for fp const/mem battery");
    assert!(
        compile.status.success(),
        "fp const/mem battery compile failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read fc_battery.o");

    let outcome: FcOracleOutcome = run_fc_oracle(&object_bytes, HOST_ABI);
    if outcome.lifted_count == 0 {
        eprintln!(
            "skipping fp const/mem behavioral differential: this build lowered none of the {} cases into the scalar float leaf class",
            FP_CONST_BATTERY.len()
        );
        return;
    }
    assert!(
        outcome.const_count >= 1,
        "fp const/mem oracle must exercise at least one rip-relative constant; got {}",
        outcome.const_count
    );
    assert!(
        outcome.mem_count >= 1,
        "fp const/mem oracle must exercise at least one float memory operand; got {}",
        outcome.mem_count
    );

    let driver: String = build_fc_driver(&outcome.recovered_decls, &outcome.driver_body);
    let driver_c: PathBuf = dir.join("fc_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write fc_driver.c");
    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "fc_harness.exe"
    } else {
        "fc_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke clang to link fc harness");
    assert!(
        link.status.success(),
        "fc harness link failed: {}\n--- fc_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );
    let run: std::process::Output = Command::new(&harness_exe).output().expect("run fc harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "fp const/mem behavioral differential FAILED ({} cases, {} const, {} mem): {stdout}\nstderr: {}",
        outcome.lifted_count,
        outcome.const_count,
        outcome.mem_count,
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "fp const/mem behavioral differential PASSED for {} leaf functions ({} rip-const, {} float-mem, host ABI)",
        outcome.lifted_count, outcome.const_count, outcome.mem_count
    );
}

#[test]
fn sysv_fp_const_and_memory_leaf_functions_recompile_to_behavioral_equivalence() {
    if !sysv_host_can_run() {
        return;
    }
    let Some(objs): Option<SysvCrossObjects> =
        compile_sysv_cross("fc", &fc_battery_source(FP_CONST_BATTERY))
    else {
        return;
    };
    let outcome: FcOracleOutcome = run_fc_oracle(&objs.sysv_object, PseudoAbi::SysV);
    assert!(
        outcome.const_count >= 2,
        "SysV fp const/mem oracle must exercise rip-relative constants; got {}",
        outcome.const_count
    );
    assert!(
        outcome.mem_count >= 1,
        "SysV fp const/mem oracle must exercise float memory operands; got {}",
        outcome.mem_count
    );
    assert!(
        outcome.lifted_count >= 3,
        "SysV fp const/mem lifter must handle at least 3 of the {} cases, only lifted {}",
        FP_CONST_BATTERY.len(),
        outcome.lifted_count
    );
    let driver: String = build_fc_driver(&outcome.recovered_decls, &outcome.driver_body);
    let stdout: String = link_and_run_sysv("fc", &driver, &objs.host_object, 30);
    assert!(
        stdout.contains("OK"),
        "SysV fp const/mem behavioral differential FAILED ({} cases, {} const, {} mem): {stdout}",
        outcome.lifted_count,
        outcome.const_count,
        outcome.mem_count
    );
    println!(
        "SysV fp const/mem behavioral differential PASSED for {} leaf functions ({} rip-const, {} float-mem, SysV ABI)",
        outcome.lifted_count, outcome.const_count, outcome.mem_count
    );
}

#[test]
fn fp_const_oracle_has_teeth_perturbing_the_constant_diverges() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guard"
        );
        return;
    }
    let Some(builder): Option<String> = clang() else {
        eprintln!("skipping fp const teeth check: clang not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let probe: &FcCase = &FP_CONST_BATTERY[0];
    let battery_c: PathBuf = dir.join("fc_teeth_battery.c");
    std::fs::write(&battery_c, probe.c_source.as_bytes()).expect("write fc_teeth_battery.c");
    let battery_o: PathBuf = dir.join("fc_teeth_battery.o");
    let compile: std::process::Output = Command::new(&builder)
        .args(["-O1", "-fno-stack-protector", "-c", "-o"])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke clang for fc teeth battery");
    assert!(
        compile.status.success(),
        "fc teeth battery compile failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read fc_teeth_battery.o");

    let Some((recovery, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
        fc_lift(probe, &object_bytes, HOST_ABI)
    else {
        eprintln!("skipping fc teeth check: probe did not lift with a rip-relative constant");
        return;
    };
    let one_five_bits: &str = "0x3ff8000000000000ULL";
    assert!(
        recovery.source.contains(one_five_bits),
        "the 1.5 constant must be recovered bit-exactly to be perturbed; source was:\n{}",
        recovery.source
    );
    let sabotaged: String = renamed.replacen(one_five_bits, "0x4004000000000000ULL", 1);
    assert_ne!(
        sabotaged, renamed,
        "the 1.5 constant must be present to be perturbed"
    );

    let mut decls: String = String::new();
    decls.push_str(&sabotaged);
    decls.push('\n');
    decls.push_str(&fc_extern_decl(probe));
    decls.push('\n');
    let driver_body: String = fc_driver_snippet(probe, &recovered_name);
    let driver: String = build_fc_driver(&decls, &driver_body);
    let driver_c: PathBuf = dir.join("fc_teeth_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write fc_teeth_driver.c");
    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "fc_teeth_harness.exe"
    } else {
        "fc_teeth_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke clang to link fc teeth harness");
    assert!(
        link.status.success(),
        "fc teeth harness link failed: {}\n--- fc_teeth_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );
    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run fc teeth harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        stdout.contains("MISMATCH") || !run.status.success(),
        "perturbing the recovered 1.5 constant to 2.5 must diverge; instead the harness reported: {stdout}"
    );
    println!("fp const oracle teeth confirmed: perturbing the rip-relative constant diverges");
}

const FP_DOUBLE_EDGE_BITS: &[(&str, u64)] = &[
    ("pos_inf", 0x7ff0_0000_0000_0000),
    ("neg_inf", 0xfff0_0000_0000_0000),
    ("quiet_nan", 0x7ff8_0000_0000_0000),
    ("signaling_nan", 0x7ff0_0000_0000_0001),
    ("neg_zero", 0x8000_0000_0000_0000),
    ("min_subnormal", 0x0000_0000_0000_0001),
    ("max_subnormal", 0x000f_ffff_ffff_ffff),
    ("integral_two", 0x4000_0000_0000_0000),
    ("all_bits_set", 0xffff_ffff_ffff_ffff),
];

const FP_FLOAT_EDGE_BITS: &[(&str, u32)] = &[
    ("pos_inf", 0x7f80_0000),
    ("neg_inf", 0xff80_0000),
    ("quiet_nan", 0x7fc0_0000),
    ("neg_zero", 0x8000_0000),
    ("min_subnormal", 0x0000_0001),
    ("integral_two", 0x4000_0000),
    ("all_bits_set", 0xffff_ffff),
];

fn recover_addsd_const_leaf(bits: u64) -> LeafRecovery {
    let code: [u8; 9] = [0xf2, 0x0f, 0x58, 0x05, 0x00, 0x00, 0x00, 0x00, 0xc3];
    let base: u64 = 0x1000;
    let consts: [FpConstant; 1] = [FpConstant { site: base, bits }];
    recover_leaf_function_const_abi(&code, base, HOST_ABI, &consts)
        .expect("addsd xmm0,[rip] leaf must lift as a scalar double add of a rip-relative constant")
}

fn recover_addss_const_leaf(bits: u32) -> LeafRecovery {
    let code: [u8; 9] = [0xf3, 0x0f, 0x58, 0x05, 0x00, 0x00, 0x00, 0x00, 0xc3];
    let base: u64 = 0x1000;
    let consts: [FpConstant; 1] = [FpConstant {
        site: base,
        bits: u64::from(bits),
    }];
    recover_leaf_function_const_abi(&code, base, HOST_ABI, &consts)
        .expect("addss xmm0,[rip] leaf must lift as a scalar float add of a rip-relative constant")
}

#[test]
fn recovered_double_constants_render_bit_exactly_for_every_edge_encoding() {
    for &(name, bits) in FP_DOUBLE_EDGE_BITS {
        let rec: LeafRecovery = recover_addsd_const_leaf(bits);
        let needle: String = format!("fp_d_from_bits(0x{bits:x}ULL)");
        assert!(
            rec.source.contains(&needle),
            "double constant {name} (bits {bits:#018x}) must lower to {needle} verbatim; source was:\n{}",
            rec.source
        );
    }
}

#[test]
fn recovered_float_constants_render_bit_exactly_for_every_edge_encoding() {
    for &(name, bits) in FP_FLOAT_EDGE_BITS {
        let rec: LeafRecovery = recover_addss_const_leaf(bits);
        let needle: String = format!("fp_f_from_bits(0x{bits:x}U)");
        assert!(
            rec.source.contains(&needle),
            "float constant {name} (bits {bits:#010x}) must lower to {needle} verbatim; source was:\n{}",
            rec.source
        );
    }
}

fn strip_helper_lines(source: &str, from_name: &str, to_name: &str) -> String {
    source
        .replacen(
            &format!("double {from_name}("),
            &format!("double {to_name}("),
            1,
        )
        .lines()
        .filter(|l: &&str| {
            !l.starts_with("#include") && !l.trim_start().starts_with("static inline")
        })
        .collect::<Vec<&str>>()
        .join("\n")
}

#[test]
fn recovered_non_finite_double_constants_recompile_to_bit_exact_values() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native double edge-constant recompile on non-windows: host cc/codegen differs; the sysv clang guards carry cross-platform x86-64 coverage"
        );
        return;
    }
    let Some(builder): Option<String> = clang() else {
        eprintln!("skipping double edge-constant recompile: clang not on PATH");
        return;
    };
    let mut decls: String = String::new();
    let mut body: String = String::new();
    for &(name, bits) in FP_DOUBLE_EDGE_BITS {
        let rec: LeafRecovery = recover_addsd_const_leaf(bits);
        let rec_name: String = format!("rec_d_{name}");
        decls.push_str(&strip_helper_lines(&rec.source, "recovered", &rec_name));
        decls.push('\n');
        let _ = writeln!(
            decls,
            "double ref_d_{name}(double a0){{ uint64_t b = 0x{bits:x}ULL; double c; memcpy(&c,&b,8); return a0 + c; }}"
        );
        let _ = write!(
            body,
            "    for (size_t k = 0; k < n_seeds; k++) {{\n\
             \x20       uint64_t want = d_bits(ref_d_{name}(seeds[k]));\n\
             \x20       uint64_t got = d_bits(rec_d_{name}(seeds[k]));\n\
             \x20       if (want != got) {{ printf(\"MISMATCH d_{name} seed=%g want=%llu got=%llu\\n\", seeds[k], (unsigned long long)want, (unsigned long long)got); return 1; }}\n\
             \x20   }}\n"
        );
    }
    let driver: String = format!(
        "#include <stdint.h>\n#include <string.h>\n#include <stdio.h>\n#include <stddef.h>\n\
         static inline double fp_d_from_bits(uint64_t b){{ double v; memcpy(&v,&b,8); return v; }}\n\
         static inline uint64_t fp_d_to_bits(double v){{ uint64_t b; memcpy(&b,&v,8); return b; }}\n\
         static inline uint64_t d_bits(double v){{ uint64_t b; memcpy(&b,&v,8); return b; }}\n\
         {decls}\n\
         int main(void) {{\n\
         \x20   double seeds[] = {{ 0.0, 1.0, -1.0, 2.5, -4.0, 7.25, 100.0, -0.5, 3.5, 42.0 }};\n\
         \x20   size_t n_seeds = sizeof(seeds)/sizeof(seeds[0]);\n\
         {body}\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n"
    );
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let driver_c: PathBuf = dir.join("fp_edge_double_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write fp_edge_double_driver.c");
    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "fp_edge_double.exe"
    } else {
        "fp_edge_double"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .output()
        .expect("invoke clang for double edge-constant harness");
    assert!(
        link.status.success(),
        "double edge-constant harness compile failed: {}\n--- driver ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );
    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run double edge-constant harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "double edge-constant recompile FAILED: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "double edge-constant recompile PASSED for {} non-finite/subnormal/integral encodings",
        FP_DOUBLE_EDGE_BITS.len()
    );
}

#[test]
fn recovered_non_finite_float_constants_recompile_to_bit_exact_values() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native float edge-constant recompile on non-windows: host cc/codegen differs; the sysv clang guards carry cross-platform x86-64 coverage"
        );
        return;
    }
    let Some(builder): Option<String> = clang() else {
        eprintln!("skipping float edge-constant recompile: clang not on PATH");
        return;
    };
    let mut decls: String = String::new();
    let mut body: String = String::new();
    for &(name, bits) in FP_FLOAT_EDGE_BITS {
        let rec: LeafRecovery = recover_addss_const_leaf(bits);
        let rec_name: String = format!("rec_f_{name}");
        decls.push_str(
            &rec.source
                .replacen("float recovered(", &format!("float {rec_name}("), 1)
                .lines()
                .filter(|l: &&str| {
                    !l.starts_with("#include") && !l.trim_start().starts_with("static inline")
                })
                .collect::<Vec<&str>>()
                .join("\n"),
        );
        decls.push('\n');
        let _ = writeln!(
            decls,
            "float ref_f_{name}(float a0){{ uint32_t b = 0x{bits:x}U; float c; memcpy(&c,&b,4); return a0 + c; }}"
        );
        let _ = write!(
            body,
            "    for (size_t k = 0; k < n_seeds; k++) {{\n\
             \x20       uint32_t want = f_bits(ref_f_{name}((float)seeds[k]));\n\
             \x20       uint32_t got = f_bits(rec_f_{name}((float)seeds[k]));\n\
             \x20       if (want != got) {{ printf(\"MISMATCH f_{name} seed=%g want=%u got=%u\\n\", seeds[k], want, got); return 1; }}\n\
             \x20   }}\n"
        );
    }
    let driver: String = format!(
        "#include <stdint.h>\n#include <string.h>\n#include <stdio.h>\n#include <stddef.h>\n\
         static inline float fp_f_from_bits(uint32_t b){{ float v; memcpy(&v,&b,4); return v; }}\n\
         static inline uint32_t fp_f_to_bits(float v){{ uint32_t b; memcpy(&b,&v,4); return b; }}\n\
         static inline uint32_t f_bits(float v){{ uint32_t b; memcpy(&b,&v,4); return b; }}\n\
         {decls}\n\
         int main(void) {{\n\
         \x20   double seeds[] = {{ 0.0, 1.0, -1.0, 2.5, -4.0, 7.25, 100.0, -0.5, 3.5, 42.0 }};\n\
         \x20   size_t n_seeds = sizeof(seeds)/sizeof(seeds[0]);\n\
         {body}\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n"
    );
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let driver_c: PathBuf = dir.join("fp_edge_float_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write fp_edge_float_driver.c");
    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "fp_edge_float.exe"
    } else {
        "fp_edge_float"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .output()
        .expect("invoke clang for float edge-constant harness");
    assert!(
        link.status.success(),
        "float edge-constant harness compile failed: {}\n--- driver ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );
    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run float edge-constant harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "float edge-constant recompile FAILED: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "float edge-constant recompile PASSED for {} non-finite/subnormal/integral encodings",
        FP_FLOAT_EDGE_BITS.len()
    );
}

const SQRT_BATTERY: &[FpCase] = &[
    FpCase {
        name: "sq_d",
        args: &[FpArg::Double],
        ret: FpRet::Double,
        c_source: "double sq_d(double a){ return __builtin_sqrt(a); }",
    },
    FpCase {
        name: "sq_f",
        args: &[FpArg::Float],
        ret: FpRet::Float,
        c_source: "float sq_f(float a){ return __builtin_sqrtf(a); }",
    },
    FpCase {
        name: "sq_hyp",
        args: &[FpArg::Double, FpArg::Double],
        ret: FpRet::Double,
        c_source: "double sq_hyp(double a, double b){ return __builtin_sqrt(a*a + b*b); }",
    },
    FpCase {
        name: "sq_twice",
        args: &[FpArg::Double, FpArg::Double],
        ret: FpRet::Double,
        c_source: "double sq_twice(double a, double b){ return __builtin_sqrt(a) + __builtin_sqrt(b); }",
    },
];

fn build_fp_sqrt_driver(recovered_decls: &str, driver_body: &str) -> String {
    format!(
        "#include <stdint.h>\n#include <string.h>\n#include <stdio.h>\n#include <stddef.h>\n\
         static inline double fp_d_from_bits(uint64_t b){{ double v; memcpy(&v,&b,8); return v; }}\n\
         static inline uint64_t fp_d_to_bits(double v){{ uint64_t b; memcpy(&b,&v,8); return b; }}\n\
         static inline float fp_f_from_bits(uint32_t b){{ float v; memcpy(&v,&b,4); return v; }}\n\
         static inline uint32_t fp_f_to_bits(float v){{ uint32_t b; memcpy(&b,&v,4); return b; }}\n\
         static inline uint64_t d_bits(double v){{ uint64_t b; memcpy(&b,&v,8); return b; }}\n\
         static inline uint32_t f_bits(float v){{ uint32_t b; memcpy(&b,&v,4); return b; }}\n\
         static inline uint64_t i_bits(long long v){{ uint64_t b; memcpy(&b,&v,8); return b; }}\n\
         {}\n\
         {recovered_decls}\n\
         int main(void) {{\n\
         \x20   double pairs[][2] = {{\n\
         \x20       {{0.0,0.0}},{{1.0,1.0}},{{2.0,3.0}},{{7.0,3.0}},{{3.5,2.25}},{{100.0,7.0}},\n\
         \x20       {{0.25,0.5}},{{123456.75,789.5}},{{2147483647.0,3.0}},{{1e18,1e-3}},\n\
         \x20       {{42.0,42.0}},{{5.0,9.0}},{{0.1,0.2}},{{1e-30,1e30}},{{1024.0,4096.0}},\n\
         \x20       {{0.0,7.0}},{{9.0,16.0}},{{2.0,2.0}}\n\
         \x20   }};\n\
         \x20   size_t n_pairs = sizeof(pairs)/sizeof(pairs[0]);\n\
         {driver_body}\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n",
        fp_semantics::prelude_source()
    )
}

fn compile_sysv_cross_extra(
    tag: &str,
    battery_src: &str,
    extra: &[&str],
) -> Option<SysvCrossObjects> {
    let host_cc: String = cc()?;
    let clang_cc: String = clang()?;
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let battery_c: PathBuf = dir.join(format!("{tag}_sysv_battery.c"));
    std::fs::write(&battery_c, battery_src.as_bytes()).expect("write sysv battery");

    let host_o: PathBuf = dir.join(format!("{tag}_sysv_host.o"));
    let mut host_cmd: Command = Command::new(&host_cc);
    host_cmd.args(["-O1", "-fno-stack-protector"]);
    host_cmd.args(extra);
    host_cmd.args(["-c", "-o"]).arg(&host_o).arg(&battery_c);
    let compile_host: std::process::Output = host_cmd
        .output()
        .expect("invoke host cc for sysv ground-truth object");
    assert!(
        compile_host.status.success(),
        "{tag} sysv ground-truth compile failed: {}",
        String::from_utf8_lossy(&compile_host.stderr)
    );

    let sysv_o: PathBuf = dir.join(format!("{tag}_sysv_target.o"));
    let mut sysv_cmd: Command = Command::new(&clang_cc);
    sysv_cmd.args([
        "--target=x86_64-unknown-linux-gnu",
        "-O1",
        "-fno-stack-protector",
        "-fcf-protection=none",
    ]);
    sysv_cmd.args(extra);
    sysv_cmd.args(["-c", "-o"]).arg(&sysv_o).arg(&battery_c);
    let compile_sysv: std::process::Output = sysv_cmd
        .output()
        .expect("invoke clang for sysv target object");
    if !compile_sysv.status.success() {
        eprintln!(
            "skipping {tag} sysv: clang cannot emit a linux/SysV object on this host: {}",
            String::from_utf8_lossy(&compile_sysv.stderr)
        );
        return None;
    }

    Some(SysvCrossObjects {
        host_object: std::fs::read(&host_o).expect("read sysv host object"),
        sysv_object: std::fs::read(&sysv_o).expect("read sysv target object"),
    })
}

#[cfg(target_os = "linux")]
#[test]
fn clang_o0_sysv_incoming_stack_argument_is_not_modeled_as_a_local() {
    let source: &str = "__attribute__((noinline)) long long rsp_arg7(long long a0, long long a1, long long a2, long long a3, long long a4, long long a5, long long a6){ volatile long long local = a0 + a1; return local ^ a6; }";
    let objects: SysvCrossObjects =
        compile_sysv_cross_extra("rsp_arg7", source, &["-O0", "-fomit-frame-pointer"])
            .expect("clang must emit the Linux x86-64 fixed-RSP stack-argument regression object");
    let (code, base): (Vec<u8>, u64) =
        function_code(&objects.sysv_object, "rsp_arg7").expect("rsp_arg7 symbol");
    let insns: Vec<DisasmInsn> =
        disassemble(Arch::X86_64, base, &code).expect("disassemble clang rsp_arg7");
    assert!(
        insns.first().is_some_and(|insn: &DisasmInsn| {
            insn.mnemonic == "sub" && insn.operands.starts_with("rsp,")
        }),
        "clang must allocate a fixed RSP frame before reading the seventh argument: {insns:?}"
    );
    assert!(
        insns
            .iter()
            .any(|insn: &DisasmInsn| insn.operands.contains("[rsp+")),
        "clang must address the incoming seventh argument through the fixed RSP frame: {insns:?}"
    );
    let error: disrobe_pass_native::Error = recover_leaf_function_abi(&code, base, PseudoAbi::SysV)
        .expect_err("a caller-owned seventh argument must not become a recovered local");
    let message: String = error.to_string();
    assert!(
        message.contains("bytes this frame owns")
            && message.contains("caller owns the frame above it"),
        "the compiler-emitted incoming stack argument must fail the frame-ownership check: {message}"
    );
}

#[test]
fn scalar_sqrt_leaf_functions_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guard"
        );
        return;
    }
    let Some(builder): Option<String> = clang() else {
        eprintln!("skipping scalar sqrt oracle: clang not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let battery_c: PathBuf = dir.join("sqrt_battery.c");
    std::fs::write(&battery_c, fp_battery_source(SQRT_BATTERY).as_bytes())
        .expect("write sqrt_battery.c");
    let battery_o: PathBuf = dir.join("sqrt_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args(["-O1", "-fno-math-errno", "-fno-stack-protector", "-c", "-o"])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke clang for scalar sqrt battery");
    assert!(
        compile_battery.status.success(),
        "scalar sqrt battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read sqrt_battery.o");

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;

    for case in SQRT_BATTERY {
        let Some((recovery, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
            fp_lift(case, &object_bytes, HOST_ABI)
        else {
            continue;
        };
        assert!(
            recovery.source.contains("fpx_sqrt_x86_f"),
            "a lifted sqrt case must carry a sqrt intrinsic: {}",
            recovery.source
        );
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        recovered_decls.push_str(&fp_extern_decl(case));
        recovered_decls.push('\n');
        driver_body.push_str(&fp_driver_snippet(case, &recovered_name));
        lifted_count += 1;
    }

    if lifted_count < 2 {
        eprintln!(
            "skipping scalar sqrt behavioral differential: this compiler build lowered only {lifted_count} of {} cases into a bare scalar sqrt leaf",
            SQRT_BATTERY.len()
        );
        return;
    }

    let driver: String = build_fp_sqrt_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("sqrt_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write sqrt_driver.c");
    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "sqrt_harness.exe"
    } else {
        "sqrt_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke clang to link sqrt harness");
    assert!(
        link.status.success(),
        "sqrt harness link failed: {}\n--- sqrt_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );
    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run sqrt harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "scalar sqrt behavioral differential FAILED ({lifted_count} cases): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "scalar sqrt behavioral differential PASSED for {lifted_count} leaf functions (host ABI)"
    );
}

#[test]
fn scalar_sqrt_oracle_has_teeth_dropping_the_sqrt_diverges() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guard"
        );
        return;
    }
    let Some(builder): Option<String> = clang() else {
        eprintln!("skipping scalar sqrt teeth check: clang not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let probe: &FpCase = &SQRT_BATTERY[0];
    let battery_c: PathBuf = dir.join("sqrt_teeth_battery.c");
    std::fs::write(&battery_c, probe.c_source.as_bytes()).expect("write sqrt_teeth_battery.c");
    let battery_o: PathBuf = dir.join("sqrt_teeth_battery.o");
    let compile: std::process::Output = Command::new(&builder)
        .args(["-O1", "-fno-math-errno", "-fno-stack-protector", "-c", "-o"])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke clang for sqrt teeth battery");
    assert!(
        compile.status.success(),
        "sqrt teeth battery compile failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read sqrt_teeth_battery.o");

    let Some((_, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
        fp_lift(probe, &object_bytes, HOST_ABI)
    else {
        eprintln!("skipping sqrt teeth check: probe did not lift into a bare sqrt leaf");
        return;
    };
    let sabotaged: String = renamed.replacen(
        "fpx_sqrt_x86_f64(fp_d_from_bits(x_xmm0))",
        "fp_d_from_bits(x_xmm0)",
        1,
    );
    assert_ne!(
        sabotaged, renamed,
        "the sqrt intrinsic must be present to be dropped"
    );

    let mut decls: String = String::new();
    decls.push_str(&sabotaged);
    decls.push('\n');
    decls.push_str(&fp_extern_decl(probe));
    decls.push('\n');
    let driver_body: String = fp_driver_snippet(probe, &recovered_name);
    let driver: String = build_fp_sqrt_driver(&decls, &driver_body);
    let driver_c: PathBuf = dir.join("sqrt_teeth_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write sqrt_teeth_driver.c");
    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "sqrt_teeth_harness.exe"
    } else {
        "sqrt_teeth_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke clang to link sqrt teeth harness");
    assert!(
        link.status.success(),
        "sqrt teeth harness link failed: {}\n--- sqrt_teeth_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );
    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run sqrt teeth harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        stdout.contains("MISMATCH") || !run.status.success(),
        "dropping the sqrt must diverge on the input battery; instead the harness reported: {stdout}"
    );
    println!("scalar sqrt oracle teeth confirmed: dropping the sqrt diverges");
}

#[test]
fn sysv_scalar_sqrt_leaf_functions_recompile_to_behavioral_equivalence() {
    if !sysv_host_can_run() {
        return;
    }
    let Some(objs): Option<SysvCrossObjects> = compile_sysv_cross_extra(
        "sqrt",
        &fp_battery_source(SQRT_BATTERY),
        &["-fno-math-errno"],
    ) else {
        return;
    };

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;

    for case in SQRT_BATTERY {
        let Some((recovery, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
            fp_lift(case, &objs.sysv_object, PseudoAbi::SysV)
        else {
            continue;
        };
        assert!(
            recovery.source.contains("fpx_sqrt_x86_f"),
            "a lifted sqrt case must carry a sqrt intrinsic: {}",
            recovery.source
        );
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        recovered_decls.push_str(&fp_extern_decl(case));
        recovered_decls.push('\n');
        driver_body.push_str(&fp_driver_snippet(case, &recovered_name));
        lifted_count += 1;
    }

    assert!(
        lifted_count >= 2,
        "SysV scalar sqrt lifter must handle at least 2 of the {} cases, only lifted {lifted_count}",
        SQRT_BATTERY.len()
    );

    let driver: String = build_fp_sqrt_driver(&recovered_decls, &driver_body);
    let stdout: String = link_and_run_sysv("sqrt", &driver, &objs.host_object, 30);
    assert!(
        stdout.contains("OK"),
        "SysV scalar sqrt behavioral differential FAILED ({lifted_count} cases): {stdout}"
    );
    println!(
        "SysV scalar sqrt behavioral differential PASSED for {lifted_count} leaf functions (SysV ABI)"
    );
}

const ROUND_BATTERY: &[FpCase] = &[
    FpCase {
        name: "rd_floor",
        args: &[FpArg::Double],
        ret: FpRet::Double,
        c_source: "double rd_floor(double a){ return __builtin_floor(a); }",
    },
    FpCase {
        name: "rd_ceil",
        args: &[FpArg::Double],
        ret: FpRet::Double,
        c_source: "double rd_ceil(double a){ return __builtin_ceil(a); }",
    },
    FpCase {
        name: "rd_trunc",
        args: &[FpArg::Double],
        ret: FpRet::Double,
        c_source: "double rd_trunc(double a){ return __builtin_trunc(a); }",
    },
    FpCase {
        name: "rd_near",
        args: &[FpArg::Double],
        ret: FpRet::Double,
        c_source: "double rd_near(double a){ return __builtin_roundeven(a); }",
    },
    FpCase {
        name: "rs_floor",
        args: &[FpArg::Float],
        ret: FpRet::Float,
        c_source: "float rs_floor(float a){ return __builtin_floorf(a); }",
    },
    FpCase {
        name: "rs_ceil",
        args: &[FpArg::Float],
        ret: FpRet::Float,
        c_source: "float rs_ceil(float a){ return __builtin_ceilf(a); }",
    },
    FpCase {
        name: "rs_trunc",
        args: &[FpArg::Float],
        ret: FpRet::Float,
        c_source: "float rs_trunc(float a){ return __builtin_truncf(a); }",
    },
    FpCase {
        name: "rs_near",
        args: &[FpArg::Float],
        ret: FpRet::Float,
        c_source: "float rs_near(float a){ return __builtin_roundevenf(a); }",
    },
];

fn round_expectations(name: &str) -> (&'static str, &'static str) {
    match name {
        "rd_floor" => ("fpx_rintm_f64", "roundsd"),
        "rd_ceil" => ("fpx_rintp_f64", "roundsd"),
        "rd_trunc" => ("fpx_rintz_f64", "roundsd"),
        "rd_near" => ("fpx_rintn_f64", "roundsd"),
        "rs_floor" => ("fpx_rintm_f32", "roundss"),
        "rs_ceil" => ("fpx_rintp_f32", "roundss"),
        "rs_trunc" => ("fpx_rintz_f32", "roundss"),
        "rs_near" => ("fpx_rintn_f32", "roundss"),
        other => panic!("no round expectation registered for `{other}`"),
    }
}

fn function_has_mnemonic(object_bytes: &[u8], name: &str, mnemonic: &str) -> bool {
    let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(object_bytes, name) else {
        return false;
    };
    let Ok(insns): Result<Vec<DisasmInsn>, _> = disassemble(Arch::X86_64, base, &code) else {
        return false;
    };
    insns
        .iter()
        .any(|insn: &DisasmInsn| insn.mnemonic == mnemonic)
}

fn function_uses_ordering_cmov(object_bytes: &[u8], name: &str) -> bool {
    let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(object_bytes, name) else {
        return false;
    };
    let Ok(insns): Result<Vec<DisasmInsn>, _> = disassemble(Arch::X86_64, base, &code) else {
        return false;
    };
    insns
        .iter()
        .take_while(|insn: &&DisasmInsn| insn.mnemonic != "ret")
        .any(|insn: &DisasmInsn| {
            insn.mnemonic
                .strip_prefix("cmov")
                .is_some_and(|suffix: &str| {
                    matches!(
                        suffix,
                        "g" | "ge" | "l" | "le" | "nl" | "nle" | "ng" | "nge"
                    )
                })
        })
}

#[test]
fn round_lift_emits_expected_builtin_for_each_mode() {
    let base: u64 = 0x1000;
    let cases: &[(&str, [u8; 7], &str)] = &[
        (
            "floor",
            [0x66, 0x0f, 0x3a, 0x0b, 0xc0, 0x09, 0xc3],
            "fpx_rintm_f64",
        ),
        (
            "ceil",
            [0x66, 0x0f, 0x3a, 0x0b, 0xc0, 0x0a, 0xc3],
            "fpx_rintp_f64",
        ),
        (
            "trunc",
            [0x66, 0x0f, 0x3a, 0x0b, 0xc0, 0x0b, 0xc3],
            "fpx_rintz_f64",
        ),
        (
            "nearest",
            [0x66, 0x0f, 0x3a, 0x0b, 0xc0, 0x08, 0xc3],
            "fpx_rintn_f64",
        ),
        (
            "floorf",
            [0x66, 0x0f, 0x3a, 0x0a, 0xc0, 0x09, 0xc3],
            "fpx_rintm_f32",
        ),
        (
            "ceilf",
            [0x66, 0x0f, 0x3a, 0x0a, 0xc0, 0x0a, 0xc3],
            "fpx_rintp_f32",
        ),
        (
            "truncf",
            [0x66, 0x0f, 0x3a, 0x0a, 0xc0, 0x0b, 0xc3],
            "fpx_rintz_f32",
        ),
        (
            "nearestf",
            [0x66, 0x0f, 0x3a, 0x0a, 0xc0, 0x08, 0xc3],
            "fpx_rintn_f32",
        ),
    ];
    for (tag, bytes, want) in cases {
        let recovery: LeafRecovery = match recover_leaf_function_abi(bytes, base, PseudoAbi::SysV) {
            Ok(r) => r,
            Err(e) => panic!("round `{tag}` must lift into the scalar float leaf class: {e}"),
        };
        assert!(
            recovery.source.contains(*want),
            "round `{tag}` must lower to `{want}`; recovered source:\n{}",
            recovery.source
        );
    }
}

#[test]
fn round_lift_rejects_mxcsr_deferred_rounding() {
    let base: u64 = 0x1000;
    let deferred: &[(&str, [u8; 7])] = &[
        ("roundsd_mxcsr", [0x66, 0x0f, 0x3a, 0x0b, 0xc0, 0x04, 0xc3]),
        (
            "roundss_mxcsr_suppressed",
            [0x66, 0x0f, 0x3a, 0x0a, 0xc0, 0x0c, 0xc3],
        ),
    ];
    for (tag, bytes) in deferred {
        let outcome: Result<LeafRecovery, disrobe_pass_native::Error> =
            recover_leaf_function_abi(bytes, base, PseudoAbi::SysV);
        assert!(
            outcome.is_err(),
            "round `{tag}` deferring to MXCSR must sound-reject rather than guess a rounding direction"
        );
    }
}

#[test]
fn scalar_round_leaf_functions_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guard"
        );
        return;
    }
    let Some(builder): Option<String> = clang() else {
        eprintln!("skipping scalar round oracle: clang not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let battery_c: PathBuf = dir.join("round_battery.c");
    std::fs::write(&battery_c, fp_battery_source(ROUND_BATTERY).as_bytes())
        .expect("write round_battery.c");
    let battery_o: PathBuf = dir.join("round_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args([
            "-O1",
            "-msse4.1",
            "-fno-math-errno",
            "-fno-stack-protector",
            "-c",
            "-o",
        ])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke clang for scalar round battery");
    assert!(
        compile_battery.status.success(),
        "scalar round battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read round_battery.o");

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;

    for case in ROUND_BATTERY {
        let (builtin, mnemonic): (&str, &str) = round_expectations(case.name);
        if !function_has_mnemonic(&object_bytes, case.name, mnemonic) {
            eprintln!(
                "skip {}: this clang build did not emit a scalar {mnemonic} (SSE4.1 rounding unavailable)",
                case.name
            );
            continue;
        }
        let Some((recovery, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
            fp_lift(case, &object_bytes, HOST_ABI)
        else {
            continue;
        };
        assert!(
            recovery.source.contains(builtin),
            "a lifted round case must carry the {builtin} intrinsic: {}",
            recovery.source
        );
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        recovered_decls.push_str(&fp_extern_decl(case));
        recovered_decls.push('\n');
        driver_body.push_str(&fp_driver_snippet(case, &recovered_name));
        lifted_count += 1;
    }

    if lifted_count < 2 {
        eprintln!(
            "skipping scalar round behavioral differential: this compiler build lowered only {lifted_count} of {} cases into a bare scalar round leaf",
            ROUND_BATTERY.len()
        );
        return;
    }

    let driver: String = build_fp_sqrt_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("round_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write round_driver.c");
    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "round_harness.exe"
    } else {
        "round_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-msse4.1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke clang to link round harness");
    assert!(
        link.status.success(),
        "round harness link failed: {}\n--- round_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );
    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run round harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "scalar round behavioral differential FAILED ({lifted_count} cases): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "scalar round behavioral differential PASSED for {lifted_count} leaf functions (host ABI)"
    );
}

#[test]
fn scalar_round_oracle_has_teeth_dropping_the_round_diverges() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guard"
        );
        return;
    }
    let Some(builder): Option<String> = clang() else {
        eprintln!("skipping scalar round teeth check: clang not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let probe: &FpCase = &ROUND_BATTERY[0];
    let (builtin, mnemonic): (&str, &str) = round_expectations(probe.name);
    let battery_c: PathBuf = dir.join("round_teeth_battery.c");
    std::fs::write(&battery_c, probe.c_source.as_bytes()).expect("write round_teeth_battery.c");
    let battery_o: PathBuf = dir.join("round_teeth_battery.o");
    let compile: std::process::Output = Command::new(&builder)
        .args([
            "-O1",
            "-msse4.1",
            "-fno-math-errno",
            "-fno-stack-protector",
            "-c",
            "-o",
        ])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke clang for round teeth battery");
    assert!(
        compile.status.success(),
        "round teeth battery compile failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read round_teeth_battery.o");

    if !function_has_mnemonic(&object_bytes, probe.name, mnemonic) {
        eprintln!("skipping round teeth check: this clang build did not emit a scalar {mnemonic}");
        return;
    }
    let Some((_, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
        fp_lift(probe, &object_bytes, HOST_ABI)
    else {
        eprintln!("skipping round teeth check: probe did not lift into a bare round leaf");
        return;
    };
    let intact: String = format!("{builtin}(fp_d_from_bits(x_xmm0))");
    let sabotaged: String = renamed.replacen(&intact, "fp_d_from_bits(x_xmm0)", 1);
    assert_ne!(
        sabotaged, renamed,
        "the round intrinsic must be present to be dropped"
    );

    let mut decls: String = String::new();
    decls.push_str(&sabotaged);
    decls.push('\n');
    decls.push_str(&fp_extern_decl(probe));
    decls.push('\n');
    let driver_body: String = fp_driver_snippet(probe, &recovered_name);
    let driver: String = build_fp_sqrt_driver(&decls, &driver_body);
    let driver_c: PathBuf = dir.join("round_teeth_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write round_teeth_driver.c");
    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "round_teeth_harness.exe"
    } else {
        "round_teeth_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-msse4.1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke clang to link round teeth harness");
    assert!(
        link.status.success(),
        "round teeth harness link failed: {}\n--- round_teeth_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );
    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run round teeth harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        stdout.contains("MISMATCH") || !run.status.success(),
        "dropping the round must diverge on the input battery; instead the harness reported: {stdout}"
    );
    println!("scalar round oracle teeth confirmed: dropping the round diverges");
}

fn link_and_run_round_sysv(
    tag: &str,
    driver: &str,
    host_object: &[u8],
    watchdog_secs: u64,
) -> String {
    let host_cc: String = cc().expect("host cc present when linking sysv round harness");
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let host_o: PathBuf = dir.join(format!("{tag}_sysv_round_link_host.o"));
    std::fs::write(&host_o, host_object).expect("write sysv round host object for link");
    let driver_c: PathBuf = dir.join(format!("{tag}_sysv_round_driver.c"));
    std::fs::write(&driver_c, driver.as_bytes()).expect("write sysv round driver");
    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        format!("{tag}_sysv_round_harness.exe")
    } else {
        format!("{tag}_sysv_round_harness")
    });
    let link: std::process::Output = Command::new(&host_cc)
        .args(["-O1", "-msse4.1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&host_o)
        .arg("-lm")
        .output()
        .expect("invoke host cc to link sysv round harness");
    assert!(
        link.status.success(),
        "{tag} sysv round harness link failed: {}\n--- {tag} sysv round driver ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );
    let BoundedRun::Exited(out): BoundedRun = run_bounded(&harness_exe, watchdog_secs) else {
        panic!("{tag} sysv round harness did not terminate within the watchdog window");
    };
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn sysv_scalar_round_leaf_functions_recompile_to_behavioral_equivalence() {
    if !cfg!(target_arch = "x86_64") {
        eprintln!(
            "skipping sysv scalar round oracle: the roundsd ground-truth build and harness link need x86-only -msse4.1, which non-x86 hosts (macos arm64) reject; ubuntu and windows x86_64 hosts cover this class"
        );
        return;
    }
    let Some(objs): Option<SysvCrossObjects> = compile_sysv_cross_extra(
        "round",
        &fp_battery_source(ROUND_BATTERY),
        &["-msse4.1", "-fno-math-errno"],
    ) else {
        return;
    };

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;

    for case in ROUND_BATTERY {
        let (builtin, mnemonic): (&str, &str) = round_expectations(case.name);
        if !function_has_mnemonic(&objs.sysv_object, case.name, mnemonic) {
            eprintln!(
                "skip {}: the SysV clang build did not emit a scalar {mnemonic}",
                case.name
            );
            continue;
        }
        let Some((recovery, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
            fp_lift(case, &objs.sysv_object, PseudoAbi::SysV)
        else {
            continue;
        };
        assert!(
            recovery.source.contains(builtin),
            "a lifted round case must carry the {builtin} intrinsic: {}",
            recovery.source
        );
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        recovered_decls.push_str(&fp_extern_decl(case));
        recovered_decls.push('\n');
        driver_body.push_str(&fp_driver_snippet(case, &recovered_name));
        lifted_count += 1;
    }

    assert!(
        lifted_count >= 2,
        "SysV scalar round lifter must handle at least 2 of the {} cases, only lifted {lifted_count}",
        ROUND_BATTERY.len()
    );

    let driver: String = build_fp_sqrt_driver(&recovered_decls, &driver_body);
    let stdout: String = link_and_run_round_sysv("round", &driver, &objs.host_object, 30);
    assert!(
        stdout.contains("OK"),
        "SysV scalar round behavioral differential FAILED ({lifted_count} cases): {stdout}"
    );
    println!(
        "SysV scalar round behavioral differential PASSED for {lifted_count} leaf functions (SysV ABI)"
    );
}

const BITCAST_BATTERY: &[FpCase] = &[
    FpCase {
        name: "bz_zero",
        args: &[],
        ret: FpRet::Double,
        c_source: "double bz_zero(void){ return 0.0; }",
    },
    FpCase {
        name: "bz_addid",
        args: &[FpArg::Double],
        ret: FpRet::Double,
        c_source: "double bz_addid(double a){ double t = 0.0; return t + a; }",
    },
    FpCase {
        name: "bz_addidf",
        args: &[FpArg::Float],
        ret: FpRet::Float,
        c_source: "float bz_addidf(float a){ float t = 0.0f; return t + a; }",
    },
    FpCase {
        name: "bz_d2bits",
        args: &[FpArg::Double],
        ret: FpRet::LongLong,
        c_source: "long long bz_d2bits(double a){ long long b; __builtin_memcpy(&b, &a, 8); return b; }",
    },
    FpCase {
        name: "bz_bits2d",
        args: &[FpArg::LongLong],
        ret: FpRet::Double,
        c_source: "double bz_bits2d(long long a){ double d; __builtin_memcpy(&d, &a, 8); return d; }",
    },
];

fn bitcast_is_lifted(recovery: &LeafRecovery) -> bool {
    recovery.source.contains("= r_")
        || recovery
            .source
            .contains("fp_d_from_bits(0x0000000000000000ULL)")
        || recovery.source.contains("r_rax = x_xmm0;")
}

#[test]
fn scalar_fp_bitcast_and_zero_leaf_functions_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guard"
        );
        return;
    }
    let Some(builder): Option<String> = clang() else {
        eprintln!("skipping scalar fp bitcast oracle: clang not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let battery_c: PathBuf = dir.join("bitcast_battery.c");
    std::fs::write(&battery_c, fp_battery_source(BITCAST_BATTERY).as_bytes())
        .expect("write bitcast_battery.c");
    let battery_o: PathBuf = dir.join("bitcast_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args(["-O1", "-fno-stack-protector", "-c", "-o"])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke clang for bitcast battery");
    assert!(
        compile_battery.status.success(),
        "bitcast battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read bitcast_battery.o");

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;

    for case in BITCAST_BATTERY {
        let Some((_, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
            fp_lift(case, &object_bytes, HOST_ABI)
        else {
            continue;
        };
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        recovered_decls.push_str(&fp_extern_decl(case));
        recovered_decls.push('\n');
        driver_body.push_str(&fp_driver_snippet(case, &recovered_name));
        lifted_count += 1;
    }

    if lifted_count < 3 {
        eprintln!(
            "skipping scalar fp bitcast differential: this compiler build lowered only {lifted_count} of {} cases into the modeled zero/bitcast leaf class",
            BITCAST_BATTERY.len()
        );
        return;
    }

    let driver: String = build_fp_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("bitcast_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write bitcast_driver.c");
    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "bitcast_harness.exe"
    } else {
        "bitcast_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke clang to link bitcast harness");
    assert!(
        link.status.success(),
        "bitcast harness link failed: {}\n--- bitcast_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );
    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run bitcast harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "scalar fp bitcast/zero behavioral differential FAILED ({lifted_count} cases): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "scalar fp bitcast/zero behavioral differential PASSED for {lifted_count} leaf functions (host ABI)"
    );
}

#[test]
fn scalar_fp_bitcast_oracle_has_teeth_corrupting_the_bitcast_diverges() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guard"
        );
        return;
    }
    let Some(builder): Option<String> = clang() else {
        eprintln!("skipping scalar fp bitcast teeth check: clang not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let probe: &FpCase = &BITCAST_BATTERY[3];
    let battery_c: PathBuf = dir.join("bitcast_teeth_battery.c");
    std::fs::write(&battery_c, probe.c_source.as_bytes()).expect("write bitcast_teeth_battery.c");
    let battery_o: PathBuf = dir.join("bitcast_teeth_battery.o");
    let compile: std::process::Output = Command::new(&builder)
        .args(["-O1", "-fno-stack-protector", "-c", "-o"])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke clang for bitcast teeth battery");
    assert!(
        compile.status.success(),
        "bitcast teeth battery compile failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read bitcast_teeth_battery.o");

    let Some((recovery, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
        fp_lift(probe, &object_bytes, HOST_ABI)
    else {
        eprintln!("skipping bitcast teeth check: probe did not lift as a movq bitcast");
        return;
    };
    assert!(
        bitcast_is_lifted(&recovery),
        "the probe must lift through the movq bitcast path: {}",
        recovery.source
    );
    let sabotaged: String = renamed.replacen("r_rax = x_xmm0;", "r_rax = (x_xmm0 ^ 0x1ULL);", 1);
    assert_ne!(
        sabotaged, renamed,
        "the movq bitcast copy must be present to be corrupted"
    );

    let mut decls: String = String::new();
    decls.push_str(&sabotaged);
    decls.push('\n');
    decls.push_str(&fp_extern_decl(probe));
    decls.push('\n');
    let driver_body: String = fp_driver_snippet(probe, &recovered_name);
    let driver: String = build_fp_driver(&decls, &driver_body);
    let driver_c: PathBuf = dir.join("bitcast_teeth_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write bitcast_teeth_driver.c");
    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "bitcast_teeth_harness.exe"
    } else {
        "bitcast_teeth_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke clang to link bitcast teeth harness");
    assert!(
        link.status.success(),
        "bitcast teeth harness link failed: {}\n--- bitcast_teeth_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );
    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run bitcast teeth harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        stdout.contains("MISMATCH") || !run.status.success(),
        "flipping a bit in the movq bitcast must diverge; instead the harness reported: {stdout}"
    );
    println!("scalar fp bitcast oracle teeth confirmed: corrupting the movq copy diverges");
}

#[test]
fn sysv_scalar_fp_bitcast_and_zero_leaf_functions_recompile_to_behavioral_equivalence() {
    if !sysv_host_can_run() {
        return;
    }
    let Some(objs): Option<SysvCrossObjects> =
        compile_sysv_cross("bitcast", &fp_battery_source(BITCAST_BATTERY))
    else {
        return;
    };

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;

    for case in BITCAST_BATTERY {
        let Some((_, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
            fp_lift(case, &objs.sysv_object, PseudoAbi::SysV)
        else {
            continue;
        };
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        recovered_decls.push_str(&fp_extern_decl(case));
        recovered_decls.push('\n');
        driver_body.push_str(&fp_driver_snippet(case, &recovered_name));
        lifted_count += 1;
    }

    assert!(
        lifted_count >= 3,
        "SysV scalar fp bitcast lifter must handle at least 3 of the {} cases, only lifted {lifted_count}",
        BITCAST_BATTERY.len()
    );

    let driver: String = build_fp_driver(&recovered_decls, &driver_body);
    let stdout: String = link_and_run_sysv("bitcast", &driver, &objs.host_object, 30);
    assert!(
        stdout.contains("OK"),
        "SysV scalar fp bitcast/zero behavioral differential FAILED ({lifted_count} cases): {stdout}"
    );
    println!(
        "SysV scalar fp bitcast/zero behavioral differential PASSED for {lifted_count} leaf functions (SysV ABI)"
    );
}

const SWITCH_BATTERY: &[Case] = &[
    Case {
        name: "sw_ops",
        arity: 3,
        c_source: "long long sw_ops(long long x, long long a, long long b){ long long r; switch (x) { case 0: r = a + b; break; case 1: r = a - b; break; case 2: r = a * b; break; case 3: r = a ^ b; break; case 4: r = a | b; break; case 5: r = a & b; break; default: r = -1; break; } return r; }",
    },
    Case {
        name: "sw_addk",
        arity: 2,
        c_source: "long long sw_addk(long long x, long long a){ long long r; switch (x) { case 0: r = a + 1; break; case 1: r = a + 2; break; case 2: r = a + 4; break; case 3: r = a + 8; break; case 4: r = a + 16; break; case 5: r = a + 32; break; case 6: r = a + 64; break; case 7: r = a + 128; break; default: r = 0; break; } return r; }",
    },
    Case {
        name: "sw_scale",
        arity: 2,
        c_source: "long long sw_scale(long long x, long long a){ long long r; switch (x) { case 0: r = a; break; case 1: r = a * 2; break; case 2: r = a * 3; break; case 3: r = a * 5; break; case 4: r = a * 7; break; default: r = a * 11; break; } return r; }",
    },
    Case {
        name: "sw_ft",
        arity: 2,
        c_source: "long long sw_ft(long long x, long long a){ long long r = 0; switch (x) { case 0: r += a; case 1: r += a * 2; break; case 2: r += a * 3; case 3: r += a * 5; break; case 4: r += a * 7; break; default: r = -1; break; } return r; }",
    },
    Case {
        name: "sw_mix",
        arity: 3,
        c_source: "long long sw_mix(long long x, long long a, long long b){ long long r; switch (x) { case 0: r = a + b + 1; break; case 1: r = a - b - 1; break; case 2: r = (a ^ b) + 3; break; case 3: r = (a | b) - 5; break; case 4: r = (a & b) * 2; break; default: r = a * b; break; } return r; }",
    },
];

const NESTED_SWITCH_BATTERY: &[Case] = &[
    Case {
        name: "nsw_div",
        arity: 3,
        c_source: "long long nsw_div(long long x, long long a, long long b){ long long r; switch (x) { case 0: r = a / b; break; case 1: r = a % b; break; case 2: r = a / b + a % b; break; case 3: r = (a + b) / b; break; case 4: r = a * b; break; case 5: r = a - b; break; default: r = -1; break; } return r; }",
    },
    Case {
        name: "nsw_udiv",
        arity: 3,
        c_source: "unsigned long long nsw_udiv(unsigned long long x, unsigned long long a, unsigned long long b){ unsigned long long r; switch (x) { case 0: r = a / b; break; case 1: r = a % b; break; case 2: r = a / b + 1; break; case 3: r = a + b; break; case 4: r = a % b + b; break; default: r = 0; break; } return r; }",
    },
    Case {
        name: "nsw_cmp",
        arity: 3,
        c_source: "long long nsw_cmp(long long x, long long a, long long b){ long long r; switch (x) { case 0: r = (a > b); break; case 1: r = (a < b); break; case 2: r = (a == b); break; case 3: r = (a >= b); break; case 4: r = (a != b); break; default: r = 0; break; } return r; }",
    },
    Case {
        name: "nsw_div32",
        arity: 3,
        c_source: "int nsw_div32(int x, int a, int b){ int r; switch (x) { case 0: r = a / b; break; case 1: r = a % b; break; case 2: r = a / b - a % b; break; case 3: r = a + b; break; default: r = -1; break; } return r; }",
    },
];

fn nested_switch_driver_snippet(case: &Case, recovery: &LeafRecovery) -> String {
    let recovered_name: String = format!("rec_{}", case.name);
    let return_mask: String = if recovery.return_width_bits == 64 {
        "0xFFFFFFFFFFFFFFFFULL".to_owned()
    } else {
        format!("0x{:x}ULL", (1u128 << recovery.return_width_bits) - 1)
    };
    let args: Vec<String> = (0..case.arity).map(|i: usize| format!("in[{i}]")).collect();
    let rec_args: Vec<String> = (0..recovery.params.len())
        .map(|i: usize| format!("(uint64_t)in[{i}]"))
        .collect();
    let mut snippet: String = String::new();
    let _ = write!(
        snippet,
        "    for (long long disc = -2; disc <= 8; disc++) {{\n\
         \x20   for (size_t k = 0; k < n_nzpairs; k++) {{\n\
         \x20       long long in[3] = {{ disc, nzpairs[k][0], nzpairs[k][1] }};\n\
         \x20       unsigned long long want = (unsigned long long){}({}) & {return_mask};\n\
         \x20       unsigned long long got = {recovered_name}({}) & {return_mask};\n\
         \x20       if (want != got) {{ printf(\"MISMATCH {} disc=%lld in=%lld,%lld want=%llu got=%llu\\n\", disc, in[1], in[2], want, got); return 1; }}\n\
         \x20   }}\n\
         \x20   }}\n",
        case.name,
        args.join(", "),
        rec_args.join(", "),
        case.name,
    );
    snippet
}

fn build_nested_switch_driver(recovered_decls: &str, driver_body: &str) -> String {
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n{recovered_decls}\n\
         int main(void) {{\n\
         \x20   long long nzpairs[][2] = {{\n\
         \x20       {{0,1}},{{1,1}},{{-1,1}},{{7,3}},{{-7,3}},{{7,-3}},{{-7,-3}},\n\
         \x20       {{100,7}},{{-100,7}},{{123456,789}},{{-123456,789}},\n\
         \x20       {{2147483647,3}},{{-2147483648LL,3}},{{0x7fffffffffffffffLL,1000000007LL}},\n\
         \x20       {{255,16}},{{65535,256}},{{1000000000LL,3}},{{-1000000000LL,-3}},\n\
         \x20       {{42,42}},{{5,9}},{{-9,-2}},{{2147483647,2147483646}}\n\
         \x20   }};\n\
         \x20   size_t n_nzpairs = sizeof(nzpairs)/sizeof(nzpairs[0]);\n\
         {driver_body}\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n"
    )
}

fn nested_switch_body_has_target_op(recovery: &LeafRecovery) -> bool {
    recovery.source.contains("div_lhs / div_rhs")
        || recovery.source.contains("div_lhs % div_rhs")
        || recovery.source.contains("? 1 : 0")
}

#[test]
fn nested_switch_division_and_setcc_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!("skipping nested-switch oracle: gcc not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let battery_c: PathBuf = dir.join("nested_switch_battery.c");
    std::fs::write(&battery_c, battery_source(NESTED_SWITCH_BATTERY).as_bytes())
        .expect("write nested_switch_battery.c");
    let battery_o: PathBuf = dir.join("nested_switch_battery.o");
    let compile: std::process::Output = Command::new(&builder)
        .args([
            "-O1",
            "-fno-stack-protector",
            "-fno-if-conversion",
            "-fno-if-conversion2",
            "-fno-tree-loop-if-convert",
            "-c",
            "-o",
        ])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke gcc for nested switch battery");
    assert!(
        compile.status.success(),
        "nested switch battery compile failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read nested_switch_battery.o");

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    let mut op_bearing: usize = 0;

    for case in NESTED_SWITCH_BATTERY {
        let Some((recovery, renamed)): Option<(LeafRecovery, String)> =
            switch_lift(case, &object_bytes, HOST_ABI)
        else {
            continue;
        };
        if nested_switch_body_has_target_op(&recovery) {
            op_bearing += 1;
        }
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        let _ = writeln!(
            recovered_decls,
            "extern long long {}({});",
            case.name,
            vec!["long long"; case.arity].join(", ")
        );
        driver_body.push_str(&nested_switch_driver_snippet(case, &recovery));
        lifted_count += 1;
    }

    if lifted_count == 0 {
        eprintln!(
            "skipping nested-switch behavioral differential: this gcc build lowered none of the {} cases into a dense jump-table switch carrying nested division/setcc",
            NESTED_SWITCH_BATTERY.len()
        );
        return;
    }
    assert!(
        op_bearing >= 1,
        "nested-switch oracle must reconstruct at least one case body that carries a threaded idiv/setcc (its whole point), reconstructed {op_bearing} such bodies across {lifted_count} lifted functions"
    );

    let driver: String = build_nested_switch_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("nested_switch_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write nested_switch_driver.c");
    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "nested_switch_harness.exe"
    } else {
        "nested_switch_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke gcc to link nested switch harness");
    assert!(
        link.status.success(),
        "nested switch harness link failed: {}\n--- nested_switch_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );
    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run nested switch harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "nested-switch behavioral differential FAILED ({lifted_count} cases, {op_bearing} op-bearing): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "nested-switch behavioral differential PASSED for {lifted_count} leaf functions ({op_bearing} carrying threaded idiv/setcc inside a case body, MS x64 ABI)"
    );
}

#[test]
fn nested_switch_oracle_has_teeth_swapping_division_signedness_diverges() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!("skipping nested-switch teeth check: gcc not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let battery_c: PathBuf = dir.join("nested_switch_teeth_battery.c");
    std::fs::write(&battery_c, battery_source(NESTED_SWITCH_BATTERY).as_bytes())
        .expect("write nested_switch_teeth_battery.c");
    let battery_o: PathBuf = dir.join("nested_switch_teeth_battery.o");
    let compile: std::process::Output = Command::new(&builder)
        .args([
            "-O1",
            "-fno-stack-protector",
            "-fno-if-conversion",
            "-fno-if-conversion2",
            "-fno-tree-loop-if-convert",
            "-c",
            "-o",
        ])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke gcc for nested switch teeth battery");
    assert!(compile.status.success(), "teeth battery compile failed");
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read teeth battery");

    let probe: &Case = &NESTED_SWITCH_BATTERY[0];
    let Some((recovery, renamed)): Option<(LeafRecovery, String)> =
        switch_lift(probe, &object_bytes, HOST_ABI)
    else {
        eprintln!(
            "skipping nested-switch teeth check: this gcc build did not reconstruct the signed-division switch to corrupt"
        );
        return;
    };
    if !renamed.contains("int64_t div_lhs = (int64_t)r_rax;") {
        eprintln!(
            "skipping nested-switch teeth check: this build did not reconstruct a signed nested division to flip"
        );
        return;
    }
    let corrupted: String = renamed
        .replace(
            "int64_t div_lhs = (int64_t)r_rax;",
            "uint64_t div_lhs = (uint64_t)r_rax;",
        )
        .replace(
            "int64_t div_rhs = (int64_t)",
            "uint64_t div_rhs = (uint64_t)",
        );
    if corrupted == renamed {
        eprintln!("skipping nested-switch teeth check: signedness flip was a no-op");
        return;
    }
    let mut decls: String = corrupted;
    decls.push('\n');
    let _ = writeln!(
        decls,
        "extern long long {}({});",
        probe.name,
        vec!["long long"; probe.arity].join(", ")
    );
    let driver: String =
        build_nested_switch_driver(&decls, &nested_switch_driver_snippet(probe, &recovery));
    let driver_c: PathBuf = dir.join("nested_switch_teeth_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write nested_switch_teeth_driver.c");
    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "nested_switch_teeth_harness.exe"
    } else {
        "nested_switch_teeth_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke gcc to link nested switch teeth harness");
    assert!(
        link.status.success(),
        "nested switch teeth harness link failed: {}",
        String::from_utf8_lossy(&link.stderr)
    );
    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run nested switch teeth harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        !stdout.contains("OK") && stdout.contains("MISMATCH"),
        "teeth check FAILED: forcing the nested case division to unsigned must diverge on a negative dividend, got: {stdout}"
    );
    println!(
        "nested-switch oracle teeth confirmed: swapping a nested case's division signedness diverges (MISMATCH observed)"
    );
}

#[test]
fn sysv_nested_switch_division_and_setcc_recompile_to_behavioral_equivalence() {
    if !sysv_host_can_run() {
        return;
    }
    let Some(objs): Option<SysvCrossObjects> =
        compile_sysv_cross("nested_switch", &battery_source(NESTED_SWITCH_BATTERY))
    else {
        return;
    };

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    let mut op_bearing: usize = 0;

    for case in NESTED_SWITCH_BATTERY {
        let Some((recovery, renamed)): Option<(LeafRecovery, String)> =
            switch_lift(case, &objs.sysv_object, PseudoAbi::SysV)
        else {
            continue;
        };
        if nested_switch_body_has_target_op(&recovery) {
            op_bearing += 1;
        }
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        let _ = writeln!(
            recovered_decls,
            "extern long long {}({});",
            case.name,
            vec!["long long"; case.arity].join(", ")
        );
        driver_body.push_str(&nested_switch_driver_snippet(case, &recovery));
        lifted_count += 1;
    }

    if lifted_count == 0 {
        eprintln!(
            "skipping SysV nested-switch differential: clang lowered none of the cases into a dense jump-table switch carrying nested idiv/setcc"
        );
        return;
    }
    assert!(
        op_bearing >= 1,
        "SysV nested-switch oracle must reconstruct at least one case body carrying a threaded idiv/setcc, saw {op_bearing}"
    );

    let driver: String = build_nested_switch_driver(&recovered_decls, &driver_body);
    let stdout: String = link_and_run_sysv("nested_switch", &driver, &objs.host_object, 30);
    assert!(
        stdout.contains("OK"),
        "SysV nested-switch behavioral differential FAILED ({lifted_count} cases, {op_bearing} op-bearing): {stdout}"
    );
    println!(
        "SysV nested-switch behavioral differential PASSED for {lifted_count} leaf functions ({op_bearing} carrying threaded idiv/setcc, SysV ABI)"
    );
}

fn switch_cmp_bound(insns: &[disrobe_pass_native::DisasmInsn], lea_addr: u64) -> Option<u64> {
    let mut bound: Option<u64> = None;
    for insn in insns {
        if insn.address >= lea_addr {
            break;
        }
        if insn.mnemonic == "cmp"
            && let Some((_, rhs)) = insn.operands.split_once(',')
        {
            let t: &str = rhs.trim().trim_end_matches('h');
            bound = t
                .parse::<u64>()
                .ok()
                .or_else(|| u64::from_str_radix(t, 16).ok());
        }
    }
    bound
}

fn resolve_switch_tables(object_bytes: &[u8], code: &[u8], base: u64) -> Option<Vec<JumpTable>> {
    let file: object::File<'_> = object::File::parse(object_bytes).ok()?;
    let insns: Vec<disrobe_pass_native::DisasmInsn> = disassemble(Arch::X86_64, base, code).ok()?;
    let text: object::Section<'_, '_> = file.section_by_name(".text")?;
    let rodata: object::Section<'_, '_> = file
        .section_by_name(".rodata")
        .or_else(|| file.section_by_name(".rdata"))?;
    let ro_addr: u64 = rodata.address();
    let ro_data: &[u8] = rodata.data().ok()?;
    let mut out: Vec<JumpTable> = Vec::new();

    for insn in &insns {
        if insn.mnemonic != "lea" || !insn.operands.contains("[rel ") {
            continue;
        }
        let va_str: &str = insn
            .operands
            .split("[rel ")
            .nth(1)?
            .trim_end_matches(']')
            .trim_end_matches('h');
        let table_va: u64 = u64::from_str_radix(va_str, 16).ok()?;
        let bound: u64 = switch_cmp_bound(&insns, insn.address)?;
        let n: usize = usize::try_from(bound).ok()?.checked_add(1)?;

        let disp_off: u64 = insn.address + insn.bytes.len() as u64 - 4;
        let mut table_ro_off: Option<u64> = None;
        for (off, reloc) in text.relocations() {
            if off != disp_off {
                continue;
            }
            let object::RelocationTarget::Symbol(si) = reloc.target() else {
                continue;
            };
            let sym: object::Symbol<'_, '_> = file.symbol_by_index(si).ok()?;
            let raw_addend: i64 = if reloc.has_implicit_addend() {
                let slot: usize = usize::try_from(off - text.address()).ok()?;
                let bytes: [u8; 4] = text.data().ok()?.get(slot..slot + 4)?.try_into().ok()?;
                i64::from(i32::from_le_bytes(bytes)) + reloc.addend()
            } else {
                reloc.addend()
            };
            let target: i64 = sym.address() as i64 + raw_addend + 4;
            table_ro_off = Some((target - ro_addr as i64) as u64);
        }
        let table_ro_off: u64 = table_ro_off?;

        let mut slots: std::collections::BTreeMap<u64, i32> = std::collections::BTreeMap::new();
        for (off, reloc) in rodata.relocations() {
            let ro_slot: u64 = off - ro_addr;
            if ro_slot < table_ro_off || ro_slot >= table_ro_off + (n as u64) * 4 {
                continue;
            }
            let object::RelocationTarget::Symbol(si) = reloc.target() else {
                continue;
            };
            let sym: object::Symbol<'_, '_> = file.symbol_by_index(si).ok()?;
            let effective: i64 = if reloc.has_implicit_addend() {
                let slot: usize = usize::try_from(ro_slot).ok()?;
                let bytes: [u8; 4] = ro_data.get(slot..slot + 4)?.try_into().ok()?;
                i64::from(i32::from_le_bytes(bytes)) + reloc.addend()
            } else {
                reloc.addend()
            };
            let case_off: i64 =
                sym.address() as i64 + effective - (ro_slot as i64 - table_ro_off as i64);
            let entry: i32 = i32::try_from(case_off - table_va as i64).ok()?;
            slots.insert(ro_slot, entry);
        }
        if slots.len() != n {
            continue;
        }
        out.push(JumpTable {
            table_va,
            entries: slots.into_values().collect(),
        });
    }
    Some(out)
}

fn switch_lift(case: &Case, object_bytes: &[u8], abi: PseudoAbi) -> Option<(LeafRecovery, String)> {
    let (code, base): (Vec<u8>, u64) = function_code(object_bytes, case.name)?;
    let tables: Vec<JumpTable> = resolve_switch_tables(object_bytes, &code, base)?;
    if tables.is_empty() {
        eprintln!("skip {}: no jump table resolved this build", case.name);
        return None;
    }
    let recovery: LeafRecovery = match recover_leaf_function_switch_abi(&code, base, abi, &tables) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("skip {}: not in dense-switch class ({e})", case.name);
            return None;
        }
    };
    if !recovery.lifted_switch {
        return None;
    }
    let recovered_name: String = format!("rec_{}", case.name);
    let renamed: String = recovery
        .source
        .replacen(
            "uint64_t recovered(",
            &format!("uint64_t {recovered_name}("),
            1,
        )
        .lines()
        .filter(|l: &&str| !l.starts_with("#include"))
        .collect::<Vec<&str>>()
        .join("\n");
    Some((recovery, renamed))
}

fn switch_driver_snippet(case: &Case, recovery: &LeafRecovery) -> String {
    let recovered_name: String = format!("rec_{}", case.name);
    let return_mask: String = if recovery.return_width_bits == 64 {
        "0xFFFFFFFFFFFFFFFFULL".to_owned()
    } else {
        format!("0x{:x}ULL", (1u128 << recovery.return_width_bits) - 1)
    };
    let args: Vec<String> = (0..case.arity).map(|i: usize| format!("in[{i}]")).collect();
    let rec_args: Vec<String> = (0..recovery.params.len())
        .map(|i: usize| format!("(uint64_t)in[{i}]"))
        .collect();
    let mut snippet: String = String::new();
    let _ = write!(
        snippet,
        "    for (long long disc = -2; disc <= 10; disc++) {{\n\
         \x20   for (size_t k = 0; k < n_inputs; k++) {{\n\
         \x20       long long in[3] = {{ disc, inputs[k][1], inputs[k][2] }};\n\
         \x20       unsigned long long want = (unsigned long long){}({}) & {return_mask};\n\
         \x20       unsigned long long got = {recovered_name}({}) & {return_mask};\n\
         \x20       if (want != got) {{ printf(\"MISMATCH {} disc=%lld in=%lld,%lld want=%llu got=%llu\\n\", disc, in[1], in[2], want, got); return 1; }}\n\
         \x20   }}\n\
         \x20   }}\n",
        case.name,
        args.join(", "),
        rec_args.join(", "),
        case.name,
    );
    snippet
}

fn compile_switch_host(builder: &str, dir: &std::path::Path) -> Vec<u8> {
    let mut battery_src: String = String::new();
    for case in SWITCH_BATTERY {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let battery_c: PathBuf = dir.join("switch_battery.c");
    std::fs::write(&battery_c, battery_src.as_bytes()).expect("write switch_battery.c");
    let battery_o: PathBuf = dir.join("switch_battery.o");
    let compile: std::process::Output = Command::new(builder)
        .args([
            "-O1",
            "-fno-stack-protector",
            "-fno-if-conversion",
            "-fno-if-conversion2",
            "-fno-tree-loop-if-convert",
            "-c",
            "-o",
        ])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke gcc for switch battery");
    assert!(
        compile.status.success(),
        "switch battery compile failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    std::fs::read(&battery_o).expect("read switch_battery.o")
}

#[test]
fn switch_dense_jump_table_leaf_functions_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!(
            "skipping switch oracle: gcc (needed for the dense jump-table idiom) not on PATH"
        );
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let object_bytes: Vec<u8> = compile_switch_host(&builder, &dir);

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;

    for case in SWITCH_BATTERY {
        let Some((recovery, renamed)): Option<(LeafRecovery, String)> =
            switch_lift(case, &object_bytes, HOST_ABI)
        else {
            continue;
        };
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        let _ = writeln!(
            recovered_decls,
            "extern long long {}({});",
            case.name,
            vec!["long long"; case.arity].join(", ")
        );
        driver_body.push_str(&switch_driver_snippet(case, &recovery));
        lifted_count += 1;
    }

    if lifted_count == 0 {
        eprintln!(
            "skipping dense-switch behavioral differential: this compiler build reconstructed none of the {} battery cases into a dense jump-table switch",
            SWITCH_BATTERY.len()
        );
        return;
    }

    let driver: String = build_call_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("switch_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write switch_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "switch_harness.exe"
    } else {
        "switch_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(dir.join("switch_battery.o"))
        .output()
        .expect("invoke gcc to link switch harness");
    assert!(
        link.status.success(),
        "switch harness link failed: {}\n--- switch_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run switch harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "dense-switch behavioral differential FAILED ({lifted_count} cases): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "dense-switch behavioral differential PASSED for {lifted_count} leaf functions (MS x64 ABI)"
    );
}

#[test]
fn switch_oracle_has_teeth_a_wrong_case_value_diverges() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!("skipping switch teeth check: gcc not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let object_bytes: Vec<u8> = compile_switch_host(&builder, &dir);

    let probe: &Case = &SWITCH_BATTERY[0];
    let Some((recovery, renamed)): Option<(LeafRecovery, String)> =
        switch_lift(probe, &object_bytes, HOST_ABI)
    else {
        eprintln!(
            "skipping switch teeth check: this compiler build did not reconstruct a dense switch to corrupt"
        );
        return;
    };
    if !(renamed.contains("case 2:") && renamed.contains("case 3:")) {
        eprintln!(
            "skipping switch teeth check: this compiler build did not reconstruct the distinct cases this check relabels"
        );
        return;
    }

    let corrupted: String = renamed.replacen("case 2: {", "case 999: {", 1);
    if corrupted == renamed {
        eprintln!(
            "skipping switch teeth check: relabeling case 2 was a no-op on this build's reconstruction"
        );
        return;
    }

    let mut decls: String = corrupted;
    decls.push('\n');
    let _ = writeln!(
        decls,
        "extern long long {}({});",
        probe.name,
        vec!["long long"; probe.arity].join(", ")
    );
    let driver: String = build_call_driver(&decls, &switch_driver_snippet(probe, &recovery));
    let driver_c: PathBuf = dir.join("switch_teeth_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write switch_teeth_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "switch_teeth_harness.exe"
    } else {
        "switch_teeth_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(dir.join("switch_battery.o"))
        .output()
        .expect("invoke gcc to link switch teeth harness");
    assert!(
        link.status.success(),
        "switch teeth harness link failed: {}\n--- switch_teeth_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run switch teeth harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        !stdout.contains("OK") && stdout.contains("MISMATCH"),
        "teeth check FAILED: relabeling case 2 to an unreachable value must diverge on disc==2, got: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "switch oracle teeth confirmed: relabeling a case value diverges on that discriminant (MISMATCH observed)"
    );
}

#[test]
fn sysv_switch_dense_jump_table_leaf_functions_recompile_to_behavioral_equivalence() {
    if !sysv_host_can_run() {
        return;
    }
    let Some(objs): Option<SysvCrossObjects> =
        compile_sysv_cross("switch", &battery_source(SWITCH_BATTERY))
    else {
        return;
    };

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    let mut fallthrough_count: usize = 0;

    for case in SWITCH_BATTERY {
        let Some((recovery, renamed)): Option<(LeafRecovery, String)> =
            switch_lift(case, &objs.sysv_object, PseudoAbi::SysV)
        else {
            continue;
        };
        if recovery.source.matches("case ").count() > recovery.source.matches("break;").count() {
            fallthrough_count += 1;
        }
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        let _ = writeln!(
            recovered_decls,
            "extern long long {}({});",
            case.name,
            vec!["long long"; case.arity].join(", ")
        );
        driver_body.push_str(&switch_driver_snippet(case, &recovery));
        lifted_count += 1;
    }

    assert!(
        lifted_count >= 4,
        "SysV dense-switch lifter must reconstruct at least 4 of the {} cases, only lifted {lifted_count}",
        SWITCH_BATTERY.len()
    );
    assert!(
        fallthrough_count >= 1,
        "SysV switch oracle must exercise at least one fallthrough case, saw {fallthrough_count}"
    );

    let driver: String = build_call_driver(&recovered_decls, &driver_body);
    let stdout: String = link_and_run_sysv("switch", &driver, &objs.host_object, 30);
    assert!(
        stdout.contains("OK"),
        "SysV dense-switch behavioral differential FAILED ({lifted_count} cases, {fallthrough_count} fallthrough): {stdout}"
    );
    println!(
        "SysV dense-switch behavioral differential PASSED for {lifted_count} leaf functions ({fallthrough_count} fallthrough, SysV ABI)"
    );
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FpSwitchWidth {
    Double,
    Float,
}

struct FpSwitchCase {
    name: &'static str,
    width: FpSwitchWidth,
    c_source: &'static str,
}

const FP_SWITCH_BATTERY: &[FpSwitchCase] = &[
    FpSwitchCase {
        name: "swf_d",
        width: FpSwitchWidth::Double,
        c_source: "double swf_d(long long x, double a, double b){ double r; switch (x) { case 0: r = a + b; break; case 1: r = a - b; break; case 2: r = a * b; break; case 3: r = a * 1.5; break; case 4: r = b + 2.0; break; case 5: r = a * b + 1.0; break; default: r = a - 3.0; break; } return r; }",
    },
    FpSwitchCase {
        name: "swf_d2",
        width: FpSwitchWidth::Double,
        c_source: "double swf_d2(long long x, double a, double b){ double r; switch (x) { case 0: r = a * 2.0 + b; break; case 1: r = a - b * 0.5; break; case 2: r = (a + b) * 0.25; break; case 3: r = a * a; break; case 4: r = b * b - a; break; default: r = a + b + 7.0; break; } return r; }",
    },
    FpSwitchCase {
        name: "swf_f",
        width: FpSwitchWidth::Float,
        c_source: "float swf_f(long long x, float a, float b){ float r; switch (x) { case 0: r = a + b; break; case 1: r = a - b; break; case 2: r = a * b; break; case 3: r = a * 3.0f; break; case 4: r = b + 1.0f; break; default: r = a + b + 9.0f; break; } return r; }",
    },
];

fn fp_switch_battery_source() -> String {
    let mut src: String = String::new();
    for case in FP_SWITCH_BATTERY {
        src.push_str(case.c_source);
        src.push('\n');
    }
    src
}

fn fp_switch_lift(
    case: &FpSwitchCase,
    object_bytes: &[u8],
    abi: PseudoAbi,
) -> Option<(LeafRecovery, String)> {
    let (code, base): (Vec<u8>, u64) = function_code(object_bytes, case.name)?;
    let tables: Vec<JumpTable> = resolve_switch_tables(object_bytes, &code, base)?;
    if tables.is_empty() {
        eprintln!("skip {}: no jump table resolved this build", case.name);
        return None;
    }
    let consts: Vec<FpConstant> = resolve_fp_constants(object_bytes, &code, base);
    let recovery: LeafRecovery =
        match recover_leaf_function_switch_const_abi(&code, base, abi, &tables, &consts) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skip {}: not in dense fp-switch class ({e})", case.name);
                return None;
            }
        };
    if !recovery.lifted_switch {
        return None;
    }
    let expected: ScalarType = match case.width {
        FpSwitchWidth::Double => ScalarType::Double,
        FpSwitchWidth::Float => ScalarType::Float,
    };
    if recovery.returns_fp != Some(expected) {
        eprintln!(
            "skip {}: switch did not type as {expected:?} return (got {:?})",
            case.name, recovery.returns_fp
        );
        return None;
    }
    let ret_type: &str = match case.width {
        FpSwitchWidth::Double => "double",
        FpSwitchWidth::Float => "float",
    };
    let recovered_name: String = format!("rec_{}", case.name);
    let renamed: String = recovery.source.replacen(
        &format!("{ret_type} recovered("),
        &format!("{ret_type} {recovered_name}("),
        1,
    );
    let renamed: String = strip_shared_fp_prelude(&renamed);
    Some((recovery, renamed))
}

fn fp_switch_driver_snippet(case: &FpSwitchCase) -> String {
    let recovered_name: String = format!("rec_{}", case.name);
    let (arg_ty, bits_fn): (&str, &str) = match case.width {
        FpSwitchWidth::Double => ("double", "d_bits"),
        FpSwitchWidth::Float => ("float", "f_bits"),
    };
    let mut snippet: String = String::new();
    let _ = write!(
        snippet,
        "    for (long long disc = -2; disc <= 9; disc++) {{\n\
         \x20   for (size_t k = 0; k < n_pairs; k++) {{\n\
         \x20       {arg_ty} a = ({arg_ty})pairs[k][0];\n\
         \x20       {arg_ty} b = ({arg_ty})pairs[k][1];\n\
         \x20       uint64_t want = {bits_fn}({}(disc, a, b));\n\
         \x20       uint64_t got = {bits_fn}({recovered_name}(a, b, (uint64_t)disc));\n\
         \x20       if (want != got) {{ printf(\"MISMATCH {} disc=%lld in=%g,%g want=%llu got=%llu\\n\", disc, (double)a, (double)b, (unsigned long long)want, (unsigned long long)got); return 1; }}\n\
         \x20   }}\n\
         \x20   }}\n",
        case.name, case.name,
    );
    snippet
}

fn fp_switch_extern_decl(case: &FpSwitchCase) -> String {
    let ret: &str = match case.width {
        FpSwitchWidth::Double => "double",
        FpSwitchWidth::Float => "float",
    };
    let arg: &str = match case.width {
        FpSwitchWidth::Double => "double",
        FpSwitchWidth::Float => "float",
    };
    format!("extern {ret} {}(long long, {arg}, {arg});", case.name)
}

fn build_fp_switch_driver(recovered_decls: &str, driver_body: &str) -> String {
    format!(
        "#include <stdint.h>\n#include <string.h>\n#include <stdio.h>\n#include <stddef.h>\n\
         static inline double fp_d_from_bits(uint64_t b){{ double v; memcpy(&v,&b,8); return v; }}\n\
         static inline uint64_t fp_d_to_bits(double v){{ uint64_t b; memcpy(&b,&v,8); return b; }}\n\
         static inline float fp_f_from_bits(uint32_t b){{ float v; memcpy(&v,&b,4); return v; }}\n\
         static inline uint32_t fp_f_to_bits(float v){{ uint32_t b; memcpy(&b,&v,4); return b; }}\n\
         static inline uint64_t d_bits(double v){{ uint64_t b; memcpy(&b,&v,8); return b; }}\n\
         static inline uint64_t f_bits(float v){{ uint32_t b; memcpy(&b,&v,4); return (uint64_t)b; }}\n\
         {recovered_decls}\n\
         int main(void) {{\n\
         \x20   double pairs[][2] = {{\n\
         \x20       {{0.0,1.0}},{{1.0,1.0}},{{-1.0,1.0}},{{7.0,3.0}},{{-7.0,3.0}},{{7.0,-3.0}},\n\
         \x20       {{3.5,2.25}},{{-3.5,2.25}},{{100.0,7.0}},{{-100.0,-7.0}},{{0.5,0.25}},\n\
         \x20       {{12.75,9.5}},{{-8.0,4.0}},{{42.0,42.0}},{{5.0,9.0}},{{0.0,-7.0}},{{-0.0,4.0}}\n\
         \x20   }};\n\
         \x20   size_t n_pairs = sizeof(pairs)/sizeof(pairs[0]);\n\
         {driver_body}\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n"
    )
}

#[test]
fn fp_switch_dense_jump_table_leaf_functions_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!(
            "skipping fp-switch oracle: gcc (needed for the dense jump-table idiom) not on PATH"
        );
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let battery_c: PathBuf = dir.join("fp_switch_battery.c");
    std::fs::write(&battery_c, fp_switch_battery_source().as_bytes())
        .expect("write fp_switch_battery.c");
    let battery_o: PathBuf = dir.join("fp_switch_battery.o");
    let compile: std::process::Output = Command::new(&builder)
        .args([
            "-O1",
            "-fno-stack-protector",
            "-fno-if-conversion",
            "-fno-if-conversion2",
            "-fno-tree-loop-if-convert",
            "-c",
            "-o",
        ])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke gcc for fp switch battery");
    assert!(
        compile.status.success(),
        "fp switch battery compile failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read fp_switch_battery.o");

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    for case in FP_SWITCH_BATTERY {
        let Some((_recovery, renamed)): Option<(LeafRecovery, String)> =
            fp_switch_lift(case, &object_bytes, HOST_ABI)
        else {
            continue;
        };
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        recovered_decls.push_str(&fp_switch_extern_decl(case));
        recovered_decls.push('\n');
        driver_body.push_str(&fp_switch_driver_snippet(case));
        lifted_count += 1;
    }

    if lifted_count == 0 {
        eprintln!(
            "skipping fp-switch behavioral differential: this compiler build reconstructed none of the {} battery cases into a dense fp-returning jump-table switch",
            FP_SWITCH_BATTERY.len()
        );
        return;
    }

    let driver: String = build_fp_switch_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("fp_switch_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write fp_switch_driver.c");
    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "fp_switch_harness.exe"
    } else {
        "fp_switch_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke gcc to link fp switch harness");
    assert!(
        link.status.success(),
        "fp switch harness link failed: {}\n--- fp_switch_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );
    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run fp switch harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "fp-switch behavioral differential FAILED ({lifted_count} cases): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "fp-switch behavioral differential PASSED for {lifted_count} fp-returning leaf functions (MS x64 ABI)"
    );
}

#[test]
fn fp_switch_oracle_has_teeth_relabeling_a_case_diverges() {
    if !cfg!(windows) {
        eprintln!("skipping fp-switch teeth check on non-windows host");
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!("skipping fp-switch teeth check: gcc not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let battery_c: PathBuf = dir.join("fp_switch_teeth_battery.c");
    std::fs::write(&battery_c, fp_switch_battery_source().as_bytes())
        .expect("write fp switch teeth battery");
    let battery_o: PathBuf = dir.join("fp_switch_teeth_battery.o");
    let compile: std::process::Output = Command::new(&builder)
        .args([
            "-O1",
            "-fno-stack-protector",
            "-fno-if-conversion",
            "-fno-if-conversion2",
            "-fno-tree-loop-if-convert",
            "-c",
            "-o",
        ])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke gcc for fp switch teeth battery");
    assert!(compile.status.success(), "fp switch teeth compile failed");
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read fp switch teeth object");

    let probe: &FpSwitchCase = &FP_SWITCH_BATTERY[0];
    let Some((_recovery, renamed)): Option<(LeafRecovery, String)> =
        fp_switch_lift(probe, &object_bytes, HOST_ABI)
    else {
        eprintln!("skipping fp-switch teeth check: probe not reconstructed as an fp switch");
        return;
    };
    let corrupted: String = renamed.replacen("case 0:", "case 9:", 1);
    if corrupted == renamed {
        eprintln!("skipping fp-switch teeth check: relabeling case 0 was a no-op on this build");
        return;
    }
    let mut decls: String = corrupted;
    decls.push('\n');
    decls.push_str(&fp_switch_extern_decl(probe));
    decls.push('\n');
    let driver: String = build_fp_switch_driver(&decls, &fp_switch_driver_snippet(probe));
    let driver_c: PathBuf = dir.join("fp_switch_teeth_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write fp switch teeth driver");
    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "fp_switch_teeth_harness.exe"
    } else {
        "fp_switch_teeth_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke gcc to link fp switch teeth harness");
    assert!(
        link.status.success(),
        "fp switch teeth harness link failed: {}\n--- fp_switch_teeth_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );
    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run fp switch teeth harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        stdout.contains("MISMATCH"),
        "fp-switch oracle has no teeth: relabeling case 0 did not diverge: {stdout}"
    );
    println!(
        "fp-switch oracle teeth confirmed: relabeling a case value diverges on that discriminant (MISMATCH observed)"
    );
}

#[test]
fn sysv_fp_switch_dense_jump_table_leaf_functions_recompile_to_behavioral_equivalence() {
    if !sysv_host_can_run() {
        return;
    }
    let Some(objs): Option<SysvCrossObjects> =
        compile_sysv_cross("fp_switch", &fp_switch_battery_source())
    else {
        return;
    };

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    for case in FP_SWITCH_BATTERY {
        let Some((_recovery, renamed)): Option<(LeafRecovery, String)> =
            fp_switch_lift(case, &objs.sysv_object, PseudoAbi::SysV)
        else {
            continue;
        };
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        recovered_decls.push_str(&fp_switch_extern_decl(case));
        recovered_decls.push('\n');
        driver_body.push_str(&fp_switch_driver_snippet(case));
        lifted_count += 1;
    }

    assert!(
        lifted_count >= 2,
        "SysV fp-switch lifter must reconstruct at least 2 of the {} fp-returning cases, only lifted {lifted_count}",
        FP_SWITCH_BATTERY.len()
    );

    let driver: String = build_fp_switch_driver(&recovered_decls, &driver_body);
    let stdout: String = link_and_run_sysv("fp_switch", &driver, &objs.host_object, 30);
    assert!(
        stdout.contains("OK"),
        "SysV fp-switch behavioral differential FAILED ({lifted_count} cases): {stdout}"
    );
    println!(
        "SysV fp-switch behavioral differential PASSED for {lifted_count} fp-returning leaf functions (SysV ABI)"
    );
}

struct BlockCase {
    name: &'static str,
    original: &'static str,
    prototype: &'static str,
    driver_call: &'static str,
    rep_mnemonic: &'static str,
}

const BLOCK_BATTERY: &[BlockCase] = &[
    BlockCase {
        name: "bm_var",
        original: "void bm_var(unsigned char *d, const unsigned char *s, unsigned long n){ __builtin_memcpy(d, s, n); }",
        prototype: "extern void bm_var(unsigned char *d, const unsigned char *s, unsigned long n);",
        driver_call: "        bm_var(orig_dst, src_buf, len);\n        rec_bm_var((uint64_t)(uintptr_t)rec_dst, (uint64_t)(uintptr_t)src_buf, (uint64_t)len);\n",
        rep_mnemonic: "movsb",
    },
    BlockCase {
        name: "bf_byte",
        original: "void bf_byte(unsigned char *d, unsigned long n, int v){ __builtin_memset(d, v, n); }",
        prototype: "extern void bf_byte(unsigned char *d, unsigned long n, int v);",
        driver_call: "        bf_byte(orig_dst, len, fill_v);\n        rec_bf_byte((uint64_t)(uintptr_t)rec_dst, (uint64_t)len, (uint64_t)(unsigned)fill_v);\n",
        rep_mnemonic: "stosb",
    },
    BlockCase {
        name: "bf_zero",
        original: "void bf_zero(unsigned char *d, unsigned long n){ __builtin_memset(d, 0, n); }",
        prototype: "extern void bf_zero(unsigned char *d, unsigned long n);",
        driver_call: "        bf_zero(orig_dst, len);\n        rec_bf_zero((uint64_t)(uintptr_t)rec_dst, (uint64_t)len);\n",
        rep_mnemonic: "stosb",
    },
];

fn block_recovered_signature(recovery: &LeafRecovery, recovered_name: &str) -> String {
    recovery
        .source
        .replacen(
            "uint64_t recovered(",
            &format!("uint64_t {recovered_name}("),
            1,
        )
        .lines()
        .filter(|l: &&str| !l.starts_with("#include"))
        .collect::<Vec<&str>>()
        .join("\n")
}

fn build_block_driver(recovered_decls: &str, extern_decls: &str, driver_body: &str) -> String {
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n#include <string.h>\n\
         {recovered_decls}\n{extern_decls}\n\
         int main(void) {{\n\
         \x20   static unsigned char pattern[512];\n\
         \x20   for (size_t i = 0; i < sizeof(pattern); i++) pattern[i] = (unsigned char)(i * 37 + 11);\n\
         \x20   size_t lens[] = {{ 0, 1, 2, 3, 7, 8, 15, 16, 31, 63, 64, 100, 255, 256, 511 }};\n\
         \x20   int fills[] = {{ 0, 1, 0x5a, 0xff, 0x80, 0x7f }};\n\
         \x20   size_t n_lens = sizeof(lens)/sizeof(lens[0]);\n\
         \x20   size_t n_fills = sizeof(fills)/sizeof(fills[0]);\n\
         \x20   for (size_t li = 0; li < n_lens; li++) {{\n\
         \x20   for (size_t vi = 0; vi < n_fills; vi++) {{\n\
         \x20       unsigned long len = (unsigned long)lens[li];\n\
         \x20       int fill_v = fills[vi];\n\
         \x20       static unsigned char orig_dst[512];\n\
         \x20       static unsigned char rec_dst[512];\n\
         \x20       static unsigned char src_buf[512];\n\
         \x20       memcpy(src_buf, pattern, sizeof(src_buf));\n\
         \x20       memset(orig_dst, 0xa5, sizeof(orig_dst));\n\
         \x20       memset(rec_dst, 0xa5, sizeof(rec_dst));\n\
         {driver_body}\
         \x20       if (memcmp(orig_dst, rec_dst, sizeof(orig_dst)) != 0) {{\n\
         \x20           for (size_t b = 0; b < sizeof(orig_dst); b++) {{\n\
         \x20               if (orig_dst[b] != rec_dst[b]) {{ printf(\"MISMATCH len=%lu fill=%d idx=%zu orig=%u rec=%u\\n\", len, fill_v, b, orig_dst[b], rec_dst[b]); return 1; }}\n\
         \x20           }}\n\
         \x20       }}\n\
         \x20   }}\n\
         \x20   }}\n\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n"
    )
}

fn gcc_rep_object(
    dir: &std::path::Path,
    tag: &str,
    battery_src: &str,
) -> Option<(Vec<u8>, PathBuf)> {
    let builder: String = gcc()?;
    let battery_c: PathBuf = dir.join(format!("{tag}_battery.c"));
    std::fs::write(&battery_c, battery_src.as_bytes()).expect("write block battery.c");
    let battery_o: PathBuf = dir.join(format!("{tag}_battery.o"));
    let compile: std::process::Output = Command::new(&builder)
        .args([
            "-O1",
            "-fno-stack-protector",
            "-minline-all-stringops",
            "-mstringop-strategy=rep_byte",
            "-mno-sse",
            "-c",
            "-o",
        ])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke gcc for block battery");
    if !compile.status.success() {
        eprintln!(
            "skipping block-move oracle: gcc rejected the rep stringop strategy flags: {}",
            String::from_utf8_lossy(&compile.stderr)
        );
        return None;
    }
    let bytes: Vec<u8> = std::fs::read(&battery_o).expect("read block battery.o");
    Some((bytes, battery_o))
}

fn code_uses_rep(object_bytes: &[u8], name: &str, rep_op: &str) -> bool {
    let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(object_bytes, name) else {
        return false;
    };
    let Ok(insns): Result<Vec<disrobe_pass_native::DisasmInsn>, _> =
        disassemble(Arch::X86_64, base, &code)
    else {
        return false;
    };
    insns
        .iter()
        .any(|i: &disrobe_pass_native::DisasmInsn| i.mnemonic == "rep" && i.operands == rep_op)
}

#[test]
fn block_move_fill_leaf_functions_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    if gcc().is_none() {
        eprintln!(
            "skipping block-move oracle: gcc (needed to force the rep movs/stos stringop idiom) not on PATH"
        );
        return;
    }
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let mut battery_src: String = String::new();
    for case in BLOCK_BATTERY {
        battery_src.push_str(case.original);
        battery_src.push('\n');
    }
    let Some((object_bytes, battery_o)): Option<(Vec<u8>, PathBuf)> =
        gcc_rep_object(&dir, "blockhost", &battery_src)
    else {
        return;
    };

    let mut recovered_decls: String = String::new();
    let mut extern_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    let mut memcpy_count: usize = 0;
    let mut memset_count: usize = 0;
    let mut rep_idiom_count: usize = 0;

    for case in BLOCK_BATTERY {
        let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(&object_bytes, case.name)
        else {
            eprintln!("skip {}: symbol not located", case.name);
            continue;
        };
        if code_uses_rep(&object_bytes, case.name, case.rep_mnemonic) {
            rep_idiom_count += 1;
        } else {
            eprintln!(
                "note {}: gcc did not emit `rep {}` this build",
                case.name, case.rep_mnemonic
            );
        }
        let recovery: LeafRecovery = match recover_leaf_function_abi(&code, base, HOST_ABI) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skip {}: not in block-move leaf class ({e})", case.name);
                continue;
            }
        };
        if recovery.source.contains("memcpy(") {
            memcpy_count += 1;
        }
        if recovery.source.contains("memset(") {
            memset_count += 1;
        }
        let recovered_name: String = format!("rec_{}", case.name);
        recovered_decls.push_str(&block_recovered_signature(&recovery, &recovered_name));
        recovered_decls.push('\n');
        extern_decls.push_str(case.prototype);
        extern_decls.push('\n');
        driver_body.push_str(case.driver_call);
        lifted_count += 1;
    }

    assert!(
        rep_idiom_count >= 2,
        "block-move oracle must exercise at least 2 real `rep movs/stos` idioms, saw {rep_idiom_count}"
    );
    assert!(
        memcpy_count >= 1 && memset_count >= 1,
        "block-move lifter must recover both a memcpy and a memset ({memcpy_count} memcpy, {memset_count} memset)"
    );

    let driver: String = build_block_driver(&recovered_decls, &extern_decls, &driver_body);
    let driver_c: PathBuf = dir.join("blockhost_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write blockhost_driver.c");
    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "blockhost_harness.exe"
    } else {
        "blockhost_harness"
    });
    let builder: String = gcc().expect("gcc present");
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke gcc to link block harness");
    assert!(
        link.status.success(),
        "block harness link failed: {}\n--- block_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run block harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "block-move behavioral differential FAILED ({lifted_count} cases, {rep_idiom_count} rep idioms): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "block-move behavioral differential PASSED for {lifted_count} leaf functions ({memcpy_count} memcpy, {memset_count} memset, {rep_idiom_count} real rep idioms, MS x64 ABI)"
    );
}

#[test]
fn block_move_oracle_has_teeth_a_wrong_copy_length_diverges() {
    if !cfg!(windows) {
        eprintln!("skipping block-move teeth on non-windows host");
        return;
    }
    if gcc().is_none() {
        eprintln!("skipping block-move teeth: gcc not on PATH");
        return;
    }
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let case: &BlockCase = &BLOCK_BATTERY[0];
    let Some((object_bytes, battery_o)): Option<(Vec<u8>, PathBuf)> =
        gcc_rep_object(&dir, "blockteeth", &format!("{}\n", case.original))
    else {
        return;
    };
    let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(&object_bytes, case.name) else {
        eprintln!("teeth: {} symbol not located", case.name);
        return;
    };
    let recovery: LeafRecovery = match recover_leaf_function_abi(&code, base, HOST_ABI) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("teeth: {} did not lift ({e})", case.name);
            return;
        }
    };
    let recovered_name: String = format!("rec_{}", case.name);
    let mut recovered: String = block_recovered_signature(&recovery, &recovered_name);
    assert!(
        recovered.contains("move_n = r_rcx * 1ULL"),
        "teeth expected the recovered memcpy length expression: {recovered}"
    );
    recovered = recovered.replace("move_n = r_rcx * 1ULL", "move_n = r_rcx * 2ULL");

    let mut recovered_decls: String = String::new();
    recovered_decls.push_str(&recovered);
    recovered_decls.push('\n');
    let mut extern_decls: String = String::new();
    extern_decls.push_str(case.prototype);
    extern_decls.push('\n');
    let driver: String = build_block_driver(&recovered_decls, &extern_decls, case.driver_call);
    let driver_c: PathBuf = dir.join("blockteeth_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write teeth driver");
    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "blockteeth_harness.exe"
    } else {
        "blockteeth_harness"
    });
    let builder: String = gcc().expect("gcc present");
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke gcc to link teeth harness");
    assert!(
        link.status.success(),
        "teeth harness link failed: {}",
        String::from_utf8_lossy(&link.stderr)
    );
    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run teeth harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        !(run.status.success() && stdout.contains("OK")),
        "teeth FAILED: doubling the memcpy length still matched the original; the oracle is not sensitive to copy length"
    );
    println!(
        "block-move oracle teeth PASSED: doubling the recovered copy length diverges from the original"
    );
}

fn assemble_sysv_leaf(body: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(body.len() + 1);
    out.extend_from_slice(body);
    out.push(0xc3);
    out
}

struct SysvBlockCase {
    name: &'static str,
    machine_code: Vec<u8>,
    ground_truth: String,
    prototype: String,
    driver_call: String,
    expect_memcpy: bool,
    expect_memset: bool,
}

fn sysv_block_battery() -> Vec<SysvBlockCase> {
    vec![
        SysvBlockCase {
            name: "sv_memcpy",
            machine_code: assemble_sysv_leaf(&[0x48, 0x89, 0xd1, 0xf3, 0xa4]),
            ground_truth:
                "void sv_memcpy(unsigned char *d, const unsigned char *s, unsigned long n){ __builtin_memcpy(d, s, n); }"
                    .to_owned(),
            prototype:
                "extern void sv_memcpy(unsigned char *d, const unsigned char *s, unsigned long n);"
                    .to_owned(),
            driver_call:
                "        sv_memcpy(orig_dst, src_buf, len);\n        rec_sv_memcpy((uint64_t)(uintptr_t)rec_dst, (uint64_t)(uintptr_t)src_buf, (uint64_t)len);\n"
                    .to_owned(),
            expect_memcpy: true,
            expect_memset: false,
        },
        SysvBlockCase {
            name: "sv_memset",
            machine_code: assemble_sysv_leaf(&[0x48, 0x89, 0xd1, 0x89, 0xf0, 0xf3, 0xaa]),
            ground_truth:
                "void sv_memset(unsigned char *d, int c, unsigned long n){ __builtin_memset(d, c, n); }"
                    .to_owned(),
            prototype: "extern void sv_memset(unsigned char *d, int c, unsigned long n);".to_owned(),
            driver_call:
                "        sv_memset(orig_dst, fill_v, len);\n        rec_sv_memset((uint64_t)(uintptr_t)rec_dst, (uint64_t)(unsigned)fill_v, (uint64_t)len);\n"
                    .to_owned(),
            expect_memcpy: false,
            expect_memset: true,
        },
        SysvBlockCase {
            name: "sv_wcpy",
            machine_code: assemble_sysv_leaf(&[0x48, 0x89, 0xd1, 0xf3, 0x48, 0xa5]),
            ground_truth:
                "void sv_wcpy(long long *d, const long long *s, unsigned long nq){ for (unsigned long i = 0; i < nq; i++) d[i] = s[i]; }"
                    .to_owned(),
            prototype:
                "extern void sv_wcpy(long long *d, const long long *s, unsigned long nq);".to_owned(),
            driver_call:
                "        sv_wcpy((long long*)orig_dst, (const long long*)src_buf, len / 8);\n        rec_sv_wcpy((uint64_t)(uintptr_t)rec_dst, (uint64_t)(uintptr_t)src_buf, (uint64_t)(len / 8));\n"
                    .to_owned(),
            expect_memcpy: true,
            expect_memset: false,
        },
        SysvBlockCase {
            name: "sv_dfill",
            machine_code: assemble_sysv_leaf(&[0x48, 0x89, 0xd1, 0x89, 0xf0, 0xf3, 0xab]),
            ground_truth:
                "void sv_dfill(int *d, int v, unsigned long nd){ for (unsigned long i = 0; i < nd; i++) d[i] = v; }"
                    .to_owned(),
            prototype: "extern void sv_dfill(int *d, int v, unsigned long nd);".to_owned(),
            driver_call:
                "        sv_dfill((int*)orig_dst, fill_v, len / 4);\n        rec_sv_dfill((uint64_t)(uintptr_t)rec_dst, (uint64_t)(unsigned)fill_v, (uint64_t)(len / 4));\n"
                    .to_owned(),
            expect_memcpy: false,
            expect_memset: false,
        },
    ]
}

#[test]
fn sysv_block_move_fill_leaf_functions_recompile_to_behavioral_equivalence() {
    if !sysv_host_can_run() {
        return;
    }
    let Some(builder): Option<String> = cc() else {
        eprintln!("skipping sysv block-move: no C compiler on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let battery: Vec<SysvBlockCase> = sysv_block_battery();

    let mut ground_src: String = String::new();
    for case in &battery {
        ground_src.push_str(&case.ground_truth);
        ground_src.push('\n');
    }
    let ground_c: PathBuf = dir.join("sysv_block_ground.c");
    std::fs::write(&ground_c, ground_src.as_bytes()).expect("write sysv block ground");
    let ground_o: PathBuf = dir.join("sysv_block_ground.o");
    let compile: std::process::Output = Command::new(&builder)
        .args(["-O1", "-fno-stack-protector", "-c", "-o"])
        .arg(&ground_o)
        .arg(&ground_c)
        .output()
        .expect("invoke cc for sysv block ground truth");
    assert!(
        compile.status.success(),
        "sysv block ground-truth compile failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let mut recovered_decls: String = String::new();
    let mut extern_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    let mut memcpy_count: usize = 0;
    let mut memset_count: usize = 0;

    for case in &battery {
        let recovery: LeafRecovery =
            match recover_leaf_function_abi(&case.machine_code, 0x2000, PseudoAbi::SysV) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!(
                        "skip sysv {}: not in block-move leaf class ({e})",
                        case.name
                    );
                    continue;
                }
            };
        if case.expect_memcpy {
            assert!(
                recovery.source.contains("memcpy("),
                "sysv {} must recover a memcpy: {}",
                case.name,
                recovery.source
            );
            memcpy_count += 1;
        }
        if case.expect_memset {
            assert!(
                recovery.source.contains("memset("),
                "sysv {} must recover a memset: {}",
                case.name,
                recovery.source
            );
            memset_count += 1;
        }
        let recovered_name: String = format!("rec_{}", case.name);
        recovered_decls.push_str(&block_recovered_signature(&recovery, &recovered_name));
        recovered_decls.push('\n');
        extern_decls.push_str(&case.prototype);
        extern_decls.push('\n');
        driver_body.push_str(&case.driver_call);
        lifted_count += 1;
    }

    assert!(
        lifted_count == battery.len(),
        "SysV block-move lifter must reconstruct all {} hand-assembled leaves, only lifted {lifted_count}",
        battery.len()
    );
    assert!(
        memcpy_count >= 1 && memset_count >= 1,
        "SysV block-move must recover memcpy and memset forms ({memcpy_count} memcpy, {memset_count} memset)"
    );

    let driver: String = build_block_driver(&recovered_decls, &extern_decls, &driver_body);
    let driver_c: PathBuf = dir.join("sysv_block_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write sysv block driver");
    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "sysv_block_harness.exe"
    } else {
        "sysv_block_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&ground_o)
        .output()
        .expect("invoke cc to link sysv block harness");
    assert!(
        link.status.success(),
        "sysv block harness link failed: {}\n--- sysv_block_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );
    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run sysv block harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "SysV block-move behavioral differential FAILED ({lifted_count} cases): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "SysV block-move behavioral differential PASSED for {lifted_count} leaf functions ({memcpy_count} memcpy, {memset_count} memset, SysV ABI)"
    );
}

#[test]
fn block_move_lifter_rejects_backward_compare_and_unbounded_string_ops() {
    let std_movsb: [u8; 4] = [0xfd, 0xf3, 0xa4, 0xc3];
    assert!(
        recover_leaf_function_abi(&std_movsb, 0x3000, PseudoAbi::SysV).is_err(),
        "a std-prefixed backward rep movsb (DF=1) must be rejected, not mis-lifted as a forward memcpy"
    );

    let repe_cmpsb: [u8; 3] = [0xf3, 0xa6, 0xc3];
    assert!(
        recover_leaf_function_abi(&repe_cmpsb, 0x3000, PseudoAbi::SysV).is_err(),
        "a rep cmpsb (compare, not copy) must be rejected"
    );

    let repne_scasb: [u8; 3] = [0xf2, 0xae, 0xc3];
    assert!(
        recover_leaf_function_abi(&repne_scasb, 0x3000, PseudoAbi::SysV).is_err(),
        "a repne scasb (scan, not copy) must be rejected"
    );

    let bare_movsb: [u8; 2] = [0xa4, 0xc3];
    assert!(
        recover_leaf_function_abi(&bare_movsb, 0x3000, PseudoAbi::SysV).is_err(),
        "an unbounded single movsb with no rep count must be rejected"
    );

    let clean_movsb: [u8; 5] = [0x48, 0x89, 0xd1, 0xf3, 0xa4];
    let leaf: Vec<u8> = assemble_sysv_leaf(&clean_movsb);
    let recovered: LeafRecovery = recover_leaf_function_abi(&leaf, 0x3000, PseudoAbi::SysV)
        .expect("the clean forward rep movsb idiom must still lift");
    assert!(
        recovered.source.contains("memcpy("),
        "the clean forward idiom must recover as memcpy: {}",
        recovered.source
    );
    println!(
        "block-move rejection PASSED: backward/compare/scan/unbounded shapes rejected, clean forward idiom lifts"
    );
}

const SETCC_BATTERY: &[Case] = &[
    Case {
        name: "b_lt",
        arity: 2,
        c_source: "long long b_lt(long long a, long long b){ return a < b; }",
    },
    Case {
        name: "b_le",
        arity: 2,
        c_source: "long long b_le(long long a, long long b){ return a <= b; }",
    },
    Case {
        name: "b_gt",
        arity: 2,
        c_source: "long long b_gt(long long a, long long b){ return a > b; }",
    },
    Case {
        name: "b_eq",
        arity: 2,
        c_source: "long long b_eq(long long a, long long b){ return a == b; }",
    },
    Case {
        name: "b_ne",
        arity: 2,
        c_source: "long long b_ne(long long a, long long b){ return a != b; }",
    },
    Case {
        name: "b_ult",
        arity: 2,
        c_source: "long long b_ult(unsigned long long a, unsigned long long b){ return a < b; }",
    },
    Case {
        name: "b_uge",
        arity: 2,
        c_source: "long long b_uge(unsigned long long a, unsigned long long b){ return a >= b; }",
    },
    Case {
        name: "b_isz",
        arity: 1,
        c_source: "long long b_isz(long long a){ return a == 0; }",
    },
    Case {
        name: "b_nz",
        arity: 1,
        c_source: "long long b_nz(long long a){ return a != 0; }",
    },
    Case {
        name: "b_addpos",
        arity: 2,
        c_source: "long long b_addpos(long long a, long long b){ return (a + b) > 0; }",
    },
];

fn recovered_has_setcc(object_bytes: &[u8], name: &str, abi: PseudoAbi) -> bool {
    let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(object_bytes, name) else {
        return false;
    };
    let recovery: LeafRecovery = match recover_leaf_function_abi(&code, base, abi) {
        Ok(r) => r,
        Err(_) => return false,
    };
    recovery
        .source
        .contains("& 0xffffffffffffff00ULL | (uint64_t)((")
}

#[test]
fn setcc_boolean_leaf_functions_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!("skipping setcc oracle: gcc (needed for the branchless setcc idiom) not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let mut battery_src: String = String::new();
    for case in SETCC_BATTERY {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let battery_c: PathBuf = dir.join("setcc_battery.c");
    std::fs::write(&battery_c, battery_src.as_bytes()).expect("write setcc_battery.c");
    let battery_o: PathBuf = dir.join("setcc_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args([
            "-O1",
            "-fno-stack-protector",
            "-fno-if-conversion",
            "-fno-if-conversion2",
            "-fno-tree-loop-if-convert",
            "-c",
            "-o",
        ])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke gcc for setcc battery");
    assert!(
        compile_battery.status.success(),
        "setcc battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read setcc_battery.o");

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    let mut setcc_count: usize = 0;

    for case in SETCC_BATTERY {
        if recovered_has_setcc(&object_bytes, case.name, HOST_ABI) {
            setcc_count += 1;
        } else {
            eprintln!(
                "note {}: gcc did not emit a branchless setcc this build",
                case.name
            );
        }
        let Some(lifted): Option<Lifted> = process_case(case, &object_bytes, HOST_ABI) else {
            continue;
        };
        recovered_decls.push_str(&lifted.decls);
        driver_body.push_str(&lifted.driver_snippet);
        lifted_count += 1;
    }

    if lifted_count == 0 {
        eprintln!(
            "skipping setcc behavioral differential: this compiler build lowered none of the {} battery cases into the leaf class ({setcc_count} setcc)",
            SETCC_BATTERY.len()
        );
        return;
    }

    let driver: String = build_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("setcc_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write setcc_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "setcc_harness.exe"
    } else {
        "setcc_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke gcc to link setcc harness");
    assert!(
        link.status.success(),
        "setcc harness link failed: {}\n--- setcc_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run setcc harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "setcc behavioral differential FAILED ({lifted_count} cases, {setcc_count} setcc): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "setcc behavioral differential PASSED for {lifted_count} leaf functions ({setcc_count} branchless conditional-set, MS x64 ABI)"
    );
}

#[test]
fn setcc_oracle_has_teeth_negating_the_predicate_diverges() {
    if !cfg!(windows) {
        eprintln!("skipping setcc teeth on non-windows host");
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!("skipping setcc teeth check: gcc not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let probe: Case = Case {
        name: "b_lt",
        arity: 2,
        c_source: SETCC_BATTERY[0].c_source,
    };
    let battery_c: PathBuf = dir.join("setcc_teeth_battery.c");
    std::fs::write(&battery_c, probe.c_source.as_bytes()).expect("write setcc_teeth_battery.c");
    let battery_o: PathBuf = dir.join("setcc_teeth_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args([
            "-O1",
            "-fno-stack-protector",
            "-fno-if-conversion",
            "-fno-if-conversion2",
            "-fno-tree-loop-if-convert",
            "-c",
            "-o",
        ])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke gcc for setcc teeth battery");
    assert!(
        compile_battery.status.success(),
        "setcc teeth battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read setcc_teeth_battery.o");

    let Some(lifted): Option<Lifted> = process_case(&probe, &object_bytes, HOST_ABI) else {
        eprintln!(
            "skipping setcc teeth check: this compiler build did not lower the probe into the leaf class"
        );
        return;
    };
    if !lifted.decls.contains(") < (") {
        eprintln!(
            "skipping setcc teeth check: this compiler build did not reconstruct the `<` predicate to negate"
        );
        return;
    }

    let corrupted: String = lifted.decls.replacen(") < (", ") >= (", 1);
    assert_ne!(
        corrupted, lifted.decls,
        "teeth corruption must negate the recovered predicate: {}",
        lifted.decls
    );

    let driver: String = build_driver(&corrupted, &lifted.driver_snippet);
    let driver_c: PathBuf = dir.join("setcc_teeth_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write setcc_teeth_driver.c");

    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "setcc_teeth_harness.exe"
    } else {
        "setcc_teeth_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke gcc to link setcc teeth harness");
    assert!(
        link.status.success(),
        "setcc teeth harness link failed: {}\n--- setcc_teeth_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run setcc teeth harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        !stdout.contains("OK") && stdout.contains("MISMATCH"),
        "teeth check FAILED: negating the recovered predicate must diverge, got: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "setcc oracle teeth confirmed: negating the recovered conditional-set predicate diverges (MISMATCH observed)"
    );
}

struct SysvSetccCase {
    name: &'static str,
    machine_code: Vec<u8>,
    ground_truth: String,
    prototype: String,
    driver_call: String,
}

fn sysv_setcc_battery() -> Vec<SysvSetccCase> {
    vec![
        SysvSetccCase {
            name: "sc_lt",
            machine_code: assemble_sysv_leaf(&[
                0x48, 0x39, 0xf7, 0x0f, 0x9c, 0xc0, 0x0f, 0xb6, 0xc0,
            ]),
            ground_truth: "long long sc_lt(long long a, long long b){ return a < b; }".to_owned(),
            prototype: "extern long long sc_lt(long long, long long);".to_owned(),
            driver_call: "sc_lt".to_owned(),
        },
        SysvSetccCase {
            name: "sc_ge",
            machine_code: assemble_sysv_leaf(&[
                0x48, 0x39, 0xf7, 0x0f, 0x9d, 0xc0, 0x0f, 0xb6, 0xc0,
            ]),
            ground_truth: "long long sc_ge(long long a, long long b){ return a >= b; }".to_owned(),
            prototype: "extern long long sc_ge(long long, long long);".to_owned(),
            driver_call: "sc_ge".to_owned(),
        },
        SysvSetccCase {
            name: "sc_eq",
            machine_code: assemble_sysv_leaf(&[
                0x48, 0x39, 0xf7, 0x0f, 0x94, 0xc0, 0x0f, 0xb6, 0xc0,
            ]),
            ground_truth: "long long sc_eq(long long a, long long b){ return a == b; }".to_owned(),
            prototype: "extern long long sc_eq(long long, long long);".to_owned(),
            driver_call: "sc_eq".to_owned(),
        },
        SysvSetccCase {
            name: "sc_ult",
            machine_code: assemble_sysv_leaf(&[
                0x48, 0x39, 0xf7, 0x0f, 0x92, 0xc0, 0x0f, 0xb6, 0xc0,
            ]),
            ground_truth:
                "long long sc_ult(unsigned long long a, unsigned long long b){ return a < b; }"
                    .to_owned(),
            prototype: "extern long long sc_ult(unsigned long long, unsigned long long);"
                .to_owned(),
            driver_call: "sc_ult".to_owned(),
        },
    ]
}

#[test]
fn sysv_setcc_boolean_leaf_functions_recompile_to_behavioral_equivalence() {
    if !sysv_host_can_run() {
        return;
    }
    let Some(builder): Option<String> = cc() else {
        eprintln!("skipping sysv setcc: no C compiler on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let battery: Vec<SysvSetccCase> = sysv_setcc_battery();

    let mut ground_src: String = String::new();
    for case in &battery {
        ground_src.push_str(&case.ground_truth);
        ground_src.push('\n');
    }
    let ground_c: PathBuf = dir.join("sysv_setcc_ground.c");
    std::fs::write(&ground_c, ground_src.as_bytes()).expect("write sysv setcc ground");
    let ground_o: PathBuf = dir.join("sysv_setcc_ground.o");
    let compile: std::process::Output = Command::new(&builder)
        .args(["-O1", "-fno-stack-protector", "-c", "-o"])
        .arg(&ground_o)
        .arg(&ground_c)
        .output()
        .expect("invoke cc for sysv setcc ground truth");
    assert!(
        compile.status.success(),
        "sysv setcc ground-truth compile failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let mut recovered_decls: String = String::new();
    let mut extern_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;

    for case in &battery {
        let recovery: LeafRecovery =
            match recover_leaf_function_abi(&case.machine_code, 0x2000, PseudoAbi::SysV) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("skip sysv {}: not in setcc leaf class ({e})", case.name);
                    continue;
                }
            };
        assert!(
            recovery
                .source
                .contains("& 0xffffffffffffff00ULL | (uint64_t)(("),
            "sysv {} must recover a conditional-set byte write: {}",
            case.name,
            recovery.source
        );
        let recovered_name: String = format!("rec_{}", case.name);
        recovered_decls.push_str(&rename_recovered(&recovery.source, &recovered_name));
        recovered_decls.push('\n');
        extern_decls.push_str(&case.prototype);
        extern_decls.push('\n');
        let return_mask: String = if recovery.return_width_bits == 64 {
            "0xFFFFFFFFFFFFFFFFULL".to_owned()
        } else {
            format!("0x{:x}ULL", (1u128 << recovery.return_width_bits) - 1)
        };
        let _ = write!(
            driver_body,
            "    for (size_t k = 0; k < n_inputs; k++) {{\n\
             \x20       long long a = inputs[k][0], b = inputs[k][1];\n\
             \x20       unsigned long long want = (unsigned long long){}(a, b) & {return_mask};\n\
             \x20       unsigned long long got = {recovered_name}((uint64_t)a, (uint64_t)b) & {return_mask};\n\
             \x20       if (want != got) {{ printf(\"MISMATCH {} a=%lld b=%lld want=%llu got=%llu\\n\", a, b, want, got); return 1; }}\n\
             \x20   }}\n",
            case.name, case.name,
        );
        let _ = &case.driver_call;
        lifted_count += 1;
    }

    assert!(
        lifted_count == battery.len(),
        "SysV setcc lifter must reconstruct all {} hand-assembled leaves, only lifted {lifted_count}",
        battery.len()
    );

    let driver: String = format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n{extern_decls}\n{recovered_decls}\n\
         int main(void) {{\n\
         \x20   long long inputs[][2] = {{\n\
         \x20       {{0,0}},{{1,1}},{{-1,-1}},{{7,3}},{{-7,3}},{{3,7}},{{-3,-7}},\n\
         \x20       {{123456,-654321}},{{2147483647,1}},{{-2147483648,-1}},\n\
         \x20       {{0x7fffffffffffffffLL,2}},{{100,200}},{{-100,50}},{{42,42}}\n\
         \x20   }};\n\
         \x20   size_t n_inputs = sizeof(inputs)/sizeof(inputs[0]);\n\
         {driver_body}\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n"
    );
    let driver_c: PathBuf = dir.join("sysv_setcc_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write sysv setcc driver");
    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "sysv_setcc_harness.exe"
    } else {
        "sysv_setcc_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&ground_o)
        .output()
        .expect("invoke cc to link sysv setcc harness");
    assert!(
        link.status.success(),
        "sysv setcc harness link failed: {}\n--- sysv_setcc_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );
    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run sysv setcc harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "SysV setcc behavioral differential FAILED ({lifted_count} cases): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "SysV setcc behavioral differential PASSED for {lifted_count} hand-assembled conditional-set leaves (SysV ABI)"
    );
}

#[test]
fn setcc_lifter_rejects_a_conditional_set_without_a_preceding_compare() {
    let orphan_setl: [u8; 4] = [0x0f, 0x9c, 0xc0, 0xc3];
    assert!(
        recover_leaf_function_abi(&orphan_setl, 0x3000, PseudoAbi::SysV).is_err(),
        "a setcc with no tracked comparison flags must be rejected, not lifted against stale flags"
    );

    let clean: [u8; 9] = [0x48, 0x39, 0xf7, 0x0f, 0x9c, 0xc0, 0x0f, 0xb6, 0xc0];
    let leaf: Vec<u8> = assemble_sysv_leaf(&clean);
    let recovered: LeafRecovery = recover_leaf_function_abi(&leaf, 0x3000, PseudoAbi::SysV)
        .expect("the clean cmp+setl+movzx idiom must still lift");
    assert!(
        recovered
            .source
            .contains("& 0xffffffffffffff00ULL | (uint64_t)(("),
        "the clean setcc idiom must recover as a byte-preserving conditional set: {}",
        recovered.source
    );
    println!(
        "setcc rejection PASSED: an orphan conditional-set with no live compare is rejected, the clean idiom lifts"
    );
}

const STACK_BATTERY: &[Case] = &[
    Case {
        name: "s_add",
        arity: 2,
        c_source: "long long s_add(long long a, long long b){ return a + b; }",
    },
    Case {
        name: "s_locals",
        arity: 3,
        c_source: "long long s_locals(long long a, long long b, long long c){ long long x = a + b; long long y = x * c; long long z = y - a; return z + x; }",
    },
    Case {
        name: "s_mix32",
        arity: 2,
        c_source: "int s_mix32(int a, int b){ int x = a + b; int y = a ^ b; return x * 3 - y; }",
    },
    Case {
        name: "s_branch",
        arity: 2,
        c_source: "long long s_branch(long long a, long long b){ long long r; if (a > b) r = a - b; else r = b - a; return r; }",
    },
    Case {
        name: "s_chain",
        arity: 3,
        c_source: "long long s_chain(long long a, long long b, long long c){ long long t = a; t = t + b; t = t * c; t = t - a; return t; }",
    },
];

#[test]
fn stack_spill_leaf_functions_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guard"
        );
        return;
    }
    let Some(compiler): Option<String> = cc() else {
        eprintln!("skipping: no C compiler (gcc/clang/cc) on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let battery_c: PathBuf = dir.join("stack_battery.c");
    std::fs::write(&battery_c, battery_source(STACK_BATTERY).as_bytes())
        .expect("write stack_battery.c");
    let battery_o: PathBuf = dir.join("stack_battery.o");
    let compile_battery: std::process::Output = Command::new(&compiler)
        .args(["-O0", "-fno-stack-protector", "-c", "-o"])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke cc for stack battery");
    assert!(
        compile_battery.status.success(),
        "stack battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read stack_battery.o");

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    for case in STACK_BATTERY {
        if let Some(lifted) = process_case(case, &object_bytes, HOST_ABI) {
            recovered_decls.push_str(&lifted.decls);
            driver_body.push_str(&lifted.driver_snippet);
            lifted_count += 1;
        }
    }

    if lifted_count == 0 {
        eprintln!(
            "skipping stack-spill behavioral differential: this compiler build lowered none of the {} -O0 frame cases into the leaf class",
            STACK_BATTERY.len()
        );
        return;
    }

    let driver: String = build_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("stack_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write stack_driver.c");
    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "stack_harness.exe"
    } else {
        "stack_harness"
    });
    let link: std::process::Output = Command::new(&compiler)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke cc to link stack harness");
    assert!(
        link.status.success(),
        "stack harness link failed: {}\n--- stack_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run stack harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "stack-spill behavioral differential FAILED ({lifted_count} cases): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "stack-spill behavioral differential PASSED for {lifted_count} -O0 frame leaf functions (host ABI)"
    );
}

#[test]
fn sysv_stack_spill_leaf_functions_recompile_to_behavioral_equivalence() {
    if !sysv_host_can_run() {
        return;
    }
    let Some(objs): Option<SysvCrossObjects> =
        compile_sysv_cross_extra("stk", &battery_source(STACK_BATTERY), &["-O0"])
    else {
        return;
    };

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    for case in STACK_BATTERY {
        if let Some(lifted) = process_case(case, &objs.sysv_object, PseudoAbi::SysV) {
            recovered_decls.push_str(&lifted.decls);
            driver_body.push_str(&lifted.driver_snippet);
            lifted_count += 1;
        }
    }

    assert!(
        lifted_count >= 4,
        "SysV -O0 stack-spill lifter must handle at least 4 of the {} cases, only lifted {lifted_count}",
        STACK_BATTERY.len()
    );

    let driver: String = build_driver(&recovered_decls, &driver_body);
    let stdout: String = link_and_run_sysv("stk", &driver, &objs.host_object, 30);
    assert!(
        stdout.contains("OK"),
        "SysV stack-spill behavioral differential FAILED ({lifted_count} cases): {stdout}"
    );
    println!(
        "SysV stack-spill behavioral differential PASSED for {lifted_count} -O0 frame leaf functions (SysV ABI)"
    );
}

#[test]
fn stack_spill_oracle_has_teeth_corrupting_a_slot_offset_diverges() {
    let Some(compiler): Option<String> = cc() else {
        eprintln!("skipping stack-spill teeth check: no C compiler on PATH");
        return;
    };
    let probe: [u8; 22] = [
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x7d, 0xf8, 0x48, 0x89, 0x75, 0xf0, 0x48, 0x8b, 0x45,
        0xf8, 0x48, 0x2b, 0x45, 0xf0, 0x5d, 0xc3,
    ];
    let recovery: LeafRecovery = recover_leaf_function_abi(&probe, 0x1000, PseudoAbi::SysV)
        .expect("the rbp-frame spill/reload subtract probe must lift");
    assert_eq!(
        recovery.params.len(),
        2,
        "the two spilled arguments must be recovered as parameters"
    );
    let renamed: String = recovery
        .source
        .replacen("uint64_t recovered(", "uint64_t rec_probe(", 1)
        .lines()
        .filter(|l: &&str| !l.starts_with("#include"))
        .collect::<Vec<&str>>()
        .join("\n");

    let reload: &str = "(uint64_t)(*(uint64_t*)(uintptr_t)(r_rbp + (uint64_t)(int64_t)-8LL))";
    let poison: &str = "(uint64_t)(*(uint64_t*)(uintptr_t)(r_rbp + (uint64_t)(int64_t)-16LL))";
    let sabotaged: String = renamed.replacen(reload, poison, 1);
    assert_ne!(
        sabotaged, renamed,
        "the reload of the minuend slot must be present to be corrupted"
    );

    let run_variant = |tag: &str, body: &str| -> String {
        let scratch: ScratchDir = scratch_dir();
        let dir: PathBuf = scratch.path().to_path_buf();
        let driver: String = format!(
            "#include <stdint.h>\n#include <stdio.h>\n{body}\n\
             int main(void) {{\n\
             \x20   long long in[][2] = {{ {{7,3}},{{1,1}},{{-5,9}},{{100,-25}},{{0,0}},{{2147483647,-1}},{{-9,-4}} }};\n\
             \x20   for (size_t k = 0; k < sizeof(in)/sizeof(in[0]); k++) {{\n\
             \x20       unsigned long long want = (unsigned long long)(in[k][0] - in[k][1]);\n\
             \x20       unsigned long long got = rec_probe((uint64_t)in[k][0], (uint64_t)in[k][1]);\n\
             \x20       if (want != got) {{ printf(\"MISMATCH in=%lld,%lld want=%llu got=%llu\\n\", in[k][0], in[k][1], want, got); return 1; }}\n\
             \x20   }}\n\
             \x20   printf(\"OK\\n\");\n\
             \x20   return 0;\n\
             }}\n"
        );
        let driver_c: PathBuf = dir.join(format!("stack_teeth_{tag}.c"));
        std::fs::write(&driver_c, driver.as_bytes()).expect("write teeth driver");
        let exe: PathBuf = dir.join(if cfg!(windows) {
            format!("stack_teeth_{tag}.exe")
        } else {
            format!("stack_teeth_{tag}")
        });
        let link: std::process::Output = Command::new(&compiler)
            .args(["-O1", "-o"])
            .arg(&exe)
            .arg(&driver_c)
            .output()
            .expect("invoke cc to link teeth harness");
        assert!(
            link.status.success(),
            "teeth harness link failed: {}\n--- driver ---\n{driver}",
            String::from_utf8_lossy(&link.stderr)
        );
        let out: std::process::Output = Command::new(&exe).output().expect("run teeth harness");
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            if out.status.success() {
                ""
            } else {
                "\nNONZERO"
            }
        )
    };

    let pristine: String = run_variant("clean", &renamed);
    assert!(
        pristine.contains("OK"),
        "the faithful spill/reload lift must round-trip a - b: {pristine}"
    );
    let broken: String = run_variant("broken", &sabotaged);
    assert!(
        broken.contains("MISMATCH") || broken.contains("NONZERO"),
        "reloading the wrong stack slot must diverge from a - b; instead: {broken}"
    );
    println!(
        "stack-spill oracle teeth confirmed: the faithful frame lift matches, corrupting a reload slot offset diverges"
    );
}

const FP_STACK_BATTERY: &[FpCase] = &[
    FpCase {
        name: "sf_dadd",
        args: &[FpArg::Double, FpArg::Double],
        ret: FpRet::Double,
        c_source: "double sf_dadd(double a, double b){ double x = a * b; double y = x + a; return y - b; }",
    },
    FpCase {
        name: "sf_dchain",
        args: &[FpArg::Double, FpArg::Double, FpArg::Double],
        ret: FpRet::Double,
        c_source: "double sf_dchain(double a, double b, double c){ double r = a + b; r = r * c; r = r - a; return r; }",
    },
    FpCase {
        name: "sf_fmul",
        args: &[FpArg::Float, FpArg::Float],
        ret: FpRet::Float,
        c_source: "float sf_fmul(float a, float b){ float x = a * b; return x + b; }",
    },
    FpCase {
        name: "sf_fchain",
        args: &[FpArg::Float, FpArg::Float],
        ret: FpRet::Float,
        c_source: "float sf_fchain(float a, float b){ float r = a - b; r = r * a; return r + b; }",
    },
    FpCase {
        name: "sf_dlt",
        args: &[FpArg::Double, FpArg::Double],
        ret: FpRet::LongLong,
        c_source: "long long sf_dlt(double a, double b){ return a < b; }",
    },
];

#[test]
fn scalar_float_stack_spill_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guard"
        );
        return;
    }
    let Some(builder): Option<String> = clang() else {
        eprintln!("skipping scalar float stack-spill oracle: clang not on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let battery_c: PathBuf = dir.join("fp_stack_battery.c");
    std::fs::write(&battery_c, fp_battery_source(FP_STACK_BATTERY).as_bytes())
        .expect("write fp_stack_battery.c");
    let battery_o: PathBuf = dir.join("fp_stack_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args(["-O0", "-fno-stack-protector", "-c", "-o"])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke clang for fp stack battery");
    assert!(
        compile_battery.status.success(),
        "fp stack battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read fp_stack_battery.o");

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    for case in FP_STACK_BATTERY {
        let Some((_, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
            fp_lift(case, &object_bytes, HOST_ABI)
        else {
            continue;
        };
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        recovered_decls.push_str(&fp_extern_decl(case));
        recovered_decls.push('\n');
        driver_body.push_str(&fp_driver_snippet(case, &recovered_name));
        lifted_count += 1;
    }

    if lifted_count == 0 {
        eprintln!(
            "skipping scalar float stack-spill differential: this compiler build lowered none of the {} -O0 fp frame cases into the scalar float leaf class",
            FP_STACK_BATTERY.len()
        );
        return;
    }

    let driver: String = build_fp_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("fp_stack_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write fp_stack_driver.c");
    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "fp_stack_harness.exe"
    } else {
        "fp_stack_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke clang to link fp stack harness");
    assert!(
        link.status.success(),
        "fp stack harness link failed: {}\n--- fp_stack_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run fp stack harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "scalar float stack-spill differential FAILED ({lifted_count} cases): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "scalar float stack-spill differential PASSED for {lifted_count} -O0 fp frame leaf functions (host ABI)"
    );
}

#[test]
fn sysv_scalar_float_stack_spill_recompile_to_behavioral_equivalence() {
    if !sysv_host_can_run() {
        return;
    }
    let Some(objs): Option<SysvCrossObjects> =
        compile_sysv_cross_extra("sf", &fp_battery_source(FP_STACK_BATTERY), &["-O0"])
    else {
        return;
    };

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    for case in FP_STACK_BATTERY {
        let Some((_, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
            fp_lift(case, &objs.sysv_object, PseudoAbi::SysV)
        else {
            continue;
        };
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        recovered_decls.push_str(&fp_extern_decl(case));
        recovered_decls.push('\n');
        driver_body.push_str(&fp_driver_snippet(case, &recovered_name));
        lifted_count += 1;
    }

    assert!(
        lifted_count >= 3,
        "SysV -O0 scalar float stack-spill lifter must handle at least 3 of the {} cases, only lifted {lifted_count}",
        FP_STACK_BATTERY.len()
    );

    let driver: String = build_fp_driver(&recovered_decls, &driver_body);
    let stdout: String = link_and_run_sysv("sf", &driver, &objs.host_object, 30);
    assert!(
        stdout.contains("OK"),
        "SysV scalar float stack-spill differential FAILED ({lifted_count} cases): {stdout}"
    );
    println!(
        "SysV scalar float stack-spill differential PASSED for {lifted_count} -O0 fp frame leaf functions (SysV ABI)"
    );
}

const RED_ZONE_BATTERY: &[Case] = &[
    Case {
        name: "rz_slot",
        arity: 2,
        c_source: "long long rz_slot(long long a, long long b){ volatile long long v = a + b; return v * 3; }",
    },
    Case {
        name: "rz_pair",
        arity: 2,
        c_source: "long long rz_pair(long long a, long long b){ volatile long long x = a; volatile long long y = b; return x * y + x - y; }",
    },
    Case {
        name: "rz_triple",
        arity: 3,
        c_source: "long long rz_triple(long long a, long long b, long long c){ volatile long long p = a; volatile long long q = b; volatile long long r = c; return p + q * 3 + r * 5; }",
    },
    Case {
        name: "rz_reuse",
        arity: 2,
        c_source: "long long rz_reuse(long long a, long long b){ volatile long long t = a; t = t + b; t = t * 3; return t - a; }",
    },
    Case {
        name: "rz_dword",
        arity: 2,
        c_source: "long long rz_dword(long long a, long long b){ volatile int v = (int)(a - b); return (long long)v * 3; }",
    },
    Case {
        name: "rz_word",
        arity: 2,
        c_source: "long long rz_word(long long a, long long b){ volatile short v = (short)(a ^ b); return (long long)v + 1; }",
    },
    Case {
        name: "rz_byte",
        arity: 2,
        c_source: "long long rz_byte(long long a, long long b){ volatile unsigned char c = (unsigned char)(a | b); return (long long)c * 7; }",
    },
    Case {
        name: "rz_widths",
        arity: 2,
        c_source: "long long rz_widths(long long a, long long b){ volatile unsigned char c = (unsigned char)a; volatile short s = (short)b; volatile int i = (int)(a + b); volatile long long q = a * b; return (long long)c + (long long)s * 3 + (long long)i * 5 + q * 7; }",
    },
    Case {
        name: "rz_branch",
        arity: 2,
        c_source: "long long rz_branch(long long a, long long b){ volatile long long v; if (a > b) v = a - b; else v = b - a; return v * 2; }",
    },
    Case {
        name: "rz_absx",
        arity: 2,
        c_source: "long long rz_absx(long long a, long long b){ volatile long long v = a; if (v < 0) v = -v; return v + b; }",
    },
    Case {
        name: "rz_shift",
        arity: 2,
        c_source: "long long rz_shift(long long a, long long b){ volatile unsigned long long v = ((unsigned long long)a >> 3) | ((unsigned long long)b << 5); return (long long)v; }",
    },
    Case {
        name: "rz_negnot",
        arity: 2,
        c_source: "long long rz_negnot(long long a, long long b){ volatile long long v = -(a + b); return ~v; }",
    },
    Case {
        name: "rz_quad",
        arity: 2,
        c_source: "long long rz_quad(long long a, long long b){ volatile long long w = a; volatile long long x = b; volatile long long y = a ^ b; volatile long long z = a - b; return w + x * 3 + y * 5 + z * 7; }",
    },
    Case {
        name: "rz_wide16",
        arity: 2,
        c_source: "long long rz_wide16(long long a, long long b){ volatile long long v0 = a + 1, v1 = a + 2, v2 = a + 3, v3 = a + 4; volatile long long v4 = b + 1, v5 = b + 2, v6 = b + 3, v7 = b + 4; volatile long long v8 = a ^ 1, v9 = a ^ 2, v10 = a ^ 3, v11 = a ^ 4; volatile long long v12 = b ^ 1, v13 = b ^ 2, v14 = b ^ 3, v15 = b ^ 4; return v0 + v1 * 3 + v2 * 5 + v3 * 7 + v4 * 9 + v5 * 11 + v6 * 13 + v7 * 15 + v8 * 17 + v9 * 19 + v10 * 21 + v11 * 23 + v12 * 25 + v13 * 27 + v14 * 29 + v15 * 31; }",
    },
];

struct RedZoneShape {
    slots: Vec<i64>,
    adjusts_stack: bool,
}

fn rsp_negative_displacements(operands: &str) -> Vec<i64> {
    let mut out: Vec<i64> = Vec::new();
    let mut rest: &str = operands;
    while let Some(at) = rest.find("[rsp-") {
        let tail: &str = rest.get(at + 5..).unwrap_or_default();
        let end: usize = tail.find(']').unwrap_or(tail.len());
        let token: &str = tail.get(..end).unwrap_or_default();
        let (digits, radix): (&str, u32) = token
            .strip_suffix('h')
            .map_or((token, 10), |hex: &str| (hex, 16));
        if let Ok(value) = i64::from_str_radix(digits, radix) {
            out.push(-value);
        }
        rest = tail.get(end..).unwrap_or_default();
    }
    out
}

fn red_zone_shape(insns: &[DisasmInsn]) -> RedZoneShape {
    let mut slots: Vec<i64> = Vec::new();
    let mut adjusts_stack: bool = false;
    for insn in insns {
        if matches!(
            insn.mnemonic.as_str(),
            "push" | "pop" | "leave" | "enter" | "call"
        ) || insn
            .operands
            .split_once(',')
            .is_some_and(|(lhs, _): (&str, &str)| lhs.trim() == "rsp")
        {
            adjusts_stack = true;
        }
        slots.extend(rsp_negative_displacements(&insn.operands));
    }
    slots.sort_unstable();
    slots.dedup();
    RedZoneShape {
        slots,
        adjusts_stack,
    }
}

fn assert_red_zone_encoding(object_bytes: &[u8], name: &str) -> Vec<i64> {
    let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(object_bytes, name) else {
        panic!("red-zone row {name}: symbol not located");
    };
    let insns: Vec<DisasmInsn> =
        disassemble(Arch::X86_64, base, &code).expect("disassemble red-zone row");
    let shape: RedZoneShape = red_zone_shape(&insns);
    assert!(
        !shape.adjusts_stack,
        "red-zone row {name} must not adjust the stack pointer, so its below-rsp slots really are the red zone: {insns:?}"
    );
    assert!(
        !shape.slots.is_empty(),
        "red-zone row {name} must store below the unadjusted stack pointer: {insns:?}"
    );
    shape.slots
}

fn build_red_zone_driver(recovered_decls: &str, driver_body: &str) -> String {
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n{recovered_decls}\n\
         int main(void) {{\n\
         \x20   long long inputs[][3] = {{\n\
         \x20       {{0,0,0}},{{-1,-1,-1}},{{1,-1,0}},{{-1,0,1}},\n\
         \x20       {{0x0123456789abcdefLL,0x1032547698badcfeLL,0x7f7e7d7c7b7a7978LL}},\n\
         \x20       {{(long long)0xfedcba9876543210ULL,(long long)0x89abcdef01234567ULL,0x3141592653589793LL}},\n\
         \x20       {{1,2,3}},{{3,1,2}},{{2,3,1}},{{3,2,1}},\n\
         \x20       {{0x7fffffffffffffffLL,(long long)0x8000000000000000ULL,-1}},\n\
         \x20       {{(long long)0x8000000000000000ULL,0x7fffffffffffffffLL,1}},\n\
         \x20       {{0x7fffffffLL,-2147483648LL,0x80000000LL}},\n\
         \x20       {{0xffLL,0xff00LL,0xffff0000LL}},{{0x100LL,0x10000LL,0x1000000LL}},\n\
         \x20       {{0x80LL,0x8000LL,(long long)0x80000000LL}},\n\
         \x20       {{(long long)0xffffffffffffff80ULL,(long long)0xffffffffffff8000ULL,-128LL}},\n\
         \x20       {{0x5555555555555555LL,(long long)0xaaaaaaaaaaaaaaaaULL,0x3333333333333333LL}},\n\
         \x20       {{-2,-3,-5}},{{123456789LL,-987654321LL,55555LL}}\n\
         \x20   }};\n\
         \x20   size_t n_inputs = sizeof(inputs)/sizeof(inputs[0]);\n\
         {driver_body}\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n"
    )
}

#[test]
fn sysv_red_zone_leaf_functions_recompile_to_behavioral_equivalence() {
    if !sysv_host_can_run() {
        return;
    }
    let Some(objs): Option<SysvCrossObjects> =
        compile_sysv_cross("rz", &battery_source(RED_ZONE_BATTERY))
    else {
        return;
    };

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut deepest: i64 = 0;
    for case in RED_ZONE_BATTERY {
        let slots: Vec<i64> = assert_red_zone_encoding(&objs.sysv_object, case.name);
        deepest = deepest.min(slots.first().copied().unwrap_or(0));
        println!("red-zone row {} uses rsp slots {slots:?}", case.name);
        let Some((code, base)): Option<(Vec<u8>, u64)> =
            function_code(&objs.sysv_object, case.name)
        else {
            panic!("red-zone row {}: symbol not located", case.name);
        };
        let recovery: LeafRecovery = recover_leaf_function_abi(&code, base, PseudoAbi::SysV)
            .unwrap_or_else(|e: disrobe_pass_native::Error| {
                panic!("red-zone row {} must recover, got: {e}", case.name)
            });
        assert!(
            recovery
                .source
                .contains("r_rsp = (uint64_t)(uintptr_t)(stack_frame +"),
            "red-zone row {} must model its below-rsp slots as a local frame:\n{}",
            case.name,
            recovery.source
        );
        let Some(lifted): Option<Lifted> = process_case(case, &objs.sysv_object, PseudoAbi::SysV)
        else {
            panic!(
                "red-zone row {} must lift into the graded driver",
                case.name
            );
        };
        recovered_decls.push_str(&lifted.decls);
        driver_body.push_str(&lifted.driver_snippet);
    }
    assert!(
        deepest <= -64,
        "the red-zone battery must reach deep into the 128-byte zone, deepest slot observed was {deepest}"
    );

    let driver: String = build_red_zone_driver(&recovered_decls, &driver_body);
    let stdout: String = link_and_run_sysv("rz", &driver, &objs.host_object, 30);
    assert!(
        stdout.contains("OK"),
        "SysV red-zone behavioral differential FAILED ({} cases): {stdout}",
        RED_ZONE_BATTERY.len()
    );
    println!(
        "SysV red-zone behavioral differential PASSED for {} leaf functions with no stack adjustment, deepest slot {deepest} (SysV ABI)",
        RED_ZONE_BATTERY.len()
    );
}

const INDEXED_FRAME_BATTERY: &[Case] = &[
    Case {
        name: "sw_arr_add",
        arity: 3,
        c_source: "long long sw_arr_add(long long i, long long a, long long b){ long long v[4]; v[0]=a; v[1]=b; v[2]=a+b; v[3]=(a+b)+0x5a5a5a5a5a5a5a5aLL; return v[i & 3]; }",
    },
    Case {
        name: "sw_arr_sub",
        arity: 3,
        c_source: "long long sw_arr_sub(long long i, long long a, long long b){ long long v[4]; v[0]=a; v[1]=b; v[2]=a-b; v[3]=(a-b)-0x5a5a5a5a5a5a5a5aLL; return v[i & 3]; }",
    },
    Case {
        name: "sw_arr_mul",
        arity: 3,
        c_source: "long long sw_arr_mul(long long i, long long a, long long b){ long long v[4]; v[0]=a; v[1]=b; v[2]=a*b; v[3]=(a*b)*0x5a5a5a5a5a5a5a5aLL; return v[i & 3]; }",
    },
    Case {
        name: "sw_arr_and",
        arity: 3,
        c_source: "long long sw_arr_and(long long i, long long a, long long b){ long long v[4]; v[0]=a; v[1]=b; v[2]=a&b; v[3]=(a&b)&0x5a5a5a5a5a5a5a5aLL; return v[i & 3]; }",
    },
    Case {
        name: "sw_arr_or",
        arity: 3,
        c_source: "long long sw_arr_or(long long i, long long a, long long b){ long long v[4]; v[0]=a; v[1]=b; v[2]=a|b; v[3]=(a|b)|0x5a5a5a5a5a5a5a5aLL; return v[i & 3]; }",
    },
    Case {
        name: "sw_arr_xor",
        arity: 3,
        c_source: "long long sw_arr_xor(long long i, long long a, long long b){ long long v[4]; v[0]=a; v[1]=b; v[2]=a^b; v[3]=(a^b)^0x5a5a5a5a5a5a5a5aLL; return v[i & 3]; }",
    },
    Case {
        name: "sw_arr_store",
        arity: 3,
        c_source: "long long sw_arr_store(long long i, long long a, long long b){ long long v[4]; v[0]=a; v[1]=b; v[2]=a^b; v[3]=a+b; v[i & 3] = a*b+1; return v[0]+v[1]*3+v[2]*5+v[3]*7; }",
    },
    Case {
        name: "sw_arr_u32",
        arity: 3,
        c_source: "long long sw_arr_u32(long long i, long long a, long long b){ unsigned int v[4]; v[0]=(unsigned)a; v[1]=(unsigned)b; v[2]=(unsigned)(a+b); v[3]=(unsigned)(a^b); return (long long)v[i & 3]; }",
    },
    Case {
        name: "sw_arr_mask1",
        arity: 3,
        c_source: "long long sw_arr_mask1(long long i, long long a, long long b){ long long v[3]; v[0]=a; v[1]=b; v[2]=a+b; return v[i & 1] + v[2]; }",
    },
];

struct IndexedFrameShape {
    index: String,
    scale: u8,
    disp: i64,
    elements: i64,
}

fn quad_name(dword: &str) -> Option<String> {
    match dword {
        "eax" => Some("rax".to_owned()),
        "ebx" => Some("rbx".to_owned()),
        "ecx" => Some("rcx".to_owned()),
        "edx" => Some("rdx".to_owned()),
        "esi" => Some("rsi".to_owned()),
        "edi" => Some("rdi".to_owned()),
        "ebp" => Some("rbp".to_owned()),
        other => other
            .strip_suffix('d')
            .filter(|stem: &&str| stem.starts_with('r'))
            .map(str::to_owned),
    }
}

fn parse_masm_i64(token: &str) -> Option<i64> {
    let (negative, body): (bool, &str) = token.strip_prefix('-').map_or_else(
        || (false, token.strip_prefix('+').unwrap_or(token)),
        |rest: &str| (true, rest),
    );
    let (digits, radix): (&str, u32) = body
        .strip_suffix('h')
        .map_or((body, 10), |hex: &str| (hex, 16));
    let value: i64 = i64::from_str_radix(digits, radix).ok()?;
    Some(if negative { -value } else { value })
}

fn indexed_rsp_accesses(operands: &str) -> Vec<(String, u8, i64)> {
    let mut out: Vec<(String, u8, i64)> = Vec::new();
    let mut rest: &str = operands;
    while let Some(at) = rest.find("[rsp+") {
        let tail: &str = rest.get(at + 5..).unwrap_or_default();
        let Some(close): Option<usize> = tail.find(']') else {
            break;
        };
        let inner: &str = tail.get(..close).unwrap_or_default();
        rest = tail.get(close..).unwrap_or_default();
        let Some((index, after)): Option<(&str, &str)> = inner.split_once('*') else {
            continue;
        };
        let scale_digits: String = after.chars().take_while(char::is_ascii_digit).collect();
        let Ok(scale): Result<u8, _> = scale_digits.parse::<u8>() else {
            continue;
        };
        let disp_token: &str = after.get(scale_digits.len()..).unwrap_or_default();
        let disp: i64 = if disp_token.is_empty() {
            0
        } else {
            match parse_masm_i64(disp_token) {
                Some(value) => value,
                None => continue,
            }
        };
        out.push((index.to_owned(), scale, disp));
    }
    out
}

fn index_mask_bound(operands: &str) -> Option<(String, i64)> {
    let (lhs, rhs): (&str, &str) = operands.split_once(',')?;
    let bound: i64 = parse_masm_i64(rhs.trim())?;
    quad_name(lhs.trim()).map(|reg: String| (reg, bound))
}

fn assert_indexed_frame_encoding(object_bytes: &[u8], name: &str) -> IndexedFrameShape {
    let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(object_bytes, name) else {
        panic!("indexed-frame row {name}: symbol not located");
    };
    let insns: Vec<DisasmInsn> =
        disassemble(Arch::X86_64, base, &code).expect("disassemble indexed-frame row");
    let shape: RedZoneShape = red_zone_shape(&insns);
    assert!(
        !shape.adjusts_stack,
        "indexed-frame row {name} must not adjust the stack pointer, so its frame really is the red zone: {insns:?}"
    );
    let mut bounds: Vec<(String, i64)> = Vec::new();
    let mut found: Option<IndexedFrameShape> = None;
    for insn in &insns {
        for (index, scale, disp) in indexed_rsp_accesses(&insn.operands) {
            let Some((_, bound)): Option<&(String, i64)> = bounds
                .iter()
                .find(|(reg, _): &&(String, i64)| *reg == index)
            else {
                panic!(
                    "indexed-frame row {name} indexes the frame with {index} before any mask bounds it: {} {}",
                    insn.mnemonic, insn.operands
                );
            };
            let elements: i64 = bound + 1;
            let end: i64 = disp + elements * i64::from(scale);
            assert!(
                (-128..0).contains(&disp) && end <= 0,
                "indexed-frame row {name} must keep its whole element range inside the red zone, got [{disp}, {end})"
            );
            assert!(
                matches!(scale, 1 | 2 | 4 | 8),
                "indexed-frame row {name} must use a machine element stride, got {scale}"
            );
            if found.is_none() {
                found = Some(IndexedFrameShape {
                    index: index.clone(),
                    scale,
                    disp,
                    elements,
                });
            }
        }
        if insn.mnemonic == "and"
            && let Some((reg, bound)) = index_mask_bound(&insn.operands)
        {
            bounds.retain(|(existing, _): &(String, i64)| *existing != reg);
            bounds.push((reg, bound));
        }
    }
    let Some(shape): Option<IndexedFrameShape> = found else {
        panic!(
            "indexed-frame row {name} must contain an indexed rsp frame access: {}",
            insns
                .iter()
                .map(|i: &DisasmInsn| format!("{} {}", i.mnemonic, i.operands))
                .collect::<Vec<String>>()
                .join("; ")
        );
    };
    shape
}

fn build_indexed_frame_driver(recovered_decls: &str, driver_body: &str) -> String {
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n{recovered_decls}\n\
         int main(void) {{\n\
         \x20   long long inputs[][3] = {{\n\
         \x20       {{0,0x0123456789abcdefLL,0x1032547698badcfeLL}},\n\
         \x20       {{1,0x0123456789abcdefLL,0x1032547698badcfeLL}},\n\
         \x20       {{2,0x0123456789abcdefLL,0x1032547698badcfeLL}},\n\
         \x20       {{3,0x0123456789abcdefLL,0x1032547698badcfeLL}},\n\
         \x20       {{4,0x0123456789abcdefLL,0x1032547698badcfeLL}},\n\
         \x20       {{5,0x0123456789abcdefLL,0x1032547698badcfeLL}},\n\
         \x20       {{6,0x0123456789abcdefLL,0x1032547698badcfeLL}},\n\
         \x20       {{7,0x0123456789abcdefLL,0x1032547698badcfeLL}},\n\
         \x20       {{8,0x0123456789abcdefLL,0x1032547698badcfeLL}},\n\
         \x20       {{-1,0x0123456789abcdefLL,0x1032547698badcfeLL}},\n\
         \x20       {{-4,0x0123456789abcdefLL,0x1032547698badcfeLL}},\n\
         \x20       {{0x7fffffffffffffffLL,0x0123456789abcdefLL,0x1032547698badcfeLL}},\n\
         \x20       {{(long long)0x8000000000000000ULL,0x0123456789abcdefLL,0x1032547698badcfeLL}},\n\
         \x20       {{0x100000003LL,0x0123456789abcdefLL,0x1032547698badcfeLL}},\n\
         \x20       {{0x300000000LL,0x0123456789abcdefLL,0x1032547698badcfeLL}},\n\
         \x20       {{0,0x5555555555555555LL,(long long)0xaaaaaaaaaaaaaaaaULL}},\n\
         \x20       {{1,0x5555555555555555LL,(long long)0xaaaaaaaaaaaaaaaaULL}},\n\
         \x20       {{2,0x5555555555555555LL,(long long)0xaaaaaaaaaaaaaaaaULL}},\n\
         \x20       {{3,0x5555555555555555LL,(long long)0xaaaaaaaaaaaaaaaaULL}},\n\
         \x20       {{0,-1,-1}},{{1,-1,0}},{{2,0,-1}},{{3,1,-1}},\n\
         \x20       {{0,0xffLL,0xff00LL}},{{1,0x100LL,0x10000LL}},\n\
         \x20       {{2,0x80LL,(long long)0x80000000LL}},{{3,123456789LL,-987654321LL}},\n\
         \x20       {{0,0x7fffffffffffffffLL,(long long)0x8000000000000000ULL}},\n\
         \x20       {{3,0x7fffffffffffffffLL,(long long)0x8000000000000000ULL}}\n\
         \x20   }};\n\
         \x20   size_t n_inputs = sizeof(inputs)/sizeof(inputs[0]);\n\
         {driver_body}\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n"
    )
}

#[test]
fn sysv_mask_bounded_indexed_frame_arrays_recompile_to_behavioral_equivalence() {
    if !sysv_host_can_run() {
        return;
    }
    let Some(objs): Option<SysvCrossObjects> =
        compile_sysv_cross("ix", &battery_source(INDEXED_FRAME_BATTERY))
    else {
        return;
    };

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut widest: i64 = 0;
    for case in INDEXED_FRAME_BATTERY {
        let shape: IndexedFrameShape = assert_indexed_frame_encoding(&objs.sysv_object, case.name);
        widest = widest.max(shape.elements);
        println!(
            "indexed-frame row {} accesses [rsp+{}*{}{:+}] over {} elements",
            case.name, shape.index, shape.scale, shape.disp, shape.elements
        );
        let Some((code, base)): Option<(Vec<u8>, u64)> =
            function_code(&objs.sysv_object, case.name)
        else {
            panic!("indexed-frame row {}: symbol not located", case.name);
        };
        let recovery: LeafRecovery = recover_leaf_function_abi(&code, base, PseudoAbi::SysV)
            .unwrap_or_else(|e: disrobe_pass_native::Error| {
                panic!("indexed-frame row {} must recover, got: {e}", case.name)
            });
        assert!(
            recovery
                .source
                .contains("r_rsp = (uint64_t)(uintptr_t)(stack_frame +"),
            "indexed-frame row {} must model its element array as a local frame:\n{}",
            case.name,
            recovery.source
        );
        assert!(
            recovery
                .source
                .contains(&format!("r_{} * {}ULL", shape.index, shape.scale)),
            "indexed-frame row {} must keep the runtime index and its stride:\n{}",
            case.name,
            recovery.source
        );
        let Some(lifted): Option<Lifted> = process_case(case, &objs.sysv_object, PseudoAbi::SysV)
        else {
            panic!(
                "indexed-frame row {} must lift into the graded driver",
                case.name
            );
        };
        recovered_decls.push_str(&lifted.decls);
        driver_body.push_str(&lifted.driver_snippet);
    }
    assert!(
        widest >= 4,
        "the indexed-frame battery must reach a four-element region, widest was {widest}"
    );

    let driver: String = build_indexed_frame_driver(&recovered_decls, &driver_body);
    let stdout: String = link_and_run_sysv("ix", &driver, &objs.host_object, 30);
    assert!(
        stdout.contains("OK"),
        "SysV indexed-frame behavioral differential FAILED ({} cases): {stdout}",
        INDEXED_FRAME_BATTERY.len()
    );
    println!(
        "SysV indexed-frame behavioral differential PASSED for {} mask-bounded runtime-index leaf functions (SysV ABI)",
        INDEXED_FRAME_BATTERY.len()
    );
}

const FP_RED_ZONE_BATTERY: &[FpCase] = &[
    FpCase {
        name: "rzf_dslot",
        args: &[FpArg::Double, FpArg::Double],
        ret: FpRet::Double,
        c_source: "double rzf_dslot(double a, double b){ volatile double v = a * b; return v + a - b; }",
    },
    FpCase {
        name: "rzf_fslot",
        args: &[FpArg::Float, FpArg::Float],
        ret: FpRet::Float,
        c_source: "float rzf_fslot(float a, float b){ volatile float v = a * b; return v + b; }",
    },
    FpCase {
        name: "rzf_dpair",
        args: &[FpArg::Double, FpArg::Double],
        ret: FpRet::Double,
        c_source: "double rzf_dpair(double a, double b){ volatile double x = a + b; volatile double y = a - b; return x * y; }",
    },
];

#[test]
fn sysv_red_zone_scalar_float_leaf_functions_recompile_to_behavioral_equivalence() {
    if !sysv_host_can_run() {
        return;
    }
    let Some(objs): Option<SysvCrossObjects> =
        compile_sysv_cross("rzf", &fp_battery_source(FP_RED_ZONE_BATTERY))
    else {
        return;
    };

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    for case in FP_RED_ZONE_BATTERY {
        let slots: Vec<i64> = assert_red_zone_encoding(&objs.sysv_object, case.name);
        println!("red-zone fp row {} uses rsp slots {slots:?}", case.name);
        let Some((_, renamed, recovered_name)): Option<(LeafRecovery, String, String)> =
            fp_lift(case, &objs.sysv_object, PseudoAbi::SysV)
        else {
            panic!("red-zone fp row {} must recover", case.name);
        };
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        recovered_decls.push_str(&fp_extern_decl(case));
        recovered_decls.push('\n');
        driver_body.push_str(&fp_driver_snippet(case, &recovered_name));
    }

    let driver: String = build_fp_driver(&recovered_decls, &driver_body);
    let stdout: String = link_and_run_sysv("rzf", &driver, &objs.host_object, 30);
    assert!(
        stdout.contains("OK"),
        "SysV red-zone scalar float differential FAILED ({} cases): {stdout}",
        FP_RED_ZONE_BATTERY.len()
    );
    println!(
        "SysV red-zone scalar float differential PASSED for {} leaf functions (SysV ABI)",
        FP_RED_ZONE_BATTERY.len()
    );
}

struct SretCase {
    name: &'static str,
    typedef: &'static str,
    ret_ty: &'static str,
    field_accessors: &'static [&'static str],
    field_cast: &'static str,
    arity: usize,
    body: &'static str,
}

const SRET_BATTERY: &[SretCase] = &[
    SretCase {
        name: "mk3",
        typedef: "typedef struct { long long a, b, c; } mk3_t;",
        ret_ty: "mk3_t",
        field_accessors: &["a", "b", "c"],
        field_cast: "long long",
        arity: 2,
        body: "mk3_t r; r.a = x + y; r.b = x - y; r.c = x * y; return r;",
    },
    SretCase {
        name: "mk4",
        typedef: "typedef struct { long long a, b, c, d; } mk4_t;",
        ret_ty: "mk4_t",
        field_accessors: &["a", "b", "c", "d"],
        field_cast: "long long",
        arity: 2,
        body: "mk4_t r; r.a = x; r.b = y; r.c = x & y; r.d = x | y; return r;",
    },
    SretCase {
        name: "mk3c",
        typedef: "typedef struct { long long a, b, c; } mk3c_t;",
        ret_ty: "mk3c_t",
        field_accessors: &["a", "b", "c"],
        field_cast: "long long",
        arity: 3,
        body: "mk3c_t r; r.a = x + y; r.b = y + z; r.c = x + z; return r;",
    },
    SretCase {
        name: "mk5i",
        typedef: "typedef struct { int a, b, c, d, e; } mk5i_t;",
        ret_ty: "mk5i_t",
        field_accessors: &["a", "b", "c", "d", "e"],
        field_cast: "int",
        arity: 2,
        body: "mk5i_t r; r.a = (int)x; r.b = (int)y; r.c = (int)(x + y); r.d = (int)(x - y); r.e = (int)(x * y); return r;",
    },
];

fn sret_arg_decl(arity: usize) -> String {
    ["long long x", "long long y", "long long z"][..arity].join(", ")
}

fn sret_battery_source() -> String {
    let mut src: String = String::new();
    for case in SRET_BATTERY {
        let _ = write!(
            src,
            "{}\n{} {}({}){{ {} }}\n",
            case.typedef,
            case.ret_ty,
            case.name,
            sret_arg_decl(case.arity),
            case.body
        );
    }
    src
}

fn sret_recovered_decl(recovery: &LeafRecovery, recovered_name: &str) -> String {
    recovery
        .source
        .replace("recovered", recovered_name)
        .lines()
        .filter(|l: &&str| !l.starts_with("#include"))
        .collect::<Vec<&str>>()
        .join("\n")
}

fn sret_case_snippet(case: &SretCase, recovery: &LeafRecovery) -> Option<String> {
    let sret: &disrobe_pass_native::SretReturn = recovery.sret.as_ref()?;
    if recovery.params.len() != case.arity || sret.field_widths.len() != case.field_accessors.len()
    {
        return None;
    }
    let recovered_name: String = format!("rec_{}", case.name);
    let orig_args: String = (0..case.arity)
        .map(|i: usize| format!("inputs[k][{i}]"))
        .collect::<Vec<String>>()
        .join(", ");
    let rec_args: String = (0..case.arity)
        .map(|i: usize| format!("(uint64_t)inputs[k][{i}]"))
        .collect::<Vec<String>>()
        .join(", ");
    let compares: String = case
        .field_accessors
        .iter()
        .enumerate()
        .map(|(i, acc): (usize, &&str)| format!("({})got.f{i} != want.{acc}", case.field_cast))
        .collect::<Vec<String>>()
        .join(" || ");
    let mut snippet: String = String::new();
    let _ = write!(
        snippet,
        "    for (size_t k = 0; k < n_inputs; k++) {{\n\
         \x20       {} want = {}({orig_args});\n\
         \x20       rec_{}_sret_t got = {recovered_name}({rec_args});\n\
         \x20       if ({compares}) {{ printf(\"MISMATCH {} in=%lld,%lld,%lld\\n\", inputs[k][0], inputs[k][1], inputs[k][2]); return 1; }}\n\
         \x20   }}\n",
        case.ret_ty, case.name, case.name, case.name,
    );
    Some(snippet)
}

fn build_sret_driver(typedefs: &str, externs: &str, recovered_decls: &str, body: &str) -> String {
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n{typedefs}\n{externs}\n{recovered_decls}\n\
         int main(void) {{\n\
         \x20   long long inputs[][3] = {{\n\
         \x20       {{0,0,0}},{{1,1,1}},{{-1,-1,-1}},{{7,3,5}},{{-7,3,-5}},\n\
         \x20       {{123456,-654321,99}},{{2147483647,1,2}},{{-2147483648,-1,-2}},\n\
         \x20       {{0x7fffffffffffffffLL,2,3}},{{100,200,300}},{{-100,50,-25}},\n\
         \x20       {{1<<20,1<<10,1<<5}},{{42,42,42}},{{0xdeadbeef,0xcafef00d,0x1234}}\n\
         \x20   }};\n\
         \x20   size_t n_inputs = sizeof(inputs)/sizeof(inputs[0]);\n\
         {body}\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n"
    )
}

struct SretLift {
    typedefs: String,
    externs: String,
    recovered_decls: String,
    driver_body: String,
    lifted: usize,
}

fn collect_sret_cases(object_bytes: &[u8], abi: PseudoAbi) -> SretLift {
    let mut out: SretLift = SretLift {
        typedefs: String::new(),
        externs: String::new(),
        recovered_decls: String::new(),
        driver_body: String::new(),
        lifted: 0,
    };
    for case in SRET_BATTERY {
        let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(object_bytes, case.name)
        else {
            eprintln!("skip {}: symbol not located", case.name);
            continue;
        };
        let recovery: LeafRecovery = match recover_leaf_function_abi(&code, base, abi) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skip {} ({abi:?}): not in leaf class ({e})", case.name);
                continue;
            }
        };
        let Some(snippet): Option<String> = sret_case_snippet(case, &recovery) else {
            eprintln!(
                "skip {} ({abi:?}): not recovered as memory-class sret",
                case.name
            );
            continue;
        };
        out.typedefs.push_str(case.typedef);
        out.typedefs.push('\n');
        let _ = writeln!(
            out.externs,
            "extern {} {}({});",
            case.ret_ty,
            case.name,
            vec!["long long"; case.arity].join(", ")
        );
        out.recovered_decls.push_str(&sret_recovered_decl(
            &recovery,
            &format!("rec_{}", case.name),
        ));
        out.recovered_decls.push('\n');
        out.driver_body.push_str(&snippet);
        out.lifted += 1;
    }
    out
}

#[test]
fn struct_return_leaf_functions_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guard"
        );
        return;
    }
    let Some(compiler): Option<String> = cc() else {
        eprintln!("skipping: no C compiler (gcc/clang/cc) on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let battery_c: PathBuf = dir.join("sret_battery.c");
    std::fs::write(&battery_c, sret_battery_source().as_bytes()).expect("write sret_battery.c");
    let battery_o: PathBuf = dir.join("sret_battery.o");
    let compile_battery: std::process::Output = Command::new(&compiler)
        .args(["-O1", "-fno-stack-protector", "-c", "-o"])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke cc for sret battery");
    assert!(
        compile_battery.status.success(),
        "sret battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read sret_battery.o");

    let lift: SretLift = collect_sret_cases(&object_bytes, HOST_ABI);
    let lifted_count: usize = lift.lifted;

    if lifted_count == 0 {
        eprintln!(
            "skipping struct-return behavioral differential: this compiler build lowered none of the {} sret cases into the leaf class",
            SRET_BATTERY.len()
        );
        return;
    }

    let driver: String = build_sret_driver(
        &lift.typedefs,
        &lift.externs,
        &lift.recovered_decls,
        &lift.driver_body,
    );
    let driver_c: PathBuf = dir.join("sret_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write sret_driver.c");
    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "sret_harness.exe"
    } else {
        "sret_harness"
    });
    let link: std::process::Output = Command::new(&compiler)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke cc to link sret harness");
    assert!(
        link.status.success(),
        "sret harness link failed: {}\n--- sret_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run sret harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "struct-return behavioral differential FAILED ({lifted_count} cases): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "struct-return behavioral differential PASSED for {lifted_count} memory-class sret leaf functions (host ABI)"
    );
}

#[test]
fn sysv_struct_return_leaf_functions_recompile_to_behavioral_equivalence() {
    if !sysv_host_can_run() {
        return;
    }
    let Some(objs): Option<SysvCrossObjects> = compile_sysv_cross("sret", &sret_battery_source())
    else {
        return;
    };

    let lift: SretLift = collect_sret_cases(&objs.sysv_object, PseudoAbi::SysV);
    let lifted_count: usize = lift.lifted;
    assert!(
        lifted_count >= 3,
        "SysV memory-class sret lifter must handle at least 3 of the {} cases, only lifted {lifted_count}",
        SRET_BATTERY.len()
    );

    let driver: String = build_sret_driver(
        &lift.typedefs,
        &lift.externs,
        &lift.recovered_decls,
        &lift.driver_body,
    );
    let stdout: String = link_and_run_sysv("sret", &driver, &objs.host_object, 30);
    assert!(
        stdout.contains("OK"),
        "SysV struct-return behavioral differential FAILED ({lifted_count} cases): {stdout}"
    );
    println!(
        "SysV struct-return behavioral differential PASSED for {lifted_count} memory-class sret leaf functions (SysV ABI)"
    );
}

#[test]
fn struct_return_oracle_has_teeth_corrupting_a_field_store_diverges() {
    let Some(compiler): Option<String> = cc() else {
        eprintln!("skipping struct-return teeth check: no C compiler on PATH");
        return;
    };
    let probe: [u8; 29] = [
        0x48, 0x89, 0xf8, 0x48, 0x8d, 0x0c, 0x32, 0x48, 0x89, 0x0f, 0x48, 0x89, 0xf1, 0x48, 0x29,
        0xd1, 0x48, 0x89, 0x4f, 0x08, 0x48, 0x0f, 0xaf, 0xd6, 0x48, 0x89, 0x57, 0x10, 0xc3,
    ];
    let recovery: LeafRecovery = recover_leaf_function_abi(&probe, 0x1000, PseudoAbi::SysV)
        .expect("the sysv three-qword sret probe must lift");
    assert!(
        recovery
            .sret
            .as_ref()
            .is_some_and(|s: &disrobe_pass_native::SretReturn| s.size == 24),
        "the probe must be recognized as a 24-byte memory-class sret"
    );
    assert_eq!(
        recovery.params.len(),
        2,
        "the hidden pointer must be dropped, leaving the two scalar args"
    );
    let renamed: String = sret_recovered_decl(&recovery, "rec_probe");

    let middle_field: &str = "(*(uint64_t*)(uintptr_t)(r_rdi + (uint64_t)(int64_t)8LL))";
    let collided_field: &str = "(*(uint64_t*)(uintptr_t)(r_rdi + (uint64_t)(int64_t)0LL))";
    let sabotaged: String = renamed.replacen(middle_field, collided_field, 1);
    assert_ne!(
        sabotaged, renamed,
        "the second field store must be present to be corrupted"
    );

    let run_variant = |tag: &str, decls: &str| -> String {
        let scratch: ScratchDir = scratch_dir();
        let dir: PathBuf = scratch.path().to_path_buf();
        let driver: String = format!(
            "#include <stdint.h>\n#include <stdio.h>\n{decls}\n\
             int main(void) {{\n\
             \x20   long long in[][2] = {{ {{7,3}},{{1,1}},{{-5,9}},{{100,-25}},{{0,0}},{{2147483647,-1}},{{-9,-4}} }};\n\
             \x20   for (size_t k = 0; k < sizeof(in)/sizeof(in[0]); k++) {{\n\
             \x20       long long x = in[k][0], y = in[k][1];\n\
             \x20       rec_probe_sret_t got = rec_probe((uint64_t)x, (uint64_t)y);\n\
             \x20       if ((long long)got.f0 != x + y || (long long)got.f1 != x - y || (long long)got.f2 != x * y) {{\n\
             \x20           printf(\"MISMATCH in=%lld,%lld f0=%lld f1=%lld f2=%lld\\n\", x, y, (long long)got.f0, (long long)got.f1, (long long)got.f2); return 1; }}\n\
             \x20   }}\n\
             \x20   printf(\"OK\\n\");\n\
             \x20   return 0;\n\
             }}\n"
        );
        let driver_c: PathBuf = dir.join(format!("sret_teeth_{tag}.c"));
        std::fs::write(&driver_c, driver.as_bytes()).expect("write teeth driver");
        let exe: PathBuf = dir.join(if cfg!(windows) {
            format!("sret_teeth_{tag}.exe")
        } else {
            format!("sret_teeth_{tag}")
        });
        let link: std::process::Output = Command::new(&compiler)
            .args(["-O1", "-o"])
            .arg(&exe)
            .arg(&driver_c)
            .output()
            .expect("invoke cc to link teeth harness");
        assert!(
            link.status.success(),
            "teeth harness link failed: {}\n--- driver ---\n{driver}",
            String::from_utf8_lossy(&link.stderr)
        );
        let out: std::process::Output = Command::new(&exe).output().expect("run teeth harness");
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            if out.status.success() {
                ""
            } else {
                "\nNONZERO"
            }
        )
    };

    let pristine: String = run_variant("clean", &renamed);
    assert!(
        pristine.contains("OK"),
        "the faithful sret lift must round-trip the three struct fields: {pristine}"
    );
    let broken: String = run_variant("broken", &sabotaged);
    assert!(
        broken.contains("MISMATCH") || broken.contains("NONZERO"),
        "colliding the second field store onto the first must diverge; instead: {broken}"
    );
    println!(
        "struct-return oracle teeth confirmed: the faithful sret lift matches, corrupting a field store offset diverges"
    );
}

const DIAMOND_BATTERY: &[Case] = &[
    Case {
        name: "dm_absdiff",
        arity: 2,
        c_source: "long long dm_absdiff(long long a, long long b){ long long r; if (a > b) { r = a - b; } else { r = b - a; } return r; }",
    },
    Case {
        name: "dm_scale",
        arity: 2,
        c_source: "long long dm_scale(long long a, long long b){ long long r; if (a > b) { r = a * 3; } else { r = b * 5; } return r ^ 7; }",
    },
    Case {
        name: "dm_bitsel",
        arity: 2,
        c_source: "long long dm_bitsel(long long a, long long b){ long long r; if ((a & 1) != 0) { r = a | b; } else { r = a & b; } return r; }",
    },
    Case {
        name: "dm_branch3",
        arity: 3,
        c_source: "long long dm_branch3(long long a, long long b, long long c){ long long r; if (a > 0) { r = b + c; } else { r = b - c; } return r * 2; }",
    },
    Case {
        name: "dm_negsel",
        arity: 2,
        c_source: "long long dm_negsel(long long a, long long b){ long long r; if (a < 0) { r = 0 - a; } else { r = a + b; } return r; }",
    },
    Case {
        name: "dm_eqpick",
        arity: 2,
        c_source: "long long dm_eqpick(long long a, long long b){ long long r; if (a == b) { r = a * a; } else { r = a - b; } return r + 1; }",
    },
];

fn diamond_recovered_has_else(object_bytes: &[u8], name: &str, abi: PseudoAbi) -> bool {
    let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(object_bytes, name) else {
        return false;
    };
    recover_leaf_function_abi(&code, base, abi)
        .is_ok_and(|r: LeafRecovery| r.source.contains("} else {"))
}

#[test]
fn if_else_diamond_leaf_functions_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!(
            "skipping if-else diamond oracle: gcc (needed to suppress if-conversion) not on PATH"
        );
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();

    let battery_c: PathBuf = dir.join("diamond_battery.c");
    std::fs::write(&battery_c, battery_source(DIAMOND_BATTERY).as_bytes())
        .expect("write diamond_battery.c");
    let battery_o: PathBuf = dir.join("diamond_battery.o");
    let compile_battery: std::process::Output = Command::new(&builder)
        .args([
            "-O1",
            "-fno-stack-protector",
            "-fno-if-conversion",
            "-fno-if-conversion2",
            "-fno-tree-loop-if-convert",
            "-c",
            "-o",
        ])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke gcc for diamond battery");
    assert!(
        compile_battery.status.success(),
        "diamond battery compile failed: {}",
        String::from_utf8_lossy(&compile_battery.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read diamond_battery.o");

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    let mut diamond_count: usize = 0;

    for case in DIAMOND_BATTERY {
        if diamond_recovered_has_else(&object_bytes, case.name, HOST_ABI) {
            diamond_count += 1;
        }
        let Some(lifted): Option<Lifted> = process_case(case, &object_bytes, HOST_ABI) else {
            continue;
        };
        recovered_decls.push_str(&lifted.decls);
        driver_body.push_str(&lifted.driver_snippet);
        lifted_count += 1;
    }

    if lifted_count == 0 {
        eprintln!(
            "skipping if-else diamond behavioral differential: this compiler build lowered none of the {} battery cases into the leaf class",
            DIAMOND_BATTERY.len()
        );
        return;
    }
    assert!(
        diamond_count >= 1,
        "the if-else diamond oracle has no teeth: none of the {lifted_count} recovered cases emitted a two-armed `else` region, so the diamond structuring path was never exercised"
    );

    let driver: String = build_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("diamond_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write diamond_driver.c");
    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "diamond_harness.exe"
    } else {
        "diamond_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke gcc to link diamond harness");
    assert!(
        link.status.success(),
        "diamond harness link failed: {}\n--- diamond_driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );
    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run diamond harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "if-else diamond behavioral differential FAILED ({lifted_count} cases, {diamond_count} diamonds): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "if-else diamond behavioral differential PASSED for {lifted_count} leaf functions ({diamond_count} two-armed diamonds, MS x64 ABI)"
    );
}

struct SelCase {
    name: &'static str,
    arity: usize,
    expect_sel_cc: bool,
    require_ternary: bool,
    allow_sound_reject: bool,
    c_source: &'static str,
}

const SEL_BATTERY: &[SelCase] = &[
    SelCase {
        name: "s_absdiff64",
        arity: 2,
        expect_sel_cc: true,
        require_ternary: false,
        allow_sound_reject: true,
        c_source: "long long s_absdiff64(long long a, long long b){ long long d = a - b; if (d < 0) d = -d; return d; }",
    },
    SelCase {
        name: "s_absdiff32",
        arity: 2,
        expect_sel_cc: true,
        require_ternary: false,
        allow_sound_reject: true,
        c_source: "int s_absdiff32(int a, int b){ int d = a - b; if (d < 0) d = -d; return d; }",
    },
    SelCase {
        name: "s_absdiff16",
        arity: 2,
        expect_sel_cc: true,
        require_ternary: false,
        allow_sound_reject: true,
        c_source: "int s_absdiff16(short a, short b){ int d = (int)a - (int)b; if (d < 0) d = -d; return d; }",
    },
    SelCase {
        name: "s_absdiff8",
        arity: 2,
        expect_sel_cc: true,
        require_ternary: false,
        allow_sound_reject: true,
        c_source: "signed char s_absdiff8(signed char a, signed char b){ int d = (int)a - (int)b; if (d < 0) d = -d; return (signed char)d; }",
    },
    SelCase {
        name: "s_abs64",
        arity: 1,
        expect_sel_cc: false,
        require_ternary: false,
        allow_sound_reject: true,
        c_source: "long long s_abs64(long long x){ return x < 0 ? -x : x; }",
    },
    SelCase {
        name: "s_abs16",
        arity: 1,
        expect_sel_cc: false,
        require_ternary: false,
        allow_sound_reject: true,
        c_source: "short s_abs16(short x){ int v = x; return (short)(v < 0 ? -v : v); }",
    },
    SelCase {
        name: "s_max64",
        arity: 2,
        expect_sel_cc: false,
        require_ternary: true,
        allow_sound_reject: false,
        c_source: "long long s_max64(long long a, long long b){ return a > b ? a : b; }",
    },
    SelCase {
        name: "s_min64",
        arity: 2,
        expect_sel_cc: false,
        require_ternary: true,
        allow_sound_reject: false,
        c_source: "long long s_min64(long long a, long long b){ return a < b ? a : b; }",
    },
    SelCase {
        name: "s_max8",
        arity: 2,
        expect_sel_cc: false,
        require_ternary: true,
        allow_sound_reject: false,
        c_source: "signed char s_max8(signed char a, signed char b){ return a > b ? a : b; }",
    },
    SelCase {
        name: "s_umax32",
        arity: 2,
        expect_sel_cc: false,
        require_ternary: true,
        allow_sound_reject: false,
        c_source: "unsigned s_umax32(unsigned a, unsigned b){ return a > b ? a : b; }",
    },
    SelCase {
        name: "s_selnz",
        arity: 2,
        expect_sel_cc: false,
        require_ternary: true,
        allow_sound_reject: false,
        c_source: "long long s_selnz(long long a, long long b){ return a != 0 ? a : b; }",
    },
    SelCase {
        name: "s_nearmiss",
        arity: 2,
        expect_sel_cc: false,
        require_ternary: false,
        allow_sound_reject: true,
        c_source: "long long s_nearmiss(long long a, long long b){ long long d = a - b; return (a >= b) ? a : d; }",
    },
];

const SEL_HARNESS_TAIL: &str = r#"
extern long long s_absdiff64(long long, long long);
extern int s_absdiff32(int, int);
extern int s_absdiff16(short, short);
extern signed char s_absdiff8(signed char, signed char);
extern long long s_abs64(long long);
extern short s_abs16(short);
extern long long s_max64(long long, long long);
extern long long s_min64(long long, long long);
extern signed char s_max8(signed char, signed char);
extern unsigned s_umax32(unsigned, unsigned);
extern long long s_selnz(long long, long long);
extern long long s_nearmiss(long long, long long);

static const long long A64[] = {
    0, 1, -1, 2, -2, 7, -7, 3, -3, 5, -5, 50, -50, 100, -100,
    123456789, -123456789, 1000000, -1000000,
    9223372036854775807LL, (-9223372036854775807LL - 1LL),
    4294967296LL, -4294967296LL, 65536, -65536
};
static const long long A32[] = {
    0, 1, -1, 2, -2, 7, -7, 100, -100,
    2147483647LL, (-2147483647LL - 1LL), 1073741824LL, -1073741824LL,
    65535, -65536, 305419896LL, -559038737LL
};
#define NA64 (sizeof(A64) / sizeof(A64[0]))
#define NA32 (sizeof(A32) / sizeof(A32[0]))

static int mism(const char *n, long long a, long long b, unsigned long long w, unsigned long long g) {
    printf("MISMATCH %s a=%lld b=%lld want=%llu got=%llu\n", n, a, b, w, g);
    return 1;
}

#ifdef SEL_HAVE_s_absdiff64
static int check_s_absdiff64(void) {
    for (size_t i = 0; i < NA64; i++) for (size_t j = 0; j < NA64; j++) {
        long long a = A64[i], b = A64[j], d;
        if (__builtin_sub_overflow(a, b, &d)) continue;
        if (d == LLONG_MIN) continue;
        unsigned long long w = (unsigned long long)s_absdiff64(a, b);
        unsigned long long g = rec_s_absdiff64((uint64_t)a, (uint64_t)b);
        if (w != g) return mism("s_absdiff64", a, b, w, g);
    }
    return 0;
}
#endif
#ifdef SEL_HAVE_s_absdiff32
static int check_s_absdiff32(void) {
    for (size_t i = 0; i < NA32; i++) for (size_t j = 0; j < NA32; j++) {
        int a = (int)A32[i], b = (int)A32[j], d;
        if (__builtin_sub_overflow(a, b, &d)) continue;
        if (d == INT_MIN) continue;
        unsigned long long w = (unsigned long long)(unsigned)s_absdiff32(a, b);
        unsigned long long g = rec_s_absdiff32((uint64_t)(long long)a, (uint64_t)(long long)b) & 0xffffffffULL;
        if (w != g) return mism("s_absdiff32", a, b, w, g);
    }
    return 0;
}
#endif
#ifdef SEL_HAVE_s_absdiff16
static int check_s_absdiff16(void) {
    static const short BS[] = { -32768, -1, 0, 1, 32767, 12345 };
    for (int ia = -32768; ia <= 32767; ia++) for (size_t k = 0; k < 6; k++) {
        short a = (short)ia, b = BS[k];
        unsigned long long w = (unsigned long long)(unsigned)s_absdiff16(a, b);
        unsigned long long g = rec_s_absdiff16((uint64_t)(long long)a, (uint64_t)(long long)b) & 0xffffffffULL;
        if (w != g) return mism("s_absdiff16", a, b, w, g);
    }
    return 0;
}
#endif
#ifdef SEL_HAVE_s_absdiff8
static int check_s_absdiff8(void) {
    for (int ia = -128; ia < 128; ia++) for (int ib = -128; ib < 128; ib++) {
        signed char a = (signed char)ia, b = (signed char)ib;
        unsigned long long w = (unsigned long long)(unsigned char)s_absdiff8(a, b);
        unsigned long long g = rec_s_absdiff8((uint64_t)(long long)a, (uint64_t)(long long)b) & 0xffULL;
        if (w != g) return mism("s_absdiff8", a, b, w, g);
    }
    return 0;
}
#endif
#ifdef SEL_HAVE_s_abs64
static int check_s_abs64(void) {
    for (size_t i = 0; i < NA64; i++) {
        long long x = A64[i];
        unsigned long long w = (unsigned long long)s_abs64(x);
        unsigned long long g = rec_s_abs64((uint64_t)x);
        if (w != g) return mism("s_abs64", x, 0, w, g);
    }
    return 0;
}
#endif
#ifdef SEL_HAVE_s_abs16
static int check_s_abs16(void) {
    for (int ix = -32768; ix <= 32767; ix++) {
        short x = (short)ix;
        unsigned long long w = (unsigned long long)(unsigned short)s_abs16(x);
        unsigned long long g = rec_s_abs16((uint64_t)(long long)x) & 0xffffULL;
        if (w != g) return mism("s_abs16", x, 0, w, g);
    }
    return 0;
}
#endif
static int check_s_max64(void) {
    for (size_t i = 0; i < NA64; i++) for (size_t j = 0; j < NA64; j++) {
        long long a = A64[i], b = A64[j];
        unsigned long long w = (unsigned long long)s_max64(a, b);
        unsigned long long g = rec_s_max64((uint64_t)a, (uint64_t)b);
        if (w != g) return mism("s_max64", a, b, w, g);
    }
    return 0;
}
static int check_s_min64(void) {
    for (size_t i = 0; i < NA64; i++) for (size_t j = 0; j < NA64; j++) {
        long long a = A64[i], b = A64[j];
        unsigned long long w = (unsigned long long)s_min64(a, b);
        unsigned long long g = rec_s_min64((uint64_t)a, (uint64_t)b);
        if (w != g) return mism("s_min64", a, b, w, g);
    }
    return 0;
}
static int check_s_max8(void) {
    for (int ia = -128; ia < 128; ia++) for (int ib = -128; ib < 128; ib++) {
        signed char a = (signed char)ia, b = (signed char)ib;
        unsigned long long w = (unsigned long long)(unsigned char)s_max8(a, b);
        unsigned long long g = rec_s_max8((uint64_t)(long long)a, (uint64_t)(long long)b) & 0xffULL;
        if (w != g) return mism("s_max8", a, b, w, g);
    }
    return 0;
}
static int check_s_umax32(void) {
    for (size_t i = 0; i < NA32; i++) for (size_t j = 0; j < NA32; j++) {
        unsigned a = (unsigned)A32[i], b = (unsigned)A32[j];
        unsigned long long w = (unsigned long long)s_umax32(a, b);
        unsigned long long g = rec_s_umax32((uint64_t)a, (uint64_t)b) & 0xffffffffULL;
        if (w != g) return mism("s_umax32", (long long)a, (long long)b, w, g);
    }
    return 0;
}
static int check_s_selnz(void) {
    for (size_t i = 0; i < NA64; i++) for (size_t j = 0; j < NA64; j++) {
        long long a = A64[i], b = A64[j];
        unsigned long long w = (unsigned long long)s_selnz(a, b);
        unsigned long long g = rec_s_selnz((uint64_t)a, (uint64_t)b);
        if (w != g) return mism("s_selnz", a, b, w, g);
    }
    return 0;
}
#ifdef SEL_HAVE_s_nearmiss
static int check_s_nearmiss(void) {
    for (size_t i = 0; i < NA64; i++) for (size_t j = 0; j < NA64; j++) {
        long long a = A64[i], b = A64[j], d;
        if (__builtin_sub_overflow(a, b, &d)) continue;
        unsigned long long w = (unsigned long long)s_nearmiss(a, b);
        unsigned long long g = rec_s_nearmiss((uint64_t)a, (uint64_t)b);
        if (w != g) return mism("s_nearmiss", a, b, w, g);
    }
    return 0;
}
#endif

int main(void) {
#ifdef SEL_HAVE_s_absdiff64
    if (check_s_absdiff64()) return 1;
#endif
#ifdef SEL_HAVE_s_absdiff32
    if (check_s_absdiff32()) return 1;
#endif
#ifdef SEL_HAVE_s_absdiff16
    if (check_s_absdiff16()) return 1;
#endif
#ifdef SEL_HAVE_s_absdiff8
    if (check_s_absdiff8()) return 1;
#endif
#ifdef SEL_HAVE_s_abs64
    if (check_s_abs64()) return 1;
#endif
#ifdef SEL_HAVE_s_abs16
    if (check_s_abs16()) return 1;
#endif
    if (check_s_max64()) return 1;
    if (check_s_min64()) return 1;
    if (check_s_max8()) return 1;
    if (check_s_umax32()) return 1;
    if (check_s_selnz()) return 1;
#ifdef SEL_HAVE_s_nearmiss
    if (check_s_nearmiss()) return 1;
#endif
    printf("OK\n");
    return 0;
}
"#;

fn sel_recovered_decls(object_bytes: &[u8], abi: PseudoAbi, clang_flavor: bool) -> String {
    let mut decls: String = String::new();
    let mut select_ternaries: usize = 0;
    for case in SEL_BATTERY {
        let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(object_bytes, case.name)
        else {
            panic!("sel case {} symbol not located", case.name);
        };
        let recovery: LeafRecovery = match recover_leaf_function_abi(&code, base, abi) {
            Ok(recovery) => recovery,
            Err(e) => {
                assert!(
                    case.allow_sound_reject,
                    "sel case {} must recover, not sound-reject: {e}",
                    case.name
                );
                continue;
            }
        };
        assert_eq!(
            recovery.params.len(),
            case.arity,
            "sel case {} inferred arity {} != {}",
            case.name,
            recovery.params.len(),
            case.arity
        );
        if recovery.source.contains(" ? ") {
            select_ternaries += 1;
        } else {
            assert!(
                !case.require_ternary,
                "sel case {} recovered without a select ternary (cmov path did not fire):\n{}",
                case.name, recovery.source
            );
        }
        if clang_flavor
            && case.expect_sel_cc
            && function_uses_ordering_cmov(object_bytes, case.name)
        {
            assert!(
                recovery.source.contains("sel_cc_"),
                "sel case {} lowered by an ordering cmov against a value-producing sub must recover via the snapshot repair:\n{}",
                case.name,
                recovery.source
            );
        }
        let renamed: String = recovery
            .source
            .replacen(
                "uint64_t recovered(",
                &format!("uint64_t rec_{}(", case.name),
                1,
            )
            .lines()
            .filter(|l: &&str| !l.starts_with("#include"))
            .collect::<Vec<&str>>()
            .join("\n");
        let _ = writeln!(decls, "#define SEL_HAVE_{}", case.name);
        decls.push_str(&renamed);
        decls.push('\n');
    }
    assert!(
        select_ternaries >= 5,
        "the cmov select path must fire for the pure-select ordering idioms; only {select_ternaries} recovered as a select ternary"
    );
    decls
}

fn sel_driver(recovered_decls: &str) -> String {
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <limits.h>\n{recovered_decls}\n{SEL_HARNESS_TAIL}"
    )
}

#[test]
fn sysv_cmov_select_idioms_recompile_to_behavioral_equivalence() {
    if !sysv_host_can_run() {
        return;
    }
    let Some(_host_cc): Option<String> = cc() else {
        eprintln!("skipping: no C compiler on PATH");
        return;
    };
    let Some(_clang): Option<String> = clang() else {
        eprintln!("skipping sysv cmov idioms: clang (needed for SysV cross object) not on PATH");
        return;
    };
    let mut battery_src: String = String::new();
    for case in SEL_BATTERY {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let Some(objects): Option<SysvCrossObjects> = compile_sysv_cross("selcmov", &battery_src)
    else {
        return;
    };
    let decls: String = sel_recovered_decls(&objects.sysv_object, PseudoAbi::SysV, true);
    let driver: String = sel_driver(&decls);
    let stdout: String = link_and_run_sysv("selcmov", &driver, &objects.host_object, 30);
    assert!(
        stdout.contains("OK") && !stdout.contains("MISMATCH"),
        "sysv cmov/abs/min/max behavioral differential FAILED: {stdout}"
    );
    println!(
        "sysv cmov/abs/min/max differential PASSED for {} idioms (adversarial + exhaustive 8/16-bit)",
        SEL_BATTERY.len()
    );
}

#[test]
fn cmov_select_idioms_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native cmov oracle on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; the sysv clang cross guard is the cross-platform proof"
        );
        return;
    }
    let Some(compiler): Option<String> = cc() else {
        eprintln!("skipping: no C compiler (gcc/clang/cc) on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let mut battery_src: String = String::new();
    for case in SEL_BATTERY {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let battery_c: PathBuf = dir.join("selcmov_host.c");
    std::fs::write(&battery_c, battery_src.as_bytes()).expect("write selcmov_host.c");
    let battery_o: PathBuf = dir.join("selcmov_host.o");
    let compiled: std::process::Output = Command::new(&compiler)
        .args(["-O1", "-fno-stack-protector", "-c", "-o"])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke cc for cmov battery");
    assert!(
        compiled.status.success(),
        "cmov battery compile failed: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read selcmov_host.o");
    let decls: String = sel_recovered_decls(&object_bytes, HOST_ABI, false);
    let driver: String = sel_driver(&decls);
    let driver_c: PathBuf = dir.join("selcmov_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write selcmov_driver.c");
    let exe: PathBuf = dir.join(if cfg!(windows) {
        "selcmov.exe"
    } else {
        "selcmov"
    });
    let link: std::process::Output = Command::new(&compiler)
        .args(["-O1", "-o"])
        .arg(&exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke cc to link cmov harness");
    assert!(
        link.status.success(),
        "cmov harness link failed: {}\n--- driver ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );
    let BoundedRun::Exited(out): BoundedRun = run_bounded(&exe, 30) else {
        panic!("cmov harness did not terminate within the watchdog window");
    };
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("OK") && !stdout.contains("MISMATCH"),
        "host cmov/abs/min/max behavioral differential FAILED: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    println!(
        "host cmov/abs/min/max differential PASSED for {} idioms (MS x64, adversarial + exhaustive 8/16-bit)",
        SEL_BATTERY.len()
    );
}

const OBJ_SWITCH_BATTERY: &[Case] = &[
    Case {
        name: "osw_bias",
        arity: 2,
        c_source: "long long osw_bias(long long k, long long a){ switch(k){ case 100: return a*3+1; case 101: return a*7-2; case 102: return a^0x5a; case 103: return a<<3; case 104: return a-99; case 105: return a*a; case 106: return ~a; case 107: return a+12345; case 108: return a*a-a; case 109: return (a>>1)+3; default: return -1; } }",
    },
    Case {
        name: "osw_dup",
        arity: 2,
        c_source: "long long osw_dup(long long k, long long a){ switch(k){ case 0: return a+7; case 1: return a+7; case 2: return a+7; case 3: return a*a; case 4: return a<<2; case 5: return a<<2; case 6: return a-13; case 7: return a^0x33; default: return -1; } }",
    },
    Case {
        name: "osw_wide",
        arity: 1,
        c_source: "long long osw_wide(long long k){ switch(k){ case 0: return 10; case 1: return 21; case 2: return 32; case 3: return 43; case 4: return 54; case 5: return 65; case 6: return 76; case 7: return 87; default: return -1; } }",
    },
];

const OBJ_SWITCH_DISCS: &str =
    "-1000,-3,-1,0,1,2,3,4,5,6,7,8,9,50,98,99,100,101,102,103,104,105,106,107,108,109,110,200,1000";
const OBJ_SWITCH_AVALS: &str =
    "0,1,-1,2,-2,7,-7,123456,-654321,2147483647,-2147483648,0x7fffffffffffffffLL";

fn object_switch_lift(
    case: &Case,
    object_bytes: &[u8],
    abi: PseudoAbi,
) -> Option<(LeafRecovery, String)> {
    let (code, base): (Vec<u8>, u64) = function_code(object_bytes, case.name)?;
    let recovery: LeafRecovery =
        match recover_leaf_function_in_object(object_bytes, &code, base, abi, &[]) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skip {}: not recovered from object ({e})", case.name);
                return None;
            }
        };
    if !recovery.lifted_switch {
        eprintln!(
            "skip {}: this build did not lower into a dense jump table",
            case.name
        );
        return None;
    }
    let recovered_name: String = format!("rec_{}", case.name);
    let renamed: String = recovery
        .source
        .replacen(
            "uint64_t recovered(",
            &format!("uint64_t {recovered_name}("),
            1,
        )
        .lines()
        .filter(|l: &&str| !l.starts_with("#include"))
        .collect::<Vec<&str>>()
        .join("\n");
    Some((recovery, renamed))
}

fn object_switch_snippet(case: &Case, recovery: &LeafRecovery) -> String {
    let recovered_name: String = format!("rec_{}", case.name);
    let return_mask: String = if recovery.return_width_bits >= 64 {
        "0xFFFFFFFFFFFFFFFFULL".to_owned()
    } else {
        format!("0x{:x}ULL", (1u128 << recovery.return_width_bits) - 1)
    };
    let orig_args: String = match case.arity {
        1 => "k".to_owned(),
        _ => "k, a".to_owned(),
    };
    let rec_args: String = (0..recovery.params.len())
        .map(|i: usize| if i == 0 { "(uint64_t)k" } else { "(uint64_t)a" }.to_owned())
        .collect::<Vec<String>>()
        .join(", ");
    let name: &str = case.name;
    let mut snippet: String = String::new();
    let _ = write!(
        snippet,
        "    for (size_t di = 0; di < n_discs; di++) {{\n\
         \x20       long long k = discs[di];\n\
         \x20       for (size_t ai = 0; ai < n_avals; ai++) {{\n\
         \x20           long long a = avals[ai];\n\
         \x20           unsigned long long want = (unsigned long long){name}({orig_args}) & {return_mask};\n\
         \x20           unsigned long long got = (unsigned long long){recovered_name}({rec_args}) & {return_mask};\n\
         \x20           if (want != got) {{ printf(\"MISMATCH {name} k=%lld a=%lld want=%llu got=%llu\\n\", k, a, want, got); return 1; }}\n\
         \x20       }}\n\
         \x20   }}\n",
    );
    snippet
}

fn object_switch_extern(case: &Case) -> String {
    let sig: String = match case.arity {
        1 => "long long".to_owned(),
        _ => "long long, long long".to_owned(),
    };
    format!("extern long long {}({sig});", case.name)
}

fn build_object_switch_driver(recovered_decls: &str, driver_body: &str) -> String {
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n{recovered_decls}\n\
         int main(void) {{\n\
         \x20   long long discs[] = {{ {OBJ_SWITCH_DISCS} }};\n\
         \x20   long long avals[] = {{ {OBJ_SWITCH_AVALS} }};\n\
         \x20   size_t n_discs = sizeof(discs)/sizeof(discs[0]);\n\
         \x20   size_t n_avals = sizeof(avals)/sizeof(avals[0]);\n\
         {driver_body}\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n"
    )
}

fn object_switch_has_stacked_case(source: &str) -> bool {
    source.lines().any(|line: &str| {
        let trimmed: &str = line.trim();
        trimmed.starts_with("case ") && trimmed.ends_with(':')
    })
}

#[test]
fn object_dense_switch_recovers_bias_and_duplicates_hostabi() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; the sysv clang cross is the cross-platform guard"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!(
            "skipping object-switch oracle: gcc (needed for the dense jump-table idiom) not on PATH"
        );
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let mut battery_src: String = String::new();
    for case in OBJ_SWITCH_BATTERY {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let battery_c: PathBuf = dir.join("obj_switch_battery.c");
    std::fs::write(&battery_c, battery_src.as_bytes()).expect("write obj_switch_battery.c");
    let battery_o: PathBuf = dir.join("obj_switch_battery.o");
    let compile: std::process::Output = Command::new(&builder)
        .args([
            "-O1",
            "-fno-stack-protector",
            "-fno-if-conversion",
            "-fno-if-conversion2",
            "-fno-tree-loop-if-convert",
            "-c",
            "-o",
        ])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke gcc for object-switch battery");
    assert!(
        compile.status.success(),
        "object-switch battery compile failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read obj_switch_battery.o");

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    let mut saw_bias: bool = false;
    let mut saw_collapse: bool = false;
    for case in OBJ_SWITCH_BATTERY {
        let Some((recovery, renamed)): Option<(LeafRecovery, String)> =
            object_switch_lift(case, &object_bytes, HOST_ABI)
        else {
            continue;
        };
        if case.name == "osw_bias" {
            assert!(
                recovery.source.contains("case 100:"),
                "biased switch must carry the source case value, not a zero-based index: {}",
                recovery.source
            );
            saw_bias = true;
        }
        if case.name == "osw_dup" && object_switch_has_stacked_case(&recovery.source) {
            saw_collapse = true;
        }
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        recovered_decls.push_str(&object_switch_extern(case));
        recovered_decls.push('\n');
        driver_body.push_str(&object_switch_snippet(case, &recovery));
        lifted_count += 1;
    }
    assert!(
        lifted_count >= 2,
        "object-switch oracle must recover at least 2 of the {} battery functions, recovered {lifted_count}",
        OBJ_SWITCH_BATTERY.len()
    );
    assert!(
        saw_bias,
        "the biased switch osw_bias must be recovered with faithful case labels"
    );
    assert!(
        saw_collapse,
        "duplicate jump-table targets must collapse into stacked multi-value case labels"
    );

    let driver: String = build_object_switch_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("obj_switch_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write obj_switch_driver.c");
    let exe: PathBuf = dir.join(if cfg!(windows) {
        "obj_switch_harness.exe"
    } else {
        "obj_switch_harness"
    });
    let link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke gcc to link object-switch harness");
    assert!(
        link.status.success(),
        "object-switch harness link failed: {}\n--- driver ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );
    let BoundedRun::Exited(out): BoundedRun = run_bounded(&exe, 30) else {
        panic!("object-switch harness did not terminate within the watchdog window");
    };
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("OK") && !stdout.contains("MISMATCH"),
        "object-switch behavioral differential FAILED ({lifted_count} cases): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    println!(
        "object-switch differential PASSED for {lifted_count} functions (MS x64, full-domain sweep incl MIN-1/MAX+1, bias + duplicate-target collapse)"
    );
}

#[test]
fn sysv_object_dense_switch_recovers_bias_and_duplicates() {
    if !sysv_host_can_run() {
        return;
    }
    let mut battery_src: String = String::new();
    for case in OBJ_SWITCH_BATTERY {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let Some(objs): Option<SysvCrossObjects> = compile_sysv_cross("obj_switch", &battery_src)
    else {
        return;
    };
    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    for case in OBJ_SWITCH_BATTERY {
        let Some((recovery, renamed)): Option<(LeafRecovery, String)> =
            object_switch_lift(case, &objs.sysv_object, PseudoAbi::SysV)
        else {
            continue;
        };
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        recovered_decls.push_str(&object_switch_extern(case));
        recovered_decls.push('\n');
        driver_body.push_str(&object_switch_snippet(case, &recovery));
        lifted_count += 1;
    }
    assert!(
        lifted_count >= 1,
        "sysv object-switch oracle recovered no dense jump-table functions of {}",
        OBJ_SWITCH_BATTERY.len()
    );
    let driver: String = build_object_switch_driver(&recovered_decls, &driver_body);
    let stdout: String = link_and_run_sysv("obj_switch", &driver, &objs.host_object, 30);
    assert!(
        stdout.contains("OK") && !stdout.contains("MISMATCH"),
        "sysv object-switch behavioral differential FAILED ({lifted_count} cases): {stdout}"
    );
    println!(
        "sysv object-switch differential PASSED for {lifted_count} functions (SysV, full-domain sweep incl MIN-1/MAX+1)"
    );
}

#[test]
fn sysv_object_dense_switch_o0_relative_jump_table_recompiles() {
    if !sysv_host_can_run() {
        return;
    }
    let mut battery_src: String = String::new();
    for case in OBJ_SWITCH_BATTERY {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let Some(objs): Option<SysvCrossObjects> =
        compile_sysv_cross_extra("obj_switch_o0", &battery_src, &["-O0"])
    else {
        return;
    };
    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    for case in OBJ_SWITCH_BATTERY {
        let Some((recovery, renamed)): Option<(LeafRecovery, String)> =
            object_switch_lift(case, &objs.sysv_object, PseudoAbi::SysV)
        else {
            continue;
        };
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        recovered_decls.push_str(&object_switch_extern(case));
        recovered_decls.push('\n');
        driver_body.push_str(&object_switch_snippet(case, &recovery));
        lifted_count += 1;
    }
    if lifted_count == 0 {
        eprintln!(
            "sound-skip clang -O0 relative-jump-table oracle: this clang build emitted no lifter-supported dense-switch form across the {} case battery (every case soundly declined, no wrong output); the recovering path is exercised on toolchains that emit the supported range-check codegen",
            OBJ_SWITCH_BATTERY.len()
        );
        return;
    }
    let driver: String = build_object_switch_driver(&recovered_decls, &driver_body);
    let stdout: String = link_and_run_sysv("obj_switch_o0", &driver, &objs.host_object, 30);
    assert!(
        stdout.contains("OK") && !stdout.contains("MISMATCH"),
        "clang -O0 relative-jump-table differential FAILED ({lifted_count} cases): {stdout}"
    );
    println!(
        "clang -O0 relative-jump-table differential PASSED for {lifted_count} functions (single-lea movsxd, sub-checked memory-homed discriminant)"
    );
}

struct NarrowShiftStub {
    name: &'static str,
    mnemonic: &'static str,
    dest: &'static str,
}

const NARROW_SHIFT_STUBS: &[NarrowShiftStub] = &[
    NarrowShiftStub {
        name: "vsh8_shl",
        mnemonic: "shl",
        dest: "al",
    },
    NarrowShiftStub {
        name: "vsh8_shr",
        mnemonic: "shr",
        dest: "al",
    },
    NarrowShiftStub {
        name: "vsh8_sar",
        mnemonic: "sar",
        dest: "al",
    },
    NarrowShiftStub {
        name: "vsh16_shl",
        mnemonic: "shl",
        dest: "ax",
    },
    NarrowShiftStub {
        name: "vsh16_shr",
        mnemonic: "shr",
        dest: "ax",
    },
    NarrowShiftStub {
        name: "vsh16_sar",
        mnemonic: "sar",
        dest: "ax",
    },
];

fn narrow_shift_asm() -> String {
    let (arg0, arg1): (&str, &str) = if cfg!(windows) {
        ("ecx", "edx")
    } else {
        ("edi", "esi")
    };
    let mut asm: String = String::from("\t.intel_syntax noprefix\n\t.text\n");
    for stub in NARROW_SHIFT_STUBS {
        let _ = write!(
            asm,
            "\t.globl {name}\n{name}:\n\tmov eax, {arg0}\n\tmov ecx, {arg1}\n\t{mnem} {dest}, cl\n\tret\n",
            name = stub.name,
            mnem = stub.mnemonic,
            dest = stub.dest,
        );
    }
    asm
}

fn narrow_shift_driver(recovered_decls: &str, driver_body: &str) -> String {
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n{recovered_decls}\n\
         int main(void) {{\n\
         \x20   unsigned long long grid[][2] = {{\n\
         \x20       {{0xffULL,0}},{{0xffULL,1}},{{0xffULL,3}},{{0xffULL,7}},\n\
         \x20       {{0xffULL,8}},{{0xffULL,12}},{{0xffULL,20}},{{0xffULL,31}},\n\
         \x20       {{0x01ULL,8}},{{0x80ULL,20}},{{0xabULL,9}},{{0x5aULL,16}},\n\
         \x20       {{0x1234ULL,8}},{{0xffffULL,20}},{{0xbeefULL,15}},{{0xffffULL,31}},\n\
         \x20       {{0xffULL,40}},{{0x1234ULL,40}},{{0x7fULL,10}},{{0xfeedULL,17}}\n\
         \x20   }};\n\
         \x20   size_t n_inputs = sizeof(grid)/sizeof(grid[0]);\n\
         {driver_body}\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n"
    )
}

#[test]
fn narrow_variable_count_shift_matches_x86_masking() {
    if cfg!(target_os = "macos") || !cfg!(target_arch = "x86_64") {
        eprintln!(
            "skipping narrow variable-count shift differential: needs an x86-64 host to execute the assembled ground-truth stubs"
        );
        return;
    }
    let Some(compiler): Option<String> = cc() else {
        eprintln!("skipping narrow variable-count shift differential: no C compiler on PATH");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let asm_path: PathBuf = dir.join("narrow_shift_stub.s");
    std::fs::write(&asm_path, narrow_shift_asm().as_bytes()).expect("write shift stub asm");
    let object_path: PathBuf = dir.join("narrow_shift_stub.o");
    let assemble: std::process::Output = Command::new(&compiler)
        .args(["-c", "-o"])
        .arg(&object_path)
        .arg(&asm_path)
        .output()
        .expect("invoke cc to assemble narrow shift stub");
    if !assemble.status.success() {
        eprintln!(
            "skipping narrow variable-count shift differential: this cc cannot assemble the intel-syntax stub: {}",
            String::from_utf8_lossy(&assemble.stderr)
        );
        return;
    }
    let object_bytes: Vec<u8> = std::fs::read(&object_path).expect("read narrow shift object");

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    for stub in NARROW_SHIFT_STUBS {
        let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(&object_bytes, stub.name)
        else {
            eprintln!("skip {}: symbol not located", stub.name);
            continue;
        };
        let recovery: LeafRecovery = match recover_leaf_function_abi(&code, base, HOST_ABI) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skip {}: not in leaf class ({e})", stub.name);
                continue;
            }
        };
        assert_eq!(
            recovery.params.len(),
            2,
            "{} recovered with unexpected arity {}: {}",
            stub.name,
            recovery.params.len(),
            recovery.source
        );
        let recovered_name: String = format!("rec_{}", stub.name);
        let renamed: String = recovery
            .source
            .replacen(
                "uint64_t recovered(",
                &format!("uint64_t {recovered_name}("),
                1,
            )
            .lines()
            .filter(|l: &&str| !l.starts_with("#include"))
            .collect::<Vec<&str>>()
            .join("\n");
        recovered_decls.push_str(&renamed);
        recovered_decls.push('\n');
        let _ = writeln!(
            recovered_decls,
            "extern unsigned long long {}(unsigned long long, unsigned long long);",
            stub.name
        );
        let return_mask: String = if recovery.return_width_bits >= 64 {
            "0xFFFFFFFFFFFFFFFFULL".to_owned()
        } else {
            format!("0x{:x}ULL", (1u128 << recovery.return_width_bits) - 1)
        };
        let _ = write!(
            driver_body,
            "    for (size_t k = 0; k < n_inputs; k++) {{\n\
             \x20       unsigned long long x = grid[k][0], c = grid[k][1];\n\
             \x20       unsigned long long want = (unsigned long long){name}(x, c) & {return_mask};\n\
             \x20       unsigned long long got = {recovered_name}((uint64_t)x, (uint64_t)c) & {return_mask};\n\
             \x20       if (want != got) {{ printf(\"MISMATCH {name} x=%llu c=%llu want=%llu got=%llu\\n\", x, c, want, got); return 1; }}\n\
             \x20   }}\n",
            name = stub.name,
        );
        lifted_count += 1;
    }

    assert!(
        lifted_count == NARROW_SHIFT_STUBS.len(),
        "expected all {} narrow-shift stubs to enter the leaf class, only {lifted_count} did",
        NARROW_SHIFT_STUBS.len()
    );

    let driver: String = narrow_shift_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("narrow_shift_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write narrow shift driver");
    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "narrow_shift_harness.exe"
    } else {
        "narrow_shift_harness"
    });
    let link: std::process::Output = Command::new(&compiler)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&object_path)
        .output()
        .expect("invoke cc to link narrow shift harness");
    assert!(
        link.status.success(),
        "narrow shift harness link failed: {}\n--- driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );
    let run: std::process::Output = Command::new(&harness_exe)
        .output()
        .expect("run narrow shift harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK") && !stdout.contains("MISMATCH"),
        "narrow variable-count shift differential FAILED ({lifted_count} cases): {stdout}\nstderr: {}\n--- driver.c ---\n{driver}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "narrow variable-count shift differential PASSED for {lifted_count} stubs ({HOST_ABI:?} ABI)"
    );
}
