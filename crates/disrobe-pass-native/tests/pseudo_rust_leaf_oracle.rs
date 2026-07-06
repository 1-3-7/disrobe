#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unreadable_literal
)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_native::{
    Arch, FpConstant, JumpTable, LeafRecovery, PseudoAbi, PseudoScalarType, ResolvedCall,
    callee_int_arity, disassemble, recover_leaf_function_abi, recover_leaf_function_const_abi,
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

const ARITH_BATTERY: &[Case] = &[
    Case {
        name: "r_add",
        arity: 2,
        c_source: "long long r_add(long long a, long long b){ return a + b; }",
    },
    Case {
        name: "r_sub",
        arity: 2,
        c_source: "long long r_sub(long long a, long long b){ return a - b; }",
    },
    Case {
        name: "r_mul",
        arity: 2,
        c_source: "long long r_mul(long long a, long long b){ return a * b; }",
    },
    Case {
        name: "r_mix",
        arity: 2,
        c_source: "int r_mix(int a, int b){ return (a + b) * 3 - (a ^ b); }",
    },
    Case {
        name: "r_andor",
        arity: 3,
        c_source: "long long r_andor(long long a, long long b, long long c){ return (a & b) | (c & ~a); }",
    },
    Case {
        name: "r_shifts",
        arity: 1,
        c_source: "unsigned r_shifts(unsigned a){ return (a >> 2) | (a << 3); }",
    },
    Case {
        name: "r_sar",
        arity: 1,
        c_source: "long long r_sar(long long a){ return a >> 5; }",
    },
    Case {
        name: "r_mac",
        arity: 3,
        c_source: "long long r_mac(long long a, long long b, long long c){ return a * b + c; }",
    },
    Case {
        name: "r_neg",
        arity: 1,
        c_source: "long long r_neg(long long a){ return -a; }",
    },
    Case {
        name: "r_not",
        arity: 1,
        c_source: "long long r_not(long long a){ return ~a; }",
    },
    Case {
        name: "r_poly",
        arity: 2,
        c_source: "int r_poly(int a, int b){ return a * a + 2 * a * b + b * b; }",
    },
    Case {
        name: "r_abs",
        arity: 1,
        c_source: "long long r_abs(long long a){ return a < 0 ? -a : a; }",
    },
    Case {
        name: "r_max",
        arity: 2,
        c_source: "long long r_max(long long a, long long b){ return a > b ? a : b; }",
    },
    Case {
        name: "r_max32",
        arity: 2,
        c_source: "int r_max32(int a, int b){ return a > b ? a : b; }",
    },
    Case {
        name: "r_umax",
        arity: 2,
        c_source: "unsigned long long r_umax(unsigned long long a, unsigned long long b){ return a > b ? a : b; }",
    },
    Case {
        name: "r_sign",
        arity: 1,
        c_source: "long long r_sign(long long a){ if (a > 0) return 1; if (a < 0) return -1; return 0; }",
    },
    Case {
        name: "r_clamp",
        arity: 3,
        c_source: "long long r_clamp(long long a, long long lo, long long hi){ long long r = a; if (r < lo) r = lo; if (r > hi) r = hi; return r; }",
    },
];

const DIV_BATTERY: &[Case] = &[
    Case {
        name: "d_sdiv",
        arity: 2,
        c_source: "long long d_sdiv(long long a, long long b){ return a / b; }",
    },
    Case {
        name: "d_srem",
        arity: 2,
        c_source: "long long d_srem(long long a, long long b){ return a % b; }",
    },
    Case {
        name: "d_udiv",
        arity: 2,
        c_source: "unsigned d_udiv(unsigned a, unsigned b){ return a / b; }",
    },
    Case {
        name: "d_urem",
        arity: 2,
        c_source: "unsigned d_urem(unsigned a, unsigned b){ return a % b; }",
    },
    Case {
        name: "d_sdiv32",
        arity: 2,
        c_source: "int d_sdiv32(int a, int b){ return a / b; }",
    },
];

const ARITH_INPUTS: &[[i64; 3]] = &[
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
];

const DIV_INPUTS: &[[i64; 3]] = &[
    [1, 1, 0],
    [7, 3, 0],
    [-7, 3, 0],
    [7, -3, 0],
    [-7, -3, 0],
    [100, 7, 0],
    [-100, 7, 0],
    [2147483647, 3, 0],
    [-2147483648, 3, 0],
    [123456, -789, 0],
    [1000000007, 13, 0],
    [0, 5, 0],
    [-1, 5, 0],
    [1, -1, 0],
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

fn rustc() -> Option<String> {
    Command::new("rustc")
        .arg("--version")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
        .then(|| "rustc".to_owned())
}

fn scratch_dir() -> PathBuf {
    let dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe-pseudo-rust-{}", std::process::id()));
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

struct Prepared {
    name: String,
    arity: usize,
    params: usize,
    rw_bits: u32,
    rust: String,
}

fn prepare(case: &Case, object_bytes: &[u8], abi: PseudoAbi) -> Option<Prepared> {
    let (code, base): (Vec<u8>, u64) = function_code(object_bytes, case.name)?;
    let rec: LeafRecovery = match recover_leaf_function_abi(&code, base, abi) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("skip {} ({abi:?}): not in leaf class ({e})", case.name);
            return None;
        }
    };
    let rw_bits: u32 = rec.return_width_bits;
    let params: usize = rec.params.len();
    if params > 3 {
        eprintln!("skip {}: arity {params} beyond driver support", case.name);
        return None;
    }
    let Some(rust): Option<String> = rec.rust_source else {
        eprintln!(
            "skip {}: in leaf class but not pure-safe rust-emittable",
            case.name
        );
        return None;
    };
    let renamed: String = rust.replacen(
        "pub fn recovered(",
        &format!("pub fn rec_{}(", case.name),
        1,
    );
    Some(Prepared {
        name: case.name.to_owned(),
        arity: case.arity,
        params,
        rw_bits,
        rust: renamed,
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

fn build_c_driver(prepared: &[Prepared], inputs: &[[i64; 3]]) -> String {
    let mut decls: String = String::new();
    for p in prepared {
        let _ = writeln!(
            decls,
            "extern long long {}({});",
            p.name,
            vec!["long long"; p.arity].join(", ")
        );
    }
    let mut body: String = String::new();
    for p in prepared {
        let args: String = ["a", "b", "c"][..p.arity].join(", ");
        let _ = writeln!(
            body,
            "        printf(\"{} %zu %llu\\n\", k, (unsigned long long){}({args}) & {});",
            p.name,
            p.name,
            mask_c(p.rw_bits)
        );
    }
    let mut arr: String = String::new();
    for row in inputs {
        let _ = write!(arr, "{{{},{},{}}},", row[0], row[1], row[2]);
    }
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n{decls}\n\
         int main(void) {{\n\
         \x20   long long inputs[][3] = {{{arr}}};\n\
         \x20   size_t n = sizeof(inputs)/sizeof(inputs[0]);\n\
         \x20   for (size_t k = 0; k < n; k++) {{\n\
         \x20       long long a=inputs[k][0], b=inputs[k][1], c=inputs[k][2];\n\
         \x20       (void)a; (void)b; (void)c;\n\
         {body}\
         \x20   }}\n\
         \x20   return 0;\n\
         }}\n"
    )
}

fn build_rust_driver(prepared: &[Prepared], inputs: &[[i64; 3]]) -> String {
    let mut out: String = String::from("#![allow(unused, unused_parens, dead_code)]\n");
    for p in prepared {
        out.push_str(&p.rust);
        out.push('\n');
    }
    let mut body: String = String::new();
    for p in prepared {
        let args: String = ["a", "b", "c"][..p.params]
            .iter()
            .map(|s: &&str| format!("{s} as u64"))
            .collect::<Vec<String>>()
            .join(", ");
        let _ = writeln!(
            body,
            "        println!(\"{} {{}} {{}}\", k, rec_{}({args}) & {});",
            p.name,
            p.name,
            mask_rs(p.rw_bits)
        );
    }
    let mut arr: String = String::new();
    for row in inputs {
        let _ = write!(arr, "[{},{},{}],", row[0], row[1], row[2]);
    }
    let _ = write!(
        out,
        "fn main() {{\n\
         \x20   let inputs: [[i64; 3]; {}] = [{arr}];\n\
         \x20   for k in 0..inputs.len() {{\n\
         \x20       let a: i64 = inputs[k][0];\n\
         \x20       let b: i64 = inputs[k][1];\n\
         \x20       let c: i64 = inputs[k][2];\n\
         \x20       let _ = (a, b, c);\n\
         {body}\
         \x20   }}\n\
         }}\n",
        inputs.len()
    );
    out
}

fn parse_results(stdout: &str) -> BTreeMap<(String, u64), u64> {
    let mut map: BTreeMap<(String, u64), u64> = BTreeMap::new();
    for line in stdout.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if let [name, k, value] = cols.as_slice()
            && let (Ok(k), Ok(value)) = (k.parse::<u64>(), value.parse::<u64>())
        {
            map.insert(((*name).to_owned(), k), value);
        }
    }
    map
}

fn run_battery(tag: &str, battery: &[Case], inputs: &[[i64; 3]], rust_token: Option<&str>) {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native rust oracle class ({tag}) on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; the x86-64 ground-truth object requires the windows host"
        );
        return;
    }
    let Some(compiler): Option<String> = cc() else {
        eprintln!("skipping {tag}: no C compiler (gcc/clang/cc) on PATH");
        return;
    };
    let Some(rustc_bin): Option<String> = rustc() else {
        eprintln!("skipping {tag}: rustc not on PATH");
        return;
    };
    let dir: PathBuf = scratch_dir();

    let mut battery_src: String = String::new();
    for case in battery {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let battery_c: PathBuf = dir.join(format!("{tag}_battery.c"));
    std::fs::write(&battery_c, battery_src.as_bytes()).expect("write battery.c");
    let battery_o: PathBuf = dir.join(format!("{tag}_battery.o"));
    let compile: std::process::Output = Command::new(&compiler)
        .args(["-O1", "-fno-stack-protector", "-c", "-o"])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke cc for battery");
    assert!(
        compile.status.success(),
        "{tag} battery compile failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read battery.o");

    let prepared: Vec<Prepared> = battery
        .iter()
        .filter_map(|case: &Case| prepare(case, &object_bytes, HOST_ABI))
        .collect();
    if prepared.is_empty() {
        eprintln!(
            "skipping {tag} rust differential: this compiler build lowered none of the {} cases into the pure-safe rust class",
            battery.len()
        );
        return;
    }

    if let Some(token) = rust_token {
        let carriers: usize = prepared
            .iter()
            .filter(|p: &&Prepared| p.rust.contains(token))
            .count();
        assert!(
            carriers >= 1,
            "the {tag} rust oracle has no teeth: not one recovered function emitted a `{token}`, so the class was never graded"
        );
    }

    run_differential(
        tag, &prepared, inputs, &compiler, &rustc_bin, &dir, &battery_o,
    );
}

#[allow(clippy::too_many_arguments)]
fn run_differential(
    tag: &str,
    prepared: &[Prepared],
    inputs: &[[i64; 3]],
    compiler: &str,
    rustc_bin: &str,
    dir: &std::path::Path,
    battery_o: &std::path::Path,
) {
    let c_driver: String = build_c_driver(prepared, inputs);
    let c_driver_path: PathBuf = dir.join(format!("{tag}_ground.c"));
    std::fs::write(&c_driver_path, c_driver.as_bytes()).expect("write c driver");
    let c_exe: PathBuf = dir.join(format!("{tag}_ground.exe"));
    let c_link: std::process::Output = Command::new(compiler)
        .args(["-O1", "-o"])
        .arg(&c_exe)
        .arg(&c_driver_path)
        .arg(battery_o)
        .output()
        .expect("link c ground-truth");
    assert!(
        c_link.status.success(),
        "{tag} c ground-truth link failed: {}\n--- driver ---\n{c_driver}",
        String::from_utf8_lossy(&c_link.stderr)
    );
    let c_run: std::process::Output = Command::new(&c_exe).output().expect("run c ground-truth");
    assert!(c_run.status.success(), "{tag} c ground-truth run failed");
    let golden: BTreeMap<(String, u64), u64> =
        parse_results(&String::from_utf8_lossy(&c_run.stdout));

    let rust_driver: String = build_rust_driver(prepared, inputs);
    let rust_driver_path: PathBuf = dir.join(format!("{tag}_recovered.rs"));
    std::fs::write(&rust_driver_path, rust_driver.as_bytes()).expect("write rust driver");
    let rust_exe: PathBuf = dir.join(format!("{tag}_recovered.exe"));
    let rust_build: std::process::Output = Command::new(rustc_bin)
        .args(["--edition", "2021", "-C", "overflow-checks=on", "-o"])
        .arg(&rust_exe)
        .arg(&rust_driver_path)
        .output()
        .expect("invoke rustc for recovered rust");
    assert!(
        rust_build.status.success(),
        "{tag} recovered rust compile failed: {}\n--- recovered.rs ---\n{rust_driver}",
        String::from_utf8_lossy(&rust_build.stderr)
    );
    let rust_run: std::process::Output = Command::new(&rust_exe)
        .output()
        .expect("run recovered rust");
    assert!(
        rust_run.status.success(),
        "{tag} recovered rust run failed (overflow-checks caught a non-wrapping op or a poison divide): {}",
        String::from_utf8_lossy(&rust_run.stderr)
    );
    let got: BTreeMap<(String, u64), u64> =
        parse_results(&String::from_utf8_lossy(&rust_run.stdout));

    assert_eq!(
        golden.len(),
        got.len(),
        "{tag} result-count mismatch: c ground truth {} vs rust {}",
        golden.len(),
        got.len()
    );
    assert!(!golden.is_empty(), "{tag} produced no comparable results");
    for (key, want) in &golden {
        let have: u64 = *got
            .get(key)
            .unwrap_or_else(|| panic!("{tag} rust missing result for {key:?}"));
        assert_eq!(
            *want, have,
            "{tag} behavioral differential MISMATCH for {key:?}: c={want} rust={have}"
        );
    }
    println!(
        "{tag} rust recompile-equivalence PASSED for {} leaf functions across {} input vectors",
        prepared.len(),
        inputs.len()
    );
}

#[test]
fn arith_leaf_functions_recompile_to_rust_equivalence() {
    run_battery("arith", ARITH_BATTERY, ARITH_INPUTS, None);
}

#[test]
fn division_leaf_functions_recompile_to_rust_equivalence() {
    run_battery("div", DIV_BATTERY, DIV_INPUTS, None);
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

const SETCC_BATTERY: &[Case] = &[
    Case {
        name: "sc_lt",
        arity: 2,
        c_source: "long long sc_lt(long long a, long long b){ return a < b; }",
    },
    Case {
        name: "sc_ge",
        arity: 2,
        c_source: "long long sc_ge(long long a, long long b){ return a >= b; }",
    },
    Case {
        name: "sc_eq",
        arity: 2,
        c_source: "long long sc_eq(long long a, long long b){ return a == b; }",
    },
    Case {
        name: "sc_ult",
        arity: 2,
        c_source: "long long sc_ult(unsigned long long a, unsigned long long b){ return a < b; }",
    },
    Case {
        name: "sc_sum",
        arity: 3,
        c_source: "long long sc_sum(long long a, long long b, long long c){ return (a > b) + (b > c) + (a > c); }",
    },
];

const MINMAX_BATTERY: &[Case] = &[
    Case {
        name: "mm_max",
        arity: 2,
        c_source: "long long mm_max(long long a, long long b){ return a > b ? a : b; }",
    },
    Case {
        name: "mm_min",
        arity: 2,
        c_source: "long long mm_min(long long a, long long b){ return a < b ? a : b; }",
    },
    Case {
        name: "mm_umax",
        arity: 2,
        c_source: "unsigned long long mm_umax(unsigned long long a, unsigned long long b){ return a > b ? a : b; }",
    },
    Case {
        name: "mm_umin",
        arity: 2,
        c_source: "unsigned long long mm_umin(unsigned long long a, unsigned long long b){ return a < b ? a : b; }",
    },
    Case {
        name: "mm_abs",
        arity: 1,
        c_source: "long long mm_abs(long long a){ return a < 0 ? -a : a; }",
    },
    Case {
        name: "mm_clampsel",
        arity: 3,
        c_source: "long long mm_clampsel(long long a, long long b, long long c){ long long m = a > b ? a : b; return m < c ? m : c; }",
    },
];

#[test]
fn width_extension_leaf_functions_recompile_to_rust_equivalence() {
    run_battery("wx", WIDTH_EXT_BATTERY, ARITH_INPUTS, Some(" as u8"));
}

#[test]
fn width_extension_rust_oracle_also_grades_signed_casts() {
    run_battery(
        "wxs",
        &WIDTH_EXT_BATTERY[1..2],
        ARITH_INPUTS,
        Some(" as i8"),
    );
}

#[test]
fn setcc_boolean_leaf_functions_recompile_to_rust_equivalence() {
    run_battery(
        "setcc",
        SETCC_BATTERY,
        ARITH_INPUTS,
        Some("0xffffffffffffff00u64"),
    );
}

#[test]
fn branchless_minmax_leaf_functions_recompile_to_rust_equivalence() {
    run_battery("minmax", MINMAX_BATTERY, ARITH_INPUTS, Some("= if "));
}

fn gcc() -> Option<String> {
    Command::new("gcc")
        .arg("--version")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
        .then(|| "gcc".to_owned())
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

struct RustCallCase {
    caller: &'static str,
    arity: usize,
    c_source: &'static str,
}

const RUST_CALL_BATTERY: &[RustCallCase] = &[
    RustCallCase {
        caller: "kr_sq",
        arity: 1,
        c_source: "__attribute__((noinline,noclone)) long long hr_sq(long long x){ return x * x; }\n\
                   long long kr_sq(long long a){ return hr_sq(a) + 1; }",
    },
    RustCallCase {
        caller: "kr_addmul",
        arity: 2,
        c_source: "__attribute__((noinline,noclone)) long long hr_add(long long a, long long b){ return a + b; }\n\
                   long long kr_addmul(long long a, long long b){ return hr_add(a, b) * 2; }",
    },
    RustCallCase {
        caller: "kr_negret",
        arity: 1,
        c_source: "__attribute__((noinline,noclone)) long long hr_id(long long a){ return a + 100; }\n\
                   long long kr_negret(long long a){ return -hr_id(a); }",
    },
    RustCallCase {
        caller: "kr_xormix",
        arity: 2,
        c_source: "__attribute__((noinline,noclone)) long long hr_xor(long long a, long long b){ return (a ^ b) + 5; }\n\
                   long long kr_xormix(long long a, long long b){ return hr_xor(a, b) ^ 0x3f; }",
    },
];

const CALL_INPUTS: &[[i64; 2]] = &[
    [0, 0],
    [1, 1],
    [-1, -1],
    [7, 3],
    [-7, 3],
    [123456, -654321],
    [2147483647, 1],
    [-2147483648, -1],
    [100, 200],
    [-100, 50],
    [42, 42],
];

struct PreparedCall {
    caller: String,
    arity: usize,
    params: usize,
    rw_bits: u32,
    caller_rust: String,
    callee_defs: Vec<String>,
}

fn prepare_call(case: &RustCallCase, object_bytes: &[u8]) -> Option<PreparedCall> {
    let (code, base): (Vec<u8>, u64) = function_code(object_bytes, case.caller)?;
    let base_rec: LeafRecovery = match recover_leaf_function_abi(&code, base, HOST_ABI) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("skip {}: caller not in call leaf class ({e})", case.caller);
            return None;
        }
    };
    if base_rec.call_targets.is_empty() {
        return None;
    }
    let mut resolved: Vec<ResolvedCall> = Vec::new();
    let mut callee_defs: Vec<String> = Vec::new();
    let mut seen: Vec<u64> = Vec::new();
    for &target in &base_rec.call_targets {
        if seen.contains(&target) {
            continue;
        }
        seen.push(target);
        let (callee_code, callee_base, name): (Vec<u8>, u64, String) =
            function_code_at(object_bytes, target)?;
        let arity: usize = callee_int_arity(&callee_code, callee_base, HOST_ABI)?;
        let callee_rec: LeafRecovery =
            recover_leaf_function_abi(&callee_code, callee_base, HOST_ABI).ok()?;
        let callee_rust: String = callee_rec.rust_source?;
        let def: String = callee_rust.replacen(
            "pub fn recovered(",
            &format!("#[unsafe(no_mangle)]\n    pub extern \"C\" fn {name}("),
            1,
        );
        callee_defs.push(def);
        resolved.push(ResolvedCall {
            target,
            name: Some(name),
            arg_count: arity,
        });
    }
    let rec: LeafRecovery =
        recover_leaf_function_with_calls(&code, base, HOST_ABI, &resolved).ok()?;
    if rec.params.len() > 2 {
        eprintln!(
            "skip {}: recovered arity beyond 2-input driver",
            case.caller
        );
        return None;
    }
    let caller_rust: String = rec.rust_source?;
    let renamed: String = caller_rust.replacen(
        "pub fn recovered(",
        &format!("pub fn rec_{}(", case.caller),
        1,
    );
    Some(PreparedCall {
        caller: case.caller.to_owned(),
        arity: case.arity,
        params: rec.params.len(),
        rw_bits: rec.return_width_bits,
        caller_rust: renamed,
        callee_defs,
    })
}

fn build_c_call_golden(prepared: &[PreparedCall], inputs: &[[i64; 2]]) -> String {
    let mut decls: String = String::new();
    for p in prepared {
        let _ = writeln!(
            decls,
            "extern long long {}({});",
            p.caller,
            vec!["long long"; p.arity].join(", ")
        );
    }
    let mut body: String = String::new();
    for p in prepared {
        let args: String = ["a", "b"][..p.arity].join(", ");
        let _ = writeln!(
            body,
            "        printf(\"{} %zu %llu\\n\", k, (unsigned long long){}({args}) & {});",
            p.caller,
            p.caller,
            mask_c(p.rw_bits)
        );
    }
    let mut arr: String = String::new();
    for row in inputs {
        let _ = write!(arr, "{{{},{}}},", row[0], row[1]);
    }
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n{decls}\n\
         int main(void) {{\n\
         \x20   long long inputs[][2] = {{{arr}}};\n\
         \x20   size_t n = sizeof(inputs)/sizeof(inputs[0]);\n\
         \x20   for (size_t k = 0; k < n; k++) {{\n\
         \x20       long long a=inputs[k][0], b=inputs[k][1];\n\
         \x20       (void)a; (void)b;\n\
         {body}\
         \x20   }}\n\
         \x20   return 0;\n\
         }}\n"
    )
}

fn build_rust_call_driver(prepared: &[PreparedCall], inputs: &[[i64; 2]]) -> String {
    let mut out: String = String::from("#![allow(unused, unused_parens, dead_code)]\n");
    out.push_str("mod recovered_helpers {\n");
    for p in prepared {
        for def in &p.callee_defs {
            out.push_str(def);
            out.push('\n');
        }
    }
    out.push_str("}\n");
    for p in prepared {
        out.push_str(&p.caller_rust);
        out.push('\n');
    }
    let mut body: String = String::new();
    for p in prepared {
        let args: String = ["a", "b"][..p.params]
            .iter()
            .map(|s: &&str| format!("{s} as u64"))
            .collect::<Vec<String>>()
            .join(", ");
        let _ = writeln!(
            body,
            "        println!(\"{} {{}} {{}}\", k, rec_{}({args}) & {});",
            p.caller,
            p.caller,
            mask_rs(p.rw_bits)
        );
    }
    let mut arr: String = String::new();
    for row in inputs {
        let _ = write!(arr, "[{},{}],", row[0], row[1]);
    }
    let _ = write!(
        out,
        "fn main() {{\n\
         \x20   let inputs: [[i64; 2]; {}] = [{arr}];\n\
         \x20   for k in 0..inputs.len() {{\n\
         \x20       let a: i64 = inputs[k][0];\n\
         \x20       let b: i64 = inputs[k][1];\n\
         \x20       let _ = (a, b);\n\
         {body}\
         \x20   }}\n\
         }}\n",
        inputs.len()
    );
    out
}

#[test]
fn call_leaf_functions_recompile_to_rust_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native rust call oracle on non-windows: the x86-64 ground-truth object requires the windows host"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!(
            "skipping rust call oracle: gcc (needed for the noinline call idiom) not on PATH"
        );
        return;
    };
    let Some(rustc_bin): Option<String> = rustc() else {
        eprintln!("skipping rust call oracle: rustc not on PATH");
        return;
    };
    let dir: PathBuf = scratch_dir();

    let mut battery_src: String = String::new();
    for case in RUST_CALL_BATTERY {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let battery_c: PathBuf = dir.join("rustcall_battery.c");
    std::fs::write(&battery_c, battery_src.as_bytes()).expect("write rustcall_battery.c");
    let battery_o: PathBuf = dir.join("rustcall_battery.o");
    let compile: std::process::Output = Command::new(&builder)
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
        .expect("invoke gcc for rust call battery");
    assert!(
        compile.status.success(),
        "rust call battery compile failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read rustcall_battery.o");

    let prepared: Vec<PreparedCall> = RUST_CALL_BATTERY
        .iter()
        .filter_map(|case: &RustCallCase| prepare_call(case, &object_bytes))
        .collect();
    if prepared.is_empty() {
        eprintln!(
            "skipping rust call differential: this build lowered none of the {} caller/helper pairs into the pure-safe rust call class",
            RUST_CALL_BATTERY.len()
        );
        return;
    }

    let c_driver: String = build_c_call_golden(&prepared, CALL_INPUTS);
    let c_driver_path: PathBuf = dir.join("rustcall_ground.c");
    std::fs::write(&c_driver_path, c_driver.as_bytes()).expect("write rustcall ground");
    let c_exe: PathBuf = dir.join("rustcall_ground.exe");
    let c_link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&c_exe)
        .arg(&c_driver_path)
        .arg(&battery_o)
        .output()
        .expect("link c call ground-truth");
    assert!(
        c_link.status.success(),
        "rust call c ground-truth link failed: {}\n--- driver ---\n{c_driver}",
        String::from_utf8_lossy(&c_link.stderr)
    );
    let c_run: std::process::Output = Command::new(&c_exe).output().expect("run c ground-truth");
    assert!(
        c_run.status.success(),
        "rust call c ground-truth run failed"
    );
    let golden: BTreeMap<(String, u64), u64> =
        parse_results(&String::from_utf8_lossy(&c_run.stdout));

    let rust_driver: String = build_rust_call_driver(&prepared, CALL_INPUTS);
    let rust_driver_path: PathBuf = dir.join("rustcall_recovered.rs");
    std::fs::write(&rust_driver_path, rust_driver.as_bytes()).expect("write rust call driver");
    let rust_exe: PathBuf = dir.join("rustcall_recovered.exe");
    let rust_build: std::process::Output = Command::new(&rustc_bin)
        .args(["--edition", "2021", "-C", "overflow-checks=on", "-o"])
        .arg(&rust_exe)
        .arg(&rust_driver_path)
        .output()
        .expect("invoke rustc for recovered rust call module");
    assert!(
        rust_build.status.success(),
        "recovered rust call module compile failed: {}\n--- recovered.rs ---\n{rust_driver}",
        String::from_utf8_lossy(&rust_build.stderr)
    );
    let rust_run: std::process::Output = Command::new(&rust_exe)
        .output()
        .expect("run recovered rust call module");
    assert!(
        rust_run.status.success(),
        "recovered rust call run failed: {}",
        String::from_utf8_lossy(&rust_run.stderr)
    );
    let got: BTreeMap<(String, u64), u64> =
        parse_results(&String::from_utf8_lossy(&rust_run.stdout));

    assert!(
        !golden.is_empty(),
        "rust call produced no comparable results"
    );
    assert_eq!(
        golden.len(),
        got.len(),
        "rust call result-count mismatch: c {} vs rust {}",
        golden.len(),
        got.len()
    );
    for (key, want) in &golden {
        let have: u64 = *got
            .get(key)
            .unwrap_or_else(|| panic!("rust call missing result for {key:?}"));
        assert_eq!(
            *want, have,
            "rust call behavioral differential MISMATCH for {key:?}: c={want} rust={have}"
        );
    }
    println!(
        "rust call recompile-equivalence PASSED for {} caller/helper pairs across {} input vectors",
        prepared.len(),
        CALL_INPUTS.len()
    );
}

const CF_MB_BATTERY: &[Case] = &[
    Case {
        name: "rc_cap",
        arity: 2,
        c_source: "long long rc_cap(long long a, long long b){ long long r = a + b; if (a > b) r += 10; return r; }",
    },
    Case {
        name: "rc_absdiff",
        arity: 2,
        c_source: "long long rc_absdiff(long long a, long long b){ long long r; if (a > b) { r = a - b; } else { r = b - a; } return r; }",
    },
    Case {
        name: "rc_sel3",
        arity: 3,
        c_source: "long long rc_sel3(long long a, long long b, long long c){ long long r; if (a > 0) { r = b + c; } else { r = b - c; } return r * 2; }",
    },
    Case {
        name: "rc_sign",
        arity: 1,
        c_source: "long long rc_sign(long long a){ if (a > 0) return 1; if (a < 0) return -1; return 0; }",
    },
    Case {
        name: "rc_clamp",
        arity: 3,
        c_source: "long long rc_clamp(long long a, long long lo, long long hi){ long long r = a; if (r < lo) r = lo; if (r > hi) r = hi; return r; }",
    },
];

const LOOP_MB_BATTERY: &[Case] = &[
    Case {
        name: "rl_sum",
        arity: 1,
        c_source: "long long rl_sum(long long n){ long long s = 0; long long i = 0; do { i++; s += i; } while (i != n); return s; }",
    },
    Case {
        name: "rl_mul",
        arity: 2,
        c_source: "long long rl_mul(long long a, long long n){ long long r = 0; long long i = 0; do { r += a; i++; } while (i != n); return r; }",
    },
    Case {
        name: "rl_fact",
        arity: 1,
        c_source: "long long rl_fact(long long n){ long long r = 1; long long i = 1; do { r *= i; i++; } while (i != n + 1); return r; }",
    },
    Case {
        name: "rl_pow2",
        arity: 1,
        c_source: "long long rl_pow2(long long k){ long long r = 1; long long i = 0; do { r += r; i++; } while (i != k); return r; }",
    },
    Case {
        name: "rl_count",
        arity: 1,
        c_source: "long long rl_count(long long n){ long long c = 0; long long i = n; do { c++; i--; } while (i != 0); return c; }",
    },
    Case {
        name: "rl_acc",
        arity: 2,
        c_source: "long long rl_acc(long long a, long long n){ long long r = a; long long i = 0; do { r += a; i++; } while (i != n); return r; }",
    },
    Case {
        name: "rl_gauss",
        arity: 2,
        c_source: "long long rl_gauss(long long a, long long n){ long long r = 0; long long i = 0; do { r += a + i; i++; } while (i != n); return r; }",
    },
    Case {
        name: "rl_popcount",
        arity: 1,
        c_source: "long long rl_popcount(unsigned long long x){ long long c = 0; do { c += (long long)(x & 1); x >>= 1; } while (x != 0); return c; }",
    },
];

const LOOP_MB_INPUTS: &[[i64; 3]] = &[
    [1, 1, 0],
    [2, 2, 0],
    [3, 1, 0],
    [4, 3, 0],
    [5, 2, 0],
    [6, 4, 0],
    [7, 7, 0],
    [8, 3, 0],
    [10, 5, 0],
    [12, 6, 0],
    [16, 4, 0],
    [20, 7, 0],
];

fn recovered_c_source(object_bytes: &[u8], name: &str) -> Option<String> {
    let (code, base): (Vec<u8>, u64) = function_code(object_bytes, name)?;
    recover_leaf_function_abi(&code, base, HOST_ABI)
        .ok()
        .map(|r: LeafRecovery| r.source)
}

fn run_bounded_output(exe: &std::path::Path, secs: u64) -> Option<std::process::Output> {
    use std::process::Stdio;
    use wait_timeout::ChildExt as _;

    let mut child: std::process::Child = Command::new(exe)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bounded harness");
    if child
        .wait_timeout(std::time::Duration::from_secs(secs))
        .expect("wait_timeout")
        .is_some()
    {
        Some(child.wait_with_output().expect("collect harness output"))
    } else {
        let _ = child.kill();
        let _ = child.wait();
        None
    }
}

fn run_multiblock_battery(
    tag: &str,
    battery: &[Case],
    inputs: &[[i64; 3]],
    c_structure_token: &str,
    rust_structure_token: Option<&str>,
) {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native rust multi-block oracle ({tag}) on non-windows: the x86-64 ground-truth object requires the windows host"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!(
            "skipping {tag}: gcc (needed to suppress if-conversion into a real branch CFG) not on PATH"
        );
        return;
    };
    let Some(rustc_bin): Option<String> = rustc() else {
        eprintln!("skipping {tag}: rustc not on PATH");
        return;
    };
    let dir: PathBuf = scratch_dir();

    let mut battery_src: String = String::new();
    for case in battery {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let battery_c: PathBuf = dir.join(format!("{tag}_battery.c"));
    std::fs::write(&battery_c, battery_src.as_bytes()).expect("write multi-block battery.c");
    let battery_o: PathBuf = dir.join(format!("{tag}_battery.o"));
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
        .expect("invoke gcc for multi-block battery");
    assert!(
        compile.status.success(),
        "{tag} battery compile failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read multi-block battery.o");

    let prepared: Vec<Prepared> = battery
        .iter()
        .filter_map(|case: &Case| prepare(case, &object_bytes, HOST_ABI))
        .collect();
    if prepared.is_empty() {
        eprintln!(
            "skipping {tag} rust multi-block differential: this build lowered none of the {} cases into the pure-safe rust class",
            battery.len()
        );
        return;
    }

    let structured_ir: usize = battery
        .iter()
        .filter(|case: &&Case| {
            recovered_c_source(&object_bytes, case.name)
                .is_some_and(|src: String| src.contains(c_structure_token))
        })
        .count();
    assert!(
        structured_ir >= 1,
        "the {tag} rust multi-block oracle has no teeth: not one recovered function carried a `{c_structure_token}` region, so the multi-block structurer was never exercised"
    );
    if let Some(rust_token) = rust_structure_token {
        let structured_rust: usize = prepared
            .iter()
            .filter(|p: &&Prepared| p.rust.contains(rust_token))
            .count();
        assert!(
            structured_rust >= 1,
            "the {tag} rust backend never emitted a `{rust_token}`: the multi-block rust path is not being graded"
        );
    }

    let c_driver: String = build_c_driver(&prepared, inputs);
    let c_driver_path: PathBuf = dir.join(format!("{tag}_ground.c"));
    std::fs::write(&c_driver_path, c_driver.as_bytes()).expect("write c driver");
    let c_exe: PathBuf = dir.join(format!("{tag}_ground.exe"));
    let c_link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&c_exe)
        .arg(&c_driver_path)
        .arg(&battery_o)
        .output()
        .expect("link c ground-truth");
    assert!(
        c_link.status.success(),
        "{tag} c ground-truth link failed: {}\n--- driver ---\n{c_driver}",
        String::from_utf8_lossy(&c_link.stderr)
    );
    let c_out: std::process::Output = run_bounded_output(&c_exe, 30)
        .unwrap_or_else(|| panic!("{tag} c ground-truth did not terminate within the watchdog"));
    assert!(c_out.status.success(), "{tag} c ground-truth run failed");
    let golden: BTreeMap<(String, u64), u64> =
        parse_results(&String::from_utf8_lossy(&c_out.stdout));

    let rust_driver: String = build_rust_driver(&prepared, inputs);
    let rust_driver_path: PathBuf = dir.join(format!("{tag}_recovered.rs"));
    std::fs::write(&rust_driver_path, rust_driver.as_bytes()).expect("write rust driver");
    let rust_exe: PathBuf = dir.join(format!("{tag}_recovered.exe"));
    let rust_build: std::process::Output = Command::new(&rustc_bin)
        .args(["--edition", "2021", "-C", "overflow-checks=on", "-o"])
        .arg(&rust_exe)
        .arg(&rust_driver_path)
        .output()
        .expect("invoke rustc for recovered rust");
    assert!(
        rust_build.status.success(),
        "{tag} recovered rust compile failed: {}\n--- recovered.rs ---\n{rust_driver}",
        String::from_utf8_lossy(&rust_build.stderr)
    );
    let rust_out: std::process::Output = run_bounded_output(&rust_exe, 30).unwrap_or_else(|| {
        panic!(
            "{tag} recovered rust did not terminate within the watchdog; a recovered loop is non-terminating"
        )
    });
    assert!(
        rust_out.status.success(),
        "{tag} recovered rust run failed (overflow-checks caught a non-wrapping op or a poison divide): {}",
        String::from_utf8_lossy(&rust_out.stderr)
    );
    let got: BTreeMap<(String, u64), u64> =
        parse_results(&String::from_utf8_lossy(&rust_out.stdout));

    assert!(!golden.is_empty(), "{tag} produced no comparable results");
    assert_eq!(
        golden.len(),
        got.len(),
        "{tag} result-count mismatch: c ground truth {} vs rust {}",
        golden.len(),
        got.len()
    );
    for (key, want) in &golden {
        let have: u64 = *got
            .get(key)
            .unwrap_or_else(|| panic!("{tag} rust missing result for {key:?}"));
        assert_eq!(
            *want, have,
            "{tag} multi-block behavioral differential MISMATCH for {key:?}: c={want} rust={have}"
        );
    }
    println!(
        "{tag} rust multi-block recompile-equivalence PASSED for {} functions ({structured_ir} structured) across {} input vectors",
        prepared.len(),
        inputs.len()
    );
}

#[test]
fn control_flow_leaf_functions_recompile_to_rust_equivalence() {
    run_multiblock_battery("cf", CF_MB_BATTERY, ARITH_INPUTS, "if (", None);
}

#[test]
fn natural_loop_leaf_functions_recompile_to_rust_equivalence() {
    run_multiblock_battery(
        "loop",
        LOOP_MB_BATTERY,
        LOOP_MB_INPUTS,
        "do {",
        Some("loop {"),
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
    Case {
        name: "sw_dup",
        arity: 2,
        c_source: "long long sw_dup(long long x, long long a){ long long r; switch (x) { case 0: r = a + 7; break; case 1: r = a + 7; break; case 2: r = a + 7; break; case 3: r = a * a; break; case 4: r = a << 2; break; case 5: r = a << 2; break; case 6: r = a - 13; break; default: r = -1; break; } return r; }",
    },
];

const SWITCH_AB_PAIRS: &[[i64; 2]] = &[
    [0, 0],
    [1, 1],
    [-1, 1],
    [7, 3],
    [-7, 3],
    [7, -3],
    [3, 5],
    [123456, -654321],
    [2147483647, 1],
    [-2147483648, -1],
    [42, 42],
    [100, 200],
];

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

        let mut slots: BTreeMap<u64, i32> = BTreeMap::new();
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

fn prepare_switch(case: &Case, object_bytes: &[u8]) -> Option<Prepared> {
    let (code, base): (Vec<u8>, u64) = function_code(object_bytes, case.name)?;
    let tables: Vec<JumpTable> = resolve_switch_tables(object_bytes, &code, base)?;
    if tables.is_empty() {
        eprintln!("skip {}: no jump table resolved this build", case.name);
        return None;
    }
    let rec: LeafRecovery = match recover_leaf_function_switch_abi(&code, base, HOST_ABI, &tables) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("skip {}: not in dense-switch class ({e})", case.name);
            return None;
        }
    };
    if !rec.lifted_switch {
        return None;
    }
    let params: usize = rec.params.len();
    if params > 3 {
        eprintln!("skip {}: arity {params} beyond driver support", case.name);
        return None;
    }
    let Some(rust): Option<String> = rec.rust_source else {
        eprintln!(
            "skip {}: dense switch but not pure-safe rust-emittable (frame/mem/fp)",
            case.name
        );
        return None;
    };
    let renamed: String = rust.replacen(
        "pub fn recovered(",
        &format!("pub fn rec_{}(", case.name),
        1,
    );
    Some(Prepared {
        name: case.name.to_owned(),
        arity: case.arity,
        params,
        rw_bits: rec.return_width_bits,
        rust: renamed,
    })
}

#[test]
fn switch_dense_jump_table_leaf_functions_recompile_to_rust_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native rust switch oracle on non-windows: the x86-64 ground-truth object requires the windows host"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!(
            "skipping rust switch oracle: gcc (needed for the dense jump-table idiom) not on PATH"
        );
        return;
    };
    let Some(rustc_bin): Option<String> = rustc() else {
        eprintln!("skipping rust switch oracle: rustc not on PATH");
        return;
    };
    let dir: PathBuf = scratch_dir();

    let mut battery_src: String = String::new();
    for case in SWITCH_BATTERY {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let battery_c: PathBuf = dir.join("rustswitch_battery.c");
    std::fs::write(&battery_c, battery_src.as_bytes()).expect("write rustswitch_battery.c");
    let battery_o: PathBuf = dir.join("rustswitch_battery.o");
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
        .expect("invoke gcc for switch battery");
    assert!(
        compile.status.success(),
        "switch battery compile failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read rustswitch_battery.o");

    let prepared: Vec<Prepared> = SWITCH_BATTERY
        .iter()
        .filter_map(|case: &Case| prepare_switch(case, &object_bytes))
        .collect();
    if prepared.is_empty() {
        eprintln!(
            "skipping rust switch differential: this gcc build reconstructed none of the {} cases into a dense-switch pure-safe rust function",
            SWITCH_BATTERY.len()
        );
        return;
    }

    let match_carriers: usize = prepared
        .iter()
        .filter(|p: &&Prepared| p.rust.contains("match "))
        .count();
    assert!(
        match_carriers >= 1,
        "the rust switch oracle has no teeth: not one recovered dense switch emitted a `match`, so the jump-table-to-match path was never graded"
    );
    if let Some(dup) = prepared.iter().find(|p: &&Prepared| p.name == "sw_dup") {
        assert!(
            dup.rust.contains(" | "),
            "sw_dup recovered but did not coalesce its duplicate case bodies into a `|` match arm; the multi-value switch path is not graded"
        );
    }

    let mut switch_inputs: Vec<[i64; 3]> = Vec::new();
    for disc in -2i64..=8 {
        for pair in SWITCH_AB_PAIRS {
            switch_inputs.push([disc, pair[0], pair[1]]);
        }
    }

    run_differential(
        "rustswitch",
        &prepared,
        &switch_inputs,
        &builder,
        &rustc_bin,
        &dir,
        &battery_o,
    );
}

fn clang() -> Option<String> {
    Command::new("clang")
        .arg("--version")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
        .then(|| "clang".to_owned())
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
        name: "fv_sqrtd",
        args: &[FpArg::Double],
        ret: FpRet::Double,
        c_source: "double fv_sqrtd(double a){ return __builtin_sqrt(a); }",
    },
    FpCase {
        name: "fv_sqrts",
        args: &[FpArg::Float],
        ret: FpRet::Float,
        c_source: "float fv_sqrts(float a){ return __builtin_sqrtf(a); }",
    },
    FpCase {
        name: "fv_floor",
        args: &[FpArg::Double],
        ret: FpRet::Double,
        c_source: "double fv_floor(double a){ return __builtin_floor(a); }",
    },
    FpCase {
        name: "fv_ceil",
        args: &[FpArg::Double],
        ret: FpRet::Double,
        c_source: "double fv_ceil(double a){ return __builtin_ceil(a); }",
    },
    FpCase {
        name: "fv_trunc",
        args: &[FpArg::Double],
        ret: FpRet::Double,
        c_source: "double fv_trunc(double a){ return __builtin_trunc(a); }",
    },
    FpCase {
        name: "fv_roundeven",
        args: &[FpArg::Double],
        ret: FpRet::Double,
        c_source: "double fv_roundeven(double a){ return __builtin_roundeven(a); }",
    },
];

const FP_PAIRS: &[[f64; 2]] = &[
    [0.0, 1.0],
    [1.0, 1.0],
    [-1.0, 1.0],
    [7.0, 3.0],
    [-7.0, 3.0],
    [7.0, -3.0],
    [3.5, 2.25],
    [-3.5, 2.25],
    [100.0, 7.0],
    [-100.0, -7.0],
    [0.1, 0.2],
    [123456.75, 789.5],
    [2147483647.0, 3.0],
    [1e18, 1000.0],
    [-1e18, 3.0],
    [42.0, 42.0],
    [5.0, 9.0],
    [0.0, -7.0],
    [1e-30, 1000000.0],
    [-0.0, 4.0],
];

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

struct PreparedFp {
    name: String,
    args: &'static [FpArg],
    ret: FpRet,
    rust: String,
}

fn prepare_fp(case: &FpCase, object_bytes: &[u8], abi: PseudoAbi) -> Option<PreparedFp> {
    let (code, base): (Vec<u8>, u64) = function_code(object_bytes, case.name)?;
    let consts: Vec<FpConstant> = resolve_fp_constants(object_bytes, &code, base);
    let rec: LeafRecovery = match recover_leaf_function_const_abi(&code, base, abi, &consts) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "skip {} ({abi:?}): not in scalar float leaf class ({e})",
                case.name
            );
            return None;
        }
    };
    let Some(rust): Option<String> = rec.rust_source else {
        eprintln!(
            "skip {}: scalar float leaf but not pure-safe rust-emittable",
            case.name
        );
        return None;
    };
    let total_params: usize = rec.fp_params.len();
    if total_params != case.args.len() {
        eprintln!(
            "skip {}: recovered {total_params} params but source declares {}",
            case.name,
            case.args.len()
        );
        return None;
    }
    let renamed: String = rust.replacen(
        "pub fn recovered(",
        &format!("pub fn rec_{}(", case.name),
        1,
    );
    Some(PreparedFp {
        name: case.name.to_owned(),
        args: case.args,
        ret: case.ret,
        rust: renamed,
    })
}

fn fp_arg_expr_c(arg: FpArg, slot: usize) -> String {
    match arg {
        FpArg::Double => format!("pairs[k][{slot}]"),
        FpArg::Float => format!("(float)pairs[k][{slot}]"),
        FpArg::LongLong => format!("(long long)pairs[k][{slot}]"),
        FpArg::Int => format!("(int)pairs[k][{slot}]"),
    }
}

fn fp_arg_expr_rs(arg: FpArg, slot: usize) -> String {
    match arg {
        FpArg::Double => format!("pairs[k][{slot}]"),
        FpArg::Float => format!("(pairs[k][{slot}] as f32)"),
        FpArg::LongLong => format!("((pairs[k][{slot}] as i64) as u64)"),
        FpArg::Int => format!("((pairs[k][{slot}] as i32) as u32 as u64)"),
    }
}

const fn fp_c_ret(ret: FpRet) -> &'static str {
    match ret {
        FpRet::Double => "double",
        FpRet::Float => "float",
        FpRet::LongLong => "long long",
    }
}

const fn fp_c_bits_fn(ret: FpRet) -> &'static str {
    match ret {
        FpRet::Double => "d_bits",
        FpRet::Float => "f_bits",
        FpRet::LongLong => "i_bits",
    }
}

fn build_fp_c_golden(prepared: &[PreparedFp]) -> String {
    let mut decls: String = String::new();
    for p in prepared {
        let argtypes: Vec<&str> = p.args.iter().map(|a: &FpArg| a.c_type()).collect();
        let sig: String = if argtypes.is_empty() {
            "void".to_owned()
        } else {
            argtypes.join(", ")
        };
        let _ = writeln!(decls, "extern {} {}({sig});", fp_c_ret(p.ret), p.name);
    }
    let mut body: String = String::new();
    for p in prepared {
        let args: String = p
            .args
            .iter()
            .enumerate()
            .map(|(slot, a): (usize, &FpArg)| fp_arg_expr_c(*a, slot))
            .collect::<Vec<String>>()
            .join(", ");
        let _ = writeln!(
            body,
            "        printf(\"{} %zu %llu\\n\", k, (unsigned long long){}({}({args})));",
            p.name,
            fp_c_bits_fn(p.ret),
            p.name
        );
    }
    let mut arr: String = String::new();
    for row in FP_PAIRS {
        let _ = write!(arr, "{{{:e},{:e}}},", row[0], row[1]);
    }
    format!(
        "#include <stdint.h>\n#include <string.h>\n#include <stdio.h>\n#include <stddef.h>\n\
         static uint64_t d_bits(double v){{ uint64_t b; memcpy(&b,&v,8); return b; }}\n\
         static uint32_t f_bits(float v){{ uint32_t b; memcpy(&b,&v,4); return b; }}\n\
         static uint64_t i_bits(long long v){{ uint64_t b; memcpy(&b,&v,8); return b; }}\n\
         {decls}\n\
         int main(void) {{\n\
         \x20   double pairs[][2] = {{{arr}}};\n\
         \x20   size_t n = sizeof(pairs)/sizeof(pairs[0]);\n\
         \x20   for (size_t k = 0; k < n; k++) {{\n\
         {body}\
         \x20   }}\n\
         \x20   return 0;\n\
         }}\n"
    )
}

fn build_fp_rust_driver(prepared: &[PreparedFp]) -> String {
    let mut out: String = String::from("#![allow(unused, unused_parens, dead_code)]\n");
    for p in prepared {
        out.push_str(&p.rust);
        out.push('\n');
    }
    let mut body: String = String::new();
    for p in prepared {
        let args: String = p
            .args
            .iter()
            .enumerate()
            .map(|(slot, a): (usize, &FpArg)| fp_arg_expr_rs(*a, slot))
            .collect::<Vec<String>>()
            .join(", ");
        let bits: String = match p.ret {
            FpRet::Double => format!("rec_{}({args}).to_bits()", p.name),
            FpRet::Float => format!("(rec_{}({args}).to_bits() as u64)", p.name),
            FpRet::LongLong => format!("rec_{}({args})", p.name),
        };
        let _ = writeln!(
            body,
            "        println!(\"{} {{}} {{}}\", k, {bits});",
            p.name
        );
    }
    let mut arr: String = String::new();
    for row in FP_PAIRS {
        let _ = write!(arr, "[{:e},{:e}],", row[0], row[1]);
    }
    let _ = write!(
        out,
        "fn main() {{\n\
         \x20   let pairs: [[f64; 2]; {}] = [{arr}];\n\
         \x20   for k in 0..pairs.len() {{\n\
         {body}\
         \x20   }}\n\
         }}\n",
        FP_PAIRS.len()
    );
    out
}

#[test]
fn scalar_float_leaf_functions_recompile_to_rust_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native rust scalar-float oracle on non-windows: the x86-64 ground-truth object requires the windows host"
        );
        return;
    }
    let Some(builder): Option<String> = clang() else {
        eprintln!(
            "skipping rust scalar-float oracle: clang (needed for a clean scalar SSE lowering) not on PATH"
        );
        return;
    };
    let Some(rustc_bin): Option<String> = rustc() else {
        eprintln!("skipping rust scalar-float oracle: rustc not on PATH");
        return;
    };
    let dir: PathBuf = scratch_dir();

    let mut battery_src: String = String::new();
    for case in FP_BATTERY {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let battery_c: PathBuf = dir.join("rustfp_battery.c");
    std::fs::write(&battery_c, battery_src.as_bytes()).expect("write rustfp_battery.c");
    let battery_o: PathBuf = dir.join("rustfp_battery.o");
    let compile: std::process::Output = Command::new(&builder)
        .args([
            "-O1",
            "-fno-stack-protector",
            "-fno-math-errno",
            "-msse4.1",
            "-c",
            "-o",
        ])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke clang for scalar float battery");
    assert!(
        compile.status.success(),
        "rust fp battery compile failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read rustfp_battery.o");

    let prepared: Vec<PreparedFp> = FP_BATTERY
        .iter()
        .filter_map(|case: &FpCase| prepare_fp(case, &object_bytes, HOST_ABI))
        .collect();
    if prepared.is_empty() {
        eprintln!(
            "skipping rust scalar-float differential: this clang build lowered none of the {} cases into the pure-safe rust float class",
            FP_BATTERY.len()
        );
        return;
    }

    let carriers: usize = prepared
        .iter()
        .filter(|p: &&PreparedFp| {
            p.rust.contains("f64::from_bits") || p.rust.contains("f32::from_bits")
        })
        .count();
    assert!(
        carriers >= 1,
        "the rust scalar-float oracle has no teeth: not one recovered function emitted an `f64::from_bits`/`f32::from_bits`, so the float path was never graded"
    );

    let c_golden: String = build_fp_c_golden(&prepared);
    let c_golden_path: PathBuf = dir.join("rustfp_ground.c");
    std::fs::write(&c_golden_path, c_golden.as_bytes()).expect("write rustfp ground");
    let c_exe: PathBuf = dir.join("rustfp_ground.exe");
    let c_link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&c_exe)
        .arg(&c_golden_path)
        .arg(&battery_o)
        .output()
        .expect("link rust fp c ground-truth");
    assert!(
        c_link.status.success(),
        "rust fp c ground-truth link failed: {}\n--- ground ---\n{c_golden}",
        String::from_utf8_lossy(&c_link.stderr)
    );
    let c_run: std::process::Output = Command::new(&c_exe).output().expect("run rust fp ground");
    assert!(c_run.status.success(), "rust fp c ground-truth run failed");
    let golden: BTreeMap<(String, u64), u64> =
        parse_results(&String::from_utf8_lossy(&c_run.stdout));

    let rust_driver: String = build_fp_rust_driver(&prepared);
    let rust_driver_path: PathBuf = dir.join("rustfp_recovered.rs");
    std::fs::write(&rust_driver_path, rust_driver.as_bytes()).expect("write rust fp driver");
    let rust_exe: PathBuf = dir.join("rustfp_recovered.exe");
    let rust_build: std::process::Output = Command::new(&rustc_bin)
        .args(["--edition", "2021", "-o"])
        .arg(&rust_exe)
        .arg(&rust_driver_path)
        .output()
        .expect("invoke rustc for recovered rust float module");
    assert!(
        rust_build.status.success(),
        "recovered rust float module compile failed: {}\n--- recovered.rs ---\n{rust_driver}",
        String::from_utf8_lossy(&rust_build.stderr)
    );
    let rust_run: std::process::Output = Command::new(&rust_exe)
        .output()
        .expect("run recovered rust float module");
    assert!(
        rust_run.status.success(),
        "recovered rust float run failed: {}",
        String::from_utf8_lossy(&rust_run.stderr)
    );
    let got: BTreeMap<(String, u64), u64> =
        parse_results(&String::from_utf8_lossy(&rust_run.stdout));

    assert!(!golden.is_empty(), "rust fp produced no comparable results");
    assert_eq!(
        golden.len(),
        got.len(),
        "rust fp result-count mismatch: c ground truth {} vs rust {}",
        golden.len(),
        got.len()
    );
    for (key, want) in &golden {
        let have: u64 = *got
            .get(key)
            .unwrap_or_else(|| panic!("rust fp missing result for {key:?}"));
        assert_eq!(
            *want, have,
            "rust fp bit-exact differential MISMATCH for {key:?}: c={want} rust={have}"
        );
    }
    println!(
        "scalar float rust bit-exact recompile-equivalence PASSED for {} leaf functions across {} input vectors",
        prepared.len(),
        FP_PAIRS.len()
    );
}

struct FpSwitchCase {
    name: &'static str,
    ret: FpRet,
    c_source: &'static str,
}

const FP_SWITCH_BATTERY: &[FpSwitchCase] = &[
    FpSwitchCase {
        name: "swf_d",
        ret: FpRet::Double,
        c_source: "double swf_d(long long x, double a, double b){ double r; switch (x) { case 0: r = a + b; break; case 1: r = a - b; break; case 2: r = a * b; break; case 3: r = a * 1.5; break; case 4: r = b + 2.0; break; case 5: r = a * b + 1.0; break; default: r = a - 3.0; break; } return r; }",
    },
    FpSwitchCase {
        name: "swf_d2",
        ret: FpRet::Double,
        c_source: "double swf_d2(long long x, double a, double b){ double r; switch (x) { case 0: r = a * 2.0 + b; break; case 1: r = a - b * 0.5; break; case 2: r = (a + b) * 0.25; break; case 3: r = a * a; break; case 4: r = b * b - a; break; default: r = a + b + 7.0; break; } return r; }",
    },
    FpSwitchCase {
        name: "swf_f",
        ret: FpRet::Float,
        c_source: "float swf_f(long long x, float a, float b){ float r; switch (x) { case 0: r = a + b; break; case 1: r = a - b; break; case 2: r = a * b; break; case 3: r = a * 3.0f; break; case 4: r = b + 1.0f; break; default: r = a + b + 9.0f; break; } return r; }",
    },
];

const FP_SWITCH_PAIRS: &[[f64; 2]] = &[
    [0.0, 1.0],
    [1.0, 1.0],
    [-1.0, 1.0],
    [7.0, 3.0],
    [-7.0, 3.0],
    [7.0, -3.0],
    [3.5, 2.25],
    [-3.5, 2.25],
    [100.0, 7.0],
    [-100.0, -7.0],
    [0.5, 0.25],
    [12.75, 9.5],
    [-8.0, 4.0],
    [42.0, 42.0],
    [5.0, 9.0],
    [0.0, -7.0],
    [-0.0, 4.0],
];

struct PreparedFpSwitch {
    name: String,
    ret: FpRet,
    rust: String,
}

fn prepare_fp_switch(
    case: &FpSwitchCase,
    object_bytes: &[u8],
    abi: PseudoAbi,
) -> Option<PreparedFpSwitch> {
    let (code, base): (Vec<u8>, u64) = function_code(object_bytes, case.name)?;
    let tables: Vec<JumpTable> = resolve_switch_tables(object_bytes, &code, base)?;
    if tables.is_empty() {
        eprintln!("skip {}: no jump table resolved this build", case.name);
        return None;
    }
    let consts: Vec<FpConstant> = resolve_fp_constants(object_bytes, &code, base);
    let rec: LeafRecovery =
        match recover_leaf_function_switch_const_abi(&code, base, abi, &tables, &consts) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skip {}: not in dense fp-switch class ({e})", case.name);
                return None;
            }
        };
    if !rec.lifted_switch {
        return None;
    }
    let expected: PseudoScalarType = match case.ret {
        FpRet::Double => PseudoScalarType::Double,
        FpRet::Float => PseudoScalarType::Float,
        FpRet::LongLong => return None,
    };
    if rec.returns_fp != Some(expected) {
        eprintln!(
            "skip {}: switch did not type as {expected:?} fp return (got {:?})",
            case.name, rec.returns_fp
        );
        return None;
    }
    let Some(rust): Option<String> = rec.rust_source else {
        eprintln!(
            "skip {}: dense fp switch but not pure-safe rust-emittable",
            case.name
        );
        return None;
    };
    let renamed: String = rust.replacen(
        "pub fn recovered(",
        &format!("pub fn rec_{}(", case.name),
        1,
    );
    Some(PreparedFpSwitch {
        name: case.name.to_owned(),
        ret: case.ret,
        rust: renamed,
    })
}

fn build_fp_switch_c_golden(prepared: &[PreparedFpSwitch]) -> String {
    let mut decls: String = String::new();
    for p in prepared {
        let ty: &str = fp_c_ret(p.ret);
        let _ = writeln!(decls, "extern {ty} {}(long long, {ty}, {ty});", p.name);
    }
    let mut body: String = String::new();
    for p in prepared {
        let (cast, bits): (&str, &str) = match p.ret {
            FpRet::Double | FpRet::LongLong => ("(double)", "d_bits"),
            FpRet::Float => ("(float)", "f_bits"),
        };
        let _ = writeln!(
            body,
            "            printf(\"{} %zu %llu\\n\", (size_t)((disc+2)*np+k), (unsigned long long){bits}({}(disc, {cast}pairs[k][0], {cast}pairs[k][1])));",
            p.name, p.name
        );
    }
    let mut arr: String = String::new();
    for row in FP_SWITCH_PAIRS {
        let _ = write!(arr, "{{{:e},{:e}}},", row[0], row[1]);
    }
    format!(
        "#include <stdint.h>\n#include <string.h>\n#include <stdio.h>\n#include <stddef.h>\n\
         static uint64_t d_bits(double v){{ uint64_t b; memcpy(&b,&v,8); return b; }}\n\
         static uint64_t f_bits(float v){{ uint32_t b; memcpy(&b,&v,4); return (uint64_t)b; }}\n\
         {decls}\n\
         int main(void) {{\n\
         \x20   double pairs[][2] = {{{arr}}};\n\
         \x20   size_t np = sizeof(pairs)/sizeof(pairs[0]);\n\
         \x20   for (long long disc = -2; disc <= 9; disc++) {{\n\
         \x20       for (size_t k = 0; k < np; k++) {{\n\
         {body}\
         \x20       }}\n\
         \x20   }}\n\
         \x20   return 0;\n\
         }}\n"
    )
}

fn build_fp_switch_rust_driver(prepared: &[PreparedFpSwitch]) -> String {
    let mut out: String = String::from("#![allow(unused, unused_parens, dead_code)]\n");
    for p in prepared {
        out.push_str(&p.rust);
        out.push('\n');
    }
    let mut body: String = String::new();
    for p in prepared {
        let call: String = match p.ret {
            FpRet::Double | FpRet::LongLong => {
                format!("rec_{}(a, b, disc as u64).to_bits()", p.name)
            }
            FpRet::Float => format!(
                "(rec_{}(a as f32, b as f32, disc as u64).to_bits() as u64)",
                p.name
            ),
        };
        let _ = writeln!(
            body,
            "            println!(\"{} {{}} {{}}\", (disc + 2) as usize * pairs.len() + k, {call});",
            p.name
        );
    }
    let mut arr: String = String::new();
    for row in FP_SWITCH_PAIRS {
        let _ = write!(arr, "[{:e},{:e}],", row[0], row[1]);
    }
    let _ = write!(
        out,
        "fn main() {{\n\
         \x20   let pairs: [[f64; 2]; {}] = [{arr}];\n\
         \x20   for disc in -2i64..=9 {{\n\
         \x20       for k in 0..pairs.len() {{\n\
         \x20           let a: f64 = pairs[k][0];\n\
         \x20           let b: f64 = pairs[k][1];\n\
         {body}\
         \x20       }}\n\
         \x20   }}\n\
         }}\n",
        FP_SWITCH_PAIRS.len()
    );
    out
}

#[test]
fn fp_switch_dense_jump_table_leaf_functions_recompile_to_rust_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native rust fp-switch oracle on non-windows: the x86-64 ground-truth object requires the windows host"
        );
        return;
    }
    let Some(builder): Option<String> = gcc() else {
        eprintln!(
            "skipping rust fp-switch oracle: gcc (needed for the dense jump-table idiom) not on PATH"
        );
        return;
    };
    let Some(rustc_bin): Option<String> = rustc() else {
        eprintln!("skipping rust fp-switch oracle: rustc not on PATH");
        return;
    };
    let dir: PathBuf = scratch_dir();

    let mut battery_src: String = String::new();
    for case in FP_SWITCH_BATTERY {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let battery_c: PathBuf = dir.join("rustfpswitch_battery.c");
    std::fs::write(&battery_c, battery_src.as_bytes()).expect("write rustfpswitch_battery.c");
    let battery_o: PathBuf = dir.join("rustfpswitch_battery.o");
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
    let object_bytes: Vec<u8> = std::fs::read(&battery_o).expect("read rustfpswitch_battery.o");

    let prepared: Vec<PreparedFpSwitch> = FP_SWITCH_BATTERY
        .iter()
        .filter_map(|case: &FpSwitchCase| prepare_fp_switch(case, &object_bytes, HOST_ABI))
        .collect();
    if prepared.is_empty() {
        eprintln!(
            "skipping rust fp-switch differential: this gcc build reconstructed none of the {} cases into a dense fp-returning jump-table switch",
            FP_SWITCH_BATTERY.len()
        );
        return;
    }

    let match_carriers: usize = prepared
        .iter()
        .filter(|p: &&PreparedFpSwitch| p.rust.contains("match "))
        .count();
    assert!(
        match_carriers >= 1,
        "the rust fp-switch oracle has no teeth: not one recovered fp switch emitted a `match`, so the fp jump-table-to-match path was never graded"
    );
    let fp_carriers: usize = prepared
        .iter()
        .filter(|p: &&PreparedFpSwitch| {
            p.rust.contains("f64::from_bits") || p.rust.contains("f32::from_bits")
        })
        .count();
    assert!(
        fp_carriers >= 1,
        "the rust fp-switch oracle has no teeth: not one recovered fp switch emitted an `f64::from_bits`/`f32::from_bits`, so the fp value path was never graded"
    );

    let c_golden: String = build_fp_switch_c_golden(&prepared);
    let c_golden_path: PathBuf = dir.join("rustfpswitch_ground.c");
    std::fs::write(&c_golden_path, c_golden.as_bytes()).expect("write rustfpswitch ground");
    let c_exe: PathBuf = dir.join("rustfpswitch_ground.exe");
    let c_link: std::process::Output = Command::new(&builder)
        .args(["-O1", "-o"])
        .arg(&c_exe)
        .arg(&c_golden_path)
        .arg(&battery_o)
        .output()
        .expect("link fp switch c ground-truth");
    assert!(
        c_link.status.success(),
        "fp switch c ground-truth link failed: {}\n--- ground ---\n{c_golden}",
        String::from_utf8_lossy(&c_link.stderr)
    );
    let c_run: std::process::Output = Command::new(&c_exe).output().expect("run fp switch ground");
    assert!(
        c_run.status.success(),
        "fp switch c ground-truth run failed"
    );
    let golden: BTreeMap<(String, u64), u64> =
        parse_results(&String::from_utf8_lossy(&c_run.stdout));

    let rust_driver: String = build_fp_switch_rust_driver(&prepared);
    let rust_driver_path: PathBuf = dir.join("rustfpswitch_recovered.rs");
    std::fs::write(&rust_driver_path, rust_driver.as_bytes()).expect("write rust fp switch driver");
    let rust_exe: PathBuf = dir.join("rustfpswitch_recovered.exe");
    let rust_build: std::process::Output = Command::new(&rustc_bin)
        .args(["--edition", "2021", "-o"])
        .arg(&rust_exe)
        .arg(&rust_driver_path)
        .output()
        .expect("invoke rustc for recovered fp switch module");
    assert!(
        rust_build.status.success(),
        "recovered rust fp switch compile failed: {}\n--- recovered.rs ---\n{rust_driver}",
        String::from_utf8_lossy(&rust_build.stderr)
    );
    let rust_run: std::process::Output = Command::new(&rust_exe)
        .output()
        .expect("run recovered rust fp switch module");
    assert!(
        rust_run.status.success(),
        "recovered rust fp switch run failed: {}",
        String::from_utf8_lossy(&rust_run.stderr)
    );
    let got: BTreeMap<(String, u64), u64> =
        parse_results(&String::from_utf8_lossy(&rust_run.stdout));

    assert!(
        !golden.is_empty(),
        "fp switch produced no comparable results"
    );
    assert_eq!(
        golden.len(),
        got.len(),
        "fp switch result-count mismatch: c {} vs rust {}",
        golden.len(),
        got.len()
    );
    for (key, want) in &golden {
        let have: u64 = *got
            .get(key)
            .unwrap_or_else(|| panic!("fp switch rust missing result for {key:?}"));
        assert_eq!(
            *want, have,
            "fp switch bit-exact differential MISMATCH for {key:?}: c={want} rust={have}"
        );
    }
    println!(
        "fp-switch rust bit-exact recompile-equivalence PASSED for {} fp-returning leaf functions across 12 discriminants x {} input vectors",
        prepared.len(),
        FP_SWITCH_PAIRS.len()
    );
}
