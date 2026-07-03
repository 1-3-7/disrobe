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
    LeafRecovery, PseudoAbi, ResolvedCall, callee_int_arity, recover_leaf_function_abi,
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

fn run_battery(tag: &str, battery: &[Case], inputs: &[[i64; 3]]) {
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

    let c_driver: String = build_c_driver(&prepared, inputs);
    let c_driver_path: PathBuf = dir.join(format!("{tag}_ground.c"));
    std::fs::write(&c_driver_path, c_driver.as_bytes()).expect("write c driver");
    let c_exe: PathBuf = dir.join(format!("{tag}_ground.exe"));
    let c_link: std::process::Output = Command::new(&compiler)
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
    let c_run: std::process::Output = Command::new(&c_exe).output().expect("run c ground-truth");
    assert!(c_run.status.success(), "{tag} c ground-truth run failed");
    let golden: BTreeMap<(String, u64), u64> =
        parse_results(&String::from_utf8_lossy(&c_run.stdout));

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
    run_battery("arith", ARITH_BATTERY, ARITH_INPUTS);
}

#[test]
fn division_leaf_functions_recompile_to_rust_equivalence() {
    run_battery("div", DIV_BATTERY, DIV_INPUTS);
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
