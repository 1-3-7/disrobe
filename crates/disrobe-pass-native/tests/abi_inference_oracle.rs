//! Non-circular calling-convention / arg-count / return-value oracle.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_native::{
    AbiInference, ArgCount, CallingConvention, ReturnKind, infer_function_abi,
};

const BASE: u64 = 0x40_0000;

fn clang() -> Option<PathBuf> {
    which("clang")
}

fn objdump() -> Option<PathBuf> {
    which("llvm-objdump").or_else(|| which("objdump"))
}

fn which(name: &str) -> Option<PathBuf> {
    let probe: &str = if cfg!(windows) { "where" } else { "which" };
    let out: std::process::Output = Command::new(probe).arg(name).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text: String = String::from_utf8_lossy(&out.stdout).to_string();
    let first: &str = text.lines().next()?.trim();
    (!first.is_empty()).then(|| PathBuf::from(first))
}

fn compile(clang: &Path, src: &Path, target: &str, extra: &[&str], out: &Path) -> bool {
    Command::new(clang)
        .arg(format!("--target={target}"))
        .args(extra)
        .args([
            "-O1",
            "-ffreestanding",
            "-fno-stack-protector",
            "-fcf-protection=none",
            "-fno-asynchronous-unwind-tables",
            "-c",
        ])
        .arg(src)
        .arg("-o")
        .arg(out)
        .status()
        .is_ok_and(|s: std::process::ExitStatus| s.success())
}

fn carve_functions(objdump: &Path, obj: &Path) -> BTreeMap<String, Vec<u8>> {
    let out: std::process::Output = Command::new(objdump)
        .args(["-d"])
        .arg(obj)
        .output()
        .expect("objdump must run");
    let text: String = String::from_utf8_lossy(&out.stdout).to_string();
    let mut result: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut current: Option<String> = None;
    let mut acc: Vec<u8> = Vec::new();
    for line in text.lines() {
        let line: &str = line.trim_end();
        if line.ends_with(">:") && line.contains('<') {
            if let Some(name) = current.take() {
                result.insert(name, std::mem::take(&mut acc));
            }
            let inner: &str = &line[line.find('<').unwrap() + 1..line.rfind(">:").unwrap()];
            current = Some(inner.to_owned());
            continue;
        }
        if current.is_none() {
            continue;
        }
        let Some((_, rest)): Option<(&str, &str)> = line.trim().split_once(':') else {
            continue;
        };
        let body: &str = rest.trim();
        let hex: &str = body.split('\t').next().unwrap_or(body).trim();
        let mut bytes: Vec<u8> = Vec::new();
        let mut ok: bool = true;
        for tok in hex.split_whitespace() {
            if tok.len() == 2 && tok.bytes().all(|b: u8| b.is_ascii_hexdigit()) {
                bytes.push(u8::from_str_radix(tok, 16).unwrap());
            } else {
                ok = false;
                break;
            }
        }
        if ok && !bytes.is_empty() {
            acc.extend_from_slice(&bytes);
        }
    }
    if let Some(name) = current {
        result.insert(name, acc);
    }
    result
}

#[derive(Debug, Clone, Copy)]
struct Expect {
    abi: Option<CallingConvention>,
    min_args: u32,
    exact_args: Option<u32>,
    returns: ReturnKind,
}

fn grade(funcs: &BTreeMap<String, Vec<u8>>, bitness: u32, name: &str, expect: Expect) -> bool {
    let key: Option<&String> = funcs
        .keys()
        .find(|k: &&String| k.as_str() == name || normalize(k) == name);
    let Some(key): Option<&String> = key else {
        println!("  MISSING fn {name} in object, skipping");
        return true;
    };
    let bytes: &[u8] = &funcs[key];
    let Some(got): Option<AbiInference> = infer_function_abi(bitness, BASE, bytes, BASE) else {
        panic!("inference returned None for {name}");
    };
    if let Some(want_abi) = expect.abi {
        assert_eq!(got.abi, want_abi, "abi mismatch for {name}: {got:?}");
    }
    if let Some(n) = expect.exact_args {
        assert!(
            matches!(got.arg_count, ArgCount::Exact(g) if g == n),
            "exact arg-count mismatch for {name}: want {n}, got {:?}",
            got.arg_count
        );
    } else {
        let lower: u32 = match got.arg_count {
            ArgCount::Exact(g) | ArgCount::AtLeast(g) => g,
            ArgCount::Unknown => 0,
        };
        assert!(
            lower >= expect.min_args,
            "arg-count under expected floor for {name}: want >= {}, got {:?}",
            expect.min_args,
            got.arg_count
        );
    }
    assert_eq!(
        got.returns_value, expect.returns,
        "return-value mismatch for {name}: {got:?}"
    );
    println!(
        "  OK {name}: {:?} args={:?} ret={:?}",
        got.abi, got.arg_count, got.returns_value
    );
    true
}

fn normalize(name: &str) -> String {
    let trimmed: &str = name.trim_start_matches('_').trim_start_matches('@');
    trimmed.split('@').next().unwrap_or(trimmed).to_owned()
}

fn write_src(dir: &Path, file: &str, content: &str) -> PathBuf {
    let path: PathBuf = dir.join(file);
    std::fs::write(&path, content).expect("write source");
    path
}

const FIXTURES_64: &str = r#"
int f_void(void) { return 0; }
void f_void_noret(void) { __asm__ volatile(""); }
int f_one(int a) { return a + 1; }
int f_two(int a, int b) { return a - b; }
int f_three(int a, int b, int c) { return a + b + c; }
int f_four(int a, int b, int c, int d) { return a + b + c + d; }
long f_long_two(long a, long b) { return a * b; }
int f_branch(int a, int b) { if (a > b) return a; return b; }
"#;

const FIXTURES_32: &str = r"
int __attribute__((cdecl)) c_two(int a, int b) { return a - b; }
int __attribute__((stdcall)) s_three(int a, int b, int c) { return a + b + c; }
int __attribute__((fastcall)) fc_two(int a, int b) { return a * b - a; }
int __attribute__((fastcall)) fc_three(int a, int b, int c) { return a + b + c; }
";

#[test]
fn abi_inference_matches_compiler_lowering() {
    let Some(clang): Option<PathBuf> = clang() else {
        println!("clang not on PATH: skipping the entire ABI oracle (no leg graded)");
        return;
    };
    let Some(objdump): Option<PathBuf> = objdump() else {
        println!("objdump not on PATH: skipping ABI oracle");
        return;
    };
    let dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe_abi_oracle_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");

    let src64: PathBuf = write_src(&dir, "fx64.c", FIXTURES_64);
    let mut graded_legs: u32 = 0;

    let sysv_obj: PathBuf = dir.join("sysv.o");
    if compile(&clang, &src64, "x86_64-unknown-linux-gnu", &[], &sysv_obj) {
        graded_legs += 1;
        let funcs: BTreeMap<String, Vec<u8>> = carve_functions(&objdump, &sysv_obj);
        println!("SysV x86-64:");
        let s = |abi: CallingConvention, exact: Option<u32>, min: u32, ret: ReturnKind| Expect {
            abi: Some(abi),
            min_args: min,
            exact_args: exact,
            returns: ret,
        };
        grade(
            &funcs,
            64,
            "f_void_noret",
            Expect {
                abi: None,
                min_args: 0,
                exact_args: Some(0),
                returns: ReturnKind::Void,
            },
        );
        grade(
            &funcs,
            64,
            "f_void",
            Expect {
                abi: None,
                min_args: 0,
                exact_args: Some(0),
                returns: ReturnKind::Value,
            },
        );
        grade(
            &funcs,
            64,
            "f_one",
            s(CallingConvention::SysV64, Some(1), 1, ReturnKind::Value),
        );
        grade(
            &funcs,
            64,
            "f_two",
            s(CallingConvention::SysV64, Some(2), 2, ReturnKind::Value),
        );
        grade(
            &funcs,
            64,
            "f_three",
            s(CallingConvention::SysV64, Some(3), 3, ReturnKind::Value),
        );
        grade(
            &funcs,
            64,
            "f_four",
            s(CallingConvention::SysV64, None, 3, ReturnKind::Value),
        );
        grade(
            &funcs,
            64,
            "f_long_two",
            s(CallingConvention::SysV64, Some(2), 2, ReturnKind::Value),
        );
        grade(
            &funcs,
            64,
            "f_branch",
            s(CallingConvention::SysV64, Some(2), 2, ReturnKind::Value),
        );
    } else {
        println!("SysV x86-64 leg could not be built: skipped honestly");
    }

    let ms_obj: PathBuf = dir.join("ms.o");
    if compile(&clang, &src64, "x86_64-pc-windows-msvc", &[], &ms_obj) {
        graded_legs += 1;
        let funcs: BTreeMap<String, Vec<u8>> = carve_functions(&objdump, &ms_obj);
        println!("MS x64:");
        let m = |exact: Option<u32>, min: u32, ret: ReturnKind| Expect {
            abi: Some(CallingConvention::Microsoft64),
            min_args: min,
            exact_args: exact,
            returns: ret,
        };
        grade(&funcs, 64, "f_one", m(Some(1), 1, ReturnKind::Value));
        grade(&funcs, 64, "f_two", m(Some(2), 2, ReturnKind::Value));
        grade(&funcs, 64, "f_three", m(Some(3), 3, ReturnKind::Value));
        grade(&funcs, 64, "f_long_two", m(Some(2), 2, ReturnKind::Value));
        grade(&funcs, 64, "f_branch", m(Some(2), 2, ReturnKind::Value));
    } else {
        println!("MS x64 leg could not be built: skipped honestly");
    }

    let src32: PathBuf = write_src(&dir, "fx32.c", FIXTURES_32);
    let x32_obj: PathBuf = dir.join("x32.o");
    if compile(&clang, &src32, "i686-pc-windows-msvc", &["-m32"], &x32_obj) {
        graded_legs += 1;
        let funcs: BTreeMap<String, Vec<u8>> = carve_functions(&objdump, &x32_obj);
        println!("x86 32-bit:");
        grade(
            &funcs,
            32,
            "c_two",
            Expect {
                abi: Some(CallingConvention::Cdecl),
                min_args: 2,
                exact_args: Some(2),
                returns: ReturnKind::Value,
            },
        );
        grade(
            &funcs,
            32,
            "s_three",
            Expect {
                abi: Some(CallingConvention::Stdcall),
                min_args: 3,
                exact_args: Some(3),
                returns: ReturnKind::Value,
            },
        );
        grade(
            &funcs,
            32,
            "fc_two",
            Expect {
                abi: Some(CallingConvention::Fastcall),
                min_args: 2,
                exact_args: None,
                returns: ReturnKind::Value,
            },
        );
        grade(
            &funcs,
            32,
            "fc_three",
            Expect {
                abi: Some(CallingConvention::Fastcall),
                min_args: 3,
                exact_args: Some(3),
                returns: ReturnKind::Value,
            },
        );
    } else {
        println!("x86 32-bit leg could not be built on this clang: skipped honestly");
    }

    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        graded_legs > 0,
        "clang is present but no ABI leg compiled; refusing to report a vacuous green"
    );
    println!("graded {graded_legs} ABI leg(s) against compiler lowering");
}
