#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::cast_possible_truncation
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_wasm_deob::{
    BaseOrigin, PointerType, Signedness, SignednessReport, SsaFunction, ValueDef, ValueId,
    build_function_cfg, build_ssa, recover_signedness,
};
use wasmparser::{FunctionBody, Parser, Payload, ValType};

struct PtrExpect {
    base_param: u32,
    width_bytes: u32,
    sign: Signedness,
}

struct Fixture {
    name: &'static str,
    c_src: &'static str,
    wat_params: &'static [&'static str],
    wat_result: Option<&'static str>,
    wat_body: &'static str,
    ssa_params: &'static [ValType],
    param_signs: &'static [(u16, Signedness)],
    pointers: &'static [PtrExpect],
}

fn fixtures() -> Vec<Fixture> {
    vec![
        Fixture {
            name: "cmp_s",
            c_src: "int cmp_s(int a, int b) { return a < b; }",
            wat_params: &["i32", "i32"],
            wat_result: Some("i32"),
            wat_body: "local.get 0 local.get 1 i32.lt_s",
            ssa_params: &[ValType::I32, ValType::I32],
            param_signs: &[(0, Signedness::Signed), (1, Signedness::Signed)],
            pointers: &[],
        },
        Fixture {
            name: "cmp_u",
            c_src: "int cmp_u(unsigned a, unsigned b) { return a < b; }",
            wat_params: &["i32", "i32"],
            wat_result: Some("i32"),
            wat_body: "local.get 0 local.get 1 i32.lt_u",
            ssa_params: &[ValType::I32, ValType::I32],
            param_signs: &[(0, Signedness::Unsigned), (1, Signedness::Unsigned)],
            pointers: &[],
        },
        Fixture {
            name: "div_s",
            c_src: "int div_s(int a, int b) { return a / b; }",
            wat_params: &["i32", "i32"],
            wat_result: Some("i32"),
            wat_body: "local.get 0 local.get 1 i32.div_s",
            ssa_params: &[ValType::I32, ValType::I32],
            param_signs: &[(0, Signedness::Signed), (1, Signedness::Signed)],
            pointers: &[],
        },
        Fixture {
            name: "div_u",
            c_src: "unsigned div_u(unsigned a, unsigned b) { return a / b; }",
            wat_params: &["i32", "i32"],
            wat_result: Some("i32"),
            wat_body: "local.get 0 local.get 1 i32.div_u",
            ssa_params: &[ValType::I32, ValType::I32],
            param_signs: &[(0, Signedness::Unsigned), (1, Signedness::Unsigned)],
            pointers: &[],
        },
        Fixture {
            name: "rem_s",
            c_src: "int rem_s(int a, int b) { return a % b; }",
            wat_params: &["i32", "i32"],
            wat_result: Some("i32"),
            wat_body: "local.get 0 local.get 1 i32.rem_s",
            ssa_params: &[ValType::I32, ValType::I32],
            param_signs: &[(0, Signedness::Signed), (1, Signedness::Signed)],
            pointers: &[],
        },
        Fixture {
            name: "rem_u",
            c_src: "unsigned rem_u(unsigned a, unsigned b) { return a % b; }",
            wat_params: &["i32", "i32"],
            wat_result: Some("i32"),
            wat_body: "local.get 0 local.get 1 i32.rem_u",
            ssa_params: &[ValType::I32, ValType::I32],
            param_signs: &[(0, Signedness::Unsigned), (1, Signedness::Unsigned)],
            pointers: &[],
        },
        Fixture {
            name: "shr_s",
            c_src: "int shr_s(int a, int b) { return a >> b; }",
            wat_params: &["i32", "i32"],
            wat_result: Some("i32"),
            wat_body: "local.get 0 local.get 1 i32.shr_s",
            ssa_params: &[ValType::I32, ValType::I32],
            param_signs: &[(0, Signedness::Signed)],
            pointers: &[],
        },
        Fixture {
            name: "shr_u",
            c_src: "unsigned shr_u(unsigned a, unsigned b) { return a >> b; }",
            wat_params: &["i32", "i32"],
            wat_result: Some("i32"),
            wat_body: "local.get 0 local.get 1 i32.shr_u",
            ssa_params: &[ValType::I32, ValType::I32],
            param_signs: &[(0, Signedness::Unsigned)],
            pointers: &[],
        },
        Fixture {
            name: "ext_s",
            c_src: "long long ext_s(int a) { return (long long)a; }",
            wat_params: &["i32"],
            wat_result: Some("i64"),
            wat_body: "local.get 0 i64.extend_i32_s",
            ssa_params: &[ValType::I32],
            param_signs: &[(0, Signedness::Signed)],
            pointers: &[],
        },
        Fixture {
            name: "ext_u",
            c_src: "unsigned long long ext_u(unsigned a) { return (unsigned long long)a; }",
            wat_params: &["i32"],
            wat_result: Some("i64"),
            wat_body: "local.get 0 i64.extend_i32_u",
            ssa_params: &[ValType::I32],
            param_signs: &[(0, Signedness::Unsigned)],
            pointers: &[],
        },
        Fixture {
            name: "load_i8s",
            c_src: "int load_i8s(signed char* p) { return *p; }",
            wat_params: &["i32"],
            wat_result: Some("i32"),
            wat_body: "local.get 0 i32.load8_s",
            ssa_params: &[ValType::I32],
            param_signs: &[],
            pointers: &[PtrExpect {
                base_param: 0,
                width_bytes: 1,
                sign: Signedness::Signed,
            }],
        },
        Fixture {
            name: "load_u8",
            c_src: "int load_u8(unsigned char* p) { return *p; }",
            wat_params: &["i32"],
            wat_result: Some("i32"),
            wat_body: "local.get 0 i32.load8_u",
            ssa_params: &[ValType::I32],
            param_signs: &[],
            pointers: &[PtrExpect {
                base_param: 0,
                width_bytes: 1,
                sign: Signedness::Unsigned,
            }],
        },
        Fixture {
            name: "load_i16s",
            c_src: "int load_i16s(short* p) { return *p; }",
            wat_params: &["i32"],
            wat_result: Some("i32"),
            wat_body: "local.get 0 i32.load16_s",
            ssa_params: &[ValType::I32],
            param_signs: &[],
            pointers: &[PtrExpect {
                base_param: 0,
                width_bytes: 2,
                sign: Signedness::Signed,
            }],
        },
        Fixture {
            name: "load_u16",
            c_src: "int load_u16(unsigned short* p) { return *p; }",
            wat_params: &["i32"],
            wat_result: Some("i32"),
            wat_body: "local.get 0 i32.load16_u",
            ssa_params: &[ValType::I32],
            param_signs: &[],
            pointers: &[PtrExpect {
                base_param: 0,
                width_bytes: 2,
                sign: Signedness::Unsigned,
            }],
        },
        Fixture {
            name: "load_i32",
            c_src: "int load_i32(int* p) { return *p; }",
            wat_params: &["i32"],
            wat_result: Some("i32"),
            wat_body: "local.get 0 i32.load",
            ssa_params: &[ValType::I32],
            param_signs: &[],
            pointers: &[PtrExpect {
                base_param: 0,
                width_bytes: 4,
                sign: Signedness::Unknown,
            }],
        },
        Fixture {
            name: "load_u32",
            c_src: "unsigned load_u32(unsigned* p) { return *p; }",
            wat_params: &["i32"],
            wat_result: Some("i32"),
            wat_body: "local.get 0 i32.load",
            ssa_params: &[ValType::I32],
            param_signs: &[],
            pointers: &[PtrExpect {
                base_param: 0,
                width_bytes: 4,
                sign: Signedness::Unknown,
            }],
        },
        Fixture {
            name: "load_i64",
            c_src: "long long load_i64(long long* p) { return *p; }",
            wat_params: &["i32"],
            wat_result: Some("i64"),
            wat_body: "local.get 0 i64.load",
            ssa_params: &[ValType::I32],
            param_signs: &[],
            pointers: &[PtrExpect {
                base_param: 0,
                width_bytes: 8,
                sign: Signedness::Unknown,
            }],
        },
        Fixture {
            name: "store_i8",
            c_src: "void store_i8(signed char* p, int v) { *p = (signed char)v; }",
            wat_params: &["i32", "i32"],
            wat_result: None,
            wat_body: "local.get 0 local.get 1 i32.store8",
            ssa_params: &[ValType::I32, ValType::I32],
            param_signs: &[],
            pointers: &[PtrExpect {
                base_param: 0,
                width_bytes: 1,
                sign: Signedness::Unknown,
            }],
        },
        Fixture {
            name: "store_u16",
            c_src: "void store_u16(unsigned short* p, int v) { *p = (unsigned short)v; }",
            wat_params: &["i32", "i32"],
            wat_result: None,
            wat_body: "local.get 0 local.get 1 i32.store16",
            ssa_params: &[ValType::I32, ValType::I32],
            param_signs: &[],
            pointers: &[PtrExpect {
                base_param: 0,
                width_bytes: 2,
                sign: Signedness::Unknown,
            }],
        },
        Fixture {
            name: "cmp_load_s",
            c_src: "int cmp_load_s(int* p, int b) { return *p < b; }",
            wat_params: &["i32", "i32"],
            wat_result: Some("i32"),
            wat_body: "local.get 0 i32.load local.get 1 i32.lt_s",
            ssa_params: &[ValType::I32, ValType::I32],
            param_signs: &[(1, Signedness::Signed)],
            pointers: &[PtrExpect {
                base_param: 0,
                width_bytes: 4,
                sign: Signedness::Signed,
            }],
        },
        Fixture {
            name: "cmp_load_u",
            c_src: "int cmp_load_u(unsigned* p, unsigned b) { return *p < b; }",
            wat_params: &["i32", "i32"],
            wat_result: Some("i32"),
            wat_body: "local.get 0 i32.load local.get 1 i32.lt_u",
            ssa_params: &[ValType::I32, ValType::I32],
            param_signs: &[(1, Signedness::Unsigned)],
            pointers: &[PtrExpect {
                base_param: 0,
                width_bytes: 4,
                sign: Signedness::Unsigned,
            }],
        },
        Fixture {
            name: "idx_i8s",
            c_src: "int idx_i8s(signed char* p, int i) { return p[i]; }",
            wat_params: &["i32", "i32"],
            wat_result: Some("i32"),
            wat_body: "local.get 0 local.get 1 i32.add i32.load8_s",
            ssa_params: &[ValType::I32, ValType::I32],
            param_signs: &[],
            pointers: &[PtrExpect {
                base_param: 0,
                width_bytes: 1,
                sign: Signedness::Signed,
            }],
        },
        Fixture {
            name: "div_load",
            c_src: "int div_load(int* p, int b) { return *p / b; }",
            wat_params: &["i32", "i32"],
            wat_result: Some("i32"),
            wat_body: "local.get 0 i32.load local.get 1 i32.div_s",
            ssa_params: &[ValType::I32, ValType::I32],
            param_signs: &[(1, Signedness::Signed)],
            pointers: &[PtrExpect {
                base_param: 0,
                width_bytes: 4,
                sign: Signedness::Signed,
            }],
        },
    ]
}

fn ssa_from_bytes(bytes: &[u8], params: &[ValType]) -> Option<SsaFunction> {
    for payload in Parser::new(0).parse_all(bytes) {
        if let Ok(Payload::CodeSectionEntry(body)) = payload {
            let body: FunctionBody<'_> = body;
            let cfg: disrobe_pass_wasm_deob::FunctionCfg = build_function_cfg(&body).ok()?;
            return build_ssa(&cfg, &body, params).ok();
        }
    }
    None
}

fn wat_module(params: &[&str], result: Option<&str>, body: &str) -> String {
    let params_clause: String = if params.is_empty() {
        String::new()
    } else {
        format!(" (param {})", params.join(" "))
    };
    let result_clause: String = result.map_or_else(String::new, |ty| format!(" (result {ty})"));
    format!("(module (memory 1) (func{params_clause}{result_clause}\n{body}\n))")
}

fn param_value(ssa: &SsaFunction, idx: u16) -> Option<ValueId> {
    ssa.values
        .iter()
        .enumerate()
        .find_map(|(i, def)| match def {
            ValueDef::Param(_, p) if *p == idx => Some(ValueId(i as u32)),
            _ => None,
        })
}

fn check(report: &SignednessReport, ssa: &SsaFunction, fixture: &Fixture) {
    for (idx, want) in fixture.param_signs {
        let vid: ValueId = param_value(ssa, *idx)
            .unwrap_or_else(|| panic!("{}: no param value {idx}", fixture.name));
        let got: Signedness = report.value(vid);
        assert_eq!(got, *want, "{}: param {idx} signedness", fixture.name);
    }
    for expect in fixture.pointers {
        let ptr: PointerType = report
            .pointer(BaseOrigin::Param(expect.base_param))
            .unwrap_or_else(|| {
                panic!(
                    "{}: no pointer type recovered for param {}",
                    fixture.name, expect.base_param
                )
            });
        assert_eq!(
            ptr.elem.width_bytes, expect.width_bytes,
            "{}: pointer element width",
            fixture.name
        );
        assert_eq!(
            ptr.elem.signedness, expect.sign,
            "{}: pointer element signedness",
            fixture.name
        );
    }
}

#[test]
fn signedness_matches_c_abi_via_wat() {
    for fixture in fixtures() {
        let wat: String = wat_module(fixture.wat_params, fixture.wat_result, fixture.wat_body);
        let bytes: Vec<u8> =
            wat::parse_str(&wat).unwrap_or_else(|e| panic!("{}: wat parse: {e}", fixture.name));
        let ssa: SsaFunction = ssa_from_bytes(&bytes, fixture.ssa_params)
            .unwrap_or_else(|| panic!("{}: ssa build", fixture.name));
        let report: SignednessReport = recover_signedness(&ssa);
        check(&report, &ssa, &fixture);
    }
}

#[test]
fn signed_and_unsigned_ops_stay_distinct() {
    let all: Vec<Fixture> = fixtures();
    let sign_of_param0 = |name: &str| -> Signedness {
        let fixture: &Fixture = all
            .iter()
            .find(|f| f.name == name)
            .expect("fixture present");
        let wat: String = wat_module(fixture.wat_params, fixture.wat_result, fixture.wat_body);
        let bytes: Vec<u8> = wat::parse_str(&wat).expect("wat parse");
        let ssa: SsaFunction = ssa_from_bytes(&bytes, fixture.ssa_params).expect("ssa");
        let report: SignednessReport = recover_signedness(&ssa);
        report.value(param_value(&ssa, 0).expect("param0"))
    };
    let ptr_sign = |name: &str| -> Signedness {
        let fixture: &Fixture = all
            .iter()
            .find(|f| f.name == name)
            .expect("fixture present");
        let wat: String = wat_module(fixture.wat_params, fixture.wat_result, fixture.wat_body);
        let bytes: Vec<u8> = wat::parse_str(&wat).expect("wat parse");
        let ssa: SsaFunction = ssa_from_bytes(&bytes, fixture.ssa_params).expect("ssa");
        let report: SignednessReport = recover_signedness(&ssa);
        report
            .pointer(BaseOrigin::Param(0))
            .expect("pointer")
            .elem
            .signedness
    };

    assert_eq!(sign_of_param0("cmp_s"), Signedness::Signed);
    assert_ne!(sign_of_param0("cmp_s"), Signedness::Unsigned);
    assert_eq!(sign_of_param0("cmp_u"), Signedness::Unsigned);
    assert_ne!(sign_of_param0("cmp_u"), Signedness::Signed);

    assert_eq!(ptr_sign("load_i8s"), Signedness::Signed);
    assert_ne!(ptr_sign("load_i8s"), Signedness::Unsigned);
    assert_eq!(ptr_sign("load_u8"), Signedness::Unsigned);
    assert_ne!(ptr_sign("load_u8"), Signedness::Signed);
}

fn clang_present() -> bool {
    Command::new("clang")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success())
}

fn compile_c(dir: &Path, name: &str, src: &str) -> Option<Vec<u8>> {
    let c_path: PathBuf = dir.join(format!("{name}.c"));
    let o_path: PathBuf = dir.join(format!("{name}.o"));
    std::fs::write(&c_path, src).ok()?;
    let out = Command::new("clang")
        .args(["--target=wasm32", "-O1", "-c"])
        .arg(&c_path)
        .arg("-o")
        .arg(&o_path)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    std::fs::read(&o_path).ok()
}

#[test]
fn signedness_matches_clang_wasm() {
    if !clang_present() {
        eprintln!("clang unavailable; skipping compiled-C signedness grading");
        return;
    }
    let dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe_wasm_sign_{}", std::process::id()));
    if std::fs::create_dir_all(&dir).is_err() {
        eprintln!("cannot create temp dir; skipping compiled-C signedness grading");
        return;
    }

    let all: Vec<Fixture> = fixtures();
    let Some(first) = all.first() else {
        return;
    };
    if compile_c(&dir, first.name, first.c_src).is_none() {
        eprintln!("clang wasm32 target unavailable; skipping compiled-C signedness grading");
        return;
    }

    let mut graded: usize = 0;
    for fixture in &all {
        let bytes: Vec<u8> = compile_c(&dir, fixture.name, fixture.c_src)
            .unwrap_or_else(|| panic!("{}: clang compile", fixture.name));
        let ssa: SsaFunction = ssa_from_bytes(&bytes, fixture.ssa_params)
            .unwrap_or_else(|| panic!("{}: ssa build from clang output", fixture.name));
        let report: SignednessReport = recover_signedness(&ssa);
        check(&report, &ssa, fixture);
        graded += 1;
    }
    assert_eq!(graded, all.len(), "every fixture graded against clang");
    let _ = std::fs::remove_dir_all(&dir);
}
