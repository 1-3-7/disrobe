#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_wasm_deob::{
    CalleeNames, FunctionSig, LiftTarget, ModuleSignatures, c_runtime_prelude, extract_signatures,
    lift_function_body, lift_module_to_wat, rust_runtime_prelude, typescript_runtime_prelude,
};
use wasmparser::{FunctionBody, Parser, Payload};

const ARITH4: &[u8] = include_bytes!("fixtures/arith4.wasm");

fn callees(sigs: &ModuleSignatures) -> CalleeNames {
    CalleeNames::with_signatures(
        sigs.callee_names(),
        sigs.call_signatures(),
        sigs.call_signatures(),
    )
}

fn defined_bodies(bytes: &[u8]) -> Vec<FunctionBody<'_>> {
    let mut out: Vec<FunctionBody<'_>> = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        if let Ok(Payload::CodeSectionEntry(body)) = payload {
            out.push(body);
        }
    }
    out
}

fn lift_all(target: LiftTarget) -> String {
    let sigs: ModuleSignatures = extract_signatures(ARITH4).expect("signatures");
    let defined: &[FunctionSig] = sigs.defined();
    let callees: CalleeNames = callees(&sigs);
    let mut out: String = match target {
        LiftTarget::Rust => rust_runtime_prelude().to_owned(),
        LiftTarget::TypeScript => typescript_runtime_prelude().to_owned(),
        LiftTarget::C => c_runtime_prelude().to_owned(),
        LiftTarget::Wat => String::new(),
    };
    for (i, body) in defined_bodies(ARITH4).iter().enumerate() {
        out.push('\n');
        out.push_str(&lift_function_body(body, &defined[i], &callees, target).pseudo_source);
    }
    out
}

fn tool_on_path(tool: &str) -> Option<PathBuf> {
    let probe: &str = if cfg!(windows) { "where" } else { "which" };
    let output: std::process::Output = Command::new(probe).arg(tool).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout: String = String::from_utf8_lossy(&output.stdout).to_string();
    let first: &str = stdout.lines().next()?.trim();
    if first.is_empty() {
        None
    } else {
        Some(PathBuf::from(first))
    }
}

#[test]
fn lifted_rust_compiles_with_rustc() {
    let src: String = lift_all(LiftTarget::Rust);
    let dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe_wasm_lift_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let rs: PathBuf = dir.join("lifted.rs");
    std::fs::write(&rs, &src).expect("write rs");

    let Some(rustc): Option<PathBuf> = tool_on_path("rustc") else {
        eprintln!("SKIP: rustc not on PATH for the compile-the-output gate");
        return;
    };
    let out: std::process::Output = Command::new(rustc)
        .args([
            "--edition",
            "2021",
            "--crate-type",
            "lib",
            "--emit=metadata",
            "-o",
        ])
        .arg(dir.join("lifted.rmeta"))
        .arg(&rs)
        .output()
        .expect("spawn rustc");
    assert!(
        out.status.success(),
        "rustc rejected lifted output (exit {:?})\n--- stderr ---\n{}\n--- source ---\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr),
        src
    );
}

#[test]
fn lifted_wat_roundtrips_through_wat_parser() {
    let sigs: ModuleSignatures = extract_signatures(ARITH4).expect("signatures");
    let defined: &[FunctionSig] = sigs.defined();
    let bodies: Vec<FunctionBody<'_>> = defined_bodies(ARITH4);
    let pairs: Vec<(FunctionBody<'_>, FunctionSig)> =
        bodies.into_iter().zip(defined.iter().cloned()).collect();
    let wat: String = lift_module_to_wat(&pairs, 0);
    let parsed: Result<Vec<u8>, wat::Error> = wat::parse_str(&wat);
    assert!(
        parsed.is_ok(),
        "emitted multi-function WAT must reparse (exit {:?})\n{}",
        parsed.err(),
        wat
    );
}

#[test]
fn lifted_c_compiles_when_compiler_available() {
    let src: String = lift_all(LiftTarget::C);
    let compiler: Option<PathBuf> = tool_on_path("cc")
        .or_else(|| tool_on_path("clang"))
        .or_else(|| tool_on_path("gcc"));
    let Some(cc): Option<PathBuf> = compiler else {
        eprintln!("SKIP: no C compiler (cc/clang/gcc) on PATH");
        return;
    };
    let dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe_wasm_lift_c_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let c: PathBuf = dir.join("lifted.c");
    std::fs::write(&c, &src).expect("write c");
    let out: std::process::Output = Command::new(cc)
        .arg("-c")
        .arg(&c)
        .arg("-o")
        .arg(dir.join("lifted.o"))
        .output()
        .expect("spawn cc");
    assert!(
        out.status.success(),
        "cc rejected lifted C (exit {:?})\n{}\n--- source ---\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr),
        src
    );
}
