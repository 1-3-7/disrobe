#![cfg(feature = "sandbox")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_wasm_deob::{
    CalleeNames, FunctionSig, LiftResult, LiftTarget, ModuleSignatures, extract_signatures,
    lift_function_body, rust_runtime_prelude,
};
use wasmparser::{FunctionBody, Parser, Payload, ValType};
use wasmtime::{Config, Engine, Linker, Module, Store, Val};

const SIMD_DIFF: &str = include_str!("fixtures/simd_diff.wat");

fn defined_bodies(bytes: &[u8]) -> Vec<FunctionBody<'_>> {
    let mut out: Vec<FunctionBody<'_>> = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        if let Ok(Payload::CodeSectionEntry(body)) = payload {
            out.push(body);
        }
    }
    out
}

fn callees(bytes: &[u8], sigs: &ModuleSignatures) -> CalleeNames {
    CalleeNames::from_module(
        bytes,
        sigs.callee_names(),
        sigs.call_signatures(),
        sigs.call_signatures(),
    )
}

fn engine() -> Engine {
    let mut config: Config = Config::new();
    config.wasm_simd(true).wasm_relaxed_simd(true);
    Engine::new(&config).expect("engine with simd")
}

const fn battery() -> [i32; 8] {
    [0, 1, 2, 7, -1, -3, 255, i32::MIN / 2]
}

struct Export {
    name: String,
    arity: usize,
}

fn exports(sigs: &ModuleSignatures) -> Vec<Export> {
    sigs.defined()
        .iter()
        .filter(|s: &&FunctionSig| s.exported)
        .filter(|s: &&FunctionSig| {
            s.params.iter().all(|t| *t == ValType::I32) && s.results == vec![ValType::I32]
        })
        .map(|s: &FunctionSig| Export {
            name: s.name.clone(),
            arity: s.params.len(),
        })
        .collect()
}

fn wasmtime_results(bytes: &[u8], exps: &[Export]) -> Vec<(String, Vec<i32>, Option<i32>)> {
    let eng: Engine = engine();
    let module: Module = Module::new(&eng, bytes).expect("module");
    let mut store: Store<()> = Store::new(&eng, ());
    let linker: Linker<()> = Linker::new(&eng);
    let instance: wasmtime::Instance = linker.instantiate(&mut store, &module).expect("instance");
    let mut out: Vec<(String, Vec<i32>, Option<i32>)> = Vec::new();
    for exp in exps {
        let func: wasmtime::Func = instance
            .get_func(&mut store, &exp.name)
            .expect("export present");
        for combo in arg_combos(exp.arity) {
            let argv: Vec<Val> = combo.iter().map(|a| Val::I32(*a)).collect();
            let mut res: [Val; 1] = [Val::I32(0)];
            let got: Option<i32> = match func.call(&mut store, &argv, &mut res) {
                Ok(()) => match res[0] {
                    Val::I32(v) => Some(v),
                    _ => None,
                },
                Err(_) => None,
            };
            out.push((exp.name.clone(), combo, got));
        }
    }
    out
}

fn arg_combos(arity: usize) -> Vec<Vec<i32>> {
    let b: [i32; 8] = battery();
    match arity {
        0 => vec![Vec::new()],
        1 => b.iter().map(|x| vec![*x]).collect(),
        _ => {
            let mut out: Vec<Vec<i32>> = Vec::new();
            for a in b {
                for c in b {
                    out.push(vec![a, c]);
                }
            }
            out
        }
    }
}

fn lifted_rust_program(bytes: &[u8], sigs: &ModuleSignatures, exps: &[Export]) -> String {
    let defined: &[FunctionSig] = sigs.defined();
    let cs: CalleeNames = callees(bytes, sigs);
    let mut src: String = rust_runtime_prelude().to_owned();
    src.push('\n');
    for (i, body) in defined_bodies(bytes).iter().enumerate() {
        let lifted: LiftResult = lift_function_body(body, &defined[i], &cs, LiftTarget::Rust);
        src.push_str(&lifted.pseudo_source);
        src.push('\n');
    }
    src.push_str("fn main() {\n");
    for exp in exps {
        for combo in arg_combos(exp.arity) {
            let args: String = combo
                .iter()
                .map(|a| format!("{a}i32"))
                .collect::<Vec<String>>()
                .join(", ");
            let argline: String = combo_label(&combo);
            src.push_str("    println!(\"");
            src.push_str(&exp.name);
            src.push(' ');
            src.push_str(&argline);
            src.push_str(" {}\", ");
            src.push_str(&exp.name);
            src.push('(');
            src.push_str(&args);
            src.push_str("));\n");
        }
    }
    src.push_str("}\n");
    src
}

fn combo_label(combo: &[i32]) -> String {
    combo
        .iter()
        .map(i32::to_string)
        .collect::<Vec<String>>()
        .join(",")
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
fn lifted_rust_simd_executes_equivalently_to_wasmtime() {
    let bytes: Vec<u8> = wat::parse_str(SIMD_DIFF).expect("assemble simd diff");
    let sigs: ModuleSignatures = extract_signatures(&bytes).expect("signatures");
    let exps: Vec<Export> = exports(&sigs);
    assert!(
        exps.len() >= 12,
        "expected a broad SIMD export set, got {}",
        exps.len()
    );

    let want: Vec<(String, Vec<i32>, Option<i32>)> = wasmtime_results(&bytes, &exps);

    let Some(rustc): Option<PathBuf> = tool_on_path("rustc") else {
        eprintln!("SKIP: rustc not on PATH for the lifted-Rust SIMD execution differential");
        return;
    };

    let src: String = lifted_rust_program(&bytes, &sigs, &exps);
    let dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe_simd_diff_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let rs: PathBuf = dir.join("simd_diff.rs");
    std::fs::write(&rs, &src).expect("write rs");
    let exe: PathBuf = dir.join(if cfg!(windows) {
        "simd_diff.exe"
    } else {
        "simd_diff"
    });
    let build: std::process::Output = Command::new(&rustc)
        .args(["--edition", "2021", "-O", "-o"])
        .arg(&exe)
        .arg(&rs)
        .output()
        .expect("spawn rustc");
    assert!(
        build.status.success(),
        "rustc rejected the lifted SIMD program\n--- stderr ---\n{}\n--- source ---\n{}",
        String::from_utf8_lossy(&build.stderr),
        src
    );

    let run: std::process::Output = Command::new(&exe)
        .output()
        .expect("run lifted simd program");
    assert!(run.status.success(), "lifted SIMD program crashed");
    let stdout: String = String::from_utf8_lossy(&run.stdout).to_string();

    let mut got: std::collections::BTreeMap<String, i32> = std::collections::BTreeMap::new();
    for line in stdout.lines() {
        let mut it: std::str::SplitWhitespace<'_> = line.split_whitespace();
        let name: &str = it.next().unwrap_or("");
        let args: &str = it.next().unwrap_or("");
        let val: i32 = it.next().unwrap_or("0").parse().unwrap_or(0);
        got.insert(format!("{name} {args}"), val);
    }

    let mut diverged: Vec<String> = Vec::new();
    for (name, combo, want_v) in &want {
        let key: String = format!("{name} {}", combo_label(combo));
        let Some(actual): Option<&i32> = got.get(&key) else {
            diverged.push(format!("{key}: missing from lifted output"));
            continue;
        };
        match want_v {
            Some(w) if w == actual => {}
            Some(w) => diverged.push(format!("{key}: wasmtime={w} lifted-rust={actual}")),
            None => {}
        }
    }
    assert!(
        diverged.is_empty(),
        "lifted Rust SIMD output diverged from wasmtime on {} case(s):\n{}",
        diverged.len(),
        diverged.join("\n")
    );
    eprintln!(
        "SIMD execution differential: {} exports, {} input cases, all lifted-Rust == wasmtime",
        exps.len(),
        want.len()
    );
}
