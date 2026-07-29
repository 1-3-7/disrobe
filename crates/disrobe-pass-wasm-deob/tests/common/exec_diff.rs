#![allow(
    dead_code,
    unreachable_pub,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_pass_wasm_deob::{
    CalleeNames, FunctionSig, LiftResult, LiftTarget, ModuleSignatures, c_runtime_prelude,
    extract_signatures, lift_function_body, rust_runtime_prelude, typescript_runtime_prelude,
};
use wasmparser::{FunctionBody, Parser, Payload, ValType};
use wasmtime::{Config, Engine, Linker, Module, Store, Val};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Rust,
    TypeScript,
    C,
}

impl Lang {
    pub const fn target(self) -> LiftTarget {
        match self {
            Self::Rust => LiftTarget::Rust,
            Self::TypeScript => LiftTarget::TypeScript,
            Self::C => LiftTarget::C,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::TypeScript => "typescript",
            Self::C => "c",
        }
    }
}

pub const ALL_LANGS: [Lang; 3] = [Lang::Rust, Lang::TypeScript, Lang::C];

#[derive(Debug, Clone)]
pub struct Export {
    pub name: String,
    pub arity: usize,
}

pub const BATTERY: [i32; 8] = [0, 1, 2, 7, -1, -3, 255, i32::MIN / 2];

pub const NON_TRAPPING_BATTERY: [i32; 8] = [1, 2, 3, 7, -3, 255, i32::MIN, 1_518_500_249];

#[must_use]
pub fn arg_combos(arity: usize, battery: &[i32]) -> Vec<Vec<i32>> {
    match arity {
        0 => vec![Vec::new()],
        1 => battery.iter().map(|x: &i32| vec![*x]).collect(),
        _ => {
            let mut out: Vec<Vec<i32>> = Vec::with_capacity(battery.len() * battery.len());
            for a in battery {
                for c in battery {
                    out.push(vec![*a, *c]);
                }
            }
            out
        }
    }
}

#[must_use]
pub fn combo_label(combo: &[i32]) -> String {
    combo
        .iter()
        .map(i32::to_string)
        .collect::<Vec<String>>()
        .join(",")
}

#[must_use]
pub fn defined_bodies(bytes: &[u8]) -> Vec<FunctionBody<'_>> {
    let mut out: Vec<FunctionBody<'_>> = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        if let Ok(Payload::CodeSectionEntry(body)) = payload {
            out.push(body);
        }
    }
    out
}

#[must_use]
pub fn callees(bytes: &[u8], sigs: &ModuleSignatures) -> CalleeNames {
    CalleeNames::from_module(
        bytes,
        sigs.callee_names(),
        sigs.call_signatures(),
        sigs.call_signatures(),
    )
}

#[must_use]
pub fn exports(sigs: &ModuleSignatures, ungraded: &[&str]) -> Vec<Export> {
    sigs.defined()
        .iter()
        .filter(|s: &&FunctionSig| s.exported)
        .filter(|s: &&FunctionSig| !ungraded.contains(&s.name.as_str()))
        .filter(|s: &&FunctionSig| {
            s.params.iter().all(|t: &ValType| *t == ValType::I32) && s.results == vec![ValType::I32]
        })
        .map(|s: &FunctionSig| Export {
            name: s.name.clone(),
            arity: s.params.len(),
        })
        .collect()
}

#[must_use]
pub fn engine(configure: fn(&mut Config)) -> Engine {
    let mut config: Config = Config::new();
    configure(&mut config);
    Engine::new(&config).expect("wasmtime engine for the configured proposal set")
}

#[must_use]
pub fn wasmtime_results(
    configure: fn(&mut Config),
    bytes: &[u8],
    exps: &[Export],
    battery: &[i32],
) -> Vec<(String, Option<i32>)> {
    let eng: Engine = engine(configure);
    let module: Module = Module::new(&eng, bytes).expect("corpus compiles under wasmtime");
    let mut store: Store<()> = Store::new(&eng, ());
    let linker: Linker<()> = Linker::new(&eng);
    let instance: wasmtime::Instance = linker
        .instantiate(&mut store, &module)
        .expect("corpus instantiates");
    let mut out: Vec<(String, Option<i32>)> = Vec::new();
    for exp in exps {
        let func: wasmtime::Func = instance
            .get_func(&mut store, &exp.name)
            .expect("export present in the corpus");
        for combo in arg_combos(exp.arity, battery) {
            let argv: Vec<Val> = combo.iter().map(|a: &i32| Val::I32(*a)).collect();
            let mut res: [Val; 1] = [Val::I32(0)];
            let got: Option<i32> = match func.call(&mut store, &argv, &mut res) {
                Ok(()) => match res[0] {
                    Val::I32(v) => Some(v),
                    _ => None,
                },
                Err(_) => None,
            };
            out.push((format!("{} {}", exp.name, combo_label(&combo)), got));
        }
    }
    out
}

#[must_use]
pub fn lifted_source(
    bytes: &[u8],
    sigs: &ModuleSignatures,
    exps: &[Export],
    lang: Lang,
    battery: &[i32],
) -> String {
    let defined: &[FunctionSig] = sigs.defined();
    let cs: CalleeNames = callees(bytes, sigs);
    let mut src: String = match lang {
        Lang::Rust => rust_runtime_prelude().to_owned(),
        Lang::TypeScript => typescript_runtime_prelude().to_owned(),
        Lang::C => {
            let mut head: String = "#include <stdio.h>\n".to_owned();
            head.push_str(c_runtime_prelude());
            head
        }
    };
    src.push('\n');
    for (i, body) in defined_bodies(bytes).iter().enumerate() {
        let sig: &FunctionSig = &defined[i];
        let lifted: LiftResult = lift_function_body(body, sig, &cs, lang.target());
        src.push_str(&lifted.pseudo_source);
        src.push('\n');
    }
    src.push_str(&driver(exps, lang, battery));
    src
}

fn driver(exps: &[Export], lang: Lang, battery: &[i32]) -> String {
    let mut out: String = String::new();
    match lang {
        Lang::Rust => out.push_str("fn main() {\n"),
        Lang::TypeScript => {}
        Lang::C => out.push_str("int main(void) {\n"),
    }
    for exp in exps {
        for combo in arg_combos(exp.arity, battery) {
            let key: String = format!("{} {}", exp.name, combo_label(&combo));
            match lang {
                Lang::Rust => {
                    let args: String = combo
                        .iter()
                        .map(|a: &i32| format!("{a}i32"))
                        .collect::<Vec<String>>()
                        .join(", ");
                    let _: Result<(), std::fmt::Error> =
                        writeln!(out, "    println!(\"{key} {{}}\", {}({args}));", exp.name);
                }
                Lang::TypeScript => {
                    let args: String = combo
                        .iter()
                        .map(i32::to_string)
                        .collect::<Vec<String>>()
                        .join(", ");
                    let _: Result<(), std::fmt::Error> = writeln!(
                        out,
                        "console.log(\"{key} \" + String({}({args})));",
                        exp.name
                    );
                }
                Lang::C => {
                    let args: String = combo
                        .iter()
                        .map(i32::to_string)
                        .collect::<Vec<String>>()
                        .join(", ");
                    let _: Result<(), std::fmt::Error> = writeln!(
                        out,
                        "    printf(\"{key} %d\\n\", (int){}({args}));",
                        exp.name
                    );
                }
            }
        }
    }
    match lang {
        Lang::Rust => out.push_str("}\n"),
        Lang::TypeScript => {}
        Lang::C => out.push_str("    return 0;\n}\n"),
    }
    out
}

#[must_use]
pub fn tool_on_path(tool: &str) -> Option<PathBuf> {
    let probe: &str = if cfg!(windows) { "where" } else { "which" };
    let output: Output = Command::new(probe).arg(tool).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout: String = String::from_utf8_lossy(&output.stdout).to_string();
    let first: &str = stdout.lines().next()?.trim();
    (!first.is_empty()).then(|| PathBuf::from(first))
}

#[must_use]
pub fn c_compiler() -> Option<PathBuf> {
    tool_on_path("cc")
        .or_else(|| tool_on_path("clang"))
        .or_else(|| tool_on_path("gcc"))
}

#[must_use]
pub fn toolchain(lang: Lang) -> Option<PathBuf> {
    match lang {
        Lang::Rust => tool_on_path("rustc"),
        Lang::TypeScript => tool_on_path("node"),
        Lang::C => c_compiler(),
    }
}

pub struct Run {
    pub values: BTreeMap<String, i32>,
}

#[must_use]
pub fn execute(label: &str, lang: Lang, src: &str, tool: &PathBuf) -> Run {
    let scratch: disrobe_core::scratch::ScratchDir = disrobe_core::scratch::ScratchDir::create(
        &format!("disrobe_wasm_{label}_{}", lang.label()),
    )
    .expect("scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    let stdout: String = match lang {
        Lang::Rust => {
            let rs: PathBuf = dir.join("lifted.rs");
            std::fs::write(&rs, src).expect("write rust source");
            let exe: PathBuf = dir.join(if cfg!(windows) {
                "lifted.exe"
            } else {
                "lifted"
            });
            let build: Output = Command::new(tool)
                .args(["--edition", "2021", "-O", "-o"])
                .arg(&exe)
                .arg(&rs)
                .output()
                .expect("spawn rustc");
            assert!(
                build.status.success(),
                "{label}/{}: rustc rejected the lifted program\n--- stderr ---\n{}\n--- source ---\n{src}",
                lang.label(),
                String::from_utf8_lossy(&build.stderr)
            );
            let run: Output = Command::new(&exe).output().expect("run lifted rust");
            assert!(
                run.status.success(),
                "{label}/{}: lifted rust program exited {:?}\n{}",
                lang.label(),
                run.status.code(),
                String::from_utf8_lossy(&run.stderr)
            );
            String::from_utf8_lossy(&run.stdout).to_string()
        }
        Lang::TypeScript => {
            let ts: PathBuf = dir.join("lifted.ts");
            std::fs::write(&ts, src).expect("write typescript source");
            let run: Output = Command::new(tool)
                .arg("--experimental-strip-types")
                .arg("--no-warnings")
                .arg(&ts)
                .output()
                .expect("spawn node");
            assert!(
                run.status.success(),
                "{label}/{}: node rejected or crashed on the lifted program\n--- stderr ---\n{}",
                lang.label(),
                String::from_utf8_lossy(&run.stderr)
            );
            String::from_utf8_lossy(&run.stdout).to_string()
        }
        Lang::C => {
            let c: PathBuf = dir.join("lifted.c");
            std::fs::write(&c, src).expect("write c source");
            let exe: PathBuf = dir.join(if cfg!(windows) {
                "lifted.exe"
            } else {
                "lifted"
            });
            let mut build: Command = Command::new(tool);
            build.arg("-O2").arg("-std=c11").arg("-o").arg(&exe).arg(&c);
            if !cfg!(windows) {
                build.arg("-lm");
            }
            let built: Output = build.output().expect("spawn c compiler");
            assert!(
                built.status.success(),
                "{label}/{}: the C compiler rejected the lifted program\n--- stderr ---\n{}\n--- source ---\n{src}",
                lang.label(),
                String::from_utf8_lossy(&built.stderr)
            );
            let run: Output = Command::new(&exe).output().expect("run lifted c");
            assert!(
                run.status.success(),
                "{label}/{}: lifted C program exited {:?}\n{}",
                lang.label(),
                run.status.code(),
                String::from_utf8_lossy(&run.stderr)
            );
            String::from_utf8_lossy(&run.stdout).to_string()
        }
    };
    let mut values: BTreeMap<String, i32> = BTreeMap::new();
    for line in stdout.lines() {
        let mut it: std::str::SplitWhitespace<'_> = line.split_whitespace();
        let Some(name): Option<&str> = it.next() else {
            continue;
        };
        let Some(args): Option<&str> = it.next() else {
            continue;
        };
        let Some(raw): Option<&str> = it.next() else {
            continue;
        };
        let Ok(value): Result<i32, _> = raw.parse::<i32>() else {
            panic!("{label}/{}: unparsable result line {line:?}", lang.label());
        };
        values.insert(format!("{name} {args}"), value);
    }
    Run { values }
}

pub struct Spec<'a> {
    pub label: &'a str,
    pub wat: &'a str,
    pub configure: fn(&mut Config),
    pub langs: &'a [Lang],
    pub min_exports: usize,
    pub ungraded: &'a [&'a str],
    pub battery: &'a [i32],
}

pub fn grade(spec: &Spec<'_>) {
    let bytes: Vec<u8> = wat::parse_str(spec.wat)
        .unwrap_or_else(|e| panic!("assemble the {} corpus: {e}", spec.label));
    let sigs: ModuleSignatures = extract_signatures(&bytes).expect("signatures");
    let exps: Vec<Export> = exports(&sigs, spec.ungraded);
    assert!(
        exps.len() >= spec.min_exports,
        "{}: expected at least {} graded exports, got {}",
        spec.label,
        spec.min_exports,
        exps.len()
    );

    let want: Vec<(String, Option<i32>)> =
        wasmtime_results(spec.configure, &bytes, &exps, spec.battery);
    let trapped: Vec<&String> = want
        .iter()
        .filter(|(_, v): &&(String, Option<i32>)| v.is_none())
        .map(|(k, _): &(String, Option<i32>)| k)
        .collect();
    assert!(
        trapped.is_empty(),
        "{}: the corpus must be trap-free so every case is comparable; trapped: {trapped:?}",
        spec.label
    );

    let mut graded_langs: Vec<&'static str> = Vec::new();
    for lang in spec.langs {
        let Some(tool): Option<PathBuf> = toolchain(*lang) else {
            eprintln!(
                "SKIP {}/{}: no toolchain on PATH for the execution differential",
                spec.label,
                lang.label()
            );
            continue;
        };
        let src: String = lifted_source(&bytes, &sigs, &exps, *lang, spec.battery);
        let run: Run = execute(spec.label, *lang, &src, &tool);
        let mut diverged: Vec<String> = Vec::new();
        for (key, want_v) in &want {
            let Some(w): Option<&i32> = want_v.as_ref() else {
                continue;
            };
            match run.values.get(key) {
                Some(got) if got == w => {}
                Some(got) => diverged.push(format!("{key}: wasmtime={w} lifted={got}")),
                None => diverged.push(format!("{key}: missing from the lifted output")),
            }
        }
        assert!(
            diverged.is_empty(),
            "{}/{}: lifted output diverged from wasmtime on {} of {} case(s):\n{}",
            spec.label,
            lang.label(),
            diverged.len(),
            want.len(),
            diverged.join("\n")
        );
        graded_langs.push(lang.label());
    }

    eprintln!(
        "{} execution differential: {} exports, {} cases, wasmtime-graded targets: {}{}",
        spec.label,
        exps.len(),
        want.len(),
        if graded_langs.is_empty() {
            "none".to_owned()
        } else {
            graded_langs.join(", ")
        },
        if spec.ungraded.is_empty() {
            String::new()
        } else {
            format!(" (ungraded exports: {:?})", spec.ungraded)
        }
    );
}

pub struct ReferenceSpec<'a> {
    pub label: &'a str,
    pub wat: &'a str,
    pub reference_wat: &'a str,
    pub configure: fn(&mut Config),
    pub langs: &'a [Lang],
    pub min_exports: usize,
}

pub fn grade_against_reference(spec: &ReferenceSpec<'_>) {
    let bytes: Vec<u8> = wat::parse_str(spec.wat)
        .unwrap_or_else(|e| panic!("assemble the {} corpus: {e}", spec.label));
    let reference: Vec<u8> = wat::parse_str(spec.reference_wat)
        .unwrap_or_else(|e| panic!("assemble the {} reference module: {e}", spec.label));
    let sigs: ModuleSignatures = extract_signatures(&bytes).expect("signatures");
    let ref_sigs: ModuleSignatures = extract_signatures(&reference).expect("reference signatures");
    let exps: Vec<Export> = exports(&sigs, &[]);
    let ref_exps: Vec<Export> = exports(&ref_sigs, &[]);
    assert!(
        exps.len() >= spec.min_exports,
        "{}: expected at least {} graded exports, got {}",
        spec.label,
        spec.min_exports,
        exps.len()
    );
    let shape = |e: &Export| (e.name.clone(), e.arity);
    assert_eq!(
        exps.iter().map(shape).collect::<Vec<(String, usize)>>(),
        ref_exps.iter().map(shape).collect::<Vec<(String, usize)>>(),
        "{}: the reference module must expose the same exports in the same order so the call \
         sequence and therefore the module state evolve identically",
        spec.label
    );

    let want: Vec<(String, Option<i32>)> =
        wasmtime_results(spec.configure, &reference, &ref_exps, &BATTERY);
    let trapped: Vec<&String> = want
        .iter()
        .filter(|(_, v): &&(String, Option<i32>)| v.is_none())
        .map(|(k, _): &(String, Option<i32>)| k)
        .collect();
    assert!(
        trapped.is_empty(),
        "{}: the reference module must be trap-free; trapped: {trapped:?}",
        spec.label
    );

    let mut graded_langs: Vec<&'static str> = Vec::new();
    for lang in spec.langs {
        let Some(tool): Option<PathBuf> = toolchain(*lang) else {
            eprintln!(
                "SKIP {}/{}: no toolchain on PATH for the reference differential",
                spec.label,
                lang.label()
            );
            continue;
        };
        let src: String = lifted_source(&bytes, &sigs, &exps, *lang, &BATTERY);
        let run: Run = execute(spec.label, *lang, &src, &tool);
        let mut diverged: Vec<String> = Vec::new();
        for (key, want_v) in &want {
            let Some(w): Option<&i32> = want_v.as_ref() else {
                continue;
            };
            match run.values.get(key) {
                Some(got) if got == w => {}
                Some(got) => diverged.push(format!("{key}: reference-wasmtime={w} lifted={got}")),
                None => diverged.push(format!("{key}: missing from the lifted output")),
            }
        }
        assert!(
            diverged.is_empty(),
            "{}/{}: lifted output diverged from the reference module on {} of {} case(s):\n{}",
            spec.label,
            lang.label(),
            diverged.len(),
            want.len(),
            diverged.join("\n")
        );
        graded_langs.push(lang.label());
    }

    eprintln!(
        "{} reference-module differential: {} exports, {} cases, graded targets: {}",
        spec.label,
        exps.len(),
        want.len(),
        if graded_langs.is_empty() {
            "none".to_owned()
        } else {
            graded_langs.join(", ")
        }
    );
}

pub fn cross_target_agreement(label: &str, wat: &str, min_exports: usize) {
    let bytes: Vec<u8> =
        wat::parse_str(wat).unwrap_or_else(|e| panic!("assemble the {label} corpus: {e}"));
    let sigs: ModuleSignatures = extract_signatures(&bytes).expect("signatures");
    let exps: Vec<Export> = exports(&sigs, &[]);
    assert!(
        exps.len() >= min_exports,
        "{label}: expected at least {min_exports} exports, got {}",
        exps.len()
    );

    let mut runs: Vec<(Lang, BTreeMap<String, i32>)> = Vec::new();
    for lang in ALL_LANGS {
        let Some(tool): Option<PathBuf> = toolchain(lang) else {
            eprintln!("SKIP {label}/{}: no toolchain on PATH", lang.label());
            continue;
        };
        let src: String = lifted_source(&bytes, &sigs, &exps, lang, &BATTERY);
        let run: Run = execute(label, lang, &src, &tool);
        runs.push((lang, run.values));
    }
    let Some((base_lang, base)): Option<&(Lang, BTreeMap<String, i32>)> = runs.first() else {
        eprintln!("SKIP {label}: no toolchain available for any target");
        return;
    };
    let mut diverged: Vec<String> = Vec::new();
    for (lang, values) in runs.iter().skip(1) {
        for (key, base_v) in base {
            match values.get(key) {
                Some(got) if got == base_v => {}
                Some(got) => diverged.push(format!(
                    "{key}: {}={base_v} {}={got}",
                    base_lang.label(),
                    lang.label()
                )),
                None => diverged.push(format!("{key}: missing from the {} run", lang.label())),
            }
        }
    }
    assert!(
        diverged.is_empty(),
        "{label}: the lifted targets disagree on {} case(s):\n{}",
        diverged.len(),
        diverged.join("\n")
    );
    eprintln!(
        "{label} cross-target agreement: {} exports, {} cases, targets: {}",
        exps.len(),
        base.len(),
        runs.iter()
            .map(|(l, _): &(Lang, BTreeMap<String, i32>)| l.label())
            .collect::<Vec<&str>>()
            .join(", ")
    );
}
