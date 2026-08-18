#![allow(
    dead_code,
    unreachable_pub,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_pass_wasm_deob::{
    CalleeNames, FunctionSig, LiftResult, LiftTarget, ModuleSignatures, c_runtime_prelude,
    extract_signatures, lift_function_body, rust_runtime_prelude, typescript_runtime_prelude,
};

const REFUSAL_CODE: &str = "DR-WASMDEOB-0003";
use wasmparser::{FunctionBody, Parser, Payload, ValType};
use wasmtime::{Config, Engine, Linker, Module, Store, Trap, Val};

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

const TYPESCRIPT_STRIP_PREFLIGHT: &str = concat!(
    "import { readFileSync } from 'node:fs'; ",
    "import { stripTypeScriptTypes } from 'node:module'; ",
    "import { SourceTextModule } from 'node:vm'; ",
    "const path = process.argv[1]; ",
    "const source = stripTypeScriptTypes(readFileSync(path, 'utf8'), { mode: 'strip', sourceUrl: path }); ",
    "new SourceTextModule(source, { identifier: path });"
);

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
pub fn wasmtime_trap(
    configure: fn(&mut Config),
    bytes: &[u8],
    export: &Export,
    args: &[i32],
) -> Trap {
    assert_eq!(
        export.arity,
        args.len(),
        "{}: expected {} argument(s), got {}",
        export.name,
        export.arity,
        args.len()
    );
    let eng: Engine = engine(configure);
    let module: Module = Module::new(&eng, bytes).expect("corpus compiles under wasmtime");
    let mut store: Store<()> = Store::new(&eng, ());
    let linker: Linker<()> = Linker::new(&eng);
    let instance: wasmtime::Instance = linker
        .instantiate(&mut store, &module)
        .expect("corpus instantiates");
    let func: wasmtime::Func = instance
        .get_func(&mut store, &export.name)
        .expect("export present in the corpus");
    let argv: Vec<Val> = args.iter().map(|arg: &i32| Val::I32(*arg)).collect();
    let mut result: [Val; 1] = [Val::I32(0)];
    let error: wasmtime::Error = func
        .call(&mut store, &argv, &mut result)
        .expect_err("the selected Wasmtime trap case must not return");
    let Some(trap): Option<&Trap> = error.downcast_ref::<Trap>() else {
        panic!(
            "{}: Wasmtime returned a non-trap call error: {error:#}",
            export.name
        );
    };
    *trap
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

fn execute_process(label: &str, lang: Lang, src: &str, tool: &PathBuf) -> Output {
    let scratch: disrobe_core::scratch::ScratchDir = disrobe_core::scratch::ScratchDir::create(
        &format!("disrobe_wasm_{label}_{}", lang.label()),
    )
    .expect("scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    match lang {
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
            Command::new(&exe).output().expect("run lifted rust")
        }
        Lang::TypeScript => {
            let ts: PathBuf = dir.join("lifted.ts");
            std::fs::write(&ts, src).expect("write typescript source");
            let preflight: Output = Command::new(tool)
                .arg("--no-warnings")
                .arg("--experimental-vm-modules")
                .arg("--input-type=module")
                .arg("--eval")
                .arg(TYPESCRIPT_STRIP_PREFLIGHT)
                .arg("--")
                .arg(&ts)
                .output()
                .expect("preflight lifted typescript");
            assert!(
                preflight.status.success(),
                "{label}/{}: Node rejected the lifted program during syntax preflight\n--- stderr ---\n{}\n--- source ---\n{src}",
                lang.label(),
                String::from_utf8_lossy(&preflight.stderr)
            );
            let run: Output = Command::new(tool)
                .arg("--experimental-strip-types")
                .arg("--no-warnings")
                .arg(&ts)
                .output()
                .expect("spawn node");
            run
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
            Command::new(&exe).output().expect("run lifted c")
        }
    }
}

#[must_use]
pub fn execute(label: &str, lang: Lang, src: &str, tool: &PathBuf) -> Run {
    let run: Output = execute_process(label, lang, src, tool);
    assert!(
        run.status.success(),
        "{label}/{}: lifted program exited {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        lang.label(),
        run.status.code(),
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let stdout: String =
        String::from_utf8(run.stdout).unwrap_or_else(|error: std::string::FromUtf8Error| {
            panic!(
                "{label}/{}: lifted program emitted non-UTF-8 stdout: {error}",
                lang.label()
            );
        });
    let mut values: BTreeMap<String, i32> = BTreeMap::new();
    for (line_number, line) in stdout.lines().enumerate() {
        let mut it: std::str::SplitWhitespace<'_> = line.split_whitespace();
        let Some(name): Option<&str> = it.next() else {
            panic!(
                "{label}/{}: empty output line {}",
                lang.label(),
                line_number + 1
            );
        };
        let Some(second): Option<&str> = it.next() else {
            panic!("{label}/{}: incomplete output line {line:?}", lang.label());
        };
        let third: Option<&str> = it.next();
        assert!(
            it.next().is_none(),
            "{label}/{}: output line has too many fields {line:?}",
            lang.label()
        );
        let (key, raw): (String, &str) = third.map_or_else(
            || (format!("{name} "), second),
            |raw: &str| (format!("{name} {second}"), raw),
        );
        let Ok(value): Result<i32, _> = raw.parse::<i32>() else {
            panic!("{label}/{}: unparsable result line {line:?}", lang.label());
        };
        assert!(
            values.insert(key.clone(), value).is_none(),
            "{label}/{}: duplicate output key {key:?}",
            lang.label()
        );
    }
    Run { values }
}

const TRAP_MARKER_NAMESPACE: &[u8] = b"DR-WASMDEOB-TRAP/1:";

pub fn validate_trap_contract(
    succeeded: bool,
    stdout: &[u8],
    stderr: &[u8],
    marker: &str,
) -> Result<(), String> {
    if succeeded {
        return Err("lifted program returned successfully instead of trapping".to_owned());
    }
    if !stdout.is_empty() {
        return Err(format!(
            "trapping lifted program wrote stdout: {}",
            String::from_utf8_lossy(stdout)
        ));
    }
    let marker_bytes: &[u8] = marker.as_bytes();
    if !marker_bytes.starts_with(TRAP_MARKER_NAMESPACE)
        || marker_bytes.len() == TRAP_MARKER_NAMESPACE.len()
    {
        return Err(format!(
            "trap marker is outside the required namespace: {marker:?}"
        ));
    }
    let lines: Vec<&[u8]> = stderr
        .split(|byte: &u8| *byte == b'\n')
        .map(|line: &[u8]| line.strip_suffix(b"\r").unwrap_or(line))
        .collect();
    let markers: Vec<&[u8]> = lines
        .iter()
        .copied()
        .filter(|line: &&[u8]| *line == marker_bytes)
        .collect();
    if markers.len() != 1 {
        return Err(format!(
            "expected exactly one {marker:?} stderr line, found {}; stderr: {}",
            markers.len(),
            String::from_utf8_lossy(stderr)
        ));
    }
    let namespaced: Vec<&[u8]> = lines
        .iter()
        .copied()
        .filter(|line: &&[u8]| line.starts_with(TRAP_MARKER_NAMESPACE))
        .collect();
    if namespaced.len() != 1 || namespaced[0] != marker_bytes {
        return Err(format!(
            "expected the sole namespaced trap marker to equal {marker:?}; found {} marker line(s); stderr: {}",
            namespaced.len(),
            String::from_utf8_lossy(stderr)
        ));
    }
    Ok(())
}

pub fn execute_trap(label: &str, lang: Lang, src: &str, tool: &PathBuf, marker: &str) {
    assert!(
        !src.contains(marker),
        "{label}/{}: trap marker must not occur in generated source",
        lang.label()
    );
    let run: Output = execute_process(label, lang, src, tool);
    if let Err(reason) =
        validate_trap_contract(run.status.success(), &run.stdout, &run.stderr, marker)
    {
        panic!(
            "{label}/{}: trap contract failed: {reason}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            lang.label(),
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );
    }
}

pub fn output_divergences(
    expected: &[(String, Option<i32>)],
    actual: &BTreeMap<String, i32>,
    reference: &str,
) -> Vec<String> {
    let mut divergences: Vec<String> = Vec::new();
    let mut expected_values: BTreeMap<&str, i32> = BTreeMap::new();
    for (key, expected_value) in expected {
        let Some(expected_value): Option<&i32> = expected_value.as_ref() else {
            divergences.push(format!("{key}: {reference} trapped"));
            continue;
        };
        expected_values.insert(key.as_str(), *expected_value);
        match actual.get(key) {
            Some(actual_value) if actual_value == expected_value => {}
            Some(actual_value) => divergences.push(format!(
                "{key}: {reference}={expected_value} lifted={actual_value}"
            )),
            None => divergences.push(format!("{key}: missing from the lifted output")),
        }
    }
    for (key, actual_value) in actual {
        if !expected_values.contains_key(key.as_str()) {
            divergences.push(format!(
                "{key}: unexpected lifted output value {actual_value}"
            ));
        }
    }
    divergences
}

pub struct Spec<'a> {
    pub label: &'a str,
    pub wat: &'a str,
    pub configure: fn(&mut Config),
    pub langs: &'a [Lang],
    pub min_exports: usize,
    pub ungraded: &'a [&'a str],
    pub refused: &'a [(Lang, &'a str)],
    pub battery: &'a [i32],
}

impl Spec<'_> {
    fn pinned_refusals(&self, lang: Lang) -> BTreeSet<String> {
        self.refused
            .iter()
            .filter(|(target, _): &&(Lang, &str)| *target == lang)
            .map(|(_, name): &(Lang, &str)| (*name).to_owned())
            .collect()
    }
}

pub fn statically_refused(
    bytes: &[u8],
    sigs: &ModuleSignatures,
    exps: &[Export],
    lang: Lang,
) -> BTreeSet<String> {
    let defined: &[FunctionSig] = sigs.defined();
    let cs: CalleeNames = callees(bytes, sigs);
    let mut refused: BTreeSet<String> = BTreeSet::new();
    for (index, body) in defined_bodies(bytes).iter().enumerate() {
        let Some(sig): Option<&FunctionSig> = defined.get(index) else {
            continue;
        };
        if !exps.iter().any(|e: &Export| e.name == sig.name) {
            continue;
        }
        let lifted: LiftResult = lift_function_body(body, sig, &cs, lang.target());
        if lifted.pseudo_source.contains(REFUSAL_CODE) {
            refused.insert(sig.name.clone());
        }
    }
    refused
}

fn assert_refusal_is_what_runs(
    label: &str,
    lang: Lang,
    bytes: &[u8],
    sigs: &ModuleSignatures,
    refused: &BTreeSet<String>,
    battery: &[i32],
    tool: &PathBuf,
) {
    for name in refused {
        let only: Vec<Export> = sigs
            .defined()
            .iter()
            .filter(|s: &&FunctionSig| s.name == *name)
            .map(|s: &FunctionSig| Export {
                name: s.name.clone(),
                arity: s.params.len(),
            })
            .collect();
        let src: String = lifted_source(bytes, sigs, &only, lang, battery);
        assert!(
            src.contains(REFUSAL_CODE),
            "{label}/{}/{name}: a refused export must carry its typed refusal in the emitted \
             source, so the refusal is what a reader sees rather than silence",
            lang.label()
        );
        let run: Output = execute_process(label, lang, &src, tool);
        assert!(
            !run.status.success(),
            "{label}/{}/{name}: the emitted program must refuse at run time rather than produce a \
             value the reference cannot be compared against",
            lang.label()
        );
        let stderr: String = String::from_utf8_lossy(&run.stderr).into_owned();
        assert!(
            stderr.contains(REFUSAL_CODE),
            "{label}/{}/{name}: the refusal must name {REFUSAL_CODE}; got: {stderr}",
            lang.label()
        );
    }
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
    let mut refusal_notes: Vec<String> = Vec::new();
    for lang in spec.langs {
        let Some(tool): Option<PathBuf> = toolchain(*lang) else {
            panic!(
                "{}/{}: required toolchain is absent for the execution differential",
                spec.label,
                lang.label()
            );
        };
        let refused: BTreeSet<String> = statically_refused(&bytes, &sigs, &exps, *lang);
        let pinned: BTreeSet<String> = spec.pinned_refusals(*lang);
        assert_eq!(
            refused,
            pinned,
            "{}/{}: the set of exports this target refuses to lift changed; a new refusal removes \
             a case from the value comparison and must be acknowledged in Spec::refused before it \
             stops being graded",
            spec.label,
            lang.label()
        );
        assert_refusal_is_what_runs(
            spec.label,
            *lang,
            &bytes,
            &sigs,
            &refused,
            spec.battery,
            &tool,
        );

        let comparable: Vec<Export> = exps
            .iter()
            .filter(|e: &&Export| !refused.contains(&e.name))
            .cloned()
            .collect();
        let expected: Vec<(String, Option<i32>)> = want
            .iter()
            .filter(|(key, _): &&(String, Option<i32>)| {
                comparable
                    .iter()
                    .any(|e: &Export| key.split_once(' ').is_some_and(|(n, _)| n == e.name))
            })
            .cloned()
            .collect();
        let src: String = lifted_source(&bytes, &sigs, &comparable, *lang, spec.battery);
        let run: Run = execute(spec.label, *lang, &src, &tool);
        let diverged: Vec<String> = output_divergences(&expected, &run.values, "wasmtime");
        assert!(
            diverged.is_empty(),
            "{}/{}: lifted output diverged from wasmtime on {} of {} case(s):\n{}",
            spec.label,
            lang.label(),
            diverged.len(),
            expected.len(),
            diverged.join("\n")
        );
        graded_langs.push(lang.label());
        if !refused.is_empty() {
            refusal_notes.push(format!(
                "{} refused {:?} and graded each as a typed refusal",
                lang.label(),
                refused
            ));
        }
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
    for note in &refusal_notes {
        eprintln!("{} execution differential: {note}", spec.label);
    }
}

pub fn grade_traps(spec: &Spec<'_>, marker: &str, expected_trap: Trap) {
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
    assert_eq!(
        exps.len(),
        1,
        "{}: a trap differential must exercise exactly one export",
        spec.label
    );

    assert!(
        spec.battery.is_empty(),
        "{}: a trap differential must use an empty argument battery",
        spec.label
    );
    assert_eq!(
        exps[0].arity, 0,
        "{}: a trap differential must exercise exactly one zero-argument export",
        spec.label
    );
    let trap: Trap = wasmtime_trap(spec.configure, &bytes, &exps[0], &[]);
    assert_eq!(
        trap, expected_trap,
        "{}: Wasmtime reported an unexpected trap variant",
        spec.label
    );
    assert!(
        !spec.langs.is_empty(),
        "{}: a trap differential must name at least one target",
        spec.label
    );

    for lang in spec.langs {
        let Some(tool): Option<PathBuf> = toolchain(*lang) else {
            panic!(
                "{}/{}: required toolchain is absent for the execution trap differential",
                spec.label,
                lang.label()
            );
        };
        let src: String = lifted_source(&bytes, &sigs, &exps, *lang, spec.battery);
        execute_trap(spec.label, *lang, &src, &tool, marker);
    }

    eprintln!(
        "{} trap differential: {} exports, {} trap cases, targets: {}",
        spec.label,
        exps.len(),
        1,
        spec.langs
            .iter()
            .map(|lang: &Lang| lang.label())
            .collect::<Vec<&str>>()
            .join(", ")
    );
}

pub struct ReferenceSpec<'a> {
    pub label: &'a str,
    pub wat: &'a str,
    pub reference_wat: &'a str,
    pub configure: fn(&mut Config),
    pub langs: &'a [Lang],
    pub min_exports: usize,
    pub refused: &'a [(Lang, &'a str)],
}

impl ReferenceSpec<'_> {
    fn pinned_refusals(&self, lang: Lang) -> BTreeSet<String> {
        self.refused
            .iter()
            .filter(|(target, _): &&(Lang, &str)| *target == lang)
            .map(|(_, name): &(Lang, &str)| (*name).to_owned())
            .collect()
    }
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
            panic!(
                "{}/{}: required toolchain is absent for the reference differential",
                spec.label,
                lang.label()
            );
        };
        let refused: BTreeSet<String> = statically_refused(&bytes, &sigs, &exps, *lang);
        let pinned: BTreeSet<String> = spec.pinned_refusals(*lang);
        assert_eq!(
            refused,
            pinned,
            "{}/{}: the set of exports this target refuses to lift changed; a new refusal removes \
             a case from the value comparison and must be acknowledged in ReferenceSpec::refused \
             before it stops being graded",
            spec.label,
            lang.label()
        );
        assert_refusal_is_what_runs(spec.label, *lang, &bytes, &sigs, &refused, &BATTERY, &tool);

        let comparable: Vec<Export> = exps
            .iter()
            .filter(|e: &&Export| !refused.contains(&e.name))
            .cloned()
            .collect();
        let expected: Vec<(String, Option<i32>)> = want
            .iter()
            .filter(|(key, _): &&(String, Option<i32>)| {
                comparable
                    .iter()
                    .any(|e: &Export| key.split_once(' ').is_some_and(|(n, _)| n == e.name))
            })
            .cloned()
            .collect();
        let src: String = lifted_source(&bytes, &sigs, &comparable, *lang, &BATTERY);
        let run: Run = execute(spec.label, *lang, &src, &tool);
        let diverged: Vec<String> =
            output_divergences(&expected, &run.values, "reference-wasmtime");
        assert!(
            diverged.is_empty(),
            "{}/{}: lifted output diverged from the reference module on {} of {} case(s):\n{}",
            spec.label,
            lang.label(),
            diverged.len(),
            expected.len(),
            diverged.join("\n")
        );
        graded_langs.push(lang.label());
        if !refused.is_empty() {
            eprintln!(
                "{} reference-module differential: {} refused {:?} and graded each as a typed \
                 refusal",
                spec.label,
                lang.label(),
                refused
            );
        }
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
            panic!(
                "{label}/{}: required toolchain is absent for cross-target agreement",
                lang.label()
            );
        };
        let src: String = lifted_source(&bytes, &sigs, &exps, lang, &BATTERY);
        let run: Run = execute(label, lang, &src, &tool);
        runs.push((lang, run.values));
    }
    let Some((base_lang, base)): Option<&(Lang, BTreeMap<String, i32>)> = runs.first() else {
        panic!("{label}: cross-target agreement has no target results");
    };
    let expected: Vec<(String, Option<i32>)> = base
        .iter()
        .map(|(key, value): (&String, &i32)| (key.clone(), Some(*value)))
        .collect();
    let mut diverged: Vec<String> = Vec::new();
    for (lang, values) in runs.iter().skip(1) {
        let reference: String = format!("{} versus {}", base_lang.label(), lang.label());
        diverged.extend(output_divergences(&expected, values, &reference));
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
