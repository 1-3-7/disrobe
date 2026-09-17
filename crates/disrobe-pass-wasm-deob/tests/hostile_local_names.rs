#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_wasm_deob::{
    CalleeNames, FunctionSig, LiftTarget, ModuleSignatures, c_runtime_prelude, extract_signatures,
    lift_function_body, rust_runtime_prelude, typescript_runtime_prelude,
};
use wasmparser::{FunctionBody, Parser, Payload};

const TOOL_TIMEOUT: Duration = Duration::from_mins(2);
const TOOL_CAPTURE: usize = 512 * 1024;
const PARAM_COUNT: usize = 2;
const LOCAL_COUNT: usize = 4;
const LONG_NAME_LEN: usize = 4096;

const BASE_MODULE: &str = r#"(module
  (func (export "subject") (param i32 i32) (result i32)
    (local i32) (local i32) (local i32) (local i32)
    local.get 0
    local.set 2
    local.get 1
    local.set 3
    local.get 2
    local.set 4
    local.get 3
    local.set 5
    local.get 4
    local.get 5
    i32.add))
"#;

fn long_name() -> String {
    "n".repeat(LONG_NAME_LEN)
}

fn cases() -> Vec<(String, [String; LOCAL_COUNT])> {
    let fixed: [(&str, [&str; LOCAL_COUNT]); 11] = [
        ("empty", ["", "b", "c", "d"]),
        ("only_separators", ["...", "---", "   ", "___"]),
        ("rust_reserved", ["crate", "extern", "pub", "Self"]),
        ("c_reserved", ["long", "unsigned", "typedef", "sizeof"]),
        (
            "typescript_reserved",
            ["null", "typeof", "instanceof", "export"],
        ),
        ("collides_with_fallback", ["p0", "p1", "l4", "l5"]),
        ("collides_with_temporary", ["t0", "t1", "t2", "t3"]),
        ("sanitises_to_the_same", ["a.b", "a_b", "a-b", "a b"]),
        ("leading_digit", ["9lives", "0", "1_2", "3d"]),
        ("punctuation", ["a.b-c d", "e/f\\g", "h(i)j", "k[l]m"]),
        (
            "non_ascii",
            ["e\u{0301}", "\u{202E}abc", "\u{4f60}\u{597d}", "\u{1f600}"],
        ),
    ];

    let mut out: Vec<(String, [String; LOCAL_COUNT])> = fixed
        .into_iter()
        .map(|(label, names): (&str, [&str; LOCAL_COUNT])| {
            (label.to_owned(), names.map(|name: &str| name.to_owned()))
        })
        .collect();
    out.push((
        "control_bytes".to_owned(),
        [
            "a\u{0}b".to_owned(),
            "c\u{7}d".to_owned(),
            "e\u{1b}f".to_owned(),
            "g\u{7f}h".to_owned(),
        ],
    ));
    out.push((
        "very_long".to_owned(),
        [
            long_name(),
            format!("{}x", long_name()),
            "c".to_owned(),
            "d".to_owned(),
        ],
    ));
    out
}

fn leb128(mut value: u32, into: &mut Vec<u8>) {
    loop {
        let mut byte: u8 = u8::try_from(value & 0x7f).unwrap_or(0);
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        into.push(byte);
        if value == 0 {
            return;
        }
    }
}

fn wasm_name(text: &str, into: &mut Vec<u8>) {
    leb128(u32::try_from(text.len()).unwrap_or(u32::MAX), into);
    into.extend_from_slice(text.as_bytes());
}

fn local_name_section(names: &[String; LOCAL_COUNT]) -> Vec<u8> {
    let mut entries: Vec<u8> = Vec::new();
    leb128(u32::try_from(names.len()).unwrap_or(u32::MAX), &mut entries);
    for (i, name) in names.iter().enumerate() {
        leb128(
            u32::try_from(PARAM_COUNT + i).unwrap_or(u32::MAX),
            &mut entries,
        );
        wasm_name(name, &mut entries);
    }

    let mut per_function: Vec<u8> = Vec::new();
    leb128(1, &mut per_function);
    leb128(0, &mut per_function);
    per_function.extend_from_slice(&entries);

    let mut subsection: Vec<u8> = Vec::new();
    subsection.push(2);
    leb128(
        u32::try_from(per_function.len()).unwrap_or(u32::MAX),
        &mut subsection,
    );
    subsection.extend_from_slice(&per_function);

    let mut payload: Vec<u8> = Vec::new();
    wasm_name("name", &mut payload);
    payload.extend_from_slice(&subsection);

    let mut section: Vec<u8> = Vec::new();
    section.push(0);
    leb128(
        u32::try_from(payload.len()).unwrap_or(u32::MAX),
        &mut section,
    );
    section.extend_from_slice(&payload);
    section
}

fn module_with_names(names: &[String; LOCAL_COUNT]) -> Vec<u8> {
    let mut bytes: Vec<u8> = wat::parse_str(BASE_MODULE).expect("assemble the base module");
    bytes.extend_from_slice(&local_name_section(names));
    bytes
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

fn lift_body(bytes: &[u8], target: LiftTarget) -> String {
    let sigs: ModuleSignatures = extract_signatures(bytes).expect("extract signatures");
    let defined: &[FunctionSig] = sigs.defined();
    let callees: CalleeNames = CalleeNames::with_signatures(
        sigs.callee_names(),
        sigs.call_signatures(),
        sigs.call_signatures(),
    );
    let bodies: Vec<FunctionBody<'_>> = defined_bodies(bytes);
    assert_eq!(
        bodies.len(),
        1,
        "the base module must contribute exactly one defined body"
    );
    lift_function_body(&bodies[0], &defined[0], &callees, target).pseudo_source
}

fn lift(bytes: &[u8], target: LiftTarget) -> String {
    let prelude: &str = match target {
        LiftTarget::Rust => rust_runtime_prelude(),
        LiftTarget::TypeScript => typescript_runtime_prelude(),
        LiftTarget::C => c_runtime_prelude(),
        LiftTarget::Wat => "",
    };
    format!("{prelude}\n{}", lift_body(bytes, target))
}

fn tool(name: &str) -> Option<PathBuf> {
    let probe: &str = if cfg!(windows) { "where" } else { "which" };
    let output: std::process::Output = Command::new(probe).arg(name).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let first: String = String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()?
        .trim()
        .to_owned();
    if first.is_empty() {
        None
    } else {
        Some(PathBuf::from(first))
    }
}

fn required_tool(candidates: &[&str], gate: &str) -> PathBuf {
    for candidate in candidates {
        if let Some(found) = tool(candidate) {
            return found;
        }
    }
    panic!(
        "DR-WASMDEOB-HOSTILENAME: {gate} requires one of {candidates:?} on PATH. This grader \
         compiles emitted source, so without the compiler it proves nothing and must not report \
         success."
    );
}

fn rustc_binary() -> PathBuf {
    let shim: PathBuf = required_tool(&["rustc"], "the hostile-name Rust gate");
    let printed: std::process::Output = Command::new(&shim)
        .arg("--print")
        .arg("sysroot")
        .output()
        .expect("ask rustc for its sysroot");
    if !printed.status.success() {
        return shim;
    }
    let sysroot: String = String::from_utf8_lossy(&printed.stdout).trim().to_owned();
    if sysroot.is_empty() {
        return shim;
    }
    for name in ["rustc.exe", "rustc"] {
        let candidate: PathBuf = PathBuf::from(&sysroot).join("bin").join(name);
        if candidate.is_file() {
            return candidate;
        }
    }
    shim
}

fn run(tool_path: &Path, args: &[OsString]) -> CapturedOutput {
    run_captured(tool_path, args, TOOL_TIMEOUT, TOOL_CAPTURE)
        .expect("spawn the compiler")
        .expect("the compiler must finish within its deadline")
}

fn rejection(out: &CapturedOutput) -> String {
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    let stdout: String = String::from_utf8_lossy(&out.stdout).into_owned();
    let detail: String = format!("{}\n{}", stderr.trim(), stdout.trim());
    let first: String = detail
        .lines()
        .filter(|line: &&str| !line.trim().is_empty())
        .take(4)
        .collect::<Vec<&str>>()
        .join(" | ");
    format!("exit {:?}: {first}", out.exit_code)
}

fn report(gate: &str, failures: &[String]) {
    assert!(
        failures.is_empty(),
        "{} of the hostile local-name cases failed the {gate} gate:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

fn scratch(label: &str) -> disrobe_core::scratch::ScratchDir {
    disrobe_core::scratch::ScratchDir::create(&format!("wasm-hostile-names-{label}"))
        .expect("create scratch directory")
}

fn declared_identifiers(source: &str, target: LiftTarget) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in source.lines() {
        let line: &str = raw.trim();
        let rest: Option<&str> = match target {
            LiftTarget::Rust => line.strip_prefix("let mut "),
            LiftTarget::TypeScript => line.strip_prefix("let "),
            LiftTarget::C => line
                .strip_prefix("int32_t ")
                .or_else(|| line.strip_prefix("int64_t "))
                .or_else(|| line.strip_prefix("float "))
                .or_else(|| line.strip_prefix("double ")),
            LiftTarget::Wat => None,
        };
        let Some(rest): Option<&str> = rest else {
            continue;
        };
        let name: &str = rest.split([':', ' ', '=', ';']).next().unwrap_or("");
        if !name.is_empty() {
            out.push(name.to_owned());
        }
    }
    out
}

#[test]
fn a_hostile_local_name_never_drops_a_local_or_collapses_two_onto_one() {
    let mut failures: Vec<String> = Vec::new();
    for (label, names) in cases() {
        let bytes: Vec<u8> = module_with_names(&names);
        for target in [LiftTarget::Rust, LiftTarget::TypeScript, LiftTarget::C] {
            let source: String = lift_body(&bytes, target);
            if !source.contains("subject") {
                failures.push(format!(
                    "{label}/{target:?}: the exported function was dropped from the emitted source"
                ));
                continue;
            }
            let declared: Vec<String> = declared_identifiers(&source, target);
            if declared.len() < LOCAL_COUNT {
                failures.push(format!(
                    "{label}/{target:?}: declared {} binding(s) for {LOCAL_COUNT} non-parameter \
                     locals: {declared:?}",
                    declared.len()
                ));
            }
            let distinct: BTreeSet<&String> = declared.iter().collect();
            if distinct.len() != declared.len() {
                failures.push(format!(
                    "{label}/{target:?}: bindings collapsed onto one identifier: {declared:?}"
                ));
            }
        }
    }
    report("distinct-identifier", &failures);
}

#[test]
fn a_hostile_local_name_still_compiles_as_rust() {
    let compiler: PathBuf = rustc_binary();
    let mut failures: Vec<String> = Vec::new();
    for (label, names) in cases() {
        let source: String = lift(&module_with_names(&names), LiftTarget::Rust);
        let dir: disrobe_core::scratch::ScratchDir = scratch(&label);
        let path: PathBuf = dir.path().join("lifted.rs");
        std::fs::write(&path, &source).expect("write the emitted Rust");
        let args: Vec<OsString> = vec![
            OsString::from("--edition"),
            OsString::from("2021"),
            OsString::from("--crate-type"),
            OsString::from("lib"),
            OsString::from("--emit=metadata"),
            OsString::from("-o"),
            dir.path().join("lifted.rmeta").into_os_string(),
            path.into_os_string(),
        ];
        let out: CapturedOutput = run(&compiler, &args);
        if out.exit_code != Some(0) {
            failures.push(format!(
                "{label}: [{}] {}",
                compiler.display(),
                rejection(&out)
            ));
        }
    }
    report("Rust compile", &failures);
}

#[test]
fn a_hostile_local_name_still_compiles_as_c() {
    let compiler: PathBuf = required_tool(&["cc", "clang", "gcc"], "the hostile-name C gate");
    let mut failures: Vec<String> = Vec::new();
    for (label, names) in cases() {
        let source: String = lift(&module_with_names(&names), LiftTarget::C);
        let dir: disrobe_core::scratch::ScratchDir = scratch(&label);
        let path: PathBuf = dir.path().join("lifted.c");
        std::fs::write(&path, &source).expect("write the emitted C");
        let args: Vec<OsString> = vec![
            OsString::from("-std=c11"),
            OsString::from("-c"),
            path.into_os_string(),
            OsString::from("-o"),
            dir.path().join("lifted.o").into_os_string(),
        ];
        let out: CapturedOutput = run(&compiler, &args);
        if out.exit_code != Some(0) {
            failures.push(format!(
                "{label}: [{}] {}",
                compiler.display(),
                rejection(&out)
            ));
        }
    }
    report("C compile", &failures);
}

#[test]
fn a_hostile_local_name_still_parses_as_typescript() {
    let compiler: PathBuf =
        required_tool(&["node", "node.exe"], "the hostile-name TypeScript gate");
    let mut failures: Vec<String> = Vec::new();
    for (label, names) in cases() {
        let source: String = lift(&module_with_names(&names), LiftTarget::TypeScript);
        let dir: disrobe_core::scratch::ScratchDir = scratch(&label);
        let path: PathBuf = dir.path().join("lifted.ts");
        std::fs::write(&path, &source).expect("write the emitted TypeScript");
        let args: Vec<OsString> = vec![
            OsString::from("--experimental-strip-types"),
            OsString::from("--no-warnings"),
            path.into_os_string(),
        ];
        let out: CapturedOutput = run(&compiler, &args);
        if out.exit_code != Some(0) {
            failures.push(format!(
                "{label}: [{}] {}",
                compiler.display(),
                rejection(&out)
            ));
        }
    }
    report("TypeScript parse", &failures);
}

const MEASURED_ACCEPTED_BUT_KEPT_RESERVED: [(LiftTarget, &str); 24] = [
    (LiftTarget::Rust, "case"),
    (LiftTarget::Rust, "default"),
    (LiftTarget::Rust, "export"),
    (LiftTarget::Rust, "switch"),
    (LiftTarget::Rust, "union"),
    (LiftTarget::C, "bool"),
    (LiftTarget::C, "complex"),
    (LiftTarget::C, "export"),
    (LiftTarget::C, "imaginary"),
    (LiftTarget::C, "int32_t"),
    (LiftTarget::C, "int64_t"),
    (LiftTarget::C, "typeof"),
    (LiftTarget::TypeScript, "any"),
    (LiftTarget::TypeScript, "as"),
    (LiftTarget::TypeScript, "async"),
    (LiftTarget::TypeScript, "boolean"),
    (LiftTarget::TypeScript, "declare"),
    (LiftTarget::TypeScript, "extern"),
    (LiftTarget::TypeScript, "number"),
    (LiftTarget::TypeScript, "string"),
    (LiftTarget::TypeScript, "struct"),
    (LiftTarget::TypeScript, "symbol"),
    (LiftTarget::TypeScript, "undefined"),
    (LiftTarget::TypeScript, "union"),
];

#[test]
fn words_measured_as_accepted_stay_reserved_on_purpose() {
    let mut unprefixed: Vec<String> = Vec::new();
    for (target, word) in MEASURED_ACCEPTED_BUT_KEPT_RESERVED {
        let names: [String; LOCAL_COUNT] = [
            word.to_owned(),
            "b".to_owned(),
            "c".to_owned(),
            "d".to_owned(),
        ];
        let source: String = lift_body(&module_with_names(&names), target);
        if declared_identifiers(&source, target)
            .iter()
            .any(|d: &String| d == word)
        {
            unprefixed.push(format!("{target:?}/{word}"));
        }
    }
    assert!(
        unprefixed.is_empty(),
        "{} word(s) measured as ACCEPTED by their target compiler are no longer being prefixed: \
         {unprefixed:?}. Each entry in this list was compiled individually as a plain local \
         binding against rustc 1.96.1, gcc 16.2.0 -std=c11, and node v24.19 in ES-module mode, \
         and each one compiled. They are kept reserved anyway, deliberately: over-prefixing costs \
         one leading underscore, under-prefixing emits source that does not compile, and an \
         isolated probe cannot model the emitter's own context. `int32_t int32_t = 0;` is the \
         clearest case, because it compiles alone and then poisons every later declaration in the \
         same function. Removing an entry here is a product decision, not a cleanup",
        unprefixed.len()
    );
}

#[test]
fn the_typescript_gate_rejects_a_program_the_emitter_must_never_produce() {
    let node: PathBuf = required_tool(&["node", "node.exe"], "the hostile-name TypeScript gate");
    let dir: disrobe_core::scratch::ScratchDir = scratch("gate-self-check");
    let path: PathBuf = dir.path().join("collision.ts");
    std::fs::write(&path, "let a: number = 1;\nlet a: number = 2;\n")
        .expect("write the collision probe");
    let args: Vec<OsString> = vec![
        OsString::from("--experimental-strip-types"),
        OsString::from("--no-warnings"),
        path.into_os_string(),
    ];
    let out: CapturedOutput = run(&node, &args);
    assert!(
        out.exit_code != Some(0),
        "the TypeScript gate accepted two bindings under one identifier, so it cannot detect the \
         collision it exists to catch. Node with --check does exactly this, because --check skips \
         type stripping and never reaches the program"
    );
}
