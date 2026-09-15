#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::missing_const_for_fn,
    clippy::too_many_lines
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_py_decompile::{NativeDecompile, decompile_micropython, decompile_pypy};
use disrobe_pass_py_disasm::alt_runtimes::micropython::{
    MpyArg, MpyBytecodeModule, MpyDecodedInsn, MpyFunction, MpyObject, parse_bytecode,
};

const MPY_HELLO: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/micropython/hello_bytecode.mpy");
const MPY_CONTROL_FLOW: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/micropython/control_flow.mpy");
const MPY_ITER_LOOPS: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/micropython/iter_loops.mpy");
const MPY_CLASSES: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/micropython/classes.mpy");
const MPY_CLOSURES: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/micropython/closures.mpy");
const MPY_GENERATORS: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/micropython/generators.mpy");
const MPY_EXCEPTIONS: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/micropython/exceptions.mpy");
const MPY_SIGNATURES: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/micropython/signatures.mpy");
const PYPY27_METHODS: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/pypy/methods.pypy27.pyc");
const PYPY39_LEGACY: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/pypy/hello_pypy39_legacy.pypy39.pyc");

const MPY_CROSS_TIMEOUT_SECS: u64 = 60;
const MPY_CROSS_MAX_CAPTURE: usize = 1024 * 1024;
const MPY_SCRATCH_PURPOSE: &str = "mpy-cross-reference-grade";
const MAX_REPORTED_DIFF_LINES: usize = 12;

const MPY_CROSS_ABSENT: &str = "SKIP (NOT GRADED): mpy-cross was not found on PATH and not at the \
     Python user Scripts directory, so the recovered MicroPython source cannot be recompiled and \
     compared against the fixture bytecode. This run proves nothing about lift fidelity. Install \
     it with `pip install mpy-cross==1.27.0` and re-run.";

#[derive(Debug)]
struct MpyFixture {
    label: &'static str,
    source_name: &'static str,
    original: &'static [u8],
    floor: f64,
    forms: &'static str,
}

static MPY_FIXTURES: [MpyFixture; 8] = [
    MpyFixture {
        label: "hello",
        source_name: "hello.py",
        original: MPY_HELLO,
        floor: 100.0,
        forms: "module-level code, positional parameters, addition, call",
    },
    MpyFixture {
        label: "control_flow",
        source_name: "control_flow.py",
        original: MPY_CONTROL_FLOW,
        floor: 100.0,
        forms: "for over range, if and else, augmented assignment, string returns",
    },
    MpyFixture {
        label: "iter_loops",
        source_name: "iter_loops.py",
        original: MPY_ITER_LOOPS,
        floor: 100.0,
        forms: "for over a sequence, for over range, accumulator returns",
    },
    MpyFixture {
        label: "classes",
        source_name: "classes.py",
        original: MPY_CLASSES,
        floor: 100.0,
        forms: "class bodies, methods, class attributes, inheritance, super()",
    },
    MpyFixture {
        label: "closures",
        source_name: "closures.py",
        original: MPY_CLOSURES,
        floor: 100.0,
        forms: "nested defs, captured cells, nonlocal rebinding, three-level nesting",
    },
    MpyFixture {
        label: "generators",
        source_name: "generators.py",
        original: MPY_GENERATORS,
        floor: 100.0,
        forms: "yield in while and for, yield from, generator with a return value",
    },
    MpyFixture {
        label: "exceptions",
        source_name: "exceptions.py",
        original: MPY_EXCEPTIONS,
        floor: 100.0,
        forms: "try and except, as-binding, else, finally, bare raise, multiple handlers",
    },
    MpyFixture {
        label: "signatures",
        source_name: "signatures.py",
        original: MPY_SIGNATURES,
        floor: 100.0,
        forms: "default arguments, keyword-only arguments, star-args, star-kwargs, keyword call \
                sites on functions and on methods",
    },
];

fn locate_python() -> Option<PathBuf> {
    if let Some(found) = uv_python() {
        return Some(found);
    }
    for cand in ["python3", "python"] {
        if which_on_path(cand).is_some() {
            return Some(PathBuf::from(cand));
        }
    }
    None
}

fn uv_python() -> Option<PathBuf> {
    let out: std::process::Output = Command::new("uv")
        .args(["python", "find", "3.12"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let raw: String = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    let path: PathBuf = PathBuf::from(raw);
    path.is_file().then_some(path)
}

fn which_on_path(exe: &str) -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        for variant in [exe.to_owned(), format!("{exe}.exe")] {
            let candidate: PathBuf = dir.join(variant);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn locate_mpy_cross() -> Option<PathBuf> {
    if let Some(found) = which_on_path("mpy-cross") {
        return Some(found);
    }
    let home: std::ffi::OsString = std::env::var_os("APPDATA")?;
    let roaming: PathBuf = PathBuf::from(home).join("Python");
    let entries: std::fs::ReadDir = std::fs::read_dir(roaming).ok()?;
    for entry in entries.flatten() {
        for variant in ["mpy-cross", "mpy-cross.exe"] {
            let candidate: PathBuf = entry.path().join("Scripts").join(variant);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn mpy_cross_version(mpy_cross: &Path) -> String {
    let args: [&str; 1] = ["--version"];
    run_captured(
        mpy_cross,
        &args,
        Duration::from_secs(MPY_CROSS_TIMEOUT_SECS),
        MPY_CROSS_MAX_CAPTURE,
    )
    .ok()
    .flatten()
    .map_or_else(
        || "version unavailable".to_owned(),
        |c: CapturedOutput| String::from_utf8_lossy(&c.stdout).trim().to_owned(),
    )
}

fn recompiles_clean(source: &str) -> Option<bool> {
    let python: PathBuf = locate_python()?;
    let script: &str = "import sys; compile(sys.stdin.read(), '<recovered>', 'exec')";
    let mut child: std::process::Child = Command::new(&python)
        .args(["-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    {
        use std::io::Write as _;
        let stdin: &mut std::process::ChildStdin = child.stdin.as_mut()?;
        stdin.write_all(source.as_bytes()).ok()?;
    }
    let out: std::process::Output = child.wait_with_output().ok()?;
    if !out.status.success() {
        eprintln!(
            "recompile stderr:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Some(out.status.success())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FnShape {
    key: String,
    label: String,
    header: String,
    steps: Vec<String>,
}

fn target_label(ordinals: &BTreeMap<usize, usize>, byte_offset: usize) -> String {
    ordinals.get(&byte_offset).map_or_else(
        || "exit".to_owned(),
        |ordinal: &usize| format!("#{ordinal}"),
    )
}

fn step_text(
    insn: &MpyDecodedInsn,
    ordinals: &BTreeMap<usize, usize>,
    module: &MpyBytecodeModule,
) -> String {
    let arg: String = match &insn.arg {
        MpyArg::None => "-".to_owned(),
        MpyArg::Qstr { text, .. } => format!("qstr {text}"),
        MpyArg::Uint(v) => format!("uint {v}"),
        MpyArg::SmallInt(v) => format!("int {v}"),
        MpyArg::Object { index } => {
            let value: String = module
                .typed_objects
                .get(usize::try_from(*index).unwrap_or(usize::MAX))
                .map_or_else(|| "<absent>".to_owned(), MpyObject::display_string);
            format!("obj {value}")
        }
        MpyArg::RelTarget { byte_offset } => format!("to {}", target_label(ordinals, *byte_offset)),
        MpyArg::UnwindTarget { byte_offset, depth } => {
            format!("to {} unwind {depth}", target_label(ordinals, *byte_offset))
        }
        MpyArg::MakeClosure {
            table_index,
            n_closed,
        } => format!("child {table_index} closed {n_closed}"),
        MpyArg::UnaryOp(o) => format!("unary {o}"),
        MpyArg::BinaryOp(o) => format!("binary {o}"),
        MpyArg::UndecodableTail {
            opcode,
            undecoded_bytes,
        } => format!("UNDECODABLE opcode {opcode:#04x} tail {undecoded_bytes}"),
    };
    format!("{} {arg}", insn.mnemonic)
}

fn canonical_steps(func: &MpyFunction, module: &MpyBytecodeModule) -> Vec<String> {
    let ordinals: BTreeMap<usize, usize> = func
        .instructions
        .iter()
        .enumerate()
        .map(|(i, insn): (usize, &MpyDecodedInsn)| (insn.offset, i))
        .collect();
    func.instructions
        .iter()
        .map(|insn: &MpyDecodedInsn| step_text(insn, &ordinals, module))
        .collect()
}

fn header_text(func: &MpyFunction) -> String {
    format!(
        "{}({}) pos {} kwonly {} defaults {} scope {:#06x} state {} exc {}",
        func.simple_name,
        func.arg_names.join(", "),
        func.n_pos_args,
        func.n_kwonly_args,
        func.n_def_pos_args,
        func.scope_flags,
        func.n_state,
        func.n_exc_stack
    )
}

fn collect_shapes(
    func: &MpyFunction,
    key: &str,
    label: &str,
    module: &MpyBytecodeModule,
    out: &mut Vec<FnShape>,
) {
    out.push(FnShape {
        key: key.to_owned(),
        label: label.to_owned(),
        header: header_text(func),
        steps: canonical_steps(func, module),
    });
    for (i, child) in func.children.iter().enumerate() {
        collect_shapes(
            child,
            &format!("{key}/{i}"),
            &format!("{label}/{}", child.simple_name),
            module,
            out,
        );
    }
}

fn shapes_of(module: &MpyBytecodeModule) -> Vec<FnShape> {
    let mut out: Vec<FnShape> = Vec::new();
    collect_shapes(&module.function, "0", "<module>", module, &mut out);
    out
}

fn lcs_matrix(left: &[String], right: &[String]) -> Vec<Vec<usize>> {
    let mut table: Vec<Vec<usize>> = vec![vec![0usize; right.len() + 1]; left.len() + 1];
    for i in (0..left.len()).rev() {
        for j in (0..right.len()).rev() {
            table[i][j] = if left[i] == right[j] {
                table[i + 1][j + 1] + 1
            } else {
                table[i + 1][j].max(table[i][j + 1])
            };
        }
    }
    table
}

fn diff_steps(left: &[String], right: &[String]) -> (usize, String) {
    let table: Vec<Vec<usize>> = lcs_matrix(left, right);
    let matched: usize = table[0][0];
    let mut report: String = String::new();
    let mut emitted: usize = 0;
    let mut i: usize = 0;
    let mut j: usize = 0;
    while i < left.len() || j < right.len() {
        if emitted >= MAX_REPORTED_DIFF_LINES {
            let _: Result<(), std::fmt::Error> = writeln!(report, "        ... diff truncated");
            break;
        }
        if i < left.len() && j < right.len() && left[i] == right[j] {
            i += 1;
            j += 1;
            continue;
        }
        if j < right.len() && (i == left.len() || table[i][j + 1] >= table[i + 1][j]) {
            let _: Result<(), std::fmt::Error> =
                writeln!(report, "        +recovered step {j}: {}", right[j]);
            j += 1;
        } else {
            let _: Result<(), std::fmt::Error> =
                writeln!(report, "        -reference step {i}: {}", left[i]);
            i += 1;
        }
        emitted += 1;
    }
    (matched, report)
}

#[derive(Debug, Clone)]
struct Agreement {
    matched: usize,
    total: usize,
    differences: Vec<String>,
}

impl Agreement {
    fn percent(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        let matched: f64 = f64::from(u32::try_from(self.matched).unwrap_or(u32::MAX));
        let total: f64 = f64::from(u32::try_from(self.total).unwrap_or(u32::MAX));
        matched * 100.0 / total
    }
}

fn compare_shapes(reference: &[FnShape], recovered: &[FnShape]) -> Agreement {
    let by_key: BTreeMap<&str, &FnShape> = recovered
        .iter()
        .map(|s: &FnShape| (s.key.as_str(), s))
        .collect();
    let mut matched: usize = 0;
    let mut total: usize = 0;
    let mut differences: Vec<String> = Vec::new();
    for reference_fn in reference {
        let Some(recovered_fn): Option<&&FnShape> = by_key.get(reference_fn.key.as_str()) else {
            total += 1 + reference_fn.steps.len();
            differences.push(format!(
                "    {} : absent from the recovered module (reference header {})",
                reference_fn.label, reference_fn.header
            ));
            continue;
        };
        total += 1;
        if reference_fn.header == recovered_fn.header {
            matched += 1;
        } else {
            differences.push(format!(
                "    {} signature: reference `{}` vs recovered `{}`",
                reference_fn.label, reference_fn.header, recovered_fn.header
            ));
        }
        total += reference_fn.steps.len().max(recovered_fn.steps.len());
        let (common, report): (usize, String) =
            diff_steps(&reference_fn.steps, &recovered_fn.steps);
        matched += common;
        if !report.is_empty() {
            differences.push(format!("    {} body:\n{report}", reference_fn.label));
        }
    }
    let reference_keys: BTreeSet<&str> =
        reference.iter().map(|s: &FnShape| s.key.as_str()).collect();
    for recovered_fn in recovered {
        if !reference_keys.contains(recovered_fn.key.as_str()) {
            total += 1 + recovered_fn.steps.len();
            differences.push(format!(
                "    {} : invented by the lift, no counterpart in the reference (header {})",
                recovered_fn.label, recovered_fn.header
            ));
        }
    }
    Agreement {
        matched,
        total,
        differences,
    }
}

#[derive(Debug)]
enum Graded {
    Compared(Agreement),
    Ungraded(String),
}

fn mpy_cross_compile(mpy_cross: &Path, source_name: &str, source: &str) -> Result<Vec<u8>, String> {
    let scratch: ScratchDir = ScratchDir::create(MPY_SCRATCH_PURPOSE)
        .map_err(|e: std::io::Error| format!("create scratch directory: {e}"))?;
    let src_path: PathBuf = scratch.path().join(source_name);
    let out_path: PathBuf = scratch.path().join("recovered.mpy");
    std::fs::write(&src_path, source.as_bytes())
        .map_err(|e: std::io::Error| format!("write recovered source: {e}"))?;
    let args: [String; 5] = [
        "-s".to_owned(),
        source_name.to_owned(),
        "-o".to_owned(),
        out_path.to_string_lossy().into_owned(),
        src_path.to_string_lossy().into_owned(),
    ];
    let captured: CapturedOutput = run_captured(
        mpy_cross,
        &args,
        Duration::from_secs(MPY_CROSS_TIMEOUT_SECS),
        MPY_CROSS_MAX_CAPTURE,
    )
    .map_err(|e: std::io::Error| format!("spawn mpy-cross: {e}"))?
    .ok_or_else(|| format!("mpy-cross timed out after {MPY_CROSS_TIMEOUT_SECS}s and was killed"))?;
    if captured.exit_code != Some(0) {
        let stderr: String = String::from_utf8_lossy(&captured.stderr).trim().to_owned();
        return Err(format!(
            "mpy-cross rejected the recovered source (exit {:?}): {stderr}",
            captured.exit_code
        ));
    }
    std::fs::read(&out_path).map_err(|e: std::io::Error| format!("read recompiled mpy: {e}"))
}

fn grade_against_reference(mpy_cross: &Path, fixture: &MpyFixture, source: &str) -> Graded {
    let recompiled: Vec<u8> = match mpy_cross_compile(mpy_cross, fixture.source_name, source) {
        Ok(bytes) => bytes,
        Err(reason) => return Graded::Ungraded(reason),
    };
    let reference: MpyBytecodeModule = parse_bytecode(fixture.original)
        .unwrap_or_else(|e| panic!("fixture {} does not parse: {e}", fixture.label));
    let recovered: MpyBytecodeModule = match parse_bytecode(&recompiled) {
        Ok(module) => module,
        Err(e) => return Graded::Ungraded(format!("recompiled mpy does not parse: {e}")),
    };
    let reference_shapes: Vec<FnShape> = shapes_of(&reference);
    let recovered_shapes: Vec<FnShape> = shapes_of(&recovered);
    for shape in reference_shapes.iter().chain(recovered_shapes.iter()) {
        assert!(
            !shape
                .steps
                .iter()
                .any(|s: &String| s.contains("UNDECODABLE")),
            "the mpy decoder left an undecodable tail in {}, so no comparison it produces can be \
             trusted: {:?}",
            shape.label,
            shape.steps
        );
    }
    Graded::Compared(compare_shapes(&reference_shapes, &recovered_shapes))
}

fn recovered_source(fixture: &MpyFixture) -> String {
    decompile_micropython(fixture.original)
        .unwrap_or_else(|e| panic!("lift {} failed: {e}", fixture.label))
        .source
}

fn fixture(label: &str) -> &'static MpyFixture {
    MPY_FIXTURES
        .iter()
        .find(|f: &&MpyFixture| f.label == label)
        .unwrap_or_else(|| panic!("no fixture named {label}"))
}

fn require_replace(source: &str, from: &str, to: &str) -> String {
    assert!(
        source.contains(from),
        "probe marker {from:?} is absent, so the probe would test nothing:\n{source}"
    );
    let mutated: String = source.replacen(from, to, 1);
    assert_ne!(
        mutated.as_str(),
        source,
        "rewriting {from:?} to {to:?} left the source unchanged"
    );
    mutated
}

fn line_index_containing(lines: &[&str], marker: &str) -> usize {
    lines
        .iter()
        .position(|l: &&str| l.contains(marker))
        .unwrap_or_else(|| panic!("no line contains {marker:?} in:\n{}", lines.join("\n")))
}

fn require_swap_lines(source: &str, first: &str, second: &str) -> String {
    let mut lines: Vec<&str> = source.lines().collect();
    let a: usize = line_index_containing(&lines, first);
    let b: usize = line_index_containing(&lines, second);
    assert_ne!(a, b, "markers {first:?} and {second:?} hit the same line");
    lines.swap(a, b);
    let mutated: String = format!("{}\n", lines.join("\n"));
    assert_ne!(
        mutated.as_str(),
        source,
        "swapping the {first:?} and {second:?} lines left the source unchanged"
    );
    mutated
}

fn require_drop_line(source: &str, marker: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let at: usize = line_index_containing(&lines, marker);
    let kept: Vec<&str> = lines
        .iter()
        .enumerate()
        .filter_map(|(i, l): (usize, &&str)| (i != at).then_some(*l))
        .collect();
    let mutated: String = format!("{}\n", kept.join("\n"));
    assert_ne!(
        mutated.as_str(),
        source,
        "dropping the {marker:?} line left the source unchanged"
    );
    mutated
}

fn first_loop_target(source: &str) -> String {
    for line in source.lines() {
        let trimmed: &str = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("for ")
            && let Some((target, _)) = rest.split_once(" in ")
        {
            assert!(
                !target.trim().is_empty(),
                "the first for-loop target is empty in:\n{source}"
            );
            return target.trim().to_owned();
        }
    }
    panic!("no for-loop found in:\n{source}")
}

#[test]
fn micropython_lift_matches_mpy_cross_reference_bytecode() {
    let Some(mpy_cross): Option<PathBuf> = locate_mpy_cross() else {
        eprintln!("{MPY_CROSS_ABSENT}");
        println!("{MPY_CROSS_ABSENT}");
        return;
    };
    println!(
        "mpy-cross reference: {} ({})",
        mpy_cross.display(),
        mpy_cross_version(&mpy_cross)
    );
    let mut ungraded: Vec<String> = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    for fixture in &MPY_FIXTURES {
        let source: String = recovered_source(fixture);
        match grade_against_reference(&mpy_cross, fixture, &source) {
            Graded::Ungraded(reason) => {
                println!("{} : UNGRADED - {reason}", fixture.label);
                ungraded.push(format!("{}: {reason}", fixture.label));
            }
            Graded::Compared(agreement) => {
                println!(
                    "{} : {}/{} units agree ({:.1}%, floor {:.1}%) [{}]",
                    fixture.label,
                    agreement.matched,
                    agreement.total,
                    agreement.percent(),
                    fixture.floor,
                    fixture.forms
                );
                for difference in &agreement.differences {
                    println!("{difference}");
                }
                if agreement.percent() < fixture.floor {
                    failures.push(format!(
                        "{}: {:.1}% is under the pinned {:.1}% floor\n{}",
                        fixture.label,
                        agreement.percent(),
                        fixture.floor,
                        agreement.differences.join("\n")
                    ));
                }
            }
        }
    }
    assert!(
        ungraded.is_empty(),
        "mpy-cross could not recompile the recovered source for {} fixture(s), so they carry no \
         agreement figure at all:\n{}",
        ungraded.len(),
        ungraded.join("\n")
    );
    assert!(
        failures.is_empty(),
        "recompiled recovered source disagrees with the fixture bytecode:\n{}",
        failures.join("\n")
    );
}

#[test]
fn micropython_reference_comparison_catches_semantic_edits() {
    let Some(mpy_cross): Option<PathBuf> = locate_mpy_cross() else {
        eprintln!("{MPY_CROSS_ABSENT}");
        println!("{MPY_CROSS_ABSENT}");
        return;
    };
    let control: &MpyFixture = fixture("control_flow");
    let loops: &MpyFixture = fixture("iter_loops");
    let classes: &MpyFixture = fixture("classes");
    let closures: &MpyFixture = fixture("closures");
    let generators: &MpyFixture = fixture("generators");
    let exceptions: &MpyFixture = fixture("exceptions");
    let signatures: &MpyFixture = fixture("signatures");
    let control_src: String = recovered_source(control);
    let loops_src: String = recovered_source(loops);
    let classes_src: String = recovered_source(classes);
    let closures_src: String = recovered_source(closures);
    let generators_src: String = recovered_source(generators);
    let exceptions_src: String = recovered_source(exceptions);
    let signatures_src: String = recovered_source(signatures);

    let probes: [(&str, &MpyFixture, String); 22] = [
        (
            "comparison flipped",
            control,
            require_replace(&control_src, " > 10", " < 10"),
        ),
        (
            "if and else bodies swapped",
            control,
            require_swap_lines(&control_src, " += ", " -= "),
        ),
        (
            "augmented assignment flipped",
            control,
            require_replace(&control_src, " += ", " -= "),
        ),
        (
            "string constant changed",
            control,
            require_replace(&control_src, "\"big\"", "\"large\""),
        ),
        (
            "module statement dropped",
            control,
            require_drop_line(&control_src, "print(classify("),
        ),
        (
            "parameter renamed",
            control,
            require_replace(
                &require_replace(&control_src, "def classify(n)", "def classify(q)"),
                "range(n)",
                "range(q)",
            ),
        ),
        (
            "loop bound changed",
            loops,
            require_replace(&loops_src, "range(", "range(1 + "),
        ),
        (
            "base class dropped",
            classes,
            require_replace(&classes_src, "class Doubler(Counter)", "class Doubler"),
        ),
        (
            "super call replaced with a direct call",
            classes,
            require_replace(&classes_src, "super().bump(", "self.bump("),
        ),
        (
            "class attribute value changed",
            classes,
            require_replace(&classes_src, "step = 1", "step = 2"),
        ),
        (
            "captured cell replaced with a parameter read",
            closures,
            require_replace(&closures_src, "return base + x", "return x + x"),
        ),
        (
            "nonlocal rebinding turned into a local one",
            closures,
            require_replace(&closures_src, "nonlocal ", "del "),
        ),
        (
            "yield turned into a return",
            generators,
            require_replace(&generators_src, "yield from ", "return "),
        ),
        (
            "trailing yield dropped",
            generators,
            require_drop_line(&generators_src, "yield 0"),
        ),
        (
            "except type widened",
            exceptions,
            require_replace(&exceptions_src, "except ValueError:", "except:"),
        ),
        (
            "finally clause dropped",
            exceptions,
            require_drop_line(&exceptions_src, "finally:"),
        ),
        (
            "second handler dropped",
            exceptions,
            require_replace(&exceptions_src, "except TypeError:", "except ValueError:"),
        ),
        (
            "default argument value changed",
            signatures,
            require_replace(&signatures_src, "b=2", "b=3"),
        ),
        (
            "keyword-only parameter made positional",
            signatures,
            require_replace(&signatures_src, "def kwonly(a, *, b", "def kwonly(a, b"),
        ),
        (
            "keyword argument passed positionally",
            signatures,
            require_replace(&signatures_src, "kwonly(1, b=2)", "kwonly(1, 2)"),
        ),
        (
            "star-kwargs parameter dropped",
            signatures,
            require_replace(&signatures_src, ", **varkwargs)", ")"),
        ),
        (
            "keyword argument to a method passed positionally",
            signatures,
            require_replace(&signatures_src, ".take(1, b=2)", ".take(1, 2)"),
        ),
    ];

    for (name, target, mutated) in probes {
        let graded: Graded = grade_against_reference(&mpy_cross, target, &mutated);
        match graded {
            Graded::Ungraded(reason) => {
                panic!(
                    "probe `{name}` on {} produced source mpy-cross rejected, so the probe proves \
                     nothing: {reason}\n{mutated}",
                    target.label
                );
            }
            Graded::Compared(agreement) => {
                println!(
                    "probe `{name}` on {}: {}/{} ({:.1}%)",
                    target.label,
                    agreement.matched,
                    agreement.total,
                    agreement.percent()
                );
                assert!(
                    !agreement.differences.is_empty() && agreement.matched < agreement.total,
                    "probe `{name}` on {} was NOT caught: the comparison still reports {}/{} with \
                     no differences, so it cannot detect this class of wrong source:\n{mutated}",
                    target.label,
                    agreement.matched,
                    agreement.total
                );
            }
        }
    }
}

#[test]
fn micropython_reference_comparison_ignores_incidental_rewrites() {
    let Some(mpy_cross): Option<PathBuf> = locate_mpy_cross() else {
        eprintln!("{MPY_CROSS_ABSENT}");
        println!("{MPY_CROSS_ABSENT}");
        return;
    };
    let control: &MpyFixture = fixture("control_flow");
    let control_src: String = recovered_source(control);
    let loop_target: String = first_loop_target(&control_src);
    let renamed_local: String = control_src.replace(&loop_target, "reflowed_index");
    assert_ne!(
        renamed_local, control_src,
        "renaming the loop target {loop_target:?} left the source unchanged"
    );

    let rewrites: [(&str, String); 3] = [
        ("blank lines added", format!("\n\n{control_src}\n\n")),
        (
            "redundant parentheses added",
            require_replace(&control_src, " > 10", " > (10)"),
        ),
        ("local variable renamed", renamed_local),
    ];

    for (name, mutated) in rewrites {
        let graded: Graded = grade_against_reference(&mpy_cross, control, &mutated);
        match graded {
            Graded::Ungraded(reason) => {
                panic!("rewrite `{name}` was rejected by mpy-cross: {reason}\n{mutated}")
            }
            Graded::Compared(agreement) => {
                println!(
                    "rewrite `{name}`: {}/{} ({:.1}%)",
                    agreement.matched,
                    agreement.total,
                    agreement.percent()
                );
                assert!(
                    agreement.differences.is_empty() && agreement.matched == agreement.total,
                    "rewrite `{name}` changes no MicroPython bytecode, so it must compare equal, \
                     got {}/{}:\n{}",
                    agreement.matched,
                    agreement.total,
                    agreement.differences.join("\n")
                );
            }
        }
    }
}

#[test]
fn micropython_hello_recovers_add_and_call() {
    let out: NativeDecompile = decompile_micropython(MPY_HELLO).expect("lift mpy hello");
    let src: &str = &out.source;
    let lifter_coverage_flag: bool = out.recovered_directly;
    assert!(
        lifter_coverage_flag,
        "the lifter reports it modelled every opcode it saw; this is a coverage counter it \
         computes about its own output, not a fidelity measure - fidelity is graded against \
         mpy-cross in micropython_lift_matches_mpy_cross_reference_bytecode: {src}"
    );
    assert!(src.contains("def add(a, b)"), "missing add def in: {src}");
    assert!(src.contains("return"), "missing return in: {src}");
    assert!(src.contains("print"), "missing print call in: {src}");
    if let Some(ok) = recompiles_clean(src) {
        assert!(ok, "recovered mpy hello must recompile:\n{src}");
    }
}

#[test]
fn micropython_control_flow_recovers_range_for_and_branch() {
    let out: NativeDecompile =
        decompile_micropython(MPY_CONTROL_FLOW).expect("lift mpy control flow");
    let src: &str = &out.source;
    let lifter_coverage_flag: bool = out.recovered_directly;
    assert!(
        lifter_coverage_flag,
        "the lifter reports it modelled every opcode it saw; this is a coverage counter it \
         computes about its own output, not a fidelity measure: {src}"
    );
    assert!(src.contains("def classify(n)"), "missing classify: {src}");
    assert!(src.contains("for "), "missing for-loop: {src}");
    assert!(
        src.contains("range("),
        "range for-loop not recovered: {src}"
    );
    assert!(
        src.contains("if ") && src.contains("else"),
        "if/else not recovered: {src}"
    );
    if let Some(ok) = recompiles_clean(src) {
        assert!(ok, "recovered mpy control_flow must recompile:\n{src}");
    }
}

#[test]
fn micropython_iter_loops_recovers_both_for_forms() {
    let out: NativeDecompile = decompile_micropython(MPY_ITER_LOOPS).expect("lift iter loops");
    let src: &str = &out.source;
    assert!(src.contains("def walk(items)"), "missing walk: {src}");
    assert!(src.contains("def counted(n)"), "missing counted: {src}");
    assert!(
        src.contains("for ") && src.contains("range("),
        "range-for not recovered: {src}"
    );
    if let Some(ok) = recompiles_clean(src) {
        assert!(ok, "recovered mpy iter_loops must recompile:\n{src}");
    }
}

#[test]
fn pypy27_methods_recovers_source() {
    let out: NativeDecompile = decompile_pypy(PYPY27_METHODS).expect("decompile pypy27");
    let src: &str = &out.source;
    let lifter_coverage_flag: bool = out.recovered_directly;
    assert!(
        lifter_coverage_flag,
        "the lifter reports it modelled every opcode it saw; this is a coverage counter it \
         computes about its own output, not a fidelity measure: {src}"
    );
    assert!(src.contains("def run"), "missing run def: {src}");
    assert!(src.contains("class Box"), "missing Box class: {src}");
    assert!(src.contains("def double"), "missing double method: {src}");
    assert!(
        src.contains(".double()"),
        "PyPy CALL_METHOD not recovered as method call: {src}"
    );
    if let Some(ok) = recompiles_clean(src) {
        assert!(ok, "recovered pypy27 source must recompile:\n{src}");
    }
}

#[test]
fn pypy39_legacy_recovers_source() {
    let out: NativeDecompile = decompile_pypy(PYPY39_LEGACY).expect("decompile pypy39 legacy");
    let src: &str = &out.source;
    let lifter_coverage_flag: bool = out.recovered_directly;
    assert!(
        lifter_coverage_flag,
        "the lifter reports it modelled every opcode it saw; this is a coverage counter it \
         computes about its own output, not a fidelity measure: {src}"
    );
    assert!(src.contains("def greet"), "missing greet def: {src}");
    if let Some(ok) = recompiles_clean(src) {
        assert!(ok, "recovered pypy39 source must recompile:\n{src}");
    }
}
