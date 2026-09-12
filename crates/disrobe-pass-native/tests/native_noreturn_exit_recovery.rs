#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines,
    clippy::too_many_arguments
)]

mod common;

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::Duration;

use common::{
    CompileOutcome, CompilerFamily, CompilerId, MAX_CAPTURE_BYTES, available_compilers,
    codegen_flags, compile_object_reasoned, function_code, scratch_dir, strip_includes,
};
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_native::{
    ProgramFunction, PseudoAbi, RecoveredFunction, RecoveredProgram, recover_program,
};

const GRADED_OPT_LEVELS: [&str; 4] = ["-O0", "-O1", "-O2", "-O3"];
const RUN_TIMEOUT: Duration = Duration::from_secs(20);
const TOOTH_TIMEOUT: Duration = Duration::from_secs(5);
const LINK_TIMEOUT: Duration = Duration::from_mins(1);
const PER_COMPILER_EQUIVALENT_FLOOR: usize = 16;
const PER_COMPILER_STATUS_FLOOR: usize = 24;

const TRANSLATION_UNIT: &str = "\
extern void exit(int);\n\
long long nr_abort_guard(long long a, long long b, long long c){ if (a == 4242) { __builtin_abort(); } if (b < 0) return -1; return a + b + c; }\n\
long long nr_exit_guard(long long a, long long b, long long c){ if (a == 4242) { exit(7); } if (b < 0) return -1; return a + b + c; }\n\
long long nr_exit_in_loop(long long a, long long b, long long c){ long long s = 0; for (long long i = 0; i < 32; i++) { if (a + i == 4242) exit(9); s += i + b; } return s + c; }\n\
long long nr_only_exit(long long a, long long b, long long c){ exit((int)(a + b + c)); }\n\
__attribute__((noinline,noclone)) long long nr_helper(long long x){ return x * 3; }\n\
long long nr_call_then_exit(long long a, long long b, long long c){ long long v = nr_helper(a); if (v == 4242) { exit(11); } return v + b + c; }\n\
";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AbiTarget {
    MsX64,
    SysV,
}

impl AbiTarget {
    const fn tag(self) -> &'static str {
        match self {
            Self::MsX64 => "ms_x64",
            Self::SysV => "sysv",
        }
    }

    const fn as_pseudo(self) -> PseudoAbi {
        match self {
            Self::MsX64 => PseudoAbi::MsX64,
            Self::SysV => PseudoAbi::SysV,
        }
    }
}

const ABI_TARGETS: [AbiTarget; 2] = [AbiTarget::MsX64, AbiTarget::SysV];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExitStatusProbe {
    None,
    Fixed(i32),
    SumOfInputs,
}

struct NoreturnShape {
    tag: &'static str,
    entry: &'static str,
    functions: &'static [&'static str],
    value_inputs: &'static [(i64, i64, i64)],
    status_inputs: &'static [(i64, i64, i64)],
    status: ExitStatusProbe,
    required_c_fragments: &'static [&'static str],
}

const SHAPES: &[NoreturnShape] = &[
    NoreturnShape {
        tag: "abort_guard",
        entry: "nr_abort_guard",
        functions: &["nr_abort_guard"],
        value_inputs: &[
            (0, 0, 0),
            (5, 7, 9),
            (-3, -4, 11),
            (17, -1, 2),
            (99, 100, 101),
        ],
        status_inputs: &[],
        status: ExitStatusProbe::None,
        required_c_fragments: &["extern void abort(void);", "abort();"],
    },
    NoreturnShape {
        tag: "exit_guard",
        entry: "nr_exit_guard",
        functions: &["nr_exit_guard"],
        value_inputs: &[
            (0, 0, 0),
            (5, 7, 9),
            (-3, -4, 11),
            (17, -1, 2),
            (99, 100, 101),
        ],
        status_inputs: &[(4242, 1, 1)],
        status: ExitStatusProbe::Fixed(7),
        required_c_fragments: &["extern void exit(int);", "exit((int)"],
    },
    NoreturnShape {
        tag: "exit_in_loop",
        entry: "nr_exit_in_loop",
        functions: &["nr_exit_in_loop"],
        value_inputs: &[(0, 1, 2), (3, 4, 5), (-7, 2, 1), (10, -2, 3)],
        status_inputs: &[(4242, 1, 1), (4230, 2, 3)],
        status: ExitStatusProbe::Fixed(9),
        required_c_fragments: &["extern void exit(int);", "exit((int)"],
    },
    NoreturnShape {
        tag: "only_exit",
        entry: "nr_only_exit",
        functions: &["nr_only_exit"],
        value_inputs: &[],
        status_inputs: &[(1, 2, 4), (10, 20, 3), (0, 0, 5)],
        status: ExitStatusProbe::SumOfInputs,
        required_c_fragments: &["extern void exit(int);", "exit((int)"],
    },
    NoreturnShape {
        tag: "call_then_exit",
        entry: "nr_call_then_exit",
        functions: &["nr_call_then_exit", "nr_helper"],
        value_inputs: &[(0, 0, 0), (5, 7, 9), (-3, -4, 11), (100, 1, 2)],
        status_inputs: &[(1414, 1, 1)],
        status: ExitStatusProbe::Fixed(11),
        required_c_fragments: &["extern void exit(int);", "exit((int)"],
    },
];

#[derive(Debug, Clone)]
enum Verdict {
    Equivalent,
    Mismatch(String),
    Abstained(String),
    NotGraded(String),
}

impl Verdict {
    const fn label(&self) -> &'static str {
        match self {
            Self::Equivalent => "equivalent",
            Self::Mismatch(_) => "mismatch",
            Self::Abstained(_) => "abstained",
            Self::NotGraded(_) => "not_graded",
        }
    }

    fn detail(&self) -> &str {
        match self {
            Self::Equivalent => "",
            Self::Mismatch(d) | Self::Abstained(d) | Self::NotGraded(d) => d,
        }
    }
}

#[derive(Debug, Clone)]
struct Row {
    shape: &'static str,
    compiler: String,
    opt: &'static str,
    abi: &'static str,
    verdict: Verdict,
    status_checked: usize,
    tooth_confirmed: bool,
}

fn row_key(row: &Row) -> String {
    format!("{}|{}|{}|{}", row.shape, row.compiler, row.opt, row.abi)
}

fn compile_flags(family: CompilerFamily) -> Vec<&'static str> {
    let mut flags: Vec<&'static str> = codegen_flags(family).to_vec();
    flags.push("-c");
    flags
}

struct RecoveredShape {
    tu: String,
    entry_params: usize,
}

fn recover_shape(
    object: &[u8],
    shape: &'static NoreturnShape,
    abi: PseudoAbi,
) -> Result<RecoveredShape, String> {
    let mut functions: Vec<ProgramFunction> = Vec::with_capacity(shape.functions.len());
    for &name in shape.functions {
        let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(object, name) else {
            return Err(format!("{name} symbol not located in object"));
        };
        functions.push(ProgramFunction {
            name: format!("rec_{name}"),
            address: base,
            code,
        });
    }
    let result: RecoveredProgram = recover_program(object, &functions, abi);
    if !result.unrecovered.is_empty() {
        return Err(result
            .unrecovered
            .iter()
            .map(|u| format!("{}: {}", u.name, u.reason))
            .collect::<Vec<String>>()
            .join("; "));
    }
    let mut tu: String = String::new();
    let mut entry_params: usize = 0;
    for (index, &name) in shape.functions.iter().enumerate() {
        let recovered: &RecoveredFunction = &result.recovered[index];
        tu.push_str(&strip_includes(&recovered.source));
        tu.push('\n');
        if name == shape.entry {
            entry_params = recovered.signature.callable_arity();
        }
    }
    Ok(RecoveredShape { tu, entry_params })
}

fn argument_list(entry_params: usize) -> String {
    (0..entry_params)
        .map(|i: usize| {
            if i < 3 {
                format!("(uint64_t)in{i}")
            } else {
                "0ULL".to_owned()
            }
        })
        .collect::<Vec<String>>()
        .join(", ")
}

fn value_driver(shape: &'static NoreturnShape, entry_params: usize, tu: &str) -> String {
    let entry: &str = shape.entry;
    let inputs: String = shape
        .value_inputs
        .iter()
        .map(|(a, b, c): &(i64, i64, i64)| format!("{{{a}LL,{b}LL,{c}LL}}"))
        .collect::<Vec<String>>()
        .join(",");
    let args: String = argument_list(entry_params);
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n{tu}\n\
         extern long long {entry}(long long, long long, long long);\n\
         int main(void) {{\n\
         \x20   long long inputs[][3] = {{ {inputs} }};\n\
         \x20   size_t n = sizeof(inputs)/sizeof(inputs[0]);\n\
         \x20   for (size_t k = 0; k < n; k++) {{\n\
         \x20       long long in0 = inputs[k][0], in1 = inputs[k][1], in2 = inputs[k][2];\n\
         \x20       unsigned long long want = (unsigned long long){entry}(in0, in1, in2);\n\
         \x20       unsigned long long got = (unsigned long long)rec_{entry}({args});\n\
         \x20       if (want != got) {{ printf(\"MISMATCH {entry} in=%lld,%lld,%lld want=%llu got=%llu\\n\", in0, in1, in2, want, got); return 1; }}\n\
         \x20   }}\n\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n",
    )
}

fn status_driver(
    shape: &'static NoreturnShape,
    entry_params: usize,
    tu: &str,
    input: (i64, i64, i64),
) -> String {
    let entry: &str = shape.entry;
    let (a, b, c): (i64, i64, i64) = input;
    let args: String = argument_list(entry_params);
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n{tu}\n\
         int main(void) {{\n\
         \x20   long long in0 = {a}LL, in1 = {b}LL, in2 = {c}LL;\n\
         \x20   printf(\"REACHED\\n\");\n\
         \x20   fflush(stdout);\n\
         \x20   (void)rec_{entry}({args});\n\
         \x20   printf(\"RETURNED\\n\");\n\
         \x20   return 0;\n\
         }}\n",
    )
}

fn expected_status(shape: &'static NoreturnShape, input: (i64, i64, i64)) -> Option<i32> {
    match shape.status {
        ExitStatusProbe::None => None,
        ExitStatusProbe::Fixed(code) => Some(code),
        ExitStatusProbe::SumOfInputs => {
            let (a, b, c): (i64, i64, i64) = input;
            i32::try_from(a.checked_add(b)?.checked_add(c)?).ok()
        }
    }
}

struct RunResult {
    stdout: String,
    exit_code: Option<i32>,
}

#[derive(Debug)]
enum RunFailure {
    Timeout,
    Reason(String),
}

fn link_and_run(
    compiler: &str,
    driver: &str,
    link_object: &[u8],
    tag: &str,
) -> Result<RunResult, String> {
    link_and_run_bounded(compiler, driver, link_object, tag, RUN_TIMEOUT).map_err(
        |failure: RunFailure| match failure {
            RunFailure::Timeout => "harness did not terminate within the watchdog".to_owned(),
            RunFailure::Reason(reason) => reason,
        },
    )
}

fn link_and_run_bounded(
    compiler: &str,
    driver: &str,
    link_object: &[u8],
    tag: &str,
    run_timeout: Duration,
) -> Result<RunResult, RunFailure> {
    let scratch: disrobe_core::scratch::ScratchDir = scratch_dir("disrobe-noreturn-link");
    let dir: &Path = scratch.path();
    let object_path: PathBuf = dir.join(format!("{tag}_link.o"));
    std::fs::write(&object_path, link_object)
        .map_err(|e| RunFailure::Reason(format!("write link object: {e}")))?;
    let driver_path: PathBuf = dir.join(format!("{tag}_driver.c"));
    std::fs::write(&driver_path, driver.as_bytes())
        .map_err(|e| RunFailure::Reason(format!("write driver: {e}")))?;
    let exe: PathBuf = dir.join(if cfg!(windows) {
        format!("{tag}.exe")
    } else {
        tag.to_owned()
    });
    let link_args: [OsString; 5] = [
        OsStr::new("-O1").to_owned(),
        OsStr::new("-o").to_owned(),
        exe.as_os_str().to_owned(),
        driver_path.as_os_str().to_owned(),
        object_path.as_os_str().to_owned(),
    ];
    match run_captured(
        Path::new(compiler),
        &link_args,
        LINK_TIMEOUT,
        MAX_CAPTURE_BYTES,
    ) {
        Ok(Some(captured)) if captured.exit_code == Some(0) => {}
        Ok(Some(captured)) => {
            return Err(RunFailure::Reason(format!(
                "link failed: {}",
                String::from_utf8_lossy(&captured.stderr)
            )));
        }
        Ok(None) => {
            return Err(RunFailure::Reason(
                "link did not complete within the watchdog".to_owned(),
            ));
        }
        Err(e) => return Err(RunFailure::Reason(format!("linker failed to spawn: {e}"))),
    }
    let no_args: [&str; 0] = [];
    match run_captured(&exe, &no_args, run_timeout, MAX_CAPTURE_BYTES) {
        Ok(Some(captured)) => Ok(RunResult {
            stdout: String::from_utf8_lossy(&captured.stdout).into_owned(),
            exit_code: captured.exit_code,
        }),
        Ok(None) => Err(RunFailure::Timeout),
        Err(e) => Err(RunFailure::Reason(format!("harness failed to spawn: {e}"))),
    }
}

const NESTED_BLOCK_INDENT: usize = 8;

fn leading_spaces(line: &str) -> usize {
    line.len().saturating_sub(line.trim_start().len())
}

fn return_after_noreturn_call(tu: &str) -> Option<String> {
    let lines: Vec<&str> = tu.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        let body: &str = line.trim();
        let is_exit_call: bool = body.starts_with("abort();")
            || body.starts_with("exit((int)")
            || body.starts_with("__builtin_trap();");
        if !is_exit_call || leading_spaces(line) < NESTED_BLOCK_INDENT {
            continue;
        }
        let next: Option<&&str> =
            lines
                .get(index.saturating_add(1)..)
                .and_then(|rest: &[&str]| {
                    rest.iter()
                        .find(|candidate: &&&str| !candidate.trim().is_empty())
                });
        if let Some(following) = next
            && following.trim().starts_with("return ")
        {
            return Some(following.trim().to_owned());
        }
    }
    None
}

fn defuse_exit_calls(tu: &str) -> Option<String> {
    if !tu.contains("exit((int)") {
        return None;
    }
    let replaced: String = tu
        .replace(
            "extern void exit(int);",
            "static void nr_defused(int x){ (void)x; }",
        )
        .replace("exit((int)", "nr_defused((int)");
    Some(replaced)
}

fn grade_row(
    shape: &'static NoreturnShape,
    compiler: &CompilerId,
    opt: &'static str,
    abi: AbiTarget,
    want_tooth: bool,
) -> Row {
    let mut row: Row = Row {
        shape: shape.tag,
        compiler: compiler.bin.to_owned(),
        opt,
        abi: abi.tag(),
        verdict: Verdict::NotGraded("ungraded".to_owned()),
        status_checked: 0,
        tooth_confirmed: false,
    };
    let tag: String = format!(
        "nr_{}_{}_{}_{}",
        shape.tag,
        compiler.bin,
        opt.trim_start_matches('-'),
        abi.tag()
    );
    let host_flags: Vec<&str> = compile_flags(compiler.family);
    let scratch: disrobe_core::scratch::ScratchDir = scratch_dir("disrobe-noreturn-host");
    let host_out: PathBuf = scratch.path().join(format!("{tag}_host.o"));
    let host_object: Vec<u8> = match compile_object_reasoned(
        compiler.bin,
        opt,
        &host_flags,
        TRANSLATION_UNIT,
        &host_out,
    ) {
        CompileOutcome::Object(bytes) => bytes,
        CompileOutcome::Rejected(reason) => {
            row.verdict = Verdict::NotGraded(reason);
            return row;
        }
    };
    let object_for_recovery: Vec<u8> = match abi {
        AbiTarget::MsX64 => host_object.clone(),
        AbiTarget::SysV => {
            let sysv_flags: [&str; 4] = [
                "--target=x86_64-unknown-linux-gnu",
                "-fno-stack-protector",
                "-fcf-protection=none",
                "-c",
            ];
            let sysv_scratch: disrobe_core::scratch::ScratchDir =
                scratch_dir("disrobe-noreturn-sysv");
            let sysv_out: PathBuf = sysv_scratch.path().join(format!("{tag}_sysv.o"));
            match compile_object_reasoned("clang", opt, &sysv_flags, TRANSLATION_UNIT, &sysv_out) {
                CompileOutcome::Object(bytes) => bytes,
                CompileOutcome::Rejected(reason) => {
                    row.verdict = Verdict::NotGraded(format!("sysv cross-compile: {reason}"));
                    return row;
                }
            }
        }
    };
    let recovered: RecoveredShape =
        match recover_shape(&object_for_recovery, shape, abi.as_pseudo()) {
            Ok(recovered) => recovered,
            Err(reason) => {
                row.verdict = Verdict::Abstained(reason);
                return row;
            }
        };
    for fragment in shape.required_c_fragments {
        assert!(
            recovered.tu.contains(fragment),
            "the recovered body for {} must name its non-returning callee: `{fragment}` missing from\n{}",
            row_key(&row),
            recovered.tu
        );
    }
    assert!(
        !recovered.tu.contains("sub_"),
        "the recovered body for {} left an unnamed callee, so the non-returning import was not resolved:\n{}",
        row_key(&row),
        recovered.tu
    );
    if let Some(dead) = return_after_noreturn_call(&recovered.tu) {
        panic!(
            "the recovered body for {} follows a non-returning call with `{dead}`, which reads a return register the path never defines:\n{}",
            row_key(&row),
            recovered.tu
        );
    }
    if recovered.entry_params < 3 {
        row.verdict = Verdict::NotGraded(format!(
            "the recovered prototype takes only {} parameters, so the three source arguments cannot be bound positionally",
            recovered.entry_params
        ));
        return row;
    }

    if !shape.value_inputs.is_empty() {
        let driver: String = value_driver(shape, recovered.entry_params, &recovered.tu);
        match link_and_run(compiler.bin, &driver, &host_object, &format!("{tag}_value")) {
            Ok(result) => {
                if !result.stdout.contains("OK") || result.stdout.contains("MISMATCH") {
                    row.verdict = Verdict::Mismatch(result.stdout.trim().to_owned());
                    return row;
                }
            }
            Err(reason) => {
                row.verdict = Verdict::NotGraded(format!("value link/run: {reason}"));
                return row;
            }
        }
    }

    for (index, &input) in shape.status_inputs.iter().enumerate() {
        let Some(expected): Option<i32> = expected_status(shape, input) else {
            continue;
        };
        let driver: String = status_driver(shape, recovered.entry_params, &recovered.tu, input);
        let run_tag: String = format!("{tag}_status{index}");
        match link_and_run(compiler.bin, &driver, &host_object, &run_tag) {
            Ok(result) => {
                assert!(
                    result.stdout.contains("REACHED"),
                    "the status harness for {} never entered the recovered body",
                    row_key(&row)
                );
                assert!(
                    !result.stdout.contains("RETURNED"),
                    "the recovered body for {} returned from a path the compiler ended with a non-returning call",
                    row_key(&row)
                );
                assert_eq!(
                    result.exit_code,
                    Some(expected),
                    "the recovered body for {} exited with {:?} where the source exits with {expected}",
                    row_key(&row),
                    result.exit_code
                );
                row.status_checked = row.status_checked.saturating_add(1);
            }
            Err(reason) => {
                row.verdict = Verdict::NotGraded(format!("status link/run: {reason}"));
                return row;
            }
        }
    }

    if row.status_checked > 0
        && want_tooth
        && let Some(defused) = defuse_exit_calls(&recovered.tu)
    {
        let input: (i64, i64, i64) = shape.status_inputs[0];
        let expected: Option<i32> = expected_status(shape, input);
        let driver: String = status_driver(shape, recovered.entry_params, &defused, input);
        match link_and_run_bounded(
            compiler.bin,
            &driver,
            &host_object,
            &format!("{tag}_tooth"),
            TOOTH_TIMEOUT,
        ) {
            Ok(result) => {
                assert_ne!(
                    result.exit_code,
                    expected,
                    "the status grade for {} has no teeth: removing the non-returning call still produced the source exit status",
                    row_key(&row)
                );
                row.tooth_confirmed = true;
            }
            Err(RunFailure::Timeout) => {
                row.tooth_confirmed = true;
            }
            Err(RunFailure::Reason(reason)) => {
                panic!("tooth harness for {} failed: {reason}", row_key(&row))
            }
        }
    }

    row.verdict = Verdict::Equivalent;
    row
}

#[test]
fn noreturn_library_exits_recover_and_reproduce_the_source_exit_status() {
    let compilers: Vec<CompilerId> = available_compilers();
    assert!(
        !compilers.is_empty(),
        "the non-returning exit grade needs a host C compiler: none of gcc/clang/cc answered --version"
    );
    let mut rows: Vec<Row> = Vec::new();
    let mut toothed: std::collections::BTreeSet<&'static str> = std::collections::BTreeSet::new();
    for shape in SHAPES {
        for compiler in &compilers {
            for &opt in &GRADED_OPT_LEVELS {
                for &abi in &ABI_TARGETS {
                    let want_tooth: bool = !toothed.contains(shape.tag);
                    let row: Row = grade_row(shape, compiler, opt, abi, want_tooth);
                    if row.tooth_confirmed {
                        toothed.insert(shape.tag);
                    }
                    rows.push(row);
                }
            }
        }
    }

    let mut equivalent: usize = 0;
    let mut status_rows: usize = 0;
    let mut teeth: usize = 0;
    let mut abstained: usize = 0;
    let mut mismatched: Vec<String> = Vec::new();
    let mut unnamed: Vec<String> = Vec::new();
    let mut equivalent_by_shape: std::collections::BTreeMap<&'static str, usize> = SHAPES
        .iter()
        .map(|shape: &NoreturnShape| (shape.tag, 0usize))
        .collect();

    for row in &rows {
        println!(
            "row {} verdict={} status_checked={} tooth={} detail={}",
            row_key(row),
            row.verdict.label(),
            row.status_checked,
            row.tooth_confirmed,
            row.verdict.detail()
        );
        if row.tooth_confirmed {
            teeth = teeth.saturating_add(1);
        }
        status_rows = status_rows.saturating_add(row.status_checked);
        match &row.verdict {
            Verdict::Equivalent => {
                equivalent = equivalent.saturating_add(1);
                *equivalent_by_shape.entry(row.shape).or_default() += 1;
            }
            Verdict::Mismatch(detail) => mismatched.push(format!("{}: {detail}", row_key(row))),
            Verdict::Abstained(detail) => {
                abstained = abstained.saturating_add(1);
                if detail.trim().is_empty() {
                    unnamed.push(row_key(row));
                }
            }
            Verdict::NotGraded(_) => {}
        }
    }

    println!(
        "non-returning exit census: rows={} equivalent={equivalent} status_checks={status_rows} teeth={teeth} abstained={abstained}",
        rows.len()
    );

    assert!(
        mismatched.is_empty(),
        "a recovered body with a non-returning exit computed a different value than the compiled function: {mismatched:#?}"
    );
    assert!(
        unnamed.is_empty(),
        "an abstention carried no reason: {unnamed:#?}"
    );
    let equivalent_floor: usize = compilers
        .len()
        .saturating_mul(PER_COMPILER_EQUIVALENT_FLOOR);
    let status_floor: usize = compilers.len().saturating_mul(PER_COMPILER_STATUS_FLOOR);
    assert!(
        equivalent >= equivalent_floor,
        "non-returning exit recovery fell below the recorded floor: {equivalent} of {} rows, floor {equivalent_floor} for {} compilers",
        rows.len(),
        compilers.len()
    );
    assert!(
        status_rows >= status_floor,
        "the process-status differential ran on too few rows to be evidence: {status_rows}, floor {status_floor} for {} compilers",
        compilers.len()
    );
    assert!(
        teeth > 0,
        "no row confirmed that removing the non-returning call changes the observed exit status"
    );
    let untoothed: Vec<&'static str> = SHAPES
        .iter()
        .filter(|shape: &&NoreturnShape| {
            !shape.status_inputs.is_empty() && !toothed.contains(shape.tag)
        })
        .map(|shape: &NoreturnShape| shape.tag)
        .collect();
    assert!(
        untoothed.is_empty(),
        "every shape with a process-status grade must confirm that removing its non-returning call changes the outcome: {untoothed:#?}"
    );
    let unexercised: Vec<&'static str> = equivalent_by_shape
        .iter()
        .filter(|(_, count): &(&&'static str, &usize)| **count == 0)
        .map(|(tag, _): (&&'static str, &usize)| *tag)
        .collect();
    assert!(
        unexercised.is_empty(),
        "every declared non-returning exit shape must recover on at least one graded row: {unexercised:#?}"
    );
}

const CONDITIONAL_EXIT_ASSEMBLY: &str = "    .text\n\
     \x20   .globl nr_cond_exit\n\
     nr_cond_exit:\n\
     \x20   cmpq $4242, %rcx\n\
     \x20   je exit\n\
     \x20   movq %rcx, %rax\n\
     \x20   addq %rdx, %rax\n\
     \x20   ret\n";

const RELOCATED_BRANCH_REFUSAL: &str = "carries a relocation, so its successor lies outside this function and the encoded displacement does not name it";

fn assemble_object(compiler: &str, source: &str, tag: &str) -> Result<Vec<u8>, String> {
    let scratch: disrobe_core::scratch::ScratchDir = scratch_dir("disrobe-noreturn-asm");
    let asm_path: PathBuf = scratch.path().join(format!("{tag}.s"));
    std::fs::write(&asm_path, source.as_bytes()).map_err(|e| format!("write assembly: {e}"))?;
    let out_path: PathBuf = scratch.path().join(format!("{tag}.o"));
    let args: [OsString; 4] = [
        OsStr::new("-c").to_owned(),
        asm_path.as_os_str().to_owned(),
        OsStr::new("-o").to_owned(),
        out_path.as_os_str().to_owned(),
    ];
    match run_captured(
        Path::new(compiler),
        &args,
        Duration::from_mins(1),
        MAX_CAPTURE_BYTES,
    ) {
        Ok(Some(captured)) if captured.exit_code == Some(0) => {
            std::fs::read(&out_path).map_err(|e| format!("read assembled object: {e}"))
        }
        Ok(Some(captured)) => Err(format!(
            "assembler rejected the source: {}",
            String::from_utf8_lossy(&captured.stderr)
        )),
        Ok(None) => Err("assembler did not complete within the watchdog".to_owned()),
        Err(e) => Err(format!("assembler failed to spawn: {e}")),
    }
}

#[test]
fn a_conditional_branch_to_a_non_returning_import_is_refused_not_taken_unconditionally() {
    let compilers: Vec<CompilerId> = available_compilers();
    assert!(
        !compilers.is_empty(),
        "the conditional-exit grade needs a host assembler: none of gcc/clang/cc answered --version"
    );
    let mut assembled: usize = 0;
    for compiler in &compilers {
        let object: Vec<u8> = match assemble_object(
            compiler.bin,
            CONDITIONAL_EXIT_ASSEMBLY,
            &format!("cond_exit_{}", compiler.bin),
        ) {
            Ok(bytes) => bytes,
            Err(reason) => {
                println!("{} cannot assemble the shape: {reason}", compiler.bin);
                continue;
            }
        };
        assembled = assembled.saturating_add(1);
        let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(&object, "nr_cond_exit")
        else {
            panic!("nr_cond_exit symbol not located in the assembled object");
        };
        let functions: Vec<ProgramFunction> = vec![ProgramFunction {
            name: "rec_nr_cond_exit".to_owned(),
            address: base,
            code,
        }];
        let program: RecoveredProgram = recover_program(&object, &functions, PseudoAbi::MsX64);
        let recovered_source: Option<String> = program
            .recovered
            .first()
            .map(|function: &RecoveredFunction| function.source.clone());
        assert!(
            recovered_source.is_none(),
            "a conditional branch to a non-returning import must not recover, because taking it unconditionally drops the fallthrough edge:\n{}",
            recovered_source.unwrap_or_default()
        );
        let reason: &str = program
            .unrecovered
            .first()
            .map_or("", |function: &disrobe_pass_native::UnrecoveredFunction| {
                function.reason.as_str()
            });
        assert!(
            reason.contains(RELOCATED_BRANCH_REFUSAL),
            "the refusal must name the relocated branch, got: {reason}"
        );
    }
    assert!(
        assembled > 0,
        "no host compiler assembled the conditional-exit shape, so the refusal was never exercised"
    );
}

fn rustc_path() -> Option<PathBuf> {
    let resolved: Option<PathBuf> = run_captured(
        Path::new("rustup"),
        &["which", "rustc"],
        Duration::from_secs(30),
        MAX_CAPTURE_BYTES,
    )
    .ok()
    .flatten()
    .filter(|captured: &CapturedOutput| captured.exit_code == Some(0))
    .map(|captured: CapturedOutput| {
        PathBuf::from(String::from_utf8_lossy(&captured.stdout).trim().to_owned())
    })
    .filter(|path: &PathBuf| path.is_file());
    if resolved.is_some() {
        return resolved;
    }
    run_captured(
        Path::new("rustc"),
        &["--version"],
        Duration::from_secs(30),
        MAX_CAPTURE_BYTES,
    )
    .ok()
    .flatten()
    .filter(|captured: &CapturedOutput| captured.exit_code == Some(0))
    .map(|_: CapturedOutput| PathBuf::from("rustc"))
}

#[test]
fn recovered_rust_declares_the_non_returning_import_as_divergent() {
    let compilers: Vec<CompilerId> = available_compilers();
    assert!(
        !compilers.is_empty(),
        "the recovered Rust leg needs a host C compiler to produce an object"
    );
    let Some(rustc): Option<PathBuf> = rustc_path() else {
        panic!("the recovered Rust leg needs a resolvable rustc to be graded");
    };
    let compiler: &CompilerId = &compilers[0];
    let host_flags: Vec<&str> = compile_flags(compiler.family);
    let scratch: disrobe_core::scratch::ScratchDir = scratch_dir("disrobe-noreturn-rust");
    let host_out: PathBuf = scratch.path().join("rust_host.o");
    let CompileOutcome::Object(object) = compile_object_reasoned(
        compiler.bin,
        "-O1",
        &host_flags,
        TRANSLATION_UNIT,
        &host_out,
    ) else {
        panic!("the host compiler rejected the non-returning translation unit");
    };
    let mut checked: usize = 0;
    let mut expected: usize = 0;
    for shape in SHAPES {
        if recover_shape(&object, shape, PseudoAbi::MsX64).is_err() {
            continue;
        }
        expected = expected.saturating_add(1);
        let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(&object, shape.entry) else {
            panic!("{} symbol not located in object", shape.entry);
        };
        let functions: Vec<ProgramFunction> = vec![ProgramFunction {
            name: format!("rec_{}", shape.entry),
            address: base,
            code,
        }];
        let program: RecoveredProgram = recover_program(&object, &functions, PseudoAbi::MsX64);
        let Some(recovered): Option<&RecoveredFunction> = program.recovered.first() else {
            panic!(
                "{} recovered as part of its shape but not on its own",
                shape.tag
            );
        };
        let Some(rust_source): Option<&str> = recovered.rust_source.as_deref() else {
            panic!("{} produced no Rust body", shape.tag);
        };
        assert!(
            rust_source.contains("-> !;"),
            "the recovered Rust for {} must declare its non-returning import as divergent:\n{rust_source}",
            shape.tag
        );
        let source_path: PathBuf = scratch.path().join(format!("{}.rs", shape.tag));
        std::fs::write(&source_path, rust_source.as_bytes()).expect("write recovered rust");
        let out_path: PathBuf = scratch.path().join(format!("{}.meta", shape.tag));
        let args: [OsString; 8] = [
            OsStr::new("--edition").to_owned(),
            OsStr::new("2021").to_owned(),
            OsStr::new("--crate-type").to_owned(),
            OsStr::new("lib").to_owned(),
            OsStr::new("--emit").to_owned(),
            OsStr::new("metadata").to_owned(),
            OsStr::new("-o").to_owned(),
            out_path.as_os_str().to_owned(),
        ];
        let mut full: Vec<OsString> = args.to_vec();
        full.push(source_path.as_os_str().to_owned());
        let captured: CapturedOutput =
            run_captured(&rustc, &full, Duration::from_mins(2), MAX_CAPTURE_BYTES)
                .expect("rustc spawn")
                .expect("rustc completed within the watchdog");
        assert_eq!(
            captured.exit_code,
            Some(0),
            "the recovered Rust for {} does not compile: stderr={} stdout={}\n{rust_source}",
            shape.tag,
            String::from_utf8_lossy(&captured.stderr),
            String::from_utf8_lossy(&captured.stdout)
        );
        checked = checked.saturating_add(1);
    }
    assert!(
        expected > 0 && checked == expected,
        "every shape whose C body recovered must also produce a compiling Rust body: {checked} of {expected}"
    );
}
