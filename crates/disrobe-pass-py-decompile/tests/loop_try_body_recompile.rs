#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
mod common;

use std::path::PathBuf;

#[cfg(feature = "chain")]
use std::fs;
#[cfg(feature = "chain")]
use std::path::Path;
#[cfg(feature = "chain")]
use std::process::{Command, Stdio};

#[cfg(feature = "chain")]
use disrobe_core::chain::Pass;
#[cfg(feature = "chain")]
use disrobe_core::{Artifact, Rung};
#[cfg(feature = "chain")]
use disrobe_pass_py_decompile::chain_detector::PY_DECOMPILE_PASS;

use crate::common::band::{
    BandInterpreter, BandOutcome, band_scratch, recompile_equiv_inline, resolve_band,
};

const WHILE_TRY_BREAK: &str = r"
def drain(active, next_item, sink):
    while active():
        try:
            item = next_item()
        except LookupError:
            break
        else:
            sink(item)
    sink('exhausted')
";

const FOR_GUARD_TRY_CONTINUE: &str = r"
def preserve_for_guard(values, guarded, read, sink):
    for value in values:
        if guarded(value):
            try:
                sink(read(value))
            except LookupError:
                sink(None)
            continue
        sink(value)
";

const WHILE_GUARD_TRY_CONTINUE: &str = r"
def preserve_while_guard(active, guarded, read, sink):
    while active():
        if guarded():
            try:
                sink(read())
            except LookupError:
                sink(None)
            continue
        sink('ready')
";

const WHILE_OR_GUARD_CONTINUE: &str = r"
def chained_guard(active, primary, secondary, sink):
    while active():
        if primary() or secondary():
            sink('guarded')
            continue
        sink('ready')
";

const WHILE_OR_GUARD_TRY_CONTINUE: &str = r"
def guarded_read(active, primary, secondary, read, sink):
    while active():
        if primary() or secondary():
            try:
                sink(read())
            except LookupError:
                sink(None)
            continue
        sink('ready')
    return None
";

const WHILE_TRY_HANDLER_FALLTHROUGH: &str = r"
def retain_handler_fallthrough(active, next_item, sink):
    while active():
        try:
            item = next_item()
        except LookupError:
            sink(None)
        sink(item)
";

const WHILE_TRY_MIXED_HANDLER_FLOW: &str = r"
def retain_mixed_handler_flow(active, next_item, sink):
    while active():
        try:
            item = next_item()
        except LookupError:
            sink(None)
        except ValueError:
            break
        sink(item)
";

#[cfg(feature = "chain")]
const WHILE_AND_TRY_BREAK: &str = r"
def consume(primary, secondary, next_item, sink):
    while primary() and secondary():
        try:
            sink(next_item())
        except LookupError:
            break
    sink('done')
";

#[cfg(feature = "chain")]
const WHILE_OR_TRY_BREAK: &str = r"
def consume(primary, secondary, next_item, sink):
    while primary() or secondary():
        try:
            sink(next_item())
        except LookupError:
            break
    sink('done')
";

#[cfg(feature = "chain")]
const WHILE_THREE_CALL_AND_TRY_BREAK: &str = r"
def consume(primary, secondary, tertiary, next_item, sink):
    while primary() and secondary() and tertiary():
        try:
            sink(next_item())
        except LookupError:
            break
    sink('done')
";

#[cfg(feature = "chain")]
const WHILE_AND_TRY_BREAK_DRIVER: &str = r"
def values(items, name, calls):
    iterator = iter(items)
    def read():
        calls.append(name)
        return next(iterator, False)
    return read

def lookup_after(items):
    iterator = iter(items)
    def read():
        value = next(iterator, None)
        if value is None:
            raise LookupError
        return value
    return read

events = []
calls = []
consume(values([True, True, False], 'primary', calls), values([True, True], 'secondary', calls), lookup_after(['one']), events.append)
print(events, calls)
";

const PRE311_ALIASES: &[&str] = &["3.8", "3.9", "3.10"];
const POST311_ALIASES: &[&str] = &["3.11", "3.12", "3.13", "3.14", "3.15"];

fn stable_interpreter() -> BandInterpreter {
    resolve_band(&["3.10"], &[])
        .into_iter()
        .next()
        .unwrap_or_else(|| {
            panic!(
                "no CPython 3.10 interpreter resolvable via uv; install it before running loop/try recovery proofs"
            )
        })
}

fn required_pre311_interpreters() -> Vec<BandInterpreter> {
    let interpreters: Vec<BandInterpreter> = resolve_band(PRE311_ALIASES, &[]);
    let resolved: Vec<&str> = interpreters
        .iter()
        .map(|interpreter: &BandInterpreter| interpreter.alias)
        .collect();
    assert_eq!(
        resolved.as_slice(),
        PRE311_ALIASES,
        "guarded-loop recovery requires CPython 3.8, 3.9, and 3.10; CI provisions all three"
    );
    interpreters
}

fn required_post311_interpreters() -> Vec<BandInterpreter> {
    let interpreters: Vec<BandInterpreter> = resolve_band(POST311_ALIASES, &[]);
    let resolved: Vec<&str> = interpreters
        .iter()
        .map(|interpreter: &BandInterpreter| interpreter.alias)
        .collect();
    assert_eq!(
        resolved.as_slice(),
        POST311_ALIASES,
        "guarded loop recovery requires CPython 3.11 through 3.15; CI provisions all five"
    );
    interpreters
}

#[cfg(feature = "chain")]
fn compile_source(interpreter: &Path, source: &Path, pyc: &Path) -> Result<(), String> {
    let output: std::process::Output = Command::new(interpreter)
        .args([
            "-c",
            "import py_compile,sys;py_compile.compile(sys.argv[1],cfile=sys.argv[2],doraise=True)",
            source.to_str().unwrap_or(""),
            pyc.to_str().unwrap_or(""),
        ])
        .env("PYTHONHASHSEED", "0")
        .stdin(Stdio::null())
        .output()
        .map_err(|error: std::io::Error| format!("spawn compiler: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}

#[cfg(feature = "chain")]
fn execute_source(interpreter: &Path, source: &Path) -> Result<String, String> {
    let output: std::process::Output = Command::new(interpreter)
        .arg(source)
        .env("PYTHONHASHSEED", "0")
        .stdin(Stdio::null())
        .output()
        .map_err(|error: std::io::Error| format!("spawn runtime: {error}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}

#[cfg(feature = "chain")]
fn recover_registered_source(interpreter: &BandInterpreter, source: &str, label: &str) -> String {
    let scratch: PathBuf = band_scratch(label);
    let source_path: PathBuf = scratch.join(format!("{label}.src.py"));
    let pyc_path: PathBuf = scratch.join(format!("{label}.src.pyc"));
    fs::write(&source_path, source)
        .unwrap_or_else(|error: std::io::Error| panic!("write {label}: {error}"));
    compile_source(&interpreter.path, &source_path, &pyc_path)
        .unwrap_or_else(|error: String| panic!("py{} compile {label}: {error}", interpreter.alias));
    let pyc: Vec<u8> = fs::read(&pyc_path)
        .unwrap_or_else(|error: std::io::Error| panic!("read {label} pyc: {error}"));
    let recovered_artifact: Artifact = PY_DECOMPILE_PASS
        .run(&Artifact::new(Rung::Raw, pyc, [0_u8; 32]))
        .unwrap_or_else(|error| {
            panic!(
                "py{} registered pass for {label}: {error}",
                interpreter.alias
            )
        });
    String::from_utf8(recovered_artifact.envelope)
        .unwrap_or_else(|error: std::string::FromUtf8Error| panic!("{label} UTF-8: {error}"))
}

#[cfg(feature = "chain")]
#[test]
fn post311_two_call_and_dispatch_excludes_or_and_longer_chains() {
    for interpreter in required_post311_interpreters() {
        let or_label: String = format!("while_or_try_break_exclusion_{}", interpreter.alias);
        let recovered_or: String =
            recover_registered_source(&interpreter, WHILE_OR_TRY_BREAK, &or_label);
        assert_eq!(
            recovered_or
                .matches("while primary() and secondary():")
                .count(),
            0,
            "OR must not enter the two-call AND path:\n{recovered_or}"
        );
        assert_eq!(
            recovered_or.matches("break").count(),
            0,
            "OR must not receive the declared handler normalization:\n{recovered_or}"
        );

        let chain_label: String = format!("while_three_call_and_exclusion_{}", interpreter.alias);
        let recovered_chain: String =
            recover_registered_source(&interpreter, WHILE_THREE_CALL_AND_TRY_BREAK, &chain_label);
        assert_eq!(
            recovered_chain
                .matches("while primary() and secondary():")
                .count(),
            0,
            "a longer chain must not be truncated into the declared shape:\n{recovered_chain}"
        );
        assert_eq!(
            recovered_chain.matches("break").count(),
            0,
            "a longer chain must not receive the declared handler normalization:\n{recovered_chain}"
        );
    }
}

#[cfg(feature = "chain")]
#[test]
fn post311_while_and_try_break_reaches_registered_pass_and_runs_equivalently() {
    for interpreter in required_post311_interpreters() {
        let label: String = format!("while_and_try_break_{}", interpreter.alias);
        let scratch: PathBuf = band_scratch(&label);
        let original_path: PathBuf = scratch.join(format!("{label}.src.py"));
        let original_exec_path: PathBuf = scratch.join(format!("{label}.exec.py"));
        let original_pyc: PathBuf = scratch.join(format!("{label}.src.pyc"));
        let original_program: String =
            format!("{WHILE_AND_TRY_BREAK}\n{WHILE_AND_TRY_BREAK_DRIVER}");
        fs::write(&original_path, WHILE_AND_TRY_BREAK)
            .unwrap_or_else(|error: std::io::Error| panic!("write original: {error}"));
        fs::write(&original_exec_path, &original_program)
            .unwrap_or_else(|error: std::io::Error| panic!("write original runtime: {error}"));
        compile_source(&interpreter.path, &original_path, &original_pyc).unwrap_or_else(
            |error: String| panic!("py{} compile original: {error}", interpreter.alias),
        );
        let original_output: String = execute_source(&interpreter.path, &original_exec_path)
            .unwrap_or_else(|error: String| {
                panic!("py{} execute original: {error}", interpreter.alias)
            });
        let pyc: Vec<u8> = fs::read(&original_pyc)
            .unwrap_or_else(|error: std::io::Error| panic!("read original pyc: {error}"));
        let recovered_artifact: Artifact = PY_DECOMPILE_PASS
            .run(&Artifact::new(Rung::Raw, pyc, [0_u8; 32]))
            .unwrap_or_else(|error| panic!("py{} registered pass: {error}", interpreter.alias));
        let recovered: String = String::from_utf8(recovered_artifact.envelope)
            .unwrap_or_else(|error: std::string::FromUtf8Error| panic!("recovered UTF-8: {error}"));

        assert_eq!(
            recovered
                .matches("while primary() and secondary():")
                .count(),
            1,
            "compound header must remain whole:\n{recovered}"
        );
        assert_eq!(
            recovered.matches("except LookupError:").count(),
            1,
            "typed handler must remain nested:\n{recovered}"
        );
        assert_eq!(
            recovered.matches("break").count(),
            1,
            "handler must exit the loop:\n{recovered}"
        );
        assert_eq!(
            recovered.matches("sink(\"done\")").count(),
            1,
            "post-loop tail must remain reachable:\n{recovered}"
        );

        let recovered_path: PathBuf = scratch.join(format!("{label}.recovered.py"));
        let recovered_pyc: PathBuf = scratch.join(format!("{label}.recovered.pyc"));
        let recovered_program: String = format!("{recovered}\n{WHILE_AND_TRY_BREAK_DRIVER}");
        fs::write(&recovered_path, &recovered_program)
            .unwrap_or_else(|error: std::io::Error| panic!("write recovered: {error}"));
        compile_source(&interpreter.path, &recovered_path, &recovered_pyc).unwrap_or_else(
            |error: String| panic!("py{} compile recovered: {error}", interpreter.alias),
        );
        let recovered_output: String = execute_source(&interpreter.path, &recovered_path)
            .unwrap_or_else(|error: String| {
                panic!("py{} execute recovered: {error}", interpreter.alias)
            });
        assert_eq!(recovered_output, original_output);

        let mutated_path: PathBuf = scratch.join(format!("{label}.mutated.py"));
        let mutated: String = recovered_program.replacen(
            "while primary() and secondary():",
            "while primary() or secondary():",
            1,
        );
        fs::write(&mutated_path, mutated)
            .unwrap_or_else(|error: std::io::Error| panic!("write mutation: {error}"));
        let mutated_output: String = execute_source(&interpreter.path, &mutated_path)
            .unwrap_or_else(|error: String| {
                panic!("py{} execute mutation: {error}", interpreter.alias)
            });
        assert_ne!(mutated_output, original_output);
    }
}

fn assert_recompile_equivalence(
    interpreter: &BandInterpreter,
    fixture: &str,
    label: &str,
) -> String {
    let scratch: PathBuf = band_scratch(label);
    let (outcome, recovered): (BandOutcome, String) =
        recompile_equiv_inline(interpreter, fixture, label, &scratch);
    assert!(
        matches!(outcome, BandOutcome::RecompileEquiv),
        "{label} must recompile equivalently, got {outcome:?}:\n{recovered}"
    );
    recovered
}

#[test]
fn while_try_except_break_recompiles_with_the_loop_intact() {
    for interpreter in required_pre311_interpreters() {
        let label: String = format!("while_try_break_{}", interpreter.alias);
        let recovered: String = assert_recompile_equivalence(&interpreter, WHILE_TRY_BREAK, &label);

        assert_eq!(
            recovered.matches("while active():").count(),
            1,
            "the while header must remain outside the protected body:\n{recovered}"
        );
        assert_eq!(
            recovered.matches("except LookupError:").count(),
            1,
            "the handler must remain nested in the loop:\n{recovered}"
        );
        assert_eq!(
            recovered.matches("break").count(),
            1,
            "the handler must exit the loop instead of returning from the function:\n{recovered}"
        );
        assert_eq!(
            recovered.matches("else:").count(),
            1,
            "the protected success arm must remain a try else branch:\n{recovered}"
        );
        assert_eq!(
            recovered.matches("sink(item)").count(),
            1,
            "the protected success arm must remain inside the try else branch:\n{recovered}"
        );
        assert_eq!(
            recovered.matches("sink(\"exhausted\")").count(),
            1,
            "the post-loop tail must remain reachable:\n{recovered}"
        );
        assert!(
            !recovered.contains("return None"),
            "the handler must not replace the loop break with a function return:\n{recovered}"
        );
    }
}

#[test]
fn pre311_handler_fallthrough_does_not_gain_try_else() {
    for interpreter in required_pre311_interpreters() {
        let label: String = format!("while_handler_fallthrough_{}", interpreter.alias);
        let recovered: String =
            assert_recompile_equivalence(&interpreter, WHILE_TRY_HANDLER_FALLTHROUGH, &label);

        assert_eq!(
            recovered.matches("else:").count(),
            0,
            "a handler that falls through must not become a try else branch:\n{recovered}"
        );
        assert_eq!(
            recovered.matches("sink(item)").count(),
            1,
            "the sibling statement must remain after the try:\n{recovered}"
        );
    }
}

#[test]
fn pre311_mixed_handler_flow_does_not_gain_try_else() {
    for interpreter in required_pre311_interpreters() {
        let label: String = format!("while_mixed_handler_flow_{}", interpreter.alias);
        let recovered: String =
            assert_recompile_equivalence(&interpreter, WHILE_TRY_MIXED_HANDLER_FLOW, &label);

        assert_eq!(
            recovered.matches("else:").count(),
            0,
            "a fallthrough handler must prevent promotion of the sibling to try else:\n{recovered}"
        );
        assert_eq!(
            recovered.matches("sink(item)").count(),
            1,
            "the sibling statement must remain after the try:\n{recovered}"
        );
    }
}

#[test]
fn guarded_for_try_continue_recompiles_equivalently() {
    let interpreter: BandInterpreter = stable_interpreter();
    let for_recovered: String = assert_recompile_equivalence(
        &interpreter,
        FOR_GUARD_TRY_CONTINUE,
        "for_guard_try_continue",
    );

    assert_eq!(
        for_recovered.matches("for value in values:").count(),
        1,
        "the for-loop guard must not be consumed as a while header:\n{for_recovered}"
    );
    assert_eq!(
        for_recovered.matches("continue").count(),
        1,
        "the guarded protected arm must retain its back-edge:\n{for_recovered}"
    );
    assert!(
        !for_recovered.contains("else:"),
        "the tail must not become an else arm after a guarded continue:\n{for_recovered}"
    );
}

#[test]
fn guarded_while_try_continue_recompiles_equivalently() {
    for interpreter in required_pre311_interpreters() {
        let label: String = format!("while_guard_try_continue_{}", interpreter.alias);
        let while_recovered: String =
            assert_recompile_equivalence(&interpreter, WHILE_GUARD_TRY_CONTINUE, &label);

        assert_eq!(
            while_recovered.matches("while active():").count(),
            1,
            "the nested guard must remain inside the while body:\n{while_recovered}"
        );
        assert_eq!(
            while_recovered.matches("continue").count(),
            1,
            "the guarded protected arm must retain its back-edge:\n{while_recovered}"
        );
        assert!(
            while_recovered.contains("sink(\"ready\")"),
            "the false arm must remain in the loop body:\n{while_recovered}"
        );
        assert!(
            !while_recovered.contains("else:"),
            "the tail must not become an else arm after a guarded continue:\n{while_recovered}"
        );
    }
}

#[test]
fn guarded_while_or_continue_recompiles_equivalently() {
    for interpreter in required_pre311_interpreters() {
        let label: String = format!("while_or_guard_continue_{}", interpreter.alias);
        let recovered: String =
            assert_recompile_equivalence(&interpreter, WHILE_OR_GUARD_CONTINUE, &label);

        assert_eq!(
            recovered.matches("while active():").count(),
            1,
            "the outer while header must remain separate from the OR guard:\n{recovered}"
        );
        assert_eq!(
            recovered.matches("if primary() or secondary():").count(),
            1,
            "the OR guard must remain whole:\n{recovered}"
        );
        assert_eq!(
            recovered.matches("continue").count(),
            1,
            "the guarded arm must retain its back-edge:\n{recovered}"
        );
        assert!(
            recovered.contains("sink(\"ready\")"),
            "the false arm must remain in the loop body:\n{recovered}"
        );
    }
}

#[test]
fn post311_while_or_guard_try_continue_recompiles_equivalently() {
    for interpreter in required_post311_interpreters() {
        let label: String = format!("while_or_guard_try_continue_{}", interpreter.alias);
        let recovered: String =
            assert_recompile_equivalence(&interpreter, WHILE_OR_GUARD_TRY_CONTINUE, &label);

        assert_eq!(
            recovered.matches("while active():").count(),
            1,
            "the loop header must own the outer region:\n{recovered}"
        );
        assert_eq!(
            recovered.matches("if primary() or secondary():").count(),
            1,
            "the short-circuit guard must stay inside the loop:\n{recovered}"
        );
        assert_eq!(
            recovered.matches("except LookupError:").count(),
            1,
            "the protected region must stay inside the guarded arm:\n{recovered}"
        );
        assert_eq!(
            recovered.matches("continue").count(),
            1,
            "the guarded arm must retain its loop edge:\n{recovered}"
        );
        assert!(
            recovered.contains("sink(\"ready\")"),
            "the false arm must stay in the loop body:\n{recovered}"
        );
    }
}
