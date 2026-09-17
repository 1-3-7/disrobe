mod common;

use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use common::band::{
    BandInterpreter, CorpusMeasurement, band_scratch, find_interpreter, measure_corpus_file,
};

const LABEL: &str = "py313-base-events-guarded-loop";
const EXTRACT_METHOD: &str = r#"import asyncio.base_events
import inspect
import textwrap

method = inspect.getsource(asyncio.base_events.BaseEventLoop.create_connection)
print("class BaseEventLoop:\n" + textwrap.indent(textwrap.dedent(method), "    "), end="")
"#;
const COUNT_GENERATORS: &str = r#"import sys

def children(code):
    return [value for value in code.co_consts if hasattr(value, "co_name")]

def find(code, name):
    if code.co_name == name:
        return code
    for child in children(code):
        found = find(child, name)
        if found is not None:
            return found
    return None

source = open(sys.argv[1], encoding="utf-8").read()
module = compile(source, sys.argv[1], "exec", dont_inherit=True)
method = find(module, "create_connection")
assert method is not None
print(sum(child.co_name == "<genexpr>" for child in children(method)))
"#;
const CHECK_CONNECTION_LOOP: &str = r#"import ast
import sys

tree = ast.parse(open(sys.argv[1], encoding="utf-8").read())
class_node = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "BaseEventLoop")
method = next(node for node in class_node.body if isinstance(node, ast.AsyncFunctionDef) and node.name == "create_connection")
branch = next(
    node
    for node in method.body
    if isinstance(node, ast.If)
    and isinstance(node.test, ast.Compare)
    and isinstance(node.test.left, ast.Name)
    and node.test.left.id == "happy_eyeballs_delay"
    and len(node.test.ops) == 1
    and isinstance(node.test.ops[0], ast.Is)
    and len(node.test.comparators) == 1
    and isinstance(node.test.comparators[0], ast.Constant)
    and node.test.comparators[0].value is None
)
loop = next(
    node
    for node in branch.body
    if isinstance(node, ast.For)
    and isinstance(node.target, ast.Name)
    and node.target.id == "addrinfo"
    and isinstance(node.iter, ast.Name)
    and node.iter.id == "infos"
)
attempt = next(node for node in loop.body if isinstance(node, ast.Try))
assert any(
    isinstance(node, ast.Assign)
    and isinstance(node.value, ast.Await)
    and any(isinstance(target, ast.Name) and target.id == "sock" for target in node.targets)
    for node in attempt.body
)
assert any(isinstance(node, ast.Break) for node in attempt.body)
handler = next(
    node
    for node in attempt.handlers
    if isinstance(node.type, ast.Name) and node.type.id == "OSError"
)
assert handler.body and isinstance(handler.body[-1], ast.Continue)
"#;

fn run_python(interpreter: &Path, script: &str, argument: Option<&Path>) -> io::Result<String> {
    let mut command: Command = Command::new(interpreter);
    command.args(["-c", script]).stdin(Stdio::null());
    if let Some(path) = argument {
        command.arg(path);
    }
    let output: std::process::Output = command.output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "CPython exited {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn generator_count(interpreter: &Path, source: &Path) -> Result<u64, Box<dyn Error>> {
    let raw: String = run_python(interpreter, COUNT_GENERATORS, Some(source))?;
    Ok(raw.trim().parse()?)
}

#[test]
fn create_connection_preserves_all_three_generator_expressions() -> Result<(), Box<dyn Error>> {
    let interpreter_path: PathBuf = find_interpreter("3.13.14").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "CPython 3.13.14 is required for the base_events guarded-loop regression",
        )
    })?;
    let interpreter: BandInterpreter = BandInterpreter {
        alias: "3.13.14",
        path: interpreter_path,
        is_prerelease: false,
    };
    let scratch: PathBuf = band_scratch(LABEL);
    let original_path: PathBuf = scratch.join(format!("{LABEL}.{}.source.py", interpreter.alias));
    let extracted: String = run_python(&interpreter.path, EXTRACT_METHOD, None)?;
    fs::write(&original_path, extracted)?;

    let measurement: CorpusMeasurement =
        measure_corpus_file(&interpreter, &original_path, LABEL, &scratch);
    let CorpusMeasurement::Measured(tally) = measurement else {
        return Err(
            io::Error::other(format!("base_events measurement failed: {measurement:?}")).into(),
        );
    };
    let recovered_path: PathBuf = scratch.join(format!("{LABEL}.{}.dec.py", interpreter.alias));
    let original_count: u64 = generator_count(&interpreter.path, &original_path)?;
    let recovered_count: u64 = generator_count(&interpreter.path, &recovered_path)?;

    assert_eq!(original_count, 3, "the installed reference method changed");
    assert_eq!(
        recovered_count, original_count,
        "recovered create_connection emitted {recovered_count} generator expressions instead of \
         the reference method's {original_count}; object failures: {:?}",
        tally.failures
    );
    run_python(
        &interpreter.path,
        CHECK_CONNECTION_LOOP,
        Some(&recovered_path),
    )?;
    Ok(())
}
