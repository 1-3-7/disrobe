#![allow(clippy::expect_used, clippy::panic, clippy::print_stdout)]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use common::band::{band_scratch, find_interpreter};
use common::stdlib_measure::find_disrobe;

const SOURCE: &str = r"def consume(active, next_item, sink):
    while active():
        try:
            item = next_item()
        except LookupError:
            break
        else:
            sink(item)
    sink('exhausted')
";

const DRIVER: &str = r"events = []
tests = iter([True, True])
items = iter(['one'])

def active():
    events.append('test')
    return next(tests)

def next_item():
    events.append('next')
    try:
        return next(items)
    except StopIteration:
        raise LookupError from None

consume(active, next_item, events.append)
print(events)
";

const STRUCTURE_CHECK: &str = r"import ast,sys
tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'consume')
assert len(function.body) in (2, 3)
loop, tail = function.body[:2]
if len(function.body) == 3:
    implicit = function.body[2]
    assert isinstance(implicit, ast.Return) and isinstance(implicit.value, ast.Constant) and implicit.value.value is None
assert isinstance(loop, ast.While)
assert isinstance(loop.test, ast.Call)
assert len(loop.body) == 1 and isinstance(loop.body[0], ast.Try)
region = loop.body[0]
assert len(region.body) == 1 and len(region.handlers) == 1 and len(region.orelse) == 1
assert len(region.handlers[0].body) == 1 and isinstance(region.handlers[0].body[0], ast.Break)
assert not region.finalbody
assert isinstance(tail, ast.Expr)
";

const MUTATE_BOTTOM_TEST: &str = r"import dis,marshal,sys,types
path = sys.argv[1]
raw = open(path, 'rb').read()
module = marshal.loads(raw[16:])
def mutate(code):
    if code.co_name != 'consume':
        return code
    instructions = list(dis.get_instructions(code, show_caches=True))
    loads = [instruction for instruction in instructions if instruction.opname == 'LOAD_FAST' and instruction.argval == 'active']
    assert len(loads) == 2
    bottom = loads[1]
    bytecode = bytearray(code.co_code)
    assert bytecode[bottom.offset] == dis.opmap['LOAD_FAST']
    bytecode[bottom.offset + 1] = code.co_varnames.index('next_item')
    return code.replace(co_code=bytes(bytecode))
module = module.replace(
    co_consts=tuple(mutate(value) if isinstance(value, types.CodeType) else value for value in module.co_consts)
)
open(path, 'wb').write(raw[:16] + marshal.dumps(module))
";

const MUTATE_ENTRY_TO_BODY: &str = r"import dis,marshal,sys,types
path = sys.argv[1]
raw = open(path, 'rb').read()
module = marshal.loads(raw[16:])
def mutate(code):
    if code.co_name != 'consume':
        return code
    instructions = list(dis.get_instructions(code, show_caches=True))
    back = next(instruction for instruction in instructions if instruction.opname == 'JUMP_BACKWARD')
    entry = next(
        instruction
        for instruction in instructions
        if instruction.opname == 'POP_JUMP_IF_FALSE' and instruction.offset < back.argval
    )
    assert entry.argval != back.argval
    bytecode = bytearray(code.co_code)
    bytecode[entry.offset + 1] = 0
    mutated = code.replace(co_code=bytes(bytecode))
    changed = list(dis.get_instructions(mutated, show_caches=True))
    changed_entry = next(instruction for instruction in changed if instruction.offset == entry.offset)
    assert changed_entry.argval == back.argval
    return mutated
module = module.replace(
    co_consts=tuple(mutate(value) if isinstance(value, types.CodeType) else value for value in module.co_consts)
)
open(path, 'wb').write(raw[:16] + marshal.dumps(module))
";

fn run(interpreter: &Path, args: &[&str], path: &Path) -> std::process::Output {
    Command::new(interpreter)
        .args(args)
        .arg(path)
        .env("PYTHONHASHSEED", "0")
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error: std::io::Error| panic!("spawn {}: {error}", interpreter.display()))
}

fn compile_fixture(interpreter: &Path, source: &Path, pyc: &Path) {
    let output: std::process::Output = Command::new(interpreter)
        .args([
            "-c",
            "import py_compile,sys;py_compile.compile(sys.argv[1],cfile=sys.argv[2],doraise=True)",
        ])
        .arg(source)
        .arg(pyc)
        .stdin(Stdio::null())
        .output()
        .expect("compile fixture");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_auto(disrobe: &Path, pyc: &Path, out: &Path) {
    let _ = std::fs::remove_dir_all(out);
    let output: std::process::Output = Command::new(disrobe)
        .args(["auto"])
        .arg(pyc)
        .args(["--out"])
        .arg(out)
        .args(["--max-depth", "3", "--capture-stages"])
        .stdin(Stdio::null())
        .output()
        .expect("spawn auto");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn captured_source(out: &Path) -> String {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(out)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", out.display()))
        .filter_map(Result::ok)
        .map(|entry: std::fs::DirEntry| entry.path().join("output.bin"))
        .filter(|path: &PathBuf| path.is_file() && path.to_string_lossy().contains("py-decompile"))
        .collect();
    paths.sort();
    let path: PathBuf = paths
        .pop()
        .unwrap_or_else(|| panic!("no py.decompile output under {}", out.display()));
    std::fs::read_to_string(path).expect("read recovered source")
}

#[test]
fn auto_preserves_rotated_while_try_handler_break() {
    let interpreter: PathBuf = find_interpreter("3.12").expect("CPython 3.12");
    let disrobe: PathBuf = find_disrobe().expect("disrobe binary");
    let scratch: PathBuf = band_scratch("rotated-while-try-handler-break-auto");
    let source_path: PathBuf = scratch.join("fixture.py");
    let pyc_path: PathBuf = scratch.join("fixture.pyc");
    let original_path: PathBuf = scratch.join("original.py");
    let recovered_path: PathBuf = scratch.join("recovered.py");
    let out: PathBuf = scratch.join("out");
    std::fs::write(&source_path, SOURCE).expect("write source");
    compile_fixture(&interpreter, &source_path, &pyc_path);
    run_auto(&disrobe, &pyc_path, &out);
    let recovered: String = captured_source(&out);
    assert_eq!(
        recovered.matches("while active():").count(),
        1,
        "{recovered}"
    );
    assert_eq!(
        recovered.matches("except LookupError:").count(),
        1,
        "{recovered}"
    );
    assert_eq!(recovered.matches("break").count(), 1, "{recovered}");
    assert_eq!(recovered.matches("else:").count(), 1, "{recovered}");
    std::fs::write(&original_path, format!("{SOURCE}\n{DRIVER}")).expect("write original");
    std::fs::write(&recovered_path, format!("{recovered}\n{DRIVER}")).expect("write recovered");
    let structure: std::process::Output =
        run(&interpreter, &["-c", STRUCTURE_CHECK], &recovered_path);
    assert!(
        structure.status.success(),
        "{}",
        String::from_utf8_lossy(&structure.stderr)
    );
    let original: std::process::Output = run(&interpreter, &[], &original_path);
    let rebuilt: std::process::Output = run(&interpreter, &[], &recovered_path);
    assert!(original.status.success() && rebuilt.status.success());
    assert_eq!(rebuilt.stdout, original.stdout);
    assert_eq!(
        String::from_utf8(original.stdout).expect("utf8").trim(),
        "['test', 'next', 'one', 'test', 'next', 'exhausted']"
    );
}

#[test]
fn auto_refuses_mismatched_rotated_while_tests() {
    let interpreter: PathBuf = find_interpreter("3.12").expect("CPython 3.12");
    let disrobe: PathBuf = find_disrobe().expect("disrobe binary");
    let scratch: PathBuf = band_scratch("rotated-while-try-handler-break-mismatch-auto");
    let source_path: PathBuf = scratch.join("fixture.py");
    let pyc_path: PathBuf = scratch.join("fixture.pyc");
    let out: PathBuf = scratch.join("out");
    std::fs::write(&source_path, SOURCE).expect("write source");
    compile_fixture(&interpreter, &source_path, &pyc_path);
    let mutation: std::process::Output = Command::new(&interpreter)
        .args(["-c", MUTATE_BOTTOM_TEST])
        .arg(&pyc_path)
        .stdin(Stdio::null())
        .output()
        .expect("mutate bottom test");
    assert!(
        mutation.status.success(),
        "{}",
        String::from_utf8_lossy(&mutation.stderr)
    );
    run_auto(&disrobe, &pyc_path, &out);
    let recovered: String = captured_source(&out);
    assert!(
        recovered.contains("decompile-error: ast builder desync at offset "),
        "mismatched tests were published as source:\n{recovered}"
    );
    assert!(
        recovered.contains("peeled and loop-back tests differ"),
        "the refusal did not identify the mismatched loop tests:\n{recovered}"
    );
    assert!(!recovered.contains("while active():"), "{recovered}");
}

#[test]
fn auto_refuses_rotated_while_entry_jump_to_body() {
    let interpreter: PathBuf = find_interpreter("3.12").expect("CPython 3.12");
    let disrobe: PathBuf = find_disrobe().expect("disrobe binary");
    let scratch: PathBuf = band_scratch("rotated-while-entry-jump-to-body-auto");
    let source_path: PathBuf = scratch.join("fixture.py");
    let pyc_path: PathBuf = scratch.join("fixture.pyc");
    let out: PathBuf = scratch.join("out");
    std::fs::write(&source_path, SOURCE).expect("write source");
    compile_fixture(&interpreter, &source_path, &pyc_path);
    let mutation: std::process::Output = Command::new(&interpreter)
        .args(["-c", MUTATE_ENTRY_TO_BODY])
        .arg(&pyc_path)
        .stdin(Stdio::null())
        .output()
        .expect("mutate entry test");
    assert!(
        mutation.status.success(),
        "{}",
        String::from_utf8_lossy(&mutation.stderr)
    );
    run_auto(&disrobe, &pyc_path, &out);
    let recovered: String = captured_source(&out);
    assert!(
        recovered.contains("decompile-error: ast builder desync at offset "),
        "body-targeted entry test was published as source:\n{recovered}"
    );
    assert!(!recovered.contains("while active():"), "{recovered}");
}
