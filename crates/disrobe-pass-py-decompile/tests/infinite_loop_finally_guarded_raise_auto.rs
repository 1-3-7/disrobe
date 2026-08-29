#![allow(clippy::expect_used, clippy::panic, clippy::print_stdout)]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use common::band::{band_scratch, find_interpreter};
use common::stdlib_measure::find_disrobe;

const SOURCE: &str = r"def consume(next_item, should_raise, make_error, should_stop, sink):
    while True:
        try:
            item = next_item()
            sink(('body', item))
        finally:
            sink(('cleanup', item))
            if should_raise():
                raise make_error(item)
            sink(('continue', item))
        if should_stop(item):
            break
    sink(('done', item))
";

const DRIVER: &str = r"def values(items):
    iterator = iter(items)
    return lambda: next(iterator)

events = []
raised = []
def make_error(item):
    events.append(('make_error', item))
    error = RuntimeError(f'raised:{item}')
    raised.append(error)
    return error

try:
    consume(values(['one', 'two']), values([False, True]), make_error, lambda item: False, events.append)
except RuntimeError as error:
    print(type(error).__name__, str(error), error is raised[0], events)

consume(values(['one', 'two']), values([False, False]), make_error, lambda item: item == 'two', events.append)
print(events)
";

const STRUCTURE_CHECK: &str = r"import ast,sys
tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'consume')
loop = function.body[0]
assert isinstance(loop, ast.While) and isinstance(loop.test, ast.Constant) and loop.test.value is True
region = loop.body[0]
assert isinstance(region, ast.Try) and len(region.body) == 2 and len(region.finalbody) == 3
guard = region.finalbody[1]
assert isinstance(guard, ast.If) and len(guard.body) == 1 and isinstance(guard.body[0], ast.Raise)
raised = guard.body[0].exc
assert isinstance(raised, ast.Call) and isinstance(raised.func, ast.Name) and raised.func.id == 'make_error'
assert len(raised.args) == 1 and isinstance(raised.args[0], ast.Name) and raised.args[0].id == 'item'
assert isinstance(region.finalbody[2], ast.Expr)
exit_guard = loop.body[1]
assert isinstance(exit_guard, ast.If) and len(exit_guard.body) == 1 and isinstance(exit_guard.body[0], ast.Break)
assert isinstance(function.body[1], ast.Expr)
";

const MUTATE_HANDLER_RAISE_OPERAND: &str = r"import dis,marshal,sys,types
path = sys.argv[1]
raw = open(path, 'rb').read()
module = marshal.loads(raw[16:])
def mutate(code):
    if code.co_name != 'consume':
        return code
    instructions = list(dis.get_instructions(code, show_caches=True))
    raises = [instruction for instruction in instructions if instruction.opname == 'RAISE_VARARGS' and instruction.arg == 1]
    assert len(raises) == 2
    handler_raise = raises[1]
    item_load = max(
        instruction
        for instruction in instructions
        if instruction.offset < handler_raise.offset and instruction.opname == 'LOAD_FAST' and instruction.argval == 'item'
    )
    bytecode = bytearray(code.co_code)
    assert bytecode[item_load.offset] == dis.opmap['LOAD_FAST']
    bytecode[item_load.offset + 1] = code.co_varnames.index('next_item')
    return code.replace(co_code=bytes(bytecode))
module = module.replace(
    co_consts=tuple(mutate(value) if isinstance(value, types.CodeType) else value for value in module.co_consts)
)
open(path, 'wb').write(raw[:16] + marshal.dumps(module))
";

const MUTATE_INLINE_GUARD_TARGET: &str = r"import dis,marshal,sys,types
path = sys.argv[1]
mode = sys.argv[2]
raw = open(path, 'rb').read()
module = marshal.loads(raw[16:])
def mutate(code):
    if code.co_name != 'consume':
        return code
    instructions = list(dis.get_instructions(code, show_caches=True))
    raises = [instruction for instruction in instructions if instruction.opname == 'RAISE_VARARGS' and instruction.arg == 1]
    assert len(raises) == 2
    inline_raise = raises[0]
    inline_guard = max(
        instruction
        for instruction in instructions
        if instruction.offset < inline_raise.offset and instruction.opname == 'POP_JUMP_IF_FALSE'
    )
    if mode == 'different-valid':
        back_edge = next(
            instruction
            for instruction in instructions
            if instruction.offset > inline_raise.offset and instruction.opname == 'JUMP_BACKWARD'
        )
        delta = back_edge.offset - (inline_guard.offset + 2)
        assert delta > 0 and delta % 2 == 0
        target_arg = delta // 2
    elif mode == 'unresolvable':
        target_arg = 255
    else:
        raise AssertionError(mode)
    assert target_arg <= 255 and target_arg != inline_guard.arg
    bytecode = bytearray(code.co_code)
    assert bytecode[inline_guard.offset] == dis.opmap['POP_JUMP_IF_FALSE']
    bytecode[inline_guard.offset + 1] = target_arg
    return code.replace(co_code=bytes(bytecode))
module = module.replace(
    co_consts=tuple(mutate(value) if isinstance(value, types.CodeType) else value for value in module.co_consts)
)
open(path, 'wb').write(raw[:16] + marshal.dumps(module))
";

const MUTATE_HANDLER_GUARD_TARGET: &str = r"import dis,marshal,sys,types
path = sys.argv[1]
mode = sys.argv[2]
raw = open(path, 'rb').read()
module = marshal.loads(raw[16:])
def mutate(code):
    if code.co_name != 'consume':
        return code
    instructions = list(dis.get_instructions(code, show_caches=True))
    raises = [instruction for instruction in instructions if instruction.opname == 'RAISE_VARARGS' and instruction.arg == 1]
    assert len(raises) == 2
    handler_raise = raises[1]
    handler_guard = max(
        instruction
        for instruction in instructions
        if instruction.offset < handler_raise.offset and instruction.opname == 'POP_JUMP_IF_FALSE'
    )
    if mode == 'different-valid':
        target_arg = 0
    elif mode == 'unresolvable':
        target_arg = 255
    else:
        raise AssertionError(mode)
    assert target_arg <= 255 and target_arg != handler_guard.arg
    bytecode = bytearray(code.co_code)
    assert bytecode[handler_guard.offset] == dis.opmap['POP_JUMP_IF_FALSE']
    bytecode[handler_guard.offset + 1] = target_arg
    return code.replace(co_code=bytes(bytecode))
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

fn compile_fixture(interpreter: &Path, source: &Path, pyc: &Path) {
    let compiled: std::process::Output = Command::new(interpreter)
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
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
}

fn assert_mutated_guarded_raise_refused<F>(scratch_name: &str, mutate: F)
where
    F: FnOnce(&Path, &Path),
{
    let interpreter: PathBuf = find_interpreter("3.12").expect("CPython 3.12");
    let disrobe: PathBuf = find_disrobe().expect("disrobe binary");
    let scratch: PathBuf = band_scratch(scratch_name);
    let source_path: PathBuf = scratch.join("fixture.py");
    let pyc_path: PathBuf = scratch.join("fixture.pyc");
    let out: PathBuf = scratch.join("out");
    let _ = std::fs::remove_dir_all(&out);
    std::fs::write(&source_path, SOURCE).expect("write source");
    compile_fixture(&interpreter, &source_path, &pyc_path);
    mutate(&interpreter, &pyc_path);
    let output: std::process::Output = Command::new(&disrobe)
        .args(["auto"])
        .arg(&pyc_path)
        .args(["--out"])
        .arg(&out)
        .args(["--max-depth", "3", "--capture-stages"])
        .stdin(Stdio::null())
        .output()
        .expect("spawn auto");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let recovered: String = captured_source(&out);
    assert!(
        recovered.contains("decompile-error: ast builder desync at offset "),
        "mismatched copies were published as source:\n{recovered}"
    );
    assert!(
        recovered.contains("guarded finally raise copies differ between inline and handler paths"),
        "the refusal did not identify the mismatched paired copies:\n{recovered}"
    );
    assert!(
        !recovered.contains("raise make_error(item)"),
        "the mismatched handler copy was published:\n{recovered}"
    );
}

fn mutate_handler_raise_operand(interpreter: &Path, pyc: &Path) {
    let output: std::process::Output = Command::new(interpreter)
        .args(["-c", MUTATE_HANDLER_RAISE_OPERAND])
        .arg(pyc)
        .stdin(Stdio::null())
        .output()
        .expect("mutate handler raise operand");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn mutate_inline_guard_target(interpreter: &Path, pyc: &Path, mode: &str) {
    let output: std::process::Output = Command::new(interpreter)
        .args(["-c", MUTATE_INLINE_GUARD_TARGET])
        .arg(pyc)
        .arg(mode)
        .stdin(Stdio::null())
        .output()
        .expect("mutate inline guard target");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn mutate_handler_guard_target(interpreter: &Path, pyc: &Path, mode: &str) {
    let output: std::process::Output = Command::new(interpreter)
        .args(["-c", MUTATE_HANDLER_GUARD_TARGET])
        .arg(pyc)
        .arg(mode)
        .stdin(Stdio::null())
        .output()
        .expect("mutate handler guard target");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn auto_preserves_guarded_nonconstant_raise_inside_infinite_loop_finally() {
    let interpreter: PathBuf = find_interpreter("3.12").expect("CPython 3.12");
    let disrobe: PathBuf = find_disrobe().expect("disrobe binary");
    let scratch: PathBuf = band_scratch("infinite-loop-finally-guarded-raise-auto");
    let source_path: PathBuf = scratch.join("fixture.py");
    let pyc_path: PathBuf = scratch.join("fixture.pyc");
    let original_path: PathBuf = scratch.join("original.py");
    let recovered_path: PathBuf = scratch.join("recovered.py");
    let out: PathBuf = scratch.join("out");
    let _ = std::fs::remove_dir_all(&out);
    std::fs::write(&source_path, SOURCE).expect("write source");
    let compiled: std::process::Output = Command::new(&interpreter)
        .args([
            "-c",
            "import py_compile,sys;py_compile.compile(sys.argv[1],cfile=sys.argv[2],doraise=True)",
        ])
        .arg(&source_path)
        .arg(&pyc_path)
        .stdin(Stdio::null())
        .output()
        .expect("compile fixture");
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let output: std::process::Output = Command::new(&disrobe)
        .args(["auto"])
        .arg(&pyc_path)
        .args(["--out"])
        .arg(&out)
        .args(["--max-depth", "3", "--capture-stages"])
        .stdin(Stdio::null())
        .output()
        .expect("spawn auto");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let recovered: String = captured_source(&out);
    assert_eq!(recovered.matches("while True:").count(), 1, "{recovered}");
    assert_eq!(
        recovered.matches("raise make_error(item)").count(),
        1,
        "{recovered}"
    );
    assert_eq!(
        recovered.matches("sink((\"continue\", item))").count(),
        1,
        "{recovered}"
    );
    assert_eq!(
        recovered.matches("if should_stop(item):").count(),
        1,
        "{recovered}"
    );
    assert_eq!(
        recovered.matches("sink((\"done\", item))").count(),
        1,
        "{recovered}"
    );
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
    let recovered_output: std::process::Output = run(&interpreter, &[], &recovered_path);
    assert!(original.status.success() && recovered_output.status.success());
    assert_eq!(recovered_output.stdout, original.stdout);
    assert_eq!(
        String::from_utf8(original.stdout).expect("utf8").trim(),
        "RuntimeError raised:two True [('body', 'one'), ('cleanup', 'one'), ('continue', 'one'), ('body', 'two'), ('cleanup', 'two'), ('make_error', 'two')]\n[('body', 'one'), ('cleanup', 'one'), ('continue', 'one'), ('body', 'two'), ('cleanup', 'two'), ('make_error', 'two'), ('body', 'one'), ('cleanup', 'one'), ('continue', 'one'), ('body', 'two'), ('cleanup', 'two'), ('continue', 'two'), ('done', 'two')]"
    );
}

#[test]
fn auto_refuses_mismatched_guarded_raise_operands() {
    assert_mutated_guarded_raise_refused(
        "infinite-loop-finally-mismatched-raise-auto",
        mutate_handler_raise_operand,
    );
}

#[test]
fn auto_refuses_mismatched_guarded_raise_targets() {
    assert_mutated_guarded_raise_refused(
        "infinite-loop-finally-mismatched-raise-target-auto",
        |interpreter: &Path, pyc: &Path| {
            mutate_inline_guard_target(interpreter, pyc, "different-valid");
        },
    );
}

#[test]
fn auto_refuses_unresolvable_guarded_raise_targets() {
    assert_mutated_guarded_raise_refused(
        "infinite-loop-finally-unresolvable-raise-target-auto",
        |interpreter: &Path, pyc: &Path| {
            mutate_inline_guard_target(interpreter, pyc, "unresolvable");
        },
    );
}

#[test]
fn auto_refuses_mismatched_handler_guarded_raise_targets() {
    assert_mutated_guarded_raise_refused(
        "infinite-loop-finally-mismatched-handler-raise-target-auto",
        |interpreter: &Path, pyc: &Path| {
            mutate_handler_guard_target(interpreter, pyc, "different-valid");
        },
    );
}

#[test]
fn auto_refuses_unresolvable_handler_guarded_raise_targets() {
    assert_mutated_guarded_raise_refused(
        "infinite-loop-finally-unresolvable-handler-raise-target-auto",
        |interpreter: &Path, pyc: &Path| {
            mutate_handler_guard_target(interpreter, pyc, "unresolvable");
        },
    );
}
