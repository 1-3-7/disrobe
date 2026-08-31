#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines
)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use common::band::find_interpreter;
use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::engine::{build_real_source, marshal_to_decompile};
use disrobe_pass_py_decompile::roundtrip::{Verdict, semantic_equiv};
use disrobe_py_marshal::{CodeObject, Object, PyVersion as MarshalVersion, PycFile, read_pyc};

const ALL: &[&str] = &["3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15"];
const BLOCK_STACK: &[&str] = &["3.9", "3.10"];
const PLAIN_TRY_EXCEPT: &[&str] = &["3.9", "3.10", "3.12", "3.14", "3.15"];
const MUTATE_ENTRY_RETURN: &str = r"import dis,marshal,sys,types
path = sys.argv[1]
raw = open(path, 'rb').read()
module = marshal.loads(raw[16:])
def mutate(code):
    if code.co_name != 'f':
        return code
    instructions = list(dis.get_instructions(code))
    entry = next(item for item in instructions if item.opname == 'POP_JUMP_IF_FALSE')
    target_index = next(index for index, item in enumerate(instructions) if item.offset == entry.argval)
    target = instructions[target_index]
    assert target.argval is None
    if target.opname == 'RETURN_CONST':
        assert instructions[target_index - 1].opname == 'RETURN_CONST'
        assert instructions[target_index - 1].argval is None
    else:
        assert target.opname == 'LOAD_CONST'
        assert instructions[target_index - 1].opname == 'RETURN_VALUE'
        assert instructions[target_index - 2].opname == 'LOAD_CONST'
        assert instructions[target_index - 2].argval is None
    marker = 137
    constants = code.co_consts + (marker,)
    assert len(constants) <= 256
    bytecode = bytearray(code.co_code)
    bytecode[target.offset + 1] = len(constants) - 1
    changed = code.replace(co_code=bytes(bytecode), co_consts=constants)
    changed_target = next(item for item in dis.get_instructions(changed) if item.offset == target.offset)
    assert changed_target.argval == marker
    return changed
module = module.replace(co_consts=tuple(mutate(value) if isinstance(value, types.CodeType) else value for value in module.co_consts))
open(path, 'wb').write(raw[:16] + marshal.dumps(module))
";

#[derive(Debug, Clone, Copy)]
struct LoopTryCase {
    label: &'static str,
    source: &'static str,
    equivalent_on: &'static [&'static str],
    open_reason: &'static str,
}

const CASES: &[LoopTryCase] = &[
    LoopTryCase {
        label: "while_try_except",
        source: "def f(active, nxt, sink):\n    while active():\n        try:\n            sink(nxt())\n        except LookupError:\n            sink(None)\n",
        equivalent_on: PLAIN_TRY_EXCEPT,
        open_reason: "3.11 and 3.13 use distinct table-era loop joins outside this slice",
    },
    LoopTryCase {
        label: "while_try_break",
        source: "def f(active, nxt, sink):\n    while active():\n        try:\n            item = nxt()\n        except LookupError:\n            break\n        else:\n            sink(item)\n    sink(0)\n",
        equivalent_on: &["3.9", "3.10", "3.12", "3.13", "3.14"],
        open_reason: "3.11 and 3.15 use different table-era loop joins outside this slice",
    },
    LoopTryCase {
        label: "while_try_finally",
        source: "def f(active, nxt, sink):\n    while active():\n        try:\n            sink(nxt())\n        finally:\n            sink(None)\n",
        equivalent_on: BLOCK_STACK,
        open_reason: "a finally duplicated along every loop exit is the region duplication class",
    },
    LoopTryCase {
        label: "while_try_except_finally",
        source: "def f(active, nxt, sink):\n    while active():\n        try:\n            sink(nxt())\n        except LookupError:\n            sink(1)\n        finally:\n            sink(2)\n",
        equivalent_on: BLOCK_STACK,
        open_reason: "a finally duplicated along every loop exit is the region duplication class",
    },
    LoopTryCase {
        label: "while_try_else",
        source: "def f(active, nxt, sink):\n    while active():\n        try:\n            v = nxt()\n        except LookupError:\n            sink(1)\n        else:\n            sink(v)\n",
        equivalent_on: &[],
        open_reason: "the try else arm and the loop re-test share a join block on every band",
    },
    LoopTryCase {
        label: "while_try_star",
        source: "def f(active, nxt, sink):\n    while active():\n        try:\n            sink(nxt())\n        except* LookupError:\n            sink(1)\n",
        equivalent_on: &[],
        open_reason: "except* groups lower through a different handler chain than except and are \
                      not reconstructed inside a loop body on any band",
    },
    LoopTryCase {
        label: "while_with",
        source: "def f(active, mgr, sink):\n    while active():\n        with mgr():\n            sink(1)\n",
        equivalent_on: &[],
        open_reason: "a with in a loop body lowers through the same exception machinery and is \
                      the with region lane",
    },
    LoopTryCase {
        label: "while_try_continue",
        source: "def f(active, nxt, sink):\n    while active():\n        try:\n            sink(nxt())\n        except LookupError:\n            continue\n",
        equivalent_on: &["3.11"],
        open_reason: "a continue out of a handler duplicates the loop re-test on the other bands",
    },
    LoopTryCase {
        label: "while_try_return",
        source: "def f(active, nxt, sink):\n    while active():\n        try:\n            return nxt()\n        except LookupError:\n            sink(1)\n",
        equivalent_on: BLOCK_STACK,
        open_reason: "a return inside the protected body is lifted past the loop on the table era",
    },
    LoopTryCase {
        label: "while_true_try_break",
        source: "def f(nxt, sink):\n    while True:\n        try:\n            sink(nxt())\n        except LookupError:\n            break\n",
        equivalent_on: &["3.10", "3.11", "3.12", "3.13", "3.14", "3.15"],
        open_reason: "3.9 lowers the unconditional back edge through the block stack",
    },
    LoopTryCase {
        label: "while_else_try",
        source: "def f(active, nxt, sink):\n    while active():\n        try:\n            sink(nxt())\n        except LookupError:\n            break\n    else:\n        sink(9)\n",
        equivalent_on: &["3.9", "3.10", "3.11", "3.14"],
        open_reason: "the loop else arm and the handler exit share a join on 3.12, 3.13 and 3.15",
    },
    LoopTryCase {
        label: "for_try_break",
        source: "def f(xs, nxt, sink):\n    for x in xs:\n        try:\n            sink(nxt(x))\n        except LookupError:\n            break\n",
        equivalent_on: &["3.11"],
        open_reason: "the break edge out of a handler inside a for body is not mapped on the \
                      other bands",
    },
    LoopTryCase {
        label: "for_else_try",
        source: "def f(xs, nxt, sink):\n    for x in xs:\n        try:\n            sink(nxt(x))\n        except LookupError:\n            break\n    else:\n        sink(9)\n",
        equivalent_on: &["3.11", "3.12", "3.13", "3.14", "3.15"],
        open_reason: "3.9 and 3.10 lower the for else arm through the block stack",
    },
    LoopTryCase {
        label: "try_outside_while",
        source: "def f(active, nxt, sink):\n    try:\n        while active():\n            sink(nxt())\n    except LookupError:\n        sink(1)\n",
        equivalent_on: &["3.9", "3.10", "3.11", "3.14", "3.15"],
        open_reason: "3.12 and 3.13 rotate the loop, so the peeled entry test sits outside the \
                      protected range that contains the rest of it",
    },
    LoopTryCase {
        label: "loop_in_try_in_loop",
        source: "def f(a, b, nxt, sink):\n    while a():\n        try:\n            while b():\n                sink(nxt())\n        except LookupError:\n            break\n",
        equivalent_on: &["3.10", "3.14"],
        open_reason: "two loop headers around one protected range need the full nesting order",
    },
    LoopTryCase {
        label: "try_in_while_else",
        source: "def f(active, nxt, sink):\n    while active():\n        sink(1)\n    else:\n        try:\n            sink(nxt())\n        except LookupError:\n            sink(2)\n",
        equivalent_on: ALL,
        open_reason: "",
    },
    LoopTryCase {
        label: "while_and_guard_try",
        source: "def f(a, b, nxt, sink):\n    while a() and b():\n        try:\n            sink(nxt())\n        except LookupError:\n            break\n",
        equivalent_on: &["3.9"],
        open_reason: "an and chain in the loop test splits the header block on the other bands",
    },
    LoopTryCase {
        label: "while_or_guard_try",
        source: "def f(a, b, nxt, sink):\n    while a() or b():\n        try:\n            sink(nxt())\n        except LookupError:\n            break\n",
        equivalent_on: &["3.10"],
        open_reason: "an or chain in the loop test splits the header block on the other bands",
    },
    LoopTryCase {
        label: "while_walrus_try",
        source: "def f(nxt, sink):\n    while (v := nxt()):\n        try:\n            sink(v)\n        except LookupError:\n            break\n",
        equivalent_on: &["3.9", "3.10", "3.14"],
        open_reason: "the walrus store splits the header block on 3.11 through 3.13 and on 3.15",
    },
    LoopTryCase {
        label: "while_not_try",
        source: "def f(a, nxt, sink):\n    while not a():\n        try:\n            sink(nxt())\n        except LookupError:\n            break\n",
        equivalent_on: &["3.9", "3.10", "3.14"],
        open_reason: "a negated loop test is not folded back on 3.11 through 3.13 and on 3.15",
    },
    LoopTryCase {
        label: "while_chained_cmp_try",
        source: "def f(a, nxt, sink):\n    while 0 < a() < 9:\n        try:\n            sink(nxt())\n        except LookupError:\n            break\n",
        equivalent_on: &["3.9"],
        open_reason: "a chained comparison in the loop test carries its own internal jumps",
    },
    LoopTryCase {
        label: "while_guard_try_continue",
        source: "def f(a, g, r, sink):\n    while a():\n        if g():\n            try:\n                sink(r())\n            except LookupError:\n                sink(None)\n            continue\n        sink(1)\n",
        equivalent_on: BLOCK_STACK,
        open_reason: "the guarded arm and the loop re-test share a join on the table era",
    },
    LoopTryCase {
        label: "for_guard_try_continue",
        source: "def f(xs, g, r, sink):\n    for x in xs:\n        if g(x):\n            try:\n                sink(r(x))\n            except LookupError:\n                sink(None)\n            continue\n        sink(x)\n",
        equivalent_on: &["3.9", "3.10", "3.11"],
        open_reason: "the guarded arm and the iterator re-entry share a join on 3.12 and later",
    },
    LoopTryCase {
        label: "while_try_yield",
        source: "def f(a, nxt, sink):\n    while a():\n        try:\n            yield nxt()\n        except LookupError:\n            break\n",
        equivalent_on: &["3.9", "3.10", "3.14"],
        open_reason: "a yield inside the protected body adds a resume edge on the other bands",
    },
    LoopTryCase {
        label: "while_try_raise",
        source: "def f(a, nxt, sink):\n    while a():\n        try:\n            sink(nxt())\n        except LookupError:\n            raise ValueError(1)\n",
        equivalent_on: &["3.9", "3.10", "3.14", "3.15"],
        open_reason: "a raise out of the handler leaves no normal exit to map on 3.11 to 3.13",
    },
    LoopTryCase {
        label: "async_for_try",
        source: "async def f(xs, sink):\n    async for x in xs:\n        try:\n            await sink(x)\n        except LookupError:\n            break\n",
        equivalent_on: &["3.11"],
        open_reason: "an async-for protected body still loses iterator ownership outside 3.11",
    },
    LoopTryCase {
        label: "for_in_for_try",
        source: "def f(rows, sink):\n    for row in rows:\n        for value in row:\n            try:\n                sink(value)\n            except LookupError:\n                continue\n",
        equivalent_on: &["3.11", "3.12", "3.13", "3.14", "3.15"],
        open_reason: "the block-stack bands flatten the inner iterator into an assignment",
    },
    LoopTryCase {
        label: "for_in_while_try",
        source: "def f(rows, active, sink):\n    for row in rows:\n        while active(row):\n            try:\n                sink(row)\n            except LookupError:\n                break\n",
        equivalent_on: &["3.10"],
        open_reason: "the nested while header and protected exit overlap on every other measured band",
    },
    LoopTryCase {
        label: "for_in_async_for_try",
        source: "async def f(groups, sink):\n    for group in groups:\n        async for value in group:\n            try:\n                await sink(value)\n            except LookupError:\n                continue\n",
        equivalent_on: &[],
        open_reason: "an async-for nested under a synchronous for still loses iterator ownership on every measured band",
    },
    LoopTryCase {
        label: "nested_for_try_with",
        source: "def f(rows, mgr, sink):\n    for row in rows:\n        try:\n            with mgr(row):\n                sink(row)\n        except LookupError:\n            continue\n",
        equivalent_on: &["3.11", "3.12", "3.13", "3.14", "3.15"],
        open_reason: "the block-stack bands flatten the outer iterator around the with region",
    },
    LoopTryCase {
        label: "for_negated_guard_try_continue",
        source: "def f(xs, g, r, sink):\n    for x in xs:\n        if not g(x):\n            try:\n                sink(r(x))\n            except LookupError:\n                sink(None)\n            continue\n        sink(x)\n",
        equivalent_on: &["3.9", "3.10", "3.11"],
        open_reason: "3.12 and later invert the guarded continuation into an else arm",
    },
    LoopTryCase {
        label: "for_try_tuple_except",
        source: "def f(xs, sink):\n    for x in xs:\n        try:\n            sink(x)\n        except (LookupError, ValueError):\n            continue\n",
        equivalent_on: &["3.11", "3.12", "3.13", "3.14", "3.15"],
        open_reason: "the block-stack bands flatten the iterator around the tuple handler",
    },
    LoopTryCase {
        label: "for_try_named_except",
        source: "def f(xs, sink):\n    for x in xs:\n        try:\n            sink(x)\n        except LookupError as error:\n            sink(error)\n",
        equivalent_on: &["3.11", "3.12", "3.13", "3.14", "3.15"],
        open_reason: "the block-stack bands flatten the iterator around the named handler",
    },
];

#[derive(Debug, Clone, Copy)]
struct HeaderOwnershipCase {
    label: &'static str,
    source: &'static str,
    required: &'static str,
    owned_on: &'static [&'static str],
    open_reason: &'static str,
}

const HEADER_OWNERSHIP: &[HeaderOwnershipCase] = &[
    HeaderOwnershipCase {
        label: "while_header_over_try_body",
        source: "def f(active, nxt, sink):\n    while active():\n        try:\n            item = nxt()\n        except LookupError:\n            break\n        else:\n            sink(item)\n    sink(0)\n",
        required: "while active():",
        owned_on: &["3.9", "3.10", "3.11", "3.14", "3.15"],
        open_reason: "3.12 and 3.13 rotate the loop, so the header the back edge targets is the \
                      body entry and the peeled test still reads as a guard",
    },
    HeaderOwnershipCase {
        label: "for_header_over_guarded_try",
        source: "def f(xs, g, r, sink):\n    for x in xs:\n        if g(x):\n            try:\n                sink(r(x))\n            except LookupError:\n                sink(None)\n            continue\n        sink(x)\n",
        required: "for x in xs:",
        owned_on: ALL,
        open_reason: "",
    },
    HeaderOwnershipCase {
        label: "guarded_try_outside_any_loop",
        source: "def f(g, r, sink):\n    if g():\n        try:\n            sink(r())\n        except LookupError:\n            sink(None)\n    sink(1)\n",
        required: "if g():",
        owned_on: ALL,
        open_reason: "",
    },
];

const EXCEPT_GROUP_BANDS: &[&str] = &["3.11", "3.12", "3.13", "3.14", "3.15"];

const EXCEPT_GROUP_SOURCES: &[(&str, &str)] = &[
    (
        "while_body",
        "def f(active, nxt, sink):\n    while active():\n        try:\n            sink(nxt())\n        except* LookupError:\n            sink(1)\n",
    ),
    (
        "while_body_named",
        "def f(active, nxt, sink):\n    while active():\n        try:\n            sink(nxt())\n        except* LookupError as eg:\n            sink(eg)\n",
    ),
    (
        "for_body",
        "def f(xs, nxt, sink):\n    for x in xs:\n        try:\n            sink(nxt(x))\n        except* LookupError:\n            sink(1)\n",
    ),
    (
        "while_body_two_handlers",
        "def f(active, nxt, sink):\n    while active():\n        try:\n            sink(nxt())\n        except* LookupError:\n            sink(1)\n        except* ValueError:\n            sink(2)\n",
    ),
    (
        "guarded_inside_while",
        "def f(active, g, nxt, sink):\n    while active():\n        if g():\n            try:\n                sink(nxt())\n            except* LookupError:\n                sink(1)\n",
    ),
    (
        "outside_any_loop",
        "def f(g, nxt, sink):\n    if g():\n        try:\n            sink(nxt())\n        except* LookupError:\n            sink(1)\n",
    ),
];

#[test]
fn an_exception_group_handler_is_never_recovered_as_a_plain_except() {
    let scratch: PathBuf = PathBuf::from("../../target/py-except-group-kind");
    fs::create_dir_all(&scratch).expect("scratch");

    let mut graded: usize = 0;
    let mut failures: Vec<String> = Vec::new();

    for &alias in EXCEPT_GROUP_BANDS {
        let Some(interpreter): Option<PathBuf> = find_interpreter(alias) else {
            continue;
        };
        for &(label, source) in EXCEPT_GROUP_SOURCES {
            let source_path: PathBuf = scratch.join(format!("{label}.{alias}.py"));
            fs::write(&source_path, source).expect("write fixture");
            let orig_pyc: PathBuf = scratch.join(format!("{label}.{alias}.pyc"));
            if compile_source(&interpreter, &source_path, &orig_pyc).is_err() {
                continue;
            }
            let (original, marshal_version): (CodeObject, MarshalVersion) =
                read_code(&orig_pyc).unwrap_or_else(|e| panic!("py{alias}/{label} read: {e}"));
            let version: PyVersion = marshal_to_decompile(marshal_version)
                .unwrap_or_else(|e| panic!("py{alias}/{label} version map: {e:?}"));
            let recovered: String = build_real_source(&original, &version, marshal_version)
                .unwrap_or_else(|e| panic!("py{alias}/{label} decompile: {e}"));
            graded += 1;

            let downgraded: Vec<&str> = recovered
                .lines()
                .map(str::trim_start)
                .filter(|line: &&str| line.starts_with("except") && !line.starts_with("except*"))
                .collect();
            if !downgraded.is_empty() {
                failures.push(format!(
                    "py{alias}/{label}: every handler in this source is an exception group, so a \
                     recovered `except` without the star silently rewrites the semantics; found \
                     {downgraded:?}\n{recovered}"
                ));
            }
        }
    }

    assert!(
        graded > 0,
        "no CPython 3.11 through 3.15 interpreter resolved, so this case graded nothing"
    );
    assert!(
        failures.is_empty(),
        "{} exception group handlers recovered as a plain except:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

#[test]
fn a_loop_header_is_never_consumed_as_a_guard_over_its_own_body_try() {
    let scratch: PathBuf = PathBuf::from("../../target/py-loop-header-ownership");
    fs::create_dir_all(&scratch).expect("scratch");

    let mut graded: usize = 0;
    let mut failures: Vec<String> = Vec::new();

    for &alias in ALL {
        let Some(interpreter): Option<PathBuf> = find_interpreter(alias) else {
            continue;
        };
        for case in HEADER_OWNERSHIP {
            let label: &str = case.label;
            assert!(
                case.owned_on.len() == ALL.len() || !case.open_reason.is_empty(),
                "{label} leaves a band unowned and states no reason"
            );
            let source_path: PathBuf = scratch.join(format!("{label}.{alias}.py"));
            fs::write(&source_path, case.source).expect("write fixture");
            let orig_pyc: PathBuf = scratch.join(format!("{label}.{alias}.pyc"));
            if compile_source(&interpreter, &source_path, &orig_pyc).is_err() {
                continue;
            }
            let (original, marshal_version): (CodeObject, MarshalVersion) =
                read_code(&orig_pyc).unwrap_or_else(|e| panic!("py{alias}/{label} read: {e}"));
            let version: PyVersion = marshal_to_decompile(marshal_version)
                .unwrap_or_else(|e| panic!("py{alias}/{label} version map: {e:?}"));
            let recovered: String = build_real_source(&original, &version, marshal_version)
                .unwrap_or_else(|e| panic!("py{alias}/{label} decompile: {e}"));
            graded += 1;

            if case.owned_on.contains(&alias) && !recovered.contains(case.required) {
                failures.push(format!(
                    "py{alias}/{label}: the recovered source must open the region with `{}`, so \
                     the header stays with the builder that owns it\n{recovered}",
                    case.required
                ));
            }
        }
    }

    assert!(
        graded > 0,
        "no CPython 3.9 through 3.15 interpreter resolved, so this case graded nothing"
    );
    assert!(
        failures.is_empty(),
        "{} header ownership failures:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

fn compile_source(interpreter: &Path, source_path: &Path, pyc_path: &Path) -> Result<(), String> {
    let script: &str =
        "import py_compile,sys;py_compile.compile(sys.argv[1],cfile=sys.argv[2],doraise=True)";
    let output: std::process::Output = Command::new(interpreter)
        .args([
            "-c",
            script,
            source_path.to_str().unwrap_or(""),
            pyc_path.to_str().unwrap_or(""),
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|e: std::io::Error| format!("spawn: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "exit={:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn assert_recompiled_equivalent(
    interpreter: &Path,
    scratch: &Path,
    label: &str,
    original: &CodeObject,
    marshal_version: MarshalVersion,
    recovered: &str,
) {
    let recovered_path: PathBuf = scratch.join(format!("{label}.recovered.py"));
    let recompiled_path: PathBuf = scratch.join(format!("{label}.recompiled.pyc"));
    fs::write(&recovered_path, recovered).expect("write recovered fixture");
    compile_source(interpreter, &recovered_path, &recompiled_path)
        .expect("compile recovered fixture");
    let (recompiled, _): (CodeObject, MarshalVersion) =
        read_code(&recompiled_path).expect("read recompiled fixture");
    assert!(
        matches!(
            semantic_equiv(original, &recompiled, marshal_version),
            Verdict::Perfect | Verdict::Semantic
        ),
        "{label}: recovered source is not semantically equivalent\n{recovered}"
    );
}

fn assert_outer_while_nesting(
    interpreter: &Path,
    scratch: &Path,
    label: &str,
    recovered: &str,
    expected: bool,
) {
    let recovered_path: PathBuf = scratch.join(format!("{label}.structure.py"));
    fs::write(&recovered_path, recovered).expect("write structure fixture");
    let script: &str = "import ast,sys; tree=ast.parse(open(sys.argv[1],encoding='utf-8').read()); function=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='f'); nested=any(isinstance(node,ast.If) and any(isinstance(child,ast.While) for child in node.body) for node in ast.walk(function)); assert nested == (sys.argv[2]=='true')";
    let output: std::process::Output = Command::new(interpreter)
        .args(["-c", script])
        .arg(&recovered_path)
        .arg(expected.to_string())
        .stdin(Stdio::null())
        .output()
        .expect("inspect recovered structure");
    assert!(
        output.status.success(),
        "{label}: outer-if/while nesting mismatch: {}\n{recovered}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_distinct_return_guard(interpreter: &Path, scratch: &Path, label: &str, recovered: &str) {
    let recovered_path: PathBuf = scratch.join(format!("{label}.guard.py"));
    fs::write(&recovered_path, recovered).expect("write guard fixture");
    let script: &str = "import ast,sys; tree=ast.parse(open(sys.argv[1],encoding='utf-8').read()); function=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='f'); guard=function.body[0]; assert isinstance(guard,ast.If); assert any(isinstance(node,ast.While) for node in guard.body); guarded_return=next(node for node in guard.body if isinstance(node,ast.Return)); assert isinstance(guarded_return.value,ast.Constant) and guarded_return.value.value is None; outer_return=function.body[-1]; assert isinstance(outer_return,ast.Return) and isinstance(outer_return.value,ast.Constant) and outer_return.value.value==137";
    let output: std::process::Output = Command::new(interpreter)
        .args(["-c", script])
        .arg(&recovered_path)
        .stdin(Stdio::null())
        .output()
        .expect("inspect distinct return guard");
    assert!(
        output.status.success(),
        "{label}: distinct return paths were collapsed: {}\n{recovered}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn read_code(pyc_path: &Path) -> Result<(CodeObject, MarshalVersion), String> {
    let bytes: Vec<u8> = fs::read(pyc_path).map_err(|e: std::io::Error| format!("read: {e}"))?;
    let pyc: PycFile = read_pyc(&bytes).map_err(|e| format!("read_pyc: {e}"))?;
    let ver: MarshalVersion = pyc.header.version;
    match pyc.code {
        Object::Code(boxed) => Ok((*boxed, ver)),
        other => Err(format!("top-level not code: {other:?}")),
    }
}

#[test]
fn loop_bodies_holding_a_try_keep_their_pinned_recovery() {
    let scratch: PathBuf = PathBuf::from("../../target/py-loop-try-input-space");
    fs::create_dir_all(&scratch).expect("scratch");

    let mut graded: usize = 0;
    let mut failures: Vec<String> = Vec::new();
    let mut skipped: Vec<&str> = Vec::new();

    for &alias in ALL {
        let Some(interpreter): Option<PathBuf> = find_interpreter(alias) else {
            skipped.push(alias);
            continue;
        };
        for case in CASES {
            let label: &str = case.label;
            assert!(
                case.equivalent_on.iter().all(|a: &&str| ALL.contains(a)),
                "{label} pins an alias this case never measures"
            );
            assert!(
                !case.equivalent_on.is_empty() || !case.open_reason.is_empty(),
                "{label} recovers on no band and states no reason"
            );
            let source_path: PathBuf = scratch.join(format!("{label}.{alias}.py"));
            fs::write(&source_path, case.source).expect("write fixture");
            let orig_pyc: PathBuf = scratch.join(format!("{label}.{alias}.pyc"));
            if let Err(e) = compile_source(&interpreter, &source_path, &orig_pyc) {
                assert!(
                    !case.equivalent_on.contains(&alias),
                    "py{alias}/{label} is pinned equivalent but CPython rejects the fixture: {e}"
                );
                continue;
            }
            let (original, marshal_version): (CodeObject, MarshalVersion) =
                read_code(&orig_pyc).unwrap_or_else(|e| panic!("py{alias}/{label} read: {e}"));
            let version: PyVersion = marshal_to_decompile(marshal_version)
                .unwrap_or_else(|e| panic!("py{alias}/{label} version map: {e:?}"));
            let recovered: String = build_real_source(&original, &version, marshal_version)
                .unwrap_or_else(|e| panic!("py{alias}/{label} decompile: {e}"));

            if label == "async_for_try" && alias == "3.11" {
                assert!(
                    recovered.contains("async for x in xs:")
                        && recovered.contains("except LookupError:"),
                    "py{alias}/{label} lost the owned async-for try region:\n{recovered}"
                );
            }

            graded += 1;

            let recovered_path: PathBuf = scratch.join(format!("{label}.rec.{alias}.py"));
            fs::write(&recovered_path, &recovered).expect("write recovered");
            let recompiled_pyc: PathBuf = scratch.join(format!("{label}.rec.{alias}.pyc"));
            let equivalent: bool = compile_source(&interpreter, &recovered_path, &recompiled_pyc)
                .is_ok()
                && read_code(&recompiled_pyc).is_ok_and(|(recompiled, _)| {
                    matches!(
                        semantic_equiv(&original, &recompiled, marshal_version),
                        Verdict::Perfect | Verdict::Semantic
                    )
                });

            if case.equivalent_on.contains(&alias) && !equivalent {
                failures.push(format!(
                    "py{alias}/{label}: pinned equivalent and is not\n{recovered}"
                ));
            }
        }
    }

    assert!(
        skipped.is_empty(),
        "required CPython interpreters were not measured: {skipped:?}"
    );
    assert!(
        graded > 0,
        "no CPython 3.9 through 3.15 interpreter resolved, so this case graded nothing"
    );
    assert!(
        failures.is_empty(),
        "{} loop-with-try failures:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

#[test]
fn identical_outer_guard_remains_outside_a_while() {
    let interpreter: PathBuf = find_interpreter("3.12").expect("CPython 3.12");
    let scratch: PathBuf = PathBuf::from("../../target/py-ci003-outer-guard");
    fs::create_dir_all(&scratch).expect("scratch");
    for (label, source, while_header, retains_outer_if) in [
        (
            "ordinary",
            "def f(active, sink):\n    while active():\n        sink()\n",
            "while active():",
            false,
        ),
        (
            "try-else-loop",
            "def f(active, nxt, sink):\n    try:\n        active = nxt()\n    except LookupError:\n        pass\n    else:\n        while active:\n            sink(active)\n            active = nxt()\n    sink(0)\n",
            "while active:",
            false,
        ),
        (
            "compound",
            "def f(active, ready, sink):\n    while active() and ready():\n        sink()\n",
            "while active() and ready():",
            false,
        ),
        (
            "repeated-compound",
            "def f(active, sink):\n    while active() and active():\n        sink()\n",
            "while active() and active():",
            false,
        ),
        (
            "outer",
            "def f(active, sink):\n    if active():\n        while active():\n            sink()\n",
            "while active():",
            true,
        ),
        (
            "outer-tail",
            "def f(active, sink):\n    if active():\n        while active():\n            sink()\n    sink(1)\n",
            "while active():",
            true,
        ),
        (
            "outer-try-break",
            "def f(active, nxt, sink):\n    if active():\n        while active():\n            try:\n                item = nxt()\n            except LookupError:\n                break\n            else:\n                sink(item)\n    sink(0)\n",
            "while active():",
            true,
        ),
        (
            "outer-multiple-handler",
            "def f(active, nxt, sink):\n    if active():\n        while active():\n            try:\n                sink(nxt())\n            except LookupError:\n                break\n            except ValueError:\n                break\n    sink(0)\n",
            "while active():",
            true,
        ),
        (
            "outer-finally",
            "def f(active, nxt, sink):\n    if active():\n        while active():\n            try:\n                sink(nxt())\n            finally:\n                sink(None)\n    sink(0)\n",
            "while active():",
            true,
        ),
        (
            "outer-with",
            "def f(active, mgr, sink):\n    if active():\n        while active():\n            with mgr():\n                sink(1)\n    sink(0)\n",
            "while active():",
            true,
        ),
        (
            "outer-distinct-returns",
            "def f(active, sink):\n    if active():\n        while active():\n            sink()\n        return 1\n    return 2\n",
            "while active():",
            true,
        ),
    ] {
        let source_path: PathBuf = scratch.join(format!("{label}.py"));
        let pyc_path: PathBuf = scratch.join(format!("{label}.pyc"));
        fs::write(&source_path, source).expect("write fixture");
        compile_source(&interpreter, &source_path, &pyc_path).expect("compile fixture");
        let (original, marshal_version): (CodeObject, MarshalVersion) =
            read_code(&pyc_path).expect("read fixture");
        let version: PyVersion = marshal_to_decompile(marshal_version).expect("version map");
        let recovered: String =
            build_real_source(&original, &version, marshal_version).expect("decompile fixture");
        assert!(recovered.contains(while_header), "{label}: {recovered}");
        assert_eq!(
            recovered.contains("if active():"),
            retains_outer_if,
            "{label}: {recovered}"
        );
        assert_outer_while_nesting(&interpreter, &scratch, label, &recovered, retains_outer_if);
        if label == "outer-distinct-returns" {
            assert_recompiled_equivalent(
                &interpreter,
                &scratch,
                label,
                &original,
                marshal_version,
                &recovered,
            );
        }
    }
}

#[test]
fn pre311_terminal_peel_keeps_a_source_outer_guard() {
    let interpreter: PathBuf = find_interpreter("3.10").expect("CPython 3.10");
    let scratch: PathBuf = PathBuf::from("../../target/py-ci003-pre311-outer-guard");
    fs::create_dir_all(&scratch).expect("scratch");
    for (label, source, retains_outer_if) in [
        (
            "outer",
            "def f(active, nxt, sink):\n    if active():\n        while active():\n            try:\n                sink(nxt())\n            except LookupError:\n                sink(None)\n",
            true,
        ),
        (
            "outer-tail",
            "def f(active, nxt, sink):\n    if active():\n        while active():\n            try:\n                sink(nxt())\n            except LookupError:\n                sink(None)\n    sink(0)\n",
            true,
        ),
        (
            "peeled",
            "def f(active, nxt, sink):\n    while active():\n        try:\n            sink(nxt())\n        except LookupError:\n            sink(None)\n",
            false,
        ),
        (
            "peeled-tail",
            "def f(active, nxt, sink):\n    while active():\n        try:\n            sink(nxt())\n        except LookupError:\n            sink(None)\n    sink(0)\n",
            false,
        ),
        (
            "outer-distinct-returns",
            "def f(active, sink):\n    if active():\n        while active():\n            sink()\n        return 1\n    return 2\n",
            true,
        ),
    ] {
        let source_path: PathBuf = scratch.join(format!("{label}.py"));
        let pyc_path: PathBuf = scratch.join(format!("{label}.pyc"));
        fs::write(&source_path, source).expect("write fixture");
        compile_source(&interpreter, &source_path, &pyc_path).expect("compile fixture");
        let (original, marshal_version): (CodeObject, MarshalVersion) =
            read_code(&pyc_path).expect("read fixture");
        let version: PyVersion = marshal_to_decompile(marshal_version).expect("version map");
        let recovered: String =
            build_real_source(&original, &version, marshal_version).expect("decompile fixture");
        assert!(
            recovered.contains("while active():"),
            "{label}: {recovered}"
        );
        assert_eq!(
            recovered.contains("if active():"),
            retains_outer_if,
            "{label}: {recovered}"
        );
        assert_outer_while_nesting(&interpreter, &scratch, label, &recovered, retains_outer_if);
        if label == "outer-distinct-returns" {
            assert_recompiled_equivalent(
                &interpreter,
                &scratch,
                label,
                &original,
                marshal_version,
                &recovered,
            );
        }
    }
}

#[test]
fn distinct_terminal_return_padding_is_never_peeled() {
    let source: &str = "def f(active, nxt, sink):\n    while active():\n        try:\n            sink(nxt())\n        except LookupError:\n            sink(None)\n";
    for alias in ["3.10", "3.12"] {
        let interpreter: PathBuf = find_interpreter(alias).expect("required CPython");
        let scratch: PathBuf = PathBuf::from("../../target/py-ci003-distinct-return-padding");
        fs::create_dir_all(&scratch).expect("scratch");
        let source_path: PathBuf = scratch.join(format!("{alias}.py"));
        let pyc_path: PathBuf = scratch.join(format!("{alias}.pyc"));
        fs::write(&source_path, source).expect("write fixture");
        compile_source(&interpreter, &source_path, &pyc_path).expect("compile fixture");
        let mutation: std::process::Output = Command::new(&interpreter)
            .args(["-c", MUTATE_ENTRY_RETURN])
            .arg(&pyc_path)
            .stdin(Stdio::null())
            .output()
            .expect("mutate entry return");
        assert!(
            mutation.status.success(),
            "{alias}: {}",
            String::from_utf8_lossy(&mutation.stderr)
        );
        let (original, marshal_version): (CodeObject, MarshalVersion) =
            read_code(&pyc_path).expect("read mutated fixture");
        let version: PyVersion = marshal_to_decompile(marshal_version).expect("version map");
        let recovered: String = build_real_source(&original, &version, marshal_version)
            .expect("recover representable distinct return paths");
        assert_distinct_return_guard(
            &interpreter,
            &scratch,
            &format!("{alias}-distinct-return-padding"),
            &recovered,
        );
    }
}
