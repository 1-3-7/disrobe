#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_const_for_fn
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use disrobe_pass_py_decompile::ast::{Comprehension, Expr, ExprCtx};
use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::codegen::{CodeEmitter, DefaultEmitter};
use disrobe_pass_py_decompile::engine::{build_real_source, marshal_to_decompile};
use disrobe_py_marshal::{CodeObject, Object, PyVersion as MarshalVersion, read_pyc};

#[test]
fn list_comp_with_multi_for_and_if() {
    let comp1: Comprehension = Comprehension {
        target: name("x", ExprCtx::Store),
        iter: name("xs", ExprCtx::Load),
        ifs: vec![name("cond", ExprCtx::Load)],
        is_async: false,
    };
    let comp2: Comprehension = Comprehension {
        target: name("y", ExprCtx::Store),
        iter: name("ys", ExprCtx::Load),
        ifs: Vec::new(),
        is_async: false,
    };
    let e: Expr = Expr::ListComp {
        elt: Box::new(Expr::Tuple {
            elts: vec![name("x", ExprCtx::Load), name("y", ExprCtx::Load)],
            ctx: ExprCtx::Load,
        }),
        generators: vec![comp1, comp2],
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_expr(&e, &v);
    assert_eq!(out, "[(x, y) for x in xs if cond for y in ys]");
}

#[test]
fn set_comp_emits_curly_braces() {
    let comp: Comprehension = Comprehension {
        target: name("x", ExprCtx::Store),
        iter: name("xs", ExprCtx::Load),
        ifs: Vec::new(),
        is_async: false,
    };
    let e: Expr = Expr::SetComp {
        elt: Box::new(name("x", ExprCtx::Load)),
        generators: vec![comp],
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_expr(&e, &v);
    assert_eq!(out, "{x for x in xs}");
}

#[test]
fn dict_comp_emits_kv_form() {
    let comp: Comprehension = Comprehension {
        target: name("k", ExprCtx::Store),
        iter: name("m", ExprCtx::Load),
        ifs: Vec::new(),
        is_async: false,
    };
    let e: Expr = Expr::DictComp {
        key: Box::new(name("k", ExprCtx::Load)),
        value: Box::new(name("v", ExprCtx::Load)),
        generators: vec![comp],
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_expr(&e, &v);
    assert_eq!(out, "{k: v for k in m}");
}

#[test]
fn generator_exp_wraps_in_parens() {
    let comp: Comprehension = Comprehension {
        target: name("x", ExprCtx::Store),
        iter: name("xs", ExprCtx::Load),
        ifs: Vec::new(),
        is_async: false,
    };
    let e: Expr = Expr::GeneratorExp {
        elt: Box::new(name("x", ExprCtx::Load)),
        generators: vec![comp],
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_expr(&e, &v);
    assert_eq!(out, "(x for x in xs)");
}

#[test]
fn async_comprehension_emits_async_for() {
    let comp: Comprehension = Comprehension {
        target: name("x", ExprCtx::Store),
        iter: name("xs", ExprCtx::Load),
        ifs: Vec::new(),
        is_async: true,
    };
    let e: Expr = Expr::ListComp {
        elt: Box::new(name("x", ExprCtx::Load)),
        generators: vec![comp],
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_expr(&e, &v);
    assert!(out.contains("async for"));
}

fn name(id: &str, ctx: ExprCtx) -> Expr {
    Expr::Name {
        id: id.to_owned(),
        ctx,
        line: None,
    }
}

const CASES_DIR: &str = "../../corpus/python/decompile/construct/cases";

fn find_3_14() -> Option<PathBuf> {
    let output: std::process::Output = Command::new("uv")
        .args(["python", "find", "3.14"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let path: PathBuf = PathBuf::from(raw);
    path.is_file().then_some(path)
}

fn compile_3_14(interpreter: &Path, source: &Path, pyc: &Path) {
    let script: &str =
        "import py_compile,sys;py_compile.compile(sys.argv[1],cfile=sys.argv[2],doraise=True)";
    let output: std::process::Output = Command::new(interpreter)
        .args([
            "-c",
            script,
            source.to_str().expect("source path utf8"),
            pyc.to_str().expect("pyc path utf8"),
        ])
        .stdin(Stdio::null())
        .output()
        .expect("spawn interpreter");
    assert!(
        output.status.success(),
        "compile failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Asserts a pure-async dict comprehension recovers its `async for` clause and inner `await` on 3.14.
#[test]
fn async_comp_for_dict_recovers_async_for_3_14() {
    let Some(interpreter): Option<PathBuf> = find_3_14() else {
        return;
    };
    let source_path: PathBuf = PathBuf::from(CASES_DIR).join("async_comp_for_dict.py");
    assert!(
        source_path.is_file(),
        "missing fixture {}",
        source_path.display()
    );
    let scratch: PathBuf = PathBuf::from("../../target/py-construct-metric/async-comp-gapb");
    std::fs::create_dir_all(&scratch).expect("create scratch dir");
    let pyc: PathBuf = scratch.join("async_comp_for_dict.3.14.pyc");
    compile_3_14(&interpreter, &source_path, &pyc);

    let bytes: Vec<u8> = std::fs::read(&pyc).expect("read pyc");
    let parsed: disrobe_py_marshal::PycFile = read_pyc(&bytes).expect("read_pyc");
    let version: MarshalVersion = parsed.header.version;
    let code: CodeObject = match parsed.code {
        Object::Code(boxed) => *boxed,
        other => panic!("top-level not code: {other:?}"),
    };
    let decompile_version: PyVersion = marshal_to_decompile(version).expect("version map");
    let source: String = build_real_source(&code, &decompile_version, version)
        .expect("decompile async_comp_for_dict");
    assert!(
        source.contains("async for x in ait(xs)"),
        "recovered source must carry the async-for clause; got:\n{source}"
    );
    assert!(
        source.contains("await g(x)"),
        "recovered source must carry the inner await; got:\n{source}"
    );
    assert!(
        !source.contains("__DR_CODE_CONST_"),
        "recovered source must not leak a code-const wrapper; got:\n{source}"
    );
    let body: &str = source
        .split_once("return")
        .map_or("", |(_, tail): (&str, &str)| tail.trim());
    assert!(
        !body.is_empty(),
        "recovered comprehension body must be non-empty; got:\n{source}"
    );
}
