#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_py_decompile::bytecode::version::PyVersion as DecompileVersion;
use disrobe_pass_py_decompile::engine::{build_real_source, marshal_to_decompile};
use disrobe_pass_py_decompile::roundtrip::{
    NormToken, NormalizedOp, Verdict, normalize_sequence, semantic_equiv,
};
use disrobe_py_marshal::{CodeObject, Object, PyVersion, PycFile, read_pyc};

const CLOSE_STDIN: &str = r#"
import sys
import os

def _close_stdin():
    if sys.stdin is None:
        return
    try:
        sys.stdin.close()
    except (OSError, ValueError):
        pass
    try:
        fd = os.open(os.devnull, os.O_RDONLY)
        try:
            sys.stdin = open(fd, encoding="utf-8", closefd=False)
        except:
            os.close(fd)
            raise
    except (OSError, ValueError):
        pass
"#;

const GUARD_TRY: &str = r"
import os

def guard_try(handle):
    if handle is None:
        return
    try:
        os.close(handle)
    except (KeyError, IndexError):
        pass
";

const TRY_TAIL_RETURN: &str = r"
def try_tail_return(a, b, step, recover):
    try:
        step(a)
        step(b)
    except ValueError:
        recover()
    return a
";

fn find_python_314() -> Option<PathBuf> {
    let direct: std::io::Result<std::process::Output> = Command::new("py")
        .args(["-3.14", "-c", "import sys;print(sys.version_info.minor)"])
        .stdin(Stdio::null())
        .output();
    if let Ok(out) = direct
        && out.status.success()
        && String::from_utf8_lossy(&out.stdout).trim() == "14"
    {
        return Some(PathBuf::from("py"));
    }
    if let Ok(out) = Command::new("uv")
        .args(["python", "find", "3.14"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        && out.status.success()
    {
        let raw: String = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        let path: PathBuf = PathBuf::from(raw);
        if path.is_file() {
            return Some(path);
        }
    }
    None
}

fn run_py(interpreter: &Path, args: &[&str]) -> std::process::Output {
    if interpreter == Path::new("py") {
        let mut full: Vec<&str> = vec!["-3.14"];
        full.extend_from_slice(args);
        Command::new("py")
            .args(&full)
            .stdin(Stdio::null())
            .output()
            .expect("spawn py")
    } else {
        Command::new(interpreter)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .expect("spawn interpreter")
    }
}

fn compile_to_pyc(interpreter: &Path, src: &Path, pyc: &Path) {
    let script: &str =
        "import py_compile,sys;py_compile.compile(sys.argv[1],cfile=sys.argv[2],doraise=True)";
    let out: std::process::Output = run_py(
        interpreter,
        &["-c", script, src.to_str().unwrap(), pyc.to_str().unwrap()],
    );
    assert!(
        out.status.success(),
        "compile failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn read_top(pyc: &Path) -> (CodeObject, PyVersion) {
    let bytes: Vec<u8> = std::fs::read(pyc).unwrap();
    let parsed: PycFile = read_pyc(&bytes).unwrap();
    let ver: PyVersion = parsed.header.version;
    match parsed.code {
        Object::Code(boxed) => (*boxed, ver),
        other => panic!("top-level not code: {other:?}"),
    }
}

fn find_child<'a>(code: &'a CodeObject, name: &str) -> Option<&'a CodeObject> {
    for k in &code.consts {
        if let Object::Code(boxed) = k {
            let child: &CodeObject = boxed.as_ref();
            let short: &str = match &child.name {
                Object::String { value, .. }
                | Object::Unicode { value, .. }
                | Object::ShortAscii { value, .. } => value.as_str(),
                _ => "",
            };
            if short == name {
                return Some(child);
            }
            if let Some(found) = find_child(child, name) {
                return Some(found);
            }
        }
    }
    None
}

fn decompile_recompile_equiv(interpreter: &Path, tmp: &Path, tag: &str, source: &str, func: &str) {
    let src: PathBuf = tmp.join(format!("{tag}.py"));
    let orig_pyc: PathBuf = tmp.join(format!("{tag}.orig.pyc"));
    std::fs::write(&src, source).unwrap();
    compile_to_pyc(interpreter, &src, &orig_pyc);
    let (original, marshal_version): (CodeObject, PyVersion) = read_top(&orig_pyc);
    let decompile_version: DecompileVersion =
        marshal_to_decompile(marshal_version).expect("version map");
    let recovered: String = build_real_source(&original, &decompile_version, marshal_version)
        .unwrap_or_else(|e| panic!("{tag}: decompile failed: {e}"));
    let dec_src: PathBuf = tmp.join(format!("{tag}.dec.py"));
    let dec_pyc: PathBuf = tmp.join(format!("{tag}.dec.pyc"));
    std::fs::write(&dec_src, &recovered).unwrap();
    compile_to_pyc(interpreter, &dec_src, &dec_pyc);
    let (recompiled, _): (CodeObject, PyVersion) = read_top(&dec_pyc);
    let original_fn: &CodeObject =
        find_child(&original, func).unwrap_or_else(|| panic!("{tag}: original {func} missing"));
    let recompiled_fn: &CodeObject =
        find_child(&recompiled, func).unwrap_or_else(|| panic!("{tag}: recompiled {func} missing"));
    let verdict: Verdict = semantic_equiv(original_fn, recompiled_fn, marshal_version);
    assert!(
        matches!(verdict, Verdict::Perfect | Verdict::Semantic),
        "{tag}: {func} did not recompile-equivalent: {verdict:?}\n--- recovered ---\n{recovered}"
    );
}

const fn op_name(op: &NormalizedOp) -> &str {
    match &op.token {
        NormToken::Op(n) => n.as_str(),
        NormToken::JRetLeaf => "JRET",
        NormToken::RetBlock => "RETBLK",
    }
}

#[test]
fn close_stdin_forward_jumps_land_on_try_body_entry() {
    let Some(interpreter): Option<PathBuf> = find_python_314() else {
        eprintln!("skip: no CPython 3.14 interpreter found");
        return;
    };
    let scratch: ScratchDir = ScratchDir::create("py-decompile-try-region-shape").expect("scratch");
    let tmp: &Path = scratch.path();

    let src: PathBuf = tmp.join("close_stdin.py");
    let pyc: PathBuf = tmp.join("close_stdin.orig.pyc");
    std::fs::write(&src, CLOSE_STDIN).unwrap();
    compile_to_pyc(&interpreter, &src, &pyc);
    let (top, ver): (CodeObject, PyVersion) = read_top(&pyc);
    let fun: &CodeObject = find_child(&top, "_close_stdin").expect("_close_stdin");
    let seq = normalize_sequence(fun, ver);

    assert_eq!(seq.ops.len(), 68, "normalized op count");
    let forward: [(usize, &str, u32); 3] = [
        (2, "JUMP_IF_NOT_NONE", 6),
        (33, "JUMP_IF_FALSE", 40),
        (59, "JUMP_IF_FALSE", 67),
    ];
    for (idx, name, target) in forward {
        let op: &NormalizedOp = &seq.ops[idx];
        assert_eq!(op_name(op), name, "op {idx} name");
        assert_eq!(
            op.jump_target_index,
            Some(target),
            "op {idx} forward jump into try must resolve to the try-body entry, not the preceding op"
        );
    }
}

#[test]
fn try_region_functions_recompile_equivalent() {
    let Some(interpreter): Option<PathBuf> = find_python_314() else {
        eprintln!("skip: no CPython 3.14 interpreter found");
        return;
    };
    let scratch: ScratchDir = ScratchDir::create("py-decompile-try-region-equiv").expect("scratch");
    let tmp: &Path = scratch.path();
    decompile_recompile_equiv(
        &interpreter,
        tmp,
        "close_stdin",
        CLOSE_STDIN,
        "_close_stdin",
    );
    decompile_recompile_equiv(&interpreter, tmp, "guard_try", GUARD_TRY, "guard_try");
    decompile_recompile_equiv(
        &interpreter,
        tmp,
        "try_tail_return",
        TRY_TAIL_RETURN,
        "try_tail_return",
    );
}
