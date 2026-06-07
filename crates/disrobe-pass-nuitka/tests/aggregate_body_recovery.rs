#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic, clippy::print_stdout)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_pass_nuitka::{
    CModuleStructure, ConstantsPool, LiftFidelity, SurfaceFunction, SurfaceModule, build_surface,
    decode_const_file, emit_python, parse_c_module,
};

const MODULE_HELLO_C: &str =
    include_str!("../../../corpus/python/nuitka/module/hello.build/module.hello.c");
const MODULE_HELLO_CONST: &[u8] =
    include_bytes!("../../../corpus/python/nuitka/module/hello.build/module.hello.const");
const MAIN_CONST: &[u8] = include_bytes!(
    "../../../corpus/python/nuitka/console-disable/hello.build/module.__main__.const"
);

#[derive(Debug, Clone)]
struct BodyCensus {
    program: &'static str,
    module_name: String,
    recovered: usize,
    total: usize,
}

impl BodyCensus {
    fn from_surface(program: &'static str, surface: &SurfaceModule) -> Self {
        let total: usize = surface.functions.len();
        let recovered: usize = surface
            .functions
            .iter()
            .filter(|f: &&SurfaceFunction| {
                f.body_recovered && matches!(f.lift_fidelity, LiftFidelity::FullBody)
            })
            .count();
        Self {
            program,
            module_name: surface.module_name.clone(),
            recovered,
            total,
        }
    }
}

fn corpus(parts: &[&str]) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    for part in parts {
        p.push(part);
    }
    p
}

fn build_from_committed(
    c_src: &str,
    const_bytes: &[u8],
    const_file: &str,
    blob_name: &str,
) -> SurfaceModule {
    let cmod: CModuleStructure = parse_c_module(c_src).expect("parse committed c module");
    let pool: ConstantsPool =
        decode_const_file(const_bytes, const_file, blob_name).expect("decode committed const blob");
    build_surface(&cmod, &pool, Some(c_src)).expect("build surface from committed c")
}

fn build_main_from_runtime_path() -> Option<SurfaceModule> {
    let c_path: PathBuf = corpus(&[
        "python",
        "nuitka",
        "onefile",
        "hello.build",
        "module.__main__.c",
    ]);
    let Ok(c_src): Result<String, std::io::Error> = std::fs::read_to_string(&c_path) else {
        eprintln!(
            "skip: __main__.c local-only fixture absent at {} (gitignored; expected absent in CI)",
            c_path.display()
        );
        return None;
    };
    let cmod: CModuleStructure = parse_c_module(&c_src).expect("parse __main__.c");
    assert_eq!(
        cmod.module_name, "__main__",
        "module.__main__.c must derive module_name `__main__`"
    );
    let pool: ConstantsPool = decode_const_file(MAIN_CONST, "module.__main__.const", "__main__")
        .expect("decode __main__ const blob");
    Some(build_surface(&cmod, &pool, Some(&c_src)).expect("build surface from __main__.c"))
}

#[test]
fn aggregate_body_recovery_spans_all_distinct_corpus_c_bodies() {
    let mut census: Vec<BodyCensus> = Vec::new();

    let hello: SurfaceModule = build_from_committed(
        MODULE_HELLO_C,
        MODULE_HELLO_CONST,
        "module.hello.const",
        "hello",
    );
    assert_eq!(hello.module_name, "hello");
    census.push(BodyCensus::from_surface("module/hello.c", &hello));

    if let Some(main_surface) = build_main_from_runtime_path() {
        census.push(BodyCensus::from_surface(
            "onefile/__main__.c",
            &main_surface,
        ));
    }

    let total: usize = census.iter().map(|c: &BodyCensus| c.total).sum();
    let recovered: usize = census.iter().map(|c: &BodyCensus| c.recovered).sum();

    for c in &census {
        println!(
            "AGGREGATE program={} module={} body_recovered={}/{}",
            c.program, c.module_name, c.recovered, c.total
        );
    }
    let pct: f64 = if total == 0 {
        0.0
    } else {
        (recovered as f64) * 100.0 / (total as f64)
    };
    println!("AGGREGATE TOTAL body_recovered={recovered}/{total} ({pct:.2}%)");

    assert_eq!(
        hello.functions.len(),
        3,
        "module/hello.c must expose greet/fib/main"
    );
    let hello_census: &BodyCensus = census
        .iter()
        .find(|c: &&BodyCensus| c.program == "module/hello.c")
        .expect("hello census present");
    assert_eq!(
        hello_census.recovered, 3,
        "module/hello.c must recover all 3 bodies (regression floor)"
    );

    if let Some(main_census) = census
        .iter()
        .find(|c: &&BodyCensus| c.program == "onefile/__main__.c")
    {
        assert_eq!(
            main_census.total, 3,
            "onefile/__main__.c must expose greet/fib/main"
        );
        assert_eq!(
            main_census.recovered, 3,
            "onefile/__main__.c must recover all 3 bodies to FullBody"
        );
        assert_eq!(
            recovered, 6,
            "with both distinct C bodies present, aggregate must be 6/6"
        );
        assert_eq!(total, 6, "two distinct programs contribute 6 functions");
    } else {
        assert_eq!(
            recovered, 3,
            "committed-only aggregate (CI) must be 3/3 from module/hello.c"
        );
        assert_eq!(total, 3);
    }
}

fn locate_python_314() -> Option<String> {
    let candidates: [(&str, &[&str]); 3] = [
        ("py", &["-3.14", "--version"]),
        ("python3.14", &["--version"]),
        ("python", &["--version"]),
    ];
    for (cmd, args) in candidates {
        let Ok(output): Result<Output, std::io::Error> = Command::new(cmd).args(args).output()
        else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let banner: String = String::from_utf8_lossy(&output.stdout).into_owned()
            + &String::from_utf8_lossy(&output.stderr);
        if banner.contains("3.14") || banner.contains("3.15") {
            return Some(cmd.to_owned());
        }
    }
    None
}

fn run_python_with_file(py: &str, code: &str, file: &Path) -> Output {
    let mut cmd: Command = Command::new(py);
    if py == "py" {
        cmd.arg("-3.14");
    }
    cmd.args(["-c", code, &file.to_string_lossy()]);
    cmd.output().expect("spawn cpython 3.14")
}

#[test]
fn lifted_main_bodies_behave_correctly_on_cpython_314() {
    let Some(main_surface): Option<SurfaceModule> = build_main_from_runtime_path() else {
        return;
    };
    let Some(py): Option<String> = locate_python_314() else {
        eprintln!("skip: no python3.14 on PATH");
        return;
    };

    let source: String = emit_python(&main_surface);

    let dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe-nuitka-main-body-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let file: PathBuf = dir.join("recovered_main.py");
    std::fs::write(&file, source.as_bytes()).expect("write recovered_main.py");

    let compile_out: Output = run_python_with_file(
        &py,
        "import sys; src=open(sys.argv[1], encoding='utf-8').read(); \
         compile(src, sys.argv[1], 'exec')",
        &file,
    );
    assert!(
        compile_out.status.success(),
        "recovered __main__ must compile on CPython 3.14: {}",
        String::from_utf8_lossy(&compile_out.stderr)
    );

    let probe_code: &str = r"
import importlib.util, sys, io, contextlib, ast

spec = importlib.util.spec_from_file_location('recovered_main', sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    ret = mod.main()
out = buf.getvalue().strip().splitlines()

def fib_ref(n):
    if n < 2:
        return n
    a, b = 0, 1
    for _ in range(n - 1):
        a, b = b, a + b
    return b

assert mod.greet('disrobe') == 'hello, disrobe', mod.greet('disrobe')
assert mod.fib(10) == fib_ref(10), mod.fib(10)
assert mod.fib(20) == fib_ref(20), mod.fib(20)
assert ret == 0, ret
assert out == ['hello, disrobe', str(fib_ref(20))], out

tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
fns = {f.name: f for f in tree.body if isinstance(f, ast.FunctionDef)}
assert set(fns) == {'greet', 'fib', 'main'}, sorted(fns)
fib_body = fns['fib'].body
assert any(isinstance(n, ast.If) for n in fib_body), 'fib must have if'
assert any(isinstance(n, ast.For) for n in fib_body), 'fib must have for'
assert not (len(fib_body) == 1 and isinstance(fib_body[0], ast.Expr)
            and isinstance(fib_body[0].value, ast.Constant)), 'fib must not be a stub'
print('MAIN_BODY_OK')
";

    let probe_out: Output = run_python_with_file(&py, probe_code.trim(), &file);
    assert!(
        probe_out.status.success(),
        "recovered __main__ behavioral oracle failed: {}",
        String::from_utf8_lossy(&probe_out.stderr)
    );
    let stdout: String = String::from_utf8_lossy(&probe_out.stdout).into_owned();
    assert!(
        stdout.contains("MAIN_BODY_OK"),
        "behavioral oracle did not confirm: {stdout}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
