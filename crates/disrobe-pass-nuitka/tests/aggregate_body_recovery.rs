#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout
)]

mod common;

use std::path::PathBuf;
use std::process::Output;

use disrobe_pass_nuitka::{
    CModuleStructure, ConstantsPool, LiftFidelity, SurfaceFunction, SurfaceModule,
    build_surface_with_python_abi, decode_const_file, emit_python, parse_c_module_with_python_abi,
};

const MODULE_HELLO_C: &str =
    include_str!("../../../corpus/python/nuitka/module/hello.build/module.hello.c");
const MODULE_HELLO_CONST: &[u8] =
    include_bytes!("../../../corpus/python/nuitka/module/hello.build/module.hello.const");
const MAIN_C: &str =
    include_str!("../../../corpus/python/nuitka/console-disable/hello.build/module.__main__.c");
const MAIN_CONST: &[u8] = include_bytes!(
    "../../../corpus/python/nuitka/console-disable/hello.build/module.__main__.const"
);
const FIXTURE_PYTHON_ABI: (u8, u8) = (3u8, 12u8);
const MAIN_PYTHON_ABI: (u8, u8) = (3u8, 14u8);

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

fn build_from_committed(
    c_src: &str,
    const_bytes: &[u8],
    const_file: &str,
    blob_name: &str,
) -> SurfaceModule {
    let cmod: CModuleStructure = parse_c_module_with_python_abi(c_src, FIXTURE_PYTHON_ABI)
        .expect("parse committed c module");
    let pool: ConstantsPool =
        decode_const_file(const_bytes, const_file, blob_name).expect("decode committed const blob");
    build_surface_with_python_abi(&cmod, &pool, Some(c_src), FIXTURE_PYTHON_ABI)
        .expect("build surface from committed c")
}

fn build_main_from_console_disable() -> SurfaceModule {
    let cmod: CModuleStructure =
        parse_c_module_with_python_abi(MAIN_C, MAIN_PYTHON_ABI).expect("parse __main__.c");
    assert_eq!(
        cmod.module_name, "__main__",
        "module.__main__.c must derive module_name `__main__`"
    );
    let pool: ConstantsPool = decode_const_file(MAIN_CONST, "module.__main__.const", "__main__")
        .expect("decode __main__ const blob");
    build_surface_with_python_abi(&cmod, &pool, Some(MAIN_C), MAIN_PYTHON_ABI)
        .expect("build surface from __main__.c")
}

#[test]
fn aggregate_body_recovery_spans_all_distinct_corpus_c_bodies() {
    let hello: SurfaceModule = build_from_committed(
        MODULE_HELLO_C,
        MODULE_HELLO_CONST,
        "module.hello.const",
        "hello",
    );
    assert_eq!(hello.module_name, "hello");
    let main_surface: SurfaceModule = build_main_from_console_disable();
    let census: [BodyCensus; 2] = [
        BodyCensus::from_surface("module/hello.c", &hello),
        BodyCensus::from_surface("console-disable/__main__.c", &main_surface),
    ];

    for c in &census {
        println!(
            "AGGREGATE program={} module={} body_recovered={}/{}",
            c.program, c.module_name, c.recovered, c.total
        );
    }
    let total: usize = census.iter().map(|c: &BodyCensus| c.total).sum();
    let recovered: usize = census.iter().map(|c: &BodyCensus| c.recovered).sum();
    println!("AGGREGATE TOTAL body_recovered={recovered}/{total}");

    let names = |surface: &SurfaceModule| -> Vec<String> {
        surface
            .functions
            .iter()
            .map(|f: &SurfaceFunction| f.name.clone())
            .collect()
    };
    assert_eq!(
        names(&hello),
        ["greet", "fib", "main"],
        "module/hello.c must expose greet/fib/main"
    );
    assert_eq!(
        names(&main_surface),
        ["greet", "fib", "main"],
        "console-disable/__main__.c must expose the greet/fib/main of the regen.ps1 source"
    );
    assert_eq!(
        (census[0].recovered, census[0].total),
        (3, 3),
        "module/hello.c must recover all 3 bodies"
    );
    assert_eq!(
        (census[1].recovered, census[1].total),
        (3, 3),
        "console-disable/__main__.c must recover all 3 bodies to FullBody"
    );
    assert_eq!((recovered, total), (6, 6), "aggregate must be 6/6");
}

#[test]
fn lifted_main_bodies_behave_like_the_regen_source_on_cpython_314() {
    let py: PathBuf = common::python314();
    let main_surface: SurfaceModule = build_main_from_console_disable();
    let source: String = emit_python(&main_surface);

    let purpose: String = format!("disrobe-nuitka-main-body-{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    let recovered: PathBuf = dir.join("recovered_main.py");
    std::fs::write(&recovered, source.as_bytes()).expect("write recovered_main.py");
    let original: PathBuf = dir.join("original_main.py");
    std::fs::write(&original, common::regen_hello_source().as_bytes())
        .expect("write original_main.py");

    let probe_code: &str = r"
import importlib.util, sys, io, contextlib, ast

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def observe(path, name):
    mod = load(name, path)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        ret = mod.main()
    tree = ast.parse(open(path, encoding='utf-8').read())
    return {
        'functions': sorted(f.name for f in tree.body if isinstance(f, ast.FunctionDef)),
        'greet': [mod.greet(v) for v in ('disrobe', '', 'x y')],
        'fib': [mod.fib(n) for n in range(0, 26)],
        'main_stdout': buf.getvalue(),
        'main_return': ret,
    }

orig = observe(sys.argv[1], 'original_main')
recov = observe(sys.argv[2], 'recovered_main')
for key in orig:
    if orig[key] != recov[key]:
        print(f'MISMATCH {key}: original={orig[key]!r} recovered={recov[key]!r}')
        sys.exit(2)
print('MAIN_BODY_OK')
";

    let probe_out: Output = common::run_python(&py, probe_code.trim(), &[&original, &recovered]);
    let stdout: String = String::from_utf8_lossy(&probe_out.stdout).into_owned();
    assert!(
        probe_out.status.success(),
        "recovered __main__ must behave like the regen.ps1 source on CPython 3.14:\nSTDOUT:\n\
         {stdout}\nSTDERR:\n{}\nRECOVERED:\n{source}",
        String::from_utf8_lossy(&probe_out.stderr)
    );
    assert_eq!(
        stdout.trim(),
        "MAIN_BODY_OK",
        "behavioral oracle output: {stdout}"
    );
}
