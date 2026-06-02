#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::process::Command;

use disrobe_pass_nuitka::{
    CModuleStructure, SurfaceModule, build_surface, decode_const_file, emit_python, parse_c_module,
};

const C_SRC: &str = include_str!("../../../corpus/python/nuitka/module/hello.build/module.hello.c");
const CONST: &[u8] =
    include_bytes!("../../../corpus/python/nuitka/module/hello.build/module.hello.const");
const PYI: &str = include_str!("../../../corpus/python/nuitka/module/hello.pyi");

fn build() -> SurfaceModule {
    let cmod: CModuleStructure = parse_c_module(C_SRC).expect("parse c");
    let pool = decode_const_file(CONST, "module.hello.const", "hello").expect("decode const");
    build_surface(&cmod, &pool, Some(C_SRC)).expect("build surface")
}

#[test]
fn c_structure_matches_real_bytes() {
    let cmod: CModuleStructure = parse_c_module(C_SRC).expect("parse c");
    assert_eq!(cmod.module_name, "hello");
    assert_eq!(cmod.impl_bodies.len(), 3);
    assert!(cmod.has_main_guard, "real bytes carry a __main__ guard");
}

#[test]
fn surface_recovers_signatures_from_real_bytes() {
    let s: SurfaceModule = build();
    let names: Vec<&str> = s.functions.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, vec!["greet", "fib", "main"]);

    let greet = &s.functions[0];
    assert_eq!(greet.params.len(), 1);
    assert_eq!(greet.params[0].name, "name");
    assert_eq!(greet.params[0].annotation.as_deref(), Some("str"));
    assert_eq!(greet.return_annotation.as_deref(), Some("str"));

    let fib = &s.functions[1];
    assert_eq!(fib.params[0].name, "n");
    assert_eq!(fib.params[0].annotation.as_deref(), Some("int"));
    assert_eq!(fib.return_annotation.as_deref(), Some("int"));

    let main = &s.functions[2];
    assert!(main.params.is_empty());
    assert_eq!(main.return_annotation.as_deref(), Some("int"));

    for f in &s.functions {
        assert!(f.docstring.is_none());
        for p in &f.params {
            assert!(p.default.is_none());
        }
    }
}

fn signature_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| l.starts_with("def ") && l.ends_with(':'))
        .map(|l| l.split_whitespace().collect::<Vec<&str>>().join(" "))
        .collect()
}

#[test]
fn emitted_signatures_equal_pyi_signatures() {
    let s: SurfaceModule = build();
    let emitted: Vec<String> = signature_lines(&emit_python(&s));
    let expected: Vec<String> = signature_lines(PYI);
    assert_eq!(emitted, expected, "emitted defs must equal .pyi defs");
}

fn locate_python_314() -> Option<String> {
    let candidates: [(&str, &[&str]); 3] = [
        ("py", &["-3.14", "--version"]),
        ("python3.14", &["--version"]),
        ("python", &["--version"]),
    ];
    for (cmd, args) in candidates {
        let Ok(output) = Command::new(cmd).args(args).output() else {
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

fn run_python(py: &str, code: &str, file: &std::path::Path) -> std::process::Output {
    let mut cmd: Command = Command::new(py);
    if py == "py" {
        cmd.arg("-3.14");
    }
    cmd.args(["-c", code, &file.to_string_lossy()]);
    cmd.output().expect("spawn python")
}

#[test]
fn emitted_python_compiles_and_parses_on_cpython_314() {
    let Some(py): Option<String> = locate_python_314() else {
        eprintln!("skip: no python3.14");
        return;
    };
    let s: SurfaceModule = build();
    let source: String = emit_python(&s);

    let dir: std::path::PathBuf =
        std::env::temp_dir().join(format!("disrobe-surface-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let file: std::path::PathBuf = dir.join("recovered_hello.py");
    std::fs::write(&file, source.as_bytes()).expect("write temp py");

    let compile_out: std::process::Output = run_python(
        &py,
        "import sys; compile(open(sys.argv[1]).read(), sys.argv[1], 'exec')",
        &file,
    );
    assert!(
        compile_out.status.success(),
        "compile failed: {}",
        String::from_utf8_lossy(&compile_out.stderr)
    );

    let ast_out: std::process::Output = run_python(
        &py,
        "import ast,sys; m=ast.parse(open(sys.argv[1]).read()); \
         fns={f.name:f for f in m.body if isinstance(f,ast.FunctionDef)}; \
         assert set(fns)=={'greet','fib','main'}, fns.keys(); \
         assert fns['greet'].args.args[0].annotation.id=='str'; \
         assert fns['fib'].returns.id=='int'; \
         assert fns['main'].returns.id=='int'",
        &file,
    );
    assert!(
        ast_out.status.success(),
        "ast gate failed: {}",
        String::from_utf8_lossy(&ast_out.stderr)
    );

    let _ = std::fs::remove_dir_all(&dir);
}
