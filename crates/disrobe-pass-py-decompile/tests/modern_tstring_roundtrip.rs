#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_py_decompile::ast::node::{ConstValue, Expr, FormatConversion, TStrItem};
use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::codegen::tstring_emit::emit_tstring;
use disrobe_pass_py_decompile::engine::{NativeDecompile, decompile_pyc};
use disrobe_pass_py_decompile::roundtrip::{Verdict, semantic_equiv};
use disrobe_py_marshal::{
    CodeObject, Object, PyVersion as MarshalVersion, PycFile, pyversion_from_magic, read_pyc,
};

const CASES_DIR: &str = "../../corpus/python/decompile/construct/cases";

const TSTRING_FIXTURES: &[&str] = &[
    "tstr_plain",
    "tstr_literal_only",
    "tstr_multi",
    "tstr_conv_s",
    "tstr_conv_r",
    "tstr_conv_a",
    "tstr_spec_simple",
    "tstr_spec_nested",
    "tstr_conv_and_spec",
    "tstr_empty_spec",
    "tstr_escaped_braces",
    "tstr_empty",
    "tstr_nested_tstring",
    "tstr_nested_fstring",
    "tstr_complex_expr",
    "tstr_debug_eq",
    "tstr_adjacent",
    "tstr_conv_nested_spec",
    "tstr_spec_strlit",
];

fn find_interpreter(alias: &str) -> Option<PathBuf> {
    let output: std::process::Output = Command::new("uv")
        .args(["python", "find", alias])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

fn compile_source(interpreter: &Path, source: &Path, pyc: &Path) -> Result<(), String> {
    let script: String = format!(
        "import py_compile; py_compile.compile(r'{}', cfile=r'{}', doraise=True)",
        source.display(),
        pyc.display()
    );
    let output: std::process::Output = Command::new(interpreter)
        .args(["-c", &script])
        .output()
        .map_err(|e: std::io::Error| e.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}

fn read_code(pyc: &Path) -> Result<(CodeObject, MarshalVersion), String> {
    let bytes: Vec<u8> = std::fs::read(pyc).map_err(|e: std::io::Error| e.to_string())?;
    let parsed: PycFile = read_pyc(&bytes).map_err(|e| format!("{e:?}"))?;
    let version: MarshalVersion = pyversion_from_magic(parsed.header.magic)
        .ok_or_else(|| format!("unknown magic 0x{:08x}", parsed.header.magic))?;
    match parsed.code {
        Object::Code(boxed) => Ok((*boxed, version)),
        other => Err(format!("top-level not code: {other:?}")),
    }
}

fn fixture_path(basename: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(CASES_DIR)
        .join(format!("{basename}.py"))
}

fn assert_case_spelling(basename: &str, source: &str) {
    match basename {
        "tstr_debug_eq" => assert!(
            source.contains("x={x!r}"),
            "debug_eq must lower to canonical x={{x!r}}:\n{source}"
        ),
        "tstr_adjacent" => assert_eq!(
            source.matches("t\"").count(),
            1,
            "adjacent literals must merge into a single t-string:\n{source}"
        ),
        "tstr_empty_spec" => assert!(
            source.contains("!r:}"),
            "empty-spec trailing colon must survive:\n{source}"
        ),
        "tstr_empty" => assert!(
            source.contains("t\"\""),
            "empty template must render t\"\":\n{source}"
        ),
        "tstr_escaped_braces" => assert!(
            source.contains("{{lit}}"),
            "escaped braces must re-double:\n{source}"
        ),
        "tstr_nested_tstring" => assert!(
            source.contains("t'in {y}'"),
            "nested t-string must replay verbatim single-quote spelling:\n{source}"
        ),
        "tstr_nested_fstring" => assert!(
            source.contains("f'in {y}'"),
            "nested f-string must replay verbatim single-quote spelling:\n{source}"
        ),
        _ => {}
    }
}

fn run_roundtrip_matrix(interp: &Path, tag: &str) {
    let tmp: PathBuf = env::temp_dir().join(format!("disrobe_tstr_rt_{tag}"));
    std::fs::create_dir_all(&tmp).expect("mk tmp");

    for basename in TSTRING_FIXTURES {
        let src_path: PathBuf = fixture_path(basename);
        let pyc: PathBuf = tmp.join(format!("{basename}.pyc"));
        compile_source(interp, &src_path, &pyc)
            .unwrap_or_else(|e: String| panic!("[{tag}] compile {basename}: {e}"));

        let bytes: Vec<u8> = std::fs::read(&pyc).expect("read pyc");
        let decoded: NativeDecompile =
            decompile_pyc(&bytes).unwrap_or_else(|e| panic!("[{tag}] decompile {basename}: {e}"));
        assert!(
            decoded.recovered_directly,
            "[{tag}] {basename}: fell back to disasm: {:?}\n{}",
            decoded.fallback_reason, decoded.source
        );
        assert!(
            !decoded.source.is_empty(),
            "[{tag}] {basename}: empty recovered source"
        );
        assert!(
            decoded.source.contains("t\""),
            "[{tag}] {basename}: recovered source has no t-string:\n{}",
            decoded.source
        );
        assert_case_spelling(basename, &decoded.source);

        let rt_py: PathBuf = tmp.join(format!("{basename}_rt.py"));
        let rt_pyc: PathBuf = tmp.join(format!("{basename}_rt.pyc"));
        std::fs::write(&rt_py, &decoded.source).expect("write rt py");
        compile_source(interp, &rt_py, &rt_pyc).unwrap_or_else(|e: String| {
            panic!(
                "[{tag}] recompile {basename}: {e}\nsource:\n{}",
                decoded.source
            )
        });

        let (orig, ver): (CodeObject, MarshalVersion) = read_code(&pyc).expect("read orig code");
        let (rt, _): (CodeObject, MarshalVersion) = read_code(&rt_pyc).expect("read rt code");
        let verdict: Verdict = semantic_equiv(&orig, &rt, ver);
        assert!(
            matches!(verdict, Verdict::Perfect | Verdict::Semantic),
            "[{tag}] {basename}: not semantically equivalent: {verdict:?}\nsource:\n{}",
            decoded.source
        );
    }
}

#[test]
fn tstring_roundtrip_3_14() {
    let Some(interp): Option<PathBuf> = find_interpreter("3.14") else {
        eprintln!("skip tstring_roundtrip_3_14: no 3.14 interpreter");
        return;
    };
    run_roundtrip_matrix(&interp, "3.14");
}

#[test]
fn tstring_roundtrip_3_15() {
    let Some(interp): Option<PathBuf> = find_interpreter("3.15") else {
        eprintln!("skip tstring_roundtrip_3_15: 3.15 interpreter unavailable (structural-only)");
        return;
    };
    run_roundtrip_matrix(&interp, "3.15");
}

#[test]
fn tstring_3_15_structural() {
    let ver: PyVersion = PyVersion::V3_15;
    assert!(ver.supports_tstring(), "3.15 must enable t-strings");
    assert_eq!(
        ver.pyc_magic() & 0xFFFF,
        3666,
        "3.15 pyc magic16 must be 3666"
    );
    assert_eq!(
        disrobe_pass_py_disasm::opname(43, MarshalVersion::PY315),
        "BUILD_INTERPOLATION"
    );
    assert_eq!(
        disrobe_pass_py_disasm::opname(2, MarshalVersion::PY315),
        "BUILD_TEMPLATE"
    );
    assert_eq!(
        disrobe_pass_py_disasm::opname(81, MarshalVersion::PY315),
        "LOAD_CONST"
    );
    assert_eq!(
        disrobe_pass_py_disasm::opname(255, MarshalVersion::PY315),
        "TRACE_RECORD"
    );

    let items: Vec<TStrItem> = vec![
        TStrItem::Literal("a ".to_owned()),
        TStrItem::Interp {
            value: Expr::Name {
                id: "x".to_owned(),
                ctx: disrobe_pass_py_decompile::ast::node::ExprCtx::Load,
                line: None,
            },
            expr_text: None,
            conversion: FormatConversion::Repr,
            format_spec: Some(Expr::Constant {
                value: ConstValue::Str(String::new()),
                line: None,
            }),
        },
    ];
    let rendered: String = emit_tstring(&items, &ver);
    assert!(
        rendered.starts_with("t\""),
        "3.15 emitter must produce a t-string: {rendered}"
    );
    assert!(
        rendered.contains("{x!r:}"),
        "empty-spec must survive in emit: {rendered}"
    );
}
