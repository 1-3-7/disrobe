#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use disrobe_pass_nuitka::{
    CModuleStructure, SurfaceFunction, SurfaceModule, build_surface_with_python_abi,
    decode_const_file, emit_python, parse_c_module_with_python_abi,
};

const FIXTURE_PYTHON_ABI: (u8, u8) = (3u8, 12u8);

fn module_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("python")
        .join("nuitka")
        .join("module")
}

fn build_module(name: &str) -> SurfaceModule {
    let dir: PathBuf = module_dir();
    let c_src: String = std::fs::read_to_string(dir.join(format!("{name}.build/module.{name}.c")))
        .unwrap_or_else(|e| panic!("read module.{name}.c: {e}"));
    let const_bytes: Vec<u8> = std::fs::read(dir.join(format!("{name}.build/module.{name}.const")))
        .unwrap_or_else(|e| panic!("read module.{name}.const: {e}"));
    let cmod: CModuleStructure = parse_c_module_with_python_abi(&c_src, FIXTURE_PYTHON_ABI)
        .unwrap_or_else(|e| panic!("parse {name}: {e}"));
    let pool = decode_const_file(&const_bytes, &format!("module.{name}.const"), name)
        .unwrap_or_else(|e| panic!("decode {name} const: {e}"));
    build_surface_with_python_abi(&cmod, &pool, Some(&c_src), FIXTURE_PYTHON_ABI)
        .unwrap_or_else(|e| panic!("surface {name}: {e}"))
}

fn find<'a>(funcs: &'a [SurfaceFunction], name: &str) -> &'a SurfaceFunction {
    funcs
        .iter()
        .find(|f: &&SurfaceFunction| f.name == name)
        .unwrap_or_else(|| panic!("function `{name}` not in {:?}", names(funcs)))
}

fn names(funcs: &[SurfaceFunction]) -> Vec<String> {
    funcs
        .iter()
        .map(|f: &SurfaceFunction| f.name.clone())
        .collect()
}

#[test]
fn shared_annotation_dict_reaches_every_sibling() {
    let m: SurfaceModule = build_module("arith");
    for fname in ["add", "sub", "mul"] {
        let f: &SurfaceFunction = find(&m.functions, fname);
        assert_eq!(
            f.params.len(),
            2,
            "`{fname}` must keep both params; got {:?}",
            f.params
        );
        for p in &f.params {
            assert_eq!(
                p.annotation.as_deref(),
                Some("int"),
                "`{fname}::{}` lost its `int` annotation; a shared annotation dict must reach every sibling, not just the first",
                p.name
            );
        }
        assert_eq!(
            f.return_annotation.as_deref(),
            Some("int"),
            "`{fname}` lost its return annotation"
        );
    }
}

#[test]
fn distinct_dicts_with_same_keyset_stay_distinct() {
    let m: SurfaceModule = build_module("advanced");
    let comp: &SurfaceFunction = find(&m.functions, "comp");
    let dict_comp: &SurfaceFunction = find(&m.functions, "dict_comp");
    assert_eq!(comp.return_annotation.as_deref(), Some("list"));
    assert_eq!(
        dict_comp.return_annotation.as_deref(),
        Some("dict"),
        "comp and dict_comp share the `{{n, return}}` key set but carry distinct return types; they must not collapse onto one dict"
    );
}

#[test]
fn nested_function_is_emitted_inside_its_parent() {
    let m: SurfaceModule = build_module("advanced");
    assert!(
        !names(&m.functions).contains(&"inner".to_owned()),
        "`inner` is nested inside `closure`; it must not appear at module top level: {:?}",
        names(&m.functions)
    );
    let closure: &SurfaceFunction = find(&m.functions, "closure");
    assert_eq!(
        closure.params.len(),
        1,
        "closure's cell-wrapped parameter `n` must still be recovered"
    );
    assert_eq!(closure.params[0].name, "n");
    assert_eq!(closure.params[0].annotation.as_deref(), Some("int"));
    assert_eq!(closure.return_annotation.as_deref(), Some("int"));

    let inner: &SurfaceFunction = find(&closure.nested, "inner");
    assert_eq!(inner.params.len(), 1);
    assert_eq!(inner.params[0].name, "x");
    assert_eq!(inner.params[0].annotation.as_deref(), Some("int"));
    assert_eq!(inner.return_annotation.as_deref(), Some("int"));

    let py: String = emit_python(&m);
    assert!(
        py.contains("def closure(n: int) -> int:"),
        "emitted closure signature wrong:\n{py}"
    );
    assert!(
        py.contains("    def inner(x: int) -> int:"),
        "nested `inner` must be indented one level inside `closure`:\n{py}"
    );
}

fn pyi_signature_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l: &&str| l.starts_with("def ") && l.ends_with(':'))
        .map(|l: &str| l.split_whitespace().collect::<Vec<&str>>().join(" "))
        .collect()
}

fn strip_param_defaults(signature: &str) -> String {
    let mut out: String = String::with_capacity(signature.len());
    let mut depth: i32 = 0i32;
    let mut chars: std::iter::Peekable<std::str::Chars<'_>> = signature.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '(' | '[' | '{' => {
                depth += 1;
                out.push(c);
            }
            ')' | ']' | '}' => {
                depth -= 1;
                out.push(c);
            }
            '=' if depth == 1 && chars.peek() != Some(&'=') => {
                while let Some(&next) = chars.peek() {
                    if matches!(next, ',' | ')') {
                        break;
                    }
                    chars.next();
                }
            }
            _ => out.push(c),
        }
    }
    out.replace(" )", ")")
        .replace(" ,", ",")
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
}

fn signature_index(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .map(str::trim)
        .filter(|l: &&str| l.starts_with("def ") && l.ends_with(':'))
        .filter_map(|l: &str| {
            let normalized: String = l.split_whitespace().collect::<Vec<&str>>().join(" ");
            let fn_name: &str = normalized
                .strip_prefix("def ")
                .and_then(|s: &str| s.split('(').next())?;
            Some((fn_name.to_owned(), normalized))
        })
        .collect()
}

#[test]
fn every_module_top_level_signature_equals_its_own_pyi() {
    let dir: PathBuf = module_dir();
    let modules: [&str; 8] = [
        "arith",
        "compares",
        "datastruct",
        "loops",
        "advanced",
        "strops",
        "multi",
        "gauntlet",
    ];
    for name in modules {
        let m: SurfaceModule = build_module(name);
        let pyi: String = std::fs::read_to_string(dir.join(format!("{name}.pyi")))
            .unwrap_or_else(|e| panic!("read {name}.pyi: {e}"));
        let expected: Vec<String> = pyi_signature_lines(&pyi);
        let emitted_full: String = emit_python(&m);
        let emitted_top: BTreeMap<String, String> = signature_index(&emitted_full)
            .into_iter()
            .filter(|(fn_name, _): &(String, String)| {
                m.functions
                    .iter()
                    .any(|f: &SurfaceFunction| &f.name == fn_name)
            })
            .collect();

        for sig in &expected {
            let fn_name: &str = sig
                .strip_prefix("def ")
                .and_then(|s: &str| s.split('(').next())
                .unwrap_or("");
            let got: &String = emitted_top
                .get(fn_name)
                .unwrap_or_else(|| panic!("{name}: no emitted signature for `{fn_name}`"));
            if got.contains('*') {
                assert!(
                    !sig.contains('*'),
                    "{name}: Nuitka's own .pyi drops star params, so `{fn_name}` should be bare in the stub"
                );
                continue;
            }
            assert_eq!(
                strip_param_defaults(got),
                strip_param_defaults(sig),
                "{name}: emitted signature for `{fn_name}` must equal the Nuitka .pyi line (defaults and star params excluded; Nuitka's own .pyi drops both)"
            );
        }
    }
}

#[test]
fn recovered_signatures_match_original_source_exactly() {
    let dir: PathBuf = module_dir();
    let modules: [&str; 8] = [
        "arith",
        "compares",
        "datastruct",
        "loops",
        "advanced",
        "strops",
        "multi",
        "gauntlet",
    ];
    for name in modules {
        let src: String = std::fs::read_to_string(dir.join(format!("{name}.src.py")))
            .unwrap_or_else(|e| panic!("read {name}.src.py: {e}"));
        let original: BTreeMap<String, String> = signature_index(&src);
        let m: SurfaceModule = build_module(name);
        let recovered: BTreeMap<String, String> = signature_index(&emit_python(&m));

        for (fn_name, orig_sig) in &original {
            let got: &String = recovered
                .get(fn_name)
                .unwrap_or_else(|| panic!("{name}: source function `{fn_name}` was not recovered"));
            assert_eq!(
                got, orig_sig,
                "{name}: recovered signature for `{fn_name}` must byte-equal the original source signature (params, annotations, defaults, varargs, return)"
            );
        }
    }
}
