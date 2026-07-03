#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_pass_nuitka::{
    DecompSourceKind, ExactNuitkaVersion, NuitkaDecompilation, SurfaceFidelity, SurfaceFunction,
    SurfaceModule, VersionConfidence, decompile_build_dir, emit_python,
    parse_exact_version_from_constants_c,
};

const GAUNTLET_DIR: &str = "../../corpus/python/nuitka/module/gauntlet.build";
const ORIGINAL: &str = "../../corpus/python/nuitka/module/gauntlet.src.py";
const PYI: &str = "../../corpus/python/nuitka/module/gauntlet.pyi";

fn repo_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn present(rel: &str) -> Option<PathBuf> {
    let path: PathBuf = repo_path(rel);
    path.exists().then_some(path)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SignatureParam {
    name: String,
    annotation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Signature {
    name: String,
    params: Vec<SignatureParam>,
    return_annotation: Option<String>,
}

fn parse_def_line(def_line: &str) -> Signature {
    let trimmed: &str = def_line.trim();
    let after_def: &str = trimmed
        .strip_prefix("def ")
        .expect("def line must start with `def `");
    let open: usize = after_def.find('(').expect("signature needs `(`");
    let name: String = after_def[..open].trim().to_owned();
    let close: usize = after_def.rfind(')').expect("signature needs `)`");
    let params_blob: &str = after_def[open + 1..close].trim();

    let return_annotation: Option<String> = after_def[close + 1..]
        .trim()
        .trim_end_matches(':')
        .trim()
        .strip_prefix("->")
        .map(|r: &str| r.trim().to_owned())
        .filter(|r: &String| !r.is_empty());

    let params: Vec<SignatureParam> = if params_blob.is_empty() {
        Vec::new()
    } else {
        params_blob
            .split(',')
            .map(|raw: &str| {
                let part: &str = raw.trim();
                let stripped: &str = part.split('=').next().unwrap_or(part).trim();
                match stripped.split_once(':') {
                    Some((pname, ann)) => SignatureParam {
                        name: pname.trim().to_owned(),
                        annotation: Some(ann.trim().to_owned()),
                    },
                    None => SignatureParam {
                        name: stripped.to_owned(),
                        annotation: None,
                    },
                }
            })
            .collect()
    };

    Signature {
        name,
        params,
        return_annotation,
    }
}

fn signatures_from(source: &str) -> BTreeMap<String, Signature> {
    source
        .lines()
        .map(str::trim)
        .filter(|l: &&str| l.starts_with("def ") && l.contains('(') && l.ends_with(':'))
        .map(|l: &str| {
            let sig: Signature = parse_def_line(l);
            (sig.name.clone(), sig)
        })
        .collect()
}

fn original_source() -> String {
    std::fs::read_to_string(repo_path(ORIGINAL)).expect("read clean original gauntlet.src.py")
}

fn unquote_pep563(annotation: &str) -> String {
    let trimmed: &str = annotation.trim();
    trimmed
        .strip_prefix('\'')
        .and_then(|s: &str| s.strip_suffix('\''))
        .or_else(|| {
            trimmed
                .strip_prefix('"')
                .and_then(|s: &str| s.strip_suffix('"'))
        })
        .unwrap_or(trimmed)
        .to_owned()
}

fn normalized_annotation(annotation: Option<&str>) -> Option<String> {
    annotation.map(unquote_pep563)
}

fn pyi_source() -> String {
    std::fs::read_to_string(repo_path(PYI)).expect("read Nuitka gauntlet.pyi")
}

fn const_symbol_ground_truth() -> (BTreeSet<String>, BTreeSet<i64>) {
    let c_source: String = std::fs::read_to_string(repo_path(
        "../../corpus/python/nuitka/module/gauntlet.build/module.gauntlet.c",
    ))
    .expect("read module.gauntlet.c ground truth");
    let mut idents: BTreeSet<String> = BTreeSet::new();
    let mut ints: BTreeSet<i64> = BTreeSet::new();
    for line in c_source.lines() {
        let trimmed: &str = line.trim();
        let Some(decl) = trimmed.strip_prefix("PyObject *const_") else {
            continue;
        };
        let symbol: &str = decl.trim_end_matches(';').trim();
        if let Some(rest) = symbol.strip_prefix("str_plain_")
            && !rest.is_empty()
        {
            idents.insert(rest.to_owned());
        } else if let Some(rest) = symbol.strip_prefix("int_pos_") {
            if let Ok(n) = rest.parse::<i64>() {
                ints.insert(n);
            }
        } else if let Some(rest) = symbol.strip_prefix("int_neg_")
            && let Ok(n) = rest.parse::<i64>()
        {
            ints.insert(-n);
        }
    }
    (idents, ints)
}

fn decompile() -> NuitkaDecompilation {
    decompile_build_dir(&repo_path(GAUNTLET_DIR)).expect("decompile real Nuitka build dir")
}

const fn surface(decomp: &NuitkaDecompilation) -> &SurfaceModule {
    match decomp.surface.as_ref() {
        Some(s) => s,
        None => panic!("surface recovered from module.gauntlet.c"),
    }
}

#[test]
fn fixtures_present_and_real() {
    assert!(
        present(&format!("{GAUNTLET_DIR}/module.gauntlet.c")).is_some(),
        "real module.gauntlet.c fixture must be committed"
    );
    assert!(
        present(&format!("{GAUNTLET_DIR}/module.gauntlet.const")).is_some(),
        "real module.gauntlet.const constants blob must be committed"
    );
    assert!(
        present(&format!("{GAUNTLET_DIR}/__constants.c")).is_some(),
        "real __constants.c version stamp must be committed"
    );
    let c_source: String =
        std::fs::read_to_string(repo_path(&format!("{GAUNTLET_DIR}/module.gauntlet.c")))
            .expect("read module.gauntlet.c");
    assert!(
        c_source.contains("created by Nuitka version 4.1.1"),
        "fixture must be real Nuitka 4.1.1 output"
    );
}

#[test]
fn exact_version_is_nuitka_411_release_from_compiler_stamp() {
    let constants_c: Vec<u8> = std::fs::read(repo_path(&format!("{GAUNTLET_DIR}/__constants.c")))
        .expect("read __constants.c");
    let version: ExactNuitkaVersion = parse_exact_version_from_constants_c(&constants_c)
        .expect("exact version recoverable from compiler's own __compiled__ stamp");
    assert_eq!(version.major, 4);
    assert_eq!(version.minor, 1);
    assert_eq!(version.micro, 1);
    assert_eq!(version.release_level, "release");
}

#[test]
fn end_to_end_decompile_reports_exact_version_and_build_dir_source() {
    let decomp: NuitkaDecompilation = decompile();
    assert_eq!(decomp.source_kind, DecompSourceKind::BuildDir);
    assert_eq!(decomp.version.confidence, VersionConfidence::Exact);
    let exact: &ExactNuitkaVersion = decomp
        .version
        .exact
        .as_ref()
        .expect("exact version present end-to-end");
    assert_eq!((exact.major, exact.minor, exact.micro), (4, 1, 1));
}

#[test]
fn constants_pool_is_superset_of_compiler_const_symbols_and_original_identifiers() {
    let decomp: NuitkaDecompilation = decompile();
    let (gt_idents, gt_ints): (BTreeSet<String>, BTreeSet<i64>) = const_symbol_ground_truth();
    assert!(
        gt_idents.len() >= 8,
        "C const symbol table must yield real identifiers, got {gt_idents:?}"
    );

    let recovered_strings: &BTreeSet<String> = &decomp.constants.all_strings;
    let missing: Vec<&String> = gt_idents
        .iter()
        .filter(|id: &&String| !recovered_strings.contains(id.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "recovered constants missing compiler const symbols {missing:?}"
    );

    let recovered_ints: &BTreeSet<i64> = &decomp.constants.all_ints;
    let missing_ints: Vec<&i64> = gt_ints
        .iter()
        .filter(|n: &&i64| !recovered_ints.contains(n))
        .collect();
    assert!(
        missing_ints.is_empty(),
        "recovered ints missing compiler const ints {missing_ints:?}; have {recovered_ints:?}"
    );

    for needed in [
        "greet",
        "fib",
        "accumulate",
        "squares",
        "main",
        "BANNER",
        "SEED",
    ] {
        assert!(
            recovered_strings.contains(needed),
            "constants must carry original identifier `{needed}`; have {recovered_strings:?}"
        );
    }
    for literal in [3i64, 5, 7, 1337] {
        assert!(
            recovered_ints.contains(&literal),
            "constants must carry original int literal {literal}; have {recovered_ints:?}"
        );
    }
}

#[test]
fn recovered_surface_signatures_equal_pyi_and_original() {
    let decomp: NuitkaDecompilation = decompile();
    let surf: &SurfaceModule = surface(&decomp);
    assert_eq!(surf.fidelity, SurfaceFidelity::StructuredFromCSource);

    let pyi_sigs: BTreeMap<String, Signature> = signatures_from(&pyi_source());
    assert_eq!(
        pyi_sigs.keys().cloned().collect::<Vec<String>>(),
        vec![
            "accumulate".to_owned(),
            "fib".to_owned(),
            "greet".to_owned(),
            "main".to_owned(),
            "squares".to_owned(),
        ],
        "pyi must define exactly the five gauntlet functions"
    );

    let recovered: BTreeMap<String, &SurfaceFunction> = surf
        .functions
        .iter()
        .map(|f: &SurfaceFunction| (f.name.clone(), f))
        .collect();
    assert_eq!(
        recovered.keys().cloned().collect::<Vec<String>>(),
        pyi_sigs.keys().cloned().collect::<Vec<String>>(),
        "recovered function set must equal the pyi function set"
    );

    for (name, gt) in &pyi_sigs {
        let got: &SurfaceFunction = recovered
            .get(name)
            .unwrap_or_else(|| panic!("recovered surface missing `{name}`"));
        assert_eq!(
            got.params.len(),
            gt.params.len(),
            "param count mismatch for `{name}`"
        );
        for (rp, gp) in got.params.iter().zip(&gt.params) {
            assert_eq!(rp.name, gp.name, "param name mismatch for `{name}`");
            assert_eq!(
                normalized_annotation(rp.annotation.as_deref()),
                gp.annotation.clone(),
                "param annotation mismatch for `{name}::{}` (recovered PEP 563 string normalized)",
                gp.name
            );
        }
        assert_eq!(
            normalized_annotation(got.return_annotation.as_deref()),
            gt.return_annotation.clone(),
            "return annotation mismatch for `{name}`"
        );
    }

    let original_sigs: BTreeMap<String, Signature> = signatures_from(&original_source());
    for (name, recovered_fn) in &recovered {
        let orig: &Signature = original_sigs
            .get(name)
            .unwrap_or_else(|| panic!("original source missing `{name}`"));
        let recovered_names: Vec<String> =
            recovered_fn.params.iter().map(|p| p.name.clone()).collect();
        let original_names: Vec<String> = orig.params.iter().map(|p| p.name.clone()).collect();
        assert_eq!(
            recovered_names, original_names,
            "recovered param names must match clean original for `{name}`"
        );
        assert_eq!(
            normalized_annotation(recovered_fn.return_annotation.as_deref()),
            orig.return_annotation.clone(),
            "recovered return annotation must match clean original for `{name}`"
        );
        for (rp, op) in recovered_fn.params.iter().zip(&orig.params) {
            assert_eq!(
                normalized_annotation(rp.annotation.as_deref()),
                op.annotation.clone(),
                "recovered param annotation must match clean original for `{name}::{}`",
                op.name
            );
        }
    }
}

#[test]
fn default_value_and_annotation_recovered_for_accumulate() {
    let decomp: NuitkaDecompilation = decompile();
    let surf: &SurfaceModule = surface(&decomp);
    let accumulate: &SurfaceFunction = surf
        .functions
        .iter()
        .find(|f: &&SurfaceFunction| f.name == "accumulate")
        .expect("accumulate recovered");

    let factor: &_ = accumulate
        .params
        .iter()
        .find(|p| p.name == "factor")
        .expect("factor param recovered");
    assert_eq!(
        normalized_annotation(factor.annotation.as_deref()),
        Some("int".to_owned()),
        "factor annotation `int` recovered (PEP 563 string normalized)"
    );
    assert_eq!(
        factor.default.as_deref(),
        Some("2"),
        "the `= 2` default value is recovered from the compiled Nuitka const blob"
    );

    let values: &_ = accumulate
        .params
        .iter()
        .find(|p| p.name == "values")
        .expect("values param recovered");
    assert!(
        values.default.is_none(),
        "default-free leading param must carry no fabricated default"
    );
    assert!(
        std::fs::read_to_string(repo_path(ORIGINAL))
            .expect("read original")
            .contains("factor: int = 2"),
        "the clean original carried the `= 2` default"
    );
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

fn run_python(py: &str, code: &str, file: &Path) -> Output {
    let mut cmd: Command = Command::new(py);
    if py == "py" {
        cmd.arg("-3.14");
    }
    cmd.args(["-c", code, &file.to_string_lossy()]);
    cmd.output().expect("spawn cpython 3.14")
}

fn run_python2(py: &str, code: &str, a: &Path, b: &Path) -> Output {
    let mut cmd: Command = Command::new(py);
    if py == "py" {
        cmd.arg("-3.14");
    }
    cmd.args(["-c", code, &a.to_string_lossy(), &b.to_string_lossy()]);
    cmd.output().expect("spawn cpython 3.14")
}

#[test]
fn emitted_python_compiles_and_ast_matches_original_on_cpython_314() {
    let Some(py): Option<String> = locate_python_314() else {
        eprintln!("skip: no python3.14");
        return;
    };

    let decomp: NuitkaDecompilation = decompile();
    let source: String = emit_python(surface(&decomp));

    let dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe-nuitka-gauntlet-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let file: PathBuf = dir.join("recovered_gauntlet.py");
    std::fs::write(&file, source.as_bytes()).expect("write recovered .py");

    let compile_out: Output = run_python(
        &py,
        "import sys; src=open(sys.argv[1], encoding='utf-8').read(); \
         compile(src, sys.argv[1], 'exec')",
        &file,
    );
    assert!(
        compile_out.status.success(),
        "recovered source must compile on cpython 3.14: {}",
        String::from_utf8_lossy(&compile_out.stderr)
    );

    let ast_out: Output = run_python(
        &py,
        "import ast, sys\n\
         m = ast.parse(open(sys.argv[1], encoding='utf-8').read())\n\
         fns = {f.name: f for f in m.body if isinstance(f, ast.FunctionDef)}\n\
         def ann(node):\n\
         \x20   if node is None: return None\n\
         \x20   if isinstance(node, ast.Name): return node.id\n\
         \x20   if isinstance(node, ast.Constant): return node.value\n\
         \x20   raise AssertionError(ast.dump(node))\n\
         assert set(fns) == {'greet','fib','accumulate','squares','main'}, sorted(fns)\n\
         assert [a.arg for a in fns['greet'].args.args] == ['name']\n\
         assert ann(fns['greet'].args.args[0].annotation) == 'str'\n\
         assert ann(fns['greet'].returns) == 'str'\n\
         assert [a.arg for a in fns['fib'].args.args] == ['n']\n\
         assert ann(fns['fib'].returns) == 'int'\n\
         assert [a.arg for a in fns['accumulate'].args.args] == ['values','factor']\n\
         assert ann(fns['accumulate'].args.args[0].annotation) == 'list'\n\
         assert ann(fns['accumulate'].args.args[1].annotation) == 'int'\n\
         assert ann(fns['accumulate'].returns) == 'int'\n\
         assert ann(fns['accumulate'].args.defaults[-1]) == 2\n\
         assert [a.arg for a in fns['squares'].args.args] == ['n']\n\
         assert ann(fns['squares'].returns) == 'dict'\n\
         assert not fns['main'].args.args\n\
         assert ann(fns['main'].returns) == 'int'\n",
        &file,
    );
    assert!(
        ast_out.status.success(),
        "recovered AST must match the clean original signatures: {}",
        String::from_utf8_lossy(&ast_out.stderr)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn recovered_main_body_ast_equals_clean_original_on_cpython_314() {
    let Some(py): Option<String> = locate_python_314() else {
        eprintln!("skip: no python3.14");
        return;
    };

    let decomp: NuitkaDecompilation = decompile();
    let source: String = emit_python(surface(&decomp));

    let dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe-nuitka-mainbody-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let recovered: PathBuf = dir.join("recovered_gauntlet.py");
    std::fs::write(&recovered, source.as_bytes()).expect("write recovered .py");

    let out: Output = run_python2(
        &py,
        "import ast, sys\n\
         class StripAnn(ast.NodeTransformer):\n\
         \x20   def visit_FunctionDef(self, node):\n\
         \x20       node.returns = None\n\
         \x20       for a in node.args.args + node.args.kwonlyargs: a.annotation = None\n\
         \x20       self.generic_visit(node)\n\
         \x20       return node\n\
         \x20   def visit_AnnAssign(self, node):\n\
         \x20       if node.value is None: return node\n\
         \x20       return ast.copy_location(ast.Assign(targets=[node.target], value=node.value), node)\n\
         def body_of(path, name):\n\
         \x20   m = ast.parse(open(path, encoding='utf-8').read())\n\
         \x20   m = StripAnn().visit(m); ast.fix_missing_locations(m)\n\
         \x20   fn = next(f for f in m.body if isinstance(f, ast.FunctionDef) and f.name == name)\n\
         \x20   return '\\n'.join(ast.dump(s) for s in fn.body)\n\
         rec = body_of(sys.argv[1], 'main')\n\
         orig = body_of(sys.argv[2], 'main')\n\
         assert rec == orig, 'MAIN BODY MISMATCH\\nRECOVERED:\\n%s\\nORIGINAL:\\n%s' % (rec, orig)\n",
        &recovered,
        &repo_path(ORIGINAL),
    );
    assert!(
        out.status.success(),
        "recovered `main` body must AST-match the clean original (intrinsics fully lowered): {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let _ = std::fs::remove_dir_all(&dir);
}
