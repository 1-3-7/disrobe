#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use disrobe_nir::NirModule;
use disrobe_nir_lift::lift_pyc;

const EDGE_CASES_PYC: &[u8] = include_bytes!(
    "../../../corpus/python/decompile/playground/__pycache__/edge_cases.cpython-314.pyc"
);
const EDGE_CASES_3_14_PYC: &[u8] = include_bytes!(
    "../../../corpus/python/decompile/playground/__pycache__/edge_cases_3_14.cpython-314.pyc"
);

const DISROBE_STMT_VARIANTS: [&str; 25] = [
    "FunctionDef",
    "ClassDef",
    "Return",
    "Delete",
    "Assign",
    "AugAssign",
    "AnnAssign",
    "TypeAlias",
    "For",
    "While",
    "If",
    "With",
    "Match",
    "Raise",
    "Try",
    "TryStar",
    "Assert",
    "Import",
    "ImportFrom",
    "Global",
    "Nonlocal",
    "Expr",
    "Pass",
    "Break",
    "Continue",
];

const DISROBE_EXPR_VARIANTS: [&str; 30] = [
    "Constant",
    "Name",
    "FormattedValue",
    "JoinedStr",
    "TStr",
    "BoolOp",
    "NamedExpr",
    "BinOp",
    "UnaryOp",
    "Lambda",
    "IfExp",
    "Dict",
    "Set",
    "ListComp",
    "SetComp",
    "DictComp",
    "GeneratorExp",
    "Await",
    "Yield",
    "YieldFrom",
    "Compare",
    "Call",
    "Attribute",
    "Subscript",
    "Starred",
    "List",
    "Tuple",
    "Slice",
    "EmptyDictUnpack",
    "EmptyDictKeyUnpack",
];

const DECLINED_STMT_VARIANTS: [&str; 8] = [
    "FunctionDef",
    "ClassDef",
    "Import",
    "ImportFrom",
    "Global",
    "Nonlocal",
    "TypeAlias",
    "Pass",
];

const RENAMED_REFERENCE_KINDS: [(&str, &str); 1] = [("TemplateStr", "TStr")];
const ASYNC_FOLDED_REFERENCE_KINDS: [(&str, &str); 3] = [
    ("AsyncFor", "For"),
    ("AsyncFunctionDef", "FunctionDef"),
    ("AsyncWith", "With"),
];
const STRUCT_FOLDED_REFERENCE_KINDS: [&str; 1] = ["Interpolation"];

const SPEC_PRESENT_CORPUS_ABSENT: [&str; 3] = ["Pass", "Assert", "YieldFrom"];
const DISROBE_ONLY_SYNTHETIC: [&str; 2] = ["EmptyDictUnpack", "EmptyDictKeyUnpack"];

const REFERENCE_STMT_EXPR_KINDS: [&str; 54] = [
    "AnnAssign",
    "Assign",
    "AsyncFor",
    "AsyncFunctionDef",
    "AsyncWith",
    "Attribute",
    "AugAssign",
    "Await",
    "BinOp",
    "BoolOp",
    "Break",
    "Call",
    "ClassDef",
    "Compare",
    "Constant",
    "Continue",
    "Delete",
    "Dict",
    "DictComp",
    "Expr",
    "For",
    "FormattedValue",
    "FunctionDef",
    "GeneratorExp",
    "Global",
    "If",
    "IfExp",
    "Import",
    "ImportFrom",
    "Interpolation",
    "JoinedStr",
    "Lambda",
    "List",
    "ListComp",
    "Match",
    "Name",
    "NamedExpr",
    "Nonlocal",
    "Raise",
    "Return",
    "Set",
    "SetComp",
    "Slice",
    "Starred",
    "Subscript",
    "TemplateStr",
    "Try",
    "TryStar",
    "Tuple",
    "TypeAlias",
    "UnaryOp",
    "While",
    "With",
    "Yield",
];

const DECLINED_BINOPKIND_VARIANTS: [&str; 3] = ["Pow", "MatMul", "Generic"];

#[derive(Debug, Clone)]
struct CpythonInvocation {
    program: PathBuf,
    prefix_args: Vec<OsString>,
}

fn probe_cpython_314(invocation: &CpythonInvocation) -> bool {
    Command::new(&invocation.program)
        .args(&invocation.prefix_args)
        .args([
            "-c",
            "import platform,sys;print(platform.python_implementation(),f'{sys.version_info.major}.{sys.version_info.minor}',sys.version_info.releaselevel,sep='|')",
        ])
        .stdin(Stdio::null())
        .output()
        .is_ok_and(|output: Output| {
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).trim() == "CPython|3.14|final"
        })
}

fn uv_python_314() -> Option<PathBuf> {
    let output: Output = Command::new("uv")
        .args(["python", "find", "3.14"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path: PathBuf = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    path.is_file().then_some(path)
}

fn find_cpython_314() -> Option<CpythonInvocation> {
    let configured: Option<CpythonInvocation> =
        std::env::var_os("DISROBE_PYTHON").map(|program| CpythonInvocation {
            program: PathBuf::from(program),
            prefix_args: Vec::new(),
        });
    let uv: Option<CpythonInvocation> = uv_python_314().map(|program: PathBuf| CpythonInvocation {
        program,
        prefix_args: Vec::new(),
    });
    let launcher: Option<CpythonInvocation> = cfg!(windows).then(|| CpythonInvocation {
        program: PathBuf::from("py"),
        prefix_args: vec![OsString::from("-3.14")],
    });
    configured
        .into_iter()
        .chain(uv)
        .chain(launcher)
        .chain(
            ["python3.14", "python"]
                .into_iter()
                .map(|program: &str| CpythonInvocation {
                    program: PathBuf::from(program),
                    prefix_args: Vec::new(),
                }),
        )
        .find(|candidate: &CpythonInvocation| probe_cpython_314(candidate))
}

fn require_cpython_314() -> CpythonInvocation {
    find_cpython_314().unwrap_or_else(|| {
        panic!(
            "final CPython 3.14 is mandatory for Python opcode completeness; install it through uv or point DISROBE_PYTHON at the interpreter"
        )
    })
}

fn scratch_dir(label: &str) -> PathBuf {
    let dir: PathBuf = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("python_opcode_completeness")
        .join(label);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates parent")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn compile_snippet(python: &CpythonInvocation, dir: &Path, stem: &str, source: &str) -> Vec<u8> {
    let py_path: PathBuf = dir.join(format!("{stem}.py"));
    let pyc_path: PathBuf = dir.join(format!("{stem}.pyc"));
    std::fs::write(&py_path, source).expect("write snippet source");
    let script: String = format!(
        "import py_compile; py_compile.compile({py:?}, cfile={pyc:?}, doraise=True)",
        py = py_path.to_string_lossy(),
        pyc = pyc_path.to_string_lossy(),
    );
    let output: Output = Command::new(&python.program)
        .args(&python.prefix_args)
        .arg("-c")
        .arg(&script)
        .output()
        .expect("run py_compile");
    assert!(
        output.status.success(),
        "py_compile failed for {stem}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::read(&pyc_path).expect("read compiled snippet")
}

fn mnemonics_of(module: &NirModule, function_name: &str) -> Vec<String> {
    module
        .functions
        .iter()
        .find(|f| f.name == function_name)
        .unwrap_or_else(|| panic!("function {function_name} must be present in the lifted module"))
        .instructions
        .iter()
        .map(|instr| instr.mnemonic.clone())
        .collect()
}

#[test]
fn stmt_and_expr_variant_rosters_are_pinned() {
    assert_eq!(
        DISROBE_STMT_VARIANTS.len(),
        25,
        "the Stmt enum grew or shrank; re-derive this roster from disrobe_pass_py_decompile::ast::node::Stmt"
    );
    assert_eq!(
        DISROBE_EXPR_VARIANTS.len(),
        30,
        "the Expr enum grew or shrank; re-derive this roster from disrobe_pass_py_decompile::ast::node::Expr"
    );
    let stmt_set: BTreeSet<&str> = DISROBE_STMT_VARIANTS.into_iter().collect();
    assert_eq!(
        stmt_set.len(),
        DISROBE_STMT_VARIANTS.len(),
        "no duplicate Stmt variant names"
    );
    let expr_set: BTreeSet<&str> = DISROBE_EXPR_VARIANTS.into_iter().collect();
    assert_eq!(
        expr_set.len(),
        DISROBE_EXPR_VARIANTS.len(),
        "no duplicate Expr variant names"
    );
    for declined in DECLINED_STMT_VARIANTS {
        assert!(
            stmt_set.contains(declined),
            "{declined} must be a real Stmt variant name"
        );
    }
}

#[test]
fn committed_edge_cases_corpus_is_non_vacuous_and_covers_every_modelled_mnemonic() {
    let module: NirModule = lift_pyc(EDGE_CASES_PYC).expect("lift the committed broad corpus");
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut total: usize = 0;
    for function in &module.functions {
        for instr in &function.instructions {
            total += 1;
            *counts.entry(instr.mnemonic.clone()).or_insert(0) += 1;
        }
    }
    assert_eq!(
        module.functions.len(),
        206,
        "the committed edge_cases.cpython-314.pyc fixture recovers a fixed function count"
    );
    assert_eq!(
        total, 1093,
        "the lifted instruction stream for a byte-fixed pyc is deterministic: {counts:?}"
    );

    let expected_minimums: [(&str, usize); 20] = [
        ("add", 42),
        ("and", 2),
        ("break", 2),
        ("call", 232),
        ("case", 54),
        ("continue", 9),
        ("div", 5),
        ("if", 61),
        ("jump", 59),
        ("load", 22),
        ("loop", 59),
        ("mul", 28),
        ("or", 3),
        ("raise", 14),
        ("rem", 7),
        ("return", 478),
        ("shl", 1),
        ("store", 6),
        ("sub", 8),
        ("xor", 1),
    ];
    for (mnemonic, expected) in expected_minimums {
        let observed: usize = counts.get(mnemonic).copied().unwrap_or(0);
        assert_eq!(
            observed, expected,
            "mnemonic {mnemonic} count drifted from the pinned measurement over the committed corpus"
        );
    }
    assert_eq!(
        counts.keys().count(),
        expected_minimums.len(),
        "an unexpected mnemonic appeared in the lifted stream: {counts:?}"
    );
}

#[test]
fn committed_tstring_corpus_surfaces_calls_inside_interpolations() {
    let module: NirModule =
        lift_pyc(EDGE_CASES_3_14_PYC).expect("lift the committed t-string corpus");
    let concatenation: Vec<String> = mnemonics_of(&module, "tstring_concatenation");
    let call_operands: Vec<String> = module
        .functions
        .iter()
        .find(|f| f.name == "tstring_concatenation")
        .expect("tstring_concatenation")
        .instructions
        .iter()
        .filter(|i| i.mnemonic == "call")
        .filter_map(|i| i.operands.first().cloned())
        .collect();
    assert_eq!(
        call_operands,
        vec!["str".to_owned(), "join".to_owned(), "sum".to_owned()],
        "a call embedded inside a t-string interpolation must reach the lifted call-site facts, \
         not be silently dropped because TStr forwarding is missing: {concatenation:?}"
    );

    let basic: Vec<String> = mnemonics_of(&module, "tstring_basic");
    assert!(
        !basic.contains(&"call".to_owned()),
        "a t-string with no calls inside its interpolations must not fabricate a call site: {basic:?}"
    );
}

#[test]
fn declined_stmt_and_expr_constructs_never_emit_an_instruction() {
    let python: CpythonInvocation = require_cpython_314();
    let dir: PathBuf = scratch_dir("declined");

    let nested_defs: Vec<u8> = compile_snippet(
        &python,
        &dir,
        "nested_defs",
        "def outer():\n    def inner():\n        return 99\n    class Inner:\n        def method(self):\n            return 1\n    return 1\n",
    );
    let module: NirModule = lift_pyc(&nested_defs).expect("lift nested_defs snippet");
    assert_eq!(mnemonics_of(&module, "outer"), vec!["return", "return"]);
    assert_eq!(
        mnemonics_of(&module, "outer.inner"),
        vec!["return", "return"]
    );
    assert_eq!(
        mnemonics_of(&module, "outer.Inner.method"),
        vec!["return", "return"]
    );

    let import_pass_typealias: Vec<u8> = compile_snippet(
        &python,
        &dir,
        "import_pass_typealias",
        "import os\nfrom sys import argv\ntype Alias = int\n\n\ndef f():\n    import json\n    from os import path\n    type Local = str\n    pass\n    return 1\n",
    );
    let module: NirModule =
        lift_pyc(&import_pass_typealias).expect("lift import_pass_typealias snippet");
    assert_eq!(
        mnemonics_of(&module, "f"),
        vec!["return", "return"],
        "Import, ImportFrom, TypeAlias and Pass inside a function body must not emit an instruction"
    );

    let global_nonlocal: Vec<u8> = compile_snippet(
        &python,
        &dir,
        "global_nonlocal",
        "counter = 0\n\n\ndef outer():\n    x = 0\n\n    def inner():\n        global counter\n        nonlocal x\n        return 1\n\n    return inner()\n",
    );
    let module: NirModule = lift_pyc(&global_nonlocal).expect("lift global_nonlocal snippet");
    assert_eq!(
        mnemonics_of(&module, "outer"),
        vec!["call", "return", "return"]
    );
    assert_eq!(
        mnemonics_of(&module, "outer.inner"),
        vec!["return", "return"],
        "Global and Nonlocal must not emit an instruction"
    );

    let bare_yield: Vec<u8> = compile_snippet(
        &python,
        &dir,
        "bare_yield",
        "def gen():\n    yield\n    return\n",
    );
    let module: NirModule = lift_pyc(&bare_yield).expect("lift bare_yield snippet");
    assert_eq!(
        mnemonics_of(&module, "gen"),
        vec!["return", "return"],
        "Expr::Yield(None) must not emit an instruction"
    );

    let assert_stmt: Vec<u8> = compile_snippet(
        &python,
        &dir,
        "assert_stmt",
        "def f(x):\n    assert x > 0\n    return 1\n",
    );
    let module: NirModule = lift_pyc(&assert_stmt).expect("lift assert_stmt snippet");
    assert_eq!(
        mnemonics_of(&module, "f"),
        vec!["return", "return"],
        "Assert over a Name/Constant comparison must not emit an instruction"
    );

    let yield_from: Vec<u8> = compile_snippet(
        &python,
        &dir,
        "yield_from",
        "def gen():\n    yield from range(3)\n",
    );
    let module: NirModule = lift_pyc(&yield_from).expect("lift yield_from snippet");
    assert_eq!(
        mnemonics_of(&module, "gen"),
        vec!["call", "return", "return"],
        "YieldFrom must forward into its inner expression rather than declining it"
    );
}

#[test]
fn declined_binopkind_variants_are_pinned() {
    let python: CpythonInvocation = require_cpython_314();
    let dir: PathBuf = scratch_dir("binop");

    let source: &str = "def f(a, b):\n    c = a ** b\n    return c\n\n\ndef g(a, b):\n    c = a + b\n    return c\n\n\ndef h(a, b):\n    c = a @ b\n    return c\n";
    let bytes: Vec<u8> = compile_snippet(&python, &dir, "pow_matmul_decline", source);
    let module: NirModule = lift_pyc(&bytes).expect("lift pow_matmul_decline snippet");

    assert_eq!(
        mnemonics_of(&module, "f"),
        vec!["return", "return"],
        "BinOpKind::Pow must not lower to a BinOp instruction: {DECLINED_BINOPKIND_VARIANTS:?} are declined"
    );
    assert_eq!(
        mnemonics_of(&module, "g"),
        vec!["add", "return", "return"],
        "BinOpKind::Add is the modelled control case for the Pow/MatMul decline check"
    );
    assert_eq!(
        mnemonics_of(&module, "h"),
        vec!["return", "return"],
        "BinOpKind::MatMul must not lower to a BinOp instruction"
    );
}

#[test]
fn cpython_ast_module_cross_check_pins_the_reference_node_kind_set() {
    let python: CpythonInvocation = require_cpython_314();
    let root: PathBuf = workspace_root();
    let edge_cases: PathBuf = root
        .join("corpus")
        .join("python")
        .join("decompile")
        .join("playground")
        .join("edge_cases.py");
    let edge_cases_3_14: PathBuf = root
        .join("corpus")
        .join("python")
        .join("decompile")
        .join("playground")
        .join("edge_cases_3_14.py");
    assert!(edge_cases.is_file(), "committed corpus source must exist");
    assert!(
        edge_cases_3_14.is_file(),
        "committed 3.14 corpus source must exist"
    );

    let script: &str = "import ast, sys\n\
\n\
names = set()\n\
for path in sys.argv[1:]:\n\
\x20\x20\x20\x20src = open(path, encoding='utf-8').read()\n\
\x20\x20\x20\x20tree = ast.parse(src)\n\
\x20\x20\x20\x20for n in ast.walk(tree):\n\
\x20\x20\x20\x20\x20\x20\x20\x20if isinstance(n, (ast.stmt, ast.expr)):\n\
\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20names.add(type(n).__name__)\n\
\n\
print('\\n'.join(sorted(names)))\n";
    let output: Output = Command::new(&python.program)
        .args(&python.prefix_args)
        .arg("-c")
        .arg(script)
        .arg(&edge_cases)
        .arg(&edge_cases_3_14)
        .output()
        .expect("run the CPython ast reference walk");
    assert!(
        output.status.success(),
        "CPython ast reference walk failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let reference: BTreeSet<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_owned)
        .filter(|line| !line.is_empty())
        .collect();
    let pinned: BTreeSet<String> = REFERENCE_STMT_EXPR_KINDS
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    assert_eq!(
        reference, pinned,
        "the live CPython 3.14 ast module's stmt/expr node kinds over the committed corpus \
         drifted from the pinned reference set; re-derive REFERENCE_STMT_EXPR_KINDS"
    );

    let renamed: BTreeMap<&str, &str> = RENAMED_REFERENCE_KINDS.into_iter().collect();
    let async_folded: BTreeMap<&str, &str> = ASYNC_FOLDED_REFERENCE_KINDS.into_iter().collect();
    let struct_folded: BTreeSet<&str> = STRUCT_FOLDED_REFERENCE_KINDS.into_iter().collect();
    let stmt_set: BTreeSet<&str> = DISROBE_STMT_VARIANTS.into_iter().collect();
    let expr_set: BTreeSet<&str> = DISROBE_EXPR_VARIANTS.into_iter().collect();

    let mut mapped_disrobe_names: BTreeSet<&str> = BTreeSet::new();
    for kind in &pinned {
        let kind: &str = kind.as_str();
        if stmt_set.contains(kind) || expr_set.contains(kind) {
            mapped_disrobe_names.insert(kind);
            continue;
        }
        if let Some(target) = renamed.get(kind) {
            assert!(
                expr_set.contains(target) || stmt_set.contains(target),
                "renamed reference kind {kind} must target a real disrobe variant"
            );
            mapped_disrobe_names.insert(target);
            continue;
        }
        if let Some(target) = async_folded.get(kind) {
            assert!(
                stmt_set.contains(target),
                "async-folded reference kind {kind} must target a real disrobe Stmt variant"
            );
            mapped_disrobe_names.insert(target);
            continue;
        }
        if struct_folded.contains(kind) {
            continue;
        }
        panic!(
            "reference stmt/expr kind {kind} is not accounted for by any disrobe variant, \
             rename, async fold, or struct fold; the classify table is missing coverage"
        );
    }

    let spec_present_corpus_absent: BTreeSet<&str> =
        SPEC_PRESENT_CORPUS_ABSENT.into_iter().collect();
    let disrobe_only_synthetic: BTreeSet<&str> = DISROBE_ONLY_SYNTHETIC.into_iter().collect();
    for variant in DISROBE_STMT_VARIANTS
        .into_iter()
        .chain(DISROBE_EXPR_VARIANTS)
    {
        if mapped_disrobe_names.contains(variant) {
            continue;
        }
        assert!(
            spec_present_corpus_absent.contains(variant)
                || disrobe_only_synthetic.contains(variant),
            "disrobe variant {variant} is exercised by neither the committed corpus nor the \
             spec-present/corpus-absent and disrobe-only-synthetic exception lists"
        );
    }
}
