#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_const_for_fn,
    clippy::items_after_statements,
    clippy::too_many_lines,
    clippy::default_trait_access,
    clippy::doc_markdown
)]

mod common;

use std::path::PathBuf;

use disrobe_pass_py_decompile::ast::{
    AstModule, ConstValue, ExceptHandler, Expr, ExprCtx, MatchCase, Pattern, Stmt, WithItem,
};
use disrobe_pass_py_decompile::bytecode::opcode::CmpOp;
use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::codegen::{CodeEmitter, DefaultEmitter};

use crate::common::band::{
    BandInterpreter, CorpusMeasurement, ObjectTally, band_scratch, measure_corpus_file,
    resolve_band,
};

const VERSIONS: &[PyVersion] = &[
    PyVersion::V3_10,
    PyVersion::V3_11,
    PyVersion::V3_12,
    PyVersion::V3_13,
    PyVersion::V3_14,
];

fn name(id: &str) -> Expr {
    Expr::Name {
        id: id.to_owned(),
        ctx: ExprCtx::Load,
        line: None,
    }
}

fn name_store(id: &str) -> Expr {
    Expr::Name {
        id: id.to_owned(),
        ctx: ExprCtx::Store,
        line: None,
    }
}

fn int(n: i128) -> Expr {
    Expr::Constant {
        value: ConstValue::Int(n),
        line: None,
    }
}

fn str_lit(s: &str) -> Expr {
    Expr::Constant {
        value: ConstValue::Str(s.to_owned()),
        line: None,
    }
}

fn render(module: &AstModule, version: &PyVersion) -> String {
    let em: DefaultEmitter = DefaultEmitter::new();
    em.emit_module(module, version)
}

#[test]
fn strict_try_except_basic_all_versions() {
    let stmt: Stmt = Stmt::Try {
        body: vec![Stmt::Assign {
            targets: vec![name_store("v")],
            value: Expr::Call {
                func: Box::new(name("int")),
                args: vec![name("s")],
                keywords: Vec::new(),
            },
            type_comment: None,
            line: None,
        }],
        handlers: vec![ExceptHandler {
            typ: Some(name("ValueError")),
            name: None,
            body: vec![Stmt::Return(Some(int(0)))],
            line: None,
        }],
        orelse: Vec::new(),
        finalbody: Vec::new(),
        line: None,
    };
    let module: AstModule = AstModule {
        docstring: None,
        body: vec![stmt],
        blank_lines: Default::default(),
    };
    for version in VERSIONS {
        let out: String = render(&module, version);
        assert!(
            out.contains("try:"),
            "version {version:?}: missing 'try:': {out}"
        );
        assert!(
            out.contains("except"),
            "version {version:?}: missing 'except'"
        );
    }
}

#[test]
fn strict_assert_with_message_all_versions() {
    let stmt: Stmt = Stmt::Assert {
        test: Expr::Compare {
            left: Box::new(name("x")),
            ops: vec![CmpOp::Ge],
            comparators: vec![int(0)],
        },
        msg: Some(str_lit("x must be non-negative")),
        line: None,
    };
    let module: AstModule = AstModule {
        docstring: None,
        body: vec![stmt],
        blank_lines: Default::default(),
    };
    for version in VERSIONS {
        let out: String = render(&module, version);
        assert!(
            out.contains("assert"),
            "version {version:?}: 'assert' dropped"
        );
        assert!(
            out.contains("x must be non-negative"),
            "version {version:?}: message dropped: {out}"
        );
        assert!(!out.contains("\npass\n"), "must not degrade to pass");
    }
}

#[test]
fn strict_with_single_item_all_versions() {
    let stmt: Stmt = Stmt::With {
        items: vec![WithItem {
            context_expr: Expr::Call {
                func: Box::new(name("open")),
                args: vec![str_lit("f")],
                keywords: Vec::new(),
            },
            optional_vars: Some(name_store("f")),
        }],
        body: vec![Stmt::Return(Some(name("f")))],
        is_async: false,
        line: None,
    };
    let module: AstModule = AstModule {
        docstring: None,
        body: vec![stmt],
        blank_lines: Default::default(),
    };
    for version in VERSIONS {
        let out: String = render(&module, version);
        assert!(out.contains("with"), "missing 'with' for {version:?}");
        assert!(out.contains("as f"), "missing 'as f' for {version:?}");
    }
}

#[test]
fn strict_for_loop_with_orelse_all_versions() {
    let stmt: Stmt = Stmt::For {
        target: name_store("x"),
        iter: name("items"),
        body: vec![Stmt::If {
            test: Expr::Compare {
                left: Box::new(name("x")),
                ops: vec![CmpOp::Eq],
                comparators: vec![int(0)],
            },
            body: vec![Stmt::Break],
            orelse: Vec::new(),
            line: None,
        }],
        orelse: vec![Stmt::Return(Some(Expr::Constant {
            value: ConstValue::True,
            line: None,
        }))],
        is_async: false,
        line: None,
    };
    let module: AstModule = AstModule {
        docstring: None,
        body: vec![stmt],
        blank_lines: Default::default(),
    };
    for version in VERSIONS {
        let out: String = render(&module, version);
        assert!(out.contains("for x in items"), "for header for {version:?}");
        assert!(out.contains("break"), "break dropped for {version:?}");
        assert!(out.contains("else:"), "for-else dropped for {version:?}");
    }
}

#[test]
fn strict_while_loop_all_versions() {
    let stmt: Stmt = Stmt::While {
        test: Expr::Compare {
            left: Box::new(name("count")),
            ops: vec![CmpOp::Lt],
            comparators: vec![int(10)],
        },
        body: vec![Stmt::AugAssign {
            target: name_store("count"),
            op: disrobe_pass_py_decompile::bytecode::opcode::BinOp::Add,
            value: int(1),
            line: None,
        }],
        orelse: Vec::new(),
        line: None,
    };
    let module: AstModule = AstModule {
        docstring: None,
        body: vec![stmt],
        blank_lines: Default::default(),
    };
    for version in VERSIONS {
        let out: String = render(&module, version);
        assert!(
            out.contains("while count < 10"),
            "while for {version:?}: {out}"
        );
    }
}

#[test]
fn strict_function_def_with_return_all_versions() {
    let stmt: Stmt = Stmt::FunctionDef {
        name: "f".to_owned(),
        type_params: Vec::new(),
        args: Default::default(),
        body: vec![Stmt::Return(Some(int(42)))],
        decorators: Vec::new(),
        returns: None,
        is_async: false,
        docstring: None,
        line: None,
    };
    let module: AstModule = AstModule {
        docstring: None,
        body: vec![stmt],
        blank_lines: Default::default(),
    };
    for version in VERSIONS {
        let out: String = render(&module, version);
        assert!(out.contains("def f()"), "def header for {version:?}");
        assert!(out.contains("return 42"), "return 42 for {version:?}");
    }
}

#[test]
fn strict_class_def_simple_all_versions() {
    let stmt: Stmt = Stmt::ClassDef {
        name: "Foo".to_owned(),
        type_params: Vec::new(),
        bases: vec![name("object")],
        keywords: Vec::new(),
        body: vec![Stmt::Pass],
        decorators: Vec::new(),
        docstring: None,
        line: None,
    };
    let module: AstModule = AstModule {
        docstring: None,
        body: vec![stmt],
        blank_lines: Default::default(),
    };
    for version in VERSIONS {
        let out: String = render(&module, version);
        assert!(out.contains("class Foo"), "class header for {version:?}");
        assert!(out.contains("(object)"), "single base for {version:?}");
    }
}

#[test]
fn strict_match_value_pattern_311_plus() {
    let stmt: Stmt = Stmt::Match {
        subject: name("cmd"),
        cases: vec![
            MatchCase {
                pattern: Pattern::MatchValue(str_lit("start")),
                guard: None,
                body: vec![Stmt::Return(Some(int(1)))],
            },
            MatchCase {
                pattern: Pattern::MatchAs {
                    pattern: None,
                    name: None,
                },
                guard: None,
                body: vec![Stmt::Return(Some(int(0)))],
            },
        ],
        line: None,
    };
    let module: AstModule = AstModule {
        docstring: None,
        body: vec![stmt],
        blank_lines: Default::default(),
    };
    for version in &[
        PyVersion::V3_11,
        PyVersion::V3_12,
        PyVersion::V3_13,
        PyVersion::V3_14,
    ] {
        let out: String = render(&module, version);
        assert!(out.contains("match cmd"), "match for {version:?}: {out}");
        assert!(out.contains("case"), "case for {version:?}");
    }
}

#[test]
fn strict_if_elif_else_chain_all_versions() {
    let stmt: Stmt = Stmt::If {
        test: Expr::Compare {
            left: Box::new(name("x")),
            ops: vec![CmpOp::Gt],
            comparators: vec![int(0)],
        },
        body: vec![Stmt::Return(Some(int(1)))],
        orelse: vec![Stmt::If {
            test: Expr::Compare {
                left: Box::new(name("x")),
                ops: vec![CmpOp::Lt],
                comparators: vec![int(0)],
            },
            body: vec![Stmt::Return(Some(Expr::UnaryOp {
                op: disrobe_pass_py_decompile::bytecode::opcode::UnaryOp::Negative,
                operand: Box::new(int(1)),
            }))],
            orelse: vec![Stmt::Return(Some(int(0)))],
            line: None,
        }],
        line: None,
    };
    let module: AstModule = AstModule {
        docstring: None,
        body: vec![stmt],
        blank_lines: Default::default(),
    };
    for version in VERSIONS {
        let out: String = render(&module, version);
        assert!(out.contains("if x > 0"), "if head for {version:?}: {out}");
        assert!(
            out.contains("elif"),
            "elif chain not flattened for {version:?}"
        );
        assert!(out.contains("else"), "else missing for {version:?}");
    }
}

#[test]
fn strict_yield_simple_all_versions() {
    let stmt: Stmt = Stmt::FunctionDef {
        name: "gen".to_owned(),
        type_params: Vec::new(),
        args: Default::default(),
        body: vec![Stmt::Expr(Expr::Yield(Some(Box::new(int(1)))))],
        decorators: Vec::new(),
        returns: None,
        is_async: false,
        docstring: None,
        line: None,
    };
    let module: AstModule = AstModule {
        docstring: None,
        body: vec![stmt],
        blank_lines: Default::default(),
    };
    for version in VERSIONS {
        let out: String = render(&module, version);
        assert!(
            out.contains("yield"),
            "yield dropped for {version:?}: {out}"
        );
    }
}

#[test]
fn strict_raise_with_cause_all_versions() {
    let stmt: Stmt = Stmt::Raise {
        exc: Some(Expr::Call {
            func: Box::new(name("ValueError")),
            args: vec![str_lit("bad")],
            keywords: Vec::new(),
        }),
        cause: Some(name("orig")),
        line: None,
    };
    let module: AstModule = AstModule {
        docstring: None,
        body: vec![stmt],
        blank_lines: Default::default(),
    };
    for version in VERSIONS {
        let out: String = render(&module, version);
        assert!(out.contains("raise"), "raise for {version:?}: {out}");
        assert!(
            out.contains("from orig"),
            "raise-from-cause for {version:?}"
        );
    }
}

#[test]
fn strict_list_dict_set_literals_all_versions() {
    let mod_body: Vec<Stmt> = vec![
        Stmt::Expr(Expr::List {
            elts: vec![int(1), int(2), int(3)],
            ctx: ExprCtx::Load,
        }),
        Stmt::Expr(Expr::Dict {
            keys: vec![Some(str_lit("a")), Some(str_lit("b"))],
            values: vec![int(1), int(2)],
        }),
        Stmt::Expr(Expr::Set(vec![int(1), int(2)])),
    ];
    let module: AstModule = AstModule {
        docstring: None,
        body: mod_body,
        blank_lines: Default::default(),
    };
    for version in VERSIONS {
        let out: String = render(&module, version);
        assert!(
            out.contains("[1, 2, 3]"),
            "list literal for {version:?}: {out}"
        );
        assert!(
            out.contains("\"a\": 1"),
            "dict literal for {version:?}: {out}"
        );
        assert!(
            out.contains("{1, 2}") || out.contains("{2, 1}"),
            "set literal for {version:?}: {out}"
        );
    }
}

#[test]
fn strict_corpus_file_present() {
    let path: &str = "../../corpus/python/decompile/playground/edge_cases.py";
    let exists: bool = std::path::Path::new(path).exists();
    assert!(exists, "edge_cases.py corpus file missing at {path}");
}

const CORPUS_OBJECT_PCT_FLOOR: f64 = 91.0;

#[test]
fn strict_full_corpus_per_object_roundtrip() {
    let corpus: &str = "../../corpus/python/decompile/playground/edge_cases.py";
    let corpus_path: PathBuf = PathBuf::from(corpus);
    assert!(
        corpus_path.is_file(),
        "edge_cases.py corpus file missing at {corpus}"
    );

    let band: Vec<BandInterpreter> = resolve_band(&["3.14"], &[]);
    let Some(interp): Option<&BandInterpreter> = band.first() else {
        eprintln!(
            "skip: no CPython 3.14 interpreter found (uv python find 3.14 / known install paths). \
             The edge-cases corpus is 3.14-shaped, so per-code-object recompile-equivalence cannot \
             be measured here; floor {CORPUS_OBJECT_PCT_FLOOR} not enforced this run. Install one \
             with `uv python install 3.14`."
        );
        return;
    };

    let scratch: PathBuf = band_scratch("edge_cases_full");
    let measurement: CorpusMeasurement =
        measure_corpus_file(interp, &corpus_path, "edge_cases", &scratch);
    let tally: ObjectTally = match measurement {
        CorpusMeasurement::Measured(t) => t,
        CorpusMeasurement::Unmeasurable(reason) => {
            panic!("edge_cases corpus could not be measured: {reason}");
        }
    };

    println!("=== EDGE-CASES FULL-CORPUS PER-CODE-OBJECT RECOMPILE-EQUIVALENCE ===");
    println!("interpreter : {} ({})", interp.path.display(), interp.alias);
    println!(
        "measured    : {}/{} code objects ({:.2}%)",
        tally.ok,
        tally.total,
        tally.object_pct()
    );
    println!(
        "breakdown   : code-diff {}, sig-diff {}, missing {}, collision {}, sibling-count \
         collisions {}",
        tally.code_diff, tally.sig_diff, tally.missing, tally.collision, tally.sibling_collisions
    );
    if !tally.failures.is_empty() {
        println!("--- per-object failures (qualname :: kind :: note) ---");
        for f in &tally.failures {
            println!("  {} :: {} :: {}", f.qualname, f.kind, f.note);
        }
    }

    assert!(
        tally.total >= 250,
        "only {} code objects walked from the corpus; expected 250+ (the corpus compiles to ~275 \
         nested code objects). The walk or compile is broken, the sample is too thin to gate on.",
        tally.total
    );
    assert!(
        tally.object_pct() >= CORPUS_OBJECT_PCT_FLOOR,
        "edge-cases per-code-object recompile-equivalence regressed: {:.2}% < floor \
         {CORPUS_OBJECT_PCT_FLOOR}% ({}/{} objects). See the per-object failure list above.",
        tally.object_pct(),
        tally.ok,
        tally.total
    );
}
