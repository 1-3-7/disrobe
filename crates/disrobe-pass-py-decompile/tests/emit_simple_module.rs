#![allow(clippy::expect_used)]
use std::time::Instant;

use disrobe_pass_py_decompile::ast::{AstModule, ConstValue, Expr, Stmt};
use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::emit::{EmitOutput, EmitPipeline};

#[test]
fn emit_simple_module_returns_42_with_provenance() {
    let module: AstModule = AstModule {
        docstring: None,
        body: vec![Stmt::Return(Some(Expr::Constant {
            value: ConstValue::Int(42),
            line: None,
        }))],
        blank_lines: std::collections::BTreeMap::new(),
    };
    let version: PyVersion = PyVersion::V3_13;
    let pipeline: EmitPipeline = EmitPipeline {
        include_provenance: true,
        include_llm_json: false,
        ..EmitPipeline::default()
    };
    let started: Option<Instant> = Some(Instant::now());
    let out: EmitOutput = pipeline.run(&module, &version, started).expect("emit ok");
    assert!(
        out.source.contains("return 42"),
        "expected source to contain 'return 42', got: {}",
        out.source
    );
    assert!(
        out.source.starts_with("# Decompiled in "),
        "expected provenance header at top, got: {}",
        out.source
    );
    assert!(
        out.source.contains("\n# Python 3.13\n"),
        "expected python version banner, got: {}",
        out.source
    );
    assert!(
        out.llm_json.is_none(),
        "llm_json must be None when disabled"
    );
}
