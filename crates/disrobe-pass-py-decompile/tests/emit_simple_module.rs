#![allow(clippy::expect_used)]

use disrobe_pass_py_decompile::ast::{AstModule, ConstValue, Expr, Stmt};
use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::emit::{EmitOutput, EmitPipeline};

#[test]
fn emit_simple_module_is_the_bare_statement_without_a_header() {
    let module: AstModule = AstModule {
        docstring: None,
        body: vec![Stmt::Return(Some(Expr::Constant {
            value: ConstValue::Int(42),
            line: None,
        }))],
        blank_lines: std::collections::BTreeMap::new(),
    };
    let out: EmitOutput = EmitPipeline::default()
        .run(&module, &PyVersion::V3_13)
        .expect("emit ok");
    assert_eq!(out.source, "return 42\n");
}
