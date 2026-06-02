#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::items_after_statements,
    clippy::single_char_pattern
)]

use std::time::Instant;

use disrobe_pass_py_decompile::ast::{Arg, Arguments, AstModule, ConstValue, Expr, ExprCtx, Stmt};
use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::emit::{EmitOutput, EmitPipeline};

#[test]
fn formatter_disabled_still_includes_header() {
    let arg: Arg = Arg {
        arg: "x".to_owned(),
        annotation: None,
        default: None,
        line: None,
    };
    let func: Stmt = Stmt::FunctionDef {
        name: "f".to_owned(),
        type_params: Vec::new(),
        args: Arguments {
            posonly: Vec::new(),
            args: vec![arg],
            vararg: None,
            kwonly: Vec::new(),
            kw_defaults: Vec::new(),
            kwarg: None,
            defaults: Vec::new(),
        },
        body: vec![Stmt::Return(Some(Expr::Name {
            id: "x".to_owned(),
            ctx: ExprCtx::Load,
            line: None,
        }))],
        decorators: Vec::new(),
        returns: None,
        is_async: false,
        docstring: None,
        line: None,
    };
    let module: AstModule = AstModule {
        docstring: None,
        body: vec![
            func,
            Stmt::Expr(Expr::Constant {
                value: ConstValue::Int(7),
                line: None,
            }),
        ],
        blank_lines: std::collections::BTreeMap::new(),
    };

    let pipeline: EmitPipeline = EmitPipeline {
        formatter_enabled: false,
        include_provenance: true,
        include_llm_json: false,
        preserve_blank_lines: true,
        ..EmitPipeline::default()
    };
    let out: EmitOutput = pipeline
        .run(&module, &PyVersion::V3_13, Instant::now())
        .expect("emit ok");

    assert!(
        out.source.starts_with("# Decompiled in "),
        "header missing: {}",
        out.source
    );
    assert!(
        out.source.contains("\n# Python 3.13\n"),
        "python banner missing"
    );
    assert!(
        out.source.contains("def f(x):\n    return x"),
        "expected raw emit body: {}",
        out.source
    );
    assert!(
        out.source.contains("7"),
        "expected trailing module expr to survive: {}",
        out.source
    );
}
