#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::time::Instant;

use disrobe_pass_py_decompile::ast::{
    Alias, Arg, Arguments, AstModule, ConstValue, Expr, ExprCtx, Stmt,
};
use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::emit::{EmitOutput, EmitPipeline, LLM_JSON_SCHEMA_ID};
use serde_json::Value;

#[test]
fn full_pipeline_all_features_on() {
    let import_stmt: Stmt = Stmt::Import(vec![Alias {
        name: "os".to_owned(),
        asname: None,
    }]);
    let from_stmt: Stmt = Stmt::ImportFrom {
        module: Some("typing".to_owned()),
        names: vec![Alias {
            name: "Optional".to_owned(),
            asname: None,
        }],
        level: 0,
        line: Some(2),
    };
    let func: Stmt = Stmt::FunctionDef {
        name: "compute".to_owned(),
        type_params: Vec::new(),
        args: Arguments {
            posonly: Vec::new(),
            args: vec![Arg {
                arg: "n".to_owned(),
                annotation: Some(Box::new(Expr::Name {
                    id: "int".to_owned(),
                    ctx: ExprCtx::Load,
                    line: None,
                })),
                default: None,
                line: None,
            }],
            vararg: None,
            kwonly: Vec::new(),
            kw_defaults: Vec::new(),
            kwarg: None,
            defaults: Vec::new(),
        },
        body: vec![Stmt::Return(Some(Expr::Constant {
            value: ConstValue::Int(99),
            line: None,
        }))],
        decorators: Vec::new(),
        returns: Some(Expr::Name {
            id: "int".to_owned(),
            ctx: ExprCtx::Load,
            line: None,
        }),
        is_async: false,
        docstring: Some("compute a value".to_owned()),
        line: Some(5),
    };
    let mut blanks: BTreeMap<u32, u8> = BTreeMap::new();
    blanks.insert(5, 1);
    let module: AstModule = AstModule {
        docstring: Some("module doc".to_owned()),
        body: vec![import_stmt, from_stmt, func],
        blank_lines: blanks,
    };

    let pipeline: EmitPipeline = EmitPipeline {
        formatter_enabled: true,
        include_provenance: true,
        include_llm_json: true,
        preserve_blank_lines: true,
        ..EmitPipeline::default()
    };
    let out: EmitOutput = pipeline
        .run(&module, &PyVersion::V3_13, Instant::now())
        .expect("emit ok");

    assert!(out.source.starts_with("# Decompiled in "));
    assert!(out.source.contains("\n# Python 3.13\n"));
    assert!(out.source.contains("def compute"));
    assert!(out.source.contains("return 99"));
    assert!(out.source.contains("import os") || out.source.contains("os"));

    let sidecar: &Value = out.llm_json.as_ref().expect("llm_json present");
    assert_eq!(
        sidecar.get("schema").and_then(Value::as_str),
        Some(LLM_JSON_SCHEMA_ID)
    );
    assert_eq!(sidecar.get("version").and_then(Value::as_str), Some("3.13"));
    let funcs: &Vec<Value> = sidecar
        .get("functions")
        .and_then(Value::as_array)
        .expect("functions");
    assert_eq!(funcs.len(), 1);
    let imports_used: &Vec<Value> = sidecar
        .get("imports_used")
        .and_then(Value::as_array)
        .expect("imports_used");
    assert!(
        imports_used
            .iter()
            .any(|v: &Value| v.as_str() == Some("os"))
    );
    assert!(
        imports_used
            .iter()
            .any(|v: &Value| v.as_str() == Some("Optional"))
    );
    let metrics: &Value = sidecar.get("metrics").expect("metrics");
    assert_eq!(metrics.get("n_functions").and_then(Value::as_u64), Some(1));
}
