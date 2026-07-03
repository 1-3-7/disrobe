#![allow(clippy::expect_used)]
use std::time::Instant;

use disrobe_pass_py_decompile::ast::{Arg, Arguments, AstModule, ConstValue, Expr, ExprCtx, Stmt};
use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::emit::{EmitOutput, EmitPipeline, LLM_JSON_SCHEMA_ID};
use serde_json::Value;

fn simple_function() -> Stmt {
    Stmt::FunctionDef {
        name: "greet".to_owned(),
        type_params: Vec::new(),
        args: Arguments {
            posonly: Vec::new(),
            args: vec![Arg {
                arg: "name".to_owned(),
                annotation: Some(Box::new(Expr::Name {
                    id: "str".to_owned(),
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
        body: vec![Stmt::Return(Some(Expr::Call {
            func: Box::new(Expr::Name {
                id: "print".to_owned(),
                ctx: ExprCtx::Load,
                line: None,
            }),
            args: vec![Expr::Name {
                id: "name".to_owned(),
                ctx: ExprCtx::Load,
                line: None,
            }],
            keywords: Vec::new(),
        }))],
        decorators: Vec::new(),
        returns: Some(Expr::Name {
            id: "None".to_owned(),
            ctx: ExprCtx::Load,
            line: None,
        }),
        is_async: false,
        docstring: Some("greet someone".to_owned()),
        line: Some(1),
    }
}

fn simple_class() -> Stmt {
    Stmt::ClassDef {
        name: "Greeter".to_owned(),
        type_params: Vec::new(),
        bases: vec![Expr::Name {
            id: "object".to_owned(),
            ctx: ExprCtx::Load,
            line: None,
        }],
        keywords: Vec::new(),
        body: vec![Stmt::Assign {
            targets: vec![Expr::Name {
                id: "kind".to_owned(),
                ctx: ExprCtx::Store,
                line: None,
            }],
            value: Expr::Constant {
                value: ConstValue::Str("polite".to_owned()),
                line: None,
            },
            type_comment: None,
            line: Some(5),
        }],
        decorators: Vec::new(),
        docstring: Some("a greeter".to_owned()),
        line: Some(4),
    }
}

#[test]
fn llm_json_schema_has_all_required_fields() {
    let module: AstModule = AstModule {
        docstring: Some("module-level docstring".to_owned()),
        body: vec![simple_function(), simple_class()],
        blank_lines: std::collections::BTreeMap::new(),
    };
    let pipeline: EmitPipeline = EmitPipeline {
        formatter_enabled: false,
        include_provenance: true,
        include_llm_json: true,
        preserve_blank_lines: false,
        ..EmitPipeline::default()
    };
    let out: EmitOutput = pipeline
        .run(&module, &PyVersion::V3_13, Some(Instant::now()))
        .expect("emit ok");
    let sidecar: &Value = out.llm_json.as_ref().expect("llm_json present");

    assert_eq!(
        sidecar.get("schema").and_then(Value::as_str),
        Some(LLM_JSON_SCHEMA_ID)
    );
    assert_eq!(sidecar.get("version").and_then(Value::as_str), Some("3.13"));
    assert!(sidecar.get("source").and_then(Value::as_str).is_some());

    let functions: &Vec<Value> = sidecar
        .get("functions")
        .and_then(Value::as_array)
        .expect("functions array");
    assert_eq!(functions.len(), 1);
    let greet: &Value = &functions[0];
    assert_eq!(greet.get("name").and_then(Value::as_str), Some("greet"));
    assert_eq!(greet.get("qualname").and_then(Value::as_str), Some("greet"));
    assert_eq!(greet.get("is_async").and_then(Value::as_bool), Some(false));
    assert_eq!(
        greet.get("is_generator").and_then(Value::as_bool),
        Some(false)
    );
    assert!(greet.get("args").and_then(Value::as_array).is_some());
    assert!(
        greet
            .get("cyclomatic_complexity")
            .and_then(Value::as_u64)
            .is_some()
    );
    assert_eq!(
        greet.get("docstring").and_then(Value::as_str),
        Some("greet someone")
    );
    let calls: &Vec<Value> = greet
        .get("calls")
        .and_then(Value::as_array)
        .expect("calls array");
    assert!(
        calls.iter().any(|v: &Value| v.as_str() == Some("print")),
        "expected 'print' in calls, got {calls:?}"
    );

    let classes: &Vec<Value> = sidecar
        .get("classes")
        .and_then(Value::as_array)
        .expect("classes array");
    assert_eq!(classes.len(), 1);
    let greeter: &Value = &classes[0];
    assert_eq!(greeter.get("name").and_then(Value::as_str), Some("Greeter"));
    assert_eq!(
        greeter.get("qualname").and_then(Value::as_str),
        Some("Greeter")
    );
    let bases: &Vec<Value> = greeter
        .get("bases")
        .and_then(Value::as_array)
        .expect("bases array");
    assert!(bases.iter().any(|v: &Value| v.as_str() == Some("object")));

    assert_eq!(
        sidecar.get("module_docstring").and_then(Value::as_str),
        Some("module-level docstring")
    );

    assert!(sidecar.get("imports").and_then(Value::as_array).is_some());
    assert!(
        sidecar
            .get("imports_used")
            .and_then(Value::as_array)
            .is_some()
    );
    assert!(
        sidecar
            .get("builtins_used")
            .and_then(Value::as_array)
            .is_some()
    );
    assert!(
        sidecar
            .get("unresolved_externals")
            .and_then(Value::as_array)
            .is_some()
    );
    assert!(
        sidecar
            .get("string_literals")
            .and_then(Value::as_array)
            .is_some()
    );
    let metrics: &Value = sidecar.get("metrics").expect("metrics object");
    assert!(metrics.get("n_functions").and_then(Value::as_u64) == Some(1));
    assert!(metrics.get("n_classes").and_then(Value::as_u64) == Some(1));
    assert!(metrics.get("total_lines").and_then(Value::as_u64).is_some());
    assert!(
        metrics
            .get("avg_cyclomatic")
            .and_then(Value::as_f64)
            .is_some()
    );

    let builtins: &Vec<Value> = sidecar
        .get("builtins_used")
        .and_then(Value::as_array)
        .expect("builtins_used");
    assert!(
        builtins.iter().any(|v: &Value| v.as_str() == Some("print")),
        "print should be recognized as a builtin call target"
    );
}
