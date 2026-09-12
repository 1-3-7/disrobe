#![allow(clippy::expect_used)]
use std::collections::BTreeMap;
use std::time::Instant;

use disrobe_pass_py_decompile::ast::{AstModule, ConstValue, Expr, ExprCtx, Stmt};
use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::emit::{EmitOutput, EmitPipeline};

fn assign(name: &str, n: i128, line: u32) -> Stmt {
    Stmt::Assign {
        targets: vec![Expr::Name {
            id: name.to_owned(),
            ctx: ExprCtx::Store,
            line: Some(line),
        }],
        value: Expr::Constant {
            value: ConstValue::Int(n),
            line: Some(line),
        },
        type_comment: None,
        line: Some(line),
    }
}

#[test]
fn preserve_blank_lines_inserts_blanks_per_map() {
    let mut blanks: BTreeMap<u32, u8> = BTreeMap::new();
    blanks.insert(3, 2);
    blanks.insert(5, 1);
    let module: AstModule = AstModule {
        docstring: None,
        body: vec![assign("a", 1, 1), assign("b", 2, 3), assign("c", 3, 5)],
        blank_lines: blanks,
    };
    let pipeline: EmitPipeline = EmitPipeline {
        formatter_enabled: false,
        include_provenance: false,
        include_llm_json: false,
        preserve_blank_lines: true,
        ..EmitPipeline::default()
    };
    let out: EmitOutput = pipeline
        .run(&module, &PyVersion::V3_13, Some(Instant::now()))
        .expect("emit ok");
    let src: &str = &out.source;

    let body_start: usize = src.find("a = 1").expect("a = 1 present");
    let b_pos: usize = src.find("b = 2").expect("b = 2 present");
    let c_pos: usize = src.find("c = 3").expect("c = 3 present");
    let between_a_b: &str = &src[body_start + "a = 1".len()..b_pos];
    let between_b_c: &str = &src[b_pos + "b = 2".len()..c_pos];

    let blanks_a_b: usize = between_a_b.matches('\n').count();
    let blanks_b_c: usize = between_b_c.matches('\n').count();

    assert!(
        blanks_a_b >= 3,
        "expected >=3 newlines between a and b (1 sep + 2 blanks), got {blanks_a_b}: {between_a_b:?}"
    );
    assert!(
        blanks_b_c >= 2,
        "expected >=2 newlines between b and c (1 sep + 1 blank), got {blanks_b_c}: {between_b_c:?}"
    );
}

#[test]
fn preserve_blank_lines_disabled_emits_no_blanks() {
    let mut blanks: BTreeMap<u32, u8> = BTreeMap::new();
    blanks.insert(3, 5);
    let module: AstModule = AstModule {
        docstring: None,
        body: vec![assign("a", 1, 1), assign("b", 2, 3)],
        blank_lines: blanks,
    };
    let pipeline: EmitPipeline = EmitPipeline {
        formatter_enabled: false,
        include_provenance: false,
        include_llm_json: false,
        preserve_blank_lines: false,
        ..EmitPipeline::default()
    };
    let out: EmitOutput = pipeline
        .run(&module, &PyVersion::V3_13, Some(Instant::now()))
        .expect("emit ok");
    let src: &str = &out.source;
    let a_pos: usize = src.find("a = 1").expect("a = 1 present");
    let b_pos: usize = src.find("b = 2").expect("b = 2 present");
    let between: &str = &src[a_pos + "a = 1".len()..b_pos];
    let blank_count: usize = between.matches('\n').count();
    assert_eq!(
        blank_count, 1,
        "expected exactly 1 separator newline between stmts, got {blank_count}: {between:?}"
    );
}
