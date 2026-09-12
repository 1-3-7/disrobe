#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;

use disrobe_pass_as3::abc::{
    self, AbcFile, ConstantPool, DisasmLine, InstanceInfo, MethodBody, MethodInfo, TraitInfo,
    disasm,
};
use disrobe_pass_as3::lifter::{Expr, LiftedBody, Stmt, lift_body};
use disrobe_pass_as3::swf::{self, DoAbc, Swf};

const FIXTURE_NAME: &str = "BO_Twin_Drivers_Level_9000.swf";
const CLASS_NAME: &str = "com.adobe.serialization.json.JSONTokenizer";
const METHOD_NAME: &str = "isWhiteSpace";
const EXPECTED_LITERALS: [&str; 4] = [" ", "\t", "\n", "\r"];

fn target_method(abc: &AbcFile) -> Option<(&MethodBody, &MethodInfo)> {
    let instance_index: usize = abc.instances.iter().position(|instance: &InstanceInfo| {
        abc.cpool
            .render_multiname(instance.name_index)
            .is_ok_and(|name: String| name == CLASS_NAME)
    })?;
    let method: &TraitInfo =
        abc.instances[instance_index]
            .traits
            .iter()
            .find(|trait_info: &&TraitInfo| {
                trait_info.kind & 0x0f == 1
                    && abc
                        .cpool
                        .render_multiname_property(trait_info.name_index)
                        .is_ok_and(|name: String| name == METHOD_NAME)
            })?;
    let body: &MethodBody = abc
        .method_bodies
        .iter()
        .find(|body: &&MethodBody| body.method == method.method_index)?;
    let method_index: usize = usize::try_from(method.method_index).ok()?;
    let info: &MethodInfo = abc.methods.get(method_index)?;
    Some((body, info))
}

fn flatten_or<'a>(expression: &'a Expr, leaves: &mut Vec<&'a Expr>) {
    match expression {
        Expr::Binary {
            op: "||", lhs, rhs, ..
        } => {
            flatten_or(lhs, leaves);
            flatten_or(rhs, leaves);
        }
        _ => leaves.push(expression),
    }
}

fn comparison_literal(expression: &Expr) -> Result<&str, String> {
    match expression {
        Expr::Binary { op: "==", lhs, rhs }
            if matches!(lhs.as_ref(), Expr::Local(1) | Expr::Param(1)) =>
        {
            match rhs.as_ref() {
                Expr::StringLit(value) => Ok(value),
                other => Err(format!("right operand is not a string literal: {other:?}")),
            }
        }
        other => Err(format!(
            "short-circuit leaf is not an equality against local 1: {other:?}"
        )),
    }
}

fn recovered_literals(lifted: &LiftedBody) -> Result<Vec<&str>, String> {
    if !lifted.structurally_recovered
        || !lifted.fully_structured
        || !lifted.reached_terminator
        || !lifted.dropped_opcodes.is_empty()
        || lifted.opaque_operands != 0
    {
        return Err(format!("recovery is incomplete: {lifted:#?}"));
    }
    let [Stmt::Return(Some(expression))] = lifted.statements.as_slice() else {
        return Err(format!(
            "predicate is not one returned expression: {:#?}",
            lifted.statements
        ));
    };
    let mut leaves: Vec<&Expr> = Vec::new();
    flatten_or(expression, &mut leaves);
    leaves.into_iter().map(comparison_literal).collect()
}

fn assert_short_circuit_shape(body: &MethodBody) {
    let lines: Vec<DisasmLine> = disasm(&body.code).expect("predicate must disassemble");
    let branches: Vec<&DisasmLine> = lines
        .iter()
        .filter(|line: &&DisasmLine| line.opcode == 0x11)
        .collect();
    assert_eq!(branches.len(), 3, "{lines:#?}");
    assert!(
        branches
            .iter()
            .all(|line: &&DisasmLine| matches!(line.operands.as_slice(), [target] if *target > 0)),
        "{branches:#?}"
    );
    assert_eq!(
        lines
            .iter()
            .filter(|line: &&DisasmLine| line.opcode == 0x2A)
            .count(),
        3,
        "{lines:#?}"
    );
    assert_eq!(
        lines
            .iter()
            .filter(|line: &&DisasmLine| line.opcode == 0x29)
            .count(),
        3,
        "{lines:#?}"
    );
}

fn encoded_abc() -> (AbcFile, MethodBody) {
    let code: Vec<u8> = vec![
        0xD1, 0x2C, 0x01, 0xAB, 0x2A, 0x11, 0x05, 0x00, 0x00, 0x29, 0xD1, 0x2C, 0x02, 0xAB, 0x2A,
        0x11, 0x05, 0x00, 0x00, 0x29, 0xD1, 0x2C, 0x03, 0xAB, 0x2A, 0x11, 0x05, 0x00, 0x00, 0x29,
        0xD1, 0x2C, 0x04, 0xAB, 0x48,
    ];
    let abc: AbcFile = AbcFile {
        minor: abc::ABC_MINOR,
        major: abc::ABC_MAJOR,
        cpool: ConstantPool {
            strings: vec![
                String::new(),
                " ".to_owned(),
                "\t".to_owned(),
                "\n".to_owned(),
                "\r".to_owned(),
            ],
            ..ConstantPool::default()
        },
        methods: Vec::new(),
        metadata_count: 0,
        instances: Vec::new(),
        classes: Vec::new(),
        scripts: Vec::new(),
        method_bodies: Vec::new(),
    };
    let body: MethodBody = MethodBody {
        method: 0,
        max_stack: 2,
        local_count: 2,
        init_scope_depth: 0,
        max_scope_depth: 0,
        code,
        exceptions: Vec::new(),
        traits: Vec::new(),
    };
    (abc, body)
}

#[test]
fn encoded_four_way_or_preserves_every_operand_in_evaluation_order() {
    let (abc, body): (AbcFile, MethodBody) = encoded_abc();
    assert_short_circuit_shape(&body);
    let lifted: LiftedBody = lift_body(&abc, &body, None).expect("encoded predicate must lift");
    let literals: Vec<&str> = recovered_literals(&lifted).unwrap_or_else(|error: String| {
        panic!("{error}");
    });
    assert_eq!(literals, EXPECTED_LITERALS);
}

#[test]
fn real_json_tokenizer_preserves_every_whitespace_operand() {
    let root: PathBuf = common::as3_corpus_root();
    if !common::require_corpus_fixture("JSONTokenizer short-circuit recovery", &root, FIXTURE_NAME)
    {
        return;
    }
    let bytes: Vec<u8> = std::fs::read(root.join(FIXTURE_NAME)).expect("corpus fixture must read");
    let swf: Swf = swf::parse(&bytes).expect("corpus fixture must parse");
    let mut recovered_methods: usize = 0;
    for block in swf.collect_do_abc() {
        let block: DoAbc = block;
        let abc: AbcFile = abc::parse(&block.abc_bytes).expect("corpus ABC must parse");
        let Some((body, info)): Option<(&MethodBody, &MethodInfo)> = target_method(&abc) else {
            continue;
        };
        assert_short_circuit_shape(body);
        let lifted: LiftedBody = lift_body(&abc, body, Some(info)).expect("predicate must lift");
        let literals: Vec<&str> = recovered_literals(&lifted).unwrap_or_else(|error: String| {
            panic!("{error}");
        });
        assert_eq!(literals, EXPECTED_LITERALS);
        recovered_methods += 1;
    }
    assert_eq!(recovered_methods, 1);
}
