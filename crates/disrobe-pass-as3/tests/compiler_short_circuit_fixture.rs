#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;

use disrobe_pass_as3::abc::{
    self, AbcFile, ClassInfo, DisasmLine, MethodBody, MethodInfo, TraitInfo, disasm,
};
use disrobe_pass_as3::lifter::{Expr, LiftedBody, Stmt, lift_body};
use disrobe_pass_as3::swf::{self, DoAbc, Swf, SwfCompression, SymbolClassEntry};

const CLASS_NAME: &str = "WhitespaceShortCircuit";
const METHOD_NAME: &str = "isWhiteSpace";
const HAXE_SOURCE: &str = include_str!("fixtures/WhitespaceShortCircuit.hx");
const PROVENANCE: &str = include_str!("fixtures/whitespace_short_circuit.provenance");
const SWF_BYTES: &[u8] = include_bytes!("fixtures/whitespace_short_circuit.swf");
const EXPECTED_HAXE_SOURCE: &str = "class WhitespaceShortCircuit {\n    static function isWhiteSpace(c:String):Bool {\n        return c == \" \" || c == \"\\t\" || c == \"\\n\" || c == \"\\r\";\n    }\n\n    static function main():Void {\n        trace(isWhiteSpace(\"x\"));\n    }\n}\n";
const EXPECTED_PROVENANCE: &str = "compiler=haxe 4.3.7\ncommand=haxe -cp crates/disrobe-pass-as3/tests/fixtures -main WhitespaceShortCircuit -swf crates/disrobe-pass-as3/tests/fixtures/whitespace_short_circuit.swf\ngenerated=2026-08-01\n";

fn expected_whitespace() -> BTreeSet<&'static str> {
    [" ", "\t", "\n", "\r"].into_iter().collect()
}

fn parse_fixture() -> AbcFile {
    assert_eq!(
        SWF_BYTES.get(..3),
        Some(b"CWS".as_slice()),
        "the committed Haxe fixture must remain zlib-compressed SWF output"
    );
    assert_eq!(
        HAXE_SOURCE, EXPECTED_HAXE_SOURCE,
        "the pre-compilation source changed; regenerate and revalidate the committed fixture"
    );
    assert_eq!(
        PROVENANCE, EXPECTED_PROVENANCE,
        "the compiler provenance changed; regenerate and revalidate the committed fixture"
    );

    let swf: Swf = swf::parse(SWF_BYTES).expect("the committed Haxe SWF must parse");
    assert_eq!(swf.header.compression, SwfCompression::Zlib);
    assert!(
        swf.file_attributes()
            .expect("the committed Haxe SWF must carry FileAttributes")
            .action_script3,
        "the committed fixture must remain ActionScript 3"
    );
    let symbols: Vec<SymbolClassEntry> = swf.symbol_classes();
    assert_eq!(
        symbols.len(),
        1,
        "the compiler output must bind one document class through SymbolClass, got {symbols:?}"
    );

    let blocks: Vec<DoAbc> = swf.collect_do_abc();
    assert_eq!(
        blocks.len(),
        1,
        "the dedicated compiler fixture must carry exactly one ABC payload"
    );
    abc::parse(&blocks[0].abc_bytes).expect("the committed Haxe ABC must parse")
}

fn target_method(abc: &AbcFile) -> (&MethodBody, &MethodInfo) {
    assert_eq!(
        abc.instances.len(),
        abc.classes.len(),
        "the ABC class and instance tables must remain parallel"
    );
    let class_indices: Vec<usize> = abc
        .instances
        .iter()
        .enumerate()
        .filter_map(|(index, instance)| {
            let name: String = abc
                .cpool
                .render_multiname(instance.name_index)
                .expect("the fixture instance name must render");
            (name == CLASS_NAME).then_some(index)
        })
        .collect();
    assert_eq!(
        class_indices.len(),
        1,
        "the fixture must define exactly one {CLASS_NAME} instance, found {class_indices:?}"
    );
    let class_index: usize = *class_indices
        .first()
        .expect("the pinned class index must exist");
    let class: &ClassInfo = abc
        .classes
        .get(class_index)
        .expect("the pinned class must have static traits");
    let methods: Vec<&TraitInfo> = class
        .traits
        .iter()
        .filter(|trait_info| trait_info.kind & 0x0F == 1)
        .filter(|trait_info| {
            let name: String = abc
                .cpool
                .render_multiname_property(trait_info.name_index)
                .expect("the fixture static method name must render");
            name == METHOD_NAME
        })
        .collect();
    assert_eq!(
        methods.len(),
        1,
        "the fixture must expose exactly one {CLASS_NAME}::{METHOD_NAME} static method"
    );
    let method: &TraitInfo = methods
        .first()
        .expect("the pinned static method trait must exist");
    let bodies: Vec<&MethodBody> = abc
        .method_bodies
        .iter()
        .filter(|body| body.method == method.method_index)
        .collect();
    assert_eq!(
        bodies.len(),
        1,
        "the pinned static method must have exactly one method body"
    );
    let body: &MethodBody = bodies
        .first()
        .expect("the pinned static method body must exist");
    let method_index: usize =
        usize::try_from(method.method_index).expect("the pinned method index must fit in usize");
    let info: &MethodInfo = abc
        .methods
        .get(method_index)
        .expect("the pinned static method must have method metadata");
    (body, info)
}

fn assert_compiler_short_circuit_shape(body: &MethodBody) {
    let lines: Vec<DisasmLine> = disasm(&body.code).expect("the pinned method must disassemble");
    let branches: Vec<&DisasmLine> = lines
        .iter()
        .filter(|line| (0x0C..=0x0F).contains(&line.opcode) || (0x11..=0x1A).contains(&line.opcode))
        .collect();
    assert_eq!(
        branches.len(),
        3,
        "the four-way OR must compile into three conditional short-circuit branches: {lines:#?}"
    );
    assert_eq!(
        branches
            .iter()
            .map(|line| line.mnemonic)
            .collect::<Vec<&str>>(),
        vec!["ifeq", "iftrue", "iffalse"],
        "the Haxe 4.3.7 lowering shape changed: {branches:#?}"
    );
    assert!(
        branches
            .iter()
            .all(|line| matches!(line.operands.as_slice(), [target] if *target > 0)),
        "every compiler branch must be forward: {branches:#?}"
    );
    assert_eq!(
        lines.iter().filter(|line| line.opcode == 0x29).count(),
        2,
        "the compiler lowering must discard two failed short-circuit values"
    );
}

fn recovered_statements(lifted: &LiftedBody) -> Result<&[Stmt], String> {
    if !lifted.structurally_recovered {
        return Err(format!(
            "structural recovery was partial: {:?}",
            lifted.fidelity_warning()
        ));
    }
    if !lifted.fully_structured {
        return Err("recovery retained raw control flow".to_owned());
    }
    if !lifted.reached_terminator {
        return Err("recovery did not reach a terminator".to_owned());
    }
    if !lifted.dropped_opcodes.is_empty() {
        return Err(format!(
            "recovery dropped opcodes: {:?}",
            lifted.dropped_opcodes
        ));
    }
    if lifted.opaque_operands != 0 {
        return Err(format!(
            "recovery produced {} opaque operand(s)",
            lifted.opaque_operands
        ));
    }
    Ok(&lifted.statements)
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

fn whitespace_predicate_leaves(statements: &[Stmt]) -> Result<Vec<&Expr>, String> {
    let [
        Stmt::IfBlock {
            cond: Expr::Unary {
                op: "!", operand, ..
            },
            body,
        },
        Stmt::Return(Some(Expr::BoolLit(true))),
    ] = statements
    else {
        return Err(format!(
            "the Haxe predicate must retain its guarded final comparison and true fallback: {statements:#?}"
        ));
    };
    let [Stmt::Return(Some(final_comparison))] = body.as_slice() else {
        return Err(format!(
            "the guarded path must return exactly one final comparison: {body:#?}"
        ));
    };
    let mut leaves: Vec<&Expr> = Vec::new();
    flatten_or(operand, &mut leaves);
    leaves.push(final_comparison);
    Ok(leaves)
}

fn is_input_parameter(expression: &Expr) -> bool {
    match expression {
        Expr::Local(1) | Expr::Param(1) => true,
        Expr::Coerce { operand, .. } => is_input_parameter(operand),
        _ => false,
    }
}

fn strip_boolean_coercion(expression: &Expr) -> &Expr {
    match expression {
        Expr::Coerce { ty, operand } if ty == "Boolean" => strip_boolean_coercion(operand),
        _ => expression,
    }
}

fn comparison_literal(expression: &Expr) -> Result<&str, String> {
    let expression: &Expr = strip_boolean_coercion(expression);
    match expression {
        Expr::Binary { op: "==", lhs, rhs } if is_input_parameter(lhs) => match rhs.as_ref() {
            Expr::StringLit(value) => Ok(value),
            _ => Err(format!(
                "comparison right operand was not a string literal: {expression:?}"
            )),
        },
        Expr::Binary { op: "==", lhs, rhs } if is_input_parameter(rhs) => match lhs.as_ref() {
            Expr::StringLit(value) => Ok(value),
            _ => Err(format!(
                "comparison left operand was not a string literal: {expression:?}"
            )),
        },
        _ => Err(format!(
            "short-circuit leaf was not an equality against the input parameter: {expression:?}"
        )),
    }
}

fn check_whitespace_predicate(
    lifted: &LiftedBody,
    expected_literals: &BTreeSet<&str>,
) -> Result<(), String> {
    let statements: &[Stmt] = recovered_statements(lifted)?;
    let leaves: Vec<&Expr> = whitespace_predicate_leaves(statements)?;
    if leaves.len() != expected_literals.len() {
        return Err(format!(
            "expected {} equality leaves, found {}: {leaves:#?}",
            expected_literals.len(),
            leaves.len()
        ));
    }
    let mut actual_literals: BTreeSet<&str> = BTreeSet::new();
    for leaf in leaves {
        let literal: &str = comparison_literal(leaf)?;
        if !actual_literals.insert(literal) {
            return Err(format!("duplicate whitespace literal {literal:?}"));
        }
    }
    if &actual_literals != expected_literals {
        return Err(format!(
            "whitespace literal set changed: expected {expected_literals:?}, got {actual_literals:?}"
        ));
    }
    Ok(())
}

fn lifted_whitespace_predicate() -> LiftedBody {
    let abc: AbcFile = parse_fixture();
    let (body, info): (&MethodBody, &MethodInfo) = target_method(&abc);
    assert_compiler_short_circuit_shape(body);
    lift_body(&abc, body, Some(info)).expect("the compiler-emitted predicate must lift")
}

fn replace_final_carriage_return(lifted: &mut LiftedBody) {
    let [
        Stmt::IfBlock { body, .. },
        Stmt::Return(Some(Expr::BoolLit(true))),
    ] = lifted.statements.as_mut_slice()
    else {
        panic!("the mutation requires the pinned Haxe early-return shape");
    };
    let [Stmt::Return(Some(Expr::Binary { op: "==", rhs, .. }))] = body.as_mut_slice() else {
        panic!("the mutation requires the final whitespace comparison");
    };
    assert!(
        matches!(rhs.as_ref(), Expr::StringLit(value) if value == "\r"),
        "the mutation must replace the carriage-return comparison"
    );
    **rhs = Expr::StringLit("x".to_owned());
}

#[test]
fn compiler_emitted_four_way_whitespace_predicate_keeps_every_operand() {
    let lifted: LiftedBody = lifted_whitespace_predicate();
    let expected: BTreeSet<&str> = expected_whitespace();
    let result: Result<(), String> = check_whitespace_predicate(&lifted, &expected);
    assert!(result.is_ok(), "{result:?}\n{:#?}", lifted.statements);
}

#[test]
fn whitespace_predicate_grader_rejects_a_corrupted_carriage_return_operand() {
    let mut corrupted: LiftedBody = lifted_whitespace_predicate();
    replace_final_carriage_return(&mut corrupted);
    let expected: BTreeSet<&str> = expected_whitespace();
    let result: Result<(), String> = check_whitespace_predicate(&corrupted, &expected);
    let error: String = result.expect_err("the corrupted carriage-return operand must be rejected");
    assert!(
        error.contains("\\r"),
        "the grader must report the missing carriage-return operand, got: {error}"
    );
}
