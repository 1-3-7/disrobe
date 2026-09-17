#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_as3::abc::{
    self, AbcFile, ClassInfo, DisasmLine, InstanceInfo, MethodBody, MethodInfo, TraitInfo, disasm,
};
use disrobe_pass_as3::lifter::{Expr, LiftedBody, Stmt, lift_body};
use disrobe_pass_as3::swf::{self, DoAbc, Swf};

const CLASS_NAME: &str = "JsonTokenizer";
const METHOD_NAME: &str = "nextChar";
const HAXE_SOURCE: &str = include_str!("fixtures/JsonTokenizer.hx");
const PROVENANCE: &str = include_str!("fixtures/json_tokenizer_postincrement.provenance");
const SWF_BYTES: &[u8] = include_bytes!("fixtures/json_tokenizer_postincrement.swf");
const EXPECTED_HAXE_SOURCE: &str = "class JsonTokenizer {\n    static function nextChar(chars:Array<String>, index:Int):String {\n        return chars[index++];\n    }\n\n    static function main():Void {\n        trace(nextChar([\"a\", \"b\"], 0));\n    }\n}\n";
const EXPECTED_PROVENANCE: &str = "compiler=haxe 4.3.7\ncommand=haxe -cp crates/disrobe-pass-as3/tests/fixtures -main JsonTokenizer -swf crates/disrobe-pass-as3/tests/fixtures/json_tokenizer_postincrement.swf\ngenerated=2026-08-01\n";

fn parse_fixture() -> AbcFile {
    assert_eq!(
        HAXE_SOURCE, EXPECTED_HAXE_SOURCE,
        "the pre-compilation source changed; regenerate and revalidate the committed fixture"
    );
    assert_eq!(
        PROVENANCE, EXPECTED_PROVENANCE,
        "the compiler provenance changed; regenerate and revalidate the committed fixture"
    );
    assert_eq!(
        SWF_BYTES.get(..3),
        Some(b"CWS".as_slice()),
        "the committed Haxe fixture must remain compiler-emitted compressed SWF"
    );
    let swf: Swf = swf::parse(SWF_BYTES).expect("the committed Haxe SWF must parse");
    let blocks: Vec<DoAbc> = swf.collect_do_abc();
    assert_eq!(
        blocks.len(),
        1,
        "the dedicated compiler fixture must carry exactly one ABC payload"
    );
    abc::parse(&blocks[0].abc_bytes).expect("the committed Haxe ABC must parse")
}

fn target_method(abc: &AbcFile) -> (&MethodBody, &MethodInfo) {
    let class_indices: Vec<usize> = abc
        .instances
        .iter()
        .enumerate()
        .filter_map(|(index, instance): (usize, &InstanceInfo)| {
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
        "the fixture must define exactly one {CLASS_NAME} instance"
    );
    let class_index: usize = class_indices[0];
    let class: &ClassInfo = abc
        .classes
        .get(class_index)
        .expect("the pinned class must have static traits");
    let methods: Vec<&TraitInfo> = class
        .traits
        .iter()
        .filter(|trait_info: &&TraitInfo| trait_info.kind & 0x0F == 1)
        .filter(|trait_info: &&TraitInfo| {
            let name: String = abc
                .cpool
                .render_multiname_property(trait_info.name_index)
                .expect("the fixture method name must render");
            name == METHOD_NAME
        })
        .collect();
    assert_eq!(
        methods.len(),
        1,
        "the fixture must expose exactly one {CLASS_NAME}::{METHOD_NAME} static method"
    );
    let method: &TraitInfo = methods[0];
    let bodies: Vec<&MethodBody> = abc
        .method_bodies
        .iter()
        .filter(|body: &&MethodBody| body.method == method.method_index)
        .collect();
    assert_eq!(
        bodies.len(),
        1,
        "the pinned static method must have exactly one method body"
    );
    let method_index: usize =
        usize::try_from(method.method_index).expect("the pinned method index must fit in usize");
    let info: &MethodInfo = abc
        .methods
        .get(method_index)
        .expect("the pinned method must have metadata");
    (bodies[0], info)
}

fn assert_compiler_postincrement_shape(body: &MethodBody) {
    let lines: Vec<DisasmLine> = disasm(&body.code).expect("the pinned method must disassemble");
    let meaningful: Vec<&str> = lines
        .iter()
        .filter(|line: &&DisasmLine| !matches!(line.opcode, 0xEF..=0xF3))
        .map(|line: &DisasmLine| line.mnemonic)
        .collect();
    assert_eq!(
        meaningful,
        vec![
            "getlocal_1",
            "getlocal_2",
            "inclocal_i",
            "getproperty",
            "coerce",
            "returnvalue"
        ],
        "the Haxe 4.3.7 postfix-index lowering shape changed: {lines:#?}"
    );
}

fn strip_coercion(expression: &Expr) -> &Expr {
    match expression {
        Expr::Coerce { operand, .. } => strip_coercion(operand),
        _ => expression,
    }
}

fn is_parameter(expression: &Expr, slot: u32) -> bool {
    matches!(strip_coercion(expression), Expr::Local(index) | Expr::Param(index) if *index == slot)
}

fn check_postincrement(lifted: &LiftedBody) -> Result<(), String> {
    if !lifted.structurally_recovered
        || !lifted.fully_structured
        || !lifted.reached_terminator
        || !lifted.dropped_opcodes.is_empty()
        || lifted.opaque_operands != 0
    {
        return Err(format!(
            "the compiler method was not recovered completely: {:?}",
            lifted.fidelity_warning()
        ));
    }
    let [Stmt::Return(Some(value))] = lifted.statements.as_slice() else {
        return Err(format!(
            "the method must recover as one return statement: {:#?}",
            lifted.statements
        ));
    };
    let Expr::Index { object, index } = strip_coercion(value) else {
        return Err(format!(
            "the return value must remain an indexed read: {value:?}"
        ));
    };
    if !is_parameter(object, 1) {
        return Err(format!(
            "the indexed object must be the chars parameter: {object:?}"
        ));
    }
    let Expr::Update {
        op: "++",
        operand,
        postfix: true,
    } = strip_coercion(index)
    else {
        return Err(format!(
            "the index must be one postfix increment expression: {index:?}"
        ));
    };
    if !is_parameter(operand, 2) {
        return Err(format!(
            "the postfix update must target the index parameter: {operand:?}"
        ));
    }
    Ok(())
}

fn lifted_postincrement() -> LiftedBody {
    let abc: AbcFile = parse_fixture();
    let (body, info): (&MethodBody, &MethodInfo) = target_method(&abc);
    assert_compiler_postincrement_shape(body);
    lift_body(&abc, body, Some(info)).expect("the compiler-emitted method must lift")
}

fn change_postfix_to_prefix(expression: &mut Expr) -> bool {
    match expression {
        Expr::Coerce { operand, .. } => change_postfix_to_prefix(operand),
        Expr::Index { index, .. } => change_postfix_to_prefix(index),
        Expr::Update {
            op: "++", postfix, ..
        } => {
            assert!(*postfix, "the mutation requires a postfix update");
            *postfix = false;
            true
        }
        _ => false,
    }
}

#[test]
fn compiler_emitted_index_postincrement_is_recovered_once_with_old_value_semantics() {
    let lifted: LiftedBody = lifted_postincrement();
    let result: Result<(), String> = check_postincrement(&lifted);
    assert!(result.is_ok(), "{result:?}\n{:#?}", lifted.statements);
}

#[test]
fn postincrement_grader_rejects_prefix_update_semantics() {
    let mut corrupted: LiftedBody = lifted_postincrement();
    let [Stmt::Return(Some(value))] = corrupted.statements.as_mut_slice() else {
        panic!("the mutation requires the pinned one-return shape");
    };
    assert!(
        change_postfix_to_prefix(value),
        "the mutation must change the recovered update"
    );
    let result: Result<(), String> = check_postincrement(&corrupted);
    let error: String = result.expect_err("a prefix update must fail the postfix grader");
    assert!(
        error.contains("postfix increment"),
        "the grader must identify the wrong update semantics: {error}"
    );
}
