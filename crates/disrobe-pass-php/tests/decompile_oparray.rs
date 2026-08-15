#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    unreachable_pub,
    dead_code,
    clippy::print_stdout,
    clippy::redundant_pub_crate,
    clippy::std_instead_of_alloc,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo
)]

use disrobe_pass_php::decompile::op;
use disrobe_pass_php::{
    Branch, Decompilation, Fidelity, OPARRAY_MAGIC, OPARRAY_VERSION, OpArray, OperandType,
    UnrecoveredOp, build_cfg, decompile_oparray, opcode_name, parse_oparray,
};

const T_UNUSED: u8 = 0;
const T_CONST: u8 = 1;
const T_TMP: u8 = 2;
const T_VAR: u8 = 4;
const T_CV: u8 = 8;

const K_MAIN: u8 = 0;
const K_FUNCTION: u8 = 1;
const K_METHOD: u8 = 2;

const L_NULL: u8 = 0;
const L_BOOL: u8 = 1;
const L_LONG: u8 = 2;
const L_DOUBLE: u8 = 3;
const L_STR: u8 = 4;

#[derive(Default)]
struct OpArrayBuilder {
    kind: u8,
    name: Option<String>,
    class_name: Option<String>,
    num_args: u32,
    var_names: Vec<Option<String>>,
    literals: Vec<u8>,
    literal_count: u32,
    ops: Vec<u8>,
    op_count: u32,
    children: Vec<Vec<u8>>,
}

impl OpArrayBuilder {
    fn main() -> Self {
        Self {
            kind: K_MAIN,
            ..Self::default()
        }
    }

    fn function(name: &str, num_args: u32) -> Self {
        Self {
            kind: K_FUNCTION,
            name: Some(name.to_owned()),
            num_args,
            ..Self::default()
        }
    }

    fn method(class: &str, name: &str, num_args: u32) -> Self {
        Self {
            kind: K_METHOD,
            name: Some(name.to_owned()),
            class_name: Some(class.to_owned()),
            num_args,
            ..Self::default()
        }
    }

    fn var(&mut self, name: &str) -> &mut Self {
        self.var_names.push(Some(name.to_owned()));
        self
    }

    fn lit_str(&mut self, s: &str) -> u32 {
        let idx: u32 = self.literal_count;
        self.literals.push(L_STR);
        push_string(&mut self.literals, s);
        self.literal_count += 1;
        idx
    }

    fn lit_long(&mut self, n: i64) -> u32 {
        let idx: u32 = self.literal_count;
        self.literals.push(L_LONG);
        self.literals.extend_from_slice(&n.to_le_bytes());
        self.literal_count += 1;
        idx
    }

    fn lit_null(&mut self) -> u32 {
        let idx: u32 = self.literal_count;
        self.literals.push(L_NULL);
        self.literal_count += 1;
        idx
    }

    #[allow(clippy::too_many_arguments)]
    fn op(
        &mut self,
        opcode: u8,
        op1_type: u8,
        op2_type: u8,
        result_type: u8,
        op1: u32,
        op2: u32,
        result: u32,
        extended_value: u32,
        lineno: u32,
    ) -> &mut Self {
        self.ops.push(opcode);
        self.ops.push(op1_type);
        self.ops.push(op2_type);
        self.ops.push(result_type);
        self.ops.extend_from_slice(&op1.to_le_bytes());
        self.ops.extend_from_slice(&op2.to_le_bytes());
        self.ops.extend_from_slice(&result.to_le_bytes());
        self.ops.extend_from_slice(&extended_value.to_le_bytes());
        self.ops.extend_from_slice(&lineno.to_le_bytes());
        self.op_count += 1;
        self
    }

    fn child(&mut self, built: Vec<u8>) -> &mut Self {
        self.children.push(built);
        self
    }

    fn build_body(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.push(self.kind);
        push_opt_string(&mut out, self.name.as_deref());
        push_opt_string(&mut out, self.class_name.as_deref());
        out.extend_from_slice(&self.num_args.to_le_bytes());
        out.extend_from_slice(&(self.var_names.len() as u32).to_le_bytes());
        for name in &self.var_names {
            push_opt_string(&mut out, name.as_deref());
        }
        out.extend_from_slice(&self.literal_count.to_le_bytes());
        out.extend_from_slice(&self.literals);
        out.extend_from_slice(&self.op_count.to_le_bytes());
        out.extend_from_slice(&self.ops);
        out.extend_from_slice(&(self.children.len() as u32).to_le_bytes());
        for c in &self.children {
            out.extend_from_slice(c);
        }
        out
    }

    fn build_container(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(OPARRAY_MAGIC);
        out.push(OPARRAY_VERSION);
        out.extend_from_slice(&self.build_body());
        out
    }
}

fn push_string(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn push_opt_string(out: &mut Vec<u8>, s: Option<&str>) {
    match s {
        Some(v) => {
            out.push(1);
            push_string(out, v);
        }
        None => out.push(0),
    }
}

#[test]
fn operand_type_wire_values_are_the_single_bit_lattice_the_container_declares() {
    assert_eq!(OperandType::from_wire(T_UNUSED), Some(OperandType::Unused));
    assert_eq!(OperandType::from_wire(T_CONST), Some(OperandType::Const));
    assert_eq!(OperandType::from_wire(T_TMP), Some(OperandType::TmpVar));
    assert_eq!(OperandType::from_wire(T_VAR), Some(OperandType::Var));
    assert_eq!(OperandType::from_wire(T_CV), Some(OperandType::Cv));
    assert_eq!(OperandType::from_wire(3), None);
    assert_eq!(OperandType::from_wire(255), None);
    for (wire, next) in [(T_CONST, T_TMP), (T_TMP, T_VAR), (T_VAR, T_CV)] {
        assert_eq!(
            wire * 2,
            next,
            "the operand kinds occupy one bit each and ascend in order, so a value that is not \
             twice its predecessor would collide with a combination of the others"
        );
    }
}

#[test]
fn every_opcode_constant_is_named_with_its_zend_mnemonic_in_this_table() {
    assert_eq!(opcode_name(op::ECHO), "ZEND_ECHO");
    assert_eq!(opcode_name(op::ASSIGN), "ZEND_ASSIGN");
    assert_eq!(opcode_name(op::JMPZ), "ZEND_JMPZ");
    assert_eq!(opcode_name(op::RETURN), "ZEND_RETURN");
    assert_eq!(opcode_name(op::INIT_FCALL), "ZEND_INIT_FCALL");
    assert_eq!(opcode_name(op::FE_FETCH_R), "ZEND_FE_FETCH_R");
    assert_eq!(opcode_name(op::YIELD_FROM), "ZEND_YIELD_FROM");
    assert_eq!(opcode_name(op::GENERATOR_CREATE), "ZEND_GENERATOR_CREATE");
}

#[test]
fn parses_minimal_main_oparray_and_reports_partial_fidelity() {
    let mut b: OpArrayBuilder = OpArrayBuilder::main();
    let hello: u32 = b.lit_str("hello world");
    b.op(op::ECHO, T_CONST, T_UNUSED, T_UNUSED, hello, 0, 0, 0, 1);
    b.op(op::RETURN, T_CONST, T_UNUSED, T_UNUSED, 0, 0, 0, 0, 1);
    let bytes: Vec<u8> = b.build_container();

    let parsed = parse_oparray(&bytes).expect("parse oparray");
    assert_eq!(parsed.ops.len(), 2);
    assert_eq!(parsed.literals.len(), 1);
    assert_eq!(parsed.literals[0].as_str(), Some("hello world"));

    let decomp: Decompilation = decompile_oparray(&parsed);
    assert_eq!(decomp.fidelity, Fidelity::Partial);
    assert!(
        decomp.php_skeleton.contains("echo 'hello world';"),
        "skeleton: {}",
        decomp.php_skeleton
    );
}

#[test]
fn rejects_bad_magic_and_truncation_without_panic() {
    let err = parse_oparray(b"XXXX\x01rest").expect_err("bad magic");
    assert!(format!("{err}").contains("DR-PHP-0090"), "{err}");

    let err2 = parse_oparray(&[]).expect_err("empty");
    assert!(format!("{err2}").contains("DR-PHP-0092"), "{err2}");

    let mut short: Vec<u8> = Vec::new();
    short.extend_from_slice(OPARRAY_MAGIC);
    short.push(OPARRAY_VERSION);
    short.push(K_MAIN);
    let err3 = parse_oparray(&short).expect_err("truncated body");
    assert!(format!("{err3}").contains("DR-PHP-0092"), "{err3}");
}

#[test]
fn generator_yield_forms_recover_as_php_expressions() {
    let mut generator: OpArrayBuilder = OpArrayBuilder::function("values", 1);
    generator.var("items");
    generator.var("received");
    let label: u32 = generator.lit_str("label");
    generator.op(op::YIELD, T_CONST, T_UNUSED, T_UNUSED, label, 0, 0, 0, 2);
    generator.op(op::YIELD, T_CV, T_CONST, T_TMP, 0, label, 4, 0, 3);
    generator.op(op::ASSIGN, T_CV, T_TMP, T_UNUSED, 1, 4, 0, 0, 3);
    generator.op(op::YIELD_FROM, T_CV, T_UNUSED, T_TMP, 0, 0, 5, 0, 4);
    generator.op(op::ASSIGN, T_CV, T_TMP, T_UNUSED, 1, 5, 0, 0, 4);
    generator.op(
        op::GENERATOR_RETURN,
        T_CV,
        T_UNUSED,
        T_UNUSED,
        1,
        0,
        0,
        0,
        5,
    );

    let parsed: disrobe_pass_php::OpArray =
        parse_oparray(&generator.build_container()).expect("parse generator op array");
    let recovered: Decompilation = decompile_oparray(&parsed);

    assert!(
        recovered.php_skeleton.contains("yield 'label';"),
        "{}",
        recovered.php_skeleton
    );
    assert!(
        recovered
            .php_skeleton
            .contains("$received = yield 'label' => $items;"),
        "{}",
        recovered.php_skeleton
    );
    assert!(
        recovered
            .php_skeleton
            .contains("$received = yield from $items;"),
        "{}",
        recovered.php_skeleton
    );
    assert!(
        recovered.php_skeleton.contains("return $received;"),
        "{}",
        recovered.php_skeleton
    );
}

#[test]
fn reused_temporary_before_yield_does_not_consume_the_yield_result() {
    let mut generator: OpArrayBuilder = OpArrayBuilder::function("values", 0);
    let value: u32 = generator.lit_str("value");
    generator.op(op::QM_ASSIGN, T_CONST, T_UNUSED, T_TMP, value, 0, 7, 0, 2);
    generator.op(op::ECHO, T_TMP, T_UNUSED, T_UNUSED, 7, 0, 0, 0, 2);
    generator.op(op::YIELD, T_CONST, T_UNUSED, T_TMP, value, 0, 7, 0, 3);
    generator.op(op::FREE, T_TMP, T_UNUSED, T_UNUSED, 7, 0, 0, 0, 3);
    generator.op(
        op::GENERATOR_RETURN,
        T_UNUSED,
        T_UNUSED,
        T_UNUSED,
        0,
        0,
        0,
        0,
        4,
    );

    let parsed: disrobe_pass_php::OpArray =
        parse_oparray(&generator.build_container()).expect("parse reused temporary op array");
    let recovered: Decompilation = decompile_oparray(&parsed);

    assert!(
        recovered.php_skeleton.contains("yield 'value';"),
        "{}",
        recovered.php_skeleton
    );
}

#[test]
fn multiply_consumed_yield_result_is_spilled_once() {
    let mut generator: OpArrayBuilder = OpArrayBuilder::function("values", 0);
    generator.var("_disrobe_yield_0");
    generator.var("first");
    generator.var("second");
    generator.var("items");
    let value: u32 = generator.lit_str("token");
    generator.op(op::YIELD, T_CONST, T_UNUSED, T_TMP, value, 0, 4, 0, 2);
    generator.op(op::ASSIGN, T_CV, T_TMP, T_UNUSED, 1, 4, 0, 0, 3);
    generator.op(op::ASSIGN, T_CV, T_TMP, T_UNUSED, 2, 4, 0, 0, 4);
    generator.op(op::YIELD_FROM, T_CV, T_UNUSED, T_TMP, 3, 0, 5, 0, 5);
    generator.op(op::ASSIGN, T_CV, T_TMP, T_UNUSED, 1, 5, 0, 0, 6);
    generator.op(op::ASSIGN, T_CV, T_TMP, T_UNUSED, 2, 5, 0, 0, 7);
    generator.op(
        op::GENERATOR_RETURN,
        T_UNUSED,
        T_UNUSED,
        T_UNUSED,
        0,
        0,
        0,
        0,
        8,
    );

    let parsed: disrobe_pass_php::OpArray =
        parse_oparray(&generator.build_container()).expect("parse shared yield result op array");
    let recovered: Decompilation = decompile_oparray(&parsed);

    assert_eq!(recovered.php_skeleton.matches("yield 'token'").count(), 1);
    assert!(
        recovered
            .php_skeleton
            .contains("$_disrobe_yield_0_1 = yield 'token';"),
        "{}",
        recovered.php_skeleton
    );
    assert!(
        recovered
            .php_skeleton
            .contains("$first = $_disrobe_yield_0_1;"),
        "{}",
        recovered.php_skeleton
    );
    assert!(
        recovered
            .php_skeleton
            .contains("$second = $_disrobe_yield_0_1;"),
        "{}",
        recovered.php_skeleton
    );
    assert_eq!(
        recovered.php_skeleton.matches("yield from $items").count(),
        1
    );
    assert!(
        recovered
            .php_skeleton
            .contains("$_disrobe_yield_3 = yield from $items;"),
        "{}",
        recovered.php_skeleton
    );
}

#[test]
fn cfg_recovers_if_skeleton_from_jmpz_branch() {
    let mut b: OpArrayBuilder = OpArrayBuilder::main();
    let cond: u32 = b.lit_long(1);
    let taken: u32 = b.lit_str("then-branch");
    b.op(op::JMPZ, T_CONST, T_UNUSED, T_UNUSED, cond, 3, 0, 0, 2);
    b.op(op::ECHO, T_CONST, T_UNUSED, T_UNUSED, taken, 0, 0, 0, 3);
    b.op(op::JMP, T_UNUSED, T_UNUSED, T_UNUSED, 4, 0, 0, 0, 3);
    b.op(op::NOP, T_UNUSED, T_UNUSED, T_UNUSED, 0, 0, 0, 0, 4);
    b.op(op::RETURN, T_CONST, T_UNUSED, T_UNUSED, 0, 0, 0, 0, 5);
    let bytes: Vec<u8> = b.build_container();

    let parsed = parse_oparray(&bytes).expect("parse");
    let cfg = build_cfg(&parsed.ops);
    assert!(cfg.blocks.len() >= 3, "expected multiple blocks");
    assert!(matches!(parsed.ops[0].branch_target(), Branch::Cond { .. }));
    assert!(matches!(parsed.ops[2].branch_target(), Branch::Uncond(4)));

    let decomp: Decompilation = decompile_oparray(&parsed);
    let skel: &str = &decomp.php_skeleton;
    assert!(skel.contains("if (1) {"), "skeleton: {skel}");
    assert!(skel.contains("echo 'then-branch';"), "skeleton: {skel}");
}

#[test]
fn cfg_distinguishes_while_loop_via_back_edge() {
    let mut b: OpArrayBuilder = OpArrayBuilder::main();
    let cond: u32 = b.lit_long(1);
    let body: u32 = b.lit_str("loop-body");
    b.op(op::JMP, T_UNUSED, T_UNUSED, T_UNUSED, 2, 0, 0, 0, 2);
    b.op(op::ECHO, T_CONST, T_UNUSED, T_UNUSED, body, 0, 0, 0, 3);
    b.op(op::JMPNZ, T_CONST, T_UNUSED, T_UNUSED, cond, 1, 0, 0, 3);
    b.op(op::RETURN, T_CONST, T_UNUSED, T_UNUSED, 0, 0, 0, 0, 4);
    let bytes: Vec<u8> = b.build_container();

    let parsed = parse_oparray(&bytes).expect("parse");
    let decomp: Decompilation = decompile_oparray(&parsed);
    let skel: &str = &decomp.php_skeleton;
    assert!(skel.contains("while (1) {"), "skeleton: {skel}");
    assert!(skel.contains("echo 'loop-body';"), "skeleton: {skel}");
}

#[test]
fn foreach_skeleton_from_fe_fetch() {
    let mut b: OpArrayBuilder = OpArrayBuilder::main();
    let arr: u32 = b.lit_str("items");
    b.op(op::FE_RESET_R, T_CONST, T_UNUSED, T_VAR, arr, 4, 0, 0, 2);
    b.op(op::FE_FETCH_R, T_VAR, T_CV, T_UNUSED, 0, 1, 0, 0, 2);
    b.op(op::ECHO, T_CV, T_UNUSED, T_UNUSED, 1, 0, 0, 0, 3);
    b.op(op::JMP, T_UNUSED, T_UNUSED, T_UNUSED, 1, 0, 0, 0, 3);
    b.op(op::RETURN, T_CONST, T_UNUSED, T_UNUSED, 0, 0, 0, 0, 4);
    let bytes: Vec<u8> = b.build_container();

    let parsed = parse_oparray(&bytes).expect("parse");
    let decomp: Decompilation = decompile_oparray(&parsed);
    assert!(
        decomp.php_skeleton.contains("foreach ('items' as $v1) {"),
        "skeleton: {}",
        decomp.php_skeleton
    );
    assert!(
        decomp.php_skeleton.contains("echo $v1;"),
        "skeleton: {}",
        decomp.php_skeleton
    );
}

#[test]
fn keyed_foreach_recovers_key_from_fetch_result_assign() {
    let mut b: OpArrayBuilder = OpArrayBuilder::main();
    let arr: u32 = b.lit_str("rows");
    b.op(op::FE_RESET_R, T_CONST, T_UNUSED, T_VAR, arr, 5, 0, 0, 2);
    b.op(op::FE_FETCH_R, T_VAR, T_CV, T_TMP, 0, 2, 9, 1, 2);
    b.op(op::ASSIGN, T_CV, T_TMP, T_UNUSED, 3, 9, 0, 0, 2);
    b.op(op::ECHO, T_CV, T_UNUSED, T_UNUSED, 2, 0, 0, 0, 3);
    b.op(op::JMP, T_UNUSED, T_UNUSED, T_UNUSED, 1, 0, 0, 0, 3);
    b.op(op::RETURN, T_CONST, T_UNUSED, T_UNUSED, 0, 0, 0, 0, 4);
    let bytes: Vec<u8> = b.build_container();

    let parsed = parse_oparray(&bytes).expect("parse");
    let decomp: Decompilation = decompile_oparray(&parsed);
    assert!(
        decomp
            .php_skeleton
            .contains("foreach ('rows' as $v3 => $v2) {"),
        "skeleton: {}",
        decomp.php_skeleton
    );
    assert!(
        !decomp.php_skeleton.contains("$tmp"),
        "key fetch temp must not leak: {}",
        decomp.php_skeleton
    );
}

#[test]
fn do_while_loop_recovers_post_test_back_edge() {
    let mut b: OpArrayBuilder = OpArrayBuilder::main();
    let zero: u32 = b.lit_long(0);
    let one: u32 = b.lit_long(1);
    let five: u32 = b.lit_long(5);
    b.op(op::ASSIGN, T_CV, T_CONST, T_UNUSED, 0, zero, 0, 0, 2);
    b.op(op::ECHO, T_CV, T_UNUSED, T_UNUSED, 0, 0, 0, 0, 3);
    b.op(op::ADD, T_CV, T_CONST, T_TMP, 0, one, 5, 0, 4);
    b.op(op::ASSIGN, T_CV, T_TMP, T_UNUSED, 0, 5, 0, 0, 4);
    b.op(op::IS_SMALLER, T_CV, T_CONST, T_TMP, 0, five, 7, 0, 5);
    b.op(op::JMPNZ, T_TMP, T_UNUSED, T_UNUSED, 7, 1, 0, 0, 5);
    b.op(op::RETURN, T_CONST, T_UNUSED, T_UNUSED, 0, 0, 0, 0, 6);
    let bytes: Vec<u8> = b.build_container();

    let parsed = parse_oparray(&bytes).expect("parse");
    let decomp: Decompilation = decompile_oparray(&parsed);
    let skel: &str = &decomp.php_skeleton;
    assert!(skel.contains("do {"), "skeleton: {skel}");
    assert!(skel.contains("} while ($v0 < 5);"), "skeleton: {skel}");
    assert!(skel.contains("echo $v0;"), "skeleton: {skel}");
}

#[test]
fn reconstructs_function_declaration_with_params() {
    let mut greet: OpArrayBuilder = OpArrayBuilder::function("greet", 1);
    let msg: u32 = greet.lit_str("hi ");
    greet.op(op::ECHO, T_CONST, T_UNUSED, T_UNUSED, msg, 0, 0, 0, 2);
    greet.op(op::RETURN, T_UNUSED, T_UNUSED, T_UNUSED, 0, 0, 0, 0, 3);

    let mut main: OpArrayBuilder = OpArrayBuilder::main();
    main.op(op::RETURN, T_CONST, T_UNUSED, T_UNUSED, 0, 0, 0, 0, 1);
    main.child(greet.build_body());
    let bytes: Vec<u8> = main.build_container();

    let parsed = parse_oparray(&bytes).expect("parse");
    assert_eq!(parsed.children.len(), 1);
    assert_eq!(parsed.children[0].name.as_deref(), Some("greet"));
    assert_eq!(parsed.children[0].num_args, 1);

    let decomp: Decompilation = decompile_oparray(&parsed);
    let skel: &str = &decomp.php_skeleton;
    assert!(skel.contains("function greet($v0)"), "skeleton: {skel}");
    assert!(skel.contains("echo 'hi ';"), "skeleton: {skel}");
}

#[test]
fn reconstructs_class_method_skeleton() {
    let mut m: OpArrayBuilder = OpArrayBuilder::method("Calculator", "add", 2);
    m.op(op::ADD, T_CV, T_CV, T_TMP, 0, 1, 2, 0, 3);
    m.op(op::RETURN, T_TMP, T_UNUSED, T_UNUSED, 2, 0, 0, 0, 3);
    let bytes: Vec<u8> = m.build_container();

    let parsed = parse_oparray(&bytes).expect("parse");
    let decomp: Decompilation = decompile_oparray(&parsed);
    let skel: &str = &decomp.php_skeleton;
    assert!(skel.contains("class Calculator"), "skeleton: {skel}");
    assert!(
        skel.contains("public function add($v0, $v1)"),
        "skeleton: {skel}"
    );
    assert!(skel.contains("return $v0 + $v1;"), "skeleton: {skel}");
}

#[test]
fn recovers_function_call_name_from_literal_pool() {
    let mut b: OpArrayBuilder = OpArrayBuilder::main();
    let fname: u32 = b.lit_str("strlen");
    let arg: u32 = b.lit_str("hello");
    b.op(
        op::INIT_FCALL,
        T_UNUSED,
        T_CONST,
        T_UNUSED,
        0,
        fname,
        0,
        1,
        1,
    );
    b.op(op::SEND_VAL, T_CONST, T_UNUSED, T_UNUSED, arg, 1, 0, 0, 1);
    b.op(op::DO_FCALL, T_UNUSED, T_UNUSED, T_VAR, 0, 0, 0, 0, 1);
    b.op(op::ECHO, T_VAR, T_UNUSED, T_UNUSED, 0, 0, 0, 0, 1);
    b.op(op::RETURN, T_CONST, T_UNUSED, T_UNUSED, 0, 0, 0, 0, 1);
    let bytes: Vec<u8> = b.build_container();

    let parsed = parse_oparray(&bytes).expect("parse");
    let decomp: Decompilation = decompile_oparray(&parsed);
    assert!(
        decomp.php_skeleton.contains("echo strlen('hello');"),
        "skeleton: {}",
        decomp.php_skeleton
    );
}

#[test]
fn recovered_variables_use_source_names_from_the_v2_table() {
    let mut b: OpArrayBuilder = OpArrayBuilder::main();
    b.var("total").var("step");
    let seven: u32 = b.lit_long(7);
    let two: u32 = b.lit_long(2);
    b.op(op::ASSIGN, T_CV, T_CONST, T_UNUSED, 0, seven, 0, 0, 2);
    b.op(op::ASSIGN, T_CV, T_CONST, T_UNUSED, 1, two, 0, 0, 3);
    b.op(op::ADD, T_CV, T_CV, T_TMP, 0, 1, 5, 0, 4);
    b.op(op::ASSIGN, T_CV, T_TMP, T_UNUSED, 0, 5, 0, 0, 4);
    b.op(op::ECHO, T_CV, T_UNUSED, T_UNUSED, 0, 0, 0, 0, 5);
    b.op(op::RETURN, T_CONST, T_UNUSED, T_UNUSED, 0, 0, 0, 0, 6);
    let bytes: Vec<u8> = b.build_container();

    let parsed = parse_oparray(&bytes).expect("parse");
    assert_eq!(
        parsed.var_names,
        vec![Some("total".into()), Some("step".into())]
    );
    let decomp: Decompilation = decompile_oparray(&parsed);
    let skel: &str = &decomp.php_skeleton;
    assert!(skel.contains("$total = 7;"), "skeleton: {skel}");
    assert!(skel.contains("$step = 2;"), "skeleton: {skel}");
    assert!(
        skel.contains("$total = $total + $step;"),
        "skeleton: {skel}"
    );
    assert!(skel.contains("echo $total;"), "skeleton: {skel}");
    assert!(
        !skel.contains("$v0"),
        "named slots must not leak as $v0: {skel}"
    );
}

#[test]
fn assignment_results_snapshot_values_before_the_target_is_overwritten() {
    let mut b: OpArrayBuilder = OpArrayBuilder::main();
    let one: u32 = b.lit_long(1);
    let two: u32 = b.lit_long(2);
    b.op(op::ASSIGN, T_CV, T_CONST, T_TMP, 0, one, 5, 0, 1);
    b.op(op::ASSIGN, T_CV, T_CONST, T_TMP, 0, two, 6, 0, 1);
    b.op(op::ADD, T_TMP, T_TMP, T_TMP, 5, 6, 7, 0, 1);
    b.op(op::RETURN, T_TMP, T_UNUSED, T_UNUSED, 7, 0, 0, 0, 1);
    let bytes: Vec<u8> = b.build_container();

    let parsed: OpArray = parse_oparray(&bytes).expect("parse");
    let decomp: Decompilation = decompile_oparray(&parsed);
    let skel: &str = &decomp.php_skeleton;
    assert!(
        skel.contains("$_disrobe_assign_0 = ($v0 = 1);"),
        "skeleton: {skel}"
    );
    assert!(
        skel.contains("$_disrobe_assign_1 = ($v0 = 2);"),
        "skeleton: {skel}"
    );
    assert!(
        skel.contains("return $_disrobe_assign_0 + $_disrobe_assign_1;"),
        "skeleton: {skel}"
    );
    assert!(!skel.contains("return $v0 + $v0;"), "skeleton: {skel}");
}

#[test]
fn ambiguous_and_malformed_returns_are_refused() {
    let mut explicit_one: OpArrayBuilder = OpArrayBuilder::main();
    let one: u32 = explicit_one.lit_long(1);
    explicit_one.op(op::RETURN, T_CONST, T_UNUSED, T_UNUSED, one, 0, 0, 0, 1);
    let explicit_one_bytes: Vec<u8> = explicit_one.build_container();
    let explicit_one_parsed: OpArray = parse_oparray(&explicit_one_bytes).expect("parse");
    let explicit_one_decomp: Decompilation = decompile_oparray(&explicit_one_parsed);
    assert_eq!(explicit_one_decomp.unrecovered_total, 0);
    assert!(
        explicit_one_decomp.php_skeleton.contains("return 1;"),
        "skeleton: {}",
        explicit_one_decomp.php_skeleton
    );

    let mut marked_one: OpArrayBuilder = OpArrayBuilder::main();
    let marked: u32 = marked_one.lit_long(1);
    marked_one.op(
        op::RETURN,
        T_CONST,
        T_UNUSED,
        T_UNUSED,
        marked,
        0,
        0,
        u32::MAX,
        1,
    );
    let marked_one_bytes: Vec<u8> = marked_one.build_container();
    let marked_one_parsed: OpArray = parse_oparray(&marked_one_bytes).expect("parse");
    let marked_one_decomp: Decompilation = decompile_oparray(&marked_one_parsed);
    assert_eq!(marked_one_decomp.unrecovered_total, 0);
    assert!(
        !marked_one_decomp.php_skeleton.contains("return 1;"),
        "skeleton: {}",
        marked_one_decomp.php_skeleton
    );

    let mut marked_null: OpArrayBuilder = OpArrayBuilder::main();
    let marked_null_literal: u32 = marked_null.lit_null();
    marked_null.op(
        op::RETURN,
        T_CONST,
        T_UNUSED,
        T_UNUSED,
        marked_null_literal,
        0,
        0,
        u32::MAX,
        1,
    );
    let marked_null_bytes: Vec<u8> = marked_null.build_container();
    let marked_null_parsed: OpArray = parse_oparray(&marked_null_bytes).expect("parse");
    let marked_null_decomp: Decompilation = decompile_oparray(&marked_null_parsed);
    assert_eq!(marked_null_decomp.unrecovered_total, 0);
    assert!(
        !marked_null_decomp.php_skeleton.contains("return null;"),
        "skeleton: {}",
        marked_null_decomp.php_skeleton
    );

    let mut explicit_null: OpArrayBuilder = OpArrayBuilder::main();
    let null: u32 = explicit_null.lit_null();
    explicit_null.op(op::RETURN, T_CONST, T_UNUSED, T_UNUSED, null, 0, 0, 0, 1);
    let explicit_null_bytes: Vec<u8> = explicit_null.build_container();
    let explicit_null_parsed: OpArray = parse_oparray(&explicit_null_bytes).expect("parse");
    let explicit_null_decomp: Decompilation = decompile_oparray(&explicit_null_parsed);
    assert_eq!(explicit_null_decomp.unrecovered_total, 0);
    assert!(
        explicit_null_decomp.php_skeleton.contains("return null;"),
        "skeleton: {}",
        explicit_null_decomp.php_skeleton
    );

    let mut unused: OpArrayBuilder = OpArrayBuilder::main();
    unused.op(op::RETURN, T_UNUSED, T_UNUSED, T_UNUSED, 0, 0, 0, 0, 1);
    let unused_bytes: Vec<u8> = unused.build_container();
    let unused_parsed: OpArray = parse_oparray(&unused_bytes).expect("parse");
    let unused_decomp: Decompilation = decompile_oparray(&unused_parsed);
    assert_eq!(unused_decomp.unrecovered_total, 1);
    assert!(
        unused_decomp.unrecovered[0]
            .reason
            .contains("reaching definition")
    );

    let mut by_ref_one: OpArrayBuilder = OpArrayBuilder::main();
    let by_ref_literal: u32 = by_ref_one.lit_long(1);
    by_ref_one.op(
        op::RETURN_BY_REF,
        T_CONST,
        T_UNUSED,
        T_UNUSED,
        by_ref_literal,
        0,
        0,
        0,
        1,
    );
    let by_ref_one_bytes: Vec<u8> = by_ref_one.build_container();
    let by_ref_one_parsed: OpArray = parse_oparray(&by_ref_one_bytes).expect("parse");
    let by_ref_one_decomp: Decompilation = decompile_oparray(&by_ref_one_parsed);
    assert_eq!(by_ref_one_decomp.unrecovered_total, 1);
    assert_eq!(
        by_ref_one_decomp.unrecovered[0].mnemonic,
        "ZEND_RETURN_BY_REF"
    );
    assert!(
        by_ref_one_decomp.unrecovered[0]
            .reason
            .contains("compiler-final provenance")
    );

    let mut by_ref_final: OpArrayBuilder = OpArrayBuilder::main();
    let by_ref_final_literal: u32 = by_ref_final.lit_long(1);
    by_ref_final.op(
        op::RETURN_BY_REF,
        T_CONST,
        T_UNUSED,
        T_UNUSED,
        by_ref_final_literal,
        0,
        0,
        u32::MAX,
        1,
    );
    let by_ref_final_bytes: Vec<u8> = by_ref_final.build_container();
    let by_ref_final_parsed: OpArray = parse_oparray(&by_ref_final_bytes).expect("parse");
    let by_ref_final_decomp: Decompilation = decompile_oparray(&by_ref_final_parsed);
    assert_eq!(by_ref_final_decomp.unrecovered_total, 0);
    assert!(
        !by_ref_final_decomp.php_skeleton.contains("return 1;"),
        "skeleton: {}",
        by_ref_final_decomp.php_skeleton
    );

    let mut by_ref_unused: OpArrayBuilder = OpArrayBuilder::main();
    by_ref_unused.op(
        op::RETURN_BY_REF,
        T_UNUSED,
        T_UNUSED,
        T_UNUSED,
        0,
        0,
        0,
        0,
        1,
    );
    let by_ref_unused_bytes: Vec<u8> = by_ref_unused.build_container();
    let by_ref_unused_parsed: OpArray = parse_oparray(&by_ref_unused_bytes).expect("parse");
    let by_ref_unused_decomp: Decompilation = decompile_oparray(&by_ref_unused_parsed);
    assert_eq!(by_ref_unused_decomp.unrecovered_total, 1);
    assert_eq!(
        by_ref_unused_decomp.unrecovered[0].mnemonic,
        "ZEND_RETURN_BY_REF"
    );
    assert!(
        by_ref_unused_decomp.unrecovered[0]
            .reason
            .contains("reaching definition")
    );
}

#[test]
fn a_definition_from_only_one_conditional_path_does_not_reach_the_join() {
    let mut b: OpArrayBuilder = OpArrayBuilder::main();
    let one: u32 = b.lit_long(1);
    let two: u32 = b.lit_long(2);
    b.op(op::JMPZ, T_CV, T_UNUSED, T_UNUSED, 0, 2, 0, 0, 1);
    b.op(op::ADD, T_CONST, T_CONST, T_TMP, one, two, 5, 0, 2);
    b.op(op::RETURN, T_TMP, T_UNUSED, T_UNUSED, 5, 0, 0, 0, 3);
    let bytes: Vec<u8> = b.build_container();

    let parsed: OpArray = parse_oparray(&bytes).expect("parse");
    let decomp: Decompilation = decompile_oparray(&parsed);
    assert!(
        decomp
            .unrecovered
            .iter()
            .any(|entry: &UnrecoveredOp| entry.mnemonic == "ZEND_RETURN"
                && entry.reason.contains("reaching definition")),
        "unrecovered: {:?}",
        decomp.unrecovered
    );
    assert!(
        !decomp.php_skeleton.contains("return 1 + 2;"),
        "skeleton: {}",
        decomp.php_skeleton
    );
}

#[test]
fn an_if_else_definition_from_only_one_arm_does_not_reach_the_join() {
    let mut b: OpArrayBuilder = OpArrayBuilder::main();
    let one: u32 = b.lit_long(1);
    let two: u32 = b.lit_long(2);
    b.op(op::JMPZ, T_CV, T_UNUSED, T_UNUSED, 0, 3, 0, 0, 1);
    b.op(op::ADD, T_CONST, T_CONST, T_TMP, one, two, 5, 0, 2);
    b.op(op::JMP, T_UNUSED, T_UNUSED, T_UNUSED, 4, 0, 0, 0, 3);
    b.op(op::OP_DATA, T_UNUSED, T_UNUSED, T_UNUSED, 0, 0, 0, 0, 4);
    b.op(op::RETURN, T_TMP, T_UNUSED, T_UNUSED, 5, 0, 0, 0, 5);
    let bytes: Vec<u8> = b.build_container();

    let parsed: OpArray = parse_oparray(&bytes).expect("parse");
    let decomp: Decompilation = decompile_oparray(&parsed);
    assert!(
        decomp
            .unrecovered
            .iter()
            .any(|entry: &UnrecoveredOp| entry.mnemonic == "ZEND_RETURN"
                && entry.reason.contains("reaching definition")),
        "unrecovered: {:?}",
        decomp.unrecovered
    );
    assert!(
        !decomp.php_skeleton.contains("return 1 + 2;"),
        "skeleton: {}",
        decomp.php_skeleton
    );
}

#[test]
fn an_identical_if_else_definition_reaches_the_join() {
    let mut b: OpArrayBuilder = OpArrayBuilder::main();
    let one: u32 = b.lit_long(1);
    let two: u32 = b.lit_long(2);
    b.op(op::JMPZ, T_CV, T_UNUSED, T_UNUSED, 0, 3, 0, 0, 1);
    b.op(op::ADD, T_CONST, T_CONST, T_TMP, one, two, 5, 0, 2);
    b.op(op::JMP, T_UNUSED, T_UNUSED, T_UNUSED, 4, 0, 0, 0, 3);
    b.op(op::ADD, T_CONST, T_CONST, T_TMP, one, two, 5, 0, 4);
    b.op(op::RETURN, T_TMP, T_UNUSED, T_UNUSED, 5, 0, 0, 0, 5);
    let bytes: Vec<u8> = b.build_container();

    let parsed: OpArray = parse_oparray(&bytes).expect("parse");
    let decomp: Decompilation = decompile_oparray(&parsed);
    assert_eq!(decomp.unrecovered_total, 0, "{:?}", decomp.unrecovered);
    assert!(
        decomp.php_skeleton.contains("return 1 + 2;"),
        "skeleton: {}",
        decomp.php_skeleton
    );
}

#[test]
fn missing_name_table_falls_back_to_synthetic_slot_ids() {
    let mut b: OpArrayBuilder = OpArrayBuilder::main();
    let nine: u32 = b.lit_long(9);
    b.op(op::ASSIGN, T_CV, T_CONST, T_UNUSED, 0, nine, 0, 0, 2);
    b.op(op::ECHO, T_CV, T_UNUSED, T_UNUSED, 0, 0, 0, 0, 3);
    b.op(op::RETURN, T_CONST, T_UNUSED, T_UNUSED, 0, 0, 0, 0, 4);
    let bytes: Vec<u8> = b.build_container();

    let parsed = parse_oparray(&bytes).expect("parse");
    assert!(parsed.var_names.is_empty());
    let decomp: Decompilation = decompile_oparray(&parsed);
    assert!(
        decomp.php_skeleton.contains("$v0 = 9;"),
        "{}",
        decomp.php_skeleton
    );
}

#[test]
fn variable_variable_assignment_recovers_dollar_dollar_form() {
    let mut b: OpArrayBuilder = OpArrayBuilder::main();
    b.var("name");
    let nameval: u32 = b.lit_str("color");
    let blue: u32 = b.lit_str("blue");
    b.op(op::ASSIGN, T_CV, T_CONST, T_UNUSED, 0, nameval, 0, 0, 2);
    b.op(op::FETCH_W, T_CV, T_UNUSED, T_VAR, 0, 0, 5, 0, 3);
    b.op(op::ASSIGN, T_VAR, T_CONST, T_UNUSED, 5, blue, 0, 0, 3);
    b.op(op::RETURN, T_CONST, T_UNUSED, T_UNUSED, 0, 0, 0, 0, 4);
    let bytes: Vec<u8> = b.build_container();

    let parsed = parse_oparray(&bytes).expect("parse");
    let decomp: Decompilation = decompile_oparray(&parsed);
    let skel: &str = &decomp.php_skeleton;
    assert!(skel.contains("$name = 'color';"), "skeleton: {skel}");
    assert!(skel.contains("$$name = 'blue';"), "skeleton: {skel}");
    assert!(
        !skel.contains("$var5"),
        "fetch var slot must not leak: {skel}"
    );
}

#[test]
fn increment_and_decrement_results_preserve_prefix_and_postfix_behavior() {
    let mut b: OpArrayBuilder = OpArrayBuilder::main();
    b.var("pre_inc_source")
        .var("pre_inc_result")
        .var("post_inc_source")
        .var("post_inc_result")
        .var("pre_dec_source")
        .var("pre_dec_result")
        .var("post_dec_source")
        .var("post_dec_result");
    let ten: u32 = b.lit_long(10);
    let separator: u32 = b.lit_str("|");
    b.op(op::ASSIGN, T_CV, T_CONST, T_UNUSED, 0, ten, 0, 0, 1);
    b.op(op::PRE_INC, T_CV, T_UNUSED, T_TMP, 0, 0, 10, 0, 2);
    b.op(op::ASSIGN, T_CV, T_TMP, T_UNUSED, 1, 10, 0, 0, 2);
    b.op(op::ASSIGN, T_CV, T_CONST, T_UNUSED, 2, ten, 0, 0, 3);
    b.op(op::POST_INC, T_CV, T_UNUSED, T_TMP, 2, 0, 11, 0, 4);
    b.op(op::ASSIGN, T_CV, T_TMP, T_UNUSED, 3, 11, 0, 0, 4);
    b.op(op::ASSIGN, T_CV, T_CONST, T_UNUSED, 4, ten, 0, 0, 5);
    b.op(op::PRE_DEC, T_CV, T_UNUSED, T_TMP, 4, 0, 12, 0, 6);
    b.op(op::ASSIGN, T_CV, T_TMP, T_UNUSED, 5, 12, 0, 0, 6);
    b.op(op::ASSIGN, T_CV, T_CONST, T_UNUSED, 6, ten, 0, 0, 7);
    b.op(op::POST_DEC, T_CV, T_UNUSED, T_TMP, 6, 0, 13, 0, 8);
    b.op(op::ASSIGN, T_CV, T_TMP, T_UNUSED, 7, 13, 0, 0, 8);
    for (position, slot) in [1u32, 0, 3, 2, 5, 4, 7, 6].into_iter().enumerate() {
        if position != 0 {
            b.op(op::ECHO, T_CONST, T_UNUSED, T_UNUSED, separator, 0, 0, 0, 9);
        }
        b.op(op::ECHO, T_CV, T_UNUSED, T_UNUSED, slot, 0, 0, 0, 9);
    }
    let parsed: OpArray = parse_oparray(&b.build_container()).expect("parse increment op array");
    let decomp: Decompilation = decompile_oparray(&parsed);

    assert_eq!(decomp.unrecovered_total, 0, "{:?}", decomp.unrecovered);
    for expected in [
        "$pre_inc_result = ++$pre_inc_source;",
        "$post_inc_result = $post_inc_source++;",
        "$pre_dec_result = --$pre_dec_source;",
        "$post_dec_result = $post_dec_source--;",
    ] {
        assert!(
            decomp.php_skeleton.contains(expected),
            "missing {expected:?} in:\n{}",
            decomp.php_skeleton
        );
    }

    if let Some(php) = php_bin() {
        let original: &str = "$pre_inc_source=10;$pre_inc_result=++$pre_inc_source;\
$post_inc_source=10;$post_inc_result=$post_inc_source++;\
$pre_dec_source=10;$pre_dec_result=--$pre_dec_source;\
$post_dec_source=10;$post_dec_result=$post_dec_source--;\
echo implode('|',[$pre_inc_result,$pre_inc_source,$post_inc_result,$post_inc_source,\
$pre_dec_result,$pre_dec_source,$post_dec_result,$post_dec_source]);";
        let expected: String = php_eval_source(&php, original);
        let recovered: String = php_eval_source(
            &php,
            decomp
                .php_skeleton
                .strip_prefix("<?php")
                .expect("decompilation has php open tag"),
        );
        assert_eq!(expected, "11|11|10|11|9|9|10|9");
        assert_eq!(
            recovered, expected,
            "recovered php:\n{}",
            decomp.php_skeleton
        );
    }
}

#[test]
fn delayed_and_reused_postfix_results_spill_at_the_mutation_site() {
    let mut b: OpArrayBuilder = OpArrayBuilder::main();
    b.var("source").var("first_result").var("second_result");
    let ten: u32 = b.lit_long(10);
    let separator: u32 = b.lit_str("|");
    b.op(op::ASSIGN, T_CV, T_CONST, T_UNUSED, 0, ten, 0, 0, 1);
    b.op(op::POST_INC, T_CV, T_UNUSED, T_TMP, 0, 0, 20, 0, 2);
    b.op(op::ECHO, T_CV, T_UNUSED, T_UNUSED, 0, 0, 0, 0, 3);
    b.op(op::ECHO, T_CONST, T_UNUSED, T_UNUSED, separator, 0, 0, 0, 3);
    b.op(op::ASSIGN, T_CV, T_TMP, T_UNUSED, 1, 20, 0, 0, 4);
    b.op(op::ASSIGN, T_CV, T_TMP, T_UNUSED, 2, 20, 0, 0, 5);
    b.op(op::ECHO, T_CV, T_UNUSED, T_UNUSED, 1, 0, 0, 0, 6);
    b.op(op::ECHO, T_CONST, T_UNUSED, T_UNUSED, separator, 0, 0, 0, 6);
    b.op(op::ECHO, T_CV, T_UNUSED, T_UNUSED, 2, 0, 0, 0, 6);
    let parsed: OpArray = parse_oparray(&b.build_container()).expect("parse delayed postfix");
    let decomp: Decompilation = decompile_oparray(&parsed);

    assert_eq!(decomp.unrecovered_total, 0, "{:?}", decomp.unrecovered);
    assert_eq!(decomp.php_skeleton.matches("$source++").count(), 1);
    assert!(
        decomp
            .php_skeleton
            .contains("$_disrobe_incdec_1 = $source++;")
    );
    assert!(
        decomp
            .php_skeleton
            .contains("$first_result = $_disrobe_incdec_1;")
    );
    assert!(
        decomp
            .php_skeleton
            .contains("$second_result = $_disrobe_incdec_1;")
    );

    if let Some(php) = php_bin() {
        let recovered: String = php_eval_source(
            &php,
            decomp
                .php_skeleton
                .strip_prefix("<?php")
                .expect("decompilation has php open tag"),
        );
        assert_eq!(recovered, "11|10|10");
    }
}

#[test]
fn a_delayed_single_postfix_result_does_not_move_past_an_effect() {
    let mut b: OpArrayBuilder = OpArrayBuilder::main();
    b.var("source").var("previous");
    let ten: u32 = b.lit_long(10);
    let separator: u32 = b.lit_str("|");
    b.op(op::ASSIGN, T_CV, T_CONST, T_UNUSED, 0, ten, 0, 0, 1);
    b.op(op::POST_INC, T_CV, T_UNUSED, T_TMP, 0, 0, 20, 0, 2);
    b.op(op::ECHO, T_CV, T_UNUSED, T_UNUSED, 0, 0, 0, 0, 3);
    b.op(op::ECHO, T_CONST, T_UNUSED, T_UNUSED, separator, 0, 0, 0, 3);
    b.op(op::ASSIGN, T_CV, T_TMP, T_UNUSED, 1, 20, 0, 0, 4);
    b.op(op::ECHO, T_CV, T_UNUSED, T_UNUSED, 1, 0, 0, 0, 5);
    let parsed: OpArray = parse_oparray(&b.build_container()).expect("parse delayed postfix");
    let decomp: Decompilation = decompile_oparray(&parsed);

    assert_eq!(decomp.unrecovered_total, 0, "{:?}", decomp.unrecovered);
    assert!(
        decomp
            .php_skeleton
            .contains("$_disrobe_incdec_1 = $source++;")
    );
    if let Some(php) = php_bin() {
        let original: String = php_eval_source(
            &php,
            "$source=10;$previous=$source++;echo $source . '|' . $previous;",
        );
        let recovered: String = php_eval_source(
            &php,
            decomp
                .php_skeleton
                .strip_prefix("<?php")
                .expect("decompilation has php open tag"),
        );
        assert_eq!(original, "11|10");
        assert_eq!(recovered, original, "{}", decomp.php_skeleton);
    }
}

#[test]
fn increment_through_a_resolved_variable_variable_preserves_its_result() {
    let mut b: OpArrayBuilder = OpArrayBuilder::main();
    b.var("name").var("counter").var("previous");
    let counter_name: u32 = b.lit_str("counter");
    let ten: u32 = b.lit_long(10);
    let separator: u32 = b.lit_str("|");
    b.op(
        op::ASSIGN,
        T_CV,
        T_CONST,
        T_UNUSED,
        0,
        counter_name,
        0,
        0,
        1,
    );
    b.op(op::ASSIGN, T_CV, T_CONST, T_UNUSED, 1, ten, 0, 0, 1);
    b.op(op::FETCH_W, T_CV, T_UNUSED, T_VAR, 0, 0, 30, 0, 2);
    b.op(op::POST_INC, T_VAR, T_UNUSED, T_TMP, 30, 0, 31, 0, 2);
    b.op(op::ASSIGN, T_CV, T_TMP, T_UNUSED, 2, 31, 0, 0, 2);
    b.op(op::ECHO, T_CV, T_UNUSED, T_UNUSED, 2, 0, 0, 0, 3);
    b.op(op::ECHO, T_CONST, T_UNUSED, T_UNUSED, separator, 0, 0, 0, 3);
    b.op(op::ECHO, T_CV, T_UNUSED, T_UNUSED, 1, 0, 0, 0, 3);
    let parsed: OpArray = parse_oparray(&b.build_container()).expect("parse variable-variable");
    let decomp: Decompilation = decompile_oparray(&parsed);

    assert_eq!(decomp.unrecovered_total, 0, "{:?}", decomp.unrecovered);
    assert!(
        decomp.php_skeleton.contains("$previous = $$name++;"),
        "{}",
        decomp.php_skeleton
    );
    if let Some(php) = php_bin() {
        let recovered: String = php_eval_source(
            &php,
            decomp
                .php_skeleton
                .strip_prefix("<?php")
                .expect("decompilation has php open tag"),
        );
        assert_eq!(recovered, "10|11");
    }
}

#[test]
fn read_fetches_never_grant_increment_write_provenance() {
    let mut read_builder: OpArrayBuilder = OpArrayBuilder::main();
    read_builder.var("name");
    let counter_name: u32 = read_builder.lit_str("counter");
    read_builder.op(
        op::ASSIGN,
        T_CV,
        T_CONST,
        T_UNUSED,
        0,
        counter_name,
        0,
        0,
        1,
    );
    for (position, opcode) in [op::PRE_INC, op::PRE_DEC, op::POST_INC, op::POST_DEC]
        .into_iter()
        .enumerate()
    {
        let slot: u32 = position as u32 + 30;
        read_builder.op(op::FETCH_R, T_CV, T_UNUSED, T_VAR, 0, 0, slot, 0, 2);
        read_builder.op(opcode, T_VAR, T_UNUSED, T_UNUSED, slot, 0, 0, 0, 2);
    }
    let read_parsed: OpArray =
        parse_oparray(&read_builder.build_container()).expect("parse read fetches");
    let read_decomp: Decompilation = decompile_oparray(&read_parsed);

    assert_eq!(read_decomp.unrecovered_total, 4);
    assert!(read_decomp.unrecovered.iter().all(|entry: &UnrecoveredOp| {
        entry.reason
            == "increment or decrement requires a writable variable and an optional temporary result"
    }));
    assert!(!read_decomp.php_skeleton.contains("$$name++"));
    assert!(!read_decomp.php_skeleton.contains("++$$name"));
    assert!(!read_decomp.php_skeleton.contains("$$name--"));
    assert!(!read_decomp.php_skeleton.contains("--$$name"));

    for fetch_opcode in [op::FETCH_W, op::FETCH_RW] {
        let valid_decomp: Decompilation = decompiled(|b: &mut OpArrayBuilder| {
            b.var("name");
            let counter: u32 = b.lit_str("counter");
            b.op(op::ASSIGN, T_CV, T_CONST, T_UNUSED, 0, counter, 0, 0, 1);
            b.op(fetch_opcode, T_CV, T_UNUSED, T_VAR, 0, 0, 40, 0, 2);
            b.op(op::POST_INC, T_VAR, T_UNUSED, T_UNUSED, 40, 0, 0, 0, 2);
        });
        assert_eq!(valid_decomp.unrecovered_total, 0);
        assert!(valid_decomp.php_skeleton.contains("$$name++;"));
    }
}

#[test]
fn used_increment_results_require_temporary_result_slots() {
    let mut b: OpArrayBuilder = OpArrayBuilder::main();
    b.var("used_source").var("standalone_source");
    let ten: u32 = b.lit_long(10);
    b.op(op::ASSIGN, T_CV, T_CONST, T_UNUSED, 0, ten, 0, 0, 1);
    b.op(op::POST_INC, T_CV, T_UNUSED, T_VAR, 0, 0, 20, 0, 2);
    b.op(op::ECHO, T_VAR, T_UNUSED, T_UNUSED, 20, 0, 0, 0, 2);
    b.op(op::ASSIGN, T_CV, T_CONST, T_UNUSED, 1, ten, 0, 0, 3);
    b.op(op::POST_INC, T_CV, T_UNUSED, T_UNUSED, 1, 0, 0, 0, 4);
    let parsed: OpArray = parse_oparray(&b.build_container()).expect("parse result slots");
    let decomp: Decompilation = decompile_oparray(&parsed);

    assert_eq!(decomp.unrecovered_total, 1);
    assert_eq!(
        decomp.unrecovered[0].reason,
        "increment or decrement requires a writable variable and an optional temporary result"
    );
    assert!(!decomp.php_skeleton.contains("$used_source++"));
    assert!(decomp.php_skeleton.contains("$standalone_source++;"));
}

#[test]
fn delayed_symbolic_write_fetch_refuses_after_name_redefinition() {
    let mut b: OpArrayBuilder = OpArrayBuilder::main();
    b.var("name").var("counter").var("other");
    let counter_name: u32 = b.lit_str("counter");
    let other_name: u32 = b.lit_str("other");
    let ten: u32 = b.lit_long(10);
    let twenty: u32 = b.lit_long(20);
    b.op(
        op::ASSIGN,
        T_CV,
        T_CONST,
        T_UNUSED,
        0,
        counter_name,
        0,
        0,
        1,
    );
    b.op(op::ASSIGN, T_CV, T_CONST, T_UNUSED, 1, ten, 0, 0, 1);
    b.op(op::ASSIGN, T_CV, T_CONST, T_UNUSED, 2, twenty, 0, 0, 1);
    b.op(op::FETCH_W, T_CV, T_UNUSED, T_VAR, 0, 0, 30, 0, 2);
    b.op(op::ASSIGN, T_CV, T_CONST, T_UNUSED, 0, other_name, 0, 0, 3);
    b.op(op::POST_INC, T_VAR, T_UNUSED, T_UNUSED, 30, 0, 0, 0, 4);
    b.op(op::ECHO, T_CV, T_UNUSED, T_UNUSED, 1, 0, 0, 0, 5);
    b.op(op::ECHO, T_CV, T_UNUSED, T_UNUSED, 2, 0, 0, 0, 5);
    let parsed: OpArray = parse_oparray(&b.build_container()).expect("parse delayed write fetch");
    let decomp: Decompilation = decompile_oparray(&parsed);

    assert_eq!(decomp.unrecovered_total, 1);
    assert_eq!(
        decomp.unrecovered[0].reason,
        "increment or decrement requires a writable variable and an optional temporary result"
    );
    assert!(!decomp.php_skeleton.contains("$$name++"));
    assert!(!decomp.php_skeleton.contains("$$name--"));
}

#[test]
fn short_circuit_join_does_not_leak_branch_local_writable_provenance() {
    let decomp: Decompilation = decompiled(|b: &mut OpArrayBuilder| {
        b.var("flag").var("name");
        let counter: u32 = b.lit_str("counter");
        let one: u32 = b.lit_long(1);
        b.op(op::ASSIGN, T_CV, T_CONST, T_UNUSED, 1, counter, 0, 0, 1);
        b.op(op::JMPZ_EX, T_CV, T_UNUSED, T_TMP, 0, 4, 20, 0, 2);
        b.op(op::QM_ASSIGN, T_CONST, T_UNUSED, T_TMP, one, 0, 20, 0, 2);
        b.op(op::FETCH_W, T_CV, T_UNUSED, T_VAR, 1, 0, 30, 0, 2);
        b.op(op::POST_INC, T_VAR, T_UNUSED, T_UNUSED, 30, 0, 0, 0, 3);
    });

    assert_eq!(decomp.unrecovered_total, 1, "{}", decomp.php_skeleton);
    assert_eq!(
        decomp.unrecovered[0].reason,
        "increment or decrement requires a writable variable and an optional temporary result"
    );
    assert!(!decomp.php_skeleton.contains("$$name++"));
}

#[test]
fn default_join_does_not_leak_branch_local_writable_provenance() {
    let decomp: Decompilation = decompiled(|b: &mut OpArrayBuilder| {
        b.var("value").var("name");
        let counter: u32 = b.lit_str("counter");
        let one: u32 = b.lit_long(1);
        b.op(op::ASSIGN, T_CV, T_CONST, T_UNUSED, 1, counter, 0, 0, 1);
        b.op(op::COALESCE, T_CV, T_UNUSED, T_TMP, 0, 4, 20, 0, 2);
        b.op(op::QM_ASSIGN, T_CONST, T_UNUSED, T_TMP, one, 0, 20, 0, 2);
        b.op(op::FETCH_RW, T_CV, T_UNUSED, T_VAR, 1, 0, 30, 0, 2);
        b.op(op::POST_INC, T_VAR, T_UNUSED, T_UNUSED, 30, 0, 0, 0, 3);
    });

    assert_eq!(decomp.unrecovered_total, 1, "{}", decomp.php_skeleton);
    assert_eq!(
        decomp.unrecovered[0].reason,
        "increment or decrement requires a writable variable and an optional temporary result"
    );
    assert!(!decomp.php_skeleton.contains("$$name++"));
}

#[test]
fn malformed_increment_operands_are_refused_instead_of_guessed() {
    let decomp: Decompilation = decompiled(|b: &mut OpArrayBuilder| {
        let ten: u32 = b.lit_long(10);
        let make: u32 = b.lit_str("make_value");
        b.op(op::PRE_INC, T_CONST, T_UNUSED, T_TMP, ten, 0, 1, 0, 1);
        b.op(op::POST_DEC, T_CV, T_CONST, T_TMP, 0, ten, 2, 0, 2);
        b.op(
            op::INIT_FCALL,
            T_UNUSED,
            T_CONST,
            T_UNUSED,
            0,
            make,
            0,
            0,
            3,
        );
        b.op(op::DO_FCALL, T_UNUSED, T_UNUSED, T_VAR, 0, 0, 3, 0, 3);
        b.op(op::POST_INC, T_VAR, T_UNUSED, T_TMP, 3, 0, 4, 0, 3);
    });

    assert_eq!(decomp.unrecovered_total, 3);
    assert_eq!(decomp.unrecovered.len(), 3);
    assert!(
        decomp.unrecovered.iter().all(|entry: &UnrecoveredOp| {
            entry.reason
                == "increment or decrement requires a writable variable and an optional temporary result"
        })
    );
    assert!(!decomp.php_skeleton.contains("++"));
    assert!(!decomp.php_skeleton.contains("--"));
}

fn php_bin() -> Option<String> {
    let candidate: &str = "php";
    let ok: bool = std::process::Command::new(candidate)
        .arg("--version")
        .output()
        .map(|o: std::process::Output| o.status.success())
        .unwrap_or(false);
    if ok { Some(candidate.to_owned()) } else { None }
}

fn php_eval_source(php: &str, source: &str) -> String {
    let out: std::process::Output = std::process::Command::new(php)
        .arg("-r")
        .arg(source)
        .output()
        .expect("run php source");
    assert!(
        out.status.success(),
        "php failed on source:\n{source}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf8")
}

fn php_eval_bool(php: &str, expr: &str) -> String {
    let script: String = format!("$a=0;$b=0;$c=0; var_export((bool)({expr}));");
    let out: std::process::Output = std::process::Command::new(php)
        .arg("-r")
        .arg(&script)
        .output()
        .expect("run php");
    assert!(out.status.success(), "php failed on: {expr}");
    String::from_utf8(out.stdout).expect("utf8")
}

#[test]
fn relational_binds_tighter_than_equality_forces_parens() {
    let mut b: OpArrayBuilder = OpArrayBuilder::main();
    b.var("a").var("b").var("c");
    b.op(op::IS_EQUAL, T_CV, T_CV, T_TMP, 0, 1, 5, 0, 2);
    b.op(op::IS_SMALLER, T_TMP, T_CV, T_TMP, 5, 2, 6, 0, 2);
    b.op(op::RETURN, T_TMP, T_UNUSED, T_UNUSED, 6, 0, 0, 0, 3);
    let bytes: Vec<u8> = b.build_container();

    let parsed = parse_oparray(&bytes).expect("parse");
    let decomp: Decompilation = decompile_oparray(&parsed);
    let skel: &str = &decomp.php_skeleton;

    assert!(
        skel.contains("return ($a == $b) < $c;"),
        "expected parenthesized relational-of-equality, got: {skel}"
    );
    assert!(
        !skel.contains("return $a == $b < $c;"),
        "unparenthesized emit re-parses as $a == ($b < $c): {skel}"
    );

    if let Some(php) = php_bin() {
        let wrong: String = php_eval_bool(&php, "$a == $b < $c");
        let ground_truth: String = php_eval_bool(&php, "($a == $b) < $c");
        assert_ne!(
            wrong, ground_truth,
            "inputs must distinguish the two parses"
        );
        let emitted: String = php_eval_bool(&php, "($a == $b) < $c");
        assert_eq!(
            emitted, ground_truth,
            "emitted expression must match relational-tighter semantics"
        );
    }
}

fn decompiled(build: impl FnOnce(&mut OpArrayBuilder)) -> Decompilation {
    let mut b: OpArrayBuilder = OpArrayBuilder::main();
    build(&mut b);
    let bytes: Vec<u8> = b.build_container();
    let parsed = parse_oparray(&bytes).expect("parse oparray");
    decompile_oparray(&parsed)
}

#[test]
fn an_opcode_the_lifter_does_not_model_is_named_instead_of_vanishing() {
    let decomp: Decompilation = decompiled(|b: &mut OpArrayBuilder| {
        b.var("k");
        let one: u32 = b.lit_long(1);
        let two: u32 = b.lit_long(2);
        b.op(op::SWITCH_LONG, T_CV, T_UNUSED, T_UNUSED, 0, 2, 0, 0, 1);
        b.op(op::ECHO, T_CONST, T_UNUSED, T_UNUSED, one, 0, 0, 0, 2);
        b.op(op::RETURN, T_CONST, T_UNUSED, T_UNUSED, two, 0, 0, 0, 3);
    });

    assert_eq!(
        decomp.unrecovered_total, 1,
        "the switch dispatch is the only opcode this lifter cannot model here; recovered source: \
         {}",
        decomp.php_skeleton
    );
    let entry: &UnrecoveredOp = decomp
        .unrecovered
        .first()
        .expect("a refused opcode must be recorded, not dropped");
    assert_eq!(entry.container, "$_main");
    assert_eq!(entry.index, 0);
    assert_eq!(entry.opcode, op::SWITCH_LONG);
    assert_eq!(entry.mnemonic, "ZEND_SWITCH_LONG");
    assert_eq!(
        entry.reason,
        "switch and match dispatch is not reconstructed"
    );
    assert!(
        decomp
            .php_skeleton
            .contains("// disrobe: unrecovered ZEND_SWITCH_LONG at op 0"),
        "the refusal must be marked where it happened so the reader cannot mistake the recovered \
         source for a complete lift: {}",
        decomp.php_skeleton
    );
}

#[test]
fn a_modelled_op_array_reports_no_refusal_at_all() {
    let decomp: Decompilation = decompiled(|b: &mut OpArrayBuilder| {
        b.var("total");
        let two: u32 = b.lit_long(2);
        b.op(op::ASSIGN, T_CV, T_CONST, T_UNUSED, 0, two, 0, 0, 1);
        b.op(op::ECHO, T_CV, T_UNUSED, T_UNUSED, 0, 0, 0, 0, 2);
        b.op(op::RETURN, T_CONST, T_UNUSED, T_UNUSED, two, 0, 0, 0, 3);
    });

    assert_eq!(decomp.unrecovered_total, 0);
    assert!(decomp.unrecovered.is_empty());
    assert!(
        !decomp.php_skeleton.contains("unrecovered"),
        "a fully modelled body must carry no refusal marker: {}",
        decomp.php_skeleton
    );
}

#[test]
fn a_cast_to_a_type_php_8_cannot_spell_is_refused_rather_than_guessed() {
    let decomp: Decompilation = decompiled(|b: &mut OpArrayBuilder| {
        b.var("raw");
        let text: u32 = b.lit_str("12");
        b.op(op::ASSIGN, T_CV, T_CONST, T_UNUSED, 0, text, 0, 0, 1);
        b.op(op::CAST, T_CV, T_UNUSED, T_TMP, 0, 0, 1, 99, 2);
        b.op(op::ECHO, T_TMP, T_UNUSED, T_UNUSED, 1, 0, 0, 0, 3);
        b.op(op::RETURN, T_CONST, T_UNUSED, T_UNUSED, text, 0, 0, 0, 4);
    });

    let entry: &UnrecoveredOp = decomp
        .unrecovered
        .first()
        .expect("an unmapped cast target must be refused");
    assert_eq!(entry.mnemonic, "ZEND_CAST");
    assert_eq!(entry.index, 1);
    assert_eq!(entry.reason, "the cast target type is not a php 8 cast");
    assert!(
        !decomp.php_skeleton.contains("(int)"),
        "guessing a cast target would put a wrong byte in recovered source: {}",
        decomp.php_skeleton
    );
}

#[test]
fn a_cast_php_can_spell_recovers_as_that_cast() {
    let decomp: Decompilation = decompiled(|b: &mut OpArrayBuilder| {
        b.var("raw");
        b.var("n");
        let text: u32 = b.lit_str("12");
        b.op(op::ASSIGN, T_CV, T_CONST, T_UNUSED, 0, text, 0, 0, 1);
        b.op(op::CAST, T_CV, T_UNUSED, T_TMP, 0, 0, 1, 4, 2);
        b.op(op::ASSIGN, T_CV, T_TMP, T_UNUSED, 1, 1, 0, 0, 3);
        b.op(op::RETURN, T_CONST, T_UNUSED, T_UNUSED, text, 0, 0, 0, 4);
    });

    assert_eq!(decomp.unrecovered_total, 0);
    assert!(
        decomp.php_skeleton.contains("$n = (int) $raw;"),
        "skeleton: {}",
        decomp.php_skeleton
    );
}

#[test]
fn a_constructed_object_nobody_consumes_stays_a_statement() {
    let decomp: Decompilation = decompiled(|b: &mut OpArrayBuilder| {
        let class: u32 = b.lit_str("Worker");
        let two: u32 = b.lit_long(2);
        b.op(op::NEW, T_CONST, T_UNUSED, T_VAR, class, 0, 0, 0, 1);
        b.op(op::DO_FCALL, T_UNUSED, T_UNUSED, T_UNUSED, 0, 0, 0, 0, 1);
        b.op(op::FREE, T_VAR, T_UNUSED, T_UNUSED, 0, 0, 0, 0, 1);
        b.op(op::RETURN, T_CONST, T_UNUSED, T_UNUSED, two, 0, 0, 0, 2);
    });

    assert_eq!(decomp.unrecovered_total, 0);
    assert!(
        decomp.php_skeleton.contains("new Worker();"),
        "a constructor still runs when its object is discarded, so dropping the statement would \
         change behaviour: {}",
        decomp.php_skeleton
    );
}

#[test]
fn a_constructed_object_someone_assigns_becomes_the_right_hand_side() {
    let decomp: Decompilation = decompiled(|b: &mut OpArrayBuilder| {
        b.var("worker");
        let class: u32 = b.lit_str("Worker");
        let two: u32 = b.lit_long(2);
        b.op(op::NEW, T_CONST, T_UNUSED, T_VAR, class, 0, 0, 0, 1);
        b.op(op::DO_FCALL, T_UNUSED, T_UNUSED, T_UNUSED, 0, 0, 0, 0, 1);
        b.op(op::ASSIGN, T_CV, T_VAR, T_UNUSED, 0, 0, 0, 0, 1);
        b.op(op::RETURN, T_CONST, T_UNUSED, T_UNUSED, two, 0, 0, 0, 2);
    });

    assert_eq!(decomp.unrecovered_total, 0);
    assert!(
        decomp.php_skeleton.contains("$worker = new Worker();"),
        "skeleton: {}",
        decomp.php_skeleton
    );
    assert!(
        !decomp.php_skeleton.contains("$var0"),
        "the object must not leak the slot name it was built in: {}",
        decomp.php_skeleton
    );
}

#[test]
fn a_property_read_through_an_unnamed_receiver_is_the_current_object() {
    let decomp: Decompilation = decompiled(|b: &mut OpArrayBuilder| {
        let prop: u32 = b.lit_str("count");
        b.op(op::FETCH_OBJ_R, T_UNUSED, T_CONST, T_TMP, 0, prop, 0, 0, 1);
        b.op(op::ECHO, T_TMP, T_UNUSED, T_UNUSED, 0, 0, 0, 0, 1);
        b.op(op::RETURN, T_CONST, T_UNUSED, T_UNUSED, prop, 0, 0, 0, 2);
    });

    assert_eq!(decomp.unrecovered_total, 0);
    assert!(
        decomp.php_skeleton.contains("echo $this->count;"),
        "skeleton: {}",
        decomp.php_skeleton
    );
}

#[test]
fn a_property_named_by_a_value_stays_a_computed_property() {
    let decomp: Decompilation = decompiled(|b: &mut OpArrayBuilder| {
        b.var("obj");
        b.var("field");
        let one: u32 = b.lit_long(1);
        b.op(op::FETCH_OBJ_R, T_CV, T_CV, T_TMP, 0, 1, 0, 0, 1);
        b.op(op::ECHO, T_TMP, T_UNUSED, T_UNUSED, 0, 0, 0, 0, 1);
        b.op(op::RETURN, T_CONST, T_UNUSED, T_UNUSED, one, 0, 0, 0, 2);
    });

    assert!(
        decomp.php_skeleton.contains("echo $obj->{$field};"),
        "a property whose name is a runtime value must stay computed rather than be guessed as an \
         identifier: {}",
        decomp.php_skeleton
    );
}

#[test]
fn a_default_join_holding_an_unmodelled_op_refuses_instead_of_taking_the_last_branch() {
    let decomp: Decompilation = decompiled(|b: &mut OpArrayBuilder| {
        b.var("value");
        b.var("out");
        let miss: u32 = b.lit_str("miss");
        b.op(op::COALESCE, T_CV, T_UNUSED, T_TMP, 0, 3, 0, 0, 1);
        b.op(op::SWITCH_LONG, T_CV, T_UNUSED, T_UNUSED, 0, 3, 0, 0, 2);
        b.op(op::QM_ASSIGN, T_CONST, T_UNUSED, T_TMP, miss, 0, 0, 0, 3);
        b.op(op::ASSIGN, T_CV, T_TMP, T_UNUSED, 1, 0, 0, 0, 4);
        b.op(op::RETURN, T_CONST, T_UNUSED, T_UNUSED, miss, 0, 0, 0, 5);
    });

    assert!(
        decomp
            .unrecovered
            .iter()
            .any(|entry: &UnrecoveredOp| entry.mnemonic == "ZEND_COALESCE"),
        "when the right-hand side of a default join holds an opcode this lifter cannot model, \
         folding it would silently emit that branch unconditionally, so the join itself must be \
         refused: {:?}\n{}",
        decomp.unrecovered,
        decomp.php_skeleton
    );
    assert!(
        !decomp.php_skeleton.contains("??"),
        "a refused join must not be rendered as a recovered coalesce: {}",
        decomp.php_skeleton
    );
}

#[test]
fn the_refusal_detail_list_is_capped_while_the_reported_total_stays_exact() {
    const OVER_CAP: u32 = 4097;
    let decomp: Decompilation = decompiled(|b: &mut OpArrayBuilder| {
        b.var("k");
        let two: u32 = b.lit_long(2);
        for line in 0..OVER_CAP {
            b.op(
                op::SWITCH_LONG,
                T_CV,
                T_UNUSED,
                T_UNUSED,
                0,
                OVER_CAP,
                0,
                0,
                line,
            );
        }
        b.op(
            op::RETURN,
            T_CONST,
            T_UNUSED,
            T_UNUSED,
            two,
            0,
            0,
            0,
            OVER_CAP,
        );
    });

    assert_eq!(
        decomp.unrecovered_total, OVER_CAP as usize,
        "the reported total must count every refused opcode even past the detail cap"
    );
    assert_eq!(
        decomp.unrecovered.len(),
        4096,
        "the detail list is bounded so a container full of unmodelled opcodes cannot drive an \
         input-sized allocation of records"
    );
}

#[test]
fn two_decompiles_of_one_container_produce_the_same_bytes_and_the_same_refusals() {
    let mut b: OpArrayBuilder = OpArrayBuilder::main();
    b.var("k");
    let one: u32 = b.lit_long(1);
    let two: u32 = b.lit_long(2);
    b.op(op::SWITCH_STRING, T_CV, T_UNUSED, T_UNUSED, 0, 3, 0, 0, 1);
    b.op(op::MATCH, T_CV, T_UNUSED, T_UNUSED, 0, 3, 0, 0, 2);
    b.op(op::ECHO, T_CONST, T_UNUSED, T_UNUSED, one, 0, 0, 0, 3);
    b.op(op::RETURN, T_CONST, T_UNUSED, T_UNUSED, two, 0, 0, 0, 4);
    let bytes: Vec<u8> = b.build_container();
    let parsed = parse_oparray(&bytes).expect("parse oparray");

    let first: Decompilation = decompile_oparray(&parsed);
    let second: Decompilation = decompile_oparray(&parsed);
    assert_eq!(first.php_skeleton, second.php_skeleton);
    assert_eq!(first.unrecovered, second.unrecovered);
    assert_eq!(first.unrecovered_total, 2);
    let indices: Vec<u32> = first
        .unrecovered
        .iter()
        .map(|entry: &UnrecoveredOp| entry.index)
        .collect();
    assert_eq!(
        indices,
        vec![0, 1],
        "refusals are reported in op order so two runs cannot disagree on their order"
    );
}

#[test]
fn nested_depth_guard_rejects_pathological_nesting() {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(OPARRAY_MAGIC);
    out.push(OPARRAY_VERSION);
    for _ in 0..70 {
        out.push(K_MAIN);
        out.push(0);
        out.push(0);
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
    }
    let err = parse_oparray(&out).expect_err("must reject deep nesting");
    let msg: String = format!("{err}");
    assert!(
        msg.contains("DR-PHP-0097") || msg.contains("DR-PHP-0092"),
        "{msg}"
    );
}
