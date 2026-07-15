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
    Branch, Decompilation, Fidelity, OPARRAY_MAGIC, OPARRAY_VERSION, OperandType, build_cfg,
    decompile_oparray, opcode_name, parse_oparray,
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
fn operand_type_wire_mapping_matches_zend_is_constants() {
    assert_eq!(OperandType::from_wire(T_UNUSED), Some(OperandType::Unused));
    assert_eq!(OperandType::from_wire(T_CONST), Some(OperandType::Const));
    assert_eq!(OperandType::from_wire(T_TMP), Some(OperandType::TmpVar));
    assert_eq!(OperandType::from_wire(T_VAR), Some(OperandType::Var));
    assert_eq!(OperandType::from_wire(T_CV), Some(OperandType::Cv));
    assert_eq!(OperandType::from_wire(3), None);
    assert_eq!(OperandType::from_wire(255), None);
}

#[test]
fn opcode_names_match_zend_vm_opcodes_header() {
    assert_eq!(opcode_name(op::ECHO), "ZEND_ECHO");
    assert_eq!(opcode_name(op::ASSIGN), "ZEND_ASSIGN");
    assert_eq!(opcode_name(op::JMPZ), "ZEND_JMPZ");
    assert_eq!(opcode_name(op::RETURN), "ZEND_RETURN");
    assert_eq!(opcode_name(op::INIT_FCALL), "ZEND_INIT_FCALL");
    assert_eq!(opcode_name(op::FE_FETCH_R), "ZEND_FE_FETCH_R");
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

fn php_bin() -> Option<String> {
    let candidate: &str = "php";
    let ok: bool = std::process::Command::new(candidate)
        .arg("--version")
        .output()
        .map(|o: std::process::Output| o.status.success())
        .unwrap_or(false);
    if ok { Some(candidate.to_owned()) } else { None }
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
