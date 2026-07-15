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
    Decompilation, OPARRAY_MAGIC, OPARRAY_VERSION, decompile_oparray, parse_oparray,
};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

const T_UNUSED: u8 = 0;
const T_CONST: u8 = 1;
const T_TMP: u8 = 2;
const K_MAIN: u8 = 0;
const L_LONG: u8 = 2;

#[derive(Default)]
struct OpArrayBuilder {
    literals: Vec<u8>,
    literal_count: u32,
    ops: Vec<u8>,
    op_count: u32,
}

impl OpArrayBuilder {
    fn main() -> Self {
        Self::default()
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
    ) -> &mut Self {
        self.ops.push(opcode);
        self.ops.push(op1_type);
        self.ops.push(op2_type);
        self.ops.push(result_type);
        self.ops.extend_from_slice(&op1.to_le_bytes());
        self.ops.extend_from_slice(&op2.to_le_bytes());
        self.ops.extend_from_slice(&result.to_le_bytes());
        self.ops.extend_from_slice(&0u32.to_le_bytes());
        self.ops.extend_from_slice(&1u32.to_le_bytes());
        self.op_count += 1;
        self
    }

    fn build_container(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(OPARRAY_MAGIC);
        out.push(OPARRAY_VERSION);
        out.push(K_MAIN);
        out.push(0);
        out.push(0);
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&self.literal_count.to_le_bytes());
        out.extend_from_slice(&self.literals);
        out.extend_from_slice(&self.op_count.to_le_bytes());
        out.extend_from_slice(&self.ops);
        out.extend_from_slice(&0u32.to_le_bytes());
        out
    }
}

fn skeleton_of(b: &OpArrayBuilder) -> String {
    let bytes: Vec<u8> = b.build_container();
    let parsed = parse_oparray(&bytes).expect("parse oparray");
    let decomp: Decompilation = decompile_oparray(&parsed);
    decomp.php_skeleton
}

fn php_eval(skeleton: &str) -> Option<(bool, String)> {
    let seq: u64 = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let name: String = format!("disrobe_php_prec_{}_{seq}.php", std::process::id());
    let path: std::path::PathBuf = std::env::temp_dir().join(name);
    std::fs::write(&path, skeleton).ok()?;
    let result = Command::new("php").arg("-n").arg(&path).output();
    let _ = std::fs::remove_file(&path);
    let out = result.ok()?;
    let stdout: String = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    Some((out.status.success(), stdout))
}

fn assert_case(skeleton: &str, expected_line: &str, expected_value: i64) {
    assert!(
        skeleton.contains(expected_line),
        "expected `{expected_line}` in skeleton:\n{skeleton}"
    );
    if let Some((ok, value)) = php_eval(skeleton) {
        assert!(ok, "php rejected emitted source:\n{skeleton}");
        assert_eq!(
            value,
            expected_value.to_string(),
            "emitted source evaluates to the wrong value:\n{skeleton}"
        );
    }
}

#[test]
fn left_nested_power_keeps_left_group_parenthesized() {
    let mut b: OpArrayBuilder = OpArrayBuilder::main();
    let two: u32 = b.lit_long(2);
    let three: u32 = b.lit_long(3);
    let two_b: u32 = b.lit_long(2);
    b.op(op::POW, T_CONST, T_CONST, T_TMP, two, three, 5);
    b.op(op::POW, T_TMP, T_CONST, T_TMP, 5, two_b, 6);
    b.op(op::ECHO, T_TMP, T_UNUSED, T_UNUSED, 6, 0, 0);
    b.op(op::RETURN, T_UNUSED, T_UNUSED, T_UNUSED, 0, 0, 0);

    let skeleton: String = skeleton_of(&b);
    let intended: i64 = 2i64.pow(3).pow(2);
    assert_case(&skeleton, "echo (2 ** 3) ** 2;", intended);
}

#[test]
fn right_nested_power_stays_bare_for_right_association() {
    let mut b: OpArrayBuilder = OpArrayBuilder::main();
    let two: u32 = b.lit_long(2);
    let three: u32 = b.lit_long(3);
    let two_b: u32 = b.lit_long(2);
    b.op(op::POW, T_CONST, T_CONST, T_TMP, three, two_b, 5);
    b.op(op::POW, T_CONST, T_TMP, T_TMP, two, 5, 6);
    b.op(op::ECHO, T_TMP, T_UNUSED, T_UNUSED, 6, 0, 0);
    b.op(op::RETURN, T_UNUSED, T_UNUSED, T_UNUSED, 0, 0, 0);

    let skeleton: String = skeleton_of(&b);
    assert!(
        !skeleton.contains("(2 ** 3)"),
        "right-associated power must not parenthesize its left leg:\n{skeleton}"
    );
    let intended: i64 = 2i64.pow(3u32.pow(2));
    assert_case(&skeleton, "echo 2 ** 3 ** 2;", intended);
}

#[test]
fn subtraction_right_operand_is_parenthesized() {
    let mut b: OpArrayBuilder = OpArrayBuilder::main();
    let twenty: u32 = b.lit_long(20);
    let eight: u32 = b.lit_long(8);
    let three: u32 = b.lit_long(3);
    b.op(op::SUB, T_CONST, T_CONST, T_TMP, eight, three, 5);
    b.op(op::SUB, T_CONST, T_TMP, T_TMP, twenty, 5, 6);
    b.op(op::ECHO, T_TMP, T_UNUSED, T_UNUSED, 6, 0, 0);
    b.op(op::RETURN, T_UNUSED, T_UNUSED, T_UNUSED, 0, 0, 0);

    let skeleton: String = skeleton_of(&b);
    assert_case(&skeleton, "echo 20 - (8 - 3);", 20 - (8 - 3));
}

#[test]
fn division_right_operand_is_parenthesized() {
    let mut b: OpArrayBuilder = OpArrayBuilder::main();
    let sixty_four: u32 = b.lit_long(64);
    let eight: u32 = b.lit_long(8);
    let two: u32 = b.lit_long(2);
    b.op(op::DIV, T_CONST, T_CONST, T_TMP, eight, two, 5);
    b.op(op::DIV, T_CONST, T_TMP, T_TMP, sixty_four, 5, 6);
    b.op(op::ECHO, T_TMP, T_UNUSED, T_UNUSED, 6, 0, 0);
    b.op(op::RETURN, T_UNUSED, T_UNUSED, T_UNUSED, 0, 0, 0);

    let skeleton: String = skeleton_of(&b);
    assert_case(&skeleton, "echo 64 / (8 / 2);", 64 / (8 / 2));
}

#[test]
fn bitwise_or_left_operand_of_add_is_parenthesized() {
    let mut b: OpArrayBuilder = OpArrayBuilder::main();
    let one: u32 = b.lit_long(1);
    let two: u32 = b.lit_long(2);
    let four: u32 = b.lit_long(4);
    b.op(op::BW_OR, T_CONST, T_CONST, T_TMP, one, two, 5);
    b.op(op::ADD, T_TMP, T_CONST, T_TMP, 5, four, 6);
    b.op(op::ECHO, T_TMP, T_UNUSED, T_UNUSED, 6, 0, 0);
    b.op(op::RETURN, T_UNUSED, T_UNUSED, T_UNUSED, 0, 0, 0);

    let skeleton: String = skeleton_of(&b);
    assert_case(&skeleton, "echo (1 | 2) + 4;", (1 | 2) + 4);
}
