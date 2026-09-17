#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_nir::{NirFunction, NirInstr, NirOp, ValueId, ValueOp, def_use};
use disrobe_nir_lift::lower_aarch64;

const RET: u32 = 0xd65f_03c0;

fn lower_one(word: u32) -> NirFunction {
    let mut bytes: Vec<u8> = word.to_le_bytes().to_vec();
    bytes.extend_from_slice(&RET.to_le_bytes());
    lower_aarch64(&bytes, 0x1000, "probe").expect("lower aarch64 instruction")
}

fn has_value(nir: &NirFunction, op: ValueOp, expected_inputs: &[&str]) -> bool {
    nir.instructions.iter().any(|instruction: &NirInstr| {
        let NirOp::Value {
            op: found, inputs, ..
        } = &instruction.op
        else {
            return false;
        };
        *found == op
            && expected_inputs
                .iter()
                .all(|wanted: &&str| inputs.iter().any(|actual: &String| actual == wanted))
    })
}

fn flag_registers(nir: &NirFunction) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for instruction in &nir.instructions {
        let flow: disrobe_nir::DefUse = def_use(instruction);
        for value in flow.defs.iter().chain(flow.uses.iter()) {
            if let ValueId::Register(name) = value
                && matches!(name.as_str(), "ng" | "zr" | "cy" | "ov")
            {
                names.push(name.clone());
            }
        }
    }
    names
}

#[test]
fn add_sub_immediate_lower_to_int_arith() {
    assert!(has_value(
        &lower_one(0x9100_0420),
        ValueOp::IntAdd,
        &["x1", "0x1"]
    ));
    assert!(has_value(
        &lower_one(0xd100_0420),
        ValueOp::IntSub,
        &["x1", "0x1"]
    ));
}

#[test]
fn shifted_register_add_lowers_with_shift() {
    let nir: NirFunction = lower_one(0x8b02_0c20);
    assert!(has_value(&nir, ValueOp::IntLeft, &["x2", "0x3"]));
    assert!(has_value(&nir, ValueOp::IntAdd, &["x1"]));
}

#[test]
fn logical_register_ops_lower_to_bitwise() {
    assert!(has_value(
        &lower_one(0xaa02_0020),
        ValueOp::IntOr,
        &["x1", "x2"]
    ));
    assert!(has_value(
        &lower_one(0xca02_0020),
        ValueOp::IntXor,
        &["x1", "x2"]
    ));
    assert!(has_value(
        &lower_one(0x8a02_0020),
        ValueOp::IntAnd,
        &["x1", "x2"]
    ));
}

#[test]
fn multiply_and_multiply_add_lower_to_int_mult() {
    assert!(has_value(
        &lower_one(0x9b02_7c20),
        ValueOp::IntMult,
        &["x1", "x2"]
    ));
    let madd: NirFunction = lower_one(0x9b02_0c20);
    assert!(has_value(&madd, ValueOp::IntMult, &["x1", "x2"]));
    assert!(has_value(&madd, ValueOp::IntAdd, &["x3"]));
}

#[test]
fn move_wide_lowers_to_constant_copy() {
    let nir: NirFunction = lower_one(0xd2a2_4680);
    assert!(nir.instructions.iter().any(|instruction: &NirInstr| {
        matches!(&instruction.op, NirOp::Copy { src, .. } if src == "0x12340000")
    }));
}

#[test]
fn load_store_lower_to_raw_memory_access() {
    let load: NirFunction = lower_one(0xf940_0420);
    assert!(load.instructions.iter().any(|instruction: &NirInstr| {
        matches!(instruction.op, NirOp::RawLoad { .. }) && instruction.reads_memory
    }));
    let store: NirFunction = lower_one(0xf900_0420);
    assert!(store.instructions.iter().any(|instruction: &NirInstr| {
        matches!(instruction.op, NirOp::RawStore { .. }) && instruction.writes_memory
    }));
}

#[test]
fn compare_branch_zero_lowers_to_int_equal_without_flags() {
    let nir: NirFunction =
        lower_aarch64(&0x3400_0040_u32.to_le_bytes(), 0x1000, "probe").expect("lower cbz block");
    assert!(has_value(&nir, ValueOp::IntEqual, &["0x0"]));
    assert!(
        nir.instructions
            .iter()
            .any(|instruction: &NirInstr| matches!(instruction.op, NirOp::CondBranch { .. }))
    );
    assert!(flag_registers(&nir).is_empty(), "cbz must not touch nzcv");
}

#[test]
fn dead_compare_flags_are_eliminated() {
    let nir: NirFunction = lower_one(0xf100_141f);
    assert!(
        flag_registers(&nir).is_empty(),
        "unused cmp flags must be discarded"
    );
}

#[test]
fn flag_setting_arithmetic_keeps_result_and_drops_dead_flags() {
    let nir: NirFunction = lower_one(0xb100_0420);
    assert!(has_value(&nir, ValueOp::IntAdd, &["x1", "0x1"]));
    assert!(
        flag_registers(&nir).is_empty(),
        "adds result is live but its dead flags must be discarded"
    );
}

#[test]
fn control_returns_and_branches_lower() {
    let ret: NirFunction = lower_aarch64(&RET.to_le_bytes(), 0x1000, "probe").expect("lower ret");
    assert!(
        ret.instructions
            .iter()
            .any(|instruction: &NirInstr| matches!(instruction.op, NirOp::Return))
    );
    let mut branch_bytes: Vec<u8> = 0x1400_000d_u32.to_le_bytes().to_vec();
    branch_bytes.extend_from_slice(&RET.to_le_bytes());
    let branch: NirFunction = lower_aarch64(&branch_bytes, 0x1000, "probe").expect("lower b block");
    assert!(
        branch
            .instructions
            .iter()
            .any(|instruction: &NirInstr| matches!(instruction.op, NirOp::Branch { .. }))
    );
}
