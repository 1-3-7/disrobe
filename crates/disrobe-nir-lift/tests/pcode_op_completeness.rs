#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use disrobe_nir::{NirFunction, NirInstr, NirOp, SourceLang};
use disrobe_nir_lift::{LiftError, PcodeLiftConfig, RegisterCell, lower_pcode_block};
use disrobe_sleigh::lifter::DecodedBlock;
use disrobe_sleigh::pcode::{DecodeStatus, PcodeInstr, PcodeOp, Space, Varnode};

const PCODE_OPERATION_COUNT: usize = 52;
const DECLINED_OPERATIONS: [&str; 0] = [];

const fn node(space: Space, offset: u64, size_bytes: u32) -> Varnode {
    Varnode {
        offset,
        size_bytes,
        space,
    }
}

const fn wide(offset: u64) -> Varnode {
    node(Space::Register, offset, 8)
}

const fn flag() -> Varnode {
    node(Space::Register, 0x100, 1)
}

const fn narrow_flag() -> Varnode {
    node(Space::Constant, 1, 1)
}

const fn wide_constant(value: u64) -> Varnode {
    node(Space::Constant, value, 8)
}

fn registers() -> Vec<RegisterCell> {
    vec![
        RegisterCell::new(0x00, 8, "r0", None),
        RegisterCell::new(0x08, 8, "r1", None),
        RegisterCell::new(0x10, 8, "r2", None),
        RegisterCell::new(0x100, 1, "fl", None),
    ]
}

fn config() -> PcodeLiftConfig {
    PcodeLiftConfig::new(SourceLang::NativeX86, registers()).with_return_value("r0")
}

fn block(operation: PcodeOp) -> DecodedBlock {
    let instruction: PcodeInstr = PcodeInstr {
        address: 0x1000,
        bytes: vec![0x90],
        length: 1,
        mnemonic: "probe".to_owned(),
        ops: vec![operation.clone()],
        operands: String::new(),
        status: DecodeStatus::Supported,
    };
    DecodedBlock {
        consumed: 1,
        instructions: vec![instruction],
        ordered_ops: vec![operation],
    }
}

const fn variant_name(operation: &PcodeOp) -> &'static str {
    match operation {
        PcodeOp::BoolAnd { .. } => "BoolAnd",
        PcodeOp::BoolNegate { .. } => "BoolNegate",
        PcodeOp::BoolOr { .. } => "BoolOr",
        PcodeOp::BoolXor { .. } => "BoolXor",
        PcodeOp::Branch { .. } => "Branch",
        PcodeOp::BranchIndirect { .. } => "BranchIndirect",
        PcodeOp::CBranch { .. } => "CBranch",
        PcodeOp::Call { .. } => "Call",
        PcodeOp::CallIndirect { .. } => "CallIndirect",
        PcodeOp::CallOther { .. } => "CallOther",
        PcodeOp::Copy { .. } => "Copy",
        PcodeOp::FloatAdd { .. } => "FloatAdd",
        PcodeOp::FloatDiv { .. } => "FloatDiv",
        PcodeOp::FloatEqual { .. } => "FloatEqual",
        PcodeOp::FloatLess { .. } => "FloatLess",
        PcodeOp::FloatLessEqual { .. } => "FloatLessEqual",
        PcodeOp::FloatMult { .. } => "FloatMult",
        PcodeOp::FloatSqrt { .. } => "FloatSqrt",
        PcodeOp::FloatSub { .. } => "FloatSub",
        PcodeOp::FloatToFloat { .. } => "FloatToFloat",
        PcodeOp::FloatTrunc { .. } => "FloatTrunc",
        PcodeOp::IntToFloat { .. } => "IntToFloat",
        PcodeOp::IntAdd { .. } => "IntAdd",
        PcodeOp::IntAnd { .. } => "IntAnd",
        PcodeOp::IntCarry { .. } => "IntCarry",
        PcodeOp::IntDiv { .. } => "IntDiv",
        PcodeOp::IntEqual { .. } => "IntEqual",
        PcodeOp::IntLeft { .. } => "IntLeft",
        PcodeOp::IntLess { .. } => "IntLess",
        PcodeOp::IntLessEqual { .. } => "IntLessEqual",
        PcodeOp::IntMult { .. } => "IntMult",
        PcodeOp::IntNegate { .. } => "IntNegate",
        PcodeOp::IntNotEqual { .. } => "IntNotEqual",
        PcodeOp::IntOr { .. } => "IntOr",
        PcodeOp::IntRem { .. } => "IntRem",
        PcodeOp::IntRight { .. } => "IntRight",
        PcodeOp::IntSignedBorrow { .. } => "IntSignedBorrow",
        PcodeOp::IntSignedCarry { .. } => "IntSignedCarry",
        PcodeOp::IntSignedDiv { .. } => "IntSignedDiv",
        PcodeOp::IntSignedLess { .. } => "IntSignedLess",
        PcodeOp::IntSignedLessEqual { .. } => "IntSignedLessEqual",
        PcodeOp::IntSignedRem { .. } => "IntSignedRem",
        PcodeOp::IntSignedRight { .. } => "IntSignedRight",
        PcodeOp::IntSub { .. } => "IntSub",
        PcodeOp::IntXor { .. } => "IntXor",
        PcodeOp::IntSext { .. } => "IntSext",
        PcodeOp::IntZext { .. } => "IntZext",
        PcodeOp::Load { .. } => "Load",
        PcodeOp::Piece { .. } => "Piece",
        PcodeOp::Return { .. } => "Return",
        PcodeOp::Store { .. } => "Store",
        PcodeOp::Subpiece { .. } => "Subpiece",
    }
}

type TernaryBuilder = fn(Varnode, Varnode, Varnode) -> PcodeOp;

const ARITHMETIC_BUILDERS: [TernaryBuilder; 14] = [
    |output, left, right| PcodeOp::FloatAdd {
        output,
        left,
        right,
    },
    |output, left, right| PcodeOp::FloatDiv {
        output,
        left,
        right,
    },
    |output, left, right| PcodeOp::FloatMult {
        output,
        left,
        right,
    },
    |output, left, right| PcodeOp::FloatSub {
        output,
        left,
        right,
    },
    |output, left, right| PcodeOp::IntAdd {
        output,
        left,
        right,
    },
    |output, left, right| PcodeOp::IntAnd {
        output,
        left,
        right,
    },
    |output, left, right| PcodeOp::IntDiv {
        output,
        left,
        right,
    },
    |output, left, right| PcodeOp::IntMult {
        output,
        left,
        right,
    },
    |output, left, right| PcodeOp::IntOr {
        output,
        left,
        right,
    },
    |output, left, right| PcodeOp::IntRem {
        output,
        left,
        right,
    },
    |output, left, right| PcodeOp::IntSignedDiv {
        output,
        left,
        right,
    },
    |output, left, right| PcodeOp::IntSignedRem {
        output,
        left,
        right,
    },
    |output, left, right| PcodeOp::IntSub {
        output,
        left,
        right,
    },
    |output, left, right| PcodeOp::IntXor {
        output,
        left,
        right,
    },
];

const PREDICATE_BUILDERS: [TernaryBuilder; 12] = [
    |output, left, right| PcodeOp::FloatEqual {
        output,
        left,
        right,
    },
    |output, left, right| PcodeOp::FloatLess {
        output,
        left,
        right,
    },
    |output, left, right| PcodeOp::FloatLessEqual {
        output,
        left,
        right,
    },
    |output, left, right| PcodeOp::IntCarry {
        output,
        left,
        right,
    },
    |output, left, right| PcodeOp::IntEqual {
        output,
        left,
        right,
    },
    |output, left, right| PcodeOp::IntLess {
        output,
        left,
        right,
    },
    |output, left, right| PcodeOp::IntLessEqual {
        output,
        left,
        right,
    },
    |output, left, right| PcodeOp::IntNotEqual {
        output,
        left,
        right,
    },
    |output, left, right| PcodeOp::IntSignedBorrow {
        output,
        left,
        right,
    },
    |output, left, right| PcodeOp::IntSignedCarry {
        output,
        left,
        right,
    },
    |output, left, right| PcodeOp::IntSignedLess {
        output,
        left,
        right,
    },
    |output, left, right| PcodeOp::IntSignedLessEqual {
        output,
        left,
        right,
    },
];

fn every_operation() -> Vec<PcodeOp> {
    let mut operations: Vec<PcodeOp> = vec![
        PcodeOp::BoolAnd {
            output: flag(),
            left: narrow_flag(),
            right: narrow_flag(),
        },
        PcodeOp::BoolNegate {
            output: flag(),
            input: narrow_flag(),
        },
        PcodeOp::BoolOr {
            output: flag(),
            left: narrow_flag(),
            right: narrow_flag(),
        },
        PcodeOp::BoolXor {
            output: flag(),
            left: narrow_flag(),
            right: narrow_flag(),
        },
        PcodeOp::Branch {
            target: node(Space::Ram, 0x2000, 8),
        },
        PcodeOp::BranchIndirect { target: wide(0x08) },
        PcodeOp::CBranch {
            target: node(Space::Ram, 0x2000, 8),
            condition: narrow_flag(),
        },
        PcodeOp::Call {
            target: node(Space::Ram, 0x3000, 8),
        },
        PcodeOp::CallIndirect { target: wide(0x08) },
        PcodeOp::CallOther {
            name: "probe_effect".to_owned(),
            output: Some(wide(0x00)),
            inputs: vec![wide(0x08)],
        },
        PcodeOp::Copy {
            output: wide(0x00),
            input: wide_constant(0x1234),
        },
        PcodeOp::FloatSqrt {
            output: wide(0x00),
            input: wide(0x08),
        },
        PcodeOp::FloatToFloat {
            output: wide(0x00),
            input: wide(0x08),
        },
        PcodeOp::FloatTrunc {
            output: wide(0x00),
            input: wide(0x08),
        },
        PcodeOp::IntToFloat {
            output: wide(0x00),
            input: wide(0x08),
        },
        PcodeOp::IntNegate {
            output: wide(0x00),
            input: wide(0x08),
        },
        PcodeOp::IntSext {
            output: wide(0x00),
            input: node(Space::Constant, 0x40, 4),
        },
        PcodeOp::IntZext {
            output: wide(0x00),
            input: node(Space::Constant, 0x40, 4),
        },
        PcodeOp::IntLeft {
            output: wide(0x00),
            input: wide(0x08),
            amount: narrow_flag(),
        },
        PcodeOp::IntRight {
            output: wide(0x00),
            input: wide(0x08),
            amount: narrow_flag(),
        },
        PcodeOp::IntSignedRight {
            output: wide(0x00),
            input: wide(0x08),
            amount: narrow_flag(),
        },
        PcodeOp::Load {
            output: wide(0x00),
            space: Space::Ram,
            pointer: wide(0x08),
        },
        PcodeOp::Piece {
            output: wide(0x00),
            high: node(Space::Constant, 0x11, 4),
            low: node(Space::Constant, 0x22, 4),
        },
        PcodeOp::Return { target: None },
        PcodeOp::Store {
            space: Space::Ram,
            pointer: wide(0x08),
            value: wide(0x10),
        },
        PcodeOp::Subpiece {
            output: node(Space::Register, 0x00, 4),
            input: wide(0x08),
            byte_offset: node(Space::Constant, 0, 1),
        },
    ];
    for build in ARITHMETIC_BUILDERS {
        operations.push(build(wide(0x00), wide(0x08), wide(0x10)));
    }
    for build in PREDICATE_BUILDERS {
        operations.push(build(flag(), wide(0x08), wide(0x10)));
    }
    operations
}

#[test]
fn every_pcode_operation_lowers_or_rejects_and_none_is_dropped() {
    let operations: Vec<PcodeOp> = every_operation();
    let names: BTreeSet<&'static str> = operations.iter().map(variant_name).collect();
    assert_eq!(
        names.len(),
        operations.len(),
        "the operation set must name each p-code operation exactly once"
    );
    assert_eq!(
        names.len(),
        PCODE_OPERATION_COUNT,
        "the pinned p-code operation count must track the sleigh operation set: {names:?}"
    );

    let lift_config: PcodeLiftConfig = config();
    let mut lowered: BTreeSet<&'static str> = BTreeSet::new();
    let mut declined: Vec<&'static str> = Vec::new();
    for operation in &operations {
        let name: &'static str = variant_name(operation);
        let decoded: DecodedBlock = block(operation.clone());
        match lower_pcode_block(&decoded, "probe", &lift_config) {
            Ok(function) => {
                let function: NirFunction = function;
                assert!(
                    !function.instructions.is_empty(),
                    "{name} lowered to an empty instruction list, which drops it from the IR"
                );
                assert!(
                    function
                        .instructions
                        .iter()
                        .all(|instruction: &NirInstr| instruction.address == 0x1000),
                    "{name} must keep the machine address of the operation it came from"
                );
                lowered.insert(name);
            }
            Err(error) => {
                let error: LiftError = error;
                assert!(
                    matches!(error, LiftError::InvalidPcode { .. }),
                    "{name} must reject with a typed p-code error, saw {error}"
                );
                declined.push(name);
            }
        }
    }

    assert_eq!(
        declined.as_slice(),
        DECLINED_OPERATIONS.as_slice(),
        "the declined p-code operation list is pinned; growing it silently hides a dropped operation"
    );
    assert_eq!(
        lowered.len(),
        PCODE_OPERATION_COUNT,
        "p-code operation coverage is {}/{PCODE_OPERATION_COUNT}",
        lowered.len()
    );
}

#[test]
fn an_operation_with_no_pcode_semantics_is_reported_not_skipped() {
    let instruction: PcodeInstr = PcodeInstr {
        address: 0x1000,
        bytes: vec![0xff, 0xff, 0xff, 0xff],
        length: 4,
        mnemonic: ".inst".to_owned(),
        ops: Vec::new(),
        operands: String::new(),
        status: DecodeStatus::NoMatch,
    };
    let decoded: DecodedBlock = DecodedBlock {
        consumed: 4,
        instructions: vec![instruction],
        ordered_ops: Vec::new(),
    };
    let error: LiftError =
        lower_pcode_block(&decoded, "probe", &config()).expect_err("an undecoded instruction");
    assert!(
        matches!(error, LiftError::InvalidPcode { .. }),
        "an instruction with no p-code semantics must be a typed refusal, saw {error}"
    );
}

#[test]
fn an_unmodelled_machine_effect_reaches_the_ir_as_a_named_gap() {
    let decoded: DecodedBlock = block(PcodeOp::CallOther {
        name: "unsupported_probe".to_owned(),
        output: None,
        inputs: Vec::new(),
    });
    let function: NirFunction =
        lower_pcode_block(&decoded, "probe", &config()).expect("lower an unmodelled effect");
    let names: Vec<String> = function
        .instructions
        .iter()
        .filter_map(|instruction: &NirInstr| match &instruction.op {
            NirOp::CallOther { effect } => Some(effect.name.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        names,
        vec!["unsupported_probe".to_owned()],
        "an unmodelled machine effect must reach the IR under its own name"
    );
}
