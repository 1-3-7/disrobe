#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_lift_x86::decode_block_x86;
use disrobe_nir::{DefUse, NirFunction, NirInstr, NirOp, SourceLang, ValueId, ValueOp, def_use};
use disrobe_nir_lift::{PcodeLiftConfig, lower_aarch64, lower_pcode_block, lower_x86_64};
use disrobe_sleigh::lifter::DecodedBlock;
use disrobe_sleigh::pcode::{DecodeStatus, PcodeInstr, PcodeOp, Space, Varnode};

const RET: u32 = 0xd65f_03c0;
const CMP_X1_X2: u32 = 0xeb02_003f;

fn x86_folded(condition_opcode: u8) -> NirFunction {
    let bytes: [u8; 6] = [0x48, 0x39, 0xc8, condition_opcode, 0x02, 0xc3];
    let block: DecodedBlock = decode_block_x86(&bytes, 0x1000, 64);
    lower_pcode_block(
        &block,
        "probe",
        &PcodeLiftConfig::x86_64().with_condition_code_folding(),
    )
    .expect("lower x86 with condition folding")
}

fn arm_folded(condition_nibble: u32) -> NirFunction {
    let branch: u32 = 0x5400_0040 | condition_nibble;
    let bytes: Vec<u8> = [CMP_X1_X2, branch, RET]
        .iter()
        .flat_map(|word: &u32| word.to_le_bytes())
        .collect();
    lower_aarch64(&bytes, 0x1000, "probe").expect("lower aarch64 with condition folding")
}

fn condition_comparison(nir: &NirFunction) -> Option<(ValueOp, Vec<String>)> {
    let branch: &NirInstr = nir
        .instructions
        .iter()
        .find(|instruction: &&NirInstr| matches!(instruction.op, NirOp::CondBranch { .. }))?;
    let predicate: &String = branch.operands.first()?;
    nir.instructions
        .iter()
        .find_map(|instruction: &NirInstr| match &instruction.op {
            NirOp::Value { op, inputs, .. } if instruction.operands.first() == Some(predicate) => {
                Some((*op, inputs.clone()))
            }
            _ => None,
        })
}

fn flag_registers(nir: &NirFunction) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for instruction in &nir.instructions {
        let flow: DefUse = def_use(instruction);
        for value in flow.defs.iter().chain(flow.uses.iter()) {
            if let ValueId::Register(name) = value
                && matches!(
                    name.as_str(),
                    "ng" | "zr" | "cy" | "ov" | "zf" | "sf" | "cf" | "of" | "pf" | "af"
                )
            {
                names.push(name.clone());
            }
        }
    }
    names
}

fn hardware_flags(a: u8, b: u8) -> (bool, bool, bool, bool) {
    let difference: u8 = a.wrapping_sub(b);
    let zero: bool = a == b;
    let sign: bool = (difference as i8) < 0;
    let carry: bool = a < b;
    let signed: i16 = i16::from(a as i8) - i16::from(b as i8);
    let overflow: bool = !(-128..=127).contains(&signed);
    (zero, sign, carry, overflow)
}

fn evaluate(op: ValueOp, left: u8, right: u8) -> bool {
    match op {
        ValueOp::IntEqual => left == right,
        ValueOp::IntNotEqual => left != right,
        ValueOp::IntLess => left < right,
        ValueOp::IntLessEqual => left <= right,
        ValueOp::IntSignedLess => (left as i8) < (right as i8),
        ValueOp::IntSignedLessEqual => (left as i8) <= (right as i8),
        other => panic!("unexpected folded comparison op {other:?}"),
    }
}

fn emitted_predicate(op: ValueOp, inputs: &[String], first: &str, a: u8, b: u8) -> bool {
    let resolve = |name: &String| -> u8 { if name == first { a } else { b } };
    let left: u8 = resolve(inputs.first().expect("comparison has a left input"));
    let right: u8 = resolve(inputs.get(1).expect("comparison has a right input"));
    evaluate(op, left, right)
}

struct Case {
    name: &'static str,
    x86_opcode: u8,
    arm_nibble: u32,
    expected: ValueOp,
    swapped: bool,
    flag_expr: fn(bool, bool, bool, bool) -> bool,
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "equal",
            x86_opcode: 0x74,
            arm_nibble: 0x0,
            expected: ValueOp::IntEqual,
            swapped: false,
            flag_expr: |zero: bool, _sign: bool, _carry: bool, _overflow: bool| zero,
        },
        Case {
            name: "not-equal",
            x86_opcode: 0x75,
            arm_nibble: 0x1,
            expected: ValueOp::IntNotEqual,
            swapped: false,
            flag_expr: |zero: bool, _sign: bool, _carry: bool, _overflow: bool| !zero,
        },
        Case {
            name: "unsigned-below",
            x86_opcode: 0x72,
            arm_nibble: 0x3,
            expected: ValueOp::IntLess,
            swapped: false,
            flag_expr: |_zero: bool, _sign: bool, carry: bool, _overflow: bool| carry,
        },
        Case {
            name: "unsigned-above-equal",
            x86_opcode: 0x73,
            arm_nibble: 0x2,
            expected: ValueOp::IntLessEqual,
            swapped: true,
            flag_expr: |_zero: bool, _sign: bool, carry: bool, _overflow: bool| !carry,
        },
        Case {
            name: "unsigned-below-equal",
            x86_opcode: 0x76,
            arm_nibble: 0x9,
            expected: ValueOp::IntLessEqual,
            swapped: false,
            flag_expr: |zero: bool, _sign: bool, carry: bool, _overflow: bool| carry || zero,
        },
        Case {
            name: "unsigned-above",
            x86_opcode: 0x77,
            arm_nibble: 0x8,
            expected: ValueOp::IntLess,
            swapped: true,
            flag_expr: |zero: bool, _sign: bool, carry: bool, _overflow: bool| !(carry || zero),
        },
        Case {
            name: "signed-less",
            x86_opcode: 0x7c,
            arm_nibble: 0xb,
            expected: ValueOp::IntSignedLess,
            swapped: false,
            flag_expr: |_zero: bool, sign: bool, _carry: bool, overflow: bool| sign ^ overflow,
        },
        Case {
            name: "signed-greater-equal",
            x86_opcode: 0x7d,
            arm_nibble: 0xa,
            expected: ValueOp::IntSignedLessEqual,
            swapped: true,
            flag_expr: |_zero: bool, sign: bool, _carry: bool, overflow: bool| !(sign ^ overflow),
        },
        Case {
            name: "signed-less-equal",
            x86_opcode: 0x7e,
            arm_nibble: 0xd,
            expected: ValueOp::IntSignedLessEqual,
            swapped: false,
            flag_expr: |zero: bool, sign: bool, _carry: bool, overflow: bool| {
                zero || (sign ^ overflow)
            },
        },
        Case {
            name: "signed-greater",
            x86_opcode: 0x7f,
            arm_nibble: 0xc,
            expected: ValueOp::IntSignedLess,
            swapped: true,
            flag_expr: |zero: bool, sign: bool, _carry: bool, overflow: bool| {
                !(zero || (sign ^ overflow))
            },
        },
    ]
}

#[test]
fn x86_condition_codes_fold_to_exact_comparisons() {
    for case in cases() {
        let nir: NirFunction = x86_folded(case.x86_opcode);
        let (op, inputs): (ValueOp, Vec<String>) =
            condition_comparison(&nir).unwrap_or_else(|| {
                panic!(
                    "{}: cbranch condition is not a folded comparison",
                    case.name
                )
            });
        assert_eq!(op, case.expected, "{}: folded op", case.name);
        let expected_inputs: Vec<&str> = if case.swapped {
            vec!["rcx", "rax"]
        } else {
            vec!["rax", "rcx"]
        };
        assert_eq!(inputs, expected_inputs, "{}: folded operands", case.name);
        assert!(
            flag_registers(&nir).is_empty(),
            "{}: eflags must be gone after folding, saw {:?}",
            case.name,
            flag_registers(&nir)
        );
    }
}

#[test]
fn aarch64_condition_codes_fold_to_exact_comparisons() {
    for case in cases() {
        let nir: NirFunction = arm_folded(case.arm_nibble);
        let (op, inputs): (ValueOp, Vec<String>) =
            condition_comparison(&nir).unwrap_or_else(|| {
                panic!(
                    "{}: cbranch condition is not a folded comparison",
                    case.name
                )
            });
        assert_eq!(op, case.expected, "{}: folded op", case.name);
        let expected_inputs: Vec<&str> = if case.swapped {
            vec!["x2", "x1"]
        } else {
            vec!["x1", "x2"]
        };
        assert_eq!(inputs, expected_inputs, "{}: folded operands", case.name);
        assert!(
            flag_registers(&nir).is_empty(),
            "{}: nzcv must be gone after folding, saw {:?}",
            case.name,
            flag_registers(&nir)
        );
    }
}

#[test]
fn folded_comparisons_match_flag_semantics_over_full_byte_domain() {
    for case in cases() {
        for (encoding, first, second) in [
            (x86_folded(case.x86_opcode), "rax", "rcx"),
            (arm_folded(case.arm_nibble), "x1", "x2"),
        ] {
            let (op, inputs): (ValueOp, Vec<String>) = condition_comparison(&encoding)
                .unwrap_or_else(|| panic!("{}: no folded comparison", case.name));
            assert!(
                inputs
                    .iter()
                    .all(|name: &String| name == first || name == second),
                "{}: comparison references only the compared operands",
                case.name
            );
            for a in 0_u16..=255 {
                for b in 0_u16..=255 {
                    let byte_a: u8 = a as u8;
                    let byte_b: u8 = b as u8;
                    let (zero, sign, carry, overflow): (bool, bool, bool, bool) =
                        hardware_flags(byte_a, byte_b);
                    let reference: bool = (case.flag_expr)(zero, sign, carry, overflow);
                    let folded: bool = emitted_predicate(op, &inputs, first, byte_a, byte_b);
                    assert_eq!(
                        folded, reference,
                        "{}: folded comparison diverges from the flag expression at a={byte_a} b={byte_b}",
                        case.name
                    );
                }
            }
        }
    }
}

#[test]
fn compare_branch_zero_is_left_as_a_direct_equality() {
    let bytes: Vec<u8> = [0x3400_0040_u32, RET]
        .iter()
        .flat_map(|word: &u32| word.to_le_bytes())
        .collect();
    let nir: NirFunction = lower_aarch64(&bytes, 0x1000, "probe").expect("lower cbz");
    let (op, inputs): (ValueOp, Vec<String>) =
        condition_comparison(&nir).expect("cbz keeps an int_equal predicate");
    assert_eq!(op, ValueOp::IntEqual);
    assert!(inputs.iter().any(|name: &String| name == "0x0"));
    assert!(flag_registers(&nir).is_empty(), "cbz never touches nzcv");
}

#[test]
fn x86_default_lowering_keeps_the_flag_expression_unfolded() {
    let nir: NirFunction = lower_x86_64(&[0x48, 0x39, 0xc8, 0x7e, 0x02, 0xc3], 0x1000, "probe")
        .expect("lower x86 without folding");
    assert!(
        !flag_registers(&nir).is_empty(),
        "the default x86 path must preserve the eflags expression for downstream consumers"
    );
    assert!(
        nir.instructions
            .iter()
            .any(|instruction: &NirInstr| matches!(
                instruction.op,
                NirOp::Value {
                    op: ValueOp::IntSignedBorrow,
                    ..
                }
            )),
        "the raw signed-overflow flag is retained without folding"
    );
}

#[test]
fn sign_and_overflow_tests_are_not_treated_as_comparisons() {
    let sign_test: NirFunction = x86_folded(0x78);
    assert!(
        sign_test
            .instructions
            .iter()
            .any(|instruction: &NirInstr| matches!(
                instruction.op,
                NirOp::Value {
                    op: ValueOp::IntSignedLess,
                    ..
                }
            )),
        "js is a sign-bit test and must keep its flag expression, not fold to a comparison"
    );
    assert!(
        !flag_registers(&sign_test).is_empty(),
        "js keeps the sign flag; it is not a two-operand comparison"
    );

    let overflow_test: NirFunction = x86_folded(0x70);
    assert!(
        overflow_test
            .instructions
            .iter()
            .any(|instruction: &NirInstr| matches!(
                instruction.op,
                NirOp::Value {
                    op: ValueOp::IntSignedBorrow,
                    ..
                }
            )),
        "jo is an overflow test and must keep its flag expression"
    );
}

const fn node(space: Space, offset: u64, size_bytes: u32) -> Varnode {
    Varnode {
        offset,
        size_bytes,
        space,
    }
}

fn pcode_instruction(address: u64, ops: Vec<PcodeOp>) -> PcodeInstr {
    PcodeInstr {
        address,
        bytes: vec![0x90],
        length: 1,
        mnemonic: "probe".to_owned(),
        ops,
        operands: String::new(),
        status: DecodeStatus::Supported,
    }
}

#[test]
fn operand_clobber_between_compare_and_branch_blocks_the_fold() {
    let rax: Varnode = node(Space::Register, 0x00, 8);
    let rcx: Varnode = node(Space::Register, 0x08, 8);
    let rdx: Varnode = node(Space::Register, 0x10, 8);
    let difference: Varnode = node(Space::Unique, 0x00, 8);
    let sign: Varnode = node(Space::Register, 0x207, 1);
    let overflow: Varnode = node(Space::Register, 0x20b, 1);
    let predicate: Varnode = node(Space::Unique, 0x08, 1);
    let instructions: Vec<PcodeInstr> = vec![
        pcode_instruction(
            0x1000,
            vec![
                PcodeOp::IntSub {
                    output: difference,
                    left: rax,
                    right: rcx,
                },
                PcodeOp::IntSignedLess {
                    output: sign,
                    left: difference,
                    right: node(Space::Constant, 0, 8),
                },
                PcodeOp::IntSignedBorrow {
                    output: overflow,
                    left: rax,
                    right: rcx,
                },
                PcodeOp::Copy {
                    output: rax,
                    input: rdx,
                },
                PcodeOp::BoolXor {
                    output: predicate,
                    left: sign,
                    right: overflow,
                },
                PcodeOp::CBranch {
                    target: node(Space::Ram, 0x1010, 8),
                    condition: predicate,
                },
            ],
        ),
        pcode_instruction(0x1004, vec![PcodeOp::Return { target: None }]),
    ];
    let ordered_ops: Vec<PcodeOp> = instructions
        .iter()
        .flat_map(|item: &PcodeInstr| item.ops.iter().cloned())
        .collect();
    let decoded: DecodedBlock = DecodedBlock {
        consumed: 2,
        instructions,
        ordered_ops,
    };
    let config: PcodeLiftConfig = PcodeLiftConfig::x86_64().with_condition_code_folding();
    let nir: NirFunction =
        lower_pcode_block(&decoded, "clobber", &config).expect("lower clobbered compare");
    assert!(
        nir.instructions
            .iter()
            .any(|instruction: &NirInstr| matches!(
                instruction.op,
                NirOp::Value {
                    op: ValueOp::BoolXor,
                    ..
                }
            )),
        "a register clobbered between the compare and the branch must abstain and keep the flag expression"
    );
}

#[test]
fn genuine_direct_equality_condition_is_left_untouched() {
    let rsi: Varnode = node(Space::Register, 0x30, 8);
    let equal: Varnode = node(Space::Register, 0x206, 1);
    let decoded: DecodedBlock = DecodedBlock {
        consumed: 2,
        instructions: vec![
            pcode_instruction(
                0x1000,
                vec![
                    PcodeOp::IntEqual {
                        output: equal,
                        left: rsi,
                        right: node(Space::Constant, 0, 8),
                    },
                    PcodeOp::CBranch {
                        target: node(Space::Ram, 0x1010, 8),
                        condition: equal,
                    },
                ],
            ),
            pcode_instruction(0x1004, vec![PcodeOp::Return { target: None }]),
        ],
        ordered_ops: Vec::new(),
    };
    let config: PcodeLiftConfig = PcodeLiftConfig::x86_64().with_condition_code_folding();
    let nir: NirFunction =
        lower_pcode_block(&decoded, "direct", &config).expect("lower direct equality");
    let (op, inputs): (ValueOp, Vec<String>) =
        condition_comparison(&nir).expect("direct equality survives");
    assert_eq!(op, ValueOp::IntEqual);
    assert!(inputs.iter().any(|name: &String| name == "rsi"));
    assert!(inputs.iter().any(|name: &String| name == "0x0"));
}

#[test]
fn generic_config_without_folding_is_a_no_op_for_conditions() {
    let nir: NirFunction = lower_x86_64(&[0x48, 0x39, 0xc8, 0x7c, 0x02, 0xc3], 0x1000, "probe")
        .expect("lower jl without folding");
    assert!(matches!(nir.source.lang, SourceLang::NativeX86));
    assert!(
        !flag_registers(&nir).is_empty(),
        "no-folding config leaves the signed-less flag expression intact"
    );
}
