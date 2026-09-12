#![allow(clippy::panic)]

use disrobe_pass_native::{LeafRecovery, recover_aarch64_function};

const ENTRY_COMPARE_FOLDS_INTO_ITS_BRANCH: [u8; 36] = [
    0x1f, 0x00, 0x01, 0xeb, 0xea, 0x00, 0x00, 0x54, 0x00, 0x04, 0x00, 0x91, 0x1f, 0x00, 0x02, 0xeb,
    0x60, 0x00, 0x00, 0x54, 0x00, 0x04, 0x00, 0x91, 0xfa, 0xff, 0xff, 0x17, 0xc0, 0x03, 0x5f, 0xd6,
    0xc0, 0x03, 0x5f, 0xd6,
];

const WORD_BYTES: usize = 4;
const IMM26_BITS: u32 = 26;
const IMM19_BITS: u32 = 19;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArmArmForm {
    CompareShiftedRegister { first: u8, second: u8 },
    BranchImmediate { target: u64 },
    BranchConditional { condition: u8, target: u64 },
    Return,
    Other,
}

fn sign_extend(value: u32, bits: u32) -> i64 {
    let shift: u32 = u32::BITS - bits;
    i64::from((value << shift) as i32 >> shift)
}

fn branch_offset(word: u32, immediate_bits: u32, low_bit: u32) -> i64 {
    let mask: u32 = (1_u32 << immediate_bits) - 1;
    let immediate: u32 = (word >> low_bit) & mask;
    sign_extend(immediate, immediate_bits)
        .wrapping_mul(i64::try_from(WORD_BYTES).unwrap_or_default())
}

fn classify(word: u32, address: u64) -> ArmArmForm {
    if word >> 26 == 0b0000_0101 {
        let offset: i64 = branch_offset(word, IMM26_BITS, 0);
        return ArmArmForm::BranchImmediate {
            target: address.wrapping_add_signed(offset),
        };
    }
    if word >> 24 == 0b0101_0100 && word & (1 << 4) == 0 {
        let offset: i64 = branch_offset(word, IMM19_BITS, 5);
        return ArmArmForm::BranchConditional {
            condition: u8::try_from(word & 0b1111).unwrap_or_default(),
            target: address.wrapping_add_signed(offset),
        };
    }
    if word >> 21 == 0b111_0101_1000 {
        let destination: u32 = word & 0b1_1111;
        if destination == 0b1_1111 {
            return ArmArmForm::CompareShiftedRegister {
                first: u8::try_from((word >> 5) & 0b1_1111).unwrap_or_default(),
                second: u8::try_from((word >> 16) & 0b1_1111).unwrap_or_default(),
            };
        }
        return ArmArmForm::Other;
    }
    if word == 0xd65f_03c0 {
        return ArmArmForm::Return;
    }
    ArmArmForm::Other
}

fn decoded_words(bytes: &[u8]) -> Vec<(u64, ArmArmForm)> {
    bytes
        .chunks_exact(WORD_BYTES)
        .enumerate()
        .map(|(index, chunk): (usize, &[u8])| {
            let address: u64 = (index * WORD_BYTES) as u64;
            let word: u32 = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            (address, classify(word, address))
        })
        .collect()
}

const CONDITION_EQ: u8 = 0b0000;
const CONDITION_GE: u8 = 0b1010;

#[test]
fn the_fixture_matches_the_arm_arm_encoding_of_a_loop_whose_entry_is_a_compare() {
    let decoded: Vec<(u64, ArmArmForm)> = decoded_words(&ENTRY_COMPARE_FOLDS_INTO_ITS_BRANCH);
    let expected: [(u64, ArmArmForm); 9] = [
        (
            0x00,
            ArmArmForm::CompareShiftedRegister {
                first: 0,
                second: 1,
            },
        ),
        (
            0x04,
            ArmArmForm::BranchConditional {
                condition: CONDITION_GE,
                target: 0x20,
            },
        ),
        (0x08, ArmArmForm::Other),
        (
            0x0c,
            ArmArmForm::CompareShiftedRegister {
                first: 0,
                second: 2,
            },
        ),
        (
            0x10,
            ArmArmForm::BranchConditional {
                condition: CONDITION_EQ,
                target: 0x1c,
            },
        ),
        (0x14, ArmArmForm::Other),
        (0x18, ArmArmForm::BranchImmediate { target: 0x00 }),
        (0x1c, ArmArmForm::Return),
        (0x20, ArmArmForm::Return),
    ];
    assert_eq!(
        decoded,
        expected.to_vec(),
        "the fixture must encode the shape this test is named for, decoded from the ARM \
         architecture reference manual field definitions rather than from the decoder under test"
    );
}

#[test]
fn a_back_edge_onto_a_folded_entry_compare_is_an_edge_inside_the_function() {
    let decoded: Vec<(u64, ArmArmForm)> = decoded_words(&ENTRY_COMPARE_FOLDS_INTO_ITS_BRANCH);
    let entry: (u64, ArmArmForm) = decoded.first().copied().unwrap_or((0, ArmArmForm::Other));
    assert!(
        matches!(entry.1, ArmArmForm::CompareShiftedRegister { .. }),
        "the entry instruction must be a compare, which the lifter folds into its branch and so \
         leaves no item of its own at the entry address: {entry:?}"
    );
    let back_edges: Vec<u64> = decoded
        .iter()
        .filter_map(|(_, form): &(u64, ArmArmForm)| match form {
            ArmArmForm::BranchImmediate { target } => Some(*target),
            _ => None,
        })
        .collect();
    assert_eq!(
        back_edges,
        vec![entry.0],
        "the only unconditional branch must target the entry address itself"
    );

    let recovered: LeafRecovery = recover_aarch64_function(&ENTRY_COMPARE_FOLDS_INTO_ITS_BRANCH, 0)
        .unwrap_or_else(|error: disrobe_pass_native::Error| {
            panic!(
                "a branch to the entry address is an edge inside this function, not a jump that \
                 leaves it: {error}"
            )
        });
    assert!(
        recovered.source.contains("continue;"),
        "the back edge onto the folded entry compare must render as a continue: {}",
        recovered.source
    );
    assert!(
        recovered.source.contains("break;"),
        "the loop exit that reaches the shared tail must render as a break: {}",
        recovered.source
    );
    assert!(
        !recovered.source.contains("goto"),
        "the recovered body must not fall back to a goto: {}",
        recovered.source
    );
}
