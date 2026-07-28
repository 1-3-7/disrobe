use std::collections::BTreeSet;

use disrobe_similarity::{
    DataReference, FunctionFeatures, FunctionId, SMALL_INTEGER_CEILING, is_discriminating_constant,
};

const ORDINARY: [u64; 26] = [
    0,
    1,
    2,
    3,
    4,
    8,
    64,
    255,
    256,
    512,
    1024,
    4096,
    0x8000_0000,
    0x7fff_ffff,
    0xffff_ffff,
    0xffff_fffe,
    0xffff_f000,
    0xffff_ff00,
    0x5555_5555,
    0x3333_3333,
    0xaaaa_aaaa,
    0xcccc_cccc,
    0x0f0f_0f0f,
    0x0101_0101,
    0x00ff_00ff,
    u64::MAX,
];

const DISCRIMINATING: [u64; 12] = [
    0x1234,
    0x1234_5678,
    0x9e37_79b9,
    0x6a09_e667,
    0xd76a_a478,
    0x811c_9dc5,
    0x0100_0193,
    0x7f45_4c46,
    0xdead_beef,
    0xcafe_babe,
    0xfeed_face,
    0x0123_4567_89ab_cdef,
];

#[test]
fn ordinary_values_are_not_discriminating() {
    for value in ORDINARY {
        assert!(
            !is_discriminating_constant(value),
            "{value:#x} was treated as discriminating"
        );
    }
}

#[test]
fn magic_values_are_discriminating() {
    for value in DISCRIMINATING {
        assert!(
            is_discriminating_constant(value),
            "{value:#x} was treated as ordinary"
        );
    }
}

#[test]
fn every_value_up_to_the_ceiling_is_ordinary() {
    for value in 0..=SMALL_INTEGER_CEILING {
        assert!(
            !is_discriminating_constant(value),
            "{value:#x} was treated as discriminating"
        );
    }
}

#[test]
fn powers_of_two_are_ordinary_at_every_width() {
    for exponent in 0..u64::BITS {
        let value: u64 = 1u64 << exponent;
        assert!(
            !is_discriminating_constant(value),
            "{value:#x} was treated as discriminating"
        );
    }
}

#[test]
fn low_bit_masks_are_ordinary_at_every_width() {
    for exponent in 1..u64::BITS {
        let value: u64 = (1u64 << exponent) - 1;
        assert!(
            !is_discriminating_constant(value),
            "{value:#x} was treated as discriminating"
        );
    }
}

#[test]
fn small_negative_values_are_ordinary_at_every_width() {
    for bits in [16u32, 32, 64] {
        let span: u64 = if bits >= u64::BITS {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };
        for offset in 0..SMALL_INTEGER_CEILING {
            let value: u64 = span - offset;
            assert!(
                !is_discriminating_constant(value),
                "{value:#x} was treated as discriminating at {bits} bits"
            );
        }
    }
}

#[test]
fn the_constant_constructor_refuses_an_ordinary_value() {
    for value in ORDINARY {
        assert_eq!(DataReference::constant(value), None);
    }
    for value in DISCRIMINATING {
        assert_eq!(
            DataReference::constant(value),
            Some(DataReference::UnusualConstant(value))
        );
    }
}

#[test]
fn ordinary_constants_are_dropped_from_a_feature_set() {
    let features: FunctionFeatures = FunctionFeatures::new(
        FunctionId(0x1000),
        [
            DataReference::UnusualConstant(0),
            DataReference::UnusualConstant(1),
            DataReference::UnusualConstant(4096),
            DataReference::UnusualConstant(0xdead_beef),
        ],
    );

    assert_eq!(
        features.references(),
        &BTreeSet::from([DataReference::UnusualConstant(0xdead_beef)])
    );
    assert!(features.has_anchor());
}

#[test]
fn a_feature_set_of_only_ordinary_constants_has_no_anchor() {
    let features: FunctionFeatures = FunctionFeatures::new(
        FunctionId(0x1000),
        ORDINARY.map(DataReference::UnusualConstant),
    );

    assert!(features.references().is_empty());
    assert!(!features.has_anchor());
}
