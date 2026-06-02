#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::items_after_statements,
    clippy::if_same_then_else,
    clippy::branches_sharing_code,
    clippy::decimal_bitwise_operands
)]

use disrobe_pass_py_decompile::bytecode::opcode::{
    CanonicalOp, JumpKind, OpcodeFamily, OpcodeMap, map_for,
};
use disrobe_pass_py_decompile::bytecode::version::PyVersion;

const RETURN_VALUE_PRE_311: u8 = 83;
const RETURN_VALUE_311: u8 = 83;
const RETURN_VALUE_312: u8 = 83;
const RETURN_VALUE_313: u8 = 36;
const RETURN_VALUE_314: u8 = 35;
const RETURN_VALUE_315: u8 = 33;

#[test]
fn v3_13_return_value_decodes_to_return() {
    let map: Box<dyn OpcodeMap> = map_for(PyVersion::V3_13);
    assert_eq!(map.decode(RETURN_VALUE_313, 0), CanonicalOp::Return);
}

#[test]
fn v3_12_return_value_decodes_to_return() {
    let map: Box<dyn OpcodeMap> = map_for(PyVersion::V3_12);
    assert_eq!(map.decode(RETURN_VALUE_312, 0), CanonicalOp::Return);
}

#[test]
fn v3_11_return_value_decodes_to_return() {
    let map: Box<dyn OpcodeMap> = map_for(PyVersion::V3_11);
    assert_eq!(map.decode(RETURN_VALUE_311, 0), CanonicalOp::Return);
}

#[test]
fn v3_10_return_value_decodes_to_return() {
    let map: Box<dyn OpcodeMap> = map_for(PyVersion::V3_10);
    assert_eq!(map.decode(RETURN_VALUE_PRE_311, 0), CanonicalOp::Return);
}

#[test]
fn v2_7_return_value_decodes_to_return() {
    let map: Box<dyn OpcodeMap> = map_for(PyVersion::V2_7);
    assert_eq!(map.decode(RETURN_VALUE_PRE_311, 0), CanonicalOp::Return);
}

#[test]
fn v3_14_return_value_decodes_to_return() {
    let map: Box<dyn OpcodeMap> = map_for(PyVersion::V3_14);
    assert_eq!(map.decode(RETURN_VALUE_314, 0), CanonicalOp::Return);
}

#[test]
fn v3_15_uses_distinct_renumbered_table() {
    let map_14: Box<dyn OpcodeMap> = map_for(PyVersion::V3_14);
    let map_15: Box<dyn OpcodeMap> = map_for(PyVersion::V3_15);
    assert_eq!(map_15.opname(RETURN_VALUE_315), "RETURN_VALUE");
    assert_eq!(map_15.decode(RETURN_VALUE_315, 0), CanonicalOp::Return);
    assert_eq!(map_14.opname(RETURN_VALUE_314), "RETURN_VALUE");
    assert_ne!(
        map_15.opname(RETURN_VALUE_314),
        "RETURN_VALUE",
        "3.15 must not alias the 3.14 table: op {RETURN_VALUE_314} is STORE_SLICE in 3.15"
    );
    assert_eq!(map_15.opname(43), "BUILD_INTERPOLATION");
    assert_eq!(map_15.opname(2), "BUILD_TEMPLATE");
    assert_eq!(map_15.opname(255), "TRACE_RECORD");
    assert_eq!(map_15.has_arg(), 41);
}

#[test]
fn nop_decodes_to_nop_across_versions() {
    for version in PyVersion::all_non_pypy() {
        let map: Box<dyn OpcodeMap> = map_for(version.clone());
        let name: &'static str = map.opname(9);
        if name == "NOP" {
            assert_eq!(map.decode(9, 0), CanonicalOp::Nop, "version {version:?}");
        }
    }
}

#[test]
fn pop_top_decodes_consistently() {
    for version in PyVersion::all_non_pypy() {
        let map: Box<dyn OpcodeMap> = map_for(version.clone());
        let pop_top_op: u8 = if version.minor() >= 11 && version.major() == 3 {
            1
        } else {
            1
        };
        let name: &'static str = map.opname(pop_top_op);
        if name == "POP_TOP" {
            assert_eq!(
                map.decode(pop_top_op, 0),
                CanonicalOp::Pop,
                "version {version:?}"
            );
        }
    }
}

#[test]
fn coverage_no_silent_other_fallthrough_for_known_ops() {
    for version in PyVersion::all_non_pypy() {
        let map: Box<dyn OpcodeMap> = map_for(version.clone());
        let mut covered: u32 = 0;
        let mut total: u32 = 0;
        for op in 0u8..=255u8 {
            let name: &'static str = map.opname(op);
            if name == "<unknown>" {
                continue;
            }
            total += 1;
            let decoded: CanonicalOp = map.decode(op, 0);
            if !matches!(decoded, CanonicalOp::Other(_, _)) {
                covered += 1;
            }
        }
        assert!(total > 0, "no opcodes found for version {version:?}");
        let percent: u32 = (covered * 100) / total;
        assert!(
            percent >= 80,
            "version {version:?}: coverage {percent}% ({covered}/{total}) below 80% threshold"
        );
    }
}

#[test]
fn jump_kind_classification_is_consistent() {
    let map: Box<dyn OpcodeMap> = map_for(PyVersion::V3_12);
    for op in 0u8..=255u8 {
        let name: &'static str = map.opname(op);
        let kind: JumpKind = map.jump_kind(op);
        match name {
            "FOR_ITER" => assert_eq!(kind, JumpKind::ForIter),
            "JUMP_FORWARD" => assert_eq!(kind, JumpKind::Relative),
            "JUMP_BACKWARD" => assert_eq!(kind, JumpKind::Backward),
            "JUMP_BACKWARD_NO_INTERRUPT" => assert_eq!(kind, JumpKind::BackwardNoInterrupt),
            _ => {}
        }
    }
}

#[test]
fn cache_size_311_load_global() {
    let map: Box<dyn OpcodeMap> = map_for(PyVersion::V3_11);
    for op in 0u8..=255u8 {
        if map.opname(op) == "LOAD_GLOBAL" {
            assert_eq!(map.cache_size(op), 5);
        }
    }
}

#[test]
fn cache_size_pre_311_zero() {
    let map: Box<dyn OpcodeMap> = map_for(PyVersion::V3_10);
    for op in 0u8..=255u8 {
        assert_eq!(map.cache_size(op), 0, "op {op} on 3.10");
    }
}

#[test]
fn has_arg_cutoffs() {
    assert_eq!(map_for(PyVersion::V2_7).has_arg(), 90);
    assert_eq!(map_for(PyVersion::V3_5).has_arg(), 90);
    assert_eq!(map_for(PyVersion::V3_13).has_arg(), 44);
    assert_eq!(map_for(PyVersion::V3_14).has_arg(), 43);
    assert_eq!(map_for(PyVersion::V3_15).has_arg(), 41);
}

#[test]
fn family_classification_smoke() {
    let map: Box<dyn OpcodeMap> = map_for(PyVersion::V3_12);
    for op in 0u8..=255u8 {
        let name: &'static str = map.opname(op);
        let family: OpcodeFamily = map.family(op);
        if name.starts_with("LOAD_") {
            assert_eq!(family, OpcodeFamily::Load, "{name}");
        } else if name.starts_with("BUILD_") {
            assert_eq!(family, OpcodeFamily::BuildCollection, "{name}");
        }
    }
}

#[test]
fn pypy_overlay_intercepts_private_opcodes() {
    let pypy_map: Box<dyn OpcodeMap> = map_for(PyVersion::PyPy(Box::new(PyVersion::V3_10)));
    assert_eq!(pypy_map.opname(201), "LOOKUP_METHOD");
    assert_eq!(pypy_map.opname(202), "CALL_METHOD");
    assert_eq!(pypy_map.opname(203), "BUILD_LIST_FROM_ARG");
    assert_eq!(pypy_map.opname(204), "JUMP_IF_NOT_DEBUG");
    assert_eq!(pypy_map.opname(205), "LOAD_REVDB_VAR");
    assert_eq!(pypy_map.opname(206), "CALL_METHOD_KW");

    assert!(matches!(pypy_map.decode(201, 5), CanonicalOp::LoadAttr(5)));
    assert!(matches!(
        pypy_map.decode(202, 3),
        CanonicalOp::CallFunction(3)
    ));
    assert!(matches!(pypy_map.decode(203, 7), CanonicalOp::BuildList(7)));
    assert!(matches!(
        pypy_map.decode(204, 4),
        CanonicalOp::JumpForward(4)
    ));
    assert!(matches!(pypy_map.decode(205, 1), CanonicalOp::LoadName(1)));
    assert!(matches!(
        pypy_map.decode(206, 2),
        CanonicalOp::CallFunctionKw(2)
    ));
}

#[test]
fn pypy_overlay_delegates_unmodified_ops_to_base() {
    let pypy_map: Box<dyn OpcodeMap> = map_for(PyVersion::PyPy(Box::new(PyVersion::V3_10)));
    let base_map: Box<dyn OpcodeMap> = map_for(PyVersion::V3_10);
    assert_eq!(pypy_map.opname(1), base_map.opname(1));
    assert_eq!(pypy_map.decode(1, 0), base_map.decode(1, 0));
}

#[test]
fn version_capability_flags_correct() {
    assert!(PyVersion::V3_11.supports_zero_cost_exceptions());
    assert!(!PyVersion::V3_10.supports_zero_cost_exceptions());
    assert!(PyVersion::V3_12.supports_super_instructions());
    assert!(!PyVersion::V3_11.supports_super_instructions());
    assert!(PyVersion::V3_14.supports_tstring());
    assert!(!PyVersion::V3_13.supports_tstring());
    assert!(PyVersion::V3_13.supports_pep_696());
    assert!(!PyVersion::V3_12.supports_pep_696());
    assert!(PyVersion::V3_6.supports_word_code());
    assert!(!PyVersion::V3_5.supports_word_code());
}

#[test]
fn from_magic_round_trip() {
    let v: PyVersion = PyVersion::from_magic(3495u32).expect("3.11 magic");
    assert_eq!(v, PyVersion::V3_11);
    let v_pypy: PyVersion = PyVersion::from_magic(0xA1B2_0000 | 3495u32).expect("pypy 3.11");
    assert_eq!(v_pypy, PyVersion::PyPy(Box::new(PyVersion::V3_11)));
    let v_py27: PyVersion = PyVersion::from_magic(62211).expect("2.7 magic");
    assert_eq!(v_py27, PyVersion::V2_7);
}

#[test]
fn binary_op_decodes_with_arg() {
    let map: Box<dyn OpcodeMap> = map_for(PyVersion::V3_11);
    for op in 0u8..=255u8 {
        if map.opname(op) == "BINARY_OP" {
            let decoded: CanonicalOp = map.decode(op, 0);
            assert!(matches!(decoded, CanonicalOp::BinaryOp(_)));
        }
    }
}

#[test]
fn specialized_pep_659_ops_decoded_for_312() {
    let map: Box<dyn OpcodeMap> = map_for(PyVersion::V3_12);
    let mut found_any: bool = false;
    for op in 0u8..=255u8 {
        let name: &'static str = map.opname(op);
        if name.starts_with("CALL_PY_") {
            found_any = true;
            assert!(
                matches!(map.decode(op, 0), CanonicalOp::CallFunction(_)),
                "{name} should be demoted to CallFunction"
            );
        }
        if name.starts_with("BINARY_OP_") && !name.starts_with("BINARY_OP_SUBSCR_") {
            found_any = true;
            assert!(
                matches!(
                    map.decode(op, 0),
                    CanonicalOp::BinaryOp(_) | CanonicalOp::LoadSubscr
                ),
                "{name} should be demoted to BinaryOp/LoadSubscr"
            );
        }
    }
    assert!(found_any, "3.12 must have at least one specialized op");
}
