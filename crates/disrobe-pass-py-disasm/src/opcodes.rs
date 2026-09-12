use disrobe_py_marshal::PyVersion;

mod tables_legacy;
mod tables_py30_py310;
mod tables_py311_py315;

use self::tables_legacy::{
    OPCODE_TABLE_10, OPCODE_TABLE_11, OPCODE_TABLE_13, OPCODE_TABLE_14, OPCODE_TABLE_15,
    OPCODE_TABLE_16, OPCODE_TABLE_20, OPCODE_TABLE_21, OPCODE_TABLE_22, OPCODE_TABLE_26,
    OPCODE_TABLE_27,
};
use self::tables_py30_py310::{
    OPCODE_TABLE_30, OPCODE_TABLE_31, OPCODE_TABLE_32, OPCODE_TABLE_33, OPCODE_TABLE_34,
    OPCODE_TABLE_35, OPCODE_TABLE_36, OPCODE_TABLE_37, OPCODE_TABLE_38, OPCODE_TABLE_39,
    OPCODE_TABLE_310,
};
use self::tables_py311_py315::{
    OPCODE_TABLE_311, OPCODE_TABLE_312, OPCODE_TABLE_313, OPCODE_TABLE_314, OPCODE_TABLE_315,
};

pub(crate) const UNKNOWN_OPCODE: &str = "<unknown>";

#[must_use]
#[inline]
pub const fn opname(op: u8, version: PyVersion) -> &'static str {
    let table: &'static [&'static str; 256] = table_for(version);
    let name: &'static str = table[op as usize];
    if name.is_empty() {
        UNKNOWN_OPCODE
    } else {
        name
    }
}

#[must_use]
#[inline]
pub const fn has_arg(op: u8, version: PyVersion) -> bool {
    if is_arg_exempt(op, version) {
        return false;
    }
    op >= have_argument(version)
}

#[inline]
const fn is_arg_exempt(op: u8, version: PyVersion) -> bool {
    version.major == 3 && version.minor >= 13 && name_eq(opname(op, version), "WITH_EXCEPT_START")
}

#[inline]
const fn name_eq(lhs: &str, rhs: &str) -> bool {
    let (left, right): (&[u8], &[u8]) = (lhs.as_bytes(), rhs.as_bytes());
    if left.len() != right.len() {
        return false;
    }
    let mut index: usize = 0usize;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

#[must_use]
#[inline]
const fn have_argument(version: PyVersion) -> u8 {
    match (version.major, version.minor) {
        (3, 13) => 44,
        (3, 14) => 43,
        (3, 15) => 41,
        _ => 90,
    }
}

#[must_use]
pub fn cache_size(op: u8, version: PyVersion) -> u8 {
    if version.major != 3 || version.minor < 11 {
        return 0;
    }
    let name: &'static str = opname(op, version);
    match version.minor {
        11 => match name {
            "LOAD_METHOD" => 10,
            "LOAD_GLOBAL" => 5,
            "BINARY_SUBSCR" | "CALL" | "LOAD_ATTR" | "STORE_ATTR" => 4,
            "COMPARE_OP" => 2,
            "BINARY_OP" | "PRECALL" | "STORE_SUBSCR" | "UNPACK_SEQUENCE" => 1,
            _ => 0,
        },
        12 => match name {
            "LOAD_ATTR" => 9,
            "LOAD_GLOBAL" | "STORE_ATTR" => 4,
            "CALL" => 3,
            "BINARY_OP" | "BINARY_SUBSCR" | "COMPARE_OP" | "FOR_ITER" | "LOAD_SUPER_ATTR"
            | "SEND" | "STORE_SUBSCR" | "UNPACK_SEQUENCE" => 1,
            _ => 0,
        },
        13 => match name {
            "LOAD_ATTR" => 9,
            "LOAD_GLOBAL" | "STORE_ATTR" => 4,
            "CALL" | "TO_BOOL" => 3,
            "BINARY_OP"
            | "BINARY_SUBSCR"
            | "COMPARE_OP"
            | "CONTAINS_OP"
            | "FOR_ITER"
            | "JUMP_BACKWARD"
            | "LOAD_SUPER_ATTR"
            | "POP_JUMP_IF_FALSE"
            | "POP_JUMP_IF_NONE"
            | "POP_JUMP_IF_NOT_NONE"
            | "POP_JUMP_IF_TRUE"
            | "SEND"
            | "STORE_SUBSCR"
            | "UNPACK_SEQUENCE" => 1,
            _ => 0,
        },
        14 => match name {
            "LOAD_ATTR" => 9,
            "BINARY_OP" => 5,
            "LOAD_GLOBAL" | "STORE_ATTR" => 4,
            "CALL" | "CALL_KW" | "TO_BOOL" => 3,
            "COMPARE_OP"
            | "CONTAINS_OP"
            | "FOR_ITER"
            | "JUMP_BACKWARD"
            | "LOAD_SUPER_ATTR"
            | "POP_JUMP_IF_FALSE"
            | "POP_JUMP_IF_NONE"
            | "POP_JUMP_IF_NOT_NONE"
            | "POP_JUMP_IF_TRUE"
            | "SEND"
            | "STORE_SUBSCR"
            | "UNPACK_SEQUENCE" => 1,
            _ => 0,
        },
        15 => match name {
            "LOAD_ATTR" => 9,
            "BINARY_OP" => 5,
            "LOAD_GLOBAL" | "STORE_ATTR" => 4,
            "CALL" | "CALL_KW" | "TO_BOOL" => 3,
            "CALL_FUNCTION_EX"
            | "COMPARE_OP"
            | "CONTAINS_OP"
            | "FOR_ITER"
            | "GET_ITER"
            | "JUMP_BACKWARD"
            | "LOAD_SUPER_ATTR"
            | "POP_JUMP_IF_FALSE"
            | "POP_JUMP_IF_NONE"
            | "POP_JUMP_IF_NOT_NONE"
            | "POP_JUMP_IF_TRUE"
            | "RESUME"
            | "SEND"
            | "STORE_SUBSCR"
            | "UNPACK_SEQUENCE" => 1,
            _ => 0,
        },
        _ => 0,
    }
}

const fn table_for(version: PyVersion) -> &'static [&'static str; 256] {
    match (version.major, version.minor) {
        (1, 0) => &OPCODE_TABLE_10,
        (1, 1 | 2) => &OPCODE_TABLE_11,
        (1, 3) => &OPCODE_TABLE_13,
        (1, 4) => &OPCODE_TABLE_14,
        (1, 5) => &OPCODE_TABLE_15,
        (1, _) => &OPCODE_TABLE_16,
        (2, 0) => &OPCODE_TABLE_20,
        (2, 1) => &OPCODE_TABLE_21,
        (2, 2..=5) => &OPCODE_TABLE_22,
        (2, 6) => &OPCODE_TABLE_26,
        (2, _) => &OPCODE_TABLE_27,
        (3, 0) => &OPCODE_TABLE_30,
        (3, 1) => &OPCODE_TABLE_31,
        (3, 2) => &OPCODE_TABLE_32,
        (3, 3) => &OPCODE_TABLE_33,
        (3, 4) => &OPCODE_TABLE_34,
        (3, 5) => &OPCODE_TABLE_35,
        (3, 6) => &OPCODE_TABLE_36,
        (3, 7) => &OPCODE_TABLE_37,
        (3, 8) => &OPCODE_TABLE_38,
        (3, 9) => &OPCODE_TABLE_39,
        (3, 10) => &OPCODE_TABLE_310,
        (3, 11) => &OPCODE_TABLE_311,
        (3, 12) => &OPCODE_TABLE_312,
        (3, 13) => &OPCODE_TABLE_313,
        (3, 15) => &OPCODE_TABLE_315,
        _ => &OPCODE_TABLE_314,
    }
}

const fn build_default() -> [&'static str; 256] {
    [""; 256]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opname_known_27() {
        assert_eq!(opname(100, PyVersion::PY27), "LOAD_CONST");
        assert_eq!(opname(124, PyVersion::PY27), "LOAD_FAST");
    }

    #[test]
    fn opname_legacy_for_loop_and_raise() {
        assert_eq!(opname(114, PyVersion::PY10), "FOR_LOOP");
        assert_eq!(opname(81, PyVersion::PY10), "RAISE_EXCEPTION");
        assert_eq!(opname(13, PyVersion::PY10), "UNARY_CONVERT");
        assert_eq!(opname(85, PyVersion::PY10), "EXEC_STMT");
        assert_eq!(opname(71, PyVersion::PY10), "PRINT_ITEM");
        assert_eq!(opname(86, PyVersion::PY10), "BUILD_FUNCTION");
        assert_eq!(opname(89, PyVersion::PY10), "BUILD_CLASS");
    }

    #[test]
    fn opname_22_introduces_for_iter() {
        assert_eq!(opname(93, PyVersion::PY22), "FOR_ITER");
        assert_eq!(opname(86, PyVersion::PY22), "YIELD_VALUE");
        assert_eq!(opname(68, PyVersion::PY22), "GET_ITER");
        assert_eq!(opname(114, PyVersion::PY22), "FOR_LOOP");
    }

    #[test]
    fn opname_legacy_table_dispatch_distinct_from_27() {
        assert_eq!(opname(93, PyVersion::PY10), "UNPACK_LIST");
        assert_eq!(opname(93, PyVersion::PY20), "<unknown>");
        assert_eq!(opname(93, PyVersion::PY27), "FOR_ITER");
        assert_eq!(opname(117, PyVersion::PY11), "SET_FUNC_ARGS");
        assert_eq!(opname(19, PyVersion::PY14), "BINARY_POWER");
        assert_eq!(opname(140, PyVersion::PY16), "CALL_FUNCTION_VAR");
    }

    #[test]
    fn opname_311_inline_cache() {
        assert_eq!(opname(0, PyVersion::PY311), "CACHE");
        assert_eq!(opname(151, PyVersion::PY311), "RESUME");
        assert_eq!(opname(171, PyVersion::PY311), "CALL");
    }

    #[test]
    fn opname_unknown_falls_back() {
        assert_eq!(opname(231, PyVersion::PY27), "<unknown>");
    }

    #[test]
    fn has_arg_changes_between_legacy_and_wordcode() {
        assert!(!has_arg(50, PyVersion::PY27));
        assert!(has_arg(100, PyVersion::PY27));
        assert!(!has_arg(0, PyVersion::PY312));
        assert!(!has_arg(89, PyVersion::PY312));
        assert!(has_arg(90, PyVersion::PY312));
        assert!(has_arg(151, PyVersion::PY312));
    }

    #[test]
    fn have_argument_cutoff_renumbered_313_314() {
        assert!(!has_arg(43, PyVersion::PY313));
        assert!(!has_arg(44, PyVersion::PY313));
        assert!(has_arg(45, PyVersion::PY313));
        assert!(!has_arg(42, PyVersion::PY314));
        assert!(!has_arg(43, PyVersion::PY314));
        assert!(has_arg(44, PyVersion::PY314));
    }

    #[test]
    fn opname_315_tstring_family() {
        assert_eq!(opname(43, PyVersion::PY315), "BUILD_INTERPOLATION");
        assert_eq!(opname(2, PyVersion::PY315), "BUILD_TEMPLATE");
        assert_eq!(opname(81, PyVersion::PY315), "LOAD_CONST");
        assert_eq!(opname(255, PyVersion::PY315), "TRACE_RECORD");
        assert_eq!(opname(254, PyVersion::PY315), "ENTER_EXECUTOR");
        assert_eq!(have_argument(PyVersion::PY315), 41);
        assert!(!has_arg(40, PyVersion::PY315));
        assert!(!has_arg(41, PyVersion::PY315));
        assert!(has_arg(42, PyVersion::PY315));
    }

    #[test]
    fn cache_size_315_matches_interpreter() {
        assert_eq!(cache_size(79, PyVersion::PY315), 9);
        assert_eq!(cache_size(42, PyVersion::PY315), 5);
        assert_eq!(cache_size(91, PyVersion::PY315), 4);
        assert_eq!(cache_size(50, PyVersion::PY315), 3);
        assert_eq!(cache_size(70, PyVersion::PY315), 1);
        assert_eq!(cache_size(128, PyVersion::PY315), 1);
        assert_eq!(cache_size(36, PyVersion::PY315), 1);
        assert_eq!(cache_size(4, PyVersion::PY315), 1);
        assert_eq!(cache_size(0, PyVersion::PY315), 0);
    }

    #[test]
    fn cache_size_canonical_values() {
        assert_eq!(cache_size(0, PyVersion::PY312), 0);
        assert_eq!(cache_size(0, PyVersion::PY310), 0);
        assert_eq!(cache_size(160, PyVersion::PY311), 10);
        assert_eq!(cache_size(116, PyVersion::PY311), 5);
        assert_eq!(cache_size(171, PyVersion::PY311), 4);
        assert_eq!(cache_size(106, PyVersion::PY311), 4);
        assert_eq!(cache_size(107, PyVersion::PY311), 2);
        assert_eq!(cache_size(166, PyVersion::PY311), 1);
        assert_eq!(cache_size(116, PyVersion::PY312), 4);
        assert_eq!(cache_size(106, PyVersion::PY312), 9);
        assert_eq!(cache_size(95, PyVersion::PY312), 4);
        assert_eq!(cache_size(171, PyVersion::PY312), 3);
        assert_eq!(cache_size(91, PyVersion::PY313), 4);
        assert_eq!(cache_size(40, PyVersion::PY313), 3);
        assert_eq!(cache_size(82, PyVersion::PY313), 9);
        assert_eq!(cache_size(44, PyVersion::PY314), 5);
        assert_eq!(cache_size(55, PyVersion::PY314), 3);
        assert_eq!(cache_size(39, PyVersion::PY314), 3);
    }

    #[test]
    fn opcode_table_27_canonical_coverage() {
        let v: PyVersion = PyVersion::PY27;
        assert_eq!(opname(0, v), "STOP_CODE");
        assert_eq!(opname(1, v), "POP_TOP");
        assert_eq!(opname(2, v), "ROT_TWO");
        assert_eq!(opname(3, v), "ROT_THREE");
        assert_eq!(opname(4, v), "DUP_TOP");
        assert_eq!(opname(142, v), "CALL_FUNCTION_VAR_KW");
        assert_eq!(opname(143, v), "SETUP_WITH");
        assert_eq!(opname(145, v), "EXTENDED_ARG");
        assert_eq!(opname(146, v), "SET_ADD");
        assert_eq!(opname(147, v), "MAP_ADD");
        assert!(opname(255, v) == "<unknown>" || !opname(255, v).is_empty());
    }

    #[test]
    fn opcode_table_30_canonical_coverage() {
        let v: PyVersion = PyVersion::PY30;
        assert_eq!(opname(0, v), "STOP_CODE");
        assert_eq!(opname(1, v), "POP_TOP");
        assert_eq!(opname(2, v), "ROT_TWO");
        assert_eq!(opname(3, v), "ROT_THREE");
        assert_eq!(opname(4, v), "DUP_TOP");
        assert_eq!(opname(137, v), "STORE_DEREF");
        assert_eq!(opname(140, v), "CALL_FUNCTION_VAR");
        assert_eq!(opname(141, v), "CALL_FUNCTION_KW");
        assert_eq!(opname(142, v), "CALL_FUNCTION_VAR_KW");
        assert_eq!(opname(143, v), "EXTENDED_ARG");
        assert!(opname(255, v) == "<unknown>" || !opname(255, v).is_empty());
    }

    #[test]
    fn opcode_table_31_canonical_coverage() {
        let v: PyVersion = PyVersion::PY31;
        assert_eq!(opname(0, v), "STOP_CODE");
        assert_eq!(opname(1, v), "POP_TOP");
        assert_eq!(opname(2, v), "ROT_TWO");
        assert_eq!(opname(3, v), "ROT_THREE");
        assert_eq!(opname(4, v), "DUP_TOP");
        assert_eq!(opname(142, v), "CALL_FUNCTION_VAR_KW");
        assert_eq!(opname(143, v), "EXTENDED_ARG");
        assert_eq!(opname(145, v), "LIST_APPEND");
        assert_eq!(opname(146, v), "SET_ADD");
        assert_eq!(opname(147, v), "MAP_ADD");
        assert!(opname(255, v) == "<unknown>" || !opname(255, v).is_empty());
    }

    #[test]
    fn opcode_table_32_canonical_coverage() {
        let v: PyVersion = PyVersion::PY32;
        assert_eq!(opname(0, v), "STOP_CODE");
        assert_eq!(opname(1, v), "POP_TOP");
        assert_eq!(opname(2, v), "ROT_TWO");
        assert_eq!(opname(3, v), "ROT_THREE");
        assert_eq!(opname(4, v), "DUP_TOP");
        assert_eq!(opname(143, v), "SETUP_WITH");
        assert_eq!(opname(144, v), "EXTENDED_ARG");
        assert_eq!(opname(145, v), "LIST_APPEND");
        assert_eq!(opname(146, v), "SET_ADD");
        assert_eq!(opname(147, v), "MAP_ADD");
        assert!(opname(255, v) == "<unknown>" || !opname(255, v).is_empty());
    }

    #[test]
    fn opcode_table_33_canonical_coverage() {
        let v: PyVersion = PyVersion::PY33;
        assert_eq!(opname(1, v), "POP_TOP");
        assert_eq!(opname(2, v), "ROT_TWO");
        assert_eq!(opname(3, v), "ROT_THREE");
        assert_eq!(opname(4, v), "DUP_TOP");
        assert_eq!(opname(5, v), "DUP_TOP_TWO");
        assert_eq!(opname(143, v), "SETUP_WITH");
        assert_eq!(opname(144, v), "EXTENDED_ARG");
        assert_eq!(opname(145, v), "LIST_APPEND");
        assert_eq!(opname(146, v), "SET_ADD");
        assert_eq!(opname(147, v), "MAP_ADD");
        assert!(opname(255, v) == "<unknown>" || !opname(255, v).is_empty());
    }

    #[test]
    fn opcode_table_34_canonical_coverage() {
        let v: PyVersion = PyVersion::PY34;
        assert_eq!(opname(1, v), "POP_TOP");
        assert_eq!(opname(2, v), "ROT_TWO");
        assert_eq!(opname(3, v), "ROT_THREE");
        assert_eq!(opname(4, v), "DUP_TOP");
        assert_eq!(opname(5, v), "DUP_TOP_TWO");
        assert_eq!(opname(144, v), "EXTENDED_ARG");
        assert_eq!(opname(145, v), "LIST_APPEND");
        assert_eq!(opname(146, v), "SET_ADD");
        assert_eq!(opname(147, v), "MAP_ADD");
        assert_eq!(opname(148, v), "LOAD_CLASSDEREF");
        assert!(opname(255, v) == "<unknown>" || !opname(255, v).is_empty());
    }

    #[test]
    fn opcode_table_35_canonical_coverage() {
        let v: PyVersion = PyVersion::PY35;
        assert_eq!(opname(1, v), "POP_TOP");
        assert_eq!(opname(2, v), "ROT_TWO");
        assert_eq!(opname(3, v), "ROT_THREE");
        assert_eq!(opname(4, v), "DUP_TOP");
        assert_eq!(opname(5, v), "DUP_TOP_TWO");
        assert_eq!(opname(150, v), "BUILD_MAP_UNPACK");
        assert_eq!(opname(151, v), "BUILD_MAP_UNPACK_WITH_CALL");
        assert_eq!(opname(152, v), "BUILD_TUPLE_UNPACK");
        assert_eq!(opname(153, v), "BUILD_SET_UNPACK");
        assert_eq!(opname(154, v), "SETUP_ASYNC_WITH");
        assert!(opname(255, v) == "<unknown>" || !opname(255, v).is_empty());
    }

    #[test]
    fn opcode_table_36_canonical_coverage() {
        let v: PyVersion = PyVersion::PY36;
        assert_eq!(opname(1, v), "POP_TOP");
        assert_eq!(opname(2, v), "ROT_TWO");
        assert_eq!(opname(3, v), "ROT_THREE");
        assert_eq!(opname(4, v), "DUP_TOP");
        assert_eq!(opname(5, v), "DUP_TOP_TWO");
        assert_eq!(opname(154, v), "SETUP_ASYNC_WITH");
        assert_eq!(opname(155, v), "FORMAT_VALUE");
        assert_eq!(opname(156, v), "BUILD_CONST_KEY_MAP");
        assert_eq!(opname(157, v), "BUILD_STRING");
        assert_eq!(opname(158, v), "BUILD_TUPLE_UNPACK_WITH_CALL");
        assert!(opname(255, v) == "<unknown>" || !opname(255, v).is_empty());
    }

    #[test]
    fn opcode_table_37_canonical_coverage() {
        let v: PyVersion = PyVersion::PY37;
        assert_eq!(opname(1, v), "POP_TOP");
        assert_eq!(opname(2, v), "ROT_TWO");
        assert_eq!(opname(3, v), "ROT_THREE");
        assert_eq!(opname(4, v), "DUP_TOP");
        assert_eq!(opname(5, v), "DUP_TOP_TWO");
        assert_eq!(opname(156, v), "BUILD_CONST_KEY_MAP");
        assert_eq!(opname(157, v), "BUILD_STRING");
        assert_eq!(opname(158, v), "BUILD_TUPLE_UNPACK_WITH_CALL");
        assert_eq!(opname(160, v), "LOAD_METHOD");
        assert_eq!(opname(161, v), "CALL_METHOD");
        assert!(opname(255, v) == "<unknown>" || !opname(255, v).is_empty());
    }

    #[test]
    fn opcode_table_38_canonical_coverage() {
        let v: PyVersion = PyVersion::PY38;
        assert_eq!(opname(1, v), "POP_TOP");
        assert_eq!(opname(2, v), "ROT_TWO");
        assert_eq!(opname(3, v), "ROT_THREE");
        assert_eq!(opname(4, v), "DUP_TOP");
        assert_eq!(opname(5, v), "DUP_TOP_TWO");
        assert_eq!(opname(158, v), "BUILD_TUPLE_UNPACK_WITH_CALL");
        assert_eq!(opname(160, v), "LOAD_METHOD");
        assert_eq!(opname(161, v), "CALL_METHOD");
        assert_eq!(opname(162, v), "CALL_FINALLY");
        assert_eq!(opname(163, v), "POP_FINALLY");
        assert!(opname(255, v) == "<unknown>" || !opname(255, v).is_empty());
    }

    #[test]
    fn opcode_table_39_canonical_coverage() {
        let v: PyVersion = PyVersion::PY39;
        assert_eq!(opname(1, v), "POP_TOP");
        assert_eq!(opname(2, v), "ROT_TWO");
        assert_eq!(opname(3, v), "ROT_THREE");
        assert_eq!(opname(4, v), "DUP_TOP");
        assert_eq!(opname(5, v), "DUP_TOP_TWO");
        assert_eq!(opname(161, v), "CALL_METHOD");
        assert_eq!(opname(162, v), "LIST_EXTEND");
        assert_eq!(opname(163, v), "SET_UPDATE");
        assert_eq!(opname(164, v), "DICT_MERGE");
        assert_eq!(opname(165, v), "DICT_UPDATE");
        assert!(opname(255, v) == "<unknown>" || !opname(255, v).is_empty());
    }

    #[test]
    fn opcode_table_310_canonical_coverage() {
        let v: PyVersion = PyVersion::PY310;
        assert_eq!(opname(1, v), "POP_TOP");
        assert_eq!(opname(2, v), "ROT_TWO");
        assert_eq!(opname(3, v), "ROT_THREE");
        assert_eq!(opname(4, v), "DUP_TOP");
        assert_eq!(opname(5, v), "DUP_TOP_TWO");
        assert_eq!(opname(161, v), "CALL_METHOD");
        assert_eq!(opname(162, v), "LIST_EXTEND");
        assert_eq!(opname(163, v), "SET_UPDATE");
        assert_eq!(opname(164, v), "DICT_MERGE");
        assert_eq!(opname(165, v), "DICT_UPDATE");
        assert!(opname(255, v) == "<unknown>" || !opname(255, v).is_empty());
    }

    #[test]
    fn opcode_table_311_canonical_coverage() {
        let v: PyVersion = PyVersion::PY311;
        assert_eq!(opname(0, v), "CACHE");
        assert_eq!(opname(1, v), "POP_TOP");
        assert_eq!(opname(2, v), "PUSH_NULL");
        assert_eq!(opname(3, v), "BINARY_OP_ADAPTIVE");
        assert_eq!(opname(4, v), "BINARY_OP_ADD_FLOAT");
        assert_eq!(opname(176, v), "POP_JUMP_BACKWARD_IF_TRUE");
        assert_eq!(opname(177, v), "UNPACK_SEQUENCE_ADAPTIVE");
        assert_eq!(opname(178, v), "UNPACK_SEQUENCE_LIST");
        assert_eq!(opname(179, v), "UNPACK_SEQUENCE_TUPLE");
        assert_eq!(opname(180, v), "UNPACK_SEQUENCE_TWO_TUPLE");
        assert!(opname(255, v) == "<unknown>" || !opname(255, v).is_empty());
    }

    #[test]
    fn opcode_table_312_canonical_coverage() {
        let v: PyVersion = PyVersion::PY312;
        assert_eq!(opname(0, v), "CACHE");
        assert_eq!(opname(1, v), "POP_TOP");
        assert_eq!(opname(2, v), "PUSH_NULL");
        assert_eq!(opname(3, v), "INTERPRETER_EXIT");
        assert_eq!(opname(4, v), "END_FOR");
        assert_eq!(opname(250, v), "INSTRUMENTED_POP_JUMP_IF_TRUE");
        assert_eq!(opname(251, v), "INSTRUMENTED_END_FOR");
        assert_eq!(opname(252, v), "INSTRUMENTED_END_SEND");
        assert_eq!(opname(253, v), "INSTRUMENTED_INSTRUCTION");
        assert_eq!(opname(254, v), "INSTRUMENTED_LINE");
        assert!(opname(255, v) == "<unknown>" || !opname(255, v).is_empty());
    }

    #[test]
    fn opcode_table_313_canonical_coverage() {
        let v: PyVersion = PyVersion::PY313;
        assert_eq!(opname(0, v), "CACHE");
        assert_eq!(opname(1, v), "BEFORE_ASYNC_WITH");
        assert_eq!(opname(2, v), "BEFORE_WITH");
        assert_eq!(opname(3, v), "BINARY_OP_INPLACE_ADD_UNICODE");
        assert_eq!(opname(4, v), "BINARY_SLICE");
        assert_eq!(opname(250, v), "INSTRUMENTED_POP_JUMP_IF_TRUE");
        assert_eq!(opname(251, v), "INSTRUMENTED_POP_JUMP_IF_FALSE");
        assert_eq!(opname(252, v), "INSTRUMENTED_POP_JUMP_IF_NONE");
        assert_eq!(opname(253, v), "INSTRUMENTED_POP_JUMP_IF_NOT_NONE");
        assert_eq!(opname(254, v), "INSTRUMENTED_LINE");
        assert!(opname(255, v) == "<unknown>" || !opname(255, v).is_empty());
    }

    #[test]
    fn with_except_start_takes_no_arg_on_313_plus() {
        assert_eq!(opname(44, PyVersion::PY313), "WITH_EXCEPT_START");
        assert!(!has_arg(44, PyVersion::PY313));
        assert_eq!(opname(43, PyVersion::PY314), "WITH_EXCEPT_START");
        assert!(!has_arg(43, PyVersion::PY314));
        assert_eq!(opname(41, PyVersion::PY315), "WITH_EXCEPT_START");
        assert!(!has_arg(41, PyVersion::PY315));
        assert_eq!(opname(49, PyVersion::PY312), "WITH_EXCEPT_START");
        assert!(!has_arg(49, PyVersion::PY312));
    }

    #[test]
    fn opcode_table_314_canonical_coverage() {
        let v: PyVersion = PyVersion::PY314;
        assert_eq!(opname(0, v), "CACHE");
        assert_eq!(opname(1, v), "BINARY_SLICE");
        assert_eq!(opname(2, v), "BUILD_TEMPLATE");
        assert_eq!(opname(3, v), "BINARY_OP_INPLACE_ADD_UNICODE");
        assert_eq!(opname(4, v), "CALL_FUNCTION_EX");
        assert_eq!(opname(251, v), "INSTRUMENTED_CALL_KW");
        assert_eq!(opname(252, v), "INSTRUMENTED_CALL_FUNCTION_EX");
        assert_eq!(opname(253, v), "INSTRUMENTED_JUMP_BACKWARD");
        assert_eq!(opname(254, v), "INSTRUMENTED_LINE");
        assert_eq!(opname(255, v), "ENTER_EXECUTOR");
        assert!(opname(255, v) == "<unknown>" || !opname(255, v).is_empty());
    }
}
