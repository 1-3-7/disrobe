use disrobe_py_marshal::PyVersion;

const UNKNOWN_OPCODE: &str = "<unknown>";

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
    op >= have_argument(version)
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

const OPCODE_TABLE_27: [&str; 256] = {
    let mut t: [&'static str; 256] = build_default();
    t[0] = "STOP_CODE";
    t[1] = "POP_TOP";
    t[2] = "ROT_TWO";
    t[3] = "ROT_THREE";
    t[4] = "DUP_TOP";
    t[5] = "ROT_FOUR";
    t[9] = "NOP";
    t[10] = "UNARY_POSITIVE";
    t[11] = "UNARY_NEGATIVE";
    t[12] = "UNARY_NOT";
    t[13] = "UNARY_CONVERT";
    t[15] = "UNARY_INVERT";
    t[19] = "BINARY_POWER";
    t[20] = "BINARY_MULTIPLY";
    t[21] = "BINARY_DIVIDE";
    t[22] = "BINARY_MODULO";
    t[23] = "BINARY_ADD";
    t[24] = "BINARY_SUBTRACT";
    t[25] = "BINARY_SUBSCR";
    t[26] = "BINARY_FLOOR_DIVIDE";
    t[27] = "BINARY_TRUE_DIVIDE";
    t[28] = "INPLACE_FLOOR_DIVIDE";
    t[29] = "INPLACE_TRUE_DIVIDE";
    t[30] = "SLICE+0";
    t[31] = "SLICE+1";
    t[32] = "SLICE+2";
    t[33] = "SLICE+3";
    t[40] = "STORE_SLICE+0";
    t[41] = "STORE_SLICE+1";
    t[42] = "STORE_SLICE+2";
    t[43] = "STORE_SLICE+3";
    t[50] = "DELETE_SLICE+0";
    t[51] = "DELETE_SLICE+1";
    t[52] = "DELETE_SLICE+2";
    t[53] = "DELETE_SLICE+3";
    t[54] = "STORE_MAP";
    t[55] = "INPLACE_ADD";
    t[56] = "INPLACE_SUBTRACT";
    t[57] = "INPLACE_MULTIPLY";
    t[58] = "INPLACE_DIVIDE";
    t[59] = "INPLACE_MODULO";
    t[60] = "STORE_SUBSCR";
    t[61] = "DELETE_SUBSCR";
    t[62] = "BINARY_LSHIFT";
    t[63] = "BINARY_RSHIFT";
    t[64] = "BINARY_AND";
    t[65] = "BINARY_XOR";
    t[66] = "BINARY_OR";
    t[67] = "INPLACE_POWER";
    t[68] = "GET_ITER";
    t[70] = "PRINT_EXPR";
    t[71] = "PRINT_ITEM";
    t[72] = "PRINT_NEWLINE";
    t[73] = "PRINT_ITEM_TO";
    t[74] = "PRINT_NEWLINE_TO";
    t[75] = "INPLACE_LSHIFT";
    t[76] = "INPLACE_RSHIFT";
    t[77] = "INPLACE_AND";
    t[78] = "INPLACE_XOR";
    t[79] = "INPLACE_OR";
    t[80] = "BREAK_LOOP";
    t[81] = "WITH_CLEANUP";
    t[82] = "LOAD_LOCALS";
    t[83] = "RETURN_VALUE";
    t[84] = "IMPORT_STAR";
    t[85] = "EXEC_STMT";
    t[86] = "YIELD_VALUE";
    t[87] = "POP_BLOCK";
    t[88] = "END_FINALLY";
    t[89] = "BUILD_CLASS";
    t[90] = "STORE_NAME";
    t[91] = "DELETE_NAME";
    t[92] = "UNPACK_SEQUENCE";
    t[93] = "FOR_ITER";
    t[94] = "LIST_APPEND";
    t[95] = "STORE_ATTR";
    t[96] = "DELETE_ATTR";
    t[97] = "STORE_GLOBAL";
    t[98] = "DELETE_GLOBAL";
    t[99] = "DUP_TOPX";
    t[100] = "LOAD_CONST";
    t[101] = "LOAD_NAME";
    t[102] = "BUILD_TUPLE";
    t[103] = "BUILD_LIST";
    t[104] = "BUILD_SET";
    t[105] = "BUILD_MAP";
    t[106] = "LOAD_ATTR";
    t[107] = "COMPARE_OP";
    t[108] = "IMPORT_NAME";
    t[109] = "IMPORT_FROM";
    t[110] = "JUMP_FORWARD";
    t[111] = "JUMP_IF_FALSE_OR_POP";
    t[112] = "JUMP_IF_TRUE_OR_POP";
    t[113] = "JUMP_ABSOLUTE";
    t[114] = "POP_JUMP_IF_FALSE";
    t[115] = "POP_JUMP_IF_TRUE";
    t[116] = "LOAD_GLOBAL";
    t[119] = "CONTINUE_LOOP";
    t[120] = "SETUP_LOOP";
    t[121] = "SETUP_EXCEPT";
    t[122] = "SETUP_FINALLY";
    t[124] = "LOAD_FAST";
    t[125] = "STORE_FAST";
    t[126] = "DELETE_FAST";
    t[130] = "RAISE_VARARGS";
    t[131] = "CALL_FUNCTION";
    t[132] = "MAKE_FUNCTION";
    t[133] = "BUILD_SLICE";
    t[134] = "MAKE_CLOSURE";
    t[135] = "LOAD_CLOSURE";
    t[136] = "LOAD_DEREF";
    t[137] = "STORE_DEREF";
    t[140] = "CALL_FUNCTION_VAR";
    t[141] = "CALL_FUNCTION_KW";
    t[142] = "CALL_FUNCTION_VAR_KW";
    t[143] = "SETUP_WITH";
    t[145] = "EXTENDED_ARG";
    t[146] = "SET_ADD";
    t[147] = "MAP_ADD";
    t
};

const OPCODE_TABLE_10: [&str; 256] = {
    let mut t: [&'static str; 256] = build_default();
    t[0] = "STOP_CODE";
    t[1] = "POP_TOP";
    t[2] = "ROT_TWO";
    t[3] = "ROT_THREE";
    t[4] = "DUP_TOP";
    t[10] = "UNARY_POSITIVE";
    t[11] = "UNARY_NEGATIVE";
    t[12] = "UNARY_NOT";
    t[13] = "UNARY_CONVERT";
    t[14] = "UNARY_CALL";
    t[15] = "UNARY_INVERT";
    t[20] = "BINARY_MULTIPLY";
    t[21] = "BINARY_DIVIDE";
    t[22] = "BINARY_MODULO";
    t[23] = "BINARY_ADD";
    t[24] = "BINARY_SUBTRACT";
    t[25] = "BINARY_SUBSCR";
    t[26] = "BINARY_CALL";
    t[30] = "SLICE+0";
    t[31] = "SLICE+1";
    t[32] = "SLICE+2";
    t[33] = "SLICE+3";
    t[40] = "STORE_SLICE+0";
    t[41] = "STORE_SLICE+1";
    t[42] = "STORE_SLICE+2";
    t[43] = "STORE_SLICE+3";
    t[50] = "DELETE_SLICE+0";
    t[51] = "DELETE_SLICE+1";
    t[52] = "DELETE_SLICE+2";
    t[53] = "DELETE_SLICE+3";
    t[60] = "STORE_SUBSCR";
    t[61] = "DELETE_SUBSCR";
    t[62] = "BINARY_LSHIFT";
    t[63] = "BINARY_RSHIFT";
    t[64] = "BINARY_AND";
    t[65] = "BINARY_XOR";
    t[66] = "BINARY_OR";
    t[70] = "PRINT_EXPR";
    t[71] = "PRINT_ITEM";
    t[72] = "PRINT_NEWLINE";
    t[80] = "BREAK_LOOP";
    t[81] = "RAISE_EXCEPTION";
    t[82] = "LOAD_LOCALS";
    t[83] = "RETURN_VALUE";
    t[84] = "LOAD_GLOBALS";
    t[85] = "EXEC_STMT";
    t[86] = "BUILD_FUNCTION";
    t[87] = "POP_BLOCK";
    t[88] = "END_FINALLY";
    t[89] = "BUILD_CLASS";
    t[90] = "STORE_NAME";
    t[91] = "DELETE_NAME";
    t[92] = "UNPACK_TUPLE";
    t[93] = "UNPACK_LIST";
    t[94] = "UNPACK_ARG";
    t[95] = "STORE_ATTR";
    t[96] = "DELETE_ATTR";
    t[97] = "STORE_GLOBAL";
    t[98] = "DELETE_GLOBAL";
    t[99] = "UNPACK_VARARG";
    t[100] = "LOAD_CONST";
    t[101] = "LOAD_NAME";
    t[102] = "BUILD_TUPLE";
    t[103] = "BUILD_LIST";
    t[104] = "BUILD_MAP";
    t[105] = "LOAD_ATTR";
    t[106] = "COMPARE_OP";
    t[107] = "IMPORT_NAME";
    t[108] = "IMPORT_FROM";
    t[109] = "ACCESS_MODE";
    t[110] = "JUMP_FORWARD";
    t[111] = "JUMP_IF_FALSE";
    t[112] = "JUMP_IF_TRUE";
    t[113] = "JUMP_ABSOLUTE";
    t[114] = "FOR_LOOP";
    t[115] = "LOAD_LOCAL";
    t[116] = "LOAD_GLOBAL";
    t[120] = "SETUP_LOOP";
    t[121] = "SETUP_EXCEPT";
    t[122] = "SETUP_FINALLY";
    t[123] = "RESERVE_FAST";
    t[124] = "LOAD_FAST";
    t[125] = "STORE_FAST";
    t[126] = "DELETE_FAST";
    t[127] = "SET_LINENO";
    t
};

const OPCODE_TABLE_11: [&str; 256] = {
    let mut t: [&'static str; 256] = OPCODE_TABLE_10;
    t[117] = "SET_FUNC_ARGS";
    t
};

const OPCODE_TABLE_13: [&str; 256] = {
    let mut t: [&'static str; 256] = build_default();
    t[0] = "STOP_CODE";
    t[1] = "POP_TOP";
    t[2] = "ROT_TWO";
    t[3] = "ROT_THREE";
    t[4] = "DUP_TOP";
    t[10] = "UNARY_POSITIVE";
    t[11] = "UNARY_NEGATIVE";
    t[12] = "UNARY_NOT";
    t[13] = "UNARY_CONVERT";
    t[15] = "UNARY_INVERT";
    t[20] = "BINARY_MULTIPLY";
    t[21] = "BINARY_DIVIDE";
    t[22] = "BINARY_MODULO";
    t[23] = "BINARY_ADD";
    t[24] = "BINARY_SUBTRACT";
    t[25] = "BINARY_SUBSCR";
    t[30] = "SLICE+0";
    t[31] = "SLICE+1";
    t[32] = "SLICE+2";
    t[33] = "SLICE+3";
    t[40] = "STORE_SLICE+0";
    t[41] = "STORE_SLICE+1";
    t[42] = "STORE_SLICE+2";
    t[43] = "STORE_SLICE+3";
    t[50] = "DELETE_SLICE+0";
    t[51] = "DELETE_SLICE+1";
    t[52] = "DELETE_SLICE+2";
    t[53] = "DELETE_SLICE+3";
    t[60] = "STORE_SUBSCR";
    t[61] = "DELETE_SUBSCR";
    t[62] = "BINARY_LSHIFT";
    t[63] = "BINARY_RSHIFT";
    t[64] = "BINARY_AND";
    t[65] = "BINARY_XOR";
    t[66] = "BINARY_OR";
    t[70] = "PRINT_EXPR";
    t[71] = "PRINT_ITEM";
    t[72] = "PRINT_NEWLINE";
    t[80] = "BREAK_LOOP";
    t[82] = "LOAD_LOCALS";
    t[83] = "RETURN_VALUE";
    t[85] = "EXEC_STMT";
    t[87] = "POP_BLOCK";
    t[88] = "END_FINALLY";
    t[89] = "BUILD_CLASS";
    t[90] = "STORE_NAME";
    t[91] = "DELETE_NAME";
    t[92] = "UNPACK_TUPLE";
    t[93] = "UNPACK_LIST";
    t[94] = "UNPACK_ARG";
    t[95] = "STORE_ATTR";
    t[96] = "DELETE_ATTR";
    t[97] = "STORE_GLOBAL";
    t[98] = "DELETE_GLOBAL";
    t[99] = "UNPACK_VARARG";
    t[100] = "LOAD_CONST";
    t[101] = "LOAD_NAME";
    t[102] = "BUILD_TUPLE";
    t[103] = "BUILD_LIST";
    t[104] = "BUILD_MAP";
    t[105] = "LOAD_ATTR";
    t[106] = "COMPARE_OP";
    t[107] = "IMPORT_NAME";
    t[108] = "IMPORT_FROM";
    t[109] = "ACCESS_MODE";
    t[110] = "JUMP_FORWARD";
    t[111] = "JUMP_IF_FALSE";
    t[112] = "JUMP_IF_TRUE";
    t[113] = "JUMP_ABSOLUTE";
    t[114] = "FOR_LOOP";
    t[115] = "LOAD_LOCAL";
    t[116] = "LOAD_GLOBAL";
    t[117] = "SET_FUNC_ARGS";
    t[120] = "SETUP_LOOP";
    t[121] = "SETUP_EXCEPT";
    t[122] = "SETUP_FINALLY";
    t[124] = "LOAD_FAST";
    t[125] = "STORE_FAST";
    t[126] = "DELETE_FAST";
    t[127] = "SET_LINENO";
    t[130] = "RAISE_VARARGS";
    t[131] = "CALL_FUNCTION";
    t[132] = "MAKE_FUNCTION";
    t
};

const OPCODE_TABLE_14: [&str; 256] = {
    let mut t: [&'static str; 256] = OPCODE_TABLE_13;
    t[19] = "BINARY_POWER";
    t[133] = "BUILD_SLICE";
    t
};

const OPCODE_TABLE_15: [&str; 256] = {
    let mut t: [&'static str; 256] = build_default();
    t[0] = "STOP_CODE";
    t[1] = "POP_TOP";
    t[2] = "ROT_TWO";
    t[3] = "ROT_THREE";
    t[4] = "DUP_TOP";
    t[10] = "UNARY_POSITIVE";
    t[11] = "UNARY_NEGATIVE";
    t[12] = "UNARY_NOT";
    t[13] = "UNARY_CONVERT";
    t[15] = "UNARY_INVERT";
    t[19] = "BINARY_POWER";
    t[20] = "BINARY_MULTIPLY";
    t[21] = "BINARY_DIVIDE";
    t[22] = "BINARY_MODULO";
    t[23] = "BINARY_ADD";
    t[24] = "BINARY_SUBTRACT";
    t[25] = "BINARY_SUBSCR";
    t[30] = "SLICE+0";
    t[31] = "SLICE+1";
    t[32] = "SLICE+2";
    t[33] = "SLICE+3";
    t[40] = "STORE_SLICE+0";
    t[41] = "STORE_SLICE+1";
    t[42] = "STORE_SLICE+2";
    t[43] = "STORE_SLICE+3";
    t[50] = "DELETE_SLICE+0";
    t[51] = "DELETE_SLICE+1";
    t[52] = "DELETE_SLICE+2";
    t[53] = "DELETE_SLICE+3";
    t[60] = "STORE_SUBSCR";
    t[61] = "DELETE_SUBSCR";
    t[62] = "BINARY_LSHIFT";
    t[63] = "BINARY_RSHIFT";
    t[64] = "BINARY_AND";
    t[65] = "BINARY_XOR";
    t[66] = "BINARY_OR";
    t[70] = "PRINT_EXPR";
    t[71] = "PRINT_ITEM";
    t[72] = "PRINT_NEWLINE";
    t[80] = "BREAK_LOOP";
    t[82] = "LOAD_LOCALS";
    t[83] = "RETURN_VALUE";
    t[85] = "EXEC_STMT";
    t[87] = "POP_BLOCK";
    t[88] = "END_FINALLY";
    t[89] = "BUILD_CLASS";
    t[90] = "STORE_NAME";
    t[91] = "DELETE_NAME";
    t[92] = "UNPACK_TUPLE";
    t[93] = "UNPACK_LIST";
    t[95] = "STORE_ATTR";
    t[96] = "DELETE_ATTR";
    t[97] = "STORE_GLOBAL";
    t[98] = "DELETE_GLOBAL";
    t[100] = "LOAD_CONST";
    t[101] = "LOAD_NAME";
    t[102] = "BUILD_TUPLE";
    t[103] = "BUILD_LIST";
    t[104] = "BUILD_MAP";
    t[105] = "LOAD_ATTR";
    t[106] = "COMPARE_OP";
    t[107] = "IMPORT_NAME";
    t[108] = "IMPORT_FROM";
    t[110] = "JUMP_FORWARD";
    t[111] = "JUMP_IF_FALSE";
    t[112] = "JUMP_IF_TRUE";
    t[113] = "JUMP_ABSOLUTE";
    t[114] = "FOR_LOOP";
    t[116] = "LOAD_GLOBAL";
    t[120] = "SETUP_LOOP";
    t[121] = "SETUP_EXCEPT";
    t[122] = "SETUP_FINALLY";
    t[124] = "LOAD_FAST";
    t[125] = "STORE_FAST";
    t[126] = "DELETE_FAST";
    t[127] = "SET_LINENO";
    t[130] = "RAISE_VARARGS";
    t[131] = "CALL_FUNCTION";
    t[132] = "MAKE_FUNCTION";
    t[133] = "BUILD_SLICE";
    t
};

const OPCODE_TABLE_16: [&str; 256] = {
    let mut t: [&'static str; 256] = OPCODE_TABLE_15;
    t[140] = "CALL_FUNCTION_VAR";
    t[141] = "CALL_FUNCTION_KW";
    t[142] = "CALL_FUNCTION_VAR_KW";
    t
};

const OPCODE_TABLE_20: [&str; 256] = {
    let mut t: [&'static str; 256] = build_default();
    t[0] = "STOP_CODE";
    t[1] = "POP_TOP";
    t[2] = "ROT_TWO";
    t[3] = "ROT_THREE";
    t[4] = "DUP_TOP";
    t[5] = "ROT_FOUR";
    t[10] = "UNARY_POSITIVE";
    t[11] = "UNARY_NEGATIVE";
    t[12] = "UNARY_NOT";
    t[13] = "UNARY_CONVERT";
    t[15] = "UNARY_INVERT";
    t[19] = "BINARY_POWER";
    t[20] = "BINARY_MULTIPLY";
    t[21] = "BINARY_DIVIDE";
    t[22] = "BINARY_MODULO";
    t[23] = "BINARY_ADD";
    t[24] = "BINARY_SUBTRACT";
    t[25] = "BINARY_SUBSCR";
    t[30] = "SLICE+0";
    t[31] = "SLICE+1";
    t[32] = "SLICE+2";
    t[33] = "SLICE+3";
    t[40] = "STORE_SLICE+0";
    t[41] = "STORE_SLICE+1";
    t[42] = "STORE_SLICE+2";
    t[43] = "STORE_SLICE+3";
    t[50] = "DELETE_SLICE+0";
    t[51] = "DELETE_SLICE+1";
    t[52] = "DELETE_SLICE+2";
    t[53] = "DELETE_SLICE+3";
    t[55] = "INPLACE_ADD";
    t[56] = "INPLACE_SUBTRACT";
    t[57] = "INPLACE_MULTIPLY";
    t[58] = "INPLACE_DIVIDE";
    t[59] = "INPLACE_MODULO";
    t[60] = "STORE_SUBSCR";
    t[61] = "DELETE_SUBSCR";
    t[62] = "BINARY_LSHIFT";
    t[63] = "BINARY_RSHIFT";
    t[64] = "BINARY_AND";
    t[65] = "BINARY_XOR";
    t[66] = "BINARY_OR";
    t[67] = "INPLACE_POWER";
    t[70] = "PRINT_EXPR";
    t[71] = "PRINT_ITEM";
    t[72] = "PRINT_NEWLINE";
    t[73] = "PRINT_ITEM_TO";
    t[74] = "PRINT_NEWLINE_TO";
    t[75] = "INPLACE_LSHIFT";
    t[76] = "INPLACE_RSHIFT";
    t[77] = "INPLACE_AND";
    t[78] = "INPLACE_XOR";
    t[79] = "INPLACE_OR";
    t[80] = "BREAK_LOOP";
    t[82] = "LOAD_LOCALS";
    t[83] = "RETURN_VALUE";
    t[84] = "IMPORT_STAR";
    t[85] = "EXEC_STMT";
    t[87] = "POP_BLOCK";
    t[88] = "END_FINALLY";
    t[89] = "BUILD_CLASS";
    t[90] = "STORE_NAME";
    t[91] = "DELETE_NAME";
    t[92] = "UNPACK_SEQUENCE";
    t[95] = "STORE_ATTR";
    t[96] = "DELETE_ATTR";
    t[97] = "STORE_GLOBAL";
    t[98] = "DELETE_GLOBAL";
    t[99] = "DUP_TOPX";
    t[100] = "LOAD_CONST";
    t[101] = "LOAD_NAME";
    t[102] = "BUILD_TUPLE";
    t[103] = "BUILD_LIST";
    t[104] = "BUILD_MAP";
    t[105] = "LOAD_ATTR";
    t[106] = "COMPARE_OP";
    t[107] = "IMPORT_NAME";
    t[108] = "IMPORT_FROM";
    t[110] = "JUMP_FORWARD";
    t[111] = "JUMP_IF_FALSE";
    t[112] = "JUMP_IF_TRUE";
    t[113] = "JUMP_ABSOLUTE";
    t[114] = "FOR_LOOP";
    t[116] = "LOAD_GLOBAL";
    t[120] = "SETUP_LOOP";
    t[121] = "SETUP_EXCEPT";
    t[122] = "SETUP_FINALLY";
    t[124] = "LOAD_FAST";
    t[125] = "STORE_FAST";
    t[126] = "DELETE_FAST";
    t[127] = "SET_LINENO";
    t[130] = "RAISE_VARARGS";
    t[131] = "CALL_FUNCTION";
    t[132] = "MAKE_FUNCTION";
    t[133] = "BUILD_SLICE";
    t[140] = "CALL_FUNCTION_VAR";
    t[141] = "CALL_FUNCTION_KW";
    t[142] = "CALL_FUNCTION_VAR_KW";
    t[143] = "EXTENDED_ARG";
    t
};

const OPCODE_TABLE_21: [&str; 256] = {
    let mut t: [&'static str; 256] = OPCODE_TABLE_20;
    t[119] = "CONTINUE_LOOP";
    t[134] = "MAKE_CLOSURE";
    t[135] = "LOAD_CLOSURE";
    t[136] = "LOAD_DEREF";
    t[137] = "STORE_DEREF";
    t
};

const OPCODE_TABLE_22: [&str; 256] = {
    let mut t: [&'static str; 256] = OPCODE_TABLE_21;
    t[26] = "BINARY_FLOOR_DIVIDE";
    t[27] = "BINARY_TRUE_DIVIDE";
    t[28] = "INPLACE_FLOOR_DIVIDE";
    t[29] = "INPLACE_TRUE_DIVIDE";
    t[68] = "GET_ITER";
    t[86] = "YIELD_VALUE";
    t[93] = "FOR_ITER";
    t
};

const OPCODE_TABLE_26: [&str; 256] = {
    let mut t: [&'static str; 256] = OPCODE_TABLE_22;
    t[54] = "STORE_MAP";
    t
};

const OPCODE_TABLE_30: [&str; 256] = {
    let mut t: [&'static str; 256] = build_default();
    t[0] = "STOP_CODE";
    t[1] = "POP_TOP";
    t[2] = "ROT_TWO";
    t[3] = "ROT_THREE";
    t[4] = "DUP_TOP";
    t[5] = "ROT_FOUR";
    t[9] = "NOP";
    t[10] = "UNARY_POSITIVE";
    t[11] = "UNARY_NEGATIVE";
    t[12] = "UNARY_NOT";
    t[15] = "UNARY_INVERT";
    t[17] = "SET_ADD";
    t[18] = "LIST_APPEND";
    t[19] = "BINARY_POWER";
    t[20] = "BINARY_MULTIPLY";
    t[22] = "BINARY_MODULO";
    t[23] = "BINARY_ADD";
    t[24] = "BINARY_SUBTRACT";
    t[25] = "BINARY_SUBSCR";
    t[26] = "BINARY_FLOOR_DIVIDE";
    t[27] = "BINARY_TRUE_DIVIDE";
    t[28] = "INPLACE_FLOOR_DIVIDE";
    t[29] = "INPLACE_TRUE_DIVIDE";
    t[54] = "STORE_MAP";
    t[55] = "INPLACE_ADD";
    t[56] = "INPLACE_SUBTRACT";
    t[57] = "INPLACE_MULTIPLY";
    t[59] = "INPLACE_MODULO";
    t[60] = "STORE_SUBSCR";
    t[61] = "DELETE_SUBSCR";
    t[62] = "BINARY_LSHIFT";
    t[63] = "BINARY_RSHIFT";
    t[64] = "BINARY_AND";
    t[65] = "BINARY_XOR";
    t[66] = "BINARY_OR";
    t[67] = "INPLACE_POWER";
    t[68] = "GET_ITER";
    t[69] = "STORE_LOCALS";
    t[70] = "PRINT_EXPR";
    t[71] = "LOAD_BUILD_CLASS";
    t[75] = "INPLACE_LSHIFT";
    t[76] = "INPLACE_RSHIFT";
    t[77] = "INPLACE_AND";
    t[78] = "INPLACE_XOR";
    t[79] = "INPLACE_OR";
    t[80] = "BREAK_LOOP";
    t[81] = "WITH_CLEANUP";
    t[83] = "RETURN_VALUE";
    t[84] = "IMPORT_STAR";
    t[86] = "YIELD_VALUE";
    t[87] = "POP_BLOCK";
    t[88] = "END_FINALLY";
    t[89] = "POP_EXCEPT";
    t[90] = "STORE_NAME";
    t[91] = "DELETE_NAME";
    t[92] = "UNPACK_SEQUENCE";
    t[93] = "FOR_ITER";
    t[94] = "UNPACK_EX";
    t[95] = "STORE_ATTR";
    t[96] = "DELETE_ATTR";
    t[97] = "STORE_GLOBAL";
    t[98] = "DELETE_GLOBAL";
    t[99] = "DUP_TOPX";
    t[100] = "LOAD_CONST";
    t[101] = "LOAD_NAME";
    t[102] = "BUILD_TUPLE";
    t[103] = "BUILD_LIST";
    t[104] = "BUILD_SET";
    t[105] = "BUILD_MAP";
    t[106] = "LOAD_ATTR";
    t[107] = "COMPARE_OP";
    t[108] = "IMPORT_NAME";
    t[109] = "IMPORT_FROM";
    t[110] = "JUMP_FORWARD";
    t[111] = "JUMP_IF_FALSE";
    t[112] = "JUMP_IF_TRUE";
    t[113] = "JUMP_ABSOLUTE";
    t[116] = "LOAD_GLOBAL";
    t[119] = "CONTINUE_LOOP";
    t[120] = "SETUP_LOOP";
    t[121] = "SETUP_EXCEPT";
    t[122] = "SETUP_FINALLY";
    t[124] = "LOAD_FAST";
    t[125] = "STORE_FAST";
    t[126] = "DELETE_FAST";
    t[130] = "RAISE_VARARGS";
    t[131] = "CALL_FUNCTION";
    t[132] = "MAKE_FUNCTION";
    t[133] = "BUILD_SLICE";
    t[134] = "MAKE_CLOSURE";
    t[135] = "LOAD_CLOSURE";
    t[136] = "LOAD_DEREF";
    t[137] = "STORE_DEREF";
    t[140] = "CALL_FUNCTION_VAR";
    t[141] = "CALL_FUNCTION_KW";
    t[142] = "CALL_FUNCTION_VAR_KW";
    t[143] = "EXTENDED_ARG";
    t
};

const OPCODE_TABLE_31: [&str; 256] = {
    let mut t: [&'static str; 256] = build_default();
    t[0] = "STOP_CODE";
    t[1] = "POP_TOP";
    t[2] = "ROT_TWO";
    t[3] = "ROT_THREE";
    t[4] = "DUP_TOP";
    t[5] = "ROT_FOUR";
    t[9] = "NOP";
    t[10] = "UNARY_POSITIVE";
    t[11] = "UNARY_NEGATIVE";
    t[12] = "UNARY_NOT";
    t[15] = "UNARY_INVERT";
    t[19] = "BINARY_POWER";
    t[20] = "BINARY_MULTIPLY";
    t[22] = "BINARY_MODULO";
    t[23] = "BINARY_ADD";
    t[24] = "BINARY_SUBTRACT";
    t[25] = "BINARY_SUBSCR";
    t[26] = "BINARY_FLOOR_DIVIDE";
    t[27] = "BINARY_TRUE_DIVIDE";
    t[28] = "INPLACE_FLOOR_DIVIDE";
    t[29] = "INPLACE_TRUE_DIVIDE";
    t[54] = "STORE_MAP";
    t[55] = "INPLACE_ADD";
    t[56] = "INPLACE_SUBTRACT";
    t[57] = "INPLACE_MULTIPLY";
    t[59] = "INPLACE_MODULO";
    t[60] = "STORE_SUBSCR";
    t[61] = "DELETE_SUBSCR";
    t[62] = "BINARY_LSHIFT";
    t[63] = "BINARY_RSHIFT";
    t[64] = "BINARY_AND";
    t[65] = "BINARY_XOR";
    t[66] = "BINARY_OR";
    t[67] = "INPLACE_POWER";
    t[68] = "GET_ITER";
    t[69] = "STORE_LOCALS";
    t[70] = "PRINT_EXPR";
    t[71] = "LOAD_BUILD_CLASS";
    t[75] = "INPLACE_LSHIFT";
    t[76] = "INPLACE_RSHIFT";
    t[77] = "INPLACE_AND";
    t[78] = "INPLACE_XOR";
    t[79] = "INPLACE_OR";
    t[80] = "BREAK_LOOP";
    t[81] = "WITH_CLEANUP";
    t[83] = "RETURN_VALUE";
    t[84] = "IMPORT_STAR";
    t[86] = "YIELD_VALUE";
    t[87] = "POP_BLOCK";
    t[88] = "END_FINALLY";
    t[89] = "POP_EXCEPT";
    t[90] = "STORE_NAME";
    t[91] = "DELETE_NAME";
    t[92] = "UNPACK_SEQUENCE";
    t[93] = "FOR_ITER";
    t[94] = "UNPACK_EX";
    t[95] = "STORE_ATTR";
    t[96] = "DELETE_ATTR";
    t[97] = "STORE_GLOBAL";
    t[98] = "DELETE_GLOBAL";
    t[99] = "DUP_TOPX";
    t[100] = "LOAD_CONST";
    t[101] = "LOAD_NAME";
    t[102] = "BUILD_TUPLE";
    t[103] = "BUILD_LIST";
    t[104] = "BUILD_SET";
    t[105] = "BUILD_MAP";
    t[106] = "LOAD_ATTR";
    t[107] = "COMPARE_OP";
    t[108] = "IMPORT_NAME";
    t[109] = "IMPORT_FROM";
    t[110] = "JUMP_FORWARD";
    t[111] = "JUMP_IF_FALSE_OR_POP";
    t[112] = "JUMP_IF_TRUE_OR_POP";
    t[113] = "JUMP_ABSOLUTE";
    t[114] = "POP_JUMP_IF_FALSE";
    t[115] = "POP_JUMP_IF_TRUE";
    t[116] = "LOAD_GLOBAL";
    t[119] = "CONTINUE_LOOP";
    t[120] = "SETUP_LOOP";
    t[121] = "SETUP_EXCEPT";
    t[122] = "SETUP_FINALLY";
    t[124] = "LOAD_FAST";
    t[125] = "STORE_FAST";
    t[126] = "DELETE_FAST";
    t[130] = "RAISE_VARARGS";
    t[131] = "CALL_FUNCTION";
    t[132] = "MAKE_FUNCTION";
    t[133] = "BUILD_SLICE";
    t[134] = "MAKE_CLOSURE";
    t[135] = "LOAD_CLOSURE";
    t[136] = "LOAD_DEREF";
    t[137] = "STORE_DEREF";
    t[140] = "CALL_FUNCTION_VAR";
    t[141] = "CALL_FUNCTION_KW";
    t[142] = "CALL_FUNCTION_VAR_KW";
    t[143] = "EXTENDED_ARG";
    t[145] = "LIST_APPEND";
    t[146] = "SET_ADD";
    t[147] = "MAP_ADD";
    t
};

const OPCODE_TABLE_32: [&str; 256] = {
    let mut t: [&'static str; 256] = build_default();
    t[0] = "STOP_CODE";
    t[1] = "POP_TOP";
    t[2] = "ROT_TWO";
    t[3] = "ROT_THREE";
    t[4] = "DUP_TOP";
    t[5] = "DUP_TOP_TWO";
    t[9] = "NOP";
    t[10] = "UNARY_POSITIVE";
    t[11] = "UNARY_NEGATIVE";
    t[12] = "UNARY_NOT";
    t[15] = "UNARY_INVERT";
    t[19] = "BINARY_POWER";
    t[20] = "BINARY_MULTIPLY";
    t[22] = "BINARY_MODULO";
    t[23] = "BINARY_ADD";
    t[24] = "BINARY_SUBTRACT";
    t[25] = "BINARY_SUBSCR";
    t[26] = "BINARY_FLOOR_DIVIDE";
    t[27] = "BINARY_TRUE_DIVIDE";
    t[28] = "INPLACE_FLOOR_DIVIDE";
    t[29] = "INPLACE_TRUE_DIVIDE";
    t[54] = "STORE_MAP";
    t[55] = "INPLACE_ADD";
    t[56] = "INPLACE_SUBTRACT";
    t[57] = "INPLACE_MULTIPLY";
    t[59] = "INPLACE_MODULO";
    t[60] = "STORE_SUBSCR";
    t[61] = "DELETE_SUBSCR";
    t[62] = "BINARY_LSHIFT";
    t[63] = "BINARY_RSHIFT";
    t[64] = "BINARY_AND";
    t[65] = "BINARY_XOR";
    t[66] = "BINARY_OR";
    t[67] = "INPLACE_POWER";
    t[68] = "GET_ITER";
    t[69] = "STORE_LOCALS";
    t[70] = "PRINT_EXPR";
    t[71] = "LOAD_BUILD_CLASS";
    t[75] = "INPLACE_LSHIFT";
    t[76] = "INPLACE_RSHIFT";
    t[77] = "INPLACE_AND";
    t[78] = "INPLACE_XOR";
    t[79] = "INPLACE_OR";
    t[80] = "BREAK_LOOP";
    t[81] = "WITH_CLEANUP";
    t[83] = "RETURN_VALUE";
    t[84] = "IMPORT_STAR";
    t[86] = "YIELD_VALUE";
    t[87] = "POP_BLOCK";
    t[88] = "END_FINALLY";
    t[89] = "POP_EXCEPT";
    t[90] = "STORE_NAME";
    t[91] = "DELETE_NAME";
    t[92] = "UNPACK_SEQUENCE";
    t[93] = "FOR_ITER";
    t[94] = "UNPACK_EX";
    t[95] = "STORE_ATTR";
    t[96] = "DELETE_ATTR";
    t[97] = "STORE_GLOBAL";
    t[98] = "DELETE_GLOBAL";
    t[100] = "LOAD_CONST";
    t[101] = "LOAD_NAME";
    t[102] = "BUILD_TUPLE";
    t[103] = "BUILD_LIST";
    t[104] = "BUILD_SET";
    t[105] = "BUILD_MAP";
    t[106] = "LOAD_ATTR";
    t[107] = "COMPARE_OP";
    t[108] = "IMPORT_NAME";
    t[109] = "IMPORT_FROM";
    t[110] = "JUMP_FORWARD";
    t[111] = "JUMP_IF_FALSE_OR_POP";
    t[112] = "JUMP_IF_TRUE_OR_POP";
    t[113] = "JUMP_ABSOLUTE";
    t[114] = "POP_JUMP_IF_FALSE";
    t[115] = "POP_JUMP_IF_TRUE";
    t[116] = "LOAD_GLOBAL";
    t[119] = "CONTINUE_LOOP";
    t[120] = "SETUP_LOOP";
    t[121] = "SETUP_EXCEPT";
    t[122] = "SETUP_FINALLY";
    t[124] = "LOAD_FAST";
    t[125] = "STORE_FAST";
    t[126] = "DELETE_FAST";
    t[130] = "RAISE_VARARGS";
    t[131] = "CALL_FUNCTION";
    t[132] = "MAKE_FUNCTION";
    t[133] = "BUILD_SLICE";
    t[134] = "MAKE_CLOSURE";
    t[135] = "LOAD_CLOSURE";
    t[136] = "LOAD_DEREF";
    t[137] = "STORE_DEREF";
    t[138] = "DELETE_DEREF";
    t[140] = "CALL_FUNCTION_VAR";
    t[141] = "CALL_FUNCTION_KW";
    t[142] = "CALL_FUNCTION_VAR_KW";
    t[143] = "SETUP_WITH";
    t[144] = "EXTENDED_ARG";
    t[145] = "LIST_APPEND";
    t[146] = "SET_ADD";
    t[147] = "MAP_ADD";
    t
};

const OPCODE_TABLE_33: [&str; 256] = {
    let mut t: [&'static str; 256] = build_default();
    t[1] = "POP_TOP";
    t[2] = "ROT_TWO";
    t[3] = "ROT_THREE";
    t[4] = "DUP_TOP";
    t[5] = "DUP_TOP_TWO";
    t[9] = "NOP";
    t[10] = "UNARY_POSITIVE";
    t[11] = "UNARY_NEGATIVE";
    t[12] = "UNARY_NOT";
    t[15] = "UNARY_INVERT";
    t[19] = "BINARY_POWER";
    t[20] = "BINARY_MULTIPLY";
    t[22] = "BINARY_MODULO";
    t[23] = "BINARY_ADD";
    t[24] = "BINARY_SUBTRACT";
    t[25] = "BINARY_SUBSCR";
    t[26] = "BINARY_FLOOR_DIVIDE";
    t[27] = "BINARY_TRUE_DIVIDE";
    t[28] = "INPLACE_FLOOR_DIVIDE";
    t[29] = "INPLACE_TRUE_DIVIDE";
    t[54] = "STORE_MAP";
    t[55] = "INPLACE_ADD";
    t[56] = "INPLACE_SUBTRACT";
    t[57] = "INPLACE_MULTIPLY";
    t[59] = "INPLACE_MODULO";
    t[60] = "STORE_SUBSCR";
    t[61] = "DELETE_SUBSCR";
    t[62] = "BINARY_LSHIFT";
    t[63] = "BINARY_RSHIFT";
    t[64] = "BINARY_AND";
    t[65] = "BINARY_XOR";
    t[66] = "BINARY_OR";
    t[67] = "INPLACE_POWER";
    t[68] = "GET_ITER";
    t[69] = "STORE_LOCALS";
    t[70] = "PRINT_EXPR";
    t[71] = "LOAD_BUILD_CLASS";
    t[72] = "YIELD_FROM";
    t[75] = "INPLACE_LSHIFT";
    t[76] = "INPLACE_RSHIFT";
    t[77] = "INPLACE_AND";
    t[78] = "INPLACE_XOR";
    t[79] = "INPLACE_OR";
    t[80] = "BREAK_LOOP";
    t[81] = "WITH_CLEANUP";
    t[83] = "RETURN_VALUE";
    t[84] = "IMPORT_STAR";
    t[86] = "YIELD_VALUE";
    t[87] = "POP_BLOCK";
    t[88] = "END_FINALLY";
    t[89] = "POP_EXCEPT";
    t[90] = "STORE_NAME";
    t[91] = "DELETE_NAME";
    t[92] = "UNPACK_SEQUENCE";
    t[93] = "FOR_ITER";
    t[94] = "UNPACK_EX";
    t[95] = "STORE_ATTR";
    t[96] = "DELETE_ATTR";
    t[97] = "STORE_GLOBAL";
    t[98] = "DELETE_GLOBAL";
    t[100] = "LOAD_CONST";
    t[101] = "LOAD_NAME";
    t[102] = "BUILD_TUPLE";
    t[103] = "BUILD_LIST";
    t[104] = "BUILD_SET";
    t[105] = "BUILD_MAP";
    t[106] = "LOAD_ATTR";
    t[107] = "COMPARE_OP";
    t[108] = "IMPORT_NAME";
    t[109] = "IMPORT_FROM";
    t[110] = "JUMP_FORWARD";
    t[111] = "JUMP_IF_FALSE_OR_POP";
    t[112] = "JUMP_IF_TRUE_OR_POP";
    t[113] = "JUMP_ABSOLUTE";
    t[114] = "POP_JUMP_IF_FALSE";
    t[115] = "POP_JUMP_IF_TRUE";
    t[116] = "LOAD_GLOBAL";
    t[119] = "CONTINUE_LOOP";
    t[120] = "SETUP_LOOP";
    t[121] = "SETUP_EXCEPT";
    t[122] = "SETUP_FINALLY";
    t[124] = "LOAD_FAST";
    t[125] = "STORE_FAST";
    t[126] = "DELETE_FAST";
    t[130] = "RAISE_VARARGS";
    t[131] = "CALL_FUNCTION";
    t[132] = "MAKE_FUNCTION";
    t[133] = "BUILD_SLICE";
    t[134] = "MAKE_CLOSURE";
    t[135] = "LOAD_CLOSURE";
    t[136] = "LOAD_DEREF";
    t[137] = "STORE_DEREF";
    t[138] = "DELETE_DEREF";
    t[140] = "CALL_FUNCTION_VAR";
    t[141] = "CALL_FUNCTION_KW";
    t[142] = "CALL_FUNCTION_VAR_KW";
    t[143] = "SETUP_WITH";
    t[144] = "EXTENDED_ARG";
    t[145] = "LIST_APPEND";
    t[146] = "SET_ADD";
    t[147] = "MAP_ADD";
    t
};

const OPCODE_TABLE_34: [&str; 256] = {
    let mut t: [&'static str; 256] = build_default();
    t[1] = "POP_TOP";
    t[2] = "ROT_TWO";
    t[3] = "ROT_THREE";
    t[4] = "DUP_TOP";
    t[5] = "DUP_TOP_TWO";
    t[9] = "NOP";
    t[10] = "UNARY_POSITIVE";
    t[11] = "UNARY_NEGATIVE";
    t[12] = "UNARY_NOT";
    t[15] = "UNARY_INVERT";
    t[19] = "BINARY_POWER";
    t[20] = "BINARY_MULTIPLY";
    t[22] = "BINARY_MODULO";
    t[23] = "BINARY_ADD";
    t[24] = "BINARY_SUBTRACT";
    t[25] = "BINARY_SUBSCR";
    t[26] = "BINARY_FLOOR_DIVIDE";
    t[27] = "BINARY_TRUE_DIVIDE";
    t[28] = "INPLACE_FLOOR_DIVIDE";
    t[29] = "INPLACE_TRUE_DIVIDE";
    t[54] = "STORE_MAP";
    t[55] = "INPLACE_ADD";
    t[56] = "INPLACE_SUBTRACT";
    t[57] = "INPLACE_MULTIPLY";
    t[59] = "INPLACE_MODULO";
    t[60] = "STORE_SUBSCR";
    t[61] = "DELETE_SUBSCR";
    t[62] = "BINARY_LSHIFT";
    t[63] = "BINARY_RSHIFT";
    t[64] = "BINARY_AND";
    t[65] = "BINARY_XOR";
    t[66] = "BINARY_OR";
    t[67] = "INPLACE_POWER";
    t[68] = "GET_ITER";
    t[70] = "PRINT_EXPR";
    t[71] = "LOAD_BUILD_CLASS";
    t[72] = "YIELD_FROM";
    t[75] = "INPLACE_LSHIFT";
    t[76] = "INPLACE_RSHIFT";
    t[77] = "INPLACE_AND";
    t[78] = "INPLACE_XOR";
    t[79] = "INPLACE_OR";
    t[80] = "BREAK_LOOP";
    t[81] = "WITH_CLEANUP";
    t[83] = "RETURN_VALUE";
    t[84] = "IMPORT_STAR";
    t[86] = "YIELD_VALUE";
    t[87] = "POP_BLOCK";
    t[88] = "END_FINALLY";
    t[89] = "POP_EXCEPT";
    t[90] = "STORE_NAME";
    t[91] = "DELETE_NAME";
    t[92] = "UNPACK_SEQUENCE";
    t[93] = "FOR_ITER";
    t[94] = "UNPACK_EX";
    t[95] = "STORE_ATTR";
    t[96] = "DELETE_ATTR";
    t[97] = "STORE_GLOBAL";
    t[98] = "DELETE_GLOBAL";
    t[100] = "LOAD_CONST";
    t[101] = "LOAD_NAME";
    t[102] = "BUILD_TUPLE";
    t[103] = "BUILD_LIST";
    t[104] = "BUILD_SET";
    t[105] = "BUILD_MAP";
    t[106] = "LOAD_ATTR";
    t[107] = "COMPARE_OP";
    t[108] = "IMPORT_NAME";
    t[109] = "IMPORT_FROM";
    t[110] = "JUMP_FORWARD";
    t[111] = "JUMP_IF_FALSE_OR_POP";
    t[112] = "JUMP_IF_TRUE_OR_POP";
    t[113] = "JUMP_ABSOLUTE";
    t[114] = "POP_JUMP_IF_FALSE";
    t[115] = "POP_JUMP_IF_TRUE";
    t[116] = "LOAD_GLOBAL";
    t[119] = "CONTINUE_LOOP";
    t[120] = "SETUP_LOOP";
    t[121] = "SETUP_EXCEPT";
    t[122] = "SETUP_FINALLY";
    t[124] = "LOAD_FAST";
    t[125] = "STORE_FAST";
    t[126] = "DELETE_FAST";
    t[130] = "RAISE_VARARGS";
    t[131] = "CALL_FUNCTION";
    t[132] = "MAKE_FUNCTION";
    t[133] = "BUILD_SLICE";
    t[134] = "MAKE_CLOSURE";
    t[135] = "LOAD_CLOSURE";
    t[136] = "LOAD_DEREF";
    t[137] = "STORE_DEREF";
    t[138] = "DELETE_DEREF";
    t[140] = "CALL_FUNCTION_VAR";
    t[141] = "CALL_FUNCTION_KW";
    t[142] = "CALL_FUNCTION_VAR_KW";
    t[143] = "SETUP_WITH";
    t[144] = "EXTENDED_ARG";
    t[145] = "LIST_APPEND";
    t[146] = "SET_ADD";
    t[147] = "MAP_ADD";
    t[148] = "LOAD_CLASSDEREF";
    t
};

const OPCODE_TABLE_35: [&str; 256] = {
    let mut t: [&'static str; 256] = build_default();
    t[1] = "POP_TOP";
    t[2] = "ROT_TWO";
    t[3] = "ROT_THREE";
    t[4] = "DUP_TOP";
    t[5] = "DUP_TOP_TWO";
    t[9] = "NOP";
    t[10] = "UNARY_POSITIVE";
    t[11] = "UNARY_NEGATIVE";
    t[12] = "UNARY_NOT";
    t[15] = "UNARY_INVERT";
    t[16] = "BINARY_MATRIX_MULTIPLY";
    t[17] = "INPLACE_MATRIX_MULTIPLY";
    t[19] = "BINARY_POWER";
    t[20] = "BINARY_MULTIPLY";
    t[22] = "BINARY_MODULO";
    t[23] = "BINARY_ADD";
    t[24] = "BINARY_SUBTRACT";
    t[25] = "BINARY_SUBSCR";
    t[26] = "BINARY_FLOOR_DIVIDE";
    t[27] = "BINARY_TRUE_DIVIDE";
    t[28] = "INPLACE_FLOOR_DIVIDE";
    t[29] = "INPLACE_TRUE_DIVIDE";
    t[50] = "GET_AITER";
    t[51] = "GET_ANEXT";
    t[52] = "BEFORE_ASYNC_WITH";
    t[55] = "INPLACE_ADD";
    t[56] = "INPLACE_SUBTRACT";
    t[57] = "INPLACE_MULTIPLY";
    t[59] = "INPLACE_MODULO";
    t[60] = "STORE_SUBSCR";
    t[61] = "DELETE_SUBSCR";
    t[62] = "BINARY_LSHIFT";
    t[63] = "BINARY_RSHIFT";
    t[64] = "BINARY_AND";
    t[65] = "BINARY_XOR";
    t[66] = "BINARY_OR";
    t[67] = "INPLACE_POWER";
    t[68] = "GET_ITER";
    t[69] = "GET_YIELD_FROM_ITER";
    t[70] = "PRINT_EXPR";
    t[71] = "LOAD_BUILD_CLASS";
    t[72] = "YIELD_FROM";
    t[73] = "GET_AWAITABLE";
    t[75] = "INPLACE_LSHIFT";
    t[76] = "INPLACE_RSHIFT";
    t[77] = "INPLACE_AND";
    t[78] = "INPLACE_XOR";
    t[79] = "INPLACE_OR";
    t[80] = "BREAK_LOOP";
    t[81] = "WITH_CLEANUP_START";
    t[82] = "WITH_CLEANUP_FINISH";
    t[83] = "RETURN_VALUE";
    t[84] = "IMPORT_STAR";
    t[86] = "YIELD_VALUE";
    t[87] = "POP_BLOCK";
    t[88] = "END_FINALLY";
    t[89] = "POP_EXCEPT";
    t[90] = "STORE_NAME";
    t[91] = "DELETE_NAME";
    t[92] = "UNPACK_SEQUENCE";
    t[93] = "FOR_ITER";
    t[94] = "UNPACK_EX";
    t[95] = "STORE_ATTR";
    t[96] = "DELETE_ATTR";
    t[97] = "STORE_GLOBAL";
    t[98] = "DELETE_GLOBAL";
    t[100] = "LOAD_CONST";
    t[101] = "LOAD_NAME";
    t[102] = "BUILD_TUPLE";
    t[103] = "BUILD_LIST";
    t[104] = "BUILD_SET";
    t[105] = "BUILD_MAP";
    t[106] = "LOAD_ATTR";
    t[107] = "COMPARE_OP";
    t[108] = "IMPORT_NAME";
    t[109] = "IMPORT_FROM";
    t[110] = "JUMP_FORWARD";
    t[111] = "JUMP_IF_FALSE_OR_POP";
    t[112] = "JUMP_IF_TRUE_OR_POP";
    t[113] = "JUMP_ABSOLUTE";
    t[114] = "POP_JUMP_IF_FALSE";
    t[115] = "POP_JUMP_IF_TRUE";
    t[116] = "LOAD_GLOBAL";
    t[119] = "CONTINUE_LOOP";
    t[120] = "SETUP_LOOP";
    t[121] = "SETUP_EXCEPT";
    t[122] = "SETUP_FINALLY";
    t[124] = "LOAD_FAST";
    t[125] = "STORE_FAST";
    t[126] = "DELETE_FAST";
    t[130] = "RAISE_VARARGS";
    t[131] = "CALL_FUNCTION";
    t[132] = "MAKE_FUNCTION";
    t[133] = "BUILD_SLICE";
    t[134] = "MAKE_CLOSURE";
    t[135] = "LOAD_CLOSURE";
    t[136] = "LOAD_DEREF";
    t[137] = "STORE_DEREF";
    t[138] = "DELETE_DEREF";
    t[140] = "CALL_FUNCTION_VAR";
    t[141] = "CALL_FUNCTION_KW";
    t[142] = "CALL_FUNCTION_VAR_KW";
    t[143] = "SETUP_WITH";
    t[144] = "EXTENDED_ARG";
    t[145] = "LIST_APPEND";
    t[146] = "SET_ADD";
    t[147] = "MAP_ADD";
    t[148] = "LOAD_CLASSDEREF";
    t[149] = "BUILD_LIST_UNPACK";
    t[150] = "BUILD_MAP_UNPACK";
    t[151] = "BUILD_MAP_UNPACK_WITH_CALL";
    t[152] = "BUILD_TUPLE_UNPACK";
    t[153] = "BUILD_SET_UNPACK";
    t[154] = "SETUP_ASYNC_WITH";
    t
};

const OPCODE_TABLE_36: [&str; 256] = {
    let mut t: [&'static str; 256] = build_default();
    t[1] = "POP_TOP";
    t[2] = "ROT_TWO";
    t[3] = "ROT_THREE";
    t[4] = "DUP_TOP";
    t[5] = "DUP_TOP_TWO";
    t[9] = "NOP";
    t[10] = "UNARY_POSITIVE";
    t[11] = "UNARY_NEGATIVE";
    t[12] = "UNARY_NOT";
    t[15] = "UNARY_INVERT";
    t[16] = "BINARY_MATRIX_MULTIPLY";
    t[17] = "INPLACE_MATRIX_MULTIPLY";
    t[19] = "BINARY_POWER";
    t[20] = "BINARY_MULTIPLY";
    t[22] = "BINARY_MODULO";
    t[23] = "BINARY_ADD";
    t[24] = "BINARY_SUBTRACT";
    t[25] = "BINARY_SUBSCR";
    t[26] = "BINARY_FLOOR_DIVIDE";
    t[27] = "BINARY_TRUE_DIVIDE";
    t[28] = "INPLACE_FLOOR_DIVIDE";
    t[29] = "INPLACE_TRUE_DIVIDE";
    t[50] = "GET_AITER";
    t[51] = "GET_ANEXT";
    t[52] = "BEFORE_ASYNC_WITH";
    t[55] = "INPLACE_ADD";
    t[56] = "INPLACE_SUBTRACT";
    t[57] = "INPLACE_MULTIPLY";
    t[59] = "INPLACE_MODULO";
    t[60] = "STORE_SUBSCR";
    t[61] = "DELETE_SUBSCR";
    t[62] = "BINARY_LSHIFT";
    t[63] = "BINARY_RSHIFT";
    t[64] = "BINARY_AND";
    t[65] = "BINARY_XOR";
    t[66] = "BINARY_OR";
    t[67] = "INPLACE_POWER";
    t[68] = "GET_ITER";
    t[69] = "GET_YIELD_FROM_ITER";
    t[70] = "PRINT_EXPR";
    t[71] = "LOAD_BUILD_CLASS";
    t[72] = "YIELD_FROM";
    t[73] = "GET_AWAITABLE";
    t[75] = "INPLACE_LSHIFT";
    t[76] = "INPLACE_RSHIFT";
    t[77] = "INPLACE_AND";
    t[78] = "INPLACE_XOR";
    t[79] = "INPLACE_OR";
    t[80] = "BREAK_LOOP";
    t[81] = "WITH_CLEANUP_START";
    t[82] = "WITH_CLEANUP_FINISH";
    t[83] = "RETURN_VALUE";
    t[84] = "IMPORT_STAR";
    t[85] = "SETUP_ANNOTATIONS";
    t[86] = "YIELD_VALUE";
    t[87] = "POP_BLOCK";
    t[88] = "END_FINALLY";
    t[89] = "POP_EXCEPT";
    t[90] = "STORE_NAME";
    t[91] = "DELETE_NAME";
    t[92] = "UNPACK_SEQUENCE";
    t[93] = "FOR_ITER";
    t[94] = "UNPACK_EX";
    t[95] = "STORE_ATTR";
    t[96] = "DELETE_ATTR";
    t[97] = "STORE_GLOBAL";
    t[98] = "DELETE_GLOBAL";
    t[100] = "LOAD_CONST";
    t[101] = "LOAD_NAME";
    t[102] = "BUILD_TUPLE";
    t[103] = "BUILD_LIST";
    t[104] = "BUILD_SET";
    t[105] = "BUILD_MAP";
    t[106] = "LOAD_ATTR";
    t[107] = "COMPARE_OP";
    t[108] = "IMPORT_NAME";
    t[109] = "IMPORT_FROM";
    t[110] = "JUMP_FORWARD";
    t[111] = "JUMP_IF_FALSE_OR_POP";
    t[112] = "JUMP_IF_TRUE_OR_POP";
    t[113] = "JUMP_ABSOLUTE";
    t[114] = "POP_JUMP_IF_FALSE";
    t[115] = "POP_JUMP_IF_TRUE";
    t[116] = "LOAD_GLOBAL";
    t[119] = "CONTINUE_LOOP";
    t[120] = "SETUP_LOOP";
    t[121] = "SETUP_EXCEPT";
    t[122] = "SETUP_FINALLY";
    t[124] = "LOAD_FAST";
    t[125] = "STORE_FAST";
    t[126] = "DELETE_FAST";
    t[127] = "STORE_ANNOTATION";
    t[130] = "RAISE_VARARGS";
    t[131] = "CALL_FUNCTION";
    t[132] = "MAKE_FUNCTION";
    t[133] = "BUILD_SLICE";
    t[135] = "LOAD_CLOSURE";
    t[136] = "LOAD_DEREF";
    t[137] = "STORE_DEREF";
    t[138] = "DELETE_DEREF";
    t[141] = "CALL_FUNCTION_KW";
    t[142] = "CALL_FUNCTION_EX";
    t[143] = "SETUP_WITH";
    t[144] = "EXTENDED_ARG";
    t[145] = "LIST_APPEND";
    t[146] = "SET_ADD";
    t[147] = "MAP_ADD";
    t[148] = "LOAD_CLASSDEREF";
    t[149] = "BUILD_LIST_UNPACK";
    t[150] = "BUILD_MAP_UNPACK";
    t[151] = "BUILD_MAP_UNPACK_WITH_CALL";
    t[152] = "BUILD_TUPLE_UNPACK";
    t[153] = "BUILD_SET_UNPACK";
    t[154] = "SETUP_ASYNC_WITH";
    t[155] = "FORMAT_VALUE";
    t[156] = "BUILD_CONST_KEY_MAP";
    t[157] = "BUILD_STRING";
    t[158] = "BUILD_TUPLE_UNPACK_WITH_CALL";
    t
};

const OPCODE_TABLE_37: [&str; 256] = {
    let mut t: [&'static str; 256] = build_default();
    t[1] = "POP_TOP";
    t[2] = "ROT_TWO";
    t[3] = "ROT_THREE";
    t[4] = "DUP_TOP";
    t[5] = "DUP_TOP_TWO";
    t[9] = "NOP";
    t[10] = "UNARY_POSITIVE";
    t[11] = "UNARY_NEGATIVE";
    t[12] = "UNARY_NOT";
    t[15] = "UNARY_INVERT";
    t[16] = "BINARY_MATRIX_MULTIPLY";
    t[17] = "INPLACE_MATRIX_MULTIPLY";
    t[19] = "BINARY_POWER";
    t[20] = "BINARY_MULTIPLY";
    t[22] = "BINARY_MODULO";
    t[23] = "BINARY_ADD";
    t[24] = "BINARY_SUBTRACT";
    t[25] = "BINARY_SUBSCR";
    t[26] = "BINARY_FLOOR_DIVIDE";
    t[27] = "BINARY_TRUE_DIVIDE";
    t[28] = "INPLACE_FLOOR_DIVIDE";
    t[29] = "INPLACE_TRUE_DIVIDE";
    t[50] = "GET_AITER";
    t[51] = "GET_ANEXT";
    t[52] = "BEFORE_ASYNC_WITH";
    t[55] = "INPLACE_ADD";
    t[56] = "INPLACE_SUBTRACT";
    t[57] = "INPLACE_MULTIPLY";
    t[59] = "INPLACE_MODULO";
    t[60] = "STORE_SUBSCR";
    t[61] = "DELETE_SUBSCR";
    t[62] = "BINARY_LSHIFT";
    t[63] = "BINARY_RSHIFT";
    t[64] = "BINARY_AND";
    t[65] = "BINARY_XOR";
    t[66] = "BINARY_OR";
    t[67] = "INPLACE_POWER";
    t[68] = "GET_ITER";
    t[69] = "GET_YIELD_FROM_ITER";
    t[70] = "PRINT_EXPR";
    t[71] = "LOAD_BUILD_CLASS";
    t[72] = "YIELD_FROM";
    t[73] = "GET_AWAITABLE";
    t[75] = "INPLACE_LSHIFT";
    t[76] = "INPLACE_RSHIFT";
    t[77] = "INPLACE_AND";
    t[78] = "INPLACE_XOR";
    t[79] = "INPLACE_OR";
    t[80] = "BREAK_LOOP";
    t[81] = "WITH_CLEANUP_START";
    t[82] = "WITH_CLEANUP_FINISH";
    t[83] = "RETURN_VALUE";
    t[84] = "IMPORT_STAR";
    t[85] = "SETUP_ANNOTATIONS";
    t[86] = "YIELD_VALUE";
    t[87] = "POP_BLOCK";
    t[88] = "END_FINALLY";
    t[89] = "POP_EXCEPT";
    t[90] = "STORE_NAME";
    t[91] = "DELETE_NAME";
    t[92] = "UNPACK_SEQUENCE";
    t[93] = "FOR_ITER";
    t[94] = "UNPACK_EX";
    t[95] = "STORE_ATTR";
    t[96] = "DELETE_ATTR";
    t[97] = "STORE_GLOBAL";
    t[98] = "DELETE_GLOBAL";
    t[100] = "LOAD_CONST";
    t[101] = "LOAD_NAME";
    t[102] = "BUILD_TUPLE";
    t[103] = "BUILD_LIST";
    t[104] = "BUILD_SET";
    t[105] = "BUILD_MAP";
    t[106] = "LOAD_ATTR";
    t[107] = "COMPARE_OP";
    t[108] = "IMPORT_NAME";
    t[109] = "IMPORT_FROM";
    t[110] = "JUMP_FORWARD";
    t[111] = "JUMP_IF_FALSE_OR_POP";
    t[112] = "JUMP_IF_TRUE_OR_POP";
    t[113] = "JUMP_ABSOLUTE";
    t[114] = "POP_JUMP_IF_FALSE";
    t[115] = "POP_JUMP_IF_TRUE";
    t[116] = "LOAD_GLOBAL";
    t[119] = "CONTINUE_LOOP";
    t[120] = "SETUP_LOOP";
    t[121] = "SETUP_EXCEPT";
    t[122] = "SETUP_FINALLY";
    t[124] = "LOAD_FAST";
    t[125] = "STORE_FAST";
    t[126] = "DELETE_FAST";
    t[130] = "RAISE_VARARGS";
    t[131] = "CALL_FUNCTION";
    t[132] = "MAKE_FUNCTION";
    t[133] = "BUILD_SLICE";
    t[135] = "LOAD_CLOSURE";
    t[136] = "LOAD_DEREF";
    t[137] = "STORE_DEREF";
    t[138] = "DELETE_DEREF";
    t[141] = "CALL_FUNCTION_KW";
    t[142] = "CALL_FUNCTION_EX";
    t[143] = "SETUP_WITH";
    t[144] = "EXTENDED_ARG";
    t[145] = "LIST_APPEND";
    t[146] = "SET_ADD";
    t[147] = "MAP_ADD";
    t[148] = "LOAD_CLASSDEREF";
    t[149] = "BUILD_LIST_UNPACK";
    t[150] = "BUILD_MAP_UNPACK";
    t[151] = "BUILD_MAP_UNPACK_WITH_CALL";
    t[152] = "BUILD_TUPLE_UNPACK";
    t[153] = "BUILD_SET_UNPACK";
    t[154] = "SETUP_ASYNC_WITH";
    t[155] = "FORMAT_VALUE";
    t[156] = "BUILD_CONST_KEY_MAP";
    t[157] = "BUILD_STRING";
    t[158] = "BUILD_TUPLE_UNPACK_WITH_CALL";
    t[160] = "LOAD_METHOD";
    t[161] = "CALL_METHOD";
    t
};

const OPCODE_TABLE_38: [&str; 256] = {
    let mut t: [&'static str; 256] = build_default();
    t[1] = "POP_TOP";
    t[2] = "ROT_TWO";
    t[3] = "ROT_THREE";
    t[4] = "DUP_TOP";
    t[5] = "DUP_TOP_TWO";
    t[6] = "ROT_FOUR";
    t[9] = "NOP";
    t[10] = "UNARY_POSITIVE";
    t[11] = "UNARY_NEGATIVE";
    t[12] = "UNARY_NOT";
    t[15] = "UNARY_INVERT";
    t[16] = "BINARY_MATRIX_MULTIPLY";
    t[17] = "INPLACE_MATRIX_MULTIPLY";
    t[19] = "BINARY_POWER";
    t[20] = "BINARY_MULTIPLY";
    t[22] = "BINARY_MODULO";
    t[23] = "BINARY_ADD";
    t[24] = "BINARY_SUBTRACT";
    t[25] = "BINARY_SUBSCR";
    t[26] = "BINARY_FLOOR_DIVIDE";
    t[27] = "BINARY_TRUE_DIVIDE";
    t[28] = "INPLACE_FLOOR_DIVIDE";
    t[29] = "INPLACE_TRUE_DIVIDE";
    t[50] = "GET_AITER";
    t[51] = "GET_ANEXT";
    t[52] = "BEFORE_ASYNC_WITH";
    t[53] = "BEGIN_FINALLY";
    t[54] = "END_ASYNC_FOR";
    t[55] = "INPLACE_ADD";
    t[56] = "INPLACE_SUBTRACT";
    t[57] = "INPLACE_MULTIPLY";
    t[59] = "INPLACE_MODULO";
    t[60] = "STORE_SUBSCR";
    t[61] = "DELETE_SUBSCR";
    t[62] = "BINARY_LSHIFT";
    t[63] = "BINARY_RSHIFT";
    t[64] = "BINARY_AND";
    t[65] = "BINARY_XOR";
    t[66] = "BINARY_OR";
    t[67] = "INPLACE_POWER";
    t[68] = "GET_ITER";
    t[69] = "GET_YIELD_FROM_ITER";
    t[70] = "PRINT_EXPR";
    t[71] = "LOAD_BUILD_CLASS";
    t[72] = "YIELD_FROM";
    t[73] = "GET_AWAITABLE";
    t[75] = "INPLACE_LSHIFT";
    t[76] = "INPLACE_RSHIFT";
    t[77] = "INPLACE_AND";
    t[78] = "INPLACE_XOR";
    t[79] = "INPLACE_OR";
    t[81] = "WITH_CLEANUP_START";
    t[82] = "WITH_CLEANUP_FINISH";
    t[83] = "RETURN_VALUE";
    t[84] = "IMPORT_STAR";
    t[85] = "SETUP_ANNOTATIONS";
    t[86] = "YIELD_VALUE";
    t[87] = "POP_BLOCK";
    t[88] = "END_FINALLY";
    t[89] = "POP_EXCEPT";
    t[90] = "STORE_NAME";
    t[91] = "DELETE_NAME";
    t[92] = "UNPACK_SEQUENCE";
    t[93] = "FOR_ITER";
    t[94] = "UNPACK_EX";
    t[95] = "STORE_ATTR";
    t[96] = "DELETE_ATTR";
    t[97] = "STORE_GLOBAL";
    t[98] = "DELETE_GLOBAL";
    t[100] = "LOAD_CONST";
    t[101] = "LOAD_NAME";
    t[102] = "BUILD_TUPLE";
    t[103] = "BUILD_LIST";
    t[104] = "BUILD_SET";
    t[105] = "BUILD_MAP";
    t[106] = "LOAD_ATTR";
    t[107] = "COMPARE_OP";
    t[108] = "IMPORT_NAME";
    t[109] = "IMPORT_FROM";
    t[110] = "JUMP_FORWARD";
    t[111] = "JUMP_IF_FALSE_OR_POP";
    t[112] = "JUMP_IF_TRUE_OR_POP";
    t[113] = "JUMP_ABSOLUTE";
    t[114] = "POP_JUMP_IF_FALSE";
    t[115] = "POP_JUMP_IF_TRUE";
    t[116] = "LOAD_GLOBAL";
    t[122] = "SETUP_FINALLY";
    t[124] = "LOAD_FAST";
    t[125] = "STORE_FAST";
    t[126] = "DELETE_FAST";
    t[130] = "RAISE_VARARGS";
    t[131] = "CALL_FUNCTION";
    t[132] = "MAKE_FUNCTION";
    t[133] = "BUILD_SLICE";
    t[135] = "LOAD_CLOSURE";
    t[136] = "LOAD_DEREF";
    t[137] = "STORE_DEREF";
    t[138] = "DELETE_DEREF";
    t[141] = "CALL_FUNCTION_KW";
    t[142] = "CALL_FUNCTION_EX";
    t[143] = "SETUP_WITH";
    t[144] = "EXTENDED_ARG";
    t[145] = "LIST_APPEND";
    t[146] = "SET_ADD";
    t[147] = "MAP_ADD";
    t[148] = "LOAD_CLASSDEREF";
    t[149] = "BUILD_LIST_UNPACK";
    t[150] = "BUILD_MAP_UNPACK";
    t[151] = "BUILD_MAP_UNPACK_WITH_CALL";
    t[152] = "BUILD_TUPLE_UNPACK";
    t[153] = "BUILD_SET_UNPACK";
    t[154] = "SETUP_ASYNC_WITH";
    t[155] = "FORMAT_VALUE";
    t[156] = "BUILD_CONST_KEY_MAP";
    t[157] = "BUILD_STRING";
    t[158] = "BUILD_TUPLE_UNPACK_WITH_CALL";
    t[160] = "LOAD_METHOD";
    t[161] = "CALL_METHOD";
    t[162] = "CALL_FINALLY";
    t[163] = "POP_FINALLY";
    t
};

const OPCODE_TABLE_39: [&str; 256] = {
    let mut t: [&'static str; 256] = build_default();
    t[1] = "POP_TOP";
    t[2] = "ROT_TWO";
    t[3] = "ROT_THREE";
    t[4] = "DUP_TOP";
    t[5] = "DUP_TOP_TWO";
    t[6] = "ROT_FOUR";
    t[9] = "NOP";
    t[10] = "UNARY_POSITIVE";
    t[11] = "UNARY_NEGATIVE";
    t[12] = "UNARY_NOT";
    t[15] = "UNARY_INVERT";
    t[16] = "BINARY_MATRIX_MULTIPLY";
    t[17] = "INPLACE_MATRIX_MULTIPLY";
    t[19] = "BINARY_POWER";
    t[20] = "BINARY_MULTIPLY";
    t[22] = "BINARY_MODULO";
    t[23] = "BINARY_ADD";
    t[24] = "BINARY_SUBTRACT";
    t[25] = "BINARY_SUBSCR";
    t[26] = "BINARY_FLOOR_DIVIDE";
    t[27] = "BINARY_TRUE_DIVIDE";
    t[28] = "INPLACE_FLOOR_DIVIDE";
    t[29] = "INPLACE_TRUE_DIVIDE";
    t[48] = "RERAISE";
    t[49] = "WITH_EXCEPT_START";
    t[50] = "GET_AITER";
    t[51] = "GET_ANEXT";
    t[52] = "BEFORE_ASYNC_WITH";
    t[54] = "END_ASYNC_FOR";
    t[55] = "INPLACE_ADD";
    t[56] = "INPLACE_SUBTRACT";
    t[57] = "INPLACE_MULTIPLY";
    t[59] = "INPLACE_MODULO";
    t[60] = "STORE_SUBSCR";
    t[61] = "DELETE_SUBSCR";
    t[62] = "BINARY_LSHIFT";
    t[63] = "BINARY_RSHIFT";
    t[64] = "BINARY_AND";
    t[65] = "BINARY_XOR";
    t[66] = "BINARY_OR";
    t[67] = "INPLACE_POWER";
    t[68] = "GET_ITER";
    t[69] = "GET_YIELD_FROM_ITER";
    t[70] = "PRINT_EXPR";
    t[71] = "LOAD_BUILD_CLASS";
    t[72] = "YIELD_FROM";
    t[73] = "GET_AWAITABLE";
    t[74] = "LOAD_ASSERTION_ERROR";
    t[75] = "INPLACE_LSHIFT";
    t[76] = "INPLACE_RSHIFT";
    t[77] = "INPLACE_AND";
    t[78] = "INPLACE_XOR";
    t[79] = "INPLACE_OR";
    t[82] = "LIST_TO_TUPLE";
    t[83] = "RETURN_VALUE";
    t[84] = "IMPORT_STAR";
    t[85] = "SETUP_ANNOTATIONS";
    t[86] = "YIELD_VALUE";
    t[87] = "POP_BLOCK";
    t[89] = "POP_EXCEPT";
    t[90] = "STORE_NAME";
    t[91] = "DELETE_NAME";
    t[92] = "UNPACK_SEQUENCE";
    t[93] = "FOR_ITER";
    t[94] = "UNPACK_EX";
    t[95] = "STORE_ATTR";
    t[96] = "DELETE_ATTR";
    t[97] = "STORE_GLOBAL";
    t[98] = "DELETE_GLOBAL";
    t[100] = "LOAD_CONST";
    t[101] = "LOAD_NAME";
    t[102] = "BUILD_TUPLE";
    t[103] = "BUILD_LIST";
    t[104] = "BUILD_SET";
    t[105] = "BUILD_MAP";
    t[106] = "LOAD_ATTR";
    t[107] = "COMPARE_OP";
    t[108] = "IMPORT_NAME";
    t[109] = "IMPORT_FROM";
    t[110] = "JUMP_FORWARD";
    t[111] = "JUMP_IF_FALSE_OR_POP";
    t[112] = "JUMP_IF_TRUE_OR_POP";
    t[113] = "JUMP_ABSOLUTE";
    t[114] = "POP_JUMP_IF_FALSE";
    t[115] = "POP_JUMP_IF_TRUE";
    t[116] = "LOAD_GLOBAL";
    t[117] = "IS_OP";
    t[118] = "CONTAINS_OP";
    t[121] = "JUMP_IF_NOT_EXC_MATCH";
    t[122] = "SETUP_FINALLY";
    t[124] = "LOAD_FAST";
    t[125] = "STORE_FAST";
    t[126] = "DELETE_FAST";
    t[130] = "RAISE_VARARGS";
    t[131] = "CALL_FUNCTION";
    t[132] = "MAKE_FUNCTION";
    t[133] = "BUILD_SLICE";
    t[135] = "LOAD_CLOSURE";
    t[136] = "LOAD_DEREF";
    t[137] = "STORE_DEREF";
    t[138] = "DELETE_DEREF";
    t[141] = "CALL_FUNCTION_KW";
    t[142] = "CALL_FUNCTION_EX";
    t[143] = "SETUP_WITH";
    t[144] = "EXTENDED_ARG";
    t[145] = "LIST_APPEND";
    t[146] = "SET_ADD";
    t[147] = "MAP_ADD";
    t[148] = "LOAD_CLASSDEREF";
    t[154] = "SETUP_ASYNC_WITH";
    t[155] = "FORMAT_VALUE";
    t[156] = "BUILD_CONST_KEY_MAP";
    t[157] = "BUILD_STRING";
    t[160] = "LOAD_METHOD";
    t[161] = "CALL_METHOD";
    t[162] = "LIST_EXTEND";
    t[163] = "SET_UPDATE";
    t[164] = "DICT_MERGE";
    t[165] = "DICT_UPDATE";
    t
};

const OPCODE_TABLE_310: [&str; 256] = {
    let mut t: [&'static str; 256] = build_default();
    t[1] = "POP_TOP";
    t[2] = "ROT_TWO";
    t[3] = "ROT_THREE";
    t[4] = "DUP_TOP";
    t[5] = "DUP_TOP_TWO";
    t[6] = "ROT_FOUR";
    t[9] = "NOP";
    t[10] = "UNARY_POSITIVE";
    t[11] = "UNARY_NEGATIVE";
    t[12] = "UNARY_NOT";
    t[15] = "UNARY_INVERT";
    t[16] = "BINARY_MATRIX_MULTIPLY";
    t[17] = "INPLACE_MATRIX_MULTIPLY";
    t[19] = "BINARY_POWER";
    t[20] = "BINARY_MULTIPLY";
    t[22] = "BINARY_MODULO";
    t[23] = "BINARY_ADD";
    t[24] = "BINARY_SUBTRACT";
    t[25] = "BINARY_SUBSCR";
    t[26] = "BINARY_FLOOR_DIVIDE";
    t[27] = "BINARY_TRUE_DIVIDE";
    t[28] = "INPLACE_FLOOR_DIVIDE";
    t[29] = "INPLACE_TRUE_DIVIDE";
    t[30] = "GET_LEN";
    t[31] = "MATCH_MAPPING";
    t[32] = "MATCH_SEQUENCE";
    t[33] = "MATCH_KEYS";
    t[34] = "COPY_DICT_WITHOUT_KEYS";
    t[49] = "WITH_EXCEPT_START";
    t[50] = "GET_AITER";
    t[51] = "GET_ANEXT";
    t[52] = "BEFORE_ASYNC_WITH";
    t[54] = "END_ASYNC_FOR";
    t[55] = "INPLACE_ADD";
    t[56] = "INPLACE_SUBTRACT";
    t[57] = "INPLACE_MULTIPLY";
    t[59] = "INPLACE_MODULO";
    t[60] = "STORE_SUBSCR";
    t[61] = "DELETE_SUBSCR";
    t[62] = "BINARY_LSHIFT";
    t[63] = "BINARY_RSHIFT";
    t[64] = "BINARY_AND";
    t[65] = "BINARY_XOR";
    t[66] = "BINARY_OR";
    t[67] = "INPLACE_POWER";
    t[68] = "GET_ITER";
    t[69] = "GET_YIELD_FROM_ITER";
    t[70] = "PRINT_EXPR";
    t[71] = "LOAD_BUILD_CLASS";
    t[72] = "YIELD_FROM";
    t[73] = "GET_AWAITABLE";
    t[74] = "LOAD_ASSERTION_ERROR";
    t[75] = "INPLACE_LSHIFT";
    t[76] = "INPLACE_RSHIFT";
    t[77] = "INPLACE_AND";
    t[78] = "INPLACE_XOR";
    t[79] = "INPLACE_OR";
    t[82] = "LIST_TO_TUPLE";
    t[83] = "RETURN_VALUE";
    t[84] = "IMPORT_STAR";
    t[85] = "SETUP_ANNOTATIONS";
    t[86] = "YIELD_VALUE";
    t[87] = "POP_BLOCK";
    t[89] = "POP_EXCEPT";
    t[90] = "STORE_NAME";
    t[91] = "DELETE_NAME";
    t[92] = "UNPACK_SEQUENCE";
    t[93] = "FOR_ITER";
    t[94] = "UNPACK_EX";
    t[95] = "STORE_ATTR";
    t[96] = "DELETE_ATTR";
    t[97] = "STORE_GLOBAL";
    t[98] = "DELETE_GLOBAL";
    t[99] = "ROT_N";
    t[100] = "LOAD_CONST";
    t[101] = "LOAD_NAME";
    t[102] = "BUILD_TUPLE";
    t[103] = "BUILD_LIST";
    t[104] = "BUILD_SET";
    t[105] = "BUILD_MAP";
    t[106] = "LOAD_ATTR";
    t[107] = "COMPARE_OP";
    t[108] = "IMPORT_NAME";
    t[109] = "IMPORT_FROM";
    t[110] = "JUMP_FORWARD";
    t[111] = "JUMP_IF_FALSE_OR_POP";
    t[112] = "JUMP_IF_TRUE_OR_POP";
    t[113] = "JUMP_ABSOLUTE";
    t[114] = "POP_JUMP_IF_FALSE";
    t[115] = "POP_JUMP_IF_TRUE";
    t[116] = "LOAD_GLOBAL";
    t[117] = "IS_OP";
    t[118] = "CONTAINS_OP";
    t[119] = "RERAISE";
    t[121] = "JUMP_IF_NOT_EXC_MATCH";
    t[122] = "SETUP_FINALLY";
    t[124] = "LOAD_FAST";
    t[125] = "STORE_FAST";
    t[126] = "DELETE_FAST";
    t[129] = "GEN_START";
    t[130] = "RAISE_VARARGS";
    t[131] = "CALL_FUNCTION";
    t[132] = "MAKE_FUNCTION";
    t[133] = "BUILD_SLICE";
    t[135] = "LOAD_CLOSURE";
    t[136] = "LOAD_DEREF";
    t[137] = "STORE_DEREF";
    t[138] = "DELETE_DEREF";
    t[141] = "CALL_FUNCTION_KW";
    t[142] = "CALL_FUNCTION_EX";
    t[143] = "SETUP_WITH";
    t[144] = "EXTENDED_ARG";
    t[145] = "LIST_APPEND";
    t[146] = "SET_ADD";
    t[147] = "MAP_ADD";
    t[148] = "LOAD_CLASSDEREF";
    t[152] = "MATCH_CLASS";
    t[154] = "SETUP_ASYNC_WITH";
    t[155] = "FORMAT_VALUE";
    t[156] = "BUILD_CONST_KEY_MAP";
    t[157] = "BUILD_STRING";
    t[160] = "LOAD_METHOD";
    t[161] = "CALL_METHOD";
    t[162] = "LIST_EXTEND";
    t[163] = "SET_UPDATE";
    t[164] = "DICT_MERGE";
    t[165] = "DICT_UPDATE";
    t
};

const OPCODE_TABLE_311: [&str; 256] = {
    let mut t: [&'static str; 256] = build_default();
    t[0] = "CACHE";
    t[1] = "POP_TOP";
    t[2] = "PUSH_NULL";
    t[3] = "BINARY_OP_ADAPTIVE";
    t[4] = "BINARY_OP_ADD_FLOAT";
    t[5] = "BINARY_OP_ADD_INT";
    t[6] = "BINARY_OP_ADD_UNICODE";
    t[7] = "BINARY_OP_INPLACE_ADD_UNICODE";
    t[8] = "BINARY_OP_MULTIPLY_FLOAT";
    t[9] = "NOP";
    t[10] = "UNARY_POSITIVE";
    t[11] = "UNARY_NEGATIVE";
    t[12] = "UNARY_NOT";
    t[13] = "BINARY_OP_MULTIPLY_INT";
    t[14] = "BINARY_OP_SUBTRACT_FLOAT";
    t[15] = "UNARY_INVERT";
    t[16] = "BINARY_OP_SUBTRACT_INT";
    t[17] = "BINARY_SUBSCR_ADAPTIVE";
    t[18] = "BINARY_SUBSCR_DICT";
    t[19] = "BINARY_SUBSCR_GETITEM";
    t[20] = "BINARY_SUBSCR_LIST_INT";
    t[21] = "BINARY_SUBSCR_TUPLE_INT";
    t[22] = "CALL_ADAPTIVE";
    t[23] = "CALL_PY_EXACT_ARGS";
    t[24] = "CALL_PY_WITH_DEFAULTS";
    t[25] = "BINARY_SUBSCR";
    t[26] = "COMPARE_OP_ADAPTIVE";
    t[27] = "COMPARE_OP_FLOAT_JUMP";
    t[28] = "COMPARE_OP_INT_JUMP";
    t[29] = "COMPARE_OP_STR_JUMP";
    t[30] = "GET_LEN";
    t[31] = "MATCH_MAPPING";
    t[32] = "MATCH_SEQUENCE";
    t[33] = "MATCH_KEYS";
    t[34] = "EXTENDED_ARG_QUICK";
    t[35] = "PUSH_EXC_INFO";
    t[36] = "CHECK_EXC_MATCH";
    t[37] = "CHECK_EG_MATCH";
    t[38] = "JUMP_BACKWARD_QUICK";
    t[39] = "LOAD_ATTR_ADAPTIVE";
    t[40] = "LOAD_ATTR_INSTANCE_VALUE";
    t[41] = "LOAD_ATTR_MODULE";
    t[42] = "LOAD_ATTR_SLOT";
    t[43] = "LOAD_ATTR_WITH_HINT";
    t[44] = "LOAD_CONST__LOAD_FAST";
    t[45] = "LOAD_FAST__LOAD_CONST";
    t[46] = "LOAD_FAST__LOAD_FAST";
    t[47] = "LOAD_GLOBAL_ADAPTIVE";
    t[48] = "LOAD_GLOBAL_BUILTIN";
    t[49] = "WITH_EXCEPT_START";
    t[50] = "GET_AITER";
    t[51] = "GET_ANEXT";
    t[52] = "BEFORE_ASYNC_WITH";
    t[53] = "BEFORE_WITH";
    t[54] = "END_ASYNC_FOR";
    t[55] = "LOAD_GLOBAL_MODULE";
    t[56] = "LOAD_METHOD_ADAPTIVE";
    t[57] = "LOAD_METHOD_CLASS";
    t[58] = "LOAD_METHOD_MODULE";
    t[59] = "LOAD_METHOD_NO_DICT";
    t[60] = "STORE_SUBSCR";
    t[61] = "DELETE_SUBSCR";
    t[62] = "LOAD_METHOD_WITH_DICT";
    t[63] = "LOAD_METHOD_WITH_VALUES";
    t[64] = "PRECALL_ADAPTIVE";
    t[65] = "PRECALL_BOUND_METHOD";
    t[66] = "PRECALL_BUILTIN_CLASS";
    t[67] = "PRECALL_BUILTIN_FAST_WITH_KEYWORDS";
    t[68] = "GET_ITER";
    t[69] = "GET_YIELD_FROM_ITER";
    t[70] = "PRINT_EXPR";
    t[71] = "LOAD_BUILD_CLASS";
    t[72] = "PRECALL_METHOD_DESCRIPTOR_FAST_WITH_KEYWORDS";
    t[73] = "PRECALL_NO_KW_BUILTIN_FAST";
    t[74] = "LOAD_ASSERTION_ERROR";
    t[75] = "RETURN_GENERATOR";
    t[76] = "PRECALL_NO_KW_BUILTIN_O";
    t[77] = "PRECALL_NO_KW_ISINSTANCE";
    t[78] = "PRECALL_NO_KW_LEN";
    t[79] = "PRECALL_NO_KW_LIST_APPEND";
    t[80] = "PRECALL_NO_KW_METHOD_DESCRIPTOR_FAST";
    t[81] = "PRECALL_NO_KW_METHOD_DESCRIPTOR_NOARGS";
    t[82] = "LIST_TO_TUPLE";
    t[83] = "RETURN_VALUE";
    t[84] = "IMPORT_STAR";
    t[85] = "SETUP_ANNOTATIONS";
    t[86] = "YIELD_VALUE";
    t[87] = "ASYNC_GEN_WRAP";
    t[88] = "PREP_RERAISE_STAR";
    t[89] = "POP_EXCEPT";
    t[90] = "STORE_NAME";
    t[91] = "DELETE_NAME";
    t[92] = "UNPACK_SEQUENCE";
    t[93] = "FOR_ITER";
    t[94] = "UNPACK_EX";
    t[95] = "STORE_ATTR";
    t[96] = "DELETE_ATTR";
    t[97] = "STORE_GLOBAL";
    t[98] = "DELETE_GLOBAL";
    t[99] = "SWAP";
    t[100] = "LOAD_CONST";
    t[101] = "LOAD_NAME";
    t[102] = "BUILD_TUPLE";
    t[103] = "BUILD_LIST";
    t[104] = "BUILD_SET";
    t[105] = "BUILD_MAP";
    t[106] = "LOAD_ATTR";
    t[107] = "COMPARE_OP";
    t[108] = "IMPORT_NAME";
    t[109] = "IMPORT_FROM";
    t[110] = "JUMP_FORWARD";
    t[111] = "JUMP_IF_FALSE_OR_POP";
    t[112] = "JUMP_IF_TRUE_OR_POP";
    t[113] = "PRECALL_NO_KW_METHOD_DESCRIPTOR_O";
    t[114] = "POP_JUMP_FORWARD_IF_FALSE";
    t[115] = "POP_JUMP_FORWARD_IF_TRUE";
    t[116] = "LOAD_GLOBAL";
    t[117] = "IS_OP";
    t[118] = "CONTAINS_OP";
    t[119] = "RERAISE";
    t[120] = "COPY";
    t[122] = "BINARY_OP";
    t[123] = "SEND";
    t[124] = "LOAD_FAST";
    t[125] = "STORE_FAST";
    t[126] = "DELETE_FAST";
    t[128] = "POP_JUMP_FORWARD_IF_NOT_NONE";
    t[129] = "POP_JUMP_FORWARD_IF_NONE";
    t[130] = "RAISE_VARARGS";
    t[131] = "GET_AWAITABLE";
    t[132] = "MAKE_FUNCTION";
    t[133] = "BUILD_SLICE";
    t[134] = "JUMP_BACKWARD_NO_INTERRUPT";
    t[135] = "MAKE_CELL";
    t[136] = "LOAD_CLOSURE";
    t[137] = "LOAD_DEREF";
    t[138] = "STORE_DEREF";
    t[139] = "DELETE_DEREF";
    t[140] = "JUMP_BACKWARD";
    t[142] = "CALL_FUNCTION_EX";
    t[143] = "PRECALL_PYFUNC";
    t[144] = "EXTENDED_ARG";
    t[145] = "LIST_APPEND";
    t[146] = "SET_ADD";
    t[147] = "MAP_ADD";
    t[148] = "LOAD_CLASSDEREF";
    t[149] = "COPY_FREE_VARS";
    t[150] = "RESUME_QUICK";
    t[151] = "RESUME";
    t[152] = "MATCH_CLASS";
    t[153] = "STORE_ATTR_ADAPTIVE";
    t[154] = "STORE_ATTR_INSTANCE_VALUE";
    t[155] = "FORMAT_VALUE";
    t[156] = "BUILD_CONST_KEY_MAP";
    t[157] = "BUILD_STRING";
    t[158] = "STORE_ATTR_SLOT";
    t[159] = "STORE_ATTR_WITH_HINT";
    t[160] = "LOAD_METHOD";
    t[161] = "STORE_FAST__LOAD_FAST";
    t[162] = "LIST_EXTEND";
    t[163] = "SET_UPDATE";
    t[164] = "DICT_MERGE";
    t[165] = "DICT_UPDATE";
    t[166] = "PRECALL";
    t[167] = "STORE_FAST__STORE_FAST";
    t[168] = "STORE_SUBSCR_ADAPTIVE";
    t[169] = "STORE_SUBSCR_DICT";
    t[170] = "STORE_SUBSCR_LIST_INT";
    t[171] = "CALL";
    t[172] = "KW_NAMES";
    t[173] = "POP_JUMP_BACKWARD_IF_NOT_NONE";
    t[174] = "POP_JUMP_BACKWARD_IF_NONE";
    t[175] = "POP_JUMP_BACKWARD_IF_FALSE";
    t[176] = "POP_JUMP_BACKWARD_IF_TRUE";
    t[177] = "UNPACK_SEQUENCE_ADAPTIVE";
    t[178] = "UNPACK_SEQUENCE_LIST";
    t[179] = "UNPACK_SEQUENCE_TUPLE";
    t[180] = "UNPACK_SEQUENCE_TWO_TUPLE";
    t
};

const OPCODE_TABLE_312: [&str; 256] = {
    let mut t: [&'static str; 256] = build_default();
    t[0] = "CACHE";
    t[1] = "POP_TOP";
    t[2] = "PUSH_NULL";
    t[3] = "INTERPRETER_EXIT";
    t[4] = "END_FOR";
    t[5] = "END_SEND";
    t[6] = "BINARY_OP_ADD_FLOAT";
    t[7] = "BINARY_OP_ADD_INT";
    t[8] = "BINARY_OP_ADD_UNICODE";
    t[9] = "NOP";
    t[10] = "BINARY_OP_INPLACE_ADD_UNICODE";
    t[11] = "UNARY_NEGATIVE";
    t[12] = "UNARY_NOT";
    t[13] = "BINARY_OP_MULTIPLY_FLOAT";
    t[14] = "BINARY_OP_MULTIPLY_INT";
    t[15] = "UNARY_INVERT";
    t[16] = "BINARY_OP_SUBTRACT_FLOAT";
    t[17] = "RESERVED";
    t[18] = "BINARY_OP_SUBTRACT_INT";
    t[19] = "BINARY_SUBSCR_DICT";
    t[20] = "BINARY_SUBSCR_GETITEM";
    t[21] = "BINARY_SUBSCR_LIST_INT";
    t[22] = "BINARY_SUBSCR_TUPLE_INT";
    t[23] = "CALL_PY_EXACT_ARGS";
    t[24] = "CALL_PY_WITH_DEFAULTS";
    t[25] = "BINARY_SUBSCR";
    t[26] = "BINARY_SLICE";
    t[27] = "STORE_SLICE";
    t[28] = "CALL_BOUND_METHOD_EXACT_ARGS";
    t[29] = "CALL_BUILTIN_CLASS";
    t[30] = "GET_LEN";
    t[31] = "MATCH_MAPPING";
    t[32] = "MATCH_SEQUENCE";
    t[33] = "MATCH_KEYS";
    t[34] = "CALL_BUILTIN_FAST_WITH_KEYWORDS";
    t[35] = "PUSH_EXC_INFO";
    t[36] = "CHECK_EXC_MATCH";
    t[37] = "CHECK_EG_MATCH";
    t[38] = "CALL_METHOD_DESCRIPTOR_FAST_WITH_KEYWORDS";
    t[39] = "CALL_NO_KW_BUILTIN_FAST";
    t[40] = "CALL_NO_KW_BUILTIN_O";
    t[41] = "CALL_NO_KW_ISINSTANCE";
    t[42] = "CALL_NO_KW_LEN";
    t[43] = "CALL_NO_KW_LIST_APPEND";
    t[44] = "CALL_NO_KW_METHOD_DESCRIPTOR_FAST";
    t[45] = "CALL_NO_KW_METHOD_DESCRIPTOR_NOARGS";
    t[46] = "CALL_NO_KW_METHOD_DESCRIPTOR_O";
    t[49] = "WITH_EXCEPT_START";
    t[50] = "GET_AITER";
    t[51] = "GET_ANEXT";
    t[52] = "BEFORE_ASYNC_WITH";
    t[53] = "BEFORE_WITH";
    t[54] = "END_ASYNC_FOR";
    t[55] = "CLEANUP_THROW";
    t[57] = "COMPARE_OP_FLOAT";
    t[58] = "COMPARE_OP_INT";
    t[59] = "COMPARE_OP_STR";
    t[60] = "STORE_SUBSCR";
    t[61] = "DELETE_SUBSCR";
    t[62] = "FOR_ITER_LIST";
    t[63] = "FOR_ITER_TUPLE";
    t[64] = "FOR_ITER_RANGE";
    t[65] = "FOR_ITER_GEN";
    t[66] = "LOAD_SUPER_ATTR_ATTR";
    t[67] = "LOAD_SUPER_ATTR_METHOD";
    t[68] = "GET_ITER";
    t[69] = "GET_YIELD_FROM_ITER";
    t[70] = "LOAD_ATTR_CLASS";
    t[71] = "LOAD_BUILD_CLASS";
    t[72] = "LOAD_ATTR_GETATTRIBUTE_OVERRIDDEN";
    t[73] = "LOAD_ATTR_INSTANCE_VALUE";
    t[74] = "LOAD_ASSERTION_ERROR";
    t[75] = "RETURN_GENERATOR";
    t[76] = "LOAD_ATTR_MODULE";
    t[77] = "LOAD_ATTR_PROPERTY";
    t[78] = "LOAD_ATTR_SLOT";
    t[79] = "LOAD_ATTR_WITH_HINT";
    t[80] = "LOAD_ATTR_METHOD_LAZY_DICT";
    t[81] = "LOAD_ATTR_METHOD_NO_DICT";
    t[82] = "LOAD_ATTR_METHOD_WITH_VALUES";
    t[83] = "RETURN_VALUE";
    t[84] = "LOAD_CONST__LOAD_FAST";
    t[85] = "SETUP_ANNOTATIONS";
    t[86] = "LOAD_FAST__LOAD_CONST";
    t[87] = "LOAD_LOCALS";
    t[88] = "LOAD_FAST__LOAD_FAST";
    t[89] = "POP_EXCEPT";
    t[90] = "STORE_NAME";
    t[91] = "DELETE_NAME";
    t[92] = "UNPACK_SEQUENCE";
    t[93] = "FOR_ITER";
    t[94] = "UNPACK_EX";
    t[95] = "STORE_ATTR";
    t[96] = "DELETE_ATTR";
    t[97] = "STORE_GLOBAL";
    t[98] = "DELETE_GLOBAL";
    t[99] = "SWAP";
    t[100] = "LOAD_CONST";
    t[101] = "LOAD_NAME";
    t[102] = "BUILD_TUPLE";
    t[103] = "BUILD_LIST";
    t[104] = "BUILD_SET";
    t[105] = "BUILD_MAP";
    t[106] = "LOAD_ATTR";
    t[107] = "COMPARE_OP";
    t[108] = "IMPORT_NAME";
    t[109] = "IMPORT_FROM";
    t[110] = "JUMP_FORWARD";
    t[111] = "LOAD_GLOBAL_BUILTIN";
    t[112] = "LOAD_GLOBAL_MODULE";
    t[113] = "STORE_ATTR_INSTANCE_VALUE";
    t[114] = "POP_JUMP_IF_FALSE";
    t[115] = "POP_JUMP_IF_TRUE";
    t[116] = "LOAD_GLOBAL";
    t[117] = "IS_OP";
    t[118] = "CONTAINS_OP";
    t[119] = "RERAISE";
    t[120] = "COPY";
    t[121] = "RETURN_CONST";
    t[122] = "BINARY_OP";
    t[123] = "SEND";
    t[124] = "LOAD_FAST";
    t[125] = "STORE_FAST";
    t[126] = "DELETE_FAST";
    t[127] = "LOAD_FAST_CHECK";
    t[128] = "POP_JUMP_IF_NOT_NONE";
    t[129] = "POP_JUMP_IF_NONE";
    t[130] = "RAISE_VARARGS";
    t[131] = "GET_AWAITABLE";
    t[132] = "MAKE_FUNCTION";
    t[133] = "BUILD_SLICE";
    t[134] = "JUMP_BACKWARD_NO_INTERRUPT";
    t[135] = "MAKE_CELL";
    t[136] = "LOAD_CLOSURE";
    t[137] = "LOAD_DEREF";
    t[138] = "STORE_DEREF";
    t[139] = "DELETE_DEREF";
    t[140] = "JUMP_BACKWARD";
    t[141] = "LOAD_SUPER_ATTR";
    t[142] = "CALL_FUNCTION_EX";
    t[143] = "LOAD_FAST_AND_CLEAR";
    t[144] = "EXTENDED_ARG";
    t[145] = "LIST_APPEND";
    t[146] = "SET_ADD";
    t[147] = "MAP_ADD";
    t[148] = "STORE_ATTR_SLOT";
    t[149] = "COPY_FREE_VARS";
    t[150] = "YIELD_VALUE";
    t[151] = "RESUME";
    t[152] = "MATCH_CLASS";
    t[153] = "STORE_ATTR_WITH_HINT";
    t[154] = "STORE_FAST__LOAD_FAST";
    t[155] = "FORMAT_VALUE";
    t[156] = "BUILD_CONST_KEY_MAP";
    t[157] = "BUILD_STRING";
    t[158] = "STORE_FAST__STORE_FAST";
    t[159] = "STORE_SUBSCR_DICT";
    t[160] = "STORE_SUBSCR_LIST_INT";
    t[161] = "UNPACK_SEQUENCE_LIST";
    t[162] = "LIST_EXTEND";
    t[163] = "SET_UPDATE";
    t[164] = "DICT_MERGE";
    t[165] = "DICT_UPDATE";
    t[166] = "UNPACK_SEQUENCE_TUPLE";
    t[167] = "UNPACK_SEQUENCE_TWO_TUPLE";
    t[168] = "SEND_GEN";
    t[171] = "CALL";
    t[172] = "KW_NAMES";
    t[173] = "CALL_INTRINSIC_1";
    t[174] = "CALL_INTRINSIC_2";
    t[175] = "LOAD_FROM_DICT_OR_GLOBALS";
    t[176] = "LOAD_FROM_DICT_OR_DEREF";
    t[237] = "INSTRUMENTED_LOAD_SUPER_ATTR";
    t[238] = "INSTRUMENTED_POP_JUMP_IF_NONE";
    t[239] = "INSTRUMENTED_POP_JUMP_IF_NOT_NONE";
    t[240] = "INSTRUMENTED_RESUME";
    t[241] = "INSTRUMENTED_CALL";
    t[242] = "INSTRUMENTED_RETURN_VALUE";
    t[243] = "INSTRUMENTED_YIELD_VALUE";
    t[244] = "INSTRUMENTED_CALL_FUNCTION_EX";
    t[245] = "INSTRUMENTED_JUMP_FORWARD";
    t[246] = "INSTRUMENTED_JUMP_BACKWARD";
    t[247] = "INSTRUMENTED_RETURN_CONST";
    t[248] = "INSTRUMENTED_FOR_ITER";
    t[249] = "INSTRUMENTED_POP_JUMP_IF_FALSE";
    t[250] = "INSTRUMENTED_POP_JUMP_IF_TRUE";
    t[251] = "INSTRUMENTED_END_FOR";
    t[252] = "INSTRUMENTED_END_SEND";
    t[253] = "INSTRUMENTED_INSTRUCTION";
    t[254] = "INSTRUMENTED_LINE";
    t
};

const OPCODE_TABLE_313: [&str; 256] = {
    let mut t: [&'static str; 256] = build_default();
    t[0] = "CACHE";
    t[1] = "BEFORE_ASYNC_WITH";
    t[2] = "BEFORE_WITH";
    t[3] = "BINARY_OP_INPLACE_ADD_UNICODE";
    t[4] = "BINARY_SLICE";
    t[5] = "BINARY_SUBSCR";
    t[6] = "CHECK_EG_MATCH";
    t[7] = "CHECK_EXC_MATCH";
    t[8] = "CLEANUP_THROW";
    t[9] = "DELETE_SUBSCR";
    t[10] = "END_ASYNC_FOR";
    t[11] = "END_FOR";
    t[12] = "END_SEND";
    t[13] = "EXIT_INIT_CHECK";
    t[14] = "FORMAT_SIMPLE";
    t[15] = "FORMAT_WITH_SPEC";
    t[16] = "GET_AITER";
    t[17] = "RESERVED";
    t[18] = "GET_ANEXT";
    t[19] = "GET_ITER";
    t[20] = "GET_LEN";
    t[21] = "GET_YIELD_FROM_ITER";
    t[22] = "INTERPRETER_EXIT";
    t[23] = "LOAD_ASSERTION_ERROR";
    t[24] = "LOAD_BUILD_CLASS";
    t[25] = "LOAD_LOCALS";
    t[26] = "MAKE_FUNCTION";
    t[27] = "MATCH_KEYS";
    t[28] = "MATCH_MAPPING";
    t[29] = "MATCH_SEQUENCE";
    t[30] = "NOP";
    t[31] = "POP_EXCEPT";
    t[32] = "POP_TOP";
    t[33] = "PUSH_EXC_INFO";
    t[34] = "PUSH_NULL";
    t[35] = "RETURN_GENERATOR";
    t[36] = "RETURN_VALUE";
    t[37] = "SETUP_ANNOTATIONS";
    t[38] = "STORE_SLICE";
    t[39] = "STORE_SUBSCR";
    t[40] = "TO_BOOL";
    t[41] = "UNARY_INVERT";
    t[42] = "UNARY_NEGATIVE";
    t[43] = "UNARY_NOT";
    t[44] = "WITH_EXCEPT_START";
    t[45] = "BINARY_OP";
    t[46] = "BUILD_CONST_KEY_MAP";
    t[47] = "BUILD_LIST";
    t[48] = "BUILD_MAP";
    t[49] = "BUILD_SET";
    t[50] = "BUILD_SLICE";
    t[51] = "BUILD_STRING";
    t[52] = "BUILD_TUPLE";
    t[53] = "CALL";
    t[54] = "CALL_FUNCTION_EX";
    t[55] = "CALL_INTRINSIC_1";
    t[56] = "CALL_INTRINSIC_2";
    t[57] = "CALL_KW";
    t[58] = "COMPARE_OP";
    t[59] = "CONTAINS_OP";
    t[60] = "CONVERT_VALUE";
    t[61] = "COPY";
    t[62] = "COPY_FREE_VARS";
    t[63] = "DELETE_ATTR";
    t[64] = "DELETE_DEREF";
    t[65] = "DELETE_FAST";
    t[66] = "DELETE_GLOBAL";
    t[67] = "DELETE_NAME";
    t[68] = "DICT_MERGE";
    t[69] = "DICT_UPDATE";
    t[70] = "ENTER_EXECUTOR";
    t[71] = "EXTENDED_ARG";
    t[72] = "FOR_ITER";
    t[73] = "GET_AWAITABLE";
    t[74] = "IMPORT_FROM";
    t[75] = "IMPORT_NAME";
    t[76] = "IS_OP";
    t[77] = "JUMP_BACKWARD";
    t[78] = "JUMP_BACKWARD_NO_INTERRUPT";
    t[79] = "JUMP_FORWARD";
    t[80] = "LIST_APPEND";
    t[81] = "LIST_EXTEND";
    t[82] = "LOAD_ATTR";
    t[83] = "LOAD_CONST";
    t[84] = "LOAD_DEREF";
    t[85] = "LOAD_FAST";
    t[86] = "LOAD_FAST_AND_CLEAR";
    t[87] = "LOAD_FAST_CHECK";
    t[88] = "LOAD_FAST_LOAD_FAST";
    t[89] = "LOAD_FROM_DICT_OR_DEREF";
    t[90] = "LOAD_FROM_DICT_OR_GLOBALS";
    t[91] = "LOAD_GLOBAL";
    t[92] = "LOAD_NAME";
    t[93] = "LOAD_SUPER_ATTR";
    t[94] = "MAKE_CELL";
    t[95] = "MAP_ADD";
    t[96] = "MATCH_CLASS";
    t[97] = "POP_JUMP_IF_FALSE";
    t[98] = "POP_JUMP_IF_NONE";
    t[99] = "POP_JUMP_IF_NOT_NONE";
    t[100] = "POP_JUMP_IF_TRUE";
    t[101] = "RAISE_VARARGS";
    t[102] = "RERAISE";
    t[103] = "RETURN_CONST";
    t[104] = "SEND";
    t[105] = "SET_ADD";
    t[106] = "SET_FUNCTION_ATTRIBUTE";
    t[107] = "SET_UPDATE";
    t[108] = "STORE_ATTR";
    t[109] = "STORE_DEREF";
    t[110] = "STORE_FAST";
    t[111] = "STORE_FAST_LOAD_FAST";
    t[112] = "STORE_FAST_STORE_FAST";
    t[113] = "STORE_GLOBAL";
    t[114] = "STORE_NAME";
    t[115] = "SWAP";
    t[116] = "UNPACK_EX";
    t[117] = "UNPACK_SEQUENCE";
    t[118] = "YIELD_VALUE";
    t[149] = "RESUME";
    t[150] = "BINARY_OP_ADD_FLOAT";
    t[151] = "BINARY_OP_ADD_INT";
    t[152] = "BINARY_OP_ADD_UNICODE";
    t[153] = "BINARY_OP_MULTIPLY_FLOAT";
    t[154] = "BINARY_OP_MULTIPLY_INT";
    t[155] = "BINARY_OP_SUBTRACT_FLOAT";
    t[156] = "BINARY_OP_SUBTRACT_INT";
    t[157] = "BINARY_SUBSCR_DICT";
    t[158] = "BINARY_SUBSCR_GETITEM";
    t[159] = "BINARY_SUBSCR_LIST_INT";
    t[160] = "BINARY_SUBSCR_STR_INT";
    t[161] = "BINARY_SUBSCR_TUPLE_INT";
    t[162] = "CALL_ALLOC_AND_ENTER_INIT";
    t[163] = "CALL_BOUND_METHOD_EXACT_ARGS";
    t[164] = "CALL_BOUND_METHOD_GENERAL";
    t[165] = "CALL_BUILTIN_CLASS";
    t[166] = "CALL_BUILTIN_FAST";
    t[167] = "CALL_BUILTIN_FAST_WITH_KEYWORDS";
    t[168] = "CALL_BUILTIN_O";
    t[169] = "CALL_ISINSTANCE";
    t[170] = "CALL_LEN";
    t[171] = "CALL_LIST_APPEND";
    t[172] = "CALL_METHOD_DESCRIPTOR_FAST";
    t[173] = "CALL_METHOD_DESCRIPTOR_FAST_WITH_KEYWORDS";
    t[174] = "CALL_METHOD_DESCRIPTOR_NOARGS";
    t[175] = "CALL_METHOD_DESCRIPTOR_O";
    t[176] = "CALL_NON_PY_GENERAL";
    t[177] = "CALL_PY_EXACT_ARGS";
    t[178] = "CALL_PY_GENERAL";
    t[182] = "COMPARE_OP_FLOAT";
    t[183] = "COMPARE_OP_INT";
    t[184] = "COMPARE_OP_STR";
    t[185] = "CONTAINS_OP_DICT";
    t[186] = "CONTAINS_OP_SET";
    t[187] = "FOR_ITER_GEN";
    t[188] = "FOR_ITER_LIST";
    t[189] = "FOR_ITER_RANGE";
    t[190] = "FOR_ITER_TUPLE";
    t[191] = "LOAD_ATTR_CLASS";
    t[192] = "LOAD_ATTR_GETATTRIBUTE_OVERRIDDEN";
    t[193] = "LOAD_ATTR_INSTANCE_VALUE";
    t[194] = "LOAD_ATTR_METHOD_LAZY_DICT";
    t[195] = "LOAD_ATTR_METHOD_NO_DICT";
    t[196] = "LOAD_ATTR_METHOD_WITH_VALUES";
    t[197] = "LOAD_ATTR_MODULE";
    t[198] = "LOAD_ATTR_NONDESCRIPTOR_NO_DICT";
    t[199] = "LOAD_ATTR_NONDESCRIPTOR_WITH_VALUES";
    t[200] = "LOAD_ATTR_PROPERTY";
    t[201] = "LOAD_ATTR_SLOT";
    t[202] = "LOAD_ATTR_WITH_HINT";
    t[203] = "LOAD_GLOBAL_BUILTIN";
    t[204] = "LOAD_GLOBAL_MODULE";
    t[205] = "LOAD_SUPER_ATTR_ATTR";
    t[206] = "LOAD_SUPER_ATTR_METHOD";
    t[207] = "RESUME_CHECK";
    t[208] = "SEND_GEN";
    t[209] = "STORE_ATTR_INSTANCE_VALUE";
    t[210] = "STORE_ATTR_SLOT";
    t[211] = "STORE_ATTR_WITH_HINT";
    t[212] = "STORE_SUBSCR_DICT";
    t[213] = "STORE_SUBSCR_LIST_INT";
    t[214] = "TO_BOOL_ALWAYS_TRUE";
    t[215] = "TO_BOOL_BOOL";
    t[216] = "TO_BOOL_INT";
    t[217] = "TO_BOOL_LIST";
    t[218] = "TO_BOOL_NONE";
    t[219] = "TO_BOOL_STR";
    t[220] = "UNPACK_SEQUENCE_LIST";
    t[221] = "UNPACK_SEQUENCE_TUPLE";
    t[222] = "UNPACK_SEQUENCE_TWO_TUPLE";
    t[236] = "INSTRUMENTED_RESUME";
    t[237] = "INSTRUMENTED_END_FOR";
    t[238] = "INSTRUMENTED_END_SEND";
    t[239] = "INSTRUMENTED_RETURN_VALUE";
    t[240] = "INSTRUMENTED_RETURN_CONST";
    t[241] = "INSTRUMENTED_YIELD_VALUE";
    t[242] = "INSTRUMENTED_LOAD_SUPER_ATTR";
    t[243] = "INSTRUMENTED_FOR_ITER";
    t[244] = "INSTRUMENTED_CALL";
    t[245] = "INSTRUMENTED_CALL_KW";
    t[246] = "INSTRUMENTED_CALL_FUNCTION_EX";
    t[247] = "INSTRUMENTED_INSTRUCTION";
    t[248] = "INSTRUMENTED_JUMP_FORWARD";
    t[249] = "INSTRUMENTED_JUMP_BACKWARD";
    t[250] = "INSTRUMENTED_POP_JUMP_IF_TRUE";
    t[251] = "INSTRUMENTED_POP_JUMP_IF_FALSE";
    t[252] = "INSTRUMENTED_POP_JUMP_IF_NONE";
    t[253] = "INSTRUMENTED_POP_JUMP_IF_NOT_NONE";
    t[254] = "INSTRUMENTED_LINE";
    t
};

const OPCODE_TABLE_314: [&str; 256] = {
    let mut t: [&'static str; 256] = build_default();
    t[0] = "CACHE";
    t[1] = "BINARY_SLICE";
    t[2] = "BUILD_TEMPLATE";
    t[3] = "BINARY_OP_INPLACE_ADD_UNICODE";
    t[4] = "CALL_FUNCTION_EX";
    t[5] = "CHECK_EG_MATCH";
    t[6] = "CHECK_EXC_MATCH";
    t[7] = "CLEANUP_THROW";
    t[8] = "DELETE_SUBSCR";
    t[9] = "END_FOR";
    t[10] = "END_SEND";
    t[11] = "EXIT_INIT_CHECK";
    t[12] = "FORMAT_SIMPLE";
    t[13] = "FORMAT_WITH_SPEC";
    t[14] = "GET_AITER";
    t[15] = "GET_ANEXT";
    t[16] = "GET_ITER";
    t[17] = "RESERVED";
    t[18] = "GET_LEN";
    t[19] = "GET_YIELD_FROM_ITER";
    t[20] = "INTERPRETER_EXIT";
    t[21] = "LOAD_BUILD_CLASS";
    t[22] = "LOAD_LOCALS";
    t[23] = "MAKE_FUNCTION";
    t[24] = "MATCH_KEYS";
    t[25] = "MATCH_MAPPING";
    t[26] = "MATCH_SEQUENCE";
    t[27] = "NOP";
    t[28] = "NOT_TAKEN";
    t[29] = "POP_EXCEPT";
    t[30] = "POP_ITER";
    t[31] = "POP_TOP";
    t[32] = "PUSH_EXC_INFO";
    t[33] = "PUSH_NULL";
    t[34] = "RETURN_GENERATOR";
    t[35] = "RETURN_VALUE";
    t[36] = "SETUP_ANNOTATIONS";
    t[37] = "STORE_SLICE";
    t[38] = "STORE_SUBSCR";
    t[39] = "TO_BOOL";
    t[40] = "UNARY_INVERT";
    t[41] = "UNARY_NEGATIVE";
    t[42] = "UNARY_NOT";
    t[43] = "WITH_EXCEPT_START";
    t[44] = "BINARY_OP";
    t[45] = "BUILD_INTERPOLATION";
    t[46] = "BUILD_LIST";
    t[47] = "BUILD_MAP";
    t[48] = "BUILD_SET";
    t[49] = "BUILD_SLICE";
    t[50] = "BUILD_STRING";
    t[51] = "BUILD_TUPLE";
    t[52] = "CALL";
    t[53] = "CALL_INTRINSIC_1";
    t[54] = "CALL_INTRINSIC_2";
    t[55] = "CALL_KW";
    t[56] = "COMPARE_OP";
    t[57] = "CONTAINS_OP";
    t[58] = "CONVERT_VALUE";
    t[59] = "COPY";
    t[60] = "COPY_FREE_VARS";
    t[61] = "DELETE_ATTR";
    t[62] = "DELETE_DEREF";
    t[63] = "DELETE_FAST";
    t[64] = "DELETE_GLOBAL";
    t[65] = "DELETE_NAME";
    t[66] = "DICT_MERGE";
    t[67] = "DICT_UPDATE";
    t[68] = "END_ASYNC_FOR";
    t[69] = "EXTENDED_ARG";
    t[70] = "FOR_ITER";
    t[71] = "GET_AWAITABLE";
    t[72] = "IMPORT_FROM";
    t[73] = "IMPORT_NAME";
    t[74] = "IS_OP";
    t[75] = "JUMP_BACKWARD";
    t[76] = "JUMP_BACKWARD_NO_INTERRUPT";
    t[77] = "JUMP_FORWARD";
    t[78] = "LIST_APPEND";
    t[79] = "LIST_EXTEND";
    t[80] = "LOAD_ATTR";
    t[81] = "LOAD_COMMON_CONSTANT";
    t[82] = "LOAD_CONST";
    t[83] = "LOAD_DEREF";
    t[84] = "LOAD_FAST";
    t[85] = "LOAD_FAST_AND_CLEAR";
    t[86] = "LOAD_FAST_BORROW";
    t[87] = "LOAD_FAST_BORROW_LOAD_FAST_BORROW";
    t[88] = "LOAD_FAST_CHECK";
    t[89] = "LOAD_FAST_LOAD_FAST";
    t[90] = "LOAD_FROM_DICT_OR_DEREF";
    t[91] = "LOAD_FROM_DICT_OR_GLOBALS";
    t[92] = "LOAD_GLOBAL";
    t[93] = "LOAD_NAME";
    t[94] = "LOAD_SMALL_INT";
    t[95] = "LOAD_SPECIAL";
    t[96] = "LOAD_SUPER_ATTR";
    t[97] = "MAKE_CELL";
    t[98] = "MAP_ADD";
    t[99] = "MATCH_CLASS";
    t[100] = "POP_JUMP_IF_FALSE";
    t[101] = "POP_JUMP_IF_NONE";
    t[102] = "POP_JUMP_IF_NOT_NONE";
    t[103] = "POP_JUMP_IF_TRUE";
    t[104] = "RAISE_VARARGS";
    t[105] = "RERAISE";
    t[106] = "SEND";
    t[107] = "SET_ADD";
    t[108] = "SET_FUNCTION_ATTRIBUTE";
    t[109] = "SET_UPDATE";
    t[110] = "STORE_ATTR";
    t[111] = "STORE_DEREF";
    t[112] = "STORE_FAST";
    t[113] = "STORE_FAST_LOAD_FAST";
    t[114] = "STORE_FAST_STORE_FAST";
    t[115] = "STORE_GLOBAL";
    t[116] = "STORE_NAME";
    t[117] = "SWAP";
    t[118] = "UNPACK_EX";
    t[119] = "UNPACK_SEQUENCE";
    t[120] = "YIELD_VALUE";
    t[128] = "RESUME";
    t[129] = "BINARY_OP_ADD_FLOAT";
    t[130] = "BINARY_OP_ADD_INT";
    t[131] = "BINARY_OP_ADD_UNICODE";
    t[132] = "BINARY_OP_EXTEND";
    t[133] = "BINARY_OP_MULTIPLY_FLOAT";
    t[134] = "BINARY_OP_MULTIPLY_INT";
    t[135] = "BINARY_OP_SUBSCR_DICT";
    t[136] = "BINARY_OP_SUBSCR_GETITEM";
    t[137] = "BINARY_OP_SUBSCR_LIST_INT";
    t[138] = "BINARY_OP_SUBSCR_LIST_SLICE";
    t[139] = "BINARY_OP_SUBSCR_STR_INT";
    t[140] = "BINARY_OP_SUBSCR_TUPLE_INT";
    t[141] = "BINARY_OP_SUBTRACT_FLOAT";
    t[142] = "BINARY_OP_SUBTRACT_INT";
    t[143] = "CALL_ALLOC_AND_ENTER_INIT";
    t[144] = "CALL_BOUND_METHOD_EXACT_ARGS";
    t[145] = "CALL_BOUND_METHOD_GENERAL";
    t[146] = "CALL_BUILTIN_CLASS";
    t[147] = "CALL_BUILTIN_FAST";
    t[148] = "CALL_BUILTIN_FAST_WITH_KEYWORDS";
    t[149] = "CALL_BUILTIN_O";
    t[150] = "CALL_ISINSTANCE";
    t[151] = "CALL_KW_BOUND_METHOD";
    t[152] = "CALL_KW_NON_PY";
    t[153] = "CALL_KW_PY";
    t[154] = "CALL_LEN";
    t[155] = "CALL_LIST_APPEND";
    t[156] = "CALL_METHOD_DESCRIPTOR_FAST";
    t[157] = "CALL_METHOD_DESCRIPTOR_FAST_WITH_KEYWORDS";
    t[158] = "CALL_METHOD_DESCRIPTOR_NOARGS";
    t[159] = "CALL_METHOD_DESCRIPTOR_O";
    t[160] = "CALL_NON_PY_GENERAL";
    t[161] = "CALL_PY_EXACT_ARGS";
    t[162] = "CALL_PY_GENERAL";
    t[166] = "COMPARE_OP_FLOAT";
    t[167] = "COMPARE_OP_INT";
    t[168] = "COMPARE_OP_STR";
    t[169] = "CONTAINS_OP_DICT";
    t[170] = "CONTAINS_OP_SET";
    t[171] = "FOR_ITER_GEN";
    t[172] = "FOR_ITER_LIST";
    t[173] = "FOR_ITER_RANGE";
    t[174] = "FOR_ITER_TUPLE";
    t[175] = "JUMP_BACKWARD_JIT";
    t[176] = "JUMP_BACKWARD_NO_JIT";
    t[177] = "LOAD_ATTR_CLASS";
    t[178] = "LOAD_ATTR_CLASS_WITH_METACLASS_CHECK";
    t[179] = "LOAD_ATTR_GETATTRIBUTE_OVERRIDDEN";
    t[180] = "LOAD_ATTR_INSTANCE_VALUE";
    t[181] = "LOAD_ATTR_METHOD_LAZY_DICT";
    t[182] = "LOAD_ATTR_METHOD_NO_DICT";
    t[183] = "LOAD_ATTR_METHOD_WITH_VALUES";
    t[184] = "LOAD_ATTR_MODULE";
    t[185] = "LOAD_ATTR_NONDESCRIPTOR_NO_DICT";
    t[186] = "LOAD_ATTR_NONDESCRIPTOR_WITH_VALUES";
    t[187] = "LOAD_ATTR_PROPERTY";
    t[188] = "LOAD_ATTR_SLOT";
    t[189] = "LOAD_ATTR_WITH_HINT";
    t[190] = "LOAD_CONST_IMMORTAL";
    t[191] = "LOAD_CONST_MORTAL";
    t[192] = "LOAD_GLOBAL_BUILTIN";
    t[193] = "LOAD_GLOBAL_MODULE";
    t[194] = "LOAD_SUPER_ATTR_ATTR";
    t[195] = "LOAD_SUPER_ATTR_METHOD";
    t[196] = "RESUME_CHECK";
    t[197] = "SEND_GEN";
    t[198] = "STORE_ATTR_INSTANCE_VALUE";
    t[199] = "STORE_ATTR_SLOT";
    t[200] = "STORE_ATTR_WITH_HINT";
    t[201] = "STORE_SUBSCR_DICT";
    t[202] = "STORE_SUBSCR_LIST_INT";
    t[203] = "TO_BOOL_ALWAYS_TRUE";
    t[204] = "TO_BOOL_BOOL";
    t[205] = "TO_BOOL_INT";
    t[206] = "TO_BOOL_LIST";
    t[207] = "TO_BOOL_NONE";
    t[208] = "TO_BOOL_STR";
    t[209] = "UNPACK_SEQUENCE_LIST";
    t[210] = "UNPACK_SEQUENCE_TUPLE";
    t[211] = "UNPACK_SEQUENCE_TWO_TUPLE";
    t[234] = "INSTRUMENTED_END_FOR";
    t[235] = "INSTRUMENTED_POP_ITER";
    t[236] = "INSTRUMENTED_END_SEND";
    t[237] = "INSTRUMENTED_FOR_ITER";
    t[238] = "INSTRUMENTED_INSTRUCTION";
    t[239] = "INSTRUMENTED_JUMP_FORWARD";
    t[240] = "INSTRUMENTED_NOT_TAKEN";
    t[241] = "INSTRUMENTED_POP_JUMP_IF_TRUE";
    t[242] = "INSTRUMENTED_POP_JUMP_IF_FALSE";
    t[243] = "INSTRUMENTED_POP_JUMP_IF_NONE";
    t[244] = "INSTRUMENTED_POP_JUMP_IF_NOT_NONE";
    t[245] = "INSTRUMENTED_RESUME";
    t[246] = "INSTRUMENTED_RETURN_VALUE";
    t[247] = "INSTRUMENTED_YIELD_VALUE";
    t[248] = "INSTRUMENTED_END_ASYNC_FOR";
    t[249] = "INSTRUMENTED_LOAD_SUPER_ATTR";
    t[250] = "INSTRUMENTED_CALL";
    t[251] = "INSTRUMENTED_CALL_KW";
    t[252] = "INSTRUMENTED_CALL_FUNCTION_EX";
    t[253] = "INSTRUMENTED_JUMP_BACKWARD";
    t[254] = "INSTRUMENTED_LINE";
    t[255] = "ENTER_EXECUTOR";
    t
};

const OPCODE_TABLE_315: [&str; 256] = {
    let mut t: [&'static str; 256] = build_default();
    t[0] = "CACHE";
    t[1] = "BINARY_SLICE";
    t[2] = "BUILD_TEMPLATE";
    t[4] = "CALL_FUNCTION_EX";
    t[5] = "CHECK_EG_MATCH";
    t[6] = "CHECK_EXC_MATCH";
    t[7] = "CLEANUP_THROW";
    t[8] = "DELETE_SUBSCR";
    t[9] = "END_FOR";
    t[10] = "END_SEND";
    t[11] = "EXIT_INIT_CHECK";
    t[12] = "FORMAT_SIMPLE";
    t[13] = "FORMAT_WITH_SPEC";
    t[14] = "GET_AITER";
    t[15] = "GET_ANEXT";
    t[16] = "GET_LEN";
    t[17] = "RESERVED";
    t[18] = "INTERPRETER_EXIT";
    t[19] = "LOAD_BUILD_CLASS";
    t[20] = "LOAD_LOCALS";
    t[21] = "MAKE_FUNCTION";
    t[22] = "MATCH_KEYS";
    t[23] = "MATCH_MAPPING";
    t[24] = "MATCH_SEQUENCE";
    t[25] = "NOP";
    t[26] = "NOT_TAKEN";
    t[27] = "POP_EXCEPT";
    t[28] = "POP_ITER";
    t[29] = "POP_TOP";
    t[30] = "PUSH_EXC_INFO";
    t[31] = "PUSH_NULL";
    t[32] = "RETURN_GENERATOR";
    t[33] = "RETURN_VALUE";
    t[34] = "SETUP_ANNOTATIONS";
    t[35] = "STORE_SLICE";
    t[36] = "STORE_SUBSCR";
    t[37] = "TO_BOOL";
    t[38] = "UNARY_INVERT";
    t[39] = "UNARY_NEGATIVE";
    t[40] = "UNARY_NOT";
    t[41] = "WITH_EXCEPT_START";
    t[42] = "BINARY_OP";
    t[43] = "BUILD_INTERPOLATION";
    t[44] = "BUILD_LIST";
    t[45] = "BUILD_MAP";
    t[46] = "BUILD_SET";
    t[47] = "BUILD_SLICE";
    t[48] = "BUILD_STRING";
    t[49] = "BUILD_TUPLE";
    t[50] = "CALL";
    t[51] = "CALL_INTRINSIC_1";
    t[52] = "CALL_INTRINSIC_2";
    t[53] = "CALL_KW";
    t[54] = "COMPARE_OP";
    t[55] = "CONTAINS_OP";
    t[56] = "CONVERT_VALUE";
    t[57] = "COPY";
    t[58] = "COPY_FREE_VARS";
    t[59] = "DELETE_ATTR";
    t[60] = "DELETE_DEREF";
    t[61] = "DELETE_FAST";
    t[62] = "DELETE_GLOBAL";
    t[63] = "DELETE_NAME";
    t[64] = "DICT_MERGE";
    t[65] = "DICT_UPDATE";
    t[66] = "END_ASYNC_FOR";
    t[67] = "EXTENDED_ARG";
    t[68] = "FOR_ITER";
    t[69] = "GET_AWAITABLE";
    t[70] = "GET_ITER";
    t[71] = "IMPORT_FROM";
    t[72] = "IMPORT_NAME";
    t[73] = "IS_OP";
    t[74] = "JUMP_BACKWARD";
    t[75] = "JUMP_BACKWARD_NO_INTERRUPT";
    t[76] = "JUMP_FORWARD";
    t[77] = "LIST_APPEND";
    t[78] = "LIST_EXTEND";
    t[79] = "LOAD_ATTR";
    t[80] = "LOAD_COMMON_CONSTANT";
    t[81] = "LOAD_CONST";
    t[82] = "LOAD_DEREF";
    t[83] = "LOAD_FAST";
    t[84] = "LOAD_FAST_AND_CLEAR";
    t[85] = "LOAD_FAST_BORROW";
    t[86] = "LOAD_FAST_BORROW_LOAD_FAST_BORROW";
    t[87] = "LOAD_FAST_CHECK";
    t[88] = "LOAD_FAST_LOAD_FAST";
    t[89] = "LOAD_FROM_DICT_OR_DEREF";
    t[90] = "LOAD_FROM_DICT_OR_GLOBALS";
    t[91] = "LOAD_GLOBAL";
    t[92] = "LOAD_NAME";
    t[93] = "LOAD_SMALL_INT";
    t[94] = "LOAD_SPECIAL";
    t[95] = "LOAD_SUPER_ATTR";
    t[96] = "MAKE_CELL";
    t[97] = "MAP_ADD";
    t[98] = "MATCH_CLASS";
    t[99] = "POP_JUMP_IF_FALSE";
    t[100] = "POP_JUMP_IF_NONE";
    t[101] = "POP_JUMP_IF_NOT_NONE";
    t[102] = "POP_JUMP_IF_TRUE";
    t[103] = "RAISE_VARARGS";
    t[104] = "RERAISE";
    t[105] = "SEND";
    t[106] = "SET_ADD";
    t[107] = "SET_FUNCTION_ATTRIBUTE";
    t[108] = "SET_UPDATE";
    t[109] = "STORE_ATTR";
    t[110] = "STORE_DEREF";
    t[111] = "STORE_FAST";
    t[112] = "STORE_FAST_LOAD_FAST";
    t[113] = "STORE_FAST_STORE_FAST";
    t[114] = "STORE_GLOBAL";
    t[115] = "STORE_NAME";
    t[116] = "SWAP";
    t[117] = "UNPACK_EX";
    t[118] = "UNPACK_SEQUENCE";
    t[119] = "YIELD_VALUE";
    t[128] = "RESUME";
    t[233] = "INSTRUMENTED_END_FOR";
    t[234] = "INSTRUMENTED_POP_ITER";
    t[235] = "INSTRUMENTED_END_SEND";
    t[236] = "INSTRUMENTED_FOR_ITER";
    t[237] = "INSTRUMENTED_INSTRUCTION";
    t[238] = "INSTRUMENTED_JUMP_FORWARD";
    t[239] = "INSTRUMENTED_NOT_TAKEN";
    t[240] = "INSTRUMENTED_POP_JUMP_IF_TRUE";
    t[241] = "INSTRUMENTED_POP_JUMP_IF_FALSE";
    t[242] = "INSTRUMENTED_POP_JUMP_IF_NONE";
    t[243] = "INSTRUMENTED_POP_JUMP_IF_NOT_NONE";
    t[244] = "INSTRUMENTED_RESUME";
    t[245] = "INSTRUMENTED_RETURN_VALUE";
    t[246] = "INSTRUMENTED_YIELD_VALUE";
    t[247] = "INSTRUMENTED_END_ASYNC_FOR";
    t[248] = "INSTRUMENTED_LOAD_SUPER_ATTR";
    t[249] = "INSTRUMENTED_CALL";
    t[250] = "INSTRUMENTED_CALL_KW";
    t[251] = "INSTRUMENTED_CALL_FUNCTION_EX";
    t[252] = "INSTRUMENTED_JUMP_BACKWARD";
    t[253] = "INSTRUMENTED_LINE";
    t[254] = "ENTER_EXECUTOR";
    t[255] = "TRACE_RECORD";
    t
};

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
        assert!(has_arg(44, PyVersion::PY313));
        assert!(!has_arg(42, PyVersion::PY314));
        assert!(has_arg(43, PyVersion::PY314));
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
        assert!(has_arg(41, PyVersion::PY315));
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
