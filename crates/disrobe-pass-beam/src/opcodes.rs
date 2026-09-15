#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpcodeSpec {
    pub name: &'static str,
    pub arity: u8,
}

pub const MAX_OPCODE: u32 = 191;

#[allow(clippy::too_many_lines)]
#[must_use]
pub const fn opcode_spec(op: u32) -> Option<OpcodeSpec> {
    Some(match op {
        1 => OpcodeSpec {
            name: "label",
            arity: 1,
        },
        2 => OpcodeSpec {
            name: "func_info",
            arity: 3,
        },
        3 => OpcodeSpec {
            name: "int_code_end",
            arity: 0,
        },
        4 => OpcodeSpec {
            name: "call",
            arity: 2,
        },
        5 => OpcodeSpec {
            name: "call_last",
            arity: 3,
        },
        6 => OpcodeSpec {
            name: "call_only",
            arity: 2,
        },
        7 => OpcodeSpec {
            name: "call_ext",
            arity: 2,
        },
        8 => OpcodeSpec {
            name: "call_ext_last",
            arity: 3,
        },
        9 => OpcodeSpec {
            name: "bif0",
            arity: 2,
        },
        10 => OpcodeSpec {
            name: "bif1",
            arity: 4,
        },
        11 => OpcodeSpec {
            name: "bif2",
            arity: 5,
        },
        12 => OpcodeSpec {
            name: "allocate",
            arity: 2,
        },
        13 => OpcodeSpec {
            name: "allocate_heap",
            arity: 3,
        },
        14 => OpcodeSpec {
            name: "allocate_zero",
            arity: 2,
        },
        15 => OpcodeSpec {
            name: "allocate_heap_zero",
            arity: 3,
        },
        16 => OpcodeSpec {
            name: "test_heap",
            arity: 2,
        },
        17 => OpcodeSpec {
            name: "init",
            arity: 1,
        },
        18 => OpcodeSpec {
            name: "deallocate",
            arity: 1,
        },
        19 => OpcodeSpec {
            name: "return",
            arity: 0,
        },
        20 => OpcodeSpec {
            name: "send",
            arity: 0,
        },
        21 => OpcodeSpec {
            name: "remove_message",
            arity: 0,
        },
        22 => OpcodeSpec {
            name: "timeout",
            arity: 0,
        },
        23 => OpcodeSpec {
            name: "loop_rec",
            arity: 2,
        },
        24 => OpcodeSpec {
            name: "loop_rec_end",
            arity: 1,
        },
        25 => OpcodeSpec {
            name: "wait",
            arity: 1,
        },
        26 => OpcodeSpec {
            name: "wait_timeout",
            arity: 2,
        },
        27 => OpcodeSpec {
            name: "m_plus",
            arity: 4,
        },
        28 => OpcodeSpec {
            name: "m_minus",
            arity: 4,
        },
        29 => OpcodeSpec {
            name: "m_times",
            arity: 4,
        },
        30 => OpcodeSpec {
            name: "m_div",
            arity: 4,
        },
        31 => OpcodeSpec {
            name: "int_div",
            arity: 4,
        },
        32 => OpcodeSpec {
            name: "int_rem",
            arity: 4,
        },
        33 => OpcodeSpec {
            name: "int_band",
            arity: 4,
        },
        34 => OpcodeSpec {
            name: "int_bor",
            arity: 4,
        },
        35 => OpcodeSpec {
            name: "int_bxor",
            arity: 4,
        },
        36 => OpcodeSpec {
            name: "int_bsl",
            arity: 4,
        },
        37 => OpcodeSpec {
            name: "int_bsr",
            arity: 4,
        },
        38 => OpcodeSpec {
            name: "int_bnot",
            arity: 3,
        },
        39 => OpcodeSpec {
            name: "is_lt",
            arity: 3,
        },
        40 => OpcodeSpec {
            name: "is_ge",
            arity: 3,
        },
        41 => OpcodeSpec {
            name: "is_eq",
            arity: 3,
        },
        42 => OpcodeSpec {
            name: "is_ne",
            arity: 3,
        },
        43 => OpcodeSpec {
            name: "is_eq_exact",
            arity: 3,
        },
        44 => OpcodeSpec {
            name: "is_ne_exact",
            arity: 3,
        },
        45 => OpcodeSpec {
            name: "is_integer",
            arity: 2,
        },
        46 => OpcodeSpec {
            name: "is_float",
            arity: 2,
        },
        47 => OpcodeSpec {
            name: "is_number",
            arity: 2,
        },
        48 => OpcodeSpec {
            name: "is_atom",
            arity: 2,
        },
        49 => OpcodeSpec {
            name: "is_pid",
            arity: 2,
        },
        50 => OpcodeSpec {
            name: "is_reference",
            arity: 2,
        },
        51 => OpcodeSpec {
            name: "is_port",
            arity: 2,
        },
        52 => OpcodeSpec {
            name: "is_nil",
            arity: 2,
        },
        53 => OpcodeSpec {
            name: "is_binary",
            arity: 2,
        },
        54 => OpcodeSpec {
            name: "is_constant",
            arity: 2,
        },
        55 => OpcodeSpec {
            name: "is_list",
            arity: 2,
        },
        56 => OpcodeSpec {
            name: "is_nonempty_list",
            arity: 2,
        },
        57 => OpcodeSpec {
            name: "is_tuple",
            arity: 2,
        },
        58 => OpcodeSpec {
            name: "test_arity",
            arity: 3,
        },
        59 => OpcodeSpec {
            name: "select_val",
            arity: 3,
        },
        60 => OpcodeSpec {
            name: "select_tuple_arity",
            arity: 3,
        },
        61 => OpcodeSpec {
            name: "jump",
            arity: 1,
        },
        62 => OpcodeSpec {
            name: "catch",
            arity: 2,
        },
        63 => OpcodeSpec {
            name: "catch_end",
            arity: 1,
        },
        64 => OpcodeSpec {
            name: "move",
            arity: 2,
        },
        65 => OpcodeSpec {
            name: "get_list",
            arity: 3,
        },
        66 => OpcodeSpec {
            name: "get_tuple_element",
            arity: 3,
        },
        67 => OpcodeSpec {
            name: "set_tuple_element",
            arity: 3,
        },
        68 => OpcodeSpec {
            name: "put_string",
            arity: 3,
        },
        69 => OpcodeSpec {
            name: "put_list",
            arity: 3,
        },
        70 => OpcodeSpec {
            name: "put_tuple",
            arity: 2,
        },
        71 => OpcodeSpec {
            name: "put",
            arity: 1,
        },
        72 => OpcodeSpec {
            name: "badmatch",
            arity: 1,
        },
        73 => OpcodeSpec {
            name: "if_end",
            arity: 0,
        },
        74 => OpcodeSpec {
            name: "case_end",
            arity: 1,
        },
        75 => OpcodeSpec {
            name: "call_fun",
            arity: 1,
        },
        76 => OpcodeSpec {
            name: "make_fun",
            arity: 3,
        },
        77 => OpcodeSpec {
            name: "is_function",
            arity: 2,
        },
        78 => OpcodeSpec {
            name: "call_ext_only",
            arity: 2,
        },
        79 => OpcodeSpec {
            name: "bs_start_match",
            arity: 2,
        },
        80 => OpcodeSpec {
            name: "bs_get_integer",
            arity: 5,
        },
        81 => OpcodeSpec {
            name: "bs_get_float",
            arity: 5,
        },
        82 => OpcodeSpec {
            name: "bs_get_binary",
            arity: 5,
        },
        83 => OpcodeSpec {
            name: "bs_skip_bits",
            arity: 4,
        },
        84 => OpcodeSpec {
            name: "bs_test_tail",
            arity: 2,
        },
        85 => OpcodeSpec {
            name: "bs_save",
            arity: 1,
        },
        86 => OpcodeSpec {
            name: "bs_restore",
            arity: 1,
        },
        87 => OpcodeSpec {
            name: "bs_init",
            arity: 2,
        },
        88 => OpcodeSpec {
            name: "bs_final",
            arity: 2,
        },
        89 => OpcodeSpec {
            name: "bs_put_integer",
            arity: 5,
        },
        90 => OpcodeSpec {
            name: "bs_put_binary",
            arity: 5,
        },
        91 => OpcodeSpec {
            name: "bs_put_float",
            arity: 5,
        },
        92 => OpcodeSpec {
            name: "bs_put_string",
            arity: 2,
        },
        93 => OpcodeSpec {
            name: "bs_need_buf",
            arity: 1,
        },
        94 => OpcodeSpec {
            name: "fclearerror",
            arity: 0,
        },
        95 => OpcodeSpec {
            name: "fcheckerror",
            arity: 1,
        },
        96 => OpcodeSpec {
            name: "fmove",
            arity: 2,
        },
        97 => OpcodeSpec {
            name: "fconv",
            arity: 2,
        },
        98 => OpcodeSpec {
            name: "fadd",
            arity: 4,
        },
        99 => OpcodeSpec {
            name: "fsub",
            arity: 4,
        },
        100 => OpcodeSpec {
            name: "fmul",
            arity: 4,
        },
        101 => OpcodeSpec {
            name: "fdiv",
            arity: 4,
        },
        102 => OpcodeSpec {
            name: "fnegate",
            arity: 3,
        },
        103 => OpcodeSpec {
            name: "make_fun2",
            arity: 1,
        },
        104 => OpcodeSpec {
            name: "try",
            arity: 2,
        },
        105 => OpcodeSpec {
            name: "try_end",
            arity: 1,
        },
        106 => OpcodeSpec {
            name: "try_case",
            arity: 1,
        },
        107 => OpcodeSpec {
            name: "try_case_end",
            arity: 1,
        },
        108 => OpcodeSpec {
            name: "raise",
            arity: 2,
        },
        109 => OpcodeSpec {
            name: "bs_init2",
            arity: 6,
        },
        110 => OpcodeSpec {
            name: "bs_bits_to_bytes",
            arity: 3,
        },
        111 => OpcodeSpec {
            name: "bs_add",
            arity: 5,
        },
        112 => OpcodeSpec {
            name: "apply",
            arity: 1,
        },
        113 => OpcodeSpec {
            name: "apply_last",
            arity: 2,
        },
        114 => OpcodeSpec {
            name: "is_boolean",
            arity: 2,
        },
        115 => OpcodeSpec {
            name: "is_function2",
            arity: 3,
        },
        116 => OpcodeSpec {
            name: "bs_start_match2",
            arity: 5,
        },
        117 => OpcodeSpec {
            name: "bs_get_integer2",
            arity: 7,
        },
        118 => OpcodeSpec {
            name: "bs_get_float2",
            arity: 7,
        },
        119 => OpcodeSpec {
            name: "bs_get_binary2",
            arity: 7,
        },
        120 => OpcodeSpec {
            name: "bs_skip_bits2",
            arity: 5,
        },
        121 => OpcodeSpec {
            name: "bs_test_tail2",
            arity: 3,
        },
        122 => OpcodeSpec {
            name: "bs_save2",
            arity: 2,
        },
        123 => OpcodeSpec {
            name: "bs_restore2",
            arity: 2,
        },
        124 => OpcodeSpec {
            name: "gc_bif1",
            arity: 5,
        },
        125 => OpcodeSpec {
            name: "gc_bif2",
            arity: 6,
        },
        126 => OpcodeSpec {
            name: "bs_final2",
            arity: 2,
        },
        127 => OpcodeSpec {
            name: "bs_bits_to_bytes2",
            arity: 2,
        },
        128 => OpcodeSpec {
            name: "put_literal",
            arity: 2,
        },
        129 => OpcodeSpec {
            name: "is_bitstr",
            arity: 2,
        },
        130 => OpcodeSpec {
            name: "bs_context_to_binary",
            arity: 1,
        },
        131 => OpcodeSpec {
            name: "bs_test_unit",
            arity: 3,
        },
        132 => OpcodeSpec {
            name: "bs_match_string",
            arity: 4,
        },
        133 => OpcodeSpec {
            name: "bs_init_writable",
            arity: 0,
        },
        134 => OpcodeSpec {
            name: "bs_append",
            arity: 8,
        },
        135 => OpcodeSpec {
            name: "bs_private_append",
            arity: 6,
        },
        136 => OpcodeSpec {
            name: "trim",
            arity: 2,
        },
        137 => OpcodeSpec {
            name: "bs_init_bits",
            arity: 6,
        },
        138 => OpcodeSpec {
            name: "bs_get_utf8",
            arity: 5,
        },
        139 => OpcodeSpec {
            name: "bs_skip_utf8",
            arity: 4,
        },
        140 => OpcodeSpec {
            name: "bs_get_utf16",
            arity: 5,
        },
        141 => OpcodeSpec {
            name: "bs_skip_utf16",
            arity: 4,
        },
        142 => OpcodeSpec {
            name: "bs_get_utf32",
            arity: 5,
        },
        143 => OpcodeSpec {
            name: "bs_skip_utf32",
            arity: 4,
        },
        144 => OpcodeSpec {
            name: "bs_utf8_size",
            arity: 3,
        },
        145 => OpcodeSpec {
            name: "bs_put_utf8",
            arity: 3,
        },
        146 => OpcodeSpec {
            name: "bs_utf16_size",
            arity: 3,
        },
        147 => OpcodeSpec {
            name: "bs_put_utf16",
            arity: 3,
        },
        148 => OpcodeSpec {
            name: "bs_put_utf32",
            arity: 3,
        },
        149 => OpcodeSpec {
            name: "on_load",
            arity: 0,
        },
        150 => OpcodeSpec {
            name: "recv_mark",
            arity: 1,
        },
        151 => OpcodeSpec {
            name: "recv_set",
            arity: 1,
        },
        152 => OpcodeSpec {
            name: "gc_bif3",
            arity: 7,
        },
        153 => OpcodeSpec {
            name: "line",
            arity: 1,
        },
        154 => OpcodeSpec {
            name: "put_map_assoc",
            arity: 5,
        },
        155 => OpcodeSpec {
            name: "put_map_exact",
            arity: 5,
        },
        156 => OpcodeSpec {
            name: "is_map",
            arity: 2,
        },
        157 => OpcodeSpec {
            name: "has_map_fields",
            arity: 3,
        },
        158 => OpcodeSpec {
            name: "get_map_elements",
            arity: 3,
        },
        159 => OpcodeSpec {
            name: "is_tagged_tuple",
            arity: 4,
        },
        160 => OpcodeSpec {
            name: "build_stacktrace",
            arity: 0,
        },
        161 => OpcodeSpec {
            name: "raw_raise",
            arity: 0,
        },
        162 => OpcodeSpec {
            name: "get_hd",
            arity: 2,
        },
        163 => OpcodeSpec {
            name: "get_tl",
            arity: 2,
        },
        164 => OpcodeSpec {
            name: "put_tuple2",
            arity: 2,
        },
        165 => OpcodeSpec {
            name: "bs_get_tail",
            arity: 3,
        },
        166 => OpcodeSpec {
            name: "bs_start_match3",
            arity: 4,
        },
        167 => OpcodeSpec {
            name: "bs_get_position",
            arity: 3,
        },
        168 => OpcodeSpec {
            name: "bs_set_position",
            arity: 2,
        },
        169 => OpcodeSpec {
            name: "swap",
            arity: 2,
        },
        170 => OpcodeSpec {
            name: "bs_start_match4",
            arity: 4,
        },
        171 => OpcodeSpec {
            name: "make_fun3",
            arity: 3,
        },
        172 => OpcodeSpec {
            name: "init_yregs",
            arity: 1,
        },
        173 => OpcodeSpec {
            name: "recv_marker_bind",
            arity: 2,
        },
        174 => OpcodeSpec {
            name: "recv_marker_clear",
            arity: 1,
        },
        175 => OpcodeSpec {
            name: "recv_marker_reserve",
            arity: 1,
        },
        176 => OpcodeSpec {
            name: "recv_marker_use",
            arity: 1,
        },
        177 => OpcodeSpec {
            name: "bs_create_bin",
            arity: 6,
        },
        178 => OpcodeSpec {
            name: "call_fun2",
            arity: 3,
        },
        179 => OpcodeSpec {
            name: "nif_start",
            arity: 0,
        },
        180 => OpcodeSpec {
            name: "badrecord",
            arity: 1,
        },
        181 => OpcodeSpec {
            name: "update_record",
            arity: 5,
        },
        182 => OpcodeSpec {
            name: "bs_match",
            arity: 3,
        },
        183 => OpcodeSpec {
            name: "executable_line",
            arity: 2,
        },
        184 => OpcodeSpec {
            name: "debug_line",
            arity: 4,
        },
        185 => OpcodeSpec {
            name: "bif3",
            arity: 6,
        },
        186 => OpcodeSpec {
            name: "is_any_native_record",
            arity: 2,
        },
        187 => OpcodeSpec {
            name: "is_native_record",
            arity: 4,
        },
        188 => OpcodeSpec {
            name: "get_record_elements",
            arity: 3,
        },
        189 => OpcodeSpec {
            name: "put_record",
            arity: 6,
        },
        190 => OpcodeSpec {
            name: "is_record_accessible",
            arity: 3,
        },
        191 => OpcodeSpec {
            name: "get_record_field",
            arity: 5,
        },
        _ => return None,
    })
}
