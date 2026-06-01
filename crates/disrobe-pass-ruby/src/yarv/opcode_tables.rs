//! Per-version YARV opcode tables for ruby 2.6 through 3.4.
//!
//! Ported clean-room from `insns.def` `DEFINE_INSN` line order (the opcode number IS the line
//! order) plus the operand-unification specializations (`*_WC_0/1`, `*_INT2FIX_*`) and `trace_*`
//! variants that `tool/ruby_vm` appends, with operand kinds from `tool/ruby_vm/models/typemap.rb`.
//! The 3.4 table is verified byte-for-byte against `RubyVM::INSTRUCTION_NAMES`; the data tables
//! are facts checked against the recovered instruction stream of the real corpus fixtures.

use serde::{Deserialize, Serialize};

/// IBF operand serialization kind, mirroring the `TS_*` enum used by `ibf_load_code` in
/// `compile.c`. Determines how each operand is consumed from the dumped bytecode stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TsKind {
    /// `TS_VALUE`: `small_value` object-table index, resolves to a literal.
    Value,
    /// `TS_ISEQ`: `small_value` iseq-table index (nested iseq).
    Iseq,
    /// `TS_OFFSET`: `small_value` branch target (relative label position in the dumped form).
    Offset,
    /// `TS_ID`: `small_value` object-table index of a Symbol, resolves to a method/name id.
    Id,
    /// `TS_CALLDATA`: consumes NOTHING from the stream (pre-allocated call-data slot).
    CallData,
    /// `TS_CALLINFO` (<= 2.6): `small_value` call-info reference.
    CallInfo,
    /// `TS_CALLCACHE` (<= 2.6): `small_value` call-cache reference.
    CallCache,
    /// `TS_CDHASH`: `small_value` object-table index of a case/when dispatch hash.
    CdHash,
    /// `TS_IC`: `small_value` object-table index (inline-constant-cache segment array).
    Ic,
    /// `TS_IVC`: `small_value` inline ivar-cache slot number.
    Ivc,
    /// `TS_ICVARC`: `small_value` inline cvar-cache slot number.
    Icvarc,
    /// `TS_ISE`: `small_value` inline storage-entry slot number.
    Ise,
    /// `TS_GENTRY` (<= 2.6): `small_value` global-entry reference.
    Gentry,
    /// `TS_NUM` / `TS_LINDEX`: `small_value` raw integer.
    Num,
    /// `TS_FUNCPTR`: `small_value` raw function pointer (unsupported in IBF upstream).
    FuncPtr,
    /// `TS_BUILTIN`: index `small_value`, then a length `small_value` and that many name bytes.
    Builtin,
    /// `TS_VARIABLE` (`...`): variable-length operand; not emitted by any dumped insn.
    Variable,
}

/// One YARV opcode: its mnemonic and the ordered operand kinds for the matching ruby version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct YarvOpcode {
    pub mnemonic: &'static str,
    pub operands: &'static [TsKind],
}

pub(crate) const V2_6: &[YarvOpcode] = &[
    YarvOpcode {
        mnemonic: "nop",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "getlocal",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setlocal",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getblockparam",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setblockparam",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getblockparamproxy",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getspecial",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setspecial",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getinstancevariable",
        operands: &[TsKind::Id, TsKind::Ic],
    },
    YarvOpcode {
        mnemonic: "setinstancevariable",
        operands: &[TsKind::Id, TsKind::Ic],
    },
    YarvOpcode {
        mnemonic: "getclassvariable",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "setclassvariable",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "getconstant",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "setconstant",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "getglobal",
        operands: &[TsKind::Gentry],
    },
    YarvOpcode {
        mnemonic: "setglobal",
        operands: &[TsKind::Gentry],
    },
    YarvOpcode {
        mnemonic: "putnil",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "putself",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "putobject",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "putspecialobject",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "putiseq",
        operands: &[TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "putstring",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "concatstrings",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "tostring",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "freezestring",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "toregexp",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "intern",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "newarray",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "duparray",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "duphash",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "expandarray",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "concatarray",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "splatarray",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "newhash",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "newrange",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "pop",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "dup",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "dupn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "swap",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "reverse",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "reput",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "topn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "adjuststack",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "defined",
        operands: &[TsKind::Num, TsKind::Value, TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "checkmatch",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "checkkeyword",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "checktype",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "defineclass",
        operands: &[TsKind::Id, TsKind::Iseq, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "send",
        operands: &[TsKind::CallInfo, TsKind::CallCache, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "opt_send_without_block",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "opt_str_freeze",
        operands: &[TsKind::Value, TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "opt_str_uminus",
        operands: &[TsKind::Value, TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "opt_newarray_max",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "opt_newarray_min",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "invokesuper",
        operands: &[TsKind::CallInfo, TsKind::CallCache, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "invokeblock",
        operands: &[TsKind::CallInfo],
    },
    YarvOpcode {
        mnemonic: "leave",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "throw",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "jump",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "branchif",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "branchunless",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "branchnil",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "opt_getinlinecache",
        operands: &[TsKind::Offset, TsKind::Ic],
    },
    YarvOpcode {
        mnemonic: "opt_setinlinecache",
        operands: &[TsKind::Ic],
    },
    YarvOpcode {
        mnemonic: "once",
        operands: &[TsKind::Iseq, TsKind::Ise],
    },
    YarvOpcode {
        mnemonic: "opt_case_dispatch",
        operands: &[TsKind::CdHash, TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "opt_plus",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "opt_minus",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "opt_mult",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "opt_div",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "opt_mod",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "opt_eq",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "opt_neq",
        operands: &[
            TsKind::CallInfo,
            TsKind::CallCache,
            TsKind::CallInfo,
            TsKind::CallCache,
        ],
    },
    YarvOpcode {
        mnemonic: "opt_lt",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "opt_le",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "opt_gt",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "opt_ge",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "opt_ltlt",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "opt_and",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "opt_or",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "opt_aref",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "opt_aset",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "opt_aset_with",
        operands: &[TsKind::Value, TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "opt_aref_with",
        operands: &[TsKind::Value, TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "opt_length",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "opt_size",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "opt_empty_p",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "opt_succ",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "opt_not",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "opt_regexpmatch1",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "opt_regexpmatch2",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "opt_call_c_function",
        operands: &[TsKind::FuncPtr],
    },
    YarvOpcode {
        mnemonic: "bitblt",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "answer",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "getlocal_WC_0",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getlocal_WC_1",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setlocal_WC_0",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setlocal_WC_1",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "putobject_INT2FIX_0_",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "putobject_INT2FIX_1_",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_nop",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_getlocal",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setlocal",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getblockparam",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setblockparam",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getblockparamproxy",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getspecial",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setspecial",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getinstancevariable",
        operands: &[TsKind::Id, TsKind::Ic],
    },
    YarvOpcode {
        mnemonic: "trace_setinstancevariable",
        operands: &[TsKind::Id, TsKind::Ic],
    },
    YarvOpcode {
        mnemonic: "trace_getclassvariable",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_setclassvariable",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_getconstant",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_setconstant",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_getglobal",
        operands: &[TsKind::Gentry],
    },
    YarvOpcode {
        mnemonic: "trace_setglobal",
        operands: &[TsKind::Gentry],
    },
    YarvOpcode {
        mnemonic: "trace_putnil",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_putself",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_putobject",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_putspecialobject",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_putiseq",
        operands: &[TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "trace_putstring",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_concatstrings",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_tostring",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_freezestring",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_toregexp",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_intern",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_newarray",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_duparray",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_duphash",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_expandarray",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_concatarray",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_splatarray",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_newhash",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_newrange",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_pop",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_dup",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_dupn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_swap",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_reverse",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_reput",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_topn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_adjuststack",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_defined",
        operands: &[TsKind::Num, TsKind::Value, TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_checkmatch",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_checkkeyword",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_checktype",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_defineclass",
        operands: &[TsKind::Id, TsKind::Iseq, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_send",
        operands: &[TsKind::CallInfo, TsKind::CallCache, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "trace_opt_send_without_block",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "trace_opt_str_freeze",
        operands: &[TsKind::Value, TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "trace_opt_str_uminus",
        operands: &[TsKind::Value, TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "trace_opt_newarray_max",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_opt_newarray_min",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_invokesuper",
        operands: &[TsKind::CallInfo, TsKind::CallCache, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "trace_invokeblock",
        operands: &[TsKind::CallInfo],
    },
    YarvOpcode {
        mnemonic: "trace_leave",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_throw",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_jump",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_branchif",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_branchunless",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_branchnil",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_opt_getinlinecache",
        operands: &[TsKind::Offset, TsKind::Ic],
    },
    YarvOpcode {
        mnemonic: "trace_opt_setinlinecache",
        operands: &[TsKind::Ic],
    },
    YarvOpcode {
        mnemonic: "trace_once",
        operands: &[TsKind::Iseq, TsKind::Ise],
    },
    YarvOpcode {
        mnemonic: "trace_opt_case_dispatch",
        operands: &[TsKind::CdHash, TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_opt_plus",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "trace_opt_minus",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "trace_opt_mult",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "trace_opt_div",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "trace_opt_mod",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "trace_opt_eq",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "trace_opt_neq",
        operands: &[
            TsKind::CallInfo,
            TsKind::CallCache,
            TsKind::CallInfo,
            TsKind::CallCache,
        ],
    },
    YarvOpcode {
        mnemonic: "trace_opt_lt",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "trace_opt_le",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "trace_opt_gt",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "trace_opt_ge",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "trace_opt_ltlt",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "trace_opt_and",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "trace_opt_or",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "trace_opt_aref",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "trace_opt_aset",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "trace_opt_aset_with",
        operands: &[TsKind::Value, TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "trace_opt_aref_with",
        operands: &[TsKind::Value, TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "trace_opt_length",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "trace_opt_size",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "trace_opt_empty_p",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "trace_opt_succ",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "trace_opt_not",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "trace_opt_regexpmatch1",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_opt_regexpmatch2",
        operands: &[TsKind::CallInfo, TsKind::CallCache],
    },
    YarvOpcode {
        mnemonic: "trace_opt_call_c_function",
        operands: &[TsKind::FuncPtr],
    },
    YarvOpcode {
        mnemonic: "trace_bitblt",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_answer",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_getlocal_WC_0",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getlocal_WC_1",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setlocal_WC_0",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setlocal_WC_1",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_putobject_INT2FIX_0_",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_putobject_INT2FIX_1_",
        operands: &[],
    },
];

pub(crate) const V2_7: &[YarvOpcode] = &[
    YarvOpcode {
        mnemonic: "nop",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "getlocal",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setlocal",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getblockparam",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setblockparam",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getblockparamproxy",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getspecial",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setspecial",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getinstancevariable",
        operands: &[TsKind::Id, TsKind::Ivc],
    },
    YarvOpcode {
        mnemonic: "setinstancevariable",
        operands: &[TsKind::Id, TsKind::Ivc],
    },
    YarvOpcode {
        mnemonic: "getclassvariable",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "setclassvariable",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "getconstant",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "setconstant",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "getglobal",
        operands: &[TsKind::Gentry],
    },
    YarvOpcode {
        mnemonic: "setglobal",
        operands: &[TsKind::Gentry],
    },
    YarvOpcode {
        mnemonic: "putnil",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "putself",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "putobject",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "putspecialobject",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "putstring",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "concatstrings",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "tostring",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "freezestring",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "toregexp",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "intern",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "newarray",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "newarraykwsplat",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "duparray",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "duphash",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "expandarray",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "concatarray",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "splatarray",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "newhash",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "newrange",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "pop",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "dup",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "dupn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "swap",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "reverse",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "topn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "adjuststack",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "defined",
        operands: &[TsKind::Num, TsKind::Value, TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "checkmatch",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "checkkeyword",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "checktype",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "defineclass",
        operands: &[TsKind::Id, TsKind::Iseq, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "definemethod",
        operands: &[TsKind::Id, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "definesmethod",
        operands: &[TsKind::Id, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "send",
        operands: &[TsKind::CallData, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "opt_send_without_block",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_str_freeze",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_nil_p",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_str_uminus",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_newarray_max",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "opt_newarray_min",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "invokesuper",
        operands: &[TsKind::CallData, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "invokeblock",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "leave",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "throw",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "jump",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "branchif",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "branchunless",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "branchnil",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "opt_getinlinecache",
        operands: &[TsKind::Offset, TsKind::Ic],
    },
    YarvOpcode {
        mnemonic: "opt_setinlinecache",
        operands: &[TsKind::Ic],
    },
    YarvOpcode {
        mnemonic: "once",
        operands: &[TsKind::Iseq, TsKind::Ise],
    },
    YarvOpcode {
        mnemonic: "opt_case_dispatch",
        operands: &[TsKind::CdHash, TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "opt_plus",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_minus",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_mult",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_div",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_mod",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_eq",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_neq",
        operands: &[TsKind::CallData, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_lt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_le",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_gt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_ge",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_ltlt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_and",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_or",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_aref",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_aset",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_aset_with",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_aref_with",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_length",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_size",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_empty_p",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_succ",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_not",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_regexpmatch2",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_call_c_function",
        operands: &[TsKind::FuncPtr],
    },
    YarvOpcode {
        mnemonic: "invokebuiltin",
        operands: &[TsKind::Builtin],
    },
    YarvOpcode {
        mnemonic: "opt_invokebuiltin_delegate",
        operands: &[TsKind::Builtin, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "opt_invokebuiltin_delegate_leave",
        operands: &[TsKind::Builtin, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getlocal_WC_0",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getlocal_WC_1",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setlocal_WC_0",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setlocal_WC_1",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "putobject_INT2FIX_0_",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "putobject_INT2FIX_1_",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_nop",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_getlocal",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setlocal",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getblockparam",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setblockparam",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getblockparamproxy",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getspecial",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setspecial",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getinstancevariable",
        operands: &[TsKind::Id, TsKind::Ivc],
    },
    YarvOpcode {
        mnemonic: "trace_setinstancevariable",
        operands: &[TsKind::Id, TsKind::Ivc],
    },
    YarvOpcode {
        mnemonic: "trace_getclassvariable",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_setclassvariable",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_getconstant",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_setconstant",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_getglobal",
        operands: &[TsKind::Gentry],
    },
    YarvOpcode {
        mnemonic: "trace_setglobal",
        operands: &[TsKind::Gentry],
    },
    YarvOpcode {
        mnemonic: "trace_putnil",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_putself",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_putobject",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_putspecialobject",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_putstring",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_concatstrings",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_tostring",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_freezestring",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_toregexp",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_intern",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_newarray",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_newarraykwsplat",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_duparray",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_duphash",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_expandarray",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_concatarray",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_splatarray",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_newhash",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_newrange",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_pop",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_dup",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_dupn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_swap",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_reverse",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_topn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_adjuststack",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_defined",
        operands: &[TsKind::Num, TsKind::Value, TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_checkmatch",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_checkkeyword",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_checktype",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_defineclass",
        operands: &[TsKind::Id, TsKind::Iseq, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_definemethod",
        operands: &[TsKind::Id, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "trace_definesmethod",
        operands: &[TsKind::Id, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "trace_send",
        operands: &[TsKind::CallData, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "trace_opt_send_without_block",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_str_freeze",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_nil_p",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_str_uminus",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_newarray_max",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_opt_newarray_min",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_invokesuper",
        operands: &[TsKind::CallData, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "trace_invokeblock",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_leave",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_throw",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_jump",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_branchif",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_branchunless",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_branchnil",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_opt_getinlinecache",
        operands: &[TsKind::Offset, TsKind::Ic],
    },
    YarvOpcode {
        mnemonic: "trace_opt_setinlinecache",
        operands: &[TsKind::Ic],
    },
    YarvOpcode {
        mnemonic: "trace_once",
        operands: &[TsKind::Iseq, TsKind::Ise],
    },
    YarvOpcode {
        mnemonic: "trace_opt_case_dispatch",
        operands: &[TsKind::CdHash, TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_opt_plus",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_minus",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_mult",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_div",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_mod",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_eq",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_neq",
        operands: &[TsKind::CallData, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_lt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_le",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_gt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_ge",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_ltlt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_and",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_or",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_aref",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_aset",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_aset_with",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_aref_with",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_length",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_size",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_empty_p",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_succ",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_not",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_regexpmatch2",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_call_c_function",
        operands: &[TsKind::FuncPtr],
    },
    YarvOpcode {
        mnemonic: "trace_invokebuiltin",
        operands: &[TsKind::Builtin],
    },
    YarvOpcode {
        mnemonic: "trace_opt_invokebuiltin_delegate",
        operands: &[TsKind::Builtin, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_opt_invokebuiltin_delegate_leave",
        operands: &[TsKind::Builtin, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getlocal_WC_0",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getlocal_WC_1",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setlocal_WC_0",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setlocal_WC_1",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_putobject_INT2FIX_0_",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_putobject_INT2FIX_1_",
        operands: &[],
    },
];

pub(crate) const V3_0: &[YarvOpcode] = &[
    YarvOpcode {
        mnemonic: "nop",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "getlocal",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setlocal",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getblockparam",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setblockparam",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getblockparamproxy",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getspecial",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setspecial",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getinstancevariable",
        operands: &[TsKind::Id, TsKind::Ivc],
    },
    YarvOpcode {
        mnemonic: "setinstancevariable",
        operands: &[TsKind::Id, TsKind::Ivc],
    },
    YarvOpcode {
        mnemonic: "getclassvariable",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "setclassvariable",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "getconstant",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "setconstant",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "getglobal",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "setglobal",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "putnil",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "putself",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "putobject",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "putspecialobject",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "putstring",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "concatstrings",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "tostring",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "toregexp",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "intern",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "newarray",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "newarraykwsplat",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "duparray",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "duphash",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "expandarray",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "concatarray",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "splatarray",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "newhash",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "newrange",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "pop",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "dup",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "dupn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "swap",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "reverse",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "topn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "adjuststack",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "defined",
        operands: &[TsKind::Num, TsKind::Value, TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "checkmatch",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "checkkeyword",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "checktype",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "defineclass",
        operands: &[TsKind::Id, TsKind::Iseq, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "definemethod",
        operands: &[TsKind::Id, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "definesmethod",
        operands: &[TsKind::Id, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "send",
        operands: &[TsKind::CallData, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "opt_send_without_block",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_str_freeze",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_nil_p",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_str_uminus",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_newarray_max",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "opt_newarray_min",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "invokesuper",
        operands: &[TsKind::CallData, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "invokeblock",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "leave",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "throw",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "jump",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "branchif",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "branchunless",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "branchnil",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "opt_getinlinecache",
        operands: &[TsKind::Offset, TsKind::Ic],
    },
    YarvOpcode {
        mnemonic: "opt_setinlinecache",
        operands: &[TsKind::Ic],
    },
    YarvOpcode {
        mnemonic: "once",
        operands: &[TsKind::Iseq, TsKind::Ise],
    },
    YarvOpcode {
        mnemonic: "opt_case_dispatch",
        operands: &[TsKind::CdHash, TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "opt_plus",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_minus",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_mult",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_div",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_mod",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_eq",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_neq",
        operands: &[TsKind::CallData, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_lt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_le",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_gt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_ge",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_ltlt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_and",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_or",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_aref",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_aset",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_aset_with",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_aref_with",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_length",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_size",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_empty_p",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_succ",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_not",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_regexpmatch2",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "invokebuiltin",
        operands: &[TsKind::Builtin],
    },
    YarvOpcode {
        mnemonic: "opt_invokebuiltin_delegate",
        operands: &[TsKind::Builtin, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "opt_invokebuiltin_delegate_leave",
        operands: &[TsKind::Builtin, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getlocal_WC_0",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getlocal_WC_1",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setlocal_WC_0",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setlocal_WC_1",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "putobject_INT2FIX_0_",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "putobject_INT2FIX_1_",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_nop",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_getlocal",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setlocal",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getblockparam",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setblockparam",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getblockparamproxy",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getspecial",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setspecial",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getinstancevariable",
        operands: &[TsKind::Id, TsKind::Ivc],
    },
    YarvOpcode {
        mnemonic: "trace_setinstancevariable",
        operands: &[TsKind::Id, TsKind::Ivc],
    },
    YarvOpcode {
        mnemonic: "trace_getclassvariable",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_setclassvariable",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_getconstant",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_setconstant",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_getglobal",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_setglobal",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_putnil",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_putself",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_putobject",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_putspecialobject",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_putstring",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_concatstrings",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_tostring",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_toregexp",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_intern",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_newarray",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_newarraykwsplat",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_duparray",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_duphash",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_expandarray",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_concatarray",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_splatarray",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_newhash",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_newrange",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_pop",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_dup",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_dupn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_swap",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_reverse",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_topn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_adjuststack",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_defined",
        operands: &[TsKind::Num, TsKind::Value, TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_checkmatch",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_checkkeyword",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_checktype",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_defineclass",
        operands: &[TsKind::Id, TsKind::Iseq, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_definemethod",
        operands: &[TsKind::Id, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "trace_definesmethod",
        operands: &[TsKind::Id, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "trace_send",
        operands: &[TsKind::CallData, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "trace_opt_send_without_block",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_str_freeze",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_nil_p",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_str_uminus",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_newarray_max",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_opt_newarray_min",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_invokesuper",
        operands: &[TsKind::CallData, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "trace_invokeblock",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_leave",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_throw",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_jump",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_branchif",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_branchunless",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_branchnil",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_opt_getinlinecache",
        operands: &[TsKind::Offset, TsKind::Ic],
    },
    YarvOpcode {
        mnemonic: "trace_opt_setinlinecache",
        operands: &[TsKind::Ic],
    },
    YarvOpcode {
        mnemonic: "trace_once",
        operands: &[TsKind::Iseq, TsKind::Ise],
    },
    YarvOpcode {
        mnemonic: "trace_opt_case_dispatch",
        operands: &[TsKind::CdHash, TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_opt_plus",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_minus",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_mult",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_div",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_mod",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_eq",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_neq",
        operands: &[TsKind::CallData, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_lt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_le",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_gt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_ge",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_ltlt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_and",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_or",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_aref",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_aset",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_aset_with",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_aref_with",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_length",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_size",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_empty_p",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_succ",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_not",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_regexpmatch2",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_invokebuiltin",
        operands: &[TsKind::Builtin],
    },
    YarvOpcode {
        mnemonic: "trace_opt_invokebuiltin_delegate",
        operands: &[TsKind::Builtin, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_opt_invokebuiltin_delegate_leave",
        operands: &[TsKind::Builtin, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getlocal_WC_0",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getlocal_WC_1",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setlocal_WC_0",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setlocal_WC_1",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_putobject_INT2FIX_0_",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_putobject_INT2FIX_1_",
        operands: &[],
    },
];

pub(crate) const V3_1: &[YarvOpcode] = &[
    YarvOpcode {
        mnemonic: "nop",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "getlocal",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setlocal",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getblockparam",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setblockparam",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getblockparamproxy",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getspecial",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setspecial",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getinstancevariable",
        operands: &[TsKind::Id, TsKind::Ivc],
    },
    YarvOpcode {
        mnemonic: "setinstancevariable",
        operands: &[TsKind::Id, TsKind::Ivc],
    },
    YarvOpcode {
        mnemonic: "getclassvariable",
        operands: &[TsKind::Id, TsKind::Ivc],
    },
    YarvOpcode {
        mnemonic: "setclassvariable",
        operands: &[TsKind::Id, TsKind::Ivc],
    },
    YarvOpcode {
        mnemonic: "getconstant",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "setconstant",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "getglobal",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "setglobal",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "putnil",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "putself",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "putobject",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "putspecialobject",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "putstring",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "concatstrings",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "anytostring",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "toregexp",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "intern",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "newarray",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "newarraykwsplat",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "duparray",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "duphash",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "expandarray",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "concatarray",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "splatarray",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "newhash",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "newrange",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "pop",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "dup",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "dupn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "swap",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "topn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "adjuststack",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "defined",
        operands: &[TsKind::Num, TsKind::Value, TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "checkmatch",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "checkkeyword",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "checktype",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "defineclass",
        operands: &[TsKind::Id, TsKind::Iseq, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "definemethod",
        operands: &[TsKind::Id, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "definesmethod",
        operands: &[TsKind::Id, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "send",
        operands: &[TsKind::CallData, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "opt_send_without_block",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "objtostring",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_str_freeze",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_nil_p",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_str_uminus",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_newarray_max",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "opt_newarray_min",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "invokesuper",
        operands: &[TsKind::CallData, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "invokeblock",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "leave",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "throw",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "jump",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "branchif",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "branchunless",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "branchnil",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "opt_getinlinecache",
        operands: &[TsKind::Offset, TsKind::Ic],
    },
    YarvOpcode {
        mnemonic: "opt_setinlinecache",
        operands: &[TsKind::Ic],
    },
    YarvOpcode {
        mnemonic: "once",
        operands: &[TsKind::Iseq, TsKind::Ise],
    },
    YarvOpcode {
        mnemonic: "opt_case_dispatch",
        operands: &[TsKind::CdHash, TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "opt_plus",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_minus",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_mult",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_div",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_mod",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_eq",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_neq",
        operands: &[TsKind::CallData, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_lt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_le",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_gt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_ge",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_ltlt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_and",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_or",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_aref",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_aset",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_aset_with",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_aref_with",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_length",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_size",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_empty_p",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_succ",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_not",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_regexpmatch2",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "invokebuiltin",
        operands: &[TsKind::Builtin],
    },
    YarvOpcode {
        mnemonic: "opt_invokebuiltin_delegate",
        operands: &[TsKind::Builtin, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "opt_invokebuiltin_delegate_leave",
        operands: &[TsKind::Builtin, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getlocal_WC_0",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getlocal_WC_1",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setlocal_WC_0",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setlocal_WC_1",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "putobject_INT2FIX_0_",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "putobject_INT2FIX_1_",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_nop",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_getlocal",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setlocal",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getblockparam",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setblockparam",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getblockparamproxy",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getspecial",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setspecial",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getinstancevariable",
        operands: &[TsKind::Id, TsKind::Ivc],
    },
    YarvOpcode {
        mnemonic: "trace_setinstancevariable",
        operands: &[TsKind::Id, TsKind::Ivc],
    },
    YarvOpcode {
        mnemonic: "trace_getclassvariable",
        operands: &[TsKind::Id, TsKind::Ivc],
    },
    YarvOpcode {
        mnemonic: "trace_setclassvariable",
        operands: &[TsKind::Id, TsKind::Ivc],
    },
    YarvOpcode {
        mnemonic: "trace_getconstant",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_setconstant",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_getglobal",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_setglobal",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_putnil",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_putself",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_putobject",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_putspecialobject",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_putstring",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_concatstrings",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_anytostring",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_toregexp",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_intern",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_newarray",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_newarraykwsplat",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_duparray",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_duphash",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_expandarray",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_concatarray",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_splatarray",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_newhash",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_newrange",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_pop",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_dup",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_dupn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_swap",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_topn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_adjuststack",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_defined",
        operands: &[TsKind::Num, TsKind::Value, TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_checkmatch",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_checkkeyword",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_checktype",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_defineclass",
        operands: &[TsKind::Id, TsKind::Iseq, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_definemethod",
        operands: &[TsKind::Id, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "trace_definesmethod",
        operands: &[TsKind::Id, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "trace_send",
        operands: &[TsKind::CallData, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "trace_opt_send_without_block",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_objtostring",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_str_freeze",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_nil_p",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_str_uminus",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_newarray_max",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_opt_newarray_min",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_invokesuper",
        operands: &[TsKind::CallData, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "trace_invokeblock",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_leave",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_throw",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_jump",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_branchif",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_branchunless",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_branchnil",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_opt_getinlinecache",
        operands: &[TsKind::Offset, TsKind::Ic],
    },
    YarvOpcode {
        mnemonic: "trace_opt_setinlinecache",
        operands: &[TsKind::Ic],
    },
    YarvOpcode {
        mnemonic: "trace_once",
        operands: &[TsKind::Iseq, TsKind::Ise],
    },
    YarvOpcode {
        mnemonic: "trace_opt_case_dispatch",
        operands: &[TsKind::CdHash, TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_opt_plus",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_minus",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_mult",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_div",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_mod",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_eq",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_neq",
        operands: &[TsKind::CallData, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_lt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_le",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_gt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_ge",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_ltlt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_and",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_or",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_aref",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_aset",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_aset_with",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_aref_with",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_length",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_size",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_empty_p",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_succ",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_not",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_regexpmatch2",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_invokebuiltin",
        operands: &[TsKind::Builtin],
    },
    YarvOpcode {
        mnemonic: "trace_opt_invokebuiltin_delegate",
        operands: &[TsKind::Builtin, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_opt_invokebuiltin_delegate_leave",
        operands: &[TsKind::Builtin, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getlocal_WC_0",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getlocal_WC_1",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setlocal_WC_0",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setlocal_WC_1",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_putobject_INT2FIX_0_",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_putobject_INT2FIX_1_",
        operands: &[],
    },
];

pub(crate) const V3_2: &[YarvOpcode] = &[
    YarvOpcode {
        mnemonic: "nop",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "getlocal",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setlocal",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getblockparam",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setblockparam",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getblockparamproxy",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getspecial",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setspecial",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getinstancevariable",
        operands: &[TsKind::Id, TsKind::Ivc],
    },
    YarvOpcode {
        mnemonic: "setinstancevariable",
        operands: &[TsKind::Id, TsKind::Ivc],
    },
    YarvOpcode {
        mnemonic: "getclassvariable",
        operands: &[TsKind::Id, TsKind::Icvarc],
    },
    YarvOpcode {
        mnemonic: "setclassvariable",
        operands: &[TsKind::Id, TsKind::Icvarc],
    },
    YarvOpcode {
        mnemonic: "opt_getconstant_path",
        operands: &[TsKind::Ic],
    },
    YarvOpcode {
        mnemonic: "getconstant",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "setconstant",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "getglobal",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "setglobal",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "putnil",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "putself",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "putobject",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "putspecialobject",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "putstring",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "concatstrings",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "anytostring",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "toregexp",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "intern",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "newarray",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "newarraykwsplat",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "duparray",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "duphash",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "expandarray",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "concatarray",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "splatarray",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "newhash",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "newrange",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "pop",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "dup",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "dupn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "swap",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "opt_reverse",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "topn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "adjuststack",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "defined",
        operands: &[TsKind::Num, TsKind::Value, TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "checkmatch",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "checkkeyword",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "checktype",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "defineclass",
        operands: &[TsKind::Id, TsKind::Iseq, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "definemethod",
        operands: &[TsKind::Id, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "definesmethod",
        operands: &[TsKind::Id, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "send",
        operands: &[TsKind::CallData, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "opt_send_without_block",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "objtostring",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_str_freeze",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_nil_p",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_str_uminus",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_newarray_max",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "opt_newarray_min",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "invokesuper",
        operands: &[TsKind::CallData, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "invokeblock",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "leave",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "throw",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "jump",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "branchif",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "branchunless",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "branchnil",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "once",
        operands: &[TsKind::Iseq, TsKind::Ise],
    },
    YarvOpcode {
        mnemonic: "opt_case_dispatch",
        operands: &[TsKind::CdHash, TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "opt_plus",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_minus",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_mult",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_div",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_mod",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_eq",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_neq",
        operands: &[TsKind::CallData, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_lt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_le",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_gt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_ge",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_ltlt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_and",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_or",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_aref",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_aset",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_aset_with",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_aref_with",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_length",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_size",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_empty_p",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_succ",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_not",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_regexpmatch2",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "invokebuiltin",
        operands: &[TsKind::Builtin],
    },
    YarvOpcode {
        mnemonic: "opt_invokebuiltin_delegate",
        operands: &[TsKind::Builtin, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "opt_invokebuiltin_delegate_leave",
        operands: &[TsKind::Builtin, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getlocal_WC_0",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getlocal_WC_1",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setlocal_WC_0",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setlocal_WC_1",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "putobject_INT2FIX_0_",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "putobject_INT2FIX_1_",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_nop",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_getlocal",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setlocal",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getblockparam",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setblockparam",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getblockparamproxy",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getspecial",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setspecial",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getinstancevariable",
        operands: &[TsKind::Id, TsKind::Ivc],
    },
    YarvOpcode {
        mnemonic: "trace_setinstancevariable",
        operands: &[TsKind::Id, TsKind::Ivc],
    },
    YarvOpcode {
        mnemonic: "trace_getclassvariable",
        operands: &[TsKind::Id, TsKind::Icvarc],
    },
    YarvOpcode {
        mnemonic: "trace_setclassvariable",
        operands: &[TsKind::Id, TsKind::Icvarc],
    },
    YarvOpcode {
        mnemonic: "trace_opt_getconstant_path",
        operands: &[TsKind::Ic],
    },
    YarvOpcode {
        mnemonic: "trace_getconstant",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_setconstant",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_getglobal",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_setglobal",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_putnil",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_putself",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_putobject",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_putspecialobject",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_putstring",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_concatstrings",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_anytostring",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_toregexp",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_intern",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_newarray",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_newarraykwsplat",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_duparray",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_duphash",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_expandarray",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_concatarray",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_splatarray",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_newhash",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_newrange",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_pop",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_dup",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_dupn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_swap",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_opt_reverse",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_topn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_adjuststack",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_defined",
        operands: &[TsKind::Num, TsKind::Value, TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_checkmatch",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_checkkeyword",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_checktype",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_defineclass",
        operands: &[TsKind::Id, TsKind::Iseq, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_definemethod",
        operands: &[TsKind::Id, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "trace_definesmethod",
        operands: &[TsKind::Id, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "trace_send",
        operands: &[TsKind::CallData, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "trace_opt_send_without_block",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_objtostring",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_str_freeze",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_nil_p",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_str_uminus",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_newarray_max",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_opt_newarray_min",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_invokesuper",
        operands: &[TsKind::CallData, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "trace_invokeblock",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_leave",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_throw",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_jump",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_branchif",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_branchunless",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_branchnil",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_once",
        operands: &[TsKind::Iseq, TsKind::Ise],
    },
    YarvOpcode {
        mnemonic: "trace_opt_case_dispatch",
        operands: &[TsKind::CdHash, TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_opt_plus",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_minus",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_mult",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_div",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_mod",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_eq",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_neq",
        operands: &[TsKind::CallData, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_lt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_le",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_gt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_ge",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_ltlt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_and",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_or",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_aref",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_aset",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_aset_with",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_aref_with",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_length",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_size",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_empty_p",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_succ",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_not",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_regexpmatch2",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_invokebuiltin",
        operands: &[TsKind::Builtin],
    },
    YarvOpcode {
        mnemonic: "trace_opt_invokebuiltin_delegate",
        operands: &[TsKind::Builtin, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_opt_invokebuiltin_delegate_leave",
        operands: &[TsKind::Builtin, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getlocal_WC_0",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getlocal_WC_1",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setlocal_WC_0",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setlocal_WC_1",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_putobject_INT2FIX_0_",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_putobject_INT2FIX_1_",
        operands: &[],
    },
];

pub(crate) const V3_3: &[YarvOpcode] = &[
    YarvOpcode {
        mnemonic: "nop",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "getlocal",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setlocal",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getblockparam",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setblockparam",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getblockparamproxy",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getspecial",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setspecial",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getinstancevariable",
        operands: &[TsKind::Id, TsKind::Ivc],
    },
    YarvOpcode {
        mnemonic: "setinstancevariable",
        operands: &[TsKind::Id, TsKind::Ivc],
    },
    YarvOpcode {
        mnemonic: "getclassvariable",
        operands: &[TsKind::Id, TsKind::Icvarc],
    },
    YarvOpcode {
        mnemonic: "setclassvariable",
        operands: &[TsKind::Id, TsKind::Icvarc],
    },
    YarvOpcode {
        mnemonic: "opt_getconstant_path",
        operands: &[TsKind::Ic],
    },
    YarvOpcode {
        mnemonic: "getconstant",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "setconstant",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "getglobal",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "setglobal",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "putnil",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "putself",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "putobject",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "putspecialobject",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "putstring",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "concatstrings",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "anytostring",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "toregexp",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "intern",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "newarray",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "newarraykwsplat",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "duparray",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "duphash",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "expandarray",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "concatarray",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "splatarray",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "splatkw",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "newhash",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "newrange",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "pop",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "dup",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "dupn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "swap",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "opt_reverse",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "topn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "adjuststack",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "defined",
        operands: &[TsKind::Num, TsKind::Value, TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "definedivar",
        operands: &[TsKind::Id, TsKind::Ivc, TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "checkmatch",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "checkkeyword",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "checktype",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "defineclass",
        operands: &[TsKind::Id, TsKind::Iseq, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "definemethod",
        operands: &[TsKind::Id, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "definesmethod",
        operands: &[TsKind::Id, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "send",
        operands: &[TsKind::CallData, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "opt_send_without_block",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "objtostring",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_str_freeze",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_nil_p",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_str_uminus",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_newarray_send",
        operands: &[TsKind::Num, TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "invokesuper",
        operands: &[TsKind::CallData, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "invokeblock",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "leave",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "throw",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "jump",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "branchif",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "branchunless",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "branchnil",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "once",
        operands: &[TsKind::Iseq, TsKind::Ise],
    },
    YarvOpcode {
        mnemonic: "opt_case_dispatch",
        operands: &[TsKind::CdHash, TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "opt_plus",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_minus",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_mult",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_div",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_mod",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_eq",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_neq",
        operands: &[TsKind::CallData, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_lt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_le",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_gt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_ge",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_ltlt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_and",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_or",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_aref",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_aset",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_aset_with",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_aref_with",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_length",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_size",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_empty_p",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_succ",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_not",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_regexpmatch2",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "invokebuiltin",
        operands: &[TsKind::Builtin],
    },
    YarvOpcode {
        mnemonic: "opt_invokebuiltin_delegate",
        operands: &[TsKind::Builtin, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "opt_invokebuiltin_delegate_leave",
        operands: &[TsKind::Builtin, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getlocal_WC_0",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getlocal_WC_1",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setlocal_WC_0",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setlocal_WC_1",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "putobject_INT2FIX_0_",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "putobject_INT2FIX_1_",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_nop",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_getlocal",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setlocal",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getblockparam",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setblockparam",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getblockparamproxy",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getspecial",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setspecial",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getinstancevariable",
        operands: &[TsKind::Id, TsKind::Ivc],
    },
    YarvOpcode {
        mnemonic: "trace_setinstancevariable",
        operands: &[TsKind::Id, TsKind::Ivc],
    },
    YarvOpcode {
        mnemonic: "trace_getclassvariable",
        operands: &[TsKind::Id, TsKind::Icvarc],
    },
    YarvOpcode {
        mnemonic: "trace_setclassvariable",
        operands: &[TsKind::Id, TsKind::Icvarc],
    },
    YarvOpcode {
        mnemonic: "trace_opt_getconstant_path",
        operands: &[TsKind::Ic],
    },
    YarvOpcode {
        mnemonic: "trace_getconstant",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_setconstant",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_getglobal",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_setglobal",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_putnil",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_putself",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_putobject",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_putspecialobject",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_putstring",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_concatstrings",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_anytostring",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_toregexp",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_intern",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_newarray",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_newarraykwsplat",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_duparray",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_duphash",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_expandarray",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_concatarray",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_splatarray",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_splatkw",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_newhash",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_newrange",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_pop",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_dup",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_dupn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_swap",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_opt_reverse",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_topn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_adjuststack",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_defined",
        operands: &[TsKind::Num, TsKind::Value, TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_definedivar",
        operands: &[TsKind::Id, TsKind::Ivc, TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_checkmatch",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_checkkeyword",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_checktype",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_defineclass",
        operands: &[TsKind::Id, TsKind::Iseq, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_definemethod",
        operands: &[TsKind::Id, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "trace_definesmethod",
        operands: &[TsKind::Id, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "trace_send",
        operands: &[TsKind::CallData, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "trace_opt_send_without_block",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_objtostring",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_str_freeze",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_nil_p",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_str_uminus",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_newarray_send",
        operands: &[TsKind::Num, TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_invokesuper",
        operands: &[TsKind::CallData, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "trace_invokeblock",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_leave",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_throw",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_jump",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_branchif",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_branchunless",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_branchnil",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_once",
        operands: &[TsKind::Iseq, TsKind::Ise],
    },
    YarvOpcode {
        mnemonic: "trace_opt_case_dispatch",
        operands: &[TsKind::CdHash, TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_opt_plus",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_minus",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_mult",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_div",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_mod",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_eq",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_neq",
        operands: &[TsKind::CallData, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_lt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_le",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_gt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_ge",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_ltlt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_and",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_or",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_aref",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_aset",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_aset_with",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_aref_with",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_length",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_size",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_empty_p",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_succ",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_not",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_regexpmatch2",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_invokebuiltin",
        operands: &[TsKind::Builtin],
    },
    YarvOpcode {
        mnemonic: "trace_opt_invokebuiltin_delegate",
        operands: &[TsKind::Builtin, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_opt_invokebuiltin_delegate_leave",
        operands: &[TsKind::Builtin, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getlocal_WC_0",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getlocal_WC_1",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setlocal_WC_0",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setlocal_WC_1",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_putobject_INT2FIX_0_",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_putobject_INT2FIX_1_",
        operands: &[],
    },
];

pub(crate) const V3_4: &[YarvOpcode] = &[
    YarvOpcode {
        mnemonic: "nop",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "getlocal",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setlocal",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getblockparam",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setblockparam",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getblockparamproxy",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getspecial",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setspecial",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getinstancevariable",
        operands: &[TsKind::Id, TsKind::Ivc],
    },
    YarvOpcode {
        mnemonic: "setinstancevariable",
        operands: &[TsKind::Id, TsKind::Ivc],
    },
    YarvOpcode {
        mnemonic: "getclassvariable",
        operands: &[TsKind::Id, TsKind::Icvarc],
    },
    YarvOpcode {
        mnemonic: "setclassvariable",
        operands: &[TsKind::Id, TsKind::Icvarc],
    },
    YarvOpcode {
        mnemonic: "opt_getconstant_path",
        operands: &[TsKind::Ic],
    },
    YarvOpcode {
        mnemonic: "getconstant",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "setconstant",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "getglobal",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "setglobal",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "putnil",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "putself",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "putobject",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "putspecialobject",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "putstring",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "putchilledstring",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "concatstrings",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "anytostring",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "toregexp",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "intern",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "newarray",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "pushtoarraykwsplat",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "duparray",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "duphash",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "expandarray",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "concatarray",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "concattoarray",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "pushtoarray",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "splatarray",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "splatkw",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "newhash",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "newrange",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "pop",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "dup",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "dupn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "swap",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "opt_reverse",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "topn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "adjuststack",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "defined",
        operands: &[TsKind::Num, TsKind::Value, TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "definedivar",
        operands: &[TsKind::Id, TsKind::Ivc, TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "checkmatch",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "checkkeyword",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "checktype",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "defineclass",
        operands: &[TsKind::Id, TsKind::Iseq, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "definemethod",
        operands: &[TsKind::Id, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "definesmethod",
        operands: &[TsKind::Id, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "send",
        operands: &[TsKind::CallData, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "sendforward",
        operands: &[TsKind::CallData, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "opt_send_without_block",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "objtostring",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_ary_freeze",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_hash_freeze",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_str_freeze",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_nil_p",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_str_uminus",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_duparray_send",
        operands: &[TsKind::Value, TsKind::Id, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "opt_newarray_send",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "invokesuper",
        operands: &[TsKind::CallData, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "invokesuperforward",
        operands: &[TsKind::CallData, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "invokeblock",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "leave",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "throw",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "jump",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "branchif",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "branchunless",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "branchnil",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "once",
        operands: &[TsKind::Iseq, TsKind::Ise],
    },
    YarvOpcode {
        mnemonic: "opt_case_dispatch",
        operands: &[TsKind::CdHash, TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "opt_plus",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_minus",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_mult",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_div",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_mod",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_eq",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_neq",
        operands: &[TsKind::CallData, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_lt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_le",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_gt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_ge",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_ltlt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_and",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_or",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_aref",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_aset",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_aset_with",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_aref_with",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_length",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_size",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_empty_p",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_succ",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_not",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "opt_regexpmatch2",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "invokebuiltin",
        operands: &[TsKind::Builtin],
    },
    YarvOpcode {
        mnemonic: "opt_invokebuiltin_delegate",
        operands: &[TsKind::Builtin, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "opt_invokebuiltin_delegate_leave",
        operands: &[TsKind::Builtin, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getlocal_WC_0",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "getlocal_WC_1",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setlocal_WC_0",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "setlocal_WC_1",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "putobject_INT2FIX_0_",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "putobject_INT2FIX_1_",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_nop",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_getlocal",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setlocal",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getblockparam",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setblockparam",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getblockparamproxy",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getspecial",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setspecial",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getinstancevariable",
        operands: &[TsKind::Id, TsKind::Ivc],
    },
    YarvOpcode {
        mnemonic: "trace_setinstancevariable",
        operands: &[TsKind::Id, TsKind::Ivc],
    },
    YarvOpcode {
        mnemonic: "trace_getclassvariable",
        operands: &[TsKind::Id, TsKind::Icvarc],
    },
    YarvOpcode {
        mnemonic: "trace_setclassvariable",
        operands: &[TsKind::Id, TsKind::Icvarc],
    },
    YarvOpcode {
        mnemonic: "trace_opt_getconstant_path",
        operands: &[TsKind::Ic],
    },
    YarvOpcode {
        mnemonic: "trace_getconstant",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_setconstant",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_getglobal",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_setglobal",
        operands: &[TsKind::Id],
    },
    YarvOpcode {
        mnemonic: "trace_putnil",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_putself",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_putobject",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_putspecialobject",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_putstring",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_putchilledstring",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_concatstrings",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_anytostring",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_toregexp",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_intern",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_newarray",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_pushtoarraykwsplat",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_duparray",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_duphash",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_expandarray",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_concatarray",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_concattoarray",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_pushtoarray",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_splatarray",
        operands: &[TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_splatkw",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_newhash",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_newrange",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_pop",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_dup",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_dupn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_swap",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_opt_reverse",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_topn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setn",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_adjuststack",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_defined",
        operands: &[TsKind::Num, TsKind::Value, TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_definedivar",
        operands: &[TsKind::Id, TsKind::Ivc, TsKind::Value],
    },
    YarvOpcode {
        mnemonic: "trace_checkmatch",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_checkkeyword",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_checktype",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_defineclass",
        operands: &[TsKind::Id, TsKind::Iseq, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_definemethod",
        operands: &[TsKind::Id, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "trace_definesmethod",
        operands: &[TsKind::Id, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "trace_send",
        operands: &[TsKind::CallData, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "trace_sendforward",
        operands: &[TsKind::CallData, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "trace_opt_send_without_block",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_objtostring",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_ary_freeze",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_hash_freeze",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_str_freeze",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_nil_p",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_str_uminus",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_duparray_send",
        operands: &[TsKind::Value, TsKind::Id, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_opt_newarray_send",
        operands: &[TsKind::Num, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_invokesuper",
        operands: &[TsKind::CallData, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "trace_invokesuperforward",
        operands: &[TsKind::CallData, TsKind::Iseq],
    },
    YarvOpcode {
        mnemonic: "trace_invokeblock",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_leave",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_throw",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_jump",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_branchif",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_branchunless",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_branchnil",
        operands: &[TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_once",
        operands: &[TsKind::Iseq, TsKind::Ise],
    },
    YarvOpcode {
        mnemonic: "trace_opt_case_dispatch",
        operands: &[TsKind::CdHash, TsKind::Offset],
    },
    YarvOpcode {
        mnemonic: "trace_opt_plus",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_minus",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_mult",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_div",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_mod",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_eq",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_neq",
        operands: &[TsKind::CallData, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_lt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_le",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_gt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_ge",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_ltlt",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_and",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_or",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_aref",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_aset",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_aset_with",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_aref_with",
        operands: &[TsKind::Value, TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_length",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_size",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_empty_p",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_succ",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_not",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_opt_regexpmatch2",
        operands: &[TsKind::CallData],
    },
    YarvOpcode {
        mnemonic: "trace_invokebuiltin",
        operands: &[TsKind::Builtin],
    },
    YarvOpcode {
        mnemonic: "trace_opt_invokebuiltin_delegate",
        operands: &[TsKind::Builtin, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_opt_invokebuiltin_delegate_leave",
        operands: &[TsKind::Builtin, TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getlocal_WC_0",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_getlocal_WC_1",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setlocal_WC_0",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_setlocal_WC_1",
        operands: &[TsKind::Num],
    },
    YarvOpcode {
        mnemonic: "trace_putobject_INT2FIX_0_",
        operands: &[],
    },
    YarvOpcode {
        mnemonic: "trace_putobject_INT2FIX_1_",
        operands: &[],
    },
];
