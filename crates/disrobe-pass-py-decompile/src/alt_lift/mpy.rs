use std::collections::BTreeMap;

use disrobe_pass_py_disasm::alt_runtimes::micropython::{
    MpyArg, MpyBytecodeModule, MpyDecodedInsn, MpyFunction, MpyObject,
};
use disrobe_py_marshal::{CodeEra, CodeObject, Object};

use crate::error::{DecompileError, Result};

const OP_POP_TOP: u8 = 1;
const OP_ROT_TWO: u8 = 2;
const OP_ROT_THREE: u8 = 3;
const OP_DUP_TOP: u8 = 4;
const OP_DUP_TOP_TWO: u8 = 5;
const OP_NOP: u8 = 9;
const OP_UNARY_POSITIVE: u8 = 10;
const OP_UNARY_NEGATIVE: u8 = 11;
const OP_UNARY_NOT: u8 = 12;
const OP_UNARY_INVERT: u8 = 15;
const OP_BINARY_MATRIX_MULTIPLY: u8 = 16;
const OP_BINARY_POWER: u8 = 19;
const OP_BINARY_MULTIPLY: u8 = 20;
const OP_BINARY_MODULO: u8 = 22;
const OP_BINARY_ADD: u8 = 23;
const OP_BINARY_SUBTRACT: u8 = 24;
const OP_BINARY_SUBSCR: u8 = 25;
const OP_BINARY_FLOOR_DIVIDE: u8 = 26;
const OP_BINARY_TRUE_DIVIDE: u8 = 27;
const OP_INPLACE_FLOOR_DIVIDE: u8 = 28;
const OP_INPLACE_TRUE_DIVIDE: u8 = 29;
const OP_INPLACE_ADD: u8 = 55;
const OP_INPLACE_SUBTRACT: u8 = 56;
const OP_INPLACE_MULTIPLY: u8 = 57;
const OP_INPLACE_MODULO: u8 = 59;
const OP_STORE_SUBSCR: u8 = 60;
const OP_BINARY_LSHIFT: u8 = 62;
const OP_BINARY_RSHIFT: u8 = 63;
const OP_BINARY_AND: u8 = 64;
const OP_BINARY_XOR: u8 = 65;
const OP_BINARY_OR: u8 = 66;
const OP_INPLACE_POWER: u8 = 67;
const OP_GET_ITER: u8 = 68;
const OP_LOAD_BUILD_CLASS: u8 = 71;
const OP_YIELD_FROM: u8 = 72;
const OP_INPLACE_LSHIFT: u8 = 75;
const OP_INPLACE_RSHIFT: u8 = 76;
const OP_INPLACE_AND: u8 = 77;
const OP_INPLACE_XOR: u8 = 78;
const OP_INPLACE_OR: u8 = 79;
const OP_IMPORT_STAR: u8 = 84;
const OP_YIELD_VALUE: u8 = 86;
const OP_POP_BLOCK: u8 = 87;
const OP_POP_EXCEPT: u8 = 89;
const OP_RETURN_VALUE: u8 = 83;
const OP_STORE_NAME: u8 = 90;
const OP_DELETE_NAME: u8 = 91;
const OP_UNPACK_SEQUENCE: u8 = 92;
const OP_FOR_ITER: u8 = 93;
const OP_UNPACK_EX: u8 = 94;
const OP_STORE_ATTR: u8 = 95;
const OP_STORE_GLOBAL: u8 = 97;
const OP_DELETE_GLOBAL: u8 = 98;
const OP_LOAD_CONST: u8 = 100;
const OP_LOAD_NAME: u8 = 101;
const OP_BUILD_TUPLE: u8 = 102;
const OP_BUILD_LIST: u8 = 103;
const OP_BUILD_SET: u8 = 104;
const OP_BUILD_MAP: u8 = 105;
const OP_LOAD_ATTR: u8 = 106;
const OP_IMPORT_NAME: u8 = 108;
const OP_IMPORT_FROM: u8 = 109;
const OP_JUMP_FORWARD: u8 = 110;
const OP_JUMP_IF_FALSE_OR_POP: u8 = 111;
const OP_JUMP_IF_TRUE_OR_POP: u8 = 112;
const OP_JUMP_ABSOLUTE: u8 = 113;
const OP_POP_JUMP_IF_FALSE: u8 = 114;
const OP_POP_JUMP_IF_TRUE: u8 = 115;
const OP_LOAD_GLOBAL: u8 = 116;
const OP_SETUP_FINALLY: u8 = 122;
const OP_LOAD_FAST: u8 = 124;
const OP_STORE_FAST: u8 = 125;
const OP_DELETE_FAST: u8 = 126;
const OP_RAISE_VARARGS: u8 = 130;
const OP_CALL_FUNCTION: u8 = 131;
const OP_MAKE_FUNCTION: u8 = 132;
const OP_BUILD_SLICE: u8 = 133;
const OP_LOAD_DEREF: u8 = 136;
const OP_STORE_DEREF: u8 = 137;
const OP_DELETE_DEREF: u8 = 138;
const OP_CALL_FUNCTION_EX: u8 = 142;
const OP_SETUP_WITH: u8 = 143;
const OP_EXTENDED_ARG: u8 = 144;
const OP_LOAD_METHOD: u8 = 160;
const OP_CALL_METHOD: u8 = 161;

const CO_OPTIMIZED: i32 = 0x0001;
const CO_NEWLOCALS: i32 = 0x0002;
const CO_VARARGS: i32 = 0x0004;
const CO_VARKEYWORDS: i32 = 0x0008;
const CO_GENERATOR: i32 = 0x0020;

const MP_SCOPE_FLAG_VARARGS: u32 = 0x01;
const MP_SCOPE_FLAG_VARKEYWORDS: u32 = 0x02;
const MP_SCOPE_FLAG_GENERATOR: u32 = 0x10;

#[derive(Debug, Clone)]
enum Emitted {
    Plain { op: u8, arg: u32 },
    JumpAbs { op: u8, mp_target: usize },
    JumpRel { op: u8, mp_target: usize },
    Unsupported { mnemonic: String },
}

pub fn lift_module(module: &MpyBytecodeModule) -> Result<CodeObject> {
    lift_function(&module.function, module, true)
}

fn lift_function(
    func: &MpyFunction,
    module: &MpyBytecodeModule,
    is_module: bool,
) -> Result<CodeObject> {
    let mut consts: ConstPool = ConstPool::new();
    let mut names: NamePool = NamePool::new();
    let mut varnames: NamePool = NamePool::new();
    let mut derefs: NamePool = NamePool::new();

    seed_varnames(func, &mut varnames);

    let mut child_codes: Vec<CodeObject> = Vec::with_capacity(func.children.len());
    for child in &func.children {
        child_codes.push(lift_function(child, module, false)?);
    }

    let emitted: Vec<(usize, Emitted)> = lift_instructions(
        func,
        module,
        &child_codes,
        &mut consts,
        &mut names,
        &mut varnames,
        &mut derefs,
    )?;

    let (code_bytes, lnotab): (Vec<u8>, Vec<u8>) = assemble(&emitted)?;

    let flags: i32 = function_flags(func, is_module);
    let argcount: i32 = i32::try_from(func.n_pos_args).unwrap_or(0);
    let kwonly: i32 = i32::try_from(func.n_kwonly_args).unwrap_or(0);

    let mut code: CodeObject = CodeObject::new(CodeEra::Py38to310);
    code.argcount = argcount;
    code.kwonlyargcount = kwonly;
    code.nlocals = i32::try_from(varnames.entries.len()).unwrap_or(0);
    code.stacksize = i32::try_from(func.n_state).unwrap_or(0);
    code.flags = flags;
    code.code = code_bytes;
    code.consts = consts.into_objects();
    code.names = names.into_objects();
    code.varnames = varnames.into_objects();
    code.cellvars = Vec::new();
    code.freevars = derefs.into_objects();
    code.filename = Object::ShortAscii {
        value: "<mpy>".to_owned(),
        interned: false,
    };
    code.name = Object::ShortAscii {
        value: func.simple_name.clone(),
        interned: false,
    };
    code.qualname = Object::ShortAscii {
        value: func.simple_name.clone(),
        interned: false,
    };
    code.firstlineno = 1;
    code.lnotab = lnotab;
    Ok(code)
}

fn function_flags(func: &MpyFunction, is_module: bool) -> i32 {
    if is_module {
        return 0;
    }
    let mut flags: i32 = CO_OPTIMIZED | CO_NEWLOCALS;
    if func.scope_flags & MP_SCOPE_FLAG_VARARGS != 0 {
        flags |= CO_VARARGS;
    }
    if func.scope_flags & MP_SCOPE_FLAG_VARKEYWORDS != 0 {
        flags |= CO_VARKEYWORDS;
    }
    if func.scope_flags & MP_SCOPE_FLAG_GENERATOR != 0 {
        flags |= CO_GENERATOR;
    }
    flags
}

fn seed_varnames(func: &MpyFunction, varnames: &mut NamePool) {
    let total_args: u32 = func.n_pos_args + func.n_kwonly_args;
    for i in 0..total_args {
        let _: u32 = varnames.intern(&format!("arg{i}"));
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn lift_instructions(
    func: &MpyFunction,
    module: &MpyBytecodeModule,
    child_codes: &[CodeObject],
    consts: &mut ConstPool,
    names: &mut NamePool,
    varnames: &mut NamePool,
    derefs: &mut NamePool,
) -> Result<Vec<(usize, Emitted)>> {
    let instrs: &[MpyDecodedInsn] = &func.instructions;
    let mut out: Vec<(usize, Emitted)> = Vec::with_capacity(instrs.len());
    let mut i: usize = 0;
    while i < instrs.len() {
        if let Some(range_loop) = detect_range_loop(instrs, i) {
            let range_name: u32 = names.intern("range");
            let bound: &MpyDecodedInsn = &instrs[range_loop.bound_idx];
            let store_i: &MpyDecodedInsn = &instrs[range_loop.store_idx];
            let for_iter_mp: usize = instrs[range_loop.jump_idx].offset;
            let exit_mp: usize = range_loop.exit_mp;

            out.push((
                bound.offset,
                Emitted::Plain {
                    op: OP_LOAD_GLOBAL,
                    arg: range_name,
                },
            ));
            for e in lift_one(bound, module, child_codes, consts, names, varnames, derefs)? {
                out.push((bound.offset, e));
            }
            out.push((
                bound.offset,
                Emitted::Plain {
                    op: OP_CALL_FUNCTION,
                    arg: 1,
                },
            ));
            out.push((
                bound.offset,
                Emitted::Plain {
                    op: OP_GET_ITER,
                    arg: 0,
                },
            ));
            out.push((
                for_iter_mp,
                Emitted::JumpRel {
                    op: OP_FOR_ITER,
                    mp_target: exit_mp,
                },
            ));
            for e in lift_one(
                store_i,
                module,
                child_codes,
                consts,
                names,
                varnames,
                derefs,
            )? {
                out.push((store_i.offset, e));
            }
            let mut last_body_off: usize = store_i.offset;
            for body in &instrs[range_loop.body_start_idx..range_loop.body_end_idx] {
                last_body_off = body.offset;
                for e in lift_one(body, module, child_codes, consts, names, varnames, derefs)? {
                    out.push((body.offset, e));
                }
            }
            out.push((
                last_body_off,
                Emitted::JumpAbs {
                    op: OP_JUMP_ABSOLUTE,
                    mp_target: for_iter_mp,
                },
            ));
            i = range_loop.end_idx;
            continue;
        }
        let insn: &MpyDecodedInsn = &instrs[i];
        for e in lift_one(insn, module, child_codes, consts, names, varnames, derefs)? {
            out.push((insn.offset, e));
        }
        i += 1;
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy)]
struct RangeLoop {
    bound_idx: usize,
    jump_idx: usize,
    store_idx: usize,
    body_start_idx: usize,
    body_end_idx: usize,
    exit_mp: usize,
    end_idx: usize,
}

const MP_BINARY_OP_LESS: u8 = 0;
const MP_BINARY_OP_ADD: u8 = 14;

fn detect_range_loop(instrs: &[MpyDecodedInsn], at: usize) -> Option<RangeLoop> {
    if at == 0 {
        return None;
    }
    let bound_idx: usize = at - 1;
    if !is_simple_load(&instrs[bound_idx]) {
        return None;
    }
    if instrs[at].mnemonic != "LOAD_CONST_SMALL_INT" || small_int_value(&instrs[at].arg) != 0 {
        return None;
    }
    let jump_idx: usize = at + 1;
    let jump: &MpyDecodedInsn = instrs.get(jump_idx)?;
    if jump.mnemonic != "JUMP" {
        return None;
    }
    let cond_mp: usize = rel_target(&jump.arg)?;
    let cond_idx: usize = instrs
        .iter()
        .position(|x: &MpyDecodedInsn| x.offset == cond_mp)?;
    let body_start_off: usize = instrs.get(jump_idx + 1)?.offset;

    let dup_idx: usize = jump_idx + 1;
    if instrs.get(dup_idx)?.mnemonic != "DUP_TOP" {
        return None;
    }
    let store_idx: usize = dup_idx + 1;
    if instrs.get(store_idx)?.mnemonic != "STORE_FAST" {
        return None;
    }
    if cond_idx < 2 {
        return None;
    }
    let incr_a: &MpyDecodedInsn = instrs.get(cond_idx - 2)?;
    let incr_b: &MpyDecodedInsn = instrs.get(cond_idx - 1)?;
    if incr_a.mnemonic != "LOAD_CONST_SMALL_INT" || small_int_value(&incr_a.arg) != 1 {
        return None;
    }
    if incr_b.mnemonic != "BINARY_OP" || !matches!(incr_b.arg, MpyArg::BinaryOp(MP_BINARY_OP_ADD)) {
        return None;
    }
    if !matches_range_tail(instrs, cond_idx, body_start_off) {
        return None;
    }
    let exit_idx: usize = cond_idx + 6;
    let exit_mp: usize = instrs
        .get(exit_idx)
        .map_or(usize::MAX, |x: &MpyDecodedInsn| x.offset);
    Some(RangeLoop {
        bound_idx,
        jump_idx,
        store_idx,
        body_start_idx: store_idx + 1,
        body_end_idx: cond_idx - 2,
        exit_mp,
        end_idx: exit_idx,
    })
}

fn matches_range_tail(instrs: &[MpyDecodedInsn], cond_idx: usize, body_start_off: usize) -> bool {
    let expect: [(&str, Option<u8>); 6] = [
        ("DUP_TOP_TWO", None),
        ("ROT_TWO", None),
        ("BINARY_OP", Some(MP_BINARY_OP_LESS)),
        ("POP_JUMP_IF_TRUE", None),
        ("POP_TOP", None),
        ("POP_TOP", None),
    ];
    for (k, (name, op)) in expect.iter().enumerate() {
        let Some(insn): Option<&MpyDecodedInsn> = instrs.get(cond_idx + k) else {
            return false;
        };
        if insn.mnemonic != *name {
            return false;
        }
        if let Some(want) = op
            && !matches!(&insn.arg, MpyArg::BinaryOp(o) if o == want)
        {
            return false;
        }
        if *name == "POP_JUMP_IF_TRUE" && rel_target(&insn.arg) != Some(body_start_off) {
            return false;
        }
    }
    true
}

fn is_simple_load(insn: &MpyDecodedInsn) -> bool {
    matches!(
        insn.mnemonic.as_str(),
        "LOAD_FAST" | "LOAD_GLOBAL" | "LOAD_NAME" | "LOAD_CONST_SMALL_INT" | "LOAD_DEREF"
    )
}

const fn rel_target(arg: &MpyArg) -> Option<usize> {
    match arg {
        MpyArg::RelTarget { byte_offset } | MpyArg::UnwindTarget { byte_offset, .. } => {
            Some(*byte_offset)
        }
        _ => None,
    }
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::match_same_arms
)]
fn lift_one(
    insn: &MpyDecodedInsn,
    module: &MpyBytecodeModule,
    child_codes: &[CodeObject],
    consts: &mut ConstPool,
    names: &mut NamePool,
    varnames: &mut NamePool,
    derefs: &mut NamePool,
) -> Result<Vec<Emitted>> {
    let m: &str = insn.mnemonic.as_str();
    let plain = |op: u8, arg: u32| -> Vec<Emitted> { vec![Emitted::Plain { op, arg }] };
    let unsupported = || -> Vec<Emitted> {
        vec![Emitted::Unsupported {
            mnemonic: insn.mnemonic.clone(),
        }]
    };

    let result: Vec<Emitted> = match m {
        "LOAD_CONST_STRING" => {
            let value: Object = qstr_str_const(&insn.arg);
            plain(OP_LOAD_CONST, consts.intern(value))
        }
        "LOAD_CONST_SMALL_INT" => {
            let v: i64 = small_int_value(&insn.arg);
            plain(OP_LOAD_CONST, consts.intern(int_object(v)))
        }
        "LOAD_CONST_OBJ" => {
            let value: Object = object_const(&insn.arg, module);
            plain(OP_LOAD_CONST, consts.intern(value))
        }
        "LOAD_CONST_NONE" => plain(OP_LOAD_CONST, consts.intern(Object::None)),
        "LOAD_CONST_FALSE" => plain(OP_LOAD_CONST, consts.intern(Object::False)),
        "LOAD_CONST_TRUE" => plain(OP_LOAD_CONST, consts.intern(Object::True)),
        "LOAD_NULL" => plain(OP_LOAD_CONST, consts.intern(Object::None)),
        "LOAD_NAME" => plain(OP_LOAD_NAME, names.intern(&qstr_text(&insn.arg))),
        "LOAD_GLOBAL" => plain(OP_LOAD_GLOBAL, names.intern(&qstr_text(&insn.arg))),
        "LOAD_ATTR" => plain(OP_LOAD_ATTR, names.intern(&qstr_text(&insn.arg))),
        "LOAD_METHOD" => plain(OP_LOAD_METHOD, names.intern(&qstr_text(&insn.arg))),
        "LOAD_SUPER_METHOD" => plain(OP_LOAD_METHOD, names.intern(&qstr_text(&insn.arg))),
        "STORE_NAME" => plain(OP_STORE_NAME, names.intern(&qstr_text(&insn.arg))),
        "STORE_GLOBAL" => plain(OP_STORE_GLOBAL, names.intern(&qstr_text(&insn.arg))),
        "STORE_ATTR" => plain(OP_STORE_ATTR, names.intern(&qstr_text(&insn.arg))),
        "DELETE_NAME" => plain(OP_DELETE_NAME, names.intern(&qstr_text(&insn.arg))),
        "DELETE_GLOBAL" => plain(OP_DELETE_GLOBAL, names.intern(&qstr_text(&insn.arg))),
        "IMPORT_NAME" => plain(OP_IMPORT_NAME, names.intern(&qstr_text(&insn.arg))),
        "IMPORT_FROM" => plain(OP_IMPORT_FROM, names.intern(&qstr_text(&insn.arg))),
        "IMPORT_STAR" => plain(OP_IMPORT_STAR, 0),
        "LOAD_FAST" | "LOAD_FAST_N" => plain(OP_LOAD_FAST, fast_slot(&insn.arg, varnames)?),
        "STORE_FAST" | "STORE_FAST_N" => plain(OP_STORE_FAST, fast_slot(&insn.arg, varnames)?),
        "DELETE_FAST" => plain(OP_DELETE_FAST, fast_slot(&insn.arg, varnames)?),
        "LOAD_DEREF" => plain(OP_LOAD_DEREF, deref_slot(&insn.arg, derefs)?),
        "STORE_DEREF" => plain(OP_STORE_DEREF, deref_slot(&insn.arg, derefs)?),
        "DELETE_DEREF" => plain(OP_DELETE_DEREF, deref_slot(&insn.arg, derefs)?),
        "BUILD_TUPLE" => plain(OP_BUILD_TUPLE, uint_arg(&insn.arg)),
        "BUILD_LIST" => plain(OP_BUILD_LIST, uint_arg(&insn.arg)),
        "BUILD_MAP" => plain(OP_BUILD_MAP, uint_arg(&insn.arg)),
        "BUILD_SET" => plain(OP_BUILD_SET, uint_arg(&insn.arg)),
        "BUILD_SLICE" => plain(OP_BUILD_SLICE, uint_arg(&insn.arg)),
        "UNPACK_SEQUENCE" => plain(OP_UNPACK_SEQUENCE, uint_arg(&insn.arg)),
        "UNPACK_EX" => plain(OP_UNPACK_EX, uint_arg(&insn.arg)),
        "MAKE_FUNCTION" => make_function(&insn.arg, child_codes, consts, 0),
        "MAKE_FUNCTION_DEFARGS" => make_function(&insn.arg, child_codes, consts, 0x01),
        "MAKE_CLOSURE" => make_closure(&insn.arg, child_codes, consts, false),
        "MAKE_CLOSURE_DEFARGS" => make_closure(&insn.arg, child_codes, consts, true),
        "CALL_FUNCTION" => call_function(&insn.arg),
        "CALL_METHOD" => call_method(&insn.arg),
        "CALL_FUNCTION_VAR_KW" => plain(OP_CALL_FUNCTION_EX, 1),
        "CALL_METHOD_VAR_KW" => plain(OP_CALL_FUNCTION_EX, 1),
        "RETURN_VALUE" => plain(OP_RETURN_VALUE, 0),
        "POP_TOP" => plain(OP_POP_TOP, 0),
        "DUP_TOP" => plain(OP_DUP_TOP, 0),
        "DUP_TOP_TWO" => plain(OP_DUP_TOP_TWO, 0),
        "ROT_TWO" => plain(OP_ROT_TWO, 0),
        "ROT_THREE" => plain(OP_ROT_THREE, 0),
        "GET_ITER" | "GET_ITER_STACK" => plain(OP_GET_ITER, 0),
        "LOAD_BUILD_CLASS" => plain(OP_LOAD_BUILD_CLASS, 0),
        "LOAD_SUBSCR" => plain(OP_BINARY_SUBSCR, 0),
        "STORE_SUBSCR" => plain(OP_STORE_SUBSCR, 0),
        "STORE_COMP" => store_comp(&insn.arg),
        "YIELD_VALUE" => plain(OP_YIELD_VALUE, 0),
        "YIELD_FROM" => plain(OP_YIELD_FROM, 0),
        "RAISE_LAST" => plain(OP_RAISE_VARARGS, 0),
        "RAISE_OBJ" => plain(OP_RAISE_VARARGS, 1),
        "RAISE_FROM" => plain(OP_RAISE_VARARGS, 2),
        "UNARY_OP" => unary_op(&insn.arg, &unsupported),
        "BINARY_OP" => binary_op(&insn.arg, &unsupported),
        "JUMP" => jump_abs(OP_JUMP_ABSOLUTE, &insn.arg),
        "POP_JUMP_IF_TRUE" => jump_abs(OP_POP_JUMP_IF_TRUE, &insn.arg),
        "POP_JUMP_IF_FALSE" => jump_abs(OP_POP_JUMP_IF_FALSE, &insn.arg),
        "JUMP_IF_TRUE_OR_POP" => jump_abs(OP_JUMP_IF_TRUE_OR_POP, &insn.arg),
        "JUMP_IF_FALSE_OR_POP" => jump_abs(OP_JUMP_IF_FALSE_OR_POP, &insn.arg),
        "FOR_ITER" => jump_rel(OP_FOR_ITER, &insn.arg),
        "SETUP_WITH" => jump_rel(OP_SETUP_WITH, &insn.arg),
        "SETUP_EXCEPT" | "SETUP_FINALLY" => jump_rel(OP_SETUP_FINALLY, &insn.arg),
        "WITH_CLEANUP" => plain(OP_POP_BLOCK, 0),
        "END_FINALLY" => plain(OP_POP_EXCEPT, 0),
        "POP_EXCEPT_JUMP" => {
            let mut v: Vec<Emitted> = vec![Emitted::Plain {
                op: OP_POP_EXCEPT,
                arg: 0,
            }];
            v.extend(jump_rel(OP_JUMP_FORWARD, &insn.arg));
            v
        }
        "STORE_MAP" => plain(OP_NOP, 0),
        _ => unsupported(),
    };
    Ok(result)
}

fn jump_abs(op: u8, arg: &MpyArg) -> Vec<Emitted> {
    match arg {
        MpyArg::RelTarget { byte_offset } | MpyArg::UnwindTarget { byte_offset, .. } => {
            vec![Emitted::JumpAbs {
                op,
                mp_target: *byte_offset,
            }]
        }
        _ => vec![Emitted::Unsupported {
            mnemonic: "jump-without-target".to_owned(),
        }],
    }
}

fn jump_rel(op: u8, arg: &MpyArg) -> Vec<Emitted> {
    match arg {
        MpyArg::RelTarget { byte_offset } | MpyArg::UnwindTarget { byte_offset, .. } => {
            vec![Emitted::JumpRel {
                op,
                mp_target: *byte_offset,
            }]
        }
        _ => vec![Emitted::Unsupported {
            mnemonic: "jump-without-target".to_owned(),
        }],
    }
}

fn call_function(arg: &MpyArg) -> Vec<Emitted> {
    let packed: u32 = uint_arg(arg);
    let n_pos: u32 = packed & 0xFF;
    let n_kw: u32 = (packed >> 8) & 0xFF;
    if n_kw == 0 {
        vec![Emitted::Plain {
            op: OP_CALL_FUNCTION,
            arg: n_pos,
        }]
    } else {
        vec![Emitted::Plain {
            op: OP_CALL_FUNCTION,
            arg: n_pos + n_kw,
        }]
    }
}

fn call_method(arg: &MpyArg) -> Vec<Emitted> {
    let packed: u32 = uint_arg(arg);
    let n_pos: u32 = packed & 0xFF;
    let n_kw: u32 = (packed >> 8) & 0xFF;
    vec![Emitted::Plain {
        op: OP_CALL_METHOD,
        arg: n_pos + n_kw,
    }]
}

fn store_comp(arg: &MpyArg) -> Vec<Emitted> {
    let packed: u32 = uint_arg(arg);
    let kind: u32 = packed & 0x03;
    let op: u8 = match kind {
        0 => OP_INPLACE_ADD,
        _ => OP_NOP,
    };
    vec![Emitted::Plain { op, arg: 0 }]
}

fn make_function(
    arg: &MpyArg,
    child_codes: &[CodeObject],
    consts: &mut ConstPool,
    flag: u32,
) -> Vec<Emitted> {
    let idx: usize = match arg {
        MpyArg::Uint(v) => usize::try_from(*v).unwrap_or(usize::MAX),
        MpyArg::MakeClosure { table_index, .. } => {
            usize::try_from(*table_index).unwrap_or(usize::MAX)
        }
        _ => usize::MAX,
    };
    let Some(code): Option<&CodeObject> = child_codes.get(idx) else {
        return vec![Emitted::Unsupported {
            mnemonic: "make-function-bad-index".to_owned(),
        }];
    };
    let name: String = code_name(code);
    let code_const: u32 = consts.intern(Object::Code(Box::new(code.clone())));
    let name_const: u32 = consts.intern(short_ascii(&name));
    vec![
        Emitted::Plain {
            op: OP_LOAD_CONST,
            arg: code_const,
        },
        Emitted::Plain {
            op: OP_LOAD_CONST,
            arg: name_const,
        },
        Emitted::Plain {
            op: OP_MAKE_FUNCTION,
            arg: flag,
        },
    ]
}

fn make_closure(
    arg: &MpyArg,
    child_codes: &[CodeObject],
    consts: &mut ConstPool,
    defargs: bool,
) -> Vec<Emitted> {
    let (idx, n_closed): (usize, u8) = match arg {
        MpyArg::MakeClosure {
            table_index,
            n_closed,
        } => (
            usize::try_from(*table_index).unwrap_or(usize::MAX),
            *n_closed,
        ),
        MpyArg::Uint(v) => (usize::try_from(*v).unwrap_or(usize::MAX), 0),
        _ => (usize::MAX, 0),
    };
    let Some(code): Option<&CodeObject> = child_codes.get(idx) else {
        return vec![Emitted::Unsupported {
            mnemonic: "make-closure-bad-index".to_owned(),
        }];
    };
    let name: String = code_name(code);
    let flag: u32 = if defargs { 0x09 } else { 0x08 };
    let code_const: u32 = consts.intern(Object::Code(Box::new(code.clone())));
    let name_const: u32 = consts.intern(short_ascii(&name));
    vec![
        Emitted::Plain {
            op: OP_BUILD_TUPLE,
            arg: u32::from(n_closed),
        },
        Emitted::Plain {
            op: OP_LOAD_CONST,
            arg: code_const,
        },
        Emitted::Plain {
            op: OP_LOAD_CONST,
            arg: name_const,
        },
        Emitted::Plain {
            op: OP_MAKE_FUNCTION,
            arg: flag,
        },
    ]
}

fn unary_op(arg: &MpyArg, unsupported: &dyn Fn() -> Vec<Emitted>) -> Vec<Emitted> {
    let ord: u8 = match arg {
        MpyArg::UnaryOp(o) => *o,
        _ => return unsupported(),
    };
    let op: u8 = match ord {
        0 => OP_UNARY_POSITIVE,
        1 => OP_UNARY_NEGATIVE,
        2 => OP_UNARY_INVERT,
        3 => OP_UNARY_NOT,
        _ => return unsupported(),
    };
    vec![Emitted::Plain { op, arg: 0 }]
}

#[allow(clippy::match_same_arms)]
fn binary_op(arg: &MpyArg, unsupported: &dyn Fn() -> Vec<Emitted>) -> Vec<Emitted> {
    let ord: u8 = match arg {
        MpyArg::BinaryOp(o) => *o,
        _ => return unsupported(),
    };
    if let Some((op, cmp_arg)) = compare_op_for(ord) {
        return vec![Emitted::Plain { op, arg: cmp_arg }];
    }
    let op: u8 = match ord {
        9 => OP_INPLACE_OR,
        10 => OP_INPLACE_XOR,
        11 => OP_INPLACE_AND,
        12 => OP_INPLACE_LSHIFT,
        13 => OP_INPLACE_RSHIFT,
        14 => OP_INPLACE_ADD,
        15 => OP_INPLACE_SUBTRACT,
        16 => OP_INPLACE_MULTIPLY,
        17 => OP_BINARY_MATRIX_MULTIPLY,
        18 => OP_INPLACE_FLOOR_DIVIDE,
        19 => OP_INPLACE_TRUE_DIVIDE,
        20 => OP_INPLACE_MODULO,
        21 => OP_INPLACE_POWER,
        22 => OP_BINARY_OR,
        23 => OP_BINARY_XOR,
        24 => OP_BINARY_AND,
        25 => OP_BINARY_LSHIFT,
        26 => OP_BINARY_RSHIFT,
        27 => OP_BINARY_ADD,
        28 => OP_BINARY_SUBTRACT,
        29 => OP_BINARY_MULTIPLY,
        30 => OP_BINARY_MATRIX_MULTIPLY,
        31 => OP_BINARY_FLOOR_DIVIDE,
        32 => OP_BINARY_TRUE_DIVIDE,
        33 => OP_BINARY_MODULO,
        34 => OP_BINARY_POWER,
        _ => return unsupported(),
    };
    vec![Emitted::Plain { op, arg: 0 }]
}

const OP_COMPARE_OP: u8 = 107;
const OP_IS_OP: u8 = 117;
const OP_CONTAINS_OP: u8 = 118;
const OP_JUMP_IF_NOT_EXC_MATCH: u8 = 121;

fn compare_op_for(ord: u8) -> Option<(u8, u32)> {
    match ord {
        0 => Some((OP_COMPARE_OP, 0)),
        1 => Some((OP_COMPARE_OP, 4)),
        2 => Some((OP_COMPARE_OP, 2)),
        3 => Some((OP_COMPARE_OP, 1)),
        4 => Some((OP_COMPARE_OP, 5)),
        5 => Some((OP_COMPARE_OP, 3)),
        6 => Some((OP_CONTAINS_OP, 0)),
        7 => Some((OP_IS_OP, 0)),
        8 => Some((OP_JUMP_IF_NOT_EXC_MATCH, 0)),
        _ => None,
    }
}

fn assemble(emitted: &[(usize, Emitted)]) -> Result<(Vec<u8>, Vec<u8>)> {
    for (_, e) in emitted {
        if let Emitted::Unsupported { mnemonic } = e {
            return Err(DecompileError::UnsupportedRuntime {
                runtime: format!("micropython opcode not modeled: {mnemonic}"),
            });
        }
    }

    let mut lengths: Vec<u32> = emitted
        .iter()
        .map(|(_, e): &(usize, Emitted)| -> u32 { instr_byte_len(non_jump_arg(e)) })
        .collect();

    let mut resolved_args: Vec<u32> = vec![0u32; emitted.len()];
    for _ in 0..16 {
        let (byte_for_index, end_byte): (Vec<u32>, u32) = layout(&lengths);
        let mp_to_byte: BTreeMap<usize, u32> = build_mp_map(emitted, &byte_for_index);
        let resolve_target = |mp_target: usize| -> u32 {
            mp_to_byte
                .range(mp_target..)
                .next()
                .map_or(end_byte, |(_, b): (&usize, &u32)| *b)
        };
        let mut changed: bool = false;
        for (i, (_, e)) in emitted.iter().enumerate() {
            let here: u32 = byte_for_index[i];
            let next: u32 = here.saturating_add(lengths[i]);
            let arg: u32 = match e {
                Emitted::Plain { arg, .. } => *arg,
                Emitted::JumpAbs { mp_target, .. } => resolve_target(*mp_target) / 2,
                Emitted::JumpRel { mp_target, .. } => {
                    resolve_target(*mp_target).saturating_sub(next) / 2
                }
                Emitted::Unsupported { .. } => 0,
            };
            resolved_args[i] = arg;
            let needed: u32 = instr_byte_len(arg);
            if needed > lengths[i] {
                lengths[i] = needed;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    let mut code: Vec<u8> = Vec::with_capacity(emitted.len() * 2);
    for (i, (_, e)) in emitted.iter().enumerate() {
        let op: u8 = match e {
            Emitted::Plain { op, .. }
            | Emitted::JumpAbs { op, .. }
            | Emitted::JumpRel { op, .. } => *op,
            Emitted::Unsupported { .. } => OP_NOP,
        };
        emit_wordcode_padded(&mut code, op, resolved_args[i], lengths[i]);
    }
    let lnotab: Vec<u8> = single_line_lnotab(code.len());
    Ok((code, lnotab))
}

fn layout(lengths: &[u32]) -> (Vec<u32>, u32) {
    let mut byte_for_index: Vec<u32> = Vec::with_capacity(lengths.len());
    let mut cursor: u32 = 0;
    for &len in lengths {
        byte_for_index.push(cursor);
        cursor = cursor.saturating_add(len);
    }
    (byte_for_index, cursor)
}

fn build_mp_map(emitted: &[(usize, Emitted)], byte_for_index: &[u32]) -> BTreeMap<usize, u32> {
    let mut mp_to_byte: BTreeMap<usize, u32> = BTreeMap::new();
    for (i, (mp_off, _)) in emitted.iter().enumerate() {
        mp_to_byte.entry(*mp_off).or_insert(byte_for_index[i]);
    }
    mp_to_byte
}

const fn non_jump_arg(e: &Emitted) -> u32 {
    match e {
        Emitted::Plain { arg, .. } => *arg,
        Emitted::JumpAbs { .. } | Emitted::JumpRel { .. } | Emitted::Unsupported { .. } => 0,
    }
}

const fn instr_byte_len(arg: u32) -> u32 {
    if arg > 0x00FF_FFFF {
        8
    } else if arg > 0x0000_FFFF {
        6
    } else if arg > 0x0000_00FF {
        4
    } else {
        2
    }
}

fn emit_wordcode_padded(code: &mut Vec<u8>, op: u8, arg: u32, byte_len: u32) {
    let len: u32 = byte_len.max(instr_byte_len(arg));
    if len >= 8 {
        code.push(OP_EXTENDED_ARG);
        code.push(u8::try_from((arg >> 24) & 0xFF).unwrap_or(0));
    }
    if len >= 6 {
        code.push(OP_EXTENDED_ARG);
        code.push(u8::try_from((arg >> 16) & 0xFF).unwrap_or(0));
    }
    if len >= 4 {
        code.push(OP_EXTENDED_ARG);
        code.push(u8::try_from((arg >> 8) & 0xFF).unwrap_or(0));
    }
    code.push(op);
    code.push(u8::try_from(arg & 0xFF).unwrap_or(0));
}

fn single_line_lnotab(code_len: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut remaining: usize = code_len;
    while remaining > 0 {
        let chunk: u8 = u8::try_from(remaining.min(254)).unwrap_or(254);
        out.push(chunk);
        out.push(0);
        remaining -= usize::from(chunk);
    }
    out
}

fn code_name(code: &CodeObject) -> String {
    match &code.name {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => value.clone(),
        _ => "<anonymous>".to_owned(),
    }
}

fn qstr_text(arg: &MpyArg) -> String {
    match arg {
        MpyArg::Qstr { text, .. } => text.clone(),
        _ => "<qstr?>".to_owned(),
    }
}

fn qstr_str_const(arg: &MpyArg) -> Object {
    match arg {
        MpyArg::Qstr { text, .. } => short_ascii(text),
        _ => Object::None,
    }
}

fn small_int_value(arg: &MpyArg) -> i64 {
    match arg {
        MpyArg::SmallInt(v) => *v,
        MpyArg::Uint(v) => i64::try_from(*v).unwrap_or(0),
        _ => 0,
    }
}

fn uint_arg(arg: &MpyArg) -> u32 {
    match arg {
        MpyArg::Uint(v) => u32::try_from(*v).unwrap_or(u32::MAX),
        MpyArg::SmallInt(v) => u32::try_from(*v).unwrap_or(0),
        _ => 0,
    }
}

const MAX_SLOT_INDEX: u32 = 1 << 16;

fn fast_slot(arg: &MpyArg, varnames: &mut NamePool) -> Result<u32> {
    let idx: u32 = uint_arg(arg);
    if idx >= MAX_SLOT_INDEX {
        return Err(DecompileError::Emit {
            reason: format!(
                "LOAD/STORE_FAST slot index {idx} exceeds the {MAX_SLOT_INDEX} local-slot cap"
            ),
        });
    }
    while varnames.entries.len() <= idx as usize {
        let n: usize = varnames.entries.len();
        let _: u32 = varnames.intern(&format!("arg{n}"));
    }
    Ok(idx)
}

fn deref_slot(arg: &MpyArg, derefs: &mut NamePool) -> Result<u32> {
    let idx: u32 = uint_arg(arg);
    if idx >= MAX_SLOT_INDEX {
        return Err(DecompileError::Emit {
            reason: format!(
                "LOAD/STORE_DEREF cell index {idx} exceeds the {MAX_SLOT_INDEX} cell-slot cap"
            ),
        });
    }
    while derefs.entries.len() <= idx as usize {
        let n: usize = derefs.entries.len();
        let _: u32 = derefs.intern(&format!("cell{n}"));
    }
    Ok(idx)
}

fn object_const(arg: &MpyArg, module: &MpyBytecodeModule) -> Object {
    let idx: usize = match arg {
        MpyArg::Object { index } => usize::try_from(*index).unwrap_or(usize::MAX),
        _ => usize::MAX,
    };
    module
        .typed_objects
        .get(idx)
        .map_or(Object::None, mpy_object_to_marshal)
}

#[allow(clippy::match_same_arms)]
fn mpy_object_to_marshal(obj: &MpyObject) -> Object {
    match obj {
        MpyObject::None | MpyObject::FunTable => Object::None,
        MpyObject::False => Object::False,
        MpyObject::True => Object::True,
        MpyObject::Ellipsis => Object::Ellipsis,
        MpyObject::Str(s) => short_ascii(s),
        MpyObject::Bytes(b) => Object::Bytes(b.clone()),
        MpyObject::Int(s) => s
            .trim()
            .parse::<i64>()
            .map_or_else(|_| short_ascii(s), int_object),
        MpyObject::Float(s) => s
            .trim()
            .parse::<f64>()
            .map_or_else(|_| short_ascii(s), Object::Float),
        MpyObject::Complex(s) => short_ascii(s),
        MpyObject::Tuple(items) => Object::Tuple(items.iter().map(mpy_object_to_marshal).collect()),
    }
}

fn int_object(v: i64) -> Object {
    i32::try_from(v).map_or(Object::Int64(v), Object::Int)
}

fn short_ascii(s: &str) -> Object {
    Object::ShortAscii {
        value: s.to_owned(),
        interned: false,
    }
}

#[derive(Debug)]
struct ConstPool {
    entries: Vec<Object>,
}

impl ConstPool {
    const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    fn intern(&mut self, value: Object) -> u32 {
        if let Some(pos) = self.entries.iter().position(|e: &Object| *e == value) {
            return u32::try_from(pos).unwrap_or(0);
        }
        let idx: u32 = u32::try_from(self.entries.len()).unwrap_or(0);
        self.entries.push(value);
        idx
    }

    fn into_objects(self) -> Vec<Object> {
        self.entries
    }
}

#[derive(Debug)]
struct NamePool {
    entries: Vec<String>,
}

impl NamePool {
    const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    fn intern(&mut self, name: &str) -> u32 {
        if let Some(pos) = self.entries.iter().position(|e: &String| e == name) {
            return u32::try_from(pos).unwrap_or(0);
        }
        let idx: u32 = u32::try_from(self.entries.len()).unwrap_or(0);
        self.entries.push(name.to_owned());
        idx
    }

    fn into_objects(self) -> Vec<Object> {
        self.entries
            .into_iter()
            .map(|s: String| short_ascii(&s))
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn fast_slot_caps_index_and_does_not_balloon_the_pool() {
        let mut pool: NamePool = NamePool::new();
        let err: DecompileError =
            fast_slot(&MpyArg::Uint(u64::from(u32::MAX)), &mut pool).unwrap_err();
        assert!(
            matches!(err, DecompileError::Emit { .. }),
            "an out-of-range fast slot must be a bounded Emit error, got {err:?}"
        );
        assert!(
            pool.entries.len() < MAX_SLOT_INDEX as usize,
            "the rejected slot must not have grown the name pool: {}",
            pool.entries.len()
        );
    }

    #[test]
    fn fast_slot_at_cap_boundary_rejects() {
        let mut pool: NamePool = NamePool::new();
        assert!(fast_slot(&MpyArg::Uint(u64::from(MAX_SLOT_INDEX)), &mut pool).is_err());
        assert!(pool.entries.is_empty());
    }

    #[test]
    fn fast_slot_under_cap_interns_and_returns_index() {
        let mut pool: NamePool = NamePool::new();
        let idx: u32 = fast_slot(&MpyArg::Uint(3), &mut pool).unwrap();
        assert_eq!(idx, 3);
        assert_eq!(pool.entries.len(), 4);
    }

    #[test]
    fn deref_slot_caps_index() {
        let mut pool: NamePool = NamePool::new();
        let err: DecompileError =
            deref_slot(&MpyArg::Uint(u64::from(u32::MAX)), &mut pool).unwrap_err();
        assert!(matches!(err, DecompileError::Emit { .. }));
        assert!(pool.entries.len() < MAX_SLOT_INDEX as usize);
    }

    #[test]
    fn deref_slot_under_cap_interns() {
        let mut pool: NamePool = NamePool::new();
        let idx: u32 = deref_slot(&MpyArg::Uint(2), &mut pool).unwrap();
        assert_eq!(idx, 2);
        assert_eq!(pool.entries.len(), 3);
    }
}
