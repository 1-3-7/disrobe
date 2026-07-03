use crate::roundtrip::{ConstValue, NameValue, NormToken, NormalizedOp, NormalizedSequence};
use disrobe_pass_py_disasm::{Instruction, disassemble};
use disrobe_py_marshal::{CodeObject, Object, PyVersion};
use std::collections::BTreeMap;

const PADDING_NAMES: &[&str] = &[
    "NOP",
    "CACHE",
    "RESUME",
    "RESUME_QUICK",
    "RESUME_CHECK",
    "EXTENDED_ARG",
    "PRECALL",
    "MAKE_CELL",
    "COPY_FREE_VARS",
    "RETURN_GENERATOR",
    "INSTRUMENTED_RESUME",
];

const RETURN_VALUE_NAME: &str = "RETURN_VALUE";
const RETURN_CONST_NAME: &str = "RETURN_CONST";
const LOAD_CONST_NAME: &str = "LOAD_CONST";
const LOAD_SMALL_INT_NAME: &str = "LOAD_SMALL_INT";
const KW_NAMES_NAME: &str = "KW_NAMES";
const POP_TOP_NAME: &str = "POP_TOP";
const YIELD_VALUE_NAME: &str = "YIELD_VALUE";
const CLEANUP_THROW_NAME: &str = "CLEANUP_THROW";
const JUMP_BACKWARD_NO_INTERRUPT_NAME: &str = "JUMP_BACKWARD_NO_INTERRUPT";

const LOAD_FAST_LOAD_FAST_NAME: &str = "LOAD_FAST_LOAD_FAST";
const STORE_FAST_LOAD_FAST_NAME: &str = "STORE_FAST_LOAD_FAST";
const STORE_FAST_STORE_FAST_NAME: &str = "STORE_FAST_STORE_FAST";

const LOAD_FAST_NAME: &str = "LOAD_FAST";
const STORE_FAST_NAME: &str = "STORE_FAST";

const FIRSTLINENO_NAME: &str = "__firstlineno__";
const STORE_NAME_OP: &str = "STORE_NAME";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JumpDirection {
    Forward,
    Backward,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JumpCondition {
    Unconditional,
    OnTrue,
    OnFalse,
    OnNone,
    OnNotNone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct JumpProfile {
    direction: JumpDirection,
    condition: JumpCondition,
}

#[must_use]
fn classify_jump(name: &str) -> Option<JumpProfile> {
    let (direction, condition): (JumpDirection, JumpCondition) = match name {
        "JUMP_FORWARD" | "JUMP" | "JUMP_ABSOLUTE" => {
            (JumpDirection::Forward, JumpCondition::Unconditional)
        }
        "JUMP_BACKWARD" | "JUMP_BACKWARD_QUICK" => {
            (JumpDirection::Backward, JumpCondition::Unconditional)
        }
        "POP_JUMP_FORWARD_IF_TRUE" | "POP_JUMP_IF_TRUE" | "JUMP_IF_TRUE_OR_POP" => {
            (JumpDirection::Forward, JumpCondition::OnTrue)
        }
        "POP_JUMP_FORWARD_IF_FALSE" | "POP_JUMP_IF_FALSE" | "JUMP_IF_FALSE_OR_POP" => {
            (JumpDirection::Forward, JumpCondition::OnFalse)
        }
        "POP_JUMP_FORWARD_IF_NONE" | "POP_JUMP_IF_NONE" => {
            (JumpDirection::Forward, JumpCondition::OnNone)
        }
        "POP_JUMP_FORWARD_IF_NOT_NONE" | "POP_JUMP_IF_NOT_NONE" => {
            (JumpDirection::Forward, JumpCondition::OnNotNone)
        }
        "POP_JUMP_BACKWARD_IF_TRUE" => (JumpDirection::Backward, JumpCondition::OnTrue),
        "POP_JUMP_BACKWARD_IF_FALSE" => (JumpDirection::Backward, JumpCondition::OnFalse),
        _ => return None,
    };
    Some(JumpProfile {
        direction,
        condition,
    })
}

#[must_use]
fn classify_load_name(name: &str) -> Option<&'static str> {
    match name {
        "LOAD_NAME" => Some("LOAD_NAME"),
        "LOAD_GLOBAL" => Some("LOAD_GLOBAL"),
        "LOAD_ATTR" => Some("LOAD_ATTR"),
        "STORE_NAME" => Some("STORE_NAME"),
        "STORE_GLOBAL" => Some("STORE_GLOBAL"),
        "STORE_ATTR" => Some("STORE_ATTR"),
        "DELETE_NAME" => Some("DELETE_NAME"),
        "DELETE_GLOBAL" => Some("DELETE_GLOBAL"),
        "DELETE_ATTR" => Some("DELETE_ATTR"),
        "IMPORT_NAME" => Some("IMPORT_NAME"),
        "IMPORT_FROM" => Some("IMPORT_FROM"),
        _ => None,
    }
}

#[must_use]
fn classify_local_name(name: &str) -> Option<&'static str> {
    match name {
        "LOAD_FAST" | "LOAD_FAST_CHECK" | "LOAD_FAST_AND_CLEAR" | "LOAD_FAST_BORROW" => {
            Some(LOAD_FAST_NAME)
        }
        "STORE_FAST" => Some(STORE_FAST_NAME),
        "DELETE_FAST" => Some("DELETE_FAST"),
        _ => None,
    }
}

#[must_use]
fn object_to_const_value(obj: &Object) -> ConstValue {
    ConstValue::from(obj.clone())
}

#[must_use]
fn object_to_name_value(obj: &Object) -> Option<NameValue> {
    match obj {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => Some(NameValue(value.clone())),
        _ => None,
    }
}

#[must_use]
const fn unpack_super_pair(super_arg: u32) -> (u32, u32) {
    ((super_arg >> 4) & 0x0F, super_arg & 0x0F)
}

#[derive(Debug, Clone)]
struct StagedOp {
    source_offset: usize,
    kind: StagedKind,
}

#[derive(Debug, Clone)]
enum StagedKind {
    Raw { name: String, arg: Option<u32> },
    LoadConst(u32),
    LoadFast(u32),
    StoreFast(u32),
    ReturnValue,
}

#[must_use]
pub fn normalize_sequence(code: &CodeObject, version: PyVersion) -> NormalizedSequence {
    let instructions: Vec<Instruction> = disassemble(code, version);
    let stage1: Vec<StagedOp> = expand_primitives(&instructions);
    let stage2: Vec<StagedOp> = strip_async_cold_handler(stage1);
    let stage3: Vec<StagedOp> = strip_generator_entry_yield(stage2);
    let offset_to_index: BTreeMap<usize, usize> = build_offset_index(&stage3);
    let normalized: Vec<NormalizedOp> =
        lower_to_normalized(&stage3, code, version, &offset_to_index);
    let normalized: Vec<NormalizedOp> = canonicalize_cmp_branches(normalized);
    let normalized: Vec<NormalizedOp> = canonicalize_jretleaf(normalized);
    let normalized: Vec<NormalizedOp> = canonicalize_retblock(normalized);
    let normalized: Vec<NormalizedOp> = drop_firstlineno_assignment(normalized);
    NormalizedSequence { ops: normalized }
}

#[must_use]
fn expand_primitives(instructions: &[Instruction]) -> Vec<StagedOp> {
    let mut out: Vec<StagedOp> = Vec::with_capacity(instructions.len());
    for ins in instructions {
        let name: &str = ins.opname.as_str();
        if is_padding(name) {
            continue;
        }
        if name == RETURN_CONST_NAME {
            let arg: u32 = ins.arg.unwrap_or(0);
            out.push(StagedOp {
                source_offset: ins.offset,
                kind: StagedKind::LoadConst(arg),
            });
            out.push(StagedOp {
                source_offset: ins.offset,
                kind: StagedKind::ReturnValue,
            });
            continue;
        }
        if name == LOAD_FAST_LOAD_FAST_NAME {
            let arg: u32 = ins.arg.unwrap_or(0);
            let (a, b): (u32, u32) = unpack_super_pair(arg);
            out.push(StagedOp {
                source_offset: ins.offset,
                kind: StagedKind::LoadFast(a),
            });
            out.push(StagedOp {
                source_offset: ins.offset,
                kind: StagedKind::LoadFast(b),
            });
            continue;
        }
        if name == STORE_FAST_LOAD_FAST_NAME {
            let arg: u32 = ins.arg.unwrap_or(0);
            let (a, b): (u32, u32) = unpack_super_pair(arg);
            out.push(StagedOp {
                source_offset: ins.offset,
                kind: StagedKind::StoreFast(a),
            });
            out.push(StagedOp {
                source_offset: ins.offset,
                kind: StagedKind::LoadFast(b),
            });
            continue;
        }
        if name == STORE_FAST_STORE_FAST_NAME {
            let arg: u32 = ins.arg.unwrap_or(0);
            let (a, b): (u32, u32) = unpack_super_pair(arg);
            out.push(StagedOp {
                source_offset: ins.offset,
                kind: StagedKind::StoreFast(a),
            });
            out.push(StagedOp {
                source_offset: ins.offset,
                kind: StagedKind::StoreFast(b),
            });
            continue;
        }
        out.push(StagedOp {
            source_offset: ins.offset,
            kind: StagedKind::Raw {
                name: name.to_owned(),
                arg: ins.arg,
            },
        });
    }
    out
}

#[must_use]
fn build_offset_index(stage: &[StagedOp]) -> BTreeMap<usize, usize> {
    let mut map: BTreeMap<usize, usize> = BTreeMap::new();
    for (idx, op) in stage.iter().enumerate() {
        map.entry(op.source_offset).or_insert(idx);
    }
    map
}

#[must_use]
fn lower_to_normalized(
    stage: &[StagedOp],
    code: &CodeObject,
    version: PyVersion,
    offset_to_index: &BTreeMap<usize, usize>,
) -> Vec<NormalizedOp> {
    let mut out: Vec<NormalizedOp> = Vec::with_capacity(stage.len());
    for op in stage {
        match &op.kind {
            StagedKind::LoadConst(arg) => out.push(make_load_const_op(*arg, code)),
            StagedKind::LoadFast(arg) => out.push(make_local_op(LOAD_FAST_NAME, *arg, code)),
            StagedKind::StoreFast(arg) => out.push(make_local_op(STORE_FAST_NAME, *arg, code)),
            StagedKind::ReturnValue => out.push(NormalizedOp {
                token: NormToken::Op(RETURN_VALUE_NAME.into()),
                const_value: None,
                name_value: None,
                jump_target_index: None,
                operator_id: None,
                raw_arg: None,
            }),
            StagedKind::Raw { name, arg } => {
                lower_raw_op(
                    name.as_str(),
                    *arg,
                    op.source_offset,
                    code,
                    version,
                    offset_to_index,
                    &mut out,
                );
            }
        }
    }
    out
}

#[must_use]
fn make_load_const_op(arg: u32, code: &CodeObject) -> NormalizedOp {
    let value: ConstValue = code
        .consts
        .get(arg as usize)
        .map_or(ConstValue::Missing, object_to_const_value);
    NormalizedOp {
        token: NormToken::Op(LOAD_CONST_NAME.into()),
        const_value: Some(value),
        name_value: None,
        jump_target_index: None,
        operator_id: None,
        raw_arg: Some(arg),
    }
}

#[must_use]
fn make_local_op(canon: &'static str, arg: u32, code: &CodeObject) -> NormalizedOp {
    let value: Option<NameValue> = code
        .varnames
        .get(arg as usize)
        .or_else(|| code.localsplusnames.get(arg as usize))
        .and_then(object_to_name_value);
    NormalizedOp {
        token: NormToken::Op(canon.into()),
        const_value: None,
        name_value: value,
        jump_target_index: None,
        operator_id: None,
        raw_arg: Some(arg),
    }
}

fn lower_raw_op(
    name: &str,
    arg: Option<u32>,
    source_offset: usize,
    code: &CodeObject,
    version: PyVersion,
    offset_to_index: &BTreeMap<usize, usize>,
    out: &mut Vec<NormalizedOp>,
) {
    let arg_value: u32 = arg.unwrap_or(0);
    if let Some(op) = lower_const_family(name, arg_value, code) {
        out.push(op);
        return;
    }
    if let Some(op) = lower_name_family(name, arg_value, code) {
        out.push(op);
        return;
    }
    if let Some(op) = lower_deref_family(name, arg_value, code, version) {
        out.push(op);
        return;
    }
    if let Some(op) = lower_function_family(name, arg) {
        out.push(op);
        return;
    }
    if let Some(op) = lower_cmp_family(name, arg_value) {
        out.push(op);
        return;
    }
    if let Some(op) = lower_arity_family(name, arg) {
        out.push(op);
        return;
    }
    if let Some(op) = lower_jump_family(name, arg_value, source_offset, version, offset_to_index) {
        out.push(op);
        return;
    }
    if let Some(op) =
        lower_iter_jump_family(name, arg_value, source_offset, version, offset_to_index)
    {
        out.push(op);
        return;
    }
    out.push(NormalizedOp {
        token: NormToken::Op(name.to_owned()),
        const_value: None,
        name_value: None,
        jump_target_index: None,
        operator_id: None,
        raw_arg: arg.map(|_| arg_value),
    });
}

#[must_use]
fn lower_const_family(name: &str, arg_value: u32, code: &CodeObject) -> Option<NormalizedOp> {
    if name == LOAD_SMALL_INT_NAME {
        return Some(NormalizedOp {
            token: NormToken::Op(LOAD_CONST_NAME.into()),
            const_value: Some(ConstValue::SmallInt(i32::try_from(arg_value).unwrap_or(0))),
            name_value: None,
            jump_target_index: None,
            operator_id: None,
            raw_arg: Some(arg_value),
        });
    }
    if name == LOAD_CONST_NAME {
        return Some(make_load_const_op(arg_value, code));
    }
    if name == KW_NAMES_NAME {
        let value: ConstValue = code
            .consts
            .get(arg_value as usize)
            .map_or(ConstValue::Missing, object_to_const_value);
        return Some(NormalizedOp {
            token: NormToken::Op(KW_NAMES_NAME.into()),
            const_value: Some(value),
            name_value: None,
            jump_target_index: None,
            operator_id: None,
            raw_arg: Some(arg_value),
        });
    }
    None
}

#[must_use]
fn classify_deref_name(name: &str) -> Option<&'static str> {
    match name {
        "LOAD_DEREF" | "LOAD_CLASSDEREF" | "LOAD_FROM_DICT_OR_DEREF" => Some("LOAD_DEREF"),
        "STORE_DEREF" => Some("STORE_DEREF"),
        "DELETE_DEREF" => Some("DELETE_DEREF"),
        "LOAD_CLOSURE" => Some("LOAD_CLOSURE"),
        _ => None,
    }
}

#[must_use]
fn deref_uses_localsplus(version: PyVersion) -> bool {
    version.major > 3 || (version.major == 3 && version.minor >= 11)
}

#[must_use]
fn resolve_deref_name(arg_value: u32, code: &CodeObject, version: PyVersion) -> Option<NameValue> {
    let index: usize = arg_value as usize;
    if deref_uses_localsplus(version) {
        return code
            .localsplusnames
            .get(index)
            .and_then(object_to_name_value);
    }
    if let Some(obj) = code.cellvars.get(index) {
        return object_to_name_value(obj);
    }
    let free_index: usize = index.saturating_sub(code.cellvars.len());
    code.freevars.get(free_index).and_then(object_to_name_value)
}

#[must_use]
fn lower_deref_family(
    name: &str,
    arg_value: u32,
    code: &CodeObject,
    version: PyVersion,
) -> Option<NormalizedOp> {
    let canon: &'static str = classify_deref_name(name)?;
    let value: Option<NameValue> = resolve_deref_name(arg_value, code, version);
    Some(NormalizedOp {
        token: NormToken::Op(canon.into()),
        const_value: None,
        name_value: value,
        jump_target_index: None,
        operator_id: None,
        raw_arg: Some(arg_value),
    })
}

#[must_use]
fn lower_function_family(name: &str, arg: Option<u32>) -> Option<NormalizedOp> {
    if !matches!(
        name.as_bytes(),
        b"MAKE_FUNCTION" | b"MAKE_CLOSURE" | b"SET_FUNCTION_ATTRIBUTE" | b"FORMAT_VALUE"
    ) {
        return None;
    }
    Some(NormalizedOp {
        token: NormToken::Op(name.to_owned()),
        const_value: None,
        name_value: None,
        jump_target_index: None,
        operator_id: Some(arg.unwrap_or(0)),
        raw_arg: arg,
    })
}

#[must_use]
fn lower_name_family(name: &str, arg_value: u32, code: &CodeObject) -> Option<NormalizedOp> {
    if let Some(canon) = classify_load_name(name) {
        let value: Option<NameValue> = code
            .names
            .get(arg_value as usize)
            .and_then(object_to_name_value);
        return Some(NormalizedOp {
            token: NormToken::Op(canon.into()),
            const_value: None,
            name_value: value,
            jump_target_index: None,
            operator_id: None,
            raw_arg: Some(arg_value),
        });
    }
    if let Some(canon) = classify_local_name(name) {
        let value: Option<NameValue> = code
            .varnames
            .get(arg_value as usize)
            .or_else(|| code.localsplusnames.get(arg_value as usize))
            .and_then(object_to_name_value);
        return Some(NormalizedOp {
            token: NormToken::Op(canon.into()),
            const_value: None,
            name_value: value,
            jump_target_index: None,
            operator_id: None,
            raw_arg: Some(arg_value),
        });
    }
    None
}

#[must_use]
fn lower_cmp_family(name: &str, arg_value: u32) -> Option<NormalizedOp> {
    if name == "COMPARE_OP" {
        return Some(NormalizedOp {
            token: NormToken::Op("COMPARE_OP".into()),
            const_value: None,
            name_value: None,
            jump_target_index: None,
            operator_id: Some(arg_value >> 4),
            raw_arg: Some(arg_value),
        });
    }
    if name == "CONTAINS_OP" || name == "IS_OP" {
        return Some(NormalizedOp {
            token: NormToken::Op(name.to_owned()),
            const_value: None,
            name_value: None,
            jump_target_index: None,
            operator_id: Some(arg_value & 0x1),
            raw_arg: Some(arg_value),
        });
    }
    None
}

#[must_use]
const fn is_arity_significant_op(name: &str) -> bool {
    matches!(
        name.as_bytes(),
        b"BINARY_OP"
            | b"CALL"
            | b"CALL_KW"
            | b"CALL_METHOD"
            | b"CALL_FUNCTION"
            | b"CALL_FUNCTION_KW"
            | b"CALL_FUNCTION_EX"
            | b"CALL_FUNCTION_VAR"
            | b"CALL_FUNCTION_VAR_KW"
            | b"BUILD_TUPLE"
            | b"BUILD_LIST"
            | b"BUILD_SET"
            | b"BUILD_MAP"
            | b"BUILD_SLICE"
            | b"BUILD_STRING"
            | b"BUILD_CONST_KEY_MAP"
            | b"UNPACK_SEQUENCE"
            | b"UNPACK_EX"
    )
}

#[must_use]
fn lower_arity_family(name: &str, arg: Option<u32>) -> Option<NormalizedOp> {
    if !is_arity_significant_op(name) {
        return None;
    }
    let arg_value: u32 = arg.unwrap_or(0);
    Some(NormalizedOp {
        token: NormToken::Op(name.to_owned()),
        const_value: None,
        name_value: None,
        jump_target_index: None,
        operator_id: Some(arg_value),
        raw_arg: arg.map(|_| arg_value),
    })
}

#[must_use]
fn lower_jump_family(
    name: &str,
    arg_value: u32,
    source_offset: usize,
    version: PyVersion,
    offset_to_index: &BTreeMap<usize, usize>,
) -> Option<NormalizedOp> {
    let profile: JumpProfile = classify_jump(name)?;
    let target_offset: i64 =
        jump_target_offset(source_offset, arg_value, profile.direction, version);
    let target_index: Option<u32> = resolve_jump_target(target_offset, offset_to_index);
    Some(NormalizedOp {
        token: NormToken::Op(canonical_jump_name(profile)),
        const_value: None,
        name_value: None,
        jump_target_index: target_index,
        operator_id: None,
        raw_arg: None,
    })
}

#[must_use]
fn classify_iter_jump(name: &str) -> Option<&'static str> {
    match name {
        "FOR_ITER" => Some("FOR_ITER"),
        "SEND" => Some("SEND"),
        _ => None,
    }
}

#[must_use]
fn lower_iter_jump_family(
    name: &str,
    arg_value: u32,
    source_offset: usize,
    version: PyVersion,
    offset_to_index: &BTreeMap<usize, usize>,
) -> Option<NormalizedOp> {
    let canon: &'static str = classify_iter_jump(name)?;
    let target_offset: i64 =
        jump_target_offset(source_offset, arg_value, JumpDirection::Forward, version);
    let target_index: Option<u32> = resolve_jump_target(target_offset, offset_to_index);
    Some(NormalizedOp {
        token: NormToken::Op(canon.into()),
        const_value: None,
        name_value: None,
        jump_target_index: target_index,
        operator_id: None,
        raw_arg: None,
    })
}

#[must_use]
fn resolve_jump_target(
    target_offset: i64,
    offset_to_index: &BTreeMap<usize, usize>,
) -> Option<u32> {
    if target_offset < 0 {
        return None;
    }
    let unsigned: usize = usize::try_from(target_offset).ok()?;
    let direct: Option<usize> = offset_to_index.get(&unsigned).copied();
    let resolved: Option<usize> = direct.or_else(|| {
        offset_to_index
            .range(..=unsigned)
            .next_back()
            .map(|(_, v)| *v)
    });
    resolved.and_then(|v| u32::try_from(v).ok())
}

#[must_use]
const fn is_padding(name: &str) -> bool {
    let mut i: usize = 0;
    while i < PADDING_NAMES.len() {
        if str_eq(PADDING_NAMES[i], name) {
            return true;
        }
        i += 1;
    }
    false
}

#[must_use]
const fn str_eq(a: &str, b: &str) -> bool {
    let ab: &[u8] = a.as_bytes();
    let bb: &[u8] = b.as_bytes();
    if ab.len() != bb.len() {
        return false;
    }
    let mut i: usize = 0;
    while i < ab.len() {
        if ab[i] != bb[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[must_use]
fn jump_target_offset(
    source_offset: usize,
    arg: u32,
    direction: JumpDirection,
    version: PyVersion,
) -> i64 {
    let step: i64 = if version.is_wordcode() { 2 } else { 3 };
    let source_signed: i64 = i64::try_from(source_offset).unwrap_or(i64::MAX);
    let base: i64 = source_signed.saturating_add(step);
    let arg_in_bytes: i64 = if version.is_wordcode() {
        i64::from(arg).saturating_mul(2)
    } else {
        i64::from(arg)
    };
    match direction {
        JumpDirection::Forward => base.saturating_add(arg_in_bytes),
        JumpDirection::Backward => base.saturating_sub(arg_in_bytes),
    }
}

#[must_use]
fn canonical_jump_name(profile: JumpProfile) -> String {
    let condition: &str = match profile.condition {
        JumpCondition::Unconditional => "JUMP",
        JumpCondition::OnTrue => "JUMP_IF_TRUE",
        JumpCondition::OnFalse => "JUMP_IF_FALSE",
        JumpCondition::OnNone => "JUMP_IF_NONE",
        JumpCondition::OnNotNone => "JUMP_IF_NOT_NONE",
    };
    condition.to_owned()
}

#[must_use]
fn canonicalize_cmp_branches(seq: Vec<NormalizedOp>) -> Vec<NormalizedOp> {
    let mut out: Vec<NormalizedOp> = Vec::with_capacity(seq.len());
    let mut i: usize = 0;
    while i < seq.len() {
        let here: &NormalizedOp = &seq[i];
        let next: Option<&NormalizedOp> = seq.get(i + 1);
        let next2: Option<&NormalizedOp> = seq.get(i + 2);

        if try_collapse_neg_cmp(here, next, &mut out) {
            i += 2;
            continue;
        }
        if try_collapse_unary_not_branch(here, next, next2, &mut out) {
            i += 3;
            continue;
        }
        out.push(here.clone());
        i += 1;
    }
    out
}

#[must_use]
fn op_name_matches(op: &NormalizedOp, target: &str) -> bool {
    matches!(&op.token, NormToken::Op(n) if n.as_str() == target)
}

#[must_use]
fn flipped_branch_token(token: &NormToken) -> NormToken {
    match token {
        NormToken::Op(n) if n.as_str() == "JUMP_IF_TRUE" => NormToken::Op("JUMP_IF_FALSE".into()),
        NormToken::Op(n) if n.as_str() == "JUMP_IF_FALSE" => NormToken::Op("JUMP_IF_TRUE".into()),
        other => other.clone(),
    }
}

#[must_use]
fn is_neg_cmp(op: &NormalizedOp) -> bool {
    (op_name_matches(op, "CONTAINS_OP") || op_name_matches(op, "IS_OP"))
        && op.operator_id == Some(1)
}

fn try_collapse_neg_cmp(
    here: &NormalizedOp,
    next: Option<&NormalizedOp>,
    out: &mut Vec<NormalizedOp>,
) -> bool {
    let Some(branch) = next else { return false };
    if !(op_name_matches(branch, "JUMP_IF_TRUE") || op_name_matches(branch, "JUMP_IF_FALSE")) {
        return false;
    }
    if !is_neg_cmp(here) {
        return false;
    }
    let mut neutralized: NormalizedOp = here.clone();
    neutralized.operator_id = Some(0);
    out.push(neutralized);
    let mut flipped: NormalizedOp = branch.clone();
    flipped.token = flipped_branch_token(&flipped.token);
    out.push(flipped);
    true
}

fn try_collapse_unary_not_branch(
    here: &NormalizedOp,
    next: Option<&NormalizedOp>,
    next2: Option<&NormalizedOp>,
    out: &mut Vec<NormalizedOp>,
) -> bool {
    let (Some(unary_not), Some(branch)) = (next, next2) else {
        return false;
    };
    if !op_name_matches(unary_not, "UNARY_NOT") {
        return false;
    }
    if !(op_name_matches(branch, "JUMP_IF_TRUE") || op_name_matches(branch, "JUMP_IF_FALSE")) {
        return false;
    }
    out.push(here.clone());
    let mut flipped: NormalizedOp = branch.clone();
    flipped.token = flipped_branch_token(&flipped.token);
    out.push(flipped);
    true
}

#[must_use]
fn canonicalize_jretleaf(seq: Vec<NormalizedOp>) -> Vec<NormalizedOp> {
    let mut out: Vec<NormalizedOp> = Vec::with_capacity(seq.len());
    let mut i: usize = 0;
    while i < seq.len() {
        let here: &NormalizedOp = &seq[i];
        if let Some(next) = seq.get(i + 1) {
            let here_is_load_const: bool = op_name_matches(here, LOAD_CONST_NAME);
            let next_is_return: bool = op_name_matches(next, RETURN_VALUE_NAME);
            if here_is_load_const && next_is_return && here.const_value.is_some() {
                out.push(NormalizedOp {
                    token: NormToken::JRetLeaf,
                    const_value: here.const_value.clone(),
                    name_value: None,
                    jump_target_index: None,
                    operator_id: None,
                    raw_arg: None,
                });
                i += 2;
                continue;
            }
        }
        out.push(here.clone());
        i += 1;
    }
    collapse_consecutive_jretleaf(out)
}

#[must_use]
fn collapse_consecutive_jretleaf(seq: Vec<NormalizedOp>) -> Vec<NormalizedOp> {
    let mut out: Vec<NormalizedOp> = Vec::with_capacity(seq.len());
    for op in seq {
        if matches!(op.token, NormToken::JRetLeaf)
            && let Some(last) = out.last()
            && last.token == NormToken::JRetLeaf
            && last.const_value == op.const_value
        {
            continue;
        }
        out.push(op);
    }
    out
}

#[must_use]
fn canonicalize_retblock(seq: Vec<NormalizedOp>) -> Vec<NormalizedOp> {
    let mut out: Vec<NormalizedOp> = Vec::with_capacity(seq.len());
    let mut i: usize = 0;
    while i < seq.len() {
        let here: &NormalizedOp = &seq[i];
        let next: Option<&NormalizedOp> = seq.get(i + 1);
        let next2: Option<&NormalizedOp> = seq.get(i + 2);
        if op_name_matches(here, LOAD_CONST_NAME)
            && let Some(n1) = next
            && op_name_matches(n1, STORE_FAST_NAME)
            && let Some(n2) = next2
            && op_name_matches(n2, RETURN_VALUE_NAME)
        {
            out.push(NormalizedOp {
                token: NormToken::RetBlock,
                const_value: here.const_value.clone(),
                name_value: n1.name_value.clone(),
                jump_target_index: None,
                operator_id: None,
                raw_arg: None,
            });
            i += 3;
            continue;
        }
        out.push(here.clone());
        i += 1;
    }
    out
}

#[must_use]
fn is_firstlineno_store(op: &NormalizedOp) -> bool {
    op_name_matches(op, STORE_NAME_OP)
        && matches!(&op.name_value, Some(NameValue(n)) if n.as_str() == FIRSTLINENO_NAME)
}

#[must_use]
fn is_integral_const_load(op: &NormalizedOp) -> bool {
    op_name_matches(op, LOAD_CONST_NAME)
        && matches!(
            &op.const_value,
            Some(ConstValue::SmallInt(_) | ConstValue::BigInt(_))
        )
}

#[must_use]
fn drop_firstlineno_assignment(seq: Vec<NormalizedOp>) -> Vec<NormalizedOp> {
    let mut out: Vec<NormalizedOp> = Vec::with_capacity(seq.len());
    let mut i: usize = 0;
    while i < seq.len() {
        if i + 1 < seq.len() && is_integral_const_load(&seq[i]) && is_firstlineno_store(&seq[i + 1])
        {
            i += 2;
            continue;
        }
        out.push(seq[i].clone());
        i += 1;
    }
    out
}

#[must_use]
fn strip_async_cold_handler(seq: Vec<StagedOp>) -> Vec<StagedOp> {
    let mut out: Vec<StagedOp> = Vec::with_capacity(seq.len());
    let mut i: usize = 0;
    while i < seq.len() {
        if i + 1 < seq.len() {
            let a: &StagedKind = &seq[i].kind;
            let b: &StagedKind = &seq[i + 1].kind;
            let a_is_throw: bool =
                matches!(a, StagedKind::Raw { name, .. } if name.as_str() == CLEANUP_THROW_NAME);
            let b_is_jbni: bool = matches!(
                b,
                StagedKind::Raw { name, .. } if name.as_str() == JUMP_BACKWARD_NO_INTERRUPT_NAME
            );
            if a_is_throw && b_is_jbni {
                i += 2;
                continue;
            }
        }
        out.push(seq[i].clone());
        i += 1;
    }
    out
}

#[must_use]
fn strip_generator_entry_yield(seq: Vec<StagedOp>) -> Vec<StagedOp> {
    let mut out: Vec<StagedOp> = Vec::with_capacity(seq.len());
    let mut i: usize = 0;
    while i < seq.len() {
        if i + 1 < seq.len() && out.is_empty() {
            let a: &StagedKind = &seq[i].kind;
            let b: &StagedKind = &seq[i + 1].kind;
            let a_is_yield: bool =
                matches!(a, StagedKind::Raw { name, .. } if name.as_str() == YIELD_VALUE_NAME);
            let b_is_pop: bool =
                matches!(b, StagedKind::Raw { name, .. } if name.as_str() == POP_TOP_NAME);
            if a_is_yield && b_is_pop {
                i += 2;
                continue;
            }
        }
        out.push(seq[i].clone());
        i += 1;
    }
    out
}
