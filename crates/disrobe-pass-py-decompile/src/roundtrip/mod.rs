pub mod normalize;

use disrobe_py_marshal::{CodeObject, Object, PyVersion};
use std::fmt::Write as _;

pub use normalize::normalize_sequence;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Perfect,
    Semantic,
    CodeDiff(DiffDetail),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffDetail {
    pub qualname: String,
    pub first_diff_offset: u32,
    pub original_op: String,
    pub recompiled_op: String,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NormToken {
    Op(String),
    JRetLeaf,
    RetBlock,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConstValue {
    None,
    Bool(bool),
    SmallInt(i32),
    BigInt(i64),
    Float(u64),
    Bytes(Vec<u8>),
    Str(String),
    Tuple(Vec<ConstValue>),
    FrozenSet(Vec<ConstValue>),
    Code(String),
    Missing,
    Other(String),
}

impl From<Object> for ConstValue {
    fn from(obj: Object) -> Self {
        match obj {
            Object::None => Self::None,
            Object::True => Self::Bool(true),
            Object::False => Self::Bool(false),
            Object::Int(i) => Self::SmallInt(i),
            Object::Int64(i) => Self::BigInt(i),
            Object::Float(f) => Self::Float(f.to_bits()),
            Object::Bytes(b) => Self::Bytes(b),
            Object::String { value, .. } | Object::ShortAscii { value, .. } => Self::Str(value),
            Object::Tuple(items) => Self::Tuple(items.into_iter().map(Self::from).collect()),
            Object::FrozenSet(items) => {
                Self::FrozenSet(items.into_iter().map(Self::from).collect())
            }
            Object::Code(boxed) => Self::Code(qualname_of(boxed.as_ref())),
            other => Self::Other(format!("{other:?}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NameValue(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NormalizedOp {
    pub token: NormToken,
    pub const_value: Option<ConstValue>,
    pub name_value: Option<NameValue>,
    pub jump_target_index: Option<u32>,
    pub operator_id: Option<u32>,
    pub raw_arg: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedSequence {
    pub ops: Vec<NormalizedOp>,
}

#[must_use]
pub fn semantic_equiv(a: &CodeObject, b: &CodeObject, version: PyVersion) -> Verdict {
    let byte_identical: bool =
        a.code == b.code && a.consts == b.consts && a.names == b.names && a.varnames == b.varnames;
    if byte_identical {
        return match compare_nested(a, b, version) {
            Verdict::CodeDiff(d) => Verdict::CodeDiff(d),
            _ => Verdict::Perfect,
        };
    }
    let norm_a: NormalizedSequence = normalize_sequence(a, version);
    let norm_b: NormalizedSequence = normalize_sequence(b, version);
    if let Some(detail) = compare_normalized(&norm_a, &norm_b, qualname_of(a)) {
        return Verdict::CodeDiff(detail);
    }
    if let Verdict::CodeDiff(d) = compare_nested(a, b, version) {
        return Verdict::CodeDiff(d);
    }
    Verdict::Semantic
}

#[must_use]
pub fn compare_normalized(
    a: &NormalizedSequence,
    b: &NormalizedSequence,
    qualname: String,
) -> Option<DiffDetail> {
    if a.ops.len() != b.ops.len() {
        let original_op: String = sequence_label(a);
        let recompiled_op: String = sequence_label(b);
        let first_diff_offset: u32 =
            u32::try_from(a.ops.len().min(b.ops.len())).unwrap_or(u32::MAX);
        return Some(DiffDetail {
            qualname,
            first_diff_offset,
            original_op,
            recompiled_op,
            note: format!(
                "normalized sequence length differs: {} vs {}",
                a.ops.len(),
                b.ops.len()
            ),
        });
    }
    for (idx, (oa, ob)) in a.ops.iter().zip(b.ops.iter()).enumerate() {
        if !ops_semantically_equal(oa, ob) {
            let first_diff_offset: u32 = u32::try_from(idx).unwrap_or(u32::MAX);
            return Some(DiffDetail {
                qualname,
                first_diff_offset,
                original_op: format_op(oa),
                recompiled_op: format_op(ob),
                note: diff_note(oa, ob),
            });
        }
    }
    None
}

#[must_use]
fn ops_semantically_equal(a: &NormalizedOp, b: &NormalizedOp) -> bool {
    a.token == b.token
        && a.const_value == b.const_value
        && a.name_value == b.name_value
        && a.jump_target_index == b.jump_target_index
        && a.operator_id == b.operator_id
}

#[must_use]
fn sequence_label(seq: &NormalizedSequence) -> String {
    seq.ops
        .iter()
        .map(|op| token_label(&op.token))
        .collect::<Vec<String>>()
        .join("/")
}

#[must_use]
fn token_label(t: &NormToken) -> String {
    match t {
        NormToken::Op(s) => s.clone(),
        NormToken::JRetLeaf => "JRET".to_owned(),
        NormToken::RetBlock => "RETBLK".to_owned(),
    }
}

#[must_use]
fn format_op(op: &NormalizedOp) -> String {
    let mut out: String = token_label(&op.token);
    if let Some(value) = &op.const_value {
        let _ = write!(out, "[const={value:?}]");
    }
    if let Some(name) = &op.name_value {
        let _ = write!(out, "[name={}]", name.0);
    }
    if let Some(tgt) = op.jump_target_index {
        let _ = write!(out, "[->idx={tgt}]");
    }
    if let Some(opid) = op.operator_id {
        let _ = write!(out, "[op={opid}]");
    }
    out
}

#[must_use]
fn diff_note(a: &NormalizedOp, b: &NormalizedOp) -> String {
    if a.token != b.token {
        return format!(
            "opcode differs: {} vs {}",
            token_label(&a.token),
            token_label(&b.token)
        );
    }
    if a.const_value != b.const_value {
        return format!(
            "const value differs: {:?} vs {:?}",
            a.const_value, b.const_value
        );
    }
    if a.name_value != b.name_value {
        return format!(
            "name value differs: {:?} vs {:?}",
            a.name_value, b.name_value
        );
    }
    if a.jump_target_index != b.jump_target_index {
        return format!(
            "jump target index differs: {:?} vs {:?}",
            a.jump_target_index, b.jump_target_index
        );
    }
    if a.operator_id != b.operator_id {
        return format!(
            "compare operator differs: {:?} vs {:?}",
            a.operator_id, b.operator_id
        );
    }
    "operand differs".to_owned()
}

#[must_use]
fn compare_nested(a: &CodeObject, b: &CodeObject, version: PyVersion) -> Verdict {
    let nested_a: Vec<&CodeObject> = a
        .consts
        .iter()
        .filter_map(|c| match c {
            Object::Code(boxed) => Some(boxed.as_ref()),
            _ => None,
        })
        .collect();
    let nested_b: Vec<&CodeObject> = b
        .consts
        .iter()
        .filter_map(|c| match c {
            Object::Code(boxed) => Some(boxed.as_ref()),
            _ => None,
        })
        .collect();
    if nested_a.len() != nested_b.len() {
        return Verdict::CodeDiff(DiffDetail {
            qualname: qualname_of(a),
            first_diff_offset: 0,
            original_op: format!("{}-nested-codes", nested_a.len()),
            recompiled_op: format!("{}-nested-codes", nested_b.len()),
            note: "differing count of nested code objects".to_owned(),
        });
    }
    for (ca, cb) in nested_a.iter().zip(nested_b.iter()) {
        if let Verdict::CodeDiff(detail) = semantic_equiv(ca, cb, version) {
            return Verdict::CodeDiff(detail);
        }
    }
    Verdict::Semantic
}

#[must_use]
pub fn qualname_of(code: &CodeObject) -> String {
    match &code.qualname {
        Object::String { value, .. } | Object::ShortAscii { value, .. } => value.clone(),
        _ => match &code.name {
            Object::String { value, .. } | Object::ShortAscii { value, .. } => value.clone(),
            _ => "<anonymous>".to_owned(),
        },
    }
}
