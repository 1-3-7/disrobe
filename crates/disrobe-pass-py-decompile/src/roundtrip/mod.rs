pub mod normalize;

use disrobe_py_marshal::{CodeObject, Object, PyVersion};

pub use normalize::normalize_sequence;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Perfect,
    Semantic,
    CodeDiff(DiffDetail),
}

impl From<&Verdict> for disrobe_core::RecoverySignal {
    #[inline]
    fn from(verdict: &Verdict) -> Self {
        match verdict {
            Verdict::Perfect => Self::ByteRoundtripVerified,
            Verdict::Semantic => Self::RecompilesEquivalent,
            Verdict::CodeDiff(_) => Self::NoRecovery,
        }
    }
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
            Object::Float(f) => Self::Float(canonical_float_bits(f)),
            Object::Bytes(b) => Self::Bytes(b),
            Object::String { value, .. }
            | Object::Unicode { value, .. }
            | Object::ShortAscii { value, .. } => Self::Str(value),
            Object::Tuple(items) => Self::Tuple(items.into_iter().map(Self::from).collect()),
            Object::FrozenSet(items) => {
                Self::FrozenSet(items.into_iter().map(Self::from).collect())
            }
            Object::Code(boxed) => Self::Code(qualname_of(boxed.as_ref())),
            other => Self::Other(format!("{other:?}")),
        }
    }
}

/// Collapse every NaN payload to one representative bit pattern.
#[must_use]
fn canonical_float_bits(f: f64) -> u64 {
    if f.is_nan() {
        f64::NAN.to_bits()
    } else {
        f.to_bits()
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
        && raw_arg_semantically_equal(a, b)
}

#[must_use]
fn raw_arg_semantically_equal(a: &NormalizedOp, b: &NormalizedOp) -> bool {
    if a.const_value.is_some()
        || a.name_value.is_some()
        || a.jump_target_index.is_some()
        || a.operator_id.is_some()
    {
        return true;
    }
    a.raw_arg == b.raw_arg
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
        let rendered: String = format!("{value:?}");
        push_segment(&mut out, "const", &rendered);
    }
    if let Some(name) = &op.name_value {
        push_segment(&mut out, "name", &name.0);
    }
    if let Some(tgt) = op.jump_target_index {
        let rendered: String = tgt.to_string();
        push_segment(&mut out, "->idx", &rendered);
    }
    if let Some(opid) = op.operator_id {
        let rendered: String = opid.to_string();
        push_segment(&mut out, "op", &rendered);
    }
    if op.const_value.is_none()
        && op.name_value.is_none()
        && op.jump_target_index.is_none()
        && op.operator_id.is_none()
        && let Some(arg) = op.raw_arg
    {
        let rendered: String = arg.to_string();
        push_segment(&mut out, "arg", &rendered);
    }
    out
}

fn push_segment(out: &mut String, key: &str, value: &str) {
    out.push('[');
    out.push_str(key);
    out.push('=');
    out.push_str(value);
    out.push(']');
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
    if !raw_arg_semantically_equal(a, b) {
        return format!("raw arg differs: {:?} vs {:?}", a.raw_arg, b.raw_arg);
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
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => value.clone(),
        _ => match &code.name {
            Object::String { value, .. }
            | Object::Unicode { value, .. }
            | Object::ShortAscii { value, .. } => value.clone(),
            _ => "<anonymous>".to_owned(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{ConstValue, Object};

    const X86_INF_TIMES_ZERO_NAN: u64 = 0xfff8_0000_0000_0000;
    const ARM_INF_TIMES_ZERO_NAN: u64 = 0x7ff8_0000_0000_0000;
    const SIGNALLING_NAN_PAYLOAD: u64 = 0x7ff0_0000_0000_0001;

    #[test]
    fn nan_const_canonicalizes_across_architectures() {
        let x86: ConstValue =
            ConstValue::from(Object::Float(f64::from_bits(X86_INF_TIMES_ZERO_NAN)));
        let arm: ConstValue =
            ConstValue::from(Object::Float(f64::from_bits(ARM_INF_TIMES_ZERO_NAN)));
        let payload: ConstValue =
            ConstValue::from(Object::Float(f64::from_bits(SIGNALLING_NAN_PAYLOAD)));
        assert_eq!(
            x86, arm,
            "x86 (sign-set) and arm (sign-clear) inf*0 NaNs must compare equal"
        );
        assert_eq!(x86, payload, "differing NaN payloads must compare equal");
    }

    #[test]
    fn signed_infinities_stay_distinct() {
        let pos: ConstValue = ConstValue::from(Object::Float(f64::INFINITY));
        let neg: ConstValue = ConstValue::from(Object::Float(f64::NEG_INFINITY));
        assert_ne!(pos, neg, "+inf and -inf are semantically different consts");
    }

    #[test]
    fn finite_floats_keep_exact_bits() {
        let a: ConstValue = ConstValue::from(Object::Float(1.062_500_000_000_001));
        let b: ConstValue = ConstValue::from(Object::Float(1.062_500_000_000_001));
        let c: ConstValue = ConstValue::from(Object::Float(9.375_000_000_000_002));
        let neg_zero: ConstValue = ConstValue::from(Object::Float(-0.0));
        let pos_zero: ConstValue = ConstValue::from(Object::Float(0.0));
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(neg_zero, pos_zero, "-0.0 and 0.0 differ under to_bits");
    }
}
