use serde::{Deserialize, Serialize};

use super::image::{
    MAX_SHORTSTRING_LEN, PeView, is_plausible_symbol, is_plausible_symbol_of_length,
};

pub(super) const TK_INTEGER: u8 = 1;
pub(super) const TK_CHAR: u8 = 2;
pub(super) const TK_ENUMERATION: u8 = 3;
pub(super) const TK_FLOAT: u8 = 4;
pub(super) const TK_STRING: u8 = 5;
pub(super) const TK_SET: u8 = 6;
pub(super) const TK_CLASS: u8 = 7;
pub(super) const TK_METHOD: u8 = 8;
pub(super) const TK_WCHAR: u8 = 9;
pub(super) const TK_RECORD: u8 = 14;
pub(super) const TK_INT64: u8 = 16;
pub(super) const TK_DYNARRAY: u8 = 17;
pub(super) const TK_MIN: u8 = 1;
pub(super) const TK_MAX: u8 = 22;

const MAX_ENUM_MEMBERS: i64 = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelphiRecordField {
    pub name: String,
    pub offset: u32,
    pub visibility: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelphiTypeInfo {
    pub name: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_value: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_value: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub element_type: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub record_fields: Vec<DelphiRecordField>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_field_evidence: Option<String>,
}

pub(super) const fn kind_label(kind: u8) -> &'static str {
    match kind {
        TK_INTEGER => "integer",
        TK_CHAR => "char",
        TK_ENUMERATION => "enumeration",
        TK_FLOAT => "float",
        TK_STRING => "short-string",
        TK_SET => "set",
        TK_CLASS => "class",
        TK_METHOD => "method",
        TK_WCHAR => "wide-char",
        10 => "ansi-string",
        11 => "wide-string",
        12 => "variant",
        13 => "array",
        14 => "record",
        15 => "interface",
        TK_INT64 => "int64",
        TK_DYNARRAY => "dynamic-array",
        18 => "unicode-string",
        19 => "class-reference",
        20 => "pointer",
        21 => "procedure",
        22 => "managed-record",
        _ => "unknown",
    }
}

const fn float_label(code: u8) -> Option<&'static str> {
    match code {
        0 => Some("Single"),
        1 => Some("Double"),
        2 => Some("Extended"),
        3 => Some("Comp"),
        4 => Some("Currency"),
        _ => None,
    }
}

pub(super) struct TypeHeader {
    pub kind: u8,
    pub name: String,
    pub body: usize,
}

pub(super) fn read_header(view: &PeView<'_>, off: usize) -> Option<TypeHeader> {
    let kind: u8 = *view.bytes.get(off)?;
    if !(TK_MIN..=TK_MAX).contains(&kind) {
        return None;
    }
    let (name, consumed): (String, usize) = view.read_shortstring(off + 1, MAX_SHORTSTRING_LEN)?;
    if !is_plausible_symbol(&name) {
        return None;
    }
    Some(TypeHeader {
        kind,
        name,
        body: off + 1 + consumed,
    })
}

pub(super) fn name_at(view: &PeView<'_>, off: usize) -> Option<String> {
    read_header(view, off).map(|h: TypeHeader| h.name)
}

pub(super) fn resolve_reference(view: &PeView<'_>, field: u64) -> Option<usize> {
    if field == 0 {
        return None;
    }
    let direct: usize = view.va_to_off(field)?;
    if read_header(view, direct).is_some() {
        return Some(direct);
    }
    let indirect: u64 = view.read_ptr(direct)?;
    if indirect == 0 {
        return None;
    }
    let off: usize = view.va_to_off(indirect)?;
    read_header(view, off).map(|_| off)
}

pub(super) fn resolve_name(view: &PeView<'_>, field: u64) -> Option<String> {
    let off: usize = resolve_reference(view, field)?;
    name_at(view, off)
}

pub(super) fn describe_at(view: &PeView<'_>, off: usize, ptr: usize) -> Option<DelphiTypeInfo> {
    let header: TypeHeader = read_header(view, off)?;
    let mut info: DelphiTypeInfo = DelphiTypeInfo {
        name: header.name,
        kind: kind_label(header.kind).to_owned(),
        unit_name: None,
        members: Vec::new(),
        min_value: None,
        max_value: None,
        element_type: None,
        record_fields: Vec::new(),
        record_field_evidence: None,
    };
    let body: usize = header.body;

    match header.kind {
        TK_ENUMERATION => fill_enumeration(view, body, ptr, &mut info),
        TK_INTEGER | TK_CHAR | TK_WCHAR => fill_ordinal(view, body, &mut info),
        TK_INT64 => fill_int64(view, body, &mut info),
        TK_FLOAT => {
            if let Some(code) = view.bytes.get(body).copied()
                && let Some(label) = float_label(code)
            {
                info.element_type = Some(label.to_owned());
            }
        }
        TK_STRING => {
            if let Some(max) = view.bytes.get(body).copied() {
                info.max_value = Some(i64::from(max));
            }
        }
        TK_SET => fill_set(view, body, ptr, &mut info),
        TK_DYNARRAY => fill_dynarray(view, body, ptr, &mut info),
        TK_RECORD => fill_record(view, body, ptr, &mut info),
        TK_CLASS => fill_class(view, body, ptr, &mut info),
        _ => {}
    }

    Some(info)
}

fn fill_ordinal(view: &PeView<'_>, body: usize, info: &mut DelphiTypeInfo) {
    let Some(min): Option<i32> = view.read_i32(body + 1) else {
        return;
    };
    let Some(max): Option<i32> = view.read_i32(body + 5) else {
        return;
    };
    if min > max {
        return;
    }
    info.min_value = Some(i64::from(min));
    info.max_value = Some(i64::from(max));
}

fn fill_int64(view: &PeView<'_>, body: usize, info: &mut DelphiTypeInfo) {
    let Some(min): Option<u64> = view.read_u64(body) else {
        return;
    };
    let Some(max): Option<u64> = view.read_u64(body + 8) else {
        return;
    };
    let (min, max): (i64, i64) = (min as i64, max as i64);
    if min > max {
        return;
    }
    info.min_value = Some(min);
    info.max_value = Some(max);
}

fn fill_enumeration(view: &PeView<'_>, body: usize, ptr: usize, info: &mut DelphiTypeInfo) {
    let Some(min): Option<i32> = view.read_i32(body + 1) else {
        return;
    };
    let Some(max): Option<i32> = view.read_i32(body + 5) else {
        return;
    };
    if min > max {
        return;
    }
    let count: i64 = i64::from(max) - i64::from(min) + 1;
    if count > MAX_ENUM_MEMBERS {
        return;
    }
    info.min_value = Some(i64::from(min));
    info.max_value = Some(i64::from(max));

    let mut cursor: usize = body + 9 + ptr;
    let mut members: Vec<String> = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let Some((name, consumed)): Option<(String, usize)> =
            view.read_shortstring(cursor, MAX_SHORTSTRING_LEN)
        else {
            return;
        };
        if !is_plausible_symbol(&name) {
            return;
        }
        cursor += consumed;
        members.push(name);
    }
    info.members = members;

    if let Some((unit, _consumed)) = view.read_shortstring(cursor, MAX_SHORTSTRING_LEN)
        && is_plausible_symbol(&unit)
    {
        info.unit_name = Some(unit);
    }
}

fn fill_set(view: &PeView<'_>, body: usize, ptr: usize, info: &mut DelphiTypeInfo) {
    for skip in [1usize, 2usize] {
        let Some(field): Option<u64> = view.read_ptr(body + skip) else {
            continue;
        };
        let Some(comp): Option<usize> = resolve_reference(view, field) else {
            continue;
        };
        let Some(header): Option<TypeHeader> = read_header(view, comp) else {
            continue;
        };
        if !matches!(header.kind, TK_ENUMERATION | TK_CHAR | TK_INTEGER) {
            continue;
        }
        info.element_type = Some(header.name);
        if header.kind == TK_ENUMERATION {
            fill_enumeration(view, header.body, ptr, info);
        }
        return;
    }
}

fn fill_dynarray(view: &PeView<'_>, body: usize, ptr: usize, info: &mut DelphiTypeInfo) {
    let el_type2_at: usize = body + 4 + ptr + 4;
    if let Some(field) = view.read_ptr(el_type2_at)
        && let Some(name) = resolve_name(view, field)
    {
        info.element_type = Some(name);
    } else if let Some(field) = view.read_ptr(body + 4)
        && let Some(name) = resolve_name(view, field)
    {
        info.element_type = Some(name);
    }
    if let Some((unit, _consumed)) = view.read_shortstring(el_type2_at + ptr, MAX_SHORTSTRING_LEN)
        && is_plausible_symbol(&unit)
    {
        info.unit_name = Some(unit);
    }
}

fn fill_class(view: &PeView<'_>, body: usize, ptr: usize, info: &mut DelphiTypeInfo) {
    let unit_at: usize = body + ptr + ptr + 2;
    if let Some((unit, _consumed)) = view.read_shortstring(unit_at, MAX_SHORTSTRING_LEN)
        && is_plausible_symbol(&unit)
    {
        info.unit_name = Some(unit);
    }
}

const MAX_RECORD_SIZE: i32 = 1 << 20;
const MAX_MANAGED_FIELDS: i32 = 4096;
const MAX_RECORD_FIELDS: i32 = 4096;
const MAX_RECORD_OPERATORS: u8 = 64;
const MAX_FIELD_VISIBILITY: u8 = 3;

const RECORD_EVIDENCE: &str = "layout read from the documented extended record RTTI; field names are graded against that specification only, not against a source tree";

fn parse_record_fields(
    view: &PeView<'_>,
    mut cursor: usize,
    ptr: usize,
    rec_size: i32,
) -> Option<Vec<DelphiRecordField>> {
    let count: i32 = view.read_i32(cursor)?;
    if count <= 0 || count > MAX_RECORD_FIELDS {
        return None;
    }
    cursor = cursor.checked_add(4)?;

    let mut fields: Vec<DelphiRecordField> = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let type_ref: u64 = view.read_ptr(cursor)?;
        let offset: i32 = view.read_i32(cursor.checked_add(ptr)?)?;
        let visibility: u8 = *view.bytes.get(cursor.checked_add(ptr)?.checked_add(4)?)?;
        let name_at: usize = cursor.checked_add(ptr)?.checked_add(5)?;
        let (name, consumed): (String, usize) =
            view.read_shortstring(name_at, MAX_SHORTSTRING_LEN)?;
        if !(0..rec_size).contains(&offset) {
            return None;
        }
        if visibility > MAX_FIELD_VISIBILITY {
            return None;
        }
        if !is_plausible_symbol_of_length(&name, 1) {
            return None;
        }
        fields.push(DelphiRecordField {
            name,
            offset: offset as u32,
            visibility,
            type_name: resolve_name(view, type_ref),
        });
        cursor = name_at.checked_add(consumed)?;
    }
    Some(fields)
}

fn fill_record(view: &PeView<'_>, body: usize, ptr: usize, info: &mut DelphiTypeInfo) {
    let Some(rec_size): Option<i32> = view.read_i32(body) else {
        return;
    };
    if rec_size <= 0 || rec_size > MAX_RECORD_SIZE {
        return;
    }
    info.min_value = Some(i64::from(rec_size));

    let Some(managed_count): Option<i32> = view.read_i32(body + 4) else {
        return;
    };
    if !(0..=MAX_MANAGED_FIELDS).contains(&managed_count) {
        return;
    }
    let managed_entry: usize = ptr + 4;
    let Some(after_managed): Option<usize> = (managed_count as usize)
        .checked_mul(managed_entry)
        .and_then(|span: usize| body.checked_add(8)?.checked_add(span))
    else {
        return;
    };

    let without_operators: Option<Vec<DelphiRecordField>> =
        parse_record_fields(view, after_managed, ptr, rec_size);

    let with_operators: Option<Vec<DelphiRecordField>> = view
        .bytes
        .get(after_managed)
        .copied()
        .filter(|ops: &u8| *ops <= MAX_RECORD_OPERATORS)
        .and_then(|ops: u8| {
            let skip: usize = 1usize.checked_add((ops as usize).checked_mul(ptr)?)?;
            parse_record_fields(view, after_managed.checked_add(skip)?, ptr, rec_size)
        });

    let chosen: Vec<DelphiRecordField> = match (without_operators, with_operators) {
        (Some(only), None) | (None, Some(only)) => only,
        _ => return,
    };

    info.record_fields = chosen;
    info.record_field_evidence = Some(RECORD_EVIDENCE.to_owned());
}
