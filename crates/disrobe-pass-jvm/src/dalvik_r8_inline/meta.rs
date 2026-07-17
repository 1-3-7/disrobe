use disrobe_bytes::read_uleb128_at;

use crate::dex::DexFile;

pub(crate) const ACC_STATIC: u32 = 0x0008;
pub(crate) const ACC_FINAL: u32 = 0x0010;
pub(crate) const ACC_SYNTHETIC: u32 = 0x1000;

#[derive(Debug, Clone)]
pub(crate) struct MethodMeta {
    pub(crate) class: String,
    pub(crate) name: String,
    pub(crate) descriptor: String,
    pub(crate) method_id_index: u32,
    pub(crate) access_flags: u32,
    pub(crate) has_code: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct FieldMeta {
    pub(crate) class: String,
    pub(crate) name: String,
    pub(crate) type_desc: String,
    pub(crate) access_flags: u32,
    pub(crate) is_static: bool,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct DexMeta {
    pub(crate) methods: Vec<MethodMeta>,
    pub(crate) fields: Vec<FieldMeta>,
}

impl MethodMeta {
    pub(crate) fn triple(&self) -> (String, String, String) {
        (
            self.class.clone(),
            self.name.clone(),
            self.descriptor.clone(),
        )
    }
}

fn read_u32_le(bytes: &[u8], off: usize) -> Option<u32> {
    let window: &[u8] = bytes.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([
        window[0], window[1], window[2], window[3],
    ]))
}

fn method_descriptor(dex: &DexFile, method_id_index: u32) -> Option<(String, String, String)> {
    let method = dex.method_ids.get(method_id_index as usize)?;
    let params: String = method.proto.parameters.concat();
    let descriptor: String = format!("({params}){}", method.proto.return_type);
    Some((method.class.clone(), method.name.clone(), descriptor))
}

fn field_descriptor(dex: &DexFile, field_id_index: u32) -> Option<(String, String, String)> {
    let field = dex.field_ids.get(field_id_index as usize)?;
    Some((
        field.class.clone(),
        field.name.clone(),
        field.type_name.clone(),
    ))
}

pub(crate) fn collect(dex: &DexFile, bytes: &[u8]) -> DexMeta {
    let mut out: DexMeta = DexMeta::default();
    let class_defs_off: usize = dex.header.class_defs_off as usize;
    let class_count: usize = (dex.header.class_defs_size as usize).min(bytes.len() / 32 + 1);
    let mut budget: usize = (dex.header.field_ids_size as usize)
        .saturating_add(dex.header.method_ids_size as usize)
        .saturating_add(class_count)
        .saturating_add(1);
    for ci in 0..class_count {
        let base: usize = match class_defs_off.checked_add(ci.saturating_mul(32)) {
            Some(v) => v,
            None => break,
        };
        let Some(class_data_off): Option<u32> = read_u32_le(bytes, base + 24) else {
            continue;
        };
        if class_data_off == 0 {
            continue;
        }
        walk_class_data(dex, bytes, class_data_off as usize, &mut out, &mut budget);
        if budget == 0 {
            break;
        }
    }
    out
}

fn walk_class_data(
    dex: &DexFile,
    bytes: &[u8],
    start: usize,
    out: &mut DexMeta,
    budget: &mut usize,
) {
    let Ok((static_fields, s1)): Result<(u64, usize), _> = read_uleb128_at(bytes, start) else {
        return;
    };
    let mut cursor: usize = start + s1;
    let Ok((instance_fields, s2)): Result<(u64, usize), _> = read_uleb128_at(bytes, cursor) else {
        return;
    };
    cursor += s2;
    let Ok((direct_methods, s3)): Result<(u64, usize), _> = read_uleb128_at(bytes, cursor) else {
        return;
    };
    cursor += s3;
    let Ok((virtual_methods, s4)): Result<(u64, usize), _> = read_uleb128_at(bytes, cursor) else {
        return;
    };
    cursor += s4;

    cursor = walk_fields(dex, bytes, cursor, static_fields, true, out, budget);
    cursor = walk_fields(dex, bytes, cursor, instance_fields, false, out, budget);
    cursor = walk_methods(dex, bytes, cursor, direct_methods, out, budget);
    let _end: usize = walk_methods(dex, bytes, cursor, virtual_methods, out, budget);
}

fn walk_fields(
    dex: &DexFile,
    bytes: &[u8],
    mut cursor: usize,
    count: u64,
    is_static: bool,
    out: &mut DexMeta,
    budget: &mut usize,
) -> usize {
    let mut field_idx: u64 = 0;
    let bounded: u64 = count.min(*budget as u64);
    for k in 0..bounded {
        let Ok((idx_diff, n1)): Result<(u64, usize), _> = read_uleb128_at(bytes, cursor) else {
            return cursor;
        };
        let Ok((access, n2)): Result<(u64, usize), _> = read_uleb128_at(bytes, cursor + n1) else {
            return cursor + n1;
        };
        cursor += n1 + n2;
        *budget = budget.saturating_sub(1);
        field_idx = if k == 0 {
            idx_diff
        } else {
            field_idx + idx_diff
        };
        if let Some((class, name, type_desc)) = field_descriptor(dex, field_idx as u32) {
            out.fields.push(FieldMeta {
                class,
                name,
                type_desc,
                access_flags: access as u32,
                is_static,
            });
        }
    }
    cursor
}

fn walk_methods(
    dex: &DexFile,
    bytes: &[u8],
    mut cursor: usize,
    count: u64,
    out: &mut DexMeta,
    budget: &mut usize,
) -> usize {
    let mut method_idx: u64 = 0;
    let bounded: u64 = count.min(*budget as u64);
    for k in 0..bounded {
        let Ok((idx_diff, n1)): Result<(u64, usize), _> = read_uleb128_at(bytes, cursor) else {
            return cursor;
        };
        let Ok((access, n2)): Result<(u64, usize), _> = read_uleb128_at(bytes, cursor + n1) else {
            return cursor + n1;
        };
        let Ok((code_off, n3)): Result<(u64, usize), _> = read_uleb128_at(bytes, cursor + n1 + n2)
        else {
            return cursor + n1 + n2;
        };
        cursor += n1 + n2 + n3;
        *budget = budget.saturating_sub(1);
        method_idx = if k == 0 {
            idx_diff
        } else {
            method_idx + idx_diff
        };
        if let Some((class, name, descriptor)) = method_descriptor(dex, method_idx as u32) {
            out.methods.push(MethodMeta {
                class,
                name,
                descriptor,
                method_id_index: method_idx as u32,
                access_flags: access as u32,
                has_code: code_off != 0,
            });
        }
    }
    cursor
}
