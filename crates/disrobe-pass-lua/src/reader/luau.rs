use crate::cursor::ByteCursor;
use crate::error::{Error, Result};
use crate::reader::common::{
    LuaChunk, LuaConstant, LuaDialect, LuaLocal, LuaProto, LuaUpvalueName, capped_u32,
};

const LUAU_SUPPORTED_MIN: u8 = 1;
const LUAU_SUPPORTED_MAX: u8 = 11;

pub fn read(bytes: &[u8]) -> Result<LuaChunk> {
    let mut c: ByteCursor<'_> = ByteCursor::new(bytes);
    let version: u8 = c.read_u8()?;
    if version == 0 {
        return Err(Error::NotLuau);
    }
    if !(LUAU_SUPPORTED_MIN..=LUAU_SUPPORTED_MAX).contains(&version) {
        return Err(Error::UnsupportedLuauVersion(version));
    }
    let types_version: u8 = if version >= 4 { c.read_u8()? } else { 0 };

    let string_count: u64 = read_varint(&mut c)?;
    let string_count: usize = c.checked_count::<String>("luau string", string_count, 1)?;
    let mut strings: Vec<String> = Vec::with_capacity(string_count);
    for _ in 0..string_count {
        let len: u64 = read_varint(&mut c)?;
        let raw: &[u8] = read_blob(&mut c, "luau string length", len)?;
        let s: String = String::from_utf8_lossy(raw).into_owned();
        strings.push(s);
    }

    if types_version == 3 {
        loop {
            let idx: u8 = c.read_u8()?;
            if idx == 0 {
                break;
            }
            let name_len: u64 = read_varint(&mut c)?;
            let _name: &[u8] = read_blob(&mut c, "luau type name length", name_len)?;
        }
    }

    let proto_count: u64 = read_varint(&mut c)?;
    let proto_count: usize = c.checked_count::<RawProto>("luau proto", proto_count, 1)?;
    let mut raw_protos: Vec<RawProto> = Vec::with_capacity(proto_count);
    for _ in 0..proto_count {
        raw_protos.push(read_proto(&mut c, &strings, version, types_version)?);
    }
    let main_proto_id: u64 = read_varint(&mut c)?;
    let main_idx: usize = usize::try_from(main_proto_id)
        .ok()
        .filter(|i: &usize| *i < raw_protos.len())
        .ok_or(Error::LuauMainProtoOutOfRange {
            index: main_proto_id,
            count: raw_protos.len(),
        })?;
    let mut assembled: Vec<Option<AssembledProto>> = vec![None; raw_protos.len()];
    let mut in_progress: Vec<bool> = vec![false; raw_protos.len()];
    let mut budget: usize = MAX_ASSEMBLED_NODES;
    let (main, _): (LuaProto, usize) = assemble_proto(
        main_idx,
        &raw_protos,
        &mut assembled,
        &mut in_progress,
        &mut budget,
        0,
    );
    Ok(LuaChunk {
        dialect: LuaDialect::Luau,
        version_byte: version,
        format: 0,
        little_endian: true,
        size_of_int: 4,
        size_of_size_t: 4,
        size_of_instruction: 4,
        size_of_lua_integer: 0,
        size_of_lua_number: 8,
        integral_number: false,
        main,
    })
}

const MAX_ASSEMBLED_NODES: usize = 1 << 16;
const MAX_PROTO_DEPTH: usize = 200;

#[derive(Debug, Clone)]
struct RawProto {
    proto: LuaProto,
    child_ids: Vec<u64>,
    closure_const_targets: Vec<(usize, u64)>,
}

#[derive(Debug, Clone)]
struct AssembledProto {
    proto: LuaProto,
    node_count: usize,
}

fn assemble_proto(
    idx: usize,
    raw: &[RawProto],
    assembled: &mut [Option<AssembledProto>],
    in_progress: &mut [bool],
    budget: &mut usize,
    depth: usize,
) -> (LuaProto, usize) {
    let Some(entry): Option<&RawProto> = raw.get(idx) else {
        return (empty_proto(), 1);
    };
    if let Some(done) = assembled.get(idx).and_then(Option::as_ref) {
        if done.node_count <= *budget {
            *budget = budget.saturating_sub(done.node_count);
            return (done.proto.clone(), done.node_count);
        }
        return (entry.proto.clone(), 1);
    }
    if depth > MAX_PROTO_DEPTH || in_progress.get(idx).copied().unwrap_or(false) || *budget == 0 {
        return (entry.proto.clone(), 1);
    }
    *budget = budget.saturating_sub(1);
    if let Some(flag) = in_progress.get_mut(idx) {
        *flag = true;
    }
    let mut proto: LuaProto = entry.proto.clone();
    let child_ids: Vec<u64> = entry.child_ids.clone();
    let closure_const_targets: Vec<(usize, u64)> = entry.closure_const_targets.clone();
    let mut node_count: usize = 1;
    proto.protos = child_ids
        .iter()
        .map(|cid: &u64| {
            let (child, child_nodes): (LuaProto, usize) = usize::try_from(*cid)
                .ok()
                .filter(|i: &usize| *i < raw.len() && *i != idx)
                .map_or_else(
                    || (empty_proto(), 1),
                    |i: usize| assemble_proto(i, raw, assembled, in_progress, budget, depth + 1),
                );
            node_count = node_count.saturating_add(child_nodes);
            child
        })
        .collect();
    for (const_idx, target_proto_id) in &closure_const_targets {
        let local_pos: Option<usize> = child_ids
            .iter()
            .position(|cid: &u64| cid == target_proto_id);
        if let (Some(LuaConstant::ClosureRef(slot)), Some(pos)) =
            (proto.constants.get_mut(*const_idx), local_pos)
        {
            *slot = u32::try_from(pos).unwrap_or(u32::MAX);
        }
    }
    if let Some(flag) = in_progress.get_mut(idx) {
        *flag = false;
    }
    if let Some(slot) = assembled.get_mut(idx) {
        *slot = Some(AssembledProto {
            proto: proto.clone(),
            node_count,
        });
    }
    (proto, node_count)
}

fn empty_proto() -> LuaProto {
    LuaProto {
        source: None,
        line_defined: 0,
        last_line_defined: 0,
        num_params: 0,
        is_vararg: 0,
        max_stack_size: 0,
        code: Vec::new(),
        constants: Vec::new(),
        protos: Vec::new(),
        source_lines: Vec::new(),
        locals: Vec::new(),
        upvalues: Vec::new(),
    }
}

fn read_varint(c: &mut ByteCursor<'_>) -> Result<u64> {
    let start: usize = c.position();
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        let byte: u8 = c.read_u8()?;
        let chunk: u64 = u64::from(byte & 0x7F);
        if shift >= 64 || chunk > (u64::MAX >> shift) {
            return Err(Error::BadUleb128(start));
        }
        let shifted: u64 = chunk << shift;
        result |= shifted;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            return Err(Error::BadUleb128(start));
        }
    }
    Ok(result)
}

fn checked_index(id: u64) -> Option<usize> {
    usize::try_from(id).ok()?.checked_sub(1)
}

fn signed_integer(negative: bool, magnitude: u64) -> i64 {
    match (negative, i64::try_from(magnitude)) {
        (false, Ok(value)) => value,
        (false, Err(_)) => i64::MAX,
        (true, Ok(value)) => value.saturating_neg(),
        (true, Err(_)) => i64::MIN,
    }
}

fn read_blob<'a>(c: &mut ByteCursor<'a>, section: &'static str, len: u64) -> Result<&'a [u8]> {
    let len: usize = c.checked_len(section, len)?;
    c.read_bytes(len)
}

const LUAU_K_NIL: u8 = 0;
const LUAU_K_BOOL: u8 = 1;
const LUAU_K_NUMBER: u8 = 2;
const LUAU_K_STRING: u8 = 3;
const LUAU_K_IMPORT: u8 = 4;
const LUAU_K_TABLE: u8 = 5;
const LUAU_K_CLOSURE: u8 = 6;
const LUAU_K_VECTOR: u8 = 7;
const LUAU_K_TABLE_WITH_CONSTANTS: u8 = 8;
const LUAU_K_INTEGER: u8 = 9;
const LUAU_K_CLASS_SHAPE: u8 = 10;

fn read_proto(
    c: &mut ByteCursor<'_>,
    strings: &[String],
    version: u8,
    types_version: u8,
) -> Result<RawProto> {
    let max_stack_size: u8 = c.read_u8()?;
    let num_params: u8 = c.read_u8()?;
    let nups: u8 = c.read_u8()?;
    let is_vararg: u8 = c.read_u8()?;
    if version >= 4 {
        let _flags: u8 = c.read_u8()?;
        if types_version == 1 || types_version == 2 || types_version == 3 {
            let types_size: u64 = read_varint(c)?;
            if types_size > 0 {
                let _types: &[u8] = read_blob(c, "luau type payload length", types_size)?;
            }
        }
    }
    let code_size: u64 = read_varint(c)?;
    let code_size: usize = c.checked_count::<u32>("luau code", code_size, 4)?;
    let mut code: Vec<u32> = Vec::with_capacity(code_size);
    for _ in 0..code_size {
        code.push(c.read_u32()?);
    }
    let const_count: u64 = read_varint(c)?;
    let const_count: usize = c.checked_count::<LuaConstant>("luau constant", const_count, 1)?;
    let mut constants: Vec<LuaConstant> = Vec::with_capacity(const_count);
    let mut closure_const_targets: Vec<(usize, u64)> = Vec::new();
    for _ in 0..const_count {
        let tag: u8 = c.read_u8()?;
        let value: LuaConstant = match tag {
            LUAU_K_NIL => LuaConstant::Nil,
            LUAU_K_BOOL => LuaConstant::Bool(c.read_u8()? != 0),
            LUAU_K_NUMBER => LuaConstant::Number(c.read_f64()?),
            LUAU_K_STRING => {
                let id: u64 = read_varint(c)?;
                checked_index(id)
                    .and_then(|idx: usize| strings.get(idx))
                    .cloned()
                    .map_or(LuaConstant::Str(String::new()), LuaConstant::Str)
            }
            LUAU_K_IMPORT => {
                let id: u32 = c.read_u32()?;
                LuaConstant::Import(resolve_import_path(id, &constants))
            }
            LUAU_K_TABLE => {
                let key_count: u64 = read_varint(c)?;
                let key_count: usize = c.checked_count::<u8>("luau table key", key_count, 1)?;
                for _ in 0..key_count {
                    let _k: u64 = read_varint(c)?;
                }
                LuaConstant::Nil
            }
            LUAU_K_CLOSURE => {
                let fid: u64 = read_varint(c)?;
                closure_const_targets.push((constants.len(), fid));
                LuaConstant::ClosureRef(u32::MAX)
            }
            LUAU_K_VECTOR => {
                let vx: f32 = f32::from_bits(c.read_u32()?);
                let vy: f32 = f32::from_bits(c.read_u32()?);
                let vz: f32 = f32::from_bits(c.read_u32()?);
                let vw: f32 = f32::from_bits(c.read_u32()?);
                LuaConstant::Vector([vx, vy, vz, vw])
            }
            LUAU_K_TABLE_WITH_CONSTANTS => {
                let key_count: u64 = read_varint(c)?;
                let key_count: usize =
                    c.checked_count::<u32>("luau table constant key", key_count, 5)?;
                for _ in 0..key_count {
                    let _k: u64 = read_varint(c)?;
                    let _v: u32 = c.read_u32()?;
                }
                LuaConstant::Nil
            }
            LUAU_K_INTEGER => {
                let neg: u8 = c.read_u8()?;
                let mag: u64 = read_varint(c)?;
                LuaConstant::Integer(signed_integer(neg != 0, mag))
            }
            LUAU_K_CLASS_SHAPE => {
                let _cnid: u64 = read_varint(c)?;
                let num_properties: u64 = read_varint(c)?;
                let num_methods: u64 = read_varint(c)?;
                let total: u64 = num_properties.saturating_add(num_methods);
                let total: usize = c.checked_count::<u8>("luau class member", total, 1)?;
                for _ in 0..total {
                    let _mid: u64 = read_varint(c)?;
                }
                LuaConstant::Nil
            }
            other => return Err(Error::BadConstantTag(other, c.position())),
        };
        constants.push(value);
    }
    let inner_proto_count: u64 = read_varint(c)?;
    let inner_proto_count: usize =
        c.checked_count::<u64>("luau child proto", inner_proto_count, 1)?;
    let mut child_ids: Vec<u64> = Vec::with_capacity(inner_proto_count);
    for _ in 0..inner_proto_count {
        child_ids.push(read_varint(c)?);
    }
    let line_defined: u64 = read_varint(c)?;
    let debug_name_id: u64 = read_varint(c)?;
    let source: Option<String> = if debug_name_id == 0 {
        None
    } else {
        checked_index(debug_name_id).and_then(|idx: usize| strings.get(idx).cloned())
    };
    let has_lineinfo: u8 = c.read_u8()?;
    if has_lineinfo != 0 {
        let linegap: u8 = c.read_u8()?;
        let span: usize = code_size;
        for _ in 0..span {
            let _: u8 = c.read_u8()?;
        }
        let shift: u32 = u32::from(linegap).min(31);
        let intervals: usize = (span.saturating_sub(1) >> shift).saturating_add(1);
        for _ in 0..intervals {
            let _: u32 = c.read_u32()?;
        }
    }
    let has_debug: u8 = c.read_u8()?;
    let mut upvalues: Vec<LuaUpvalueName> = Vec::with_capacity(usize::from(nups));
    let mut locals: Vec<LuaLocal> = Vec::new();
    if has_debug != 0 {
        let local_count: u64 = read_varint(c)?;
        let local_count: usize = c.checked_count::<LuaLocal>("luau local", local_count, 4)?;
        locals.reserve(local_count);
        for _ in 0..local_count {
            let name_id: u64 = read_varint(c)?;
            let start: u64 = read_varint(c)?;
            let end: u64 = read_varint(c)?;
            let reg: u8 = c.read_u8()?;
            let name: String = checked_index(name_id)
                .and_then(|idx: usize| strings.get(idx))
                .cloned()
                .unwrap_or_else(|| format!("L{reg}"));
            locals.push(LuaLocal {
                name,
                start_pc: capped_u32(start),
                end_pc: capped_u32(end),
            });
        }
        let upval_count: u64 = read_varint(c)?;
        let upval_count: usize =
            c.checked_count::<LuaUpvalueName>("luau upvalue name", upval_count, 1)?;
        upvalues.reserve(upval_count);
        for _ in 0..upval_count {
            let id: u64 = read_varint(c)?;
            let name: String = checked_index(id)
                .and_then(|idx: usize| strings.get(idx))
                .cloned()
                .unwrap_or_default();
            upvalues.push(LuaUpvalueName { name });
        }
    }
    if version >= 11 {
        let feedback_count: u64 = read_varint(c)?;
        let feedback_count: usize = c.checked_count::<u8>("luau feedback", feedback_count, 2)?;
        for _ in 0..feedback_count {
            let _slottype: u8 = c.read_u8()?;
            let _pc: u64 = read_varint(c)?;
        }
    }
    Ok(RawProto {
        proto: LuaProto {
            source,
            line_defined: capped_u32(line_defined),
            last_line_defined: 0,
            num_params,
            is_vararg,
            max_stack_size,
            code,
            constants,
            protos: Vec::new(),
            source_lines: Vec::new(),
            locals,
            upvalues,
        },
        child_ids,
        closure_const_targets,
    })
}

#[must_use]
fn resolve_import_path(id: u32, constants: &[LuaConstant]) -> Vec<String> {
    let count: u32 = id >> 30;
    let parts: [u32; 3] = [(id >> 20) & 0x3FF, (id >> 10) & 0x3FF, id & 0x3FF];
    let mut path: Vec<String> = Vec::with_capacity(count.min(3) as usize);
    for slot in parts.iter().take(count.min(3) as usize) {
        if let Some(LuaConstant::Str(s)) = constants.get(*slot as usize) {
            path.push(s.clone());
        }
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_rejects_bits_shifted_past_u64() {
        let mut bytes: Vec<u8> = vec![0x80u8; 9];
        bytes.push(0x02u8);
        let mut cursor: ByteCursor<'_> = ByteCursor::new(&bytes);
        let result: Result<u64> = read_varint(&mut cursor);
        assert!(matches!(result, Err(Error::BadUleb128(0))));
    }
}
