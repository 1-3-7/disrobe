use crate::cursor::ByteCursor;
use crate::error::{Error, Result};
use crate::reader::common::{
    LuaChunk, LuaConstant, LuaDialect, LuaLocal, LuaProto, LuaUpvalueName, capped_u32,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const LUAU_SUPPORTED_MIN: u8 = 1;
const LUAU_SUPPORTED_MAX: u8 = 11;
const MAX_OPCODE_MAP_BYTES: u64 = 64 << 10;
const MAX_BUILD_ID_BYTES: usize = 128;
const LUAU_DECLARED_OPCODE_MAX: u8 = 87;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpcodeMap {
    build_id: String,
    bytecode_version: u8,
    client_to_canonical: BTreeMap<u8, u8>,
    observed_client_opcodes: BTreeSet<u8>,
    canonical_sha256: String,
    client_sha256: String,
}

impl OpcodeMap {
    #[must_use]
    pub fn build_id(&self) -> &str {
        &self.build_id
    }

    #[must_use]
    pub const fn bytecode_version(&self) -> u8 {
        self.bytecode_version
    }

    #[must_use]
    pub fn canonical_opcode(&self, client_opcode: u8) -> Option<u8> {
        self.client_to_canonical.get(&client_opcode).copied()
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let encoded: Vec<u8> = serde_json::to_vec_pretty(self)
            .map_err(|error| Error::LuauOpcodeMap(format!("serialize map: {error}")))?;
        std::fs::write(path, encoded)?;
        Ok(())
    }

    pub fn load(path: &Path, build_id: &str, bytecode_version: u8) -> Result<Self> {
        let metadata = std::fs::metadata(path)?;
        if metadata.len() > MAX_OPCODE_MAP_BYTES {
            return Err(Error::LuauOpcodeMap(format!(
                "map file exceeds {MAX_OPCODE_MAP_BYTES} byte limit"
            )));
        }
        let encoded: Vec<u8> = std::fs::read(path)?;
        let map: Self = serde_json::from_slice(&encoded)
            .map_err(|error| Error::LuauOpcodeMap(format!("parse map: {error}")))?;
        map.validate()?;
        if map.build_id != build_id || map.bytecode_version != bytecode_version {
            return Err(Error::LuauOpcodeMap(format!(
                "map is for build {} version {}, not build {build_id} version {bytecode_version}",
                map.build_id, map.bytecode_version
            )));
        }
        Ok(map)
    }

    fn validate(&self) -> Result<()> {
        if self.build_id.trim().is_empty() || self.build_id.len() > MAX_BUILD_ID_BYTES {
            return Err(Error::LuauOpcodeMap(
                "map build identifier is empty or exceeds its limit".to_owned(),
            ));
        }
        if !(LUAU_SUPPORTED_MIN..=LUAU_SUPPORTED_MAX).contains(&self.bytecode_version) {
            return Err(Error::LuauOpcodeMap(
                "map has an unsupported bytecode version".to_owned(),
            ));
        }
        let keys: BTreeSet<u8> = self.client_to_canonical.keys().copied().collect();
        if keys != self.observed_client_opcodes {
            return Err(Error::LuauOpcodeMap(
                "map observed opcode set does not match its entries".to_owned(),
            ));
        }
        let mut canonical: BTreeSet<u8> = BTreeSet::new();
        for value in self.client_to_canonical.values() {
            if !canonical_opcode_is_legal(self.bytecode_version, *value)
                || !canonical.insert(*value)
            {
                return Err(Error::LuauOpcodeMap(
                    "map is not a legal canonical opcode bijection".to_owned(),
                ));
            }
        }
        if !is_sha256(&self.canonical_sha256) || !is_sha256(&self.client_sha256) {
            return Err(Error::LuauOpcodeMap(
                "map has invalid paired-bytecode SHA-256 provenance".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpcodeMapImport {
    pub map: OpcodeMap,
    pub mapped: usize,
    pub observed: usize,
}

pub fn import_opcode_map(
    build_id: &str,
    canonical: &[u8],
    client: &[u8],
) -> Result<OpcodeMapImport> {
    if build_id.trim().is_empty() || build_id.len() > MAX_BUILD_ID_BYTES {
        return Err(Error::LuauOpcodeMap(
            "a non-empty client build identifier is required".to_owned(),
        ));
    }
    let (canonical_version, canonical_raw, canonical_main) = read_raw(canonical)?;
    let (client_version, client_raw, client_main) = read_raw(client)?;
    if canonical_version != client_version {
        return Err(Error::LuauOpcodeMap(
            "paired chunks have different bytecode versions".to_owned(),
        ));
    }
    validate_raw_graph(&canonical_raw, canonical_main)?;
    validate_raw_graph(&client_raw, client_main)?;
    if canonical_main != client_main || canonical_raw.len() != client_raw.len() {
        return Err(Error::LuauOpcodeMap(
            "paired chunks have different serialized prototype graphs".to_owned(),
        ));
    }
    let mut forward: BTreeMap<u8, u8> = BTreeMap::new();
    let mut reverse: BTreeMap<u8, u8> = BTreeMap::new();
    let mut observed: BTreeSet<u8> = BTreeSet::new();
    for (canonical_proto, client_proto) in canonical_raw.iter().zip(client_raw.iter()) {
        if canonical_proto.child_ids != client_proto.child_ids
            || canonical_proto.proto.code.len() != client_proto.proto.code.len()
        {
            return Err(Error::LuauOpcodeMap(
                "paired chunks have incompatible prototype layouts".to_owned(),
            ));
        }
        let mut pc: usize = 0;
        while pc < canonical_proto.proto.code.len() {
            let canonical_word: u32 = canonical_proto.proto.code[pc];
            let client_word: u32 = client_proto.proto.code[pc];
            if canonical_word & !0xFF != client_word & !0xFF {
                return Err(Error::LuauOpcodeMap(format!(
                    "non-opcode bits differ at instruction {pc}"
                )));
            }
            let canonical_opcode: u8 = canonical_word as u8;
            if !canonical_opcode_is_legal(canonical_version, canonical_opcode) {
                return Err(Error::LuauOpcodeMap(format!(
                    "canonical opcode {canonical_opcode} is not supported for exact alignment"
                )));
            }
            let client_opcode: u8 = client_word as u8;
            if let Some(previous) = forward.insert(canonical_opcode, client_opcode)
                && previous != client_opcode
            {
                return Err(Error::LuauOpcodeMap(format!(
                    "canonical opcode {canonical_opcode} maps to both {previous} and {client_opcode}"
                )));
            }
            if let Some(previous) = reverse.insert(client_opcode, canonical_opcode)
                && previous != canonical_opcode
            {
                return Err(Error::LuauOpcodeMap(format!(
                    "client opcode {client_opcode} maps to both {previous} and {canonical_opcode}"
                )));
            }
            observed.insert(client_opcode);
            let width: usize = crate::decompile::luau_lift::test_op_length(canonical_opcode);
            let end: usize = pc.checked_add(width).ok_or_else(|| {
                Error::LuauOpcodeMap("instruction width overflows paired code range".to_owned())
            })?;
            if end > canonical_proto.proto.code.len() {
                return Err(Error::LuauOpcodeMap(format!(
                    "truncated canonical instruction at {pc} requires {width} words"
                )));
            }
            for aux_pc in pc + 1..end {
                if canonical_proto.proto.code[aux_pc] != client_proto.proto.code[aux_pc] {
                    return Err(Error::LuauOpcodeMap(format!(
                        "auxiliary word differs at instruction {pc}, word {aux_pc}"
                    )));
                }
            }
            pc = end;
        }
    }
    let observed_count: usize = observed.len();
    Ok(OpcodeMapImport {
        map: OpcodeMap {
            build_id: build_id.to_owned(),
            bytecode_version: canonical_version,
            client_to_canonical: reverse,
            observed_client_opcodes: observed,
            canonical_sha256: sha256_hex(canonical),
            client_sha256: sha256_hex(client),
        },
        mapped: forward.len(),
        observed: observed_count,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

const fn canonical_opcode_is_legal(version: u8, opcode: u8) -> bool {
    if opcode > LUAU_DECLARED_OPCODE_MAX {
        return false;
    }
    match opcode {
        60 => version >= 6,
        71 | 72 => version >= 5,
        59 | 61 => version < 3,
        76..=80 => version >= 2,
        81 | 82 => version >= 4,
        83..=85 => version >= 9,
        86 => version >= 10,
        87 => version >= 11,
        _ => true,
    }
}

fn validate_raw_graph(raw: &[RawProto], main: usize) -> Result<()> {
    if raw.len() > MAX_ASSEMBLED_NODES || main >= raw.len() {
        return Err(Error::LuauOpcodeMap(
            "serialized prototype population exceeds its limit".to_owned(),
        ));
    }
    let mut seen: Vec<bool> = vec![false; raw.len()];
    let mut active: Vec<bool> = vec![false; raw.len()];
    validate_raw_node(main, raw, &mut seen, &mut active, 0)?;
    if seen.iter().any(|value| !value) {
        return Err(Error::LuauOpcodeMap(
            "serialized prototype graph has orphan prototypes".to_owned(),
        ));
    }
    Ok(())
}

fn validate_raw_node(
    index: usize,
    raw: &[RawProto],
    seen: &mut [bool],
    active: &mut [bool],
    depth: usize,
) -> Result<()> {
    if depth > MAX_PROTO_DEPTH {
        return Err(Error::LuauOpcodeMap(
            "serialized prototype graph exceeds depth limit".to_owned(),
        ));
    }
    if active[index] {
        return Err(Error::LuauOpcodeMap(
            "serialized prototype graph has a cycle".to_owned(),
        ));
    }
    if seen[index] {
        return Err(Error::LuauOpcodeMap(
            "serialized prototype graph has a shared child".to_owned(),
        ));
    }
    seen[index] = true;
    active[index] = true;
    for child in &raw[index].child_ids {
        let child = usize::try_from(*child).map_err(|_| {
            Error::LuauOpcodeMap("serialized child prototype id is invalid".to_owned())
        })?;
        if child >= raw.len() {
            return Err(Error::LuauOpcodeMap(
                "serialized child prototype id is out of range".to_owned(),
            ));
        }
        validate_raw_node(child, raw, seen, active, depth + 1)?;
    }
    active[index] = false;
    Ok(())
}

pub fn read_with_opcode_map(bytes: &[u8], map: &OpcodeMap, build_id: &str) -> Result<LuaChunk> {
    let mut chunk: LuaChunk = read(bytes)?;
    if chunk.version_byte != map.bytecode_version || map.build_id != build_id {
        return Err(Error::LuauOpcodeMap(
            "map build or bytecode version does not match the requested input".to_owned(),
        ));
    }
    map.validate()?;
    apply_map(&mut chunk.main, map, "0")?;
    Ok(chunk)
}

fn apply_map(proto: &mut LuaProto, map: &OpcodeMap, location: &str) -> Result<()> {
    let mut pc: usize = 0;
    while pc < proto.code.len() {
        let client_opcode: u8 = proto.code[pc] as u8;
        let Some(canonical_opcode) = map.canonical_opcode(client_opcode) else {
            return Err(Error::LuauOpcodeMap(format!(
                "incomplete map; first unaligned client byte {location}:{pc}=0x{client_opcode:02X}, {} words remain unaligned",
                proto.code.len().saturating_sub(pc + 1)
            )));
        };
        proto.code[pc] = (proto.code[pc] & !0xFF) | u32::from(canonical_opcode);
        let width: usize = crate::decompile::luau_lift::test_op_length(canonical_opcode);
        let end: usize = pc
            .checked_add(width)
            .ok_or_else(|| Error::LuauOpcodeMap("mapped instruction width overflow".to_owned()))?;
        if end > proto.code.len() {
            return Err(Error::LuauOpcodeMap(format!(
                "mapped instruction {location}:{pc} requires {width} words, only {} remain",
                proto.code.len().saturating_sub(pc)
            )));
        }
        pc = end;
    }
    for (index, child) in proto.protos.iter_mut().enumerate() {
        apply_map(child, map, &format!("{location}.{index}"))?;
    }
    Ok(())
}

pub fn read(bytes: &[u8]) -> Result<LuaChunk> {
    let (version, raw_protos, main_idx) = read_raw(bytes)?;
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

fn read_raw(bytes: &[u8]) -> Result<(u8, Vec<RawProto>, usize)> {
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
    Ok((version, raw_protos, main_idx))
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
