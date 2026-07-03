use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::bytenode::{BytenodeCacheBody, NodeVersion};
use super::flat_bytecode_disasm::{DecodedOperand, Disassembly, disassemble};
use super::root_names::RootNameTable;
use crate::error::{Error, Result};

pub const TAGGED_SIZE_NO_COMPRESSION: usize = 8usize;

pub const SYSTEM_POINTER_SIZE: usize = 8usize;

pub const BYTECODE_ARRAY_SCALAR_HEADER: usize = 16usize;

pub const RETURN_OPCODE_NODE24: u8 = 0xB3u8;

const ABSENT: u8 = 0xFFu8;

const BC_ROOT_ARRAY_CONSTANTS_LO: u8 = 0x40u8;
const BC_ROOT_ARRAY_CONSTANTS_HI: u8 = 0x5Fu8;
const BC_FIXED_RAW_DATA_LO: u8 = 0x60u8;
const BC_FIXED_RAW_DATA_HI: u8 = 0x7Fu8;
const BC_FIXED_REPEAT_ROOT_LO: u8 = 0x80u8;
const BC_FIXED_REPEAT_ROOT_HI: u8 = 0x8Fu8;
const BC_HOT_OBJECT_LO: u8 = 0x90u8;
const BC_HOT_OBJECT_HI: u8 = 0x97u8;

const FIXED_REPEAT_ROOT_MIN_COUNT: u32 = 2u32;
const VARIABLE_REPEAT_ROOT_MIN_COUNT: u32 = 18u32;

const MAX_FRAME_SIZE: i32 = 1i32 << 24i32;

const MAX_DESERIALIZE_OBJECTS: usize = 1usize << 20usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SerializerOpcodes {
    backref: u8,
    read_only_heap_ref: u8,
    read_only_object_cache: u8,
    startup_object_cache: u8,
    root_array: u8,
    attached_reference: u8,
    shared_heap_object_cache: u8,
    nop: u8,
    synchronize: u8,
    variable_repeat: u8,
    off_heap_backing_store: u8,
    off_heap_resizable_backing_store: u8,
    embedder_fields_data: u8,
    api_wrapper_fields_data: u8,
    variable_raw_data: u8,
    api_reference: u8,
    external_reference: u8,
    raw_external_reference: u8,
    sandboxed_api_reference: u8,
    sandboxed_external_reference: u8,
    sandboxed_raw_external_reference: u8,
    internal_reference: u8,
    cleared_weak_reference: u8,
    weak_prefix: u8,
    off_heap_target: u8,
    register_pending_forward_ref: u8,
    resolve_pending_forward_ref: u8,
    new_meta_map: u8,
    new_contextless_meta_map: u8,
    new_contextful_meta_map: u8,
    indirect_pointer_prefix: u8,
    initialize_self_indirect_pointer: u8,
    allocate_js_dispatch_entry: u8,
    js_dispatch_entry: u8,
    protected_pointer_prefix: u8,
    code_body: u8,
}

impl SerializerOpcodes {
    const fn for_node(node: NodeVersion) -> Self {
        match node {
            NodeVersion::Node18 => Self::V8_10_2,
            NodeVersion::Node20 => Self::V8_11_3,
            NodeVersion::Node22 => Self::V8_12_4,
            NodeVersion::Node24 | NodeVersion::Unknown => Self::V8_13_6,
        }
    }

    const fn new_object_hi(self) -> u8 {
        self.backref.saturating_sub(1u8)
    }

    const fn is_new_object(self, opcode: u8) -> bool {
        opcode <= self.new_object_hi()
    }

    const V8_10_2: Self = Self {
        backref: 0x04,
        read_only_heap_ref: 0x05,
        startup_object_cache: 0x06,
        root_array: 0x07,
        attached_reference: 0x08,
        read_only_object_cache: 0x09,
        shared_heap_object_cache: 0x0A,
        nop: 0x0B,
        synchronize: 0x0C,
        variable_repeat: 0x0D,
        off_heap_backing_store: 0x0E,
        off_heap_resizable_backing_store: 0x0F,
        embedder_fields_data: 0x10,
        variable_raw_data: 0x11,
        api_reference: 0x12,
        external_reference: 0x13,
        sandboxed_api_reference: 0x14,
        sandboxed_external_reference: 0x15,
        internal_reference: 0x16,
        cleared_weak_reference: 0x17,
        weak_prefix: 0x18,
        off_heap_target: 0x19,
        register_pending_forward_ref: 0x1A,
        resolve_pending_forward_ref: 0x1B,
        new_meta_map: 0x1C,
        code_body: 0x1D,
        api_wrapper_fields_data: ABSENT,
        raw_external_reference: ABSENT,
        sandboxed_raw_external_reference: ABSENT,
        new_contextless_meta_map: ABSENT,
        new_contextful_meta_map: ABSENT,
        indirect_pointer_prefix: ABSENT,
        initialize_self_indirect_pointer: ABSENT,
        allocate_js_dispatch_entry: ABSENT,
        js_dispatch_entry: ABSENT,
        protected_pointer_prefix: ABSENT,
    };

    const V8_11_3: Self = Self {
        backref: 0x03,
        read_only_heap_ref: 0x04,
        startup_object_cache: 0x05,
        root_array: 0x06,
        attached_reference: 0x07,
        read_only_object_cache: 0x08,
        shared_heap_object_cache: 0x09,
        nop: 0x0A,
        synchronize: 0x0B,
        variable_repeat: 0x0C,
        off_heap_backing_store: 0x0D,
        off_heap_resizable_backing_store: 0x0E,
        embedder_fields_data: 0x0F,
        variable_raw_data: 0x10,
        api_reference: 0x11,
        external_reference: 0x12,
        raw_external_reference: 0x13,
        sandboxed_api_reference: 0x14,
        sandboxed_external_reference: 0x15,
        sandboxed_raw_external_reference: 0x16,
        internal_reference: 0x17,
        cleared_weak_reference: 0x18,
        weak_prefix: 0x19,
        off_heap_target: 0x1A,
        register_pending_forward_ref: 0x1B,
        resolve_pending_forward_ref: 0x1C,
        new_meta_map: 0x1D,
        code_body: 0x1E,
        api_wrapper_fields_data: ABSENT,
        new_contextless_meta_map: ABSENT,
        new_contextful_meta_map: ABSENT,
        indirect_pointer_prefix: ABSENT,
        initialize_self_indirect_pointer: ABSENT,
        allocate_js_dispatch_entry: ABSENT,
        js_dispatch_entry: ABSENT,
        protected_pointer_prefix: ABSENT,
    };

    const V8_12_4: Self = Self {
        backref: 0x04,
        read_only_heap_ref: 0x05,
        startup_object_cache: 0x06,
        root_array: 0x07,
        attached_reference: 0x08,
        shared_heap_object_cache: 0x09,
        nop: 0x0A,
        synchronize: 0x0B,
        variable_repeat: 0x0C,
        off_heap_backing_store: 0x0D,
        off_heap_resizable_backing_store: 0x0E,
        embedder_fields_data: 0x0F,
        variable_raw_data: 0x10,
        api_reference: 0x11,
        external_reference: 0x12,
        sandboxed_api_reference: 0x13,
        sandboxed_external_reference: 0x14,
        sandboxed_raw_external_reference: 0x15,
        cleared_weak_reference: 0x16,
        weak_prefix: 0x17,
        register_pending_forward_ref: 0x18,
        resolve_pending_forward_ref: 0x19,
        new_contextless_meta_map: 0x1A,
        new_contextful_meta_map: 0x1B,
        indirect_pointer_prefix: 0x1C,
        initialize_self_indirect_pointer: 0x1D,
        protected_pointer_prefix: 0x1E,
        read_only_object_cache: ABSENT,
        api_wrapper_fields_data: ABSENT,
        raw_external_reference: ABSENT,
        internal_reference: ABSENT,
        off_heap_target: ABSENT,
        new_meta_map: ABSENT,
        allocate_js_dispatch_entry: ABSENT,
        js_dispatch_entry: ABSENT,
        code_body: ABSENT,
    };

    const V8_13_6: Self = Self {
        backref: 0x04,
        read_only_heap_ref: 0x05,
        startup_object_cache: 0x06,
        root_array: 0x07,
        attached_reference: 0x08,
        shared_heap_object_cache: 0x09,
        nop: 0x0A,
        synchronize: 0x0B,
        variable_repeat: 0x0C,
        off_heap_backing_store: 0x0D,
        off_heap_resizable_backing_store: 0x0E,
        embedder_fields_data: 0x0F,
        api_wrapper_fields_data: 0x10,
        variable_raw_data: 0x11,
        api_reference: 0x12,
        external_reference: 0x13,
        sandboxed_api_reference: 0x14,
        sandboxed_external_reference: 0x15,
        sandboxed_raw_external_reference: 0x16,
        cleared_weak_reference: 0x17,
        weak_prefix: 0x18,
        register_pending_forward_ref: 0x19,
        resolve_pending_forward_ref: 0x1A,
        new_contextless_meta_map: 0x1B,
        new_contextful_meta_map: 0x1C,
        indirect_pointer_prefix: 0x1D,
        initialize_self_indirect_pointer: 0x1E,
        allocate_js_dispatch_entry: 0x1F,
        js_dispatch_entry: 0x20,
        protected_pointer_prefix: 0x21,
        read_only_object_cache: ABSENT,
        raw_external_reference: ABSENT,
        internal_reference: ABSENT,
        off_heap_target: ABSENT,
        new_meta_map: ABSENT,
        code_body: ABSENT,
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SerializerBuild {
    NoCompressionNoSandbox,
}

impl SerializerBuild {
    #[must_use]
    pub const fn for_node(node: NodeVersion) -> Option<Self> {
        match node {
            NodeVersion::Node18
            | NodeVersion::Node20
            | NodeVersion::Node22
            | NodeVersion::Node24 => Some(Self::NoCompressionNoSandbox),
            NodeVersion::Unknown => None,
        }
    }

    #[must_use]
    pub const fn tagged_size(self) -> usize {
        match self {
            Self::NoCompressionNoSandbox => TAGGED_SIZE_NO_COMPRESSION,
        }
    }
}

#[must_use]
pub const fn return_opcode_for(node: NodeVersion) -> u8 {
    match node {
        NodeVersion::Node18 | NodeVersion::Node20 => 0xA9u8,
        NodeVersion::Node22 => 0xAEu8,
        NodeVersion::Node24 | NodeVersion::Unknown => 0xB3u8,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum ConstantPoolEntry {
    InlineString {
        value: String,
    },
    BuiltinName {
        name: String,
        root_index: Option<u32>,
    },
    InnerFunction {
        object_index: usize,
    },
    RootIndex {
        root_index: u32,
    },
    ReadOnlyHeap {
        chunk: u32,
        offset: u32,
    },
    NestedArray {
        object_index: usize,
    },
    Other {
        object_index: usize,
    },
}

impl ConstantPoolEntry {
    #[must_use]
    pub const fn as_inline_string(&self) -> Option<&str> {
        match self {
            Self::InlineString { value } => Some(value.as_str()),
            _ => None,
        }
    }

    #[must_use]
    pub const fn resolved_name(&self) -> Option<&str> {
        match self {
            Self::InlineString { value } => Some(value.as_str()),
            Self::BuiltinName { name, .. } => Some(name.as_str()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredBytecodeArray {
    pub bytecode_file_offset: usize,
    pub frame_size: i32,
    pub parameter_count: u16,
    pub max_arguments: u16,
    pub incoming_new_target_or_generator_register: i32,
    pub bytecode: Vec<u8>,
    pub serialized_object_index: usize,
    pub constant_pool: Vec<ConstantPoolEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeSerializerGraph {
    pub node_version: NodeVersion,
    pub build: SerializerBuild,
    pub object_count: usize,
    pub bytes_consumed: usize,
    pub payload_length: usize,
    pub bytecode_arrays: Vec<RecoveredBytecodeArray>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawRun {
    payload_offset: usize,
    bytes: Vec<u8>,
    owner_object_index: usize,
    slot_index: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChildRef {
    Object(usize),
    Root(u32),
    ReadOnlyHeap { chunk: u32, offset: u32 },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ObjectRecord {
    children: Vec<ChildRef>,
}

struct Cursor<'a> {
    payload: &'a [u8],
    payload_base_in_file: usize,
    pos: usize,
    tagged_size: usize,
    ops: SerializerOpcodes,
    object_index: usize,
    runs: Vec<RawRun>,
    depth: usize,
    records: BTreeMap<usize, ObjectRecord>,
    open_objects: Vec<usize>,
}

const MAX_RECURSION_DEPTH: usize = 256usize;

impl Cursor<'_> {
    const fn file_offset(&self) -> usize {
        self.payload_base_in_file.saturating_add(self.pos)
    }

    fn read_byte(&mut self) -> Result<u8> {
        let Some(&byte): Option<&u8> = self.payload.get(self.pos) else {
            return Err(Error::OxcParse(format!(
                "v8 code-serializer stream truncated reading opcode at payload offset {}",
                self.pos
            )));
        };
        self.pos = self.pos.saturating_add(1usize);
        Ok(byte)
    }

    fn read_uint30(&mut self) -> Result<u32> {
        let first: u8 = *self.payload.get(self.pos).ok_or_else(|| {
            Error::OxcParse(format!(
                "v8 code-serializer uint30 truncated at payload offset {}",
                self.pos
            ))
        })?;
        let byte_count: usize = (first as usize & 0b11usize) + 1usize;
        let end: usize = self.pos.checked_add(byte_count).ok_or_else(|| {
            Error::OxcParse("v8 code-serializer uint30 length overflow".to_owned())
        })?;
        let slice: &[u8] = self.payload.get(self.pos..end).ok_or_else(|| {
            Error::OxcParse(format!(
                "v8 code-serializer uint30 ({byte_count} bytes) past end at payload offset {}",
                self.pos
            ))
        })?;
        let mut assembled: u32 = 0u32;
        for (i, &b) in slice.iter().enumerate() {
            assembled |= u32::from(b) << (8u32 * u32::try_from(i).unwrap_or(0u32));
        }
        self.pos = end;
        let shift: u32 = u32::try_from(byte_count)
            .unwrap_or(1u32)
            .saturating_mul(8u32);
        let mask: u32 = if shift >= 32u32 {
            u32::MAX
        } else {
            (1u32 << shift) - 1u32
        };
        Ok((assembled & mask) >> 2u32)
    }

    fn read_uint32(&mut self) -> Result<u32> {
        let end: usize = self
            .pos
            .checked_add(4usize)
            .ok_or_else(|| Error::OxcParse("v8 code-serializer uint32 overflow".to_owned()))?;
        let slice: &[u8] = self.payload.get(self.pos..end).ok_or_else(|| {
            Error::OxcParse(format!(
                "v8 code-serializer uint32 past end at payload offset {}",
                self.pos
            ))
        })?;
        let value: u32 = u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]);
        self.pos = end;
        Ok(value)
    }

    fn take_raw(&mut self, byte_len: usize) -> Result<(usize, Vec<u8>)> {
        let start: usize = self.pos;
        let end: usize = start.checked_add(byte_len).ok_or_else(|| {
            Error::OxcParse("v8 code-serializer raw-data length overflow".to_owned())
        })?;
        let slice: &[u8] = self.payload.get(start..end).ok_or_else(|| {
            Error::OxcParse(format!(
                "v8 code-serializer raw-data ({byte_len} bytes) past end at payload offset {start}"
            ))
        })?;
        let bytes: Vec<u8> = slice.to_vec();
        self.pos = end;
        Ok((start, bytes))
    }

    fn record_child(&mut self, child: ChildRef) {
        if let Some(&owner) = self.open_objects.last() {
            self.records.entry(owner).or_default().children.push(child);
        }
    }

    fn read_reference(&mut self) -> Result<()> {
        if self.depth >= MAX_RECURSION_DEPTH {
            return Err(Error::OxcParse(
                "v8 code-serializer object graph nests past the recursion guard".to_owned(),
            ));
        }
        let opcode: u8 = self.read_byte()?;
        let ops: SerializerOpcodes = self.ops;
        if ops.is_new_object(opcode) {
            let size_in_tagged: u32 = self.read_uint30()?;
            let new_index: usize = self.object_index.saturating_add(1usize);
            self.record_child(ChildRef::Object(new_index));
            return self.read_object(size_in_tagged);
        }
        if opcode == ops.backref {
            let index: u32 = self.read_uint30()?;
            self.record_child(ChildRef::Object(index as usize));
            return Ok(());
        }
        if opcode == ops.root_array {
            let index: u32 = self.read_uint30()?;
            self.record_child(ChildRef::Root(index));
            return Ok(());
        }
        if opcode == ops.startup_object_cache
            || opcode == ops.shared_heap_object_cache
            || opcode == ops.attached_reference
            || matches_present(opcode, ops.read_only_object_cache)
        {
            let _index: u32 = self.read_uint30()?;
            return Ok(());
        }
        if opcode == ops.read_only_heap_ref {
            let chunk: u32 = self.read_uint30()?;
            let offset: u32 = self.read_uint30()?;
            self.record_child(ChildRef::ReadOnlyHeap { chunk, offset });
            return Ok(());
        }
        if (BC_ROOT_ARRAY_CONSTANTS_LO..=BC_ROOT_ARRAY_CONSTANTS_HI).contains(&opcode) {
            self.record_child(ChildRef::Root(u32::from(
                opcode - BC_ROOT_ARRAY_CONSTANTS_LO,
            )));
            return Ok(());
        }
        if (BC_HOT_OBJECT_LO..=BC_HOT_OBJECT_HI).contains(&opcode)
            || opcode == ops.cleared_weak_reference
        {
            return Ok(());
        }
        if matches_present(opcode, ops.new_contextless_meta_map)
            || matches_present(opcode, ops.new_contextful_meta_map)
            || matches_present(opcode, ops.new_meta_map)
        {
            self.register_meta_map();
            return Ok(());
        }
        if matches_present(opcode, ops.protected_pointer_prefix)
            || matches_present(opcode, ops.indirect_pointer_prefix)
            || opcode == ops.weak_prefix
        {
            return self.read_reference();
        }
        Err(Error::OxcParse(format!(
            "v8 code-serializer map/reference position holds unexpected opcode 0x{opcode:02X} \
             at file offset {}",
            self.file_offset()
        )))
    }

    fn read_slot(&mut self, owner_index: usize, slot_index: usize) -> Result<u32> {
        let opcode: u8 = self.read_byte()?;
        let ops: SerializerOpcodes = self.ops;
        if (BC_FIXED_RAW_DATA_LO..=BC_FIXED_RAW_DATA_HI).contains(&opcode) {
            let tagged_words: usize = (opcode - BC_FIXED_RAW_DATA_LO) as usize + 1usize;
            let byte_len: usize = tagged_words.saturating_mul(self.tagged_size);
            let (offset, bytes): (usize, Vec<u8>) = self.take_raw(byte_len)?;
            self.runs.push(RawRun {
                payload_offset: offset,
                bytes,
                owner_object_index: owner_index,
                slot_index,
            });
            return Ok(u32::try_from(tagged_words).unwrap_or(u32::MAX));
        }
        if opcode == ops.variable_raw_data {
            let tagged_words: u32 = self.read_uint30()?;
            let byte_len: usize = (tagged_words as usize).saturating_mul(self.tagged_size);
            let (offset, bytes): (usize, Vec<u8>) = self.take_raw(byte_len)?;
            self.runs.push(RawRun {
                payload_offset: offset,
                bytes,
                owner_object_index: owner_index,
                slot_index,
            });
            return Ok(tagged_words);
        }
        if (BC_FIXED_REPEAT_ROOT_LO..=BC_FIXED_REPEAT_ROOT_HI).contains(&opcode) {
            let count: u32 =
                u32::from(opcode - BC_FIXED_REPEAT_ROOT_LO) + FIXED_REPEAT_ROOT_MIN_COUNT;
            let _root_index: u8 = self.read_byte()?;
            return Ok(count);
        }
        if opcode == ops.variable_repeat {
            let count: u32 = self
                .read_uint30()?
                .saturating_add(VARIABLE_REPEAT_ROOT_MIN_COUNT);
            let _root_index: u8 = self.read_byte()?;
            return Ok(count);
        }
        if (BC_ROOT_ARRAY_CONSTANTS_LO..=BC_ROOT_ARRAY_CONSTANTS_HI).contains(&opcode) {
            self.record_child(ChildRef::Root(u32::from(
                opcode - BC_ROOT_ARRAY_CONSTANTS_LO,
            )));
            return Ok(1u32);
        }
        if (BC_HOT_OBJECT_LO..=BC_HOT_OBJECT_HI).contains(&opcode)
            || matches_present(opcode, ops.initialize_self_indirect_pointer)
            || opcode == ops.cleared_weak_reference
            || opcode == ops.register_pending_forward_ref
        {
            return Ok(1u32);
        }
        if ops.is_new_object(opcode) {
            let size_in_tagged: u32 = self.read_uint30()?;
            let new_index: usize = self.object_index.saturating_add(1usize);
            self.record_child(ChildRef::Object(new_index));
            self.read_object(size_in_tagged)?;
            return Ok(1u32);
        }
        if opcode == ops.backref {
            let index: u32 = self.read_uint30()?;
            self.record_child(ChildRef::Object(index as usize));
            return Ok(1u32);
        }
        if opcode == ops.root_array {
            let index: u32 = self.read_uint30()?;
            self.record_child(ChildRef::Root(index));
            return Ok(1u32);
        }
        if opcode == ops.startup_object_cache
            || opcode == ops.shared_heap_object_cache
            || opcode == ops.attached_reference
            || matches_present(opcode, ops.read_only_object_cache)
        {
            let _index: u32 = self.read_uint30()?;
            return Ok(1u32);
        }
        if opcode == ops.read_only_heap_ref {
            let chunk: u32 = self.read_uint30()?;
            let offset: u32 = self.read_uint30()?;
            self.record_child(ChildRef::ReadOnlyHeap { chunk, offset });
            return Ok(1u32);
        }
        if matches_present(opcode, ops.new_contextless_meta_map)
            || matches_present(opcode, ops.new_contextful_meta_map)
            || matches_present(opcode, ops.new_meta_map)
        {
            self.register_meta_map();
            return Ok(1u32);
        }
        if matches_present(opcode, ops.protected_pointer_prefix)
            || matches_present(opcode, ops.indirect_pointer_prefix)
            || opcode == ops.weak_prefix
            || opcode == ops.nop
            || opcode == ops.synchronize
        {
            return Ok(0u32);
        }
        if opcode == ops.resolve_pending_forward_ref {
            let _index: u32 = self.read_uint30()?;
            return Ok(0u32);
        }
        if opcode == ops.external_reference || opcode == ops.api_reference {
            let _index: u32 = self.read_uint30()?;
            return Ok(self.pointer_slots());
        }
        if matches_present(opcode, ops.raw_external_reference)
            || matches_present(opcode, ops.internal_reference)
            || matches_present(opcode, ops.off_heap_target)
        {
            let _value: u32 = self.read_uint30()?;
            return Ok(self.pointer_slots());
        }
        if opcode == ops.sandboxed_external_reference || opcode == ops.sandboxed_api_reference {
            let _index: u32 = self.read_uint30()?;
            let _tag: u32 = self.read_uint30()?;
            return Ok(self.pointer_slots());
        }
        if matches_present(opcode, ops.sandboxed_raw_external_reference) {
            let _raw: (usize, Vec<u8>) = self.take_raw(SYSTEM_POINTER_SIZE)?;
            let _tag: u32 = self.read_uint30()?;
            return Ok(self.pointer_slots());
        }
        if opcode == ops.off_heap_backing_store {
            let byte_len: u32 = self.read_uint32()?;
            let _raw: (usize, Vec<u8>) = self.take_raw(byte_len as usize)?;
            return Ok(0u32);
        }
        if opcode == ops.off_heap_resizable_backing_store {
            let byte_len: u32 = self.read_uint32()?;
            let _max: u32 = self.read_uint32()?;
            let _raw: (usize, Vec<u8>) = self.take_raw(byte_len as usize)?;
            return Ok(0u32);
        }
        if matches_present(opcode, ops.allocate_js_dispatch_entry) {
            let _entries: u32 = self.read_uint30()?;
            let _parameter_count: u32 = self.read_uint30()?;
            return Ok(self.pointer_slots());
        }
        if matches_present(opcode, ops.js_dispatch_entry) {
            let _index: u32 = self.read_uint30()?;
            return Ok(self.pointer_slots());
        }
        if matches_present(opcode, ops.embedder_fields_data) {
            return Err(Error::OxcParse(format!(
                "v8 code-serializer slot at file offset {} is an EmbedderFieldsData record \
                 (embedder-allocated internal fields); its per-field embedder payload layout is \
                 not decoded",
                self.file_offset()
            )));
        }
        if matches_present(opcode, ops.api_wrapper_fields_data) {
            return Err(Error::OxcParse(format!(
                "v8 code-serializer slot at file offset {} is an ApiWrapperFieldsData record; its \
                 cpp-heap wrapper field layout is not decoded",
                self.file_offset()
            )));
        }
        if matches_present(opcode, ops.code_body) {
            return Err(Error::OxcParse(format!(
                "v8 code-serializer slot at file offset {} is a CodeBody record (serialized \
                 InstructionStream); its reloc-info body layout is not decoded",
                self.file_offset()
            )));
        }
        Err(Error::OxcParse(format!(
            "v8 code-serializer slot holds unexpected opcode 0x{opcode:02X} at file offset {} \
             (owner object {owner_index} slot {slot_index})",
            self.file_offset()
        )))
    }

    const fn pointer_slots(&self) -> u32 {
        let slots: usize = SYSTEM_POINTER_SIZE / self.tagged_size;
        if slots > u32::MAX as usize {
            u32::MAX
        } else {
            slots as u32
        }
    }

    const fn register_meta_map(&mut self) {
        self.object_index = self.object_index.saturating_add(1usize);
    }

    fn read_object(&mut self, size_in_tagged: u32) -> Result<()> {
        if self.object_index >= MAX_DESERIALIZE_OBJECTS {
            return Err(Error::OxcParse(
                "v8 code-serializer object count exceeds the deserialize guard".to_owned(),
            ));
        }
        self.object_index = self.object_index.saturating_add(1usize);
        let owner_index: usize = self.object_index;
        self.records.entry(owner_index).or_default();
        self.depth = self.depth.saturating_add(1usize);
        self.read_map_slot()?;
        self.open_objects.push(owner_index);
        let mut current: u32 = 1u32;
        while current < size_in_tagged {
            let advance: u32 = self.read_slot(owner_index, current as usize)?;
            current = current.saturating_add(advance);
        }
        self.open_objects.pop();
        if current != size_in_tagged {
            self.depth = self.depth.saturating_sub(1usize);
            return Err(Error::OxcParse(format!(
                "v8 code-serializer object {owner_index} overshot its declared size: filled \
                 {current} tagged slots, declared {size_in_tagged}"
            )));
        }
        self.depth = self.depth.saturating_sub(1usize);
        Ok(())
    }

    fn read_map_slot(&mut self) -> Result<()> {
        if self.depth >= MAX_RECURSION_DEPTH {
            return Err(Error::OxcParse(
                "v8 code-serializer object graph nests past the recursion guard".to_owned(),
            ));
        }
        let opcode: u8 = self.read_byte()?;
        let ops: SerializerOpcodes = self.ops;
        if ops.is_new_object(opcode) {
            let size_in_tagged: u32 = self.read_uint30()?;
            return self.read_object(size_in_tagged);
        }
        if opcode == ops.backref
            || opcode == ops.startup_object_cache
            || opcode == ops.shared_heap_object_cache
            || opcode == ops.attached_reference
            || matches_present(opcode, ops.read_only_object_cache)
        {
            let _index: u32 = self.read_uint30()?;
            return Ok(());
        }
        if opcode == ops.root_array {
            let _index: u32 = self.read_uint30()?;
            return Ok(());
        }
        if opcode == ops.read_only_heap_ref {
            let _chunk: u32 = self.read_uint30()?;
            let _offset: u32 = self.read_uint30()?;
            return Ok(());
        }
        if (BC_ROOT_ARRAY_CONSTANTS_LO..=BC_ROOT_ARRAY_CONSTANTS_HI).contains(&opcode) {
            return Ok(());
        }
        if (BC_HOT_OBJECT_LO..=BC_HOT_OBJECT_HI).contains(&opcode)
            || opcode == ops.cleared_weak_reference
        {
            return Ok(());
        }
        if matches_present(opcode, ops.new_contextless_meta_map)
            || matches_present(opcode, ops.new_contextful_meta_map)
            || matches_present(opcode, ops.new_meta_map)
        {
            self.register_meta_map();
            return Ok(());
        }
        if matches_present(opcode, ops.protected_pointer_prefix)
            || matches_present(opcode, ops.indirect_pointer_prefix)
            || opcode == ops.weak_prefix
        {
            return self.read_map_slot();
        }
        Err(Error::OxcParse(format!(
            "v8 code-serializer map position holds unexpected opcode 0x{opcode:02X} \
             at file offset {}",
            self.file_offset()
        )))
    }
}

const fn matches_present(opcode: u8, slot: u8) -> bool {
    slot != ABSENT && opcode == slot
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BytecodeArrayLayout {
    pub header_size: usize,
    pub parameter_field_is_size_in_bytes: bool,
    pub has_max_arguments: bool,
}

impl BytecodeArrayLayout {
    #[must_use]
    pub const fn for_node(node: NodeVersion) -> Self {
        match node {
            NodeVersion::Node18 | NodeVersion::Node22 => Self {
                header_size: 16usize,
                parameter_field_is_size_in_bytes: true,
                has_max_arguments: false,
            },
            NodeVersion::Node20 => Self {
                header_size: 14usize,
                parameter_field_is_size_in_bytes: true,
                has_max_arguments: false,
            },
            NodeVersion::Node24 | NodeVersion::Unknown => Self {
                header_size: BYTECODE_ARRAY_SCALAR_HEADER,
                parameter_field_is_size_in_bytes: false,
                has_max_arguments: true,
            },
        }
    }
}

#[must_use]
pub fn recover_bytecode_array_from_run(
    run_bytes: &[u8],
    tagged_size: usize,
) -> Option<RawBytecodeView> {
    recover_bytecode_array_with_layout(
        run_bytes,
        tagged_size,
        BytecodeArrayLayout::for_node(NodeVersion::Node24),
    )
}

#[must_use]
pub fn recover_bytecode_array_with_layout(
    run_bytes: &[u8],
    tagged_size: usize,
    layout: BytecodeArrayLayout,
) -> Option<RawBytecodeView> {
    let header_size: usize = layout.header_size;
    let header: &[u8] = run_bytes.get(..header_size)?;
    if run_bytes.len() <= header_size {
        return None;
    }
    let frame_size: i32 = i32::from_le_bytes(header.get(0usize..4usize)?.try_into().ok()?);
    let (parameter_count, max_arguments): (u16, u16) = if layout.parameter_field_is_size_in_bytes {
        let parameter_size: i32 = i32::from_le_bytes(header.get(4usize..8usize)?.try_into().ok()?);
        if parameter_size < 0i32 {
            return None;
        }
        let size: usize = parameter_size as usize;
        if size == 0usize || !size.is_multiple_of(SYSTEM_POINTER_SIZE) {
            return None;
        }
        (u16::try_from(size / SYSTEM_POINTER_SIZE).ok()?, 0u16)
    } else {
        let parameter_count: u16 = u16::from_le_bytes(header.get(4usize..6usize)?.try_into().ok()?);
        let max_arguments: u16 = u16::from_le_bytes(header.get(6usize..8usize)?.try_into().ok()?);
        (parameter_count, max_arguments)
    };
    let incoming: i32 = i32::from_le_bytes(header.get(8usize..12usize)?.try_into().ok()?);
    if layout.has_max_arguments && header_size >= 16usize {
        let alignment_pad: u32 = u32::from_le_bytes(header.get(12usize..16usize)?.try_into().ok()?);
        if alignment_pad != 0u32 {
            return None;
        }
    }
    if !(0i32..=MAX_FRAME_SIZE).contains(&frame_size) {
        return None;
    }
    if parameter_count == 0u16 {
        return None;
    }
    let mut end: usize = run_bytes.len();
    while end > header_size && run_bytes.get(end - 1usize) == Some(&0u8) {
        end -= 1usize;
    }
    if end <= header_size {
        return None;
    }
    let trailing_pad: usize = run_bytes.len().saturating_sub(end);
    if trailing_pad >= tagged_size {
        return None;
    }
    let bytecode: Vec<u8> = run_bytes.get(header_size..end)?.to_vec();
    Some(RawBytecodeView {
        frame_size,
        parameter_count,
        max_arguments,
        incoming_new_target_or_generator_register: incoming,
        bytecode,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawBytecodeView {
    pub frame_size: i32,
    pub parameter_count: u16,
    pub max_arguments: u16,
    pub incoming_new_target_or_generator_register: i32,
    pub bytecode: Vec<u8>,
}

fn decode_string_from_run(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 8usize {
        return None;
    }
    let length: u32 = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let len: usize = length as usize;
    if len == 0usize || len > MAX_STRING_BODY {
        return None;
    }
    let chars: &[u8] = bytes.get(8usize..8usize.checked_add(len)?)?;
    let printable: bool = chars
        .iter()
        .all(|&b: &u8| matches!(b, 0x09u8..=0x0Du8 | 0x20u8..=0x7Eu8));
    if !printable {
        return None;
    }
    let tail: &[u8] = bytes.get(8usize.saturating_add(len)..).unwrap_or(&[]);
    if !tail.iter().all(|&b: &u8| b == 0u8) {
        return None;
    }
    Some(chars.iter().map(|&b: &u8| b as char).collect())
}

const MAX_STRING_BODY: usize = 1usize << 20usize;

fn decode_strings_by_object(runs: &[RawRun]) -> BTreeMap<usize, String> {
    let mut out: BTreeMap<usize, String> = BTreeMap::new();
    for run in runs {
        if let Some(value) = decode_string_from_run(&run.bytes) {
            out.entry(run.owner_object_index).or_insert(value);
        }
    }
    out
}

fn child_to_entry(
    child: ChildRef,
    roots: Option<RootNameTable>,
    records: &BTreeMap<usize, ObjectRecord>,
    strings: &BTreeMap<usize, String>,
) -> ConstantPoolEntry {
    match child {
        ChildRef::Root(root_index) => roots
            .and_then(|t: RootNameTable| t.root_name(root_index))
            .map_or(ConstantPoolEntry::RootIndex { root_index }, |name: &str| {
                ConstantPoolEntry::BuiltinName {
                    name: name.to_owned(),
                    root_index: Some(root_index),
                }
            }),
        ChildRef::ReadOnlyHeap { chunk, offset } => roots
            .and_then(|t: RootNameTable| t.read_only_heap_name(chunk, offset))
            .map_or(
                ConstantPoolEntry::ReadOnlyHeap { chunk, offset },
                |name: &str| ConstantPoolEntry::BuiltinName {
                    name: name.to_owned(),
                    root_index: None,
                },
            ),
        ChildRef::Object(object_index) => object_to_entry(object_index, records, strings),
    }
}

fn object_to_entry(
    object_index: usize,
    records: &BTreeMap<usize, ObjectRecord>,
    strings: &BTreeMap<usize, String>,
) -> ConstantPoolEntry {
    if let Some(value) = strings.get(&object_index) {
        return ConstantPoolEntry::InlineString {
            value: value.clone(),
        };
    }
    if object_holds_bytecode(object_index, records, strings) {
        return ConstantPoolEntry::InnerFunction { object_index };
    }
    if is_fixed_array(object_index, records) {
        return ConstantPoolEntry::NestedArray { object_index };
    }
    ConstantPoolEntry::Other { object_index }
}

fn object_holds_bytecode(
    object_index: usize,
    records: &BTreeMap<usize, ObjectRecord>,
    strings: &BTreeMap<usize, String>,
) -> bool {
    let Some(record): Option<&ObjectRecord> = records.get(&object_index) else {
        return false;
    };
    record.children.iter().any(|c: &ChildRef| match c {
        ChildRef::Object(inner) => !strings.contains_key(inner) && is_fixed_array(*inner, records),
        _ => false,
    })
}

fn is_fixed_array(object_index: usize, records: &BTreeMap<usize, ObjectRecord>) -> bool {
    records
        .get(&object_index)
        .is_some_and(|r: &ObjectRecord| !r.children.is_empty())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PoolSlotDemand {
    index: u32,
    requires_name: bool,
}

fn pool_slot_demands(bytecode: &[u8], node: NodeVersion) -> Vec<PoolSlotDemand> {
    let disasm: Disassembly = disassemble(bytecode, node);
    let mut demands: Vec<PoolSlotDemand> = Vec::new();
    for ins in &disasm.instructions {
        let requires_name: bool = matches!(
            ins.mnemonic,
            "LdaGlobal"
                | "LdaGlobalInsideTypeof"
                | "StaGlobal"
                | "GetNamedProperty"
                | "GetNamedPropertyFromSuper"
                | "SetNamedProperty"
                | "DefineNamedOwnProperty"
        );
        let slot: Option<u32> = match ins.mnemonic {
            "LdaConstant" | "LdaGlobal" | "LdaGlobalInsideTypeof" | "StaGlobal" => ins
                .operands
                .first()
                .map(|o: &DecodedOperand| o.unsigned_value as u32),
            "GetNamedProperty"
            | "GetNamedPropertyFromSuper"
            | "SetNamedProperty"
            | "DefineNamedOwnProperty" => ins
                .operands
                .get(1usize)
                .map(|o: &DecodedOperand| o.unsigned_value as u32),
            _ => None,
        };
        if let Some(index) = slot {
            demands.push(PoolSlotDemand {
                index,
                requires_name,
            });
        }
    }
    demands
}

fn resolve_constant_pool(
    bytecode_owner: usize,
    bytecode: &[u8],
    node: NodeVersion,
    records: &BTreeMap<usize, ObjectRecord>,
    strings: &BTreeMap<usize, String>,
) -> Vec<ConstantPoolEntry> {
    let Some(owner): Option<&ObjectRecord> = records.get(&bytecode_owner) else {
        return Vec::new();
    };
    let roots: Option<RootNameTable> = RootNameTable::for_node(node);
    let demands: Vec<PoolSlotDemand> = pool_slot_demands(bytecode, node);
    let Some(pool_index): Option<usize> =
        pick_constant_pool(owner, &demands, roots, records, strings)
    else {
        return Vec::new();
    };
    let Some(pool): Option<&ObjectRecord> = records.get(&pool_index) else {
        return Vec::new();
    };
    pool.children
        .iter()
        .map(|&c: &ChildRef| child_to_entry(c, roots, records, strings))
        .collect()
}

fn pick_constant_pool(
    owner: &ObjectRecord,
    demands: &[PoolSlotDemand],
    roots: Option<RootNameTable>,
    records: &BTreeMap<usize, ObjectRecord>,
    strings: &BTreeMap<usize, String>,
) -> Option<usize> {
    let mut best: Option<(usize, usize)> = None;
    for child in &owner.children {
        let ChildRef::Object(idx): &ChildRef = child else {
            continue;
        };
        if strings.contains_key(idx) {
            continue;
        }
        let Some(record): Option<&ObjectRecord> = records.get(idx) else {
            continue;
        };
        let entries: Vec<ConstantPoolEntry> = record
            .children
            .iter()
            .map(|&c: &ChildRef| child_to_entry(c, roots, records, strings))
            .collect();
        if entries.is_empty() || !pool_satisfies_demands(&entries, demands) {
            continue;
        }
        let take: bool = best.is_none_or(|(_, score): (usize, usize)| entries.len() > score);
        if take {
            best = Some((*idx, entries.len()));
        }
    }
    best.map(|(idx, _): (usize, usize)| idx)
}

fn pool_satisfies_demands(entries: &[ConstantPoolEntry], demands: &[PoolSlotDemand]) -> bool {
    for demand in demands {
        let Some(entry): Option<&ConstantPoolEntry> = entries.get(demand.index as usize) else {
            return false;
        };
        if demand.requires_name
            && !matches!(
                entry,
                ConstantPoolEntry::InlineString { .. }
                    | ConstantPoolEntry::BuiltinName { .. }
                    | ConstantPoolEntry::RootIndex { .. }
                    | ConstantPoolEntry::ReadOnlyHeap { .. }
            )
        {
            return false;
        }
    }
    true
}

pub fn parse_code_serializer_graph(body: &BytenodeCacheBody) -> Result<CodeSerializerGraph> {
    let node: NodeVersion = body.header.version_hash.node;
    let Some(build): Option<SerializerBuild> = SerializerBuild::for_node(node) else {
        return Err(Error::OxcParse(format!(
            "v8 code-serializer object-graph parse covers the node 18/20/22/24 stream encodings \
             (v8 10.2 / 11.3 / 12.4 / 13.6); this artifact is {}, whose v8 serializer opcode \
             numbering is not mapped",
            node.label()
        )));
    };
    let tagged_size: usize = build.tagged_size();
    let ops: SerializerOpcodes = SerializerOpcodes::for_node(node);
    let return_opcode: u8 = return_opcode_for(node);
    let mut cursor: Cursor<'_> = Cursor {
        payload: &body.payload,
        payload_base_in_file: body.payload_offset,
        pos: 0usize,
        tagged_size,
        ops,
        object_index: 0usize,
        runs: Vec::new(),
        depth: 0usize,
        records: BTreeMap::new(),
        open_objects: Vec::new(),
    };
    cursor.read_reference()?;
    loop {
        let opcode: u8 = cursor.read_byte()?;
        if opcode == ops.synchronize {
            break;
        }
        if !ops.is_new_object(opcode) {
            return Err(Error::OxcParse(format!(
                "v8 code-serializer deferred section expected a new-object opcode, got 0x{opcode:02X} \
                 at file offset {}",
                cursor.file_offset()
            )));
        }
        let size_in_tagged: u32 = cursor.read_uint30()?;
        cursor.read_object(size_in_tagged)?;
    }
    let bytes_consumed: usize = cursor.pos;
    let object_count: usize = cursor.object_index;
    let layout: BytecodeArrayLayout = BytecodeArrayLayout::for_node(node);
    let strings_by_object: BTreeMap<usize, String> = decode_strings_by_object(&cursor.runs);
    let mut bytecode_arrays: Vec<RecoveredBytecodeArray> = Vec::new();
    for run in &cursor.runs {
        let Some(view): Option<RawBytecodeView> =
            recover_bytecode_array_with_layout(&run.bytes, tagged_size, layout)
        else {
            continue;
        };
        if view.bytecode.last() != Some(&return_opcode) {
            continue;
        }
        let constant_pool: Vec<ConstantPoolEntry> = resolve_constant_pool(
            run.owner_object_index,
            &view.bytecode,
            node,
            &cursor.records,
            &strings_by_object,
        );
        bytecode_arrays.push(RecoveredBytecodeArray {
            bytecode_file_offset: run.payload_offset.saturating_add(body.payload_offset)
                + layout.header_size,
            frame_size: view.frame_size,
            parameter_count: view.parameter_count,
            max_arguments: view.max_arguments,
            incoming_new_target_or_generator_register: view
                .incoming_new_target_or_generator_register,
            bytecode: view.bytecode,
            serialized_object_index: run.owner_object_index,
            constant_pool,
        });
    }
    Ok(CodeSerializerGraph {
        node_version: node,
        build,
        object_count,
        bytes_consumed,
        payload_length: body.payload.len(),
        bytecode_arrays,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn uint30_round_trips_one_byte_values() {
        let payload: Vec<u8> = vec![(5u32 << 2u32) as u8];
        let mut cursor: Cursor<'_> = test_cursor(&payload);
        assert_eq!(cursor.read_uint30().unwrap(), 5u32);
    }

    #[test]
    fn uint30_round_trips_multi_byte_values() {
        let value: u32 = 300u32;
        let shifted: u32 = (value << 2u32) | 1u32;
        let payload: Vec<u8> = vec![
            (shifted & 0xFFu32) as u8,
            ((shifted >> 8u32) & 0xFFu32) as u8,
        ];
        let mut cursor: Cursor<'_> = test_cursor(&payload);
        assert_eq!(cursor.read_uint30().unwrap(), 300u32);
    }

    fn test_cursor(payload: &[u8]) -> Cursor<'_> {
        Cursor {
            payload,
            payload_base_in_file: 0usize,
            pos: 0usize,
            tagged_size: TAGGED_SIZE_NO_COMPRESSION,
            ops: SerializerOpcodes::for_node(NodeVersion::Node24),
            object_index: 0usize,
            runs: Vec::new(),
            depth: 0usize,
            records: BTreeMap::new(),
            open_objects: Vec::new(),
        }
    }

    #[test]
    fn rejects_run_with_nonzero_alignment_padding() {
        let mut run: Vec<u8> = vec![0u8; 16];
        run[4] = 1u8;
        run[12] = 0xFFu8;
        run.push(0xB3u8);
        assert!(recover_bytecode_array_from_run(&run, TAGGED_SIZE_NO_COMPRESSION).is_none());
    }

    #[test]
    fn recovers_minimal_bytecode_run() {
        let mut run: Vec<u8> = Vec::new();
        run.extend_from_slice(&24i32.to_le_bytes());
        run.extend_from_slice(&2u16.to_le_bytes());
        run.extend_from_slice(&1u16.to_le_bytes());
        run.extend_from_slice(&0i32.to_le_bytes());
        run.extend_from_slice(&0u32.to_le_bytes());
        run.extend_from_slice(&[0x0Eu8, 0xB3u8]);
        run.extend_from_slice(&[0u8; 6]);
        let view: RawBytecodeView =
            recover_bytecode_array_from_run(&run, TAGGED_SIZE_NO_COMPRESSION).expect("recovered");
        assert_eq!(view.frame_size, 24i32);
        assert_eq!(view.parameter_count, 2u16);
        assert_eq!(view.bytecode, vec![0x0Eu8, 0xB3u8]);
    }

    #[test]
    fn rejects_zero_parameter_count() {
        let mut run: Vec<u8> = Vec::new();
        run.extend_from_slice(&0i32.to_le_bytes());
        run.extend_from_slice(&0u16.to_le_bytes());
        run.extend_from_slice(&0u16.to_le_bytes());
        run.extend_from_slice(&0i32.to_le_bytes());
        run.extend_from_slice(&0u32.to_le_bytes());
        run.push(0xB3u8);
        run.extend_from_slice(&[0u8; 7]);
        assert!(recover_bytecode_array_from_run(&run, TAGGED_SIZE_NO_COMPRESSION).is_none());
    }

    #[test]
    fn build_selection_covers_node_18_through_24() {
        assert_eq!(
            SerializerBuild::for_node(NodeVersion::Node24),
            Some(SerializerBuild::NoCompressionNoSandbox)
        );
        assert_eq!(
            SerializerBuild::for_node(NodeVersion::Node18),
            Some(SerializerBuild::NoCompressionNoSandbox)
        );
        assert_eq!(
            SerializerBuild::for_node(NodeVersion::Node22),
            Some(SerializerBuild::NoCompressionNoSandbox)
        );
        assert_eq!(SerializerBuild::for_node(NodeVersion::Unknown), None);
    }

    #[test]
    fn return_opcode_is_version_pinned() {
        assert_eq!(return_opcode_for(NodeVersion::Node18), 0xA9u8);
        assert_eq!(return_opcode_for(NodeVersion::Node20), 0xA9u8);
        assert_eq!(return_opcode_for(NodeVersion::Node22), 0xAEu8);
        assert_eq!(return_opcode_for(NodeVersion::Node24), 0xB3u8);
    }

    #[test]
    fn serializer_opcode_tables_have_distinct_scalar_layouts() {
        assert_eq!(
            SerializerOpcodes::for_node(NodeVersion::Node18).backref,
            0x04
        );
        assert_eq!(
            SerializerOpcodes::for_node(NodeVersion::Node20).backref,
            0x03
        );
        assert_eq!(
            SerializerOpcodes::for_node(NodeVersion::Node18).synchronize,
            0x0C
        );
        assert_eq!(
            SerializerOpcodes::for_node(NodeVersion::Node24).synchronize,
            0x0B
        );
        assert_eq!(
            SerializerOpcodes::for_node(NodeVersion::Node22).new_contextless_meta_map,
            0x1A
        );
        assert_eq!(
            SerializerOpcodes::for_node(NodeVersion::Node18).new_meta_map,
            0x1C
        );
        assert_eq!(
            SerializerOpcodes::for_node(NodeVersion::Node18).new_contextless_meta_map,
            ABSENT
        );
    }
}
