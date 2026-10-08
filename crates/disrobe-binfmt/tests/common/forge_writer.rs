#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use disrobe_binfmt::containers::forge::{
    DESCRIPTOR_TAG, DESCRIPTOR_TERMINATOR, DIRECTORY_RECORD_LEN, DescriptorField, DescriptorValue,
    ENTRY_NAME_KEY_STEP, ENTRY_PAGE, FAST_LOAD_TOC_TAG, FAT_RECORD_LEN, FILE_NAME_KEY_STEP,
    FORGE_MAGIC, FastLoadToc, META_NAME_LEN, META_RECORD_LEN, TABLE_DESCRIPTOR_LEN, V34_OFFSET_K1,
    V34_OFFSET_K2, V34_SIZE_K1, V34_SIZE_K2, V34_UID_K1, V34_UID_K2, extra_header_words,
    header_len_for, name_xor,
};
use disrobe_binfmt::containers::forge_block::{
    BLOCK_MAGIC_V34, BLOCK_MAGIC_V37, BlockMagic, PackMethod, adler32_seed0,
};
use disrobe_binfmt::containers::forge_depgraph::{DEPGRAPH_TAG, DepGraphLink};
use disrobe_binfmt::containers::forge_flat::ForgeSubFile;

pub const DEFAULT_CHUNK_BYTES: usize = 256 * 1024;
const BLOCK_VERSION: u16 = 3;
const BLOCK_FLAGS: u16 = 0x8004;
const ZSTD_LEVEL: i32 = 3;

pub type Packer = fn(PackMethod, &[u8]) -> Vec<u8>;

pub fn basic_packer(method: PackMethod, chunk: &[u8]) -> Vec<u8> {
    if method != PackMethod::Zstd {
        return chunk.to_vec();
    }
    let packed: Vec<u8> = zstd::bulk::compress(chunk, ZSTD_LEVEL).expect("zstd compress");
    if packed.len() < chunk.len() {
        packed
    } else {
        chunk.to_vec()
    }
}

pub const fn scramble_v34_offset(offset: u64) -> u64 {
    V34_OFFSET_K1.wrapping_sub(offset) ^ V34_OFFSET_K2
}

pub const fn scramble_v34_size(size: u32) -> u32 {
    V34_SIZE_K1.wrapping_sub(size) ^ V34_SIZE_K2
}

pub const fn scramble_v34_uid(uid: u64) -> u64 {
    V34_UID_K1.wrapping_sub(uid ^ V34_UID_K2)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgeWriteFile {
    pub name: Option<String>,
    pub file_type: u32,
    pub timestamp: u32,
    pub subfiles: Vec<ForgeSubFile>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForgeWriteBody {
    Descriptor(Vec<DescriptorField>),
    FastLoadToc(FastLoadToc),
    File(ForgeWriteFile),
    RawRiff(Vec<u8>),
    Raw(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgeWriteEntry {
    pub uid: u64,
    pub body: ForgeWriteBody,
}

#[derive(Debug, Clone)]
pub struct ForgeWriteSpec {
    pub version: u32,
    pub block_magic: BlockMagic,
    pub pack_method: PackMethod,
    pub packer: Packer,
    pub chunk_bytes: usize,
    pub tables: usize,
    pub free_slots: usize,
    pub meta_names: bool,
    pub entries: Vec<ForgeWriteEntry>,
}

impl ForgeWriteSpec {
    pub fn scimitar(version: u32) -> Self {
        Self {
            version,
            block_magic: BlockMagic::V37,
            pack_method: PackMethod::OodleLeviathan,
            packer: basic_packer,
            chunk_bytes: DEFAULT_CHUNK_BYTES,
            tables: 1,
            free_slots: 2,
            meta_names: false,
            entries: Vec::new(),
        }
    }
}

pub const fn block_magic_value(magic: BlockMagic) -> u64 {
    match magic {
        BlockMagic::Anvil33 => 0x1004_FA99_57FB_AA33,
        BlockMagic::V34 => BLOCK_MAGIC_V34,
        BlockMagic::V35 => BLOCK_MAGIC_V37 - 2,
        BlockMagic::V36 => BLOCK_MAGIC_V37 - 1,
        BlockMagic::V37 => BLOCK_MAGIC_V37,
    }
}

pub fn write_block(
    magic: BlockMagic,
    method: PackMethod,
    packer: Packer,
    chunk_bytes: usize,
    payload: &[u8],
) -> Vec<u8> {
    let chunk_bytes: usize = chunk_bytes.max(1);
    let chunks: Vec<&[u8]> = if payload.is_empty() {
        vec![&[][..]]
    } else {
        payload.chunks(chunk_bytes).collect()
    };
    let packed: Vec<Vec<u8>> = chunks
        .iter()
        .map(|chunk: &&[u8]| packer(method, chunk))
        .collect();
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&block_magic_value(magic).to_le_bytes());
    out.extend_from_slice(&BLOCK_VERSION.to_le_bytes());
    out.extend_from_slice(&method.code().to_le_bytes());
    out.push(0);
    out.extend_from_slice(&BLOCK_FLAGS.to_le_bytes());
    out.extend_from_slice(&(chunks.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    for (chunk, data) in chunks.iter().zip(&packed) {
        out.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    }
    if method == PackMethod::Streaming {
        for data in &packed {
            out.extend_from_slice(&adler32_seed0(data).to_le_bytes());
        }
        for data in &packed {
            out.extend_from_slice(data);
        }
    } else {
        for data in &packed {
            out.extend_from_slice(&adler32_seed0(data).to_le_bytes());
            out.extend_from_slice(data);
        }
    }
    out
}

pub fn write_descriptor(fields: &[DescriptorField]) -> Vec<u8> {
    let mut out: Vec<u8> = DESCRIPTOR_TAG.to_le_bytes().to_vec();
    for field in fields {
        out.extend_from_slice(&field.id.to_le_bytes());
        out.extend_from_slice(&field.kind.to_le_bytes());
        match &field.value {
            DescriptorValue::U32(value) => out.extend_from_slice(&value.to_le_bytes()),
            DescriptorValue::U64(value) => out.extend_from_slice(&value.to_le_bytes()),
            DescriptorValue::Text(text) => {
                out.extend_from_slice(&(text.len() as u32).to_le_bytes());
                out.extend_from_slice(text.as_bytes());
                out.push(0);
            }
        }
    }
    out.extend_from_slice(&DESCRIPTOR_TERMINATOR);
    out
}

pub fn write_fast_load_toc(toc: &FastLoadToc) -> Vec<u8> {
    let mut out: Vec<u8> = FAST_LOAD_TOC_TAG.to_le_bytes().to_vec();
    out.extend_from_slice(&toc.hash_a.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&toc.hash_b.to_le_bytes());
    match &toc.name {
        None => out.extend_from_slice(&0u32.to_le_bytes()),
        Some(name) => {
            out.extend_from_slice(&1u32.to_le_bytes());
            let mut field: [u8; 64] = [0u8; 64];
            let take: usize = name.len().min(63);
            field[..take].copy_from_slice(&name.as_bytes()[..take]);
            out.extend_from_slice(&field);
        }
    }
    out.extend_from_slice(&toc.trailer);
    out
}

pub fn write_subfile_index(records: &[ForgeSubFile]) -> Vec<u8> {
    let mut out: Vec<u8> = (records.len() as i32).to_le_bytes().to_vec();
    for record in records {
        out.extend_from_slice(&record.uid.to_le_bytes());
        out.extend_from_slice(&record.length.to_le_bytes());
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlatRecordSpec<'a> {
    pub name: Option<&'a str>,
    pub name_flags: u16,
    pub file_type: u32,
    pub uid: u64,
    pub payload: &'a [u8],
}

pub fn write_flat_archive(records: &[FlatRecordSpec<'_>]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for record in records {
        let name: &[u8] = record.name.map_or(&[], str::as_bytes);
        let mut encoded: Vec<u8> = name.to_vec();
        if record.name_flags == 0 {
            name_xor(
                &mut encoded,
                record.uid,
                0,
                record.file_type,
                FILE_NAME_KEY_STEP,
            );
        }
        let name_field: u32 = name.len() as u32 | (u32::from(record.name_flags) << 16);
        out.extend_from_slice(&name_field.to_le_bytes());
        out.extend_from_slice(&encoded);
        out.extend_from_slice(&((record.payload.len() + 8) as u32).to_le_bytes());
        out.extend_from_slice(&record.file_type.to_le_bytes());
        out.extend_from_slice(&record.uid.to_le_bytes());
        out.extend_from_slice(record.payload);
    }
    out
}

pub fn write_depgraph_payload(links: &[DepGraphLink]) -> Vec<u8> {
    let mut out: Vec<u8> = vec![DEPGRAPH_TAG];
    for link in links {
        out.extend_from_slice(&link.parent_uid.to_le_bytes());
        out.extend_from_slice(&link.child_uid.to_le_bytes());
        out.extend_from_slice(&link.child_type.to_le_bytes());
        out.extend_from_slice(&link.unknown.to_le_bytes());
        out.push(link.flags);
        out.push(link.unknown_tail);
    }
    out
}

fn entry_container(spec: &ForgeWriteSpec, entry: &ForgeWriteEntry) -> Vec<u8> {
    match &entry.body {
        ForgeWriteBody::Descriptor(fields) => write_descriptor(fields),
        ForgeWriteBody::FastLoadToc(toc) => write_fast_load_toc(toc),
        ForgeWriteBody::RawRiff(bytes) | ForgeWriteBody::Raw(bytes) => bytes.clone(),
        ForgeWriteBody::File(file) => {
            let index: Vec<u8> = write_subfile_index(&file.subfiles);
            let mut out: Vec<u8> = write_block(
                spec.block_magic,
                spec.pack_method,
                spec.packer,
                spec.chunk_bytes,
                &index,
            );
            out.extend(write_block(
                spec.block_magic,
                spec.pack_method,
                spec.packer,
                spec.chunk_bytes,
                &file.payload,
            ));
            out
        }
    }
}

fn meta_record(
    spec: &ForgeWriteSpec,
    entry: &ForgeWriteEntry,
    data_offset: u64,
    size: u32,
) -> Vec<u8> {
    let mut record: Vec<u8> = vec![0u8; META_RECORD_LEN as usize];
    let ForgeWriteBody::File(file) = &entry.body else {
        return record;
    };
    if !spec.meta_names {
        return record;
    }
    let name: &[u8] = file.name.as_deref().map_or(&[], str::as_bytes);
    let take: usize = name.len().min(META_NAME_LEN);
    let mut encoded: [u8; META_NAME_LEN] = [0u8; META_NAME_LEN];
    encoded[..take].copy_from_slice(&name[..take]);
    name_xor(
        &mut encoded,
        entry.uid,
        data_offset,
        file.file_type,
        ENTRY_NAME_KEY_STEP,
    );
    if spec.version >= 30 {
        record[0x04..0x08].copy_from_slice(&4u32.to_le_bytes());
        record[0x10..0x14].copy_from_slice(&4u32.to_le_bytes());
        record[0x14..0x14 + META_NAME_LEN].copy_from_slice(&encoded);
        record[0x113] = take as u8;
        record[0x114..0x118].copy_from_slice(&file.timestamp.to_le_bytes());
        record[0x11C..0x120].copy_from_slice(&(-1i32).to_le_bytes());
        record[0x120..0x124].copy_from_slice(&(-1i32).to_le_bytes());
        record[0x12C..0x130].copy_from_slice(&file.file_type.to_le_bytes());
        record[0x13C..0x140].copy_from_slice(&size.to_le_bytes());
    } else {
        record[0x00..0x04].copy_from_slice(&size.to_le_bytes());
        record[0x10..0x14].copy_from_slice(&file.file_type.to_le_bytes());
        record[0x1C..0x20].copy_from_slice(&(-1i32).to_le_bytes());
        record[0x20..0x24].copy_from_slice(&(-1i32).to_le_bytes());
        record[0x24..0x28].copy_from_slice(&file.timestamp.to_le_bytes());
        record[0x28..0x28 + META_NAME_LEN].copy_from_slice(&encoded);
        record[0x127] = take as u8;
    }
    record
}

fn directory_records(num_files: u32) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(2 * DIRECTORY_RECORD_LEN as usize);
    let mut root: Vec<u8> = vec![0u8; DIRECTORY_RECORD_LEN as usize];
    root[0..4].copy_from_slice(&num_files.to_le_bytes());
    root[4..8].copy_from_slice(&1u32.to_le_bytes());
    for field in 2..5 {
        root[field * 4..field * 4 + 4].copy_from_slice(&(-1i32).to_le_bytes());
    }
    out.extend_from_slice(&root);
    let mut lost: Vec<u8> = vec![0u8; DIRECTORY_RECORD_LEN as usize];
    for field in 0..4 {
        lost[field * 4..field * 4 + 4].copy_from_slice(&(-1i32).to_le_bytes());
    }
    let label: &[u8] = b"_Lost&Found";
    lost[20..20 + label.len()].copy_from_slice(label);
    out.extend_from_slice(&lost);
    out
}

const fn align_up(value: u64, align: u64) -> u64 {
    value.div_ceil(align) * align
}

pub fn write_forge(spec: &ForgeWriteSpec) -> Vec<u8> {
    let tables: usize = spec.tables.max(1);
    let per_table: usize = spec.entries.len().div_ceil(tables).max(1);
    let groups: Vec<&[ForgeWriteEntry]> = if spec.entries.is_empty() {
        vec![&[][..]]
    } else {
        spec.entries.chunks(per_table).collect()
    };
    let header_len: u64 = header_len_for(spec.version) as u64;
    let mut table_positions: Vec<u64> = Vec::with_capacity(groups.len());
    let mut cursor: u64 = header_len;
    let mut slot_counts: Vec<usize> = Vec::with_capacity(groups.len());
    for (index, group) in groups.iter().enumerate() {
        let free: usize = if index + 1 == groups.len() {
            spec.free_slots
        } else {
            0
        };
        let slots: usize = group.len() + free;
        slot_counts.push(slots);
        table_positions.push(cursor);
        cursor += TABLE_DESCRIPTOR_LEN as u64
            + (slots * FAT_RECORD_LEN) as u64
            + slots as u64 * META_RECORD_LEN
            + 2 * DIRECTORY_RECORD_LEN;
    }
    let containers: Vec<Vec<u8>> = spec
        .entries
        .iter()
        .map(|entry: &ForgeWriteEntry| entry_container(spec, entry))
        .collect();
    let mut data_offsets: Vec<u64> = Vec::with_capacity(containers.len());
    let mut data_cursor: u64 = align_up(cursor, ENTRY_PAGE);
    for container in &containers {
        data_offsets.push(data_cursor);
        data_cursor = align_up(data_cursor + container.len() as u64, ENTRY_PAGE);
    }
    let total_slots: usize = slot_counts.iter().sum();
    let total_files: usize = spec.entries.len();

    let mut out: Vec<u8> = Vec::with_capacity(data_cursor as usize);
    out.extend_from_slice(FORGE_MAGIC);
    out.extend_from_slice(&spec.version.to_le_bytes());
    out.extend_from_slice(&(header_len as u32 - 0x2C).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0x10u64.to_le_bytes());
    out.push(1);
    out.extend_from_slice(&(total_slots as u32).to_le_bytes());
    out.extend_from_slice(&(2 * groups.len() as u32).to_le_bytes());
    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    for _ in 0..extra_header_words(spec.version) {
        out.extend_from_slice(&0u32.to_le_bytes());
    }
    let first_free_file: i32 = if spec.free_slots > 0 {
        total_files as i32
    } else {
        -1
    };
    out.extend_from_slice(&first_free_file.to_le_bytes());
    out.extend_from_slice(&(-1i32).to_le_bytes());
    out.extend_from_slice(&((total_files + 2 * groups.len()) as u32).to_le_bytes());
    out.extend_from_slice(&(groups.len() as u32).to_le_bytes());
    out.extend_from_slice(&table_positions[0].to_le_bytes());
    assert_eq!(out.len() as u64, header_len, "header length");

    let mut entry_index: usize = 0;
    let mut first_index: u32 = 0;
    for (table_index, group) in groups.iter().enumerate() {
        let slots: usize = slot_counts[table_index];
        let position: u64 = table_positions[table_index];
        let pos_fat: u64 = position + TABLE_DESCRIPTOR_LEN as u64;
        let meta_offset: u64 = pos_fat + (slots * FAT_RECORD_LEN) as u64;
        let dir_offset: u64 = meta_offset + slots as u64 * META_RECORD_LEN;
        let next: i64 = table_positions
            .get(table_index + 1)
            .map_or(-1, |&p: &u64| p as i64);
        out.extend_from_slice(&(group.len() as i32).to_le_bytes());
        out.extend_from_slice(&2i32.to_le_bytes());
        out.extend_from_slice(&(pos_fat as i64).to_le_bytes());
        out.extend_from_slice(&next.to_le_bytes());
        out.extend_from_slice(&(first_index as i32).to_le_bytes());
        out.extend_from_slice(&((first_index + slots as u32).wrapping_sub(1) as i32).to_le_bytes());
        out.extend_from_slice(&(meta_offset as i64).to_le_bytes());
        out.extend_from_slice(&(dir_offset as i64).to_le_bytes());
        let mut meta: Vec<u8> = Vec::with_capacity(slots * META_RECORD_LEN as usize);
        for slot in 0..slots {
            if slot < group.len() {
                let entry: &ForgeWriteEntry = &group[slot];
                let offset: u64 = data_offsets[entry_index];
                let size: u32 = containers[entry_index].len() as u32;
                let (raw_offset, raw_uid, raw_size): (u64, u64, u32) = if spec.version == 34 {
                    (
                        scramble_v34_offset(offset),
                        scramble_v34_uid(entry.uid),
                        scramble_v34_size(size),
                    )
                } else {
                    (offset, entry.uid, size)
                };
                out.extend_from_slice(&raw_offset.to_le_bytes());
                out.extend_from_slice(&raw_uid.to_le_bytes());
                out.extend_from_slice(&raw_size.to_le_bytes());
                meta.extend(meta_record(spec, entry, offset, size));
                entry_index += 1;
            } else {
                out.extend_from_slice(&[0u8; FAT_RECORD_LEN]);
                meta.extend(std::iter::repeat_n(0u8, META_RECORD_LEN as usize));
            }
        }
        out.extend_from_slice(&meta);
        out.extend_from_slice(&directory_records(group.len() as u32));
        first_index += slots as u32;
    }
    for (container, offset) in containers.iter().zip(&data_offsets) {
        out.resize(*offset as usize, 0);
        out.extend_from_slice(container);
    }
    out.resize(data_cursor as usize, 0);
    out
}
