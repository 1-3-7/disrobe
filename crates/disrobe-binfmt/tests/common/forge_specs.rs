#![allow(dead_code, unreachable_pub)]

use disrobe_binfmt::containers::forge::{DescriptorField, DescriptorValue, FastLoadToc};
use disrobe_binfmt::containers::forge_block::{BlockMagic, PackMethod};
use disrobe_binfmt::containers::forge_depgraph::DepGraphLink;
use disrobe_binfmt::containers::forge_flat::ForgeSubFile;
use disrobe_binfmt::containers::forge_types::{DESCRIPTOR_UID, FAST_LOAD_TOC_UID, type_id};

use super::forge_writer::{
    FlatRecordSpec, ForgeWriteBody, ForgeWriteEntry, ForgeWriteFile, ForgeWriteSpec, basic_packer,
    write_block, write_depgraph_payload, write_flat_archive,
};
use super::oodle_encoder::{Codec, LzStyle, lz_stream};

pub const FIXTURE_DIR: &str = "forge";

pub const FORGE_FIXTURES: &[&str] = &[
    "v34_min.forge",
    "v34_zstd.forge",
    "v34_riff.forge",
    "v34_multitable.forge",
    "v33_min.forge",
    "v30_named.forge",
    "v34_leviathan.forge",
    "v30_kraken.forge",
];

pub const DEPGRAPH_FIXTURES: &[&str] = &[
    "min.depgraphbin",
    "zstd.depgraphbin",
    "leviathan.depgraphbin",
];

pub fn oodle_packer(method: PackMethod, chunk: &[u8]) -> Vec<u8> {
    let codec: Codec = match method {
        PackMethod::OodleKraken => Codec::Kraken,
        PackMethod::OodleLeviathan => Codec::Leviathan,
        PackMethod::Zstd | PackMethod::Streaming | PackMethod::Unknown(_) => {
            return basic_packer(method, chunk);
        }
    };
    if chunk.len() < 64 {
        return chunk.to_vec();
    }
    let packed: Vec<u8> = lz_stream(codec, 0, LzStyle::default(), chunk);
    if packed.len() < chunk.len() {
        packed
    } else {
        chunk.to_vec()
    }
}

pub struct Xorshift64 {
    state: u64,
}

impl Xorshift64 {
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    pub const fn next_u64(&mut self) -> u64 {
        let mut x: u64 = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    pub const fn next_usize(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        (self.next_u64() % bound as u64) as usize
    }

    pub const fn next_byte(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }
}

#[must_use]
pub fn patterned_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut rng: Xorshift64 = Xorshift64::new(seed);
    let words: [&[u8]; 4] = [b"mesh ", b"vertex ", b"normal ", b"index "];
    let mut out: Vec<u8> = Vec::with_capacity(len);
    while out.len() < len {
        let word: &[u8] = words[rng.next_usize(words.len())];
        out.extend_from_slice(word);
        out.push(rng.next_byte());
    }
    out.truncate(len);
    out
}

#[must_use]
pub fn descriptor_fields() -> Vec<DescriptorField> {
    vec![
        DescriptorField {
            id: 4,
            kind: 1,
            value: DescriptorValue::Text("//disrobe-fixture/livecert/".to_owned()),
        },
        DescriptorField {
            id: 5,
            kind: 1,
            value: DescriptorValue::Text(String::new()),
        },
        DescriptorField {
            id: 2,
            kind: 0,
            value: DescriptorValue::U32(0x0012_3456),
        },
        DescriptorField {
            id: 0xC,
            kind: 0,
            value: DescriptorValue::U32(0x0097_4E60),
        },
        DescriptorField {
            id: 0x10,
            kind: 5,
            value: DescriptorValue::U64(0),
        },
    ]
}

#[must_use]
pub fn descriptor_entry() -> ForgeWriteEntry {
    ForgeWriteEntry {
        uid: DESCRIPTOR_UID,
        body: ForgeWriteBody::Descriptor(descriptor_fields()),
    }
}

#[must_use]
pub fn toc_entry(name: Option<&str>) -> ForgeWriteEntry {
    ForgeWriteEntry {
        uid: FAST_LOAD_TOC_UID,
        body: ForgeWriteBody::FastLoadToc(FastLoadToc {
            hash_a: 0x1111_2222_3333_4444,
            hash_b: 0x5555_6666_7777_8888,
            name: name.map(str::to_owned),
            trailer: if name.is_some() {
                [0x11u8; 20].to_vec()
            } else {
                Vec::new()
            },
        }),
    }
}

#[must_use]
pub fn file_entry(
    uid: u64,
    name: Option<&str>,
    class: &str,
    records: &[(Option<&str>, &str, u64, Vec<u8>)],
) -> ForgeWriteEntry {
    file_entry_with_name_flags(uid, name, class, records, 0)
}

#[must_use]
pub fn file_entry_with_name_flags(
    uid: u64,
    name: Option<&str>,
    class: &str,
    records: &[(Option<&str>, &str, u64, Vec<u8>)],
    name_flags: u16,
) -> ForgeWriteEntry {
    let specs: Vec<FlatRecordSpec<'_>> = records
        .iter()
        .map(
            |(record_name, record_class, record_uid, payload): &(
                Option<&str>,
                &str,
                u64,
                Vec<u8>,
            )| {
                FlatRecordSpec {
                    name: *record_name,
                    name_flags,
                    file_type: type_id(record_class),
                    uid: *record_uid,
                    payload,
                }
            },
        )
        .collect();
    let payload: Vec<u8> = write_flat_archive(&specs);
    let subfiles: Vec<ForgeSubFile> = records
        .iter()
        .map(
            |(_, _, record_uid, payload): &(Option<&str>, &str, u64, Vec<u8>)| ForgeSubFile {
                uid: *record_uid,
                length: payload.len() as i32,
            },
        )
        .collect();
    ForgeWriteEntry {
        uid,
        body: ForgeWriteBody::File(ForgeWriteFile {
            name: name.map(str::to_owned),
            file_type: type_id(class),
            timestamp: 1_700_000_000,
            subfiles,
            payload,
        }),
    }
}

#[must_use]
pub fn riff_entry(uid: u64, body_len: usize) -> ForgeWriteEntry {
    let body: Vec<u8> = patterned_bytes(uid, body_len);
    let mut bytes: Vec<u8> = b"RIFF".to_vec();
    bytes.extend_from_slice(&((body.len() + 4) as u32).to_le_bytes());
    bytes.extend_from_slice(b"WAVE");
    bytes.extend_from_slice(&body);
    ForgeWriteEntry {
        uid,
        body: ForgeWriteBody::RawRiff(bytes),
    }
}

#[must_use]
pub fn spec_for(name: &str) -> ForgeWriteSpec {
    match name {
        "v34_min.forge" => {
            let mut spec: ForgeWriteSpec = ForgeWriteSpec::scimitar(34);
            spec.entries = vec![
                descriptor_entry(),
                file_entry(
                    0x0100_0000_0000_0001,
                    None,
                    "CompiledMeshObject",
                    &[(
                        None,
                        "CompiledMeshObject",
                        0x0100_0000_0000_0001,
                        patterned_bytes(1, 3000),
                    )],
                ),
                file_entry_with_name_flags(
                    0x0100_0000_0000_0002,
                    None,
                    "Material",
                    &[
                        (
                            Some("opaque-name-bytes"),
                            "Material",
                            0x0100_0000_0000_0002,
                            patterned_bytes(2, 700),
                        ),
                        (
                            None,
                            "TextureMapSpec",
                            0x0100_0000_0000_0003,
                            patterned_bytes(3, 90),
                        ),
                    ],
                    2,
                ),
                toc_entry(None),
            ];
            spec
        }
        "v34_zstd.forge" => {
            let mut spec: ForgeWriteSpec = ForgeWriteSpec::scimitar(34);
            spec.block_magic = BlockMagic::V34;
            spec.pack_method = PackMethod::Zstd;
            spec.chunk_bytes = 4096;
            spec.entries = vec![
                descriptor_entry(),
                file_entry(
                    0x0200_0000_0000_0001,
                    None,
                    "CompiledTextureMap",
                    &[(
                        None,
                        "CompiledTextureMap",
                        0x0200_0000_0000_0001,
                        patterned_bytes(11, 10_000),
                    )],
                ),
                file_entry(
                    0x0200_0000_0000_0002,
                    None,
                    "CompiledSoundBank",
                    &[(
                        None,
                        "CompiledSoundBank",
                        0x0200_0000_0000_0002,
                        vec![0u8; 20_000],
                    )],
                ),
                toc_entry(None),
            ];
            spec
        }
        "v34_riff.forge" => {
            let mut spec: ForgeWriteSpec = ForgeWriteSpec::scimitar(34);
            spec.entries = vec![
                descriptor_entry(),
                riff_entry(0x0300_0000_0000_0001, 600),
                file_entry(
                    0x0300_0000_0000_0002,
                    None,
                    "CompiledSoundMedia",
                    &[(
                        None,
                        "CompiledSoundMedia",
                        0x0300_0000_0000_0002,
                        patterned_bytes(31, 1200),
                    )],
                ),
                riff_entry(0x0300_0000_0000_0003, 44),
                toc_entry(None),
            ];
            spec
        }
        "v34_multitable.forge" => {
            let mut spec: ForgeWriteSpec = ForgeWriteSpec::scimitar(34);
            spec.tables = 3;
            spec.free_slots = 1;
            spec.entries = (1..=6u64)
                .map(|n: u64| {
                    file_entry(
                        0x0400_0000_0000_0000 + n,
                        None,
                        "Entity",
                        &[(
                            None,
                            "Entity",
                            0x0400_0000_0000_0000 + n,
                            patterned_bytes(40 + n, 200 * n as usize),
                        )],
                    )
                })
                .collect();
            spec
        }
        "v33_min.forge" => {
            let mut spec: ForgeWriteSpec = ForgeWriteSpec::scimitar(33);
            spec.entries = vec![
                descriptor_entry(),
                file_entry(
                    0x0500_0000_0000_0001,
                    None,
                    "CompiledMeshShapeDataObject",
                    &[(
                        None,
                        "CompiledMeshShapeDataObject",
                        0x0500_0000_0000_0001,
                        patterned_bytes(51, 2500),
                    )],
                ),
                toc_entry(None),
            ];
            spec
        }
        "v30_named.forge" => {
            let mut spec: ForgeWriteSpec = ForgeWriteSpec::scimitar(30);
            spec.block_magic = BlockMagic::V34;
            spec.pack_method = PackMethod::Zstd;
            spec.chunk_bytes = 8192;
            spec.meta_names = true;
            spec.entries = vec![
                descriptor_entry(),
                file_entry(
                    0x0600_0000_0000_0001,
                    Some("data/hero.mesh"),
                    "Mesh",
                    &[(
                        Some("hero_body"),
                        "Mesh",
                        0x0600_0000_0000_0001,
                        patterned_bytes(61, 9000),
                    )],
                ),
                file_entry(
                    0x0600_0000_0000_0002,
                    Some("textures/hero.tex"),
                    "TextureMap",
                    &[
                        (
                            Some("hero_diffuse"),
                            "TextureMap",
                            0x0600_0000_0000_0002,
                            patterned_bytes(62, 1500),
                        ),
                        (
                            Some("hero_diffuse_spec"),
                            "TextureMapSpec",
                            0x0600_0000_0000_0003,
                            patterned_bytes(63, 300),
                        ),
                    ],
                ),
                toc_entry(Some("fixture-toc")),
            ];
            spec
        }
        "v34_leviathan.forge" => {
            let mut spec: ForgeWriteSpec = ForgeWriteSpec::scimitar(34);
            spec.packer = oodle_packer;
            spec.chunk_bytes = 16 * 1024;
            spec.entries = vec![
                descriptor_entry(),
                file_entry(
                    0x0700_0000_0000_0001,
                    None,
                    "CompiledMeshObject",
                    &[(
                        None,
                        "CompiledMeshObject",
                        0x0700_0000_0000_0001,
                        patterned_bytes(71, 40_000),
                    )],
                ),
                file_entry(
                    0x0700_0000_0000_0002,
                    None,
                    "Material",
                    &[
                        (
                            None,
                            "Material",
                            0x0700_0000_0000_0002,
                            patterned_bytes(72, 5000),
                        ),
                        (
                            None,
                            "TextureMapSpec",
                            0x0700_0000_0000_0003,
                            vec![0u8; 3000],
                        ),
                    ],
                ),
                toc_entry(None),
            ];
            spec
        }
        "v30_kraken.forge" => {
            let mut spec: ForgeWriteSpec = ForgeWriteSpec::scimitar(30);
            spec.block_magic = BlockMagic::V34;
            spec.pack_method = PackMethod::OodleKraken;
            spec.packer = oodle_packer;
            spec.chunk_bytes = 32 * 1024;
            spec.meta_names = true;
            spec.entries = vec![
                descriptor_entry(),
                file_entry(
                    0x0800_0000_0000_0001,
                    Some("data/kraken.mesh"),
                    "Mesh",
                    &[(
                        Some("kraken_body"),
                        "Mesh",
                        0x0800_0000_0000_0001,
                        patterned_bytes(81, 50_000),
                    )],
                ),
                toc_entry(None),
            ];
            spec
        }
        other => panic!("no forge fixture spec named {other}"),
    }
}

#[must_use]
pub fn fixture_role(name: &str) -> &'static str {
    match name {
        "v34_min.forge" => {
            "version 34 header with scrambled FAT fields, descriptor and fast-load TOC entries, two \
             file containers (one and two flat-archive records, the second with a flag-2 name \
             the reader withholds), AA37 blocks with pack method 15 \
             and stored chunks only, two free slots"
        }
        "v34_zstd.forge" => {
            "version 34, AA34 blocks with pack method 3: a 10,000-byte payload across 4 KiB \
             chunks and a 20,000-byte zero run that compresses to a few bytes per chunk"
        }
        "v34_riff.forge" => "version 34 with two raw RIFF (Wwise) entries beside a file container",
        "v34_multitable.forge" => {
            "version 34 with three chained table descriptors (next_pos_fat chain ending at -1) \
             over six file containers and one free slot"
        }
        "v33_min.forge" => {
            "version 33 header (one reserved word fewer than 34), clear FAT offsets and sizes, \
             uid field reported as opaque, AA37 stored blocks"
        }
        "v30_named.forge" => {
            "version 30 with a populated 0x140-byte meta table (XOR-encoded names, timestamps, \
             type ids), AA34 blocks with pack method 3, named flat-archive records and a named \
             fast-load TOC"
        }
        "min.depgraphbin" => {
            "one bare AA37 block, pack method 15, stored chunk, 40 dependency links"
        }
        "zstd.depgraphbin" => "one bare AA34 block, pack method 3, 256-byte zstd chunks, 40 links",
        "v34_leviathan.forge" => {
            "version 34, AA37 blocks with pack method 15 whose chunks are Oodle Leviathan streams              from the test-tree encoder (16 KiB chunks), a stored chunk for the small sub-file              index, descriptor and fast-load TOC entries"
        }
        "v30_kraken.forge" => {
            "version 30 with a named meta table, AA34 blocks with pack method 13 whose chunks are              Oodle Kraken streams from the test-tree encoder (32 KiB chunks)"
        }
        "leviathan.depgraphbin" => {
            "one bare AA37 block, pack method 15, 40 links in one Oodle Leviathan chunk"
        }
        other => panic!("no forge fixture role for {other}"),
    }
}

#[must_use]
pub fn depgraph_links() -> Vec<DepGraphLink> {
    (0..40u64)
        .map(|n: u64| DepGraphLink {
            parent_uid: 0x0100_0000_0000_0001 + n / 4,
            child_uid: 0x0700_0000_0000_0000 + n,
            child_type: if n.is_multiple_of(3) {
                -1
            } else {
                type_id("Material") as i32
            },
            unknown: 0,
            flags: if n.is_multiple_of(2) { 0xEF } else { 0xFF },
            unknown_tail: (n % 8) as u8,
        })
        .collect()
}

#[must_use]
pub fn depgraph_for(name: &str) -> Vec<u8> {
    let payload: Vec<u8> = write_depgraph_payload(&depgraph_links());
    match name {
        "min.depgraphbin" => write_block(
            BlockMagic::V37,
            PackMethod::OodleLeviathan,
            basic_packer,
            256 * 1024,
            &payload,
        ),
        "zstd.depgraphbin" => write_block(
            BlockMagic::V34,
            PackMethod::Zstd,
            basic_packer,
            256,
            &payload,
        ),
        "leviathan.depgraphbin" => write_block(
            BlockMagic::V37,
            PackMethod::OodleLeviathan,
            oodle_packer,
            256 * 1024,
            &payload,
        ),
        other => panic!("no depgraph fixture named {other}"),
    }
}
