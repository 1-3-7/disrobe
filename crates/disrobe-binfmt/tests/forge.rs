#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

#[path = "common/forge_specs.rs"]
mod forge_specs;
#[path = "common/forge_writer.rs"]
mod forge_writer;
#[path = "common/oodle_encoder/mod.rs"]
mod oodle_encoder;

use std::fmt::Write as _;
use std::path::Path;

use common::requirement::required_fixture;
use disrobe_binfmt::carve::{CarveConfig, CarveReport, carve_recursive};
use disrobe_binfmt::classify::{Action, classify_input};
use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::containers::forge::{
    ForgeArchive, ForgeEntry, ForgeEntryKind, ForgeTable, archive_extent, forge_entry_bytes,
    header_len_for, parse_descriptor, parse_fast_load_toc, parse_forge,
};
use disrobe_binfmt::containers::forge_block::{
    BlockDecoder, ForgeBlock, MAX_CHUNK_UNPACKED, parse_block,
};
use disrobe_binfmt::containers::forge_depgraph::{DepGraph, parse_depgraph};
use disrobe_binfmt::containers::forge_flat::{
    ForgeSubFileIndex, parse_flat_archive, parse_subfile_index,
};
use disrobe_binfmt::containers::oodle::OodleError;
use disrobe_binfmt::{Error, ExtractionResult, extract_to};
use forge_specs::{
    DEPGRAPH_FIXTURES, FIXTURE_DIR, FORGE_FIXTURES, depgraph_for, depgraph_links, patterned_bytes,
    spec_for,
};
use forge_writer::{
    FlatRecordSpec, ForgeWriteBody, ForgeWriteEntry, ForgeWriteFile, ForgeWriteSpec,
    scramble_v34_offset, scramble_v34_size, scramble_v34_uid, write_depgraph_payload,
    write_flat_archive, write_forge, write_subfile_index,
};
use sha2::{Digest, Sha256};

const CAP: u64 = 64 * 1024 * 1024;

fn scratch(label: &str) -> disrobe_core::scratch::ScratchDir {
    disrobe_core::scratch::ScratchDir::create(&format!("forge-{label}")).expect("scratch dir")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    let mut out: String = String::with_capacity(64);
    for byte in digest {
        write!(out, "{byte:02x}").expect("writing to a String cannot fail");
    }
    out
}

fn decode_entry(bytes: &[u8], entry: &ForgeEntry) -> (ForgeBlock, Vec<u8>, ForgeBlock, Vec<u8>) {
    let container: &[u8] = forge_entry_bytes(bytes, entry).expect("entry bytes");
    let block_a: ForgeBlock = parse_block(container).expect("block a");
    let rest: &[u8] = &container[block_a.total_len..];
    let block_b: ForgeBlock = parse_block(rest).expect("block b");
    assert_eq!(block_a.total_len + block_b.total_len, container.len());
    let mut decoder: BlockDecoder = BlockDecoder::new();
    let meta: Vec<u8> = decoder
        .decode(container, &block_a, "a", CAP)
        .expect("decode a");
    let payload: Vec<u8> = decoder.decode(rest, &block_b, "b", CAP).expect("decode b");
    (block_a, meta, block_b, payload)
}

fn respec(bytes: &[u8], archive: &ForgeArchive, original: &ForgeWriteSpec) -> ForgeWriteSpec {
    let mut spec: ForgeWriteSpec = ForgeWriteSpec {
        version: archive.header.version,
        block_magic: original.block_magic,
        pack_method: original.pack_method,
        packer: original.packer,
        chunk_bytes: original.chunk_bytes,
        tables: archive.tables.len(),
        free_slots: archive.free_slots,
        meta_names: archive
            .entries
            .iter()
            .any(|e: &ForgeEntry| e.meta.as_ref().is_some_and(|m| m.name.is_some())),
        entries: Vec::new(),
    };
    for entry in &archive.entries {
        let container: &[u8] = forge_entry_bytes(bytes, entry).expect("entry bytes");
        let body: ForgeWriteBody = match entry.kind {
            ForgeEntryKind::Descriptor => {
                ForgeWriteBody::Descriptor(parse_descriptor(container).expect("descriptor"))
            }
            ForgeEntryKind::FastLoadToc => {
                ForgeWriteBody::FastLoadToc(parse_fast_load_toc(container).expect("toc"))
            }
            ForgeEntryKind::RawRiff => ForgeWriteBody::RawRiff(container.to_vec()),
            ForgeEntryKind::FileContainer { magic } => {
                assert_eq!(magic, original.block_magic);
                let (block_a, meta, block_b, payload) = decode_entry(bytes, entry);
                assert_eq!(block_a.pack_method, original.pack_method);
                assert_eq!(block_b.pack_method, original.pack_method);
                let ForgeSubFileIndex::Records(subfiles) =
                    parse_subfile_index(&meta).expect("subfile index")
                else {
                    panic!("authored sub-file index must parse as records");
                };
                let (name, file_type, timestamp): (Option<String>, u32, u32) = entry
                    .meta
                    .as_ref()
                    .map_or((None, 0, 0), |m| (m.name.clone(), m.file_type, m.timestamp));
                ForgeWriteBody::File(ForgeWriteFile {
                    name,
                    file_type,
                    timestamp,
                    subfiles,
                    payload,
                })
            }
            ForgeEntryKind::Empty | ForgeEntryKind::Unknown { .. } => {
                ForgeWriteBody::Raw(container.to_vec())
            }
        };
        spec.entries.push(ForgeWriteEntry {
            uid: entry.uid,
            body,
        });
    }
    spec
}

#[test]
fn every_authored_archive_round_trips_byte_for_byte_through_the_writer() {
    for name in FORGE_FIXTURES {
        let spec: ForgeWriteSpec = spec_for(name);
        let bytes: Vec<u8> = write_forge(&spec);
        let archive: ForgeArchive = parse_forge(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(archive.header.version, spec.version, "{name}");
        assert_eq!(
            archive.header.header_len,
            header_len_for(spec.version),
            "{name}"
        );
        assert_eq!(archive.tables.len(), spec.tables, "{name}");
        assert_eq!(archive.free_slots, spec.free_slots, "{name}");
        assert_eq!(archive.entries.len(), spec.entries.len(), "{name}");
        assert_eq!(archive.directories, 2 * spec.tables, "{name}");
        assert_eq!(
            archive.tables.last().map(|t: &ForgeTable| t.next_pos_fat),
            Some(-1),
            "{name}"
        );
        for (entry, wanted) in archive.entries.iter().zip(&spec.entries) {
            assert_eq!(entry.uid, wanted.uid, "{name} uid");
            assert_eq!(entry.uid_opaque, spec.version == 33, "{name} opacity flag");
            assert!(entry.page_aligned, "{name} entry {:x} alignment", entry.uid);
            match &wanted.body {
                ForgeWriteBody::File(file) => {
                    assert!(matches!(entry.kind, ForgeEntryKind::FileContainer { .. }));
                    let (_, meta, _, payload) = decode_entry(&bytes, entry);
                    assert_eq!(payload, file.payload, "{name} payload {:x}", entry.uid);
                    assert_eq!(
                        parse_subfile_index(&meta).unwrap(),
                        ForgeSubFileIndex::Records(file.subfiles.clone())
                    );
                    let records = parse_flat_archive(&payload, "t").unwrap();
                    assert_eq!(records.len(), file.subfiles.len());
                    if spec.meta_names {
                        let meta = entry.meta.as_ref().expect("meta record");
                        assert_eq!(meta.name, file.name);
                        assert_eq!(meta.file_type, file.file_type);
                        assert_eq!(meta.timestamp, file.timestamp);
                        assert_eq!(meta.data_size, entry.size);
                    } else {
                        assert!(entry.meta.is_none(), "{name} has no meta names");
                    }
                }
                ForgeWriteBody::Descriptor(fields) => {
                    assert_eq!(entry.kind, ForgeEntryKind::Descriptor);
                    assert_eq!(
                        &parse_descriptor(forge_entry_bytes(&bytes, entry).unwrap()).unwrap(),
                        fields
                    );
                }
                ForgeWriteBody::FastLoadToc(toc) => {
                    assert_eq!(entry.kind, ForgeEntryKind::FastLoadToc);
                    assert_eq!(
                        &parse_fast_load_toc(forge_entry_bytes(&bytes, entry).unwrap()).unwrap(),
                        toc
                    );
                }
                ForgeWriteBody::RawRiff(riff) => {
                    assert_eq!(entry.kind, ForgeEntryKind::RawRiff);
                    assert_eq!(forge_entry_bytes(&bytes, entry).unwrap(), riff.as_slice());
                }
                ForgeWriteBody::Raw(_) => panic!("{name} has no raw entries"),
            }
        }
        let rebuilt: ForgeWriteSpec = respec(&bytes, &archive, &spec);
        assert_eq!(write_forge(&rebuilt), bytes, "{name} byte identity");
    }
}

#[test]
fn a_changed_payload_byte_changes_the_rewritten_archive() {
    let mut spec: ForgeWriteSpec = spec_for("v34_min.forge");
    let bytes: Vec<u8> = write_forge(&spec);
    if let ForgeWriteBody::File(file) = &mut spec.entries[1].body {
        file.payload[40] ^= 1;
    }
    assert_ne!(write_forge(&spec), bytes);
}

fn manifest_fields(manifest: &str, name: &str) -> (String, usize) {
    let mut lines = manifest.lines();
    while let Some(line) = lines.next() {
        if line.trim() == format!("path = \"{name}\"") {
            let size: usize = lines
                .next()
                .and_then(|l| l.strip_prefix("size_bytes = "))
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| panic!("size_bytes row after {name}"));
            let sha: String = lines
                .next()
                .and_then(|l| l.strip_prefix("sha256 = \""))
                .map_or_else(
                    || panic!("sha256 row after {name}"),
                    |v| v.trim_end_matches('"').to_owned(),
                );
            return (sha, size);
        }
    }
    panic!("MANIFEST.toml has no row for {name}");
}

#[test]
fn committed_forge_fixtures_match_the_writer_and_their_manifest() {
    let manifest: String = String::from_utf8(required_fixture(FIXTURE_DIR, "MANIFEST.toml"))
        .expect("manifest is utf-8");
    for name in FORGE_FIXTURES {
        let committed: Vec<u8> = required_fixture(FIXTURE_DIR, name);
        assert_eq!(
            committed,
            write_forge(&spec_for(name)),
            "{name} drifted from its writer"
        );
        let (sha, size): (String, usize) = manifest_fields(&manifest, name);
        assert_eq!(sha, sha256_hex(&committed), "{name} manifest sha256");
        assert_eq!(size, committed.len(), "{name} manifest size");
    }
    for name in DEPGRAPH_FIXTURES {
        let committed: Vec<u8> = required_fixture(FIXTURE_DIR, name);
        assert_eq!(
            committed,
            depgraph_for(name),
            "{name} drifted from its writer"
        );
        let (sha, size): (String, usize) = manifest_fields(&manifest, name);
        assert_eq!(sha, sha256_hex(&committed), "{name} manifest sha256");
        assert_eq!(size, committed.len(), "{name} manifest size");
    }
}

fn fat_record_offset(archive: &ForgeArchive, slot: usize) -> usize {
    archive.tables[0].pos_fat as usize + slot * 20
}

#[test]
fn v34_fat_fields_are_scrambled_on_disk_and_validated_after_descrambling() {
    let bytes: Vec<u8> = write_forge(&spec_for("v34_min.forge"));
    let archive: ForgeArchive = parse_forge(&bytes).unwrap();
    let at: usize = fat_record_offset(&archive, 1);
    let raw_offset: u64 = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    let raw_uid: u64 = u64::from_le_bytes(bytes[at + 8..at + 16].try_into().unwrap());
    let raw_size: u32 = u32::from_le_bytes(bytes[at + 16..at + 20].try_into().unwrap());
    assert_ne!(raw_offset, archive.entries[1].data_offset);
    assert_ne!(raw_uid, archive.entries[1].uid);
    assert_ne!(raw_size, archive.entries[1].size);
    assert_eq!(archive.entries[0].uid, 0x10);
    assert_eq!(archive.entries[3].uid, 0xBE0);

    let mut shifted: Vec<u8> = bytes;
    shifted[at + 5] ^= 0x01;
    let error: Error = parse_forge(&shifted).unwrap_err();
    assert!(matches!(error, Error::ForgeMalformed(_)), "{error}");
    assert!(error.to_string().contains("runs past"), "{error}");

    let v33: Vec<u8> = write_forge(&spec_for("v33_min.forge"));
    let clear: ForgeArchive = parse_forge(&v33).unwrap();
    let at33: usize = fat_record_offset(&clear, 1);
    assert_eq!(
        u64::from_le_bytes(v33[at33..at33 + 8].try_into().unwrap()),
        clear.entries[1].data_offset
    );
    assert!(clear.entries.iter().all(|e: &ForgeEntry| e.uid_opaque));
}

fn first_file_entry(archive: &ForgeArchive) -> &ForgeEntry {
    archive
        .entries
        .iter()
        .find(|e: &&ForgeEntry| matches!(e.kind, ForgeEntryKind::FileContainer { .. }))
        .expect("a file container")
}

fn block_b_start(bytes: &[u8], entry: &ForgeEntry) -> usize {
    let container: &[u8] = forge_entry_bytes(bytes, entry).unwrap();
    entry.data_offset as usize + parse_block(container).unwrap().total_len
}

fn decode_first_file(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let archive: ForgeArchive = parse_forge(bytes)?;
    let entry: &ForgeEntry = first_file_entry(&archive);
    let container: &[u8] = forge_entry_bytes(bytes, entry)?;
    let block_a: ForgeBlock = parse_block(container)?;
    let rest: &[u8] = &container[block_a.total_len..];
    let block_b: ForgeBlock = parse_block(rest)?;
    let mut decoder: BlockDecoder = BlockDecoder::new();
    decoder.decode(container, &block_a, "a", CAP)?;
    decoder.decode(rest, &block_b, "b", CAP)
}

#[test]
fn hostile_header_and_table_mutations_are_typed_refusals() {
    let bytes: Vec<u8> = write_forge(&spec_for("v34_min.forge"));
    let archive: ForgeArchive = parse_forge(&bytes).unwrap();
    let header_len: usize = archive.header.header_len;

    let mut version: Vec<u8> = bytes.clone();
    version[9..13].copy_from_slice(&31u32.to_le_bytes());
    assert!(matches!(
        parse_forge(&version).unwrap_err(),
        Error::ForgeUnsupportedVersion { version: 31, .. }
    ));

    let mut tables: Vec<u8> = bytes.clone();
    tables[header_len - 12..header_len - 8].copy_from_slice(&0u32.to_le_bytes());
    assert!(matches!(
        parse_forge(&tables).unwrap_err(),
        Error::ForgeMalformed(_)
    ));

    let mut table_pos: Vec<u8> = bytes.clone();
    table_pos[header_len - 8..header_len].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
    assert!(matches!(
        parse_forge(&table_pos).unwrap_err(),
        Error::ForgeMalformed(_)
    ));

    let mut loop_chain: Vec<u8> = bytes.clone();
    let table_at: usize = archive.tables[0].position as usize;
    loop_chain[table_at + 16..table_at + 24].copy_from_slice(&(table_at as i64).to_le_bytes());
    let error: Error = parse_forge(&loop_chain).unwrap_err();
    assert!(error.to_string().contains("revisits"), "{error}");

    let mut slots: Vec<u8> = bytes;
    slots[table_at + 28..table_at + 32].copy_from_slice(&0x7FFF_FFFFi32.to_le_bytes());
    assert!(matches!(
        parse_forge(&slots).unwrap_err(),
        Error::ForgeMalformed(_)
    ));

    let v33: Vec<u8> = write_forge(&spec_for("v33_min.forge"));
    let clear: ForgeArchive = parse_forge(&v33).unwrap();
    let at: usize = fat_record_offset(&clear, 1) + 16;
    let mut inflated: Vec<u8> = v33;
    inflated[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    let error: Error = parse_forge(&inflated).unwrap_err();
    assert!(error.to_string().contains("runs past"), "{error}");

    assert!(matches!(
        parse_forge(b"scimitar\0").unwrap_err(),
        Error::ForgeMalformed(_)
    ));
    assert!(matches!(
        parse_forge(b"").unwrap_err(),
        Error::ForgeMalformed(_)
    ));
}

#[test]
fn hostile_block_mutations_are_typed_refusals() {
    let stored: Vec<u8> = write_forge(&spec_for("v34_min.forge"));
    let archive: ForgeArchive = parse_forge(&stored).unwrap();
    let entry: &ForgeEntry = first_file_entry(&archive);
    let block_a: usize = entry.data_offset as usize;
    let block_b: usize = block_b_start(&stored, entry);

    let mut count: Vec<u8> = stored.clone();
    count[block_a + 15..block_a + 17].copy_from_slice(&0xFFFFu16.to_le_bytes());
    let error: Error = decode_first_file(&count).unwrap_err();
    assert!(matches!(error, Error::ForgeMalformed(_)), "{error}");
    assert!(error.to_string().contains("chunk cap"), "{error}");

    let mut shrunk: Vec<u8> = stored.clone();
    shrunk[block_b + 19..block_b + 23].copy_from_slice(&0u32.to_le_bytes());
    assert!(matches!(
        decode_first_file(&shrunk).unwrap_err(),
        Error::ForgeChunkSize { chunk: 0, .. }
    ));

    let mut oversize: Vec<u8> = stored.clone();
    oversize[block_b + 19..block_b + 23].copy_from_slice(&(MAX_CHUNK_UNPACKED + 1).to_le_bytes());
    let error: Error = decode_first_file(&oversize).unwrap_err();
    assert!(error.to_string().contains("-byte cap"), "{error}");

    let mut flipped: Vec<u8> = stored.clone();
    let data_at: usize = block_b + 19 + 8 + 4;
    flipped[data_at] ^= 0x10;
    assert!(matches!(
        decode_first_file(&flipped).unwrap_err(),
        Error::ForgeChunkChecksum { chunk: 0, .. }
    ));

    let mut magic: Vec<u8> = stored;
    magic[block_a + 7] = 0x11;
    assert!(matches!(
        parse_block(&magic[block_a..]).unwrap_err(),
        Error::ForgeBlockUnsupported { .. }
    ));
    let demoted: ForgeArchive = parse_forge(&magic).unwrap();
    assert!(matches!(
        demoted.entries[1].kind,
        ForgeEntryKind::Unknown { .. }
    ));

    let zstd: Vec<u8> = write_forge(&spec_for("v34_zstd.forge"));
    let zarchive: ForgeArchive = parse_forge(&zstd).unwrap();
    let zentry: &ForgeEntry = first_file_entry(&zarchive);
    let zblock_b: usize = block_b_start(&zstd, zentry);
    let block: ForgeBlock = parse_block(&zstd[zblock_b..]).unwrap();
    assert!(
        block.compressed_chunks() >= 1,
        "fixture must carry a compressed chunk"
    );

    let mut bomb: Vec<u8> = zstd.clone();
    bomb[zblock_b + 19..zblock_b + 23].copy_from_slice(&MAX_CHUNK_UNPACKED.to_le_bytes());
    assert!(matches!(
        decode_first_file(&bomb).unwrap_err(),
        Error::ForgeChunkSize { chunk: 0, .. }
    ));

    let mut unknown_method: Vec<u8> = zstd.clone();
    unknown_method[zblock_b + 10..zblock_b + 12].copy_from_slice(&2u16.to_le_bytes());
    assert!(matches!(
        decode_first_file(&unknown_method).unwrap_err(),
        Error::ForgePackMethodUnsupported { method: 2, .. }
    ));

    let mut oodle_claim: Vec<u8> = zstd.clone();
    oodle_claim[zblock_b + 10..zblock_b + 12].copy_from_slice(&15u16.to_le_bytes());
    let error: Error = decode_first_file(&oodle_claim).unwrap_err();
    assert!(
        matches!(
            error,
            Error::ForgeOodle {
                chunk: 0,
                detail: OodleError::BadBlockHeader { .. },
                ..
            }
        ),
        "{error}"
    );

    let mut streaming_compressed: Vec<u8> = zstd;
    streaming_compressed[zblock_b + 10..zblock_b + 12].copy_from_slice(&7u16.to_le_bytes());
    let error: Error = decode_first_file(&streaming_compressed).unwrap_err();
    assert!(
        matches!(
            error,
            Error::ForgePackMethodUnsupported { method: 7, .. }
                | Error::ForgeChunkChecksum { .. }
                | Error::ForgeMalformed(_)
        ),
        "{error}"
    );
}

fn read_out(dir: &Path, name: &str) -> Vec<u8> {
    std::fs::read(dir.join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

#[test]
fn extraction_writes_the_layout_and_one_file_per_entry_and_record() {
    let bytes: Vec<u8> = write_forge(&spec_for("v34_min.forge"));
    let dir = scratch("extract-v34-min");
    let result: ExtractionResult = extract_to(ContainerKind::Forge, &bytes, dir.path()).unwrap();
    assert_eq!(result.kind, ContainerKind::Forge);
    assert!(
        result.integrity_violations.is_empty(),
        "{:?}",
        result.integrity_violations
    );
    let layout: serde_json::Value =
        serde_json::from_slice(&read_out(dir.path(), ".disrobe-forge-layout.json")).unwrap();
    let entries: &Vec<serde_json::Value> = layout["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 4);
    assert!(
        entries
            .iter()
            .all(|e: &serde_json::Value| e["extracted"] == true)
    );
    assert_eq!(entries[1]["type_name"], "CompiledMeshObject");
    assert_eq!(entries[2]["records"], 2);
    assert_eq!(entries[2]["record_names_withheld"], 1);
    assert_eq!(entries[1]["record_names_withheld"], 0);
    assert_eq!(entries[1]["blocks"][1]["pack_method"], "oodle-leviathan");
    assert_eq!(entries[1]["blocks"][1]["compressed_chunks"], 0);

    assert!(
        dir.path()
            .join("0000000000000010.globalmeta.json")
            .is_file()
    );
    assert!(
        dir.path()
            .join("0000000000000be0.fastload-toc.json")
            .is_file()
    );
    assert_eq!(
        read_out(
            dir.path(),
            "0100000000000001/0100000000000001.CompiledMeshObject"
        ),
        patterned_bytes(1, 3000)
    );
    assert_eq!(
        read_out(
            dir.path(),
            "0100000000000002/0100000000000003.TextureMapSpec"
        ),
        patterned_bytes(3, 90)
    );
    assert_eq!(
        read_out(dir.path(), "0100000000000002/0100000000000002.Material"),
        patterned_bytes(2, 700)
    );
    let payload: Vec<u8> = read_out(dir.path(), "0100000000000002.Material.bin");
    assert_eq!(parse_flat_archive(&payload, "t").unwrap().len(), 2);
    let meta: Vec<u8> = read_out(dir.path(), "0100000000000001.meta.bin");
    assert_eq!(
        parse_subfile_index(&meta).unwrap().single_uid(),
        Some(0x0100_0000_0000_0001)
    );
    let descriptor: serde_json::Value =
        serde_json::from_slice(&read_out(dir.path(), "0000000000000010.globalmeta.json")).unwrap();
    assert_eq!(
        descriptor[0]["value"]["text"],
        "//disrobe-fixture/livecert/"
    );
}

#[test]
fn named_v30_entries_extract_under_their_archive_names() {
    let bytes: Vec<u8> = write_forge(&spec_for("v30_named.forge"));
    let dir = scratch("extract-v30");
    let result: ExtractionResult = extract_to(ContainerKind::Forge, &bytes, dir.path()).unwrap();
    assert!(
        result.integrity_violations.is_empty(),
        "{:?}",
        result.integrity_violations
    );
    let payload: Vec<u8> = read_out(dir.path(), "data/hero.mesh");
    assert_eq!(
        parse_flat_archive(&payload, "t").unwrap()[0]
            .name
            .as_deref(),
        Some("hero_body")
    );
    assert_eq!(
        read_out(dir.path(), "0600000000000001/hero_body"),
        patterned_bytes(61, 9000)
    );
    assert_eq!(
        read_out(dir.path(), "0600000000000002/hero_diffuse_spec"),
        patterned_bytes(63, 300)
    );
    assert!(dir.path().join("textures/hero.tex").is_file());
    let toc: serde_json::Value =
        serde_json::from_slice(&read_out(dir.path(), "0000000000000be0.fastload-toc.json"))
            .unwrap();
    assert_eq!(toc["name"], "fixture-toc");
    assert_eq!(
        result
            .encoding
            .get("data/hero.mesh")
            .copied()
            .map(|c| format!("{c:?}")),
        Some("Zstd".to_owned())
    );
}

#[test]
fn riff_entries_and_multitable_archives_extract_every_entry() {
    let riff: Vec<u8> = write_forge(&spec_for("v34_riff.forge"));
    let dir = scratch("extract-riff");
    let result: ExtractionResult = extract_to(ContainerKind::Forge, &riff, dir.path()).unwrap();
    assert!(
        result.integrity_violations.is_empty(),
        "{:?}",
        result.integrity_violations
    );
    let wem: Vec<u8> = read_out(dir.path(), "0300000000000001.wem");
    assert!(wem.starts_with(b"RIFF"));
    assert_eq!(wem.len(), 600 + 12);
    assert!(dir.path().join("0300000000000003.wem").is_file());

    let multi: Vec<u8> = write_forge(&spec_for("v34_multitable.forge"));
    let dir2 = scratch("extract-multitable");
    let result: ExtractionResult = extract_to(ContainerKind::Forge, &multi, dir2.path()).unwrap();
    assert!(
        result.integrity_violations.is_empty(),
        "{:?}",
        result.integrity_violations
    );
    let layout: serde_json::Value =
        serde_json::from_slice(&read_out(dir2.path(), ".disrobe-forge-layout.json")).unwrap();
    assert_eq!(layout["tables"].as_array().unwrap().len(), 3);
    assert_eq!(layout["entries"].as_array().unwrap().len(), 6);
    for n in 1..=6u64 {
        assert_eq!(
            read_out(
                dir2.path(),
                &format!(
                    "{:016x}/{:016x}.Entity",
                    0x0400_0000_0000_0000 + n,
                    0x0400_0000_0000_0000 + n
                )
            ),
            patterned_bytes(40 + n, 200 * n as usize)
        );
    }
}

#[test]
fn forge_and_scimitar_blocks_are_detected_classified_and_carved() {
    for name in FORGE_FIXTURES {
        let bytes: Vec<u8> = write_forge(&spec_for(name));
        assert_eq!(
            detect_container(&bytes),
            Some(ContainerKind::Forge),
            "{name}"
        );
        let classified = classify_input(Path::new(name), &bytes);
        assert!(
            matches!(
                classified.primary_action,
                Action::ExtractArchive {
                    container: ContainerKind::Forge
                }
            ),
            "{name}: {:?}",
            classified.primary_action
        );
    }
    for name in DEPGRAPH_FIXTURES {
        let bytes: Vec<u8> = depgraph_for(name);
        assert_eq!(
            detect_container(&bytes),
            Some(ContainerKind::ScimitarBlock),
            "{name}"
        );
    }
    let archive: Vec<u8> = write_forge(&spec_for("v34_zstd.forge"));
    let mut blob: Vec<u8> = vec![0u8; 4096];
    blob.extend_from_slice(&archive);
    blob.extend(std::iter::repeat_n(0xAAu8, 2048));
    let report: CarveReport = carve_recursive(&blob, "blob", CarveConfig::new(1), None);
    let found = report
        .root
        .chunks
        .iter()
        .find(|c| c.kind == Some(ContainerKind::Forge))
        .expect("carved forge chunk");
    assert_eq!(found.start, 4096);
    let parsed: ForgeArchive = parse_forge(&archive).unwrap();
    assert_eq!(found.end, 4096 + archive_extent(&parsed));
    assert!(archive_extent(&parsed) > 16_384);
}

#[test]
fn depgraph_sidecars_decode_to_their_links_and_extract() {
    for name in DEPGRAPH_FIXTURES {
        let bytes: Vec<u8> = depgraph_for(name);
        let graph: DepGraph = parse_depgraph(&bytes, CAP).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(graph.links, depgraph_links(), "{name}");
        assert_eq!(graph.block.total_len, bytes.len());
        let dir = scratch(&format!("depgraph-{}", name.replace('.', "-")));
        let result: ExtractionResult =
            extract_to(ContainerKind::ScimitarBlock, &bytes, dir.path()).unwrap();
        assert!(
            result.integrity_violations.is_empty(),
            "{:?}",
            result.integrity_violations
        );
        let links: serde_json::Value =
            serde_json::from_slice(&read_out(dir.path(), "depgraph.json")).unwrap();
        assert_eq!(links.as_array().unwrap().len(), 40);
        assert_eq!(
            read_out(dir.path(), "block0.bin"),
            write_depgraph_payload(&depgraph_links())
        );
        let mut truncated: Vec<u8> = bytes.clone();
        truncated.truncate(bytes.len() - 1);
        assert!(parse_depgraph(&truncated, CAP).is_err(), "{name}");
        let mut padded: Vec<u8> = bytes.clone();
        padded.push(0);
        assert!(matches!(
            parse_depgraph(&padded, CAP).unwrap_err(),
            Error::ForgeMalformed(_)
        ));
    }
}

#[test]
fn v34_scramble_and_descramble_invert_each_other_on_every_bit() {
    use disrobe_binfmt::containers::forge::{
        V34_OFFSET_K1, V34_OFFSET_K2, descramble_v34_offset, descramble_v34_size,
        descramble_v34_uid,
    };
    for shift in 0..64u32 {
        let value: u64 = 1u64 << shift;
        assert_eq!(descramble_v34_offset(scramble_v34_offset(value)), value);
        assert_eq!(descramble_v34_uid(scramble_v34_uid(value)), value);
        let mixed: u64 = value.wrapping_mul(0x9E37_79B9);
        assert_eq!(descramble_v34_offset(scramble_v34_offset(mixed)), mixed);
    }
    for shift in 0..32u32 {
        let value: u32 = 1u32 << shift;
        assert_eq!(descramble_v34_size(scramble_v34_size(value)), value);
    }
    assert_eq!(descramble_v34_uid(scramble_v34_uid(0x10)), 0x10);
    assert_eq!(descramble_v34_uid(scramble_v34_uid(0xBE0)), 0xBE0);
    let wrong: u64 = (V34_OFFSET_K1 ^ 1).wrapping_sub(scramble_v34_offset(4096) ^ V34_OFFSET_K2);
    assert_ne!(wrong, 4096, "a changed constant must break the round trip");
}

#[test]
fn sub_file_indexes_flat_archives_and_depgraph_payloads_round_trip() {
    use disrobe_binfmt::containers::forge_depgraph::{
        looks_like_depgraph_payload, parse_depgraph_payload,
    };
    use disrobe_binfmt::containers::forge_flat::ForgeSubFile;
    let records: Vec<ForgeSubFile> = vec![
        ForgeSubFile {
            uid: 0x1122_3344_5566_7788,
            length: 4096,
        },
        ForgeSubFile {
            uid: 0x10,
            length: 7,
        },
    ];
    let index: Vec<u8> = write_subfile_index(&records);
    assert_eq!(
        parse_subfile_index(&index).unwrap(),
        ForgeSubFileIndex::Records(records.clone())
    );
    let mut wide: Vec<u8> = 1i32.to_le_bytes().to_vec();
    wide.extend_from_slice(&0x77u64.to_le_bytes());
    wide.extend_from_slice(&(0x4000_0000u32 | 0x12C).to_le_bytes());
    wide.extend(std::iter::repeat_n(0xA5u8, 16));
    let parsed: ForgeSubFileIndex = parse_subfile_index(&wide).unwrap();
    assert_eq!(parsed.single_uid(), Some(0x77));
    assert_eq!(parsed.lengths(), Some(vec![0x12C]));
    let mut odd: Vec<u8> = 1i32.to_le_bytes().to_vec();
    odd.extend(std::iter::repeat_n(0u8, 20));
    assert_eq!(
        parse_subfile_index(&odd).unwrap(),
        ForgeSubFileIndex::Opaque {
            declared_count: 1,
            bytes: 24
        }
    );
    assert_eq!(
        ForgeSubFileIndex::Records(records[1..].to_vec()).single_uid(),
        Some(0x10)
    );
    let specs: [FlatRecordSpec<'_>; 2] = [
        FlatRecordSpec {
            name: Some("hero/body.material"),
            name_flags: 0,
            file_type: 0x85C8_17C3,
            uid: 0xABCD_EF01_2345_6789,
            payload: b"material-bytes",
        },
        FlatRecordSpec {
            name: None,
            name_flags: 0,
            file_type: 0x1323_7FE9,
            uid: 0x42,
            payload: &[],
        },
    ];
    let flat: Vec<u8> = write_flat_archive(&specs);
    let parsed: Vec<disrobe_binfmt::containers::forge_flat::ForgeFlatRecord> =
        parse_flat_archive(&flat, "test").unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].name.as_deref(), Some("hero/body.material"));
    assert_eq!(parsed[0].file_type, 0x85C8_17C3);
    assert_eq!(
        &flat[parsed[0].payload_offset..parsed[0].payload_offset + parsed[0].payload_len],
        b"material-bytes"
    );
    assert_ne!(
        &flat[4..4 + 18],
        b"hero/body.material",
        "names are stored encoded"
    );
    assert_eq!(parsed[1].name, None);
    let payload: Vec<u8> = write_depgraph_payload(&depgraph_links());
    assert!(looks_like_depgraph_payload(&payload));
    assert_eq!(parse_depgraph_payload(&payload).unwrap(), depgraph_links());
    assert!(parse_depgraph_payload(&payload[..payload.len() - 1]).is_err());
    assert!(parse_depgraph_payload(&[0x03]).is_err());
}

#[test]
fn oodle_chunks_inside_forge_blocks_decode_and_name_their_refusals() {
    let bytes: Vec<u8> = write_forge(&spec_for("v34_leviathan.forge"));
    let archive: ForgeArchive = parse_forge(&bytes).unwrap();
    let entry: &ForgeEntry = first_file_entry(&archive);
    let (_, _, block_b, payload) = decode_entry(&bytes, entry);
    assert!(
        block_b.compressed_chunks() >= 2,
        "fixture must carry Leviathan chunks"
    );
    let records: Vec<disrobe_binfmt::containers::forge_flat::ForgeFlatRecord> =
        parse_flat_archive(&payload, "t").unwrap();
    assert_eq!(
        &payload[records[0].payload_offset..records[0].payload_offset + records[0].payload_len],
        patterned_bytes(71, 40_000).as_slice()
    );
    let start: usize = block_b_start(&bytes, entry);
    let chunk: disrobe_binfmt::containers::forge_block::ForgeChunk = block_b.chunks[0];
    assert_ne!(
        chunk.unpacked, chunk.packed,
        "first payload chunk is compressed"
    );
    let data_at: usize = start + chunk.data_offset;
    let mut unsigned: Vec<u8> = bytes;
    unsigned[data_at + 1] = 0x07;
    let error: Error = decode_first_file(&unsigned).unwrap_err();
    assert!(
        matches!(error, Error::ForgeChunkChecksum { .. }),
        "the Adler-32 guards the Oodle bytes first: {error}"
    );
    let mut resigned: Vec<u8> = unsigned;
    let checksum: u32 = disrobe_binfmt::containers::forge_block::adler32_seed0(
        &resigned[data_at..data_at + chunk.packed as usize],
    );
    resigned[data_at - 4..data_at].copy_from_slice(&checksum.to_le_bytes());
    let error: Error = decode_first_file(&resigned).unwrap_err();
    assert!(
        matches!(
            error,
            Error::ForgeOodle {
                detail: OodleError::UnknownDecoder { id: 7 },
                ..
            }
        ),
        "{error}"
    );
}
