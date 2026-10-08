#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use disrobe_binfmt::containers::forge::{
    ForgeArchive, ForgeEntry, ForgeEntryKind, parse_descriptor, parse_fast_load_toc,
    parse_forge_from, read_entry,
};
use disrobe_binfmt::containers::forge_block::{
    BlockDecoder, ForgeBlock, chunk_data, parse_block, verify_checksums,
};
use disrobe_binfmt::containers::forge_depgraph::{DepGraph, parse_depgraph};
use disrobe_binfmt::containers::forge_flat::{
    ForgeFlatRecord, ForgeSubFileIndex, parse_flat_archive, parse_subfile_index,
};
use disrobe_binfmt::containers::forge_types::{type_id, type_label};
use disrobe_binfmt::containers::oodle::{OodleBlockHeader, OodleCensus, parse_block_header};

const DIR_ENV: &str = "DISROBE_FORGE_DIR";
const PREREQUISITE: &str = "disrobe-binfmt::forge-local";
const FILTER_ENV: &str = "DISROBE_FORGE_FILTER";
const THREADS_ENV: &str = "DISROBE_FORGE_THREADS";
const ENTRY_CAP: u64 = 1 << 30;
const MAX_REPORTED_FAILURES: usize = 40;
const MAGIC_WINDOW: usize = 256;

#[derive(Default)]
struct Tally {
    archives_by_version: BTreeMap<u32, usize>,
    entries_by_kind: BTreeMap<&'static str, usize>,
    blocks_by_magic_method: BTreeMap<String, usize>,
    chunks_stored: usize,
    chunks_compressed: usize,
    oodle_headers: BTreeMap<String, usize>,
    unpacked_bytes: u64,
    decoded_bytes: u64,
    file_containers: usize,
    single_uid_matches: usize,
    opaque_subfile_indexes: usize,
    wide_subfile_indexes: usize,
    records_by_type: BTreeMap<String, usize>,
    record_heads: BTreeMap<String, BTreeMap<String, usize>>,
    predicted_magic_checked: BTreeMap<&'static str, usize>,
    wide_flags: BTreeMap<u8, usize>,
    sound_media: BTreeMap<&'static str, usize>,
    opaque_shapes: BTreeMap<String, usize>,
    riff_entries: usize,
    descriptors: usize,
    tocs: usize,
    depgraphs: usize,
    depgraph_links: usize,
    census: OodleCensus,
    failures: Vec<String>,
    failure_count: usize,
}

impl Tally {
    fn fail(&mut self, message: String) {
        self.failure_count += 1;
        if self.failures.len() < MAX_REPORTED_FAILURES {
            self.failures.push(message);
        }
    }

    fn merge(&mut self, other: Self) {
        fn add<K: Ord>(into: &mut BTreeMap<K, usize>, from: BTreeMap<K, usize>) {
            for (key, value) in from {
                *into.entry(key).or_default() += value;
            }
        }
        add(&mut self.archives_by_version, other.archives_by_version);
        add(&mut self.entries_by_kind, other.entries_by_kind);
        add(
            &mut self.blocks_by_magic_method,
            other.blocks_by_magic_method,
        );
        add(&mut self.oodle_headers, other.oodle_headers);
        add(&mut self.records_by_type, other.records_by_type);
        add(
            &mut self.predicted_magic_checked,
            other.predicted_magic_checked,
        );
        add(&mut self.wide_flags, other.wide_flags);
        add(&mut self.sound_media, other.sound_media);
        add(&mut self.opaque_shapes, other.opaque_shapes);
        for (kind, heads) in other.record_heads {
            add(self.record_heads.entry(kind).or_default(), heads);
        }
        self.chunks_stored += other.chunks_stored;
        self.chunks_compressed += other.chunks_compressed;
        self.unpacked_bytes += other.unpacked_bytes;
        self.decoded_bytes += other.decoded_bytes;
        self.file_containers += other.file_containers;
        self.single_uid_matches += other.single_uid_matches;
        self.opaque_subfile_indexes += other.opaque_subfile_indexes;
        self.wide_subfile_indexes += other.wide_subfile_indexes;
        self.riff_entries += other.riff_entries;
        self.descriptors += other.descriptors;
        self.tocs += other.tocs;
        self.depgraphs += other.depgraphs;
        self.depgraph_links += other.depgraph_links;
        self.census.merge(&other.census);
        self.failure_count += other.failure_count;
        for failure in other.failures {
            if self.failures.len() < MAX_REPORTED_FAILURES {
                self.failures.push(failure);
            }
        }
    }
}

fn listed(dir: &Path, extension: &str) -> Vec<PathBuf> {
    let filter: Option<String> = std::env::var(FILTER_ENV)
        .ok()
        .filter(|f: &String| !f.is_empty());
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{DIR_ENV}={}: {e}", dir.display()))
        .filter_map(Result::ok)
        .map(|entry: std::fs::DirEntry| entry.path())
        .filter(|path: &PathBuf| {
            path.extension()
                .is_some_and(|ext: &std::ffi::OsStr| ext.eq_ignore_ascii_case(extension))
        })
        .filter(|path: &PathBuf| {
            filter.as_ref().is_none_or(|f: &String| {
                path.file_name()
                    .and_then(|n: &std::ffi::OsStr| n.to_str())
                    .is_some_and(|n: &str| f.split(',').any(|part: &str| n.contains(part)))
            })
        })
        .collect();
    files.sort();
    files
}

fn record_block(block: &ForgeBlock, bytes: &[u8], tally: &mut Tally) {
    *tally
        .blocks_by_magic_method
        .entry(format!(
            "{} method {}",
            block.magic.label(),
            block.pack_method.code()
        ))
        .or_default() += 1;
    for chunk in &block.chunks {
        if chunk.unpacked == chunk.packed {
            tally.chunks_stored += 1;
            continue;
        }
        tally.chunks_compressed += 1;
        let data: &[u8] = chunk_data(bytes, chunk).unwrap_or(&[]);
        let key: String = parse_block_header(data).map_or_else(
            |e| format!("refused: {e}"),
            |h: OodleBlockHeader| {
                format!(
                    "{} restart={} uncompressed={} checksums={}",
                    h.decoder.label(),
                    h.restart_decoder,
                    h.uncompressed,
                    h.checksums
                )
            },
        );
        *tally.oodle_headers.entry(key).or_default() += 1;
    }
}

fn hex_head(body: &[u8]) -> String {
    body.iter()
        .take(4)
        .fold(String::new(), |mut out: String, b: &u8| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

struct Prediction {
    check: &'static str,
    magic: &'static [u8],
    at: Option<usize>,
}

fn predicted_magic(type_name: &str) -> Option<Prediction> {
    match type_name {
        "CompiledSoundMedia" => Some(Prediction {
            check: "CompiledSoundMedia carries a Wwise RIFF header or a PLUG chunk at offset 16",
            magic: b"RIFF",
            at: None,
        }),
        "CompiledSoundBank" => Some(Prediction {
            check: "CompiledSoundBank carries BKHD",
            magic: b"BKHD",
            at: None,
        }),
        _ => None,
    }
}

fn check_records(payload: &[u8], records: &[ForgeFlatRecord], label: &str, tally: &mut Tally) {
    for record in records {
        let name: String = type_label(record.file_type);
        let body: &[u8] =
            &payload[record.payload_offset..record.payload_offset + record.payload_len];
        *tally.records_by_type.entry(name.clone()).or_default() += 1;
        *tally
            .record_heads
            .entry(name.clone())
            .or_default()
            .entry(hex_head(body))
            .or_default() += 1;
        *tally
            .predicted_magic_checked
            .entry("record payload leads with its own type id")
            .or_default() += 1;
        if body.get(..4) != Some(record.file_type.to_le_bytes().as_slice()) {
            tally.fail(format!(
                "{label}: record {:016x} of type {name} does not lead with its type id",
                record.uid
            ));
        }
        if name.contains("TextureMap") {
            let tag: [u8; 4] = type_id("CompiledTextureMapData").to_le_bytes();
            let present: bool = body.windows(4).take(64).any(|w: &[u8]| w == tag);
            *tally
                .predicted_magic_checked
                .entry("texture records carry the CompiledTextureMapData tag")
                .or_default() += 1;
            if !present {
                tally.fail(format!(
                    "{label}: record {:016x} of type {name} lacks the CompiledTextureMapData tag",
                    record.uid
                ));
            }
        }
        if name == "CompiledSoundMedia" {
            let riff: bool = body
                .windows(4)
                .take(MAGIC_WINDOW)
                .any(|w: &[u8]| w == b"RIFF");
            *tally
                .sound_media
                .entry(if riff {
                    "Wwise RIFF header"
                } else {
                    "PLUG chunk without RIFF"
                })
                .or_default() += 1;
        }
        if let Some(prediction) = predicted_magic(&name) {
            *tally
                .predicted_magic_checked
                .entry(prediction.check)
                .or_default() += 1;
            let found: bool = prediction.at.map_or_else(
                || {
                    body.windows(prediction.magic.len())
                        .take(MAGIC_WINDOW)
                        .any(|w: &[u8]| w == prediction.magic)
                },
                |at: usize| body.get(at..at + prediction.magic.len()) == Some(prediction.magic),
            ) || (name == "CompiledSoundMedia"
                && body.get(16..20) == Some(b"PLUG".as_slice()));
            if !found {
                tally.fail(format!(
                    "{label}: record {:016x} of type {name} fails the predicted magic check ({})",
                    record.uid, prediction.check
                ));
            }
        }
    }
}

fn check_file_container(
    container: &[u8],
    entry: &ForgeEntry,
    label: &str,
    decoder: &mut BlockDecoder,
    tally: &mut Tally,
) {
    tally.file_containers += 1;
    let block_a: ForgeBlock = match parse_block(container) {
        Ok(block) => block,
        Err(e) => return tally.fail(format!("{label}: block a: {e}")),
    };
    let rest: &[u8] = &container[block_a.total_len..];
    let block_b: ForgeBlock = match parse_block(rest) {
        Ok(block) => block,
        Err(e) => return tally.fail(format!("{label}: block b: {e}")),
    };
    if block_a.total_len + block_b.total_len != container.len() {
        return tally.fail(format!(
            "{label}: FAT size {} against reassembled blocks {} + {}",
            container.len(),
            block_a.total_len,
            block_b.total_len
        ));
    }
    for (block, bytes) in [(&block_a, container), (&block_b, rest)] {
        if let Err(e) = verify_checksums(bytes, block, label) {
            return tally.fail(format!("{label}: {e}"));
        }
        record_block(block, bytes, tally);
    }
    tally.unpacked_bytes += block_a.unpacked_total + block_b.unpacked_total;
    let meta: Vec<u8> = match decoder.decode(container, &block_a, label, ENTRY_CAP) {
        Ok(bytes) => bytes,
        Err(e) => return tally.fail(format!("{label}: block a: {e}")),
    };
    let mut probe: BlockDecoder = BlockDecoder::new();
    let payload: Vec<u8> = match probe.decode(rest, &block_b, label, ENTRY_CAP) {
        Ok(bytes) => {
            decoder.census.merge(&probe.census);
            bytes
        }
        Err(e) => {
            return tally.fail(format!(
                "{label}: block b: {e}; paths before the refusal {:?}",
                probe.census.paths
            ));
        }
    };
    if meta.len() as u64 != block_a.unpacked_total || payload.len() as u64 != block_b.unpacked_total
    {
        return tally.fail(format!(
            "{label}: decoded sizes differ from the declarations"
        ));
    }
    tally.decoded_bytes += (meta.len() + payload.len()) as u64;
    let index: ForgeSubFileIndex = match parse_subfile_index(&meta) {
        Ok(index) => index,
        Err(e) => return tally.fail(format!("{label}: sub-file index: {e}")),
    };
    let records: Vec<ForgeFlatRecord> = match parse_flat_archive(&payload, label) {
        Ok(records) => records,
        Err(e) => return tally.fail(format!("{label}: flat archive: {e}")),
    };
    if let Some(lengths) = index.lengths() {
        let total: i64 = lengths.iter().map(|&l: &i32| i64::from(l)).sum();
        if total != payload.len() as i64 {
            tally.fail(format!(
                "{label}: sub-file lengths sum to {total}, block b holds {}",
                payload.len()
            ));
        }
    }
    if let Some(uid) = index.single_uid()
        && !entry.uid_opaque
    {
        if uid == entry.uid {
            tally.single_uid_matches += 1;
        } else {
            tally.fail(format!(
                "{label}: sub-file uid {uid:016x} against the descrambled FAT uid"
            ));
        }
    }
    if let ForgeSubFileIndex::WideRecords(wide) = &index {
        tally.wide_subfile_indexes += 1;
        for record in wide {
            *tally.wide_flags.entry(record.flags).or_default() += 1;
        }
    }
    match &index {
        ForgeSubFileIndex::Records(_) | ForgeSubFileIndex::WideRecords(_) => {
            let declared: usize = index.lengths().map_or(0, |l: Vec<i32>| l.len());
            if declared != records.len() {
                tally.fail(format!(
                    "{label}: {declared} sub-files against {} flat-archive records",
                    records.len()
                ));
            }
        }
        ForgeSubFileIndex::Opaque {
            declared_count,
            bytes,
        } => {
            tally.opaque_subfile_indexes += 1;
            *tally
                .opaque_shapes
                .entry(format!(
                    "count {declared_count} bytes {bytes} records {}",
                    records.len()
                ))
                .or_default() += 1;
        }
    }
    check_records(&payload, &records, label, tally);
}

fn check_archive(path: &Path, decoder: &mut BlockDecoder, tally: &mut Tally) {
    let name: String = path.file_name().unwrap().to_string_lossy().into_owned();
    let file: File = File::open(path).unwrap_or_else(|e| panic!("{name}: open: {e}"));
    let archive: ForgeArchive = match parse_forge_from(&file) {
        Ok(archive) => archive,
        Err(e) => return tally.fail(format!("{name}: parse: {e}")),
    };
    *tally
        .archives_by_version
        .entry(archive.header.version)
        .or_default() += 1;
    for entry in &archive.entries {
        let label: String = format!("{name} entry {} uid {:016x}", entry.index, entry.uid);
        *tally.entries_by_kind.entry(entry.kind.label()).or_default() += 1;
        if !entry.page_aligned {
            tally.fail(format!(
                "{label}: entry at {} is not 4 KiB aligned",
                entry.data_offset
            ));
        }
        let container: Vec<u8> = match read_entry(&file, entry, ENTRY_CAP) {
            Ok(bytes) => bytes,
            Err(e) => {
                tally.fail(format!("{label}: read: {e}"));
                continue;
            }
        };
        match entry.kind {
            ForgeEntryKind::FileContainer { .. } => {
                check_file_container(&container, entry, &label, decoder, tally);
            }
            ForgeEntryKind::RawRiff => {
                let riff_size: u32 = u32::from_le_bytes(container[4..8].try_into().unwrap());
                if u64::from(riff_size) + 8 != u64::from(entry.size) {
                    tally.fail(format!(
                        "{label}: RIFF size {riff_size} against the FAT size"
                    ));
                }
                tally.riff_entries += 1;
            }
            ForgeEntryKind::Descriptor => match parse_descriptor(&container) {
                Ok(_) => tally.descriptors += 1,
                Err(e) => tally.fail(format!("{label}: descriptor: {e}")),
            },
            ForgeEntryKind::FastLoadToc => match parse_fast_load_toc(&container) {
                Ok(_) => tally.tocs += 1,
                Err(e) => tally.fail(format!("{label}: fast-load toc: {e}")),
            },
            ForgeEntryKind::Empty => {}
            ForgeEntryKind::Unknown { head } => {
                tally.fail(format!("{label}: unknown entry kind {head:#018x}"));
            }
        }
    }
}

fn check_depgraph(path: &Path, tally: &mut Tally) {
    let name: String = path.file_name().unwrap().to_string_lossy().into_owned();
    let bytes: Vec<u8> = std::fs::read(path).unwrap_or_else(|e| panic!("{name}: read: {e}"));
    match parse_depgraph(&bytes, ENTRY_CAP) {
        Ok(graph) => {
            let graph: DepGraph = graph;
            record_block(&graph.block, &bytes, tally);
            tally.depgraphs += 1;
            tally.depgraph_links += graph.links.len();
        }
        Err(e) => tally.fail(format!("{name}: {e}")),
    }
}

fn report(tally: &Tally) {
    println!(
        "forge oracle: archives by version {:?}",
        tally.archives_by_version
    );
    println!("forge oracle: entries by kind {:?}", tally.entries_by_kind);
    println!(
        "forge oracle: blocks by magic and pack method {:?}",
        tally.blocks_by_magic_method
    );
    println!(
        "forge oracle: chunks stored {} compressed {}; Oodle block headers {:?}",
        tally.chunks_stored, tally.chunks_compressed, tally.oodle_headers
    );
    println!(
        "forge oracle: file containers {}; unpacked bytes declared {} decoded {}",
        tally.file_containers, tally.unpacked_bytes, tally.decoded_bytes
    );
    println!("forge oracle: decoder paths {:?}", tally.census.paths);
    println!(
        "forge oracle: single sub-file uid matches {}; 28-byte sub-file indexes {}; opaque sub-file indexes {}",
        tally.single_uid_matches, tally.wide_subfile_indexes, tally.opaque_subfile_indexes
    );
    println!("forge oracle: records by type {:?}", tally.records_by_type);
    println!(
        "forge oracle: predicted magic checks {:?}",
        tally.predicted_magic_checked
    );
    println!(
        "forge oracle: 28-byte sub-file record flags {:?}",
        tally.wide_flags
    );
    println!("forge oracle: sound media payloads {:?}", tally.sound_media);
    println!(
        "forge oracle: opaque sub-file index shapes {:?}",
        tally.opaque_shapes
    );
    for (kind, heads) in &tally.record_heads {
        let mut top: Vec<(&String, &usize)> = heads.iter().collect();
        top.sort_by(|a: &(&String, &usize), b: &(&String, &usize)| b.1.cmp(a.1));
        top.truncate(4);
        println!("forge oracle: {kind} leading bytes {top:?}");
    }
    println!(
        "forge oracle: raw RIFF entries {} descriptors {} tocs {} depgraphs {} links {}",
        tally.riff_entries, tally.descriptors, tally.tocs, tally.depgraphs, tally.depgraph_links
    );
    println!("forge oracle: failures {}", tally.failure_count);
    for failure in &tally.failures {
        println!("forge oracle failure: {failure}");
    }
}

#[test]
fn every_local_forge_archive_decodes_against_its_own_declarations() {
    let found: Option<PathBuf> = std::env::var_os(DIR_ENV).map(PathBuf::from);
    let what: String = format!(
        "{DIR_ENV} set to a local game folder holding Scimitar .forge archives; the owner's game files are never \
         committed, so only a local run reads them ({FILTER_ENV} narrows the archive names)"
    );
    match disrobe_testkit::require(PREREQUISITE, &what, found) {
        Ok(available) => {
            if let Some(dir) = available.present() {
                run_oracle(&dir);
            } else {
                println!("SKIPPED by name: {PREREQUISITE} is not measured here: {what}");
            }
        }
        Err(error) => panic!("the local Forge check graded nothing: {error}"),
    }
}

fn run_oracle(dir: &Path) {
    let forges: Vec<PathBuf> = listed(dir, "forge");
    let depgraphs: Vec<PathBuf> = listed(dir, "depgraphbin");
    assert!(
        !forges.is_empty() || !depgraphs.is_empty(),
        "{DIR_ENV}={} holds no .forge or .depgraphbin file matching the filter",
        dir.display()
    );
    let threads: usize = std::env::var(THREADS_ENV)
        .ok()
        .and_then(|v: String| v.parse().ok())
        .unwrap_or(4)
        .max(1);
    let queue: Mutex<Vec<PathBuf>> = Mutex::new(forges.iter().rev().cloned().collect());
    let total: Mutex<Tally> = Mutex::new(Tally::default());
    std::thread::scope(|scope: &std::thread::Scope<'_, '_>| {
        for _ in 0..threads {
            scope.spawn(|| {
                let mut tally: Tally = Tally::default();
                let mut decoder: BlockDecoder = BlockDecoder::new();
                loop {
                    let next: Option<PathBuf> = queue.lock().unwrap().pop();
                    let Some(path) = next else { break };
                    check_archive(&path, &mut decoder, &mut tally);
                }
                tally.census.merge(&decoder.census);
                total.lock().unwrap().merge(tally);
            });
        }
    });
    let mut tally: Tally = total.into_inner().unwrap();
    for path in &depgraphs {
        check_depgraph(path, &mut tally);
    }
    report(&tally);
    assert_eq!(
        tally.failure_count, 0,
        "the local Forge check found failures"
    );
    assert_eq!(tally.decoded_bytes, tally.unpacked_bytes);
    assert!(
        tally
            .oodle_headers
            .keys()
            .all(|k: &String| !k.starts_with("refused")),
        "compressed chunks without a decodable Oodle header: {:?}",
        tally.oodle_headers
    );
}
