#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use disrobe_pass_go::{EmbedDigestFamily, EmbedFile, EmbedMap, GoAnalysis, analyze};

const HEADER_WORDS: usize = 3;
const POINTER_SIZE: usize = 8;
const RECORD_STRIDE: usize = 4 * POINTER_SIZE + 16;
const SCAN_BUDGET: Duration = Duration::from_secs(45);

fn repository_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

fn tracked_image() -> Vec<u8> {
    let path: PathBuf =
        repository_root().join("crates/disrobe-pass-go/tests/fixtures/hello_embed.exe");
    match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => panic!(
            "required reference image {} is unreadable: {error}. Every case in this file mutates \
             a real compiler-produced image and cannot run without it.",
            path.display()
        ),
    }
}

fn find_unique(haystack: &[u8], needle: &[u8]) -> usize {
    let hits: Vec<usize> = haystack
        .windows(needle.len())
        .enumerate()
        .filter(|(_, window): &(usize, &[u8])| *window == needle)
        .map(|(index, _): (usize, &[u8])| index)
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "expected exactly one occurrence of the located pattern, found {}",
        hits.len()
    );
    hits[0]
}

struct Located {
    bytes: Vec<u8>,
    header_offset: usize,
    records_offset: usize,
    map: EmbedMap,
}

fn locate() -> Located {
    let bytes: Vec<u8> = tracked_image();
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze the tracked image");
    assert_eq!(
        analysis.embed.maps.len(),
        1,
        "the tracked image must yield exactly one embed map before mutation"
    );
    let map: EmbedMap = analysis.embed.maps[0].clone();

    let mut needle: Vec<u8> = Vec::with_capacity(HEADER_WORDS * POINTER_SIZE);
    needle.extend_from_slice(&map.records_va.to_le_bytes());
    needle.extend_from_slice(&map.entry_count.to_le_bytes());
    needle.extend_from_slice(&map.entry_count.to_le_bytes());
    let header_offset: usize = find_unique(&bytes, &needle);
    let records_offset: usize = header_offset + HEADER_WORDS * POINTER_SIZE;

    Located {
        bytes,
        header_offset,
        records_offset,
        map,
    }
}

fn analyze_within_budget(bytes: &[u8], label: &str) -> GoAnalysis {
    let started: Instant = Instant::now();
    let analysis: GoAnalysis = analyze(bytes).expect("analyze the mutated image");
    let elapsed: Duration = started.elapsed();
    assert!(
        elapsed < SCAN_BUDGET,
        "{label} took {elapsed:?}, over the {SCAN_BUDGET:?} scan budget"
    );
    analysis
}

fn write_word(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + POINTER_SIZE].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn a_declared_entry_count_beyond_the_section_yields_no_map() {
    let mut located: Located = locate();
    write_word(
        &mut located.bytes,
        located.header_offset + POINTER_SIZE,
        u64::MAX,
    );
    write_word(
        &mut located.bytes,
        located.header_offset + 2 * POINTER_SIZE,
        u64::MAX,
    );
    let analysis: GoAnalysis = analyze_within_budget(&located.bytes, "saturated entry count");
    assert!(
        analysis.embed.maps.is_empty(),
        "an entry count of u64::MAX must not produce a map; got {:?}",
        analysis.embed.maps
    );
    assert!(
        analysis.embed.files.is_empty(),
        "an entry count of u64::MAX must not produce files"
    );
}

#[test]
fn a_length_that_disagrees_with_capacity_yields_no_map() {
    let mut located: Located = locate();
    let inflated: u64 = located.map.entry_count.saturating_add(1);
    write_word(
        &mut located.bytes,
        located.header_offset + POINTER_SIZE,
        inflated,
    );
    let analysis: GoAnalysis = analyze_within_budget(&located.bytes, "length above capacity");
    assert!(
        analysis.embed.maps.is_empty(),
        "a slice header whose length exceeds its capacity is not a compiler-emitted map; got {:?}",
        analysis.embed.maps
    );
}

#[test]
fn a_length_below_capacity_yields_no_map() {
    let mut located: Located = locate();
    let short: u64 = located
        .map
        .entry_count
        .checked_sub(1)
        .expect("the tracked map carries more than one record");
    write_word(
        &mut located.bytes,
        located.header_offset + POINTER_SIZE,
        short,
    );
    let analysis: GoAnalysis = analyze_within_budget(&located.bytes, "length below capacity");
    assert!(
        analysis.embed.maps.is_empty(),
        "a length below capacity would read a prefix of the records and report it as the whole \
         map, so it must be rejected rather than silently under-recovered; got {:?}",
        analysis
            .embed
            .files
            .iter()
            .map(|file: &EmbedFile| file.name.as_str())
            .collect::<Vec<&str>>()
    );
}

#[test]
fn a_file_record_carrying_the_directory_digest_sentinel_rejects_the_whole_map() {
    let located: Located = locate();
    let mut bytes: Vec<u8> = located.bytes;
    let file_index: usize = 1;
    let digest_offset: usize =
        located.records_offset + file_index * RECORD_STRIDE + 4 * POINTER_SIZE;
    assert_ne!(
        &bytes[digest_offset..digest_offset + 16],
        &[0u8; 16],
        "record {file_index} must be a file record carrying a real digest before mutation"
    );
    bytes[digest_offset..digest_offset + 16].copy_from_slice(&[0u8; 16]);
    let analysis: GoAnalysis = analyze_within_budget(&bytes, "file record with zero digest");
    assert!(
        analysis.embed.maps.is_empty(),
        "an all-zero digest is the compiler's directory sentinel, so a file record carrying it is \
         not compiler output and must not be accepted; got {:?}",
        analysis.embed.maps
    );
}

#[test]
fn a_records_pointer_outside_every_section_yields_no_map() {
    let mut located: Located = locate();
    write_word(&mut located.bytes, located.header_offset, 0xdead_0000_0000);
    let analysis: GoAnalysis =
        analyze_within_budget(&located.bytes, "records pointer out of range");
    assert!(
        analysis.embed.maps.is_empty(),
        "the anchor requires the records pointer to sit three words past the header; got {:?}",
        analysis.embed.maps
    );
}

#[test]
fn a_traversal_component_in_an_embedded_path_rejects_the_whole_map() {
    let located: Located = locate();
    let mut bytes: Vec<u8> = located.bytes;
    let target: &[u8] = b"assets/note.txt";
    let name_offset: usize = find_unique(&bytes, target);
    bytes[name_offset..name_offset + target.len()].copy_from_slice(b"assets/../etc.x");
    let analysis: GoAnalysis = analyze_within_budget(&bytes, "traversal path");
    assert!(
        analysis.embed.maps.is_empty(),
        "a record naming a parent-directory component must reject the map; got {:?}",
        analysis
            .embed
            .files
            .iter()
            .map(|file: &EmbedFile| file.name.as_str())
            .collect::<Vec<&str>>()
    );
}

#[test]
fn an_absolute_embedded_path_rejects_the_whole_map() {
    let located: Located = locate();
    let mut bytes: Vec<u8> = located.bytes;
    let target: &[u8] = b"assets/note.txt";
    let name_offset: usize = find_unique(&bytes, target);
    bytes[name_offset..name_offset + target.len()].copy_from_slice(b"/etc/shadow.txt");
    let analysis: GoAnalysis = analyze_within_budget(&bytes, "absolute path");
    assert!(
        analysis.embed.maps.is_empty(),
        "a record naming an absolute path must reject the map; got {:?}",
        analysis
            .embed
            .files
            .iter()
            .map(|file: &EmbedFile| file.name.as_str())
            .collect::<Vec<&str>>()
    );
}

#[test]
fn a_nonzero_directory_digest_rejects_the_whole_map() {
    let located: Located = locate();
    let mut bytes: Vec<u8> = located.bytes;
    let directory_index: usize = 0;
    let digest_offset: usize =
        located.records_offset + directory_index * RECORD_STRIDE + 4 * POINTER_SIZE;
    assert_eq!(
        &bytes[digest_offset..digest_offset + 16],
        &[0u8; 16],
        "record {directory_index} must be the directory record with an all-zero digest"
    );
    bytes[digest_offset] = 0x01;
    let analysis: GoAnalysis = analyze_within_budget(&bytes, "nonzero directory digest");
    assert!(
        analysis.embed.maps.is_empty(),
        "a directory record carrying a nonzero digest is not compiler output; got {:?}",
        analysis.embed.maps
    );
}

#[test]
fn corrupting_one_embedded_byte_fails_only_that_file_s_digest() {
    let located: Located = locate();
    let mut bytes: Vec<u8> = located.bytes;
    let target: &[u8] = b"disrobe embed fixture payload alpha\n";
    let data_offset: usize = find_unique(&bytes, target);
    bytes[data_offset] ^= 0x01;

    let analysis: GoAnalysis = analyze_within_budget(&bytes, "corrupted member byte");
    assert_eq!(
        analysis.embed.maps.len(),
        1,
        "corrupting member content must not destroy the structural map"
    );
    let map: &EmbedMap = &analysis.embed.maps[0];
    assert_eq!(
        map.digest_family,
        Some(EmbedDigestFamily::Sha256LowByte),
        "the surviving files still identify the digest family"
    );
    assert_eq!(
        map.verified_files,
        map.file_count - 1,
        "exactly one of {} files must fail verification after a single byte flip",
        map.file_count
    );
    let failing: Vec<&str> = analysis
        .embed
        .files
        .iter()
        .filter(|file: &&EmbedFile| !file.is_dir && !file.digest_verified)
        .map(|file: &EmbedFile| file.name.as_str())
        .collect();
    assert_eq!(
        failing,
        vec!["assets/note.txt"],
        "the flipped byte belongs to assets/note.txt and only that file must fail"
    );
}

#[test]
fn embed_recovery_is_byte_identical_across_repeated_runs() {
    let bytes: Vec<u8> = tracked_image();
    let first: GoAnalysis = analyze(&bytes).expect("first analysis");
    let second: GoAnalysis = analyze(&bytes).expect("second analysis");
    assert_eq!(
        first.embed, second.embed,
        "embed recovery must be deterministic across runs"
    );
    let names: Vec<&str> = first
        .embed
        .files
        .iter()
        .map(|file: &EmbedFile| file.name.as_str())
        .collect();
    let mut sorted: Vec<&str> = names.clone();
    sorted.sort_unstable();
    assert_eq!(
        names, sorted,
        "recovered files must be emitted in path order"
    );
}

#[test]
fn a_truncated_image_neither_panics_nor_reports_files() {
    let bytes: Vec<u8> = tracked_image();
    for fraction in [2usize, 4, 8, 16] {
        let cut: usize = bytes.len() / fraction;
        let truncated: &[u8] = &bytes[..cut];
        let Ok(analysis): Result<GoAnalysis, _> = analyze(truncated) else {
            continue;
        };
        for file in &analysis.embed.files {
            assert!(
                !file.name.contains(".."),
                "a truncated image produced a traversal path {:?}",
                file.name
            );
        }
    }
}

fn count_verified(path: &Path) -> (usize, usize) {
    let bytes: Vec<u8> = std::fs::read(path).expect("tracked image");
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze");
    let files: usize = analysis
        .embed
        .files
        .iter()
        .filter(|file: &&EmbedFile| !file.is_dir)
        .count();
    let verified: usize = analysis
        .embed
        .files
        .iter()
        .filter(|file: &&EmbedFile| !file.is_dir && file.digest_verified)
        .count();
    (verified, files)
}

#[test]
fn every_recovered_file_in_the_tracked_images_verifies_against_its_stored_digest() {
    let root: PathBuf = repository_root();
    let cases: [(&str, PathBuf); 2] = [
        (
            "hello_embed.exe",
            root.join("crates/disrobe-pass-go/tests/fixtures/hello_embed.exe"),
        ),
        ("wvfix.exe", root.join("corpus/webview/wails/wvfix.exe")),
    ];
    let mut total_verified: usize = 0;
    let mut total_files: usize = 0;
    for (label, path) in cases {
        let (verified, files): (usize, usize) = count_verified(&path);
        assert_eq!(verified, files, "{label} verified {verified} of {files}");
        total_verified += verified;
        total_files += files;
    }
    assert_eq!(
        (total_verified, total_files),
        (13, 13),
        "stored-digest verification across both tracked images"
    );
}
